import copy
import io
import json
import os
import subprocess
import sys
import urllib.error
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer import pipeline
from icsot_observer.core import Config, ObjectStore, canonical_json, sha256
from icsot_observer.github import APIRequestDeferred, GitHubAPI
from icsot_observer.github_state import GhCliStateTransport, GitHubStateStore, StateConflictError, StateDeferredError, StateError
from icsot_observer.recurrence import BoundedStateTransport, build_plan, load_cohort, load_resource_limits, public_outcome, select_entry
from test_github_runner_integration import MemoryGitHub, keys
from icsot_observer.runtime import Finalization
from icsot_observer.history import FULL_HISTORY, RECENT_HISTORY, load_history_settings, repository_history_policy


CODE = "a" * 40
SOURCES = {"config_source_sha256": "1" * 64, "csv_sha256": "2" * 64, "cohort_count": 3}


def config(tmp_path):
    return Config(tmp_path / "unused", ("one/repo", "two/repo", "three/repo"), "2026-03-10",
                  "research", "NO_TEST_TOKEN", 5, 1000000, 48, 100)


def plan(tmp_path, **options):
    cfg = config(tmp_path)
    identities = {slug: {"id": number, "private": False, "size": 100} for number, slug in enumerate(cfg.repositories, 17)}
    pointer = canonical_json({"repository_id": 17, "slug": "one/repo", "generation": "a" * 32})
    return build_plan(cfg, sources=SOURCES, code_sha=CODE,
                      identity_loader=options.pop("identity_loader", identities.__getitem__),
                      pointer_loader=options.pop("pointer_loader", lambda repo_id: pointer if repo_id == 17 else None),
                      now=options.pop("now", 100000), cold_bootstraps=options.pop("cold_bootstraps", 2), **options)


def test_entire_cohort_plan_selects_ready_state_and_only_bounded_explicit_cold_wave(tmp_path):
    result = plan(tmp_path, cold_bootstraps=1)
    assert len(result["repositories"]) == 3
    assert len(result["matrix"]["include"]) == 2
    assert result["counts"] == {"ready_incremental": 1, "fresh_public_bootstrap": 1, "bootstrap_pending": 1}
    ready = next(row for row in result["matrix"]["include"] if row["plan_status"] == "ready_incremental")
    cold = next(row for row in result["matrix"]["include"] if row["plan_status"] == "fresh_public_bootstrap")
    assert ready["allow_bootstrap"] is False and ready["expected_pointer_sha256"]
    assert cold["allow_bootstrap"] is True and cold["expected_pointer_sha256"] is None
    assert result["max_parallel"] == 8
    assert result["monthly_cap_enforced"] is False
    assert "monthly_evidence_policy_bytes" not in result


def test_manual_and_scheduled_retries_share_slot_and_cold_attempts_rotate(tmp_path):
    first = plan(tmp_path, now=100000, cold_bootstraps=1)
    retry = plan(tmp_path, now=100001, cold_bootstraps=1)
    next_slot = plan(tmp_path, now=100000 + 21600, cold_bootstraps=1)
    assert first["matrix"] == retry["matrix"]
    cold = lambda result: next(row for row in result["matrix"]["include"] if row["allow_bootstrap"])
    assert cold(first)["slug"] != cold(next_slot)["slug"]
    assert first["matrix"]["include"][0]["observation_key"] != next_slot["matrix"]["include"][0]["observation_key"]
    assert plan(tmp_path, cold_bootstraps=0)["counts"]["bootstrap_pending"] == 2
    with pytest.raises(ValueError, match="0 through 8"):
        plan(tmp_path, cold_bootstraps=9)


@pytest.fixture
def full_cohort_planner():
    root = Path(__file__).resolve().parents[2]
    cfg, sources = load_cohort(root / "icsot-observatory/config.corpus.toml", root / "public_patch_corpus_185.csv")
    identifiers = {slug: number for number, slug in enumerate(cfg.repositories, 20000)}
    def build(slot=123456, *, ready_count=185, cold_bootstraps=0, offset_seconds=0):
        pointers = {repo_id: canonical_json({"repository_id": repo_id, "slug": slug, "generation": "b" * 32})
                    for slug, repo_id in list(identifiers.items())[:ready_count]}
        return build_plan(cfg, sources=sources, code_sha=CODE,
            identity_loader=lambda slug: {"id": identifiers[slug], "private": False, "size": 100},
            pointer_loader=pointers.get, cold_bootstraps=cold_bootstraps,
            now=slot * 21600 + offset_seconds)
    return cfg, sources, identifiers, build


@pytest.mark.parametrize("cold_bootstraps", [0, 3])
def test_shuffled_matrix_preserves_full_canonical_cohort_lock_and_eligibility(full_cohort_planner, cold_bootstraps):
    cfg, sources, identifiers, build = full_cohort_planner
    result = build(ready_count=174, cold_bootstraps=cold_bootstraps)
    rows, selected = result["repositories"], result["matrix"]["include"]
    assert tuple(row["slug"] for row in rows) == cfg.repositories and len(rows) == 185
    expected_hash = sha256(canonical_json([{"slug": slug, "repository_id": identifiers[slug]} for slug in cfg.repositories]))
    assert result["cohort_identity_sha256"] == expected_hash
    assert {row["slug"] for row in selected} == {
        row["slug"] for row in rows if row["plan_status"] in ("ready_incremental", "fresh_public_bootstrap")}
    assert len(selected) == len({row["repository_id"] for row in selected}) == 174 + cold_bootstraps
    missing = list(cfg.repositories[174:])
    offset = (result["slot"] * cold_bootstraps) % len(missing)
    expected_cold = (missing[offset:] + missing[:offset])[:cold_bootstraps]
    assert {row["slug"] for row in rows if row["allow_bootstrap"]} == set(expected_cold)
    for row in rows:
        assert row["repository_id"] == identifiers[row["slug"]]
        assert row["cohort_identity_sha256"] == expected_hash and row["code_sha"] == CODE
        assert row["slot"] == result["slot"] and row["observation_key"] == f"six-hour-slot-{result['slot']}"
        assert all(row[key] == value for key, value in sources.items())
    for row in selected:
        assert select_entry(result, row["slug"], config=cfg, sources=sources, code_sha=CODE) == row
    assert result["execution_order_sha256"] == sha256(canonical_json([row["repository_id"] for row in selected]))


def test_execution_priority_replays_within_slot_and_varies_prefix_across_slots(full_cohort_planner):
    cfg, _, _, build = full_cohort_planner
    plans = [build(slot=123456 + offset) for offset in range(8)]
    replay = build(slot=123456, offset_seconds=120)
    assert replay["repositories"] == plans[0]["repositories"] and replay["matrix"] == plans[0]["matrix"]
    assert replay["execution_order_seed_sha256"] == plans[0]["execution_order_seed_sha256"]
    assert len({item["cohort_identity_sha256"] for item in plans}) == 1
    assert len({item["execution_order_seed_sha256"] for item in plans}) == len(plans)
    assert len({item["execution_order_sha256"] for item in plans}) == len(plans)
    prefixes = {tuple(row["slug"] for row in item["matrix"]["include"][:8]) for item in plans}
    assert len(prefixes) == len(plans)
    for item in plans:
        assert {row["slug"] for row in item["matrix"]["include"]} == set(cfg.repositories)
        assert tuple(row["slug"] for row in item["repositories"]) == cfg.repositories
        assert tuple(row["slug"] for row in item["matrix"]["include"]) != cfg.repositories


def test_execution_priority_is_independent_of_python_hash_seed(tmp_path):
    script = '''
import json
from pathlib import Path
from icsot_observer.core import Config, canonical_json
from icsot_observer.recurrence import build_plan
repositories = tuple(f"sector{number // 37}/repo{number}" for number in range(185))
config = Config(Path("unused"), repositories, "2026-03-10", "research", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
identifiers = {slug: number for number, slug in enumerate(repositories, 20000)}
slugs = {number: slug for slug, number in identifiers.items()}
plan = build_plan(config, sources={"cohort_count": 185}, code_sha="a" * 40,
    identity_loader=lambda slug: {"id": identifiers[slug], "private": False, "size": 100},
    pointer_loader=lambda number: canonical_json({"repository_id": number, "slug": slugs[number], "generation": "b" * 32}),
    now=123456 * 21600)
print(json.dumps({"matrix": plan["matrix"], "seed": plan["execution_order_seed_sha256"], "digest": plan["execution_order_sha256"]}, sort_keys=True))
'''
    source_root = Path(__file__).resolve().parents[1] / "src"
    outputs = [subprocess.check_output([sys.executable, "-c", script], cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(source_root), "PYTHONHASHSEED": seed}) for seed in ("1", "987654")]
    assert outputs[0] == outputs[1]
    assert len(json.loads(outputs[0])["matrix"]["include"]) == 185


@pytest.mark.parametrize("category", ["secondary_rate_limit", None])
def test_shared_or_unclassified_source_rate_deferral_pauses_remaining_identity_requests(tmp_path, category):
    called = []

    def identity(slug):
        called.append(slug)
        error = APIRequestDeferred(200000, "potentially shared throttling")
        error.diagnostic_category = category
        raise error

    result = plan(tmp_path, identity_loader=identity)
    assert called == ["one/repo"]
    assert result["matrix"]["include"] == []
    assert result["counts"] == {"paused_identity": 3}
    assert result["repositories"][0]["retry_not_before"] == 200000
    assert result["repositories"][1]["reason_code"] == "shared_source_rate_deferred"


@pytest.mark.parametrize("category", ["primary_reserve_future_reset", "primary_reserve_wait_budget", "primary_rate_limit"])
def test_primary_account_deferral_does_not_suppress_later_identity_requests(tmp_path, category):
    called = []

    def identity(slug):
        called.append(slug)
        if slug == "one/repo":
            error = APIRequestDeferred(200000, "primary allowance exhausted")
            error.diagnostic_category = category
            raise error
        return {"id": 18 if slug == "two/repo" else 19, "private": False, "size": 100}

    result = plan(tmp_path, identity_loader=identity, cold_bootstraps=0)
    assert called == list(config(tmp_path).repositories)
    assert result["counts"] == {"paused_identity": 1, "bootstrap_pending": 2}
    assert result["repositories"][0]["retry_not_before"] == 200000


@pytest.mark.parametrize("exhausted_slot", [0, 1])
def test_initialized_plan_keeps_healthy_fixed_credential_slot_after_primary_reserve(tmp_path, monkeypatch, exhausted_slot):
    from test_source_tokens import Reply
    repositories = ("test/alpha", "test/beta", "test/gamma", "test/delta", "test/zeta", "test/epsilon")
    cfg = replace(config(tmp_path), repositories=repositories, token_env="GITHUB_TOKEN", primary_rate_reserve=40,
                  primary_rate_wait_seconds=0)
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-primary")
    monkeypatch.setenv("COLLECTOR_READ_TOKEN_SECONDARY", "synthetic-secondary")
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000)
    api = GitHubAPI(cfg, ObjectStore(cfg.root), [], defer_on_rate=True)
    slots = dict(zip(repositories, (0, 1, 0, 1, 0, 1)))
    identifiers = {slug: number for number, slug in enumerate(repositories, 17)}
    requests, identities, pointers = [], [], []

    def opened(request, timeout):
        slug = request.full_url.removeprefix("https://api.github.com/repos/")
        requests.append((slug, request.get_header("Authorization")))
        return Reply(canonical_json({"id": identifiers[slug], "private": False, "size": 100}),
                     {"X-RateLimit-Remaining": "39" if slots[slug] == exhausted_slot else "4999",
                      "X-RateLimit-Reset": "1060"})

    monkeypatch.setattr(api.opener, "open", opened)
    # A real response primes only its assigned account's reserve observation.
    api.get_json("/repos/" + repositories[exhausted_slot], "repository_identity")

    def identity(slug):
        identities.append(slug)
        return api.get_json("/repos/" + slug, "repository_identity")

    def pointer(repo_id):
        pointers.append(repo_id)
        slug = next(slug for slug in repositories if identifiers[slug] == repo_id)
        return canonical_json({"repository_id": repo_id, "slug": slug, "generation": "a" * 32})

    result = build_plan(cfg, sources={**SOURCES, "cohort_count": 6}, code_sha=CODE,
                        identity_loader=identity, pointer_loader=pointer, now=1000)
    healthy = {slug for slug in repositories if slots[slug] != exhausted_slot}
    assert identities == list(repositories)
    assert {row["slug"] for row in result["matrix"]["include"]} == healthy
    assert set(pointers) == {identifiers[slug] for slug in healthy}
    assert result["counts"] == {"paused_identity": 3, "ready_incremental": 3}
    assert all(row["expected_pointer_sha256"] and not row["allow_bootstrap"] for row in result["matrix"]["include"])
    assert all(row["retry_not_before"] == 1061 for row in result["repositories"] if row["slug"] not in healthy)
    assert len(requests) == 4  # Warmup, then only the healthy account's three identities.
    assert all(auth == "Bearer " + ("synthetic-primary" if slots[slug] == 0 else "synthetic-secondary")
               for slug, auth in requests)


def test_real_secondary_deferral_stops_plan_before_other_account_identity_or_pointer(tmp_path, monkeypatch):
    cfg = replace(config(tmp_path), repositories=("test/alpha", "test/beta"), token_env="GITHUB_TOKEN")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-primary")
    monkeypatch.setenv("COLLECTOR_READ_TOKEN_SECONDARY", "synthetic-secondary")
    api = GitHubAPI(cfg, ObjectStore(cfg.root), [], defer_on_rate=True)
    requests, identities = [], []

    def opened(request, timeout):
        requests.append(request.get_header("Authorization"))
        raise urllib.error.HTTPError(request.full_url, 429, "limited", {"Retry-After": "120"}, io.BytesIO(b"{}"))

    def identity(slug):
        identities.append(slug)
        return api.get_json("/repos/" + slug, "repository_identity")

    monkeypatch.setattr(api.opener, "open", opened)
    result = build_plan(cfg, sources=SOURCES, code_sha=CODE, identity_loader=identity,
                        pointer_loader=lambda repo_id: pytest.fail("no identity was admitted"), now=1000)
    assert identities == ["test/alpha"] and requests == ["Bearer synthetic-primary"]
    assert result["matrix"]["include"] == [] and result["counts"] == {"paused_identity": 2}
    assert result["repositories"][1]["reason_code"] == "shared_source_rate_deferred"


def test_identity_reuse_and_invalid_pointer_never_become_fresh_bootstrap(tmp_path):
    result = plan(tmp_path, identity_loader=lambda slug: {"id": 17, "private": False})
    assert result["matrix"]["include"] == []
    assert all(row["reason_code"] == "duplicate_numeric_identity" for row in result["repositories"])
    result = plan(tmp_path, pointer_loader=lambda repo_id: canonical_json({"repository_id": 999}))
    assert result["counts"] == {"paused_state": 3}


def test_large_profile_is_reported_size_only_frozen_and_paused_until_validated(tmp_path):
    identities = {slug: {"id": number, "private": False, "size": size}
                  for number, slug, size in [(17, "one/repo", 100), (18, "two/repo", 6_000_000),
                                             (19, "three/repo", 200)]}
    result = plan(tmp_path, identity_loader=identities.__getitem__)
    large = result["repositories"][1]
    assert large["plan_status"] == "large_profile_pending"
    assert large not in result["matrix"]["include"]
    assert large["history_policy"]["profile"] == RECENT_HISTORY
    assert large["history_policy"]["window_days"] == 730
    assert large["history_policy"]["reported_size_kb"] == 6_000_000
    assert large["history_policy"]["threshold_kb"] == 5_000_000
    assert large["history_policy"]["cutoff_utc"] == "1968-01-03T00:00:00Z"
    assert result["repositories"][0]["history_policy"]["profile"] == FULL_HISTORY
    assert len(result["matrix"]["include"]) == 2
    forced = plan(tmp_path, identity_loader=identities.__getitem__,
                  history_settings={"overrides": {"two/repo": FULL_HISTORY}})
    assert forced["repositories"][1]["history_policy"]["selection_reason"] == "manual"
    assert forced["repositories"][1]["plan_status"] == "fresh_public_bootstrap"


def test_history_threshold_and_manual_override_are_configuration_locked(tmp_path):
    path = tmp_path / "history.toml"
    path.write_text('[history]\nlarge_repo_threshold_kb=123456\nwindow_days=730\n'
                    '[history.overrides]\n"one/repo"="recent_history_shallow_v1"\n')
    settings = load_history_settings(path, config(tmp_path).repositories)
    assert settings["threshold_kb"] == 123456
    assert settings["overrides"] == {"one/repo": RECENT_HISTORY}
    path.write_text('[history.overrides]\n"outside/repo"="full_history"\n')
    with pytest.raises(ValueError, match="declared repositories"):
        load_history_settings(path, config(tmp_path).repositories)


def test_large_comparison_is_strict_and_uses_unconverted_reported_units():
    assert repository_history_policy("one/repo", 5_000_000, 100)["profile"] == FULL_HISTORY
    assert repository_history_policy("one/repo", 5_000_001, 100)["profile"] == RECENT_HISTORY


def test_resource_limits_are_reported_and_can_be_overridden_per_repository(tmp_path):
    path = tmp_path / "resources.toml"
    path.write_text('[recurrence.limits]\njob_timeout_minutes=120\n'
                    '[recurrence.overrides."two/repo"]\nmax_new_evidence_ciphertext_bytes=12345\n')
    limits = load_resource_limits(path, config(tmp_path).repositories)
    result = plan(tmp_path, resource_limits=limits)
    assert all(row["resource_limits"]["job_timeout_minutes"] == 120 for row in result["repositories"])
    assert result["repositories"][1]["resource_limits"]["max_new_evidence_ciphertext_bytes"] == 12345
    assert result["repositories"][0]["resource_limits"]["max_new_evidence_ciphertext_bytes"] == 2 * 1024 ** 3


def test_locked_plan_rejects_source_hash_identity_slot_or_selection_changes(tmp_path):
    result = plan(tmp_path)
    options = dict(config=config(tmp_path), sources=SOURCES, code_sha=CODE)
    assert select_entry(result, "one/repo", **options)["repository_id"] == 17
    with pytest.raises(ValueError, match="configuration/CSV"):
        select_entry(result, "one/repo", **{**options, "sources": {**SOURCES, "csv_sha256": "3" * 64}})
    changed = copy.deepcopy(result)
    changed["repositories"][0]["repository_id"] = 999
    with pytest.raises(ValueError, match="identity lock"):
        select_entry(changed, "one/repo", **options)
    changed = copy.deepcopy(result)
    changed["repositories"][0]["observation_key"] = "another-slot"
    with pytest.raises(ValueError, match="slot"):
        select_entry(changed, "one/repo", **options)


def test_source_csv_order_is_part_of_locked_cohort(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[collector]\nroot="evidence"\napi_version="2026-03-10"\nuser_agent="research"\n'
                   'token_env="NO_TEST_TOKEN"\n[cohort]\nrepositories=["one/repo","two/repo"]\n')
    csv = tmp_path / "cohort.csv"
    csv.write_text("Repository_URL\nhttps://github.com/one/repo\nhttps://github.com/two/repo\n")
    _, hashes = load_cohort(cfg, csv, expected_count=2)
    assert hashes["csv_sha256"] == sha256(csv.read_bytes())
    csv.write_text("Repository_URL\nhttps://github.com/two/repo\nhttps://github.com/one/repo\n")
    with pytest.raises(ValueError, match="every CSV row"):
        load_cohort(cfg, csv, expected_count=2)


def test_per_job_upload_limits_account_state_and_evidence_separately_before_write(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(GhCliStateTransport, "upload_asset", lambda self, tag, name, source: calls.append((tag, name)))
    transport = BoundedStateTransport("owner/collector", evidence_bytes=3, state_bytes=4)
    small = tmp_path / "small"
    small.write_bytes(b"123")
    transport.upload_asset("collector-observations-r17-gabc", "evidence.enc", small)
    transport.upload_asset("collector-state-r17-gabc", "state.enc", small)
    with pytest.raises(StateDeferredError, match="evidence upload limit"):
        transport.upload_asset("collector-observations-r17-gabc", "overflow.enc", small)
    assert len(calls) == 2 and transport.uploaded_bytes == {"evidence": 3, "state": 3}


@pytest.mark.parametrize("guard", ["bootstrap_not_approved", "stale_pointer", "oversized_state"])
def test_hosted_guards_run_before_restore_or_capture(tmp_path, monkeypatch, guard):
    state_public, state_private = keys(tmp_path, "state")
    evidence_public, _ = keys(tmp_path, "evidence")
    transport = MemoryGitHub()
    options = dict(allow_bootstrap=False)
    error_type = StateError
    if guard == "stale_pointer":
        options = dict(require_planned_state=True, expected_state_pointer_sha256="0" * 64)
        error_type = StateConflictError
    elif guard == "oversized_state":
        monkeypatch.setattr(GitHubStateStore, "read", lambda self: SimpleNamespace(
            pointer={"generation": "a" * 32}, index={"files": [{"bytes": 11}]}))
        options = dict(max_restored_state_plaintext_bytes=10)
    restored = []
    monkeypatch.setattr(GitHubStateStore, "restore", lambda self, selection: restored.append(selection))
    monkeypatch.setattr(pipeline, "run_persistent", lambda *a, **k: pytest.fail("capture ran before hosted guard"))
    with pytest.raises(error_type):
        pipeline.run_github_persistent(config(tmp_path), slug="one/repo", repository_id=17,
            destination_repository="owner/collector", state_public_key=state_public,
            state_private_key=state_private, evidence_public_key=evidence_public,
            code_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            config_source_sha256="1" * 64, transport=transport, logical_root=tmp_path / "working", **options)
    assert not restored and not transport.assets


def test_public_outcome_keeps_deferred_api_partial_even_when_git_completed(tmp_path):
    entry = plan(tmp_path)["matrix"]["include"][0]
    result = {"working_state_origin": "resumed_authenticated_state", "new_evidence_upload_bytes": 4,
              "publication": {"state_uploaded_ciphertext_bytes": 5, "state_referenced_ciphertext_bytes": 6, "generation": "a" * 32},
              "collection": {"queue": {"states": {"complete": 1, "queued": 1}}, "partial_captures": [],
                             "runtime": {"completed": 1}}}
    report = public_outcome(result, entry)
    assert report["status"] == "partial" and report["pending_jobs"] == 1
    assert report["new_evidence_upload_bytes"] == 4 and report["new_state_upload_bytes"] == 5


@pytest.mark.parametrize("ots_status", ["pending_bitcoin_completion", "bitcoin_attestation_unverified"])
def test_complete_coverage_preserves_failed_freetsa_pending_registration_and_unverified_ots(tmp_path, ots_status):
    entry = plan(tmp_path)["matrix"]["include"][0]
    result = {"working_state_origin": "resumed_authenticated_state", "new_evidence_upload_bytes": 4,
              "publication": {"state_uploaded_ciphertext_bytes": 5, "state_referenced_ciphertext_bytes": 6, "generation": "a" * 32},
              "proof_maintenance_registration": {"status": "registration_pending", "catalog_key": "c" * 64, "proofs_in_catalog": 6},
              "collection": {"queue": {"states": {"complete": 2}}, "partial_captures": [], "runtime": {"completed": 2},
                             "current_observation": {"status": "complete", "lane_outcomes": [
                                 {"capture_id": lane + "-capture", "lane": lane, "status": "complete"} for lane in ("api", "git")]}}}
    result["lane_publication_outcomes"] = [{
        "capture_id": lane + "-capture", "lane": lane, "manifest_sha256": "a" * 64, "index_sha256": "b" * 64,
        "verification": {"raw_response_objects_verified": 2, "raw_response_bytes_verified": 100,
                         "portable_git_restore": "passed_into_empty_repository", "unknown": "private-body-marker"},
        "archive_status": "complete", "encryption_status": "encrypted", "transfer_status": "uploaded_dependency_verified",
        "timestamp_provider_outcomes": {
            "rfc3161": {"provider": "digicert", "status": "verified_chain_and_imprint", "verification": {
                "nonce_and_query_verified": True, "certificate_chain_verified": True, "subject_imprint_verified": True}},
            "freetsa": {"status": "failed", "message": "private-body-marker"},
            "opentimestamps": {"status": ots_status, "verification": {"bitcoin_verified": False}, "body": "private-body-marker"}},
        "response_body": "private-body-marker"} for lane in ("api", "git")]
    report = public_outcome(result, entry)
    assert report["status"] == "complete" and report["status_scope"] == "collection_coverage"
    assert report["proof_maintenance_registration"] == result["proof_maintenance_registration"]
    assert "private-body-marker" not in json.dumps(report)
    assert len(report["lane_publication_outcomes"]) == 2
    for lane in report["lane_publication_outcomes"]:
        assert lane["manifest_sha256"] == "a" * 64 and lane["index_sha256"] == "b" * 64
        assert lane["verification"]["raw_response_objects_verified"] == 2
        providers = lane["timestamp_provider_outcomes"]
        assert providers["rfc3161"]["provider"] == "digicert"
        assert providers["rfc3161"]["verification"]["certificate_chain_verified"] is True
        assert providers["freetsa"]["status"] == "failed"
        assert providers["opentimestamps"]["status"] == ots_status
        assert providers["opentimestamps"]["verification"]["bitcoin_verified"] is False
    unsafe = copy.deepcopy(result)
    detail = unsafe["lane_publication_outcomes"][0]
    detail.update(archive_status="private-body-marker", index_sha256="abcd1234", manifest_sha256=17)
    detail["verification"]["git_mirror_fsck"] = "private-body-marker"
    detail["timestamp_provider_outcomes"]["opentimestamps"].update(status="private-body-marker", retry="private-body-marker")
    unsafe["proof_maintenance_registration"].update(status="private-body-marker", catalog_key=17)
    sanitized = public_outcome(unsafe, entry)
    assert "private-body-marker" not in json.dumps(sanitized)
    assert sanitized["lane_publication_outcomes"][0]["archive_status"] == "unknown"
    assert "index_sha256" not in sanitized["lane_publication_outcomes"][0]
    assert "manifest_sha256" not in sanitized["lane_publication_outcomes"][0]
    assert sanitized["lane_publication_outcomes"][0]["timestamp_provider_outcomes"]["opentimestamps"]["status"] == "unknown"
    assert sanitized["proof_maintenance_registration"]["status"] == "unknown"


def test_public_lane_outcomes_distinguish_missing_current_capture_from_completed_older_capture(tmp_path):
    entry = plan(tmp_path)["matrix"]["include"][0]
    result = {"working_state_origin": "resumed_authenticated_state", "new_evidence_upload_bytes": 0,
              "publication": {"state_uploaded_ciphertext_bytes": 5, "state_referenced_ciphertext_bytes": 6, "generation": "a" * 32},
              "collection": {"queue": {"states": {"complete": 1, "queued": 1}}, "partial_captures": [], "runtime": {"completed": 1},
                             "current_observation": {"status": "partial", "lane_outcomes": [
                                 {"capture_id": "current-git", "lane": "git", "status": "queued"}],
                                 "missing_lanes": [{"slug": entry["slug"], "lane": "api"}]},
                             "resumed_older_captures": [{"capture_id": "older-api", "lane": "api", "status": "complete"}]},
              "lane_publication_outcomes": [{"capture_id": "older-api", "lane": "api", "manifest_sha256": "a" * 64,
                  "index_sha256": "b" * 64, "verification": {"raw_response_objects_verified": 3},
                  "archive_status": "complete", "encryption_status": "encrypted", "transfer_status": "retained_authenticated_catalog"}]}
    report = public_outcome(result, entry)
    current_git, missing_api, older_api = report["lane_publication_outcomes"]
    assert report["status"] == "partial"
    assert current_git["collection_status"] == "queued" and current_git["archive_status"] == "not_run"
    assert missing_api["collection_status"] == "not_collected" and missing_api["verification"] == {}
    assert missing_api["timestamp_provider_outcomes"]["opentimestamps"]["status"] == "not_recorded"
    assert older_api["observation"] == "resumed_older" and older_api["collection_status"] == "complete"
    assert older_api["transfer_status"] == "retained_authenticated_catalog" and older_api["index_sha256"] == "b" * 64


@pytest.mark.parametrize("outcome", ["complete", "paused", "failed"])
def test_cli_outcomes_retain_planned_execution_provenance(tmp_path, monkeypatch, outcome):
    from icsot_observer import recurrence
    from icsot_observer.priorities import FrozenPriorities
    cfg = config(tmp_path)
    priorities = FrozenPriorities(cfg.repositories, {slug: "P2" for slug in cfg.repositories}, "d" * 64)
    result = plan(tmp_path, frozen_priorities=priorities)
    entry = result["matrix"]["include"][-1]
    raw = canonical_json(result)
    plan_path, output = tmp_path / "plan.json", tmp_path / "outcome.json"
    plan_path.write_bytes(raw)
    def capture(*args, **kwargs):
        if outcome == "paused":
            raise StateDeferredError("bounded mock deferral", reason="destination_quota_deferred")
        if outcome == "failed":
            raise ValueError("arbitrary exception text must stay private")
        return {"working_state_origin": "resumed_authenticated_state", "new_evidence_upload_bytes": 4,
                "publication": {"state_uploaded_ciphertext_bytes": 5, "state_referenced_ciphertext_bytes": 6,
                                "generation": "b" * 32},
                "collection": {"queue": {"states": {"complete": 2}}, "partial_captures": [],
                               "runtime": {"completed": 2}}}
    monkeypatch.setattr(recurrence.subprocess, "check_output", lambda *args, **kwargs: CODE)
    monkeypatch.setattr(recurrence, "load_cohort", lambda *args: (cfg, SOURCES))
    monkeypatch.setattr(recurrence, "load_frozen_priorities", lambda *args, **kwargs: priorities)
    monkeypatch.setattr(recurrence, "load_history_settings", lambda *args: {})
    monkeypatch.setattr(recurrence, "load_resource_limits", lambda *args: {})
    monkeypatch.setattr(pipeline, "run_github_persistent", capture)
    code = recurrence.main(["run", "--config", str(tmp_path / "config"), "--csv", str(tmp_path / "csv"),
        "--code-sha", CODE, "--destination-repository", "owner/collector", "--output", str(output),
        "--plan", str(plan_path), "--plan-sha256", sha256(raw), "--slug", entry["slug"],
        "--state-public-key", str(tmp_path / "unused-state-public"),
        "--state-private-key", str(tmp_path / "unused-state-private"),
        "--evidence-public-key", str(tmp_path / "unused-evidence-public")])
    report = json.loads(output.read_bytes())
    assert report["status"] == outcome and code == {"complete": 0, "paused": 75, "failed": 2}[outcome]
    for key in ("execution_order_policy", "execution_order_seed_sha256", "execution_order_sha256", "execution_order_qualification"):
        assert report[key] == result[key]
    assert report["planned_execution_position"] == len(result["matrix"]["include"])
    assert report["priority"] == entry["priority"] == "P2"
    assert report["priority_order_position"] == entry["priority_order_position"]
    assert report["priority_policy_sha256"] == priorities.sha256
    assert "arbitrary exception text" not in output.read_text()


@pytest.mark.parametrize("partial", [False, True])
def test_same_slot_restart_retains_origin_and_partial_without_recapturing_completed_lanes(tmp_path, monkeypatch, partial):
    cfg = replace(config(tmp_path), root=tmp_path / "working", repositories=("one/repo",))
    captures = []

    def capture(cfg, job, queue):
        captures.append(job.capture_id)
        return {"capture_id": job.capture_id, "slug": job.slug, "repository_id": 17, "lane": job.lane,
                "mode": "full", "requested_mode": job.mode, "responses": [],
                "failures": ["incomplete scope"] if partial and job.lane == "api" else [],
                "started_at": "2026-10-26T00:00:00Z", "finished_at": "2026-10-26T00:00:01Z",
                "working_state_origin": job.payload["working_state_origin"]}

    def finalize(cfg, job, result, **options):
        info = pipeline.append_capture_manifest(cfg, result)
        return Finalization(info["manifest"], info["manifest_sha256"])

    monkeypatch.setattr(pipeline, "capture_lane", capture)
    monkeypatch.setattr(pipeline, "finalize_lane", finalize)
    first = pipeline.run_persistent(cfg, once=True, stamp=False, observation_key="six-hour-slot-123",
                                    working_state_origin="fresh_public_bootstrap")
    second = pipeline.run_persistent(cfg, once=True, stamp=False, observation_key="six-hour-slot-123",
                                     working_state_origin="resumed_authenticated_state")
    assert first["runtime"]["completed"] == 2 and second["runtime"]["completed"] == 0
    expected = "partial" if partial else "complete"
    assert first["current_observation"]["status"] == second["current_observation"]["status"] == expected
    assert bool(first["partial_captures"]) == bool(second["partial_captures"]) == partial
    assert len(captures) == 2
    manifests = [json.loads(path.read_bytes()) for path in (cfg.root / "runs" / "17").glob("*.manifest.json")]
    assert len(manifests) == 2
    assert all(item["working_state_origin"] == "fresh_public_bootstrap" for item in manifests)


def test_runtime_keeps_frozen_plan_slot_across_a_six_hour_boundary(tmp_path, monkeypatch):
    cfg = replace(config(tmp_path), root=tmp_path / "working", repositories=("one/repo",))
    slots = []
    def capture(cfg, job, queue):
        slots.append(job.payload["schedule_slot"])
        return {"capture_id": job.capture_id, "slug": job.slug, "repository_id": 17, "lane": job.lane,
                "mode": "full", "requested_mode": job.mode, "responses": [], "failures": [],
                "started_at": "2026-10-26T06:00:00Z", "finished_at": "2026-10-26T06:00:01Z"}
    def finalize(cfg, job, result, **options):
        info = pipeline.append_capture_manifest(cfg, result)
        return Finalization(info["manifest"], info["manifest_sha256"])
    monkeypatch.setattr(pipeline, "capture_lane", capture)
    monkeypatch.setattr(pipeline, "finalize_lane", finalize)
    monkeypatch.setattr(pipeline.time, "time", lambda: 124 * 21600 + 1)
    result = pipeline.run_persistent(cfg, once=True, stamp=False, schedule_slot=123)
    assert slots == [123, 123]
    assert result["current_observation"]["status"] == "complete"
    assert {row["schedule_slot"] for row in result["current_observation"]["lane_outcomes"]} == {123}
    assert all(row["started_at"] == "2026-10-26T06:00:00Z" for row in result["current_observation"]["lane_outcomes"])


def test_resuming_an_older_pending_slot_does_not_claim_current_slot_coverage(tmp_path, monkeypatch):
    from icsot_observer.runtime import RetryDeferred
    cfg = replace(config(tmp_path), root=tmp_path / "working", repositories=("one/repo",))
    deferred = [True]

    def capture(cfg, job, queue):
        if deferred[0] and job.lane == "api":
            raise RetryDeferred(0, "resume in a later slot")
        return {"capture_id": job.capture_id, "slug": job.slug, "repository_id": 17, "lane": job.lane,
                "mode": "full", "requested_mode": job.mode, "responses": [], "failures": [],
                "started_at": "2026-10-26T00:00:00Z", "finished_at": "2026-10-26T00:00:01Z"}

    def finalize(cfg, job, result, **options):
        info = pipeline.append_capture_manifest(cfg, result)
        return Finalization(info["manifest"], info["manifest_sha256"])

    monkeypatch.setattr(pipeline, "capture_lane", capture)
    monkeypatch.setattr(pipeline, "finalize_lane", finalize)
    pipeline.run_persistent(cfg, once=True, stamp=False, observation_key="six-hour-slot-123")
    deferred[0] = False
    later = pipeline.run_persistent(cfg, once=True, stamp=False, observation_key="six-hour-slot-124")
    assert later["current_observation"]["status"] == "partial"
    assert later["current_observation"]["missing_lanes"] == [{"slug": "one/repo", "lane": "api"}]
    assert later["resumed_older_captures"][0]["observation_key"] == "six-hour-slot-123"
    assert later["resumed_older_captures"][0]["state"] == "complete"
