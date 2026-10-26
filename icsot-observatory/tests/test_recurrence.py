import copy
import json
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer import pipeline
from icsot_observer.core import Config, canonical_json, sha256
from icsot_observer.github import APIRequestDeferred
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
                      now=options.pop("now", 100000), **options)


def test_entire_cohort_plan_selects_ready_state_and_only_bounded_explicit_cold_wave(tmp_path):
    result = plan(tmp_path, cold_bootstraps=1)
    assert len(result["repositories"]) == 3
    assert len(result["matrix"]["include"]) == 2
    assert result["counts"] == {"ready_incremental": 1, "fresh_public_bootstrap": 1, "bootstrap_pending": 1}
    ready, cold = result["matrix"]["include"]
    assert ready["allow_bootstrap"] is False and ready["expected_pointer_sha256"]
    assert cold["allow_bootstrap"] is True and cold["expected_pointer_sha256"] is None
    assert result["max_parallel"] == 8
    assert result["monthly_cap_enforced"] is False


def test_manual_and_scheduled_retries_share_slot_and_cold_attempts_rotate(tmp_path):
    first = plan(tmp_path, now=100000, cold_bootstraps=1)
    retry = plan(tmp_path, now=100001, cold_bootstraps=1)
    next_slot = plan(tmp_path, now=100000 + 21600, cold_bootstraps=1)
    assert first["matrix"] == retry["matrix"]
    assert first["matrix"]["include"][1]["slug"] != next_slot["matrix"]["include"][1]["slug"]
    assert first["matrix"]["include"][0]["observation_key"] != next_slot["matrix"]["include"][0]["observation_key"]
    assert plan(tmp_path, cold_bootstraps=0)["counts"]["bootstrap_pending"] == 2
    with pytest.raises(ValueError, match="0 through 8"):
        plan(tmp_path, cold_bootstraps=9)


def test_shared_source_rate_deferral_pauses_remaining_identity_requests(tmp_path):
    called = []

    def identity(slug):
        called.append(slug)
        raise APIRequestDeferred(200000, "shared primary quota")

    result = plan(tmp_path, identity_loader=identity)
    assert called == ["one/repo"]
    assert result["matrix"]["include"] == []
    assert result["counts"] == {"paused_identity": 3}


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
