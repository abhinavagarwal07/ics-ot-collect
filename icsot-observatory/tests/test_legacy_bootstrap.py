import copy
import base64
import errno
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer.core import Config, canonical_json, sha256, write_once
from icsot_observer.github_state import StateDeferredError
from icsot_observer.legacy_api import validate_legacy_api_seed
from icsot_observer.legacy_bootstrap import (
    GitHubMigrationLedger, MigrationError, MigrationHelpers, backlog_matrix, backlog_plan, build_migration_plan,
    commit_legacy_watermarks, initialize_repository, migration_id, validate_catalog,
)
from icsot_observer.legacy_seed_catalog import seal_legacy_seed, validate_legacy_seed
from icsot_observer.recurrence import build_plan
from icsot_observer.runtime import PersistentQueue
from test_legacy_api import Source

CODE, OWNER, OPERATIONAL = "e" * 40, "b" * 64, "a" * 64


def ref(name, raw=b"{}", number=1):
    return {"release_repository": "owner/collector", "release_tag": "original-baseline",
            "release_id": 10, "asset_id": number, "name": name, "sha256": sha256(raw), "bytes": len(raw)}


def config(root, count=3):
    return Config(root, tuple(f"owner/repo{number}" for number in range(count)), "2026-03-10", "test",
                  "NO_TEST_TOKEN", 5, 1000000, 48, 100)


def sources(count):
    return {"config_source_sha256": "1" * 64, "csv_sha256": "2" * 64, "cohort_count": count}


def catalog_for(cfg):
    rows = []
    for ordinal, slug in enumerate(cfg.repositories, 1):
        manifest = {"repository_id": ordinal, "repository_input_slug": slug, "run_id": "original",
            "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
            "status": "partial", "mode": "full", "responses": [], "git": None, "failures": ["original API gap"]}
        raw = canonical_json(manifest)
        source_manifest = {"path": f"runs/{ordinal}/original.manifest.json", "sha256": sha256(raw), "bytes": len(raw),
                           **{key: manifest[key] for key in ("run_id", "started_at", "finished_at", "status", "mode")}}
        index = {"repository": slug, "release_repository": "owner/collector", "release_tag": "original-baseline",
            "collector_code_sha": "a" * 40, "archive": {"complete": True, "encrypted": True,
                "recipient_spki_sha256": OWNER, "parts": [{"name": "original.enc", "sha256": "4" * 64, "bytes": 1000,
                    "plaintext": {"name": "original.xz", "sha256": "5" * 64, "bytes": 500}}]},
            "manifests": [{**source_manifest, "repository_id": ordinal}]}
        index_raw = canonical_json(index)
        binding = {"repository_id": ordinal, "repository": slug, "release_repository": "owner/collector",
            "release_tag": "original-baseline", "release_id": 10, "asset_name": "original.enc", "asset_id": 100 + ordinal,
            "part_number": 1, "part_count": 1, "sealed_index_sha256": sha256(index_raw),
            "ciphertext_sha256": "4" * 64, "ciphertext_bytes": 1000}
        rows.append({"slug": slug, "repository_id": ordinal, "source_index": ref("original.index.json", index_raw, ordinal),
            "source_manifest": source_manifest, "source_collector_code_sha": "a" * 40,
            "candidate_kind": "partial_baseline", "candidate_git": True, "candidate_api": True,
            "owner_recipient_spki_sha256": OWNER,
            "parts": [{"binding": binding, "capsule": ref("capsule.json", number=200 + ordinal), "transport_alias": None}],
            "fixture_manifest_raw": raw.decode(), "fixture_index_raw": index_raw.decode()})
    return {"schema_version": 1, "kind": "icsot_legacy_capsule_catalog", "inventory_sha256": "9" * 64,
            "config_source_sha256": "1" * 64, "csv_sha256": "2" * 64,
            "operational_recipient_spki_sha256": OPERATIONAL, "publication_status": "published", "repositories": rows}


class Ledger:
    def __init__(self):
        self.records, self.writes = {}, []
    def read(self, identifier, repo_id):
        return self.records.get((identifier, repo_id))
    def write(self, record):
        value = copy.deepcopy(record)
        self.records[record["migration_id"], record["repository_id"]] = value
        self.writes.append(value)
        return value


def plan_for(cfg, catalog=None, pointer_loader=lambda repo_id: None):
    catalog = catalog or catalog_for(cfg)
    return build_migration_plan(cfg, sources=sources(len(cfg.repositories)), catalog=catalog,
        catalog_sha256=sha256(canonical_json(catalog)), code_sha=CODE, pointer_loader=pointer_loader)


def test_all_185_sources_are_planned_without_a_cold_wave_gate(tmp_path):
    cfg = config(tmp_path, 185)
    catalog = catalog_for(cfg)
    for row in catalog["repositories"][:167]:
        row["candidate_kind"] = "accepted_baseline"
    plan = plan_for(cfg, catalog)
    assert len(plan["repositories"]) == len(plan["matrix"]["include"]) == 185
    assert plan["max_parallel"] == 8 and plan["cold_bootstrap_throttle"] is None
    assert all(row["disposition"] == "queued" for row in plan["repositories"])
    assert all(set(row) == {"slug", "repository_id"} for row in plan["matrix"]["include"])


@pytest.mark.parametrize("field", ["config_source_sha256", "csv_sha256"])
def test_source_hash_mismatch_fails_before_any_pointer_read(tmp_path, field):
    cfg = config(tmp_path)
    catalog = catalog_for(cfg)
    catalog[field] = "0" * 64
    with pytest.raises(MigrationError, match="configuration/CSV"):
        plan_for(cfg, catalog, pointer_loader=lambda repo_id: pytest.fail("Pointer read before source hash binding"))


def test_current_operational_state_skips_even_if_preparation_snapshot_is_old(tmp_path):
    cfg = config(tmp_path)
    catalog = catalog_for(cfg)
    catalog["repositories"][0].update(parts=[], ready_state_pointer_sha256="0" * 64)
    pointer = canonical_json({"repository_id": 1, "slug": cfg.repositories[0], "generation": "newer"})
    plan = plan_for(cfg, catalog, pointer_loader=lambda repo_id: pointer if repo_id == 1 else None)
    assert plan["repositories"][0]["disposition"] == "state_published"
    assert plan["repositories"][0]["expected_state_pointer_sha256"] == sha256(pointer)
    assert len(plan["matrix"]["include"]) == 2
    assert plan_for(cfg, catalog)["repositories"][0]["disposition"] == "source_repair_pending"


def test_unpublished_capsules_cannot_enter_hosted_migration_matrix(tmp_path):
    cfg = config(tmp_path)
    catalog = catalog_for(cfg)
    catalog["repositories"][0]["parts"][0]["capsule"].update(asset_id=None, release_id=None)
    assert validate_catalog(catalog, cfg.repositories, allow_unpublished=True)
    with pytest.raises(MigrationError, match="published"):
        plan_for(cfg, catalog)


def test_zero_part_draft_cannot_be_activated_even_if_current_states_exist(tmp_path):
    cfg = config(tmp_path)
    catalog = catalog_for(cfg)
    catalog["publication_status"] = "unpublished"
    for row in catalog["repositories"]:
        row["parts"] = []
    with pytest.raises(MigrationError, match="unpublished"):
        plan_for(cfg, catalog, pointer_loader=lambda repo_id: canonical_json({
            "repository_id": repo_id, "slug": cfg.repositories[repo_id - 1]}))


def test_migration_id_survives_capsule_publication_but_not_source_change(tmp_path):
    catalog = catalog_for(config(tmp_path))
    original = migration_id(catalog)
    catalog["repositories"][0]["parts"][0]["capsule"].update(asset_id=9999, release_id=8888, release_tag="published-capsules")
    assert migration_id(catalog) == original
    catalog["repositories"][0]["parts"][0]["capsule"]["sha256"] = "0" * 64
    assert migration_id(catalog) != original


def test_unbound_repair_row_is_retained_but_never_guessed_or_selected(tmp_path):
    cfg = config(tmp_path)
    catalog = catalog_for(cfg)
    catalog["repositories"][0].update(repository_id=None, candidate_kind="repair_required", source_manifest=None, parts=[])
    plan = plan_for(cfg, catalog)
    assert len(plan["repositories"]) == 3 and len(plan["matrix"]["include"]) == 2
    assert plan["repositories"][0]["reason_codes"] == ["original_repository_identity_unproven"]


def test_backlog_keeps_every_unfinished_source_and_does_not_reapply_cold_two(tmp_path):
    cfg = config(tmp_path, 20)
    plan, ledger = plan_for(cfg), Ledger()
    ledger.write({"migration_id": plan["migration_id"], "repository_id": 2, "disposition": "deferred"})
    ledger.write({"migration_id": plan["migration_id"], "repository_id": 3, "disposition": "source_repair_pending"})
    pointer = canonical_json({"repository_id": 1, "slug": cfg.repositories[0]})
    matrix = backlog_matrix(plan, pointer_loader=lambda repo_id: pointer if repo_id == 1 else None, ledger=ledger)
    assert {row["repository_id"] for row in matrix["include"]} == set(range(2, 21)) - {3}


def test_backlog_holds_survive_repeated_planning_and_current_pointers_win(tmp_path):
    cfg = config(tmp_path, 185)
    plan, ledger = plan_for(cfg), Ledger()
    holds = {
        1: {"external_recovery_required": True, "reason_code": "prepared_state_unavailable_after_runner_loss"},
        2: {"prepared_generation": "a" * 32},
        3: {"fresh_capture_attempt_started": True},
        4: {"disposition": "source_repair_pending", "reason_code": "LegacySeedError"},
        5: {"disposition": "state_published"},
        6: {"fresh_capture_publication_started": True},
    }
    for repo_id, fields in holds.items():
        ledger.write({"migration_id": plan["migration_id"], "repository_id": repo_id,
                      "disposition": "deferred", **fields})
    plan["repositories"][6]["disposition"] = "source_repair_pending"
    before = copy.deepcopy(ledger.records)
    def pointers(repo_id):
        return canonical_json({"repository_id": repo_id, "slug": cfg.repositories[repo_id - 1]}) if repo_id in (3, 7) else None
    first = backlog_plan(plan, pointer_loader=pointers, ledger=ledger)
    second = backlog_plan(plan, pointer_loader=pointers, ledger=ledger)
    assert first == second and ledger.records == before and len(ledger.writes) == len(holds)
    assert first["cohort_count"] == len(first["repositories"]) == 185
    assert first["counts"] == {"blocked": 5, "already_operational": 2, "eligible": 178}
    assert first["blocked_count"] == 5 and first["migration_complete"] is False
    assert first["blocked_reason_counts"]["authoritative_state_missing"] == 1
    assert first["blocked_reason_counts"]["LegacySeedError"] == 1
    assert {row["repository_id"] for row in first["matrix"]["include"]} == set(range(8, 186))


def test_all_blocked_targets_are_reported_as_incomplete_with_no_jobs(tmp_path):
    cfg = config(tmp_path, 3)
    plan, ledger = plan_for(cfg), Ledger()
    for repo_id in range(1, 4):
        ledger.write({"migration_id": plan["migration_id"], "repository_id": repo_id,
                      "disposition": "deferred", "prepared_generation": "a" * 32})
    result = backlog_plan(plan, pointer_loader=lambda _: None, ledger=ledger)
    assert result["status"] == "blocked" and result["migration_complete"] is False
    assert result["matrix"] == {"include": []} and result["blocked_count"] == 3
    assert result["blocked_reason_counts"] == {"prepared_generation_requires_reviewed_recovery": 3}


def test_ledger_batch_freezes_one_head_while_later_head_changes():
    class MovingTransport:
        repository = "owner/collector"
        def __init__(self):
            self.calls, self.head_reads = [], 0
        def _api(self, endpoint, **options):
            self.calls.append(endpoint)
            if "/git/ref/" in endpoint:
                self.head_reads += 1
                return {"object": {"sha": str(self.head_reads) * 40}}
            repo_id = int(endpoint.split("/repos/")[-1].split(".json")[0])
            raw = canonical_json({"repository_id": repo_id, "snapshot": endpoint.split("?ref=")[1]})
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(raw).decode()}
    transport = MovingTransport()
    ledger = GitHubMigrationLedger(transport)
    records = ledger.read_many("a" * 64, range(1, 186))
    assert len(records) == 185 and transport.head_reads == 1
    assert {row["snapshot"] for row in records.values()} == {"1" * 40}
    assert ledger.read("a" * 64, 1)["snapshot"] == "2" * 40


def test_backlog_reads_only_missing_pointer_dispositions_in_one_batch(tmp_path):
    cfg = config(tmp_path, 185)
    plan = plan_for(cfg)
    class BatchLedger:
        def __init__(self):
            self.batches = []
        def read(self, *args):
            pytest.fail("Planner performed a per-row mutable-head ledger read")
        def read_many(self, identifier, repo_ids):
            self.batches.append((identifier, tuple(repo_ids)))
            return {repo_id: {"disposition": "deferred", "external_recovery_required": True} for repo_id in repo_ids}
    ledger = BatchLedger()
    def pointers(repo_id):
        return canonical_json({"repository_id": repo_id, "slug": cfg.repositories[repo_id - 1]}) if repo_id <= 174 else None
    result = backlog_plan(plan, pointer_loader=pointers, ledger=ledger)
    assert ledger.batches == [(plan["migration_id"], tuple(range(175, 186)))]
    assert result["counts"] == {"already_operational": 174, "blocked": 11}
    assert result["status"] == "blocked" and result["migration_complete"] is False


def test_seed_error_reports_exact_inner_predicate_without_exception_text():
    from icsot_observer.legacy_bootstrap import safe_error_location
    from icsot_observer.legacy_seed_catalog import LegacySeedError, _asset
    with pytest.raises(LegacySeedError) as caught:
        _asset({"name": "proof", "bytes": 1, "sha256": "PRIVATE_ARBITRARY_TEXT"})
    location = safe_error_location(caught.value)
    assert location["module"] == "legacy_seed_catalog.py" and location["function"] == "_hash"
    assert type(location["line"]) is int and location["line"] > 0
    assert set(location) == {"module", "function", "line"}
    assert "PRIVATE_ARBITRARY_TEXT" not in canonical_json(location).decode()


@pytest.mark.parametrize("strategy", ["legacy_seed", "fresh_repair"])
def test_cli_shares_bounded_destination_transport_and_counts_ledger_requests(tmp_path, monkeypatch, strategy):
    from icsot_observer import legacy_bootstrap
    from icsot_observer.recurrence import BoundedStateTransport
    cfg = config(tmp_path / "working", 1)
    plan = plan_for(cfg)
    entry = plan["repositories"][0]
    entry.update(strategy=strategy, **{("repair_resource_limits" if strategy == "fresh_repair" else "resource_limits"):
                                     {"max_new_evidence_ciphertext_bytes": 123456}})
    plan_raw = canonical_json(plan)
    plan_path, outcome = tmp_path / "plan.json", tmp_path / "outcome.json"
    plan_path.write_bytes(plan_raw)
    commands, transports = [], []
    source_reader = object()
    def runner(command, **options):
        commands.append(command)
        endpoint = command[2]
        if "/git/ref/" in endpoint:
            return SimpleNamespace(returncode=0, stdout=canonical_json({"object": {"sha": "a" * 40}}), stderr=b"")
        if "/contents/" in endpoint:
            return SimpleNamespace(returncode=1, stdout=b"HTTP/2 404 Not Found\r\n\r\n{}", stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")
    def transport_factory(repository, **options):
        value = BoundedStateTransport(repository, runner=runner, **options)
        transports.append(value)
        return value
    def initialize(*args, **options):
        destination = options["transport"]
        assert options["ledger"].transport is destination
        assert options["reader"] is source_reader
        assert destination.upload_limits == {"evidence": 123456, "state": 8 * 1024 ** 3}
        assert options["ledger"].read(plan["migration_id"], 1) is None
        destination._api("repos/owner/collector/releases")
        return {"disposition": "deferred", "reason_code": "explicit_mocked_destination_failure"}
    monkeypatch.setattr(legacy_bootstrap, "load_cohort", lambda *args: (cfg, sources(1)))
    monkeypatch.setattr(legacy_bootstrap.subprocess, "check_output", lambda *args, **options: CODE)
    monkeypatch.setattr(legacy_bootstrap, "BoundedStateTransport", transport_factory)
    monkeypatch.setattr(legacy_bootstrap, "GitHubSourceReader", lambda: source_reader)
    monkeypatch.setattr(legacy_bootstrap, "initialize_repository", initialize)
    result = legacy_bootstrap.main(["run", "--config", str(tmp_path / "config"), "--csv", str(tmp_path / "csv"),
        "--destination-repository", "owner/collector", "--output", str(outcome), "--plan", str(plan_path),
        "--plan-sha256", sha256(plan_raw), "--slug", cfg.repositories[0], "--code-sha", CODE,
        "--state-private-key", str(tmp_path / "unused-private"), "--state-public-key", str(tmp_path / "unused-public"),
        "--evidence-public-key", str(tmp_path / "unused-evidence")])
    value = json.loads(outcome.read_bytes())
    assert result == 75 and len(transports) == 1 and len(commands) == 3
    assert value["destination_github_api_requests_total"] == value["destination_github_rest_api_requests_total"] == 3
    assert value["destination_github_graphql_api_requests_total"] == 0
    assert value["destination_accounting_scope"] == "this_process_shared_destination_transport_only"


def test_manual_initializer_queues_with_recurring_collection_under_shared_worker_limit():
    root = Path(__file__).resolve().parents[2]
    initializer = (root / ".github/workflows/baseline-state-initialize.yml").read_text()
    recurring = (root / ".github/workflows/corpus-incremental.yml").read_text()
    pilot = (root / ".github/workflows/persistent-selected.yml").read_text()
    tier = (root / ".github/workflows/corpus-priority-tier.yml").read_text()
    assert "  schedule:" not in initializer and "  workflow_dispatch:" in initializer
    assert "  schedule:" not in recurring and "  workflow_dispatch:" in recurring
    for workflow in (initializer, recurring, pilot):
        concurrency = workflow.split("\nconcurrency:\n", 1)[1].split("\ndefaults:\n", 1)[0]
        assert "  group: persistent-collection\n" in concurrency
        assert "  cancel-in-progress: false\n" in concurrency and "  queue: max\n" in concurrency
    for workflow in (initializer, tier):
        assert "      max-parallel: 8\n" in workflow
    assert "${{ steps.plan.outputs.blocked_count }}" in initializer
    assert "${{ steps.plan.outputs.planning_status }}" in initializer


def test_planner_cli_reports_blocked_cohort_without_false_completion(tmp_path, monkeypatch, capsys):
    from icsot_observer import legacy_bootstrap
    cfg = config(tmp_path / "working", 185)
    plan = plan_for(cfg)
    raw = canonical_json(plan)
    destination = SimpleNamespace(request_count=0, graphql_request_count=0)
    class HeldLedger:
        def __init__(self, transport):
            assert transport is destination
        def active_plan(self):
            destination.request_count += 1
            return {"plan": ref("plan.json", raw)}
        def read_many(self, identifier, repo_ids):
            destination.request_count += len(repo_ids) + 1
            return {repo_id: {"disposition": "deferred", "prepared_generation": "a" * 32} for repo_id in repo_ids}
        def write(self, *args):
            pytest.fail("Planning rewrote an unchanged recovery hold")
    class Reader:
        def metadata(self, reference):
            assert reference["sha256"] == sha256(raw)
            return raw
    plan_path, outputs, summary = tmp_path / "migration.json", tmp_path / "outputs", tmp_path / "summary"
    monkeypatch.setattr(legacy_bootstrap, "load_cohort", lambda *args: (cfg, sources(185)))
    monkeypatch.setattr(legacy_bootstrap.subprocess, "check_output", lambda *args, **options: CODE)
    monkeypatch.setattr(legacy_bootstrap, "BoundedStateTransport", lambda *args, **options: destination)
    monkeypatch.setattr(legacy_bootstrap, "GitHubMigrationLedger", HeldLedger)
    monkeypatch.setattr(legacy_bootstrap, "GitHubSourceReader", Reader)
    monkeypatch.setattr(legacy_bootstrap, "operational_pointer_loader", lambda transport: lambda _: None)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert legacy_bootstrap.main(["plan", "--config", str(tmp_path / "config"), "--csv", str(tmp_path / "csv"),
        "--destination-repository", "owner/collector", "--code-sha", CODE,
        "--output", str(plan_path), "--github-output", str(outputs)]) == 0
    public = json.loads(capsys.readouterr().out)
    assert public["status"] == "blocked" and public["migration_complete"] is False
    assert public["selected"] == 0 and public["blocked_count"] == public["cohort_count"] == 185
    assert "planned_count=0\n" in outputs.read_text() and "blocked_count=185\n" in outputs.read_text()
    assert "planning_status=blocked\n" in outputs.read_text() and '"migration_complete": false' in summary.read_text()
    assert len(json.loads(plan_path.with_suffix(".backlog.json").read_bytes())["repositories"]) == 185


@pytest.mark.parametrize("truncated", [None, "root", "repos"])
def test_pointer_inventory_uses_only_frozen_nonrecursive_repos_subtree(truncated):
    from icsot_observer.legacy_bootstrap import operational_pointer_loader
    class Transport:
        repository = "owner/collector"
        def __init__(self):
            self.calls, self.pointer_reads = [], []
        def branch_head(self):
            return "a" * 40
        def _api(self, endpoint):
            self.calls.append(endpoint)
            assert "recursive" not in endpoint
            if endpoint.endswith("a" * 40):
                return {"truncated": truncated == "root", "tree": [
                    {"path": "proof-outbox", "type": "tree", "sha": "c" * 40},
                    {"path": "repos", "type": "tree", "sha": "b" * 40}]}
            assert endpoint.endswith("b" * 40)
            return {"truncated": truncated == "repos", "tree": [{"path": "1.json", "type": "blob"}]}
        def read_pointer(self, head, repo_id):
            self.pointer_reads.append((head, repo_id))
            return b"frozen-pointer"
    transport = Transport()
    if truncated:
        with pytest.raises(MigrationError, match="incomplete"):
            operational_pointer_loader(transport)
        assert transport.pointer_reads == []
    else:
        loader = operational_pointer_loader(transport)
        assert loader(1) == b"frozen-pointer" and loader(2) is None
        assert transport.pointer_reads == [("a" * 40, 1)]
    assert len(transport.calls) == (1 if truncated == "root" else 2)


def test_active_migration_suppresses_fresh_recollection_but_keeps_ready_targets(tmp_path):
    cfg = config(tmp_path)
    pointer = canonical_json({"repository_id": 1, "slug": cfg.repositories[0], "generation": "a" * 32})
    plan = build_plan(cfg, sources=sources(3), code_sha=CODE,
        identity_loader=lambda slug: {"id": cfg.repositories.index(slug) + 1, "private": False, "size": 10},
        pointer_loader=lambda repo_id: pointer if repo_id == 1 else None, migration_pending_slugs=set(cfg.repositories),
        cold_bootstraps=8, now=100000)
    assert plan["counts"] == {"ready_incremental": 1, "migration_pending": 2}
    assert [row["slug"] for row in plan["matrix"]["include"]] == [cfg.repositories[0]]


@pytest.fixture
def engine(tmp_path, monkeypatch):
    cfg = config(tmp_path / "working", 1)
    plan, ledger, events, now = plan_for(cfg), Ledger(), [], [1000.0]
    entry = plan["repositories"][0]
    class Reader:
        def metadata(self, reference, **options):
            events.append("metadata:" + reference["name"])
            return entry["fixture_index_raw"].encode() if reference["name"] == "original.index.json" else b"{}"
    class Transport:
        def publication_budget(self, requests):
            events.append("quota_preflight")
            return {"requested": requests}
    class Backend:
        recipient = OPERATIONAL
        selection = SimpleNamespace(pointer=None, index=None)
        deferred = False
        def read(self):
            return self.selection
        def prepare(self, selection, **options):
            events.append("prepare")
            assert PersistentQueue(cfg.root).jobs() == []
            assert ledger.writes[-1]["disposition"] == "seed_verified"
            self.prepared = SimpleNamespace(generation=options["generation"], manifest_sha256="7" * 64,
                release_tags=("state-generation",), pointer={"generation": options["generation"]}, assets=())
            return self.prepared
        def publish_prepared(self, prepared, **options):
            events.append("publish")
            assert prepared is self.prepared
            assert ledger.writes[-1]["prepared_manifest_sha256"] == "7" * 64
            if self.deferred:
                self.deferred = False
                raise StateDeferredError("quota", retry_not_before=now[0] + 120, reason="rate_limit")
            return {"generation": prepared.generation, "pointer_commit": "8" * 40,
                    "state_uploaded_ciphertext_bytes": 100, "state_referenced_ciphertext_bytes": 120}
    backend = Backend()
    transport, reader = Transport(), Reader()
    def archive_import(raw, refs, **options):
        events.append("archive_import")
        evidence = options["output_root"] / "evidence"
        path = evidence / entry["source_manifest"]["path"]
        write_once(path, entry["fixture_manifest_raw"].encode())
        item = {"path": "evidence/" + entry["source_manifest"]["path"], "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
        return SimpleNamespace(evidence_root=evidence, manifest=json.loads(path.read_bytes()), files=[item], cas={},
                               parts=[{"authentication": "synthetic_verified_fixture"}])
    def git_import(root, manifest_raw, index_raw, **options):
        events.append("git_verify")
        from icsot_observer.core import ObjectStore
        descriptor_sha = ObjectStore(root).put(canonical_json({"synthetic_descriptor": True}))
        return {"imported": True, "source_history_profile": "full_history", "descriptor_sha256": descriptor_sha}
    def api_validate(*args, **options):
        events.append("api_verify")
        return {"proof_sha256": "6" * 64, "eligible_watermarks": {}, "scope_decisions": {"issues": {"status": "fresh_repair"}}}
    helpers = MigrationHelpers(archive_import, git_import, api_validate, seal_legacy_seed, validate_legacy_seed)
    monkeypatch.setattr("icsot_observer.encryption.public_key_fingerprint", lambda path: OWNER)
    def run(**options):
        return initialize_repository(plan, cfg.repositories[0], code_sha=CODE, config=cfg,
            destination_repository="owner/collector", operational_private_key_path=tmp_path / "unused-private",
            state_public_key_path=tmp_path / "unused-public", evidence_public_key_path=tmp_path / "unused-evidence-public",
            working_root=cfg.root, scratch=tmp_path / "scratch", transport=options.pop("transport", transport), reader=reader, ledger=ledger,
            helpers=helpers, backend=backend, clock=lambda: now[0], sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds), **options)
    return SimpleNamespace(run=run, plan=plan, config=cfg, entry=entry, backend=backend, ledger=ledger,
                           helpers=helpers, events=events, now=now, transport=transport, reader=reader)


def test_import_preserves_original_times_fresh_queue_and_prepared_publication_order(engine):
    result = engine.run()
    assert result["disposition"] == "state_published", {
        key: result.get(key) for key in ("disposition", "reason_code", "error_location")}
    assert result["new_observations"] == result["fresh_queue_jobs"] == 0
    assert result["original_source_status"] == "partial"
    assert result["existing_main_ciphertext_bytes"] == 1000 and result["state_uploaded_ciphertext_bytes"] == 100
    assert result["combined_referenced_main_and_state_bytes"] == 1120
    assert engine.events.index("quota_preflight") < engine.events.index("archive_import") < engine.events.index("prepare")
    assert PersistentQueue(engine.config.root).jobs() == []
    assert (engine.config.root / engine.entry["source_manifest"]["path"]).read_bytes() == engine.entry["fixture_manifest_raw"].encode()
    receipt = json.loads(next((engine.config.root / "imports/legacy-bootstrap").glob("*.json")).read_bytes())
    assert receipt["source_observation_interval"] == {"started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z"}


def test_quota_reset_retries_the_identical_prepared_object_without_reimport(engine):
    engine.backend.deferred = True
    result = engine.run()
    assert result["disposition"] == "state_published", result
    assert engine.events.count("archive_import") == engine.events.count("prepare") == 1
    assert engine.events.count("publish") == 2 and engine.now[0] == 1120
    deferred = [record for record in engine.ledger.writes if record["disposition"] == "deferred"]
    assert deferred[0]["prepared_generation"] == result["prepared_generation"]
    assert deferred[0]["prepared_manifest_sha256"] == result["prepared_manifest_sha256"]


def test_legacy_quota_retry_keeps_prepared_bytes_when_retry_telemetry_is_also_refused(engine):
    engine.backend.deferred = True
    original_write = engine.ledger.write
    def refused(value):
        if value["disposition"] == "deferred":
            raise StateDeferredError("shared quota also refuses optional telemetry", retry_not_before=1120.)
        return original_write(value)
    engine.ledger.write = refused
    result = engine.run()
    assert result["disposition"] == "state_published", result
    assert engine.events.count("archive_import") == engine.events.count("prepare") == 1
    assert engine.events.count("publish") == 2 and engine.now[0] == 1120.


def test_lost_prepared_bytes_are_held_without_new_uuid_reencryption_or_transfer(engine):
    engine.ledger.write({"migration_id": engine.plan["migration_id"], "repository_id": 1,
                         "disposition": "deferred", "prepared_generation": "9" * 32, "prepared_manifest_sha256": "8" * 64})
    result = engine.run()
    assert result["disposition"] == "deferred" and result["external_recovery_required"]
    assert result["reason_code"] == "prepared_state_unavailable_after_runner_loss"


def test_unchanged_external_hold_is_not_rewritten_or_reimported(engine):
    held = {"migration_id": engine.plan["migration_id"], "repository_id": 1, "disposition": "deferred",
            "external_recovery_required": True, "reason_code": "reviewed_recovery_required", "created_at": "original"}
    engine.ledger.write(held)
    assert engine.run() == held and engine.run() == held
    assert engine.ledger.writes == [held]
    assert "archive_import" not in engine.events and "prepare" not in engine.events
    assert not engine.events


def test_existing_operational_pointer_wins_without_any_legacy_source_transfer(engine):
    engine.backend.selection = SimpleNamespace(pointer={"generation": "existing"}, index={})
    result = engine.run()
    assert result["disposition"] == "state_published" and result["reason_code"] == "already_operational"
    assert not engine.events


def test_no_independently_proven_capability_is_explicit_repair_not_a_seed(engine):
    def fail_git(*args, **options):
        raise ValueError("synthetic invalid portable closure")
    engine.helpers.git_import = fail_git
    result = engine.run()
    assert result["disposition"] == "source_repair_pending"
    assert result["reason_code"] == "no_independently_proven_seed_capability"
    assert "prepare" not in engine.events and "publish" not in engine.events


def test_quota_admission_refuses_before_source_transfer(engine, monkeypatch):
    def quota_refusal(count):
        raise StateDeferredError("shared quota reserve", reason="quota_headroom", retry_not_before=1500)
    monkeypatch.setattr(engine.transport, "publication_budget", quota_refusal)
    result = engine.run()
    assert result["disposition"] == "deferred" and result["reason_code"] == "quota_headroom"
    assert not any(event.startswith("metadata:") for event in engine.events)
    assert "archive_import" not in engine.events


@pytest.mark.parametrize("phase", ["ledger_read", "state_read", "ledger_write", "publication_budget"])
def test_startup_destination_quota_waits_before_source_work_without_replaying_import(engine, phase):
    target, name = {"ledger_read": (engine.ledger, "read"), "state_read": (engine.backend, "read"),
                    "ledger_write": (engine.ledger, "write"), "publication_budget": (engine.transport, "publication_budget")}[phase]
    original, calls, first_inputs = getattr(target, name), [], []
    def quota_once(*args, **kwargs):
        calls.append(engine.now[0])
        if len(calls) <= 2:
            first_inputs.append(args)
        if len(calls) == 1:
            raise StateDeferredError("destination quota", reason="rate_limit", retry_not_before=1120.)
        return original(*args, **kwargs)
    setattr(target, name, quota_once)
    result = engine.run()
    assert result["disposition"] == "state_published", result
    assert calls[:2] == [1000., 1120.] and engine.now[0] == 1120.
    assert engine.events.count("archive_import") == engine.events.count("prepare") == engine.events.count("publish") == 1
    if phase == "ledger_write":
        assert first_inputs[0][0] is first_inputs[1][0]  # SAME frozen record across reset.


def test_startup_wait_never_crosses_the_existing_job_deadline(engine):
    def quota(*args, **kwargs):
        raise StateDeferredError("later reset", reason="rate_limit", retry_not_before=1120.)
    engine.backend.read = quota
    result = engine.run(max_runtime_seconds=60)
    assert result["disposition"] == "deferred" and engine.now[0] == 1000.
    assert not engine.events


def test_unknown_prior_during_quota_never_overwrites_a_held_prepared_generation(engine):
    key = (engine.plan["migration_id"], engine.entry["repository_id"])
    held = {"migration_id": key[0], "repository_id": key[1], "disposition": "deferred",
            "prepared_generation": "9" * 32, "prepared_manifest_sha256": "8" * 64,
            "prepared_pointer": {"generation": "9" * 32},
            "prepared_assets": [{"release_tag": "held-state", "name": "part-0001.enc", "ciphertext_sha256": "7" * 64}],
            "prepared_local_only": True}
    engine.ledger.records[key] = copy.deepcopy(held)
    original_bytes = canonical_json(engine.ledger.records[key])
    reads = []
    def unreadable(*args, **kwargs):
        reads.append(engine.now[0])
        raise StateDeferredError("shared destination quota", reason="rate_limit", retry_not_before=engine.now[0] + 10)
    engine.ledger.read = unreadable
    result = engine.run()
    assert result["disposition"] == "deferred"
    assert result["disposition_recording"] == "not_attempted_prior_unknown"
    assert len(reads) == 6 and engine.ledger.writes == []
    assert canonical_json(engine.ledger.records[key]) == original_bytes
    assert engine.events == [] and result["new_observations"] == result["new_evidence_upload_bytes"] == 0


@pytest.mark.parametrize("changed_pointer", [False, True])
def test_shared_ledger_exhaustion_retries_only_when_own_pointer_is_unchanged(engine, changed_pointer):
    from icsot_observer.github_state import StateConflictError
    original, writes = engine.ledger.write, []
    def collide(value):
        writes.append(value)
        if len(writes) == 1:
            if changed_pointer:
                engine.backend.selection = SimpleNamespace(pointer={"generation": "newer"})
            raise StateConflictError("Migration disposition changed concurrently")
        return original(value)
    engine.ledger.write = collide
    result = engine.run()
    if changed_pointer:
        assert result["reason_code"] == "StateConflictError" and engine.now[0] == 1000.
        assert "archive_import" not in engine.events and "publish" not in engine.events
    else:
        assert result["disposition"] == "state_published" and engine.now[0] == 1002.
        assert writes[0] is writes[1] and engine.events.count("archive_import") == 1


def test_shared_state_branch_exhaustion_keeps_the_same_prepared_snapshot(engine):
    from icsot_observer.github_state import StateConflictError
    original, calls = engine.backend.publish_prepared, []
    def collide(prepared, **options):
        calls.append(prepared)
        if len(calls) == 1:
            raise StateConflictError("Too many concurrent state branch updates")
        return original(prepared, **options)
    engine.backend.publish_prepared = collide
    result = engine.run()
    assert result["disposition"] == "state_published" and engine.now[0] == 1002.
    assert len(calls) == 2 and calls[0] is calls[1]
    assert engine.events.count("prepare") == engine.events.count("archive_import") == 1


def test_migration_state_copy_cap_is_eight_gib_without_changing_evidence_guard(engine, monkeypatch):
    from icsot_observer import legacy_bootstrap
    limits = {}
    def transport(repository, **options):
        limits.update(options)
        return engine.transport
    monkeypatch.setattr(legacy_bootstrap, "BoundedStateTransport", transport)
    result = engine.run(transport=None)
    assert result["disposition"] == "state_published"
    assert limits == {"evidence_bytes": 2 * 1024 ** 3, "state_bytes": 8 * 1024 ** 3}
    assert result["migration_state_ciphertext_cap_bytes"] == 8 * 1024 ** 3


def test_host_resource_limit_pauses_without_reclassifying_original_source(engine):
    from icsot_observer.archive_reader import ArchiveError
    def cap(*args, **options):
        raise ArchiveError("Restored payload exceeds the restore byte cap")
    engine.helpers.archive_import = cap
    result = engine.run()
    assert result["disposition"] == "deferred" and result["resource_review_required"]
    assert result["reason_code"] == "archive_host_resource_limit" and result["original_source_status"] == "partial"
    assert "prepare" not in engine.events


@pytest.mark.parametrize("number", [errno.ENOSPC, errno.EDQUOT])
def test_actual_disk_exhaustion_is_deferred_without_reclassifying_source(engine, number):
    def disk_full(*args, **options):
        raise OSError(number, "synthetic disk exhaustion")
    engine.helpers.archive_import = disk_full
    result = engine.run()
    assert result["disposition"] == "deferred" and result["reason_code"] == "host_disk_exhausted"
    assert result["original_source_status"] == "partial"


def test_public_failure_location_contains_only_reviewed_source_coordinates(engine):
    from icsot_observer.archive_reader import ArchiveError
    sentinel = "UNTRUSTED_BODY_EXCEPTION_MESSAGE_SENTINEL"
    def failure(*args, **options):
        raise ArchiveError(sentinel)
    engine.helpers.archive_import = failure
    result = engine.run()
    assert result["reason_code"] == "ArchiveError"
    location = result["error_location"]
    assert set(location) == {"module", "function", "line"}
    assert location["module"] == "legacy_bootstrap.py" and location["function"] == "import_legacy_seed"
    assert type(location["line"]) is int
    assert sentinel not in json.dumps(engine.ledger.writes)


@pytest.mark.parametrize("max_elapsed,inactivity", [(0.05, 10), (10, 0.05)])
def test_source_transfer_deadlines_terminate_blocked_child_process_group(max_elapsed, inactivity):
    from icsot_observer.legacy_bootstrap import GitHubSourceReader
    children = []
    def spawn(*args, **options):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], **options)
        children.append(child)
        return child
    reader = GitHubSourceReader(inactivity_seconds=inactivity, max_elapsed_seconds=max_elapsed, popen=spawn)
    with pytest.raises(StateDeferredError, match="timed out") as error:
        reader.metadata(ref("blocked.json"))
    assert error.value.reason == "source_read_deadline"
    assert len(children) == 1 and children[0].poll() is not None


def test_bounded_source_reader_handles_short_reads_and_verifies_exact_metadata():
    from icsot_observer.legacy_bootstrap import GitHubSourceReader
    def spawn(*args, **options):
        return subprocess.Popen([sys.executable, "-c", "import os,time; os.write(1,b'{'); time.sleep(.02); os.write(1,b'}')"], **options)
    assert GitHubSourceReader(popen=spawn).metadata(ref("split.json")) == b"{}"


def fresh_catalog(cfg):
    from icsot_observer.legacy_bootstrap import FRESH_REPAIR_IDENTITIES, REPAIR_INVENTORY_SHA256
    catalog = catalog_for(config(cfg.root, len(cfg.repositories)))
    catalog["inventory_sha256"] = REPAIR_INVENTORY_SHA256
    for row, slug in zip(catalog["repositories"], cfg.repositories):
        row.update(slug=slug, repository_id=None, source_manifest=None, parts=[], candidate_kind="repair_required",
                   candidate_git=False, candidate_api=False, requested_strategy="fresh_repair",
                   fresh_repair_repository_id=FRESH_REPAIR_IDENTITIES[slug])
    return catalog


def test_only_explicit_frozen_three_unusable_sources_get_fresh_collection_strategy(tmp_path):
    from icsot_observer.legacy_bootstrap import FRESH_REPAIR_IDENTITIES
    cfg = replace(config(tmp_path), repositories=tuple(FRESH_REPAIR_IDENTITIES))
    catalog = fresh_catalog(cfg)
    plan = plan_for(cfg, catalog)
    assert len(plan["matrix"]["include"]) == 3
    assert {row["strategy"] for row in plan["repositories"]} == {"fresh_repair"}
    assert [row["repository_id"] for row in plan["repositories"]] == list(FRESH_REPAIR_IDENTITIES.values())
    assert {row["original_repository_id"] for row in plan["repositories"]} == {None}
    changed = copy.deepcopy(catalog)
    changed["repositories"][0]["requested_strategy"] = "legacy_seed"
    assert migration_id(changed) != migration_id(catalog)
    catalog["inventory_sha256"] = "0" * 64
    with pytest.raises(MigrationError, match="closed authorization"):
        plan_for(cfg, catalog)


def test_current_public_identity_is_checked_before_frozen_fresh_repair(tmp_path):
    cfg = replace(config(tmp_path, 1), repositories=("nodejs/node",))
    with pytest.raises(MigrationError, match="Current public identity"):
        build_migration_plan(cfg, sources=sources(1), catalog=fresh_catalog(cfg), catalog_sha256="1" * 64,
            code_sha=CODE, pointer_loader=lambda _: None,
            repair_identity_loader=lambda _: {"id": 999, "private": False})


@pytest.mark.parametrize("defer_phase", ["prepared_state", "uncertain_evidence_upload", "prepare_preflight", "retry_telemetry"])
def test_fresh_repair_collects_once_and_reuses_main_and_prepared_bytes_across_quota_reset(
        tmp_path, monkeypatch, defer_phase):
    from icsot_observer import pipeline
    from icsot_observer.core import ObjectStore
    from icsot_observer.github_state import GitHubStateStore
    from test_github_runner_integration import MemoryGitHub, keys
    cfg = replace(config(tmp_path / "working", 1), repositories=("nodejs/node",))
    plan = plan_for(cfg, fresh_catalog(cfg))
    plan["code_sha"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    state_public, state_private = keys(tmp_path, "repair-state")
    evidence_public, _ = keys(tmp_path, "repair-evidence")
    ledger, now, captures, prepared, publication_objects = Ledger(), [1000.], [], [], []
    if defer_phase == "retry_telemetry":
        original_write = ledger.write
        def quota_refused_telemetry(value):
            if value["disposition"] == "deferred" and now[0] < 1120.:
                raise StateDeferredError("telemetry quota too", retry_not_before=1120.)
            return original_write(value)
        ledger.write = quota_refused_telemetry
    class Destination(MemoryGitHub):
        deferred = False
        def find_asset(self, tag, name, *, refresh=False):
            raw = self.assets.get((tag, name))
            return None if raw is None else {"name": name, "size": len(raw), "digest": "sha256:" + sha256(raw)}
        def upload_asset(self, tag, name, source):
            is_state = tag.startswith("collector-state-")
            if not self.deferred and defer_phase in ("prepared_state", "retry_telemetry") and is_state:
                self.deferred = True
                raise StateDeferredError("quota after main upload", reason="rate_limit", retry_not_before=1120.)
            super().upload_asset(tag, name, source)
            if not self.deferred and defer_phase == "uncertain_evidence_upload" and not is_state:
                self.deferred = True
                raise StateDeferredError("uncertain response after successful immutable write", reason="rate_limit", retry_not_before=1120.)
    destination = Destination()
    def capture(config, job, queue):
        captures.append(job.lane)
        pipeline._bind_identity(config, job.slug, {"id": 27193779, "private": False}, "2026-10-26T00:00:00Z")
        body = canonical_json({"id": 27193779, "fixture": "new actual observation"})
        return {"capture_id": job.capture_id, "slug": job.slug, "repository_id": 27193779, "lane": job.lane,
                "mode": "full", "requested_mode": "full", "started_at": "2026-10-26T00:00:00Z",
                "finished_at": "2026-10-26T00:00:01Z", "responses": [{"purpose": "identity", "api_version": config.api_version,
                "body_sha256": ObjectStore(config.root).put(body), "body_bytes": len(body)}], "failures": [],
                "public_config": pipeline._public_config(config)}
    monkeypatch.setattr(pipeline, "capture_lane", capture)
    original_prepare, original_publish = GitHubStateStore.prepare, GitHubStateStore.publish_prepared
    def prepare(self, *args, **kwargs):
        if defer_phase == "prepare_preflight" and not destination.deferred:
            destination.deferred = True
            kwargs["directory"].mkdir(exist_ok=True)
            raise StateDeferredError("preparation quota after main upload", reason="rate_limit", retry_not_before=1120.)
        result = original_prepare(self, *args, **kwargs)
        prepared.append(result)
        return result
    def publish(self, value, *args, **kwargs):
        publication_objects.append(value)
        return original_publish(self, value, *args, **kwargs)
    monkeypatch.setattr(GitHubStateStore, "prepare", prepare)
    monkeypatch.setattr(GitHubStateStore, "publish_prepared", publish)
    def runner(config, **options):
        return pipeline.run_github_persistent(config, stamp=False, **options)
    check_backend = SimpleNamespace(read=lambda: SimpleNamespace(pointer=None))
    result = initialize_repository(plan, "nodejs/node", code_sha=plan["code_sha"], config=cfg,
        destination_repository="owner/collector", operational_private_key_path=state_private,
        state_public_key_path=state_public, evidence_public_key_path=evidence_public,
        working_root=cfg.root, scratch=tmp_path / "scratch", transport=destination, ledger=ledger,
        backend=check_backend, repair_runner=runner, repair_identity_loader=lambda _: {"id": 27193779, "private": False},
        clock=lambda: now[0], sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds))
    assert result["disposition"] == "state_published", {
        key: result.get(key) for key in ("disposition", "reason_code", "error_location")}
    assert sorted(captures) == ["api", "git"] and len(prepared) == 1
    assert all(value is prepared[0] for value in publication_objects)
    assert len(publication_objects) == (2 if defer_phase in ("prepared_state", "retry_telemetry") else 1)
    uploads = [(event[1], event[2]) for event in destination.events if event[0] == "upload"]
    assert len(uploads) == len(set(uploads))  # Even an uncertain response never duplicates a POST.
    assert destination.deferred and now[0] == 1120.
    assert result["new_evidence_upload_bytes"] > 0 and result["imported_api_scopes"] == []
    assert result["new_observations"] == 2
    assert result["fresh_collection"]["runtime"]["completed"] == 2
    assert result["observation_claim"] == "new_observation_for_explicit_source_repair"


def test_lost_fresh_capture_context_blocks_automatic_recollection(tmp_path):
    cfg = replace(config(tmp_path / "working", 1), repositories=("nodejs/node",))
    plan, ledger = plan_for(cfg, fresh_catalog(cfg)), Ledger()
    ledger.write({"migration_id": plan["migration_id"], "repository_id": 27193779,
                  "disposition": "deferred", "fresh_capture_attempt_started": True})
    result = initialize_repository(plan, "nodejs/node", code_sha=CODE, config=cfg,
        destination_repository="owner/collector", operational_private_key_path=tmp_path / "unused",
        state_public_key_path=tmp_path / "unused", evidence_public_key_path=tmp_path / "unused",
        working_root=cfg.root, scratch=tmp_path / "scratch", transport=object(), ledger=ledger,
        backend=SimpleNamespace(read=lambda: SimpleNamespace(pointer=None)),
        repair_runner=lambda *args, **kwargs: pytest.fail("Lost fresh capture was automatically recollected"))
    assert result["disposition"] == "deferred" and result["external_recovery_required"]
    assert result["reason_code"] == "fresh_publication_recovery_required"


def test_public_fresh_projection_preserves_partial_status_without_exception_text(tmp_path):
    from icsot_observer.legacy_bootstrap import RepairPublicationController, public_repair_collection
    sentinel = "UNTRUSTED_API_LINK_EXCEPTION_SECRET_SENTINEL"
    collection = {"runtime": {"completed": 1, "deferred": 1,
                  "errors": [{"error": sentinel, "lane": "api"}],
                  "results": [{"lane": "git", "capture_id": "safe-capture", "manifest": sentinel,
                               "manifest_sha256": "a" * 64}]},
                  "queue": {"states": {"complete": 1, "queued": 1}, "lane_cooldowns": [{"reason": sentinel}]},
                  "current_observation": {"status": "partial", "lane_outcomes": [
                      {"lane": "api", "state": "complete", "status": "partial", "failure_count": 1,
                       "capture_id": "safe-capture", "failures": [sentinel]}]},
                  "partial_captures": [{"failures": [sentinel]}]}
    public = public_repair_collection(collection)
    assert sentinel not in json.dumps(public)
    assert public["current_observation"]["status"] == "partial"
    assert public["current_observation"]["lane_outcomes"][0]["failure_count"] == 1
    records = []
    controller = RepairPublicationController(record=lambda disposition, **details: records.append(details),
        entry={}, plan={}, directory=tmp_path / "prepared", deadline=100)
    exports = tmp_path / "exports"
    exports.mkdir()
    controller.capture_completed(collection=collection, release_tag="safe-generation", exports=exports)
    assert sentinel not in json.dumps(records)
    assert collection["partial_captures"][0]["failures"] == [sentinel]


def import_receipt(source, proof):
    entry = {"repository_id": 42, "slug": "test/repo", "source_manifest": {"sha256": source.manifest_sha},
             "source_index": {"sha256": source.index_sha}}
    path = source.root / "imports/receipt.json"
    write_once(path, canonical_json({"kind": "icsot_legacy_state_import_receipt", "repository_id": 42, "slug": "test/repo",
        "source_manifest_sha256": source.manifest_sha, "source_index": entry["source_index"], "api_seed_proof": proof}))
    return entry, path


def test_real_api_proof_is_revalidated_before_atomic_seed_and_creates_no_historical_jobs(tmp_path):
    source = Source(tmp_path)
    entry, path = import_receipt(source, source.validate())
    queue = PersistentQueue(source.root)
    imported = commit_legacy_watermarks(queue, receipt_path=path, root=source.root, manifest_path=source.path,
        source_index_path=source.index_path, entry=entry, api_version="2026-03-10", validator=validate_legacy_api_seed)
    assert queue.jobs() == []
    assert queue.scope_watermark(42, "issues") == imported["eligible_watermarks"]["issues"]
    with queue._connection() as db:
        assert db.execute("SELECT count(*) FROM legacy_seed_imports").fetchone()[0] == 1
    assert source.path.read_bytes() == canonical_json(source.manifest)


def test_changed_import_proof_cannot_advance_a_cursor(tmp_path):
    source = Source(tmp_path)
    proof = source.validate()
    proof["eligible_watermarks"]["issues"] = "2099-01-01T00:00:00Z"
    entry, path = import_receipt(source, proof)
    queue = PersistentQueue(source.root)
    with pytest.raises(MigrationError, match="differs"):
        commit_legacy_watermarks(queue, receipt_path=path, root=source.root, manifest_path=source.path,
            source_index_path=source.index_path, entry=entry, api_version="2026-03-10", validator=validate_legacy_api_seed)
    assert queue.scope_watermark(42, "issues") is None and queue.jobs() == []


def test_generated_crypto_archive_git_and_compact_backend_integrate_without_source_network(tmp_path, monkeypatch):
    import contextlib
    import io
    import shutil
    import tarfile
    from dataclasses import asdict
    from icsot_observer import gitstore
    from icsot_observer.core import ObjectStore
    from icsot_observer.encryption import encrypt_file, public_key_fingerprint
    from icsot_observer.gitstore import collect_git, run_git
    from icsot_observer.github_state import GitHubStateStore
    from icsot_observer.legacy_capsules import create_capsule, read_envelope_aad
    from test_github_runner_integration import MemoryGitHub, keys

    upstream, old_root = tmp_path / "generated-upstream", tmp_path / "old-evidence"
    run_git(["init", "--template=", "-b", "main", str(upstream)])
    run_git(["-C", str(upstream), "config", "user.name", "Generated Fixture"])
    run_git(["-C", str(upstream), "config", "user.email", "fixture@example.invalid"])
    (upstream / "file").write_text("synthetic original content\n")
    run_git(["-C", str(upstream), "add", "."])
    run_git(["-C", str(upstream), "commit", "-m", "synthetic original"])
    def redirected(arguments, **options):
        arguments = list(arguments)
        if arguments[0] == "ls-remote":
            arguments[1] = str(upstream)
        elif len(arguments) > 2 and arguments[2] == "fetch" and "origin" in arguments:
            arguments[arguments.index("origin")] = str(upstream)
        return run_git(arguments, **options)
    monkeypatch.setattr(gitstore, "run_git", redirected)
    git = collect_git(old_root, "test/repo", 17, "original", bundle_full=True)
    working = tmp_path / "imported"
    cfg = Config(working, ("test/repo",), "2026-03-10", "test", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    public = {key: value for key, value in asdict(cfg).items() if key not in ("root", "token_env")}
    manifest = {"schema_version": 1, "collector_version": "0.1.0", "repository_id": 17,
        "repository_input_slug": "test/repo", "run_id": "original", "mode": "full", "status": "complete",
        "previous_manifest_sha256": None, "started_at": git["ls_remote_started_at"],
        "finished_at": git["ls_remote_completed_at"], "api_version": cfg.api_version,
        "public_config": public, "public_config_sha256": sha256(canonical_json(public)),
        "responses": [], "api": {"mode": "full", "scopes": {}}, "git": git, "failures": []}
    manifest_raw = canonical_json(manifest)
    relative = "runs/17/original.manifest.json"
    write_once(old_root / relative, manifest_raw)
    write_once(old_root / (relative + ".ots"), b"synthetic original unverified receipt\n")
    write_once(old_root / "registry/test__repo.json", canonical_json({"input_slug": "test/repo", "repository_id": 17}))
    reports = tmp_path / "reports"
    reports.mkdir()
    config_raw, csv_raw = b"synthetic original config", b"synthetic original csv"
    (reports / "config.corpus.toml").write_bytes(config_raw)
    (reports / "public_patch_corpus_185.csv").write_bytes(csv_raw)
    archive_path = tmp_path / "original.tar.xz"
    with tarfile.open(archive_path, "w:xz") as archive:
        archive.add(reports, arcname="reports")
        archive.add(old_root, arcname="evidence", filter=lambda item: None if item.name.startswith("evidence/git") else item)
    owner_public, owner_private = keys(tmp_path, "generated-owner")
    operational_public, operational_private = keys(tmp_path, "generated-operational")
    encrypted = tmp_path / "original.enc"
    encryption = encrypt_file(archive_path, encrypted, owner_public)
    source_manifest = {"path": relative, "sha256": sha256(manifest_raw), "bytes": len(manifest_raw),
        **{field: manifest[field] for field in ("run_id", "status", "mode", "started_at", "finished_at", "public_config_sha256")},
        "repository_id": 17, "portable_full_bundle": git["portable_full_bundle"]}
    index = {"schema_version": 1, "repository": "test/repo", "release_repository": "owner/collector",
        "release_tag": "original-baseline", "collector_code_sha": "a" * 40,
        "config_source_sha256": sha256(config_raw), "csv_sha256": sha256(csv_raw),
        "status": "complete_for_declared_shallow_baseline", "complete": True, "capture_accepted": True,
        "manifests": [source_manifest], "collector_result": {"repo": "test/repo", "repository_id": 17,
            "run_id": "original", "status": "complete", "manifest_sha256": sha256(manifest_raw)},
        "verification": {"ok": True, "portable_git_bundles_verified": 1, "raw_observations": 0},
        "archive": {"complete": True, "encrypted": True, "git_mirror_included": False,
            "recipient_spki_sha256": public_key_fingerprint(owner_public), "parts": [{
                "name": encrypted.name, "sha256": encryption["ciphertext_sha256"], "bytes": encryption["ciphertext_bytes"],
                "plaintext": {"name": archive_path.name, "sha256": encryption["plaintext_sha256"], "bytes": encryption["plaintext_bytes"]}}]}}
    index_raw = canonical_json(index)
    binding = {"repository_id": 17, "repository": "test/repo", "release_repository": "owner/collector",
        "release_tag": "original-baseline", "release_id": 10, "asset_name": encrypted.name, "asset_id": 100,
        "part_number": 1, "part_count": 1, "sealed_index_sha256": sha256(index_raw),
        "ciphertext_sha256": encryption["ciphertext_sha256"], "ciphertext_bytes": encryption["ciphertext_bytes"]}
    with encrypted.open("rb") as stream:
        aad = read_envelope_aad(stream)
    capsule = create_capsule(aad, binding=binding, owner_private_key_path=owner_private,
                             operational_public_key_path=operational_public)
    row = {"slug": "test/repo", "repository_id": 17, "source_index": ref("original.index.json", index_raw, 20),
        "source_manifest": source_manifest, "source_collector_code_sha": "a" * 40, "candidate_kind": "accepted_baseline",
        "owner_recipient_spki_sha256": public_key_fingerprint(owner_public),
        "parts": [{"binding": binding, "capsule": ref("original.capsule.json", capsule, 30), "transport_alias": None}],
        "restore_limits": {"max_staging_bytes": 1_000_000, "max_restore_bytes": 2_000_000,
            "max_tar_stream_bytes": 3_000_000, "max_member_bytes": 1_000_000, "max_members": 256, "max_path_depth": 16}}
    catalog = {"schema_version": 1, "kind": "icsot_legacy_capsule_catalog", "inventory_sha256": "9" * 64,
        "publication_status": "published",
        "config_source_sha256": sha256(config_raw), "csv_sha256": sha256(csv_raw),
        "operational_recipient_spki_sha256": public_key_fingerprint(operational_public), "repositories": [row]}
    plan = build_migration_plan(cfg, sources={"config_source_sha256": sha256(config_raw),
        "csv_sha256": sha256(csv_raw), "cohort_count": 1}, catalog=catalog,
        catalog_sha256=sha256(canonical_json(catalog)), code_sha=CODE, pointer_loader=lambda _: None)
    class Reader:
        def metadata(self, reference, **options):
            return {20: index_raw, 30: capsule}[reference["asset_id"]]
        @contextlib.contextmanager
        def open(self, reference):
            assert reference["asset_id"] == 100
            with encrypted.open("rb") as stream:
                yield stream
    class Destination(MemoryGitHub):
        def find_asset(self, tag, name, *, refresh=False):
            raw = self.assets.get((tag, name))
            return {"name": name, "size": len(raw), "digest": "sha256:" + sha256(raw)} if raw is not None else None
    destination, ledger = Destination(), Ledger()
    backend = GitHubStateStore(destination, repository_id=17, slug="test/repo", public_key=operational_public,
        private_key=operational_private, logical_root=working, part_bytes=65536, mutable_group_bytes=20000)
    outcome = initialize_repository(plan, "test/repo", code_sha=CODE, config=cfg,
        destination_repository="owner/collector", operational_private_key_path=operational_private,
        state_public_key_path=operational_public, evidence_public_key_path=owner_public,
        working_root=working, scratch=tmp_path / "scratch-real", transport=destination, reader=Reader(), ledger=ledger,
        backend=backend)
    assert outcome["disposition"] == "state_published", outcome
    assert outcome["imported_git"] and outcome["imported_api_scopes"] == []
    assert outcome["new_observations"] == outcome["new_evidence_upload_bytes"] == 0
    assert PersistentQueue(working).jobs() == []
    transfer = json.loads((working / "transfer-catalog.json").read_bytes())
    assert transfer["exports"] == [] and len(transfer["legacy_seed_packages"]) == 1
    assert (working / relative).read_bytes() == manifest_raw
    bundle = git["portable_full_bundle"]
    assert ObjectStore(working).get(bundle["sha256"]) == ObjectStore(old_root).get(bundle["sha256"])
    shutil.rmtree(working)
    restored = GitHubStateStore(destination, repository_id=17, slug="test/repo", public_key=operational_public,
        private_key=operational_private, logical_root=working, part_bytes=65536, mutable_group_bytes=20000)
    assert restored.restore(restored.read())["restored"]
    assert (working / relative).read_bytes() == manifest_raw
    assert PersistentQueue(working).jobs() == []
    # An API-first observation has no new Git manifest to discover the derived
    # descriptor. The migration receipt must independently export that closure.
    from icsot_observer.pipeline import CaptureExporter
    seed = json.loads((working / "transfer-catalog.json").read_bytes())["legacy_seed_packages"][0]
    api_manifest = {**manifest, "run_id": "fresh-api", "capture_id": "fresh-api", "lane": "api", "git": None,
                    "previous_manifest_sha256": None}
    api_path = working / "runs/17/fresh-api.manifest.json"
    write_once(api_path, canonical_json(api_manifest))
    exporter = CaptureExporter(working, tmp_path / "api-first-exports", owner_public, verified_legacy_seeds=[seed])
    exported = exporter.export({"manifest": str(api_path), "manifest_sha256": sha256(api_path.read_bytes()),
                                "run_id": "fresh-api", "repository_id": 17})
    receipt = json.loads((working / seed["import_receipt"]["path"]).read_bytes())
    descriptor_sha = receipt["git_seed_proof"]["descriptor_sha256"]
    exported_digests = {member["sha256"] for member in exported["members"]}
    assert descriptor_sha in exported_digests and seed["import_receipt"]["sha256"] in exported_digests
    assert bundle["sha256"] not in exported_digests


def test_restore_admission_uses_live_free_disk_not_reported_repository_size(tmp_path, monkeypatch):
    from icsot_observer.legacy_bootstrap import admit_restore_limits
    cfg = config(tmp_path, 1)
    entry = catalog_for(cfg)["repositories"][0]
    entry["restore_limits"] = {"max_restore_bytes": 50_000_000, "max_member_bytes": 50_000_000, "max_members": 16}
    entry["restore_safety_margin_bytes"] = 0
    monkeypatch.setattr("icsot_observer.legacy_bootstrap.shutil.disk_usage", lambda path: SimpleNamespace(free=2_000_000))
    limits, admission = admit_restore_limits(entry, json.loads(entry["fixture_index_raw"]), tmp_path)
    assert limits.max_restore_bytes == 2_000_000 - 500 - (16 + 8) * 8192
    assert limits.max_member_bytes == limits.max_restore_bytes
    assert admission["host_free_bytes_before_transfer"] == 2_000_000
    monkeypatch.setattr("icsot_observer.legacy_bootstrap.shutil.disk_usage", lambda path: SimpleNamespace(free=100))
    with pytest.raises(StateDeferredError, match="live disk"):
        admit_restore_limits(entry, json.loads(entry["fixture_index_raw"]), tmp_path)


def test_durable_git_disposition_ledger_preserves_other_repositories_and_published_terminal_state():
    import base64
    from urllib.parse import unquote
    from icsot_observer.github_state import StateError
    from icsot_observer.legacy_bootstrap import GitHubMigrationLedger
    class GitAPI:
        repository = "owner/collector"
        head = None
        def __init__(self):
            self.trees, self.commits, self.serial = {}, {}, 0
        def _api(self, endpoint, *, method="GET", payload=None, missing_ok=False):
            tail = endpoint.removeprefix("repos/owner/collector/")
            if tail == "git/ref/heads/collector-migrations":
                return {"object": {"sha": self.head}} if self.head else None
            if tail.startswith("contents/"):
                path, head = tail[len("contents/"):].split("?ref=")
                commit = self.commits[unquote(head)]
                raw = self.trees[commit["tree"]["sha"]].get(path)
                return {"type": "file", "encoding": "base64", "content": base64.b64encode(raw.encode()).decode()} if raw else None
            if tail.startswith("git/commits/"):
                return self.commits[tail.split("/")[-1]]
            if tail == "git/trees" and method == "POST":
                self.serial += 1
                tree = dict(self.trees.get(payload.get("base_tree"), {}))
                tree.update({row["path"]: row["content"] for row in payload["tree"]})
                key = "tree" + str(self.serial)
                self.trees[key] = tree
                return {"sha": key}
            if tail == "git/commits" and method == "POST":
                self.serial += 1
                key = "commit" + str(self.serial)
                self.commits[key] = {"tree": {"sha": payload["tree"]}, "parents": payload["parents"]}
                return {"sha": key}
            if tail in ("git/refs", "git/refs/heads/collector-migrations"):
                target = payload["sha"]
                if self.head is not None and self.head not in self.commits[target]["parents"]:
                    raise StateError("not fast forward")
                self.head = target
                return {}
            raise AssertionError((endpoint, method))
    api, identifier = GitAPI(), "a" * 64
    ledger = GitHubMigrationLedger(api)
    one = {"migration_id": identifier, "repository_id": 1, "disposition": "queued"}
    two = {"migration_id": identifier, "repository_id": 2, "disposition": "seed_verified"}
    ledger.write(one)
    ledger.write(two)
    assert ledger.read(identifier, 1) == one and ledger.read(identifier, 2) == two
    published = {**one, "disposition": "state_published", "state_generation": "b" * 32}
    ledger.write(published)
    assert ledger.write(one) == published
    assert ledger.read(identifier, 2) == two

