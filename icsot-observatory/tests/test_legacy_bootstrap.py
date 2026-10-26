import copy
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
    MigrationError, MigrationHelpers, backlog_matrix, build_migration_plan,
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
            working_root=cfg.root, scratch=tmp_path / "scratch", transport=transport, reader=reader, ledger=ledger,
            helpers=helpers, backend=backend, clock=lambda: now[0], sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds), **options)
    return SimpleNamespace(run=run, plan=plan, config=cfg, entry=entry, backend=backend, ledger=ledger,
                           helpers=helpers, events=events, now=now, transport=transport, reader=reader)


def test_import_preserves_original_times_fresh_queue_and_prepared_publication_order(engine):
    result = engine.run()
    assert result["disposition"] == "state_published", result
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


@pytest.mark.parametrize("defer_phase", ["proof_registration", "prepared_state", "uncertain_evidence_upload", "prepare_preflight", "retry_telemetry"])
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
        def save(self, *args, **kwargs):
            if not self.deferred and defer_phase == "proof_registration":
                self.deferred = True
                raise StateDeferredError("quota after main upload", reason="rate_limit", retry_not_before=1120.)
            return super().save(*args, **kwargs)
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
    assert result["disposition"] == "state_published", result
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

