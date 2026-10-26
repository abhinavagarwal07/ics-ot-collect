import copy
import json
import shutil
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import gitstore, pipeline
from icsot_observer.checks import verify_all
from icsot_observer.core import Config, ObjectStore, canonical_json, sha256, write_once
from icsot_observer.diff import diff_latest
from icsot_observer.encryption import decrypt_file
from icsot_observer.gitarchive import verify_portable_archive
from icsot_observer.gitstore import collect_git, run_git
from icsot_observer.runtime import ControllerLock, PersistentQueue, RetryDeferred


def config(root):
    return Config(root, ("test/repo",), "2026-03-10", "research", "NO_TEST_TOKEN", 5,
                  1000000, 48, 100)


def captured(capture_id, lane="api", *, git=None, api=None, responses=None, failures=None):
    return {"capture_id": capture_id, "slug": "test/repo", "repository_id": 17,
            "lane": lane, "requested_mode": "delta", "mode": "delta",
            "started_at": "2026-10-20T00:00:00.000000Z", "finished_at": "2026-10-20T00:00:01.000000Z",
            "responses": responses or [], "failures": failures or [], "git": git, "api": api}


def read(info):
    return json.loads(Path(info["manifest"]).read_bytes())


def test_reverse_completion_and_concurrent_lanes_form_one_sorted_chain(tmp_path):
    cfg = config(tmp_path)
    release_first, second_done = threading.Event(), threading.Event()

    def first():
        assert release_first.wait(5)
        return pipeline.append_capture_manifest(cfg, captured("started-first", "api"))

    def second():
        info = pipeline.append_capture_manifest(cfg, captured("started-second", "git"))
        second_done.set()
        return info

    with ThreadPoolExecutor(2) as pool:
        one, two = pool.submit(first), pool.submit(second)
        assert second_done.wait(5)
        release_first.set()
        first_info, second_info = one.result(), two.result()
    assert first_info["run_id"] > second_info["run_id"]
    assert read(first_info)["previous_manifest_sha256"] == second_info["manifest_sha256"]
    assert read(second_info)["previous_manifest_sha256"] is None
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda n: pipeline.append_capture_manifest(cfg, captured(f"parallel-{n}", "api" if n % 2 else "git")), range(16)))
    assert verify_all(tmp_path, check_git=False)["ok"]
    assert len(list((tmp_path / "runs/17").glob("*.manifest.json"))) == 18


def test_manifest_clock_rollback_clamps_namespace_without_rewriting_observations(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    clocks = iter([datetime(2026, 10, 25, tzinfo=timezone.utc), datetime(2026, 10, 24, tzinfo=timezone.utc)])
    monkeypatch.setattr(pipeline, "utc_now", lambda: next(clocks))
    one = pipeline.append_capture_manifest(cfg, captured("one"))
    two_capture = captured("two")
    two = pipeline.append_capture_manifest(cfg, two_capture)
    manifest = read(two)
    assert two["run_id"] > one["run_id"]
    assert manifest["manifest_namespace_clock_clamped"] is True
    assert manifest["manifest_allocated_at"].startswith("2026-10-24")
    assert manifest["started_at"] == two_capture["started_at"]
    assert manifest["finished_at"] == two_capture["finished_at"]
    assert verify_all(tmp_path, check_git=False)["ok"]


def test_finalize_retry_reuses_manifest_and_commits_only_successful_scope(tmp_path):
    now = [1000.0]
    queue = PersistentQueue(tmp_path, clock=lambda: now[0])
    job = queue.enqueue("test/repo", capture_id="scope-capture")
    scope_time = "2026-10-20T00:00:00Z"
    capture = captured(job.capture_id, api={"scope_statuses": {
        "issues": {"status": "complete_for_query", "query_started_at": scope_time},
        "pulls": {"status": "failed"}}}, failures=["pulls: synthetic failure"])
    capture["watermark_candidates"] = {"issues": scope_time}
    captured_count = [0]

    def handler(job):
        captured_count[0] += 1
        return capture

    def first_finalizer(job, result):
        pipeline.finalize_lane(config(tmp_path), job, result, stamp=False)
        raise RuntimeError("Crash after immutable manifest, before cursor commit")

    first = queue.run_pending(handler, handler, first_finalizer)
    assert first["deferred"] == 1
    assert queue.scope_watermark(17, "issues") is None
    assert len(list((tmp_path / "runs/17").glob("*.manifest.json"))) == 1
    now[0] += 61
    second = queue.run_pending(handler, handler, lambda job, result: pipeline.finalize_lane(config(tmp_path), job, result, stamp=False))
    assert second["completed"] == 1 and captured_count == [1]
    assert queue.scope_watermark(17, "issues") == scope_time
    assert queue.scope_watermark(17, "pulls") is None
    assert len(list((tmp_path / "runs/17").glob("*.manifest.json"))) == 1
    changed = copy.deepcopy(capture)
    changed["failures"] = []
    with pytest.raises(RuntimeError, match="different captured evidence"):
        pipeline.append_capture_manifest(config(tmp_path), changed)


def test_delayed_export_preserves_frozen_observation_interval_after_finalize_replay(tmp_path, monkeypatch):
    cfg = config(tmp_path / "evidence")
    capture = captured("frozen-interval")
    capture["started_at"] = "2026-10-20T01:02:03.123456Z"
    capture["finished_at"] = "2026-10-20T01:03:04.654321Z"
    first = pipeline.finalize_lane(cfg, None, capture, stamp=False)
    original_manifest_bytes = Path(first.manifest_path).read_bytes()
    # Publication may happen long after capture, including finalizer-only retry.
    monkeypatch.setattr(pipeline, "utc_iso", lambda value=None: "2040-12-31T23:59:59.999999Z")
    public = tmp_path / "public.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    exporter = pipeline.CaptureExporter(cfg.root, tmp_path / "exports", public)
    replay = pipeline.finalize_lane(cfg, None, capture, stamp=False, exporter=exporter)
    assert replay.manifest_digest == first.manifest_digest
    assert Path(replay.manifest_path).read_bytes() == original_manifest_bytes
    index = json.loads(next((tmp_path / "exports").glob("*.index.json")).read_bytes())
    assert index["observation_started_at"] == "2026-10-20T01:02:03.123456Z"
    assert index["observation_finished_at"] == "2026-10-20T01:03:04.654321Z"
    assert index["clock_source"] == "runner_system_clock"
    assert "2040" not in index["observation_started_at"] + index["observation_finished_at"]


def test_stamp_request_times_are_original_recorded_interval_and_survive_replay(tmp_path, monkeypatch):
    info = pipeline.append_capture_manifest(config(tmp_path), captured("stamp-times"))
    stamp_calls = []
    times = iter(["2026-10-20T01:02:03.123456Z", "2026-10-20T01:02:05.654321Z"])
    monkeypatch.setattr(pipeline, "utc_iso", lambda value=None: next(times))
    monkeypatch.setattr(pipeline.shutil, "which", lambda name: "/test/ots")

    def stamp(args, **kwargs):
        stamp_calls.append(args)
        Path(args[-1] + ".ots").write_bytes(b"synthetic receipt for timing-only test")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(pipeline.subprocess, "run", stamp)
    first = pipeline.attest_manifest(tmp_path, info)
    provenance_bytes = Path(first["timestamp_provenance_path"]).read_bytes()
    monkeypatch.setattr(pipeline, "utc_iso", lambda value=None: "2040-12-31T23:59:59.999999Z")
    replay = pipeline.attest_manifest(tmp_path, info)
    assert len(stamp_calls) == 1
    assert replay["timestamp_provenance"] == first["timestamp_provenance"]
    assert Path(replay["timestamp_provenance_path"]).read_bytes() == provenance_bytes
    assert replay["timestamp_provenance"]["requested_at"] == "2026-10-20T01:02:03.123456Z"
    assert replay["timestamp_provenance"]["received_at"] == "2026-10-20T01:02:05.654321Z"


def test_preexisting_receipt_does_not_invent_original_request_times(tmp_path, monkeypatch):
    info = pipeline.append_capture_manifest(config(tmp_path), captured("historical-receipt"))
    proof = Path(info["manifest"] + ".ots")
    proof.write_bytes(b"previously retained receipt")
    initial = tmp_path / "proofs/initial" / (info["manifest_sha256"] + ".ots")
    write_once(initial, proof.read_bytes())
    monkeypatch.setattr(pipeline, "utc_iso", lambda value=None: "2040-12-31T23:59:59.999999Z")
    result = pipeline.attest_manifest(tmp_path, info)
    assert result["timestamp_provenance"]["requested_at"] is None
    assert result["timestamp_provenance"]["received_at"] is None
    assert result["timestamp_provenance"]["request_timing_source"] == "unknown_preexisting_receipt"


def test_rfc_failure_retries_only_finalization_and_exports_verified_sidecars(tmp_path, monkeypatch):
    root, now = tmp_path / "evidence", [1000.0]
    cfg, queue = config(root), PersistentQueue(root, clock=lambda: now[0])
    ca_file = tmp_path / "explicit-root.pem"
    ca_file.write_bytes(b"explicit trust fixture; cryptographic verification is tested by helper tests")
    policy = pipeline._rfc3161_policy("http://tsa.example.invalid", ca_file, None)
    capture = captured("rfc-retry", api={"scope_statuses": {"issues": {
        "status": "complete_for_query", "query_started_at": "2026-10-20T00:00:00Z"}}})
    capture["rfc3161_policy"] = policy
    capture["watermark_candidates"] = {"issues": "2026-10-20T00:00:00Z"}
    queue.enqueue("test/repo", capture_id=capture["capture_id"])
    captures, tsa_calls = [], []
    public = tmp_path / "public.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    exporter = pipeline.CaptureExporter(root, tmp_path / "exports", public)

    def tsa(output_dir, **options):
        tsa_calls.append(options)
        if len(tsa_calls) == 1:
            raise RuntimeError("TSA temporarily unavailable")
        output_dir.mkdir(parents=True, exist_ok=True)

        def asset(name, contents):
            write_once(output_dir / name, contents)
            return {"name": name, "sha256": sha256(contents), "bytes": len(contents)}

        request = asset("request.tsq", b"retained digest-only request")
        proof = asset("response.tsr", b"signed response fixture")
        trust = asset("root.pem", ca_file.read_bytes())
        details = asset("response.txt", b"retained signed TSTInfo text")
        metadata = {"method": "rfc3161", "status": "verified_chain_and_imprint",
                    "subject_sha256": options["manifest_sha256"],
                    "observation_interval": {"started_at": options["observation_started_at"],
                                             "finished_at": options["observation_finished_at"]}}
        sidecar = asset("attestation.json", canonical_json(metadata))
        return {"metadata": metadata, "request_asset": request, "proof_asset": proof,
                "details_asset": details, "trust_assets": [trust], "metadata_asset": sidecar}

    monkeypatch.setattr("icsot_observer.attestations.publish_rfc3161_attestation", tsa)

    def handler(job):
        captures.append(job.capture_id)
        return capture

    finalizer = lambda job, result: pipeline.finalize_lane(cfg, job, result, stamp=False, exporter=exporter)
    assert queue.run_pending(handler, handler, finalizer)["deferred"] == 1
    assert queue.scope_watermark(17, "issues") is None
    first_manifest = next((root / "runs/17").glob("*.manifest.json")).read_bytes()
    now[0] += 61
    assert queue.run_pending(handler, handler, finalizer)["completed"] == 1
    assert captures == ["rfc-retry"]
    assert next((root / "runs/17").glob("*.manifest.json")).read_bytes() == first_manifest
    assert queue.scope_watermark(17, "issues") == "2026-10-20T00:00:00Z"
    index = json.loads(next((tmp_path / "exports").glob("*.index.json")).read_bytes())
    assert index["timestamp_evidence"]["rfc3161"]["metadata"]["status"] == "verified_chain_and_imprint"
    assert {asset["name"] for asset in index["public_sidecars"]} == {
        "request.tsq", "response.tsr", "response.txt", "root.pem", "attestation.json"}
    assert tsa_calls[1]["observation_started_at"] == capture["started_at"]
    assert tsa_calls[1]["observation_finished_at"] == capture["finished_at"]
    assert all((tmp_path / "exports" / asset["name"]).is_file() for asset in index["public_sidecars"])


def test_failed_scope_candidate_is_rejected_before_manifest_or_watermark(tmp_path):
    capture = captured("invalid", api={"scope_statuses": {"issues": {"status": "failed"}}})
    capture["watermark_candidates"] = {"issues": "2026-10-20T00:00:00Z"}
    with pytest.raises(ValueError, match="complete captured scope"):
        pipeline.finalize_lane(config(tmp_path), None, capture, stamp=False)
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize("corruption", ["bytes", "declared-length"])
def test_finalization_rejects_raw_corruption_before_manifest_export_or_cursor(tmp_path, corruption):
    store = ObjectStore(tmp_path)
    body = b"raw original API bytes"
    digest = store.put(body)
    capture = captured("corrupt", responses=[{"body_sha256": digest, "body_bytes": len(body)}])
    if corruption == "bytes":
        store.location(digest).write_bytes(b"corrupted")
    else:
        capture["responses"][0]["body_bytes"] += 1
    with pytest.raises(RuntimeError, match="CAS digest or size"):
        pipeline.finalize_lane(config(tmp_path), None, capture, stamp=False)
    assert not (tmp_path / "runs").exists()


def test_finalization_rejects_failed_independent_git_restore(tmp_path, monkeypatch):
    mirror = tmp_path / "git/17.git"
    run_git(["init", "--bare", str(mirror)])
    git = {"mirror_path_relative": "git/17.git", "advertised_refs": [],
           "archive_ref_prefix": "refs/archive/broken/", "portable_archive": {"kind": "baseline"}}

    def failed_restore(*args):
        raise RuntimeError("synthetic independent restoration failure")

    monkeypatch.setattr("icsot_observer.gitarchive.verify_portable_archive", failed_restore)
    with pytest.raises(RuntimeError, match="independent restoration"):
        pipeline.finalize_lane(config(tmp_path), None, captured("broken", "git", git=git), stamp=False)
    assert not (tmp_path / "runs").exists()


def test_finalization_rejects_missing_reachable_mirror_blob(tmp_path, monkeypatch):
    source, mirror = tmp_path / "source", tmp_path / "git/17.git"
    run_git(["init", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.email", "test@example.invalid"])
    run_git(["-C", str(source), "config", "user.name", "Test"])
    (source / "file.txt").write_text("reachable file bytes\n")
    run_git(["-C", str(source), "add", "."])
    run_git(["-C", str(source), "commit", "-m", "initial"])
    mirror.parent.mkdir(parents=True)
    run_git(["clone", "--bare", str(source), str(mirror)])
    commit = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    blob = run_git(["-C", str(source), "rev-parse", "HEAD:file.txt"]).strip()
    archive_ref = "refs/archive/corrupt/heads/main"
    run_git(["-C", str(mirror), "update-ref", archive_ref, commit])
    (mirror / "objects" / blob[:2] / blob[2:]).unlink()
    git = {"mirror_path_relative": "git/17.git", "archive_ref_prefix": "refs/archive/corrupt/",
           "advertised_refs": [{"published_ref": "refs/heads/main", "object_id": commit,
                                 "local_immutable_ref": archive_ref}], "portable_archive": {"kind": "baseline"}}
    monkeypatch.setattr("icsot_observer.gitarchive.verify_portable_archive",
                        lambda *args: pytest.fail("missing mirror blob passed its acceptance gate"))
    with pytest.raises(RuntimeError, match="missing blob"):
        pipeline.finalize_lane(config(tmp_path), None, captured("corrupt", "git", git=git), stamp=False)
    assert not (tmp_path / "runs").exists()


def test_persistent_slots_are_idempotent_and_lanes_have_independent_cadence(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    now, calls = [100000.0], []
    monkeypatch.setattr(pipeline.time, "time", lambda: now[0])

    def fake_capture(cfg, job, queue):
        assert ControllerLock.owned(cfg.root)
        calls.append(job.lane)
        pipeline._bind_identity(cfg, job.slug, {"id": 17, "private": False}, "2026-10-20T00:00:00Z")
        return captured(job.capture_id, job.lane)

    monkeypatch.setattr(pipeline, "capture_lane", fake_capture)
    options = dict(once=True, api_interval_seconds=600, git_interval_seconds=60, stamp=False)
    assert pipeline.run_persistent(cfg, **options)["runtime"]["completed"] == 2
    assert pipeline.run_persistent(cfg, **options)["runtime"]["completed"] == 0
    now[0] += 61
    assert pipeline.run_persistent(cfg, **options)["runtime"]["completed"] == 1
    assert calls.count("api") == 1 and calls.count("git") == 2
    queue = PersistentQueue(tmp_path)
    assert all(job.payload["collector_config"]["user_agent"] == cfg.user_agent for job in queue.jobs())
    assert verify_all(tmp_path, check_git=False)["ok"]


def test_api_capture_uses_frozen_scope_cursor_and_fresh_identity_on_resume(tmp_path, monkeypatch):
    now = [1000.0]
    cfg, queue = config(tmp_path), PersistentQueue(tmp_path, clock=lambda: now[0])
    pipeline._bind_identity(cfg, "test/repo", {"id": 17, "private": False}, "2026-10-20T00:00:00Z")
    prior_capture = captured("prior", api={"scope_statuses": {"issues": {
        "status": "complete_for_query", "query_started_at": "2026-10-20T00:00:00Z"}}})
    prior_capture["watermark_candidates"] = {"issues": "2026-10-20T00:00:00Z"}
    prior = pipeline.append_capture_manifest(cfg, prior_capture)
    queue.commit_scope_watermarks(prior["manifest_sha256"], [{"repository_id": 17, "scope": "issues",
                                                            "value": "2026-10-20T00:00:00Z"}], manifest_path=prior["manifest"])
    job = pipeline.enqueue_capture(queue, cfg, "test/repo", "api", "resumable")
    frozen = job.payload["scope_since"]
    later_capture = captured("later", api={"scope_statuses": {"issues": {
        "status": "complete_for_query", "query_started_at": "2026-10-24T00:00:00Z"}}})
    later_capture["watermark_candidates"] = {"issues": "2026-10-24T00:00:00Z"}
    later = pipeline.append_capture_manifest(cfg, later_capture)
    queue.commit_scope_watermarks(later["manifest_sha256"], [{"repository_id": 17, "scope": "issues",
                                                            "value": "2026-10-24T00:00:00Z"}], manifest_path=later["manifest"])
    identity_calls, query_calls = [], []

    def identity(api, path, purpose):
        identity_calls.append(purpose)
        body = canonical_json({"id": 17, "private": False})
        api.records.append({"purpose": purpose, "status": 200, "body_sha256": api.store.put(body), "body_bytes": len(body),
                            "request_started_at": f"2026-10-25T00:00:0{len(identity_calls)}Z"})
        return {"id": 17, "private": False}

    def collect(api, slug, mode, since, deep_full, scope_since):
        query_calls.append(scope_since)
        if len(query_calls) == 1:
            return {"repository_id": 17, "deferred": {"retry_not_before": 1001, "reason": "quota", "lane_wide": True}}
        value = "2026-10-25T00:00:00Z"
        return {"repository_id": 17, "scope_statuses": {"issues": {"status": "complete_for_query", "query_started_at": value}},
                "watermark_candidates": {"issues": value}, "failures": []}

    monkeypatch.setattr(pipeline.GitHubAPI, "get_json", identity)
    monkeypatch.setattr(pipeline.GitHubAPI, "collect_resumable", collect)
    handler = lambda job: pipeline.capture_lane(cfg, job, queue)
    finalizer = lambda job, result: pipeline.finalize_lane(cfg, job, result, stamp=False)
    assert queue.run_pending(handler, handler, finalizer)["deferred"] == 1
    assert len(list((tmp_path / "runs/17").glob("*.manifest.json"))) == 2
    now[0] = 1002
    assert queue.run_pending(handler, handler, finalizer)["completed"] == 1
    assert identity_calls == ["repository_identity", "repository_identity"]
    assert query_calls == [frozen, frozen]
    assert frozen["issues"] == "2026-10-18T00:00:00.000000Z"
    assert queue.scope_watermark(17, "issues") == "2026-10-25T00:00:00Z"
    manifest = json.loads(sorted((tmp_path / "runs/17").glob("*.manifest.json"))[-1].read_bytes())
    assert len(manifest["responses"]) >= 2
    assert manifest["verification"]["raw_response_objects_verified"] >= 2


def test_git_lane_revalidates_bound_repository_identity(tmp_path, monkeypatch):
    cfg, queue = config(tmp_path), PersistentQueue(tmp_path)
    pipeline._bind_identity(cfg, "test/repo", {"id": 17, "private": False}, "2026-10-20T00:00:00Z")
    job = pipeline.enqueue_capture(queue, cfg, "test/repo", "git", "renamed")
    monkeypatch.setattr(pipeline.GitHubAPI, "get_json", lambda *args: {"id": 99, "private": False})
    monkeypatch.setattr(pipeline, "collect_git", lambda *args, **kwargs: pytest.fail("Git fetched reused slug"))
    with pytest.raises(RuntimeError, match="REPOSITORY_IDENTITY_CHANGED"):
        pipeline.capture_lane(cfg, job, queue)


def test_unbound_identity_failure_preserves_envelopes_until_later_binding(tmp_path, monkeypatch):
    cfg, queue = config(tmp_path), PersistentQueue(tmp_path)
    job = pipeline.enqueue_capture(queue, cfg, "test/repo", "api", "identity-retry")
    calls = []

    def identity(api, path, purpose):
        calls.append(purpose)
        body = canonical_json({"id": 17, "private": False}) if len(calls) > 1 else b'{"message":"temporary outage"}'
        api.records.append({"purpose": purpose, "status": 200 if len(calls) > 1 else 503,
                            "body_sha256": api.store.put(body), "body_bytes": len(body),
                            "request_started_at": f"2026-10-20T00:00:0{len(calls)}Z"})
        if len(calls) == 1:
            raise RuntimeError("temporary identity outage")
        return {"id": 17, "private": False}

    monkeypatch.setattr(pipeline.GitHubAPI, "get_json", identity)
    monkeypatch.setattr(pipeline.GitHubAPI, "collect_resumable", lambda *args, **kwargs: {
        "repository_id": 17, "scope_statuses": {}, "watermark_candidates": {}, "failures": []})
    with pytest.raises(RuntimeError, match="temporary identity"):
        pipeline.capture_lane(cfg, job, queue)
    attempts = list((tmp_path / "quarantine/identity").glob("*/*/*.json"))
    assert len(attempts) == 1
    assert json.loads(attempts[0].read_bytes())["records"][0]["status"] == 503
    result = pipeline.capture_lane(cfg, job, queue)
    assert [record["status"] for record in result["responses"]] == [503, 200]
    assert result["started_at"] == "2026-10-20T00:00:01Z"
    assert result["repository_id"] == 17


def test_frozen_api_version_is_used_by_finalization_after_config_changes(tmp_path):
    cfg = config(tmp_path)
    capture = captured("old-config")
    capture["public_config"] = {**pipeline._public_config(cfg), "api_version": "2022-11-28"}
    finalized = pipeline.finalize_lane(cfg, None, capture, stamp=False)
    assert json.loads(Path(finalized.manifest_path).read_bytes())["api_version"] == "2022-11-28"


def test_api_rate_deferral_retains_capture_without_committing_or_blocking_git(tmp_path, monkeypatch):
    queue = PersistentQueue(tmp_path)
    queue.enqueue("test/repo", "api", capture_id="api-rate")
    queue.enqueue("test/repo", "git", capture_id="git-ready")

    def api(job):
        raise RetryDeferred(4000000000, "primary quota reset", lane_wide=True)

    done = queue.run_pending(api, lambda job: captured(job.capture_id, "git"),
                             lambda job, result: pipeline.finalize_lane(config(tmp_path), job, result, stamp=False))
    assert done["completed"] == done["deferred"] == 1
    assert queue.jobs(lane="api")[0].captured is False
    assert queue.jobs(lane="api")[0].capture_id == "api-rate"
    assert queue.jobs(lane="git")[0].state == "complete"
    assert queue.scope_watermark(17, "issues") is None


def test_diff_compares_api_and_git_lanes_separately(tmp_path):
    store, cfg = ObjectStore(tmp_path), config(tmp_path)

    def api_capture(name, value):
        body = canonical_json([{"id": 1, "number": 1, "body": value}])
        return captured(name, responses=[{"purpose": "issues", "status": 200,
                                         "body_sha256": store.put(body), "body_bytes": len(body)}])

    def git_capture(name, oid):
        return captured(name, "git", git={"advertised_refs": [{"published_ref": "refs/heads/main", "object_id": oid}]})

    a1 = pipeline.append_capture_manifest(cfg, api_capture("api1", "before"))
    g1 = pipeline.append_capture_manifest(cfg, git_capture("git1", "a" * 40))
    a2 = pipeline.append_capture_manifest(cfg, api_capture("api2", "after"))
    g2 = pipeline.append_capture_manifest(cfg, git_capture("git2", "b" * 40))
    diff = diff_latest(tmp_path, 17)
    assert diff["api_comparison"] == {"old_run_id": a1["run_id"], "new_run_id": a2["run_id"]}
    assert diff["git_comparison"] == {"old_run_id": g1["run_id"], "new_run_id": g2["run_id"]}
    assert len(diff["entity_types"]["issues"]["representation_changed"]) == 1
    assert diff["git_refs"]["added"] == diff["git_refs"]["not_advertised_now"] == []
    assert diff["git_refs"]["moved"][0]["prior_sha"] == "a" * 40


def test_diff_with_api_only_has_no_git_disappearance_inference(tmp_path):
    cfg = config(tmp_path)
    pipeline.append_capture_manifest(cfg, captured("api1"))
    pipeline.append_capture_manifest(cfg, captured("git1", "git", git={"advertised_refs": []}))
    pipeline.append_capture_manifest(cfg, captured("api2"))
    diff = diff_latest(tmp_path, 17)
    assert diff["git_comparison"] is None
    assert diff["git_refs"]["comparison_available"] is False
    assert diff["git_refs"]["not_advertised_now"] == []


def test_encrypted_incremental_exports_restore_offline_without_repacking_baseline(tmp_path, monkeypatch):
    root, source = tmp_path / "evidence", tmp_path / "source"
    run_git(["init", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.email", "test@example.invalid"])
    run_git(["-C", str(source), "config", "user.name", "Test"])
    (source / "file.txt").write_text("before\n")
    run_git(["-C", str(source), "add", "."])
    run_git(["-C", str(source), "commit", "-m", "baseline"])

    def local(args, **kwargs):
        args = list(args)
        if args[0] == "ls-remote":
            args[1] = str(source)
        elif len(args) > 2 and args[2] == "fetch" and "origin" in args:
            args[args.index("origin")] = str(source)
        return run_git(args, **kwargs)

    monkeypatch.setattr(gitstore, "run_git", local)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_path, private_path = tmp_path / "public.pem", tmp_path / "private.pem"
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    exporter = pipeline.CaptureExporter(root, tmp_path / "exports", public_path)
    cfg = config(root)
    one_git = collect_git(root, "test/repo", 17, "one", archive_mode="incremental")
    finalized_one = pipeline.finalize_lane(cfg, None, captured("one", "git", git=one_git), stamp=False, exporter=exporter)
    one_manifest = json.loads(Path(finalized_one.manifest_path).read_bytes())
    first = json.loads((tmp_path / "exports" / (one_manifest["run_id"] + ".index.json")).read_bytes())
    assert one_manifest["verification"]["portable_git_restore"] == "passed_into_empty_repository"
    (source / "file.txt").write_text("after\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "delta"])
    expected = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    two_git = collect_git(root, "test/repo", 17, "two", archive_mode="incremental")
    finalized_two = pipeline.finalize_lane(cfg, None, captured("two", "git", git=two_git), stamp=False, exporter=exporter)
    two_manifest = json.loads(Path(finalized_two.manifest_path).read_bytes())
    second = json.loads((tmp_path / "exports" / (two_manifest["run_id"] + ".index.json")).read_bytes())
    baseline_digest = one_git["portable_archive"]["bundle"]["sha256"]
    assert baseline_digest in second["requires_cas_sha256"]
    assert baseline_digest not in {member["sha256"] for member in second["members"]}
    assert exporter.export({"manifest": str(finalized_two.manifest_path), "manifest_sha256": finalized_two.manifest_digest,
                            "run_id": two_manifest["run_id"]}) == second
    shutil.rmtree(source)
    shutil.rmtree(root)
    restored = tmp_path / "restore"
    for number, index in enumerate((first, second)):
        asset = tmp_path / "exports" / index["asset"]["name"]
        assert sha256(asset.read_bytes()) == index["asset"]["sha256"]
        plaintext = tmp_path / f"decrypted-{number}.tar.xz"
        decrypt_file(asset, plaintext, private_path)
        with tarfile.open(plaintext, "r:xz") as archive:
            archive.extractall(restored, filter="data")
    offline_root = restored / "evidence"
    assert verify_all(offline_root, check_git=False)["ok"]
    assert pipeline.restore_mirrors(offline_root)["ok"]
    assert (offline_root / "git/17.git/icsot-archive-head").is_file()
    offline_git = tmp_path / "offline.git"
    verify_portable_archive(offline_root, two_git, offline_git)
    assert run_git(["-C", str(offline_git), "rev-parse", "refs/archive/two/heads/main"]).strip() == expected
    assert not list((tmp_path / "exports").glob("*.tar.xz"))


def test_persistent_export_key_configuration_fails_before_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "capture_lane", lambda *args: pytest.fail("network handler called"))
    with pytest.raises(ValueError, match="both --export-directory and --public-key"):
        pipeline.run_persistent(config(tmp_path), once=True, export_directory=tmp_path / "exports")


def test_encrypted_transfer_parts_are_bounded_and_restore_in_order(tmp_path):
    root = tmp_path / "evidence"
    store = ObjectStore(root)
    body = b"".join(sha256(str(n).encode()).encode() for n in range(50))
    capture = captured("multipart", responses=[{"body_sha256": store.put(body), "body_bytes": len(body)}])
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public, secret = tmp_path / "public.pem", tmp_path / "private.pem"
    public.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    secret.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    exporter = pipeline.CaptureExporter(root, tmp_path / "exports", public, part_bytes=300)
    finalized = pipeline.finalize_lane(config(root), None, capture, stamp=False, exporter=exporter)
    manifest = json.loads(Path(finalized.manifest_path).read_bytes())
    index = json.loads((tmp_path / "exports" / (manifest["run_id"] + ".index.json")).read_bytes())
    assert len(index["assets"]) > 1 and "asset" not in index
    combined = tmp_path / "combined.tar.xz"
    with combined.open("wb") as output:
        for n, part in enumerate(index["assets"]):
            assert 0 < part["encryption"]["plaintext_bytes"] <= 300
            restored = tmp_path / f"part-{n}"
            decrypt_file(tmp_path / "exports" / part["name"], restored, secret)
            output.write(restored.read_bytes())
    with tarfile.open(combined, "r:xz") as archive:
        archive.extractall(tmp_path / "restored", filter="data")
    assert ObjectStore(tmp_path / "restored/evidence").get(sha256(body)) == body
    pipeline.CaptureExporter(root, tmp_path / "exports", public, part_bytes=300)
    assert not list((tmp_path / "exports").glob(".capture-export-*"))
