import hashlib
import json
import sqlite3
import threading
import time

import pytest

from icsot_observer.core import canonical_json, write_once
from icsot_observer.pipeline import exclusive_lock
from icsot_observer.runtime import (
    ControllerBusyError, ControllerLock, Finalization, LeaseLostError,
    PersistentQueue, RetryDeferred, ScopeWatermark,
)


def manifest(root, job, candidates=()):
    candidates = list(candidates)
    scopes = {item.scope: item.value for item in candidates}
    repo_id = job.payload.get("repository_id", 17)
    path = root / "runs" / str(repo_id) / f"{job.capture_id}-{job.lane}.manifest.json"
    raw = canonical_json({"repository_id": repo_id, "capture_id": job.capture_id, "lane": job.lane,
                          "watermark_candidates": scopes,
                          "api": {"capture_result": job.result, "scope_statuses": {
                              scope: {"status": "complete_for_query", "query_started_at": value}
                              for scope, value in scopes.items()}}})
    if not path.exists():
        write_once(path, raw)
    return Finalization(path, hashlib.sha256(path.read_bytes()).hexdigest(), candidates)


def enqueue(queue, capture="capture-1", lane="api", slug="test/repo", **kwargs):
    return queue.enqueue(slug, lane, "delta", capture, {"repository_id": 17}, **kwargs)


def test_jobs_and_attempts_survive_restart_and_inputs_are_immutable(tmp_path):
    queue = PersistentQueue(tmp_path, clock=lambda: 100)
    job = enqueue(queue, cohort="cohort-sha", ref="refs/heads/main")
    assert enqueue(queue, cohort="cohort-sha", ref="refs/heads/main") == job
    with pytest.raises(ValueError, match="immutable"):
        queue.enqueue(job.slug, job.lane, job.mode, job.capture_id, {"repository_id": 18})
    lease = queue.lease("api", lease_seconds=10)
    queue.defer(lease, 120, "quota", lane_wide=True)
    reopened = PersistentQueue(tmp_path, clock=lambda: 110)
    stored = reopened.get(job.id)
    assert (stored.input_hash, stored.cohort, stored.ref) == (job.input_hash, "cohort-sha", "refs/heads/main")
    assert stored.attempts == 1
    assert reopened.job_attempts(job.id)[0]["outcome"] == "deferred"
    assert reopened.lease("api") is None
    assert reopened.status()["lane_cooldowns"][0]["retry_not_before"] == 120
    assert reopened.status()["next_retry_not_before"] == 120


@pytest.mark.parametrize("capture_id", ["", "../escape", "/absolute", ".hidden", "a/b", "a" * 201])
def test_capture_ids_are_safe_path_components(tmp_path, capture_id):
    with pytest.raises(ValueError, match="safe immutable path"):
        enqueue(PersistentQueue(tmp_path), capture_id)


def test_expired_lease_is_recovered_and_old_token_is_fenced(tmp_path):
    now = [100.0]
    queue = PersistentQueue(tmp_path, clock=lambda: now[0])
    enqueue(queue)
    old = queue.lease("api", lease_seconds=10)
    now[0] = 111
    restarted = PersistentQueue(tmp_path, clock=lambda: now[0])
    new = restarted.lease("api", lease_seconds=10)
    assert new.id == old.id and new.lease_token != old.lease_token
    assert new.attempts == 2
    with pytest.raises(LeaseLostError):
        queue.mark_captured(old, {"stale": True})
    with pytest.raises(LeaseLostError):
        queue.renew(old)
    with pytest.raises(LeaseLostError):
        queue.defer(old, 150, "stale")
    attempts = restarted.job_attempts(new.id)
    assert attempts[0]["outcome"] == "lease_expired"
    assert attempts[1]["outcome"] is None


def test_only_one_repo_lane_lease_but_lanes_and_other_repos_are_independent(tmp_path):
    queue = PersistentQueue(tmp_path)
    first = enqueue(queue, "first")
    enqueue(queue, "second")
    git = enqueue(queue, "git", lane="git")
    other = queue.enqueue("other/repo", "api", "full", "other", {"repository_id": 18})
    assert queue.lease("api").id == first.id
    assert queue.lease("api").id == other.id
    assert queue.lease("api") is None
    assert queue.lease("git").id == git.id


def test_scope_watermarks_require_verified_manifest_and_do_not_regress(tmp_path):
    queue = PersistentQueue(tmp_path)
    candidate = ScopeWatermark(17, "issues", "2026-10-25T00:00:00Z")
    with pytest.raises(ValueError, match="before watermark"):
        queue.commit_scope_watermarks("0" * 64, [candidate])
    assert queue.scope_watermark(17, "issues") is None
    job = enqueue(queue)
    finalized = manifest(tmp_path, job, [candidate])
    with pytest.raises(ValueError, match="digest"):
        queue.commit_scope_watermarks("0" * 64, [candidate], manifest_path=finalized.manifest_path)
    assert queue.scope_watermark(17, "issues") is None
    queue.commit_scope_watermarks(finalized.manifest_digest, [candidate], manifest_path=finalized.manifest_path)
    older_candidate = ScopeWatermark(17, "issues", "2026-10-24T00:00:00Z")
    older = manifest(tmp_path, enqueue(queue, "older"), [older_candidate])
    queue.commit_scope_watermarks(older.manifest_digest, [older_candidate], manifest_path=older.manifest_path)
    assert queue.scope_watermark(17, "issues") == candidate.value
    assert queue.scope_watermark(17, "releases") is None
    with pytest.raises(ValueError, match="repository"):
        queue.commit_scope_watermarks(finalized.manifest_digest, [ScopeWatermark(18, "issues", candidate.value)])
    # A registered path is rechecked, so a changed evidence file cannot advance a cursor.
    finalized.manifest_path.write_bytes(b'{"repository_id": 17, "tampered": true}')
    with pytest.raises(ValueError, match="digest"):
        queue.commit_scope_watermarks(finalized.manifest_digest, [ScopeWatermark(17, "issues", "2026-10-26T00:00:00Z")])
    assert queue.scope_watermark(17, "issues") == candidate.value


@pytest.mark.parametrize("mismatch", ["git_lane", "failed_scope", "different_candidate", "different_query_start", "missing_scope"])
def test_cursor_commit_requires_exact_successful_api_scope(tmp_path, mismatch):
    queue = PersistentQueue(tmp_path)
    candidate = ScopeWatermark(17, "issues", "2026-10-25T00:00:00Z")
    artifact = manifest(tmp_path, enqueue(queue), [candidate])
    document = json.loads(artifact.manifest_path.read_bytes())
    if mismatch == "git_lane":
        document["lane"] = "git"
    elif mismatch == "failed_scope":
        document["api"]["scope_statuses"]["issues"]["status"] = "error"
    elif mismatch == "different_candidate":
        document["watermark_candidates"]["issues"] = "2026-10-24T00:00:00Z"
    elif mismatch == "different_query_start":
        document["api"]["scope_statuses"]["issues"]["query_started_at"] = "2026-10-24T00:00:00Z"
    else:
        document["api"]["scope_statuses"] = {}
    raw = canonical_json(document)
    artifact.manifest_path.write_bytes(raw)
    with pytest.raises(ValueError, match="completed API scope"):
        queue.commit_scope_watermarks(hashlib.sha256(raw).hexdigest(), [candidate], manifest_path=artifact.manifest_path)
    assert queue.scope_watermark(17, "issues") is None


def test_finalization_retry_after_manifest_write_never_recaptures(tmp_path):
    now = [100.0]
    queue = PersistentQueue(tmp_path, clock=lambda: now[0])
    job = enqueue(queue)
    captures, finalizes = [], []

    def capture(leased):
        captures.append(leased.capture_id)
        return {"records": ["stable captured bytes"]}

    def finalize(leased, result):
        finalizes.append(leased.capture_id)
        artifact = manifest(tmp_path, leased, [ScopeWatermark(17, "issues", "2026-10-25T00:00:00Z")])
        if len(finalizes) == 1:
            raise OSError("crash after immutable manifest append")
        return artifact

    summary = queue.run_pending(capture, capture, finalize)
    assert summary["completed"] == 0 and summary["deferred"] == 1
    assert queue.get(job.id).state == "finalize_pending"
    assert queue.scope_watermark(17, "issues") is None
    now[0] = 161
    reopened = PersistentQueue(tmp_path, clock=lambda: now[0])
    summary = reopened.run_pending(capture, capture, finalize)
    assert summary["completed"] == 1
    assert len(captures) == 1 and len(finalizes) == 2
    stored = reopened.get(job.id)
    assert (stored.attempts, stored.finalize_attempts, stored.state) == (1, 2, "complete")
    assert reopened.scope_watermark(17, "issues") == "2026-10-25T00:00:00Z"
    assert len(list((tmp_path / "runs" / "17").glob("*.manifest.json"))) == 1


def test_crash_after_capture_before_finalize_uses_durable_result(tmp_path):
    now = [100.0]
    queue = PersistentQueue(tmp_path, clock=lambda: now[0])
    enqueue(queue)
    leased = queue.lease("api", lease_seconds=10)
    queue.mark_captured(leased, {"immutable": "result"})
    now[0] = 111
    restarted = PersistentQueue(tmp_path, clock=lambda: now[0])
    recovered = restarted.lease("api")
    assert recovered.captured and recovered.result == {"immutable": "result"}
    assert recovered.state == "finalizing" and recovered.attempts == 1
    restarted.complete(recovered, manifest(tmp_path, recovered))
    assert restarted.get(recovered.id).state == "complete"


def test_api_rate_deferral_does_not_block_git_pool(tmp_path):
    queue = PersistentQueue(tmp_path)
    enqueue(queue, "api")
    enqueue(queue, "git-one", lane="git")
    enqueue(queue, "git-two", lane="git")
    api_started, git_finished = threading.Event(), threading.Event()

    def api(job):
        api_started.set()
        assert git_finished.wait(5), "Git pool did not run independently"
        raise RetryDeferred(time.time() + 3600, "API quota reset", lane_wide=True)

    git_captures = []

    def git(job):
        assert api_started.wait(5)
        git_captures.append(job.capture_id)
        git_finished.set()
        return {"git": "captured"}

    summary = queue.run_pending(api, git, lambda j, r: manifest(tmp_path, j), git_workers=2)
    assert summary["completed"] == 2 and summary["deferred"] == 1
    assert git_captures == ["git-one", "git-two"]
    assert queue.jobs(lane="api")[0].state == "queued"
    assert queue.jobs(lane="git", include_complete=False) == []


def test_git_workers_overlap_different_repositories(tmp_path):
    queue = PersistentQueue(tmp_path)
    enqueue(queue, "git-one", lane="git")
    queue.enqueue("other/repo", "git", "delta", "git-two", {"repository_id": 18})
    both_started = threading.Barrier(2)

    def capture(job):
        both_started.wait(timeout=5)
        return {"repository_id": job.payload["repository_id"]}

    summary = queue.run_pending(capture, capture, lambda j, r: manifest(tmp_path, j), git_workers=2)
    assert summary["completed"] == 2 and not summary["errors"]


def test_live_repo_lane_exclusion_survives_expired_lease(tmp_path, monkeypatch):
    now = [100.0]
    queue = PersistentQueue(tmp_path, clock=lambda: now[0])
    enqueue(queue, "first", lane="git", priority=20)
    queue.enqueue("other/repo", "git", "delta", "unrelated", {"repository_id": 18}, priority=10)
    enqueue(queue, "second", lane="git")
    first_started, first_finished = threading.Event(), threading.Event()
    allow_first_finish, post_expiry_lease = threading.Event(), threading.Event()
    overlapping_callback = threading.Event()
    actual_lease = queue.lease

    def observe_lease(*args, **kwargs):
        leased = actual_lease(*args, **kwargs)
        if first_started.is_set() and now[0] > 110 and not first_finished.is_set():
            post_expiry_lease.set()
        return leased

    monkeypatch.setattr(queue, "lease", observe_lease)

    def capture(job):
        if job.capture_id == "first":
            first_started.set()
            assert allow_first_finish.wait(5)
            first_finished.set()
        elif job.capture_id == "unrelated":
            assert first_started.wait(5)
            # Model a stopped/failed heartbeat while an external side effect
            # from the first callback is still in flight.
            now[0] = 200
        elif not first_finished.is_set():
            overlapping_callback.set()
        return {"repository_id": job.payload["repository_id"]}

    output = []
    runner = threading.Thread(target=lambda: output.append(queue.run_pending(
        capture, capture, lambda j, r: manifest(tmp_path, j), git_workers=2, lease_seconds=10)))
    runner.start()
    try:
        assert post_expiry_lease.wait(5), "The other worker never attempted a post-expiry lease"
        assert not overlapping_callback.wait(0.1), "Same-repo callback overlapped the expired live handler"
    finally:
        allow_first_finish.set()
        runner.join(timeout=5)
    assert not runner.is_alive()
    assert not overlapping_callback.is_set()
    assert queue.jobs(slug="test/repo")[-1].state == "complete"
    assert output[0]["completed"] == 1


def test_fifo_priority_and_fair_retry_drain_each_job_at_most_once(tmp_path):
    queue = PersistentQueue(tmp_path)
    first = enqueue(queue, "first")
    enqueue(queue, "second", priority=10)
    order = []

    def retry(job):
        order.append(job.capture_id)
        raise RetryDeferred(0, "already due; still retry next controller run")

    result = queue.run_pending(retry, retry, lambda j, r: manifest(tmp_path, j), api_workers=2)
    assert order == ["second", "first"]
    assert result["deferred"] == 2
    assert queue.get(first.id).attempts == 1


def test_callbacks_hold_no_sqlite_transaction_and_long_calls_renew_leases(tmp_path):
    queue = PersistentQueue(tmp_path)
    original = enqueue(queue)

    def capture(job):
        with sqlite3.connect(queue.path, timeout=0.1) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("SELECT 1")
        time.sleep(0.18)
        assert queue.lease("api", lease_seconds=0.1) is None
        return {"long": True}

    result = queue.run_pending(capture, capture, lambda j, r: manifest(tmp_path, j), lease_seconds=0.1)
    assert result["completed"] == 1
    assert queue.get(original.id).attempts == 1


def test_controller_collision_and_legacy_collector_share_lock(tmp_path):
    queue = PersistentQueue(tmp_path)
    with ControllerLock(tmp_path):
        with pytest.raises(ControllerBusyError):
            queue.run_pending(lambda j: {}, lambda j: {}, lambda j, r: None)
        with pytest.raises(BlockingIOError):
            with exclusive_lock(tmp_path):
                pytest.fail("Legacy collector overlapped controller")
    with exclusive_lock(tmp_path):
        with pytest.raises(ControllerBusyError):
            with ControllerLock(tmp_path):
                pytest.fail("Controller overlapped legacy collector")
    assert queue.run_pending(lambda j: {}, lambda j: {}, lambda j, r: None)["completed"] == 0


def test_daemon_can_hold_controller_lock_across_drains(tmp_path):
    queue = PersistentQueue(tmp_path)
    with pytest.raises(ValueError, match="hold ControllerLock"):
        queue.run_pending(lambda j: {}, lambda j: {}, lambda j, r: None, controller_locked=True)
    with ControllerLock(tmp_path):
        result = queue.run_pending(lambda j: {}, lambda j: {}, lambda j, r: None, controller_locked=True)
        assert result["completed"] == 0
        with pytest.raises(BlockingIOError):
            with exclusive_lock(tmp_path):
                pytest.fail("Legacy collector overlapped the daemon's interval wait")


def test_manifest_watermarks_and_job_completion_are_atomic(tmp_path):
    queue = PersistentQueue(tmp_path)
    original = enqueue(queue)
    leased = queue.lease("api")
    captured = queue.mark_captured(leased, {"x": 1})
    finalizing = queue.begin_finalize(captured)
    final = manifest(tmp_path, finalizing, [
        ScopeWatermark(17, "issues", "2026-10-25T00:00:00Z"),
        ScopeWatermark(18, "wrong-repo", "2026-10-25T00:00:00Z"),
    ])
    with pytest.raises(ValueError, match="repository"):
        queue.complete(finalizing, final)
    assert queue.scope_watermark(17, "issues") is None
    assert queue.get(original.id).state == "finalizing"


def test_completion_rejects_manifest_from_another_capture(tmp_path):
    queue = PersistentQueue(tmp_path)
    enqueue(queue)
    leased = queue.lease("api")
    captured = queue.mark_captured(leased, {})
    finalizing = queue.begin_finalize(captured)
    unrelated = enqueue(queue, "unrelated")
    with pytest.raises(ValueError, match="capture and lane"):
        queue.complete(finalizing, manifest(tmp_path, unrelated))
    assert queue.get(finalizing.id).state == "finalizing"
