import io
import json
import shutil
import urllib.error
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

from icsot_observer.checkpoints import CheckpointError, CheckpointStore
from icsot_observer.core import Config, ObjectStore, canonical_json, sha256
from icsot_observer.github import APIRequestDeferred, GitHubAPI


class Crash(BaseException):
    """Represents termination which ordinary scope error handling cannot catch."""


class Reply:
    status = 200

    def __init__(self, body, headers=None):
        self.body, self.headers = body, headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, limit):
        return self.body[:limit]


def client(root, handler, *, capture="capture-1", config=None, records=None):
    cfg = config or Config(root=root, repositories=("test/repo",), api_version="2026-03-10",
                           user_agent="test", token_env="CHECKPOINT_TEST_NO_TOKEN", http_timeout_seconds=5,
                           max_response_bytes=1000000, overlap_hours=48, max_pages=100)
    checkpoint = CheckpointStore(root, 42, capture)
    api = GitHubAPI(cfg, ObjectStore(root), records if records is not None else [], checkpoint)
    calls = []

    def open_request(request, timeout):
        calls.append(request.full_url)
        return handler(request.full_url)

    api.opener.open = open_request
    return api, checkpoint, calls


METADATA = "https://api.github.com/repos/test/repo"
EVENTS = METADATA + "/events?per_page=100"
SECOND = "https://api.github.com/repositories/42/events?per_page=100&after=opaque%3D&page=2"
PUBLIC = b'{"id":42,"private":false,"full_name":"test/repo"}'
FIRST_BODY = b'[{"id":1}]'
LINK = {"Link": f'<{SECOND}>; rel="next"'}


def test_response_and_page_are_durable_before_next_request_and_resume(tmp_path):
    def interrupted(url):
        if url == METADATA:
            return Reply(PUBLIC)
        if url == EVENTS:
            return Reply(FIRST_BODY, LINK)
        # A second reader sees the fsynced envelope and its page lineage before
        # the next HTTP call is issued. Simulate process death at that boundary.
        disk = CheckpointStore(tmp_path, 42, "capture-1")
        state = disk.scope_state("events")
        record = disk.response(state["pages"][0]["response_sequence"])
        assert record["url"] == EVENTS
        assert ObjectStore(tmp_path).get(record["body_sha256"]) == FIRST_BODY
        raise Crash()

    api, cp, _ = client(tmp_path, interrupted)
    with pytest.raises(Crash):
        api.collect_resumable("test/repo", "events")
    original = [record for record in cp.responses() if record["url"] == EVENTS][0]
    original_query_start = cp.scope_state("events")["query_started_at"]

    def restored(url):
        if url == EVENTS:
            return Reply(FIRST_BODY, LINK)
        assert url == SECOND
        return Reply(b'[{"id":2}]')

    resumed, _, calls = client(tmp_path, restored)
    result = resumed.collect_resumable("test/repo", "events")
    assert calls == [EVENTS, SECOND, EVENTS]
    assert result["scopes"]["events"]["count"] == 2
    assert result["watermark_candidates"]["events"] == original_query_start
    reused = next(record for record in resumed.records if record["body_sha256"] == original["body_sha256"])
    assert reused["request_started_at"] == original["request_started_at"]
    assert reused["request_completed_at"] == original["request_completed_at"]
    assert reused["checkpoint_provenance"]["reused_from_checkpoint"] is True
    assert result["scopes"]["events"]["interpretation"] == "OPPORTUNISTIC_NOT_COMPLETE"
    # This same capture can be finalized/retried without any HTTP traffic.
    done, _, done_calls = client(tmp_path, lambda url: pytest.fail(url))
    assert done.collect_resumable("test/repo", "events")["scopes"]["events"]["reused_from_checkpoint"]
    assert done_calls == []
    # A scheduled later capture performs fresh requests even when CAS deduplicates.
    fresh, _, fresh_calls = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else b"[]"), capture="capture-2")
    fresh.collect_resumable("test/repo", "events")
    assert fresh_calls == [METADATA, EVENTS]


def test_resume_drift_retains_old_attempt_and_restarts_without_stitching(tmp_path):
    def interrupted(url):
        if url == METADATA:
            return Reply(PUBLIC)
        if url == EVENTS:
            return Reply(FIRST_BODY, LINK)
        raise Crash()
    api, _, _ = client(tmp_path, interrupted)
    with pytest.raises(Crash):
        api.collect_resumable("test/repo", "events")
    resumed, cp, calls = client(tmp_path, lambda url: Reply(b'[{"id":9}]'))
    result = resumed.collect_resumable("test/repo", "events")
    assert calls == [EVENTS, EVENTS]  # validation then a separately bound new attempt
    assert result["scopes"]["events"]["count"] == 1
    assert ObjectStore(tmp_path).get(sha256(FIRST_BODY)) == FIRST_BODY
    assert len([event for event in cp.events if event["kind"] == "scope_abandoned"]) == 1
    state = cp.scope_state("events")
    assert state["restarts"] == 1 and len(state["pages"]) == 1
    record = cp.response(state["pages"][0]["response_sequence"])
    assert ObjectStore(tmp_path).get(record["body_sha256"]) == b'[{"id":9}]'
    assert state["query_started_at"] <= record["request_started_at"]


def test_repeated_first_page_drift_has_bounded_restart_budget(tmp_path):
    reads = 0
    def moving(url):
        nonlocal reads
        if url == METADATA:
            return Reply(PUBLIC)
        if url == EVENTS:
            reads += 1
            return Reply(json.dumps([{"id": reads}]).encode(), LINK)
        return Reply(b'[{"id":99}]')
    api, cp, _ = client(tmp_path, moving)
    result = api.collect_resumable("test/repo", "events")
    assert reads == 4
    assert result["scopes"]["events"]["status"] == "partial_drift"
    assert "restart budget exhausted" in result["failures"][0]
    assert "events" not in result["watermark_candidates"]
    assert len([event for event in cp.events if event["kind"] == "scope_abandoned"]) == 1
    assert len([record for record in cp.responses() if record["url"] == EVENTS]) == 4


def test_failed_scope_does_not_suppress_others_and_retry_skips_successes(tmp_path):
    def unavailable(url):
        if url == METADATA:
            return Reply(PUBLIC)
        if urlsplit(url).path.endswith("/issues"):
            raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b'{"message":"Not Found"}'))
        return Reply(b"[]")
    api, _, calls = client(tmp_path, unavailable)
    result = api.collect_resumable("test/repo", "full")
    assert result["scopes"]["issues"]["status"] == "unavailable"
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert len(calls) == 8
    assert "issues" not in result["watermark_candidates"]
    retry, cp, retried = client(tmp_path, lambda url: Reply(b"[]"))
    recovered = retry.collect_resumable("test/repo", "full")
    assert len(retried) == 1 and urlsplit(retried[0]).path.endswith("/issues")
    assert recovered["failures"] == []
    assert any(record["status"] == 404 for record in cp.responses())


@pytest.mark.parametrize("status,headers", [(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1120"}),
                                            (429, {"Retry-After": "120"}),
                                            (403, {"Retry-After": "120"})])
def test_checkpoint_rates_defer_without_sleep_or_losing_refusal(tmp_path, monkeypatch, status, headers):
    clock = [1000.0]
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: clock[0])
    monkeypatch.setattr("icsot_observer.github.time.sleep", lambda seconds: pytest.fail("checkpoint mode slept"))
    def limited(url):
        if url == METADATA:
            return Reply(PUBLIC)
        raise urllib.error.HTTPError(url, status, "rate", headers, io.BytesIO(b'{"message":"rate limit"}'))
    api, cp, calls = client(tmp_path, limited)
    result = api.collect_resumable("test/repo", "events")
    outcome = result["scopes"]["events"]
    assert calls == [METADATA, EVENTS]
    assert outcome["status"] == "deferred" and outcome["retry_not_before"] >= 1120
    assert outcome["lane_wide"] is True
    assert cp.responses()[-1]["status"] == status
    assert cp.scope_state("events")["outcome"]["status"] == "deferred"
    early, _, early_calls = client(tmp_path, lambda url: pytest.fail("early retry"))
    assert early.collect_resumable("test/repo", "events")["deferred"]["retry_not_before"] >= 1120
    assert early_calls == []
    clock[0] = 1122
    retry, _, retry_calls = client(tmp_path, lambda url: Reply(b"[]"))
    assert retry.collect_resumable("test/repo", "events")["failures"] == []
    assert retry_calls == [EVENTS]


def test_lane_wide_deferral_prevents_later_requests_but_reports_scopes(tmp_path, monkeypatch):
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000.0)
    def limited(url):
        if url == METADATA:
            return Reply(PUBLIC)
        raise urllib.error.HTTPError(url, 429, "rate", {"Retry-After": "120"}, io.BytesIO(b"{}"))
    api, cp, calls = client(tmp_path, limited)
    result = api.collect_resumable("test/repo", "full")
    assert len(calls) == 2
    assert all(result["scopes"][name]["status"] == "deferred" for name in ("issues", "pulls", "tags", "events"))
    assert any(event["kind"] == "scope_not_started" for event in cp.events)


def test_corrupt_cached_body_is_refused_without_a_fresh_observation(tmp_path):
    api, _, _ = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else FIRST_BODY))
    api.collect_resumable("test/repo", "events")
    api.store.location(sha256(FIRST_BODY)).write_bytes(b"tampered")
    retry, _, calls = client(tmp_path, lambda url: pytest.fail(url))
    result = retry.collect_resumable("test/repo", "events")
    assert calls == []
    assert result["scopes"]["events"]["status"] == "checkpoint_invalid"
    assert "events" not in result["watermark_candidates"]
    assert "CAS missing or corrupt" in result["failures"][0]


@pytest.mark.parametrize("change", [{"max_pages": 9}, {"max_response_bytes": 99}, {"api_version": "2025-01-01"}])
def test_changed_capture_options_are_rejected_before_network(tmp_path, change):
    api, _, _ = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else b"[]"))
    api.collect_resumable("test/repo", "events")
    changed, _, calls = client(tmp_path, lambda url: pytest.fail(url), config=replace(api.config, **change))
    with pytest.raises(CheckpointError, match="query/options changed"):
        changed.collect_resumable("test/repo", "events")
    assert calls == []


def test_changed_since_and_deep_options_are_rejected(tmp_path):
    api, _, _ = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else b"[]"))
    api.collect_resumable("test/repo", "full")
    with pytest.raises(CheckpointError, match="query/options changed"):
        api.collect_resumable("test/repo", "full", deep_full=True)
    with pytest.raises(CheckpointError, match="query/options changed"):
        api.collect_resumable("test/repo", "delta", scope_since={"issues": "2026-10-20T00:00:00Z"})


@pytest.mark.parametrize("next_url", [EVENTS.replace("per_page=100", "per_page=1") + "&page=2",
                                      SECOND.replace("/42/", "/999/"),
                                      SECOND.replace("/events?", "/issues?"),
                                      SECOND + "&since=2020-01-01T00%3A00%3A00Z"])
def test_checkpoint_rejects_changed_page_query_or_repository_before_request(tmp_path, next_url):
    api, cp, calls = client(tmp_path, lambda url: Reply(PUBLIC) if url == METADATA else Reply(FIRST_BODY, {"Link": f'<{next_url}>; rel="next"'}))
    result = api.collect_resumable("test/repo", "events")
    assert calls == [METADATA, EVENTS]
    assert result["scopes"]["events"]["status"] == "checkpoint_invalid"
    assert len(cp.responses()) == 2  # rejected source bytes still durable


def test_max_page_cap_is_partial_and_never_yields_candidate(tmp_path):
    api, cp, _ = client(tmp_path, lambda url: Reply(PUBLIC) if url == METADATA else Reply(FIRST_BODY, LINK))
    api.config = replace(api.config, max_pages=1)
    result = api.collect_resumable("test/repo", "events")
    assert result["scopes"]["events"]["status"] == "capped"
    assert "events" not in result["watermark_candidates"]
    assert len(cp.scope_state("events")["pages"]) == 1


def test_scoped_since_is_exact_and_candidates_use_query_start_not_finish(tmp_path):
    api, _, calls = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else b"[]"))
    boundaries = {"issues": "2026-10-20T00:00:00Z", "pulls": None,
                  "issue_comments": "2026-10-19T00:00:00Z"}
    result = api.collect_resumable("test/repo", "delta", scope_since=boundaries)
    urls = {urlsplit(url).path: parse_qs(urlsplit(url).query) for url in calls}
    assert urls["/repos/test/repo/issues"]["since"] == [boundaries["issues"]]
    assert urls["/repos/test/repo/issues/comments"]["since"] == [boundaries["issue_comments"]]
    assert "since" not in urls["/repos/test/repo/pulls"]
    for scope, watermark in result["watermark_candidates"].items():
        outcome = result["scopes"][scope]
        assert watermark == outcome["query_started_at"] < outcome["completed_at"]


def test_deep_scope_caps_preserve_other_successes(tmp_path):
    def respond(url):
        path = urlsplit(url).path
        if url == METADATA:
            return Reply(PUBLIC)
        if path in ("/repos/test/repo/issues", "/repos/test/repo/pulls"):
            return Reply(b'[{"id":1,"number":3,"pull_request":{}}]')
        if path == "/repos/test/repo/pulls/3":
            return Reply(b'{"commits":251,"changed_files":3001}')
        return Reply(b"[]")
    api, _, _ = client(tmp_path, respond)
    result = api.collect_resumable("test/repo", "full", deep_full=True)
    assert result["scopes"]["pull_commits:3"]["status"] == "capped"
    assert result["scopes"]["pull_files:3"]["status"] == "capped"
    assert result["scopes"]["pull_reviews:3"]["status"] == "complete_for_query"
    assert result["scopes"]["deep_pull_details"]["status"] == "partial"
    assert "pull_commits:3" not in result["watermark_candidates"]


def test_ledger_detects_corruption_deletion_and_root_rebinding(tmp_path):
    cp = CheckpointStore(tmp_path, 42, "capture-1")
    cp.append("one", {"value": 1})
    cp.append("two", {"value": 2})
    files = sorted(cp.home.glob("*.event.json"))
    original = files[0].read_bytes()
    event = json.loads(original)
    event["data"]["value"] = 99
    files[0].write_bytes(canonical_json(event))
    with pytest.raises(CheckpointError, match="Corrupt"):
        CheckpointStore(tmp_path, 42, "capture-1")
    files[0].write_bytes(original)
    files[0].unlink()
    with pytest.raises(CheckpointError, match="Corrupt"):
        CheckpointStore(tmp_path, 42, "capture-1")
    relocated = tmp_path / "new-root"
    shutil.copytree(tmp_path / "checkpoints", relocated / "checkpoints")
    with pytest.raises(CheckpointError, match="binding changed"):
        CheckpointStore(relocated, 42, "capture-1")


def test_binding_validation_and_concurrent_writer_refusal(tmp_path):
    with pytest.raises(ValueError):
        CheckpointStore(tmp_path, 0, "capture-1")
    with pytest.raises(ValueError):
        CheckpointStore(tmp_path, 42, "../other")
    first = CheckpointStore(tmp_path, 42, "capture-1")
    second = CheckpointStore(tmp_path, 42, "capture-1")
    first.append("event", {})
    with pytest.raises(CheckpointError, match="Concurrent"):
        second.append("event", {})


def test_identity_envelope_is_bound_and_durable_before_next_request(tmp_path):
    cfg = Config(root=tmp_path, repositories=("test/repo",), api_version="2026-03-10",
                 user_agent="test", token_env="CHECKPOINT_TEST_NO_TOKEN", http_timeout_seconds=5,
                 max_response_bytes=1000000, overlap_hours=48, max_pages=100)
    records = []
    identity = GitHubAPI(cfg, ObjectStore(tmp_path), records)
    identity.opener.open = lambda request, timeout: Reply(PUBLIC)
    identity.get_json("/repos/test/repo", "repository_identity")
    original_start = records[0]["request_started_at"]
    bound, cp, _ = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else b"[]"), records=records)
    assert cp.responses()[0]["purpose"] == "repository_identity"
    assert cp.responses()[0]["request_started_at"] == original_start
    result = bound.collect_resumable("test/repo", "events")
    assert result["failures"] == []


def test_checkpoint_reserve_defers_before_request_and_can_retry_same_instance(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: clock[0])
    monkeypatch.setattr("icsot_observer.github.time.sleep", lambda seconds: pytest.fail("checkpoint mode slept"))
    def reply(url):
        if url == METADATA:
            return Reply(PUBLIC, {"X-RateLimit-Remaining": "39", "X-RateLimit-Reset": "1060"})
        return Reply(b"[]")
    api, cp, calls = client(tmp_path, reply)
    api.config = replace(api.config, primary_rate_reserve=40)
    result = api.collect_resumable("test/repo", "events")
    assert calls == [METADATA]
    assert result["scopes"]["events"]["status"] == "deferred"
    assert cp.responses()[-1]["status"] == 200  # no fictional HTTP refusal
    clock[0] = 1062
    result = api.collect_resumable("test/repo", "events")
    assert result["failures"] == []
    assert calls == [METADATA, EVENTS]


def test_byte_cap_preserves_truncated_diagnostic_without_completion(tmp_path):
    api, cp, calls = client(tmp_path, lambda url: Reply(PUBLIC if url == METADATA else b"[" + b" " * 100))
    api.config = replace(api.config, max_response_bytes=len(PUBLIC) + 1)
    result = api.collect_resumable("test/repo", "events")
    assert result["scopes"]["events"]["status"] == "capped"
    record = cp.responses()[-1]
    assert record["error"] == "RESPONSE_EXCEEDS_CAP"
    assert record["body_bytes"] == api.config.max_response_bytes + 1
    assert "events" not in result["watermark_candidates"]


def test_missing_identity_reports_unattempted_scopes_without_faking_empty(tmp_path):
    def missing(url):
        raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b"{}"))
    api, _, calls = client(tmp_path, missing)
    result = api.collect_resumable("test/repo", "full")
    assert calls == [METADATA]
    assert result["scopes"]["repository_metadata"]["status"] == "unavailable"
    assert result["scopes"]["issues"]["status"] == "not_attempted"
    assert "count" not in result["scopes"]["issues"]
    assert result["watermark_candidates"] == {}


def test_rate_deferral_survives_crash_before_scope_failure_record(tmp_path, monkeypatch):
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000.0)
    def limited(url):
        if url == METADATA:
            return Reply(PUBLIC)
        raise urllib.error.HTTPError(url, 429, "rate", {"Retry-After": "120"}, io.BytesIO(b"{}"))
    api, cp, _ = client(tmp_path, limited)
    append = cp.append
    def interrupted_append(kind, data):
        if kind == "scope_failed":
            raise Crash()
        return append(kind, data)
    cp.append = interrupted_append
    with pytest.raises(Crash):
        api.collect_resumable("test/repo", "events")
    disk = CheckpointStore(tmp_path, 42, "capture-1")
    assert disk.events[-1]["kind"] == "rate_deferral"
    assert disk.scope_state("events")["outcome"] is None
    retry, _, calls = client(tmp_path, lambda url: pytest.fail("rate refusal was lost"))
    result = retry.collect_resumable("test/repo", "events")
    assert result["scopes"]["events"]["status"] == "deferred"
    assert calls == []


def test_crash_after_durable_abandon_starts_replacement_without_reusing_old_pages(tmp_path):
    reads = 0
    def drifting(url):
        nonlocal reads
        if url == METADATA:
            return Reply(PUBLIC)
        if url == EVENTS:
            reads += 1
            return Reply(FIRST_BODY, LINK) if reads == 1 else Reply(b'[{"id":9}]')
        return Reply(b'[{"id":2}]')
    api, cp, _ = client(tmp_path, drifting)
    append = cp.append
    def interrupted_append(kind, data):
        event = append(kind, data)
        if kind == "scope_abandoned":
            raise Crash()
        return event
    cp.append = interrupted_append
    with pytest.raises(Crash):
        api.collect_resumable("test/repo", "events")
    retry, cp, calls = client(tmp_path, lambda url: Reply(b'[{"id":9}]'))
    result = retry.collect_resumable("test/repo", "events")
    assert result["scopes"]["events"]["count"] == 1
    assert calls == [EVENTS]
    assert cp.scope_state("events")["restarts"] == 1
    assert ObjectStore(tmp_path).get(sha256(FIRST_BODY)) == FIRST_BODY


def test_reuse_validates_cas_from_abandoned_attempt_too(tmp_path):
    reads = 0
    def drifting(url):
        nonlocal reads
        if url == METADATA:
            return Reply(PUBLIC)
        if url == EVENTS:
            reads += 1
            return Reply(FIRST_BODY, LINK) if reads == 1 else Reply(b'[{"id":9}]')
        return Reply(b'[{"id":2}]')
    api, _, _ = client(tmp_path, drifting)
    assert api.collect_resumable("test/repo", "events")["failures"] == []
    api.store.location(sha256(FIRST_BODY)).write_bytes(b"damaged abandoned attempt")
    retry, _, calls = client(tmp_path, lambda url: pytest.fail(url))
    result = retry.collect_resumable("test/repo", "events")
    assert calls == []
    assert result["scopes"]["events"]["status"] == "checkpoint_invalid"
    assert "events" not in result["watermark_candidates"]


def test_incomplete_deep_pr_withholds_both_parent_cursors_until_old_item_repaired(tmp_path):
    old_cursor = "1999-01-01T00:00:00Z"
    updated = "2000-01-01T00:00:00Z"
    item = {"id": 7, "number": 7, "updated_at": updated, "pull_request": {}}
    def handler(url, fail_files):
        path, params = urlsplit(url).path, parse_qs(urlsplit(url).query)
        if url == METADATA:
            return Reply(PUBLIC)
        if path == "/repos/test/repo/issues":
            # The unchanged old PR would be omitted after an incorrect advance.
            return Reply(json.dumps([item] if params["since"][0] <= updated else []).encode())
        if path == "/repos/test/repo/pulls":
            return Reply(json.dumps([item]).encode())
        if path == "/repos/test/repo/pulls/7":
            return Reply(b'{"commits":1,"changed_files":1}')
        if path == "/repos/test/repo/pulls/7/files" and fail_files:
            raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b"{}"))
        return Reply(b"[]")
    boundaries = {"issues": old_cursor, "pulls": old_cursor}
    first, _, _ = client(tmp_path, lambda url: handler(url, True))
    partial = first.collect_resumable("test/repo", "delta", scope_since=boundaries)
    assert partial["scopes"]["issues"]["status"] == "complete_for_query"
    assert partial["scopes"]["pull_files:7"]["status"] == "unavailable"
    assert "issues" not in partial["watermark_candidates"]
    assert "pulls" not in partial["watermark_candidates"]
    assert partial["watermark_withheld"]["issues"]["incomplete_scopes"] == ["pull_files:7"]
    assert partial["watermark_withheld"]["pulls"]["incomplete_scopes"] == ["pull_files:7"]
    assert "tags" in partial["watermark_candidates"]
    assert partial["scopes"]["issues"]["query_started_at"] > updated
    # Model committing only candidates after the partial immutable manifest. The
    # next capture keeps its original parent cursors even after overlap expires.
    next_boundaries = {name: partial["watermark_candidates"].get(name, value)
                       for name, value in boundaries.items()}
    second, _, calls = client(tmp_path, lambda url: handler(url, False), capture="capture-2")
    repaired = second.collect_resumable("test/repo", "delta", scope_since=next_boundaries)
    assert next_boundaries == boundaries
    assert any(urlsplit(url).path == "/repos/test/repo/pulls/7/files" for url in calls)
    assert repaired["failures"] == []
    assert repaired["watermark_withheld"] == {}
    assert all(name in repaired["watermark_candidates"] for name in boundaries)


def test_failed_issue_timeline_withholds_its_parent_without_blocking_unrelated_cursor(tmp_path):
    def handler(url):
        path = urlsplit(url).path
        if url == METADATA:
            return Reply(PUBLIC)
        if path == "/repos/test/repo/issues":
            return Reply(b'[{"id":1,"number":1}]')
        if path == "/repos/test/repo/issues/1/timeline":
            raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b"{}"))
        return Reply(b"[]")
    api, _, _ = client(tmp_path, handler)
    result = api.collect_resumable("test/repo", "delta", scope_since={
        "issues": "2026-01-01T00:00:00Z", "pulls": "2026-01-01T00:00:00Z"})
    assert "issues" not in result["watermark_candidates"]
    assert "pulls" in result["watermark_candidates"]
    assert result["watermark_withheld"]["issues"]["incomplete_scopes"] == ["issue_timeline:1"]


def test_mixed_delta_missing_parent_cursor_is_shallow_repair_with_bounded_other_parent(tmp_path):
    def handler(url):
        path = urlsplit(url).path
        if url == METADATA:
            return Reply(PUBLIC)
        if path == "/repos/test/repo/issues":
            return Reply(b'[{"id":1,"number":1,"pull_request":{}},{"id":2,"number":2}]')
        if path == "/repos/test/repo/pulls":
            return Reply(b'[{"id":3,"number":3,"updated_at":"2026-10-24T00:00:00Z"},'
                         b'{"id":4,"number":4,"updated_at":"2000-01-01T00:00:00Z"}]')
        if path == "/repos/test/repo/pulls/3":
            return Reply(b'{"commits":1,"changed_files":1}')
        return Reply(b"[]")
    api, _, calls = client(tmp_path, handler)
    result = api.collect_resumable("test/repo", "delta", scope_since={
        "issues": None, "pulls": "2026-10-20T00:00:00Z"})
    issue = result["scopes"]["issues"]
    assert issue["query_mode"] == "full_shallow_repair"
    assert issue["deep_selection"] == "not_requested_for_full_listing"
    assert issue["skipped_historical_deep_count"] == 2
    assert issue["selected_deep_item_count"] == 0
    assert result["scopes"]["pulls"]["query_mode"] == "delta"
    assert result["scopes"]["pulls"]["selected_deep_item_count"] == 1
    deep_urls = [urlsplit(url).path for url in calls if "/pulls/" in urlsplit(url).path or "/issues/" in urlsplit(url).path]
    assert "/repos/test/repo/pulls/3/files" in deep_urls
    assert "/repos/test/repo/issues/3/timeline" in deep_urls
    assert not any(path in deep_urls for path in ("/repos/test/repo/issues/1/timeline",
                                                 "/repos/test/repo/issues/2/timeline",
                                                 "/repos/test/repo/issues/4/timeline"))
    assert result["scopes"]["deep_pull_details"]["claim_scope"] == "requested_delta_or_explicit_deep_full_items"
    assert result["scopes"]["deep_pull_details"]["requested_parent_scopes"] == ["pulls"]
    assert result["scopes"]["deep_pull_details"]["status"] == "complete_for_requested_items"


def test_delta_without_parent_cursors_skips_historical_deep_unless_explicitly_requested(tmp_path):
    def handler(url):
        path = urlsplit(url).path
        if url == METADATA:
            return Reply(PUBLIC)
        if path in ("/repos/test/repo/issues", "/repos/test/repo/pulls"):
            return Reply(b'[{"id":1,"number":1,"pull_request":{}}]')
        if path == "/repos/test/repo/pulls/1":
            return Reply(b'{"commits":1,"changed_files":1}')
        return Reply(b"[]")
    shallow, _, shallow_calls = client(tmp_path, handler)
    result = shallow.collect_resumable("test/repo", "delta", scope_since={"issues": None, "pulls": None})
    assert len(shallow_calls) == 8
    assert result["scopes"]["deep_issue_timeline"]["status"] == "NOT_REQUESTED"
    assert result["scopes"]["issues"]["skipped_historical_deep_count"] == 1
    assert result["scopes"]["pulls"]["skipped_historical_deep_count"] == 1
    assert all(name in result["watermark_candidates"] for name in ("issues", "pulls"))
    deep, _, deep_calls = client(tmp_path, handler, capture="explicit-deep")
    requested = deep.collect_resumable("test/repo", "delta", deep_full=True,
                                       scope_since={"issues": None, "pulls": None})
    assert requested["scopes"]["issues"]["deep_selection"] == "explicit_deep_full"
    assert requested["scopes"]["deep_pull_details"]["count"] == 1
    assert sum(urlsplit(url).path == "/repos/test/repo/issues/1/timeline" for url in deep_calls) == 1
    assert sum(urlsplit(url).path == "/repos/test/repo/pulls/1/files" for url in deep_calls) == 1


def test_unbound_identity_can_opt_into_immediate_rate_deferral(tmp_path, monkeypatch):
    api, _, _ = client(tmp_path, lambda url: Reply(PUBLIC))
    identity = GitHubAPI(api.config, api.store, [], defer_on_rate=True)
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000.0)
    monkeypatch.setattr("icsot_observer.github.time.sleep", lambda seconds: pytest.fail("identity slept"))
    def limited(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 429, "rate", {"Retry-After": "3600"}, io.BytesIO(b"{}"))
    identity.opener.open = limited
    with pytest.raises(APIRequestDeferred) as caught:
        identity.get_json("/repos/test/repo", "repository_identity")
    assert caught.value.retry_not_before == 4600
    assert identity.records[-1]["status"] == 429
    assert identity.store.get(identity.records[-1]["body_sha256"]) == b"{}"


def test_primary_reserve_deferral_honors_announced_distant_reset(tmp_path, monkeypatch):
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000.0)
    api, cp, calls = client(tmp_path, lambda url: Reply(PUBLIC, {
        "X-RateLimit-Remaining": "39", "X-RateLimit-Reset": "4000"}))
    api.config = replace(api.config, primary_rate_reserve=40)
    result = api.collect_resumable("test/repo", "events")
    assert calls == [METADATA]
    assert result["deferred"]["retry_not_before"] == 4001
    assert cp.events[-2]["kind"] == "rate_deferral"


def test_resume_accepts_representation_change_without_relabeling_original_page(tmp_path):
    old_body = b'[{"id":1,"nested":{"count":10}}]'
    fresh_body = b'[{"id":1,"nested":{"count":11}}]'
    def interrupted(url):
        if url == METADATA:
            return Reply(PUBLIC)
        if url == EVENTS:
            return Reply(old_body, LINK)
        raise Crash()
    api, cp, _ = client(tmp_path, interrupted)
    with pytest.raises(Crash):
        api.collect_resumable("test/repo", "events")
    original_query_start = cp.scope_state("events")["query_started_at"]
    original_record = next(record for record in api.records if record["url"] == EVENTS)
    def repaired(url):
        return Reply(fresh_body, LINK) if url == EVENTS else Reply(b'[{"id":2}]')
    retry, cp, calls = client(tmp_path, repaired)
    result = retry.collect_resumable("test/repo", "events")
    assert calls == [EVENTS, SECOND, EVENTS]
    assert result["watermark_candidates"]["events"] == original_query_start
    assert result["scopes"]["events"]["representation_changed_during_validation"] is True
    assert not any(event["kind"] == "scope_abandoned" for event in cp.events)
    original_page = cp.response(cp.scope_state("events")["pages"][0]["response_sequence"])
    assert original_page["body_sha256"] == original_record["body_sha256"]
    assert original_page["request_started_at"] == original_record["request_started_at"]
    assert original_page["request_completed_at"] == original_record["request_completed_at"]
    assert retry.store.get(original_page["body_sha256"]) == old_body
    assert retry.store.get(sha256(fresh_body)) == fresh_body


def test_malformed_json_diagnostic_is_durable_before_retry_and_survives_crash(tmp_path):
    reads = 0
    bad = b'[{"id":'
    def interrupted(url):
        nonlocal reads
        if url == METADATA:
            return Reply(PUBLIC)
        reads += 1
        if reads == 1:
            return Reply(bad)
        disk = CheckpointStore(tmp_path, 42, "capture-1")
        event = disk.events[-1]
        assert event["kind"] == "response_decode_error"
        original = disk.response(event["data"]["response_sequence"])
        assert original["status"] == 200
        assert ObjectStore(tmp_path).get(original["body_sha256"]) == bad
        raise Crash()
    api, _, _ = client(tmp_path, interrupted)
    with pytest.raises(Crash):
        api.collect_resumable("test/repo", "events")
    retry, cp, calls = client(tmp_path, lambda url: Reply(b'[{"id":1}]'))
    result = retry.collect_resumable("test/repo", "events")
    assert calls == [EVENTS]
    assert result["failures"] == []
    assert len(result["decode_errors"]) == 1
    assert retry.store.get(result["decode_errors"][0]["body_sha256"]) == bad
    assert len(cp.scope_state("events")["pages"]) == 1


def test_bound_identity_get_json_persists_decode_annotation_even_outside_scope(tmp_path):
    reads = 0
    def handler(url):
        nonlocal reads
        reads += 1
        return Reply(b"{") if reads == 1 else Reply(PUBLIC)
    api, cp, _ = client(tmp_path, handler)
    assert api.get_json("/repos/test/repo", "repository_identity")["id"] == 42
    errors = [event for event in cp.events if event["kind"] == "response_decode_error"]
    assert len(errors) == 1
    assert cp.response(errors[0]["data"]["response_sequence"])["purpose"] == "repository_identity"
