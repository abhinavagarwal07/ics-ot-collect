"""Regression coverage for real baseline failures, on both collection paths."""
import io
import json
import urllib.error
from dataclasses import replace
from urllib.parse import urlsplit

import pytest

from icsot_observer.checkpoints import CheckpointStore
from icsot_observer.core import Config, ObjectStore, sha256
from icsot_observer.github import GitHubAPI


META_URL = "https://api.github.com/repos/test/repo"
EVENT_URL = META_URL + "/events?per_page=100"
EVENT_NEXT = "https://api.github.com/repositories/42/events?per_page=100&page=2"
EVENT_LINK = {"Link": f'<{EVENT_NEXT}>; rel="next"'}
PUBLIC = {"id": 42, "private": False, "full_name": "test/repo"}


class Reply:
    status = 200

    def __init__(self, body, headers=None):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, maximum):
        return self.body[:maximum]


@pytest.fixture(params=[False, True], ids=["legacy", "checkpointed"])
def collector(request, tmp_path, monkeypatch):
    checkpointed = request.param
    cfg = Config(root=tmp_path, repositories=("test/repo",), api_version="2026-03-10",
                 user_agent="test", token_env="API_RECOVERY_TEST_NO_TOKEN", http_timeout_seconds=5,
                 max_response_bytes=1000000, overlap_hours=48, max_pages=100)
    cp = CheckpointStore(tmp_path, 42, "recovery") if checkpointed else None
    api = GitHubAPI(cfg, ObjectStore(tmp_path), [], cp)
    calls = []

    def configure(handler):
        def open_request(req, timeout):
            calls.append(req.full_url)
            return handler(req.full_url)
        api.opener.open = open_request

    def collect(mode="full", **kwargs):
        method = api.collect_resumable if checkpointed else api.collect
        return method("test/repo", mode, **kwargs)

    monkeypatch.setattr("icsot_observer.github.time.sleep", lambda delay: pytest.fail("unexpected sleep"))
    return api, cp, calls, configure, collect


def test_disabled_pr_capability_preserves_other_scopes_without_empty_pr_claim(collector):
    api, cp, calls, configure, collect = collector
    metadata = {**PUBLIC, "has_pull_requests": False}
    def handler(url):
        path = urlsplit(url).path
        if url == META_URL:
            return Reply(metadata)
        if path == "/repos/test/repo/issues":
            return Reply([{"id": 1, "number": 1}, {"id": 2, "number": 2, "pull_request": {}}])
        assert "/pulls" not in path
        assert path != "/repos/test/repo/issues/2/timeline"
        return Reply([])
    configure(handler)
    result = collect(deep_full=True)
    assert result["failures"] == []
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert result["scopes"]["issue_timeline:1"]["status"] == "complete_for_query"
    assert result["scopes"]["deep_issue_timeline"]["status"] == "partial"
    for scope in ("pulls", "review_comments", "issue_timeline:2", "pull_detail:2",
                  "pull_reviews:2", "pull_commits:2", "pull_files:2", "deep_pull_details"):
        outcome = result["scopes"][scope]
        assert outcome["status"] == "unavailable"
        assert outcome["reason"] == "repository_pull_requests_disabled"
        assert "count" not in outcome
        assert scope not in result["watermark_candidates"]
        evidence = outcome["capability"]["metadata_evidence"]
        assert json.loads(api.store.get(evidence["body_sha256"])) == metadata
        assert evidence["request_started_at"] <= evidence["request_completed_at"]
    assert "issues" not in result["watermark_candidates"]  # selected PR children unavailable
    assert "pull_files:2" in result["watermark_withheld"]["issues"]["incomplete_scopes"]
    assert all("/pulls" not in urlsplit(url).path for url in calls)
    if cp:
        assert any(event["kind"] == "scope_unavailable" for event in cp.events)


@pytest.mark.parametrize("capability", ["missing", None, True, 0, "false"])
def test_unknown_or_enabled_capability_never_turns_pr_404_into_empty_complete(collector, capability):
    api, cp, calls, configure, collect = collector
    metadata = dict(PUBLIC)
    if capability != "missing":
        metadata["has_pull_requests"] = capability
    def handler(url):
        if url == META_URL:
            return Reply(metadata)
        if urlsplit(url).path == "/repos/test/repo/pulls":
            raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b'{"message":"Not Found"}'))
        return Reply([])
    configure(handler)
    result = collect()
    assert any(urlsplit(url).path == "/repos/test/repo/pulls" for url in calls)
    assert result["scopes"]["pulls"]["status"] == "unavailable"
    assert result["scopes"]["pulls"].get("reason") != "repository_pull_requests_disabled"
    assert "count" not in result["scopes"]["pulls"]
    assert "pulls" not in result["watermark_candidates"]
    assert any(failure.startswith("pulls:") for failure in result["failures"])
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert any(record["status"] == 404 for record in api.records)


def test_creation_restriction_keeps_existing_pr_read_scope_enabled(collector):
    _, _, calls, configure, collect = collector
    configure(lambda url: Reply({**PUBLIC, "has_pull_requests": True,
                                  "pull_request_creation_policy": "collaborators_only"}) if url == META_URL else Reply([]))
    result = collect()
    assert result["scopes"]["pulls"]["status"] == "complete_for_query"
    assert any(urlsplit(url).path == "/repos/test/repo/pulls" for url in calls)


def test_representation_only_first_page_change_is_retained_without_restart(collector):
    api, cp, calls, configure, collect = collector
    original = [{"id": "1", "repo": {"watchers_count": 10}, "updated_at": "2026-10-20T00:00:00Z"}]
    changed = [{"id": "1", "repo": {"watchers_count": 11}, "updated_at": "2026-10-21T00:00:00Z"}]
    first_reads = 0
    def handler(url):
        nonlocal first_reads
        if url == META_URL:
            return Reply(PUBLIC)
        if url == EVENT_URL:
            first_reads += 1
            return Reply(original if first_reads == 1 else changed, EVENT_LINK)
        assert url == EVENT_NEXT
        return Reply([{"id": "2"}])
    configure(handler)
    result = collect("events")
    outcome = result["scopes"]["events"]
    assert result["failures"] == []
    assert outcome["status"] == "complete_for_query" and outcome["count"] == 2
    assert outcome["pagination_attempts"] == 1
    assert outcome["representation_changed_during_validation"] is True
    assert outcome["claim_scope"] == "non_atomic_response_intervals"
    assert outcome["interpretation"] == "OPPORTUNISTIC_NOT_COMPLETE"
    assert calls == [META_URL, EVENT_URL, EVENT_NEXT, EVENT_URL]
    first_responses = [record for record in api.records if record["url"] == EVENT_URL]
    assert [json.loads(api.store.get(record["body_sha256"])) for record in first_responses] == [original, changed]
    assert first_responses[0]["request_completed_at"] <= first_responses[1]["request_started_at"]
    if cp:
        state = cp.scope_state("events")
        first_page = cp.response(state["pages"][0]["response_sequence"])
        assert json.loads(api.store.get(first_page["body_sha256"])) == original
        assert any(event["kind"] == "scope_validation" and event["data"]["representation_changed"] for event in cp.events)


@pytest.mark.parametrize("drift", ["membership", "order", "duplicate"])
def test_true_page_drift_restarts_entire_scope_once_and_retains_old_attempt(collector, drift):
    api, cp, _, configure, collect = collector
    first_reads, second_reads = 0, 0
    old_first = [{"id": 1}, {"id": 2}]
    new_first = [{"id": 2}, {"id": 1}] if drift == "order" else [{"id": 4}, {"id": 2}]
    bad_second = [{"id": 2}, {"id": 3}] if drift == "duplicate" else [{"id": 3}]
    def handler(url):
        nonlocal first_reads, second_reads
        if url == META_URL:
            return Reply(PUBLIC)
        if url == EVENT_URL:
            first_reads += 1
            return Reply(old_first if first_reads == 1 else new_first, EVENT_LINK)
        assert url == EVENT_NEXT
        second_reads += 1
        return Reply(bad_second if second_reads == 1 else [{"id": 3}])
    configure(handler)
    result = collect("events")
    assert result["failures"] == []
    assert result["scopes"]["events"]["pagination_attempts"] == 2
    assert result["scopes"]["events"]["count"] == 3
    assert second_reads == 2
    archived = [json.loads(api.store.get(record["body_sha256"])) for record in api.records]
    assert old_first in archived and bad_second in archived and new_first in archived
    first_records = [record for record in api.records if record["url"] == EVENT_URL]
    accepted = first_records[1 if drift == "duplicate" else 2]
    previous = api.records[api.records.index(accepted) - 1]
    candidate = result["watermark_candidates"]["events"]
    assert previous["request_completed_at"] <= candidate <= accepted["request_started_at"]
    if cp:
        assert len([event for event in cp.events if event["kind"] == "scope_abandoned"]) == 1
        state = cp.scope_state("events")
        accepted_first = cp.response(state["pages"][0]["response_sequence"])
        assert json.loads(api.store.get(accepted_first["body_sha256"])) == new_first


@pytest.mark.parametrize("drift", ["duplicate", "unknown_identity", "cursor"])
def test_persistent_drift_is_bounded_partial_and_keeps_other_good_scopes(collector, drift):
    _, cp, calls, configure, collect = collector
    first_reads = 0
    def handler(url):
        nonlocal first_reads
        if url == META_URL:
            return Reply(PUBLIC)
        if url == EVENT_URL:
            first_reads += 1
            if drift == "unknown_identity":
                return Reply([{"unknown": first_reads}], EVENT_LINK)
            if drift == "cursor":
                return Reply([{"id": 1}], {"Link": f'<{EVENT_NEXT}&after={first_reads}>; rel="next"'})
            return Reply([{"id": 1}], EVENT_LINK)
        if urlsplit(url).path == "/repositories/42/events":
            return Reply([{"id": 1 if drift == "duplicate" else 2}])
        return Reply([])
    configure(handler)
    result = collect()
    assert result["scopes"]["events"]["status"] == "partial_drift"
    assert "events" not in result["watermark_candidates"]
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert len([url for url in calls if "/events?" in url]) <= 6
    assert any(failure.startswith("events:") for failure in result["failures"])
    if cp:
        assert cp.scope_state("events")["outcome"]["status"] == "partial_drift"


@pytest.mark.parametrize("malformed", [b'{"truncated":', b'\xff'])
def test_malformed_success_metadata_retries_preserving_each_raw_envelope(collector, malformed):
    api, cp, calls, configure, collect = collector
    metadata_reads = 0
    def handler(url):
        nonlocal metadata_reads
        if url == META_URL:
            metadata_reads += 1
            return Reply(malformed) if metadata_reads == 1 else Reply(PUBLIC)
        return Reply([])
    configure(handler)
    result = collect()
    assert result["failures"] == [] and metadata_reads == 2
    assert result["decode_errors"][0]["purpose"] == "repository_metadata"
    assert api.store.get(result["decode_errors"][0]["body_sha256"]) == malformed
    assert [record["status"] for record in api.records[:2]] == [200, 200]
    assert api.records[0]["request_completed_at"] <= api.records[1]["request_started_at"]
    if cp:
        error = next(event for event in cp.events if event["kind"] == "response_decode_error")
        assert error["data"]["response_sequence"] == api.records[0]["checkpoint_provenance"]["event_sequence"]
        reloaded = CheckpointStore(cp.root, cp.repository_id, cp.capture_id)
        assert any(event["kind"] == "response_decode_error" for event in reloaded.events)


def test_malformed_success_second_page_retries_same_url_without_stitching(collector):
    api, cp, calls, configure, collect = collector
    second_reads = 0
    def handler(url):
        nonlocal second_reads
        if url == META_URL:
            return Reply(PUBLIC)
        if url == EVENT_URL:
            return Reply([{"id": 1}], EVENT_LINK)
        assert url == EVENT_NEXT
        second_reads += 1
        return Reply(b'[{"id":') if second_reads == 1 else Reply([{"id": 2}])
    configure(handler)
    result = collect("events")
    assert result["failures"] == []
    assert calls == [META_URL, EVENT_URL, EVENT_NEXT, EVENT_NEXT, EVENT_URL]
    assert result["scopes"]["events"]["count"] == 2
    assert api.store.get(sha256(b'[{"id":')) == b'[{"id":'
    if cp:
        assert len(cp.scope_state("events")["pages"]) == 2


def test_repeated_malformed_success_is_bounded_failure_without_erasing_good_scopes(collector):
    api, cp, calls, configure, collect = collector
    bad_reads = 0
    def handler(url):
        nonlocal bad_reads
        if url == META_URL:
            return Reply(PUBLIC)
        if url == EVENT_URL:
            bad_reads += 1
            return Reply(b'{"bad":' + str(bad_reads).encode())
        return Reply([])
    configure(handler)
    result = collect()
    assert bad_reads == 3
    assert result["scopes"]["events"]["status"] == "failed"
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert "events" not in result["watermark_candidates"]
    assert len(result["decode_errors"]) == 3
    assert all(api.store.get(error["body_sha256"]).startswith(b'{"bad":') for error in result["decode_errors"])
    if cp:
        assert cp.scope_state("events")["pages"] == []
        assert len([event for event in cp.events if event["kind"] == "response_decode_error"]) == 3


def test_wrong_json_shape_is_not_retried_or_accepted_as_empty(collector):
    _, _, calls, configure, collect = collector
    configure(lambda url: Reply(PUBLIC) if url == META_URL else Reply({}) if url == EVENT_URL else Reply([]))
    result = collect()
    assert result["scopes"]["events"]["status"] == "failed"
    assert calls.count(EVENT_URL) == 1
    assert "events" not in result["watermark_candidates"]
    assert result["scopes"]["tags"]["status"] == "complete_for_query"


def test_truncated_response_never_becomes_complete_after_json_retries(collector):
    api, _, calls, configure, collect = collector
    api.config = replace(api.config, max_response_bytes=80)
    configure(lambda url: Reply(PUBLIC) if url == META_URL else Reply(b"[" + b" " * 100) if url == EVENT_URL else Reply([]))
    result = collect()
    assert calls.count(EVENT_URL) == 1
    assert result["scopes"]["events"]["status"] in ("failed", "capped")
    assert "events" not in result["watermark_candidates"]
    assert result["decode_errors"] == []
    record = next(record for record in api.records if record["url"] == EVENT_URL)
    assert record["error"] == "RESPONSE_EXCEEDS_CAP"
    assert record["body_bytes"] == 81


def test_deep_endpoint_caps_withhold_selecting_parents_on_both_paths(collector):
    _, _, _, configure, collect = collector
    def handler(url):
        path = urlsplit(url).path
        if url == META_URL:
            return Reply(PUBLIC)
        if path in ("/repos/test/repo/issues", "/repos/test/repo/pulls"):
            return Reply([{"id": 7, "number": 7, "pull_request": {}}])
        if path == "/repos/test/repo/pulls/7":
            return Reply({"commits": 251, "changed_files": 3001})
        return Reply([])
    configure(handler)
    result = collect(deep_full=True)
    for child in ("pull_commits:7", "pull_files:7"):
        assert result["scopes"][child]["status"] == "capped"
        assert child not in result["watermark_candidates"]
    assert result["scopes"]["pull_reviews:7"]["status"] == "complete_for_query"
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert result["scopes"]["deep_pull_details"]["status"] == "partial"
    for parent in ("issues", "pulls"):
        assert parent not in result["watermark_candidates"]
        assert result["watermark_withheld"][parent]["incomplete_scopes"] == ["pull_commits:7", "pull_files:7"]


def test_tag_name_identity_accepts_changed_target_without_erasing_original_response(collector):
    api, _, _, configure, collect = collector
    first = META_URL + "/tags?per_page=100"
    second = "https://api.github.com/repositories/42/tags?per_page=100&page=2"
    link = {"Link": f'<{second}>; rel="next"'}
    old = [{"name": "v1", "commit": {"sha": "a" * 40}}]
    changed = [{"name": "v1", "commit": {"sha": "b" * 40}}]
    reads = 0
    def handler(url):
        nonlocal reads
        if url == META_URL:
            return Reply(PUBLIC)
        if url == first:
            reads += 1
            return Reply(old if reads == 1 else changed, link)
        if url == second:
            return Reply([{"name": "v0", "commit": {"sha": "c" * 40}}])
        return Reply([])
    configure(handler)
    result = collect()
    assert result["failures"] == []
    assert result["scopes"]["tags"]["count"] == 2
    assert result["scopes"]["tags"]["representation_changed_during_validation"] is True
    assert result["scopes"]["tags"]["pagination_attempts"] == 1
    records = [record for record in api.records if record["url"] == first]
    assert [json.loads(api.store.get(record["body_sha256"])) for record in records] == [old, changed]


@pytest.mark.parametrize("has_issues", [True, False, None, "missing"])
@pytest.mark.parametrize("has_pull_requests", [True, False, None, "missing"])
def test_issue_comment_feed_excluded_only_when_both_capabilities_explicitly_false(
        collector, has_issues, has_pull_requests):
    api, cp, calls, configure, collect = collector
    metadata = dict(PUBLIC)
    for field, value in (("has_issues", has_issues), ("has_pull_requests", has_pull_requests)):
        if value != "missing":
            metadata[field] = value
    comments_path = "/repos/test/repo/issues/comments"
    def handler(url):
        if url == META_URL:
            return Reply(metadata)
        if urlsplit(url).path == comments_path:
            raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b'{"message":"Not Found"}'))
        return Reply([])
    configure(handler)
    result = collect()
    outcome = result["scopes"]["issue_comments"]
    requested = any(urlsplit(url).path == comments_path for url in calls)
    excluded = has_issues is False and has_pull_requests is False
    assert requested is not excluded
    assert outcome["status"] == "unavailable"
    assert "count" not in outcome
    assert "issue_comments" not in result["watermark_candidates"]
    assert result["scopes"]["releases"]["status"] == "complete_for_query"
    assert result["scopes"]["tags"]["status"] == "complete_for_query"
    assert result["scopes"]["events"]["status"] == "complete_for_query"
    if excluded:
        assert result["failures"] == []
        assert outcome["reason"] == "repository_issues_and_pull_requests_disabled"
        assert outcome["capability"]["has_issues"] is False
        assert outcome["capability"]["has_pull_requests"] is False
        evidence = outcome["capability"]["metadata_evidence"]
        assert json.loads(api.store.get(evidence["body_sha256"])) == metadata
        assert evidence["request_started_at"] <= evidence["request_completed_at"]
        assert all(record["status"] == 200 for record in api.records)
        assert len(calls) == 5  # metadata, issues, releases, tags, events
        if cp:
            assert any(event["kind"] == "scope_unavailable" and event["data"]["scope"] == "issue_comments"
                       for event in cp.events)
    else:
        assert outcome.get("reason") != "repository_issues_and_pull_requests_disabled"
        assert any(failure.startswith("issue_comments:") for failure in result["failures"])
        assert any(record["status"] == 404 for record in api.records)
