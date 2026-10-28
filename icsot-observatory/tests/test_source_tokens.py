import io
import json
import os
import urllib.error

import pytest

from icsot_observer.checkpoints import CheckpointStore
from icsot_observer.core import Config, ObjectStore
from icsot_observer.diagnostics import diagnostic_context
from icsot_observer.github import APIRequestDeferred, GitHubAPI


PRIMARY = "synthetic-source-primary"
SECONDARY = "synthetic-source-secondary"


class Reply:
    status = 200

    def __init__(self, body=b"[]", headers=None):
        self.body, self.headers = body, headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, limit):
        return self.body[:limit]


def client(tmp_path, monkeypatch, *, secondary=SECONDARY, token_env="GITHUB_TOKEN",
           source_repository=None, checkpoint=None, **policy):
    monkeypatch.setenv(token_env, PRIMARY)
    if secondary is None:
        monkeypatch.delenv("COLLECTOR_READ_TOKEN_SECONDARY", raising=False)
    else:
        monkeypatch.setenv("COLLECTOR_READ_TOKEN_SECONDARY", secondary)
    monkeypatch.setenv("GH_TOKEN", "synthetic-destination")
    config = Config(root=tmp_path, repositories=("test/alpha", "test/beta"), api_version="2026-03-10",
                    user_agent="test", token_env=token_env, http_timeout_seconds=5,
                    max_response_bytes=10000, overlap_hours=48, max_pages=100, **policy)
    return GitHubAPI(config, ObjectStore(tmp_path), [], checkpoint_store=checkpoint,
                     source_repository=source_repository)


def record_requests(monkeypatch, api, replies):
    requested, pending = [], iter(replies)

    def open_request(request, timeout):
        requested.append((request.full_url, request.get_header("Authorization")))
        reply = next(pending)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(api.opener, "open", open_request)
    return requested


@pytest.mark.parametrize("token_env", ["GITHUB_TOKEN", "COLLECTOR_READ_TOKEN"])
def test_stable_partition_across_clients_case_scopes_and_pages(tmp_path, monkeypatch, token_env):
    first = client(tmp_path, monkeypatch, token_env=token_env)
    requested = record_requests(monkeypatch, first, [Reply()] * 4)
    for path in ("/repos/test/alpha/issues", "/repos/test/beta/issues",
                 "/repos/TEST/ALPHA/pulls?page=2", "/repos/test/beta/releases"):
        first.get("https://api.github.com" + path, "test")
    # Fixed vectors guard against process-randomized hash() and route/page-based selection.
    assert [auth for _, auth in requested] == [
        "Bearer " + PRIMARY, "Bearer " + SECONDARY, "Bearer " + PRIMARY, "Bearer " + SECONDARY]
    second = client(tmp_path, monkeypatch, token_env=token_env)
    again = record_requests(monkeypatch, second, [Reply(), Reply()])
    second.get(second.url("/repos/test/beta/tags"), "tags")
    second.get(second.url("/repos/test/alpha/events"), "events")
    assert [auth for _, auth in again] == ["Bearer " + SECONDARY, "Bearer " + PRIMARY]


@pytest.mark.parametrize("secondary", [None, "", "  ", PRIMARY])
def test_missing_or_duplicate_secondary_preserves_single_token(tmp_path, monkeypatch, secondary):
    api = client(tmp_path, monkeypatch, secondary=secondary)
    requested = record_requests(monkeypatch, api, [Reply()])
    api.get(api.url("/repositories/99/issues"), "issues")
    assert requested[0][1] == "Bearer " + PRIMARY


def test_secondary_does_not_override_custom_or_missing_primary(tmp_path, monkeypatch):
    custom = client(tmp_path, monkeypatch, token_env="CUSTOM_READ_TOKEN")
    requested = record_requests(monkeypatch, custom, [Reply()])
    custom.get(custom.url("/repos/test/beta/issues"), "issues")
    assert requested[0][1] == "Bearer " + PRIMARY
    standard = client(tmp_path, monkeypatch)
    monkeypatch.delenv("GITHUB_TOKEN")
    anonymous = GitHubAPI(standard.config, standard.store, [])
    requested = record_requests(monkeypatch, anonymous, [Reply()])
    anonymous.get(anonymous.url("/repos/test/alpha/issues"), "issues")
    assert requested[0][1] is None


def test_identity_numeric_pagination_and_rename_stay_on_job_slot(tmp_path, monkeypatch):
    api = client(tmp_path, monkeypatch, source_repository="test/alpha")
    numeric = "https://api.github.com/repositories/99/issues?per_page=100&page=2"
    first = Reply(b'[{"id":1}]', {"Link": '<' + numeric + '>; rel="next"'})
    requested = record_requests(monkeypatch, api, [
        Reply(b'{"id":99,"full_name":"test/beta"}'), first, Reply(b'[{"id":2}]'), first,
        first, Reply(b'[{"id":2}]'), first,
    ])
    api.get_json("/repos/test/alpha", "repository_identity")
    assert [item["id"] for item in api.list_pages("/repos/test/alpha/issues", "issues")] == [1, 2]
    assert [item["id"] for item in api.list_pages("/repos/test/beta/issues", "renamed_alias")] == [1, 2]
    assert {auth for _, auth in requested} == {"Bearer " + PRIMARY}


def test_restored_numeric_first_request_uses_current_job_partition(tmp_path, monkeypatch):
    checkpoint = CheckpointStore(tmp_path, 99, "resumed-api-job")
    # Historic data does not pin a later source client to its former primary credential.
    checkpoint.append("historic_single_token_observation", {"auth": "token_present"})
    api = client(tmp_path, monkeypatch, checkpoint=checkpoint, source_repository="test/beta")
    requested = record_requests(monkeypatch, api, [Reply()])
    api.get(api.url("/repositories/99/issues"), "issues")
    assert requested[0][1] == "Bearer " + SECONDARY


@pytest.mark.parametrize("path", ["/repositories/99/issues", "/repos/test/beta/issues"])
def test_unknown_or_other_repository_binding_fails_before_network(tmp_path, monkeypatch, path):
    api = client(tmp_path, monkeypatch, source_repository="test/alpha")
    requested = record_requests(monkeypatch, api, [])
    with pytest.raises(RuntimeError, match="credential binding unavailable"):
        api.get(api.url(path), "issues")
    assert requested == []


def test_shared_planner_unknown_numeric_binding_fails_before_network(tmp_path, monkeypatch):
    api = client(tmp_path, monkeypatch)
    requested = record_requests(monkeypatch, api, [])
    with pytest.raises(RuntimeError, match="credential binding unavailable"):
        api.get(api.url("/repositories/99/issues"), "issues")
    assert requested == []


def test_shared_planner_observed_alias_inherits_original_slot(tmp_path, monkeypatch):
    api = client(tmp_path, monkeypatch)
    requested = record_requests(monkeypatch, api, [
        Reply(b'{"id":99,"full_name":"test/beta"}'), Reply(), Reply()])
    api.get_json("/repos/test/alpha", "identity")
    api.get(api.url("/repos/test/beta/issues"), "renamed_alias")
    api.get(api.url("/repositories/99/issues"), "numeric_alias")
    assert {auth for _, auth in requested} == {"Bearer " + PRIMARY}


def test_conflicting_known_aliases_fail_instead_of_rebinding(tmp_path, monkeypatch):
    api = client(tmp_path, monkeypatch)
    requested = record_requests(monkeypatch, api, [Reply(), Reply(b'{"id":99,"full_name":"test/alpha"}')])
    api.get(api.url("/repos/test/alpha/issues"), "issues")
    with pytest.raises(RuntimeError, match="Conflicting public source repository credential bindings"):
        api.get_json("/repos/test/beta", "identity")
    assert [auth for _, auth in requested] == ["Bearer " + PRIMARY, "Bearer " + SECONDARY]
    api.opener.open = lambda *args, **kwargs: pytest.fail("conflicting numeric alias must remain unbound")
    with pytest.raises(RuntimeError, match="credential binding unavailable"):
        api.get(api.url("/repositories/99/issues"), "issues")


def test_independent_primary_reserve_windows_are_not_erased_or_shared(tmp_path, monkeypatch):
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000)
    api = client(tmp_path, monkeypatch, primary_rate_reserve=40)
    api.defer_on_rate = True
    requested = record_requests(monkeypatch, api, [
        Reply(headers={"X-RateLimit-Remaining": "39", "X-RateLimit-Reset": "1060"}),
        Reply(headers={"X-RateLimit-Remaining": "4999", "X-RateLimit-Reset": "1100"}),
        Reply(),
    ])
    api.get(api.url("/repos/test/alpha"), "identity")
    api.get(api.url("/repos/test/beta"), "identity")
    with pytest.raises(APIRequestDeferred) as error:
        api.get(api.url("/repos/test/alpha/issues"), "issues")
    assert error.value.retry_not_before == 1061
    api.get(api.url("/repos/test/beta/issues"), "issues")
    assert len(requested) == 3


@pytest.mark.parametrize("status,headers,body", [
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1060"}, b'{"message":"rate limit"}'),
    (429, {"Retry-After": "120"}, b'{}'),
])
def test_throttling_defers_without_trying_other_token_or_leaking(tmp_path, monkeypatch, status, headers, body):
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000)
    checkpoint = CheckpointStore(tmp_path, 99, "deferred-api-job")
    api = client(tmp_path, monkeypatch, source_repository="test/alpha", checkpoint=checkpoint)
    api.defer_on_rate = True
    error = urllib.error.HTTPError(api.url("/repos/test/alpha/issues"), status, "limited", headers,
                                   io.BytesIO(body))
    requested = record_requests(monkeypatch, api, [error])
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream), pytest.raises(APIRequestDeferred) as caught:
        api.get(api.url("/repos/test/alpha/issues"), "issues")
    assert [auth for _, auth in requested] == ["Bearer " + PRIMARY]
    visible = stream.getvalue() + json.dumps(api.records) + json.dumps(checkpoint.events) + str(caught.value)
    assert PRIMARY not in visible and SECONDARY not in visible and "synthetic-destination" not in visible
    assert os.environ["GH_TOKEN"] == "synthetic-destination"


def test_bounded_retry_keeps_assigned_credential(tmp_path, monkeypatch):
    sleeps = []
    monkeypatch.setattr("icsot_observer.github.time.sleep", sleeps.append)
    api = client(tmp_path, monkeypatch, source_repository="test/beta")
    error = urllib.error.HTTPError(api.url("/repos/test/beta/issues"), 429, "limited", {}, io.BytesIO(b'{}'))
    requested = record_requests(monkeypatch, api, [error, Reply()])
    api.get(api.url("/repos/test/beta/issues"), "issues")
    assert [auth for _, auth in requested] == ["Bearer " + SECONDARY] * 2
    assert sleeps == [60]
