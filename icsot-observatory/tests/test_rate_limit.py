import io
import urllib.error
from dataclasses import replace

import pytest

from icsot_observer.core import Config, ObjectStore
from icsot_observer.github import GitHubAPI


def client(tmp_path, monkeypatch, replies, allowance=0, error_status=403,
           error_body=b'{"message":"rate limited"}'):
    cfg = Config(root=tmp_path, repositories=("test/repo",), api_version="2026-03-10",
                 user_agent="test", token_env="NO_TEST_TOKEN", http_timeout_seconds=5,
                 max_response_bytes=1000, overlap_hours=48, max_pages=100,
                 primary_rate_wait_seconds=allowance)
    api = GitHubAPI(cfg, ObjectStore(tmp_path), [])
    sleeps = []
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1000)
    monkeypatch.setattr("icsot_observer.github.time.sleep", sleeps.append)
    pending = iter(replies)

    class Success:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, reserve=False):
            if reserve:
                self.headers = {**self.headers, "X-RateLimit-Remaining": "39", "X-RateLimit-Reset": "1060"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, length):
            return b"[]"

    def open_request(request, timeout):
        reply = next(pending)
        if reply is None:
            return Success()
        if reply == "reserve":
            return Success(reserve=True)
        raise urllib.error.HTTPError(request.full_url, error_status, "limited", reply,
                                     io.BytesIO(error_body))

    monkeypatch.setattr(api.opener, "open", open_request)
    return api, sleeps


def test_opted_in_wait_preserves_refusal_then_captures_success(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch,
                         [{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1100"}, None],
                         allowance=101)
    assert api.get(api.url("/repos/test/repo/issues"), "issues").body == b"[]"
    assert sleeps == [101]
    assert [r["status"] for r in api.records] == [403, 200]
    assert api.records[0]["primary_rate_wait_seconds"] == 101
    assert api.store.get(api.records[0]["body_sha256"]) == b'{"message":"rate limited"}'


def test_primary_exhaustion_also_honors_longer_retry_after(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch,
        [{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1060", "Retry-After": "120"}, None],
        allowance=120)
    api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [120]


@pytest.mark.parametrize("allowance,reset", [(0, "1100"), (100, "1100"), (3605, "999999"),
                                               (3605, "missing"), (3605, "")])
def test_disabled_excessive_or_invalid_wait_fails_without_sleep(tmp_path, monkeypatch, allowance, reset):
    api, sleeps = client(tmp_path, monkeypatch,
                         [{"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}], allowance)
    with pytest.raises(RuntimeError, match="Rate-limit budget exhausted"):
        api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == []
    assert api.records[0]["status"] == 403


def test_wait_allowance_is_shared_across_requests(tmp_path, monkeypatch):
    limited = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1060"}
    api, sleeps = client(tmp_path, monkeypatch, [limited, None, limited], allowance=100)
    api.get(api.url("/repos/test/repo/issues"), "issues")
    with pytest.raises(RuntimeError, match="Rate-limit budget exhausted"):
        api.get(api.url("/repos/test/repo/pulls"), "pulls")
    assert sleeps == [61]
    assert [r["status"] for r in api.records] == [403, 200, 403]


def test_rate_wait_config_validation(tmp_path):
    path = tmp_path / "config.toml"
    template = '''[collector]
root = "./data"
api_version = "2026-03-10"
user_agent = "test"
token_env = "NO_TEST_TOKEN"
primary_rate_wait_seconds = VALUE
[cohort]
repositories = ["test/repo"]
'''
    path.write_text(template.replace("VALUE", "3605"))
    assert Config.load(path).primary_rate_wait_seconds == 3605
    path.write_text(template.replace("VALUE", "-1"))
    with pytest.raises(ValueError, match="nonnegative"):
        Config.load(path)
    path.write_text(template.replace("primary_rate_wait_seconds = VALUE", "primary_rate_reserve = -1"))
    with pytest.raises(ValueError, match="primary_rate_reserve must be nonnegative"):
        Config.load(path)
    path.write_text(template.replace("primary_rate_wait_seconds = VALUE", "secondary_rate_wait_seconds = -1"))
    with pytest.raises(ValueError, match="secondary_rate_wait_seconds must be nonnegative"):
        Config.load(path)


def test_reserve_waits_before_next_request_without_fabricating_failure(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, ["reserve", None], allowance=100)
    api.config = replace(api.config, primary_rate_reserve=40)
    api.get(api.url("/repos/test/repo"), "identity")
    assert sleeps == []
    api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [61]
    assert [r["status"] for r in api.records] == [200, 200]
    assert api.records[0]["error"] is None
    assert api.records[0]["primary_rate_reserve_wait_seconds"] == 61


def test_reserve_stops_before_consuming_transfer_capacity(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, ["reserve"], allowance=60)
    api.config = replace(api.config, primary_rate_reserve=40)
    api.get(api.url("/repos/test/repo"), "identity")
    with pytest.raises(RuntimeError, match="Rate-limit reserve reached"):
        api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [] and len(api.records) == 1


def test_disabled_reserve_does_not_change_ordinary_capture(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, ["reserve", None])
    api.get(api.url("/repos/test/repo"), "identity")
    api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [] and len(api.records) == 2


def test_secondary_without_retry_after_waits_one_minute(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, [{}, None])
    api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [60]
    assert api.records[0]["secondary_rate_wait_seconds"] == 60


@pytest.mark.parametrize("retry_after,expected", [("120", 120),
    ("Thu, 01 Jan 1970 00:18:40 GMT", 120), ("invalid", 60), ("NaN", 60), ("-10", 60)])
def test_secondary_respects_retry_after_seconds_or_http_date(tmp_path, monkeypatch, retry_after, expected):
    api, sleeps = client(tmp_path, monkeypatch, [{"Retry-After": retry_after}, None])
    api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [expected]


def test_secondary_wait_allowance_is_shared_and_bounded(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, [{}, None, {}])
    api.config = replace(api.config, secondary_rate_wait_seconds=90)
    api.get(api.url("/repos/test/repo/issues"), "issues")
    with pytest.raises(RuntimeError, match="API failure"):
        api.get(api.url("/repos/test/repo/pulls"), "pulls")
    assert sleeps == [60] and len(api.records) == 3


def test_secondary_long_deferral_returns_partial_without_early_retry(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, [{"Retry-After": "1000"}])
    with pytest.raises(RuntimeError, match="API failure"):
        api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [] and len(api.records) == 1


def test_permission_denial_does_not_retry_as_throttling(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, [{}], error_body=b'{"message":"Resource not accessible by integration"}')
    with pytest.raises(RuntimeError, match="HTTP 403"):
        api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [] and len(api.records) == 1


def test_429_without_secondary_message_still_waits(tmp_path, monkeypatch):
    api, sleeps = client(tmp_path, monkeypatch, [{}, None], error_status=429, error_body=b'{}')
    api.get(api.url("/repos/test/repo/issues"), "issues")
    assert sleeps == [60]


@pytest.mark.parametrize("defer", [False, True])
def test_expired_reset_9ee_ast_case_clears_even_after_all_wait_allowance_spent(tmp_path, monkeypatch, defer):
    api, sleeps = client(tmp_path, monkeypatch, [], allowance=3605)
    api.config = replace(api.config, primary_rate_reserve=40)
    api.defer_on_rate = defer
    api.primary_rate_waited_seconds = 3605
    api._last_rate_record = {"headers": {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1000"}}
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1002)
    api._preserve_primary_reserve("review_comments")
    assert api._last_rate_record is None
    assert api.primary_rate_waited_seconds == 3605
    assert api.requests == 0 and api.records == [] and sleeps == []


@pytest.mark.parametrize("defer", [False, True])
def test_future_reset_with_exhausted_wait_allowance_still_refuses(tmp_path, monkeypatch, defer):
    from icsot_observer.github import APIRequestDeferred
    api, sleeps = client(tmp_path, monkeypatch, [], allowance=3605)
    api.config = replace(api.config, primary_rate_reserve=40)
    api.defer_on_rate = defer
    api.primary_rate_waited_seconds = 3605
    record = {"headers": {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1100"}}
    api._last_rate_record = record
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1002)
    with pytest.raises(APIRequestDeferred if defer else RuntimeError) as caught:
        api._preserve_primary_reserve("review_comments")
    assert caught.value.retry_not_before == 1101
    assert api._last_rate_record is record
    assert api.requests == 0 and api.records == [] and sleeps == []


def test_expired_reserve_diagnostic_exposes_reset_and_spent_budget_without_new_request(tmp_path, monkeypatch):
    import json
    from icsot_observer.diagnostics import diagnostic_context
    api, sleeps = client(tmp_path, monkeypatch, [], allowance=3605)
    api.config = replace(api.config, primary_rate_reserve=40)
    api.primary_rate_waited_seconds = 3605
    api._last_rate_record = {"headers": {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1000"}}
    monkeypatch.setattr("icsot_observer.github.time.time", lambda: 1002)
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream):
        api._preserve_primary_reserve("review_comments")
    rows = [json.loads(line.removeprefix("ICSOT_DEBUG ")) for line in stream.getvalue().splitlines()]
    decision = next(row for row in rows if row["event"] == "api_rate_reserve")
    assert decision["decision"] == "clear_expired" and decision["reason"] == "expired_reset_cleared"
    assert decision["reset"] == 1000 and decision["remaining"] == 0
    assert decision["primary_wait_used_seconds"] == decision["primary_wait_allowance_seconds"] == 3605
    assert decision["wait_available_seconds"] == 0 and decision["scope"] == "review_comments"
    assert api.requests == 0 and api.records == [] and sleeps == []
