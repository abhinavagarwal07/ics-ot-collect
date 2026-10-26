import io
import urllib.error
from dataclasses import replace

import pytest

from icsot_observer.core import Config, ObjectStore
from icsot_observer.github import GitHubAPI


def client(tmp_path, monkeypatch, replies, allowance=0):
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
        raise urllib.error.HTTPError(request.full_url, 403, "limited", reply,
                                     io.BytesIO(b'{"message":"rate limited"}'))

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
