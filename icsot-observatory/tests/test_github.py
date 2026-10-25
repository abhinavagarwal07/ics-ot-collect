import json
from pathlib import Path

import pytest

from icsot_observer.core import Config, ObjectStore, parse_github_time
from icsot_observer.github import GitHubAPI, Response


def api(tmp_path):
    cfg = Config(root=tmp_path, repositories=("test/repo",), api_version="2026-03-10",
                 user_agent="research", token_env="DUMMY_TEST_NOT_PRESENT", http_timeout_seconds=5,
                 max_response_bytes=1000000, overlap_hours=48, max_pages=100)
    return GitHubAPI(cfg, ObjectStore(tmp_path), [])


def test_pages_and_stop_at_older_updated_date(tmp_path):
    client = api(tmp_path)
    first = "https://api.github.com/repos/test/repo/pulls?state=all&sort=updated&direction=desc&per_page=100"
    second = first + "&page=2"
    responses = {
        first: (b'[{"id":1,"updated_at":"2026-10-20T00:00:00Z"}]', {"link": f'<{second}>; rel="next"'}),
        second: (b'[{"id":2,"updated_at":"2026-10-10T00:00:00Z"}]', {}),
    }
    def fake_get(url, purpose):
        body, headers = responses[url]
        return Response(body, {"headers": headers, "body_sha256": client.store.put(body)})
    client.get = fake_get
    items = client.list_pages("/repos/test/repo/pulls", "pulls",
                              params={"state":"all", "sort":"updated", "direction":"desc"},
                              updated_before=parse_github_time("2026-10-15T00:00:00Z"))
    assert [x["id"] for x in items] == [1, 2]


def test_detects_first_page_drift(tmp_path):
    client = api(tmp_path)
    first = "https://api.github.com/repos/test/repo/issues?per_page=100"
    second = first + "&page=2"
    seen = {"first": 0}
    def fake_get(url, purpose):
        if url == first:
            seen["first"] += 1
            body = b'[{"id":3}]' if seen["first"] == 1 else b'[{"id":9}]'
            headers = {"link": f'<{second}>; rel="next"'}
        else:
            body, headers = b'[{"id":4}]', {}
        return Response(body, {"headers": headers, "body_sha256": client.store.put(body)})
    client.get = fake_get
    with pytest.raises(RuntimeError, match="non-atomic"):
        client.list_pages("/repos/test/repo/issues", "issues")
