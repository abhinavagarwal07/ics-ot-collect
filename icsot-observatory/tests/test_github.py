import json
from pathlib import Path

import pytest

from icsot_observer.core import Config, ObjectStore, parse_github_time, sha256
from icsot_observer.github import GitHubAPI, NoRedirect, Response


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


def test_first_page_membership_drift_restarts_once_without_stitching(tmp_path):
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
    assert [item["id"] for item in client.list_pages("/repos/test/repo/issues", "issues")] == [9, 4]
    assert seen["first"] == 4
    assert client.store.get(sha256(b'[{"id":3}]')) == b'[{"id":3}]'


def test_numeric_repository_pagination_follows_opaque_link_and_rechecks_first_page(tmp_path):
    client = api(tmp_path)
    metadata = "https://api.github.com/repos/test/repo"
    first = metadata + "/issues?state=all&sort=updated&direction=desc&per_page=100"
    second = ("https://api.github.com/repositories/48296177/issues?state=all&sort=updated&direction=desc"
              "&per_page=100&after=Y3Vyc29yOnYyOpLPAAABn-vnJXDPAAAAATCQq8I%3D&page=2")
    responses = {
        metadata: (b'{"id":48296177,"private":false}', {}),
        first: (b'[{"id":1}]', {"Link": f'<{second}>; rel="next"'}),
        second: (b'[{"id":2}]', {}),
    }
    requested = []

    class FakeResponse:
        status = 200

        def __init__(self, body, headers):
            self.body, self.headers = body, headers

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return self.body[:limit]

    class FakeOpener:
        def open(self, request, timeout):
            requested.append(request.full_url)
            return FakeResponse(*responses[request.full_url])

    client.opener = FakeOpener()
    client.get_json("/repos/test/repo", "repository_metadata")
    items = client.list_pages("/repos/test/repo/issues", "issues",
                              params={"state": "all", "sort": "updated", "direction": "desc"})
    assert [item["id"] for item in items] == [1, 2]
    assert requested == [metadata, first, second, first]
    assert [record["url"] for record in client.records] == requested
    assert client.records[-1]["purpose"] == "issues_first_page_recheck"
    assert client.store.get(client.records[2]["body_sha256"]) == b'[{"id":2}]'
    assert GitHubAPI.url("/repositories/48296177/issues", {"page": 2}) == "https://api.github.com/repositories/48296177/issues?page=2"


@pytest.mark.parametrize("url", [
    "http://api.github.com/repositories/48296177/issues",
    "https://api.github.com.evil.example/repositories/48296177/issues",
    "https://evil.example/repositories/48296177/issues",
    "https://user:password@api.github.com/repositories/48296177/issues",
    "https://api.github.com:444/repositories/48296177/issues",
    "https://api.github.com/repositories/not-a-number/issues",
    "https://api.github.com/repositories/-1/issues",
    "https://api.github.com/repositories/0/issues",
    "https://api.github.com/repositories/48296177suffix/issues",
    "https://api.github.com/repositories/%34%38/issues",
    "https://api.github.com/repositories/48296177/../users",
    "https://api.github.com/repositories/48296177/issues#fragment",
    "https://api.github.com/repositories/48296177/issues\n",
])
def test_numeric_repository_url_boundaries_reject_unsafe_links(url):
    with pytest.raises(ValueError):
        GitHubAPI.validate_url(url)


@pytest.mark.parametrize("next_url", [
    "https://api.github.com/repositories/48296177/pulls?page=2",
    "https://api.github.com/repositories/999/issues?page=2",
    "https://api.github.com/repos/other/repo/issues?page=2",
])
def test_pagination_still_rejects_endpoint_or_repository_changes(tmp_path, next_url):
    client = api(tmp_path)

    def fake_get(url, purpose):
        if purpose == "repository_metadata":
            body, headers = b'{"id":48296177}', {}
        else:
            body, headers = b'[{"id":1}]', {"link": f'<{next_url}>; rel="next"'}
        return Response(body, {"headers": headers, "body_sha256": client.store.put(body)})

    client.get = fake_get
    client.get_json("/repos/test/repo", "repository_metadata")
    with pytest.raises(RuntimeError, match="Unexpected (endpoint|repository) changed"):
        client.list_pages("/repos/test/repo/issues", "issues")


def test_redirect_handler_never_forwards_request_credentials():
    assert NoRedirect().redirect_request(None, None, 302, "Found", {},
                                         "https://api.github.com/repositories/48296177/issues") is None
