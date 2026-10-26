"""HTTP security and adapter-boundary checks; fixtures never download evidence."""

import http.client
import json
import threading

import pytest

from icsot_observer.viewer import MAX_RESPONSE_BYTES, create_server


class FixtureData:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.large = False

    def overview(self, refresh=False):
        if refresh:
            self.calls.append(("overview_refresh",))
        if self.failure:
            raise self.failure
        if self.large:
            return {"text": "x" * MAX_RESPONSE_BYTES}
        return {"repos": [{"key": "repo-a", "slug": "fixture/local", "capture_count": 2}], "gaps": []}

    def repo(self, key):
        self.calls.append(("repo", key))
        return {"repo": {"key": key}, "captures": [{"key": "capture-a", "load_state": "metadata_only"}]}

    def compare(self, *args, **kwargs):
        self.calls.append(("compare", args, kwargs))
        return {"items": [{"id": "17", "change": "representation_changed", "before": {"body": "<script>untrusted</script>"}, "after": {"body": "changed"}}], "total": 1}

    def entity_detail(self, *args):
        self.calls.append(("entity", args))
        return {"status": "observed", "raw_refs": ["response-0"]}

    def raw_record(self, *args):
        self.calls.append(("raw", args))
        return {"status": "loaded", "text": "<script>untrusted</script>", "sha256": "a" * 64}

    def budget_status(self):
        return {"limit_bytes": 2000000000, "used_bytes": 4096}

    def load(self, *args):
        self.calls.append(("load", args))
        return {"status": "loaded"}

    def git_diff(self, *args, **kwargs):
        self.calls.append(("git_diff", args, kwargs))
        return {"status": "available", "files": [{"path": "src/file.py", "status": "M"}], "patch": "+ <script>plain captured text</script>", "base_oid": args[2], "head_oid": args[3], "truncated": False}


@pytest.fixture
def local_viewer():
    adapter = FixtureData()
    server = create_server(adapter)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, adapter
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def request(server, path="/api/overview", *, method="GET", headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
    connection.request(method, path, headers=headers or {}, body=body)
    response = connection.getresponse()
    status, response_headers, raw = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return status, response_headers, raw


def origin(server):
    return "http://127.0.0.1:" + str(server.server_address[1])


def test_browsing_is_read_only_and_assets_have_security_headers(local_viewer):
    server, adapter = local_viewer
    for path in ("/", "/viewer.js", "/viewer.css", "/api/overview", "/api/session"):
        status, headers, raw = request(server, path)
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert "script-src 'self'" in headers["Content-Security-Policy"]
        assert not any(k.lower().startswith("access-control-") for k in headers)
        assert raw
    assert not adapter.calls


def test_remote_metadata_retry_is_explicit_and_same_origin(local_viewer):
    server, adapter = local_viewer
    assert request(server, "/api/overview")[0] == 200
    assert not adapter.calls
    assert request(server, "/api/overview?refresh=1")[0] == 200
    assert adapter.calls == [("overview_refresh",)]
    for query in ("refresh=0", "refresh=true", "refresh=1&refresh=1"):
        assert request(server, "/api/overview?" + query)[0] == 400
    assert request(server, "/api/overview?refresh=1", headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"})[0] == 403
    assert adapter.calls == [("overview_refresh",)]


@pytest.mark.parametrize("headers", [
    {"Host": "attacker.example"},
    {"Host": "127.0.0.1.evil.example:8765"},
    {"Origin": "https://attacker.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
])
def test_dns_rebinding_and_cross_site_reads_are_rejected(local_viewer, headers):
    server, adapter = local_viewer
    status, _, _ = request(server, headers=headers)
    assert status == 403
    assert not adapter.calls


def test_cross_site_browser_bootstrap_is_public_but_evidence_and_tokens_are_not(local_viewer):
    server, adapter = local_viewer
    navigation = {"Origin": "chrome-extension://fixture-extension", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
    for path in ("/", "/viewer.css", "/viewer.js"):
        status, headers, raw = request(server, path, headers=navigation)
        assert status == 200 and raw
        assert headers["X-Frame-Options"] == "DENY"
        assert "Access-Control-Allow-Origin" not in headers
    status, _, raw = request(server, "/", method="HEAD", headers=navigation)
    assert status == 200 and raw == b""
    for path in ("/api/overview", "/api/session", "/api/budget", "/api/repos/repo-a", "/api/raw?repo=r&capture=c&ref=response-0"):
        assert request(server, path, headers=navigation)[0] == 403
    body = json.dumps({"repo": "r", "capture": "c"})
    assert request(server, "/api/load", method="POST", headers={**navigation, "Content-Type": "application/json", "X-Viewer-Token": server.csrf_token}, body=body)[0] == 403
    assert request(server, "/", headers={**navigation, "Host": "attacker.example"})[0] == 403
    assert not adapter.calls


def test_load_requires_origin_token_and_exact_identifier_body(local_viewer):
    server, adapter = local_viewer
    body = json.dumps({"repo": "repo-a", "capture": "capture-b"})
    base = {"Content-Type": "application/json"}
    assert request(server, "/api/load", method="POST", headers=base, body=body)[0] == 403
    base["Origin"] = origin(server)
    assert request(server, "/api/load", method="POST", headers=base, body=body)[0] == 403
    base["X-Viewer-Token"] = "\u00ff"
    assert request(server, "/api/load", method="POST", headers=base, body=body)[0] == 403
    token = json.loads(request(server, "/api/session")[2])["token"]
    base["X-Viewer-Token"] = token
    assert request(server, "/api/load", method="POST", headers=base, body=body)[0] == 200
    assert adapter.calls == [("load", ("repo-a", "capture-b"))]
    adapter.calls.clear()
    bad = json.dumps({"repo": "repo-a", "capture": "capture-b", "private_key": "/should/not/be/accepted"})
    assert request(server, "/api/load", method="POST", headers=base, body=bad)[0] == 400
    assert not adapter.calls
    assert request(server, "/api/load", method="GET")[0] == 404


def test_bounded_compare_and_raw_routes_forward_ids_without_execution(local_viewer):
    server, adapter = local_viewer
    status, _, raw = request(server, "/api/compare?repo=repo-a&left=capture-a&right=capture-b&category=issues&offset=100&limit=25")
    assert status == 200
    assert json.loads(raw)["items"][0]["before"]["body"] == "<script>untrusted</script>"
    assert adapter.calls[-1] == ("compare", ("repo-a", "capture-a", "capture-b"), {"category": "issues", "offset": 100, "limit": 25})
    assert request(server, "/api/raw?repo=repo-a&capture=capture-b&ref=response-0")[0] == 200
    assert adapter.calls[-1] == ("raw", ("repo-a", "capture-b", "response-0"))
    count = len(adapter.calls)
    for suffix in ("category=unknown", "limit=101", "limit=0", "offset=-1", "offset=1000001", "limit=1&limit=2"):
        assert request(server, "/api/compare?repo=repo-a&left=a&right=b&" + suffix)[0] == 400
    assert len(adapter.calls) == count


def test_no_filesystem_serving_cors_or_secret_exception_messages(local_viewer):
    server, adapter = local_viewer
    for path in ("/../../pyproject.toml", "/web/viewer.html", "/api/file?path=/etc/passwd", "/api/repos/one%2Ftwo"):
        assert request(server, path)[0] in (400, 404)
    adapter.failure = ValueError("SECRET_KEY_PATH=/private/fixture.pem")
    status, _, raw = request(server)
    assert status == 400
    assert b"SECRET" not in raw and b"fixture.pem" not in raw and b"Traceback" not in raw
    adapter.failure = RuntimeError("plaintext body and filesystem details")
    assert request(server)[0] == 409
    status, headers, _ = request(server, method="OPTIONS")
    assert status == 405
    assert "Access-Control-Allow-Origin" not in headers


def test_budget_errors_and_oversized_results_are_safe_conflicts(local_viewer):
    server, adapter = local_viewer
    class LocalBudgetExceeded(RuntimeError):
        pass
    adapter.failure = LocalBudgetExceeded("private location")
    status, _, raw = request(server)
    assert status == 409 and json.loads(raw)["error"]["code"] == "budget_limit"
    adapter.failure = None
    adapter.large = True
    status, _, raw = request(server)
    assert status == 409 and len(raw) < 1024
    assert json.loads(raw)["error"]["code"] == "response_limit"


@pytest.mark.parametrize("load_status,code", [("key_required", "key_required"), ("busy", "capture_busy"), ("budget_unavailable", "budget_limit"), ("load_failed", "load_unavailable")])
def test_load_failure_results_are_safe_conflicts(local_viewer, load_status, code):
    server, adapter = local_viewer
    adapter.load = lambda *args: {"status": load_status, "reason": "SECRET_KEY_PATH=/private/fixture.pem"}
    status, _, raw = request(server, "/api/load", method="POST", headers={"Origin": origin(server), "X-Viewer-Token": server.csrf_token, "Content-Type": "application/json"}, body=json.dumps({"repo": "r", "capture": "c"}))
    assert status == 409 and json.loads(raw)["error"]["code"] == code
    assert b"SECRET" not in raw and b"fixture.pem" not in raw


def test_non_loopback_bind_is_rejected():
    with pytest.raises(ValueError, match="loopback"):
        create_server(FixtureData(), bind="0.0.0.0")


def test_git_diff_is_explicit_same_origin_and_oid_only(local_viewer):
    server, adapter = local_viewer
    value = {"repo": "repo-a", "capture": "capture-b", "base": "a" * 40, "head": "b" * 40}
    body = json.dumps(value)
    assert request(server, "/api/git-diff", method="POST", headers={"Content-Type": "application/json"}, body=body)[0] == 403
    assert request(server, "/api/git-diff")[0] == 404
    headers = {"Content-Type": "application/json", "Origin": origin(server), "X-Viewer-Token": server.csrf_token}
    status, _, raw = request(server, "/api/git-diff", method="POST", headers=headers, body=body)
    assert status == 200 and json.loads(raw)["patch"].startswith("+ <script>")
    assert adapter.calls[-1] == ("git_diff", ("repo-a", "capture-b", "a" * 40, "b" * 40), {"path": None})
    value["path"] = "src/name with spaces.py"
    assert request(server, "/api/git-diff", method="POST", headers=headers, body=json.dumps(value))[0] == 200
    assert adapter.calls[-1][2] == {"path": "src/name with spaces.py"}
    count = len(adapter.calls)
    for bad_base in ("HEAD", "--output=/private/file", "refs/heads/main", "a" * 39, "A" * 40):
        assert request(server, "/api/git-diff", method="POST", headers=headers, body=json.dumps({**value, "base": bad_base}))[0] == 400
    assert request(server, "/api/git-diff", method="POST", headers=headers, body=json.dumps({**value, "command": "status"}))[0] == 400
    assert len(adapter.calls) == count
    adapter.git_diff = lambda *args, **kwargs: {"status": "unavailable", "reason": "SECRET private key path"}
    status, _, raw = request(server, "/api/git-diff", method="POST", headers=headers, body=body)
    assert status == 409 and b"SECRET" not in raw


def test_concurrent_metadata_remains_available_during_explicit_load(local_viewer):
    server, adapter = local_viewer
    started, finish = threading.Event(), threading.Event()
    def load(*args):
        started.set()
        assert finish.wait(3)
        return {"status": "loaded"}
    adapter.load = load
    result = []
    def post():
        result.append(request(server, "/api/load", method="POST", headers={"Origin": origin(server), "X-Viewer-Token": server.csrf_token, "Content-Type": "application/json"}, body=json.dumps({"repo": "r", "capture": "c"}))[0])
    worker = threading.Thread(target=post)
    worker.start()
    assert started.wait(2)
    try:
        assert request(server, "/api/repos/repo-a")[0] == 200
    finally:
        finish.set()
        worker.join(3)
    assert result == [200]


def test_shutdown_waits_for_active_operation_cleanup(local_viewer):
    server, adapter = local_viewer
    started, finish, cleaned, closed = (threading.Event() for _ in range(4))
    def load(*args):
        started.set()
        try:
            assert finish.wait(3)
            return {"status": "loaded"}
        finally:
            cleaned.set()
    adapter.load = load
    def post():
        request(server, "/api/load", method="POST", headers={"Origin": origin(server), "X-Viewer-Token": server.csrf_token, "Content-Type": "application/json"}, body=json.dumps({"repo": "r", "capture": "c"}))
    worker = threading.Thread(target=post)
    worker.start()
    assert started.wait(2)
    server.shutdown()
    def close():
        server.server_close()
        closed.set()
    closer = threading.Thread(target=close)
    closer.start()
    try:
        assert not closed.wait(0.05)
        assert not cleaned.is_set()
    finally:
        finish.set()
        worker.join(3)
        closer.join(3)
    assert cleaned.is_set() and closed.is_set()
