"""Offline checks for public release asset downloads and authenticated fallback."""

import hashlib
import io
import subprocess
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from icsot_observer.github_state import GhCliStateTransport, StateDeferredError, StateError


REPO = "owner/collector"
TAG = "snapshot"
NAME = "part.enc"
CONTENT = b"encrypted payload"
URL = f"https://github.com/{REPO}/releases/download/{TAG}/{NAME}"
CDN = "https://release-assets.githubusercontent.com/blob?signature=example"


class Response(io.BytesIO):
    def __init__(self, body=b"", status=200, headers=None):
        super().__init__(body)
        self.status = self.code = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def getcode(self):
        return self.status


class Opener:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        assert self.outcomes, "Unexpected public network request"
        result = self.outcomes.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def http_error(status, headers=None):
    message = Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return HTTPError(URL, status, "error", message, io.BytesIO(b""))


class BinaryRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        assert args[2] == f"repos/{REPO}/releases/assets/7", args
        kwargs["stdout"].write(CONTENT)
        return subprocess.CompletedProcess(args, 0, None, b"")


def transport(opener, *, runner=None, mode="public-first", draft=False, url=URL,
              size=len(CONTENT), digest=True, clock=lambda: 1000):
    runner = runner or BinaryRunner()
    result = GhCliStateTransport(REPO, runner=runner, clock=clock,
                                 asset_download_mode=mode, public_opener=opener)
    asset = {"id": 7, "name": NAME, "size": size}
    if url is not None:
        asset["browser_download_url"] = url
    if digest:
        asset["digest"] = "sha256:" + hashlib.sha256(CONTENT).hexdigest()
    result._releases[TAG] = {"id": 1, "tag_name": TAG, "draft": draft, "assets": [asset]}
    result._assets[TAG] = {NAME: asset}
    return result, runner


def test_public_redirects_use_fresh_credential_free_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "do-not-leak-this-token")
    opener = Opener(http_error(302, {"Location": CDN}), Response(CONTENT))
    client, runner = transport(opener)
    before = client.request_count
    destination = tmp_path / NAME
    client.download_asset(TAG, NAME, destination)
    assert destination.read_bytes() == CONTENT
    assert runner.calls == []
    assert client.request_count == before
    assert client.asset_download_counts == {
        "public_http_requests": 2, "public_downloads": 1, "public_bytes": len(CONTENT),
        "authenticated_downloads": 0, "fallbacks": 0,
    }
    assert [request.full_url for request, _ in opener.requests] == [URL, CDN]
    for request, timeout in opener.requests:
        assert request.get_method() == "GET"
        assert 0 < timeout <= 35
        headers = {key.lower(): value for key, value in request.header_items()}
        assert not ({"authorization", "proxy-authorization", "cookie"} & headers.keys())
        assert "do-not-leak-this-token" not in repr(headers)


@pytest.mark.parametrize("status", [401, 403, 404, 408, 410, 500, 501, 503, 505, 599])
def test_public_unavailability_falls_back_once(tmp_path, status):
    opener = Opener(http_error(status))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    client.download_asset(TAG, NAME, destination)
    assert destination.read_bytes() == CONTENT
    assert len(opener.requests) == len(runner.calls) == 1
    assert client.request_count == 1
    assert client.asset_download_counts == {
        "public_http_requests": 1, "public_downloads": 0, "public_bytes": 0,
        "authenticated_downloads": 1, "fallbacks": 1,
    }


def test_private_like_404_is_cached_for_the_release(tmp_path):
    opener = Opener(http_error(404))
    client, runner = transport(opener)
    for number in range(2):
        client.download_asset(TAG, NAME, tmp_path / str(number))
    assert len(opener.requests) == 1
    assert len(runner.calls) == 2


def test_network_failure_before_body_falls_back(tmp_path):
    opener = Opener(URLError("offline"))
    client, runner = transport(opener)
    client.download_asset(TAG, NAME, tmp_path / NAME)
    assert len(opener.requests) == len(runner.calls) == 1
    assert (tmp_path / NAME).read_bytes() == CONTENT


@pytest.mark.parametrize("status,headers,deadline", [
    (429, {}, 1060),
    (403, {"Retry-After": "120"}, 1120),
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "5000"}, 5000),
])
def test_public_rate_limit_defers_without_authenticated_fallback(tmp_path, status, headers, deadline):
    opener = Opener(http_error(status, headers))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    with pytest.raises(StateDeferredError) as error:
        client.download_asset(TAG, NAME, destination)
    assert error.value.retry_not_before == deadline
    assert not destination.exists()
    assert not runner.calls


def test_public_only_does_not_fallback_after_404(tmp_path):
    opener = Opener(http_error(404))
    client, runner = transport(opener, mode="public-only")
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists()
    assert len(opener.requests) == 1
    assert not runner.calls


@pytest.mark.parametrize("draft,url", [(True, URL), (False, None)])
def test_draft_or_legacy_metadata_uses_authenticated_path(tmp_path, draft, url):
    opener = Opener()
    client, runner = transport(opener, draft=draft, url=url)
    client.download_asset(TAG, NAME, tmp_path / NAME)
    assert not opener.requests
    assert len(runner.calls) == 1
    assert (tmp_path / NAME).read_bytes() == CONTENT


@pytest.mark.parametrize("url", [
    f"http://github.com/{REPO}/releases/download/{TAG}/{NAME}",
    f"https://github.com.attacker.test/{REPO}/releases/download/{TAG}/{NAME}",
    f"https://evil@github.com/{REPO}/releases/download/{TAG}/{NAME}",
    f"https://github.com/other/collector/releases/download/{TAG}/{NAME}",
    f"https://github.com/{REPO}/releases/download/{TAG}/other.enc",
])
def test_unsafe_initial_url_fails_without_fallback(tmp_path, url):
    opener = Opener()
    client, runner = transport(opener, url=url)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists()
    assert not opener.requests and not runner.calls


@pytest.mark.parametrize("redirect", [
    "http://release-assets.githubusercontent.com/blob",
    "https://release-assets.githubusercontent.com.attacker.test/blob",
    "https://user@release-assets.githubusercontent.com/blob",
    "https://example.com/blob",
])
def test_unsafe_redirect_fails_without_fallback(tmp_path, redirect):
    opener = Opener(http_error(302, {"Location": redirect}))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists()
    assert len(opener.requests) == 1
    assert not runner.calls


def test_redirect_chain_is_bounded(tmp_path):
    opener = Opener(*(http_error(302, {"Location": CDN}) for _ in range(8)))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists()
    assert len(opener.requests) <= 6
    assert not runner.calls


@pytest.mark.parametrize("body", [CONTENT[:-1], CONTENT + b"x", b"X" + CONTENT[1:]])
def test_public_integrity_failure_removes_partial_file_without_fallback(tmp_path, body):
    opener = Opener(Response(body))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists()
    assert len(opener.requests) == 1
    assert not runner.calls


def test_authenticated_mode_bypasses_public_download(tmp_path):
    opener = Opener()
    client, runner = transport(opener, mode="authenticated")
    client.download_asset(TAG, NAME, tmp_path / NAME)
    assert not opener.requests
    assert len(runner.calls) == 1


def test_mode_env_default_override_and_validation(monkeypatch):
    monkeypatch.delenv("ICSOT_ASSET_DOWNLOAD_MODE", raising=False)
    assert GhCliStateTransport(REPO).asset_download_mode == "public-first"
    monkeypatch.setenv("ICSOT_ASSET_DOWNLOAD_MODE", "public-only")
    assert GhCliStateTransport(REPO).asset_download_mode == "public-only"
    assert GhCliStateTransport(REPO, asset_download_mode="authenticated").asset_download_mode == "authenticated"
    monkeypatch.setenv("ICSOT_ASSET_DOWNLOAD_MODE", "typo")
    with pytest.raises(ValueError):
        GhCliStateTransport(REPO)


def test_systemic_public_failure_cools_down_other_releases_then_recovers(tmp_path):
    now = [1000.0]
    opener = Opener(http_error(503), Response(CONTENT))
    client, runner = transport(opener, clock=lambda: now[0])
    asset = dict(client._assets[TAG][NAME])
    second_tag = "other-snapshot"
    asset["browser_download_url"] = f"https://github.com/{REPO}/releases/download/{second_tag}/{NAME}"
    client._releases[second_tag] = {"id": 2, "tag_name": second_tag, "draft": False, "assets": [asset]}
    client._assets[second_tag] = {NAME: asset}
    client.download_asset(TAG, NAME, tmp_path / "first")
    client.download_asset(second_tag, NAME, tmp_path / "second")
    assert len(opener.requests) == 1
    assert len(runner.calls) == 2
    now[0] += 61
    client.download_asset(second_tag, NAME, tmp_path / "third")
    assert len(opener.requests) == 2
    assert len(runner.calls) == 2
    assert (tmp_path / "third").read_bytes() == CONTENT


def test_network_reset_discards_partial_public_body_before_fallback(tmp_path):
    class BrokenBody(Response):
        def __init__(self):
            super().__init__()
            self.reads = 0

        def read(self, size=-1):
            self.reads += 1
            if self.reads == 1:
                return CONTENT[:3]
            raise OSError("connection reset during body")

        read1 = read

    opener = Opener(BrokenBody())
    client, runner = transport(opener)
    destination = tmp_path / NAME
    client.download_asset(TAG, NAME, destination)
    assert destination.read_bytes() == CONTENT
    assert len(opener.requests) == len(runner.calls) == 1


def test_public_asset_without_github_digest_is_still_size_checked(tmp_path):
    opener = Opener(Response(CONTENT))
    client, runner = transport(opener, digest=False)
    client.download_asset(TAG, NAME, tmp_path / NAME)
    assert (tmp_path / NAME).read_bytes() == CONTENT
    assert len(opener.requests) == 1
    assert not runner.calls


def test_runtime_copy_preserves_public_policy_and_counters(tmp_path):
    from icsot_observer.proof_maintenance import ProofTransport

    opener = Opener(http_error(404))
    original, runner = transport(opener)
    original.download_asset(TAG, NAME, tmp_path / "first")
    wrapped = ProofTransport(REPO)
    original.copy_runtime_state_to(wrapped)
    assert wrapped.asset_download_mode == original.asset_download_mode
    assert wrapped._public_opener is opener
    assert wrapped.asset_download_counts == original.asset_download_counts
    assert wrapped.asset_download_counts is not original.asset_download_counts
    wrapped.runner = runner
    wrapped.download_asset(TAG, NAME, tmp_path / "second")
    assert len(opener.requests) == 1
    assert len(runner.calls) == 2
    assert wrapped.asset_download_counts["authenticated_downloads"] == 2
    assert original.asset_download_counts["authenticated_downloads"] == 1


def test_caller_descriptor_hash_remains_authoritative(tmp_path):
    from icsot_observer.github_state import GitHubStateStore, StateIntegrityError

    opener = Opener(Response(CONTENT))
    client, runner = transport(opener)
    store = object.__new__(GitHubStateStore)
    store.transport = client
    store._verified_downloads = set()
    ref = {"release_tag": TAG, "name": NAME,
           "ciphertext_sha256": hashlib.sha256(b"different").hexdigest(),
           "ciphertext_bytes": len(CONTENT)}
    with pytest.raises(StateIntegrityError):
        store._download_verified(ref, tmp_path / NAME)
    assert not store._verified_downloads
    assert len(opener.requests) == 1 and not runner.calls


@pytest.mark.parametrize("body", [CONTENT[:-1], CONTENT + b"x", b"X" + CONTENT[1:]])
def test_corrupt_authenticated_fallback_fails_and_cleans(tmp_path, body):
    class CorruptRunner(BinaryRunner):
        def __call__(self, args, **kwargs):
            self.calls.append(args)
            kwargs["stdout"].write(body)
            return subprocess.CompletedProcess(args, 0, None, b"")

    opener = Opener(http_error(404))
    runner = CorruptRunner()
    client, _ = transport(opener, runner=runner)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists()
    assert len(opener.requests) == len(runner.calls) == 1
    assert client.asset_download_counts["fallbacks"] == 1


def test_public_diagnostics_and_metrics_exclude_signed_url(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr("icsot_observer.diagnostics.emit", lambda event, **fields: events.append((event, fields)))
    monkeypatch.setenv("GH_TOKEN", "secret-token")
    opener = Opener(http_error(302, {"Location": CDN}), Response(CONTENT))
    client, _ = transport(opener)
    client.download_asset(TAG, NAME, tmp_path / NAME)
    event, fields = events[-1]
    assert event == "stage_end" and fields["stage"] == "asset_download"
    assert fields["public_http_requests"] == 2 and fields["public_bytes"] == len(CONTENT)
    assert "signature=example" not in repr(events) and "secret-token" not in repr(events)
    metrics = client.download_metrics()
    assert metrics["destination_github_public_asset_requests_total"] == 2
    assert metrics["destination_github_public_asset_download_bytes_total"] == len(CONTENT)
    assert metrics["destination_github_authenticated_asset_downloads_total"] == 0


def test_download_budget_accommodates_large_assets_and_has_a_ceiling():
    from icsot_observer.public_assets import download_budget_seconds

    assert download_budget_seconds(128 * 1024 ** 2) == 248
    assert download_budget_seconds(1024 ** 3) == 1144
    assert download_budget_seconds(2 * 1024 ** 3 - 1) == 1800


def test_total_public_deadline_discards_partial_bytes_before_fallback(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from icsot_observer import public_assets

    now = [0.0]
    monkeypatch.setattr(public_assets, "time", SimpleNamespace(monotonic=lambda: now[0]))

    class SlowBody(Response):
        def read1(self, size=-1):
            now[0] = 2000
            return CONTENT[:3]

    opener = Opener(SlowBody())
    client, runner = transport(opener)
    destination = tmp_path / NAME
    client.download_asset(TAG, NAME, destination)
    assert destination.read_bytes() == CONTENT
    assert len(opener.requests) == len(runner.calls) == 1


def test_incomplete_http_body_is_fatal_without_fallback(tmp_path):
    import http.client

    class TruncatedBody(Response):
        def read1(self, size=-1):
            raise http.client.IncompleteRead(CONTENT[:3])

    opener = Opener(TruncatedBody())
    client, runner = transport(opener)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists() and not runner.calls


def test_public_only_network_failure_has_no_authenticated_retry(tmp_path):
    opener = Opener(URLError("offline"))
    client, runner = transport(opener, mode="public-only")
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists() and not runner.calls


def test_content_length_mismatch_is_fatal_without_fallback(tmp_path):
    opener = Opener(Response(CONTENT, headers={"Content-Length": str(len(CONTENT) + 1)}))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, destination)
    assert not destination.exists() and not runner.calls


def test_default_urllib_opener_does_not_automatically_follow_redirects(monkeypatch):
    import urllib.request
    from urllib.response import addinfourl
    from icsot_observer.public_assets import public_opener

    seen = []

    class FakeHTTPSHandler(urllib.request.BaseHandler):
        def https_open(self, request):
            seen.append(request.full_url)
            headers = Message()
            headers["Location"] = "https://attacker.test/steal"
            response = addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "Found"
            return response

    monkeypatch.setattr(urllib.request, "HTTPSHandler", FakeHTTPSHandler)
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})
    opener = public_opener()
    with pytest.raises(HTTPError) as error:
        opener(urllib.request.Request(URL), timeout=1)
    error.value.close()
    assert seen == [URL]


def test_existing_destination_is_never_deleted(tmp_path):
    opener = Opener(Response(CONTENT))
    client, runner = transport(opener)
    destination = tmp_path / NAME
    destination.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        client.download_asset(TAG, NAME, destination)
    assert destination.read_bytes() == b"existing"
    assert not opener.requests and not runner.calls


@pytest.mark.parametrize("url", [123, {"url": URL}, True])
def test_non_string_public_url_fails_closed(tmp_path, url):
    opener = Opener()
    client, runner = transport(opener, url=url)
    with pytest.raises(StateError):
        client.download_asset(TAG, NAME, tmp_path / NAME)
    assert not opener.requests and not runner.calls


def test_signed_redirect_url_is_not_in_error(tmp_path):
    secret = "private-signed-query"
    opener = Opener(http_error(302, {"Location": "https://example.com/blob?signature=" + secret}))
    client, runner = transport(opener)
    with pytest.raises(StateError) as error:
        client.download_asset(TAG, NAME, tmp_path / NAME)
    assert secret not in str(error.value)
    assert not runner.calls


def test_proof_marker_uses_public_asset_route(tmp_path, monkeypatch):
    import tempfile
    from icsot_observer.proof_maintenance import MARKER, ProofTransport

    opener = Opener(Response(CONTENT))
    runner = BinaryRunner()
    client = ProofTransport(REPO, runner=runner, public_opener=opener)
    asset = {"id": 7, "name": MARKER, "size": len(CONTENT),
             "browser_download_url": f"https://github.com/{REPO}/releases/download/{TAG}/{MARKER}"}
    release = {"id": 1, "tag_name": TAG, "draft": False, "assets": [asset]}
    monkeypatch.setattr(client, "_api", lambda *args, **kwargs: release)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    assert client.marker(TAG) == CONTENT
    assert len(opener.requests) == 1
    assert not runner.calls
    assert client.asset_download_counts["public_downloads"] == 1


def test_urllib_redirect_flow_over_local_http_without_credentials(tmp_path, monkeypatch):
    import http.client
    import threading
    import urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from icsot_observer.public_assets import public_opener

    received = []

    class ServerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.path, dict(self.headers)))
            if self.path.startswith("/owner/"):
                self.send_response(302)
                self.send_header("Location", CDN)
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", str(len(CONTENT)))
                self.end_headers()
                self.wfile.write(CONTENT)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), ServerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        class LocalConnection(http.client.HTTPConnection):
            def __init__(self, host, **kwargs):
                super().__init__("127.0.0.1", server.server_port, **kwargs)

        class LocalHTTPSHandler(urllib.request.HTTPSHandler):
            def https_open(self, request):
                return self.do_open(LocalConnection, request)

        monkeypatch.setattr(urllib.request, "HTTPSHandler", LocalHTTPSHandler)
        monkeypatch.setattr(urllib.request, "getproxies", lambda: {})
        monkeypatch.setenv("GH_TOKEN", "sensitive-test-token")
        client, runner = transport(public_opener())
        client.download_asset(TAG, NAME, tmp_path / NAME)
        assert (tmp_path / NAME).read_bytes() == CONTENT
        assert len(received) == 2
        assert received[0][0].endswith(f"/{TAG}/{NAME}")
        assert received[1][0] == "/blob?signature=example"
        for _, headers in received:
            normalized = {key.lower(): value for key, value in headers.items()}
            assert not ({"authorization", "proxy-authorization", "cookie"} & normalized.keys())
            assert "sensitive-test-token" not in repr(headers)
        assert not runner.calls
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
