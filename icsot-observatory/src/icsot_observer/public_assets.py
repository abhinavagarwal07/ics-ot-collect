"""Credential-free, bounded byte downloads from GitHub's public asset route.

Metadata discovery stays with the authenticated transport. Never pass its
headers or credentials to this opener, including on redirects.
"""
from __future__ import annotations

import hashlib
import http.client
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import unquote, urljoin, urlsplit

MAX_PUBLIC_ASSET_BYTES = 2 * 1024 ** 3 - 1
PUBLIC_ASSET_IDLE_TIMEOUT_SECONDS = 35
_DELIVERY_HOSTS = frozenset(("github.com", "release-assets.githubusercontent.com",
                             "objects.githubusercontent.com", "github-releases.githubusercontent.com"))
_HEADERS = {"Accept": "application/octet-stream", "Accept-Encoding": "identity",
            "User-Agent": "ICSOT-Observatory public-asset reader"}


class PublicAssetInvalid(RuntimeError):
    """Policy or integrity failure; authenticated retry cannot repair trust."""


class PublicAssetUnavailable(RuntimeError):
    """A bounded public availability failure may use authenticated fallback."""

    def __init__(self, *, status: int | None = None):
        super().__init__("Public GitHub asset is unavailable")
        self.status = status


def _raise_network_failure(error: Exception) -> None:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if (isinstance(reason, ssl.SSLCertVerificationError) or
            isinstance(reason, ssl.SSLError) and getattr(reason, "reason", None) == "CERTIFICATE_VERIFY_FAILED"):
        raise PublicAssetInvalid("Public GitHub asset TLS certificate verification failed") from None
    raise PublicAssetUnavailable() from None


class PublicAssetRateLimited(RuntimeError):
    def __init__(self, retry_after: str | None, reset: str | None = None):
        super().__init__("Public GitHub asset download was rate limited")
        self.retry_after = retry_after
        self.reset = reset


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def public_opener():
    return urllib.request.build_opener(_NoRedirect()).open


def _allowed_url(url: str) -> None:
    if not isinstance(url, str):
        raise PublicAssetInvalid("Untrusted public GitHub asset URL")
    try:
        parts = urlsplit(url)
        valid = (parts.scheme == "https" and parts.hostname in _DELIVERY_HOSTS and
                 parts.port in (None, 443) and not parts.username and not parts.password and
                 not parts.fragment and not any(ord(char) <= 32 or ord(char) == 127 for char in url))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise PublicAssetInvalid("Untrusted public GitHub asset URL")


def check_browser_url(url: str, repository: str, tag: str, name: str) -> None:
    _allowed_url(url)
    parts = urlsplit(url)
    path = unquote(parts.path)
    prefix = "/" + repository + "/releases/download/"
    if (parts.hostname != "github.com" or parts.query or
            path[:len(prefix)].lower() != prefix.lower() or path[len(prefix):] != tag + "/" + name):
        raise PublicAssetInvalid("Public asset URL does not match the selected release asset")


def download_budget_seconds(size: int) -> int:
    # Allow a slow but useful 1 MiB/s transfer plus two minutes of setup margin.
    # The fixed ceiling also bounds near-2-GiB legacy assets.
    return min(1800, 120 + (size + 1024 ** 2 - 1) // (1024 ** 2))


def download_public(url: str, target, *, size: int, digest: str | None, opener,
                    on_request, timeout: float | None = None) -> None:
    """At most six HTTP requests (five redirects), one deadline, exact bytes.

    Truncation and hash/length mismatches never trigger another transport.
    Network timeouts/resets may discard partial bytes and use the caller's
    authenticated fallback; local write errors are not network failures.
    """
    deadline = time.monotonic() + (download_budget_seconds(size) if timeout is None else timeout)
    for hop in range(6):
        _allowed_url(url)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublicAssetUnavailable()
        # Build a new request at every hop; signed URLs never receive auth,
        # cookies, a Referer, or arbitrary headers from a previous response.
        request = urllib.request.Request(url, headers=dict(_HEADERS), method="GET")
        on_request()
        try:
            response = opener(request, timeout=min(PUBLIC_ASSET_IDLE_TIMEOUT_SECONDS, remaining))
        except urllib.error.HTTPError as error:
            try:
                status, headers = error.code, error.headers
                retry_after = headers.get("Retry-After")
                body = error.read(4096) if status == 403 else b""
                if (status == 429 or retry_after is not None or
                        status == 403 and (headers.get("X-RateLimit-Remaining") == "0" or
                        b"rate limit" in body.lower() or b"secondary rate" in body.lower() or
                        b"abuse" in body.lower())):
                    raise PublicAssetRateLimited(retry_after, headers.get("X-RateLimit-Reset"))
                if status in (301, 302, 303, 307, 308):
                    location = headers.get("Location")
                    if hop == 5 or not location:
                        raise PublicAssetInvalid("Public asset redirect bound exceeded or missing location")
                    url = urljoin(url, location)
                    _allowed_url(url)
                    continue
                if status in (401, 403, 404, 408, 410) or 500 <= status <= 599:
                    raise PublicAssetUnavailable(status=status)
                raise PublicAssetInvalid("Unexpected public GitHub asset response")
            finally:
                error.close()
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            _raise_network_failure(error)
        with response:
            if response.getcode() != 200:
                raise PublicAssetInvalid("Unexpected public GitHub asset response")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) != size):
                raise PublicAssetInvalid("Public GitHub asset length differs from metadata")
            actual, hasher = 0, hashlib.sha256()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PublicAssetUnavailable()
                try:
                    # urllib's HTTPResponse exposes the connected socket here.
                    # read1 makes at most one underlying read, so a slow stream
                    # cannot refresh the original timeout indefinitely.
                    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                    if sock is not None:
                        sock.settimeout(min(PUBLIC_ASSET_IDLE_TIMEOUT_SECONDS, remaining))
                    reader = getattr(response, "read1", response.read)
                    chunk = reader(min(1024 * 1024, size - actual + 1))
                except http.client.HTTPException:
                    raise PublicAssetInvalid("Public GitHub asset body was truncated or malformed") from None
                except (OSError, TimeoutError, urllib.error.URLError) as error:
                    _raise_network_failure(error)
                if not chunk:
                    break
                actual += len(chunk)
                if actual > size:
                    raise PublicAssetInvalid("Public GitHub asset exceeds its advertised size")
                target.write(chunk)
                hasher.update(chunk)
            if actual != size or digest is not None and hasher.hexdigest() != digest:
                raise PublicAssetInvalid("Public GitHub asset hash or size differs from metadata")
            return
    raise PublicAssetInvalid("Public asset redirect bound exceeded")
