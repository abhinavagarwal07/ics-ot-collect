"""Selected-repository encrypted working snapshots on GitHub Releases.

The authoritative selector is ``collector-state:repos/<numeric id>.json``.
Release names and timestamps are never selectors. The pointer names an immutable
index ciphertext; its decrypted context is checked before any state is restored.
The existing RSA-OAEP/AES-GCM envelope is used for every part and index.

Call ``publish(..., quiescent=True)`` only after all capture/finalizer callbacks
have joined. A controller lock excludes another local collector, and SQLite's
backup API captures committed WAL contents without copying WAL/SHM files. This
module retains every generation and makes no aggregate storage-cap claim.
Git ancestry detects concurrent writers, not an administrator replacing history.
"""
from __future__ import annotations

import copy
import hashlib
import json
import lzma
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import time
import tempfile
import uuid
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol
from urllib.parse import quote

from .core import REPO_RE, canonical_json, utc_iso
from .encryption import decrypt_file, encrypt_file, public_key_fingerprint
from .runtime import ControllerLock
from .public_assets import (MAX_PUBLIC_ASSET_BYTES, PublicAssetInvalid, PublicAssetRateLimited,
                            PublicAssetUnavailable, check_browser_url, download_public,
                            public_opener as make_public_opener)

SCHEMA_VERSION = 1
BRANCH = "collector-state"
MAX_PART_BYTES = 1024 ** 3
# Maximum codec header plus framing and GCM tag.
ENVELOPE_OVERHEAD = 65536 + 64
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"[0-9a-f]{32}\Z")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


class StateError(RuntimeError):
    """Invalid, corrupt, incompatible, or concurrently changed working state."""


class StateIntegrityError(StateError):
    """A bounded, non-payload description of a verified integrity mismatch."""

    def __init__(self, message: str, *, stage: str, subject: str, field: str,
                 expected: str | int, actual: str | int):
        if stage not in {"asset_download", "part_decode", "file_reconstruction", "group_verification", "tar_member"}:
            raise StateError("Invalid integrity diagnostic stage")
        if not isinstance(subject, str) or not re.fullmatch(
                r"(?:asset:|part:|path-sha256:)[0-9a-f]{64}|[A-Za-z0-9._/ -]{1,256}", subject):
            raise StateError("Invalid integrity diagnostic subject")
        if field == "sha256":
            valid = all(isinstance(value, str) and _HASH.fullmatch(value) for value in (expected, actual))
        elif field == "bytes":
            valid = all(type(value) is int and 0 <= value <= 2 ** 63 - 1 for value in (expected, actual))
        else:
            valid = False
        if not valid:
            raise StateError("Invalid integrity diagnostic values")
        super().__init__(message)
        self.detail = {"stage": stage, "subject": subject, "field": field,
                       "expected": expected, "actual": actual}


def _diagnostic_path(path: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9._/ -]{1,256}", path):
        return path
    return "path-sha256:" + hashlib.sha256(path.encode("utf-8", errors="surrogatepass")).hexdigest()


def _verify_file_integrity(path: Path, *, size: int, digest: str, stage: str,
                           subject: str, message: str) -> None:
    actual_size = path.stat().st_size
    if actual_size != size:
        raise StateIntegrityError(message, stage=stage, subject=subject, field="bytes",
                                  expected=size, actual=actual_size)
    actual_digest = _digest(path)
    if actual_digest != digest:
        raise StateIntegrityError(message, stage=stage, subject=subject, field="sha256",
                                  expected=digest, actual=actual_digest)


class StateReleaseMissingError(StateError):
    """Exact authorized REST/GraphQL lookup established release absence."""


class StateDeferredError(StateError):
    """Publication deferred by destination API headroom or a rate response."""

    def __init__(self, message: str, *, retry_not_before: float | None = None,
                 reason: str = "rate_limit", request_count: int = 0):
        super().__init__(message)
        self.retry_not_before = retry_not_before
        self.reason = reason
        self.request_count = request_count


class StateConflictError(StateError):
    """The selected repository's authoritative pointer changed concurrently."""


class StateTransport(Protocol):
    def branch_head(self) -> str | None: ...
    def read_pointer(self, head: str, repository_id: int) -> bytes | None: ...
    def read_slug_binding(self, head: str, slug: str) -> bytes | None: ...
    def commit_pointer(self, parent: str | None, repository_id: int, data: bytes) -> str: ...
    def advance_branch(self, expected_head: str | None, commit: str) -> bool: ...
    def ensure_release(self, tag: str) -> None: ...
    def upload_asset(self, tag: str, name: str, source: Path) -> None: ...
    def download_asset(self, tag: str, name: str, destination: Path) -> None: ...
    def find_asset(self, tag: str, name: str, *, refresh: bool = False) -> dict | None: ...


@dataclass(frozen=True)
class StateSelection:
    head: str | None
    pointer: dict[str, Any] | None
    index: dict[str, Any] | None


@dataclass(frozen=True)
class RecoveryCandidatePool:
    """Audited, target-specific candidates; never an authoritative predecessor.

    The containing recovery descriptor pins the source ledger and epoch. Each
    selected part still needs authenticated decryption and exact decoded-content
    matching before it can enter a newly sealed generation.
    """

    destination_repository: str
    repository_id: int
    slug: str
    recipient_spki_sha256: str
    recovery_epoch: str
    source_ledger_sha256: str
    old_generation: str
    parts: tuple[dict[str, Any], ...]
    lineage_generations: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedState:
    """Local SHA-pinned bytes for one generation; retain directory until commit."""

    directory: Path
    manifest_sha256: str
    generation: str
    source_import_sha256: str
    pointer: dict[str, Any]
    assets: tuple[dict[str, Any], ...]
    release_tags: tuple[str, ...]


class _PreparedSink:
    def __init__(self, directory: Path):
        self.directory = directory
        self.assets: list[dict] = []
        self.index: dict | None = None
        self.source_files: list[dict] = []
        self.proof_outbox_node: dict | None = None

    def capture(self, ref: dict, source: Path) -> None:
        relative = f"assets/{ref['release_tag']}/{ref['name']}"
        target = self.directory / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.exists():
            raise StateError("Prepared ciphertext path already exists")
        try:
            os.link(source, target)
        except OSError:
            shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        if target.stat().st_size != ref["ciphertext_bytes"] or _digest(target) != ref["ciphertext_sha256"]:
            raise StateError("Prepared ciphertext differs from encryption output")
        self.assets.append({"path": relative, "ref": dict(ref)})


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(4 * 1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def _json(raw: bytes, label: str) -> dict:
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or canonical_json(obj) != raw:
            raise ValueError("noncanonical object")
        return obj
    except (ValueError, TypeError, UnicodeError) as exc:
        raise StateError(f"Invalid {label}") from exc


def _safe_path(name: Any) -> str:
    if (not isinstance(name, str) or not name or "\\" in name or "\x00" in name or
            name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/")) or
            PurePosixPath(name).is_absolute()):
        raise StateError("Unsafe snapshot member path")
    if name.split("/", 1)[0] == ".collector.lock":
        raise StateError("Snapshot must not replace the controller lock")
    return name


def _asset_ref(value: Any) -> dict:
    if not isinstance(value, dict):
        raise StateError("Invalid immutable asset reference")
    for key in ("release_tag", "name"):
        if not isinstance(value.get(key), str) or not _ASSET.fullmatch(value[key]):
            raise StateError("Invalid immutable asset name")
    if (not isinstance(value.get("ciphertext_sha256"), str) or
            not _HASH.fullmatch(value["ciphertext_sha256"]) or
            type(value.get("ciphertext_bytes")) is not int or value["ciphertext_bytes"] < 1):
        raise StateError("Invalid immutable asset digest/size")
    return value


def _slug_path(slug: str) -> str:
    return "slugs/" + hashlib.sha256(slug.lower().encode("utf-8")).hexdigest() + ".json"


def _slug_binding(slug: str, repository_id: int) -> dict:
    return {"schema_version": SCHEMA_VERSION, "slug_key": slug.lower(), "repository_id": repository_id}


def _asset_identity(value: dict) -> bytes:
    return canonical_json({key: value[key] for key in
                           ("release_tag", "name", "ciphertext_sha256", "ciphertext_bytes")})


class GhCliStateTransport:
    """GitHub transport using the existing ``gh`` authentication environment.

    It never reads or substitutes the public-source PAT. GitHub Actions should
    supply its destination credential as GH_TOKEN. ``runner`` is injectable for
    offline tests; constructing this object performs no network request.
    """

    def __init__(self, destination_repository: str, *, runner: Callable = subprocess.run,
                 rate_reserve: int = 100, transient_retries: int = 1,
                 clock: Callable[[], float] = time.time, asset_download_mode: str | None = None,
                 public_opener: Callable | None = None, cycle_slot: int | None = None):
        if not REPO_RE.fullmatch(destination_repository):
            raise ValueError("Invalid destination repository")
        if type(rate_reserve) is not int or rate_reserve < 0 or not 0 <= transient_retries <= 2:
            raise ValueError("Invalid bounded GitHub transport retry/reserve policy")
        mode = asset_download_mode if asset_download_mode is not None else os.getenv(
            "ICSOT_ASSET_DOWNLOAD_MODE", "public-first")
        if mode not in ("public-first", "public-only", "authenticated"):
            raise ValueError("Invalid GitHub asset download mode")
        self.asset_download_mode = mode
        self._public_opener = public_opener if public_opener is not None else make_public_opener()
        self._public_unavailable_releases: set[str] = set()
        self._public_unavailable_until = 0.0
        self.asset_download_counts = {"public_http_requests": 0, "public_downloads": 0,
                                      "public_bytes": 0, "authenticated_downloads": 0,
                                      "authenticated_attempts": 0, "fallbacks": 0}
        self.repository, self.runner = destination_repository, runner
        if cycle_slot is None and os.getenv("ICSOT_RELEASE_LAYOUT") == "cycle-v1":
            configured = os.getenv("ICSOT_CYCLE_SLOT")
            if configured is not None and not configured.isdecimal():
                raise ValueError("Invalid frozen cycle slot")
            cycle_slot = int(configured) if configured is not None else int(clock() // 21600)
        if cycle_slot is not None and (type(cycle_slot) is not int or cycle_slot < 0):
            raise ValueError("Invalid frozen cycle slot")
        from .cycle_release import CycleReleaseCatalog
        self.cycle_slot = cycle_slot
        self._cycle_catalog = CycleReleaseCatalog(self, cycle_slot)
        self.rate_reserve, self.transient_retries, self.clock = rate_reserve, transient_retries, clock
        self.request_count = 0
        self.rate_remaining: int | None = None
        self.rate_reset: float | None = None
        self.retry_not_before: float | None = None
        self._rate_windows: dict[tuple, int] = {}
        self.graphql_request_count = 0
        self.graphql_rate_remaining: int | None = None
        self.graphql_rate_reset: float | None = None
        self._graphql_rate_windows: dict[tuple, int] = {}
        self._last_graphql_rate_headers: dict[str, Any] = {}
        self._last_repo_rate_headers: dict[str, Any] = {}
        self._last_response_rate_headers: dict[str, Any] = {}
        self._last_response_retry_not_before: float | None = None
        self._last_quota_probe: dict[str, Any] = {}
        self._fallback_rate_seconds = 60
        self.last_budget_metrics: dict[str, Any] = {}
        self._releases: dict[str, dict] = {}
        self._assets: dict[str, dict[str, dict]] = {}
        self._listed: set[str] = set()
        self._git_files: dict[tuple[str, str], bytes | None] = {}

    def copy_runtime_state_to(self, other: "GhCliStateTransport") -> None:
        """Preserve rate constraints when a specialized adapter wraps this one."""
        if other.repository != self.repository:
            raise ValueError("Destination transport state cannot cross repositories")
        for name in ("request_count", "rate_remaining", "rate_reset", "retry_not_before",
                     "_rate_windows", "_last_repo_rate_headers", "_last_response_rate_headers",
                     "graphql_request_count", "graphql_rate_remaining", "graphql_rate_reset",
                     "_graphql_rate_windows", "_last_graphql_rate_headers", "_last_response_retry_not_before",
                     "_last_quota_probe", "_fallback_rate_seconds", "last_budget_metrics"):
            setattr(other, name, copy.deepcopy(getattr(self, name)))
        other.asset_download_mode, other._public_opener = self.asset_download_mode, self._public_opener
        other._public_unavailable_until = self._public_unavailable_until
        other.asset_download_counts = copy.deepcopy(self.asset_download_counts)
        other._public_unavailable_releases = self._public_unavailable_releases
        other.cycle_slot = self.cycle_slot
        other._cycle_catalog.slot = self.cycle_slot
        for name in ("documents", "locators", "dirty", "git_downloads", "git_bytes"):
            setattr(other._cycle_catalog, name, getattr(self._cycle_catalog, name))
        # These caches name immutable Git objects and uploaded asset identities;
        # specialized adapters can retain discoveries made in either direction.
        for name in ("_releases", "_assets", "_listed", "_git_files"):
            setattr(other, name, getattr(self, name))

    @staticmethod
    def _rate_headers(headers: dict[str, str]) -> dict[str, Any]:
        measured: dict[str, Any] = {}
        for header, field, parser in (("x-ratelimit-remaining", "remaining", int),
                                       ("x-ratelimit-reset", "reset", float),
                                       ("x-ratelimit-limit", "limit", int)):
            if header in headers:
                try:
                    measured[field] = parser(headers[header])
                except ValueError:
                    pass
        if "x-ratelimit-resource" in headers:
            measured["resource"] = headers["x-ratelimit-resource"]
        return measured

    def _refresh_rate_windows(self) -> None:
        now = self.clock()
        for key in list(self._rate_windows):
            if key[1] <= now:
                del self._rate_windows[key]
        if self._rate_windows:
            # Keep each reset independent. A larger or differently scoped
            # observation cannot erase a still-live, more restrictive window.
            key, remaining = min(self._rate_windows.items(), key=lambda item: (item[1], -item[0][1]))
            self.rate_remaining, self.rate_reset = remaining, key[1]
        else:
            self.rate_remaining, self.rate_reset = None, None

    def _observe_rate(self, measured: dict[str, Any], *, scope: str) -> None:
        if (type(measured.get("remaining")) is not int or measured["remaining"] < 0 or
                not isinstance(measured.get("reset"), (int, float)) or measured["reset"] <= self.clock()):
            return
        key = (scope, float(measured["reset"]), measured.get("resource"), measured.get("limit"))
        previous = self._rate_windows.get(key)
        self._rate_windows[key] = min(previous, measured["remaining"]) if previous is not None else measured["remaining"]
        self._refresh_rate_windows()

    def _refresh_graphql_windows(self) -> None:
        for key in list(self._graphql_rate_windows):
            if key[0] <= self.clock():
                del self._graphql_rate_windows[key]
        if self._graphql_rate_windows:
            key, remaining = min(self._graphql_rate_windows.items(), key=lambda item: (item[1], -item[0][0]))
            self.graphql_rate_remaining, self.graphql_rate_reset = remaining, key[0]
        else:
            self.graphql_rate_remaining, self.graphql_rate_reset = None, None

    def _observe_graphql_rate(self, measured: dict[str, Any]) -> None:
        if (type(measured.get("remaining")) is not int or measured["remaining"] < 0 or
                not isinstance(measured.get("reset"), (int, float)) or measured["reset"] <= self.clock()):
            return
        key = (float(measured["reset"]), measured.get("limit"))
        previous = self._graphql_rate_windows.get(key)
        self._graphql_rate_windows[key] = min(previous, measured["remaining"]) if previous is not None else measured["remaining"]
        self._last_graphql_rate_headers = dict(measured)
        self._refresh_graphql_windows()

    def _retry_after(self, value: str | None) -> float | None:
        if value is None:
            return None
        try:
            return self.clock() + max(0, float(value))
        except ValueError:
            from email.utils import parsedate_to_datetime
            try:
                return parsedate_to_datetime(value).timestamp()
            except (ValueError, TypeError, OverflowError):
                return None

    def _destination_endpoint(self, endpoint: str) -> bool:
        path = f"repos/{self.repository}"
        return endpoint == path or endpoint.startswith(path + "/") or endpoint.startswith(
            f"https://uploads.github.com/{path}/")

    @staticmethod
    def _response(raw: bytes) -> tuple[dict[str, str], bytes, int | None]:
        headers: dict[str, str] = {}
        status = None
        while raw.startswith(b"HTTP/"):
            candidates = [(raw.find(marker), marker) for marker in (b"\r\n\r\n", b"\n\n")]
            candidates = [(offset, marker) for offset, marker in candidates if offset >= 0]
            if not candidates:
                raise StateError("Invalid GitHub API response headers")
            offset, marker = min(candidates, key=lambda item: item[0])
            if offset > 65536:
                raise StateError("Oversized GitHub API response headers")
            lines = raw[:offset].decode("iso-8859-1").splitlines()
            try:
                status = int(lines[0].split()[1])
            except (ValueError, IndexError) as exc:
                raise StateError("Invalid GitHub API response status") from exc
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.lower().strip()] = value.strip()
            raw = raw[offset + len(marker):]
        return headers, raw, status

    def _defer(self, reason: str, retry: float | None = None) -> StateDeferredError:
        error = StateDeferredError("GitHub state publication deferred: " + reason,
                                   retry_not_before=retry, reason=reason, request_count=self.request_count)
        error.rate_measurements = dict(self.last_budget_metrics)
        if self._last_graphql_rate_headers:
            error.rate_measurements["destination_github_graphql_rate_probe"] = dict(self._last_graphql_rate_headers)
        if self._last_quota_probe:
            error.rate_measurements["destination_github_recovery_rate_probe"] = dict(self._last_quota_probe)
        return error

    def _probe_core_quota(self) -> dict:
        """One free-primary GET, outside the exhausted-request guard.

        It is still a counted HTTP operation. Probe failures preserve the
        original deferral; original response diagnostics remain untouched.
        """
        self.request_count += 1
        self._last_quota_probe = {"status": "unavailable"}
        try:
            result = self.runner(["gh", "api", "rate_limit", "--method", "GET", "--include"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            _, raw, status = self._response(result.stdout or b"")
            if result.returncode or status is not None and not 200 <= status < 300:
                return {}
            value = json.loads(raw)
            core = value.get("resources", {}).get("core", {})
            if (not isinstance(core, dict) or type(core.get("remaining")) is not int or core["remaining"] < 0 or
                    type(core.get("limit")) is not int or core["limit"] < 1 or
                    not isinstance(core.get("reset"), (int, float)) or core["reset"] <= self.clock()):
                return {}
            measured = {key: core[key] for key in ("remaining", "reset", "limit")}
            measured["resource"] = "core"
            self._observe_rate(measured, scope="generic_core_probe")
            self._last_quota_probe = {"status": "complete", **measured}
            return measured
        except (OSError, subprocess.SubprocessError, StateError, ValueError, TypeError, AttributeError):
            return {}

    def _rate_retry(self, observed: dict, combined: str, retry: float | None, *, graphql: bool) -> float:
        secondary = "secondary" in combined.lower() or "abuse" in combined.lower()
        primary = observed.get("remaining") == 0 or (not secondary and "api rate limit exceeded" in combined.lower())
        resource = observed.get("resource") or self._last_repo_rate_headers.get("resource", "core")
        known = [key[1] for key in self._rate_windows if key[2] in (None, resource)] if not graphql else []
        known_reset = max(known, default=None)
        reset = observed.get("reset") or (self.graphql_rate_reset if graphql else known_reset)
        if not graphql and resource == "core" and retry is None and "reset" not in observed and not secondary:
            probe = self._probe_core_quota()
            primary = primary or probe.get("remaining") == 0
            if probe.get("reset") is not None:
                reset = max(reset or 0, probe["reset"])
        if primary and reset is not None:
            retry = max(retry or 0, reset)
        if retry is None:
            retry = self.clock() + self._fallback_rate_seconds
            self._fallback_rate_seconds = min(900, self._fallback_rate_seconds * 2)
        if primary and not graphql:
            self._observe_rate({"remaining": 0, "reset": retry, "resource": resource,
                "limit": self._last_repo_rate_headers.get("limit")}, scope="repository")
        if self._last_response_retry_not_before is not None or secondary or not primary or graphql and reset is None:
            self.retry_not_before = max(self.retry_not_before or 0, retry)
        return retry

    def _guard_rate(self, *, graphql: bool = False) -> None:
        self._refresh_rate_windows()
        self._refresh_graphql_windows()
        now = self.clock()
        if self.retry_not_before is not None and now < self.retry_not_before:
            raise self._defer("destination Retry-After has not elapsed", self.retry_not_before)
        if graphql and self.graphql_rate_remaining is not None and self.graphql_rate_remaining <= 0:
            raise self._defer("destination GraphQL quota exhausted", self.graphql_rate_reset)
        if (not graphql and self.rate_remaining is not None and self.rate_remaining <= self.rate_reserve and
                (self.rate_reset is None or now < self.rate_reset)):
            raise self._defer("destination primary API reserve reached", self.rate_reset)

    def _run(self, args: list[str], *, data: bytes | None = None,
             stdout: Any = subprocess.PIPE, missing_ok: bool = False) -> Any:
        is_get = "--method" not in args or args[args.index("--method") + 1] == "GET"
        graphql = args[1] == "graphql"
        capture_headers = stdout == subprocess.PIPE
        command = ["gh", *args, *(["--include"] if capture_headers else [])]
        for attempt in range(self.transient_retries + 1):
            self._guard_rate(graphql=graphql)
            self.request_count += 1
            if graphql:
                self.graphql_request_count += 1
                # This fixed scalar lookup has cost one; response headers/body
                # provide the authoritative remaining GraphQL points.
                for key in self._graphql_rate_windows:
                    self._graphql_rate_windows[key] = max(0, self._graphql_rate_windows[key] - 1)
                self._refresh_graphql_windows()
            else:
                for key in self._rate_windows:
                    self._rate_windows[key] = max(0, self._rate_windows[key] - 1)
                self._refresh_rate_windows()
            result = self.runner(command, input=data, stdout=stdout, stderr=subprocess.PIPE, check=False)
            raw = result.stdout or b""
            headers, body, status = self._response(raw) if capture_headers else ({}, raw, None)
            self._last_http_status = status
            observed = self._rate_headers(headers)
            self._last_response_rate_headers = observed
            retry = self._retry_after(headers.get("retry-after"))
            self._last_response_retry_not_before = retry
            if graphql:
                self._observe_graphql_rate(observed)
            elif self._destination_endpoint(args[1]):
                if "remaining" in observed and "reset" in observed:
                    self._last_repo_rate_headers = dict(observed)
                self._observe_rate(observed, scope="repository")
            if not result.returncode:
                return body if capture_headers else result.stdout
            error = result.stderr.decode("utf-8", "replace") if result.stderr else ""
            if missing_ok and (status == 404 or status is None and "HTTP 404" in error):
                return None
            combined = (body.decode("utf-8", "replace") if capture_headers else "") + error
            rate_failure = (status == 429 or "HTTP 429" in error or
                            "rate limit" in combined.lower() or "secondary rate" in combined.lower() or
                            status == 403 and observed.get("remaining") == 0 or retry is not None)
            if rate_failure:
                retry = self._rate_retry(observed, combined, retry, graphql=graphql)
                raise self._defer("destination API rate limit", retry)
            transient = (status in (502, 503, 504) or any(f"HTTP {code}" in error for code in (502, 503, 504)) or any(text in error.lower() for text in
                         ("connection reset", "connection timed out", "unexpected eof")))
            if is_get and transient and attempt < self.transient_retries:
                if stdout != subprocess.PIPE:
                    stdout.seek(0)
                    stdout.truncate()
                continue  # One immediate retry; never sleep or blindly retry a write.
            raise StateError("GitHub state transport request failed")
        raise StateError("GitHub state transport retry bound reached")

    def _api(self, endpoint: str, *, method: str = "GET", payload: dict | None = None,
             missing_ok: bool = False) -> Any:
        args = ["api", endpoint, "--method", method]
        data = None
        if payload is not None:
            args += ["--input", "-"]
            data = canonical_json(payload)
        raw = self._run(args, data=data, missing_ok=missing_ok)
        if raw is None:
            return None  # Only _run's explicit missing_ok 404 path.
        try:
            value = json.loads(raw) if raw else None
        except (ValueError, UnicodeError) as exc:
            raise StateError("Invalid GitHub API JSON response") from exc
        if missing_ok and value is None:
            raise StateError("Empty GitHub API response cannot establish a missing resource")
        return value

    def publication_budget(self, required_requests: int) -> dict:
        """Measure repository headers and generic core without widening headroom."""
        self._api(f"repos/{self.repository}")
        repository_headers = dict(self._last_response_rate_headers)
        if "remaining" not in repository_headers or "reset" not in repository_headers:
            raise StateError("Destination repository rate headers could not be measured")
        measured = self._api("rate_limit")
        generic_headers = dict(self._last_response_rate_headers)
        core = measured.get("resources", {}).get("core", {})
        if (type(core.get("remaining")) is not int or
                not isinstance(core.get("reset"), (int, float))):
            raise StateError("Destination token generic rate headroom could not be measured")
        # /rate_limit may report a different applicable bucket. It can add a
        # smaller conservative constraint, but cannot replace repository headers
        # with a larger remaining count or discard an earlier live reset.
        if self.rate_remaining is None:
            raise StateError("Destination repository rate window is unavailable")
        if core["remaining"] <= self.rate_remaining:
            self._observe_rate({**core, "resource": "core"}, scope="generic_core")
        self.last_budget_metrics = {
            "destination_github_repository_rate_probe": repository_headers,
            "destination_github_generic_core_rate_probe": dict(core),
            "destination_github_generic_rate_response_headers": generic_headers,
            "destination_github_rate_remaining_before_state_upload": self.rate_remaining,
            "destination_github_required_requests_estimate": required_requests,
            "destination_github_rate_reserve": self.rate_reserve,
            "destination_github_rate_reset": self.rate_reset,
        }
        if required_requests > max(0, self.rate_remaining - self.rate_reserve):
            raise self._defer(f"destination headroom {self.rate_remaining} is below estimated "
                              f"{required_requests} requests plus reserve {self.rate_reserve}", self.rate_reset)
        return dict(self.last_budget_metrics)

    def branch_head(self) -> str | None:
        ref = self._api(f"repos/{self.repository}/git/ref/heads/{BRANCH}", missing_ok=True)
        return ref["object"]["sha"] if ref else None

    def _read_git_file(self, head: str, path: str) -> bytes | None:
        import base64
        cache_key = (head, path)
        if cache_key in self._git_files:
            return self._git_files[cache_key]
        obj = self._api(f"repos/{self.repository}/contents/{path}?ref={quote(head, safe='')}", missing_ok=True)
        if obj is None:
            self._git_files[cache_key] = None
            return None
        if obj.get("encoding") != "base64" or obj.get("type") != "file":
            raise StateError("Invalid state pointer Git blob")
        try:
            raw = base64.b64decode(obj["content"], validate=False)
            self._git_files[cache_key] = raw
            return raw
        except (ValueError, TypeError) as exc:
            raise StateError("Invalid state pointer Git encoding") from exc

    def read_pointer(self, head: str, repository_id: int) -> bytes | None:
        return self._read_git_file(head, f"repos/{repository_id}.json")

    def read_slug_binding(self, head: str, slug: str) -> bytes | None:
        return self._read_git_file(head, _slug_path(slug))

    def read_proof_outbox(self, head: str, repository_id: int, ref: dict) -> bytes | None:
        return self._read_git_file(head, f"proof-outbox/{repository_id}/{ref['sha256']}.json")

    def commit_pointer(self, parent: str | None, repository_id: int, data: bytes,
                       *, proof_outbox_node: bytes | None = None) -> str:
        import base64
        pointer = _json(data, "Git state pointer")
        slug = pointer.get("slug")
        if not isinstance(slug, str) or not REPO_RE.fullmatch(slug):
            raise StateError("Invalid pointer slug")
        binding = _slug_binding(slug, repository_id)
        previous_binding = self.read_slug_binding(parent, slug) if parent else None
        if previous_binding is not None and previous_binding != canonical_json(binding):
            raise StateConflictError("Repository slug is already bound to another numeric ID")
        outbox = None
        if proof_outbox_node is not None:
            node = _json(proof_outbox_node, "public proof outbox node")
            descriptor = {"sha256": hashlib.sha256(proof_outbox_node).hexdigest(), "bytes": len(proof_outbox_node)}
            if (len(proof_outbox_node) > 4096 or pointer.get("proof_outbox") != descriptor or
                    node.get("repository_id") != repository_id or node.get("slug") != slug or
                    node.get("generation") != pointer.get("generation")):
                raise StateError("Proof outbox node differs from state pointer")
            path = f"proof-outbox/{repository_id}/{descriptor['sha256']}.json"
            old = self._read_git_file(parent, path) if parent else None
            if old is not None and old != proof_outbox_node:
                raise StateConflictError("Immutable proof outbox node differs")
            outbox = {"path": path, "mode": "100644", "type": "blob", "content": proof_outbox_node.decode("utf-8")}
        blob = self._api(f"repos/{self.repository}/git/blobs", method="POST",
                         payload={"content": base64.b64encode(data).decode(), "encoding": "base64"})
        binding_blob = self._api(f"repos/{self.repository}/git/blobs", method="POST", payload={
            "content": base64.b64encode(canonical_json(binding)).decode(), "encoding": "base64"})
        tree_payload = {"tree": [{"path": f"repos/{repository_id}.json", "mode": "100644",
                                   "type": "blob", "sha": blob["sha"]},
                                  {"path": _slug_path(slug), "mode": "100644",
                                   "type": "blob", "sha": binding_blob["sha"]}]}
        if outbox is not None:
            tree_payload["tree"].append(outbox)
        if parent:
            commit = self._api(f"repos/{self.repository}/git/commits/{parent}")
            tree_payload["base_tree"] = commit["tree"]["sha"]
        tree = self._api(f"repos/{self.repository}/git/trees", method="POST", payload=tree_payload)
        result = self._api(f"repos/{self.repository}/git/commits", method="POST", payload={
            "message": f"Update encrypted working state for repository {repository_id}",
            "tree": tree["sha"], "parents": [parent] if parent else [],
        })
        return result["sha"]

    def advance_branch(self, expected_head: str | None, commit: str) -> bool:
        if self.branch_head() != expected_head:
            return False
        try:
            if expected_head is None:
                self._api(f"repos/{self.repository}/git/refs", method="POST",
                          payload={"ref": f"refs/heads/{BRANCH}", "sha": commit})
            else:
                self._api(f"repos/{self.repository}/git/refs/heads/{BRANCH}", method="PATCH",
                          payload={"sha": commit, "force": False})
            return True
        except StateDeferredError:
            raise
        except StateError:
            # The caller rereads the branch after conflicts/uncertain responses.
            return False

    @staticmethod
    def _validate_release(release: Any, tag: str, *, expected_id: int | None = None) -> dict:
        if (not isinstance(release, dict) or type(release.get("id")) is not int or release["id"] < 1 or
                release.get("tag_name") != tag or type(release.get("draft")) is not bool or
                expected_id is not None and release["id"] != expected_id or
                not isinstance(release.get("assets", []), list)):
            raise StateError("Invalid or mismatched GitHub release identity")
        assets = release.get("assets", [])
        if any(not isinstance(asset, dict) or not isinstance(asset.get("name"), str) for asset in assets):
            raise StateError("Invalid GitHub release asset metadata")
        if len({asset["name"] for asset in assets}) != len(assets):
            raise StateError("Duplicate GitHub release asset metadata")
        return release

    def _record_graphql_quota(self, quota: Any) -> None:
        if (not isinstance(quota, dict) or type(quota.get("remaining")) is not int or quota["remaining"] < 0 or
                type(quota.get("limit")) is not int or quota["limit"] < 1 or quota["remaining"] > quota["limit"] or
                type(quota.get("cost")) is not int or quota["cost"] < 0 or
                not isinstance(quota.get("resetAt"), str) or not quota["resetAt"].endswith("Z")):
            raise StateError("Malformed GitHub GraphQL quota response")
        try:
            reset = datetime.fromisoformat(quota["resetAt"].replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise StateError("Malformed GitHub GraphQL quota reset") from None
        self._observe_graphql_rate({"remaining": quota["remaining"], "reset": reset, "cost": quota["cost"],
                                    "limit": quota["limit"], "resource": "graphql"})

    def _find_release_after_tag_404(self, tag: str) -> dict | None:
        # Exact GraphQL lookup includes authorized drafts, unlike REST's tag
        # route. GitHub CLI uses this same lookup followed by REST's numeric ID.
        owner, name = self.repository.split("/", 1)
        query = ("query CollectorReleaseByTag($owner:String!,$name:String!,$tag:String!){"
                 "repository(owner:$owner,name:$name){nameWithOwner release(tagName:$tag){databaseId tagName isDraft}}"
                 " rateLimit{cost remaining resetAt limit}}")
        result = self._api("graphql", method="POST", payload={
            "query": query, "variables": {"owner": owner, "name": name, "tag": tag}})
        if not isinstance(result, dict):
            raise StateError("Malformed GitHub GraphQL release response")
        data = result.get("data")
        if isinstance(data, dict) and "rateLimit" in data:
            self._record_graphql_quota(data["rateLimit"])
        errors = result.get("errors", [])
        if not isinstance(errors, list):
            raise StateError("Malformed GitHub GraphQL errors")
        if errors:
            if any(not isinstance(error, dict) for error in errors):
                raise StateError("Malformed GitHub GraphQL errors")
            rate_limited = any(error.get("type") in ("RATE_LIMITED", "RATE_LIMIT") or
                               "rate limit" in str(error.get("message", "")).lower() or
                               "abuse" in str(error.get("message", "")).lower() for error in errors)
            if rate_limited:
                secondary = any("secondary" in str(error.get("message", "")).lower() or
                                "abuse" in str(error.get("message", "")).lower() for error in errors)
                retry = self._last_response_retry_not_before
                if retry is None and self.graphql_rate_remaining == 0:
                    retry = self.graphql_rate_reset
                if retry is None:
                    retry, secondary = self.clock() + 60, True
                if self._last_response_retry_not_before is not None or secondary:
                    self.retry_not_before = retry
                raise self._defer("destination GraphQL API rate limit", retry)
            raise StateError("GitHub GraphQL release lookup returned errors")
        repository = data.get("repository") if isinstance(data, dict) else None
        if (not isinstance(repository, dict) or not isinstance(repository.get("nameWithOwner"), str) or
                repository["nameWithOwner"].lower() != self.repository.lower() or "release" not in repository):
            raise StateError("GraphQL release lookup did not bind the destination repository")
        if "rateLimit" not in data:
            raise StateError("Missing GitHub GraphQL quota response")
        candidate = repository["release"]
        if candidate is None:
            return None  # A valid error-free exact lookup, never a transport/auth failure.
        if (not isinstance(candidate, dict) or type(candidate.get("databaseId")) is not int or
                candidate["databaseId"] < 1 or candidate.get("tagName") != tag or
                type(candidate.get("isDraft")) is not bool):
            raise StateError("Malformed or mismatched GraphQL release identity")
        release = self._api(f"repos/{self.repository}/releases/{candidate['databaseId']}")
        self._validate_release(release, tag, expected_id=candidate["databaseId"])
        if release["draft"] != candidate["isDraft"]:
            raise StateError("GitHub release draft status changed during lookup")
        return release

    def _release(self, tag: str, *, create: bool = False) -> dict:
        if not _ASSET.fullmatch(tag):
            raise StateError("Invalid state release tag")
        if tag in self._releases:
            return self._releases[tag]
        release = self._api(f"repos/{self.repository}/releases/tags/{tag}", missing_ok=True)
        if release is None:
            release = self._find_release_after_tag_404(tag)
        new = release is None
        if new:
            if not create:
                raise StateReleaseMissingError("GitHub release tag was not found")
            try:
                release = self._api(f"repos/{self.repository}/releases", method="POST", payload={
                    "tag_name": tag, "prerelease": True, "name": tag,
                    "body": "Encrypted collector snapshot; retain pinned Git metadata and prerequisites."})
            except StateDeferredError:
                raise
            except StateError:
                # A concurrent cycle publisher may have created this exact
                # release. Reconcile with a read; never blindly repeat POST.
                release = self._api(f"repos/{self.repository}/releases/tags/{tag}", missing_ok=True)
                if release is None:
                    raise
                new = False
        self._validate_release(release, tag)
        self._releases[tag] = release
        self._assets[tag] = {asset["name"]: asset for asset in release.get("assets", [])}
        if new:
            self._listed.add(tag)
        return release

    def ensure_release(self, tag: str) -> None:
        if self._cycle_catalog.writable(tag):
            self._cycle_catalog.ensure(tag)
            return
        self._release(tag, create=True)

    def upload_asset(self, tag: str, name: str, source: Path) -> None:
        _asset_ref({"release_tag": tag, "name": name, "ciphertext_sha256": "0" * 64,
                    "ciphertext_bytes": 1})
        if self._cycle_catalog.writable(tag):
            self._cycle_catalog.upload(tag, name, source)
            return
        release = self._release(tag, create=True)
        if name in self._assets[tag]:
            raise StateError("Immutable GitHub asset name already exists")
        endpoint = (f"https://uploads.github.com/repos/{self.repository}/releases/{release['id']}/assets"
                    f"?name={quote(name, safe='')}")
        raw = self._run(["api", endpoint, "--method", "POST", "--input", str(source),
                         "-H", "Content-Type: application/octet-stream"])
        asset = json.loads(raw)
        if (not isinstance(asset, dict) or type(asset.get("id")) is not int or
                asset.get("name") != name or asset.get("size") != source.stat().st_size or
                asset.get("state", "uploaded") != "uploaded"):
            raise StateError("Uploaded GitHub asset response differs from local file")
        digest = asset.get("digest")
        if digest is not None and digest != "sha256:" + _digest(source):
            raise StateError("Uploaded GitHub asset digest differs from local ciphertext")
        self._assets[tag][name] = asset

    def find_asset(self, tag: str, name: str, *, refresh: bool = False) -> dict | None:
        if self._cycle_catalog.known(tag):
            return self._cycle_catalog.asset(tag, name)
        self._release(tag)
        if refresh:
            self._listed.discard(tag)
            self._assets[tag] = {}
        return self._find_asset(tag, name)

    def _asset(self, tag: str, name: str) -> dict:
        asset = self._find_asset(tag, name)
        if asset is None:
            raise StateError("Immutable state asset is missing or ambiguous")
        return asset

    def _find_asset(self, tag: str, name: str) -> dict | None:
        if self._cycle_catalog.known(tag):
            return self._cycle_catalog.asset(tag, name)
        release = self._release(tag)
        if name in self._assets[tag]:
            asset = self._assets[tag][name]
            if type(asset.get("id")) is not int:
                raise StateError("Invalid immutable asset ID")
            return asset
        if tag not in self._listed:
            assets = {}
            for page in range(1, 12):  # Releases contain at most 1,000 assets.
                listed = self._api(f"repos/{self.repository}/releases/{release['id']}/assets?per_page=100&page={page}")
                if not isinstance(listed, list):
                    raise StateError("Invalid GitHub release asset listing")
                for asset in listed:
                    if not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or asset["name"] in assets:
                        raise StateError("Invalid or duplicate immutable asset name")
                    assets[asset["name"]] = asset
                if len(listed) < 100:
                    break
            else:
                raise StateError("GitHub release asset listing exceeds supported bound")
            # Preserve IDs just uploaded through this instance if a list read
            # races GitHub's listing visibility; a trusted hash is still checked.
            assets.update(self._assets[tag])
            self._assets[tag] = assets
            self._listed.add(tag)
        asset = self._assets[tag].get(name)
        if asset is None:
            return None
        if type(asset.get("id")) is not int:
            raise StateError("Invalid immutable asset ID")
        return asset

    def download_asset(self, tag: str, name: str, destination: Path) -> None:
        _asset_ref({"release_tag": tag, "name": name, "ciphertext_sha256": "0" * 64,
                    "ciphertext_bytes": 1})
        if self._cycle_catalog.known(tag):
            self._cycle_catalog.download(tag, name, destination)
            return
        asset = self._asset(tag, name)
        release = self._releases[tag]  # _asset already cached the validated release.
        size, digest = asset.get("size"), asset.get("digest")
        if (type(size) is not int or not 0 <= size <= MAX_PUBLIC_ASSET_BYTES or
                digest is not None and (not isinstance(digest, str) or
                                        not re.fullmatch(r"sha256:[0-9a-f]{64}", digest))):
            raise StateError("Invalid GitHub asset size or digest metadata")
        digest = digest[7:] if digest is not None else None
        public_url = asset.get("browser_download_url")
        mode = self.asset_download_mode
        if public_url is not None and mode != "authenticated" and release["draft"] is False:
            try:
                check_browser_url(public_url, self.repository, tag, name)
            except PublicAssetInvalid:
                raise StateError("Untrusted public GitHub asset URL") from None
        public_ready = (mode != "authenticated" and release["draft"] is False and public_url is not None and
                        tag not in self._public_unavailable_releases and self.clock() >= self._public_unavailable_until)
        # A known secondary/Retry-After constraint applies to both routes. A
        # primary REST reserve alone does not debit a public byte download.
        if self.retry_not_before is not None and self.clock() < self.retry_not_before:
            raise self._defer("destination Retry-After has not elapsed", self.retry_not_before)
        created = False
        try:
            with destination.open("xb") as target:
                created = True
                os.chmod(destination, 0o600)
                if public_ready:
                    def counted_request():
                        self.asset_download_counts["public_http_requests"] += 1
                    try:
                        download_public(public_url, target, size=size, digest=digest,
                                        opener=self._public_opener, on_request=counted_request)
                    except PublicAssetRateLimited as error:
                        retry = self._retry_after(error.retry_after) or self.clock() + 60
                        if isinstance(error.reset, str) and error.reset.isdecimal():
                            retry = max(retry, int(error.reset))
                        self.retry_not_before = max(self.retry_not_before or 0, retry)
                        raise self._defer("destination public asset rate limit", self.retry_not_before) from None
                    except PublicAssetInvalid:
                        raise StateError("Public GitHub asset policy or integrity check failed") from None
                    except PublicAssetUnavailable as error:
                        if error.status in (401, 403, 404, 410):
                            self._public_unavailable_releases.add(tag)
                        else:
                            self._public_unavailable_until = self.clock() + 60
                        target.seek(0)
                        target.truncate()
                    else:
                        self.asset_download_counts["public_downloads"] += 1
                        self.asset_download_counts["public_bytes"] += size
                        self._emit_asset_download("public_download", size)
                        return
                if mode == "public-only":
                    raise StateError("Public GitHub asset download unavailable; authenticated fallback disabled")
                if mode == "public-first" and public_ready:
                    self.asset_download_counts["fallbacks"] += 1
                self.asset_download_counts["authenticated_attempts"] += 1
                self._run(["api", f"repos/{self.repository}/releases/assets/{asset['id']}",
                           "--method", "GET", "-H", "Accept: application/octet-stream"], stdout=target)
            # Retain the trusted caller's SHA/AEAD checks as well. GitHub's
            # optional digest is an additional transport check, not their source.
            if destination.stat().st_size != size or digest is not None and _digest(destination) != digest:
                raise StateError("Authenticated GitHub asset hash or size differs from metadata")
            self.asset_download_counts["authenticated_downloads"] += 1
            self._emit_asset_download("authenticated_fallback" if mode == "public-first" and public_ready
                                      else "authenticated_download", size)
        except Exception:
            if created:
                destination.unlink(missing_ok=True)
            raise

    def download_metrics(self) -> dict[str, int]:
        return {"destination_git_metadata_downloads_total": self._cycle_catalog.git_downloads,
                "destination_git_metadata_download_bytes_total": self._cycle_catalog.git_bytes,
                "destination_github_public_asset_requests_total": self.asset_download_counts["public_http_requests"],
                "destination_github_public_asset_downloads_total": self.asset_download_counts["public_downloads"],
                "destination_github_public_asset_download_bytes_total": self.asset_download_counts["public_bytes"],
                "destination_github_authenticated_asset_downloads_total": self.asset_download_counts["authenticated_downloads"],
                "destination_github_authenticated_asset_download_attempts_total": self.asset_download_counts["authenticated_attempts"],
                "destination_github_asset_download_fallbacks_total": self.asset_download_counts["fallbacks"]}

    def _emit_asset_download(self, reason: str, size: int) -> None:
        from .diagnostics import emit
        emit("stage_end", stage="asset_download", status="complete", reason=reason, bytes=size,
             request_count=self.request_count, **self.asset_download_counts)

    def pin_asset_ref(self, ref: dict) -> None:
        from .cycle_release import CycleCatalogError
        try:
            self._cycle_catalog.pin(ref)
        except CycleCatalogError:
            raise StateError("Pinned cycle catalog failed validation") from None

    def bind_asset_ref(self, ref: dict) -> dict:
        return self._cycle_catalog.bind(ref)

    def bind_asset_refs(self, refs) -> None:
        for ref in refs:
            self.bind_asset_ref(ref)


class GitHubStateStore:
    def __init__(self, transport: StateTransport, *, repository_id: int, slug: str,
                 public_key: Path | str, private_key: Path | str | None = None,
                 logical_root: Path | str | None = None, part_bytes: int = MAX_PART_BYTES,
                 mutable_group_bytes: int = 64 * 1024 * 1024,
                 max_assets_per_release: int = 900,
                 small_immutable_bytes: int = 64 * 1024 * 1024,
                 immutable_group_bytes: int = 128 * 1024 * 1024,
                 immutable_group_members: int = 4096):
        if type(repository_id) is not int or repository_id < 1 or not REPO_RE.fullmatch(slug):
            raise ValueError("Selected positive repository ID and slug required")
        if not 10240 <= part_bytes <= MAX_PART_BYTES:
            raise ValueError("State plaintext parts must be between 10 KiB and 1 GiB")
        if type(max_assets_per_release) is not int or not 2 <= max_assets_per_release <= 1000:
            raise ValueError("State release asset limit must be between 2 and 1000")
        if (type(small_immutable_bytes) is not int or not 0 <= small_immutable_bytes <= 64 * 1024 * 1024 or
                type(immutable_group_bytes) is not int or not 10240 <= immutable_group_bytes <= 128 * 1024 * 1024 or
                type(immutable_group_members) is not int or not 1 <= immutable_group_members <= 4096):
            raise ValueError("Invalid bounded immutable snapshot packing policy")
        self.max_assets_per_release = max_assets_per_release
        self.small_immutable_bytes = small_immutable_bytes
        self.immutable_group_bytes = min(immutable_group_bytes, part_bytes)
        self.immutable_group_members = immutable_group_members
        self.transport, self.repository_id, self.slug = transport, repository_id, slug
        self.root = Path(logical_root or f"/tmp/icsot-persistent-state/{repository_id}").resolve()
        self.public_key = Path(public_key).resolve()
        self.private_key = Path(private_key).resolve() if private_key else None
        if self.private_key and self.private_key.is_relative_to(self.root):
            raise ValueError("Working-state private key must be outside the captured root")
        self.recipient = public_key_fingerprint(self.public_key)
        self.part_bytes = part_bytes
        self.grouped_profile = os.environ.get("ICSOT_ARCHIVE_PROFILE") == "grouped-xz-v2"
        self.profile_group_bytes = min(500 * 1024**2, part_bytes)
        self.group_bytes = min(mutable_group_bytes, part_bytes - 10240)
        if self.group_bytes < 1:
            self.group_bytes = 1
        self._verified_parts: set[bytes] = set()
        self._prepared_verified: dict[str, set[bytes]] = {}
        self._verified_downloads: set[bytes] = set()
        self.compaction_candidate_pointer_sha256: str | None = None

    def _lock(self):
        return nullcontext() if ControllerLock.owned(self.root) else ControllerLock(self.root)

    def _binding(self, generation: str, predecessor: str | None) -> dict:
        return {"schema_version": SCHEMA_VERSION, "repository_id": self.repository_id,
                "slug": self.slug, "generation": generation,
                "predecessor_index_sha256": predecessor, "logical_root": str(self.root)}

    def _check_pointer(self, pointer: dict) -> None:
        generation = pointer.get("generation")
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise StateError("Invalid state generation")
        predecessor = pointer.get("predecessor_index_sha256")
        if predecessor is not None and (not isinstance(predecessor, str) or not _HASH.fullmatch(predecessor)):
            raise StateError("Invalid predecessor index hash")
        for key, value in self._binding(generation, predecessor).items():
            if pointer.get(key) != value:
                raise StateError("State pointer does not bind the selected repository/root")
        if not isinstance(pointer.get("context_sha256"), str) or not _HASH.fullmatch(pointer["context_sha256"]):
            raise StateError("Invalid state context hash")
        outbox = pointer.get("proof_outbox")
        if outbox is not None and (not isinstance(outbox, dict) or set(outbox) != {"sha256", "bytes"} or
                not isinstance(outbox.get("sha256"), str) or not _HASH.fullmatch(outbox["sha256"]) or
                type(outbox.get("bytes")) is not int or not 1 <= outbox["bytes"] <= 4096):
            raise StateError("Invalid public proof outbox pointer")
        for field in ("snapshot_started_at", "snapshot_sealed_at"):
            value = pointer.get(field)
            if not isinstance(value, str) or not _UTC.fullmatch(value):
                raise StateError("Invalid UTC snapshot interval")
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise StateError("Invalid UTC snapshot interval") from exc
        if (pointer.get("clock_source") != "runner_system_clock" or
                pointer["snapshot_started_at"] > pointer["snapshot_sealed_at"]):
            raise StateError("Invalid snapshot clock source or interval ordering")
        index = _asset_ref(pointer.get("index"))
        if (not isinstance(index.get("plaintext_sha256"), str) or
                not _HASH.fullmatch(index["plaintext_sha256"]) or
                type(index.get("plaintext_bytes")) is not int or
                not 1 <= index["plaintext_bytes"] <= self.part_bytes or
                index.get("public_key_fingerprint_sha256") != self.recipient):
            raise StateError("Invalid encrypted index metadata/key binding")
        encoding = index.get("encoding", "raw")
        if encoding == "xz":
            if (index.get("compression_profile") != "grouped-xz-v2" or
                    type(index.get("decoded_bytes")) is not int or
                    not 1 <= index["decoded_bytes"] <= self.part_bytes or
                    not isinstance(index.get("decoded_sha256"), str) or
                    not _HASH.fullmatch(index["decoded_sha256"])):
                raise StateError("Invalid compressed index metadata")
        elif encoding != "raw" or any(field in index for field in
                                      ("decoded_bytes", "decoded_sha256", "compression_profile")):
            raise StateError("Invalid index encoding metadata")

    def _check_index(self, pointer: dict, index: dict) -> None:
        self._check_pointer(pointer)
        raw_index = canonical_json(index)
        index_ref = pointer["index"]
        digest_field, size_field = (("decoded_sha256", "decoded_bytes") if index_ref.get("encoding") == "xz"
                                    else ("plaintext_sha256", "plaintext_bytes"))
        if (hashlib.sha256(raw_index).hexdigest() != index_ref[digest_field] or
                len(raw_index) != index_ref[size_field]):
            raise StateError("In-memory index differs from authenticated pointer digest")
        context = index.get("context")
        if not isinstance(context, dict):
            raise StateError("Missing authenticated state context")
        for key, value in self._binding(pointer["generation"], pointer["predecessor_index_sha256"]).items():
            if context.get(key) != value:
                raise StateError("Decrypted state context differs from selected Git pointer")
        for field in ("snapshot_started_at", "snapshot_sealed_at", "clock_source"):
            if context.get(field) != pointer[field]:
                raise StateError("Decrypted snapshot UTC interval differs from selected Git pointer")
        if context.get("proof_outbox") != pointer.get("proof_outbox"):
            raise StateError("Decrypted proof outbox differs from selected Git pointer")
        if hashlib.sha256(canonical_json(context)).hexdigest() != pointer["context_sha256"]:
            raise StateError("Authenticated state context hash differs from Git pointer")
        if (context.get("recipient_spki_sha256") != self.recipient or
                context.get("file_map_sha256") != hashlib.sha256(canonical_json(index.get("files"))).hexdigest()):
            raise StateError("State file-map/key binding differs")
        if not all(isinstance(context.get(key), dict) for key in
                   ("code_hashes", "config_hashes", "lane_heads", "evidence_heads")):
            raise StateError("Missing state provenance context")
        if not isinstance(index.get("parts"), dict) or not isinstance(index.get("files"), list):
            raise StateError("Invalid state file map")
        for part_id, part in index["parts"].items():
            if (not isinstance(part_id, str) or not _HASH.fullmatch(part_id) or not isinstance(part, dict) or
                    part.get("plaintext_sha256") != part_id or
                    type(part.get("plaintext_bytes")) is not int or
                    not 0 <= part["plaintext_bytes"] <= self.part_bytes or
                    part.get("kind") not in ("raw", "tar") or
                    part.get("encoding") not in ("raw", "xz") or
                    type(part.get("decoded_bytes")) is not int or
                    not 0 <= part["decoded_bytes"] <= self.part_bytes or
                    not isinstance(part.get("decoded_sha256"), str) or
                    not _HASH.fullmatch(part["decoded_sha256"]) or
                    part.get("public_key_fingerprint_sha256") != self.recipient):
                raise StateError("Invalid state part binding")
            if "compression_profile" in part and (part["compression_profile"] != "grouped-xz-v2" or
                    part["encoding"] != "xz" or
                    (part["kind"] == "tar" and part["decoded_bytes"] > 500 * 1024**2)):
                raise StateError("Invalid state part compression profile")
            _asset_ref(part)
        seen = set()
        used_parts = set()
        for item in index["files"]:
            if not isinstance(item, dict):
                raise StateError("Invalid state file metadata")
            name = _safe_path(item.get("path"))
            if name in seen:
                raise StateError("Duplicate snapshot member path")
            seen.add(name)
            if (type(item.get("bytes")) is not int or item["bytes"] < 0 or
                    not isinstance(item.get("sha256"), str) or not _HASH.fullmatch(item["sha256"]) or
                    type(item.get("mode")) is not int or item["mode"] not in (0o600, 0o700)):
                raise StateError("Invalid state file metadata")
            segments = item.get("segments")
            if not isinstance(segments, list) or not segments:
                raise StateError("Missing state file segments")
            total = 0
            for segment in segments:
                if not isinstance(segment, dict) or not isinstance(segment.get("part"), str):
                    raise StateError("Invalid state file segment")
                part = index["parts"].get(segment.get("part"))
                if part is None:
                    raise StateError("State file references missing part")
                used_parts.add(segment["part"])
                if part["kind"] == "tar":
                    if len(segments) != 1 or segment.get("member") != name:
                        raise StateError("Invalid grouped state member")
                    total += item["bytes"]
                else:
                    total += part["decoded_bytes"]
            if total != item["bytes"]:
                raise StateError("State file segment sizes differ")
        for name in seen:
            if any(str(parent) in seen for parent in PurePosixPath(name).parents if str(parent) != "."):
                raise StateError("Snapshot file path is also a directory")
        if used_parts != set(index["parts"]):
            raise StateError("Unreferenced state parts")
        dependencies = index.get("dependencies")
        if not isinstance(dependencies, list):
            raise StateError("Invalid state evidence prerequisites")
        for dependency in dependencies:
            _asset_ref(dependency)
        if context.get("dependencies_sha256") != hashlib.sha256(canonical_json(dependencies)).hexdigest():
            raise StateError("State prerequisite context differs")

    def _download_verified(self, ref: dict, target: Path) -> None:
        _asset_ref(ref)
        pin = getattr(self.transport, "pin_asset_ref", None)
        if callable(pin):
            pin(ref)
        self.transport.download_asset(ref["release_tag"], ref["name"], target)
        _verify_file_integrity(target, size=ref["ciphertext_bytes"], digest=ref["ciphertext_sha256"],
                               stage="asset_download", subject="asset:" + ref["ciphertext_sha256"],
                               message="Remote immutable asset hash/size differs")
        self._verified_downloads.add(_asset_identity(ref))

    def _decrypt(self, ref: dict, encrypted: Path, plaintext: Path) -> None:
        if self.private_key is None:
            raise StateError("Working-state private key required to restore state")
        try:
            record = decrypt_file(encrypted, plaintext, self.private_key)
        except ValueError as exc:
            raise StateError("Unable to authenticate encrypted working state") from exc
        for key in ("ciphertext_sha256", "ciphertext_bytes", "plaintext_sha256", "plaintext_bytes",
                    "public_key_fingerprint_sha256"):
            if ref.get(key) != record[key]:
                raise StateError("Decrypted state part metadata differs")

    def _decode_part(self, ref: dict, plaintext: Path, decoded: Path) -> Path:
        if ref["encoding"] == "raw":
            target = plaintext
        else:
            try:
                if ref.get("compression_profile") == "grouped-xz-v2":
                    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * 1024**2)
                    copied = 0
                    with plaintext.open("rb") as source, decoded.open("xb") as output:
                        while not decoder.eof:
                            data = source.read(4 * 1024 * 1024) if decoder.needs_input else b""
                            if not data and decoder.needs_input:
                                raise EOFError("Truncated XZ working-state part")
                            chunk = decoder.decompress(data, max_length=min(4 * 1024 * 1024,
                                                       ref["decoded_bytes"] - copied + 1))
                            copied += len(chunk)
                            if copied > ref["decoded_bytes"]:
                                raise StateIntegrityError("Decoded state part exceeds authenticated size",
                                    stage="part_decode", subject="part:" + ref["plaintext_sha256"], field="bytes",
                                    expected=ref["decoded_bytes"], actual=copied)
                            output.write(chunk)
                        if decoder.unused_data or source.read(1):
                            raise StateError("Trailing data after XZ working-state part")
                else:
                    with lzma.open(plaintext, "rb") as source, decoded.open("xb") as output:
                        copied = 0
                        while chunk := source.read(min(4 * 1024 * 1024, ref["decoded_bytes"] - copied + 1)):
                            copied += len(chunk)
                            if copied > ref["decoded_bytes"]:
                                raise StateIntegrityError("Decoded state part exceeds authenticated size",
                                    stage="part_decode", subject="part:" + ref["plaintext_sha256"], field="bytes",
                                    expected=ref["decoded_bytes"], actual=copied)
                            output.write(chunk)
                target = decoded
            except (lzma.LZMAError, EOFError) as exc:
                raise StateError("Invalid XZ working-state part") from exc
        _verify_file_integrity(target, size=ref["decoded_bytes"], digest=ref["decoded_sha256"],
                               stage="part_decode", subject="part:" + ref["plaintext_sha256"],
                               message="Decoded state part hash/size differs")
        return target

    def _check_slug_binding(self, head: str | None) -> dict | None:
        raw = self.transport.read_slug_binding(head, self.slug) if head else None
        if raw is None:
            return None
        binding = _json(raw, "repository slug binding")
        if binding != _slug_binding(self.slug, self.repository_id):
            raise StateConflictError("Repository slug is already bound to another numeric ID; "
                                     "an explicit identity amendment is required")
        return binding

    def read(self) -> StateSelection:
        head = self.transport.branch_head()
        binding = self._check_slug_binding(head)
        raw = self.transport.read_pointer(head, self.repository_id) if head else None
        if raw is None:
            if binding is not None:
                raise StateError("Repository slug binding exists but its state pointer is missing")
            return StateSelection(head, None, None)
        if binding is None:
            raise StateError("State pointer has no authoritative repository slug binding")
        pointer = _json(raw, "Git state pointer")
        self._check_pointer(pointer)
        with tempfile.TemporaryDirectory(prefix="icsot-state-read-") as temporary:
            encrypted, plaintext = Path(temporary) / "index.enc", Path(temporary) / "index.json"
            self._download_verified(pointer["index"], encrypted)
            self._decrypt(pointer["index"], encrypted, plaintext)
            decoded = (self._decode_part(pointer["index"], plaintext, Path(temporary) / "index.decoded")
                       if pointer["index"].get("encoding") == "xz" else plaintext)
            index = _json(decoded.read_bytes(), "encrypted state index")
            self._check_index(pointer, index)
        return StateSelection(head, pointer, index)

    def restore(self, selection: StateSelection) -> dict:
        if selection.pointer is None:
            if selection.index is not None:
                raise StateError("Index without authoritative pointer")
            with self._lock():
                self._require_empty_root()
            return {"restored": False, "repository_id": self.repository_id, "files": 0}
        if selection.index is None:
            raise StateError("Pointer without authenticated index")
        self._check_index(selection.pointer, selection.index)
        index = selection.index
        with self._lock(), tempfile.TemporaryDirectory(prefix="icsot-state-restore-") as temporary:
            self._require_empty_root()
            staging, downloads = Path(temporary) / "state", Path(temporary) / "parts"
            staging.mkdir(mode=0o700)
            downloads.mkdir(mode=0o700)
            state_bytes = sum(item["bytes"] for item in index["files"])
            part_overhead = max((ref["ciphertext_bytes"] + ref["plaintext_bytes"] +
                                 (ref["decoded_bytes"] if ref["encoding"] == "xz" else 0)
                                 for ref in index["parts"].values()), default=0)
            peak_temporary = state_bytes + part_overhead
            self._preflight_disk(directory=Path(temporary), required=peak_temporary,
                                 operation="restore temporary staging")
            same_device = self.root.stat().st_dev == Path(temporary).stat().st_dev
            if not same_device:
                self._preflight_disk(directory=self.root, required=state_bytes,
                                     operation="restore destination")
            self._reconstruct(index, staging, downloads)
            # All ciphertexts, context, member names, and file hashes are checked
            # before materializing state. Keep the held controller lock's inode.
            self._require_empty_root()
            for child in staging.iterdir():
                shutil.move(str(child), self.root / child.name)
        return {"restored": True, "repository_id": self.repository_id,
                "generation": selection.pointer["generation"], "files": len(index["files"]),
                "state_plaintext_bytes": state_bytes,
                "restore_peak_temporary_bytes_estimate": peak_temporary,
                "restore_peak_additional_disk_bytes_estimate": peak_temporary + (0 if same_device else state_bytes)}

    def _reconstruct(self, index: dict, staging: Path, downloads: Path,
                     check_progress: Callable[[], None] | None = None) -> None:
        """Freshly authenticate and reconstruct every indexed part into staging."""
        grouped: dict[str, dict[str, dict]] = {}
        for item in index["files"]:
            if index["parts"][item["segments"][0]["part"]]["kind"] == "tar":
                grouped.setdefault(item["segments"][0]["part"], {})[item["path"]] = item
        usages: dict[str, list[tuple[str, int]]] = {}
        for item in index["files"]:
            if "member" in item["segments"][0]:
                continue
            target = staging / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb"):
                pass
            offset = 0
            for segment in item["segments"]:
                usages.setdefault(segment["part"], []).append((item["path"], offset))
                offset += index["parts"][segment["part"]]["decoded_bytes"]
        for part_id, ref in index["parts"].items():
            if check_progress is not None:
                check_progress()
            encrypted, plain = downloads / (part_id + ".enc"), downloads / part_id
            self._download_verified(ref, encrypted)
            self._decrypt(ref, encrypted, plain)
            decoded = self._decode_part(ref, plain, downloads / (part_id + ".decoded"))
            self._verified_parts.add(_asset_identity(ref))
            if ref["kind"] == "tar":
                self._extract_group(decoded, staging, grouped[part_id])
            else:
                for name, offset in usages[part_id]:
                    with (staging / name).open("r+b") as output, decoded.open("rb") as source:
                        output.seek(offset)
                        shutil.copyfileobj(source, output, length=4 * 1024 * 1024)
            encrypted.unlink()
            if decoded != plain:
                decoded.unlink()
            plain.unlink()
        for item in index["files"]:
            target = staging / item["path"]
            _verify_file_integrity(target, size=item["bytes"], digest=item["sha256"],
                                   stage="file_reconstruction", subject=_diagnostic_path(item["path"]),
                                   message="Restored state file hash/size differs")
            os.chmod(target, item["mode"])

    @staticmethod
    def _preflight_disk(*, directory: Path, required: int, operation: str) -> None:
        free = shutil.disk_usage(directory).free
        if free < required:
            raise StateError(f"Insufficient disk for {operation}: need approximately {required} free bytes; "
                             f"{free} available. Select a smaller repository or use a larger runner.")

    @staticmethod
    def _compaction_disk_bytes(*, max_upload_bytes: int, index_plaintext_bound: int,
                               state_bytes: int, max_old_part_scratch: int,
                               immutable_group_bytes: int, compressed_index: bool = False) -> int:
        # Frozen assets include one encrypted index. Capture's copy fallback
        # additionally holds the original encrypted index and its plaintext;
        # fresh remote index verification has the same two scratch allocations.
        index_scratch = (3 if compressed_index else 2) * index_plaintext_bound + ENVELOPE_OVERHEAD
        # Index scratch is removed before reconstructing the complete tree.
        reconstruction_scratch = (state_bytes + max_old_part_scratch +
                                  4 * (immutable_group_bytes + ENVELOPE_OVERHEAD))
        return max_upload_bytes + max(index_scratch, reconstruction_scratch)

    def _require_empty_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if any(child.name != ".collector.lock" for child in self.root.iterdir()):
            raise StateError("Restore requires an empty state root except the controller lock")

    @staticmethod
    def _extract_group(plain: Path, staging: Path, expected: dict[str, dict]) -> None:
        seen = set()
        previous_end = 0
        archive_bytes = plain.stat().st_size
        try:
            with tarfile.open(plain, "r:") as archive:
                for member in archive:
                    name = _safe_path(member.name)
                    if not member.isfile() or name not in expected or name in seen:
                        raise StateError("Unsafe, duplicate, or unlisted state archive member")
                    if (getattr(member, "sparse", None) is not None or
                            member.offset < previous_end or member.offset % 512 or member.offset_data % 512 or
                            member.offset_data < member.offset + 512 or
                            member.offset_data + ((member.size + 511) // 512) * 512 > archive_bytes):
                        raise StateError("Invalid or overlapping state archive member offsets")
                    previous_end = member.offset_data + ((member.size + 511) // 512) * 512
                    if member.size != expected[name]["bytes"]:
                        raise StateIntegrityError("State archive member size differs", stage="tar_member",
                            subject=_diagnostic_path(name), field="bytes", expected=expected[name]["bytes"],
                            actual=member.size)
                    seen.add(name)
                    target = staging / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise StateError("Missing state archive member bytes")
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, length=4 * 1024 * 1024)
        except (tarfile.TarError, OSError) as exc:
            raise StateError("Invalid state archive") from exc
        if seen != set(expected):
            raise StateError("State archive is missing expected members")

    @classmethod
    def _verify_group_files(cls, archive: Path, members: list[dict], staging: Path) -> None:
        """Check the actual new archive against the frozen logical file map."""
        staging.mkdir(mode=0o700)
        try:
            cls._extract_group(archive, staging, {item["path"]: item for item in members})
            for item in members:
                target = staging / item["path"]
                _verify_file_integrity(target, size=item["bytes"], digest=item["sha256"],
                                       stage="group_verification", subject=_diagnostic_path(item["path"]),
                                       message="Grouped snapshot member hash/size differs")
        finally:
            shutil.rmtree(staging)

    @staticmethod
    def _excluded(path: str) -> bool:
        pieces = path.split("/")
        return (pieces[-1].endswith((".lock", "-wal", "-shm")) or
                any(piece.startswith((".icsot-", ".capture-export-")) for piece in pieces) or
                any(piece in ("icsot-verified-archive.git", "icsot-verified-recent.git") for piece in pieces))

    def _snapshot_files(self, staging: Path, *, materialize: bool = True) -> list[dict]:
        files = []
        for source in sorted(self.root.rglob("*")):
            name = source.relative_to(self.root).as_posix()
            if self._excluded(name):
                continue
            info = source.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise StateError("Working snapshot cannot contain symlinks")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StateError("Working snapshot requires regular files without hardlinks")
            _safe_path(name)
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as handle:
                prefix = handle.read(80)
            if b"PRIVATE KEY-----" in prefix:
                raise StateError("Private key found inside working-state root")
            if name.endswith((".sqlite3", ".sqlite", ".db")) and prefix.startswith(b"SQLite format 3\x00"):
                original = sqlite3.connect(f"file:{quote(str(source), safe='/')}?mode=ro", uri=True)
                backup = sqlite3.connect(target)
                try:
                    original.backup(backup)
                    if backup.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise StateError("SQLite working-state backup failed integrity check")
                finally:
                    backup.close()
                    original.close()
            elif materialize:
                shutil.copyfile(source, target)
            else:
                target = source
            if target != source:
                os.chmod(target, 0o600)
            digest = _digest(target)
            if name.startswith("objects/sha256/") and source.name != digest:
                raise StateError("Working-state CAS filename/hash differs")
            files.append({"path": name, "bytes": target.stat().st_size, "sha256": digest,
                          "mode": 0o700 if info.st_mode & 0o111 else 0o600})
        return files

    def _reuse_part(self, existing: dict, directory: Path, parts: dict, metrics: dict,
                    *, prepared_sink: _PreparedSink | None = None, fresh: bool = False) -> str:
        digest = existing["plaintext_sha256"]
        if digest in parts:
            if parts[digest] != existing:
                raise StateError("Conflicting immutable snapshot part identities")
            return digest
        authenticated = _asset_identity(existing) in self._verified_parts
        if not authenticated or prepared_sink is not None or fresh:
            encrypted, plain = directory / (digest + ".verify.enc"), directory / (digest + ".verify")
            self._download_verified(existing, encrypted)
            if not authenticated or prepared_sink is not None:
                self._decrypt(existing, encrypted, plain)
                decoded = self._decode_part(existing, plain, directory / (digest + ".verify.decoded"))
                if decoded != plain:
                    decoded.unlink()
                plain.unlink()
            self._verified_parts.add(_asset_identity(existing))
            if prepared_sink is not None:
                prepared_sink.capture(existing, encrypted)
            encrypted.unlink()
        parts[digest] = dict(existing)
        metrics["reused_parts"] += 1
        return digest

    @staticmethod
    def _profile_compress(source: Path, destination: Path) -> None:
        from .compression import XZ_COMMAND
        try:
            with source.open("rb") as input_file, destination.open("xb") as output_file:
                subprocess.run(XZ_COMMAND, stdin=input_file, stdout=output_file,
                               stderr=subprocess.DEVNULL, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            destination.unlink(missing_ok=True)
            raise StateError("Grouped XZ compression failed") from exc

    def _index_ref(self, raw_index: bytes, directory: Path, release: str) -> tuple[dict, Path, Path]:
        plaintext, encrypted = directory / "index.json", directory / "index.enc"
        if len(raw_index) > self.part_bytes:
            raise StateError("State index exceeds plaintext part limit")
        plaintext.write_bytes(raw_index)
        encoded = plaintext
        extra = {}
        if self.grouped_profile:
            encoded = directory / "index.json.xz"
            self._profile_compress(plaintext, encoded)
            if encoded.stat().st_size > self.part_bytes:
                raise StateDeferredError("Encoded state index exceeds plaintext part limit", reason="state_index_limit")
            extra = {"encoding": "xz", "decoded_sha256": hashlib.sha256(raw_index).hexdigest(),
                     "decoded_bytes": len(raw_index), "compression_profile": "grouped-xz-v2"}
        record = encrypt_file(encoded, encrypted, self.public_key)
        if encoded != plaintext:
            encoded.unlink()
        return {**record, **extra, "release_tag": release, "name": "index.enc"}, plaintext, encrypted

    def _part(self, plaintext: Path, kind: str, release: str, prior: dict, directory: Path,
              parts: dict, metrics: dict, *, compress: bool = True,
              prepared_sink: _PreparedSink | None = None, capture_reused: bool = False,
              preencoded: Path | None = None) -> str:
        decoded_sha256, decoded_bytes = _digest(plaintext), plaintext.stat().st_size
        existing = prior.get((decoded_sha256, decoded_bytes, kind))
        if existing:
            return self._reuse_part(existing, directory, parts, metrics,
                                    prepared_sink=prepared_sink if capture_reused else None)
        encoding = "raw"
        if compress:
            compressed = preencoded or directory / ("encoded-" + uuid.uuid4().hex + ".xz")
            if preencoded is not None:
                if not self.grouped_profile or kind != "tar":
                    raise StateError("Preencoded state group requires grouped XZ profile")
            elif self.grouped_profile:
                self._profile_compress(plaintext, compressed)
            else:
                with plaintext.open("rb") as source, lzma.open(compressed, "wb", preset=1) as output:
                    shutil.copyfileobj(source, output, length=4 * 1024 * 1024)
            if self.grouped_profile and compressed.stat().st_size > self.part_bytes:
                raise StateDeferredError("Encoded state part exceeds plaintext part limit", reason="state_group_limit")
            if self.grouped_profile or compressed.stat().st_size <= min(self.part_bytes, plaintext.stat().st_size):
                plaintext, encoding = compressed, "xz"
            else:
                compressed.unlink()  # Incompressible input at the part limit.
        digest = _digest(plaintext)
        if digest in parts:
            if parts[digest]["kind"] != kind:
                raise StateError("Identical state payload has incompatible archive roles")
            if encoding == "xz":
                plaintext.unlink()
            return digest
        encrypted = directory / (digest + ".enc")
        record = encrypt_file(plaintext, encrypted, self.public_key)
        name = "part-" + digest + ".enc"
        shard = metrics["_asset_count"] // (self.max_assets_per_release - 1)
        actual_release = release if shard == 0 else release + f"-p{shard + 1}"
        if actual_release not in metrics["_releases"]:
            if prepared_sink is None:
                self.transport.ensure_release(actual_release)
            metrics["_releases"].add(actual_release)
        metrics["_asset_count"] += 1
        ref = {**record, "release_tag": actual_release, "name": name, "kind": kind,
               "encoding": encoding, "decoded_sha256": decoded_sha256, "decoded_bytes": decoded_bytes}
        if self.grouped_profile and encoding == "xz":
            ref["compression_profile"] = "grouped-xz-v2"
        if prepared_sink is None:
            self.transport.upload_asset(actual_release, name, encrypted)
            verify = directory / (digest + ".remote")
            self._download_verified(ref, verify)
            verify.unlink()
            self._verified_parts.add(_asset_identity(ref))
        else:
            prepared_sink.capture(ref, encrypted)
        encrypted.unlink()
        parts[digest] = ref
        metrics["new_parts"] += 1
        metrics["state_uploaded_ciphertext_bytes"] += ref["ciphertext_bytes"]
        if encoding == "xz":
            plaintext.unlink()
        return digest

    @staticmethod
    def _immutable(name: str) -> bool:
        return (name.startswith("objects/sha256/") or
                name.startswith("git/") and "/objects/" in name)

    @staticmethod
    def _tar_info(item: dict) -> tarfile.TarInfo:
        info = tarfile.TarInfo(item["path"])
        info.size, info.mode, info.mtime = item["bytes"], item["mode"], 0
        return info

    @classmethod
    def _tar_member_bytes(cls, item: dict) -> int:
        return len(cls._tar_info(item).tobuf(tarfile.PAX_FORMAT)) + ((item["bytes"] + 511) // 512) * 512

    @staticmethod
    def _tar_total_bytes(member_bytes: int) -> int:
        return ((member_bytes + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE

    def _group_files(self, items: list[dict], target: int) -> list[list[dict]]:
        groups, group, size = [], [], 0
        for item in items:
            required = self._tar_member_bytes(item)
            if self._tar_total_bytes(required) > target:
                raise StateError("Snapshot member cannot fit the selected packed block")
            if group and (len(group) >= self.immutable_group_members or self._tar_total_bytes(size + required) > target):
                groups.append(group)
                group, size = [], 0
            group.append(item)
            size += required
        if group:
            groups.append(group)
        return groups

    def _snapshot_plan(self, files: list[dict], prior: dict) -> dict:
        previous = {item["path"]: item for item in prior.get("files", [])}
        current = {item["path"]: item for item in files}
        # Immutable closure is append-only. A vanished old packed member cannot
        # be dropped from a reused block's exact extraction map.
        for name, old in previous.items():
            if self._immutable(name) and not self._excluded(name) and name not in current:
                raise StateError("Previously retained immutable state file is missing")
        raw, small, mutable, reused = [], [], [], {}
        legacy_fallback_count = 0
        mutable_target = min(self.part_bytes, max(tarfile.RECORDSIZE, self.group_bytes))
        if self.grouped_profile:
            mutable_target = self.profile_group_bytes
        for item in files:
            name, old = item["path"], previous.get(item["path"])
            if self._immutable(name):
                if old is not None:
                    if item["sha256"] != old["sha256"] or item["bytes"] != old["bytes"]:
                        raise StateError("Previously retained immutable state file changed")
                    reused[name] = copy.deepcopy(old["segments"])
                    continue
                if self.grouped_profile:
                    if self._tar_total_bytes(self._tar_member_bytes(item)) > self.profile_group_bytes:
                        raw.append(item)
                        legacy_fallback_count += 1
                    else:
                        small.append(item)
                elif (self.small_immutable_bytes and item["bytes"] <= self.small_immutable_bytes and
                        self._tar_total_bytes(self._tar_member_bytes(item)) <= self.immutable_group_bytes):
                    small.append(item)
                else:
                    raw.append(item)
            elif self.grouped_profile:
                if self._tar_total_bytes(self._tar_member_bytes(item)) > self.profile_group_bytes:
                    raw.append(item)
                    legacy_fallback_count += 1
                else:
                    mutable.append(item)
            elif (item["bytes"] <= self.group_bytes and
                  self._tar_total_bytes(self._tar_member_bytes(item)) <= mutable_target):
                mutable.append(item)
            else:
                raw.append(item)
        groups = self._group_files(small, self.profile_group_bytes if self.grouped_profile else self.immutable_group_bytes) + self._group_files(mutable, mutable_target)
        return {"raw": raw, "groups": groups, "reused": reused,
                "new_small_immutable_files": len(small),
                "large_member_legacy_fallback_count": legacy_fallback_count}

    def _publication_requests_estimate(self, files: list[dict], prior: dict,
                                      recovery_parts: dict | None = None) -> int:
        plan = self._snapshot_plan(files, prior)
        raw_parts = sum(max(1, (item["bytes"] + self.part_bytes - 1) // self.part_bytes) for item in plan["raw"])
        parts = raw_parts + len(plan["groups"])  # Mutable groups conservatively all new.
        matched = {(part["decoded_sha256"], part["decoded_bytes"], part["kind"]): part
                   for item in plan["raw"] if item["bytes"] <= self.part_bytes
                   if (part := (recovery_parts or {}).get((item["sha256"], item["bytes"], "raw"))) is not None}
        parts -= len(matched)
        releases = max(1, (parts + self.max_assets_per_release - 2) // (self.max_assets_per_release - 1))
        unverified = [part for part in prior["parts"].values()
                      if _asset_identity(part) not in self._verified_parts]
        # A cold authorized draft can need REST tag 404 + numeric ID recheck
        # + up to eleven asset-list pages; GraphQL lookup has its own bucket.
        old_release_reads = 13 * len({part["release_tag"] for part in unverified}) + len(unverified)
        recovery_reads = [part for part in matched.values() if _asset_identity(part) not in self._verified_parts]
        return (2 * (parts + 1) + 2 * releases + 18 + old_release_reads + len(recovery_reads) +
                13 * len({part["release_tag"] for part in recovery_reads}))

    def _compaction_plan(self, index: dict, max_input_bytes: int, max_input_parts: int) -> dict:
        # A part is eligible only when every reference is an eligible complete
        # single-segment immutable file. This includes shared raw segments and
        # prevents leaving a tar with an incomplete extraction member map.
        by_part: dict[str, list[dict]] = {}
        for item in index["files"]:
            for segment in item["segments"]:
                by_part.setdefault(segment["part"], []).append(item)
        candidates = []
        for part_id, members in by_part.items():
            unique = {item["path"]: item for item in members}
            if any(not self._immutable(item["path"]) or len(item["segments"]) != 1 or
                   item["bytes"] > self.small_immutable_bytes or
                   self._tar_total_bytes(self._tar_member_bytes(item)) > self.immutable_group_bytes
                   for item in unique.values()):
                continue
            size = sum(item["bytes"] for item in unique.values())
            candidates.append((size, part_id, list(unique.values())))
        chosen, selected, total = [], [], 0
        for size, part_id, members in sorted(candidates, key=lambda row: (row[0], row[1])):
            if len(chosen) >= max_input_parts or total + size > max_input_bytes:
                continue
            chosen.append(part_id)
            selected.extend(members)
            total += size
        groups = self._group_files(sorted(selected, key=lambda item: item["path"]), self.immutable_group_bytes)
        return {"parts": chosen, "groups": groups, "input_bytes": total,
                "part_savings": len(chosen) - len(groups)}

    def _check_compaction_root(self, index: dict) -> None:
        actual = []
        for path in sorted(self.root.rglob("*")):
            name = path.relative_to(self.root).as_posix()
            if self._excluded(name):
                continue
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StateError("Compaction root requires regular files without hardlinks")
            _safe_path(name)
            actual.append({"path": name, "bytes": info.st_size, "sha256": _digest(path),
                           "mode": stat.S_IMODE(info.st_mode)})
        expected = [{key: item[key] for key in ("path", "bytes", "sha256", "mode")}
                    for item in index["files"]]
        if actual != sorted(expected, key=lambda item: item["path"]):
            raise StateError("Compaction root differs from authenticated predecessor file map")

    @staticmethod
    def _check_compaction_file_map(predecessor: dict, candidate: dict) -> None:
        def logical(index: dict) -> list[dict]:
            return sorted(({key: item[key] for key in ("path", "bytes", "sha256", "mode")}
                           for item in index["files"]), key=lambda item: item["path"])
        if logical(predecessor) != logical(candidate):
            raise StateError("Compaction logical file map differs from predecessor")

    def validate_compaction_metadata(self, head: str | None, pointer: dict) -> None:
        """Verify pinned slug and immediate outbox node at one exact Git head."""
        transport = self.transport
        binding = transport.read_slug_binding(head, self.slug) if head is not None else None
        if binding is None or _json(binding, "compaction slug binding") != _slug_binding(self.slug, self.repository_id):
            raise StateConflictError("Compaction requires its pinned repository slug binding")
        if transport.read_pointer(head, self.repository_id) != canonical_json(pointer):
            raise StateConflictError("Compaction pointer differs from pinned metadata head")
        ref = pointer.get("proof_outbox")
        if ref is None:
            return
        self._check_pointer(pointer)
        reader = getattr(transport, "read_proof_outbox", None)
        if not callable(reader):
            reader = getattr(transport, "outbox_node", None)
        if not callable(reader):
            raise StateError("Compaction transport cannot read its pinned proof outbox node")
        try:
            raw = reader(head, self.repository_id, ref)
        except KeyError as exc:
            raise StateError("Compaction proof outbox node is missing") from exc
        if (not isinstance(raw, bytes) or len(raw) != ref["bytes"] or
                hashlib.sha256(raw).hexdigest() != ref["sha256"]):
            raise StateError("Compaction proof outbox node is missing or differs")
        node = _json(raw, "compaction proof outbox node")
        if (set(node) != {"schema_version", "kind", "repository_id", "slug", "generation", "created_at", "catalog", "previous"} or
                node.get("schema_version") != 1 or node.get("kind") != "icsot_public_proof_outbox" or
                type(node.get("repository_id")) is not int or node["repository_id"] != self.repository_id or
                node.get("slug") != self.slug or not isinstance(node.get("generation"), str) or
                not _GENERATION.fullmatch(node["generation"]) or not isinstance(node.get("created_at"), str) or
                not _UTC.fullmatch(node["created_at"])):
            raise StateError("Invalid compaction proof outbox node identity")
        try:
            datetime.fromisoformat(node["created_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise StateError("Invalid compaction proof outbox node time") from exc
        catalog, previous = node["catalog"], node["previous"]
        catalog_keys = {"release_tag", "name", "sha256", "bytes"}
        if (not isinstance(catalog, dict) or set(catalog) not in (catalog_keys, catalog_keys | {"storage"}) or
                not isinstance(catalog.get("release_tag"), str) or not re.fullmatch(
                    rf"collector-observations-r{self.repository_id}-g[0-9a-f]{{32}}", catalog["release_tag"]) or
                catalog.get("name") != "metadata-catalog.json" or not isinstance(catalog.get("sha256"), str) or
                not _HASH.fullmatch(catalog["sha256"]) or type(catalog.get("bytes")) is not int or
                not 1 <= catalog["bytes"] <= 16 * 1024 * 1024):
            raise StateError("Invalid compaction proof outbox catalog")
        if "storage" in catalog:
            from .proof_maintenance import _ref
            _ref(catalog)
        if (previous is not None and (not isinstance(previous, dict) or set(previous) != {"sha256", "bytes"} or
                not isinstance(previous.get("sha256"), str) or not _HASH.fullmatch(previous["sha256"]) or
                type(previous.get("bytes")) is not int or not 1 <= previous["bytes"] <= 4096 or previous == ref)):
            raise StateError("Invalid compaction proof outbox predecessor")

    def compact(self, selection: StateSelection, *, max_input_bytes: int, max_input_parts: int,
                max_upload_bytes: int, min_part_savings: int = 1, max_runtime_seconds: int,
                quiescent: bool = False) -> dict:
        """Compact bounded immutable closures after restoring the selected state.

        New remote assets remain unreachable until a fresh full reconstruction
        succeeds and the predecessor pointer is advanced by compare-and-swap.
        """
        self.compaction_candidate_pointer_sha256 = None
        if getattr(self.transport, "cycle_slot", None) is not None:
            raise StateError("Manual compaction retains the legacy Release transport; disable cycle layout")
        bounds = (max_input_bytes, max_input_parts, max_upload_bytes, min_part_savings, max_runtime_seconds)
        if any(type(value) is not int or value < 1 for value in bounds):
            raise ValueError("Positive integer compaction limits are required")
        if not quiescent or self.private_key is None:
            raise StateError("Compaction requires a quiescent root and working-state private key")
        if selection.pointer is None or selection.index is None:
            raise StateError("Compaction requires authenticated existing state")
        self._check_index(selection.pointer, selection.index)
        known_pointer_fields = {"schema_version", "repository_id", "slug", "generation",
                                "predecessor_index_sha256", "logical_root", "snapshot_started_at",
                                "snapshot_sealed_at", "clock_source", "index", "context_sha256",
                                "proof_outbox"}
        if set(selection.pointer) - known_pointer_fields:
            raise StateError("Compaction does not support unknown predecessor pointer fields")
        before_count = len(selection.index["parts"])
        before_bytes = sum(ref["ciphertext_bytes"] for ref in selection.index["parts"].values())
        def no_op(plan: dict, estimated_requests: int = 0) -> dict:
            return {"status": "no_op", "input_parts": len(plan["parts"]),
                    "input_bytes": plan["input_bytes"], "part_savings": 0,
                    "before_part_count": before_count, "after_part_count": before_count,
                    "before_referenced_part_ciphertext_bytes": before_bytes,
                    "after_referenced_part_ciphertext_bytes": before_bytes,
                    "full_remote_reconstruction_verified": False,
                    "verification_scope": "working_state_files_only",
                    "predecessor_snapshot_started_at": selection.pointer["snapshot_started_at"],
                    "predecessor_snapshot_sealed_at": selection.pointer["snapshot_sealed_at"],
                    "snapshot_started_at": None, "snapshot_sealed_at": None,
                    "estimated_api_requests": estimated_requests}
        deadline = time.monotonic() + max_runtime_seconds
        def check_time() -> None:
            if time.monotonic() >= deadline:
                raise StateDeferredError("Compaction runtime budget exhausted", reason="compaction_runtime_limit")
        with self._lock(), tempfile.TemporaryDirectory(prefix="icsot-state-compact-") as temporary:
            directory = Path(temporary)
            current_head, actual = self._authoritative_pointer()
            if actual != canonical_json(selection.pointer):
                raise StateConflictError("State pointer changed before compaction")
            self.validate_compaction_metadata(selection.head, selection.pointer)
            if current_head != selection.head:
                self.validate_compaction_metadata(current_head, selection.pointer)
            self._check_compaction_root(selection.index)
            plan = self._compaction_plan(selection.index, max_input_bytes, max_input_parts)
            if plan["part_savings"] < min_part_savings:
                return no_op(plan)
            check_time()
            # XZ is only retained when no larger than its input. Include a
            # generous envelope and index-growth allowance before producing
            # frozen assets, so local preparation also respects the byte cap.
            archive_bound = sum(self._tar_total_bytes(sum(self._tar_member_bytes(item) for item in group))
                                for group in plan["groups"])
            index_bound = min(self.part_bytes,
                              len(canonical_json(selection.index)) + ENVELOPE_OVERHEAD +
                              sum(len(canonical_json(item["path"])) + 512
                                  for group in plan["groups"] for item in group) +
                              4096 * len(plan["groups"]))
            if archive_bound + index_bound + ENVELOPE_OVERHEAD * (len(plan["groups"]) + 1) > max_upload_bytes:
                raise StateDeferredError("Compaction cannot fit ciphertext upload byte budget",
                                         reason="compaction_byte_limit")
            state_bytes = sum(item["bytes"] for item in selection.index["files"])
            max_old = max((ref["ciphertext_bytes"] + ref["plaintext_bytes"] +
                           (ref["decoded_bytes"] if ref["encoding"] == "xz" else 0)
                           for ref in selection.index["parts"].values()), default=0)
            required_disk = self._compaction_disk_bytes(
                max_upload_bytes=max_upload_bytes, index_plaintext_bound=index_bound,
                state_bytes=state_bytes, max_old_part_scratch=max_old,
                immutable_group_bytes=self.immutable_group_bytes, compressed_index=self.grouped_profile)
            self._preflight_disk(directory=directory, required=required_disk,
                                 operation="compaction reconstruction and frozen assets")
            estimated_requests = (2 * (len(plan["groups"]) + 1) + 15 * (len(plan["groups"]) + 1) +
                                  len(selection.index["parts"]) + 13 * len({ref["release_tag"] for ref in selection.index["parts"].values()}) + 50)
            budget = getattr(self.transport, "publication_budget", None)
            budget_metrics = budget(estimated_requests) if callable(budget) else {}
            check_time()
            generation = uuid.uuid4().hex
            predecessor = selection.pointer["index"]["ciphertext_sha256"]
            release = f"collector-state-r{self.repository_id}-g{generation}"
            sink = _PreparedSink(directory / "frozen")
            files = copy.deepcopy(selection.index["files"])
            files_by_name = {item["path"]: item for item in files}
            parts = {key: copy.deepcopy(ref) for key, ref in selection.index["parts"].items()
                     if key not in plan["parts"]}
            metrics = {"new_parts": 0, "reused_parts": 0, "state_uploaded_ciphertext_bytes": 0,
                       "_asset_count": 0, "_releases": {release}}
            started = utc_iso()
            for number, members in enumerate(plan["groups"]):
                check_time()
                archive = directory / f"group-{number}.tar"
                with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
                    for item in members:
                        with (self.root / item["path"]).open("rb") as source:
                            output.addfile(self._tar_info(item), source)
                if archive.stat().st_size > self.immutable_group_bytes:
                    raise StateError("Compaction archive exceeds its selected bound")
                self._verify_group_files(archive, members, directory / f"check-{number}")
                part_id = self._part(archive, "tar", release, {}, directory, parts, metrics,
                                     prepared_sink=sink)
                for item in members:
                    files_by_name[item["path"]]["segments"] = [{"part": part_id, "member": item["path"]}]
                archive.unlink()
            times = {"snapshot_started_at": started, "snapshot_sealed_at": utc_iso(),
                     "clock_source": "runner_system_clock"}
            context = copy.deepcopy(selection.index["context"])
            context.update(self._binding(generation, predecessor))
            context.update(times)
            context["file_map_sha256"] = hashlib.sha256(canonical_json(files)).hexdigest()
            context["maintenance"] = {
                "kind": "state_compaction",
                "predecessor_snapshot_started_at": selection.pointer["snapshot_started_at"],
                "predecessor_snapshot_sealed_at": selection.pointer["snapshot_sealed_at"],
                "predecessor_context_sha256": selection.pointer["context_sha256"],
                "new_observations": 0, "main_evidence_bytes": 0,
            }
            index = {**copy.deepcopy(selection.index), "context": context, "files": files, "parts": parts}
            self._check_compaction_file_map(selection.index, index)
            raw_index = canonical_json(index)
            if len(raw_index) > index_bound:
                raise StateDeferredError("Compacted state index exceeds admitted plaintext bound",
                                         reason="compaction_byte_limit")
            ref, plaintext, encrypted = self._index_ref(raw_index, directory, release)
            pointer = {**self._binding(generation, predecessor), **times, "index": ref,
                       "context_sha256": hashlib.sha256(canonical_json(context)).hexdigest()}
            if selection.pointer.get("proof_outbox") is not None:
                pointer["proof_outbox"] = copy.deepcopy(selection.pointer["proof_outbox"])
            self._check_index(pointer, index)
            sink.capture(ref, encrypted)
            # Keep the frozen ciphertext through upload and reconstruction, but
            # release both preparation paths even when capture copied the file.
            plaintext.unlink()
            encrypted.unlink()
            upload_bytes = sum(asset["ref"]["ciphertext_bytes"] for asset in sink.assets)
            if upload_bytes > max_upload_bytes:
                raise StateDeferredError("Compaction exceeds ciphertext upload byte budget", reason="compaction_byte_limit")
            if len(selection.index["parts"]) - len(parts) < min_part_savings:
                return no_op(plan, estimated_requests)
            self._check_compaction_root(selection.index)
            for asset in sink.assets:
                check_time()
                asset_ref = asset["ref"]
                self.transport.ensure_release(asset_ref["release_tag"])
                self.transport.upload_asset(asset_ref["release_tag"], asset_ref["name"], sink.directory / asset["path"])
                target = directory / "upload-check"
                self._download_verified(asset_ref, target)
                target.unlink()
            check_time()
            remote_index = directory / "remote-index.enc"
            decoded_index = directory / "remote-index.json"
            self._download_verified(ref, remote_index)
            self._decrypt(ref, remote_index, decoded_index)
            index_json = (self._decode_part(ref, decoded_index, directory / "remote-index.decoded")
                          if ref.get("encoding") == "xz" else decoded_index)
            fresh_index = _json(index_json.read_bytes(), "compacted encrypted state index")
            self._check_index(pointer, fresh_index)
            self._check_compaction_file_map(selection.index, fresh_index)
            if fresh_index != index:
                raise StateError("Compacted remote index differs from frozen index")
            remote_index.unlink()
            if index_json != decoded_index:
                index_json.unlink()
            decoded_index.unlink()
            staging, downloads = directory / "reconstructed", directory / "downloads"
            staging.mkdir(mode=0o700)
            downloads.mkdir(mode=0o700)
            self._reconstruct(fresh_index, staging, downloads, check_progress=check_time)
            for item in fresh_index["files"]:
                if stat.S_IMODE((staging / item["path"]).stat().st_mode) != item["mode"]:
                    raise StateError("Compacted reconstructed file mode differs")
            self._check_compaction_root(selection.index)
            check_time()
            self.compaction_candidate_pointer_sha256 = hashlib.sha256(canonical_json(pointer)).hexdigest()
            commit = self._advance(selection, pointer, metadata_validator=self.validate_compaction_metadata)
            return {**budget_metrics, "status": "complete", "pointer": pointer, "pointer_commit": commit,
                    "input_parts": len(plan["parts"]), "input_bytes": plan["input_bytes"],
                    "part_savings": len(selection.index["parts"]) - len(parts),
                    "before_part_count": before_count, "after_part_count": len(parts),
                    "before_referenced_part_ciphertext_bytes": before_bytes,
                    "after_referenced_part_ciphertext_bytes": sum(ref["ciphertext_bytes"] for ref in parts.values()),
                    "full_remote_reconstruction_verified": True, "estimated_api_requests": estimated_requests,
                    "verification_scope": "working_state_files_only",
                    "predecessor_snapshot_started_at": selection.pointer["snapshot_started_at"],
                    "predecessor_snapshot_sealed_at": selection.pointer["snapshot_sealed_at"],
                    "snapshot_started_at": times["snapshot_started_at"],
                    "snapshot_sealed_at": times["snapshot_sealed_at"],
                    "state_uploaded_ciphertext_bytes": upload_bytes,
                    "compaction_peak_additional_disk_bytes_estimate": required_disk}

    def _recovery_parts(self, pool: RecoveryCandidatePool | None, selection: StateSelection) -> dict:
        if pool is None:
            return {}
        if not isinstance(pool, RecoveryCandidatePool):
            raise StateError("Explicit frozen recovery candidate pool required")
        if (not isinstance(pool.parts, tuple) or len(pool.parts) > 20000 or
                not isinstance(pool.lineage_generations, tuple) or len(pool.lineage_generations) > 16):
            raise StateError("Invalid bounded recovery candidate pool")
        if selection.pointer is not None or selection.index is not None:
            raise StateError("Recovery candidates require an actually missing authoritative state")
        if (pool.repository_id != self.repository_id or pool.slug != self.slug or
                pool.recipient_spki_sha256 != self.recipient or
                pool.destination_repository != getattr(self.transport, "repository", None) or
                not REPO_RE.fullmatch(pool.destination_repository) or
                not isinstance(pool.recovery_epoch, str) or not _GENERATION.fullmatch(pool.recovery_epoch) or
                not isinstance(pool.old_generation, str) or not _GENERATION.fullmatch(pool.old_generation) or
                not isinstance(pool.source_ledger_sha256, str) or not _HASH.fullmatch(pool.source_ledger_sha256)):
            raise StateError("Recovery candidate repository/recipient/ledger binding differs")
        generations = (pool.old_generation, *pool.lineage_generations)
        if any(not isinstance(value, str) or not _GENERATION.fullmatch(value) for value in generations):
            raise StateError("Invalid frozen recovery generation lineage")
        prefixes = [f"collector-state-r{self.repository_id}-g{value}" for value in generations]
        result = {}
        for candidate in pool.parts:
            ref = copy.deepcopy(candidate)
            _asset_ref(ref)
            if not any(ref.get("release_tag") == prefix or
                       re.fullmatch(re.escape(prefix) + r"-p(?:[2-9]|[1-9][0-9]+)", ref["release_tag"])
                       for prefix in prefixes):
                raise StateError("Recovery candidate is outside the frozen target generation")
            if (ref.get("kind") not in ("raw", "tar") or ref.get("encoding") not in ("raw", "xz") or
                    ref.get("public_key_fingerprint_sha256") != self.recipient or
                    any(not isinstance(ref.get(field), str) or not _HASH.fullmatch(ref[field])
                        for field in ("plaintext_sha256", "decoded_sha256")) or
                    any(type(ref.get(field)) is not int or not 0 <= ref[field] <= self.part_bytes
                        for field in ("plaintext_bytes", "decoded_bytes")) or
                    ref["name"] != "part-" + ref["plaintext_sha256"] + ".enc" or
                    ref["encoding"] == "raw" and (ref["plaintext_sha256"] != ref["decoded_sha256"] or
                                                  ref["plaintext_bytes"] != ref["decoded_bytes"])):
                raise StateError("Invalid recovery candidate part binding")
            key = (ref["decoded_sha256"], ref["decoded_bytes"], ref["kind"])
            if key in result:
                raise StateError("Ambiguous duplicate recovery candidate content")
            result[key] = ref
        return result

    def publish(self, selection: StateSelection, *, dependencies: list[dict] | tuple = (),
                code_hashes: dict | None = None, config_hashes: dict | None = None,
                lane_heads: dict | None = None, evidence_heads: dict | None = None,
                quiescent: bool = False, proof_catalog: dict | None = None) -> dict:
        return self._build_publication(selection, dependencies=dependencies, code_hashes=code_hashes,
                                       config_hashes=config_hashes, lane_heads=lane_heads,
                                       evidence_heads=evidence_heads, quiescent=quiescent, proof_catalog=proof_catalog)

    def _build_publication(self, selection: StateSelection, *, dependencies: list[dict] | tuple = (),
                code_hashes: dict | None = None, config_hashes: dict | None = None,
                lane_heads: dict | None = None, evidence_heads: dict | None = None,
                quiescent: bool = False, generation: str | None = None,
                prepared_sink: _PreparedSink | None = None,
                recovery_candidates: RecoveryCandidatePool | None = None, proof_catalog: dict | None = None) -> dict:
        request_start = getattr(self.transport, "request_count", 0)
        graphql_start = getattr(self.transport, "graphql_request_count", 0)
        if not quiescent:
            raise StateError("Snapshot publication requires joined capture/finalizer callbacks")
        if selection.pointer is not None:
            if selection.index is None:
                raise StateError("Pointer without authenticated index")
            self._check_index(selection.pointer, selection.index)
        elif selection.index is not None:
            raise StateError("Index without authoritative pointer")
        prior = selection.index or {"parts": {}, "dependencies": []}
        recovery_parts = self._recovery_parts(recovery_candidates, selection)
        if recovery_candidates is not None and prepared_sink is None:
            raise StateError("Recovery requires a durably prepared publication")
        generation = generation or uuid.uuid4().hex
        if not _GENERATION.fullmatch(generation):
            raise ValueError("A prepared generation must be 32 lowercase hexadecimal characters")
        predecessor = selection.pointer["index"]["ciphertext_sha256"] if selection.pointer else None
        release = f"collector-state-r{self.repository_id}-g{generation}"
        metrics = {"new_parts": 0, "reused_parts": 0, "state_uploaded_ciphertext_bytes": 0,
                   "_asset_count": 0, "_releases": set()}
        with self._lock(), tempfile.TemporaryDirectory(prefix="icsot-state-publish-") as temporary:
            directory = Path(temporary)
            all_dependencies = list(prior["dependencies"])
            known = {_asset_identity(ref) for ref in all_dependencies}
            # Evidence must be independently uploaded and verified before state
            # publication. Previously authenticated prerequisites retain their
            # exact original identities without downloading the old corpus.
            for ref in dependencies:
                _asset_ref(ref)
                identity = _asset_identity(ref)
                if identity not in known:
                    target = directory / ("dependency-" + str(len(all_dependencies)))
                    self._download_verified(ref, target)
                    target.unlink()
                    all_dependencies.append(dict(ref))
                    known.add(identity)
            source_bytes = 0
            source_files = 0
            largest_file = 0
            for path in self.root.rglob("*"):
                name = path.relative_to(self.root).as_posix()
                if not self._excluded(name) and path.is_file():
                    size = path.stat().st_size
                    source_bytes += size
                    source_files += 1
                    largest_file = max(largest_file, size)
                    if name.endswith((".sqlite3", ".sqlite", ".db")):
                        wal = Path(str(path) + "-wal")
                        if wal.is_file():
                            source_bytes += wal.stat().st_size
            largest_payload = min(self.part_bytes, max(largest_file,
                                  min(self.profile_group_bytes if self.grouped_profile else self.immutable_group_bytes,
                                      source_bytes + 10240 * (source_files + 1)),
                                  min(source_bytes, self.profile_group_bytes if self.grouped_profile else self.group_bytes)
                                      + 10240 * (source_files + 1)))
            # Snapshot copy + current raw/tar + XZ + local/remote ciphertext.
            # Encryption envelope overhead is bounded by the codec's 64 KiB header.
            if self.grouped_profile:
                # Raw oversized chunks are processed serially; only tar groups
                # use the four-worker batch. Do not charge thirteen raw chunks.
                group_peak = 13 * (min(self.profile_group_bytes, largest_payload) + 8 * 1024**2 + 65536)
                publish_peak = source_bytes + max(group_peak, 4 * (largest_payload + 65536))
            else:
                publish_peak = source_bytes + 4 * (largest_payload + 65536)
            if prepared_sink is not None:
                # Retain every encrypted asset plus a generous per-file/index
                # metadata allowance until authoritative pointer acknowledgement.
                publish_peak += source_bytes + 65536 * (source_files + 1)
            self._preflight_disk(directory=directory, required=publish_peak,
                                 operation="publication snapshot and encrypted verification")
            staging = directory / "snapshot"
            staging.mkdir(mode=0o700)
            snapshot_started_at = utc_iso()
            files = self._snapshot_files(staging)
            if prepared_sink is not None:
                prepared_sink.source_files = copy.deepcopy(files)
            estimate = self._publication_requests_estimate(files, prior, recovery_parts)
            budget = getattr(self.transport, "publication_budget", None)
            if callable(budget):
                metrics.update(budget(estimate))
            metrics["publish_peak_additional_disk_bytes_estimate"] = publish_peak
            metrics["snapshot_staging_bytes"] = sum(item["bytes"] for item in files)
            parts = {}
            prior_parts = {(part["decoded_sha256"], part["decoded_bytes"], part["kind"]): part
                           for part in prior["parts"].values()}
            prior_parts.update(recovery_parts)
            if prepared_sink is None:
                self.transport.ensure_release(release)
            else:
                # Finish any old-part remote authentication before producing
                # new ciphertext, so a quota deferral cannot leave half a seal.
                verified_prior, verification_metrics = {}, {"reused_parts": 0}
                for ref in prior["parts"].values():
                    self._reuse_part(ref, directory, verified_prior, verification_metrics)
            metrics["_releases"].add(release)
            plan = self._snapshot_plan(files, prior)
            metrics["new_small_immutable_files_packed"] = plan["new_small_immutable_files"]
            if self.grouped_profile:
                metrics["large_member_legacy_fallback_count"] = plan["large_member_legacy_fallback_count"]
                metrics["large_member_legacy_fallback_profile"] = "mixed-raw-or-custom-xz-parts"
            for item in files:
                if item["path"] in plan["reused"]:
                    item["segments"] = plan["reused"][item["path"]]
                    for segment in item["segments"]:
                        self._reuse_part(prior["parts"][segment["part"]], directory, parts, metrics)
            for item in plan["raw"]:
                item["segments"] = []
                with (staging / item["path"]).open("rb") as source:
                    prefix = source.read(32)
                    source.seek(0)
                    already_compressed = (item["path"].startswith("git/") and "/objects/" in item["path"] or
                                          prefix.startswith((b"PACK", b"# v2 git bundle", b"# v3 git bundle",
                                                             b"\xfd7zXZ\x00", b"\x1f\x8b")))
                    while True:
                        chunk = directory / "chunk"
                        with chunk.open("wb") as output:
                            remaining = self.part_bytes
                            while remaining and (data := source.read(min(4 * 1024 * 1024, remaining))):
                                output.write(data)
                                remaining -= len(data)
                        if chunk.stat().st_size == 0 and item["segments"]:
                            chunk.unlink()
                            break
                        digest = self._part(chunk, "raw", release, prior_parts, directory, parts, metrics,
                                            compress=not already_compressed, prepared_sink=prepared_sink,
                                            capture_reused=recovery_candidates is not None)
                        item["segments"].append({"part": digest})
                        count = chunk.stat().st_size
                        chunk.unlink()
                        if count < self.part_bytes:
                            break
            groups = plan["groups"]
            def prepare_group(number: int, members: list[dict]) -> tuple[Path, Path | None]:
                archive_path = directory / f"group-{number}.tar"
                with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
                    for item in members:
                        with (staging / item["path"]).open("rb") as source:
                            archive.addfile(self._tar_info(item), source)
                limit = self.profile_group_bytes if self.grouped_profile else self.part_bytes
                if archive_path.stat().st_size > limit:
                    raise StateError("Grouped snapshot exceeds plaintext part limit")
                self._verify_group_files(archive_path, members, directory / f"group-check-{number}")
                encoded = None
                if self.grouped_profile:
                    encoded = directory / f"group-{number}.xz"
                    self._profile_compress(archive_path, encoded)
                return archive_path, encoded

            def upload_group(members: list[dict], prepared: tuple[Path, Path | None]) -> None:
                archive_path, encoded = prepared
                part_id = self._part(archive_path, "tar", release, prior_parts, directory, parts, metrics,
                                     prepared_sink=prepared_sink, capture_reused=recovery_candidates is not None,
                                     preencoded=encoded)
                for item in members:
                    item["segments"] = [{"part": part_id, "member": item["path"]}]
                archive_path.unlink()
                if encoded is not None:
                    encoded.unlink(missing_ok=True)

            if self.grouped_profile:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=4) as pool:
                    for offset in range(0, len(groups), 4):
                        batch = groups[offset:offset + 4]
                        futures = [pool.submit(prepare_group, offset + i, members)
                                   for i, members in enumerate(batch)]
                        # Resolve the entire batch before the first upload. The
                        # temporary directory cleans all partial outputs on error.
                        ready = [future.result() for future in futures]
                        for members, prepared in zip(batch, ready):
                            upload_group(members, prepared)
            else:
                for number, members in enumerate(groups):
                    upload_group(members, prepare_group(number, members))
            bind = getattr(self.transport, "bind_asset_refs", None)
            if prepared_sink is None and callable(bind):
                bind(parts.values())
            snapshot_times = {"snapshot_started_at": snapshot_started_at, "snapshot_sealed_at": utc_iso(),
                              "clock_source": "runner_system_clock"}
            context = {**self._binding(generation, predecessor), **snapshot_times,
                       "recipient_spki_sha256": self.recipient,
                       "file_map_sha256": hashlib.sha256(canonical_json(files)).hexdigest(),
                       "dependencies_sha256": hashlib.sha256(canonical_json(all_dependencies)).hexdigest(),
                       "code_hashes": code_hashes or {}, "config_hashes": config_hashes or {},
                       "lane_heads": lane_heads or {}, "evidence_heads": evidence_heads or {}}
            if self.grouped_profile:
                context["state_archive_profile"] = {
                    "name": "grouped-xz-v2",
                    "large_member_legacy_fallback_count": plan["large_member_legacy_fallback_count"],
                    "large_member_legacy_fallback_profile": "mixed-raw-or-custom-xz-parts",
                }
            proof_node = None
            proof_head = (selection.pointer or {}).get("proof_outbox")
            if proof_catalog is not None:
                catalog_keys = {"release_tag", "name", "sha256", "bytes"}
                if (not isinstance(proof_catalog, dict) or
                        set(proof_catalog) not in (catalog_keys, catalog_keys | {"storage"}) or
                        proof_catalog.get("name") != "metadata-catalog.json" or
                        not isinstance(proof_catalog.get("release_tag"), str) or
                        not re.fullmatch(f"collector-observations-r{self.repository_id}-g[0-9a-f]{{32}}", proof_catalog["release_tag"]) or
                        not isinstance(proof_catalog.get("sha256"), str) or not _HASH.fullmatch(proof_catalog["sha256"]) or
                        type(proof_catalog.get("bytes")) is not int or not 1 <= proof_catalog["bytes"] <= 8 * 1024 * 1024):
                    raise StateError("Invalid verified public proof catalog descriptor")
                if "storage" in proof_catalog:
                    from .proof_maintenance import _ref
                    _ref(proof_catalog)
                marker = next((ref for ref in all_dependencies
                    if ref.get("release_tag") == proof_catalog["release_tag"] and ref.get("name") == proof_catalog["name"] and
                    ref.get("ciphertext_sha256") == proof_catalog["sha256"] and
                    ref.get("ciphertext_bytes") == proof_catalog["bytes"] and
                    ref.get("storage") == proof_catalog.get("storage")), None)
                if marker is None or _asset_identity(marker) not in self._verified_downloads:
                    raise StateError("Public proof outbox requires a remotely verified marker dependency")
                proof_node = {"schema_version": 1, "kind": "icsot_public_proof_outbox",
                              "repository_id": self.repository_id, "slug": self.slug, "generation": generation,
                              "created_at": snapshot_times["snapshot_sealed_at"], "catalog": copy.deepcopy(proof_catalog),
                              "previous": copy.deepcopy(proof_head)}
                raw_node = canonical_json(proof_node)
                if len(raw_node) > 4096:
                    raise StateError("Public proof outbox node exceeds bounded metadata size")
                proof_head = {"sha256": hashlib.sha256(raw_node).hexdigest(), "bytes": len(raw_node)}
            if proof_head is not None:
                context["proof_outbox"] = proof_head
            index = {"context": context, "files": files, "parts": parts,
                     "dependencies": all_dependencies}
            ref, plaintext, encrypted = self._index_ref(canonical_json(index), directory, release)
            pointer = {**self._binding(generation, predecessor), **snapshot_times, "index": ref,
                       "context_sha256": hashlib.sha256(canonical_json(context)).hexdigest()}
            if proof_head is not None:
                pointer["proof_outbox"] = proof_head
            self._check_index(pointer, index)
            if prepared_sink is None:
                self.transport.upload_asset(release, ref["name"], encrypted)
                binder = getattr(self.transport, "bind_asset_ref", None)
                if callable(binder):
                    binder(ref)
                self._download_verified(ref, directory / "verified-index.enc")
                commit = self._advance(selection, pointer,
                                       proof_outbox_node=canonical_json(proof_node) if proof_node else None)
            else:
                prepared_sink.capture(ref, encrypted)
                prepared_sink.index = copy.deepcopy(index)
                prepared_sink.proof_outbox_node = copy.deepcopy(proof_node)
                commit = None
            metrics["state_uploaded_ciphertext_bytes"] += ref["ciphertext_bytes"]
        state_release_count = len(metrics.pop("_releases"))
        metrics.pop("_asset_count")
        request_total = getattr(self.transport, "request_count", 0)
        graphql_total = getattr(self.transport, "graphql_request_count", 0)
        download_metrics = getattr(self.transport, "download_metrics", lambda: {})()
        return {**metrics, **download_metrics, "state_release_count": state_release_count,
                "destination_github_api_requests_total": request_total,
                "destination_github_graphql_api_requests_total": graphql_total,
                "destination_github_graphql_api_requests_for_publish": graphql_total - graphql_start,
                "destination_github_rest_api_requests_total": request_total - graphql_total,
                "destination_github_rest_api_requests_for_publish": request_total - request_start - (graphql_total - graphql_start),
                "destination_github_graphql_rate_probe": dict(getattr(self.transport, "_last_graphql_rate_headers", {})),
                "destination_github_graphql_rate_remaining": getattr(self.transport, "graphql_rate_remaining", None),
                "destination_github_graphql_rate_reset": getattr(self.transport, "graphql_rate_reset", None),
                "destination_github_api_requests_for_publish": request_total - request_start,
                "state_encoding": ("grouped-xz-v2" if self.grouped_profile else
                                   "per-part XZ by default; already compressed Git data stays raw"),
                "generation": generation, "pointer_commit": commit,
                "index_sha256": ref["ciphertext_sha256"], "pointer": pointer,
                "state_referenced_ciphertext_bytes": sum(p["ciphertext_bytes"] for p in parts.values()) + ref["ciphertext_bytes"],
                "state_plaintext_bytes": sum(item["bytes"] for item in files)}

    @staticmethod
    def _local_record(path: Path, value: dict, *, replace: bool = False) -> None:
        temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("xb") as output:
                os.chmod(temporary, 0o600)
                output.write(canonical_json(value))
                output.flush()
                os.fsync(output.fileno())
            if replace:
                os.replace(temporary, path)
            else:
                os.link(temporary, path)
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def _authoritative_pointer(self) -> tuple[str | None, bytes | None]:
        head = self.transport.branch_head()
        binding = self._check_slug_binding(head)
        raw = self.transport.read_pointer(head, self.repository_id) if head else None
        if binding is not None and raw is None:
            raise StateConflictError("Repository binding exists without its authoritative state pointer")
        if raw is not None:
            if binding is None:
                raise StateConflictError("State pointer has no authoritative repository slug binding")
            self._check_pointer(_json(raw, "authoritative state pointer"))
        return head, raw

    def _prepared_directory(self, directory: Path | str) -> Path:
        directory = Path(directory).resolve()
        if directory.is_relative_to(self.root) or self.root.is_relative_to(directory):
            raise StateError("Prepared state directory must be separate from the captured root")
        if self.private_key and self.private_key.is_relative_to(directory):
            raise StateError("Prepared state directory must not contain the operational private key")
        return directory

    def prepare(self, selection: StateSelection, *, directory: Path | str, generation: str,
                source_import_sha256: str, dependencies: list[dict] | tuple = (),
                code_hashes: dict | None = None, config_hashes: dict | None = None,
                lane_heads: dict | None = None, evidence_heads: dict | None = None,
                quiescent: bool = False,
                recovery_candidates: RecoveryCandidatePool | None = None, proof_catalog: dict | None = None) -> PreparedState:
        """Freeze local bytes without uploading or committing any GitHub state.

        Record the returned generation, manifest hash and asset references in
        the caller's durable disposition before ``publish_prepared``. Keep this
        directory across bounded reset waits; no backend sleep or new generation
        retry is performed. Recovery on another runner needs these exact files.
        """
        if not quiescent:
            raise StateError("Preparation requires joined capture/finalizer callbacks")
        if getattr(self.transport, "cycle_slot", None) is not None:
            raise StateError("Prepared maintenance publication retains the legacy Release transport")
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise ValueError("Explicit stable 32-hex generation required")
        if not isinstance(source_import_sha256, str) or not _HASH.fullmatch(source_import_sha256):
            raise ValueError("Source import SHA-256 required")
        directory = self._prepared_directory(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(directory.iterdir()):
            raise StateError("Preparation requires an empty directory; load existing prepared bytes by their SHA")
        os.chmod(directory, 0o700)
        heads = dict(evidence_heads or {})
        if heads.get("source_import_sha256", source_import_sha256) != source_import_sha256:
            raise StateError("Source import binding differs from evidence heads")
        heads["source_import_sha256"] = source_import_sha256
        if recovery_candidates is not None:
            self._recovery_parts(recovery_candidates, selection)
            recovery = {"recovery_epoch": recovery_candidates.recovery_epoch,
                        "source_ledger_sha256": recovery_candidates.source_ledger_sha256,
                        "old_generation": recovery_candidates.old_generation,
                        "lineage_generations": list(recovery_candidates.lineage_generations),
                        "candidate_pool_sha256": hashlib.sha256(canonical_json(list(recovery_candidates.parts))).hexdigest(),
                        "expected_pointer": None, "expected_slug_binding": None}
            if heads.get("recovery", recovery) != recovery:
                raise StateError("Recovery lineage differs from evidence heads")
            heads["recovery"] = recovery
        with self._lock():
            _, actual = self._authoritative_pointer()
            expected = canonical_json(selection.pointer) if selection.pointer else None
            if actual != expected:
                raise StateConflictError("State pointer changed before preparation")
            sink = _PreparedSink(directory)
            metrics = self._build_publication(selection, dependencies=dependencies,
                                             code_hashes=code_hashes, config_hashes=config_hashes,
                                             lane_heads=lane_heads, evidence_heads=heads, quiescent=True,
                                             generation=generation, prepared_sink=sink,
                                             recovery_candidates=recovery_candidates, proof_catalog=proof_catalog)
            assert sink.index is not None
            metrics["state_generation_new_ciphertext_bytes"] = metrics["state_uploaded_ciphertext_bytes"]
            metrics["state_reused_referenced_ciphertext_bytes"] = sum(
                ref["ciphertext_bytes"] for ref in sink.index["parts"].values()
                if ref["release_tag"] != f"collector-state-r{self.repository_id}-g{generation}" and
                not ref["release_tag"].startswith(f"collector-state-r{self.repository_id}-g{generation}-p"))
            metrics["state_prepared_ciphertext_bytes"] = sum(asset["ref"]["ciphertext_bytes"] for asset in sink.assets)
            metrics["state_uploaded_ciphertext_bytes"] = 0
            metrics["status"] = "prepared_locally"
            value = {"schema_version": 1, "kind": "icsot_prepared_state_v1",
                     "repository_id": self.repository_id, "slug": self.slug, "logical_root": str(self.root),
                     "recipient_spki_sha256": self.recipient, "generation": generation,
                     "source_import_sha256": source_import_sha256,
                     "selection": {"head": selection.head, "pointer": selection.pointer, "index": selection.index},
                     "expected_pointer_sha256": hashlib.sha256(canonical_json(selection.pointer)).hexdigest(),
                     "pointer": metrics["pointer"], "index": sink.index, "source_files": sink.source_files,
                     "assets": sink.assets, "metrics": metrics}
            if sink.proof_outbox_node is not None:
                value["proof_outbox_node"] = sink.proof_outbox_node
            self._local_record(directory / "prepared.json", value)
            digest = _digest(directory / "prepared.json")
        return self.load_prepared(directory, digest)

    def load_prepared(self, directory: Path | str, expected_manifest_sha256: str) -> PreparedState:
        """Load only a caller-pinned manifest; the upload journal is not authority."""
        directory = self._prepared_directory(directory)
        if not isinstance(expected_manifest_sha256, str) or not _HASH.fullmatch(expected_manifest_sha256):
            raise ValueError("Pinned prepared-manifest SHA-256 required")
        raw = (directory / "prepared.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
            raise StateError("Prepared manifest SHA-256 differs")
        value = _json(raw, "prepared state manifest")
        self._validate_prepared(value, directory, check_payloads=False)
        return PreparedState(directory, expected_manifest_sha256, value["generation"], value["source_import_sha256"],
                             copy.deepcopy(value["pointer"]), tuple(copy.deepcopy(asset["ref"]) for asset in value["assets"]),
                             tuple(sorted({asset["ref"]["release_tag"] for asset in value["assets"]})))

    def _validate_prepared(self, value: dict, directory: Path, *, check_payloads: bool) -> StateSelection:
        if (value.get("schema_version") != 1 or value.get("kind") != "icsot_prepared_state_v1" or
                value.get("repository_id") != self.repository_id or value.get("slug") != self.slug or
                value.get("logical_root") != str(self.root) or value.get("recipient_spki_sha256") != self.recipient or
                public_key_fingerprint(self.public_key) != self.recipient):
            raise StateError("Prepared state repository/root/recipient binding differs")
        generation, source = value.get("generation"), value.get("source_import_sha256")
        if (not isinstance(generation, str) or not _GENERATION.fullmatch(generation) or
                not isinstance(source, str) or not _HASH.fullmatch(source)):
            raise StateError("Invalid prepared generation/source binding")
        pointer, index = value.get("pointer"), value.get("index")
        if not isinstance(pointer, dict) or not isinstance(index, dict):
            raise StateError("Missing prepared pointer/index")
        self._check_index(pointer, index)
        if pointer["generation"] != generation or index["context"]["evidence_heads"].get("source_import_sha256") != source:
            raise StateError("Prepared source/generation differs from encrypted index context")
        original = value.get("selection")
        if not isinstance(original, dict):
            raise StateError("Missing prepared predecessor selection")
        selection = StateSelection(original.get("head"), original.get("pointer"), original.get("index"))
        if selection.pointer is not None:
            if not isinstance(selection.index, dict):
                raise StateError("Prepared predecessor pointer lacks index")
            self._check_index(selection.pointer, selection.index)
        elif selection.index is not None:
            raise StateError("Prepared predecessor index lacks pointer")
        if value.get("expected_pointer_sha256") != hashlib.sha256(canonical_json(selection.pointer)).hexdigest():
            raise StateError("Prepared expected-pointer hash differs")
        predecessor = selection.pointer["index"]["ciphertext_sha256"] if selection.pointer else None
        if pointer["predecessor_index_sha256"] != predecessor:
            raise StateError("Prepared predecessor lineage differs")
        node = value.get("proof_outbox_node")
        previous_outbox = (selection.pointer or {}).get("proof_outbox")
        if node is not None:
            raw_node = canonical_json(node)
            catalog = node.get("catalog")
            marker_matches = isinstance(catalog, dict) and any(
                ref.get("release_tag") == catalog.get("release_tag") and ref.get("name") == catalog.get("name") and
                ref.get("ciphertext_sha256") == catalog.get("sha256") and ref.get("ciphertext_bytes") == catalog.get("bytes")
                for ref in index["dependencies"])
            if (node.get("schema_version") != 1 or node.get("kind") != "icsot_public_proof_outbox" or
                    node.get("repository_id") != self.repository_id or node.get("slug") != self.slug or
                    node.get("generation") != generation or node.get("previous") != previous_outbox or
                    node.get("created_at") != pointer["snapshot_sealed_at"] or len(raw_node) > 4096 or not marker_matches or
                    pointer.get("proof_outbox") != {"sha256": hashlib.sha256(raw_node).hexdigest(), "bytes": len(raw_node)}):
                raise StateError("Prepared proof outbox lineage differs")
        elif pointer.get("proof_outbox") != previous_outbox:
            raise StateError("Prepared proof outbox lacks its immutable node")
        source_files = [{key: item[key] for key in ("path", "bytes", "sha256", "mode")} for item in index["files"]]
        if value.get("source_files") != source_files:
            raise StateError("Prepared source file map differs from encrypted index")
        assets = value.get("assets")
        if not isinstance(assets, list) or not assets:
            raise StateError("Prepared state has no ciphertext assets")
        expected_refs = {_asset_identity(ref) for ref in index["parts"].values()}
        expected_refs.add(_asset_identity(pointer["index"]))
        prior_refs = {_asset_identity(ref) for ref in (selection.index or {}).get("parts", {}).values()}
        seen = set()
        for asset in assets:
            if not isinstance(asset, dict):
                raise StateError("Invalid prepared asset")
            ref = _asset_ref(asset.get("ref"))
            identity = _asset_identity(ref)
            name = f"assets/{ref['release_tag']}/{ref['name']}"
            if asset.get("path") != name or identity in seen:
                raise StateError("Invalid or duplicate prepared asset path")
            seen.add(identity)
            path = directory / name
            if not path.resolve().is_relative_to(directory) or path.is_symlink() or not path.is_file():
                raise StateError("Prepared ciphertext is missing or unsafe")
            if check_payloads and (path.stat().st_size != ref["ciphertext_bytes"] or _digest(path) != ref["ciphertext_sha256"]):
                raise StateError("Prepared ciphertext SHA-256/size differs")
        if seen != expected_refs - prior_refs:
            raise StateError("Prepared asset set differs from new encrypted index dependencies")
        if _asset_identity(assets[-1]["ref"]) != _asset_identity(pointer["index"]):
            raise StateError("Prepared index must be the final uploaded state asset")
        return selection

    def _validate_prepared_root(self, value: dict) -> None:
        with tempfile.TemporaryDirectory(prefix="icsot-prepared-root-check-") as temporary:
            files = self._snapshot_files(Path(temporary), materialize=False)
        if files != value["source_files"]:
            raise StateError("Quiescent working root changed after preparation")

    def publish_prepared(self, prepared: PreparedState, *, source_import_sha256: str | None = None,
                         quiescent: bool = False, progress_callback: Callable[[dict], None] | None = None,
                         progress_requests_reserve: int = 0) -> dict:
        """Upload one frozen generation; caller controls bounded reset-aware retries."""
        if not quiescent:
            raise StateError("Prepared publication requires joined callbacks")
        if getattr(self.transport, "cycle_slot", None) is not None:
            raise StateError("Prepared maintenance publication retains the legacy Release transport")
        if not isinstance(prepared, PreparedState):
            raise TypeError("A SHA-pinned PreparedState is required")
        if type(progress_requests_reserve) is not int or not 0 <= progress_requests_reserve <= 100000:
            raise ValueError("Bounded durable progress request reserve required")
        loaded = self.load_prepared(prepared.directory, prepared.manifest_sha256)
        if (loaded.generation != prepared.generation or loaded.source_import_sha256 != prepared.source_import_sha256 or
                source_import_sha256 is not None and source_import_sha256 != loaded.source_import_sha256):
            raise StateError("Prepared source/generation request changed")
        value = _json((loaded.directory / "prepared.json").read_bytes(), "prepared state manifest")
        selection = self._validate_prepared(value, loaded.directory, check_payloads=False)
        current_tag = f"collector-state-r{self.repository_id}-g{loaded.generation}"
        def generation_asset(ref):
            return ref["release_tag"] == current_tag or re.fullmatch(
                re.escape(current_tag) + r"-p(?:[2-9]|[1-9][0-9]+)", ref["release_tag"])
        if value["pointer"]["index"]["release_tag"] != current_tag:
            raise StateError("Prepared index is outside its current generation namespace")
        historical = [asset["ref"] for asset in value["assets"] if not generation_asset(asset["ref"])]
        historical_ids = {_asset_identity(ref) for ref in historical}
        request_start = getattr(self.transport, "request_count", 0)
        graphql_start = getattr(self.transport, "graphql_request_count", 0)
        verified = self._prepared_verified.setdefault(loaded.manifest_sha256, set())
        # Captured historical parts are read-only dependencies. Their remote
        # existence must be checked again even when this process verified them.
        verified.difference_update(historical_ids)
        acknowledged_upload_bytes = 0
        def progress(status: str, *, pointer_commit: str | None = None) -> None:
            record = {
                "schema_version": 1, "status": status, "generation": loaded.generation,
                "prepared_manifest_sha256": loaded.manifest_sha256,
                "source_import_sha256": loaded.source_import_sha256,
                "release_tags": list(loaded.release_tags), "pointer": loaded.pointer,
                "verified_assets": [asset["ref"] for asset in value["assets"] if _asset_identity(asset["ref"]) in verified],
                "pointer_commit": pointer_commit}
            self._local_record(loaded.directory / "progress.json", record, replace=True)
            if progress_callback is not None:
                progress_callback(copy.deepcopy(record))
        with self._lock():
            head, actual = self._authoritative_pointer()
            desired = canonical_json(value["pointer"])
            already_committed = actual == desired
            old = canonical_json(selection.pointer) if selection.pointer else None
            if not already_committed and actual != old:
                raise StateConflictError("State pointer changed before prepared publication")
            if not already_committed:
                self._validate_prepared_root(value)
                self._validate_prepared(value, loaded.directory, check_payloads=True)
                progress("publication_pending")  # Durable local disposition BEFORE any mutation.
                pending = [asset for asset in value["assets"]
                           if _asset_identity(asset["ref"]) not in verified | historical_ids]
                new_assets = {_asset_identity(asset["ref"]) for asset in value["assets"]}
                cold_prior = [ref for ref in value["index"]["parts"].values()
                              if _asset_identity(ref) not in new_assets and _asset_identity(ref) not in self._verified_parts]
                prior_dependencies = {_asset_identity(ref) for ref in (selection.index or {}).get("dependencies", [])}
                dependencies = [ref for ref in value["index"]["dependencies"]
                                if _asset_identity(ref) not in prior_dependencies | self._verified_downloads]
                tags = {asset["ref"]["release_tag"] for asset in pending}
                required = (2 * len(pending) + 15 * len(tags) + 18 + len(dependencies) +
                            13 * len({ref["release_tag"] for ref in dependencies}) + len(cold_prior) +
                            13 * len({ref["release_tag"] for ref in cold_prior}) + len(historical) +
                            13 * len({ref["release_tag"] for ref in historical}) + progress_requests_reserve)
                budget = getattr(self.transport, "publication_budget", None)
                budget_metrics = budget(required) if callable(budget) else {}
                maximum_download = max([asset["ref"]["ciphertext_bytes"] for asset in pending] +
                                       [ref["ciphertext_bytes"] for ref in dependencies] +
                                       [ref["ciphertext_bytes"] + ref["plaintext_bytes"] +
                                        (ref["decoded_bytes"] if ref["encoding"] == "xz" else 0) for ref in cold_prior] +
                                       [ref["ciphertext_bytes"] + (0 if _asset_identity(ref) in self._verified_parts else
                                        ref["plaintext_bytes"] + (ref["decoded_bytes"] if ref["encoding"] == "xz" else 0))
                                        for ref in historical] + [0])
                self._preflight_disk(directory=loaded.directory, required=maximum_download,
                                     operation="prepared upload verification")
                find_asset = getattr(self.transport, "find_asset", None)
                if (pending or historical) and not callable(find_asset):
                    raise StateError("Prepared transport must support exact asset reconciliation")
                with tempfile.TemporaryDirectory(prefix="icsot-prepared-verify-", dir=loaded.directory) as temporary:
                    temporary = Path(temporary)
                    authenticated_prior, prior_metrics = {}, {"reused_parts": 0}
                    historical_tags = set()
                    for ref in historical:
                        remote = find_asset(ref["release_tag"], ref["name"], refresh=ref["release_tag"] not in historical_tags)
                        historical_tags.add(ref["release_tag"])
                        if (remote is None or remote.get("name") != ref["name"] or remote.get("state") != "uploaded" or
                                remote.get("size") != ref["ciphertext_bytes"] or
                                remote.get("digest") not in (None, "sha256:" + ref["ciphertext_sha256"])):
                            raise StateError("Historical prepared asset is missing or changed; refusing repair")
                        self._reuse_part(ref, temporary, authenticated_prior, prior_metrics, fresh=True)
                        verified.add(_asset_identity(ref))
                        progress("publication_pending")
                    for ref in cold_prior:
                        self._reuse_part(ref, temporary, authenticated_prior, prior_metrics)
                    for number, ref in enumerate(dependencies):
                        target = temporary / f"dependency-{number}"
                        self._download_verified(ref, target)
                        target.unlink()
                    refreshed = set()
                    for number, asset in enumerate(pending):
                        ref = asset["ref"]
                        tag, name = ref["release_tag"], ref["name"]
                        self.transport.ensure_release(tag)
                        remote = find_asset(tag, name, refresh=tag not in refreshed)
                        refreshed.add(tag)
                        if remote is None:
                            try:
                                self.transport.upload_asset(tag, name, loaded.directory / asset["path"])
                                acknowledged_upload_bytes += ref["ciphertext_bytes"]
                            except Exception:
                                progress("upload_unacknowledged")
                                raise  # Retry SAME prepared bytes, never another UUID.
                        else:
                            if (remote.get("name") != name or remote.get("size") != ref["ciphertext_bytes"] or
                                    remote.get("digest") not in (None, "sha256:" + ref["ciphertext_sha256"])):
                                raise StateError("Existing prepared asset identity differs; refusing replacement")
                        target = temporary / f"asset-{number}"
                        self._download_verified(ref, target)
                        target.unlink()
                        verified.add(_asset_identity(ref))
                        progress("publication_pending")
                self._validate_prepared_root(value)
                # Every ciphertext asset and prerequisite has now been fetched
                # and verified. A durable callback may advertise remote closure
                # only at this point; earlier progress is a partial generation.
                progress("remote_prepared")
                _, current = self._authoritative_pointer()
                if current != old and current != desired:
                    raise StateConflictError("State pointer changed before prepared commit")
                head = self._advance(selection, value["pointer"], proof_outbox_node=(
                    canonical_json(value["proof_outbox_node"]) if value.get("proof_outbox_node") else None)
                    ) if current != desired else self.transport.branch_head()
                progress("complete", pointer_commit=head)
            else:
                budget_metrics = {}
                progress("complete", pointer_commit=head)
        report = dict(value["metrics"])
        request_total = getattr(self.transport, "request_count", 0)
        graphql_total = getattr(self.transport, "graphql_request_count", 0)
        report.update(budget_metrics)
        report.update(getattr(self.transport, "download_metrics", lambda: {})())
        report.update(status="already_committed" if already_committed else "complete", pointer_commit=head,
                      prepared_manifest_sha256=loaded.manifest_sha256,
                      source_import_sha256=loaded.source_import_sha256,
                      state_prepared_ciphertext_bytes=sum(asset["ref"]["ciphertext_bytes"] for asset in value["assets"]),
                      state_generation_new_ciphertext_bytes=value["metrics"].get("state_generation_new_ciphertext_bytes",
                          sum(asset["ref"]["ciphertext_bytes"] for asset in value["assets"])),
                      state_uploaded_ciphertext_bytes=0 if already_committed else value["metrics"].get(
                          "state_generation_new_ciphertext_bytes", sum(asset["ref"]["ciphertext_bytes"] for asset in value["assets"])),
                      state_upload_bytes_acknowledged_this_attempt=acknowledged_upload_bytes,
                      destination_github_api_requests_total=request_total,
                      destination_github_api_requests_for_publish=request_total - request_start,
                      destination_github_graphql_api_requests_total=graphql_total,
                      destination_github_graphql_api_requests_for_publish=graphql_total - graphql_start,
                      destination_github_rest_api_requests_total=request_total - graphql_total,
                      destination_github_rest_api_requests_for_publish=request_total - request_start - (graphql_total - graphql_start))
        return report

    def _advance(self, selection: StateSelection, pointer: dict, *, proof_outbox_node: bytes | None = None,
                 metadata_validator: Callable[[str | None, dict], None] | None = None) -> str:
        expected, old = selection.head, canonical_json(selection.pointer) if selection.pointer else None
        raw = canonical_json(pointer)
        for _ in range(8):
            binding = self._check_slug_binding(expected)
            current = self.transport.read_pointer(expected, self.repository_id) if expected else None
            if binding is not None and current is None:
                raise StateConflictError("Repository slug binding exists but its state pointer is missing")
            if current != old:
                raise StateConflictError("Selected repository state pointer changed")
            if metadata_validator is not None:
                metadata_validator(expected, selection.pointer)
            commit = (self.transport.commit_pointer(expected, self.repository_id, raw, proof_outbox_node=proof_outbox_node)
                      if proof_outbox_node is not None else self.transport.commit_pointer(expected, self.repository_id, raw))
            try:
                advanced = self.transport.advance_branch(expected, commit)
            except StateDeferredError:
                raise
            except Exception:
                # A network error after a successful Git update is ambiguous.
                # The exact pointer identity resolves it without a force push.
                advanced = False
            if advanced:
                return commit
            head = self.transport.branch_head()
            actual = self.transport.read_pointer(head, self.repository_id) if head else None
            if actual == raw:
                if metadata_validator is not None:
                    metadata_validator(head, pointer)
                return head
            if actual != old:
                raise StateConflictError("Selected repository state pointer changed concurrently")
            expected = head  # Other repository only: preserve its new tree.
        raise StateConflictError("Too many concurrent state branch updates")
