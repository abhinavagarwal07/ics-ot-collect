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

SCHEMA_VERSION = 1
BRANCH = "collector-state"
MAX_PART_BYTES = 1024 ** 3
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"[0-9a-f]{32}\Z")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


class StateError(RuntimeError):
    """Invalid, corrupt, incompatible, or concurrently changed working state."""


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


@dataclass(frozen=True)
class StateSelection:
    head: str | None
    pointer: dict[str, Any] | None
    index: dict[str, Any] | None


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
                 clock: Callable[[], float] = time.time):
        if not REPO_RE.fullmatch(destination_repository):
            raise ValueError("Invalid destination repository")
        if type(rate_reserve) is not int or rate_reserve < 0 or not 0 <= transient_retries <= 2:
            raise ValueError("Invalid bounded GitHub transport retry/reserve policy")
        self.repository, self.runner = destination_repository, runner
        self.rate_reserve, self.transient_retries, self.clock = rate_reserve, transient_retries, clock
        self.request_count = 0
        self.rate_remaining: int | None = None
        self.rate_reset: float | None = None
        self.retry_not_before: float | None = None
        self._releases: dict[str, dict] = {}
        self._assets: dict[str, dict[str, dict]] = {}
        self._listed: set[str] = set()
        self._git_files: dict[tuple[str, str], bytes | None] = {}

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
        return StateDeferredError("GitHub state publication deferred: " + reason,
                                  retry_not_before=retry, reason=reason, request_count=self.request_count)

    def _guard_rate(self) -> None:
        now = self.clock()
        if self.retry_not_before is not None and now < self.retry_not_before:
            raise self._defer("destination Retry-After has not elapsed", self.retry_not_before)
        if (self.rate_remaining is not None and self.rate_remaining <= self.rate_reserve and
                (self.rate_reset is None or now < self.rate_reset)):
            raise self._defer("destination primary API reserve reached", self.rate_reset)

    def _run(self, args: list[str], *, data: bytes | None = None,
             stdout: Any = subprocess.PIPE, missing_ok: bool = False) -> Any:
        is_get = "--method" not in args or args[args.index("--method") + 1] == "GET"
        capture_headers = stdout == subprocess.PIPE
        command = ["gh", *args, *(["--include"] if capture_headers else [])]
        for attempt in range(self.transient_retries + 1):
            self._guard_rate()
            self.request_count += 1
            if self.rate_remaining is not None:
                self.rate_remaining = max(0, self.rate_remaining - 1)
            result = self.runner(command, input=data, stdout=stdout, stderr=subprocess.PIPE, check=False)
            raw = result.stdout or b""
            headers, body, status = self._response(raw) if capture_headers else ({}, raw, None)
            for name, attribute, parser in (("x-ratelimit-remaining", "rate_remaining", int),
                                            ("x-ratelimit-reset", "rate_reset", float)):
                if name in headers:
                    try:
                        setattr(self, attribute, parser(headers[name]))
                    except ValueError:
                        pass
            if not result.returncode:
                return body if capture_headers else result.stdout
            error = result.stderr.decode("utf-8", "replace") if result.stderr else ""
            if missing_ok and (status == 404 or "HTTP 404" in error):
                return None
            combined = (body.decode("utf-8", "replace") if capture_headers else "") + error
            retry = None
            if "retry-after" in headers:
                try:
                    retry = self.clock() + max(0, float(headers["retry-after"]))
                except ValueError:
                    from email.utils import parsedate_to_datetime
                    try:
                        retry = parsedate_to_datetime(headers["retry-after"]).timestamp()
                    except (ValueError, TypeError, OverflowError):
                        pass
            rate_failure = (status == 429 or "HTTP 429" in error or
                            "rate limit" in combined.lower() or "secondary rate" in combined.lower() or
                            status == 403 and self.rate_remaining == 0 or retry is not None)
            if rate_failure:
                if retry is None and self.rate_remaining == 0:
                    retry = self.rate_reset
                self.retry_not_before = retry
                raise self._defer("destination API rate limit", retry)
            transient = (status in (502, 503, 504) or any(text in error.lower() for text in
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
        return json.loads(raw) if raw else None

    def publication_budget(self, required_requests: int) -> dict:
        """Measure this runner's destination-token bucket before any state upload."""
        measured = self._api("rate_limit")
        core = measured.get("resources", {}).get("core", {})
        if (type(core.get("remaining")) is not int or
                not isinstance(core.get("reset"), (int, float))):
            raise StateError("Destination token rate headroom could not be measured")
        self.rate_remaining, self.rate_reset = core["remaining"], float(core["reset"])
        if required_requests > max(0, self.rate_remaining - self.rate_reserve):
            raise self._defer(f"destination headroom {self.rate_remaining} is below estimated "
                              f"{required_requests} requests plus reserve {self.rate_reserve}", self.rate_reset)
        return {"destination_github_rate_remaining_before_state_upload": self.rate_remaining,
                "destination_github_required_requests_estimate": required_requests,
                "destination_github_rate_reserve": self.rate_reserve,
                "destination_github_rate_reset": self.rate_reset}

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

    def commit_pointer(self, parent: str | None, repository_id: int, data: bytes) -> str:
        import base64
        pointer = _json(data, "Git state pointer")
        slug = pointer.get("slug")
        if not isinstance(slug, str) or not REPO_RE.fullmatch(slug):
            raise StateError("Invalid pointer slug")
        binding = _slug_binding(slug, repository_id)
        previous_binding = self.read_slug_binding(parent, slug) if parent else None
        if previous_binding is not None and previous_binding != canonical_json(binding):
            raise StateConflictError("Repository slug is already bound to another numeric ID")
        blob = self._api(f"repos/{self.repository}/git/blobs", method="POST",
                         payload={"content": base64.b64encode(data).decode(), "encoding": "base64"})
        binding_blob = self._api(f"repos/{self.repository}/git/blobs", method="POST", payload={
            "content": base64.b64encode(canonical_json(binding)).decode(), "encoding": "base64"})
        tree_payload = {"tree": [{"path": f"repos/{repository_id}.json", "mode": "100644",
                                   "type": "blob", "sha": blob["sha"]},
                                  {"path": _slug_path(slug), "mode": "100644",
                                   "type": "blob", "sha": binding_blob["sha"]}]}
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

    def _release(self, tag: str, *, create: bool = False) -> dict:
        if not _ASSET.fullmatch(tag):
            raise StateError("Invalid state release tag")
        if tag in self._releases:
            return self._releases[tag]
        release = self._api(f"repos/{self.repository}/releases/tags/{tag}", missing_ok=create)
        new = release is None
        if new:
            release = self._api(f"repos/{self.repository}/releases", method="POST", payload={
                "tag_name": tag, "prerelease": True, "name": tag,
                "body": "Encrypted collector working state; retain prerequisites."})
        if not isinstance(release, dict) or type(release.get("id")) is not int:
            raise StateError("Invalid GitHub release metadata")
        self._releases[tag] = release
        self._assets[tag] = {asset["name"]: asset for asset in release.get("assets", [])}
        if new:
            self._listed.add(tag)
        return release

    def ensure_release(self, tag: str) -> None:
        self._release(tag, create=True)

    def upload_asset(self, tag: str, name: str, source: Path) -> None:
        _asset_ref({"release_tag": tag, "name": name, "ciphertext_sha256": "0" * 64,
                    "ciphertext_bytes": 1})
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

    def _asset(self, tag: str, name: str) -> dict:
        release = self._release(tag)
        if name in self._assets[tag]:
            return self._assets[tag][name]
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
        if not asset or type(asset.get("id")) is not int:
            raise StateError("Immutable state asset is missing or ambiguous")
        return asset

    def download_asset(self, tag: str, name: str, destination: Path) -> None:
        _asset_ref({"release_tag": tag, "name": name, "ciphertext_sha256": "0" * 64,
                    "ciphertext_bytes": 1})
        asset = self._asset(tag, name)
        try:
            with destination.open("xb") as target:
                os.chmod(destination, 0o600)
                self._run(["api", f"repos/{self.repository}/releases/assets/{asset['id']}",
                           "--method", "GET", "-H", "Accept: application/octet-stream"], stdout=target)
        except Exception:
            destination.unlink(missing_ok=True)
            raise


class GitHubStateStore:
    def __init__(self, transport: StateTransport, *, repository_id: int, slug: str,
                 public_key: Path | str, private_key: Path | str | None = None,
                 logical_root: Path | str | None = None, part_bytes: int = MAX_PART_BYTES,
                 mutable_group_bytes: int = 64 * 1024 * 1024,
                 max_assets_per_release: int = 900):
        if type(repository_id) is not int or repository_id < 1 or not REPO_RE.fullmatch(slug):
            raise ValueError("Selected positive repository ID and slug required")
        if not 10240 <= part_bytes <= MAX_PART_BYTES:
            raise ValueError("State plaintext parts must be between 10 KiB and 1 GiB")
        if type(max_assets_per_release) is not int or not 2 <= max_assets_per_release <= 1000:
            raise ValueError("State release asset limit must be between 2 and 1000")
        self.max_assets_per_release = max_assets_per_release
        self.transport, self.repository_id, self.slug = transport, repository_id, slug
        self.root = Path(logical_root or f"/tmp/icsot-persistent-state/{repository_id}").resolve()
        self.public_key = Path(public_key).resolve()
        self.private_key = Path(private_key).resolve() if private_key else None
        if self.private_key and self.private_key.is_relative_to(self.root):
            raise ValueError("Working-state private key must be outside the captured root")
        self.recipient = public_key_fingerprint(self.public_key)
        self.part_bytes = part_bytes
        self.group_bytes = min(mutable_group_bytes, part_bytes - 10240)
        if self.group_bytes < 1:
            self.group_bytes = 1
        self._verified_parts: set[bytes] = set()

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

    def _check_index(self, pointer: dict, index: dict) -> None:
        self._check_pointer(pointer)
        raw_index = canonical_json(index)
        if (hashlib.sha256(raw_index).hexdigest() != pointer["index"]["plaintext_sha256"] or
                len(raw_index) != pointer["index"]["plaintext_bytes"]):
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
        self.transport.download_asset(ref["release_tag"], ref["name"], target)
        if target.stat().st_size != ref["ciphertext_bytes"] or _digest(target) != ref["ciphertext_sha256"]:
            raise StateError("Remote immutable asset hash/size differs")

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
                with lzma.open(plaintext, "rb") as source, decoded.open("xb") as output:
                    copied = 0
                    while chunk := source.read(min(4 * 1024 * 1024, ref["decoded_bytes"] - copied + 1)):
                        copied += len(chunk)
                        if copied > ref["decoded_bytes"]:
                            raise StateError("Decoded state part exceeds authenticated size")
                        output.write(chunk)
                target = decoded
            except (lzma.LZMAError, EOFError) as exc:
                raise StateError("Invalid XZ working-state part") from exc
        if target.stat().st_size != ref["decoded_bytes"] or _digest(target) != ref["decoded_sha256"]:
            raise StateError("Decoded state part hash/size differs")
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
            index = _json(plaintext.read_bytes(), "encrypted state index")
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
            for part_id, ref in index["parts"].items():
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
                if target.stat().st_size != item["bytes"] or _digest(target) != item["sha256"]:
                    raise StateError("Restored state file hash/size differs")
                os.chmod(target, item["mode"])
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

    @staticmethod
    def _preflight_disk(*, directory: Path, required: int, operation: str) -> None:
        free = shutil.disk_usage(directory).free
        if free < required:
            raise StateError(f"Insufficient disk for {operation}: need approximately {required} free bytes; "
                             f"{free} available. Select a smaller repository or use a larger runner.")

    def _require_empty_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if any(child.name != ".collector.lock" for child in self.root.iterdir()):
            raise StateError("Restore requires an empty state root except the controller lock")

    @staticmethod
    def _extract_group(plain: Path, staging: Path, expected: dict[str, dict]) -> None:
        seen = set()
        try:
            with tarfile.open(plain, "r:") as archive:
                for member in archive:
                    name = _safe_path(member.name)
                    if not member.isfile() or name not in expected or name in seen:
                        raise StateError("Unsafe, duplicate, or unlisted state archive member")
                    if member.size != expected[name]["bytes"]:
                        raise StateError("State archive member size differs")
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

    @staticmethod
    def _excluded(path: str) -> bool:
        pieces = path.split("/")
        return (pieces[-1].endswith((".lock", "-wal", "-shm")) or
                any(piece.startswith((".icsot-", ".capture-export-")) for piece in pieces) or
                "icsot-verified-archive.git" in pieces)

    def _snapshot_files(self, staging: Path) -> list[dict]:
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
            else:
                shutil.copyfile(source, target)
            os.chmod(target, 0o600)
            digest = _digest(target)
            if name.startswith("objects/sha256/") and source.name != digest:
                raise StateError("Working-state CAS filename/hash differs")
            files.append({"path": name, "bytes": target.stat().st_size, "sha256": digest,
                          "mode": 0o700 if info.st_mode & 0o111 else 0o600})
        return files

    def _part(self, plaintext: Path, kind: str, release: str, prior: dict, directory: Path,
              parts: dict, metrics: dict, *, compress: bool = True) -> str:
        decoded_sha256, decoded_bytes = _digest(plaintext), plaintext.stat().st_size
        existing = prior.get((decoded_sha256, decoded_bytes, kind))
        if existing:
            digest = existing["plaintext_sha256"]
            if digest in parts:
                return digest
            # Reuse the original ciphertext identity, never fresh encryption for
            # unchanged CAS/packs. Restore already checked both hashes; callers
            # that skipped restore pay this verification once before reuse.
            if _asset_identity(existing) not in self._verified_parts:
                encrypted, plain = directory / (digest + ".verify.enc"), directory / (digest + ".verify")
                self._download_verified(existing, encrypted)
                self._decrypt(existing, encrypted, plain)
                decoded = self._decode_part(existing, plain, directory / (digest + ".verify.decoded"))
                self._verified_parts.add(_asset_identity(existing))
                encrypted.unlink()
                if decoded != plain:
                    decoded.unlink()
                plain.unlink()
            parts[digest] = dict(existing)
            metrics["reused_parts"] += 1
            return digest
        encoding = "raw"
        if compress:
            compressed = directory / ("encoded-" + uuid.uuid4().hex + ".xz")
            with plaintext.open("rb") as source, lzma.open(compressed, "wb", preset=1) as output:
                shutil.copyfileobj(source, output, length=4 * 1024 * 1024)
            if compressed.stat().st_size <= self.part_bytes:
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
            self.transport.ensure_release(actual_release)
            metrics["_releases"].add(actual_release)
        metrics["_asset_count"] += 1
        ref = {**record, "release_tag": actual_release, "name": name, "kind": kind,
               "encoding": encoding, "decoded_sha256": decoded_sha256, "decoded_bytes": decoded_bytes}
        self.transport.upload_asset(actual_release, name, encrypted)
        verify = directory / (digest + ".remote")
        self._download_verified(ref, verify)
        verify.unlink()
        encrypted.unlink()
        self._verified_parts.add(_asset_identity(ref))
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

    def _publication_requests_estimate(self, files: list[dict], prior: dict) -> int:
        previous = {item["path"]: item for item in prior.get("files", [])}
        raw_parts = 0
        groups = 0
        group_size = 10240
        group_items = 0
        for item in files:
            if self._immutable(item["path"]) or item["bytes"] > self.group_bytes:
                old = previous.get(item["path"])
                chunk_count = max(1, (item["bytes"] + self.part_bytes - 1) // self.part_bytes)
                old_segments = old.get("segments", []) if old else []
                chunk_sizes = [min(self.part_bytes, max(0, item["bytes"] - offset * self.part_bytes))
                               for offset in range(chunk_count)]
                unchanged_chunks = (old and old["sha256"] == item["sha256"] and old["bytes"] == item["bytes"] and
                                    len(old_segments) == chunk_count and
                                    all(prior["parts"][segment["part"]]["kind"] == "raw" and
                                        prior["parts"][segment["part"]]["decoded_bytes"] == expected
                                        for segment, expected in zip(old_segments, chunk_sizes)))
                if unchanged_chunks:
                    continue  # Original plaintext chunks can reuse verified ciphertext.
                raw_parts += chunk_count
                continue
            required = ((item["bytes"] + 511) // 512) * 512 + 512 + 10240
            if group_items and group_size + required > self.part_bytes:
                groups += 1
                group_items, group_size = 0, 10240
            group_items += 1
            group_size += required
            if group_size >= self.group_bytes:
                groups += 1
                group_items, group_size = 0, 10240
        groups += bool(group_items)
        parts = raw_parts + groups  # Mutable groups conservatively all new.
        releases = max(1, (parts + self.max_assets_per_release - 2) // (self.max_assets_per_release - 1))
        unverified = [part for part in prior["parts"].values()
                      if _asset_identity(part) not in self._verified_parts]
        old_release_reads = 12 * len({part["release_tag"] for part in unverified}) + len(unverified)
        # Upload+verification per payload/index, release lookup+creation, and
        # generous fixed Git blob/tree/commit/CAS plus one-conflict headroom.
        return 2 * (parts + 1) + 2 * releases + 18 + old_release_reads

    def publish(self, selection: StateSelection, *, dependencies: list[dict] | tuple = (),
                code_hashes: dict | None = None, config_hashes: dict | None = None,
                lane_heads: dict | None = None, evidence_heads: dict | None = None,
                quiescent: bool = False) -> dict:
        request_start = getattr(self.transport, "request_count", 0)
        if not quiescent:
            raise StateError("Snapshot publication requires joined capture/finalizer callbacks")
        if selection.pointer is not None:
            if selection.index is None:
                raise StateError("Pointer without authenticated index")
            self._check_index(selection.pointer, selection.index)
        elif selection.index is not None:
            raise StateError("Index without authoritative pointer")
        prior = selection.index or {"parts": {}, "dependencies": []}
        generation = uuid.uuid4().hex
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
                                  min(source_bytes, self.group_bytes) + 10240 * (source_files + 1)))
            # Snapshot copy + current raw/tar + XZ + local/remote ciphertext.
            # Encryption envelope overhead is bounded by the codec's 64 KiB header.
            publish_peak = source_bytes + 4 * (largest_payload + 65536)
            self._preflight_disk(directory=directory, required=publish_peak,
                                 operation="publication snapshot and encrypted verification")
            staging = directory / "snapshot"
            staging.mkdir(mode=0o700)
            snapshot_started_at = utc_iso()
            files = self._snapshot_files(staging)
            estimate = self._publication_requests_estimate(files, prior)
            budget = getattr(self.transport, "publication_budget", None)
            if callable(budget):
                metrics.update(budget(estimate))
            metrics["publish_peak_additional_disk_bytes_estimate"] = publish_peak
            metrics["snapshot_staging_bytes"] = sum(item["bytes"] for item in files)
            parts = {}
            prior_parts = {(part["decoded_sha256"], part["decoded_bytes"], part["kind"]): part
                           for part in prior["parts"].values()}
            self.transport.ensure_release(release)
            metrics["_releases"].add(release)
            groups: list[list[dict]] = []
            group: list[dict] = []
            group_size = 10240
            for item in files:
                immutable = self._immutable(item["path"])
                if immutable or item["bytes"] > self.group_bytes:
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
                                                compress=not already_compressed)
                            item["segments"].append({"part": digest})
                            count = chunk.stat().st_size
                            chunk.unlink()
                            if count < self.part_bytes:
                                break
                else:
                    padded = ((item["bytes"] + 511) // 512) * 512 + 512
                    # PAX extended names require extra headers. Reserve a full
                    # 10 KiB per member and check the actual tar before upload.
                    required = padded + 10240
                    if group and group_size + required > self.part_bytes:
                        groups.append(group)
                        group, group_size = [], 10240
                    group.append(item)
                    group_size += required
                    if group_size >= self.group_bytes:
                        groups.append(group)
                        group, group_size = [], 10240
            if group:
                groups.append(group)
            for number, members in enumerate(groups):
                archive_path = directory / f"group-{number}.tar"
                with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
                    for item in members:
                        info = tarfile.TarInfo(item["path"])
                        info.size, info.mode, info.mtime = item["bytes"], item["mode"], 0
                        with (staging / item["path"]).open("rb") as source:
                            archive.addfile(info, source)
                if archive_path.stat().st_size > self.part_bytes:
                    raise StateError("Grouped snapshot exceeds plaintext part limit")
                part_id = self._part(archive_path, "tar", release, prior_parts, directory, parts, metrics)
                for item in members:
                    item["segments"] = [{"part": part_id, "member": item["path"]}]
                archive_path.unlink()
            snapshot_times = {"snapshot_started_at": snapshot_started_at, "snapshot_sealed_at": utc_iso(),
                              "clock_source": "runner_system_clock"}
            context = {**self._binding(generation, predecessor), **snapshot_times,
                       "recipient_spki_sha256": self.recipient,
                       "file_map_sha256": hashlib.sha256(canonical_json(files)).hexdigest(),
                       "dependencies_sha256": hashlib.sha256(canonical_json(all_dependencies)).hexdigest(),
                       "code_hashes": code_hashes or {}, "config_hashes": config_hashes or {},
                       "lane_heads": lane_heads or {}, "evidence_heads": evidence_heads or {}}
            index = {"context": context, "files": files, "parts": parts,
                     "dependencies": all_dependencies}
            plaintext, encrypted = directory / "index.json", directory / "index.enc"
            plaintext.write_bytes(canonical_json(index))
            if plaintext.stat().st_size > self.part_bytes:
                raise StateError("State index exceeds plaintext part limit")
            record = encrypt_file(plaintext, encrypted, self.public_key)
            ref = {**record, "release_tag": release, "name": "index.enc"}
            pointer = {**self._binding(generation, predecessor), **snapshot_times, "index": ref,
                       "context_sha256": hashlib.sha256(canonical_json(context)).hexdigest()}
            self._check_index(pointer, index)
            self.transport.upload_asset(release, ref["name"], encrypted)
            self._download_verified(ref, directory / "verified-index.enc")
            metrics["state_uploaded_ciphertext_bytes"] += ref["ciphertext_bytes"]
            commit = self._advance(selection, pointer)
        state_release_count = len(metrics.pop("_releases"))
        metrics.pop("_asset_count")
        request_total = getattr(self.transport, "request_count", 0)
        return {**metrics, "state_release_count": state_release_count,
                "destination_github_api_requests_total": request_total,
                "destination_github_api_requests_for_publish": request_total - request_start,
                "state_encoding": "per-part XZ by default; already compressed Git data stays raw",
                "generation": generation, "pointer_commit": commit,
                "index_sha256": ref["ciphertext_sha256"], "pointer": pointer,
                "state_referenced_ciphertext_bytes": sum(p["ciphertext_bytes"] for p in parts.values()) + ref["ciphertext_bytes"],
                "state_plaintext_bytes": sum(item["bytes"] for item in files)}

    def _advance(self, selection: StateSelection, pointer: dict) -> str:
        expected, old = selection.head, canonical_json(selection.pointer) if selection.pointer else None
        raw = canonical_json(pointer)
        for _ in range(8):
            binding = self._check_slug_binding(expected)
            current = self.transport.read_pointer(expected, self.repository_id) if expected else None
            if binding is not None and current is None:
                raise StateConflictError("Repository slug binding exists but its state pointer is missing")
            if current != old:
                raise StateConflictError("Selected repository state pointer changed")
            commit = self.transport.commit_pointer(expected, self.repository_id, raw)
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
                return head
            if actual != old:
                raise StateConflictError("Selected repository state pointer changed concurrently")
            expected = head  # Other repository only: preserve its new tree.
        raise StateConflictError("Too many concurrent state branch updates")
