"""Read-only projections for the local evidence viewer.

This module never calls a collector, mutates evidence, or writes GitHub state.
The public surface accepts registered identifiers, never browser-supplied paths.
Release metadata is cached in memory; encrypted payloads are opt-in and streamed
through the local disk guard and authenticated archive reader.
"""
from __future__ import annotations

import csv
import base64
import hashlib
import difflib
import io
import json
import os
import re
import selectors
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .core import canonical_json, sha256

HASH = re.compile(r"[0-9a-f]{64}\Z")
SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
CATEGORIES = ("issues", "pulls", "comments", "releases", "tags", "events", "git_refs", "raw_records")
METADATA_LIMIT = 10_000_000
JSON_LIMIT = 16 * 1024 * 1024
CAPTURE_MEMORY_LIMIT = 64 * 1024 * 1024
GIT_BUNDLE_LIMIT = 32 * 1024 * 1024
GIT_CACHE_LIMIT = 64 * 1024 * 1024
QUALIFICATION = ("Changes compare observed representations in the selected collection intervals. "
                 "Missing entities mean not observed in that query, never proven deletion. "
                 "Delta captures are overlapping query results, not full repository snapshots. "
                 "Events are opportunistic; collection is non-atomic and does not establish first publication.")


def _utc(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def _safe_path(root: Path, relative: str) -> Path:
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts or not part.parts:
        raise ValueError("Unsafe evidence path")
    path = root / part
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("Evidence symlinks are not followed")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Evidence path escapes its registered root")
    return path


def _read(path: Path, maximum: int = JSON_LIMIT, digest: str | None = None) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise ValueError("Evidence file is missing, unsafe, or exceeds the read bound")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum or (digest is not None and sha256(raw) != digest):
        raise ValueError("Evidence bytes differ from their registered size/hash")
    return raw


def _kind(purpose: str) -> str | None:
    if any(word in purpose for word in ("_first_page_recheck", "_resume_first_page_validation")):
        return None
    base = purpose.split(":", 1)[0]
    if base in ("issue_comments", "review_comments", "pull_review_comments", "pull_comments", "reviews", "pull_reviews"):
        return "comments"
    if base in ("issue_timeline", "timeline", "pull_events"):
        return "events"
    return base if base in CATEGORIES else None


def _identity(item: dict, purpose: str) -> str | None:
    # ID namespaces are typed: issue and review comments can have equal IDs.
    value = item.get("id", item.get("node_id"))
    if value is None and purpose.split(":")[0] == "tags":
        value = item.get("name")
    if value is None:
        value = item.get("sha")
    return str(value) if value is not None else None


def _text_excerpt(value: Any, maximum: int = 2000) -> str | None:
    if value is None:
        return None
    raw = str(value).encode("utf-8")
    return raw[:maximum].decode("utf-8", errors="ignore")


def _display_value(value: Any, maximum: int = 4000, _depth: int = 0) -> Any:
    """Keep useful JSON structure while bounding only its displayed values.

    Hashing/change detection always uses the complete original representation.
    A missing preview key is explicitly qualified, never evidence of absence.
    """
    raw = canonical_json(value)
    if len(raw) <= maximum:
        return value
    if isinstance(value, str):
        suffix = " … [display truncated]"
        # JSON escaping can be larger than the UTF-8 source string.
        kept = value.encode("utf-8")[:max(0, maximum - 64)].decode("utf-8", errors="ignore")
        while kept and len(canonical_json(kept + suffix)) > maximum:
            kept = kept[:len(kept) * 3 // 4]
        return kept + suffix
    if isinstance(value, list):
        result = []
        for entry in value[:12]:
            candidate = _display_value(entry, max(64, min(400, maximum // 3)), _depth + 1)
            marker = {"_viewer_omitted_items": len(value) - len(result) - 1}
            if len(canonical_json([*result, candidate, marker])) > maximum:
                break
            result.append(candidate)
        if len(result) < len(value):
            result.append({"_viewer_omitted_items": len(value) - len(result)})
        return result
    if isinstance(value, dict) and _depth < 4:
        important = ("id", "number", "title", "state", "body", "labels", "login", "name", "sha", "ref",
                     "tag_name", "type", "created_at", "updated_at", "closed_at", "published_at", "user",
                     "assignee", "assignees", "html_url", "url", "comments", "locked", "draft")
        ordered = [name for name in important if name in value]
        ordered.extend(name for name in value if name not in ordered)
        result, truncated = {}, []
        def envelope():
            return {"_viewer_preview": {"truncated": True, "original_json_bytes": len(raw),
                    "omitted_key_count": len(value) - len(result), "truncated_keys": truncated[:8]}}
        for name in ordered:
            if len(str(name).encode("utf-8")) > 256:
                continue
            cap = min(1600, maximum // 2) if name == "body" else min(800, maximum // 3) if name in ("labels", "assignees") else min(400, maximum // 4)
            candidate = _display_value(value[name], max(64, cap), _depth + 1)
            changed = candidate != value[name]
            result[name] = candidate
            if changed:
                truncated.append(name)
            if len(canonical_json({**result, **envelope()})) > maximum:
                del result[name]
                if changed:
                    truncated.pop()
        return {**result, **envelope()}
    return {"_viewer_omitted": True, "original_json_bytes": len(raw)}


def _proof(source: dict, local_receipt: bool = False) -> dict:
    result: dict[str, Any] = {"checked_by_viewer": False,
        "qualification": "Archived verifier statements; this viewer does not independently verify timestamp cryptography."}
    evidence = source.get("timestamp_evidence") or {}
    for name in ("opentimestamps", "rfc3161"):
        entry = evidence.get(name) or {}
        metadata = entry.get("metadata", entry)
        status = metadata.get("status")
        if not status and name == "opentimestamps":
            status = (source.get("collector_result") or {}).get("attestation")
        if not status:
            status = "receipt_present_unverified" if name == "opentimestamps" and local_receipt else "not_recorded"
        result[name] = {"status": status, "verification": metadata.get("verification"),
                        "tsa_generation_time": metadata.get("tsa_generation_time"),
                        "bitcoin_block_heights": metadata.get("bitcoin_block_heights"),
                        "metadata_sha256": (entry.get("metadata_asset") or {}).get("sha256")}
    return result


class MetadataError(ValueError):
    pass


class GitHubMetadata:
    """Bounded, GET-only gh transport; no token is read or returned to callers."""

    def __init__(self, repository: str, maximum_bytes: int = METADATA_LIMIT):
        if not SLUG.fullmatch(repository):
            raise ValueError("Invalid release repository")
        self.repository = repository
        self.maximum_bytes = maximum_bytes
        self.bytes_read = 0
        self.request_count = 0
        self.request_limit = 200
        self.cache: dict[str, Any] = {}
        self._asset_identities: dict[str, tuple[str, int]] = {}
        self._transport_lock = threading.RLock()

    def _bytes(self, endpoint: str, maximum: int, *, raw: bool = False) -> bytes:
        with self._transport_lock:
            return self._transfer_bytes(endpoint, maximum, raw=raw)

    def _transfer_bytes(self, endpoint: str, maximum: int, *, raw: bool = False) -> bytes:
        # All endpoints are constructed internally; no caller-controlled URLs.
        if endpoint != "rate_limit" and not endpoint.startswith(f"repos/{self.repository}/"):
            raise MetadataError("Metadata endpoint is outside the configured source repository")
        if self.request_count >= self.request_limit:
            raise MetadataError("Session metadata request limit reached")
        remaining = min(maximum, self.maximum_bytes - self.bytes_read)
        if remaining <= 0:
            raise MetadataError("Session metadata limit reached; remaining coverage is unknown")
        self.request_count += 1
        command = ["gh", "api", "--method", "GET", endpoint]
        if raw:
            command.extend(["-H", "Accept: application/octet-stream"])
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert process.stdout is not None
        output = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 45
        try:
            while True:
                wait = deadline - time.monotonic()
                if wait <= 0 or not selector.select(min(wait, 1)):
                    if wait <= 0:
                        raise MetadataError("GitHub metadata request timed out")
                    continue
                chunk = os.read(process.stdout.fileno(), min(65536, remaining + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                self.bytes_read += len(chunk)
                if len(output) > remaining:
                    raise MetadataError("GitHub metadata exceeds the session/per-file bound")
            if process.wait(timeout=5) != 0:
                raise MetadataError("GitHub metadata unavailable; check the existing gh authentication")
            return bytes(output)
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

    def json(self, endpoint: str, *, maximum: int = JSON_LIMIT) -> Any:
        with self._transport_lock:
            if endpoint not in self.cache:
                self.cache[endpoint] = json.loads(self._bytes(endpoint, maximum))
            return self.cache[endpoint]

    def availability(self) -> dict:
        """Read the dedicated quota endpoint before spending core requests."""
        value = self.json("rate_limit", maximum=100_000)
        return (value.get("resources") or {}).get("core") or {}

    def clear_mutable(self):
        # Immutable asset bytes stay cached and retain their hash identity.
        with self._transport_lock:
            self.cache = {key: value for key, value in self.cache.items() if key.startswith("asset:")}

    def asset(self, asset: dict, expected: str | None = None) -> dict:
        with self._transport_lock:
            return self._cached_asset(asset, expected)

    def _cached_asset(self, asset: dict, expected: str | None = None) -> dict:
        asset_id, size = asset.get("id"), asset.get("size")
        if type(asset_id) is not int or type(size) is not int or not 0 < size <= METADATA_LIMIT:
            raise MetadataError("Invalid metadata asset identity/size")
        claims = []
        if expected is not None:
            if not isinstance(expected, str) or not HASH.fullmatch(expected):
                raise MetadataError("Invalid expected metadata SHA-256")
            claims.append(expected)
        declared = asset.get("digest")
        if declared not in (None, ""):
            if not isinstance(declared, str) or not declared.startswith("sha256:") or not HASH.fullmatch(declared[7:]):
                raise MetadataError("Invalid declared metadata SHA-256")
            claims.append(declared[7:])
        if not claims:
            raise MetadataError("Metadata asset is missing a SHA-256 identity")
        key = f"asset:{asset_id}"
        if key not in self.cache:
            raw = self._bytes(f"repos/{self.repository}/releases/assets/{asset_id}", size, raw=True)
            observed = (sha256(raw), len(raw))
            if observed[1] != size or any(claim != observed[0] for claim in claims):
                raise MetadataError("Metadata asset length/SHA-256 mismatch or missing digest")
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise MetadataError("Metadata asset must contain a JSON object")
            self.cache[key] = obj
            self._asset_identities[key] = observed
        else:
            # JSON reserialization is not the original-byte identity. A fresh
            # remote claim cannot rebind an old cached historical JSON object.
            observed = self._asset_identities.get(key)
            if observed is None or observed[1] != size or any(claim != observed[0] for claim in claims):
                raise MetadataError("Conflicting cached metadata identity")
        return self.cache[key]


class ViewerData:
    def __init__(self, workspace: Path, roots: Iterable[Path] | None = None, *,
                 loader=None, budget=None, private_key_path: Path | None = None,
                 offline: bool = False, release_repository: str = "abhinavagarwal07/ics-ot-collect",
                 metadata=None, git_volume_factory=None, git_runner_factory=None):
        self.workspace = Path(workspace).resolve()
        if not (self.workspace / "public_patch_corpus_185.csv").is_file() and (self.workspace.parent / "public_patch_corpus_185.csv").is_file():
            self.workspace = self.workspace.parent
        self.private_key_path = Path(private_key_path).resolve() if private_key_path else None
        self.loader, self.budget = loader, budget
        self.offline = offline
        self.remote = metadata or GitHubMetadata(release_repository)
        self.release_repository = release_repository
        self.gaps: list[dict] = []
        self._repos: dict[str, dict] = {}
        self._by_slug: dict[str, str] = {}
        self._captures: dict[str, dict] = {}
        self._releases: dict[str, dict] = {}
        self._remote_done = False
        self._remote_attempted = False
        self._repo_remote_done: set[str] = set()
        self._repo_remote_attempted: set[str] = set()
        self._metadata_state = "offline" if offline else "not_attempted"
        self._metadata_attempts = 0
        self._metadata_retry_at: float | None = None
        self._metadata_last_error: str | None = None
        self._metadata_last_attempt_at: str | None = None
        self._metadata_last_success_at: str | None = None
        self._lock = threading.RLock()
        self._load_lock = threading.Lock()
        self._objects: dict[str, bytes] = {}
        self._manifests: dict[str, bytes] = {}
        self._memory_bytes = 0
        self._bundle_cache: dict[str, tuple[Path, int]] = {}
        self._git_volume_factory, self._git_runner_factory = git_volume_factory, git_runner_factory
        self._proof_head: str | None = None
        self._proof_head_checked = False
        self._proof_checked: set[str] = set()
        self._load_csv()
        if roots is None:
            evidence = self.workspace / "evidence"
            roots = sorted({p.parent.resolve() for p in evidence.rglob("runs")
                            if p.is_dir() and not p.is_symlink()}) if evidence.exists() else []
            if (self.workspace / "runs").is_dir():
                roots = [*roots, self.workspace]
        self.roots = tuple(dict.fromkeys(Path(root).resolve() for root in roots))
        for root in self.roots:
            self._index_root(root)

    def _gap(self, reason: str, **fields):
        gap = {"reason": reason, **fields}
        if gap not in self.gaps:
            self.gaps.append(gap)

    @staticmethod
    def _record_attempt(repo: dict, attempt: dict):
        if attempt not in repo["attempts"]:
            repo["attempts"].append(attempt)

    def _metadata_status(self) -> dict:
        bytes_read = getattr(self.remote, "bytes_read", 0)
        byte_limit = getattr(self.remote, "maximum_bytes", METADATA_LIMIT)
        request_count = getattr(self.remote, "request_count", 0)
        request_limit = getattr(self.remote, "request_limit", 200)
        retry_allowed = (not self.offline and self._metadata_attempts < 5 and bytes_read < byte_limit
                         and request_count < request_limit
                         and (self._metadata_retry_at is None or time.time() >= self._metadata_retry_at))
        return {"state": self._metadata_state, "last_error": self._metadata_last_error,
            "retry_at": datetime.fromtimestamp(self._metadata_retry_at, timezone.utc).isoformat().replace("+00:00", "Z") if self._metadata_retry_at else None,
            "retry_allowed": retry_allowed, "attempts": self._metadata_attempts, "max_attempts": 5,
            "bytes_read": bytes_read, "byte_limit": byte_limit, "request_count": request_count,
            "request_limit": request_limit, "last_attempt_at": self._metadata_last_attempt_at,
            "last_success_at": self._metadata_last_success_at,
            "qualification": "Local and previously verified metadata remain available; an unavailable remote catalog does not establish zero captures."}

    def _prepare_metadata_refresh(self):
        if not self._metadata_status()["retry_allowed"]:
            return
        if hasattr(self.remote, "clear_mutable"):
            self.remote.clear_mutable()
        self._remote_done = self._remote_attempted = False
        self._repo_remote_done.clear()
        self._repo_remote_attempted.clear()
        self._proof_head_checked = False
        self._proof_checked.clear()
        transient = {"remote_metadata_unavailable", "release_catalog_unavailable", "repository_index_unavailable"}
        self.gaps[:] = [gap for gap in self.gaps if gap.get("reason") not in transient]

    def _repo_discovery(self, repo: dict) -> dict:
        if self.offline:
            return {"state": "offline", "availability_known": False}
        if not self._remote_done:
            return {"state": "partial" if self._releases else "unknown", "availability_known": False}
        if repo["key"] in self._repo_remote_done or not self._repo_descriptor_count(repo):
            return {"state": "complete", "availability_known": True}
        return {"state": "partial" if repo["key"] in self._repo_remote_attempted else "not_read",
                "availability_known": False}

    def _repo_descriptor_count(self, repo: dict) -> int:
        descriptors = list(repo["index_assets"])
        descriptors.extend(self._captures[key]["remote"] for key in repo["captures"] if self._captures[key].get("remote"))
        return len({(item.get("release_tag"), item.get("name")) for item in descriptors})

    def _repository(self, slug: str, repository_id: int | None = None, row: dict | None = None) -> dict:
        if not isinstance(slug, str) or not SLUG.fullmatch(slug):
            raise ValueError("Invalid repository identity")
        lower = slug.lower()
        key = self._by_slug.get(lower) or "r-" + sha256(lower.encode())[:20]
        if key not in self._repos:
            row = row or {}
            self._repos[key] = {"key": key, "id": key, "name": slug, "slug": slug,
                "repository_id": repository_id, "cohort": row.get("Cohort"), "cohort_id": row.get("ID"),
                "role": row.get("Repository_Role", "validation_capture"),
                "measurement_caveat": row.get("Measurement_Caveat") or None,
                "authoritative_source": row.get("Authoritative_Source") or None,
                "captures": [], "attempts": [], "index_assets": []}
            self._by_slug[lower] = key
        repo = self._repos[key]
        if repository_id is not None:
            if type(repository_id) is not int or repository_id <= 0:
                raise ValueError("Invalid numeric repository ID")
            if repo["repository_id"] not in (None, repository_id):
                raise ValueError("Repository slug is bound to conflicting numeric identities")
            repo["repository_id"] = repository_id
        return repo

    def _load_csv(self):
        path = self.workspace / "public_patch_corpus_185.csv"
        self.csv_sha256 = None
        if path.is_file() and not path.is_symlink():
            raw = _read(path, METADATA_LIMIT)
            self.csv_sha256 = sha256(raw)
            for row in csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))):
                url = row.get("Repository_URL", "")
                slug = url.removeprefix("https://github.com/").rstrip("/")
                if SLUG.fullmatch(slug):
                    self._repository(slug, row=row)

    def _add_capture(self, repo: dict, summary: dict, *, manifest=None, root=None,
                     path=None, remote=None, source=None) -> dict:
        digest = summary.get("sha256") or summary.get("manifest_sha256")
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError("Capture requires immutable manifest SHA-256 identity")
        key = "c-" + digest
        existing = self._captures.get(key)
        if existing:
            if existing["repo_key"] != repo["key"]:
                raise ValueError("One manifest digest is bound to different repositories")
            if remote is not None:
                existing["remote"] = {**(existing.get("remote") or {}), **remote}
            for field in ("run_id", "capture_id", "mode"):
                if existing.get(field) is None and summary.get(field) is not None:
                    existing[field] = summary[field]
            for field, names in (("started_at", ("started_at", "observation_started_at")),
                                 ("completed_at", ("finished_at", "observation_finished_at"))):
                if existing["interval"][field] is None:
                    existing["interval"][field] = _utc(summary.get(names[0], summary.get(names[1])))
            existing["captured_at"] = existing["interval"]["completed_at"] or existing["interval"]["started_at"]
            if source and source.get("timestamp_evidence"):
                existing["proof"] = _proof(source)
            return existing
        lane = summary.get("lane") or (manifest or {}).get("lane") or "combined"
        status = summary.get("status") or "coverage_unknown"
        capture = {"key": key, "id": key, "repo_key": repo["key"], "run_id": summary.get("run_id"),
            "capture_id": summary.get("capture_id"), "lane": lane, "kind": lane,
            "mode": summary.get("mode"), "status": status, "manifest_sha256": digest,
            "interval": {"started_at": _utc(summary.get("started_at", summary.get("observation_started_at"))),
                         "completed_at": _utc(summary.get("finished_at", summary.get("observation_finished_at")))},
            "load_state": "loaded" if manifest is not None else "metadata_only",
            "coverage": (manifest or {}).get("api") or {}, "proof": _proof(source or {},
                bool(path and Path(str(path) + ".ots").is_file())),
            "gaps": list((manifest or {}).get("failures") or []),
            "source": source or {}, "manifest": manifest, "root": root, "path": path,
            "remote": remote, "progress": {"phase": "idle"}}
        capture["captured_at"] = capture["interval"]["completed_at"] or capture["interval"]["started_at"]
        if manifest is None:
            capture["gaps"].append("Encrypted contents have not been loaded; entity counts and coverage remain unknown.")
        self._captures[key] = capture
        repo["captures"].append(key)
        return capture

    def _index_root(self, root: Path):
        if not root.is_dir() or root.is_symlink():
            self._gap("invalid_local_root")
            return
        for path in sorted((root / "runs").glob("*/*.manifest.json")):
            try:
                path = _safe_path(root, path.relative_to(root).as_posix())
                raw = _read(path)
                manifest = json.loads(raw)
                if not isinstance(manifest, dict):
                    raise ValueError("Manifest is not an object")
                rid, run = manifest.get("repository_id"), manifest.get("run_id")
                if str(rid) != path.parent.name or path.name != str(run) + ".manifest.json":
                    raise ValueError("Manifest path/identity mismatch")
                repo = self._repository(manifest.get("repository_input_slug"), rid)
                summary = {**manifest, "sha256": sha256(raw)}
                self._add_capture(repo, summary, manifest=manifest, root=root, path=path)
            except (OSError, ValueError, TypeError) as error:
                self._gap("invalid_local_manifest", file=path.name, detail=type(error).__name__)

    def _discover_remote(self):
        if self._remote_done or self._remote_attempted or self.offline:
            return
        self._remote_attempted = True
        self._metadata_attempts += 1
        self._metadata_state = "loading"
        self._metadata_last_error = None
        self._metadata_last_attempt_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        complete = True
        try:
            if hasattr(self.remote, "availability"):
                core = self.remote.availability()
                if core.get("remaining") == 0:
                    reset = core.get("reset")
                    self._metadata_retry_at = max(time.time() + 1, reset if isinstance(reset, (int, float)) else time.time() + 60)
                    self._metadata_state = "rate_limited"
                    self._metadata_last_error = "GitHub core API quota is exhausted; remote capture availability is unknown until an explicit retry after reset"
                    self._gap("remote_metadata_unavailable", detail=self._metadata_last_error)
                    return
            for page in range(1, 11):
                releases = self.remote.json(f"repos/{self.release_repository}/releases?per_page=100&page={page}")
                if not isinstance(releases, list):
                    raise MetadataError("Release listing is not a list")
                for release in releases:
                    tag = release.get("tag_name", "")
                    if not tag.startswith(("corpus-baseline-", "collector-observations-")):
                        continue
                    if not SAFE.fullmatch(tag) or type(release.get("id")) is not int:
                        raise MetadataError("Unsafe release identity")
                    # Fetch paginated assets explicitly; embedded release assets
                    # are not a pagination/completeness guarantee.
                    assets = {}
                    for asset_page in range(1, 31):
                        rows = self.remote.json(f"repos/{self.release_repository}/releases/{release['id']}/assets?per_page=100&page={asset_page}")
                        if not isinstance(rows, list):
                            raise MetadataError("Asset listing is not a list")
                        for asset in rows:
                            name = asset.get("name", "")
                            if SAFE.fullmatch(name):
                                if name in assets and assets[name]["id"] != asset["id"]:
                                    raise MetadataError("Conflicting immutable asset names")
                                assets[name] = asset
                        if len(rows) < 100:
                            break
                    else:
                        complete = False
                        self._gap("release_asset_page_cap", release=tag)
                    self._releases[tag] = {"tag": tag, "id": release["id"], "assets": assets,
                        "published_at": release.get("published_at")}
                    for name, handler in (("baseline-inventory.json", self._inventory),
                                          ("metadata-catalog.json", self._native_catalog)):
                        if name in assets:
                            try:
                                handler(self.remote.asset(assets[name]), tag)
                            except (OSError, ValueError, TypeError, KeyError) as error:
                                complete = False
                                self._gap("release_catalog_unavailable", release=tag, name=name, detail=str(error))
                    # Even failed attempts without a final inventory retain
                    # their index asset and are discoverable by repository key.
                    for repo in self._repos.values():
                        prefix = repo["slug"].lower().replace("/", "__") + "-" + sha256(repo["slug"].lower().encode())[:12]
                        name = prefix + ".index.json"
                        if name in assets:
                            descriptor = {"release_tag": tag, "name": name, "asset": assets[name]}
                            if not any(d.get("release_tag") == tag and d.get("name") == name for d in repo["index_assets"]):
                                repo["index_assets"].append(descriptor)
                if len(releases) < 100:
                    break
            else:
                complete = False
                self._gap("release_page_cap")
            self._remote_done = complete
            self._metadata_state = "complete" if complete else "partial"
            self._metadata_last_success_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self._metadata_retry_at = time.time() + 30
            if not complete:
                self._metadata_last_error = "Some remote metadata could not be read; coverage remains unknown for those records"
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self._metadata_state = "session_limit" if "Session metadata" in str(error) else "unavailable"
            self._metadata_last_error = str(error)
            self._metadata_retry_at = time.time() + 60
            self._gap("remote_metadata_unavailable", detail=str(error))

    def _inventory(self, inventory: dict, tag: str):
        if inventory.get("release_tag") != tag:
            raise MetadataError("Inventory release binding mismatch")
        if inventory.get("csv_sha256") not in (None, self.csv_sha256):
            self._gap("historical_source_cohort_differs", release=tag)
        for row in inventory.get("repositories", []):
            slug = row.get("repository")
            if not isinstance(slug, str) or slug.lower() not in self._by_slug:
                self._gap("inventory_repository_outside_local_cohort", release=tag)
                continue
            repo = self._repos[self._by_slug[slug.lower()]]
            self._record_attempt(repo, {"release_tag": tag, "status": row.get("capture_status") or "not_observed",
                "complete": row.get("complete"), "errors": row.get("errors"),
                "index_asset": row.get("index_asset"), "source_release_tag": row.get("source_release_tag", tag)})
            source_tag = row.get("source_release_tag", tag)
            remote = {"release_tag": source_tag, "name": row.get("index_asset"),
                "expected_sha256": row.get("index_sha256"), "aliases": row.get("archive_transport_aliases") or [],
                "source_csv_sha256": inventory.get("csv_sha256")}
            for summary in row.get("manifests") or []:
                repo = self._repository(slug, summary.get("repository_id"))
                self._add_capture(repo, summary, remote=remote, source={**row, "csv_sha256": inventory.get("csv_sha256")})

    def _native_catalog(self, catalog: dict, tag: str):
        slug = catalog.get("slug")
        if catalog.get("generation_release", tag) != tag:
            raise MetadataError("Native catalog release binding mismatch")
        for observation in catalog.get("observations", []):
            observed_slug = slug or observation.get("repository")
            if not isinstance(observed_slug, str) or not SLUG.fullmatch(observed_slug):
                raise MetadataError("Public catalog repository identity missing")
            if slug is None and observed_slug.lower() not in self._by_slug:
                self._gap("catalog_repository_outside_local_cohort", release=tag)
                continue
            repo = self._repository(observed_slug, catalog.get("repository_id") if slug else None)
            index = observation.get("index") or {}
            remote = {"release_tag": index.get("release_tag", tag), "name": index.get("name"),
                      "expected_sha256": index.get("sha256")}
            source = {"timestamp_evidence": observation.get("timestamp_evidence") or {}}
            self._add_capture(repo, observation, remote=remote, source=source)

    def _index_remote_repository(self, repo: dict):
        if (repo["key"] in self._repo_remote_done or repo["key"] in self._repo_remote_attempted or self.offline
                or self._metadata_state in ("rate_limited", "unavailable", "session_limit")):
            return
        self._repo_remote_attempted.add(repo["key"])
        complete = True
        descriptors = list(repo["index_assets"])
        descriptors.extend(c["remote"] for c in self._captures.values()
                           if c["repo_key"] == repo["key"] and c.get("remote"))
        seen = set()
        for descriptor in descriptors:
            identity = (descriptor.get("release_tag"), descriptor.get("name"))
            if identity in seen:
                continue
            seen.add(identity)
            try:
                index = self._fetch_index(repo, descriptor)
                summaries = index.get("manifests")
                if summaries is None:
                    members = index.get("members") or []
                    manifests = [m for m in members if str(m.get("path", "")).endswith(".manifest.json")
                                 and m.get("sha256") == index.get("manifest_sha256")]
                    if len(manifests) > 1:
                        raise MetadataError("Native index declares duplicate selected manifests")
                    if manifests:
                        run = Path(manifests[0]["path"]).name.removesuffix(".manifest.json")
                    else:
                        # Persistent exports omit members already delivered by
                        # an earlier export. The immutable index basename still
                        # identifies this run; its manifest remains a prerequisite.
                        name = descriptor.get("name", "")
                        if not SAFE.fullmatch(name) or not name.endswith(".index.json"):
                            raise MetadataError("Native index has no safe run identifier")
                        run = name.removesuffix(".index.json")
                    summaries = [{**index, "sha256": index.get("manifest_sha256"),
                        "run_id": run}]
                for summary in summaries:
                    cap = self._add_capture(repo, summary, remote=descriptor, source=index)
                    cap["source"] = index
                    if index.get("timestamp_evidence"):
                        cap["proof"] = _proof(index)
                    if cap["manifest"] is None:
                        cap["status"] = summary.get("status") or ("complete" if index.get("capture_accepted") is True else "coverage_unknown")
                        cap["mode"] = summary.get("mode")
                self._record_attempt(repo, {"release_tag": identity[0], "status": index.get("status", "index_present"),
                    "complete": index.get("complete"), "errors": index.get("errors") or [], "index_asset": identity[1]})
            except (OSError, ValueError, TypeError) as error:
                complete = False
                self._gap("repository_index_unavailable", repository=repo["slug"], release=identity[0], detail=str(error))
        if complete:
            self._repo_remote_done.add(repo["key"])
        for key in repo["captures"]:
            self._refresh_proof(self._captures[key])

    def _refresh_proof(self, capture: dict):
        initial = capture["proof"]["opentimestamps"]
        key = initial.get("metadata_sha256")
        if not key or key in self._proof_checked or not HASH.fullmatch(key):
            return
        self._proof_checked.add(key)
        try:
            if not self._proof_head_checked:
                self._proof_head_checked = True
                ref = self.remote.json(f"repos/{self.release_repository}/git/ref/heads/collector-attestations")
                head = (ref.get("object") or {}).get("sha")
                if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
                    raise MetadataError("Proof maintenance branch has no valid immutable commit")
                self._proof_head = head
            if self._proof_head is None:
                raise MetadataError("Proof maintenance branch unavailable")
            obj = self.remote.json(f"repos/{self.release_repository}/contents/proofs/{key}.json?ref={self._proof_head}")
            raw = base64.b64decode(obj["content"], validate=False)
            if len(raw) > JSON_LIMIT:
                raise MetadataError("Proof maintenance record exceeds bound")
            record = json.loads(raw)
            if record.get("subject_sha256") != capture["manifest_sha256"]:
                raise MetadataError("Proof maintenance record subject mismatch")
            history = record.get("history") or []
            if not history or (history[0].get("metadata") or {}).get("sha256") != key:
                raise MetadataError("Proof maintenance initial metadata identity mismatch")
            initial.update(initial_status=initial["status"], status=history[-1].get("status", initial["status"]),
                maintenance_status=record.get("maintenance_status"), last_verification_result=record.get("last_verification_result"),
                current_record_commit=self._proof_head, history_count=len(history))
        except (OSError, ValueError, KeyError, TypeError) as error:
            initial["current_maintenance_status"] = "unavailable"
            initial["current_maintenance_gap"] = str(error)

    def _fetch_index(self, repo: dict, descriptor: dict) -> dict:
        release = self._releases.get(descriptor.get("release_tag"))
        if release is None:
            raise MetadataError("Referenced parent release has not been inventoried")
        name = descriptor.get("name")
        asset = release["assets"].get(name)
        if asset is None:
            raise MetadataError("Referenced immutable index asset is missing")
        index = self.remote.asset(asset, descriptor.get("expected_sha256"))
        if index.get("repository") is not None and str(index["repository"]).lower() != repo["slug"].lower():
            raise MetadataError("Index repository identity differs from selected repository")
        declared_ids = {m.get("repository_id") for m in index.get("manifests") or []}
        if index.get("repository_id") is not None:
            declared_ids.add(index["repository_id"])
        if len(declared_ids) > 1:
            raise MetadataError("Index contains conflicting repository identities")
        if declared_ids:
            self._repository(repo["slug"], declared_ids.pop())
        if index.get("release_tag") not in (None, descriptor["release_tag"]):
            raise MetadataError("Index release binding mismatch")
        expected_cohort = descriptor.get("source_csv_sha256")
        if expected_cohort and index.get("csv_sha256") != expected_cohort:
            raise MetadataError("Index source cohort differs from its inventory")
        for manifest in index.get("manifests") or []:
            if manifest.get("repository_id") != repo["repository_id"]:
                raise MetadataError("Index manifest repository identity mismatch")
        descriptor["index"] = index
        return index

    def _get_repo(self, key: str) -> dict:
        if key in self._repos:
            return self._repos[key]
        raise KeyError("Unknown registered repository identifier")

    def _get_capture(self, repo: dict, key: str) -> dict:
        capture = self._captures.get(key)
        if capture is None or capture["repo_key"] != repo["key"]:
            raise KeyError("Unknown capture for selected repository")
        return capture

    def _public_capture(self, capture: dict) -> dict:
        result = {k: capture[k] for k in ("key", "id", "run_id", "capture_id", "lane", "kind", "mode", "status",
            "manifest_sha256", "interval", "captured_at", "load_state", "proof", "gaps", "progress")}
        api = capture.get("coverage") or {}
        result["coverage"] = api.get("scope_statuses") or api.get("scopes") or {}
        result["raw_record_count"] = len((capture.get("manifest") or {}).get("responses", [])) if capture.get("manifest") is not None else None
        result["source_release"] = (capture.get("remote") or {}).get("release_tag")
        result["clock_qualification"] = "Collector system clock UTC; interval observed and non-atomic."
        source = capture.get("source") or {}
        remote = capture.get("remote") or {}
        result["source_lineage"] = {"release_tag": remote.get("release_tag"), "index_name": remote.get("name"),
            "index_sha256": remote.get("expected_sha256"), "csv_sha256": source.get("csv_sha256"),
            "collector_code_sha": source.get("collector_code_sha"),
            "public_config_sha256": (capture.get("manifest") or {}).get("public_config_sha256")}
        if source.get("encrypted") is True:
            result["manifest_prerequisite"] = not any(m.get("sha256") == capture["manifest_sha256"]
                                                      for m in source.get("members") or [])
        manifest = capture.get("manifest") or {}
        responses = manifest.get("responses") or []
        starts = [_utc(r.get("request_started_at")) for r in responses if _utc(r.get("request_started_at"))]
        finishes = [_utc(r.get("request_completed_at")) for r in responses if _utc(r.get("request_completed_at"))]
        git = manifest.get("git") or {}
        result["lane_intervals"] = {
            "api": {"started_at": min(starts) if starts else None, "completed_at": max(finishes) if finishes else None},
            "git_refs": {"started_at": _utc(git.get("ls_remote_started_at")), "completed_at": _utc(git.get("ls_remote_completed_at"))}}
        result["git_file_diff"] = self._git_capability(capture)
        return result

    def _public_repo(self, repo: dict) -> dict:
        result = {k: repo[k] for k in ("key", "id", "name", "slug", "repository_id", "cohort", "cohort_id", "role",
            "measurement_caveat", "authoritative_source")}
        captures = [self._captures[k] for k in repo["captures"]]
        captures.sort(key=lambda c: c["captured_at"] or "")
        latest = captures[-1] if captures else None
        discovery = self._repo_discovery(repo)
        result.update(capture_count=len(captures), lanes=sorted({c["lane"] for c in captures}),
            status=latest["status"] if latest else ("index_available_not_read" if repo["index_assets"] and repo["key"] not in self._repo_remote_done else
                "attempted_without_loaded_manifest" if repo["attempts"] else "not_observed" if discovery["availability_known"] else "metadata_unknown"),
            load_state=latest["load_state"] if latest else "not_loaded", latest_at=latest["captured_at"] if latest else None,
            proof=latest["proof"] if latest else _proof({}), attempt_count=len(repo["attempts"]),
            pending_index_count=0 if repo["key"] in self._repo_remote_done else self._repo_descriptor_count(repo),
            capture_count_known=discovery["availability_known"], remote_discovery=discovery,
            timeline_qualification="Registered manifests only; select this repository to inspect its remaining public index assets")
        return result

    def list_repositories(self, refresh: bool = False) -> dict:
        with self._lock:
            if type(refresh) is not bool:
                raise ValueError("Metadata refresh must be explicit boolean")
            if refresh:
                self._prepare_metadata_refresh()
            self._discover_remote()
            rows = sorted((self._public_repo(r) for r in self._repos.values()), key=lambda r: r["slug"].lower())
            return {"repositories": rows, "repos": rows, "gaps": self.gaps,
                "stats": {"repositories": len(rows), "captures": len(self._captures),
                          "loaded_captures": sum(c["load_state"] == "loaded" for c in self._captures.values()),
                          "metadata_bytes": getattr(self.remote, "bytes_read", None)},
                "qualification": QUALIFICATION, "metadata_status": self._metadata_status()}

    overview = list_repositories

    def list_captures(self, repo_key: str) -> dict:
        with self._lock:
            self._discover_remote()
            repo = self._get_repo(repo_key)
            self._index_remote_repository(repo)
            captures = [self._public_capture(self._captures[k]) for k in repo["captures"]]
            captures.sort(key=lambda c: c["captured_at"] or "")
            return {"repository": self._public_repo(repo), "repo": self._public_repo(repo), "captures": captures,
                    "attempts": repo["attempts"], "categories": list(CATEGORIES), "gaps": self.gaps,
                    "qualification": QUALIFICATION, "metadata_status": self._metadata_status()}

    repo = list_captures

    def _manifest(self, capture: dict) -> dict | None:
        if capture.get("path"):
            raw = _read(_safe_path(capture["root"], capture["path"].relative_to(capture["root"]).as_posix()), digest=capture["manifest_sha256"])
            return json.loads(raw)
        return capture.get("manifest")

    def _body(self, capture: dict, digest: str) -> bytes:
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError("Invalid content address")
        if digest in self._objects:
            raw = self._objects[digest]
        elif capture.get("root"):
            raw = _read(_safe_path(capture["root"], f"objects/sha256/{digest[:2]}/{digest}"), digest=digest)
        else:
            # A later native export may depend on previous captures. Reuse only
            # explicitly addressed and hash-verified local CAS bytes.
            for root in self.roots:
                path = _safe_path(root, f"objects/sha256/{digest[:2]}/{digest}")
                if path.is_file():
                    raw = _read(path, digest=digest)
                    break
            else:
                raise ValueError("Referenced raw object is not loaded; prerequisite capture may be required")
        if sha256(raw) != digest:
            raise ValueError("CAS SHA-256 mismatch")
        return raw

    def _entities(self, capture: dict, category: str) -> tuple[dict[str, dict], dict]:
        manifest = self._manifest(capture)
        state = {"status": "coverage_unknown", "gaps": [], "scopes": {}, "projected_response_count": 0,
                 "qualification": QUALIFICATION}
        if manifest is None:
            state["gaps"].append("Capture payload is not loaded")
            return {}, state
        if capture["lane"] == "git":
            state["gaps"].append("Selected capture is in the Git lane")
            return {}, state
        api = manifest.get("api") or {}
        outcomes = api.get("scope_statuses") or api.get("scopes") or {}
        relevant = {name: outcome for name, outcome in outcomes.items() if _kind(name) == category}
        state["scopes"] = relevant
        if relevant and all(o.get("status") == "unavailable" for o in relevant.values()):
            state["status"] = "capability_unavailable"
        elif relevant and all(str(o.get("status", "")).startswith("complete_for_") for o in relevant.values()):
            state["status"] = "complete_for_query"
        elif relevant:
            state["status"] = "partial"
        entities: dict[str, dict] = {}
        found = False
        projection_bytes = 0
        for position, response in enumerate(manifest.get("responses") or []):
            purpose = str(response.get("purpose", ""))
            if _kind(purpose) != category or response.get("status") != 200 or not response.get("body_sha256"):
                continue
            scope = outcomes.get(purpose) or {}
            provenance = response.get("checkpoint_provenance") or {}
            accepted_attempt = scope.get("attempt_id")
            if scope.get("pagination_attempts", 1) > 1 and not accepted_attempt and not scope.get("query_started_at"):
                state["gaps"].append("Multiple pagination attempts lack an accepted attempt boundary; raw pages retained without entity projection")
                continue
            # Retain abandoned attempt pages in raw_records; they must not
            # contaminate the accepted traversal's entity projection.
            if accepted_attempt and provenance.get("attempt_id") != accepted_attempt:
                continue
            if scope.get("query_started_at") and not accepted_attempt:
                response_start = response.get("request_started_at")
                if response_start and response_start < scope["query_started_at"]:
                    continue
            if not scope and any(purpose + suffix in outcomes for suffix in ("_first_page_recheck",)):
                state["gaps"].append("Scope pagination qualification is unavailable")
            found = True
            try:
                raw = self._body(capture, response["body_sha256"])
                if projection_bytes + len(raw) > CAPTURE_MEMORY_LIMIT:
                    state["gaps"].append({"reason": "entity_projection_memory_bound", "ref": f"response-{position}",
                                          "qualification": "Remaining pages are retained as raw references but not projected"})
                    break
                projection_bytes += len(raw)
                value = json.loads(raw)
                items = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
                if not isinstance(value, (list, dict)):
                    raise ValueError("Response JSON is not an entity listing")
                state["projected_response_count"] += 1
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    identity = _identity(item, purpose)
                    if identity is None:
                        continue
                    # REST issues include PR representations. Keep them as
                    # captured in issues, with their source type explicit.
                    namespace = purpose.split(":", 1)[0]
                    entity_key = namespace + ":" + identity if category in ("comments", "events") else identity
                    entities[entity_key] = {"id": entity_key, "entity_type": category,
                        "source_type": namespace, "number": item.get("number"),
                        "title": item.get("title") or item.get("name") or item.get("tag_name") or f"{namespace} {identity}",
                        "value": item, "sha256": sha256(canonical_json(item)),
                        "observed_at": _utc(response.get("request_completed_at")),
                        "raw_refs": [{"key": f"response-{position}", "sha256": response["body_sha256"],
                                      "purpose": purpose, "url": response.get("url")}],
                        "qualification": "accepted_attempt" if accepted_attempt else "captured_page; legacy attempt qualification may be unavailable"}
            except (OSError, ValueError, UnicodeError) as error:
                state["gaps"].append({"reason": "raw_response_unreadable", "ref": f"response-{position}", "detail": str(error)})
        if state["gaps"] and state["status"] == "complete_for_query":
            state["status"] = "partial"
        if not state["projected_response_count"] and state["status"] != "capability_unavailable":
            state["gaps"].append("No usable accepted entity response is loaded; the observed count is unknown")
            if state["status"] == "complete_for_query":
                state["status"] = "partial"
        if not found and state["status"] == "coverage_unknown":
            state["gaps"].append("No usable captured listing; absence and count are unknown")
        if state["projected_response_count"] and not relevant:
            state["status"] = "observed_pages_coverage_unknown"
        return entities, state

    def _raw_summaries(self, capture: dict) -> list[dict]:
        manifest = self._manifest(capture)
        if manifest is None:
            return []
        return [{"id": f"response-{i}", "title": str(r.get("purpose", "response")), "status": r.get("status"),
                 "change": "captured_attempt", "entity_type": "raw_records", "before": None, "after": _display_value(r, 8000),
                 "fields": [], "raw_refs": [{"key": f"response-{i}", "sha256": r.get("body_sha256")}],
                 "body_before": None, "body_after": None}
                for i, r in enumerate(manifest.get("responses") or [])]

    def _refs(self, capture: dict) -> tuple[dict, bool]:
        manifest = self._manifest(capture)
        git = (manifest or {}).get("git")
        if not isinstance(git, dict):
            return {}, False
        refs = {r["published_ref"]: r["object_id"] for r in git.get("advertised_refs", [])
                if isinstance(r, dict) and isinstance(r.get("published_ref"), str) and isinstance(r.get("object_id"), str)}
        return refs, True

    def compare(self, repo_key: str, left_key: str, right_key: str, category: str | None = None,
                offset: int = 0, limit: int = 100) -> dict:
        if category is not None and category not in (*CATEGORIES, "coverage", "git"):
            raise ValueError("Unknown comparison category")
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= 100:
            raise ValueError("Pagination requires offset >= 0 and limit in 1..100")
        repo = self._get_repo(repo_key)
        left, right = self._get_capture(repo, left_key), self._get_capture(repo, right_key)
        if left["lane"] != right["lane"]:
            compatible = left["lane"] == "combined" or right["lane"] == "combined"
        else:
            compatible = True
        out = {"repository": self._public_repo(repo), "left": self._public_capture(left),
            "right": self._public_capture(right), "qualification": QUALIFICATION,
            "entity_types": {}, "gaps": []}
        if not compatible:
            out["gaps"].append("Selected API and Git lanes differ; entity/ref comparisons require corresponding lanes.")
        selected = category or "issues"
        types = (selected,) if selected in CATEGORIES and selected not in ("git_refs", "raw_records") else (CATEGORIES[:6] if selected == "coverage" or category is None else ())
        all_changes = []
        for kind in types:
            before, before_state = self._entities(left, kind)
            after, after_state = self._entities(right, kind)
            changes = []
            change_count = 0
            not_left = not_right = 0
            changed_count = 0
            if compatible:
                ordered = sorted(set(before) | set(after), key=lambda identity: (
                    0 if identity in before and identity in after else 1 if identity in after else 2, identity))
                for identity in ordered:
                    a, b = before.get(identity), after.get(identity)
                    if a and b and a["sha256"] == b["sha256"] and left_key != right_key:
                        continue
                    change = "observed" if left_key == right_key else "representation_changed" if a and b else "not_observed_left" if b else "not_observed_right"
                    not_left += change == "not_observed_left"
                    not_right += change == "not_observed_right"
                    changed_count += change == "representation_changed"
                    change_count += 1
                    if selected == "coverage" or not offset <= change_count - 1 < offset + limit:
                        continue
                    av, bv = (a or {}).get("value"), (b or {}).get("value")
                    fields = []
                    if av is not None and bv is not None:
                        fields = [{"field": name, "before": _display_value(av.get(name), 256), "after": _display_value(bv.get(name), 256),
                            "before_present": name in av, "after_present": name in bv}
                            for name in sorted(set(av) | set(bv)) if (name in av) != (name in bv) or av.get(name) != bv.get(name)]
                    atext = json.dumps(av, ensure_ascii=False, sort_keys=True, indent=2)
                    btext = json.dumps(bv, ensure_ascii=False, sort_keys=True, indent=2)
                    changes.append({"id": identity, "title": _text_excerpt((b or a)["title"], 300), "entity_type": kind,
                        "change": change, "status": change, "before": _display_value(av), "after": _display_value(bv),
                        "fields": fields[:20], "changed_fields": [f["field"] for f in fields], "field_count": len(fields),
                        "body_before": _text_excerpt((av or {}).get("body")), "body_after": _text_excerpt((bv or {}).get("body")),
                        "display_qualification": "JSON/body/diff previews are bounded excerpts; raw response retains exact captured bytes",
                        "raw_refs": {"left": (a or {}).get("raw_refs", []), "right": (b or {}).get("raw_refs", [])},
                        "raw_diff": _text_excerpt("".join(difflib.unified_diff(atext[:8000].splitlines(True),
                                  btext[:8000].splitlines(True), fromfile="left captured JSON", tofile="right captured JSON")), 4000)})
            counts = {"left": len(before) if before_state["projected_response_count"] and before_state["status"] != "capability_unavailable" else None,
                      "right": len(after) if after_state["projected_response_count"] and after_state["status"] != "capability_unavailable" else None}
            statuses = {before_state["status"], after_state["status"]}
            comparison_status = "capability_unavailable" if "capability_unavailable" in statuses else "coverage_unknown" if "coverage_unknown" in statuses else "partial" if "partial" in statuses else "comparable_observations"
            details = {"status": comparison_status if compatible else "lane_mismatch",
                "counts": counts, "coverage": {"left": before_state, "right": after_state},
                "changes": [{"id": c["id"], "change": c["change"], "changed_fields": c["changed_fields"]} for c in changes],
                "change_count": change_count,
                "change_breakdown": {"representation_changed": changed_count, "not_observed_left": not_left,
                                     "not_observed_right": not_right,
                                     "observed": change_count if left_key == right_key else 0},
                "count_qualification": "Entity representations observed in these query results; delta counts are not full snapshot counts",
                "not_observed_left": not_left,
                "not_observed_right": not_right,
                "gaps": before_state["gaps"] + after_state["gaps"]}
            out["entity_types"][kind] = details
            all_changes.extend(changes)
        a, a_ok = self._refs(left)
        b, b_ok = self._refs(right)
        available = a_ok and b_ok and compatible
        out["git_refs"] = {"comparison_available": available,
            "added": [{"ref": ref, "new_sha": b[ref]} for ref in sorted(set(b) - set(a))] if available else [],
            "not_advertised_now": [{"ref": ref, "prior_sha": a[ref]} for ref in sorted(set(a) - set(b))] if available else [],
            "moved": [{"ref": ref, "prior_sha": a[ref], "new_sha": b[ref]} for ref in sorted(set(a) & set(b)) if a[ref] != b[ref]] if available else [],
            "file_diff": {"left": self._git_capability(left), "right": self._git_capability(right)},
            "qualification": "Refs were advertised in separate observation intervals; absence is not proven deletion."}
        if selected in ("git", "git_refs"):
            all_changes = []
            if available:
                for ref in sorted(set(a) | set(b)):
                    if a.get(ref) == b.get(ref) and left_key != right_key:
                        continue
                    change = "observed" if left_key == right_key else "oid_changed" if ref in a and ref in b else "not_advertised_left" if ref in b else "not_advertised_right"
                    all_changes.append({"id": ref, "title": ref, "entity_type": "git_refs", "change": change,
                        "status": change, "before": a.get(ref), "after": b.get(ref),
                        "fields": [{"field": "object_id", "before": a.get(ref), "after": b.get(ref)}]})
            else:
                out["gaps"].append("Both selected captures need loaded Git ref observations")
        if selected == "raw_records":
            all_changes = self._raw_summaries(right)
        if selected in CATEGORIES[:6]:
            total_changes = out["entity_types"][selected]["change_count"]
            page_items = all_changes
        else:
            total_changes = len(all_changes)
            page_items = all_changes[offset:offset + limit]
        out.update(items=page_items, total=total_changes, offset=offset, limit=limit,
            coverage=(out["entity_types"].get(selected) or {}).get("coverage") or
            {"left": self._public_capture(left)["coverage"], "right": self._public_capture(right)["coverage"]})
        return out

    def entity_detail(self, repo_key: str, capture_key: str, kind: str, entity_id: str) -> dict:
        if kind not in CATEGORIES[:6]:
            raise ValueError("Unknown entity category")
        repo = self._get_repo(repo_key)
        capture = self._get_capture(repo, capture_key)
        entities, state = self._entities(capture, kind)
        entity = entities.get(entity_id)
        if entity:
            entity = {**entity, "value": _display_value(entity["value"], 512_000)}
        return {"status": "observed" if entity else "not_observed_coverage_unknown", "entity": entity,
                "raw_refs": (entity or {}).get("raw_refs", []), "coverage": state, "gaps": state["gaps"]}

    def raw_record(self, repo_key: str, capture_key: str, ref_key: str) -> dict:
        repo = self._get_repo(repo_key)
        capture = self._get_capture(repo, capture_key)
        manifest = self._manifest(capture)
        if ref_key == "manifest":
            return {"status": "loaded" if manifest else "not_loaded", "record": _display_value(manifest, 512_000),
                    "sha256": capture["manifest_sha256"], "encoding": "utf-8", "gaps": []}
        if not re.fullmatch(r"response-[0-9]{1,7}", ref_key):
            raise ValueError("Unknown raw record identifier")
        responses = (manifest or {}).get("responses") or []
        position = int(ref_key.split("-")[1])
        if position >= len(responses):
            raise KeyError("Raw record is not present in this capture")
        record = responses[position]
        result = {"status": "metadata_only", "record": record, "sha256": record.get("body_sha256"),
                  "encoding": None, "gaps": []}
        if record.get("body_sha256"):
            try:
                raw = self._body(capture, record["body_sha256"])
                result["bytes"] = len(raw)
                # The raw response retains its hash identity. Display text is
                # bounded and replacement decoding is explicitly labeled.
                snippet = raw[:512_000]
                try:
                    result["text"] = snippet.decode("utf-8")
                    result["encoding"] = "utf-8"
                except UnicodeDecodeError:
                    result["text"] = snippet.decode("utf-8", errors="replace")
                    result["encoding"] = "invalid_utf8_display_replacement"
                    result["gaps"].append("Original bytes fail UTF-8 decoding; replacement characters are display-only")
                result["truncated"] = len(raw) > len(snippet)
                result["status"] = "loaded"
            except (OSError, ValueError) as error:
                result["gaps"].append(str(error))
        return result

    def _full_bundle(self, capture: dict) -> dict | None:
        git = (capture.get("manifest") or {}).get("git") or {}
        bundle = git.get("portable_full_bundle")
        if not bundle:
            portable = git.get("portable_archive") or {}
            if portable.get("kind") == "baseline" and not portable.get("prerequisites"):
                bundle = portable.get("bundle")
        if (not isinstance(bundle, dict) or not isinstance(bundle.get("sha256"), str)
                or not HASH.fullmatch(bundle["sha256"]) or type(bundle.get("bytes")) is not int or bundle["bytes"] <= 0):
            return None
        return bundle

    def _git_capability(self, capture: dict) -> dict:
        result = {"capture_key": capture["key"], "status": "not_loaded", "bundle_bytes": None,
                  "reason": "Load the selected capture to inspect its Git archive descriptor", "refs": [],
                  "refs_total": None, "refs_truncated": False}
        manifest = capture.get("manifest")
        if manifest is None:
            return result
        bundle = self._full_bundle(capture)
        git = manifest.get("git") or {}
        refs = [{"ref": r["published_ref"], "oid": r["object_id"]} for r in git.get("advertised_refs") or []
                if isinstance(r, dict) and isinstance(r.get("published_ref"), str)
                and isinstance(r.get("object_id"), str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", r["object_id"])]
        result.update(refs=refs[:500], refs_total=len(refs), refs_truncated=len(refs) > 500,
                      bundle_bytes=bundle["bytes"] if bundle else None)
        if bundle is None:
            result.update(status="unavailable", reason="No self-contained full Git bundle is declared; incremental restoration is not performed by this viewer")
        elif bundle["bytes"] > GIT_BUNDLE_LIMIT:
            result.update(status="unavailable", reason="The declared full bundle exceeds this viewer's 32 MiB bounded Git preparation limit")
        else:
            result.update(status="available_to_prepare", reason="Explicit preparation restores and fscks this full bundle on a fixed 256 MiB local volume")
        return result

    @staticmethod
    def _verify_bundle_file(path: Path, bundle: dict):
        digest, count = hashlib.sha256(), 0
        if path.is_symlink() or not path.is_file():
            raise ValueError("Git bundle must be an owned or registered regular evidence file")
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                count += len(block)
                if count > bundle["bytes"]:
                    raise ValueError("Git bundle length exceeds its manifest")
                digest.update(block)
        if count != bundle["bytes"] or digest.hexdigest() != bundle["sha256"]:
            raise ValueError("Git bundle SHA-256/length differs from selected manifest")

    @contextmanager
    def _bundle_source(self, repo: dict, capture: dict, bundle: dict):
        digest = bundle["sha256"]
        cached = self._bundle_cache.get(digest)
        if cached and cached[0].is_file():
            with self.budget.open_cached(cached[0]):
                self._verify_bundle_file(cached[0], bundle)
                yield cached[0]
            return
        self._bundle_cache.pop(digest, None)
        for root in dict.fromkeys([*([capture["root"]] if capture.get("root") else []), *self.roots]):
            path = _safe_path(root, f"objects/sha256/{digest[:2]}/{digest}")
            if path.is_file():
                # Snapshot into a bounded owned stage so an evidence-path swap
                # cannot race the subsequent Git processes.
                with self.budget.stage(bundle["bytes"], suffix=".bundle", purpose="immutable local Git bundle snapshot") as stage:
                    with path.open("rb") as source:
                        stage.copy_from(source)
                    self._verify_bundle_file(stage.path, bundle)
                    yield stage.path
                return
        if self.private_key_path is None:
            raise ValueError("The bundle is not local; loading it requires the server-local private key")
        self._bundle_cache = {key: value for key, value in self._bundle_cache.items() if value[0].is_file()}
        if sum(size for _, size in self._bundle_cache.values()) + bundle["bytes"] > GIT_CACHE_LIMIT:
            raise ValueError("The viewer's 64 MiB managed Git bundle cache limit is reached")
        reader, _ = self._remote_reader(repo, capture)
        target = f"evidence/objects/sha256/{digest[:2]}/{digest}"
        found = False
        with self.budget.stage(bundle["bytes"], suffix=".bundle", purpose="authenticated selected Git bundle") as stage:
            def member(record, stream):
                nonlocal found
                if record.path != target:
                    return
                if found or record.bytes != bundle["bytes"]:
                    raise ValueError("Selected Git bundle member identity differs from manifest")
                stage.copy_from(stream)
                found = True
            capture["progress"] = {"phase": "loading_selected_git_bundle", "parts_complete": 0}
            reader.scan(member)
            if not found:
                raise ValueError("The selected full bundle is a prerequisite from an earlier export and is not present in this archive")
            self._verify_bundle_file(stage.path, bundle)
            path = stage.preserve()
            self._bundle_cache[digest] = (path, bundle["bytes"])
        # All ciphertext stages have been released before a native Git volume
        # can be created. This lease protects the retained bundle from eviction.
        with self.budget.open_cached(path):
            yield path

    def git_diff(self, repo_key: str, capture_key: str, base_oid: str, head_oid: str,
                 path: str | None = None) -> dict:
        """Explicit, offline file diff from a bounded self-contained bundle."""
        for oid in (base_oid, head_oid):
            if not isinstance(oid, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
                raise ValueError("Git diff requires explicit captured object IDs")
        if path is not None and (not isinstance(path, str) or not path or len(path.encode("utf-8")) > 4096
                                 or "\0" in path or Path(path).is_absolute() or ".." in Path(path).parts):
            raise ValueError("Invalid repository-relative Git path")
        repo = self._get_repo(repo_key)
        capture = self._get_capture(repo, capture_key)
        result = {"status": "unavailable", "base_oid": base_oid, "head_oid": head_oid,
            "files": None, "files_total": None, "patch": None, "truncated": False, "gaps": [],
            "qualification": "Offline diff of retained Git bytes. Commit author/committer dates are source assertions, not collection times or first-publication evidence."}
        bundle = self._full_bundle(capture)
        capability = self._git_capability(capture)
        if capability["status"] != "available_to_prepare" or bundle is None:
            result["gaps"].append(capability["reason"])
            return result
        allowed = set()
        for key in repo["captures"]:
            git = (self._captures[key].get("manifest") or {}).get("git") or {}
            for ref in git.get("advertised_refs") or []:
                allowed.update(value for value in (ref.get("object_id"), ref.get("peeled_object_id")) if value)
        if base_oid not in allowed or head_oid not in allowed:
            raise ValueError("Both Git OIDs must occur in this repository's loaded captured ref observations")
        if not self._load_lock.acquire(blocking=False):
            result.update(status="busy", gaps=["Another bounded capture or Git preparation is active"])
            return result
        try:
            from .corpus_audit import BoundedGit, FixedGitVolume, read_bundle_header
            self.budget_status()
            if self.budget is None:
                raise ValueError("Shared disk budget is unavailable")
            # Revalidate immutable local manifest identity before trusting its
            # bundle declaration or preparing a writable Git graph.
            manifest = self._manifest(capture)
            if manifest is None:
                raise ValueError("Selected capture manifest is not loaded")
            with self._bundle_source(repo, capture, bundle) as bundle_path:
                with bundle_path.open("rb") as stream:
                    header = read_bundle_header(stream)
                if header["prerequisite_object_ids"]:
                    raise ValueError("A full-bundle diff cannot depend on external Git objects")
                if header["pack_objects"] > 100_000:
                    raise ValueError("Git object count exceeds this viewer's bounded preparation limit")
                git_info = manifest.get("git") or {}
                expected = {r.get("local_immutable_ref", r["published_ref"]): r["object_id"]
                            for r in git_info.get("advertised_refs") or []}
                if any(header["refs"].get(ref) != oid for ref, oid in expected.items()):
                    raise ValueError("Full bundle header does not contain the selected manifest's captured refs")
                object_format = git_info.get("git_object_hash_algorithm", "sha1")
                if object_format not in ("sha1", "sha256"):
                    raise ValueError("Unsupported captured Git object format")
                volume = (self._git_volume_factory or FixedGitVolume)(self.budget)
                capture["progress"] = {"phase": "restoring_bounded_git_bundle"}
                with volume as mount:
                    runner = (self._git_runner_factory or BoundedGit)(mount, self.budget)
                    git, restored = runner.run, str(runner.repo)
                    git(["init", "--bare", f"--object-format={object_format}", restored])
                    git(["-C", restored, "bundle", "verify", str(bundle_path.resolve())])
                    git(["-C", restored, "fetch", "--no-tags", str(bundle_path.resolve()), "+refs/*:refs/*", "--no-auto-maintenance"])
                    capture["progress"]["phase"] = "checking_git_objects"
                    git(["-C", restored, "fsck", "--full", "--no-reflogs"])
                    actual = dict(line.split(" ", 1) for line in git(["-C", restored, "for-each-ref", "--format=%(refname) %(objectname)"]).splitlines())
                    if any(actual.get(ref) != oid for ref, oid in expected.items()):
                        raise ValueError("Restored refs differ from selected manifest")
                    commits = {}
                    for side, oid in (("base", base_oid), ("head", head_oid)):
                        resolved = git(["-C", restored, "rev-parse", "--verify", oid + "^{commit}"], max_output_bytes=4096).strip()
                        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", resolved):
                            raise ValueError("Captured OID does not resolve to a retained commit")
                        values = git(["-C", restored, "show", "-s", "--format=%H%x00%s%x00%an%x00%aI%x00%cn%x00%cI", resolved, "--"], max_output_bytes=32_000).strip().split("\0")
                        if len(values) != 6:
                            raise ValueError("Retained commit metadata is malformed")
                        commits[side] = dict(zip(("oid", "subject", "author", "authored_at", "committer", "committed_at"),
                                                (_text_excerpt(value, 2000) for value in values)))
                    base, head = commits["base"]["oid"], commits["head"]["oid"]
                    capture["progress"]["phase"] = "diffing_retained_git_files"
                    names = git(["-C", restored, "diff", "--name-status", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", base, head, "--"], max_output_bytes=512_000, timeout=60)
                    fields = names.rstrip("\0").split("\0") if names else []
                    if len(fields) % 2:
                        raise ValueError("Git name-status output is malformed")
                    files = [{"status": fields[i], "path": fields[i + 1], "old_path": None}
                             for i in range(0, len(fields), 2)]
                    if path is not None and path not in {entry["path"] for entry in files}:
                        raise ValueError("Selected Git path is not present in this retained commit comparison")
                    command = ["-C", restored, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", "--unified=3", base, head, "--"]
                    if path is not None:
                        command.append(":(literal)" + path)
                    patch = None
                    patch_gap = []
                    try:
                        patch = git(command, max_output_bytes=512_000, timeout=60)
                    except RuntimeError as error:
                        if "output bound" not in str(error):
                            raise
                        patch_gap.append("Patch exceeded the 512,000-byte display bound; select a smaller changed file")
                    result.update(status="complete", files=files[:500], files_total=len(files),
                        patch=patch, path=path, truncated=len(files) > 500 or bool(patch_gap), gaps=patch_gap,
                        commits=commits, resolved_base_oid=base, resolved_head_oid=head,
                        verification={"status": "offline_restore_fsck_verified", "bundle_sha256": bundle["sha256"],
                                      "bundle_bytes": bundle["bytes"], "pack_objects": header["pack_objects"],
                                      "captured_refs_checked": len(expected)})
            capture["progress"] = {"phase": "git_diff_complete"}
            result["budget"] = self.budget_status()
            return result
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            message = str(error)
            if self.private_key_path:
                message = message.replace(str(self.private_key_path), "[local key]")
            result["gaps"].append(message)
            capture["progress"] = {"phase": "git_diff_unavailable"}
            return result
        finally:
            self._load_lock.release()

    def budget_status(self) -> dict:
        if self.budget is None:
            try:
                from .localbudget import LocalBudget
                self.budget = LocalBudget(self.workspace / "analysis" / "local-data-budget", roots=[self.workspace, *self.roots], limit_bytes=2_000_000_000)
            except (ImportError, OSError, ValueError) as error:
                return {"limit_bytes": 2_000_000_000, "status": "unavailable", "reason": str(error), "payload_downloads_allowed": False}
        snapshot = self.budget.snapshot()
        return snapshot.as_dict() if hasattr(snapshot, "as_dict") else snapshot

    def load_capture(self, repo_key: str, capture_key: str) -> dict:
        repo = self._get_repo(repo_key)
        capture = self._get_capture(repo, capture_key)
        if capture["load_state"] == "loaded":
            return {"status": "loaded", "capture": self._public_capture(capture), "budget": self.budget_status()}
        if not self._load_lock.acquire(blocking=False):
            return {"status": "busy", "reason": "One bounded capture is already loading"}
        try:
            if self.loader:
                return self.loader(repo, capture)
            if self.private_key_path is None:
                return {"status": "key_required", "reason": "Start the server with a local private key path to load encrypted evidence", "capture": self._public_capture(capture)}
            self.budget_status()
            if self.budget is None:
                return {"status": "budget_unavailable", "capture": self._public_capture(capture)}
            capture["load_state"] = "loading"
            capture["progress"] = {"phase": "index", "parts_complete": 0}
            self._load_remote(repo, capture)
            capture["load_state"] = "loaded"
            capture["progress"]["phase"] = "complete"
            capture["gaps"] = list((capture["manifest"] or {}).get("failures") or []) + capture.get("projection_gaps", [])
            return {"status": "loaded", "capture": self._public_capture(capture), "budget": self.budget_status()}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            capture["load_state"] = "load_failed"
            capture["progress"]["phase"] = "failed"
            message = str(error)
            if self.private_key_path:
                message = message.replace(str(self.private_key_path), "[local key]")
            capture["gaps"].append(message)
            return {"status": "load_failed", "reason": message, "capture": self._public_capture(capture), "budget": self.budget_status()}
        finally:
            self._load_lock.release()

    load = load_capture

    def _remote_reader(self, repo: dict, capture: dict):
        from .archive_reader import ArchivePart, VerifiedArchiveReader
        descriptor = capture.get("remote")
        if not descriptor:
            raise ValueError("No remote archive reference exists for this capture")
        index = descriptor.get("index") or self._fetch_index(repo, descriptor)
        release = self._releases[descriptor["release_tag"]]
        expected_members = None
        archive = index.get("archive") or {}
        if index.get("encrypted") is True or archive.get("encrypted") is True:
            if index.get("encrypted") is True:
                parts = index.get("assets") or [index.get("asset")]
                expected_members = index.get("members")
            else:
                parts = archive.get("parts") or []
            descriptions = []
            for part in parts:
                encrypted = part.get("encryption") or {}
                descriptions.append({"name": part["name"], "ciphertext_sha256": part["sha256"],
                    "ciphertext_bytes": part["bytes"], "plaintext_sha256": encrypted.get("plaintext_sha256"),
                    "plaintext_bytes": encrypted.get("plaintext_bytes")})
        else:
            aliases = {p["plaintext"]["name"]: p for p in descriptor.get("aliases") or []}
            if not aliases:
                migration_asset = release["assets"].get("encryption-migration-index.json")
                if migration_asset is None:
                    raise ValueError("Historical plaintext archive has no encrypted migration mapping")
                mapping = self.remote.asset(migration_asset)
                if mapping.get("release_tag") != release["tag"] or mapping.get("repository") != self.release_repository:
                    raise ValueError("Historical encrypted transport mapping binding mismatch")
                aliases = mapping.get("parts") or {}
            descriptions = []
            for part in archive.get("parts") or []:
                alias = aliases.get(part["name"])
                if not alias or alias.get("plaintext") != {k: part[k] for k in ("name", "bytes", "sha256")}:
                    raise ValueError("Historical encrypted transport differs from original ordered part identity")
                cipher = alias["ciphertext"]
                descriptions.append({"name": cipher["name"], "ciphertext_sha256": cipher["sha256"],
                    "ciphertext_bytes": cipher["bytes"], "plaintext_sha256": part["sha256"], "plaintext_bytes": part["bytes"]})
        if not descriptions:
            raise ValueError("No complete encrypted archive parts are declared")
        contexts = []
        for description in descriptions:
            name = description["name"]
            asset = release["assets"].get(name)
            if asset is None or asset.get("size") != description["ciphertext_bytes"] or asset.get("digest") != "sha256:" + description["ciphertext_sha256"]:
                raise ValueError("Immutable encrypted asset is missing or differs from index")
            contexts.append(self._download_part(asset, description, capture, ArchivePart))
        expected = {"evidence/" + m["path"]: {"bytes": m["bytes"], "sha256": m["sha256"]}
                    for m in expected_members} if expected_members is not None else None
        reader = VerifiedArchiveReader(contexts, self.private_key_path, expected_members=expected,
                                       allowed_prefixes=("evidence", "reports"))
        return reader, index

    def _load_remote(self, repo: dict, capture: dict):
        reader, index = self._remote_reader(repo, capture)
        staged: dict[str, bytes] = {}
        staged_manifest_hashes: set[str] = set()
        total = 0
        projection_gaps = []
        expected_manifest = capture["manifest_sha256"]
        def member(record, stream):
            nonlocal total
            # Reader supplies a validated path and length. JSON projections are
            # provisional until every encrypted part/archive member verifies.
            path = record.path if hasattr(record, "path") else record["path"]
            size = record.bytes if hasattr(record, "bytes") else record.get("bytes", record.get("size", 0))
            if not ("/objects/sha256/" in "/" + path or path.endswith(".manifest.json")):
                return
            is_manifest = path.endswith(".manifest.json")
            if size > JSON_LIMIT:
                projection_gaps.append({"reason": "archive_member_exceeds_json_projection_bound", "member": path, "bytes": size})
                return
            bound = CAPTURE_MEMORY_LIMIT if is_manifest else CAPTURE_MEMORY_LIMIT - JSON_LIMIT
            if total + size > bound:
                projection_gaps.append({"reason": "archive_member_not_loaded_memory_bound", "member": path, "bytes": size})
                return
            first = stream.read(min(64, size))
            if not is_manifest and first.startswith((b"# v2 git bundle\n", b"# v3 git bundle\n")):
                return
            raw = first + stream.read(size - len(first))
            digest = sha256(raw)
            if "/objects/sha256/" in "/" + path and Path(path).name != digest:
                raise ValueError("Archive CAS member differs from its path hash")
            staged[digest] = raw
            if is_manifest:
                staged_manifest_hashes.add(digest)
            total += len(raw)
            capture["progress"].update(phase="authenticating_archive", json_bytes=total)
        reader.scan(member)
        manifest_raw = staged.get(expected_manifest) or self._manifests.get(expected_manifest)
        if manifest_raw is None:
            raise ValueError("Selected manifest is a prerequisite from an earlier export; load the earlier capture containing it before retrying")
        manifest = json.loads(manifest_raw)
        if manifest.get("repository_id") != repo["repository_id"] or str(manifest.get("repository_input_slug", "")).lower() != repo["slug"].lower():
            raise ValueError("Decrypted manifest does not belong to selected repository")
        if manifest.get("run_id") != capture["run_id"] or (manifest.get("lane") or "combined") != capture["lane"]:
            raise ValueError("Decrypted manifest run/lane differs from registered capture")
        wanted = {r.get("body_sha256") for r in manifest.get("responses") or []}
        selected = {digest: raw for digest, raw in staged.items() if digest in wanted and digest not in self._objects}
        selected_manifests = {digest: staged[digest] for digest in staged_manifest_hashes if digest not in self._manifests}
        additional = sum(map(len, selected.values())) + sum(map(len, selected_manifests.values()))
        if self._memory_bytes + additional > CAPTURE_MEMORY_LIMIT * 2:
            raise ValueError("Viewer in-memory capture limit reached; restart to load a different selection")
        self._objects.update(selected)
        self._manifests.update(selected_manifests)
        self._memory_bytes += additional
        capture.update(manifest=manifest, coverage=manifest.get("api") or {}, status=manifest.get("status", "coverage_unknown"),
                       mode=manifest.get("mode"), source=index, projection_gaps=projection_gaps)
        if index.get("timestamp_evidence"):
            capture["proof"] = _proof(index)
        metadata_key = capture["proof"]["opentimestamps"].get("metadata_sha256")
        if metadata_key:
            self._proof_checked.discard(metadata_key)
            self._refresh_proof(capture)

    @contextmanager
    def _download_part(self, asset: dict, description: dict, capture: dict, part_class):
        size = description["ciphertext_bytes"]
        with self.budget.stage(size, suffix=".enc") as stage:
            process = subprocess.Popen(["gh", "api", "--method", "GET",
                f"repos/{self.release_repository}/releases/assets/{asset['id']}",
                "-H", "Accept: application/octet-stream"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True)
            assert process.stdout is not None
            capture["progress"].update(phase="downloading_encrypted_part", current_part_bytes=size)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline, idle_deadline, count = time.monotonic() + 3600, time.monotonic() + 90, 0
            try:
                with stage.open_writer() as target:
                    while True:
                        remaining = min(deadline, idle_deadline) - time.monotonic()
                        if remaining <= 0:
                            raise ValueError("Encrypted asset download exceeded its total/inactivity time bound")
                        if not selector.select(min(remaining, 1)):
                            continue
                        block = os.read(process.stdout.fileno(), 64 * 1024)
                        if not block:
                            break
                        target.write(block)
                        count += len(block)
                        idle_deadline = time.monotonic() + 90
                        capture["progress"]["downloaded_part_bytes"] = count
                if process.wait(timeout=15) != 0:
                    raise ValueError("Encrypted asset download failed")
                if stage.path.stat().st_size != size:
                    raise ValueError("Encrypted asset download length differs from metadata")
                yield part_class(path=stage.path, **description)
                capture["progress"]["parts_complete"] += 1
            finally:
                selector.close()
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                process.stdout.close()
