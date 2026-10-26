"""Prepare encrypted key capsules and an immutable legacy migration catalog.

Only original envelope prefixes/headers are read. This is neither payload
authentication nor a new repository observation. Publication is a separate,
explicit operation; this tool never writes to GitHub or reads an operational
private key. The owner private key is used only by create_capsule in memory.
"""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from icsot_observer.core import Config, REPO_RE, canonical_json, sha256, utc_iso, write_once
from icsot_observer.encryption import public_key_fingerprint
from icsot_observer.legacy_archive import normalize_legacy_parts
from icsot_observer.legacy_bootstrap import migration_id, validate_catalog
from icsot_observer.legacy_capsules import (
    MAX_AAD_BYTES, MAX_CAPSULE_BYTES, create_capsule, envelope_aad_size,
    inspect_capsule, inspect_envelope_aad, read_envelope_aad,
)
from icsot_observer.localbudget import LocalBudget

EXPECTED_REPOSITORIES = 185
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_PARTS = 4000
HASH = re.compile(r"[0-9a-f]{64}\Z")
CODE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
REF_FIELDS = {"release_repository", "release_tag", "release_id", "asset_id", "name", "sha256", "bytes"}
# Explicit repair authorization for this sealed corpus only. These are current
# public identities, never replacements for missing original manifest IDs.
FRESH_REPAIR_INVENTORY = "3b39f6a290794a0e6ad763a48ccc9a78b782d1da375658142489238678505d21"
FRESH_REPAIR_IDENTITIES = {"php/php-src": 1903522, "nodejs/node": 27193779, "zephyrproject-rtos/zephyr": 59771425}


class PreparationError(RuntimeError):
    pass


class RangeReadError(PreparationError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PreparationError("Duplicate metadata field")
        result[key] = value
    return result


def metadata(raw: bytes, expected_sha256: str | None = None) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JSON_BYTES:
        raise PreparationError("Metadata exceeds its bound")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256) or sha256(raw) != expected_sha256):
        raise PreparationError("Frozen metadata digest mismatch")
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise PreparationError("Invalid bounded metadata") from None
    if not isinstance(value, dict):
        raise PreparationError("Expected a metadata object")
    return value


def local_bytes(path: Path, limit: int = MAX_JSON_BYTES) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise PreparationError("Expected a regular input file")
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise PreparationError("Input exceeds its bound")
    return raw


def asset_ref(value: dict, *, unpublished: bool = False) -> dict:
    if not isinstance(value, dict) or set(value) != REF_FIELDS:
        raise PreparationError("Invalid frozen asset reference fields")
    if (not isinstance(value["release_repository"], str) or not REPO_RE.fullmatch(value["release_repository"]) or
            any(part in (".", "..") for part in value["release_repository"].split("/")) or
            not isinstance(value["release_tag"], str) or not NAME.fullmatch(value["release_tag"]) or
            not isinstance(value["name"], str) or not NAME.fullmatch(value["name"]) or
            not isinstance(value["sha256"], str) or not HASH.fullmatch(value["sha256"]) or
            type(value["bytes"]) is not int or value["bytes"] <= 0):
        raise PreparationError("Invalid frozen asset identity")
    for key in ("release_id", "asset_id"):
        if unpublished and value[key] is None:
            continue
        if type(value[key]) is not int or not 0 < value[key] < 2**63:
            raise PreparationError("Asset publication ID is missing or invalid")
    return dict(value)


def cohort(config_path: Path, csv_path: Path, inventory: dict, *, expected_count=EXPECTED_REPOSITORIES) -> tuple[str, ...]:
    import csv
    config = Config.load(config_path)
    raw = csv_path.read_bytes()
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    slugs = []
    for row in rows:
        url = urllib.parse.urlsplit(row["Repository_URL"])
        slug = url.path.strip("/")
        if (url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment or not REPO_RE.fullmatch(slug) or
                any(part in (".", "..") for part in slug.split("/"))):
            raise PreparationError("Invalid cohort URL")
        slugs.append(slug)
    if (tuple(slugs) != config.repositories or len(slugs) != expected_count or
            len({slug.lower() for slug in slugs}) != len(slugs) or
            [row.get("repository") for row in inventory.get("repositories", [])] != slugs or
            inventory.get("cohort_count") != expected_count or inventory.get("csv_sha256") != sha256(raw) or
            inventory.get("config_source_sha256") != sha256(config_path.read_bytes())):
        raise PreparationError("Cohort order or original configuration identity differs")
    return tuple(slugs)


class _PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443) or
                parsed.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
                                        "github-releases.githubusercontent.com"}):
            raise RangeReadError("Unexpected public asset redirect")
        return super().redirect_request(request, response, code, message, headers, url)


class _GhResponse:
    """Stream a frozen asset through existing gh auth without reading a token.

    Headers are consumed before any body read. Closing stops gh rather than
    draining an ignored range or an oversized response. Neither stderr nor
    arbitrary response headers are copied to a log or temporary file.
    """

    def __init__(self, command, *, body_limit, popen=subprocess.Popen, timeout=60):
        if type(body_limit) is not int or not 0 < body_limit <= MAX_JSON_BYTES:
            raise RangeReadError("Invalid authenticated asset read bound")
        self.remaining = body_limit
        self.process = popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, bufsize=0)
        def timeout_kill():
            try:
                if self.process.poll() is None:
                    self.process.kill()
            except ProcessLookupError:
                pass
        self.timer = threading.Timer(timeout, timeout_kill)
        self.timer.daemon = True
        try:
            self.timer.start()
            line = self.process.stdout.readline(8193)
            match = re.fullmatch(rb"HTTP/[0-9.]+ ([0-9]{3})[^\r\n]*\r?\n", line)
            if not match:
                raise RangeReadError("Invalid authenticated asset status")
            self.status = int(match[1])
            self.headers, consumed = {}, len(line)
            while True:
                line = self.process.stdout.readline(8193)
                consumed += len(line)
                if not line or len(line) > 8192 or consumed > 32768:
                    raise RangeReadError("Invalid authenticated asset headers")
                if line in (b"\r\n", b"\n"):
                    break
                key, separator, value = line.partition(b":")
                if not separator:
                    raise RangeReadError("Invalid authenticated asset header")
                key = key.decode("ascii").lower()
                if key in self.headers:
                    raise RangeReadError("Duplicate authenticated asset header")
                self.headers[key] = value.strip().decode("ascii")
            # urllib's response headers are case insensitive; keep the same
            # narrowly used lookup behavior for this injected reader.
            from email.message import Message
            headers = Message()
            for key, value in self.headers.items():
                headers[key] = value
            self.headers = headers
        except BaseException:
            self.close()
            raise

    def read(self, count):
        if type(count) is not int or count < 0 or count > self.remaining:
            raise RangeReadError("Unbounded authenticated asset read")
        block = self.process.stdout.read(count)
        self.remaining -= len(block)
        return block

    def close(self):
        self.timer.cancel()
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class GitHubReader:
    """GH JSON metadata plus unauthenticated bounded public CDN reads.

    gh is NEVER used to capture octet-stream payloads. Range status and headers
    are inspected before the first body read, including after HTTPS redirects.
    """

    def __init__(self, *, runner=subprocess.run, opener=None, popen=subprocess.Popen):
        self.runner = runner
        self.opener = opener or urllib.request.build_opener(_PublicRedirects())
        self.popen = popen
        self.releases = {}
        self.urls = {}

    def _json(self, endpoint, *args):
        result = self.runner(["gh", "api", endpoint, "--hostname", "github.com", *args], capture_output=True, timeout=120)
        if result.returncode or len(result.stdout) > MAX_JSON_BYTES:
            raise PreparationError("Bounded public metadata request failed")
        try:
            return json.loads(result.stdout, object_pairs_hook=_unique)
        except (ValueError, UnicodeError):
            raise PreparationError("Invalid remote metadata") from None

    def release_assets(self, repository: str, release_id: int, tag: str) -> dict:
        key = repository, release_id
        if key not in self.releases:
            release = self._json(f"repos/{repository}/releases/{release_id}")
            if (release.get("id") != release_id or release.get("tag_name") != tag or
                    type(release.get("draft")) is not bool):
                raise PreparationError("Original release identity differs")
            pages = self._json(f"repos/{repository}/releases/{release_id}/assets?per_page=100", "--paginate", "--slurp")
            assets = {}
            for page in pages:
                if not isinstance(page, list):
                    raise PreparationError("Invalid asset metadata page")
                for item in page:
                    if item.get("name") in assets:
                        raise PreparationError("Duplicate original asset name")
                    assets[item["name"]] = item
            self.releases[key] = {"tag": tag, "draft": release["draft"], "assets": assets}
        if self.releases[key]["tag"] != tag:
            raise PreparationError("Frozen release tag changed")
        return self.releases[key]["assets"]

    def ref(self, repository, release_id, tag, name):
        item = self.release_assets(repository, release_id, tag).get(name)
        if (not item or item.get("state") != "uploaded" or type(item.get("id")) is not int or
                not isinstance(item.get("digest"), str) or not item["digest"].startswith("sha256:")):
            raise PreparationError("Original immutable asset metadata is unavailable")
        ref = asset_ref({"release_repository": repository, "release_tag": tag, "release_id": release_id,
                         "asset_id": item["id"], "name": name, "sha256": item["digest"][7:], "bytes": item["size"]})
        expected = f"https://github.com/{repository}/releases/download/{tag}/{name}"
        actual = item.get("browser_download_url")
        if self.releases[repository, release_id]["draft"]:
            # GitHub exposes draft assets under an untagged URL. This URL is
            # descriptive only: draft reads use the authenticated numeric ID.
            parsed = urllib.parse.urlsplit(actual) if isinstance(actual, str) else None
            prefix = f"/{repository}/releases/download/"
            if (parsed is None or parsed.scheme != "https" or parsed.netloc != "github.com" or
                    parsed.query or parsed.fragment or not parsed.path.startswith(prefix) or
                    parsed.path[len(prefix):].split("/")[-1:] != [name] or
                    len(parsed.path[len(prefix):].split("/")) != 2):
                raise PreparationError("Original draft asset locator differs")
        elif actual != expected:
            raise PreparationError("Original public asset URL differs")
        self.urls[repository, ref["asset_id"]] = expected
        return ref

    def _url(self, ref):
        current = self.ref(ref["release_repository"], ref["release_id"], ref["release_tag"], ref["name"])
        if current != asset_ref(ref):
            raise PreparationError("Frozen asset metadata differs")
        return self.urls[ref["release_repository"], ref["asset_id"]]

    def read_json(self, ref):
        ref = asset_ref(ref)
        if not ref["name"].endswith(".json") or ref["bytes"] > MAX_JSON_BYTES:
            raise PreparationError("Not a bounded public JSON asset")
        url = self._url(ref)
        request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
        response = self._authenticated(ref) if self.releases[ref["release_repository"], ref["release_id"]]["draft"] else self.opener.open(request, timeout=60)
        with response:
            if response.status != 200 or response.headers.get("Content-Length") not in (None, str(ref["bytes"])):
                raise PreparationError("Public JSON response size differs")
            blocks, remaining = [], ref["bytes"]
            while remaining:
                block = response.read(remaining)
                if not isinstance(block, bytes) or not block or len(block) > remaining:
                    raise PreparationError("Public JSON response is truncated or oversized")
                blocks.append(block)
                remaining -= len(block)
            raw = b"".join(blocks)
        if len(raw) != ref["bytes"] or sha256(raw) != ref["sha256"]:
            raise PreparationError("Public JSON digest differs")
        metadata(raw)
        return raw

    def open_range(self, ref, start, end):
        if (type(start) is not int or type(end) is not int or not 0 <= start <= end < MAX_AAD_BYTES or
                end >= ref["bytes"]):
            raise RangeReadError("Range is outside the bounded envelope prefix")
        url = self._url(ref)
        if self.releases[ref["release_repository"], ref["release_id"]]["draft"]:
            return self._authenticated(ref, start, end)
        request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}", "Accept": "application/octet-stream"})
        return self.opener.open(request, timeout=60)

    def _authenticated(self, ref, start=None, end=None):
        command = ["gh", "api", f"repos/{ref['release_repository']}/releases/assets/{ref['asset_id']}",
                   "--hostname", "github.com", "-H", "Accept: application/octet-stream", "--include"]
        if start is not None:
            command.extend(["-H", f"Range: bytes={start}-{end}"])
        return _GhResponse(command, body_limit=ref["bytes"] if start is None else end - start + 1, popen=self.popen)


def _range(reader, ref, start, end):
    count = end - start + 1
    with reader.open_range(ref, start, end) as response:
        # A 200 is rejected before reading its body, never drained by gh.
        if (response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{end}/{ref['bytes']}" or
                response.headers.get("Content-Length") not in (None, str(count))):
            raise RangeReadError("Original asset did not honor the exact bounded range")
        blocks, remaining = [], count
        while remaining:
            block = response.read(remaining)
            if not isinstance(block, bytes) or not block or len(block) > remaining:
                raise RangeReadError("Truncated or oversized header range")
            blocks.append(block)
            remaining -= len(block)
    return b"".join(blocks)


def envelope_header(reader, ref):
    ref = asset_ref(ref)
    prefix = _range(reader, ref, 0, 12)
    total = envelope_aad_size(prefix)
    if not 13 < total <= MAX_AAD_BYTES or total + 16 > ref["bytes"]:
        raise RangeReadError("Invalid bounded envelope size")
    aad = prefix + _range(reader, ref, 13, total - 1)
    return read_envelope_aad(io.BytesIO(aad))


def _location(row, inventory_ref):
    repository = row.get("source_release_repository") or inventory_ref["release_repository"]
    identifier = row.get("source_release_id") or inventory_ref["release_id"]
    tag = row.get("source_release_tag") or inventory_ref["release_tag"]
    if (not isinstance(repository, str) or not REPO_RE.fullmatch(repository) or any(part in (".", "..") for part in repository.split("/")) or
            type(identifier) is not int or identifier <= 0 or not isinstance(tag, str) or not NAME.fullmatch(tag)):
        raise PreparationError("Invalid original release location")
    return repository, identifier, tag


def _aliases(row):
    values = row.get("archive_transport_aliases") or []
    result = {}
    for value in values:
        if (not isinstance(value, dict) or not {"plaintext", "ciphertext"} <= set(value) or
                set(value) - {"plaintext", "ciphertext", "recipient", "source_asset_id"} or
                any(set(value[key]) != {"name", "sha256", "bytes"} for key in ("plaintext", "ciphertext"))):
            raise PreparationError("Unexpected original transport alias metadata")
        if value.get("recipient") is not None and (not isinstance(value["recipient"], str) or not HASH.fullmatch(value["recipient"])):
            raise PreparationError("Invalid original transport recipient")
        if value.get("source_asset_id") is not None and (type(value["source_asset_id"]) is not int or value["source_asset_id"] <= 0):
            raise PreparationError("Invalid original transport source ID")
        name = value["plaintext"]["name"]
        if name in result:
            raise PreparationError("Duplicate frozen transport alias")
        result[name] = copy.deepcopy(value)
    return result


def _sealed_asset(ref, row, inventory, inventory_ref):
    values = row.get("verified_archive_assets") or []
    if _location(row, inventory_ref) == (inventory_ref["release_repository"], inventory_ref["release_id"], inventory_ref["release_tag"]):
        values = inventory.get("assets_observed_before_final_inventory", [])
    found = next((item for item in values if item.get("name") == ref["name"]), None)
    if found is not None:
        digest = found.get("sha256") or str(found.get("digest", "")).removeprefix("sha256:")
        if (found.get("id") != ref["asset_id"] or (found.get("bytes", found.get("size"))) != ref["bytes"] or
                digest != ref["sha256"]):
            raise PreparationError("Asset differs from the sealed inventory")


def freeze_sources(inventory_raw, inventory_sha256, inventory_ref, config_path, csv_path, reader, *, expected_count=EXPECTED_REPOSITORIES):
    """Metadata-only phase: freeze exact original index and part asset refs."""
    inventory = metadata(inventory_raw, inventory_sha256)
    inventory_ref = asset_ref(inventory_ref)
    if inventory_ref["sha256"] != inventory_sha256 or inventory_ref["bytes"] != len(inventory_raw) or inventory_ref["release_tag"] != inventory["release_tag"]:
        raise PreparationError("Sealed inventory asset identity differs")
    slugs = cohort(config_path, csv_path, inventory, expected_count=expected_count)
    rows = []
    for slug, source in zip(slugs, inventory["repositories"]):
        row = {"slug": slug, "source_index": None, "parts": [], "transport_index": None}
        rows.append(row)
        if not source.get("index_sha256"):
            continue
        repository, release_id, tag = _location(source, inventory_ref)
        ref = reader.ref(repository, release_id, tag, source["index_asset"])
        if ref["sha256"] != source["index_sha256"] or (source.get("source_index_asset_id") is not None and ref["asset_id"] != source["source_index_asset_id"]):
            raise PreparationError("Original index reference differs")
        _sealed_asset(ref, source, inventory, inventory_ref)
        index = metadata(reader.read_json(ref), ref["sha256"])
        row["source_index"] = ref
        if source.get("transport_index_asset"):
            row["transport_index"] = reader.ref(repository, release_id, tag, source["transport_index_asset"])
            if (row["transport_index"]["asset_id"] != source["transport_index_asset_id"] or
                    row["transport_index"]["sha256"] != source["transport_index_sha256"]):
                raise PreparationError("Original transport index reference differs")
        if not (index.get("archive") or {}).get("parts"):
            continue
        normalized = normalize_legacy_parts(index, _aliases(source))
        for part in normalized:
            cipher = part["ciphertext"]
            part_ref = reader.ref(repository, release_id, tag, cipher["name"])
            if any(part_ref[key] != cipher[key] for key in ("name", "sha256", "bytes")):
                raise PreparationError("Original ciphertext identity differs")
            _sealed_asset(part_ref, source, inventory, inventory_ref)
            row["parts"].append(part_ref)
    if sum(len(row["parts"]) for row in rows) > MAX_PARTS:
        raise PreparationError("Too many original parts for a bounded preparation")
    return canonical_json({"schema_version": 1, "kind": "icsot_legacy_source_catalog",
                           "inventory_asset": inventory_ref, "inventory_sha256": inventory_sha256,
                           "repositories": rows})


def _manifest(index, source):
    manifests = index.get("manifests") or []
    if manifests != (source.get("manifests") or []):
        raise PreparationError("Original manifest metadata differs from sealed inventory")
    if len(manifests) != 1:
        return None
    item = manifests[0]
    if (type(item.get("repository_id")) is not int or item["repository_id"] <= 0 or
            not isinstance(item.get("sha256"), str) or not HASH.fullmatch(item["sha256"]) or
            not isinstance(item.get("run_id"), str) or not NAME.fullmatch(item["run_id"]) or
            item.get("path") != f"runs/{item['repository_id']}/{item['run_id']}.manifest.json"):
        raise PreparationError("Invalid original manifest identity")
    if (source.get("repository_id") is not None and source["repository_id"] != item["repository_id"] or
            index.get("repository_id") not in (None, item["repository_id"]) or
            (index.get("collector_result") or {}).get("repository_id") not in (None, item["repository_id"])):
        raise PreparationError("Original numeric repository identity differs")
    result = index.get("collector_result") or {}
    if result.get("run_id") not in (None, item["run_id"]) or result.get("manifest_sha256") not in (None, item["sha256"]):
        raise PreparationError("Original collector/manifest identity differs")
    times = []
    for key in ("started_at", "finished_at"):
        value = item.get(key)
        if value is None:
            times.append(None)
            continue
        try:
            instant = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else None
            if instant is None or instant.utcoffset() is None or instant.utcoffset().total_seconds() != 0:
                raise ValueError()
        except (ValueError, TypeError):
            raise PreparationError("Original public observation time is not UTC") from None
        times.append(instant)
    if times[0] is not None and times[1] is not None and times[0] > times[1]:
        raise PreparationError("Original observation interval is reversed")
    return {key: item.get(key) for key in ("path", "sha256", "run_id", "started_at", "finished_at", "status", "mode")}


def _candidates(inventory, sources, slugs, reader):
    if ([row.get("slug") for row in sources.get("repositories", [])] != list(slugs) or
            sources.get("kind") != "icsot_legacy_source_catalog" or sources.get("schema_version") != 1):
        raise PreparationError("Source catalog differs from ordered cohort")
    inventory_ref = asset_ref(sources["inventory_asset"])
    candidates, seen_ids, transport_cache = [], set(), {}
    for slug, source, frozen in zip(slugs, inventory["repositories"], sources["repositories"]):
        row = {"slug": slug, "repository_id": None, "source_index": None, "source_manifest": None,
               "source_collector_code_sha": None, "candidate_kind": "repair_required", "candidate_git": False,
               "candidate_api": False, "parts": [], "reason_codes": [], "migration_index": None,
               "source_capture_status": source.get("capture_status")}
        candidate = {"row": row, "parts": [], "source_complete": source.get("complete") is True}
        candidates.append(candidate)
        if frozen.get("source_index") is None:
            if source.get("index_sha256"):
                raise PreparationError("Frozen source catalog omitted an original index")
            row["reason_codes"] = ["source_index_unavailable"]
            continue
        ref = asset_ref(frozen["source_index"])
        if (ref["sha256"] != source.get("index_sha256") or ref["name"] != source.get("index_asset") or
                (ref["release_repository"], ref["release_id"], ref["release_tag"]) != _location(source, inventory_ref) or
                source.get("source_index_asset_id") not in (None, ref["asset_id"])):
            raise PreparationError("Frozen original source index differs")
        _sealed_asset(ref, source, inventory, inventory_ref)
        raw = reader.read_json(ref)
        if len(raw) != ref["bytes"]:
            raise PreparationError("Original index length differs")
        index = metadata(raw, ref["sha256"])
        expected_code = source.get("collector_code_sha") or inventory["collector_code_sha"]
        if not isinstance(expected_code, str) or not CODE.fullmatch(expected_code):
            raise PreparationError("Invalid original collector code identity")
        if (index.get("repository") != slug or index.get("release_tag") != ref["release_tag"] or
                index.get("release_repository", ref["release_repository"]) != ref["release_repository"] or
                index.get("collector_code_sha") != expected_code or
                any(index.get(key) != inventory.get(key) for key in ("config_source_sha256", "csv_sha256", "cohort_count"))):
            raise PreparationError("Original source index identity differs")
        if source.get("complete") is True and (index.get("complete") is not True or index.get("capture_accepted") is not True):
            raise PreparationError("Original accepted-source disposition is inconsistent")
        row.update(source_index=ref, source_collector_code_sha=expected_code, source_manifest=_manifest(index, source))
        if row["source_manifest"] is None:
            row["reason_codes"] = ["source_manifest_unavailable"]
            continue
        repo_id = index["manifests"][0]["repository_id"]
        if repo_id in seen_ids:
            raise PreparationError("Duplicate original numeric repository identity")
        seen_ids.add(repo_id)
        row["repository_id"] = repo_id
        aliases = _aliases(source)
        transport = frozen.get("transport_index")
        if aliases:
            transport = asset_ref(transport)
            if (transport["sha256"] != source.get("transport_index_sha256") or transport["asset_id"] != source.get("transport_index_asset_id") or
                    transport["name"] != source.get("transport_index_asset") or
                    any(transport[key] != ref[key] for key in ("release_repository", "release_tag", "release_id"))):
                raise PreparationError("Frozen migration metadata differs")
            if transport["sha256"] not in transport_cache:
                transport_cache[transport["sha256"]] = metadata(reader.read_json(transport), transport["sha256"])
            original_aliases = transport_cache[transport["sha256"]].get("parts", {})
            if any(original_aliases.get(name) != value for name, value in aliases.items()):
                raise PreparationError("Original migration aliases differ")
            row["migration_index"] = transport
        archive = index.get("archive") or {}
        if archive.get("complete") is not True or not archive.get("parts"):
            row["reason_codes"] = ["source_archive_incomplete"]
            continue
        normalized = normalize_legacy_parts(index, aliases)
        if len(normalized) != len(frozen.get("parts", [])):
            raise PreparationError("Frozen original part count differs")
        for ordinal, (part, frozen_part) in enumerate(zip(normalized, frozen["parts"]), 1):
            part_ref = asset_ref(frozen_part)
            cipher = part["ciphertext"]
            if (any(part_ref[key] != cipher[key] for key in ("name", "sha256", "bytes")) or
                    any(part_ref[key] != ref[key] for key in ("release_repository", "release_id", "release_tag"))):
                raise PreparationError("Frozen original part identity differs")
            _sealed_asset(part_ref, source, inventory, inventory_ref)
            binding = {"repository_id": repo_id, "repository": slug, "release_repository": part_ref["release_repository"],
                       "release_id": part_ref["release_id"], "release_tag": part_ref["release_tag"], "asset_id": part_ref["asset_id"],
                       "asset_name": part_ref["name"], "part_number": ordinal, "part_count": len(normalized),
                       "sealed_index_sha256": ref["sha256"], "ciphertext_sha256": cipher["sha256"], "ciphertext_bytes": cipher["bytes"]}
            original = archive["parts"][ordinal - 1]
            enc = original.get("encryption") or {}
            candidate["parts"].append({"binding": binding, "asset": part_ref, "plaintext": part["plaintext"],
                "transport_alias": copy.deepcopy(aliases.get(part["plaintext"]["name"])),
                "expected_owner": enc.get("public_key_fingerprint_sha256") or (aliases.get(part["plaintext"]["name"]) or {}).get("recipient") or archive.get("recipient_spki_sha256"),
                "expected_header": enc.get("original_header_sha256", enc.get("header_sha256")),
                "expected_aad": enc.get("original_aad_sha256", enc.get("aad_sha256"))})
        verification = index.get("verification") or {}
        row.update(candidate_kind="accepted_baseline" if source.get("complete") is True else "partial_baseline",
                   candidate_git=bool(index["manifests"][0].get("portable_full_bundle") and verification.get("portable_git_bundles_verified", 0) > 0),
                   candidate_api=verification.get("raw_observations", 0) > 0)
    if sum(len(item["parts"]) for item in candidates) > MAX_PARTS:
        raise PreparationError("Original part count exceeds the preparation bound")
    return candidates


@contextmanager
def output_lock(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise PreparationError("Output directory may not be a symlink")
    fd = os.open(directory / ".prepare.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def _same_or_create(path: Path, raw: bytes):
    if path.exists() or path.is_symlink():
        if local_bytes(path) != raw:
            raise PreparationError("Create-only output already has different bytes")
    else:
        write_once(path, raw)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _public_context(document):
    return document["context"]


def _fresh_repairs(inventory_sha256, supplied):
    if supplied is None:
        return {}
    if inventory_sha256 != FRESH_REPAIR_INVENTORY or supplied != FRESH_REPAIR_IDENTITIES:
        raise PreparationError("Fresh repair is outside the explicitly authorized inventory and identity set")
    return dict(supplied)


def _prepared_part(part, *, reader, recipient, owner_key, operational_key, directory, password=None):
    binding = part["binding"]
    key = sha256(canonical_json({"binding": binding, "operational_recipient_spki_sha256": recipient}))
    name = f"capsule-{key}.json"
    committed = directory / "capsules" / key
    if committed.is_symlink():
        raise PreparationError("Unsafe existing encrypted output")
    if committed.is_dir() and not any(committed.iterdir()):
        # A crash after the exclusive name claim but before atomic rename can
        # leave only an empty directory. The caller holds the output lock.
        # Never remove or replace a nonempty capsule/receipt directory.
        committed.rmdir()
    aad = envelope_header(reader, part["asset"])
    header = inspect_envelope_aad(aad)
    if (header["plaintext_sha256"] != part["plaintext"]["sha256"] or
            header["plaintext_bytes"] != part["plaintext"]["bytes"] or
            header["ciphertext_bytes"] != binding["ciphertext_bytes"] or
            header["owner_key_fingerprint_sha256"] == recipient):
        raise PreparationError("Original header plaintext/recipient/size identity differs")
    for expected, actual in ((part["expected_owner"], header["owner_key_fingerprint_sha256"]),
                             (part["expected_header"], header["original_header_sha256"]),
                             (part["expected_aad"], header["original_aad_sha256"])):
        if expected is not None and expected != actual:
            raise PreparationError("Original header digest or recipient differs")
    if committed.exists():
        if committed.is_symlink():
            raise PreparationError("Unsafe existing encrypted output")
        receipt = metadata(local_bytes(committed / "receipt.json"))
        raw = local_bytes(committed / name, MAX_CAPSULE_BYTES)
        context = _public_context(inspect_capsule(raw))
        if (receipt.get("sha256") != sha256(raw) or receipt.get("bytes") != len(raw) or receipt.get("name") != name or
                any(context.get(field) != value for field, value in binding.items()) or
                context["operational_key_fingerprint_sha256"] != recipient or
                any(context[field] != header[field] for field in ("original_header_sha256", "original_aad_sha256", "owner_key_fingerprint_sha256"))):
            raise PreparationError("Existing encrypted capsule or receipt differs")
        return {"name": name, "sha256": sha256(raw), "bytes": len(raw)}
    # The only plaintext key operation is inside this function. Only its
    # already-encrypted return value and public metadata reach the filesystem.
    raw = create_capsule(aad, binding=binding, owner_private_key_path=owner_key,
                         operational_public_key_path=operational_key, password=password)
    context = _public_context(inspect_capsule(raw))
    if context["operational_key_fingerprint_sha256"] != recipient or any(context.get(field) != value for field, value in binding.items()):
        raise PreparationError("Created capsule context differs")
    descriptor = {"name": name, "sha256": sha256(raw), "bytes": len(raw)}
    staging = directory / ".staging"
    staging.mkdir(exist_ok=True)
    (directory / "capsules").mkdir(exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="encrypted-", dir=staging))
    try:
        write_once(temporary / name, raw)
        write_once(temporary / "receipt.json", canonical_json({**descriptor, "context": context,
                   "prepared_at": utc_iso(), "clock_source": "local_system_clock"}))
        _sync_directory(temporary)
        # The output lock serializes writers. A committed directory is never
        # replaced; a crash before rename leaves only encrypted staging bytes.
        if committed.exists():
            raise PreparationError("Create-only part directory already exists")
        # Claim the final name with exclusive mkdir as well, closing an empty
        # directory collision between the earlier check and publication.
        committed.mkdir()
        os.rename(temporary, committed)
        _sync_directory(directory / "capsules")
        _sync_directory(directory)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return descriptor


def prepare(inventory_raw, inventory_sha256, sources_raw, sources_sha256, *, config_path, csv_path, reader,
            owner_private_key_path, operational_public_key_path, output_directory, budget,
            capsule_release_repository, capsule_release_tag, ready_states=None, password=None,
            fresh_repairs=None,
            expected_count=EXPECTED_REPOSITORIES):
    """Create immutable encrypted outputs; return a qualified unpublished catalog.

    All source identities are validated before the first owner-key operation.
    Header/network failures affect one row and produce an immutable partial
    catalog. A restart reuses complete encrypted part directories byte-for-byte.
    """
    inventory = metadata(inventory_raw, inventory_sha256)
    sources = metadata(sources_raw, sources_sha256)
    if sources.get("inventory_sha256") != inventory_sha256:
        raise PreparationError("Source catalog refers to another sealed inventory")
    inventory_ref = asset_ref(sources["inventory_asset"])
    if inventory_ref["sha256"] != inventory_sha256 or inventory_ref["bytes"] != len(inventory_raw):
        raise PreparationError("Sealed inventory asset context differs")
    slugs = cohort(config_path, csv_path, inventory, expected_count=expected_count)
    # This completes metadata validation for the whole batch before loading the
    # owner private key. No original payload is fetched in this phase.
    candidates = _candidates(inventory, sources, slugs, reader)
    fresh = _fresh_repairs(inventory_sha256, fresh_repairs)
    recipient = public_key_fingerprint(operational_public_key_path)
    if (not REPO_RE.fullmatch(capsule_release_repository) or any(part in (".", "..") for part in capsule_release_repository.split("/")) or
            not NAME.fullmatch(capsule_release_tag) or len(capsule_release_tag) > 249):
        raise PreparationError("Invalid capsule publication destination")
    ready = {str(key): value for key, value in (ready_states or {}).items()}
    known_ids = {str(item["row"]["repository_id"]) for item in candidates if item["row"]["repository_id"] is not None}
    if any(key not in known_ids or not isinstance(value, str) or not HASH.fullmatch(value) for key, value in ready.items()):
        raise PreparationError("Ready-state snapshot differs from verified source identities")
    intent_identity = {"schema_version": 1, "inventory_sha256": inventory_sha256, "sources_sha256": sources_sha256,
        "config_source_sha256": inventory["config_source_sha256"], "csv_sha256": inventory["csv_sha256"],
        "operational_recipient_spki_sha256": recipient, "capsule_release_repository": capsule_release_repository,
        "capsule_release_tag": capsule_release_tag, "ready_states": ready, "fresh_repairs": fresh}
    requested_directory = Path(output_directory).absolute()
    if requested_directory.is_symlink():
        raise PreparationError("Output directory may not be a symlink")
    directory = requested_directory.resolve()
    count = sum(len(item["parts"]) for item in candidates
                if str(item["row"]["repository_id"]) not in ready and item["row"]["slug"] not in fresh)
    # Account for encrypted capsule + public receipt directories, two catalog
    # snapshots and filesystem overhead. Runtime admission is the caller's
    # separate reservation; the CLI reserves it before starting cached Python.
    additional = count * (MAX_CAPSULE_BYTES + 32768) + 4 * MAX_JSON_BYTES + 131072
    with budget.reserve(additional, purpose="encrypted legacy capsules and immutable public preparation catalogs") as reservation:
        if not directory.exists():
            reservation.track(directory)
        else:
            budget.register_root(directory)
        with output_lock(directory):
            if any((directory / name).is_symlink() for name in ("capsules", ".staging")):
                raise PreparationError("Preparation control directories may not be symlinks")
            intent_path = directory / "intent.json"
            if intent_path.exists():
                intent = metadata(local_bytes(intent_path))
                if intent.get("identity") != intent_identity:
                    raise PreparationError("Preparation inputs changed; use a new output directory")
            else:
                intent = {"identity": intent_identity, "preparation_started_at": utc_iso()}
                write_once(intent_path, canonical_json(intent))
            rows, failures, prepared, offset = [], 0, 0, 0
            for candidate in candidates:
                row = copy.deepcopy(candidate["row"])
                rows.append(row)
                start_offset = offset
                offset += len(candidate["parts"])
                if row["slug"] in fresh:
                    row.update(candidate_api=False, candidate_git=False, parts=[], requested_strategy="fresh_repair",
                               fresh_repair_repository_id=fresh[row["slug"]],
                               reason_codes=[*row["reason_codes"], "explicit_fresh_repair"])
                    continue
                if str(row["repository_id"]) in ready:
                    row.update(candidate_api=False, candidate_git=False, parts=[], reason_codes=["already_operational"],
                               prep_ready_state_pointer_sha256=ready[str(row["repository_id"])])
                    continue
                if not candidate["parts"]:
                    continue
                complete_parts = []
                try:
                    for part_index, part in enumerate(candidate["parts"]):
                        descriptor = _prepared_part(part, reader=reader, recipient=recipient, owner_key=owner_private_key_path,
                            operational_key=operational_public_key_path, directory=directory, password=password)
                        complete_parts.append({"binding": part["binding"], "capsule": {
                            "release_repository": capsule_release_repository,
                            "release_tag": f"{capsule_release_tag}-{(start_offset + part_index) // 900 + 1:04d}",
                            "release_id": None, "asset_id": None, **descriptor}, "transport_alias": part["transport_alias"]})
                        prepared += 1
                except Exception as error:
                    failures += 1
                    row.update(candidate_kind="repair_required", candidate_api=False, candidate_git=False, parts=[],
                               reason_codes=["capsule_preparation_failed"], preparation_error_type=type(error).__name__)
                    continue
                row["parts"] = complete_parts
            catalog = {"schema_version": 1, "kind": "icsot_legacy_capsule_catalog", "publication_status": "unpublished",
                "preparation_status": "partial" if failures else "complete", "inventory_sha256": inventory_sha256,
                "inventory_asset": inventory_ref, "sources_sha256": sources_sha256,
                "operational_recipient_spki_sha256": recipient, "preparation_started_at": intent["preparation_started_at"],
                "preparation_clock_source": "local_system_clock",
                "config_source_sha256": inventory["config_source_sha256"], "csv_sha256": inventory["csv_sha256"],
                "repositories": rows}
            catalog["migration_id"] = migration_id(catalog)
            validate_catalog(catalog, tuple(slugs), allow_unpublished=True)
            raw = canonical_json(catalog)
            if len(raw) > MAX_JSON_BYTES:
                raise PreparationError("Public capsule catalog exceeds its bound")
            digest = sha256(raw)
            path = directory / f"catalog-{digest}.json"
            _same_or_create(path, raw)
            _same_or_create(directory / f"catalog-{digest}.sha256", (digest + "\n").encode())
            # Upload only these encrypted capsule files, never receipt.json,
            # copied original indexes, or previous partial catalogs.
            files = []
            seen_names = set()
            for row in rows:
                for part in row["parts"]:
                    ref = part["capsule"]
                    if ref["name"] in seen_names:
                        continue
                    seen_names.add(ref["name"])
                    key = ref["name"].removeprefix("capsule-").removesuffix(".json")
                    files.append({"relative_path": f"capsules/{key}/{ref['name']}", "asset": ref})
            publication_files = canonical_json({"schema_version": 1, "kind": "icsot_encrypted_capsule_publication_files",
                                                "catalog_sha256": digest, "files": files})
            publication_path = directory / f"publication-files-{digest}.json"
            _same_or_create(publication_path, publication_files)
            reservation.check()
            return {"catalog": catalog, "catalog_path": path, "catalog_sha256": digest,
                    "publication_files_path": publication_path, "prepared_parts": prepared, "failed_rows": failures}


def bind_publication(catalog_raw, catalog_sha256, published_refs):
    """Fill verified public AssetRefs after a separately authorized upload.

    No network writes occur here. The logical migration identity intentionally
    excludes capsule publication locations/IDs, while retaining their hashes.
    """
    catalog = metadata(catalog_raw, catalog_sha256)
    if catalog.get("kind") != "icsot_legacy_capsule_catalog" or catalog.get("publication_status") != "unpublished":
        raise PreparationError("Expected an unpublished capsule catalog")
    expected = {part["capsule"]["name"]: part["capsule"] for row in catalog["repositories"] for part in row["parts"]}
    if set(published_refs) != set(expected):
        raise PreparationError("Published capsule set differs")
    for row in catalog["repositories"]:
        for part in row["parts"]:
            old = part["capsule"]
            current = asset_ref(published_refs[old["name"]])
            if any(current[key] != old[key] for key in ("sha256", "bytes")):
                raise PreparationError("Published encrypted capsule identity differs")
            part["capsule"] = current
    catalog["publication_status"] = "published"
    if migration_id(catalog) != catalog["migration_id"]:
        raise PreparationError("Publication changed the logical migration identity")
    validate_catalog(catalog, tuple(row["slug"] for row in catalog["repositories"]))
    return canonical_json(catalog)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("freeze-sources", "prepare", "bind-publication"):
        child = commands.add_parser(name)
        child.add_argument("--budget-root", type=Path, required=True,
                           help="The SAME canonical shared local-data-budget directory used by other task clients")
        if name != "bind-publication":
            child.add_argument("--inventory", type=Path, required=True)
            child.add_argument("--inventory-sha256", required=True)
            child.add_argument("--config", type=Path, required=True)
            child.add_argument("--csv", type=Path, required=True)
        if name == "freeze-sources":
            child.add_argument("--release-repository", required=True)
            child.add_argument("--release-id", type=int, required=True)
            child.add_argument("--inventory-asset-id", type=int, required=True)
            child.add_argument("--output", type=Path, required=True)
        elif name == "prepare":
            child.add_argument("--sources", type=Path, required=True)
            child.add_argument("--sources-sha256", required=True)
            child.add_argument("--owner-private-key", type=Path, required=True)
            child.add_argument("--operational-public-key", type=Path, required=True)
            child.add_argument("--capsule-release-repository", required=True)
            child.add_argument("--capsule-release-tag", required=True, help="Immutable publication tag prefix; shard suffixes are automatic")
            child.add_argument("--ready-states", type=Path)
            child.add_argument("--ready-states-sha256")
            child.add_argument("--fresh-repairs", type=Path,
                               help="Hash-pinned explicit repair authorization; only the sealed inventory/three approved identities are accepted")
            child.add_argument("--fresh-repairs-sha256")
            child.add_argument("--output-directory", type=Path, required=True)
        else:
            child.add_argument("--catalog", type=Path, required=True)
            child.add_argument("--catalog-sha256", required=True)
            child.add_argument("--published-refs", type=Path, required=True)
            child.add_argument("--published-refs-sha256", required=True)
            child.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    budget = LocalBudget(args.budget_root)
    reader = GitHubReader()
    if args.command == "bind-publication":
        catalog_raw = local_bytes(args.catalog)
        published = metadata(local_bytes(args.published_refs), args.published_refs_sha256)
        for ref in published.values():
            ref = asset_ref(ref)
            if reader.ref(ref["release_repository"], ref["release_id"], ref["release_tag"], ref["name"]) != ref:
                raise PreparationError("Published capsule metadata differs")
        raw = bind_publication(catalog_raw, args.catalog_sha256, published)
    else:
        inventory_raw = local_bytes(args.inventory)
        inventory = metadata(inventory_raw, args.inventory_sha256)
        if args.command == "freeze-sources":
            original = asset_ref({"release_repository": args.release_repository, "release_tag": inventory["release_tag"],
                "release_id": args.release_id, "asset_id": args.inventory_asset_id, "name": "baseline-inventory.json",
                "sha256": args.inventory_sha256, "bytes": len(inventory_raw)})
            if reader.ref(args.release_repository, args.release_id, inventory["release_tag"], original["name"]) != original:
                raise PreparationError("Original inventory publication differs")
            raw = freeze_sources(inventory_raw, args.inventory_sha256, original, args.config, args.csv, reader)
        else:
            ready = None
            if args.ready_states:
                if not args.ready_states_sha256:
                    parser.error("--ready-states-sha256 is required with --ready-states")
                ready = metadata(local_bytes(args.ready_states), args.ready_states_sha256).get("states")
                if not isinstance(ready, dict):
                    raise PreparationError("Expected a hash-pinned ready-state snapshot")
            fresh = None
            if args.fresh_repairs:
                if not args.fresh_repairs_sha256:
                    parser.error("--fresh-repairs-sha256 is required with --fresh-repairs")
                authorization = metadata(local_bytes(args.fresh_repairs), args.fresh_repairs_sha256)
                if (set(authorization) != {"inventory_sha256", "repositories"} or
                        authorization["inventory_sha256"] != args.inventory_sha256):
                    raise PreparationError("Fresh repair authorization refers to another sealed inventory")
                fresh = authorization["repositories"]
            result = prepare(inventory_raw, args.inventory_sha256, local_bytes(args.sources), args.sources_sha256,
                config_path=args.config, csv_path=args.csv, reader=reader,
                owner_private_key_path=args.owner_private_key, operational_public_key_path=args.operational_public_key,
                output_directory=args.output_directory, budget=budget,
                capsule_release_repository=args.capsule_release_repository, capsule_release_tag=args.capsule_release_tag,
                ready_states=ready, fresh_repairs=fresh)
            print(json.dumps({"catalog_sha256": result["catalog_sha256"], "migration_id": result["catalog"]["migration_id"],
                "repository_rows": len(result["catalog"]["repositories"]), "prepared_parts": result["prepared_parts"],
                "failed_rows": result["failed_rows"],
                "repair_rows": sum(row["candidate_kind"] == "repair_required" for row in result["catalog"]["repositories"]),
                "already_operational_rows": sum("already_operational" in row["reason_codes"] for row in result["catalog"]["repositories"]),
                "explicit_fresh_repair_rows": sum(row.get("requested_strategy") == "fresh_repair" for row in result["catalog"]["repositories"]),
                "publication_status": "unpublished"}, sort_keys=True))
            return 2 if result["failed_rows"] else 0
    with budget.reserve(MAX_JSON_BYTES + 65536, purpose="create-only public migration metadata") as reservation:
        if not args.output.exists():
            reservation.track(args.output)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _same_or_create(args.output, raw)
        reservation.check()
    print(json.dumps({"sha256": sha256(raw), "bytes": len(raw), "remote_writes": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # No exception message, body, header, private key path or key contents.
        name = type(error).__name__
        print(json.dumps({"status": "failed", "error_type": name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name) else "Error"}), file=__import__("sys").stderr)
        raise SystemExit(1)
