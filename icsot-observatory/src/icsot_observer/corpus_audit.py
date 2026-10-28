"""Read-only recovery audit of an explicitly approved baseline release lineage.

Payloads are streamed through the shared authenticated archive reader.  Full
Git graph checks are deliberately limited to deterministic small samples on an
enforced, fixed-size native volume; a successful byte audit is not a Git fsck.
"""
from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
import plistlib
import re
import select
import signal
import stat
import struct
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

from .archive_reader import ArchivePart, VerifiedArchiveReader, reader_options, verify_encrypted_part
from .attestations import AttestationDependencyError, inspect_ots_receipt
from .checks import _git_namespace
from .core import Config, REPO_RE, canonical_json, sha256, utc_iso
from .gitstore import _valid_refname, _validate_oid
from .localbudget import BudgetError, LocalBudget
from .encryption import decrypt_file

TAG_RE = re.compile(r"corpus-baseline-(\d+)-(\d+)\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
CAS_RE = re.compile(r"evidence/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})\Z")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_METADATA_TOTAL = 64 * 1024 * 1024
DEFAULT_BUNDLE_LIMIT = 16 * 1024 * 1024
DEFAULT_VOLUME_BYTES = 256 * 1024 * 1024
# Capture implementation identities when the watcher imports this code, rather
# than attributing a long-running process to files edited later in its checkout.
AUDIT_IMPLEMENTATION = {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
    "corpus_audit.py", "archive_reader.py", "localbudget.py", "encryption.py", "checks.py", "gitstore.py", "attestations.py")}


class ReadOnlyTransferError(RuntimeError):
    """An unavailable GET is an audit gap, not evidence of payload corruption."""


def safe_name(value: Any) -> str:
    if (not isinstance(value, str) or not value or value in {".", ".."} or
            any(char in value for char in "/\\\x00\r\n")):
        raise ValueError("Invalid asset name")
    return value


def identity(value: Any) -> dict:
    if (not isinstance(value, dict) or not isinstance(value.get("sha256"), str) or
            not SHA_RE.fullmatch(value["sha256"]) or type(value.get("bytes")) is not int or
            value["bytes"] < 0):
        raise ValueError("Invalid SHA-256/byte identity")
    return {"sha256": value["sha256"], "bytes": value["bytes"]}


def asset_identity(asset: dict, expected: dict) -> None:
    identity(expected)
    if asset.get("state") != "uploaded" or asset.get("size") != expected["bytes"]:
        raise ValueError("Remote asset is absent, incomplete, or the wrong length")
    if asset.get("digest") and asset["digest"] != "sha256:" + expected["sha256"]:
        raise ValueError("Remote SHA-256 differs from indexed identity")


def index_is_accepted(index: dict) -> bool:
    """Independently require the baseline's complete acceptance invariants."""
    result, verification, manifests = index.get("collector_result") or {}, index.get("verification") or {}, index.get("manifests") or []
    if (not isinstance(result, dict) or not isinstance(verification, dict) or not isinstance(manifests, list) or
            len(manifests) != 1 or not isinstance(manifests[0], dict)):
        return False
    manifest = manifests[0]
    bundle = manifest.get("portable_full_bundle") or {}
    return bool(
        index.get("complete") is True and index.get("capture_accepted") is True and
        index.get("status") == "complete_for_declared_shallow_baseline" and index.get("errors") == [] and
        result.get("status") == "complete" and result.get("repo") == index.get("repository") and
        result.get("attestation") == "pending_bitcoin_completion" and
        all(isinstance(result.get(key), str) and result[key] for key in ("proof", "immutable_initial_proof")) and
        result.get("manifest_sha256") == manifest.get("sha256") and
        isinstance(manifest.get("sha256"), str) and SHA_RE.fullmatch(manifest["sha256"]) and
        result.get("run_id") == manifest.get("run_id") and bool(manifest.get("run_id")) and
        result.get("repository_id") == manifest.get("repository_id") and type(manifest.get("repository_id")) is int and
        manifest.get("status") == "complete" and manifest.get("mode") == "full" and manifest.get("has_git") is True and
        isinstance(bundle, dict) and isinstance(bundle.get("sha256"), str) and SHA_RE.fullmatch(bundle["sha256"]) and
        type(bundle.get("bytes")) is int and bundle["bytes"] > 0 and
        verification.get("ok") is True and verification.get("errors") == [] and
        verification.get("manifests") == 1 and verification.get("portable_git_bundles_verified") == 1 and
        verification.get("git_repositories_verified") == 1 and verification.get("raw_observations", 0) > 0 and
        verification.get("partial_runs") == 0 and verification.get("unstamped_runs") == 0)


@dataclass(frozen=True)
class Cohort:
    repositories: tuple[str, ...]
    roles: dict[str, str]
    sources: dict


def load_cohort(config_path: Path, csv_path: Path, *, expected_count: int = 185) -> Cohort:
    config = Config.load(config_path)
    raw = csv_path.read_bytes()
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    slugs, roles = [], {}
    for row in rows:
        url = urlsplit(row["Repository_URL"])
        slug = url.path.strip("/")
        if (url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment or
                not REPO_RE.fullmatch(slug)):
            raise ValueError("Invalid CSV repository URL")
        slugs.append(slug)
        roles[slug] = row.get("Repository_Role", "unspecified")
    if tuple(slugs) != config.repositories or len(slugs) != expected_count:
        raise ValueError("Config and CSV must identify the complete expected cohort in order")
    return Cohort(tuple(slugs), roles, {"config_source_sha256": sha256(config_path.read_bytes()),
                  "csv_sha256": sha256(raw), "cohort_count": len(slugs)})


class GitHubReadOnly:
    """Only GET requests; payload writes go through a bounded caller-owned sink."""

    def __init__(self, repository: str):
        if not REPO_RE.fullmatch(repository):
            raise ValueError("Invalid release repository")
        self.repository = repository

    def _get(self, endpoint: str, target: BinaryIO, *, paginate: bool = False,
             maximum: int, binary: bool = False, timeout: int = 3600) -> int:
        arguments = ["gh", "api", endpoint]
        if paginate:
            arguments += ["--paginate", "--slurp"]
        if binary:
            arguments += ["-H", "Accept: application/octet-stream"]
        started, count = time.monotonic(), 0
        with subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                while True:
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise ReadOnlyTransferError("Read-only GitHub transfer exceeded its time bound")
                    ready, _, _ = select.select([process.stdout], [], [], min(remaining, 1.0))
                    if not ready:
                        continue
                    block = os.read(process.stdout.fileno(), 64 * 1024)
                    if not block:
                        break
                    count += len(block)
                    if count > maximum:
                        raise ValueError("Read-only GitHub transfer exceeded its byte bound")
                    target.write(block)
                if process.wait(timeout=max(1, timeout - (time.monotonic() - started))):
                    raise ReadOnlyTransferError("Read-only GitHub request failed")
            except BaseException:
                process.kill()
                process.wait()
                raise
        return count

    def json(self, endpoint: str, *, paginate: bool = False):
        target = io.BytesIO()
        self._get(endpoint, target, paginate=paginate, maximum=MAX_JSON_BYTES, timeout=120)
        return json.loads(target.getvalue())

    def release(self, tag: str) -> dict:
        if not TAG_RE.fullmatch(tag):
            raise ValueError("Invalid approved release tag")
        try:
            release = self.json(f"repos/{self.repository}/releases/tags/{tag}")
        except RuntimeError:
            pages = self.json(f"repos/{self.repository}/releases?per_page=100", paginate=True)
            matches = [item for page in pages for item in page if item.get("tag_name") == tag]
            if len(matches) != 1:
                raise ValueError("Cannot identify exactly one approved release")
            release = matches[0]
        if release.get("tag_name") != tag or type(release.get("id")) is not int:
            raise ValueError("Release identity mismatch")
        return release

    def assets(self, release_id: int) -> dict[str, dict]:
        pages = self.json(f"repos/{self.repository}/releases/{int(release_id)}/assets?per_page=100", paginate=True)
        result = {}
        for page in pages:
            for asset in page:
                name = safe_name(asset["name"])
                if name in result:
                    raise ValueError("Duplicate release asset name")
                result[name] = asset
        return result

    def read_asset(self, asset: dict) -> tuple[dict, bytes]:
        if not 0 <= asset.get("size", -1) <= MAX_JSON_BYTES:
            raise ValueError("Metadata asset exceeds the bounded JSON allowance")
        sink = io.BytesIO()
        self._get(f"repos/{self.repository}/releases/assets/{int(asset['id'])}", sink,
                  maximum=asset["size"], binary=True, timeout=120)
        raw = sink.getvalue()
        asset_identity(asset, {"bytes": len(raw), "sha256": sha256(raw)})
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object metadata asset")
        return value, raw

    def download(self, asset: dict, target: BinaryIO) -> None:
        self._get(f"repos/{self.repository}/releases/assets/{int(asset['id'])}", target,
                  maximum=asset["size"], binary=True)


def validate_ready_inventory(inventory: dict, cohort: Cohort, final_tag: str,
                             approved_tags: tuple[str, ...]) -> None:
    if (not approved_tags or approved_tags[0] != final_tag or len(set(approved_tags)) != len(approved_tags) or
            any(not TAG_RE.fullmatch(tag) for tag in approved_tags)):
        raise ValueError("Explicit, unique approved lineage must start with the final release")
    if (inventory.get("release_tag") != final_tag or inventory.get("complete") is not True or
            inventory.get("status") != "complete_for_declared_shallow_baseline" or
            inventory.get("complete_repositories") != len(cohort.repositories) or
            inventory.get("incomplete_repositories") != 0 or
            any(inventory.get(key) != value for key, value in cohort.sources.items())):
        raise ValueError("Final inventory does not establish complete expected-cohort coverage")
    rows = inventory.get("repositories")
    if not isinstance(rows, list) or tuple(row.get("repository") for row in rows) != cohort.repositories:
        raise ValueError("Final inventory differs from the ordered CSV cohort")
    parents = inventory.get("parent_release_tags", [inventory["parent_release_tag"]]
                            if inventory.get("parent_release_tag") else [])
    if tuple(parents) != approved_tags[1:]:
        raise ValueError("Final inventory parent lineage differs from explicit approval")
    for row in rows:
        if row.get("complete") is not True or row.get("capture_accepted") is not True or row.get("errors"):
            raise ValueError("A final inventory row is incomplete or inconsistent")
        for ref in [row, *row.get("accepted_parent_references", [])]:
            if ref.get("source_release_tag", final_tag) not in approved_tags:
                raise ValueError("Final inventory references an unapproved source release")
            identity({"sha256": ref.get("index_sha256"), "bytes": 0})


def readiness_snapshot(github: GitHubReadOnly, cohort: Cohort,
                       approved_tags: tuple[str, ...]) -> dict:
    final_tag = approved_tags[0]
    release = github.release(final_tag)
    run_id = int(TAG_RE.fullmatch(final_tag).group(1))
    run = github.json(f"repos/{github.repository}/actions/runs/{run_id}")
    if (run.get("id") != run_id or run.get("run_attempt") != int(TAG_RE.fullmatch(final_tag).group(2)) or
            run.get("status") != "completed" or release.get("draft") is not False):
        raise ValueError("Final run and published final inventory are not yet stable and complete")
    assets = github.assets(release["id"])
    inventory, raw = github.read_asset(assets["baseline-inventory.json"])
    validate_ready_inventory(inventory, cohort, final_tag, approved_tags)
    if run.get("head_sha") != inventory.get("collector_code_sha"):
        raise ValueError("Final workflow source differs from final inventory collector SHA")
    return {"at": utc_iso(), "repository": github.repository, "release_tag": final_tag,
            "release_id": release["id"], "run_id": run_id, "run_conclusion": run.get("conclusion"),
            "inventory_sha256": sha256(raw), "inventory_bytes": len(raw), "inventory": inventory}


@dataclass
class Capture:
    repository: str
    role: str
    tag: str
    source_index: dict
    index: dict
    assets: dict[str, dict]
    migration: dict = field(default_factory=dict)
    migration_reference: dict | None = None
    selected: bool = False

    @property
    def key(self) -> str:
        return sha256(canonical_json({"tag": self.tag, "index": self.source_index}))

    @property
    def accepted(self) -> bool:
        return index_is_accepted(self.index)

    @property
    def bundle(self) -> dict | None:
        manifests = self.index.get("manifests", [])
        return manifests[0].get("portable_full_bundle") if len(manifests) == 1 else None

    @property
    def transport_format(self) -> str:
        parts = (self.index.get("archive") or {}).get("parts", [])
        return "migrated" if any(part.get("name") in self.migration for part in parts) else "native_encrypted"


def catalog_lineage(github: GitHubReadOnly, cohort: Cohort, snapshot: dict,
                    approved_tags: tuple[str, ...]) -> tuple[list[Capture], list[dict]]:
    captures, releases = [], []
    for tag in approved_tags:
        release = github.release(tag)
        target = release.get("target_commitish", "")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", target):
            raise ValueError("Approved release must identify its exact collector commit")
        assets = github.assets(release["id"])
        mapping, migration_reference = {}, None
        referenced = {"baseline-inventory.json", "baseline-timestamp-catalog.json"}
        if "encryption-migration-index.json" in assets:
            item = assets["encryption-migration-index.json"]
            migration, raw = github.read_asset(item)
            if (migration.get("schema_version") != 1 or migration.get("release_tag") != tag or
                    migration.get("repository") != github.repository or not isinstance(migration.get("parts"), dict)):
                raise ValueError("Encryption migration metadata differs from its source release")
            mapping = migration["parts"]
            migration_reference = {"name": item["name"], "asset_id": item["id"], "sha256": sha256(raw), "bytes": len(raw)}
            referenced.add(item["name"])
        count = 0
        legacy = migration.get("legacy_actions_artifacts", []) if migration_reference else []
        for entry in legacy:
            referenced.add(entry.get("ciphertext", {}).get("name"))
        for name, asset in sorted(assets.items()):
            if not name.endswith(".index.json"):
                continue
            index, raw = github.read_asset(asset)
            slug = index.get("repository")
            if (slug not in cohort.repositories or index.get("release_tag") != tag or
                    index.get("release_repository", github.repository) != github.repository or
                    index.get("collector_code_sha") != target or
                    any(index.get(key) != value for key, value in cohort.sources.items())):
                raise ValueError("Source capture index differs from cohort/config/release identity")
            reference = {"repository": github.repository, "release_tag": tag, "release_id": release["id"],
                         "name": name, "asset_id": asset["id"], "sha256": sha256(raw), "bytes": len(raw),
                         "collector_code_sha": index.get("collector_code_sha")}
            capture = Capture(slug, cohort.roles[slug], tag, reference, index, assets, mapping, migration_reference)
            captures.append(capture)
            count += 1
            referenced.add(name)
            for part in (index.get("archive") or {}).get("parts", []):
                referenced.add(part.get("name"))
                if part.get("name") in mapping:
                    referenced.add(mapping[part["name"]].get("ciphertext", {}).get("name"))
            referenced.update(item.get("name") for item in index.get("public_sidecars", []))
        releases.append({"tag": tag, "release_id": release["id"], "draft": release.get("draft"),
                         "indexed_attempts": count, "migration_reference": migration_reference,
                         "indexed_legacy_zip_transports": legacy,
                         "orphan_assets": [{key: asset.get(key) for key in ("id", "name", "size", "digest", "state")}
                                           for name, asset in sorted(assets.items()) if name not in referenced]})
    known = {(capture.tag, capture.source_index["sha256"]): capture for capture in captures}
    for row in snapshot["inventory"]["repositories"]:
        for reference in [row, *row.get("accepted_parent_references", [])]:
            tag = reference.get("source_release_tag", approved_tags[0])
            capture = known.get((tag, reference["index_sha256"]))
            if capture is None or capture.repository != row["repository"] or not capture.accepted:
                raise ValueError("Accepted final inventory source index is unavailable or inconsistent")
            if (reference.get("manifests") != capture.index.get("manifests") or
                    reference.get("source_release_repository", github.repository) != github.repository or
                    reference.get("source_index_asset_id", capture.source_index["asset_id"]) != capture.source_index["asset_id"] or
                    reference.get("collector_code_sha", snapshot["inventory"]["collector_code_sha"]) != capture.index["collector_code_sha"]):
                raise ValueError("Accepted final inventory metadata differs from its actual source index")
    return captures, releases


def transport_parts(capture: Capture) -> tuple[list[dict], list[dict]]:
    available, gaps, names = [], [], set()
    archive = capture.index.get("archive") or {}
    for original in archive.get("parts", []):
        try:
            name = safe_name(original.get("name"))
            if name in names:
                raise ValueError("Duplicate archive part")
            names.add(name)
            original_identity = {"name": name, **identity(original)}
            if original.get("encryption"):
                ciphertext, plaintext = original_identity, original.get("plaintext")
                identity(plaintext)
                encryption = original["encryption"]
                if any(encryption.get(key) != value for key, value in (
                    ("ciphertext_sha256", ciphertext["sha256"]), ("ciphertext_bytes", ciphertext["bytes"]),
                    ("plaintext_sha256", plaintext["sha256"]), ("plaintext_bytes", plaintext["bytes"]))):
                    raise ValueError("Envelope metadata identity mismatch")
                transport_format = "native_encrypted"
            elif name in capture.migration:
                alias = capture.migration[name]
                if alias.get("plaintext") != original_identity:
                    raise ValueError("Migration alias differs from original plaintext identity")
                ciphertext, plaintext = alias.get("ciphertext"), original_identity
                identity(ciphertext)
                transport_format = "migrated"
            else:
                raise ValueError("No indexed encrypted transport is available")
            remote = capture.assets[safe_name(ciphertext["name"])]
            asset_identity(remote, ciphertext)
            available.append({"asset": remote, "ciphertext": ciphertext, "plaintext": plaintext,
                              "transport_format": transport_format})
        except (ValueError, KeyError, TypeError) as error:
            gaps.append({"part": original.get("name"), "reason": str(error)})
    if not archive.get("parts"):
        gaps.append({"part": None, "reason": "No indexed archive parts retained"})
    return available, gaps


def select_spotchecks(captures: list[Capture], *, maximum: int = 12,
                      bundle_limit: int = DEFAULT_BUNDLE_LIMIT) -> list[str]:
    eligible = [capture for capture in captures if capture.bundle and
                type(capture.bundle.get("bytes")) is int and 0 < capture.bundle["bytes"] <= bundle_limit]
    groups = {}
    for capture in eligible:
        size = "under_1MiB" if capture.bundle["bytes"] < 1024 * 1024 else "1_to_16MiB"
        groups[capture.key] = {(axis, value) for axis, value in (
            ("source", capture.tag), ("role", capture.role), ("outcome", "accepted" if capture.accepted else "partial"),
            ("format", capture.transport_format), ("size", size))}
    selected, covered = [], set()
    while groups and len(selected) < maximum:
        key = min(groups, key=lambda item: (-len(groups[item] - covered), item))
        covered.update(groups.pop(key))
        selected.append(key)
    for capture in captures:
        capture.selected = capture.key in selected
    return selected


def read_bundle_header(stream: BinaryIO, *, copy_to: BinaryIO | None = None,
                       first_line: bytes | None = None) -> dict:
    header_bytes = 0
    def line() -> bytes:
        nonlocal header_bytes
        value = stream.readline(1024 * 1024 + 1)
        if len(value) > 1024 * 1024 or not value.endswith(b"\n"):
            raise ValueError("Incomplete or oversized Git bundle header line")
        header_bytes += len(value)
        if header_bytes > MAX_METADATA_TOTAL:
            raise ValueError("Git bundle ref header exceeds its explicit metadata bound")
        if copy_to is not None:
            copy_to.write(value)
        return value
    first = line() if first_line is None else first_line
    if first_line is not None and copy_to is not None:
        copy_to.write(first_line)
    if first not in (b"# v2 git bundle\n", b"# v3 git bundle\n"):
        raise ValueError("Unsupported Git bundle header")
    refs, prerequisites, capabilities = {}, [], []
    while (raw := line()) != b"\n":
        value = raw[:-1].decode("utf-8")
        if value.startswith("@"):
            capabilities.append(value)
            continue
        oid, name = value.split(" ", 1)
        if oid.startswith("-"):
            _validate_oid(oid[1:])
            prerequisites.append(oid[1:])
        else:
            _validate_oid(oid)
            if (name != "HEAD" and not _valid_refname(name)) or name in refs:
                raise ValueError("Invalid or duplicate Git bundle ref")
            refs[name] = oid
    pack = stream.read(12)
    if len(pack) != 12 or pack[:4] != b"PACK" or int.from_bytes(pack[4:8], "big") not in (2, 3):
        raise ValueError("Missing or invalid Git pack header")
    if copy_to is not None:
        copy_to.write(pack)
        while block := stream.read(1024 * 1024):
            copy_to.write(block)
    return {"refs": refs, "prerequisite_object_ids": prerequisites, "capabilities": capabilities,
            "pack_objects": int.from_bytes(pack[8:12], "big")}


class MemberAudit:
    def __init__(self, capture: Capture, bundle_writer: BinaryIO | None = None):
        self.capture, self.bundle_writer = capture, bundle_writer
        self.metadata: dict[str, tuple[bytes, dict]] = {}
        self.cas_json: dict[str, dict] = {}
        self.json_status: dict[str, str] = {}
        self.headers: dict[str, dict] = {}
        self.receipts: dict[str, bytes] = {}
        self.metadata_bytes = 0
        self.bundle_digest = capture.bundle.get("sha256") if capture.bundle else None

    def on_member(self, record, stream: BinaryIO):
        path, size = record.path, record.bytes
        match = CAS_RE.fullmatch(path)
        if match:
            digest = match.group(2)
            buffered = io.BufferedReader(stream, buffer_size=64 * 1024)
            try:
                first = buffered.readline(1024 * 1024 + 1)
                if first in (b"# v2 git bundle\n", b"# v3 git bundle\n"):
                    header = read_bundle_header(buffered, first_line=first,
                                                copy_to=self.bundle_writer if digest == self.bundle_digest else None)
                    self.metadata_bytes += len(canonical_json(header))
                    if self.metadata_bytes > MAX_METADATA_TOTAL:
                        raise ValueError("Retained Git metadata exceeds its explicit memory bound")
                    self.headers[digest] = header
                elif size <= MAX_JSON_BYTES:
                    raw = first + buffered.read(size - len(first) + 1)
                    try:
                        value = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        self.json_status[digest] = "preserved_invalid_json"
                    else:
                        self.json_status[digest] = "valid_json"
                        if isinstance(value, dict) and "parent_archive_sha256" in value and "covered_object_tips" in value:
                            self.metadata_bytes += len(raw)
                            if self.metadata_bytes > MAX_METADATA_TOTAL:
                                raise ValueError("Retained descriptor metadata exceeds its explicit memory bound")
                            self.cas_json[digest] = value
                else:
                    self.json_status[digest] = "not_parsed_over_16MiB_limit"
            finally:
                buffered.detach()
        elif path.endswith(".ots"):
            if size > MAX_JSON_BYTES or self.metadata_bytes + size > MAX_METADATA_TOTAL:
                raise ValueError("Audit proof metadata exceeds its explicit memory bound")
            self.receipts[path] = stream.read(size + 1)
            self.metadata_bytes += size
        elif path.endswith(".json"):
            if size > MAX_JSON_BYTES or self.metadata_bytes + size > MAX_METADATA_TOTAL:
                raise ValueError("Audit JSON metadata exceeds its explicit memory bound")
            raw = stream.read(size + 1)
            value = json.loads(raw)
            self.metadata_bytes += len(raw)
            self.metadata[path] = (raw, value)

    def validate(self, members: list) -> dict:
        paths = {member.path: member for member in members}
        cas = {match.group(2): member for member in members
               if (match := CAS_RE.fullmatch(member.path))}
        errors, manifests, observations, failures, unavailable, parsing = [], [], [], [], [], Counter()
        receipt_statuses, decode_errors = [], []
        expected = {item["sha256"]: item for item in self.capture.index.get("manifests", [])}
        for path, (raw, value) in sorted(self.metadata.items()):
            if not re.fullmatch(r"evidence/runs/\d+/[^/]+\.manifest\.json", path):
                continue
            digest = sha256(raw)
            manifests.append((path, digest, value))
            if raw != canonical_json(value):
                errors.append(f"Noncanonical manifest: {path}")
            if (value.get("repository_input_slug") != self.capture.repository or
                    value.get("repository_id") != int(path.split("/")[2]) or
                    Path(path).name != value.get("run_id", "") + ".manifest.json"):
                errors.append(f"Manifest identity/path mismatch: {path}")
            if digest not in expected or expected[digest].get("run_id") != value.get("run_id"):
                errors.append(f"Manifest is absent from source index or has changed: {path}")
            elif any(expected[digest].get(key) != value.get(key) for key in (
                    "repository_id", "status", "mode", "public_config_sha256", "started_at", "finished_at")
                    if key in expected[digest]):
                errors.append(f"Manifest summary differs from its source index: {path}")
            if "public_config" in value and sha256(canonical_json(value["public_config"])) != value.get("public_config_sha256"):
                errors.append(f"Public config digest mismatch: {path}")
            failures.extend({"manifest_sha256": digest, "failure": item} for item in value.get("failures", []))
            api = value.get("api") or {}
            decode_errors.extend(api.get("decode_errors", []))
            unavailable.extend({"scope": scope, "detail": detail}
                               for scope, detail in (api.get("unavailable_scopes") or {}).items())
            for scope, detail in (api.get("scope_statuses") or api.get("scopes") or {}).items():
                if (isinstance(detail, dict) and detail.get("status") == "unavailable" and
                        scope not in (api.get("unavailable_scopes") or {})):
                    unavailable.append({"scope": scope, "detail": detail})
            for scope, detail in (api.get("scope_availability") or {}).items():
                if isinstance(detail, dict) and detail.get("available") is False:
                    unavailable.append({"scope": scope, "detail": detail})
            for receipt_path in (path + ".ots", f"evidence/proofs/initial/{digest}.ots"):
                raw_receipt = self.receipts.get(receipt_path)
                if not raw_receipt:
                    receipt_statuses.append({"path": receipt_path, "status": "missing"})
                    if self.capture.accepted:
                        errors.append(f"Accepted capture's OTS receipt missing/empty: {receipt_path}")
                    continue
                try:
                    inspection = inspect_ots_receipt(raw_receipt, digest)
                except AttestationDependencyError:
                    inspection = {"status": "not_inspected_missing_OTS_dependency"}
                except ValueError as error:
                    errors.append(f"OTS receipt binding/structure: {receipt_path}: {error}")
                    inspection = {"status": "invalid_receipt_or_subject"}
                receipt_statuses.append({"path": receipt_path, **inspection, "bitcoin_verified": False})
            provenance = self.metadata.get(f"evidence/proofs/initial/{digest}.stamp.json")
            initial = paths.get(f"evidence/proofs/initial/{digest}.ots")
            if provenance and (provenance[1].get("manifest_sha256") != digest or initial is None or
                               provenance[1].get("receipt_sha256") != initial.sha256):
                errors.append("Initial timestamp receipt provenance does not bind the manifest/receipt")
            for response in value.get("responses", []):
                body = response.get("body_sha256")
                if not body:
                    continue
                member = cas.get(body)
                if member is None or member.bytes != response.get("body_bytes"):
                    errors.append(f"Raw response CAS dependency missing/wrong-sized: {body}")
                status = self.json_status.get(body, "not_parsed")
                parsing[status] += 1
                observations.append({"body_sha256": body, "status": response.get("status"),
                                     "error": response.get("error"), "purpose": response.get("purpose"),
                                     "json_status": status})
            git = value.get("git")
            if git:
                try:
                    _git_namespace(value)
                    for ref in git.get("advertised_refs", []):
                        _validate_oid(ref["object_id"])
                        if ref.get("peeled_object_id"):
                            _validate_oid(ref["peeled_object_id"])
                    bundle = git.get("portable_full_bundle")
                    if bundle:
                        member, header = cas.get(bundle["sha256"]), self.headers.get(bundle["sha256"])
                        if member is None or member.bytes != bundle["bytes"] or header is None:
                            raise ValueError("Full Git bundle missing, wrong-sized, or unparsed")
                        if header["prerequisite_object_ids"]:
                            raise ValueError("Full Git bundle unexpectedly requires objects")
                        for ref in git["advertised_refs"]:
                            if header["refs"].get(ref["local_immutable_ref"]) != ref["object_id"]:
                                raise ValueError("Full bundle header does not declare manifest's ref/OID")
                    descriptor = git.get("portable_archive")
                    if descriptor:
                        if any(descriptor.get(key) != git.get(source) for key, source in (
                            ("advertised_refs", "advertised_refs"), ("archive_ref_prefix", "archive_ref_prefix"),
                            ("object_format", "git_object_hash_algorithm"), ("remote", "remote"))):
                            raise ValueError("Portable archive descriptor differs from manifest Git inventory")
                        self._descriptor(descriptor, cas, set())
                except (KeyError, TypeError, ValueError) as error:
                    errors.append(f"Git descriptor/header dependency validation: {error}")
        seen = {digest for _, digest, _ in manifests}
        if seen != set(expected):
            errors.append("Manifest set differs from immutable source index")
        by_repository = {}
        for path, digest, manifest in manifests:
            by_repository.setdefault(manifest["repository_id"], []).append((path, digest, manifest))
        for chain in by_repository.values():
            previous = None
            for path, digest, manifest in sorted(chain):
                if manifest.get("previous_manifest_sha256") != previous:
                    errors.append(f"Manifest predecessor dependency missing or inconsistent: {path}")
                previous = digest
        if self.capture.index.get("complete") is True and not self.capture.accepted:
            errors.append("Source index's accepted flag violates baseline acceptance invariants")
        if self.capture.index.get("capture_accepted") is True:
            if any(manifest.get("status") != "complete" or manifest.get("failures") for _, _, manifest in manifests):
                errors.append("Accepted index contains a partial/failing manifest")
        for path, source_key in (("reports/config.corpus.toml", "config_source_sha256"),
                                 ("reports/public_patch_corpus_185.csv", "csv_sha256")):
            if path not in paths or paths[path].sha256 != self.capture.index.get(source_key):
                errors.append(f"Archived source input missing or inconsistent: {path}")
        inventory_digest = hashlib.sha256()
        for member in sorted(members, key=lambda item: item.path):
            inventory_digest.update(canonical_json({"path": member.path, "sha256": member.sha256, "bytes": member.bytes}))
        return {"errors": errors, "manifests": len(manifests), "cas_objects": len(cas),
                "members": len(members), "all_member_bytes_hashed": sum(member.bytes for member in members),
                "member_hash_inventory_sha256": inventory_digest.hexdigest(),
                "manifest_chain": "verified" if not errors else "see_errors",
                "raw_observations": len(observations), "raw_json_statuses": dict(parsing),
                "raw_failures_preserved": [item for item in observations if item["status"] != 200 or item["error"] or
                                            item["json_status"] == "preserved_invalid_json"],
                "declared_failures": failures, "declared_unavailable_scopes": unavailable,
                "declared_api_decode_errors": decode_errors, "ots_receipt_inspection": receipt_statuses,
                "git_headers_checked": len(self.headers), "git_graph_verification": "not_fscked",
                "bitcoin_verification": "not_attempted_no_trusted_Bitcoin_node",
                "timestamp_index_evidence": self.capture.index.get("timestamp_evidence", {}),
                "proof_members": [{"path": member.path, "sha256": member.sha256, "bytes": member.bytes}
                                  for member in members if member.path.endswith((".ots", ".tsr", ".tsq"))]}

    def _descriptor(self, descriptor: dict, cas: dict, seen: set) -> None:
        digest = sha256(canonical_json(descriptor))
        if digest in seen or self.cas_json.get(digest) != descriptor or digest not in cas:
            raise ValueError("Portable descriptor cyclic or absent from CAS")
        seen.add(digest)
        if (descriptor.get("schema_version") != 1 or descriptor.get("object_format") not in ("sha1", "sha256") or
                descriptor.get("kind") not in ("baseline", "incremental", "refs-only") or
                (descriptor.get("bundle") is None) != (descriptor.get("kind") == "refs-only")):
            raise ValueError("Invalid portable descriptor schema/kind/object format")
        for oid in descriptor.get("covered_object_tips", []):
            _validate_oid(oid)
        for bundle in descriptor.get("prerequisites", []) + ([descriptor["bundle"]] if descriptor.get("bundle") else []):
            member = cas.get(bundle["sha256"])
            header = self.headers.get(bundle["sha256"])
            if member is None or member.bytes != bundle["bytes"] or header is None:
                raise ValueError("Portable bundle prerequisite CAS absent/wrong-sized")
            if header["prerequisite_object_ids"] != bundle.get("prerequisite_object_ids"):
                raise ValueError("Portable bundle prerequisite OIDs differ from actual header")
        if descriptor.get("kind") == "baseline":
            header = self.headers[descriptor["bundle"]["sha256"]]
            if header["prerequisite_object_ids"]:
                raise ValueError("Portable baseline has object prerequisites")
            for ref in descriptor.get("advertised_refs", []):
                if header["refs"].get(ref["local_immutable_ref"]) != ref["object_id"]:
                    raise ValueError("Portable baseline lacks declared immutable ref/OID")
        parent = descriptor.get("parent_archive_sha256")
        if parent:
            previous = self.cas_json.get(parent)
            if previous is None or descriptor.get("prerequisites") != previous.get("prerequisites", []) + (
                    [previous["bundle"]] if previous.get("bundle") else []):
                raise ValueError("Portable Git prerequisite lineage differs from parent")
            if (descriptor.get("kind") == "baseline" or any(descriptor.get(key) != previous.get(key) for key in (
                    "repository_id", "remote", "object_format")) or
                    not set(previous.get("covered_object_tips", [])).issubset(descriptor.get("covered_object_tips", []))):
                raise ValueError("Portable Git lineage changed repository/format or lost covered tips")
            self._descriptor(previous, cas, seen)
        elif descriptor.get("kind") != "baseline" or descriptor.get("prerequisites"):
            raise ValueError("Portable archive has no full baseline dependency")


class FixedGitVolume:
    """An owned fixed-size HFS+ image; all opaque Git output is confined here."""

    def __init__(self, budget: LocalBudget, *, size_bytes: int = DEFAULT_VOLUME_BYTES, runner=None):
        if (type(size_bytes) is not int or not 32 * 1024 * 1024 <= size_bytes <= DEFAULT_VOLUME_BYTES or
                size_bytes % 512):
            raise ValueError("Git volume size must be between 32 and 256 MiB in whole 512-byte sectors")
        self.budget, self.size_bytes = budget, size_bytes
        self.runner = runner or subprocess.run
        self.directory = budget.root / "staging" / ("git-volume-" + uuid.uuid4().hex)
        self.image, self.mount = self.directory / "audit.dmg", self.directory / "mount"
        self.device = None
        self.reservation = None
        self.attach_attempted = False
        self.attach_succeeded = False

    def _run(self, args, *, timeout=120):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TMPDIR": str(self.directory), "LC_ALL": "C"}
        process = self.runner(args, capture_output=True, timeout=timeout, env=env)
        if process.returncode:
            operation = args[1] if len(args) > 1 and args[1] in {"create", "attach", "info", "imageinfo", "detach"} else "unknown"
            raise RuntimeError(f"Fixed-volume operation failed ({operation}; exit {process.returncode})")
        return process.stdout

    def __enter__(self) -> Path:
        if sys.platform != "darwin" or not shutil.which("hdiutil"):
            raise RuntimeError("Enforced native Git spot-check volume unavailable on this host")
        self.reservation = self.budget.reserve(2 * self.size_bytes + 8 * 1024 * 1024,
                                             purpose="fixed Git image plus mounted allocation")
        try:
            self.reservation.track(self.directory)
            self.directory.mkdir(mode=0o700)
            self.mount.mkdir(mode=0o700)
            # hdiutil's -size suffix 'b' means 512-byte sectors, NOT bytes.
            # An explicit sector count makes the pre-create byte ceiling exact.
            self._run(["/usr/bin/hdiutil", "create", "-sectors", str(self.size_bytes // 512), "-fs", "Case-sensitive HFS+",
                       "-type", "UDIF", "-layout", "NONE", "-nospotlight", "-volname", "ICSOT_AUDIT", str(self.image)])
            image_info = self.image.lstat()
            if self.image.is_symlink() or image_info.st_uid != os.geteuid() or image_info.st_size > self.size_bytes + 4 * 1024 * 1024:
                raise RuntimeError("Fixed image exceeded its reserved file bound")
            self.attach_attempted = True
            attached_raw = self._run(["/usr/bin/hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on",
                                      "-mountpoint", str(self.mount), str(self.image)])
            self.attach_succeeded = True
            attached = plistlib.loads(attached_raw)
            entities = attached.get("system-entities", [])
            devices = [entity.get("dev-entry") for entity in entities if entity.get("mount-point") == str(self.mount)]
            if len(devices) != 1 or not re.fullmatch(r"/dev/disk\d+(?:s\d+)?", devices[0]):
                raise RuntimeError("Attached volume lacks the expected mount/device identity")
            info = plistlib.loads(self._run(["/usr/bin/hdiutil", "info", "-plist"]))
            owners = [item for item in info.get("images", []) if item.get("image-path") == str(self.image)]
            if len(owners) != 1 or not any(item.get("dev-entry") == devices[0] for item in owners[0].get("system-entities", [])):
                raise RuntimeError("Attached device does not belong to this owned image")
            self.device = devices[0]
            capacity = shutil.disk_usage(self.mount).total
            if capacity > self.size_bytes:
                raise RuntimeError("Mounted filesystem capacity exceeds the fixed image bound")
            self.reservation.check()
            return self.mount
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.attach_attempted:
            # Recheck the exact image before detach; a recycled device name is
            # never sufficient authority to detach an unrelated filesystem.
            info = plistlib.loads(self._run(["/usr/bin/hdiutil", "info", "-plist"]))
            owners = [item for item in info.get("images", []) if item.get("image-path") == str(self.image)]
            if len(owners) != 1:
                if self.attach_succeeded:
                    raise RuntimeError("Cannot verify attachment ownership; owned image preserved")
            else:
                devices = [item.get("dev-entry") for item in owners[0].get("system-entities", [])
                           if item.get("mount-point") == str(self.mount) or item.get("dev-entry") == self.device]
                if len(devices) != 1 or not re.fullmatch(r"/dev/disk\d+(?:s\d+)?", devices[0]):
                    raise RuntimeError("Cannot verify cleanup device; owned image preserved")
                self._run(["/usr/bin/hdiutil", "detach", devices[0]])
            self.device, self.attach_attempted, self.attach_succeeded = None, False, False
        if self.mount.is_mount():
            raise RuntimeError("Owned Git volume remains mounted; image preserved")
        if self.image.exists():
            self.image.unlink()
        if self.mount.exists():
            self.mount.rmdir()
        if self.directory.exists():
            self.directory.rmdir()
        if self.reservation:
            self.reservation.close()
            self.reservation = None

    def __exit__(self, *args):
        self.close()


class BoundedGit:
    """Bounded command output and local-only Git state on an enforced volume.

    Callers own FixedGitVolume's lifetime and must release ciphertext stages
    first. Only caller-constructed commands are accepted; writable paths must
    remain within this volume. No arbitrary user command passthrough is safe.
    """

    def __init__(self, mount: Path, budget: LocalBudget):
        self.mount, self.budget = mount, budget
        home, temporary, self.repo = mount / "home", mount / "tmp", mount / "restored.git"
        home.mkdir()
        temporary.mkdir()
        self.environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "TMPDIR": str(temporary),
                            "XDG_CACHE_HOME": str(home), "XDG_CONFIG_HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file", "LC_ALL": "C"}
        self.prefix = ["git", "-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                       "-c", "fetch.writeCommitGraph=false", "-c", "fetch.unpackLimit=0", "-c", "transfer.unpackLimit=0"]

    def run(self, args: list[str], input_text: str | None = None, *, max_output_bytes: int = 2 * 1024 * 1024,
            timeout: float = 600) -> str:
        if not 0 < max_output_bytes <= MAX_METADATA_TOTAL or timeout <= 0:
            raise ValueError("Explicit positive Git output/time bounds required")
        output, diagnostic, total = bytearray(), bytearray(), 0
        started = time.monotonic()
        encoded = input_text.encode() if input_text is not None else b""
        if len(encoded) > 32 * 1024:
            raise ValueError("Git stdin exceeds the bounded control-input allowance")
        with subprocess.Popen(self.prefix + args, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.mount, env=self.environment,
                              start_new_session=True, bufsize=0) as process:
            try:
                input_offset = 0
                if process.stdin is not None:
                    os.set_blocking(process.stdin.fileno(), False)
                if process.stdin is not None and not encoded:
                    process.stdin.close()
                pending = [process.stdout, process.stderr]
                while pending or input_offset < len(encoded):
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise RuntimeError("Offline Git command exceeded its time bound")
                    write_pending = [process.stdin] if input_offset < len(encoded) else []
                    ready, writable, _ = select.select(pending, write_pending, [], min(remaining, 1.0))
                    if writable:
                        try:
                            input_offset += os.write(process.stdin.fileno(), encoded[input_offset:input_offset + 4096])
                        except BlockingIOError:
                            pass
                        if input_offset == len(encoded):
                            process.stdin.close()
                    for stream in ready:
                        block = os.read(stream.fileno(), 64 * 1024)
                        if not block:
                            pending.remove(stream)
                            continue
                        total += len(block)
                        if total > max_output_bytes:
                            raise RuntimeError("Offline Git command exceeded its output bound")
                        (output if stream is process.stdout else diagnostic).extend(block)
                code = process.wait(timeout=max(1, timeout - (time.monotonic() - started)))
                self.budget.check()
                if code:
                    raise RuntimeError(f"Offline Git restore/check failed (exit {code}; fixed volume may be full)")
                return output.decode("utf-8", errors="replace")
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise


def verify_small_bundle(path: Path, git: dict, budget: LocalBudget, *, volume_factory=FixedGitVolume) -> dict:
    started = time.monotonic()
    volume = volume_factory(budget)
    with volume as mount:
        runner = BoundedGit(mount, budget)
        git_run, repo = runner.run, runner.repo
        object_format = git.get("git_object_hash_algorithm", "sha1")
        if object_format not in ("sha1", "sha256"):
            raise ValueError("Unsupported Git object format")
        git_run(["init", "--bare", f"--object-format={object_format}", str(repo)])
        git_run(["-C", str(repo), "bundle", "verify", str(path.resolve())])
        git_run(["-C", str(repo), "fetch", "--no-tags", str(path.resolve()), "+refs/*:refs/*", "--no-auto-maintenance"])
        git_run(["-C", str(repo), "fsck", "--full", "--no-reflogs"])
        actual = dict(line.split(" ", 1) for line in git_run(
            ["-C", str(repo), "for-each-ref", "--format=%(refname) %(objectname)"]).splitlines())
        expected = {ref["local_immutable_ref"]: ref["object_id"] for ref in git["advertised_refs"]}
        if any(actual.get(ref) != oid for ref, oid in expected.items()):
            raise ValueError("Restored Git refs differ from declared manifest refs")
        expressions = {ref["object_id"]: ref["object_id"] for ref in git["advertised_refs"]}
        expressions.update({ref["object_id"] + "^{}": ref["peeled_object_id"]
                            for ref in git["advertised_refs"] if ref.get("peeled_object_id")})
        if expressions:
            pairs = list(expressions.items())
            for offset in range(0, len(pairs), 128):
                chunk = pairs[offset:offset + 128]
                output = git_run(["-C", str(repo), "cat-file", "--batch-check=%(objectname)"],
                                 "\n".join(expression for expression, _ in chunk) + "\n")
                if output.splitlines() != [value for _, value in chunk]:
                    raise ValueError("Restored Git object or annotated-tag peeled target differs")
        counts = {}
        for line in git_run(["-C", str(repo), "count-objects", "-v"]).splitlines():
            key, _, value = line.partition(": ")
            if key in {"count", "in-pack", "packs"}:
                counts[key] = int(value)
        return {"status": "offline_restore_fsck_verified", "declared_refs": len(expected),
                "restored_refs": len(actual), "fixed_volume_bytes": volume.size_bytes,
                "git_object_storage_counts": counts,
                "elapsed_seconds": round(time.monotonic() - started, 3)}


@contextlib.contextmanager
def downloaded_part(github: GitHubReadOnly, budget: LocalBudget, part: dict):
    cipher, plain = part["ciphertext"], part["plaintext"]
    with budget.stage(cipher["bytes"], suffix=".enc", purpose="one indexed encrypted archive part") as stage:
        with stage.open_writer() as target:
            github.download(part["asset"], target)
        yield ArchivePart(stage.path, cipher["sha256"], cipher["bytes"], plain["sha256"], plain["bytes"], cipher["name"])


def zip_directory_bound(path: Path) -> dict:
    """Validate bounded classic ZIP directory metadata before ZipFile loads it."""
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    while offset >= 0:
        if len(tail) - offset >= 22 and offset + 22 + int.from_bytes(tail[offset + 20:offset + 22], "little") == len(tail):
            break
        offset = tail.rfind(b"PK\x05\x06", 0, offset)
    if offset < 0:
        raise ValueError("ZIP end-of-central-directory record is missing")
    magic, disk, central_disk, disk_count, count, central_bytes, central_offset, comment = struct.unpack(
        "<4s4H2IH", tail[offset:offset + 22])
    if offset + 22 + comment != len(tail) or disk or central_disk or disk_count != count:
        raise ValueError("Unsupported multi-volume or malformed ZIP directory")
    if count == 65535 or central_bytes == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise NotImplementedError("ZIP64 container requires a separate bounded directory implementation")
    if central_bytes > MAX_JSON_BYTES or count > 100_000:
        raise ValueError("ZIP central directory exceeds its explicit metadata bound")
    if central_offset + central_bytes > size - len(tail) + offset:
        raise ValueError("ZIP central directory extends beyond its footer")
    return {"entries": count, "central_directory_bytes": central_bytes}


def inspect_zip_members(path: Path) -> dict:
    directory = zip_directory_bound(path)
    inventory, retained, names, total, count = hashlib.sha256(), [], set(), 0, 0
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) != directory["entries"]:
            raise ValueError("ZIP entry count differs from its footer")
        for info in archive.infolist():
            name = info.filename.rstrip("/") if info.is_dir() else info.filename
            if (not name or len(name.encode()) > 4096 or name.startswith("/") or "\\" in name or
                    any(ord(char) < 32 or ord(char) == 127 for char in name) or
                    any(part in ("", ".", "..") for part in name.split("/")) or name in names):
                raise ValueError("Unsafe or duplicate ZIP member path")
            names.add(name)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise ValueError("ZIP links/special files are not accepted")
            if info.flag_bits & 1:
                raise ValueError("Nested password-encrypted ZIP member is unsupported")
            digest, size = hashlib.sha256(), 0
            with archive.open(info) as member:
                while block := member.read(1024 * 1024):
                    size += len(block)
                    total += len(block)
                    if total > 1 << 40:
                        raise ValueError("ZIP expanded member total exceeds its explicit bound")
                    digest.update(block)
            if size != info.file_size:
                raise ValueError("ZIP member size differs from directory")
            record = {"path": info.filename, "bytes": size, "sha256": digest.hexdigest(), "crc32": f"{info.CRC:08x}"}
            inventory.update(canonical_json(record))
            if len(retained) < 1000:
                retained.append(record)
            count += 1
    return {"status": "legacy_ZIP_members_CRC_and_SHA256_verified", **directory, "members": count,
            "expanded_bytes_hashed": total, "member_hash_inventory_sha256": inventory.hexdigest(),
            "member_records_first_1000": retained, "nested_payloads": "hashed_as_members_not_recursively_restored"}


def audit_legacy_zip(entry: dict, release: dict, assets: dict, github: GitHubReadOnly,
                     budget: LocalBudget, private_key_path: Path) -> dict:
    result = {"migration_reference": release.get("migration_reference"), "release_tag": release["tag"],
              "original_transport": entry, "audit_complete": True}
    directory = None
    try:
        cipher, plain = entry["ciphertext"], entry["plaintext"]
        identity(cipher)
        identity(plain)
        if plain["bytes"] > cipher["bytes"]:
            raise ValueError("Legacy ZIP plaintext length exceeds its envelope length")
        asset = assets[safe_name(cipher["name"])]
        asset_identity(asset, cipher)
        # Admit BOTH ciphertext and seekable plaintext before a byte is fetched.
        # The existing codec's temporary/link lifecycle occupies at most one
        # plaintext allocation; no custom seekable crypto is introduced.
        with budget.reserve(plain["bytes"] + 16384, purpose="bounded seekable legacy ZIP plaintext") as reservation:
            with budget.stage(cipher["bytes"], suffix=".enc", purpose="one legacy ZIP ciphertext") as stage:
                directory = budget.root / "staging" / ("legacy-zip-" + uuid.uuid4().hex)
                reservation.track(directory)
                directory.mkdir(mode=0o700)
                try:
                    with stage.open_writer() as target:
                        github.download(asset, target)
                    part = ArchivePart(stage.path, cipher["sha256"], cipher["bytes"], plain["sha256"], plain["bytes"], cipher["name"])
                    result["authentication"] = verify_encrypted_part(part, private_key_path)
                    restored = directory / "legacy.zip"
                    observed = decrypt_file(stage.path, restored, private_key_path)
                    if any(observed[key] != value for key, value in (("plaintext_sha256", plain["sha256"]),
                           ("plaintext_bytes", plain["bytes"]), ("ciphertext_sha256", cipher["sha256"]), ("ciphertext_bytes", cipher["bytes"]))):
                        raise ValueError("Legacy ZIP decryption identity differs from migration index")
                    result.update(inspect_zip_members(restored))
                finally:
                    (directory / "legacy.zip").unlink(missing_ok=True)
                    directory.rmdir()
        budget.check()
    except BudgetError:
        result.update(status="deferred_local_disk_admission", coverage="metadata_only",
                      reason="Ciphertext plus seekable plaintext do not fit the shared hard local ceiling")
    except NotImplementedError as error:
        result.update(status="deferred_unsupported_ZIP_directory", coverage="authenticated_container_metadata_only", reason=str(error))
    except ReadOnlyTransferError as error:
        result.update(status="transport_unavailable_audit_incomplete", audit_complete=False, error=str(error))
    except Exception as error:
        result.update(status="legacy_ZIP_integrity_or_structure_failure", error=f"{type(error).__name__}: {error}")
    return result


def audit_capture(capture: Capture, github: GitHubReadOnly, budget: LocalBudget, private_key_path: Path,
                  *, git_volume_bytes: int = DEFAULT_VOLUME_BYTES) -> dict:
    parts, gaps = transport_parts(capture)
    result = {"capture_key": capture.key, "repository": capture.repository, "repository_role": capture.role,
              "source_index": capture.source_index, "transport_migration_index": capture.migration_reference,
              "accepted_by_source_index": capture.accepted, "index_status": capture.index.get("status"),
              "source_capture_accepted": capture.index.get("capture_accepted") is True,
              "source_transfer_complete": capture.index.get("complete") is True,
              "index_errors": capture.index.get("errors", []), "part_gaps": gaps, "errors": [], "parts": [],
              "full_git_spot_selected": capture.selected, "git_graph_verification": "not_fscked", "audit_complete": True,
              "archive_declared_complete": (capture.index.get("archive") or {}).get("complete") is True}
    result["indexed_encrypted_transports"] = [{"release_tag": capture.tag, "asset_id": part["asset"]["id"],
            "ciphertext": part["ciphertext"], "plaintext": part["plaintext"], "transport_format": part["transport_format"]}
            for part in parts]
    declared_complete = (capture.index.get("archive") or {}).get("complete") is True
    def local_admission_gap(context):
        result["errors"].append(f"Local disk admission unavailable for {context}; payload integrity is not disproved")
        result.update(audit_complete=False, local_admission_unavailable=True,
                      classification="local_admission_unavailable_audit_incomplete")
    # Authenticate every available indexed part independently first. A corrupt
    # early tar member must never prevent checking later retained ciphertext.
    for part in parts:
        for attempt in range(3):
            try:
                with downloaded_part(github, budget, part) as archive_part:
                    result["parts"].append(verify_encrypted_part(archive_part, private_key_path))
                break
            except BudgetError:
                local_admission_gap("encrypted archive part")
            except ReadOnlyTransferError as error:
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                result["errors"].append(f"Encrypted part transfer unavailable: {error}")
                result["audit_complete"] = False
            except Exception as error:
                result["errors"].append(f"Encrypted part integrity: {type(error).__name__}: {error}")
            break
    if gaps or not parts or result["errors"]:
        result["classification"] = "declared_missing_or_incomplete_package"
        if result["errors"]:
            result["classification"] = ("local_admission_unavailable_audit_incomplete" if result.get("local_admission_unavailable") else
                "transport_unavailable_audit_incomplete" if not result["audit_complete"] else "encrypted_part_integrity_failure")
        return result
    bundle = capture.bundle
    try:
        context = budget.stage(bundle["bytes"], suffix=".bundle", purpose="verified small Git sample") if (
            capture.selected and bundle and bundle["bytes"] <= DEFAULT_BUNDLE_LIMIT) else contextlib.nullcontext(None)
    except BudgetError:
        local_admission_gap("small Git bundle staging")
        return result
    with context as selected:
        writer = selected.open_writer() if selected is not None else None
        audit = MemberAudit(capture, writer)
        try:
            options = reader_options(capture.index)
            expected = ({"evidence/" + member["path"]: {"bytes": member["bytes"], "sha256": member["sha256"]}
                         for member in capture.index.get("members", [])} if options else None)
            reader = VerifiedArchiveReader((downloaded_part(github, budget, part) for part in parts),
                                           private_key_path=private_key_path, allowed_prefixes=("evidence", "reports"),
                                           expected_members=expected, **options)
            scan = reader.scan(audit.on_member)
            result["parts"] = scan.parts
            result.update(audit.validate(scan.members))
            result["classification"] = ("accepted_complete" if capture.accepted else
                "source_declares_scientifically_complete_transport_incomplete" if capture.index.get("capture_accepted") is True and
                capture.index.get("complete") is not True else "recoverable_partial")
            if result["errors"]:
                result["classification"] = "integrity_or_dependency_failure"
            if writer is not None:
                writer.close()
                if not result["errors"]:
                    manifests = [value for path, (_, value) in audit.metadata.items() if path.endswith(".manifest.json")]
                    try:
                        result["git_spotcheck"] = verify_small_bundle(selected.path, manifests[0]["git"], budget,
                            volume_factory=lambda shared: FixedGitVolume(shared, size_bytes=git_volume_bytes))
                        result["git_graph_verification"] = result["git_spotcheck"]["status"]
                    except BudgetError:
                        local_admission_gap("selected offline Git volume")
                        result["git_graph_verification"] = "sample_restore_unverified"
                    except Exception as error:
                        result["git_spotcheck"] = {"status": "failed_or_fixed_volume_limit", "error": f"{type(error).__name__}: {error}"}
                        result["git_graph_verification"] = "sample_restore_unverified"
                        result["errors"].append("Selected offline Git restoration/fsck did not complete; inspect git_spotcheck")
        except BudgetError:
            local_admission_gap("complete archive stream")
        except ReadOnlyTransferError as error:
            result["errors"].append(f"Complete-package stream unavailable: {error}")
            result["audit_complete"] = False
            result["classification"] = "transport_unavailable_audit_incomplete"
        except Exception as error:
            result["errors"].append(f"{type(error).__name__}: {error}")
            result["classification"] = ("integrity_or_dependency_failure" if declared_complete else
                                         "declared_missing_or_incomplete_package")
        finally:
            if writer is not None:
                writer.close()
    return result


def save_json(path: Path, value: dict, budget: LocalBudget) -> None:
    raw = canonical_json(value)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Audit report exceeds its bounded output allowance")
    budget.register_root(path.parent)
    with budget.stage(len(raw), suffix=".json", purpose="bounded audit report") as stage:
        with stage.open_writer() as target:
            target.write(raw)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(stage.path, path)
    budget.check()


def render_review(report: dict) -> str:
    classifications = Counter(item["classification"] for item in report["captures"])
    full = sum(item.get("git_graph_verification") == "offline_restore_fsck_verified" for item in report["captures"])
    legacy = report.get("legacy_archives", [])
    errors = sum(bool(item.get("errors")) for item in report["captures"]) + sum("error" in item for item in legacy)
    lines = ["# One-time corpus recovery audit", "", f"Disposition: **{'PASS WITH COVERAGE LIMITS' if not errors else 'HOLD — REVIEW REQUIRED'}**.", "",
             f"Final inventory: `{report['inventory_sha256']}`; expected cohort: {report['expected_repositories']} repositories.",
             f"Retained indexed attempts inspected: {len(report['captures'])}; classifications: {dict(classifications)}.",
             f"Full offline Git restoration and fsck: {full} deterministic small samples. Other Git graphs were not fully fscked.", "",
             f"Migrated legacy ZIP containers: {dict(Counter(item['status'] for item in legacy))}.", "",
             "Every successful complete-package scan authenticates all encrypted parts, validates XZ/TAR structure, hashes every regular member/CAS object, and checks declared manifest/raw/Git dependencies.",
             "Missing or declared incomplete packages remain coverage gaps. Invalid raw API JSON is retained evidence when its recorded bytes/hash survive; it is not silently treated as a successful listing.",
             "Bitcoin timestamp verification was not attempted: no trusted Bitcoin node was supplied. A pending receipt or calendar/Bitcoin attestation is not independently verified Bitcoin time.", "",
             f"Orphan assets inventoried without blind payload download: {sum(len(item['orphan_assets']) for item in report['releases'])}.", ""]
    for item in report["captures"]:
        if item.get("errors") or item.get("part_gaps") or item["classification"] != "accepted_complete":
            lines += [f"- `{item['repository']}` / `{item['source_index']['release_tag']}`: {item['classification']}; "
                      f"errors={len(item.get('errors', []))}, part gaps={len(item.get('part_gaps', []))}."]
    lines += ["", "The JSON report and per-capture checkpoints retain exact source-index and encrypted migration/transport references. This is byte recoverability plus bounded restore sampling; it does not establish source authenticity, atomic collection, first-publication time, or exhaustive Git graph recovery.", ""]
    return "\n".join(lines)


def run_audit(github: GitHubReadOnly, cohort: Cohort, snapshot: dict, approved_tags: tuple[str, ...],
              budget: LocalBudget, private_key_path: Path, report_root: Path, *, spot_count: int = 12) -> dict:
    captures, releases = catalog_lineage(github, cohort, snapshot, approved_tags)
    selected = select_spotchecks(captures, maximum=spot_count)
    checkpoints = report_root / "captures"
    budget.register_root(report_root)
    results = []
    for capture in captures:
        path = checkpoints / (capture.key + ".json")
        if path.exists():
            previous = json.loads(path.read_bytes())
            if previous.get("source_index") != capture.source_index:
                raise ValueError("Existing recovery checkpoint source identity differs")
            if previous.get("audit_complete") is True:
                results.append(previous)
                continue
        result = audit_capture(capture, github, budget, private_key_path)
        save_json(path, result, budget)
        results.append(result)
    legacy_results = []
    for release in releases:
        assets = next((capture.assets for capture in captures if capture.tag == release["tag"]), None)
        if assets is None:
            assets = github.assets(release["release_id"])
        for entry in release["indexed_legacy_zip_transports"]:
            key = sha256(canonical_json({"release": release["tag"], "migration": release["migration_reference"], "entry": entry}))
            path = report_root / "legacy" / (key + ".json")
            previous = json.loads(path.read_bytes()) if path.exists() else None
            if previous and previous.get("audit_complete") is True:
                result = previous
            else:
                result = audit_legacy_zip(entry, release, assets, github, budget, private_key_path)
                save_json(path, result, budget)
            legacy_results.append(result)
    report = {"schema_version": 1, "audit_finished_at": utc_iso(), "repository": github.repository,
              "audit_implementation_sha256": AUDIT_IMPLEMENTATION, "python": sys.version,
              "approved_release_tags": list(approved_tags), "expected_repositories": len(cohort.repositories),
              "sources": cohort.sources, "inventory_sha256": snapshot["inventory_sha256"],
              "readiness_snapshot": {key: value for key, value in snapshot.items() if key != "inventory"},
              "releases": releases, "selected_git_spot_capture_keys": selected, "captures": results, "legacy_archives": legacy_results,
              "budget": budget.snapshot().as_dict(), "audit_complete": all(item.get("audit_complete") is True for item in results + legacy_results),
              "human_review": "mechanical_audit_complete_GPT_review_pending"}
    save_json(report_root / "recovery-audit.json", report, budget)
    text = render_review(report).encode()
    with budget.stage(len(text), suffix=".md", purpose="bounded human recovery audit report") as stage:
        with stage.open_writer() as target:
            target.write(text)
        os.replace(stage.path, report_root / "RECOVERY_REVIEW.md")
    return report
