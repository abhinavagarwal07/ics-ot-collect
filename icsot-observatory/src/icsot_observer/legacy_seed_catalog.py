"""Explicit legacy package prerequisites, not synthetic capture indexes.

An import receipt and member inventory describe a verified derivation. Original
index, manifest, timestamp proofs and encrypted archive bytes keep their exact
identities. Independent recovery replays those originals before a native
increment; it never needs the operational working state or an upstream clone.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .archive_reader import ArchivePart, VerifiedArchiveReader
from .core import canonical_json, sha256
from .legacy_archive import normalize_legacy_parts

KIND = "legacy_baseline_package_v1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MAX_METADATA_BYTES = 16 * 1024 * 1024


class LegacySeedError(ValueError):
    """A missing or inconsistent prerequisite must pause recovery/export."""


def _hash(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise LegacySeedError("Expected an exact lowercase SHA-256 identity")
    return value


def _path(value):
    if (not isinstance(value, str) or not value or "\\" in value or value.startswith("/")
            or any(part in ("", ".", "..") for part in value.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise LegacySeedError("Unsafe prerequisite member path")
    return value


def _identity(value, *, path=False):
    if (not isinstance(value, dict) or type(value.get("bytes")) is not int or value["bytes"] < 0):
        raise LegacySeedError("Invalid prerequisite byte identity")
    _hash(value.get("sha256"))
    name = _path(value.get("path" if path else "name"))
    if not path and "/" in name:
        raise LegacySeedError("Asset names must be basenames")
    return value


def _asset(value):
    _identity(value)
    if (not SLUG.fullmatch(str(value.get("release_repository", "")))
            or not isinstance(value.get("release_tag"), str) or not value["release_tag"]
            or any(ord(char) < 32 for char in value["release_tag"])
            or any(type(value.get(key)) is not int or value[key] <= 0 for key in ("release_id", "asset_id"))):
        raise LegacySeedError("Invalid frozen source asset reference")
    return value


def _json(source, reference=None):
    if isinstance(source, dict):
        return source  # Caller must already have checked its original-byte hash.
    if not isinstance(source, bytes) or not 0 < len(source) <= MAX_METADATA_BYTES:
        raise LegacySeedError("Bounded original metadata bytes required")
    if reference and (len(source) != reference["bytes"] or sha256(source) != reference["sha256"]):
        raise LegacySeedError("Original metadata bytes differ from frozen reference")
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise LegacySeedError("Duplicate original metadata key")
            obj[key] = value
        return obj
    try:
        result = json.loads(source, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LegacySeedError("Invalid original metadata JSON") from error
    if not isinstance(result, dict):
        raise LegacySeedError("Original metadata must be a JSON object")
    return result


def legacy_seed_digest(seed: dict) -> str:
    return sha256(canonical_json({key: value for key, value in seed.items() if key != "seed_sha256"}))


def seal_legacy_seed(seed_fields: dict) -> dict:
    seed = copy.deepcopy(seed_fields)
    seed.setdefault("membership_scope", "authenticated_subset")
    seed["members"] = sorted(seed.get("members", []), key=lambda item: item["path"])
    seed["membership_sha256"] = sha256(canonical_json(seed["members"]))
    seed["seed_sha256"] = legacy_seed_digest(seed)
    return validate_legacy_seed(seed)


def registerable_members(seed: dict) -> list[dict]:
    return [{"path": item["path"][len("evidence/"):], "sha256": item["sha256"], "bytes": item["bytes"]}
            for item in seed["members"] if item["path"].startswith("evidence/")]


def public_legacy_reference(seed: dict) -> dict:
    return copy.deepcopy(validate_legacy_seed(seed))


def validate_legacy_manifest(seed: dict, raw: bytes) -> dict:
    source = seed["source_manifest"]
    original = _json(raw, source)
    if (original.get("repository_id") != seed["repository_id"] or original.get("repository_input_slug") != seed["slug"]
            or any(original.get(key) != source[key] for key in ("run_id", "started_at", "finished_at"))):
        raise LegacySeedError("Original manifest identity/interval changed")
    return original


def _file_identity(path: Path) -> tuple[str, int]:
    digest, count = hashlib.sha256(), 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            count += len(block)
    return digest.hexdigest(), count


def _under(root: Path, relative: str, *, create=False) -> Path:
    path = root / _path(relative)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        if current.is_symlink():
            raise LegacySeedError("Prerequisite directory may not be a symlink")
        if create:
            current.mkdir(exist_ok=True)
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise LegacySeedError("Prerequisite path escapes its root")
    return path


def validate_legacy_seed(seed: dict, *, repository_id: int | None = None, slug: str | None = None,
                         root: Path | None = None, source_index=None, migration_index=None) -> dict:
    if (not isinstance(seed, dict) or seed.get("schema_version") != 1 or seed.get("kind") != KIND
            or seed.get("membership_scope") != "authenticated_subset"
            or type(seed.get("repository_id")) is not int or seed["repository_id"] <= 0
            or not SLUG.fullmatch(str(seed.get("slug", "")))):
        raise LegacySeedError("Unsupported or invalid legacy seed package")
    if any(key in seed for key in ("encrypted", "capture_id", "lane", "manifest_sha256", "assets")):
        raise LegacySeedError("A legacy source package is not an ordinary native capture index")
    if repository_id is not None and seed["repository_id"] != repository_id or slug is not None and seed["slug"] != slug:
        raise LegacySeedError("Legacy seed repository binding changed")
    if len(canonical_json(seed)) > MAX_METADATA_BYTES:
        raise LegacySeedError("Legacy seed metadata exceeds the explicit bound")
    if _hash(seed.get("seed_sha256")) != legacy_seed_digest(seed):
        raise LegacySeedError("Legacy seed digest differs")
    index_ref = _asset(seed.get("source_index"))
    _hash(seed.get("owner_recipient_spki_sha256"))
    members = seed.get("members")
    if not isinstance(members, list) or not members:
        raise LegacySeedError("Authenticated original member inventory required")
    paths = []
    for item in members:
        _identity(item, path=True)
        name = item["path"]
        if not name.startswith(("evidence/", "reports/")):
            raise LegacySeedError("Original member is outside evidence/reports")
        paths.append(name)
        if name.startswith("evidence/objects/sha256/"):
            parts = name.split("/")
            if len(parts) != 5 or parts[-2] != item["sha256"][:2] or parts[-1] != item["sha256"]:
                raise LegacySeedError("Original CAS member path/hash differs")
    if paths != sorted(set(paths)) or seed.get("membership_sha256") != sha256(canonical_json(members)):
        raise LegacySeedError("Original member inventory order/digest differs")
    source = seed.get("source_manifest")
    _identity(source, path=True)
    if (source["path"] != f"runs/{seed['repository_id']}/{source.get('run_id')}.manifest.json"
            or {"path": "evidence/" + source["path"], "sha256": source["sha256"], "bytes": source["bytes"]} not in members):
        raise LegacySeedError("Original manifest is absent or misbound")
    times = {}
    for key in ("started_at", "finished_at"):
        try:
            stamp = datetime.fromisoformat(source[key].replace("Z", "+00:00"))
            if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
                raise ValueError()
            times[key] = stamp
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            raise LegacySeedError("Original UTC observation interval required") from error
    if times["started_at"] > times["finished_at"]:
        raise LegacySeedError("Original observation interval is reversed")
    receipt = _identity(seed.get("import_receipt"), path=True)
    if receipt["path"].startswith(("objects/", "runs/")) or any(m["path"] == "evidence/" + receipt["path"] for m in members):
        raise LegacySeedError("A new import receipt may not be claimed as originally delivered")
    transport = seed.get("transport")
    if not isinstance(transport, dict) or transport.get("kind") not in ("native_encrypted_baseline", "migrated_encrypted_baseline"):
        raise LegacySeedError("Unsupported original package transport")
    parts = transport.get("parts")
    if not isinstance(parts, list) or not parts:
        raise LegacySeedError("Ordered original archive parts required")
    for ordinal, part in enumerate(parts, 1):
        if not isinstance(part, dict) or type(part.get("ordinal")) is not int or part["ordinal"] != ordinal:
            raise LegacySeedError("Original part order differs")
        _identity(part.get("plaintext"))
        cipher = _asset(part.get("ciphertext"))
        if any(cipher[key] != index_ref[key] for key in ("release_repository", "release_tag", "release_id")):
            raise LegacySeedError("Original encrypted part references another source release")
        if part.get("capsule") is not None:
            _asset(part["capsule"])
    migration_ref = transport.get("migration_index")
    if transport["kind"] == "migrated_encrypted_baseline":
        _asset(migration_ref)
    elif migration_ref is not None:
        raise LegacySeedError("Native encrypted baseline cannot claim migration aliases")
    if source_index is not None:
        index = _json(source_index, index_ref)
        if index.get("repository") != seed["slug"] or index.get("release_tag") != index_ref["release_tag"]:
            raise LegacySeedError("Original source index identity differs")
        if (index.get("archive") or {}).get("complete") is not True:
            raise LegacySeedError("Original source package is incomplete")
        rows = index.get("manifests")
        if not isinstance(rows, list) or len(rows) != 1 or any(rows[0].get(k) != source[k] for k in ("path", "sha256", "bytes", "run_id")):
            raise LegacySeedError("Original source manifest/interval binding differs")
        if any(rows[0].get(key) is not None and rows[0][key] != source[key] for key in ("started_at", "finished_at")):
            raise LegacySeedError("Original source interval binding differs")
        if rows[0].get("repository_id") != seed["repository_id"]:
            raise LegacySeedError("Original source repository ID differs")
        bundle = rows[0].get("portable_full_bundle")
        if bundle:
            expected_bundle = {"path": f"evidence/objects/sha256/{bundle['sha256'][:2]}/{bundle['sha256']}",
                               "sha256": bundle["sha256"], "bytes": bundle["bytes"]}
            if expected_bundle not in members:
                raise LegacySeedError("Original full bundle is not in the delivered seed membership")
        overrides = None
        if migration_ref is not None:
            if migration_index is None:
                raise LegacySeedError("Frozen original migration mapping is required")
            migration = _json(migration_index, migration_ref)
            if (migration.get("release_tag") != index_ref["release_tag"]
                    or migration.get("repository") != index_ref["release_repository"]):
                raise LegacySeedError("Original migration mapping source differs")
            all_overrides = migration.get("parts")
            source_parts = index["archive"].get("parts")
            if not isinstance(all_overrides, dict) or not isinstance(source_parts, list):
                raise LegacySeedError("Frozen original migration part mapping is invalid")
            # A release migration index covers many repositories. Authenticate
            # that whole document above, then give the strict per-package
            # normalizer only aliases named by this unchanged source index.
            overrides = {}
            for part in source_parts:
                name = _identity(part)["name"]
                if name in all_overrides:
                    overrides[name] = all_overrides[name]
        normalized = normalize_legacy_parts(index, overrides)
        expected = [{"plaintext": p["plaintext"], "ciphertext": {k: p["ciphertext"][k] for k in ("name", "sha256", "bytes")}} for p in parts]
        if normalized != expected:
            raise LegacySeedError("Frozen original ordered part identities differ")
    if root is not None:
        root = Path(root).resolve()
        for item in [*registerable_members(seed), receipt]:
            path = _under(root, item["path"])
            if not path.is_file() or _file_identity(path) != (item["sha256"], item["bytes"]):
                raise LegacySeedError("Restored prerequisite member/receipt differs")
        original = validate_legacy_manifest(seed, _under(root, source["path"]).read_bytes())
        receipt_body = _json(_under(root, receipt["path"]).read_bytes(), receipt)
        if receipt_body.get("source_index") is not None and receipt_body["source_index"] != index_ref:
            raise LegacySeedError("Import receipt names a different original source index")
        if receipt_body.get("source_index_sha256", index_ref["sha256"]) != index_ref["sha256"]:
            raise LegacySeedError("Import receipt original source hash differs")
        if receipt_body.get("source_manifest_sha256", source["sha256"]) != source["sha256"]:
            raise LegacySeedError("Import receipt original manifest hash differs")
        delivered = {item["sha256"] for item in registerable_members(seed)}
        if any(record.get("body_sha256") not in delivered for record in original.get("responses") or [] if record.get("body_sha256")):
            raise LegacySeedError("An original response CAS member is not delivered by this seed")
        bundle = (original.get("git") or {}).get("portable_full_bundle")
        if bundle and bundle.get("sha256") not in delivered:
            raise LegacySeedError("Original Git bundle may not be silently reuploaded")
    return seed


def legacy_part_contexts(seed: dict, open_asset: Callable):
    """Owner-key decoder inputs; capsule references remain provenance metadata."""
    @contextmanager
    def part(row):
        cipher, plain = row["ciphertext"], row["plaintext"]
        with open_asset(cipher) as path:
            yield ArchivePart(Path(path), cipher["sha256"], cipher["bytes"], plain["sha256"], plain["bytes"], cipher["name"])
    return [part(row) for row in seed["transport"]["parts"]]


def restore_legacy_seeded_capture(native_index_bytes: bytes, native_index_ref: dict, *, open_asset: Callable,
                                  owner_private_key_path: Path, output_root: Path, budget=None,
                                  max_restore_bytes: int = 64 * 1024 * 1024,
                                  max_archive_bytes: int = 1024 * 1024 * 1024) -> dict:
    """Restore original package(s) then one native increment, without upstream.

    ``open_asset`` resolves only frozen references to local files or bounded
    caller-owned stages. On any error, files created by this call are removed;
    existing evidence is never overwritten. All output is provisional until the
    complete closure returns successfully.
    """
    # Ordinary public native catalogs historically publish tag/name/hash/size,
    # without numeric asset/release IDs. Preserve that existing recovery form;
    # the explicitly typed legacy source references retain their fuller binding.
    _identity(native_index_ref)
    index = _json(native_index_bytes, native_index_ref)
    if index.get("schema_version") != 1 or index.get("encrypted") is not True or type(index.get("repository_id")) is not int:
        raise LegacySeedError("Expected an ordinary encrypted native capture index")
    native_parts = index.get("assets") or ([index["asset"]] if index.get("asset") else [])
    if not isinstance(native_parts, list) or not native_parts:
        raise LegacySeedError("Native encrypted part identities are required before recovery")
    for part in native_parts:
        _identity(part)
        encryption = part.get("encryption") or {}
        _hash(encryption.get("plaintext_sha256"))
        if type(encryption.get("plaintext_bytes")) is not int or encryption["plaintext_bytes"] < 0:
            raise LegacySeedError("Native part plaintext identity is invalid")
        if any(encryption.get(key) != part[field] for key, field in (("ciphertext_sha256", "sha256"), ("ciphertext_bytes", "bytes"))):
            raise LegacySeedError("Native encrypted part metadata disagrees")
    seeds = index.get("legacy_prerequisites") or []
    if not isinstance(seeds, list):
        raise LegacySeedError("Invalid native legacy prerequisite list")
    for seed in seeds:
        validate_legacy_seed(seed, repository_id=index["repository_id"])
    native_members = index.get("members")
    if not isinstance(native_members, list):
        raise LegacySeedError("Native capture member inventory required")
    expected_native = {}
    for member in native_members:
        _identity(member, path=True)
        path = "evidence/" + member["path"]
        if path in expected_native:
            raise LegacySeedError("Duplicate native capture member")
        expected_native[path] = member
    maximum = sum(m["bytes"] for seed in seeds for m in seed["members"]) + sum(m["bytes"] for m in native_members)
    if maximum > max_restore_bytes:
        raise LegacySeedError("Declared restoration exceeds the selected recovery bound")
    output_root = Path(output_root).absolute()
    if output_root.is_symlink():
        raise LegacySeedError("Recovery root may not be a symlink")
    created = []
    wanted_paths = set(expected_native)
    wanted_sizes = {path: item["bytes"] for path, item in expected_native.items()}
    def metadata(ref):
        with open_asset(ref) as path:
            path = Path(path)
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
                raise LegacySeedError("Original metadata exceeds recovery bound")
            raw = path.read_bytes()
        _json(raw, ref)
        return raw
    def receive(record, stream):
        if record.path not in wanted_paths:
            return
        if record.bytes != wanted_sizes[record.path]:
            raise LegacySeedError("Selected archive member size differs from the admitted output size")
        destination = _under(output_root, record.path, create=True)
        if destination.exists():
            return  # Complete scan still authenticates/hash-checks these bytes.
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created.append(destination)
        with os.fdopen(fd, "wb") as target:
            while block := stream.read(min(1024 * 1024, stream.remaining)):
                target.write(block)
    def check_files(records):
        for record in records:
            if record.path not in wanted_paths:
                continue
            if _file_identity(_under(output_root, record.path)) != (record.sha256, record.bytes):
                raise LegacySeedError("Existing or restored immutable member differs")
    all_output_paths = set(expected_native)
    all_output_paths.update(item["path"] for seed in seeds for item in seed["members"])
    implicit_directories = {str(parent) for name in all_output_paths for parent in PurePosixPath(name).parents
                            if str(parent) != "."}
    missing_root_directories = []
    ancestor = output_root
    while not ancestor.exists():
        missing_root_directories.append(ancestor)
        ancestor = ancestor.parent
    admission_root = missing_root_directories[-1] if missing_root_directories else output_root
    allocation_entries = len(all_output_paths) + len(implicit_directories) + len(missing_root_directories) + 8
    reservation = budget.reserve(maximum + allocation_entries * 16384,
                                 purpose="bounded independent legacy/native closure") if budget else nullcontext()
    try:
        with reservation as admitted:
            if budget:
                # This helper owns a new/empty recovery directory.
                admitted.track(admission_root)
            output_root.mkdir(parents=True, exist_ok=True)
            packages = []
            archive_inventory_hashes = {}
            for seed in seeds:
                source = metadata(seed["source_index"])
                migration = metadata(seed["transport"]["migration_index"]) if seed["transport"].get("migration_index") else None
                validate_legacy_seed(seed, source_index=source, migration_index=migration)
                expected = {m["path"]: {"sha256": m["sha256"], "bytes": m["bytes"]} for m in seed["members"]}
                wanted_paths = set(expected)
                wanted_sizes = {path: item["bytes"] for path, item in expected.items()}
                scan = VerifiedArchiveReader(legacy_part_contexts(seed, open_asset), owner_private_key_path,
                    allowed_prefixes=("evidence", "reports"), max_total_bytes=max_archive_bytes,
                    max_tar_stream_bytes=max_archive_bytes + 16 * 1024 * 1024).scan(receive)
                actual = {record.path: {"sha256": record.sha256, "bytes": record.bytes} for record in scan.members if record.path in expected}
                if actual != expected:
                    raise LegacySeedError("A declared original member is absent or differs from the authenticated package")
                check_files(scan.members)
                packages.append(seed["seed_sha256"])
                archive_inventory_hashes[seed["seed_sha256"]] = sha256(canonical_json([
                    {"path": record.path, "sha256": record.sha256, "bytes": record.bytes} for record in scan.members]))
            @contextmanager
            def native_part(part):
                ref = {**native_index_ref, "name": part["name"], "sha256": part["sha256"], "bytes": part["bytes"]}
                # Part IDs need not equal the index asset's ID. Offline resolvers
                # select by the exact release/name/hash, never this index ID.
                ref.pop("asset_id", None)
                with open_asset(ref) as path:
                    encryption = part["encryption"]
                    yield ArchivePart(Path(path), part["sha256"], part["bytes"], encryption["plaintext_sha256"], encryption["plaintext_bytes"], part["name"])
            wanted_paths = set(expected_native)
            wanted_sizes = {path: item["bytes"] for path, item in expected_native.items()}
            scan = VerifiedArchiveReader([native_part(p) for p in native_parts],
                owner_private_key_path, expected_members={p: {"sha256": m["sha256"], "bytes": m["bytes"]} for p, m in expected_native.items()},
                allowed_prefixes=("evidence",), max_total_bytes=max_restore_bytes).scan(receive)
            check_files(scan.members)
            evidence = output_root / "evidence"
            for digest in index.get("requires_cas_sha256") or []:
                _hash(digest)
                path = _under(evidence, f"objects/sha256/{digest[:2]}/{digest}")
                if not path.is_file() or _file_identity(path)[0] != digest:
                    raise LegacySeedError("Native capture CAS prerequisite remains missing")
            selected = _hash(index.get("manifest_sha256"))
            manifests = {sha256(path.read_bytes()): path for path in (evidence / "runs" / str(index["repository_id"])).glob("*.manifest.json")
                         if not path.is_symlink() and path.stat().st_size <= MAX_METADATA_BYTES}
            if selected not in manifests or index.get("previous_manifest_sha256") not in (None, *manifests):
                raise LegacySeedError("Native capture manifest chain prerequisite remains missing")
            for seed in seeds:
                validate_legacy_seed(seed, root=evidence)
                receipt = seed["import_receipt"]
                receipt_body = _json(_under(evidence, receipt["path"]).read_bytes(), receipt)
                if (receipt_body.get("archive_members_sha256") is not None and
                        receipt_body["archive_members_sha256"] != archive_inventory_hashes[seed["seed_sha256"]]):
                    raise LegacySeedError("Import receipt full original archive inventory differs")
            if budget:
                admitted.check()
            return {"status": "restored", "legacy_seed_packages": packages, "native_manifest_sha256": selected,
                    "files_created": len(created), "evidence_root": str(evidence), "restored_bytes_bound": maximum,
                    "qualification": "Original observations/proofs are unchanged; import is a later derivation, not a new source observation."}
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        parents = {parent for path in created for parent in path.parents
                   if parent != output_root and parent.is_relative_to(output_root)}
        for parent in sorted(parents, key=lambda path: len(path.parts), reverse=True):
            try:
                parent.rmdir()
            except OSError:
                pass
        raise
