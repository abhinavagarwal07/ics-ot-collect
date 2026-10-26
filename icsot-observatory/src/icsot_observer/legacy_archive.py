"""Bounded import of an unchanged, authenticated legacy baseline archive.

The source index and each capsule binding are frozen inputs, not a new
observation. Only one authenticated compressed part is staged at a time; the
XZ and tar streams are never joined on disk. The output is provisional until
this function returns and is emptied on failure. Git graph verification and
the derivation receipt belong to the caller.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO, Callable, ContextManager, Mapping, Sequence

from .archive_reader import ArchiveError, _ChunkReader, _pax_fields, _safe_path, _xz_chunks
from . import encryption
from .core import canonical_json
from .legacy_capsules import decrypt_capsule_stream, inspect_capsule, read_envelope_aad
from .localbudget import LocalBudget

_CHUNK = 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CAS = re.compile(r"evidence/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})\Z")
_SLUG = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")


@dataclass(frozen=True)
class RestoreLimits:
    """Host-selected bounds; the owner's local 2 GB policy is not a Linux cap."""

    max_staging_bytes: int = 1024 ** 3
    max_restore_bytes: int = 48 * 1024 ** 3
    max_tar_stream_bytes: int = 64 * 1024 ** 3
    max_member_bytes: int = 32 * 1024 ** 3
    # An admission ceiling, not a claim about uninspected retained archives.
    # Every created directory must itself be an earlier tar member.
    max_members: int = 200_000
    max_path_depth: int = 32
    max_metadata_bytes: int = 16 * _CHUNK
    max_index_bytes: int = 16 * _CHUNK
    max_parts: int = 100_000
    xz_memory_limit: int = 64 * _CHUNK
    filesystem_allocation_unit_bytes: int = 4096

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in self.__dict__.values()):
            raise ValueError("Restore bounds must be positive integers")
        if self.max_metadata_bytes > 16 * _CHUNK or self.max_index_bytes > 16 * _CHUNK:
            raise ValueError("Metadata/index bounds may not exceed 16 MiB")


@dataclass(frozen=True)
class LegacyPartRef:
    """An ordered frozen transport/capsule pair. No payload URL is inferred."""

    binding: Mapping[str, Any]
    capsule: bytes


@dataclass
class LegacyArchiveImport:
    evidence_root: Path
    source_index_sha256: str
    manifest_paths: list[Path]
    manifest_sha256: str
    manifest: dict[str, Any]
    files: list[dict[str, Any]]
    cas: dict[str, dict[str, Any]]
    parts: list[dict[str, Any]]
    compressed_sha256: str
    compressed_bytes: int
    restored_bytes: int
    restored_entries: int = 0
    allocation_guard: dict[str, int] = field(default_factory=dict)
    compressed_hash_source: str = "derived_at_import"
    git_validation: str = "caller_must_verify_bundle_and_heads"


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArchiveError("Duplicate JSON field")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError):
        raise ArchiveError("Invalid bounded JSON object") from None
    if not isinstance(value, dict):
        raise ArchiveError("Expected a JSON object")
    return value


def _hash(value: Any) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ArchiveError("Expected a declared SHA-256 identity")
    return value


def _identity(value: Any) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or type(value.get("bytes")) is not int
            or value["bytes"] <= 0 or not isinstance(value.get("name"), str)
            or "/" in value["name"] or "\\" in value["name"]):
        raise ArchiveError("Invalid declared archive part identity")
    _safe_path(value["name"])
    return {"name": value["name"], "sha256": _hash(value.get("sha256")), "bytes": value["bytes"]}


def _read_index(source: bytes | str | os.PathLike, limit: int) -> bytes:
    if isinstance(source, bytes):
        raw = source
    else:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ArchiveError("Source index must be a regular file")
            raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ArchiveError("Source index exceeds its bounded size")
    return raw


def normalize_legacy_parts(index: dict[str, Any], transport_overrides: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Normalize frozen native/migrated parts without payload or key I/O.

    Each ordered row is ``{"plaintext": {name,sha256,bytes}, "ciphertext":
    {name,sha256,bytes}}``. Legacy plaintext indexes require the exact frozen
    ``capture_baseline`` migration alias keyed by original plaintext name.
    """
    archive = index.get("archive")
    if not isinstance(archive, dict) or not isinstance(archive.get("parts"), list) or not archive["parts"]:
        raise ArchiveError("Missing ordered archive parts")
    overrides, selected, names, cipher_names = dict(transport_overrides or {}), [], set(), set()
    for part in archive["parts"]:
        original = _identity(part)
        if original["name"] in names:
            raise ArchiveError("Duplicate archive part name")
        names.add(original["name"])
        if isinstance(part.get("plaintext"), dict):
            plain, cipher = _identity(part["plaintext"]), original
            if original["name"] in overrides:
                raise ArchiveError("Native encrypted part may not have a transport override")
        else:
            alias = overrides.pop(original["name"], None)
            if not isinstance(alias, dict) or alias.get("plaintext") != original:
                raise ArchiveError("Legacy plaintext part requires its exact frozen transport alias")
            plain, cipher = original, _identity(alias.get("ciphertext"))
        if cipher["name"] in cipher_names:
            raise ArchiveError("Duplicate transport part name")
        cipher_names.add(cipher["name"])
        selected.append({"plaintext": plain, "ciphertext": cipher})
    if overrides:
        raise ArchiveError("Unused transport overrides")
    return selected


def preflight_legacy_archive(source_index: bytes | str | os.PathLike,
                            part_refs: Sequence[LegacyPartRef], *, expected_index_sha256: str,
                            expected_repository: str, expected_repository_id: int,
                            expected_manifest_sha256: str, limits: RestoreLimits = RestoreLimits(),
                            transport_overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate frozen metadata without opening payloads or private keys.

    ``maximum_required_disk_bytes`` includes the restore cap, the largest
    single compressed part, and conservative directory/file allocation. Each
    parent directory must be declared before its children, so at most one
    filesystem entry is created per tar member, regardless of path depth. The
    original format has no decompressed size, so a sealed size cannot provide
    a smaller safe restore reservation.
    """
    raw = _read_index(source_index, limits.max_index_bytes)
    index_hash = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(index_hash, _hash(expected_index_sha256)):
        raise ArchiveError("Source index SHA-256 mismatch")
    if (not isinstance(expected_repository, str) or not _SLUG.fullmatch(expected_repository)
            or type(expected_repository_id) is not int or expected_repository_id <= 0):
        raise ArchiveError("Invalid expected repository identity")
    index = _json(raw)
    if index.get("repository") != expected_repository:
        raise ArchiveError("Source index repository identity mismatch")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1 or not isinstance(manifests[0], dict):
        raise ArchiveError("Legacy baseline must declare exactly one source manifest")
    manifest = manifests[0]
    manifest_path = _safe_path(manifest.get("path", ""))
    if (not manifest_path.startswith(f"runs/{expected_repository_id}/")
            or not manifest_path.endswith(".manifest.json")
            or type(manifest.get("repository_id")) is not int or manifest["repository_id"] != expected_repository_id
            or manifest.get("sha256") != _hash(expected_manifest_sha256)
            or type(manifest.get("bytes")) is not int
            or not 0 < manifest["bytes"] <= limits.max_metadata_bytes):
        raise ArchiveError("Source manifest identity mismatch")
    archive = index.get("archive")
    if not isinstance(archive, dict) or archive.get("complete") is not True:
        raise ArchiveError("Incomplete original archive")
    parts = archive.get("parts")
    if (not isinstance(parts, list) or not 0 < len(parts) <= limits.max_parts
            or len(part_refs) != len(parts)):
        raise ArchiveError("Missing or excessive ordered archive parts")
    selected, asset_ids = [], set()
    normalized = normalize_legacy_parts(index, transport_overrides)
    for ordinal, (part, ref) in enumerate(zip(normalized, part_refs), 1):
        if not isinstance(ref, LegacyPartRef):
            raise ArchiveError("Invalid part reference")
        plain, cipher = part["plaintext"], part["ciphertext"]
        if plain["bytes"] > limits.max_staging_bytes:
            raise ArchiveError("Compressed part exceeds the staging byte cap")
        context = inspect_capsule(ref.capsule)["context"]
        binding = dict(ref.binding)
        if any(context.get(key) != value for key, value in binding.items()):
            raise ArchiveError("Capsule differs from frozen part binding")
        # inspect_capsule validates the exact binding field set; also prohibit
        # incomplete external bindings that would otherwise omit an identity.
        expected_fields = {key for key in context if not key.startswith(("original_", "owner_key_", "operational_key_"))}
        if set(binding) != expected_fields:
            raise ArchiveError("Incomplete frozen capsule binding")
        expected = {"repository": expected_repository, "repository_id": expected_repository_id,
                    "release_repository": index.get("release_repository"), "release_tag": index.get("release_tag"),
                    "sealed_index_sha256": index_hash, "asset_name": cipher["name"],
                    "ciphertext_sha256": cipher["sha256"], "ciphertext_bytes": cipher["bytes"],
                    "part_number": ordinal, "part_count": len(parts)}
        if any(binding.get(key) != value for key, value in expected.items()):
            raise ArchiveError("Ordered archive part binding differs from source identity")
        if binding["asset_id"] in asset_ids:
            raise ArchiveError("Duplicate transport asset ID")
        asset_ids.add(binding["asset_id"])
        if selected and any(binding[key] != selected[0]["ref"].binding[key]
                            for key in ("release_id", "release_repository", "release_tag")):
            raise ArchiveError("Archive parts disagree on original release identity")
        selected.append({"plaintext": plain, "ciphertext": cipher,
                         "ref": LegacyPartRef(MappingProxyType(binding), ref.capsule)})
    compressed_bytes = sum(part["plaintext"]["bytes"] for part in selected)
    if "bytes" in archive and (type(archive["bytes"]) is not int or archive["bytes"] != compressed_bytes):
        raise ArchiveError("Whole compressed archive size mismatch")
    if "sha256" in archive:
        _hash(archive["sha256"])
    for field in ("config_source_sha256", "csv_sha256"):
        _hash(index.get(field))
    # One allocation unit for final-block rounding/directory payload, plus
    # 4096 bytes per inode/entry for metadata. The importer checks the actual
    # host allocation unit before transport opens. Eight entries cover owned
    # staging/control paths beyond the bounded tar member count.
    overhead = (limits.max_members + 8) * (limits.filesystem_allocation_unit_bytes + 4096)
    peak_part = max(part["plaintext"]["bytes"] for part in selected)
    return {"index": index, "source_index_sha256": index_hash, "parts": selected,
            "manifest_path": "evidence/" + manifest_path, "compressed_bytes": compressed_bytes,
            "max_staged_part_bytes": peak_part, "restore_cap_bytes": limits.max_restore_bytes,
            "max_filesystem_entries": limits.max_members,
            "filesystem_allocation_unit_bytes": limits.filesystem_allocation_unit_bytes,
            "allocation_overhead_bytes": overhead,
            "maximum_required_disk_bytes": limits.max_restore_bytes + peak_part + overhead}


def _owned_empty_directory(path: Path):
    if not path.is_absolute():
        raise ArchiveError("Import directories must be absolute owned paths")
    for candidate in (path, *path.parents):
        if not stat.S_ISDIR(candidate.lstat().st_mode):
            raise ArchiveError("Import directory ancestors must be real directories")
    if path.stat().st_uid != os.getuid() or any(path.iterdir()):
        raise ArchiveError("Import output must be an empty owned directory")


def _allocated(path: Path) -> int:
    info = path.lstat()
    if not hasattr(info, "st_blocks") or info.st_blocks < 0:
        raise ArchiveError("Host filesystem does not expose physical allocation accounting")
    return info.st_blocks * 512


def _mtime(member, fields):
    try:
        value = float(fields.get("mtime", member.mtime))
    except (ValueError, TypeError, OverflowError):
        raise ArchiveError("Invalid tar modification time") from None
    if not math.isfinite(value) or abs(value) > 1e12:
        raise ArchiveError("Invalid tar modification time")
    return value


class _PrefixedReader:
    def __init__(self, prefix: bytes, source: BinaryIO):
        self.prefix, self.offset, self.source = prefix, 0, source

    def read(self, size: int) -> bytes:
        if size <= 0:
            raise ArchiveError("Encrypted stream reads must be explicitly bounded")
        if self.offset < len(self.prefix):
            result = self.prefix[self.offset:self.offset + size]
            self.offset += len(result)
            return result
        return self.source.read(size)


def _restore_tar(source: _ChunkReader, root: Path, limits: RestoreLimits):
    files, cas, seen, directories = [], {}, set(), {}
    pending, global_fields, longname, extensions, headers, total = {}, {}, None, 0, 0, 0
    while True:
        block = source.exact(512)
        if block == b"\0" * 512:
            if pending or longname is not None or source.exact(512) != b"\0" * 512:
                raise ArchiveError("Invalid tar end marker or unapplied metadata")
            while trailing := source.read(_CHUNK):
                if trailing.strip(b"\0"):
                    raise ArchiveError("Unexpected data after tar end marker")
            break
        try:
            member = tarfile.TarInfo.frombuf(block, encoding="utf-8", errors="strict")
        except (tarfile.HeaderError, UnicodeError, ValueError):
            raise ArchiveError("Invalid tar header") from None
        headers += 1
        if headers > limits.max_members * 4:
            raise ArchiveError("Tar header count exceeds the bound")
        if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            extensions += 1
            if extensions > 16 or not 0 <= member.size <= limits.max_metadata_bytes:
                raise ArchiveError("Tar extension metadata exceeds the bound")
            raw = source.exact(member.size)
            if source.exact((-member.size) % 512).strip(b"\0"):
                raise ArchiveError("Nonzero tar extension padding")
            if member.type == tarfile.GNUTYPE_LONGNAME:
                if longname is not None:
                    raise ArchiveError("Duplicate tar long-name extension")
                try:
                    longname = raw.rstrip(b"\0").decode("utf-8", errors="strict")
                except UnicodeError:
                    raise ArchiveError("Invalid tar long name") from None
            else:
                fields = _pax_fields(raw)
                target = global_fields if member.type == tarfile.XGLTYPE else pending
                if (member.type == tarfile.XGLTYPE and {"path", "size"} & fields.keys()
                        or target.keys() & fields.keys()):
                    raise ArchiveError("Unsupported or duplicate tar extension fields")
                target.update(fields)
                if sum(len(key.encode()) + len(value.encode()) for key, value in target.items()) > limits.max_metadata_bytes:
                    raise ArchiveError("Accumulated tar metadata exceeds the bound")
            continue
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or member.sparse is not None:
            raise ArchiveError("Only nonsparse regular files and directories are permitted")
        fields = {**global_fields, **pending}
        name = fields.get("path", longname if longname is not None else member.name)
        path = _safe_path(name.rstrip("/") if member.isdir() else name)
        if path.split("/", 1)[0] not in {"reports", "evidence"}:
            raise ArchiveError("Tar member is outside the reports/evidence namespace")
        if len(path.split("/")) > limits.max_path_depth:
            raise ArchiveError("Archive path depth exceeds the bound")
        if path in seen:
            raise ArchiveError("Duplicate tar member path")
        seen.add(path)
        if len(seen) > limits.max_members:
            raise ArchiveError("Archive member count exceeds the bound")
        size = member.size
        if "size" in fields:
            if not fields["size"].isascii() or not fields["size"].isdigit() or len(fields["size"]) > 20:
                raise ArchiveError("Invalid PAX member size")
            size = int(fields["size"])
        mtime = _mtime(member, fields)
        pending, longname, extensions = {}, None, 0
        if size < 0 or size > limits.max_member_bytes:
            raise ArchiveError("Tar member size exceeds the bound")
        destination = root / path
        parent = path.rpartition("/")[0]
        if parent and root / parent not in directories:
            raise ArchiveError("Tar parent directory must be declared before its children")
        if member.isdir():
            if size:
                raise ArchiveError("Tar directory carries a payload")
            destination.mkdir(mode=0o700)
            directories[destination] = mtime
            continue
        total += size
        if total > limits.max_restore_bytes:
            raise ArchiveError("Restored payload exceeds the restore byte cap")
        digest, remaining = hashlib.sha256(), size
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as target:
            while remaining:
                chunk = source.exact(min(_CHUNK, remaining))
                target.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        if source.exact((-size) % 512).strip(b"\0"):
            raise ArchiveError("Nonzero tar member padding")
        os.utime(destination, (mtime, mtime), follow_symlinks=False)
        record = {"path": path, "bytes": size, "sha256": digest.hexdigest()}
        match = _CAS.fullmatch(path)
        if path.startswith("evidence/objects/sha256/"):
            if not match or match[1] != match[2][:2] or not hmac.compare_digest(match[2], record["sha256"]):
                raise ArchiveError("Content-addressed member SHA-256 mismatch")
            cas[match[2]] = record
        files.append(record)
    for path, mtime in sorted(directories.items(), key=lambda row: len(row[0].parts), reverse=True):
        os.utime(path, (mtime, mtime), follow_symlinks=False)
    allocated = _allocated(root) + sum(_allocated(root / path) for path in seen)
    return files, cas, total, len(seen), allocated


def _validate_restored(plan, root, files, cas, expected_repository, expected_repository_id, limits):
    inventory = {row["path"]: row for row in files}
    declared = plan["index"]["manifests"][0]
    record = inventory.get(plan["manifest_path"])
    if record is None or any(record[key] != declared[key] for key in ("bytes", "sha256")):
        raise ArchiveError("Missing or altered source manifest")
    manifest = _json((root / record["path"]).read_bytes())
    if (type(manifest.get("repository_id")) is not int or manifest["repository_id"] != expected_repository_id
            or manifest.get("repository_input_slug") != expected_repository
            or manifest.get("run_id") != declared.get("run_id")):
        raise ArchiveError("Restored manifest repository/capture identity mismatch")
    for key in ("public_config_sha256", "status", "mode", "started_at", "finished_at"):
        if key in declared and manifest.get(key) != declared[key]:
            raise ArchiveError("Restored manifest differs from frozen source metadata")
    if "public_config" in manifest:
        if (not isinstance(manifest["public_config"], dict)
                or hashlib.sha256(canonical_json(manifest["public_config"])).hexdigest() != manifest.get("public_config_sha256")):
            raise ArchiveError("Original public config digest differs from original manifest")
    actual_manifests = {path for path in inventory if path.startswith("evidence/runs/") and path.endswith(".manifest.json")}
    if actual_manifests != {plan["manifest_path"]}:
        raise ArchiveError("Unexpected source manifest namespace")
    for path, field in (("reports/config.corpus.toml", "config_source_sha256"),
                        ("reports/public_patch_corpus_185.csv", "csv_sha256")):
        if inventory.get(path, {}).get("sha256") != plan["index"][field]:
            raise ArchiveError("Restored original source config/CSV hash mismatch")
    responses = manifest.get("responses")
    if not isinstance(responses, list):
        raise ArchiveError("Invalid original response manifest")
    for response in responses:
        if not isinstance(response, dict):
            raise ArchiveError("Invalid original response record")
        if response.get("body_sha256"):
            digest = _hash(response["body_sha256"])
            if (digest not in cas or type(response.get("body_bytes")) is not int
                    or cas[digest]["bytes"] != response["body_bytes"]):
                raise ArchiveError("Missing or wrong-sized source response CAS object")
    git = manifest.get("git") or {}
    if not isinstance(git, dict):
        raise ArchiveError("Invalid original Git manifest")
    bundle = git.get("portable_full_bundle")
    if bundle is not None:
        if (not isinstance(bundle, dict) or _hash(bundle.get("sha256")) not in cas
                or type(bundle.get("bytes")) is not int or cas[bundle["sha256"]]["bytes"] != bundle["bytes"]):
            raise ArchiveError("Missing or wrong-sized original portable bundle CAS object")
    if git and plan["index"]["archive"].get("git_mirror_included") is False:
        verification = plan["index"].get("verification") or {}
        if (not bundle or verification.get("ok") is not True
                or verification.get("portable_git_bundles_verified") != 1):
            raise ArchiveError("Omitted Git mirror lacks original verified portable bundle")
    # Immutable proof sidecars and the create-only identity registry must survive
    # the same archive closure; they are never recreated or restamped here.
    proof = plan["manifest_path"] + ".ots"
    if proof not in inventory or inventory[proof]["bytes"] <= 0:
        raise ArchiveError("Missing original manifest timestamp proof")
    registry = "evidence/registry/" + expected_repository.lower().replace("/", "__") + ".json"
    if registry not in inventory or inventory[registry]["bytes"] > limits.max_metadata_bytes:
        raise ArchiveError("Missing or oversized source identity registry")
    binding = _json((root / registry).read_bytes())
    if (type(binding.get("repository_id")) is not int or binding["repository_id"] != expected_repository_id
            or binding.get("input_slug") != expected_repository):
        raise ArchiveError("Restored registry repository identity mismatch")
    return manifest


def import_legacy_archive(source_index: bytes | str | os.PathLike, part_refs: Sequence[LegacyPartRef], *,
                          expected_index_sha256: str, expected_repository: str, expected_repository_id: int,
                          expected_manifest_sha256: str, output_root: str | os.PathLike,
                          staging_root: str | os.PathLike,
                          open_part: Callable[[LegacyPartRef], ContextManager[BinaryIO]],
                          operational_private_key_path: str | os.PathLike,
                          limits: RestoreLimits = RestoreLimits(),
                          transport_overrides: Mapping[str, Any] | None = None,
                          budget: LocalBudget | None = None) -> LegacyArchiveImport:
    """Restore original reports/evidence bytes after authenticating each part.

    ``open_part`` supplies only the selected immutable asset. It must not stage
    unaccounted downloads. This adapter itself stages no ciphertext. With a
    local budget it reserves both the bounded restoration and one compressed
    plaintext stage, including allocation overhead, before opening transport.
    """
    plan = preflight_legacy_archive(source_index, part_refs, expected_index_sha256=expected_index_sha256,
        expected_repository=expected_repository, expected_repository_id=expected_repository_id,
        expected_manifest_sha256=expected_manifest_sha256, limits=limits, transport_overrides=transport_overrides)
    root, stage_parent = Path(output_root), Path(staging_root)
    _owned_empty_directory(root)
    # Staging may contain other workers' owned stages, but never symlink through
    # an ancestor or write inside the output tree.
    for candidate in (stage_parent, *stage_parent.parents):
        if not candidate.is_absolute() or not stat.S_ISDIR(candidate.lstat().st_mode):
            raise ArchiveError("Staging ancestors must be real absolute directories")
    if root == stage_parent or root in stage_parent.parents or stage_parent in root.parents:
        raise ArchiveError("Restore and staging directories must not overlap")
    for directory in (root, stage_parent):
        space = os.statvfs(directory)
        allocation_unit = space.f_frsize or space.f_bsize
        if not 0 < allocation_unit <= limits.filesystem_allocation_unit_bytes:
            raise ArchiveError("Host filesystem allocation unit exceeds the reserved bound")
        _allocated(directory)
    with contextlib.ExitStack() as stack:
        if budget is not None:
            reservation = stack.enter_context(budget.reserve(plan["maximum_required_disk_bytes"],
                                                             purpose="bounded legacy baseline import"))
            reservation.track(root)
        else:
            reservation = None
        temporary = Path(tempfile.mkdtemp(prefix=".legacy-archive-", dir=stage_parent))
        stack.callback(shutil.rmtree, temporary)
        if reservation is not None:
            reservation.track(temporary)
        digest, count, part_results, peak_stage_allocation = hashlib.sha256(), 0, [], 0

        def plaintext():
            nonlocal count, peak_stage_allocation
            path = temporary / "authenticated.xz.part"
            for part in plan["parts"]:
                ref = part["ref"]
                try:
                    with open_part(ref) as encrypted:
                        aad = read_envelope_aad(encrypted)
                        header, _, _ = encryption._parse_header(aad[encryption._PREFIX.size:])
                        if (header["plaintext_bytes"] != part["plaintext"]["bytes"]
                                or header["plaintext_sha256"] != part["plaintext"]["sha256"]):
                            raise ArchiveError("Envelope compressed part exceeds or differs from frozen plaintext identity")
                        metadata = decrypt_capsule_stream(_PrefixedReader(aad, encrypted), path, ref.capsule, binding=dict(ref.binding),
                            operational_private_key_path=operational_private_key_path)
                    if (metadata["plaintext_bytes"] != part["plaintext"]["bytes"]
                            or metadata["plaintext_sha256"] != part["plaintext"]["sha256"]):
                        raise ArchiveError("Authenticated compressed part differs from original source index")
                    peak_stage_allocation = max(peak_stage_allocation, _allocated(path) + _allocated(temporary))
                    with path.open("rb") as source:
                        while chunk := source.read(_CHUNK):
                            digest.update(chunk)
                            count += len(chunk)
                            yield chunk
                    part_results.append({**dict(ref.binding), "plaintext_sha256": metadata["plaintext_sha256"],
                                         "plaintext_bytes": metadata["plaintext_bytes"], "authentication": "original_gcm_verified"})
                finally:
                    path.unlink(missing_ok=True)
            if count != plan["compressed_bytes"]:
                raise ArchiveError("Concatenated original compressed byte count mismatch")
            expected_hash = plan["index"]["archive"].get("sha256")
            if expected_hash is not None and not hmac.compare_digest(digest.hexdigest(), expected_hash):
                raise ArchiveError("Whole original compressed archive SHA-256 mismatch")

        chunks = plaintext()
        source = _ChunkReader(_xz_chunks(chunks, memory_limit=limits.xz_memory_limit,
                                        max_output_bytes=limits.max_tar_stream_bytes))
        try:
            files, cas, total, entries, allocated = _restore_tar(source, root, limits)
            allocation_cap = limits.max_restore_bytes + plan["allocation_overhead_bytes"]
            if allocated + peak_stage_allocation > allocation_cap + plan["max_staged_part_bytes"]:
                raise ArchiveError("Physical filesystem allocation exceeds the reserved import cap")
            manifest = _validate_restored(plan, root, files, cas, expected_repository, expected_repository_id, limits)
            if reservation is not None:
                reservation.check()
            return LegacyArchiveImport(root / "evidence", plan["source_index_sha256"],
                [root / plan["manifest_path"]], expected_manifest_sha256, manifest, files, cas,
                part_results, digest.hexdigest(), count, total, restored_entries=entries,
                allocation_guard={"actual_restored_allocated_bytes": allocated,
                    "actual_peak_staged_allocated_bytes": peak_stage_allocation,
                    "maximum_reserved_bytes": plan["maximum_required_disk_bytes"],
                    "allocation_overhead_bytes": plan["allocation_overhead_bytes"],
                    "configured_allocation_unit_bytes": limits.filesystem_allocation_unit_bytes,
                    "max_filesystem_entries": limits.max_members},
                compressed_hash_source="original_index" if "sha256" in plan["index"]["archive"] else "derived_at_import")
        except BaseException:
            for child in root.iterdir():
                shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
            raise
        finally:
            source.close()
            chunks.close()
