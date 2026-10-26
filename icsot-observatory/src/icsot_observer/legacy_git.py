"""Derive an incremental Git seed from authenticated legacy full-bundle bytes.

Authentication of the encrypted source archive and selection of its sealed
index happen in the caller. Expected hashes/context must come from that trusted
selection, not from an unauthenticated public acceptance summary. This helper
performs content binding and independent Git closure verification; it neither
loads keys nor contacts a source or destination service.
"""
from __future__ import annotations

import copy
import fcntl
import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .checks import _git_namespace
from .core import ObjectStore, REPO_RE, canonical_json, sha256, utc_iso, write_once
from .gitarchive import _bundle_header, _refs, descriptor_digest
from .gitstore import _validate_oid, _verify_advertised_objects, run_git

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_CONTEXT = frozenset({
    "repository_id", "repository", "source_release_repository", "source_release_tag", "source_release_id",
    "source_index_asset", "source_index_asset_id", "source_index_sha256", "source_index_bytes",
    "manifest_sha256", "collector_code_sha",
})


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field in legacy source JSON")
        result[key] = value
    return result


def _document(raw: bytes, expected: str, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not _HASH.fullmatch(expected) or sha256(raw) != expected:
        raise ValueError(f"Legacy {label} differs from the independently selected hash")
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError(f"Legacy {label} must be a JSON object")
    return value


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Legacy import requires explicit UTC timestamps")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _exact_file(path: Path, raw: bytes) -> None:
    try:
        write_once(path, raw)
    except FileExistsError:
        if path.read_bytes() != raw:
            raise RuntimeError("Conflicting immutable legacy Git import record")


def _validate_context(source: dict, manifest: dict, index: dict, *, manifest_hash: str,
                      index_hash: str, index_bytes: int) -> tuple[str, dict]:
    if not isinstance(source, dict) or source.keys() != _CONTEXT:
        raise ValueError("Unexpected legacy Git import source context")
    for field in ("repository_id", "source_release_id", "source_index_asset_id", "source_index_bytes"):
        if type(source[field]) is not int or source[field] <= 0:
            raise ValueError("Invalid numeric legacy Git import source identity")
    for field in ("repository", "source_release_repository"):
        if not isinstance(source[field], str) or not REPO_RE.fullmatch(source[field]):
            raise ValueError("Invalid legacy Git import repository identity")
    tag = source["source_release_tag"]
    asset = source["source_index_asset"]
    if (not isinstance(tag, str) or not 0 < len(tag.encode()) <= 255 or
            any(ord(c) < 32 or ord(c) == 127 for c in tag) or
            not isinstance(asset, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", asset) is None):
        raise ValueError("Invalid immutable legacy index transport identity")
    if (source["manifest_sha256"] != manifest_hash or source["source_index_sha256"] != index_hash or
            source["source_index_bytes"] != index_bytes or not isinstance(source["collector_code_sha"], str) or
            not _CODE.fullmatch(source["collector_code_sha"])):
        raise ValueError("Legacy source context differs from selected content identities")
    if (type(manifest.get("repository_id")) is not int or manifest.get("repository_id") != source["repository_id"] or
            manifest.get("repository_input_slug") != source["repository"] or
            index.get("repository") != source["repository"] or
            index.get("collector_code_sha") != source["collector_code_sha"]):
        raise ValueError("Legacy manifest/index repository or collector identity mismatch")
    for key, field in (("release_repository", "source_release_repository"), ("release_tag", "source_release_tag")):
        if key in index and index[key] != source[field]:
            raise ValueError("Legacy sealed index transport context mismatch")
    matches = [entry for entry in index.get("manifests", []) if entry.get("sha256") == manifest_hash]
    if (len(matches) != 1 or type(matches[0].get("repository_id")) is not int or
            matches[0].get("repository_id") != source["repository_id"]):
        raise ValueError("Original manifest is not uniquely bound by the selected sealed index")
    entry = matches[0]
    if entry.get("run_id") != manifest.get("run_id"):
        raise ValueError("Legacy manifest run differs from sealed index")
    capture = manifest.get("capture_id", manifest["run_id"])
    if not isinstance(capture, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", capture) is None:
        raise ValueError("Invalid original Git capture namespace")
    original_path = entry.get("path", f"runs/{source['repository_id']}/{manifest['run_id']}.manifest.json")
    path = Path(original_path)
    if (path.is_absolute() or ".." in path.parts or len(path.parts) != 3 or
            path.parts[:2] != ("runs", str(source["repository_id"])) or not path.name.endswith(".manifest.json")):
        raise ValueError("Unsafe original legacy manifest member path")
    return original_path, entry


def _full_bundle_context(path: Path, object_format: str) -> tuple[list[str], dict[str, str]]:
    prerequisites, refs = _bundle_header(path)
    if prerequisites:
        raise ValueError("Legacy portable full bundle has object prerequisites")
    with path.open("rb") as stream:
        stream.readline()
        while True:
            line = stream.readline(1024 * 1024)
            if line == b"\n":
                break
            if not line.endswith(b"\n"):
                raise ValueError("Incomplete legacy Git bundle header")
            if line.startswith(b"@") and line != f"@object-format={object_format}\n".encode():
                raise ValueError("Filtered or unsupported legacy full-bundle capability")
    return prerequisites, refs


def _no_external_object_supply(repo: Path) -> None:
    """Reject alternate/promisor supplies before reading existing Git objects."""
    if (repo.is_symlink() or (repo / "config").is_symlink() or (repo / ".git").exists() or
            (repo / "commondir").exists() or (repo / "config.worktree").exists()):
        raise ValueError("Legacy import requires self-contained bare Git configuration")
    objects = repo / "objects"
    if any(path.is_symlink() for path in (objects, objects / "info", objects / "pack")):
        raise ValueError("Legacy mirror object storage must not use external links")
    alternates = objects / "info" / "alternates"
    if alternates.exists() or alternates.is_symlink() or list((objects / "pack").glob("*.promisor")):
        raise ValueError("Legacy mirror must not borrow alternate or promisor objects")
    # Do not follow config includes from an imported mirror: they can name
    # files outside the authenticated archive and supply a promisor remote.
    configuration = run_git(["-C", str(repo), "config", "--local", "--no-includes", "--list"])
    for line in configuration.splitlines():
        name = line.split("=", 1)[0].lower()
        if (name.startswith(("include.", "includeif.")) or name in ("extensions.partialclone", "extensions.worktreeconfig") or
                (name.startswith("remote.") and name.endswith((".promisor", ".partialclonefilter")))):
            raise ValueError("Legacy mirror has external include or partial-clone configuration")


def import_legacy_git(root: Path, manifest_raw: bytes, sealed_index_raw: bytes, *,
                      expected_manifest_sha256: str, expected_index_sha256: str,
                      source_context: dict[str, Any], importer_code_sha: str,
                      imported_at_utc: str | None = None) -> dict[str, Any]:
    """Create a derived full-history archive head without a new observation.

    Only original source members are described as already retained. The new
    descriptor, receipt, and index remain undelivered metadata for the caller's
    additive legacy-seed/export path; this is not a fabricated native export.
    """
    root = Path(root)
    manifest = _document(manifest_raw, expected_manifest_sha256, "manifest")
    index = _document(sealed_index_raw, expected_index_sha256, "sealed index")
    if not isinstance(importer_code_sha, str) or not _CODE.fullmatch(importer_code_sha):
        raise ValueError("A full importer code SHA is required")
    original_path, source_entry = _validate_context(
        source_context, manifest, index, manifest_hash=expected_manifest_sha256,
        index_hash=expected_index_sha256, index_bytes=len(sealed_index_raw))
    if _time(manifest["started_at"]) > _time(manifest["finished_at"]):
        raise ValueError("Original legacy observation interval is reversed")
    git = copy.deepcopy(manifest.get("git"))
    if (not isinstance(git, dict) or not git.get("portable_full_bundle") or git.get("portable_recent_archive") or
            git.get("history_profile", "full_history") != "full_history" or git.get("history_scope")):
        raise ValueError("Legacy import requires an original full-history portable Git bundle")
    prefix = _git_namespace(manifest)
    repo_id = source_context["repository_id"]
    remote = f"https://github.com/{source_context['repository']}.git"
    if git.get("remote", remote) != remote or git.get("mirror_path_relative", f"git/{repo_id}.git") != f"git/{repo_id}.git":
        raise ValueError("Legacy Git source or mirror identity mismatch")
    bundle = git["portable_full_bundle"]
    if (not _HASH.fullmatch(bundle["sha256"]) or type(bundle["bytes"]) is not int or bundle["bytes"] <= 0):
        raise ValueError("Invalid original full-bundle content identity")
    if source_entry.get("portable_full_bundle") and any(
            source_entry["portable_full_bundle"].get(key) != bundle[key] for key in ("sha256", "bytes")):
        raise ValueError("Legacy sealed index and manifest bundle identities differ")
    store = ObjectStore(root)
    path = store.location(bundle["sha256"])
    if path.stat().st_size != bundle["bytes"] or not store.verify(bundle["sha256"]):
        raise RuntimeError("Legacy full-bundle bytes do not match the original manifest")
    object_format = git.get("git_object_hash_algorithm", "sha1")
    if object_format not in ("sha1", "sha256"):
        raise ValueError("Unsupported original Git object format")
    _, contained = _full_bundle_context(path, object_format)
    for oid in contained.values():
        _validate_oid(oid)
    intended = {ref["local_immutable_ref"]: ref["object_id"] for ref in git["advertised_refs"]}
    if any(contained.get(ref) != oid for ref, oid in intended.items()):
        raise RuntimeError("Legacy full bundle omits an original declared immutable ref")
    origin = {"kind": "authenticated_legacy_full_bundle", "source": copy.deepcopy(source_context),
              "source_manifest_status": manifest.get("status"),
              "source_index_status": index.get("status"),
              "source_observation_started_at": manifest["started_at"],
              "source_observation_finished_at": manifest["finished_at"],
              "source_git_observation_started_at": git.get("ls_remote_started_at"),
              "source_git_observation_finished_at": git.get("ls_remote_completed_at"),
              "claim": "Derived offline verification of retained bytes; not a new source observation."}
    descriptor = {"schema_version": 1, "kind": "baseline", "repository_id": repo_id, "remote": remote,
                  "object_format": object_format, "archive_ref_prefix": prefix,
                  "advertised_refs": git["advertised_refs"], "covered_object_tips": sorted(set(contained.values())),
                  "bundle": {"sha256": bundle["sha256"], "bytes": bundle["bytes"], "prerequisite_object_ids": []},
                  "prerequisites": [], "parent_archive_sha256": None, "legacy_import": origin}
    digest = descriptor_digest(descriptor)
    mirror = root / "git" / f"{repo_id}.git"
    mirror.parent.mkdir(parents=True, exist_ok=True)
    lock_path = mirror.parent / f".legacy-git-import-{repo_id}.lock"
    with lock_path.open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        head = mirror / "icsot-archive-head"
        if head.exists() and head.read_text().strip() != digest:
            raise RuntimeError("Existing Git archive head is bound to another descriptor")
        created = not head.exists()
        if mirror.exists():
            _no_external_object_supply(mirror)
        with tempfile.TemporaryDirectory(prefix=".legacy-git-verify-", dir=mirror.parent) as directory:
            restored = Path(directory) / "verified.git"
            run_git(["init", "--bare", "--template=", f"--object-format={object_format}", str(restored)])
            run_git(["-C", str(restored), "bundle", "verify", str(path.resolve())], timeout=1800)
            run_git(["-C", str(restored), "fetch", "--no-tags", str(path.resolve()), "+refs/*:refs/*",
                     "--no-auto-maintenance"], timeout=1800)
            _no_external_object_supply(restored)
            expected_refs = {name: oid for name, oid in contained.items() if name.startswith("refs/")}
            if _refs(restored) != expected_refs or {name: oid for name, oid in _refs(restored, prefix).items()} != intended:
                raise RuntimeError("Legacy full bundle restores different original refs")
            if (restored / "shallow").exists() or list((restored / "objects" / "pack").glob("*.promisor")):
                raise ValueError("Legacy full-history verification cannot use shallow or promisor objects")
            _verify_advertised_objects(restored, git["advertised_refs"])
            _verify_advertised_objects(restored, [{"object_id": oid} for oid in descriptor["covered_object_tips"]])
            run_git(["-C", str(restored), "fsck", "--full", "--no-reflogs"], timeout=1800)
            if mirror.exists():
                if (mirror / "shallow").exists() or (mirror / "icsot-history-policy.json").exists() or _refs(mirror) != expected_refs:
                    raise RuntimeError("Existing legacy mirror namespace or history profile differs")
                _verify_advertised_objects(mirror, git["advertised_refs"])
                run_git(["-C", str(mirror), "fsck", "--full", "--no-reflogs"], timeout=1800)
                if run_git(["-C", str(mirror), "remote", "get-url", "origin"]).strip() != remote:
                    raise ValueError("Existing legacy mirror origin differs")
            else:
                run_git(["-C", str(restored), "remote", "add", "origin", remote])
                restored.rename(mirror)
        # Only independently verified closure can become a persistent archive
        # descriptor/head. Original bundle bytes are reused without a new pack.
        if store.put(canonical_json(descriptor)) != digest:
            raise RuntimeError("Derived legacy Git descriptor identity mismatch")
        identity = sha256(canonical_json({"manifest": expected_manifest_sha256, "index": expected_index_sha256}))
        home = root / "imports" / "legacy-git" / identity
        _exact_file(home / "source.manifest.json", manifest_raw)
        _exact_file(home / "source.index.json", sealed_index_raw)
        receipt_path = home / "receipt.json"
        static = {"schema_version": 1, "kind": "legacy_git_import", "source": origin,
                  "descriptor_sha256": digest, "new_source_observation": False,
                  "api_scope_imported": False, "new_git_bundle_bytes": 0,
                  "timestamp_semantics": "Import metadata, not source observation or head-publication time; a supplied time is not verification completion.",
                  "verification": {"independent_empty_restore": True, "full_fsck": True,
                                   "original_refs_and_peels_verified": len(intended), "source_network_used": False}}
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_bytes())
            if (receipt_path.read_bytes() != canonical_json(receipt) or
                    {key: value for key, value in receipt.items() if key not in ("imported_at_utc", "importer_code_sha", "imported_at_provenance")} != static):
                raise RuntimeError("Existing immutable legacy Git import receipt differs")
            _time(receipt["imported_at_utc"])
            if (receipt["imported_at_provenance"] not in ("supplied_frozen_import_context", "local_system_clock_after_verification") or
                    not isinstance(receipt["importer_code_sha"], str) or not _CODE.fullmatch(receipt["importer_code_sha"])):
                raise ValueError("Invalid immutable legacy import clock/code provenance")
        else:
            supplied_time = imported_at_utc is not None
            imported_at_utc = imported_at_utc or utc_iso()
            _time(imported_at_utc)
            receipt = {**static, "imported_at_utc": imported_at_utc, "importer_code_sha": importer_code_sha,
                       "imported_at_provenance": "supplied_frozen_import_context" if supplied_time else "local_system_clock_after_verification"}
            _exact_file(receipt_path, canonical_json(receipt))
        manifest_member = {"path": original_path, "sha256": expected_manifest_sha256, "bytes": len(manifest_raw)}
        bundle_member = {"path": store.location(bundle["sha256"]).relative_to(root).as_posix(),
                         "sha256": bundle["sha256"], "bytes": bundle["bytes"]}
        catalog = {"schema_version": 1, "kind": "authenticated_legacy_git_seed_v1", "source": copy.deepcopy(source_context),
                   "retained_members": [manifest_member, bundle_member],
                   "original_archive": copy.deepcopy(index.get("archive")),
                   "claim": "Original retained members only; derived import metadata is new and undelivered."}
        imported_index = {"schema_version": 1, "kind": "legacy_git_import_index", "source": origin,
                          "history_profile": "full_history", "new_source_observation": False,
                          "descriptor": {"sha256": digest, "bytes": len(canonical_json(descriptor))},
                          "receipt": {"path": receipt_path.relative_to(root).as_posix(),
                                      "sha256": sha256(canonical_json(receipt)), "bytes": len(canonical_json(receipt))},
                          "legacy_prior_export_catalog": catalog, "new_git_bundle_bytes": 0}
        index_path = home / "index.json"
        _exact_file(index_path, canonical_json(imported_index))
        _exact_file(head, (digest + "\n").encode())
    return {"imported": True, "created": created, "source_history_profile": "full_history",
            "archive_descriptor": descriptor, "descriptor_sha256": digest,
            "mirror_path_relative": mirror.relative_to(root).as_posix(), "head_path": str(head),
            "head_path_relative": head.relative_to(root).as_posix(),
            "receipt_path": str(receipt_path), "receipt_path_relative": receipt_path.relative_to(root).as_posix(),
            "receipt_sha256": sha256(canonical_json(receipt)),
            "index_path": str(index_path), "index_path_relative": index_path.relative_to(root).as_posix(),
            "index_sha256": sha256(canonical_json(imported_index)),
            "legacy_prior_export_catalog": catalog, "verification": receipt["verification"],
            "new_git_bundle_bytes": 0}
