"""Incremental Git archives with explicit, independently restorable CAS closure."""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .core import ObjectStore, canonical_json, sha256
from .gitstore import _pin_refs, _validate_oid, _verify_advertised_objects, run_git


def _refs(repo: Path, prefix: str = "") -> dict[str, str]:
    args = ["-C", str(repo), "for-each-ref", "--format=%(refname) %(objectname)"]
    if prefix:
        args.append(prefix)
    output = run_git(args)
    return dict(line.split(" ", 1) for line in output.splitlines())


def _bundle_header(path: Path) -> tuple[list[str], dict[str, str]]:
    prerequisites, refs = [], {}
    with path.open("rb") as stream:
        if stream.readline() not in (b"# v2 git bundle\n", b"# v3 git bundle\n"):
            raise ValueError("Unsupported Git bundle header")
        while True:
            line = stream.readline(1024 * 1024)
            if line == b"\n":
                break
            if not line.endswith(b"\n"):
                raise ValueError("Incomplete Git bundle header")
            text = line.decode("utf-8").rstrip("\n")
            if text.startswith("@"):
                continue  # Git itself validates v3 capability lines on restore.
            oid, name = text.split(" ", 1)
            if oid.startswith("-"):
                _validate_oid(oid[1:])
                prerequisites.append(oid[1:])
            else:
                _validate_oid(oid)
                if name in refs:
                    raise ValueError("Duplicate ref in Git bundle header")
                refs[name] = oid
    return prerequisites, refs


def _bundle_path(store: ObjectStore, bundle: dict[str, Any]) -> Path:
    path = store.location(bundle["sha256"])
    if (not isinstance(bundle["bytes"], int) or isinstance(bundle["bytes"], bool) or
            bundle["bytes"] < 0 or path.stat().st_size != bundle["bytes"]):
        raise RuntimeError("Portable Git archive bundle size mismatch")
    if not store.verify(bundle["sha256"]):
        raise RuntimeError("Portable Git archive bundle SHA-256 mismatch")
    prerequisites, _ = _bundle_header(path)
    if prerequisites != bundle["prerequisite_object_ids"]:
        raise RuntimeError("Git bundle prerequisite IDs differ from archive descriptor")
    return path.resolve()


def descriptor_digest(descriptor: dict[str, Any]) -> str:
    return sha256(canonical_json(descriptor))


def _bundle_chain(descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    return descriptor["prerequisites"] + ([descriptor["bundle"]] if descriptor["bundle"] else [])


def _validated_lineage(store: ObjectStore, descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    """Descriptors are immutable evidence; the mutable head pointer is only a hint."""
    lineage, seen = [], set()
    current = descriptor
    while True:
        digest = descriptor_digest(current)
        if digest in seen:
            raise ValueError("Cyclic portable Git archive lineage")
        seen.add(digest)
        if store.get(digest) != canonical_json(current):
            raise RuntimeError("Portable Git archive descriptor differs from CAS")
        if current["schema_version"] != 1 or current["object_format"] not in ("sha1", "sha256"):
            raise ValueError("Unsupported portable Git archive descriptor")
        kind, bundle = current["kind"], current["bundle"]
        if kind not in ("baseline", "incremental", "refs-only") or (bundle is None) != (kind == "refs-only"):
            raise ValueError("Invalid portable Git archive kind/bundle combination")
        for oid in current["covered_object_tips"]:
            _validate_oid(oid)
        lineage.append(current)
        parent = current["parent_archive_sha256"]
        if parent is None:
            if kind != "baseline" or current["prerequisites"]:
                raise ValueError("Portable Git archive lacks a full baseline")
            if bundle["prerequisite_object_ids"]:
                raise ValueError("Portable Git baseline has object prerequisites")
            break
        if kind == "baseline":
            raise ValueError("Portable Git baseline must start a new archive lineage")
        current = json.loads(store.get(parent))
    lineage.reverse()
    for parent, child in zip(lineage, lineage[1:]):
        if (child["parent_archive_sha256"] != descriptor_digest(parent) or
                child["prerequisites"] != _bundle_chain(parent) or
                child["repository_id"] != parent["repository_id"] or
                child["remote"] != parent["remote"] or
                child["object_format"] != parent["object_format"] or
                not set(parent["covered_object_tips"]).issubset(child["covered_object_tips"])):
            raise ValueError("Portable Git archive prerequisite lineage differs from parent")
    return lineage


def _validate_declared_refs(repo: Path, descriptor: dict[str, Any]) -> None:
    declared = descriptor["advertised_refs"]
    prefix = descriptor["archive_ref_prefix"]
    intended = {ref["local_immutable_ref"]: ref["object_id"] for ref in declared}
    if len(intended) != len(declared) or any(not ref.startswith(prefix) for ref in intended):
        raise ValueError("Invalid portable Git archive ref inventory")
    _verify_advertised_objects(repo, declared)
    actual = _refs(repo, prefix)
    if any(ref not in intended or intended[ref] != oid for ref, oid in actual.items()):
        raise RuntimeError("Portable Git archive restored different immutable refs")
    _pin_refs(repo, [ref for ref in declared if ref["local_immutable_ref"] not in actual])
    # These roots, rather than all objects that happen to be in the live mirror,
    # are the only permitted exclusions for the next incremental bundle.
    _verify_advertised_objects(repo, [{"object_id": oid} for oid in descriptor["covered_object_tips"]])
    run_git(["-C", str(repo), "fsck", "--full", "--no-reflogs"], timeout=1800)


def _apply_archive(store: ObjectStore, repo: Path, descriptor: dict[str, Any]) -> None:
    bundle = descriptor["bundle"]
    if bundle is not None:
        path = _bundle_path(store, bundle)
        _, contained = _bundle_header(path)
        if descriptor["kind"] == "baseline":
            for ref in descriptor["advertised_refs"]:
                if contained.get(ref["local_immutable_ref"]) != ref["object_id"]:
                    raise RuntimeError("Portable Git baseline does not contain declared immutable ref")
        retained = _refs(repo, "refs/archive/")
        run_git(["-C", str(repo), "bundle", "verify", str(path)], timeout=1800)
        run_git(["-C", str(repo), "fetch", "--no-tags", str(path), "+refs/*:refs/*",
                 "--no-auto-maintenance"], timeout=1800)
        actual = _refs(repo, "refs/archive/")
        if any(actual.get(ref) != oid for ref, oid in retained.items()):
            raise RuntimeError("Portable Git archive overwrote an earlier immutable ref")
    _validate_declared_refs(repo, descriptor)


def _verify_namespaces(repo: Path, lineage: list[dict[str, Any]]) -> None:
    actual = _refs(repo, "refs/archive/")
    for item in lineage:
        prefix = item["archive_ref_prefix"]
        intended = {ref["local_immutable_ref"]: ref["object_id"] for ref in item["advertised_refs"]}
        if {ref: oid for ref, oid in actual.items() if ref.startswith(prefix)} != intended:
            raise RuntimeError("Portable Git archive changed an earlier capture namespace")


def restore_archive(root: Path, descriptor: dict[str, Any], restored: Path) -> str:
    """Independently restore the complete ordered closure into an EMPTY repo."""
    store = ObjectStore(root)
    lineage = _validated_lineage(store, descriptor)
    if restored.exists():
        raise ValueError("Portable Git archive restoration requires an empty destination")
    run_git(["init", "--bare", f"--object-format={descriptor['object_format']}", str(restored)])
    for item in lineage:
        _apply_archive(store, restored, item)
    _verify_namespaces(restored, lineage)
    return descriptor_digest(descriptor)


def _manifest_descriptor(git_info: dict[str, Any]) -> dict[str, Any]:
    descriptor = git_info["portable_archive"]
    if (descriptor["advertised_refs"] != git_info["advertised_refs"] or
            descriptor["archive_ref_prefix"] != git_info["archive_ref_prefix"] or
            descriptor["object_format"] != git_info["git_object_hash_algorithm"] or
            descriptor["remote"] != git_info["remote"]):
        raise ValueError("Portable Git archive descriptor differs from manifest")
    return descriptor


def verify_portable_archive(root: Path, git_info: dict[str, Any], restored: Path) -> None:
    restore_archive(root, _manifest_descriptor(git_info), restored)


class PortableArchiveVerifier:
    """Replay a repository's chain once in a fresh, offline verification repo."""

    def __init__(self, root: Path, directory: Path):
        self.root, self.directory = root, directory
        self.head: str | None = None
        self.restored: Path | None = None
        self.generation = 0

    def verify(self, git_info: dict[str, Any]) -> None:
        descriptor = _manifest_descriptor(git_info)
        lineage = _validated_lineage(ObjectStore(self.root), descriptor)
        restored = self.restored
        reuse = restored is not None and descriptor["parent_archive_sha256"] == self.head
        self.head, self.restored = None, None  # Failed replay must never be reused.
        if reuse:
            _apply_archive(ObjectStore(self.root), restored, descriptor)
        else:
            self.generation += 1
            restored = self.directory / str(self.generation)
            restore_archive(self.root, descriptor, restored)
        # Every earlier capture namespace must still be exact after later
        # bundles are applied; preserving only its existing names is insufficient.
        _verify_namespaces(restored, lineage)
        self.head = descriptor_digest(descriptor)
        self.restored = restored


def verify_archive_integrity(root: Path, git_info: dict[str, Any], *,
                             verified_bundles: dict[str, bytes] | None = None) -> None:
    """Hash every declared dependency even when Git execution is disabled."""
    store = ObjectStore(root)
    descriptor = _manifest_descriptor(git_info)
    _validated_lineage(store, descriptor)
    for bundle in _bundle_chain(descriptor):
        metadata = canonical_json(bundle)
        if verified_bundles is not None and bundle["sha256"] in verified_bundles:
            if verified_bundles[bundle["sha256"]] != metadata:
                raise ValueError("Conflicting metadata for an archived Git bundle")
            continue
        _bundle_path(store, bundle)
        if verified_bundles is not None:
            verified_bundles[bundle["sha256"]] = metadata


def _atomic_pointer(path: Path, digest: str) -> None:
    fd, name = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(digest + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        Path(name).unlink(missing_ok=True)


def collect_incremental_archive(root: Path, repo: Path, repo_id: int,
                                git_info: dict[str, Any]) -> dict[str, Any]:
    # The normal scheduler serializes a repo's Git lane. This lock also protects
    # direct callers and renamed slug aliases that resolve to the same repo ID.
    with (repo / "icsot-archive.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _collect_incremental_archive_locked(root, repo, repo_id, git_info)


def _collect_incremental_archive_locked(root: Path, repo: Path, repo_id: int,
                                       git_info: dict[str, Any]) -> dict[str, Any]:
    store = ObjectStore(root)
    head = repo / "icsot-archive-head"
    cache_head = repo / "icsot-archive-cache-head"
    cache = repo / "icsot-verified-archive.git"
    previous = None
    previous_digest = None
    if head.exists():
        previous_digest = head.read_text().strip()
        previous = json.loads(store.get(previous_digest))
        if (descriptor_digest(previous) != previous_digest or previous["repository_id"] != repo_id or
                previous["remote"] != git_info["remote"] or
                previous["object_format"] != git_info["git_object_hash_algorithm"]):
            raise RuntimeError("Portable Git archive state does not match repository")
        lineage = _validated_lineage(store, previous)
        if not cache.exists() or not cache_head.exists() or cache_head.read_text().strip() != previous_digest:
            if cache.exists():
                shutil.rmtree(cache)
            restore_archive(root, previous, cache)
            _atomic_pointer(cache_head, previous_digest)
        # Missing/corrupt archived input must fail even if the warm cache still
        # contains its objects. Hash inputs before deciding on any exclusions.
        for bundle in _bundle_chain(previous):
            _bundle_path(store, bundle)
        _validate_declared_refs(cache, previous)
        _verify_namespaces(cache, lineage)
        # An interrupted caller may have accepted the archive before it could
        # persist its final capture result. Return that exact immutable result,
        # without creating another descriptor or moving a newer head backwards.
        for accepted in lineage:
            if accepted["archive_ref_prefix"] == git_info["archive_ref_prefix"]:
                if accepted["advertised_refs"] != git_info["advertised_refs"]:
                    raise RuntimeError("Accepted Git archive differs from pending capture")
                return accepted
    else:
        if cache.exists():
            shutil.rmtree(cache)
        run_git(["init", "--bare", f"--object-format={git_info['git_object_hash_algorithm']}", str(cache)])

    covered = sorted(set(_refs(repo).values()))
    for oid in covered:
        _validate_oid(oid)
    exclusions = "" if previous is None else "".join(f"^{oid}\n" for oid in previous["covered_object_tips"])
    changed = previous is None or bool(run_git(
        ["-C", str(repo), "rev-list", "--objects", "--all", "--stdin"],
        input_text=exclusions, timeout=1800).strip())
    bundle_info = None
    if changed:
        with tempfile.TemporaryDirectory(prefix="icsot-git-delta-") as directory:
            path = Path(directory) / "archive.bundle"
            run_git(["-C", str(repo), "bundle", "create", str(path), "--all", "--stdin"],
                    input_text=exclusions, timeout=1800)
            prerequisites, _ = _bundle_header(path)
            digest, length = store.put_file(path)
            bundle_info = {"sha256": digest, "bytes": length,
                           "prerequisite_object_ids": prerequisites}
    descriptor = {
        "schema_version": 1,
        "kind": "baseline" if previous is None else ("incremental" if changed else "refs-only"),
        "repository_id": repo_id, "remote": git_info["remote"],
        "object_format": git_info["git_object_hash_algorithm"],
        "archive_ref_prefix": git_info["archive_ref_prefix"],
        "advertised_refs": git_info["advertised_refs"],
        "covered_object_tips": covered, "bundle": bundle_info,
        "prerequisites": [] if previous is None else _bundle_chain(previous),
        "parent_archive_sha256": previous_digest,
    }
    # Invalidate first: a failed validation may have partially changed the cache.
    # The next attempt must rebuild from the last accepted immutable descriptor.
    cache_head.unlink(missing_ok=True)
    _apply_archive(store, cache, descriptor)
    digest = store.put(canonical_json(descriptor))
    _atomic_pointer(cache_head, digest)
    _atomic_pointer(head, digest)
    return descriptor
