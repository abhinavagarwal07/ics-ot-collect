from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .core import ObjectStore, canonical_json, sha256
from .gitstore import _valid_refname, _verify_advertised_objects, run_git


def _git_namespace(obj: dict[str, Any]) -> str:
    git_info = obj["git"]
    prefix = f"refs/archive/{obj.get('capture_id', obj['run_id'])}/"
    if git_info.get("archive_ref_prefix", prefix) != prefix:
        raise ValueError("Git archive namespace differs from manifest capture ID")
    refs = git_info["advertised_refs"]
    if len({ref["published_ref"] for ref in refs}) != len(refs):
        raise ValueError("Duplicate advertised Git ref in manifest")
    for ref in refs:
        published = ref["published_ref"]
        if (not _valid_refname(published) or not published.startswith(("refs/heads/", "refs/tags/", "refs/pull/")) or
                (published.startswith("refs/pull/") and not published.endswith("/head")) or
                ref["local_immutable_ref"] != prefix + published[len("refs/"):]):
            raise ValueError("Git immutable ref differs from manifest capture namespace")
    return prefix


def _verify_peeled_targets(repo: Path, refs: list[dict[str, Any]]) -> None:
    _verify_advertised_objects(repo, refs, runner=run_git)


def _verify_portable_bundle(bundle_path: Path, git_info: dict[str, Any]) -> None:
    """Restore using only the archived bundle, with no preexisting object supply."""
    with tempfile.TemporaryDirectory(prefix="icsot-verify-bundle-") as directory:
        restored = Path(directory) / "restored.git"
        object_format = git_info.get("git_object_hash_algorithm", "sha1")
        if object_format not in ("sha1", "sha256"):
            raise ValueError(f"Unsupported Git object format: {object_format}")
        run_git(["init", "--bare", f"--object-format={object_format}", str(restored)])
        # Running bundle verify in the EMPTY repo rejects incremental bundles that
        # could misleadingly verify against the collector's populated mirror.
        bundle = str(bundle_path.resolve())
        run_git(["-C", str(restored), "bundle", "verify", bundle], timeout=1800)
        run_git(["-C", str(restored), "fetch", "--no-tags", bundle, "+refs/*:refs/*",
                 "--no-auto-maintenance"], timeout=1800)
        run_git(["-C", str(restored), "fsck", "--full", "--no-reflogs"], timeout=1800)
        restored_refs = {}
        for line in run_git(["-C", str(restored), "for-each-ref", "--format=%(refname) %(objectname)"]).splitlines():
            ref, oid = line.split(" ", 1)
            restored_refs[ref] = oid
        for ref in git_info["advertised_refs"]:
            if restored_refs.get(ref["local_immutable_ref"]) != ref["object_id"]:
                raise RuntimeError(f"Portable Git bundle does not restore declared ref: {ref['local_immutable_ref']}")
        _verify_peeled_targets(restored, git_info["advertised_refs"])


def verify_all(root: Path, *, check_git: bool = True, check_ots: bool = False) -> dict[str, Any]:
    store = ObjectStore(root)
    errors: list[str] = []
    stats = {"manifests": 0, "raw_observations": 0, "bytes_verified": 0,
             "git_refs_verified": 0, "git_repositories_verified": 0,
             "portable_git_bundles_verified": 0, "timestamp_proofs_verified": 0,
             "portable_git_archives_verified": 0,
             "partial_runs": 0, "unstamped_runs": 0}
    integrity_checked: set[Path] = set()
    archive_verifiers: dict[Path, Any] = {}
    archive_bundles_checked: dict[str, bytes] = {}
    archive_temporary = tempfile.TemporaryDirectory(prefix="icsot-verify-archives-")
    runs_root = root / "runs"
    for repo_dir in sorted(runs_root.iterdir()) if runs_root.exists() else []:
        if not repo_dir.is_dir():
            continue
        last_digest = None
        for fn in sorted(repo_dir.glob("*.manifest.json")):
            stats["manifests"] += 1
            raw = fn.read_bytes()
            digest = sha256(raw)
            try:
                obj = json.loads(raw)
                if raw != canonical_json(obj):
                    errors.append(f"Non-canonical manifest bytes: {fn}")
                if obj["previous_manifest_sha256"] != last_digest:
                    errors.append(f"Hash chain break at {fn}")
                last_digest = digest
                if obj.get("status") != "complete":
                    stats["partial_runs"] += 1
                for r in obj["responses"]:
                    if r.get("body_sha256"):
                        data = store.get(r["body_sha256"])
                        if len(data) != r.get("body_bytes"):
                            errors.append(f"Body length mismatch {fn}: {r['purpose']}")
                        stats["bytes_verified"] += len(data)
                        stats["raw_observations"] += 1
                prefix = _git_namespace(obj) if obj.get("git") else None
                if obj.get("git") and obj["git"].get("portable_full_bundle"):
                    bundle = obj["git"]["portable_full_bundle"]
                    if not store.verify(bundle["sha256"]):
                        errors.append(f"Portable Git bundle SHA-256 mismatch {fn}")
                    elif store.location(bundle["sha256"]).stat().st_size != bundle["bytes"]:
                        errors.append(f"Portable Git bundle size mismatch {fn}")
                    elif check_git:
                        try:
                            _verify_portable_bundle(store.location(bundle["sha256"]), obj["git"])
                            stats["portable_git_bundles_verified"] += 1
                        except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as e:
                            errors.append(f"Portable Git bundle restore failed {fn}: {e}")
                if obj.get("git") and obj["git"].get("portable_archive"):
                    from .gitarchive import PortableArchiveVerifier, verify_archive_integrity
                    try:
                        if obj["git"]["portable_archive"]["repository_id"] != obj["repository_id"]:
                            raise ValueError("Portable Git archive repository differs from manifest")
                        verify_archive_integrity(root, obj["git"], verified_bundles=archive_bundles_checked)
                        if check_git:
                            if repo_dir not in archive_verifiers:
                                archive_verifiers[repo_dir] = PortableArchiveVerifier(
                                    root, Path(archive_temporary.name) / str(len(archive_verifiers)))
                            archive_verifiers[repo_dir].verify(obj["git"])
                            stats["portable_git_archives_verified"] += 1
                    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as e:
                        errors.append(f"Portable Git archive restore failed {fn}: {e}")
                if check_git and obj.get("git"):
                    mirror = root / obj["git"]["mirror_path_relative"]
                    mirror_key = mirror.resolve()
                    if mirror_key not in integrity_checked:
                        integrity_checked.add(mirror_key)
                        try:
                            # Ref IDs alone do not establish that reachable trees
                            # and file blobs survive in the evidence archive.
                            run_git(["-C", str(mirror), "fsck", "--full", "--no-reflogs"], timeout=1800)
                            stats["git_repositories_verified"] += 1
                        except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
                            errors.append(f"Git object graph integrity failed {mirror}: {e}")
                    fetched = run_git(["-C", str(mirror), "for-each-ref", "--format=%(refname) %(objectname)", prefix])
                    live = {}
                    for line in fetched.splitlines():
                        r, h = line.split(" ", 1)
                        live[r] = h
                    intended = {r["local_immutable_ref"]: r["object_id"] for r in obj["git"]["advertised_refs"]}
                    if intended != live:
                        errors.append(f"Git refs differ from manifest {fn}")
                    else:
                        _verify_peeled_targets(mirror, obj["git"]["advertised_refs"])
                        stats["git_refs_verified"] += len(intended)
                proof = Path(str(fn) + ".ots")
                if check_ots:
                    if not proof.exists() or shutil.which("ots") is None:
                        errors.append(f"No OTS proof or client at {fn}")
                    else:
                        p = subprocess.run(["ots", "verify", str(proof)], capture_output=True, text=True, timeout=120)
                        if p.returncode:
                            errors.append(f"OTS verification failed or still pending for {fn}: {p.stderr[-200:]}")
                        else:
                            stats["timestamp_proofs_verified"] += 1
                elif not proof.exists():
                    stats["unstamped_runs"] += 1
            except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as e:
                errors.append(f"Error validating {fn}: {type(e).__name__}: {e}")
    stats["errors"] = errors
    stats["ok"] = len(errors) == 0
    archive_temporary.cleanup()
    return stats
