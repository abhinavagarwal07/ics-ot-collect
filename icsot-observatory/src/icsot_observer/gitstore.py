from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .core import ObjectStore, canonical_json, sha256, utc_iso, write_once

ALLOWED_REF_PREFIXES = ("refs/heads/", "refs/tags/", "refs/pull/")


def run_git(args: list[str], *, timeout: int = 1200, input_text: str | None = None) -> str:
    # No accidental access to nonpublic code via local Git credential helpers.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_ASKPASS"] = "false"
    # Empty restore repositories must not borrow object supply or configuration
    # from the caller's checkout or an inherited alternate object directory.
    for name in ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                 "GIT_NAMESPACE", "GIT_SHALLOW_FILE", "GIT_CONFIG_PARAMETERS"):
        env.pop(name, None)
    env["GIT_CONFIG_COUNT"] = "0"
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    p = subprocess.run(["git", *args], env=env, capture_output=True, text=True,
                       input=input_text, timeout=timeout)
    if p.returncode:
        # fsck reports missing-object diagnostics on stdout even when stderr
        # contains a harmless HEAD notice; retain both channels on failure.
        detail = "\n".join(part.strip() for part in (p.stderr, p.stdout) if part.strip())
        raise RuntimeError(f"Git command failed (exit {p.returncode}): {detail[-1200:]}")
    return p.stdout


def _remote_ref_advertisement(remote: str) -> tuple[dict[str, str], dict[str, str]]:
    """Separate real refs from annotated tags' advertised peeled targets."""
    out = run_git(["ls-remote", remote], timeout=300)
    refs, peeled = {}, {}
    for line in out.splitlines():
        sha, ref = line.split("\t", 1)
        if ref.endswith("^{}"):
            if ref.startswith("refs/tags/"):
                _validate_oid(sha)
                if ref[:-3] in peeled or not _valid_refname(ref[:-3]):
                    raise ValueError("Duplicate or invalid advertised peeled Git ref")
                peeled[ref[:-3]] = sha
            continue  # peeling is metadata, never a ref accepted by update-ref
        if (ref.startswith(("refs/heads/", "refs/tags/")) or
            (ref.startswith("refs/pull/") and ref.endswith("/head"))):
            _validate_oid(sha)
            if ref in refs or not _valid_refname(ref):
                raise ValueError("Duplicate or invalid advertised Git ref")
            refs[ref] = sha
    return refs, {ref: sha for ref, sha in peeled.items() if ref in refs}


def remote_refs(remote: str) -> dict[str, str]:
    """Return only real advertised heads, tags, and PR heads."""
    return _remote_ref_advertisement(remote)[0]


def _valid_refname(ref: str) -> bool:
    """Check Git's ref grammar before putting a name into a stdin command."""
    return ("/" in ref and not ref.endswith(("/", ".")) and
            not any(token in ref for token in ("//", "..", "@{")) and
            not any(ord(char) <= 32 or ord(char) == 127 or char in "~^:?*[\\"
                    for char in ref) and
            all(part and not part.startswith(".") and not part.endswith(".lock")
                for part in ref.split("/")))


def _validate_oid(oid: str) -> None:
    if not isinstance(oid, str) or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", oid) is None:
        raise ValueError(f"Invalid advertised Git object ID: {oid!r}")


def _verify_advertised_objects(repo: Path, refs: list[dict[str, Any]], *, runner=None,
                               source: str = "manifest") -> None:
    """Check all objects and tag peels in one Git process, including missing IDs."""
    if not refs:
        return
    expressions: dict[str, str] = {}
    peeled_refs: dict[str, str] = {}
    for ref in refs:
        oid = ref["object_id"]
        _validate_oid(oid)
        expressions[oid] = oid
        if ref.get("peeled_object_id") is not None:
            peeled = ref["peeled_object_id"]
            _validate_oid(peeled)
            if oid + "^{}" in expressions and expressions[oid + "^{}"] != peeled:
                raise RuntimeError(f"Git peeled target differs between advertised refs: {ref['published_ref']}")
            expressions[oid + "^{}"] = peeled
            peeled_refs[oid + "^{}"] = ref["published_ref"]
    output = (runner or run_git)(
        ["-C", str(repo), "cat-file", "--batch-check=%(objectname)"],
        input_text="\n".join(expressions) + "\n", timeout=1200).splitlines()
    if len(output) != len(expressions):
        raise RuntimeError("Git object batch returned an incomplete response")
    for (expression, expected), actual in zip(expressions.items(), output):
        if actual != expected:
            if expression in peeled_refs:
                raise RuntimeError(f"Git peeled target differs from {source}: {peeled_refs[expression]}")
            raise RuntimeError(f"Git advertised object missing or invalid: {expression}: {actual}")


def _pin_refs(repo: Path, refs: list[dict[str, Any]]) -> None:
    """Create the complete immutable namespace atomically, never overwrite it."""
    if not refs:
        return
    commands = ["start"]
    for ref in refs:
        name = ref["local_immutable_ref"]
        if not _valid_refname(name):
            raise ValueError(f"Invalid immutable Git ref name: {name!r}")
        commands.append(f"create {name} {ref['object_id']}")
    commands.extend(("prepare", "commit"))
    run_git(["-C", str(repo), "update-ref", "--stdin"],
            input_text="\n".join(commands) + "\n", timeout=1200)


def _capture_inventory(repo: Path, git_info: dict[str, Any]) -> dict[str, str]:
    actual = {}
    for line in run_git(["-C", str(repo), "for-each-ref", "--format=%(refname) %(objectname)",
                         git_info["archive_ref_prefix"]]).splitlines():
        ref, oid = line.split(" ", 1)
        actual[ref] = oid
    return actual


def _read_capture(path: Path, *, repo_id: int, rid: str, remote: str, mode: str) -> dict[str, Any]:
    raw = path.read_bytes()
    record = json.loads(raw)
    if (raw != canonical_json(record) or record["schema_version"] != 1 or
            record["repository_id"] != repo_id or record["capture_id"] != rid or
            record["archive_mode"] != mode or record["git"]["remote"] != remote or
            record["git"]["archive_ref_prefix"] != f"refs/archive/{rid}/"):
        raise RuntimeError("Durable Git capture differs from requested capture")
    return record["git"]


def _verify_capture_replay(root: Path, repo: Path, git_info: dict[str, Any]) -> None:
    intended = {ref["local_immutable_ref"]: ref["object_id"] for ref in git_info["advertised_refs"]}
    if _capture_inventory(repo, git_info) != intended:
        raise RuntimeError("Durable Git capture immutable refs differ from saved observation")
    _verify_advertised_objects(repo, git_info["advertised_refs"])
    run_git(["-C", str(repo), "fsck", "--full", "--no-reflogs"], timeout=1800)
    if git_info.get("portable_full_bundle"):
        from .checks import _verify_portable_bundle
        bundle = git_info["portable_full_bundle"]
        store = ObjectStore(root)
        if not store.verify(bundle["sha256"]) or store.location(bundle["sha256"]).stat().st_size != bundle["bytes"]:
            raise RuntimeError("Durable Git capture full bundle integrity failure")
        _verify_portable_bundle(store.location(bundle["sha256"]), git_info)
    if git_info.get("portable_archive"):
        from .gitarchive import verify_portable_archive
        with tempfile.TemporaryDirectory(prefix="icsot-replay-archive-") as directory:
            verify_portable_archive(root, git_info, Path(directory) / "restored.git")


def collect_git(root: Path, slug: str, repo_id: int, rid: str,
                *, bundle_full: bool = False, archive_mode: str | None = None) -> dict[str, Any]:
    """Pin every observed advertised ref in a permanent per-run namespace.

    No destructive pruning; source is public HTTPS Git endpoint. Git objects are
    not part of the OTS file itself; retain and independently back up this mirror.
    """
    if archive_mode not in (None, "full", "incremental"):
        raise ValueError("Git archive mode must be 'full' or 'incremental'")
    if not _valid_refname(f"refs/archive/{rid}/capture"):
        raise ValueError(f"Invalid immutable Git ref name: {rid!r}")
    mode = archive_mode or ("full" if bundle_full else "none")
    remote = f"https://github.com/{slug}.git"
    repo = root / "git" / f"{repo_id}.git"
    journal = repo / "icsot-captures" / sha256(rid.encode("utf-8"))
    complete = journal.with_suffix(".complete.json")
    pending = journal.with_suffix(".pending.json")
    if complete.exists():
        result = _read_capture(complete, repo_id=repo_id, rid=rid, remote=remote, mode=mode)
        _verify_capture_replay(root, repo, result)
        return result
    if not repo.exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        run_git(["init", "--bare", str(repo)])
        run_git(["-C", str(repo), "remote", "add", "origin", remote])
    else:
        existing = run_git(["-C", str(repo), "remote", "get-url", "origin"]).strip()
        if existing != remote:
            raise RuntimeError(f"Origin changed for repository {repo_id}; manually audit rename")

    resumed = pending.exists()
    if resumed:
        result = _read_capture(pending, repo_id=repo_id, rid=rid, remote=remote, mode=mode)
        _verify_advertised_objects(repo, result["advertised_refs"])
    else:
        before_start = utc_iso()
        before, before_peeled = _remote_ref_advertisement(remote)
        # Track heads, tags, and GitHub pull head refs separately from permanent refs.
        run_git([
            "-C", str(repo), "fetch", "--no-prune", "--no-tags", "origin",
            "+refs/heads/*:refs/live/heads/*",
            "+refs/tags/*:refs/live/tags/*",
            "+refs/pull/*/head:refs/live/pull/*/head",
        ])
        after, after_peeled = _remote_ref_advertisement(remote)
        after_end = utc_iso()
        if before != after or before_peeled != after_peeled:
            raise RuntimeError("Remote ref set changed across fetch; no atomic git snapshot")

        pinned = []
        for ref, oid in sorted(after.items()):
            if ref.startswith("refs/pull/") and not ref.endswith("/head"):
                continue
            if not _valid_refname(ref):
                raise ValueError(f"Invalid advertised Git ref name: {ref!r}")
            immutable_ref = f"refs/archive/{rid}/{ref[len('refs/') :]}"
            record = {"published_ref": ref, "object_id": oid, "local_immutable_ref": immutable_ref}
            if ref in after_peeled:
                record["peeled_object_id"] = after_peeled[ref]
            pinned.append(record)
        _verify_advertised_objects(repo, pinned, source="advertisement")
        result = {
            "portable_full_bundle": None, "portable_archive": None,
            "remote": remote, "ls_remote_started_at": before_start,
            "ls_remote_completed_at": after_end,
            "git_ref_count": len(pinned), "advertised_refs": pinned,
            "archive_ref_prefix": f"refs/archive/{rid}/",
            "git_object_hash_algorithm": run_git(["-C", str(repo), "rev-parse", "--show-object-format"]).strip(),
            "mirror_path_relative": str(repo.relative_to(root)),
            "warning": "Retain git mirror/packfiles off-host; OTS attests only to this manifest's ref inventory, not to missing Git objects.",
        }
        write_once(pending, canonical_json({"schema_version": 1, "repository_id": repo_id,
                                           "capture_id": rid, "archive_mode": mode, "git": result}))
    pinned = result["advertised_refs"]
    if resumed:
        actual = _capture_inventory(repo, result)
        intended = {ref["local_immutable_ref"]: ref["object_id"] for ref in pinned}
        if actual and actual != intended:
            raise RuntimeError("Pending Git capture contains a partial or changed immutable namespace")
        if not actual:
            _pin_refs(repo, pinned)
    else:
        _pin_refs(repo, pinned)
    bundle_info = None
    if mode == "full":
        with tempfile.TemporaryDirectory(prefix="icsot-git-") as tmpdir:
            archive = Path(tmpdir) / "snapshot.bundle"
            run_git(["-C", str(repo), "bundle", "create", str(archive), "--all"], timeout=1800)
            digest, length = ObjectStore(root).put_file(archive)
            bundle_info = {"sha256": digest, "bytes": length,
                           "scope": "complete local repository bundle of all refs reachable at this run; verify contained refs"}
    result["portable_full_bundle"] = bundle_info
    if mode == "incremental":
        from .gitarchive import collect_incremental_archive
        result["portable_archive"] = collect_incremental_archive(root, repo, repo_id, result)
    write_once(complete, canonical_json({"schema_version": 1, "repository_id": repo_id,
                                       "capture_id": rid, "archive_mode": mode, "git": result}))
    return result
