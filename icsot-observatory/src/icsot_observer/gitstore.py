from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .core import ObjectStore, utc_iso

ALLOWED_REF_PREFIXES = ("refs/heads/", "refs/tags/", "refs/pull/")


def run_git(args: list[str], *, timeout: int = 1200) -> str:
    # No accidental access to nonpublic code via local Git credential helpers.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_ASKPASS"] = "false"
    p = subprocess.run(["git", *args], env=env, capture_output=True, text=True, timeout=timeout)
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
                peeled[ref[:-3]] = sha
            continue  # peeling is metadata, never a ref accepted by update-ref
        if (ref.startswith(("refs/heads/", "refs/tags/")) or
            (ref.startswith("refs/pull/") and ref.endswith("/head"))):
            refs[ref] = sha
    return refs, {ref: sha for ref, sha in peeled.items() if ref in refs}


def remote_refs(remote: str) -> dict[str, str]:
    """Return only real advertised heads, tags, and PR heads."""
    return _remote_ref_advertisement(remote)[0]


def collect_git(root: Path, slug: str, repo_id: int, rid: str,
                *, bundle_full: bool = False) -> dict[str, Any]:
    """Pin every observed advertised ref in a permanent per-run namespace.

    No destructive pruning; source is public HTTPS Git endpoint. Git objects are
    not part of the OTS file itself; retain and independently back up this mirror.
    """
    remote = f"https://github.com/{slug}.git"
    repo = root / "git" / f"{repo_id}.git"
    if not repo.exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        run_git(["init", "--bare", str(repo)])
        run_git(["-C", str(repo), "remote", "add", "origin", remote])
    else:
        existing = run_git(["-C", str(repo), "remote", "get-url", "origin"]).strip()
        if existing != remote:
            raise RuntimeError(f"Origin changed for repository {repo_id}; manually audit rename")

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
    for ref, sha in sorted(after.items()):
        if ref.startswith("refs/pull/") and not ref.endswith("/head"):
            continue  # pull merge refs are generated and may not be fetchable consistently
        run_git(["-C", str(repo), "cat-file", "-e", sha + "^{object}"], timeout=30)
        peeled = after_peeled.get(ref)
        if peeled is not None:
            actual = run_git(["-C", str(repo), "rev-parse", sha + "^{}"], timeout=30).strip()
            if actual != peeled:
                raise RuntimeError(f"Fetched tag peeled target differs from advertisement: {ref}")
        immutable_ref = f"refs/archive/{rid}/{ref[len('refs/') :]}"
        run_git(["-C", str(repo), "update-ref", immutable_ref, sha], timeout=30)
        record = {"published_ref": ref, "object_id": sha, "local_immutable_ref": immutable_ref}
        if peeled is not None:
            record["peeled_object_id"] = peeled
        pinned.append(record)
    bundle_info = None
    if bundle_full:
        with tempfile.TemporaryDirectory(prefix="icsot-git-") as tmpdir:
            archive = Path(tmpdir) / "snapshot.bundle"
            run_git(["-C", str(repo), "bundle", "create", str(archive), "--all"], timeout=1800)
            digest, length = ObjectStore(root).put_file(archive)
            bundle_info = {"sha256": digest, "bytes": length,
                           "scope": "complete local repository bundle of all refs reachable at this run; verify contained refs"}
    return {
        "portable_full_bundle": bundle_info,
        "remote": remote, "ls_remote_started_at": before_start,
        "ls_remote_completed_at": after_end,
        "git_ref_count": len(pinned), "advertised_refs": pinned,
        "git_object_hash_algorithm": run_git(["-C", str(repo), "rev-parse", "--show-object-format"]).strip(),
        "mirror_path_relative": str(repo.relative_to(root)),
        "warning": "Retain git mirror/packfiles off-host; OTS attests only to this manifest's ref inventory, not to missing Git objects.",
    }
