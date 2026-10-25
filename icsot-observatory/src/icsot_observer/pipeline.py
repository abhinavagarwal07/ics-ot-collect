from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .core import Config, ObjectStore, canonical_json, parse_github_time, run_id, sha256, utc_iso, utc_now, write_once
from .github import GitHubAPI
from .gitstore import collect_git


@contextmanager
def exclusive_lock(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    fd = os.open(root / ".collector.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def prior_manifest(root: Path, repo_id: int, *, successful_only: bool = False) -> tuple[dict, str] | None:
    home = root / "runs" / str(repo_id)
    if not home.exists():
        return None
    for file in sorted(home.glob("*.manifest.json"), reverse=True):
        raw = file.read_bytes()
        obj = json.loads(raw)
        if successful_only and (obj.get("status") != "complete" or obj["mode"] not in ("full", "delta")):
            continue
        return obj, sha256(raw)
    return None


def collect_one(config: Config, slug: str, mode: str, *, deep_full: bool = False,
                bundle_full: bool = False, stamp: bool = True) -> dict[str, Any]:
    rid, started = run_id(), utc_iso()
    records: list[dict] = []
    store = ObjectStore(config.root)
    api = GitHubAPI(config, store, records)
    result: dict[str, Any] | None = None
    git_result: dict[str, Any] | None = None
    failures: list[str] = []
    repo_id: int | None = None
    # First fetch is public repository identity, captured in the same unmodified object store.
    try:
        meta = api.get_json(f"/repos/{slug}", "repository_identity")
        if meta.get("private") is not False or not isinstance(meta.get("id"), int):
            raise RuntimeError("Repository does not unambiguously appear public")
        repo_id = meta["id"]
        # Explicit cohort ID lock prevents same owner/repo slug later silently mapping to a namesake.
        cohort_id_path = config.root / "registry" / (slug.lower().replace("/", "__") + ".json")
        if cohort_id_path.exists():
            prior_id = json.loads(cohort_id_path.read_bytes())
            if prior_id.get("repository_id") != repo_id:
                raise RuntimeError("REPOSITORY_IDENTITY_CHANGED: slug now points to another repository id")
        else:
            write_once(cohort_id_path, canonical_json({
                "input_slug": slug, "repository_id": repo_id, "first_identified_at": started,
                "note": "Create-only registry binding; changes require audited cohort amendment",
            }))
    except Exception as e:
        # Failed identity fetches are not notarized under a guessed repository ID.
        failures.append(f"identity: {type(e).__name__}: {e}")
        repo_id = None
    if repo_id is None:
        # Preserve attempts under a separate quarantine; do not consider baseline collected.
        q = config.root / "quarantine" / (rid + ".json")
        write_once(q, canonical_json({"run_id": rid, "slug": slug, "records": records, "failures": failures}))
        return {"repo": slug, "status": "identity_error", "quarantine": str(q), "failures": failures}

    previous = prior_manifest(config.root, repo_id)
    previous_success = prior_manifest(config.root, repo_id, successful_only=True)
    since = None
    if mode == "delta" and previous_success:
        last = parse_github_time(previous_success[0]["started_at"])
        since = (last - timedelta(hours=config.overlap_hours)).isoformat(timespec="seconds").replace("+00:00", "Z")
    effective_mode = "full" if mode == "delta" and since is None else mode
    try:
        # Avoid collecting a repository that becomes private after the identity fetch.
        result = api.collect(slug, effective_mode, since=since,
                             deep_full=deep_full if effective_mode == "full" else True)
        if result["repository_id"] != repo_id:
            raise RuntimeError("Repository identity changed during collection")
    except Exception as e:
        failures.append(f"api: {type(e).__name__}: {e}")
    if effective_mode != "events":
        try:
            git_result = collect_git(config.root, slug, repo_id, rid, bundle_full=bundle_full)
        except Exception as e:
            failures.append(f"git: {type(e).__name__}: {e}")
    finished = utc_iso()
    config_for_manifest = {
        "repositories": list(config.repositories),
        "api_version": config.api_version,
        "user_agent": config.user_agent,
        "overlap_hours": config.overlap_hours,
        "max_pages": config.max_pages,
        "max_response_bytes": config.max_response_bytes,
        "deep_full": deep_full,
        "bundle_full": bundle_full,
    }
    manifest = {
        "schema_version": 1,
        "public_config_sha256": sha256(canonical_json(config_for_manifest)),
        "public_config": config_for_manifest,
        "collector_version": __version__,
        "run_id": rid,
        "repository_input_slug": slug,
        "repository_id": repo_id,
        "mode": effective_mode,
        "requested_mode": mode,
        "status": "complete" if not failures else "partial",
        "claim_scope": "successful API requests and Git fetches observed during their separate collection intervals",
        "started_at": started,
        "finished_at": finished,
        "previous_manifest_sha256": previous[1] if previous else None,
        "since": since,
        "api_version": config.api_version,
        "config": {"overlap_hours": config.overlap_hours, "max_pages": config.max_pages,
                   "deep_full": deep_full,
        "bundle_full": bundle_full, "user_agent": config.user_agent},
        "api": result,
        "git": git_result,
        "responses": records,
        "failures": failures,
        "limitation": "No proof of GitHub source authenticity or absolute first publication; evidence is interval-observed and non-atomic.",
    }
    fn = config.root / "runs" / str(repo_id) / (rid + ".manifest.json")
    contents = canonical_json(manifest)
    write_once(fn, contents)
    info: dict[str, Any] = {"repo": slug, "repository_id": repo_id, "run_id": rid,
                            "status": manifest["status"], "manifest_sha256": sha256(contents),
                            "manifest": str(fn), "failures": failures}
    if stamp:
        ots = shutil.which("ots")
        if not ots:
            info["attestation"] = "error: ots CLI not found"
        else:
            p = subprocess.run([ots, "stamp", str(fn)], capture_output=True, text=True, timeout=180)
            if p.returncode != 0:
                info["attestation"] = f"error: ots stamp exit {p.returncode}; {p.stderr[-300:]}"
            else:
                proof = Path(str(fn) + ".ots")
                if proof.is_file():
                    # Stamping not considered verified Bitcoin completion until upgrade + verify.
                    original_proof = config.root / "proofs" / "initial" / (sha256(contents) + ".ots")
                    write_once(original_proof, proof.read_bytes())
                    info["attestation"] = "pending_bitcoin_completion"
                    info["proof"] = str(proof)
                    info["immutable_initial_proof"] = str(original_proof)
                else:
                    info["attestation"] = "error: ots returned success but receipt missing"
    else:
        info["attestation"] = "DISABLED_UNSAFE_FOR_PROVENANCE_CLAIMS"
    return info


def collect_all(config: Config, mode: str, *, deep_full: bool = False,
                bundle_full: bool = False, stamp: bool = True) -> list[dict[str, Any]]:
    results = []
    with exclusive_lock(config.root):
        for slug in config.repositories:
            # An individual repo failure does not suppress later cohort collection.
            try:
                results.append(collect_one(config, slug, mode, deep_full=deep_full,
                                           bundle_full=bundle_full, stamp=stamp))
            except Exception as e:
                results.append({"repo": slug, "status": "unexpected_error", "error": f"{type(e).__name__}: {e}"})
    return results
