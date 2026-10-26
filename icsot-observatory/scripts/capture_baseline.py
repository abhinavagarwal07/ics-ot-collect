"""One-time, sharded baseline transfer through private GitHub Release assets.

Release parts are temporary working transfers to an owner-controlled private
release; this helper does not promise an independent or indefinite archive.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import lzma
import os
import platform
import re
import subprocess
import sys
import tarfile
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from icsot_observer.checks import verify_all
from icsot_observer.core import Config, ObjectStore, REPO_RE, canonical_json, sha256, utc_iso
from icsot_observer.gitstore import run_git
from icsot_observer.pipeline import collect_one

PART_BYTES = 1024 ** 3
EXPECTED_REPOSITORIES = 185
SCOPE = (
    "One initial public GitHub observation: shallow full REST listings, advertised "
    "branch/tag/pull-head Git refs and reachable Git objects. Per-item historical "
    "timelines/reviews, Discussions and first-publication times are not established. "
    "OTS receipts remain pending until separately upgraded and verified."
)


def repository_key(slug: str) -> str:
    if not REPO_RE.fullmatch(slug):
        raise ValueError("Invalid repository slug")
    return slug.lower().replace("/", "__") + "-" + sha256(slug.lower().encode())[:12]


def load_sources(config_path: Path, csv_path: Path, *, expected_count: int = EXPECTED_REPOSITORIES):
    config = Config.load(config_path)
    csv_bytes = csv_path.read_bytes()
    rows = list(csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig"))))
    csv_slugs = []
    for row in rows:
        url = urlsplit(row["Repository_URL"])
        slug = url.path.strip("/")
        if url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment or not REPO_RE.fullmatch(slug):
            raise ValueError("CSV contains an invalid repository URL")
        csv_slugs.append(slug)
    if tuple(csv_slugs) != config.repositories or len(csv_slugs) != expected_count:
        raise ValueError("Configuration must match every CSV repository in order and expected count")
    return config, {
        "config_source_sha256": sha256(config_path.read_bytes()),
        "csv_sha256": sha256(csv_bytes),
        "cohort_count": len(csv_slugs),
    }


def file_identity(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while block := source.read(4 * 1024 * 1024):
            digest.update(block)
            size += len(block)
    return {"name": path.name, "sha256": digest.hexdigest(), "bytes": size}


class SplitWriter(io.RawIOBase):
    """A streaming sink; no intermediate complete tar or XZ file is created."""

    def __init__(self, directory: Path, prefix: str, limit: int = PART_BYTES):
        super().__init__()
        if limit < 1:
            raise ValueError("Part limit must be positive")
        directory.mkdir(parents=True, exist_ok=True)
        self.directory, self.prefix, self.limit = directory, prefix, limit
        self.parts: list[dict] = []
        self.current = None
        self.current_size = 0
        self.digest = hashlib.sha256()

    def writable(self):
        return True

    def _finish_part(self):
        if self.current is None:
            return
        self.current.flush()
        os.fsync(self.current.fileno())
        name = Path(self.current.name).name
        self.current.close()
        self.parts.append({"name": name, "sha256": self.digest.hexdigest(), "bytes": self.current_size})
        self.current = None

    def write(self, data):
        if self.closed:
            raise ValueError("Write to closed split stream")
        view = memoryview(data)
        original = len(view)
        while view:
            if self.current is None:
                name = f"{self.prefix}.tar.xz.part-{len(self.parts) + 1:04d}"
                self.current = (self.directory / name).open("xb")
                self.current_size = 0
                self.digest = hashlib.sha256()
            count = min(len(view), self.limit - self.current_size)
            piece = view[:count]
            self.current.write(piece)
            self.digest.update(piece)
            self.current_size += count
            view = view[count:]
            if self.current_size == self.limit:
                self._finish_part()
        return original

    def close(self):
        if not self.closed:
            self._finish_part()
        super().close()


def package_archive(work: Path, assets: Path, key: str, *, include_mirror: bool, part_bytes: int = PART_BYTES) -> dict:
    sink = SplitWriter(assets, key, part_bytes)

    def select(member):
        if not include_mirror and (member.name == "evidence/git" or member.name.startswith("evidence/git/")):
            return None
        return member

    try:
        with lzma.LZMAFile(sink, "w", preset=1) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(work.iterdir()):
                    archive.add(path, arcname=path.name, filter=select)
    finally:
        sink.close()
    # Re-read each actual output rather than trusting only the streaming counters.
    for part in sink.parts:
        if file_identity(assets / part["name"]) != part:
            raise RuntimeError("Archive part integrity mismatch")
    return {
        "complete": True, "encoding": "one tar stream compressed with XZ, split in listed order",
        "xz_preset": 1, "maximum_part_bytes": part_bytes,
        "restore": "Verify each part, concatenate in listed order, then decompress XZ and extract tar.",
        "git_mirror_included": include_mirror, "parts": sink.parts,
    }


def inspect_manifests(root: Path) -> list[dict]:
    manifests = []
    for path in sorted((root / "runs").glob("*/*.manifest.json")):
        record = {"path": path.relative_to(root).as_posix(), **file_identity(path)}
        try:
            manifest = json.loads(path.read_bytes())
            record.update({
                "run_id": manifest.get("run_id"), "status": manifest.get("status"),
                "mode": manifest.get("mode"), "repository_id": manifest.get("repository_id"),
                "public_config_sha256": manifest.get("public_config_sha256"),
                "started_at": manifest.get("started_at"), "finished_at": manifest.get("finished_at"),
                "has_git": bool(manifest.get("git")),
                "portable_full_bundle": (manifest.get("git") or {}).get("portable_full_bundle"),
            })
        except (ValueError, OSError) as error:
            record["error"] = f"{type(error).__name__}: {error}"
        manifests.append(record)
    return manifests


def can_omit_mirror(root: Path, manifests: list[dict], verification: dict) -> bool:
    if not (root / "git").exists():
        return True
    git_manifests = [row for row in manifests if row.get("has_git")]
    return bool(
        verification.get("ok") and git_manifests and
        all(row.get("portable_full_bundle") for row in git_manifests) and
        verification.get("portable_git_bundles_verified", 0) == len(git_manifests) and
        verification.get("git_repositories_verified", 0) > 0
    )


def capture_accepted(result: dict, verification: dict, manifests: list[dict]) -> bool:
    return bool(
        result.get("status") == "complete" and
        result.get("attestation") == "pending_bitcoin_completion" and
        all(Path(result.get(key, "")).is_file() and Path(result[key]).stat().st_size > 0
            for key in ("proof", "immutable_initial_proof")) and
        verification.get("ok") and verification.get("manifests") == 1 and
        verification.get("portable_git_bundles_verified") == 1 and
        verification.get("git_repositories_verified") == 1 and
        verification.get("raw_observations", 0) > 0 and
        verification.get("partial_runs") == 0 and verification.get("unstamped_runs") == 0 and
        len(manifests) == 1 and manifests[0].get("status") == "complete" and
        manifests[0].get("mode") == "full" and manifests[0].get("portable_full_bundle")
    )


def wait_for_github_reset() -> bool:
    """Use the primary-free rate endpoint after a CLI failure, at most once."""
    process = subprocess.run(["gh", "api", "rate_limit"], capture_output=True, timeout=60)
    if process.returncode:
        return False
    try:
        core = json.loads(process.stdout)["resources"]["core"]
        delay = float(core["reset"]) - time.time() + 3
        if core["remaining"] != 0 or not 0 < delay <= 3605:
            return False
    except (ValueError, KeyError, TypeError):
        return False
    time.sleep(delay)
    return True


def gh(*args: str, timeout: int = 1800, retry_rate_limit: bool = True) -> bytes:
    # The runner supplies GH_TOKEN through the environment. Never print its value
    # or a command environment; gh performs authenticated HTTPS transfers.
    for attempt in range(2):
        process = subprocess.run(["gh", *args], capture_output=True, timeout=timeout)
        if process.returncode == 0:
            return process.stdout
        if attempt == 0 and retry_rate_limit and wait_for_github_reset():
            continue
        raise RuntimeError(f"GitHub CLI operation {args[0]} failed with exit {process.returncode}")
    raise AssertionError("unreachable")


def release_assets(repository: str, release_id: int) -> list[dict]:
    pages = json.loads(gh("api", f"repos/{repository}/releases/{release_id}/assets?per_page=100",
                         "--paginate", "--slurp"))
    return [asset for page in pages for asset in page]


def upload_asset(tag: str, path: Path, repository: str):
    try:
        # A retry following an uncertain upload must first check the existing
        # asset. Never overwrite evidence with --clobber.
        gh("release", "upload", tag, str(path), "--repo", repository, retry_rate_limit=False)
        return
    except (RuntimeError, subprocess.TimeoutExpired):
        wait_for_github_reset()
    release = json.loads(gh("api", f"repos/{repository}/releases/tags/{tag}"))
    identity = file_identity(path)
    for asset in release_assets(repository, release["id"]):
        if asset["name"] == path.name:
            if asset["size"] == identity["bytes"] and asset.get("digest") == "sha256:" + identity["sha256"]:
                return
            raise RuntimeError("Existing release asset cannot be confirmed identical; refusing overwrite")
    gh("release", "upload", tag, str(path), "--repo", repository, retry_rate_limit=False)


def write_json(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def capture(args) -> int:
    config, sources = load_sources(args.config, args.csv)
    if args.slug not in config.repositories:
        raise ValueError("Target is outside the declared cohort")
    key = repository_key(args.slug)
    work = args.work_root / key
    work.mkdir(parents=True, exist_ok=False)
    reports, evidence = work / "reports", work / "evidence"
    reports.mkdir()
    evidence.mkdir()
    assets = args.work_root / (key + "-assets")
    assets.mkdir(exist_ok=False)
    (reports / "config.corpus.toml").write_bytes(args.config.read_bytes())
    (reports / "public_patch_corpus_185.csv").write_bytes(args.csv.read_bytes())
    index = {
        "schema_version": 1, "repository": args.slug, "repository_key": key,
        "release_tag": args.release_tag, "release_repository": args.release_repository,
        "collector_code_sha": args.code_sha, **sources,
        "github_run_id": os.getenv("GITHUB_RUN_ID"), "github_run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "started_at": utc_iso(), "scope": SCOPE,
        "retention": "Private GitHub Release assets have no expiry configured by this workflow; deletion remains possible. No independent or indefinite-retention guarantee.",
        "timestamp_status": "OTS submission requested; completed Bitcoin verification is not performed here.",
        "errors": [],
    }
    write_json(reports / "capture-request.json", index)
    write_json(reports / "environment.json", {"python": sys.version, "platform": platform.platform()})
    result: dict = {"status": "unexpected_error"}
    verification: dict = {"ok": False, "errors": ["Verification did not run"]}
    try:
        # One API reset wait is opt-in for this bounded baseline, not a change to
        # the ordinary collector default or a monthly storage-budget layer.
        single = replace(config, root=evidence.resolve(), repositories=(args.slug,),
                         primary_rate_wait_seconds=3605, primary_rate_reserve=40)
        result = collect_one(single, args.slug, "full", deep_full=False, bundle_full=True, stamp=True)
    except BaseException as error:
        result = {"repo": args.slug, "status": "unexpected_error", "error": f"{type(error).__name__}: {error}"}
        index["errors"].append(result["error"])
    finally:
        write_json(reports / "collector-result.json", result)
        try:
            verification = verify_all(evidence)
        except BaseException as error:
            verification = {"ok": False, "errors": [f"{type(error).__name__}: {error}"]}
        write_json(reports / "verification.json", verification)
        manifests = inspect_manifests(evidence)
        index.update({"collector_result": result, "verification": verification, "manifests": manifests})
        index["capture_accepted"] = capture_accepted(result, verification, manifests)
        include_mirror = not can_omit_mirror(evidence, manifests, verification)
        write_json(reports / "capture-outcome.json", index)
        try:
            archive = package_archive(work, assets, key, include_mirror=include_mirror)
        except BaseException as error:
            index["errors"].append(f"Packaging: {type(error).__name__}: {error}")
            archive = {
                "complete": False, "git_mirror_included": include_mirror,
                "parts": [file_identity(path) for path in sorted(assets.glob(f"{key}.tar.xz.part-*"))],
            }
        index["archive"] = archive
        for part in archive["parts"]:
            try:
                upload_asset(args.release_tag, assets / part["name"], args.release_repository)
                part["uploaded"] = True
            except Exception as error:
                part["uploaded"] = False
                index["errors"].append(f"Upload {part['name']}: {type(error).__name__}: {error}")
        index["finished_at"] = utc_iso()
        index["complete"] = bool(index["capture_accepted"] and archive["complete"] and archive["parts"] and
                                 all(part["uploaded"] for part in archive["parts"]) and not index["errors"])
        index["status"] = "complete_for_declared_shallow_baseline" if index["complete"] else "incomplete"
        index_path = assets / (key + ".index.json")
        write_json(index_path, index)
        # An index is uploaded only after every part has been attempted. It is
        # also emitted for failed captures and failed/partial archive uploads.
        upload_asset(args.release_tag, index_path, args.release_repository)
        print(json.dumps({"repository": args.slug, "status": index["status"], "index_asset": index_path.name,
                          "parts": len(archive["parts"]), "errors": index["errors"]}, indent=2))
    return 0 if index["complete"] else 2


def finalize(args) -> int:
    config, sources = load_sources(args.config, args.csv)
    release = json.loads(gh("api", f"repos/{args.release_repository}/releases/tags/{args.release_tag}"))
    if not release["draft"]:
        raise RuntimeError("Expected the unpublished draft baseline release")
    observed_assets = release_assets(args.release_repository, release["id"])
    assets = {asset["name"]: asset for asset in observed_assets}
    summary = {
        "schema_version": 1, "release_tag": args.release_tag, "collector_code_sha": args.code_sha,
        **sources, "finalized_at": utc_iso(), "scope": SCOPE,
        "matrix_result": os.getenv("BASELINE_MATRIX_RESULT", "unknown"),
        "assets_observed_before_final_inventory": [
            {key: asset.get(key) for key in ("id", "name", "size", "digest", "state")}
            for asset in observed_assets
        ],
        "repositories": [], "timestamp_status": "Pending OTS receipts are not verified Bitcoin timestamps.",
        "retention": "No automatic expiry/deletion configured; GitHub owner/admin deletion remains possible. No independent backup is configured.",
    }
    for slug in config.repositories:
        name = repository_key(slug) + ".index.json"
        row = {"repository": slug, "index_asset": name, "complete": False, "errors": []}
        try:
            asset = assets[name]
            raw = gh("api", f"repos/{args.release_repository}/releases/assets/{asset['id']}",
                     "-H", "Accept: application/octet-stream")
            if len(raw) != asset["size"] or (asset.get("digest") and asset["digest"] != "sha256:" + sha256(raw)):
                raise ValueError("Index asset length/digest mismatch")
            index = json.loads(raw)
            if (index["repository"] != slug or index["release_tag"] != args.release_tag or
                    index["collector_code_sha"] != args.code_sha or
                    any(index[key] != value for key, value in sources.items())):
                raise ValueError("Index source identity mismatch")
            row.update({"index_sha256": sha256(raw), "capture_status": index["status"],
                        "capture_accepted": index["capture_accepted"], "manifests": index["manifests"]})
            parts = index["archive"]["parts"]
            for part in parts:
                remote = assets.get(part["name"])
                if not part.get("uploaded") or remote is None or remote["size"] != part["bytes"]:
                    raise ValueError("Missing or wrong-sized archive part")
                if remote.get("digest") and remote["digest"] != "sha256:" + part["sha256"]:
                    raise ValueError("Archive part release digest mismatch")
            row["complete"] = bool(index["complete"] and index["archive"]["complete"] and parts)
            row["errors"] = index["errors"]
        except (KeyError, ValueError, TypeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            row["errors"].append(f"{type(error).__name__}: {error}")
        summary["repositories"].append(row)
    summary["complete_repositories"] = sum(row["complete"] for row in summary["repositories"])
    summary["incomplete_repositories"] = len(config.repositories) - summary["complete_repositories"]
    summary["complete"] = summary["incomplete_repositories"] == 0
    summary["status"] = "complete_for_declared_shallow_baseline" if summary["complete"] else "incomplete"
    args.work_root.mkdir(parents=True, exist_ok=True)
    inventory = args.work_root / "baseline-inventory.json"
    write_json(inventory, summary)
    upload_asset(args.release_tag, inventory, args.release_repository)
    notes = args.work_root / "release-notes.md"
    notes.write_text(
        f"One-time 185-repository shallow baseline: **{summary['status']}**.\n\n"
        f"Accepted repositories: {summary['complete_repositories']}/185; incomplete or missing: {summary['incomplete_repositories']}. "
        "See baseline-inventory.json and each repository's index asset for capture, verification, source hashes and ordered archive-part digests. "
        "A missing index represents missing/failed transfer, not successful coverage.\n\n"
        f"Collector commit: `{args.code_sha}`. Config SHA-256: `{sources['config_source_sha256']}`. CSV SHA-256: `{sources['csv_sha256']}`.\n\n"
        f"{SCOPE}\n\n"
        "All matrix jobs have reached a terminal state. This release is published once after collection; no cron, later state restore, "
        "automatic deletion or expiry is configured. Private Release storage remains deletable and is not an independent backup.\n"
    )
    # All assets and the inventory are present before publication. This also
    # works where the repository makes published releases immutable.
    gh("release", "edit", args.release_tag, "--repo", args.release_repository,
       "--notes-file", str(notes), "--draft=false")
    print(json.dumps({key: summary[key] for key in ("status", "complete_repositories", "incomplete_repositories")}, indent=2))
    return 0 if summary["complete"] else 2


def restore_mirrors(root: Path) -> dict:
    """Recreate disposable mirrors offline using only retained portable bundles."""
    initial = verify_all(root, check_git=False)
    if not initial["ok"]:
        raise RuntimeError("Archived bytes failed verification before offline restore")
    store = ObjectStore(root)
    for path in sorted((root / "runs").glob("*/*.manifest.json")):
        manifest = json.loads(path.read_bytes())
        git = manifest.get("git")
        if not git:
            continue
        expected = f"git/{manifest['repository_id']}.git"
        if git["mirror_path_relative"] != expected:
            raise ValueError("Unexpected mirror path in manifest")
        mirror = root / expected
        if mirror.exists():
            continue  # A retained partial mirror is checked by the full verifier.
        bundle = git.get("portable_full_bundle")
        if not bundle:
            raise RuntimeError("No portable bundle for missing mirror")
        mirror.parent.mkdir(parents=True, exist_ok=True)
        object_format = git.get("git_object_hash_algorithm", "sha1")
        if object_format not in ("sha1", "sha256"):
            raise ValueError("Unsupported Git object format")
        run_git(["init", "--bare", f"--object-format={object_format}", str(mirror)])
        archive = str(store.location(bundle["sha256"]).resolve())
        run_git(["-C", str(mirror), "bundle", "verify", archive], timeout=1800)
        run_git(["-C", str(mirror), "fetch", "--no-tags", archive, "+refs/*:refs/*"], timeout=1800)
    return verify_all(root)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    restore = sub.add_parser("restore", help="Offline: recreate omitted Git mirrors from retained bundles and fully verify")
    restore.add_argument("--root", type=Path, required=True)
    for command in ("plan", "capture", "finalize"):
        child = sub.add_parser(command)
        child.add_argument("--config", type=Path, required=True)
        child.add_argument("--csv", type=Path, required=True)
        if command == "plan":
            child.add_argument("--github-output", type=Path)
        else:
            child.add_argument("--release-tag", required=True)
            child.add_argument("--release-repository", required=True)
            child.add_argument("--code-sha", required=True)
            child.add_argument("--work-root", type=Path, required=True)
            if command == "capture":
                child.add_argument("--slug", required=True)
    args = parser.parse_args(argv)
    if args.command == "restore":
        verification = restore_mirrors(args.root)
        print(json.dumps(verification, indent=2))
        return 0 if verification["ok"] else 3
    if args.command == "plan":
        config, sources = load_sources(args.config, args.csv)
        outputs = {"matrix": json.dumps({"include": [{"slug": slug, "key": repository_key(slug)} for slug in config.repositories]}, separators=(",", ":")),
                   **sources}
        if args.github_output:
            with args.github_output.open("a") as output:
                for key, value in outputs.items():
                    output.write(f"{key}={value}\n")
        print(json.dumps(outputs, indent=2))
        return 0
    if not REPO_RE.fullmatch(args.release_repository) or not re.fullmatch(r"corpus-baseline-[0-9]+-[0-9]+", args.release_tag):
        raise ValueError("Invalid release destination")
    actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if args.code_sha != actual_sha:
        raise ValueError("Collector checkout does not match requested code SHA")
    return capture(args) if args.command == "capture" else finalize(args)


if __name__ == "__main__":
    raise SystemExit(main())
