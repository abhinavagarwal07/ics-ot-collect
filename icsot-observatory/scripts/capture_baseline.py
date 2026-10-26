"""One-time, sharded baseline transfer through encrypted GitHub Release assets.

Release parts are encrypted transfers to an owner-controlled
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
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import replace
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from icsot_observer.checks import verify_all
from icsot_observer.core import Config, ObjectStore, REPO_RE, canonical_json, sha256, utc_iso
from icsot_observer.gitstore import run_git
from icsot_observer.encryption import encrypt_file, public_key_fingerprint
from icsot_observer.pipeline import collect_one

PART_BYTES = 1024 ** 3
EXPECTED_REPOSITORIES = 185
CAPTURE_TIMEOUT_SECONDS = 120 * 60
VERIFICATION_TIMEOUT_SECONDS = 20 * 60
RESULTS_PUBLIC_KEY = Path(__file__).resolve().parents[1] / "keys/results-rsa-public.pem"
SCOPE = (
    "One initial public GitHub observation: shallow full REST listings, advertised "
    "branch/tag/pull-head Git refs and reachable Git objects. Per-item historical "
    "timelines/reviews, Discussions and first-publication times are not established. "
    "OTS receipts remain pending until separately upgraded and verified."
)


class PhaseDeadlineExceeded(BaseException):
    """Escape the collector's ordinary per-endpoint Exception handlers."""


@contextmanager
def phase_deadline(seconds: float, phase: str):
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0)
    started = time.monotonic()

    def expired(signum, frame):
        raise PhaseDeadlineExceeded(f"{phase} exceeded its {seconds:g}-second phase deadline")

    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            remaining = max(0.001, previous_timer[0] - (time.monotonic() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])


def environment_report(work: Path) -> dict:
    disk = shutil.disk_usage(work)
    report = {"python": sys.version, "platform": platform.platform(),
              "disk_free_bytes": disk.free, "disk_used_bytes": disk.used, "disk_total_bytes": disk.total,
              "phase_deadlines_seconds": {"collection": CAPTURE_TIMEOUT_SECONDS,
                                           "verification": VERIFICATION_TIMEOUT_SECONDS},
              "tools": {}}
    for name in ("git", "gh", "ots"):
        try:
            result = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=10)
            report["tools"][name] = {"path": shutil.which(name), "exit_code": result.returncode,
                                     "version": (result.stdout or result.stderr).strip()[:1000]}
        except (OSError, subprocess.TimeoutExpired) as error:
            report["tools"][name] = {"error": f"{type(error).__name__}: {error}"}
    return report


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


def encrypt_archive_parts(archive: dict, assets: Path, public_key: Path) -> dict:
    """Fail closed: this function never returns a plaintext upload candidate."""
    recipient = public_key_fingerprint(public_key)
    encrypted = {**archive, "encrypted": True, "recipient_spki_sha256": recipient, "parts": []}
    for original in archive["parts"]:
        source = assets / original["name"]
        destination = source.with_name(source.name + ".enc")
        record = encrypt_file(source, destination, public_key)
        if (record["plaintext_sha256"] != original["sha256"] or record["plaintext_bytes"] != original["bytes"]):
            raise ValueError("Archive changed before encryption")
        encrypted["parts"].append({
            "name": destination.name, "sha256": record["ciphertext_sha256"], "bytes": record["ciphertext_bytes"],
            "plaintext": {key: original[key] for key in ("name", "sha256", "bytes")}, "encryption": record,
        })
    return encrypted


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


def downloaded_asset_identity(repository: str, asset: dict) -> dict:
    """Hash a remote asset with bounded memory when GitHub omits its digest."""
    arguments = ["gh", "api", f"repos/{repository}/releases/assets/{asset['id']}",
                 "-H", "Accept: application/octet-stream"]
    with tempfile.TemporaryFile() as output:
        for attempt in range(2):
            output.seek(0)
            output.truncate()
            process = subprocess.run(arguments, stdout=output, stderr=subprocess.PIPE, timeout=1800)
            if process.returncode == 0:
                output.seek(0)
                digest, size = hashlib.sha256(), 0
                while block := output.read(4 * 1024 * 1024):
                    digest.update(block)
                    size += len(block)
                return {"sha256": digest.hexdigest(), "bytes": size}
            if attempt == 0 and wait_for_github_reset():
                continue
            raise RuntimeError(f"GitHub asset download failed with exit {process.returncode}")
    raise AssertionError("unreachable")


def verify_remote_asset(repository: str, asset: dict, identity: dict) -> None:
    if asset.get("state") != "uploaded" or asset.get("size") != identity["bytes"]:
        raise ValueError("Release asset is not uploaded or has the wrong size")
    expected = "sha256:" + identity["sha256"]
    if asset.get("digest"):
        if asset["digest"] != expected:
            raise ValueError("Release asset digest mismatch")
    elif downloaded_asset_identity(repository, asset) != {
            "sha256": identity["sha256"], "bytes": identity["bytes"]}:
        raise ValueError("Downloaded release asset identity mismatch")


def read_json_asset(repository: str, asset: dict) -> tuple[dict, bytes]:
    raw = gh("api", f"repos/{repository}/releases/assets/{asset['id']}",
             "-H", "Accept: application/octet-stream")
    if asset.get("state") != "uploaded" or len(raw) != asset.get("size"):
        raise ValueError("JSON asset is not uploaded or has the wrong length")
    if asset.get("digest") and asset["digest"] != "sha256:" + sha256(raw):
        raise ValueError("JSON asset digest mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object asset")
    return value, raw


def index_capture_accepted(index: dict) -> bool:
    """Recheck scientific acceptance instead of trusting the index summary flag."""
    result = index.get("collector_result") or {}
    verification = index.get("verification") or {}
    manifests = index.get("manifests") or []
    if not isinstance(result, dict) or not isinstance(verification, dict) or not isinstance(manifests, list):
        return False
    if len(manifests) != 1 or not isinstance(manifests[0], dict):
        return False
    manifest = manifests[0]
    bundle = manifest.get("portable_full_bundle") or {}
    if not isinstance(bundle, dict):
        return False
    return bool(
        index.get("complete") is True and index.get("capture_accepted") is True and
        index.get("status") == "complete_for_declared_shallow_baseline" and index.get("errors") == [] and
        result.get("status") == "complete" and result.get("repo") == index.get("repository") and
        result.get("attestation") == "pending_bitcoin_completion" and
        all(isinstance(result.get(key), str) and result[key] for key in ("proof", "immutable_initial_proof")) and
        result.get("manifest_sha256") == manifest.get("sha256") and
        isinstance(manifest.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]) and
        result.get("run_id") == manifest.get("run_id") and bool(manifest.get("run_id")) and
        result.get("repository_id") == manifest.get("repository_id") and
        type(manifest.get("repository_id")) is int and
        manifest.get("status") == "complete" and manifest.get("mode") == "full" and
        manifest.get("has_git") is True and
        isinstance(bundle.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", bundle["sha256"]) and
        type(bundle.get("bytes")) is int and bundle["bytes"] > 0 and
        verification.get("ok") is True and verification.get("errors") == [] and
        verification.get("manifests") == 1 and verification.get("portable_git_bundles_verified") == 1 and
        verification.get("git_repositories_verified") == 1 and verification.get("raw_observations", 0) > 0 and
        verification.get("partial_runs") == 0 and verification.get("unstamped_runs") == 0
    )


def release_capture_outcome(slug: str, repository: str, tag: str, assets: dict,
                            sources: dict, code_sha: str | None, *, parent: bool = False,
                            transport_aliases: dict | None = None) -> dict:
    """Verify one transferred outcome; resume never downloads large archive parts."""
    name = repository_key(slug) + ".index.json"
    row = {"repository": slug, "index_asset": name, "complete": False, "errors": []}
    try:
        asset = assets[name]
        if parent and not asset.get("digest"):
            raise ValueError("Parent index has no remote SHA-256 digest")
        index, raw = read_json_asset(repository, asset)
        capture_sha = index["collector_code_sha"]
        if (index["repository"] != slug or index["release_tag"] != tag or
                index.get("release_repository", repository) != repository or
                not isinstance(capture_sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", capture_sha) or
                (code_sha is not None and capture_sha != code_sha) or
                any(index[key] != value for key, value in sources.items())):
            raise ValueError("Index source identity mismatch")
        row.update({"index_sha256": sha256(raw), "capture_status": index["status"],
                    "capture_accepted": index["capture_accepted"], "manifests": index["manifests"]})
        if parent:
            row.update({"source_release_tag": tag, "source_release_repository": repository,
                        "source_index_asset_id": asset["id"], "collector_code_sha": capture_sha})
        if not isinstance(index["errors"], list) or not all(isinstance(error, str) for error in index["errors"]):
            raise ValueError("Invalid index errors")
        row["errors"] = list(index["errors"])
        if not isinstance(index["archive"], dict):
            raise ValueError("Invalid archive record")
        parts = index["archive"]["parts"]
        if not isinstance(parts, list) or not all(isinstance(part, dict) for part in parts):
            raise ValueError("Invalid archive part list")
        if len({part["name"] for part in parts}) != len(parts):
            raise ValueError("Duplicate archive part names")
        for part in parts:
            remote = assets.get(part["name"])
            if (part.get("uploaded") is not True or type(part.get("bytes")) is not int or
                    part["bytes"] <= 0 or not isinstance(part.get("sha256"), str) or
                    not re.fullmatch(r"[0-9a-f]{64}", part["sha256"])):
                raise ValueError("Missing or wrong-sized archive part")
            identity = part
            if parent and transport_aliases and part["name"] in transport_aliases:
                alias = transport_aliases[part["name"]]
                expected = {key: part[key] for key in ("name", "sha256", "bytes")}
                if not isinstance(alias, dict) or alias.get("plaintext") != expected:
                    raise ValueError("Parent transport alias plaintext identity mismatch")
                identity = alias.get("ciphertext")
                if (not isinstance(identity, dict) or not isinstance(identity.get("name"), str) or
                        type(identity.get("bytes")) is not int or identity["bytes"] <= 0 or
                        not isinstance(identity.get("sha256"), str) or
                        not re.fullmatch(r"[0-9a-f]{64}", identity["sha256"])):
                    raise ValueError("Invalid parent ciphertext identity")
                remote = assets.get(identity["name"])
                row.setdefault("archive_transport_aliases", []).append(alias)
            if remote is None:
                raise ValueError("Missing archive transport asset")
            if parent and not remote.get("digest"):
                raise ValueError("Parent archive part has no remote SHA-256 digest")
            verify_remote_asset(repository, remote, identity)
        row["complete"] = bool(index_capture_accepted(index) and index["archive"].get("complete") is True and parts)
        if index.get("complete") and not row["complete"]:
            row["errors"].append("Index claims completion but acceptance evidence is inconsistent")
    except (KeyError, ValueError, TypeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        row["errors"].append(f"{type(error).__name__}: {error}")
    return row


def parent_capture_outcomes(config: Config, sources: dict, repository: str, tag: str) -> dict[str, dict]:
    if not REPO_RE.fullmatch(repository) or not re.fullmatch(r"corpus-baseline-[0-9]+-[0-9]+", tag):
        raise ValueError("Invalid parent release destination")
    release = json.loads(gh("api", f"repos/{repository}/releases/tags/{tag}"))
    target = release.get("target_commitish", "")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", target):
        raise ValueError("Parent release must identify a full capture code SHA")
    assets = {asset["name"]: asset for asset in release_assets(repository, release["id"])}
    migration_asset = assets.get("encryption-migration-index.json")
    aliases, migration_raw = {}, None
    if migration_asset:
        if not migration_asset.get("digest"):
            raise ValueError("Parent encryption migration index has no remote SHA-256 digest")
        migration, migration_raw = read_json_asset(repository, migration_asset)
        if migration.get("schema_version") != 1 or not isinstance(migration.get("parts"), dict):
            raise ValueError("Invalid parent encryption migration index")
        aliases = migration["parts"]
    outcomes = {slug: release_capture_outcome(slug, repository, tag, assets, sources, target, parent=True,
                                             transport_aliases=aliases) for slug in config.repositories}
    for row in outcomes.values():
        if row.get("archive_transport_aliases"):
            row.update({"transport_index_asset": migration_asset["name"],
                        "transport_index_sha256": sha256(migration_raw)})
    return outcomes


def plan(args) -> int:
    config, sources = load_sources(args.config, args.csv)
    parent_tag = getattr(args, "parent_release_tag", None)
    inherited = parent_capture_outcomes(config, sources, args.release_repository, parent_tag) if parent_tag else {}
    remaining = [slug for slug in config.repositories if not inherited.get(slug, {}).get("complete")]
    outputs = {"matrix": json.dumps({"include": [{"slug": slug, "key": repository_key(slug)} for slug in remaining]},
                                    separators=(",", ":")),
               "remaining_count": len(remaining), "inherited_complete_count": len(config.repositories) - len(remaining),
               **sources}
    if args.github_output:
        with args.github_output.open("a") as output:
            for key, value in outputs.items():
                output.write(f"{key}={value}\n")
    print(json.dumps(outputs, indent=2))
    return 0


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
            try:
                verify_remote_asset(repository, asset, identity)
                return
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                raise RuntimeError("Existing release asset cannot be confirmed identical; refusing overwrite") from error
    gh("release", "upload", tag, str(path), "--repo", repository, retry_rate_limit=False)


def write_json(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def capture(args) -> int:
    config, sources = load_sources(args.config, args.csv)
    public_key = Path(getattr(args, "public_key", RESULTS_PUBLIC_KEY))
    recipient = public_key_fingerprint(public_key)  # fail before capture when no valid public key is configured
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
        "retention": "Encrypted Release assets have no automatic expiry configured; owner deletion remains possible. The RSA private key stays local.",
        "timestamp_status": "OTS submission requested; completed Bitcoin verification is not performed here.",
        "results_encryption": {"format": "icsot-encrypted-v1", "recipient_spki_sha256": recipient},
        "errors": [],
    }
    write_json(reports / "capture-request.json", index)
    write_json(reports / "environment.json", environment_report(work))
    result: dict = {"status": "unexpected_error"}
    verification: dict = {"ok": False, "errors": ["Verification did not run"]}
    try:
        # One API reset wait is opt-in for this bounded baseline, not a change to
        # the ordinary collector default or a monthly storage-budget layer.
        single = replace(config, root=evidence.resolve(), repositories=(args.slug,),
                         primary_rate_wait_seconds=3605, primary_rate_reserve=40)
        with phase_deadline(CAPTURE_TIMEOUT_SECONDS, "Collection"):
            result = collect_one(single, args.slug, "full", deep_full=False, bundle_full=True, stamp=True)
    except BaseException as error:
        result = {"repo": args.slug, "status": "unexpected_error", "error": f"{type(error).__name__}: {error}"}
        index["errors"].append(result["error"])
    finally:
        write_json(reports / "collector-result.json", result)
        try:
            with phase_deadline(VERIFICATION_TIMEOUT_SECONDS, "Verification"):
                verification = verify_all(evidence)
        except BaseException as error:
            verification = {"ok": False, "errors": [f"{type(error).__name__}: {error}"]}
            index["errors"].append(f"Verification: {type(error).__name__}: {error}")
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
        try:
            archive = encrypt_archive_parts(archive, assets, public_key)
        except BaseException as error:
            index["errors"].append(f"Encryption: {type(error).__name__}: {error}")
            # Preserve diagnostics without ever falling back to uploading plaintext.
            archive = {"complete": False, "encrypted": True, "parts": [], "recipient_spki_sha256": recipient}
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
    target = release.get("target_commitish", "")
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", target) and target.lower() != args.code_sha.lower():
        raise ValueError("Release target commit differs from expected capture code SHA")
    observed_assets = release_assets(args.release_repository, release["id"])
    assets = {asset["name"]: asset for asset in observed_assets}
    parent_tag = getattr(args, "parent_release_tag", None)
    if parent_tag == args.release_tag:
        raise ValueError("Parent and current release must differ")
    inherited = parent_capture_outcomes(config, sources, args.release_repository, parent_tag) if parent_tag else {}
    summary = {
        "schema_version": 1, "release_tag": args.release_tag, "collector_code_sha": args.code_sha,
        "finalizer_code_sha": getattr(args, "finalizer_code_sha", args.code_sha),
        **sources, "finalized_at": utc_iso(), "scope": SCOPE,
        "matrix_result": os.getenv("BASELINE_MATRIX_RESULT", "unknown"),
        "assets_observed_before_final_inventory": [
            {key: asset.get(key) for key in ("id", "name", "size", "digest", "state")}
            for asset in observed_assets
        ],
        "repositories": [], "timestamp_status": "Pending OTS receipts are not verified Bitcoin timestamps.",
        "retention": "No automatic expiry/deletion configured; GitHub owner/admin deletion remains possible. No independent backup is configured.",
    }
    if parent_tag:
        summary["parent_release_tag"] = parent_tag
    for slug in config.repositories:
        row = release_capture_outcome(slug, args.release_repository, args.release_tag, assets, sources, args.code_sha)
        if not row["complete"] and inherited.get(slug, {}).get("complete"):
            row = inherited[slug]
        summary["repositories"].append(row)
    summary["complete_repositories"] = sum(row["complete"] for row in summary["repositories"])
    summary["incomplete_repositories"] = len(config.repositories) - summary["complete_repositories"]
    summary["complete"] = summary["incomplete_repositories"] == 0
    summary["status"] = "complete_for_declared_shallow_baseline" if summary["complete"] else "incomplete"
    args.work_root.mkdir(parents=True, exist_ok=True)
    inventory = args.work_root / "baseline-inventory.json"
    existing_inventory = assets.get(inventory.name)
    if existing_inventory is not None:
        recorded, recorded_raw = read_json_asset(args.release_repository, existing_inventory)
        stable_keys = ("schema_version", "release_tag", "collector_code_sha", *sources,
                       "repositories", "complete_repositories", "incomplete_repositories", "complete", "status")
        if parent_tag:
            stable_keys += ("parent_release_tag",)
        if any(recorded.get(key) != summary[key] for key in stable_keys):
            raise ValueError("Existing inventory differs from verified current capture outcomes; refusing overwrite")
        inventory.write_bytes(recorded_raw)
        summary = recorded
    else:
        if not release["draft"]:
            raise RuntimeError("Published baseline release has no verifiable inventory")
        write_json(inventory, summary)
        upload_asset(args.release_tag, inventory, args.release_repository)
    if not release["draft"]:
        print(json.dumps({**{key: summary[key] for key in ("status", "complete_repositories", "incomplete_repositories")},
                          "already_published": True, "finalizer_code_sha": getattr(args, "finalizer_code_sha", args.code_sha)}, indent=2))
        return 0 if summary["complete"] else 2
    notes = args.work_root / "release-notes.md"
    notes.write_text(
        f"One-time 185-repository shallow baseline: **{summary['status']}**.\n\n"
        f"Accepted repositories: {summary['complete_repositories']}/185; incomplete or missing: {summary['incomplete_repositories']}. "
        "See baseline-inventory.json and each repository's index asset for capture, verification, source hashes and ordered archive-part digests. "
        "A missing index represents missing/failed transfer, not successful coverage.\n\n"
        f"Collector commit: `{args.code_sha}`. Config SHA-256: `{sources['config_source_sha256']}`. CSV SHA-256: `{sources['csv_sha256']}`.\n\n"
        f"Finalizer commit: `{getattr(args, 'finalizer_code_sha', args.code_sha)}`.\n\n"
        + (f"Accepted captures referenced from parent release: `{parent_tag}`. Parent assets remain in that release; "
           "each inherited inventory row records its source release, original collector commit, and index SHA-256.\n\n" if parent_tag else "") +
        f"{SCOPE}\n\n"
        "All matrix jobs have reached a terminal state. This release is published once after collection; no cron, later state restore, "
        "automatic deletion or expiry is configured. Payloads are encrypted; Release storage remains deletable and is not an independent backup.\n"
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
            child.add_argument("--release-repository")
        else:
            child.add_argument("--release-tag", required=True)
            child.add_argument("--release-repository", required=True)
            child.add_argument("--code-sha", required=True)
            child.add_argument("--work-root", type=Path, required=True)
            if command == "capture":
                child.add_argument("--slug", required=True)
                child.add_argument("--public-key", type=Path, default=RESULTS_PUBLIC_KEY)
        if command in ("plan", "finalize"):
            child.add_argument("--parent-release-tag")
    args = parser.parse_args(argv)
    if args.command == "restore":
        verification = restore_mirrors(args.root)
        print(json.dumps(verification, indent=2))
        return 0 if verification["ok"] else 3
    if args.command == "plan":
        if args.parent_release_tag and not args.release_repository:
            parser.error("--release-repository is required with --parent-release-tag")
        return plan(args)
    if not REPO_RE.fullmatch(args.release_repository) or not re.fullmatch(r"corpus-baseline-[0-9]+-[0-9]+", args.release_tag):
        raise ValueError("Invalid release destination")
    actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.code_sha):
        raise ValueError("Expected a full capture code SHA")
    if args.command == "capture" and args.code_sha != actual_sha:
        raise ValueError("Collector checkout does not match requested code SHA")
    if args.command == "finalize":
        args.finalizer_code_sha = actual_sha
    return capture(args) if args.command == "capture" else finalize(args)


if __name__ == "__main__":
    raise SystemExit(main())
