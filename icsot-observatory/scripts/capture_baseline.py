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
from icsot_observer.core import Config, ObjectStore, REPO_RE, canonical_json, sha256, utc_iso, write_once
from icsot_observer.gitstore import run_git
from icsot_observer.encryption import encrypt_file, public_key_fingerprint
from icsot_observer.pipeline import collect_one, restore_mirrors as restore_evidence_mirrors

PART_BYTES = 1024 ** 3
EXPECTED_REPOSITORIES = 185
CAPTURE_TIMEOUT_SECONDS = 120 * 60
VERIFICATION_TIMEOUT_SECONDS = 20 * 60
RESULTS_PUBLIC_KEY = Path(__file__).resolve().parents[1] / "keys/results-rsa-public.pem"
MAX_PARENT_RELEASES = 16
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


def release_by_tag(repository: str, tag: str) -> dict:
    """Unpublished draft tags may not resolve through the tag endpoint."""
    try:
        return json.loads(gh("api", f"repos/{repository}/releases/tags/{tag}"))
    except RuntimeError:
        pages = json.loads(gh("api", f"repos/{repository}/releases?per_page=100", "--paginate", "--slurp"))
        matches = [release for page in pages for release in page if release.get("tag_name") == tag]
        if len(matches) != 1:
            raise RuntimeError("Could not identify one accessible release for the requested tag")
        return matches[0]


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
        if "timestamp_evidence" in index:
            if not isinstance(index["timestamp_evidence"], dict) or not isinstance(index.get("public_sidecars"), list):
                raise ValueError("Invalid public timestamp evidence")
            sidecars = index["public_sidecars"]
            if len({item["name"] for item in sidecars}) != len(sidecars):
                raise ValueError("Duplicate public timestamp sidecar")
            for item in sidecars:
                if (not isinstance(item.get("name"), str) or type(item.get("bytes")) is not int or item["bytes"] <= 0 or
                        not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                    raise ValueError("Invalid public timestamp sidecar identity")
                remote = assets[item["name"]]
                if parent and not remote.get("digest"):
                    raise ValueError("Parent timestamp sidecar has no remote SHA-256 digest")
                verify_remote_asset(repository, remote, item)
            ots = index["timestamp_evidence"].get("opentimestamps", {})
            if "metadata" in ots and any(ots[key] not in sidecars for key in ("proof_asset", "metadata_asset")):
                raise ValueError("Timestamp evidence references an unpublished sidecar")
            row.update(timestamp_evidence=index["timestamp_evidence"], public_sidecars=sidecars,
                       timestamp_sidecar_status="published" if "metadata" in ots else ots.get("status", "not_collected"))
        else:
            row["timestamp_sidecar_status"] = "not_recorded_in_original_index; encrypted_receipt_backfill_not_attempted"
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
            if parent:
                row.setdefault("verified_archive_assets", []).append({
                    "id": remote["id"], "name": remote["name"], "sha256": identity["sha256"], "bytes": identity["bytes"],
                })
        row["complete"] = bool(index_capture_accepted(index) and index["archive"].get("complete") is True and parts)
        if index.get("complete") and not row["complete"]:
            row["errors"].append("Index claims completion but acceptance evidence is inconsistent")
    except (KeyError, ValueError, TypeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        row["errors"].append(f"{type(error).__name__}: {error}")
    return row


def parent_capture_outcomes(config: Config, sources: dict, repository: str, tag: str) -> dict[str, dict]:
    if not REPO_RE.fullmatch(repository) or not re.fullmatch(r"corpus-baseline-[0-9]+-[0-9]+", tag):
        raise ValueError("Invalid parent release destination")
    release = release_by_tag(repository, tag)
    target = release.get("target_commitish", "")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", target):
        raise ValueError("Parent release must identify a full capture code SHA")
    assets = unique_release_assets(release_assets(repository, release["id"]))
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
        if row.get("complete"):
            row.update({"source_release_id": release["id"], "source_release_target_commitish": target,
                        "repository_id": row["manifests"][0]["repository_id"]})
        if row.get("archive_transport_aliases"):
            row.update({"transport_index_asset": migration_asset["name"],
                        "transport_index_asset_id": migration_asset["id"],
                        "transport_index_sha256": sha256(migration_raw)})
    return outcomes


def unique_release_assets(items: list[dict]) -> dict[str, dict]:
    assets = {}
    for asset in items:
        name = asset["name"]
        if not isinstance(name, str) or name in assets:
            raise ValueError("Duplicate or invalid release asset name")
        assets[name] = asset
    return assets


def requested_parent_tags(args) -> list[str]:
    primary = getattr(args, "parent_release_tag", None)
    tags = ([primary] if primary else []) + list(getattr(args, "additional_parent_release_tag", None) or [])
    tags = [tag.strip() for tag in tags]
    if len(tags) > MAX_PARENT_RELEASES:
        raise ValueError(f"At most {MAX_PARENT_RELEASES} explicit parent releases are supported")
    if any(not re.fullmatch(r"corpus-baseline-[0-9]+-[0-9]+", tag) for tag in tags):
        raise ValueError("Invalid parent release tag")
    if len(set(tags)) != len(tags):
        raise ValueError("Duplicate parent releases are not allowed")
    if getattr(args, "release_tag", None) in tags:
        raise ValueError("Parent and current release must differ")
    return tags


def _capture_identity(row: dict) -> tuple[int, str, tuple]:
    manifest = row["manifests"][0]
    bundle = manifest["portable_full_bundle"]
    return manifest["repository_id"], manifest["run_id"], (
        manifest["sha256"], bundle["sha256"], bundle["bytes"], row["collector_code_sha"])


def _capture_reference(row: dict) -> dict:
    return {key: value for key, value in row.items() if key != "accepted_parent_references"}


def parent_capture_outcomes_many(config: Config, sources: dict, repository: str, tags: list[str]) -> dict[str, dict]:
    """Union explicit parents; never infer lineage from mutable release notes."""
    if len(tags) > MAX_PARENT_RELEASES or len(set(tags)) != len(tags):
        raise ValueError("Parent list exceeds its bound or contains a duplicate/cycle")
    selected: dict[str, dict] = {}
    references: dict[str, list[dict]] = {}
    seen_capture: dict[tuple[int, str], tuple] = {}
    seen_index_asset: dict[tuple[str, int], str] = {}
    repository_ids: dict[str, int] = {}
    # Validate every requested release, even if an earlier parent covers all.
    for tag in tags:
        outcomes = parent_capture_outcomes(config, sources, repository, tag)
        for slug, row in outcomes.items():
            if slug not in selected:
                selected[slug] = row
            if not row.get("complete"):
                continue
            repo_id, capture_id, fingerprint = _capture_identity(row)
            if slug in repository_ids and repository_ids[slug] != repo_id:
                raise ValueError(f"Conflicting stable repository IDs across accepted parents: {slug}")
            repository_ids[slug] = repo_id
            identity = (repo_id, capture_id)
            if identity in seen_capture and seen_capture[identity] != fingerprint:
                raise ValueError(f"Conflicting accepted capture identity across parents: {slug}")
            seen_capture[identity] = fingerprint
            asset_key = (row["source_release_repository"], row["source_index_asset_id"])
            if asset_key in seen_index_asset and seen_index_asset[asset_key] != row["index_sha256"]:
                raise ValueError("One source index asset ID has conflicting SHA-256 identities")
            seen_index_asset[asset_key] = row["index_sha256"]
            references.setdefault(slug, []).append(_capture_reference(row))
            if not selected[slug].get("complete"):
                selected[slug] = row
    if len(tags) > 1:
        for slug, refs in references.items():
            selected[slug] = {**selected[slug], "accepted_parent_references": refs}
    return selected


def plan(args) -> int:
    config, sources = load_sources(args.config, args.csv)
    parent_tags = requested_parent_tags(args)
    inherited = parent_capture_outcomes_many(config, sources, args.release_repository, parent_tags) if parent_tags else {}
    remaining = [slug for slug in config.repositories if not inherited.get(slug, {}).get("complete")]
    outputs = {"matrix": json.dumps({"include": [{"slug": slug, "key": repository_key(slug)} for slug in remaining]},
                                    separators=(",", ":")),
               "remaining_count": len(remaining), "inherited_complete_count": len(config.repositories) - len(remaining),
               "parent_release_tags": json.dumps(parent_tags, separators=(",", ":")),
               **sources}
    if args.github_output:
        with args.github_output.open("a") as output:
            for key, value in outputs.items():
                output.write(f"{key}={value}\n")
    if getattr(args, "plan_output", None):
        write_once(args.plan_output, canonical_json({
            "schema_version": 1, "planned_at": utc_iso(), "release_repository": getattr(args, "release_repository", None),
            "parent_release_tags": parent_tags, **sources,
            "reused_repository_count": outputs["inherited_complete_count"],
            "remaining_count": len(remaining), "remaining_repositories": remaining,
            "reused_captures": [inherited[slug] for slug in config.repositories if inherited.get(slug, {}).get("complete")],
            "remaining_parent_outcomes": [inherited[slug] for slug in remaining if slug in inherited],
            "claim": "Metadata-only accepted-capture reuse; no archive payload download or new observation. Live outcomes may change after planned_at.",
        }))
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
    release = release_by_tag(repository, tag)
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
        index["public_sidecars"] = []
        index["timestamp_evidence"] = {"opentimestamps": {"status": "not_collected"}}
        if len(manifests) == 1 and result.get("immutable_initial_proof"):
            try:
                from icsot_observer.attestations import publish_ots_attestation
                manifest = manifests[0]
                timing = result.get("timestamp_provenance", {})
                evidence = publish_ots_attestation(
                    assets, manifest_sha256=manifest["sha256"], proof_path=Path(result["immutable_initial_proof"]),
                    observation_started_at=manifest["started_at"], observation_finished_at=manifest["finished_at"],
                    requested_at=timing.get("requested_at"), received_at=timing.get("received_at"),
                    collected_at=timing.get("receipt_collected_at"))
                for sidecar in (evidence["proof_asset"], evidence["metadata_asset"]):
                    upload_asset(args.release_tag, assets / sidecar["name"], args.release_repository)
                index.update(observation_started_at=manifest["started_at"], observation_finished_at=manifest["finished_at"],
                             manifest_sha256=manifest["sha256"], repository_id=manifest["repository_id"],
                             clock_source="runner_system_clock", public_sidecars=[evidence["proof_asset"], evidence["metadata_asset"]],
                             timestamp_evidence={"opentimestamps": evidence})
            except Exception as error:
                index["timestamp_evidence"] = {"opentimestamps": {"status": "publication_failed"}}
                index["errors"].append(f"Timestamp sidecars: {type(error).__name__}: {error}")
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


def publish_baseline_timestamp_catalog(args, summary: dict, current_rows: list[dict], assets: dict, *, draft: bool) -> None:
    """One finalizer barrier; capture jobs never race on the shared filename."""
    existing = assets.get("metadata-catalog.json")
    if existing is None and not any("timestamp_evidence" in row for row in current_rows):
        return  # Frozen older indexes remain valid; no receipt backfill/decryption.
    indexes, observations, gaps = [], [], []
    for row in current_rows:
        if not row.get("index_sha256"):
            continue
        ref = {"release_tag": args.release_tag, "name": row["index_asset"],
               "sha256": row["index_sha256"], "bytes": assets[row["index_asset"]]["size"]}
        indexes.append(ref)
        ots = row.get("timestamp_evidence", {}).get("opentimestamps", {})
        if "metadata" not in ots:
            gaps.append({"repository": row["repository"], "index": ref,
                         "status": row.get("timestamp_sidecar_status", "public_proof_unavailable")})
            continue
        observations.append({"repository": row["repository"], "manifest_sha256": ots["metadata"]["subject_sha256"],
                             "index": ref, "timestamp_evidence": row["timestamp_evidence"],
                             "public_sidecars": [{"release_tag": args.release_tag, **item} for item in row["public_sidecars"]]})
    value = {"schema_version": 1, "kind": "icsot_evidence_metadata_catalog", "generation_release": args.release_tag,
             "publication_recorded_at": summary["finalized_at"], "clock_source": "runner_system_clock",
             "parent_release_tags": requested_parent_tags(args), "indexes": indexes, "observations": observations,
             "indexes_without_public_proof": gaps,
             "inherited_public_proof_backfill_gaps": [
                 {"repository": row["repository"], "source_release_tag": row.get("source_release_tag"),
                  "index_sha256": row.get("index_sha256"), "status": row["timestamp_sidecar_status"]}
                 for row in summary["repositories"] if row.get("source_release_tag") and
                 row.get("timestamp_sidecar_status", "").startswith("not_recorded")],
             "inventory_sha256": sha256((args.work_root / "baseline-inventory.json").read_bytes())}
    destination = args.work_root / "metadata-catalog.json"
    if existing is not None:
        recorded, raw = read_json_asset(args.release_repository, existing)
        if recorded != value:
            raise ValueError("Existing timestamp catalog differs from verified outcomes; refusing overwrite")
        destination.write_bytes(raw)
    else:
        if not draft:
            return  # Do not add metadata to a frozen historical published release.
        write_json(destination, value)
        upload_asset(args.release_tag, destination, args.release_repository)
    from icsot_observer.github_state import GhCliStateTransport
    from icsot_observer.proof_maintenance import register_catalog
    register_catalog(GhCliStateTransport(args.release_repository), {
        "release_tag": args.release_tag, "name": destination.name, **{key: file_identity(destination)[key] for key in ("sha256", "bytes")}})


def finalize(args) -> int:
    config, sources = load_sources(args.config, args.csv)
    release = release_by_tag(args.release_repository, args.release_tag)
    target = release.get("target_commitish", "")
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", target) and target.lower() != args.code_sha.lower():
        raise ValueError("Release target commit differs from expected capture code SHA")
    observed_assets = release_assets(args.release_repository, release["id"])
    assets = unique_release_assets(observed_assets)
    parent_tags = requested_parent_tags(args)
    parent_tag = parent_tags[0] if parent_tags else None
    inherited = parent_capture_outcomes_many(config, sources, args.release_repository, parent_tags) if parent_tags else {}
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
        summary["parent_release_tags"] = parent_tags
    current_rows = []
    for slug in config.repositories:
        row = release_capture_outcome(slug, args.release_repository, args.release_tag, assets, sources, args.code_sha)
        current_rows.append(row)
        prior = inherited.get(slug, {})
        if row["complete"] and prior.get("complete"):
            current_id, current_run, current_fingerprint = _capture_identity({**row, "collector_code_sha": args.code_sha})
            for reference in prior.get("accepted_parent_references", [_capture_reference(prior)]):
                prior_id, prior_run, prior_fingerprint = _capture_identity(reference)
                if current_id != prior_id or (current_run == prior_run and current_fingerprint != prior_fingerprint):
                    raise ValueError(f"Current capture conflicts with an accepted parent identity: {slug}")
            row["accepted_parent_references"] = prior.get("accepted_parent_references", [_capture_reference(prior)])
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
            if len(parent_tags) > 1 or "parent_release_tags" in recorded:
                stable_keys += ("parent_release_tags",)
        if any(recorded.get(key) != summary[key] for key in stable_keys):
            raise ValueError("Existing inventory differs from verified current capture outcomes; refusing overwrite")
        inventory.write_bytes(recorded_raw)
        summary = recorded
    else:
        if not release["draft"]:
            raise RuntimeError("Published baseline release has no verifiable inventory")
        write_json(inventory, summary)
        upload_asset(args.release_tag, inventory, args.release_repository)
    publish_baseline_timestamp_catalog(args, summary, current_rows, assets, draft=release["draft"])
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
        + (f"Accepted captures referenced from ordered parent releases: `{', '.join(parent_tags)}`. Parent assets remain in those releases; "
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
    """Compatibility entry point for offline full/incremental Git restoration."""
    return restore_evidence_mirrors(root)


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
            child.add_argument("--plan-output", type=Path, help="Create-only local audit of all reused references and remaining targets")
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
            child.add_argument("--additional-parent-release-tag", action="append", default=[],
                               help="Additional explicit fallback parent, in priority order; at most 16 total")
    args = parser.parse_args(argv)
    if args.command == "restore":
        verification = restore_mirrors(args.root)
        print(json.dumps(verification, indent=2))
        return 0 if verification["ok"] else 3
    if args.command == "plan":
        if requested_parent_tags(args) and not args.release_repository:
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
