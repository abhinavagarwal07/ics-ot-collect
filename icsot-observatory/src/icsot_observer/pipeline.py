from __future__ import annotations

import fcntl
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .core import Config, ObjectStore, canonical_json, parse_github_time, run_id, sha256, utc_iso, utc_now, write_once
from .diagnostics import emit, exception_fields, failure_category
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


def _legacy_api_cursor_qualified(manifest: dict[str, Any]) -> bool:
    """A global delta boundary requires every base listing, not just run success."""
    api = manifest.get("api") or {}
    if api.get("failures") or api.get("watermark_withheld") or api.get("unavailable_scopes"):
        return False
    scopes = api.get("scope_statuses") or api.get("scopes") or {}
    required = ("issues", "pulls", "issue_comments", "review_comments", "releases", "tags", "events")
    return all(scopes.get(name, {}).get("status") == "complete_for_query" for name in required)


@contextmanager
def manifest_append_lock(root: Path, repo_id: int):
    """Serialize only immutable manifest allocation, never network or stamping."""
    home = root / "runs" / str(repo_id)
    home.mkdir(parents=True, exist_ok=True)
    fd = os.open(home / ".append.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _public_config(config: Config) -> dict[str, Any]:
    # Environment variable names and secrets are deliberately excluded.
    return {key: value for key, value in asdict(config).items()
            if key not in ("root", "token_env")}


def _rfc3161_policy(endpoint: str | None, ca_file: Path | None, untrusted_file: Path | None) -> dict | None:
    if endpoint is None and ca_file is None and untrusted_file is None:
        return None
    if not endpoint or ca_file is None:
        raise ValueError("RFC 3161 requires both a TSA URL and an explicit trusted CA file")
    ca = Path(ca_file).resolve()
    chain = Path(untrusted_file).resolve() if untrusted_file else None
    return {"endpoint": endpoint, "ca_file": str(ca), "ca_sha256": _file_sha256(ca),
            "untrusted_file": str(chain) if chain else None,
            "untrusted_sha256": _file_sha256(chain) if chain else None}


def _public_timestamp_policy(policy: dict | None) -> dict | None:
    return {key: policy[key] for key in ("endpoint", "ca_sha256", "untrusted_sha256")} if policy else None


def _registry_path(root: Path, slug: str) -> Path:
    return root / "registry" / (slug.lower().replace("/", "__") + ".json")


def _bind_identity(config: Config, slug: str, meta: dict, started: str) -> int:
    if meta.get("private") is not False or type(meta.get("id")) is not int or meta["id"] <= 0:
        raise RuntimeError("Repository does not unambiguously appear public")
    repo_id = meta["id"]
    path = _registry_path(config.root, slug)
    if not path.exists():
        try:
            write_once(path, canonical_json({
                "input_slug": slug, "repository_id": repo_id, "first_identified_at": started,
                "note": "Create-only registry binding; changes require audited cohort amendment",
            }))
        except FileExistsError:
            pass  # Independent first API/Git jobs may establish the same binding.
    if json.loads(path.read_bytes()).get("repository_id") != repo_id:
        raise RuntimeError("REPOSITORY_IDENTITY_CHANGED: slug now points to another repository id")
    return repo_id


def _next_manifest_id(previous: tuple[dict, str] | None, actual: datetime) -> tuple[str, bool]:
    namespace_time = actual.astimezone(timezone.utc)
    clamped = False
    if previous:
        prior_id = previous[0]["run_id"]
        try:
            prior_time = datetime.strptime(prior_id.split("-", 1)[0], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
        except ValueError as error:
            raise RuntimeError("Cannot append persistent evidence after an unrecognized run ID") from error
        if namespace_time <= prior_time:
            namespace_time = prior_time + timedelta(microseconds=1)
            clamped = True
    return namespace_time.strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8], clamped


def append_capture_manifest(config: Config, capture: dict[str, Any]) -> dict[str, Any]:
    """Idempotently publish a captured lane, linking to the latest finalized lane.

    Capture IDs name work and Git pins. Run IDs order finalized manifests only;
    allocating them at capture start would fork the chain on reverse completion.
    """
    repo_id = capture["repository_id"]
    if type(repo_id) is not int or repo_id <= 0 or capture["lane"] not in ("api", "git"):
        raise ValueError("Capture needs a positive repository ID and known lane")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", capture["capture_id"]):
        raise ValueError("Safe explicit capture_id required")
    capture_digest = sha256(canonical_json(capture))
    with manifest_append_lock(config.root, repo_id):
        home = config.root / "runs" / str(repo_id)
        for path in home.glob("*.manifest.json"):
            raw = path.read_bytes()
            existing = json.loads(raw)
            if existing.get("capture_id") == capture["capture_id"]:
                if existing.get("capture_payload_sha256") != capture_digest:
                    raise RuntimeError("Capture ID already finalized with different captured evidence")
                return {"manifest": str(path), "manifest_sha256": sha256(raw),
                        "run_id": existing["run_id"], "status": existing["status"]}
        previous = prior_manifest(config.root, repo_id)
        allocated_at = utc_now()
        rid, clamped = _next_manifest_id(previous, allocated_at)
        public = capture.get("public_config", _public_config(config))
        manifest = {
            "schema_version": 1, "collector_version": capture.get("collector_version", __version__),
            "finalizer_version": __version__,
            "public_config": public, "public_config_sha256": sha256(canonical_json(public)),
            "run_id": rid, "capture_id": capture["capture_id"], "lane": capture["lane"],
            "capture_payload_sha256": capture_digest,
            "repository_input_slug": capture["slug"], "repository_id": repo_id,
            "expected_repository_id": capture.get("expected_repository_id"),
            "working_state_origin": capture.get("working_state_origin"),
            "history_policy": capture.get("history_policy"),
            "mode": capture["mode"], "requested_mode": capture["requested_mode"],
            "status": "partial" if capture["failures"] else "complete",
            "started_at": capture["started_at"], "finished_at": capture["finished_at"],
            "manifest_allocated_at": utc_iso(allocated_at),
            "manifest_namespace_clock_clamped": clamped,
            "previous_manifest_sha256": previous[1] if previous else None,
            "api_version": public["api_version"], "since": capture.get("since"),
            "scope_since": capture.get("scope_since", {}),
            "watermark_candidates": capture.get("watermark_candidates", {}),
            "api": capture.get("api"), "git": capture.get("git"),
            "responses": capture["responses"], "failures": capture["failures"],
            "telemetry": capture.get("telemetry", {}),
            "verification": capture.get("verification"),
            "timestamp_policy": _public_timestamp_policy(capture.get("rfc3161_policy")),
            "claim_scope": "successful requests or Git fetches in this lane's separate observation intervals",
            "limitation": "No proof of GitHub source authenticity or absolute first publication; evidence is interval-observed and non-atomic.",
        }
        path = home / (rid + ".manifest.json")
        raw = canonical_json(manifest)
        write_once(path, raw)
        return {"manifest": str(path), "manifest_sha256": sha256(raw), "run_id": rid,
                "status": manifest["status"]}


def attest_manifest(root: Path, info: dict[str, Any], *, stamp: bool = True) -> dict[str, Any]:
    """Keep network timestamp work outside the short manifest append lock."""
    if not stamp:
        return {**info, "attestation": "DISABLED_UNSAFE_FOR_PROVENANCE_CLAIMS"}
    path, digest = Path(info["manifest"]), info["manifest_sha256"]
    proof = Path(str(path) + ".ots")
    initial = root / "proofs" / "initial" / (digest + ".ots")
    if proof.is_file() and initial.is_file():
        receipt = _timestamp_receipt_info(root, info, proof, initial)
        emit("stage_end", stage="timestamp_receipt", status="reused_pending_bitcoin_completion"
             if receipt["attestation"] == "pending_bitcoin_completion" else "invalid_receipt")
        return receipt
    ots = shutil.which("ots")
    if not ots:
        emit("stage_end", stage="timestamp_receipt", status="client_unavailable", failure_category="proof_failed")
        return {**info, "attestation": "error: ots CLI not found"}
    requested_at = received_at = None
    if not proof.exists():
        stage_started = time.monotonic()
        emit("stage_start", stage="timestamp_request")
        requested_at = utc_iso()
        try:
            result = subprocess.run([ots, "stamp", str(path)], capture_output=True, text=True, timeout=180)
        except BaseException as error:
            emit("stage_end", stage="timestamp_request", status="failed",
                 elapsed_seconds=round(time.monotonic() - stage_started, 3), **exception_fields(error))
            raise
        received_at = utc_iso()
        emit("stage_end", stage="timestamp_request", status="returned" if result.returncode == 0 else "failed",
             returncode=result.returncode, signal=-result.returncode if result.returncode < 0 else None,
             elapsed_seconds=round(time.monotonic() - stage_started, 3),
             **({"failure_category": "proof_failed"} if result.returncode else {}))
        if result.returncode:
            return {**info, "attestation": f"error: ots stamp exit {result.returncode}"}
    if not proof.is_file():
        emit("stage_end", stage="timestamp_receipt", status="receipt_missing", failure_category="proof_failed")
        return {**info, "attestation": "error: ots returned success but receipt missing"}
    try:
        write_once(initial, proof.read_bytes())
    except FileExistsError:
        pass
    receipt = _timestamp_receipt_info(root, info, proof, initial, requested_at=requested_at, received_at=received_at)
    emit("stage_end", stage="timestamp_receipt", status="pending_bitcoin_completion"
         if receipt["attestation"] == "pending_bitcoin_completion" else "invalid_receipt")
    return receipt


def _timestamp_receipt_info(root: Path, info: dict[str, Any], proof: Path, initial: Path, *,
                            requested_at: str | None = None, received_at: str | None = None) -> dict[str, Any]:
    """Bind first recorded stamp timing without guessing historical request times."""
    if not proof.stat().st_size or not initial.stat().st_size:
        return {**info, "attestation": "error: empty timestamp receipt"}
    provenance_path = root / "proofs" / "initial" / (info["manifest_sha256"] + ".stamp.json")
    provenance = {"schema_version": 1, "manifest_sha256": info["manifest_sha256"],
                  "receipt_sha256": _file_sha256(initial), "requested_at": requested_at,
                  "received_at": received_at, "receipt_collected_at": received_at or utc_iso(),
                  "request_timing_source": "recorded_around_ots_stamp" if requested_at else "unknown_preexisting_receipt",
                  "clock_source": "runner_system_clock"}
    try:
        write_once(provenance_path, canonical_json(provenance))
    except FileExistsError:
        provenance = json.loads(provenance_path.read_bytes())
    if (provenance.get("manifest_sha256") != info["manifest_sha256"] or
            provenance.get("receipt_sha256") != _file_sha256(initial)):
        raise RuntimeError("Timestamp receipt timing record differs from immutable receipt")
    return {**info, "attestation": "pending_bitcoin_completion", "proof": str(proof),
            "immutable_initial_proof": str(initial), "timestamp_provenance": provenance,
            "timestamp_provenance_path": str(provenance_path)}


def capture_lane(config: Config, job: Any, queue: Any) -> dict[str, Any]:
    """Capture one resumable API job or one incremental Git job, without appending."""
    from .checkpoints import CheckpointStore
    from .github import APIRequestDeferred, BASE_SCOPES
    from .runtime import RetryDeferred

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", job.capture_id):
        raise ValueError("Safe explicit capture_id required")
    if job.payload.get("collector_config"):
        frozen = dict(job.payload["collector_config"])
        frozen["repositories"] = tuple(frozen["repositories"])
        config = Config(root=config.root, token_env=config.token_env, **frozen)
    started, phase_start = utc_iso(), time.monotonic()
    records: list[dict] = []
    identity_quarantine = config.root / "quarantine" / "identity" / sha256(job.slug.lower().encode())[:24] / job.capture_id
    if identity_quarantine.exists():
        for path in sorted(identity_quarantine.glob("*.json")):
            attempt = json.loads(path.read_bytes())
            if attempt["capture_id"] != job.capture_id or attempt["slug"] != job.slug:
                raise RuntimeError("Identity attempt quarantine binding changed")
            records.extend(attempt["records"])
    prior_identity_records = len(records)
    store = ObjectStore(config.root)
    identity_path = _registry_path(config.root, job.slug)
    # A fresh numeric binding is required even for Git: a reused owner/name may
    # otherwise silently add another repository's objects to the old ID mirror.
    bound = json.loads(identity_path.read_bytes())["repository_id"] if identity_path.exists() else None
    checkpoint = CheckpointStore(config.root, bound, job.capture_id) if bound is not None else None
    if checkpoint:
        saved = {canonical_json({key: value for key, value in record.items() if key != "checkpoint_provenance"})
                 for record in checkpoint.responses()}
        records[:] = [record for record in records if canonical_json(
            {key: value for key, value in record.items() if key != "checkpoint_provenance"}) not in saved]
    try:
        api = GitHubAPI(config, store, records, checkpoint_store=checkpoint, defer_on_rate=True,
                        source_repository=job.slug)
        meta = api.get_json(f"/repos/{job.slug}", "repository_identity")
        expected = job.payload.get("expected_repository_id")
        if expected is not None and meta.get("id") != expected:
            raise RuntimeError("REPOSITORY_IDENTITY_CHANGED: observed ID differs from selected repository ID")
        repo_id = _bind_identity(config, job.slug, meta, started)
    except Exception as error:
        if bound is None:
            write_once(identity_quarantine / (run_id() + ".json"), canonical_json({
                "capture_id": job.capture_id, "slug": job.slug, "started_at": started,
                "finished_at": utc_iso(), "records": records[prior_identity_records:],
                "failure": f"{type(error).__name__}: {error}",
            }))
        if isinstance(error, APIRequestDeferred):
            raise RetryDeferred(error.retry_not_before, error.reason, lane_wide=True) from error
        raise
    payload: dict[str, Any] = {
        "capture_id": job.capture_id, "slug": job.slug, "repository_id": repo_id,
        "lane": job.lane, "requested_mode": job.mode, "mode": job.mode,
        "collector_version": __version__,
        "expected_repository_id": job.payload.get("expected_repository_id"),
        "working_state_origin": job.payload.get("working_state_origin"),
        "history_policy": job.payload.get("history_policy"),
        "started_at": started, "responses": records, "failures": [],
        "public_config": _public_config(config),
        "rfc3161_policy": job.payload.get("rfc3161_policy"),
    }
    # Bind identity envelopes durably before either lane continues, including a
    # first Git capture whose result may outlive its worker process.
    checkpoint = CheckpointStore(config.root, repo_id, job.capture_id)
    api = GitHubAPI(config, store, records, checkpoint_store=checkpoint, source_repository=job.slug)
    if job.lane == "api":
        scope_since = job.payload.get("scope_since")
        if scope_since is None:
            scope_since = _scope_boundaries(queue, config, repo_id, BASE_SCOPES)
        effective_mode = job.payload.get("effective_api_mode", "full" if job.mode == "delta" and not any(scope_since.values()) else job.mode)
        result = api.collect_resumable(job.slug, effective_mode, since=None,
                                      deep_full=bool(job.payload.get("deep_full", False)),
                                      scope_since=scope_since)
        if result["repository_id"] != repo_id:
            raise RuntimeError("Repository identity changed during API collection")
        if result.get("deferred"):
            deferred = result["deferred"]
            raise RetryDeferred(deferred["retry_not_before"], deferred["reason"],
                                lane_wide=deferred.get("lane_wide", True))
        payload.update(api=result, mode=effective_mode, scope_since=scope_since,
                       failures=result.get("failures", []),
                       watermark_candidates=result.get("watermark_candidates", {}))
    elif job.lane == "git":
        payload["git"] = collect_git(config.root, job.slug, repo_id, job.capture_id,
                                     archive_mode="incremental")
    else:
        raise ValueError("Unknown capture lane")
    # Resumed records retain their source intervals, including earlier attempts.
    interval_starts = [started] + [r["request_started_at"] for r in records if r.get("request_started_at")]
    if (payload.get("git") or {}).get("ls_remote_started_at"):
        interval_starts.append(payload["git"]["ls_remote_started_at"])
    payload["started_at"] = min(interval_starts)
    payload["finished_at"] = utc_iso()
    payload["telemetry"] = {"capture_elapsed_seconds": round(time.monotonic() - phase_start, 6),
                            "response_records": len(records), "job_id": job.id,
                            "capture_attempt": job.attempts}
    return payload


class _EncryptedParts(io.RawIOBase):
    """Bound the plaintext staging space while XZ streams into transfer parts."""

    def __init__(self, temporary: Path, destination: Path, prefix: str, public_key: Path, limit: int):
        super().__init__()
        self.temporary, self.destination, self.prefix, self.public_key, self.limit = temporary, destination, prefix, public_key, limit
        self.current = None
        self.current_size = 0
        self.parts: list[dict] = []

    def writable(self):
        return True

    def _finish(self):
        from .encryption import encrypt_file
        if self.current is None:
            return
        source = Path(self.current.name)
        self.current.flush()
        os.fsync(self.current.fileno())
        self.current.close()
        self.current = None
        name = f"{self.prefix}.tar.xz.part-{len(self.parts) + 1:04d}.enc"
        encryption = encrypt_file(source, self.destination / name, self.public_key)
        self.parts.append({"name": name, "sha256": encryption["ciphertext_sha256"],
                           "bytes": encryption["ciphertext_bytes"], "encryption": encryption})
        source.unlink()

    def write(self, data):
        if self.closed:
            raise ValueError("Write to closed encrypted transfer")
        view, original = memoryview(data), len(data)
        while view:
            if self.current is None:
                self.current = (self.temporary / "part.plaintext").open("xb")
                self.current_size = 0
            count = min(len(view), self.limit - self.current_size)
            self.current.write(view[:count])
            self.current_size += count
            view = view[count:]
            if self.current_size == self.limit:
                self._finish()
        return original

    def close(self):
        if not self.closed:
            self._finish()
        super().close()


class CaptureExporter:
    """Encrypted per-capture transfer packages; prior packages remain required.

    CAS and manifest bytes are included once across this export directory. The
    public index names all prerequisites, so copying only an incremental part is
    never represented as a self-contained archive. No upload credential is used.
    """

    def __init__(self, root: Path, directory: Path, public_key: Path, *, part_bytes: int = 1024 ** 3,
                 verified_prior_indexes: list[dict[str, Any]] | None = None,
                 verified_legacy_seeds: list[dict[str, Any]] | None = None):
        from .encryption import public_key_fingerprint
        self.root, self.directory, self.public_key = root.resolve(), directory.resolve(), public_key
        self.recipient = public_key_fingerprint(public_key)
        if part_bytes < 1 or part_bytes > 1024 ** 3:
            raise ValueError("Encrypted transfer plaintext parts must be between one byte and 1 GiB")
        self.part_bytes = part_bytes
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.delivered: set[str] = set()
        self.delivered_objects: set[str] = set()
        self.known_exports: dict[str, dict] = {}
        self.legacy_seeds: list[dict] = []
        # Only an adapter's authenticated, remotely reconciled catalog may use
        # this path. Local-only operation still checks its retained ciphertext.
        for index in verified_prior_indexes or []:
            self._register_index(index, verify_assets=False)
        for seed in verified_legacy_seeds or []:
            from .legacy_seed_catalog import registerable_members, validate_legacy_seed
            validate_legacy_seed(seed, root=self.root)
            if seed["owner_recipient_spki_sha256"] != self.recipient:
                raise ValueError("Legacy seed owner recipient differs from native evidence recipient")
            members = registerable_members(seed)
            self.delivered.update(member["sha256"] for member in members)
            self.delivered_objects.update(member["sha256"] for member in members
                                          if member["path"].startswith("objects/sha256/"))
            self.legacy_seeds.append(seed)
        for path in self.directory.glob("*.index.json"):
            index = json.loads(path.read_bytes())
            self._register_index(index, verify_assets=True)

    def _register_index(self, index: dict, *, verify_assets: bool):
        if (index.get("schema_version") != 1 or index.get("encrypted") is not True or
                index.get("recipient_spki_sha256") != self.recipient or
                re.fullmatch(r"[0-9a-f]{64}", index.get("manifest_sha256", "")) is None):
            raise ValueError("Invalid encrypted export catalog or recipient")
        for member in index["members"]:
            path = Path(member["path"])
            if path.is_absolute() or ".." in path.parts or re.fullmatch(r"[0-9a-f]{64}", member["sha256"]) is None:
                raise ValueError("Invalid export catalog member")
        if verify_assets:
            for part in [*index.get("assets", [index.get("asset")]), *index.get("public_sidecars", [])]:
                asset_name = part["name"]
                if Path(asset_name).name != asset_name:
                    raise ValueError("Invalid encrypted export asset name")
                asset = self.directory / asset_name
                if not asset.is_file() or _file_sha256(asset) != part["sha256"]:
                    raise RuntimeError("Prior encrypted export asset is missing or corrupt")
        self.delivered.update(member["sha256"] for member in index["members"])
        self.delivered_objects.update(member["sha256"] for member in index["members"]
                                      if member["path"].startswith("objects/sha256/"))
        self.known_exports[index["manifest_sha256"]] = index

    def _git_objects(self, store: ObjectStore, git: dict | None) -> set[str]:
        objects: set[str] = set()
        if not git:
            return objects
        if git.get("portable_full_bundle"):
            objects.add(git["portable_full_bundle"]["sha256"])
        descriptor = git.get("portable_archive")
        while descriptor:
            digest = sha256(canonical_json(descriptor))
            if digest in objects:
                raise ValueError("Cyclic Git archive export prerequisites")
            objects.add(digest)
            if store.get(digest) != canonical_json(descriptor):
                raise RuntimeError("Git archive descriptor is not preserved in CAS")
            for bundle in descriptor["prerequisites"] + ([descriptor["bundle"]] if descriptor["bundle"] else []):
                objects.add(bundle["sha256"])
            parent = descriptor["parent_archive_sha256"]
            descriptor = json.loads(store.get(parent)) if parent else None
        return objects

    def export(self, info: dict[str, Any]) -> dict[str, Any]:
        path = Path(info["manifest"])
        with self.lock:
            if info["manifest_sha256"] in self.known_exports:
                return self.known_exports[info["manifest_sha256"]]
            index_path = self.directory / (info["run_id"] + ".index.json")
            if index_path.exists():
                index = json.loads(index_path.read_bytes())
                if index["manifest_sha256"] != info["manifest_sha256"]:
                    raise RuntimeError("Export index capture binding changed")
                return index
            store = ObjectStore(self.root)
            manifest = json.loads(path.read_bytes())
            objects = {r["body_sha256"] for r in manifest["responses"] if r.get("body_sha256")}
            objects.update(self._git_objects(store, manifest.get("git")))
            files: set[Path] = set()
            # A first export also carries older unexported manifest chain links.
            for prior in path.parent.glob("*.manifest.json"):
                if sha256(prior.read_bytes()) not in self.delivered:
                    files.add(prior)
                    prior_manifest = json.loads(prior.read_bytes())
                    objects.update(r["body_sha256"] for r in prior_manifest["responses"] if r.get("body_sha256"))
                    objects.update(self._git_objects(store, prior_manifest.get("git")))
                proof = Path(str(prior) + ".ots")
                if proof.is_file():
                    files.add(proof)
                initial = self.root / "proofs" / "initial" / (sha256(prior.read_bytes()) + ".ots")
                if initial.is_file():
                    files.add(initial)
                provenance = initial.with_suffix(".stamp.json")
                if provenance.is_file():
                    files.add(provenance)
                rfc_home = self.root / "proofs" / "rfc3161" / sha256(prior.read_bytes())
                if rfc_home.exists():
                    files.update(item for item in rfc_home.rglob("*") if item.is_file())
            files.update(store.location(digest) for digest in objects if digest not in self.delivered_objects)
            for seed in self.legacy_seeds:
                receipt_ref = seed["import_receipt"]
                receipt_path = self.root / receipt_ref["path"]
                receipt = json.loads(receipt_path.read_bytes())
                for reference in [receipt_ref, *receipt.get("derived_artifacts", [])]:
                    relative = Path(reference["path"])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("Unsafe derived migration artifact path")
                    artifact = self.root / relative
                    if (_file_sha256(artifact) != reference["sha256"] or artifact.stat().st_size != reference["bytes"]):
                        raise RuntimeError("Derived migration artifact differs from its verified receipt")
                    if reference["sha256"] not in self.delivered:
                        files.add(artifact)
            registry = _registry_path(self.root, manifest["repository_input_slug"])
            if registry.exists():
                files.add(registry)
            ledger = self.root / "checkpoints" / "api" / str(manifest["repository_id"]) / manifest["capture_id"]
            if ledger.exists():
                files.update(item for item in ledger.rglob("*") if item.is_file())
            members = [{"path": file.relative_to(self.root).as_posix(), "sha256": _file_sha256(file),
                        "bytes": file.stat().st_size} for file in sorted(files)]
            with tempfile.TemporaryDirectory(prefix=".capture-export-", dir=self.directory) as temporary:
                sink = _EncryptedParts(Path(temporary), self.directory,
                                       info["run_id"] + "-" + uuid.uuid4().hex[:8], self.public_key, self.part_bytes)
                try:
                    with lzma.LZMAFile(sink, "w", preset=1) as compressed:
                        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                            for member in members:
                                archive.add(self.root / member["path"], arcname="evidence/" + member["path"], recursive=False)
                finally:
                    sink.close()
            index = {
                "schema_version": 1, "capture_id": manifest["capture_id"], "lane": manifest["lane"],
                "repository_id": manifest["repository_id"], "manifest_sha256": info["manifest_sha256"],
                **_observation_metadata(manifest),
                "recipient_spki_sha256": self.recipient, "encrypted": True,
                "assets": sink.parts, "maximum_plaintext_part_bytes": self.part_bytes,
                "encoding": "one tar/XZ stream, split in order before independent encryption",
                "members": members, "requires_cas_sha256": sorted(objects & self.delivered_objects),
                "legacy_prerequisites": self.legacy_seeds,
                "previous_manifest_sha256": manifest["previous_manifest_sha256"],
                "restore": "Verify each encrypted asset hash, decrypt every part, concatenate plaintext parts in listed order, extract into the same evidence root as all prerequisites, then verify and restore Git offline.",
            }
            if info.get("immutable_initial_proof"):
                from .attestations import publish_ots_attestation
                timing = info.get("timestamp_provenance", {})
                evidence = publish_ots_attestation(
                    self.directory, manifest_sha256=info["manifest_sha256"],
                    proof_path=Path(info["immutable_initial_proof"]),
                    observation_started_at=manifest["started_at"], observation_finished_at=manifest["finished_at"],
                    requested_at=timing.get("requested_at"), received_at=timing.get("received_at"),
                    collected_at=timing.get("receipt_collected_at"))
                index["timestamp_evidence"] = {"opentimestamps": evidence}
                index["public_sidecars"] = [evidence["proof_asset"], evidence["metadata_asset"]]
            else:
                index["timestamp_evidence"] = {"opentimestamps": {
                    "status": "not_collected", "reason": info.get("attestation", "receipt_unavailable")}}
                index["public_sidecars"] = []
            if info.get("rfc3161_evidence"):
                evidence = info["rfc3161_evidence"]
                source = Path(info["rfc3161_source"])
                assets = [evidence["request_asset"], evidence["proof_asset"],
                          *([evidence["details_asset"]] if evidence.get("details_asset") else []),
                          *evidence["trust_assets"], evidence["metadata_asset"]]
                for asset in assets:
                    if Path(asset["name"]).name != asset["name"]:
                        raise ValueError("Unsafe timestamp sidecar asset name")
                    contents = (source / asset["name"]).read_bytes()
                    if sha256(contents) != asset["sha256"] or len(contents) != asset["bytes"]:
                        raise RuntimeError("RFC 3161 sidecar differs from verified receipt metadata")
                    try:
                        write_once(self.directory / asset["name"], contents)
                    except FileExistsError:
                        if (self.directory / asset["name"]).read_bytes() != contents:
                            raise RuntimeError("Conflicting immutable timestamp sidecar")
                index["timestamp_evidence"]["rfc3161"] = evidence
                index["public_sidecars"].extend(assets)
            else:
                index["timestamp_evidence"]["rfc3161"] = {"status": "not_configured"}
            if len(sink.parts) == 1:
                index["asset"] = sink.parts[0]  # Compatibility with initial single-part exports.
            write_once(index_path, canonical_json(index))
            self.delivered.update(member["sha256"] for member in members)
            self.delivered_objects.update(member["sha256"] for member in members
                                          if member["path"].startswith("objects/sha256/"))
            self.known_exports[info["manifest_sha256"]] = index
            return index


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _observation_metadata(manifest: dict[str, Any]) -> dict[str, str]:
    """Copy frozen capture times, never substitute export or publication time."""
    return {"observation_started_at": manifest["started_at"],
            "observation_finished_at": manifest["finished_at"],
            "clock_source": "runner_system_clock"}


def _scope_boundaries(queue: Any, config: Config, repo_id: int | None, scopes: tuple[str, ...]) -> dict[str, str | None]:
    boundaries = {}
    for scope in scopes:
        watermark = queue.scope_watermark(repo_id, scope) if repo_id is not None else None
        boundaries[scope] = utc_iso(parse_github_time(watermark) - timedelta(hours=config.overlap_hours)) if watermark else None
    return boundaries


def enqueue_capture(queue: Any, config: Config, slug: str, lane: str, capture_id: str, *,
                    mode: str = "delta", deep_full: bool = False, input_hash: str | None = None,
                    extra_payload: dict[str, Any] | None = None):
    """Freeze query/config inputs before enqueue, shared by host and state adapters."""
    from .github import BASE_SCOPES
    if slug not in config.repositories:
        raise ValueError("Target is outside the declared cohort")
    payload = {"deep_full": deep_full, "collector_config": _public_config(config)}
    binding = _registry_path(config.root, slug)
    repo_id = json.loads(binding.read_bytes())["repository_id"] if binding.exists() else None
    if repo_id is not None:
        payload["repository_id"] = repo_id
    if lane == "api":
        payload["scope_since"] = _scope_boundaries(queue, config, repo_id, BASE_SCOPES)
        payload["effective_api_mode"] = "full" if mode == "delta" and not any(payload["scope_since"].values()) else mode
    if extra_payload:
        if payload.keys() & extra_payload.keys():
            raise ValueError("Additional job payload may not replace frozen capture inputs")
        payload.update(extra_payload)
    return queue.enqueue(slug, lane=lane, mode=mode, capture_id=capture_id,
                         input_hash=input_hash, payload=payload)


def restore_mirrors(root: Path) -> dict[str, Any]:
    """Rebuild disposable mirrors offline from each repository's latest closure."""
    with exclusive_lock(root):
        return _restore_mirrors(root)


def _restore_mirrors(root: Path) -> dict[str, Any]:
    from .checks import verify_all
    from .gitarchive import verify_portable_archive
    from .gitstore import run_git
    initial = verify_all(root, check_git=False)
    if not initial["ok"]:
        raise RuntimeError("Archived bytes failed verification before offline restore")
    latest = {}
    for path in sorted((root / "runs").glob("*/*.manifest.json")):
        manifest = json.loads(path.read_bytes())
        if manifest.get("git"):
            latest[manifest["repository_id"]] = manifest["git"]
    store = ObjectStore(root)
    for repo_id, git in latest.items():
        expected = f"git/{repo_id}.git"
        if git["mirror_path_relative"] != expected:
            raise ValueError("Unexpected mirror path in manifest")
        mirror = root / expected
        if mirror.exists():
            continue
        mirror.parent.mkdir(parents=True, exist_ok=True)
        if git.get("portable_archive"):
            verify_portable_archive(root, git, mirror)
            # The descriptor is immutable; this disposable pointer avoids a new
            # full baseline if this restored root is used for future captures.
            write_once(mirror / "icsot-archive-head", (sha256(canonical_json(git["portable_archive"])) + "\n").encode())
        elif git.get("portable_full_bundle"):
            object_format = git.get("git_object_hash_algorithm", "sha1")
            if object_format not in ("sha1", "sha256"):
                raise ValueError("Unsupported Git object format")
            run_git(["init", "--bare", f"--object-format={object_format}", str(mirror)])
            bundle = str(store.location(git["portable_full_bundle"]["sha256"]).resolve())
            run_git(["-C", str(mirror), "bundle", "verify", bundle], timeout=1800)
            run_git(["-C", str(mirror), "fetch", "--no-auto-maintenance", "--no-tags", bundle, "+refs/*:refs/*"], timeout=1800)
        else:
            raise RuntimeError("No portable Git closure for missing mirror")
        if git.get("remote"):
            run_git(["-C", str(mirror), "remote", "add", "origin", git["remote"]])
    return verify_all(root)


def finalize_lane(config: Config, job: Any, capture: dict[str, Any], *, stamp: bool = True,
                  exporter: CaptureExporter | None = None):
    from .runtime import Finalization, ScopeWatermark
    store = ObjectStore(config.root)
    verified_objects, verified_bytes = 0, 0
    expected_api_version = capture.get("public_config", _public_config(config))["api_version"]
    for record in capture["responses"]:
        if record.get("api_version", expected_api_version) != expected_api_version:
            raise RuntimeError("Captured response API version differs from frozen configuration")
        digest = record.get("body_sha256")
        if not digest:
            continue
        if not store.verify(digest) or store.location(digest).stat().st_size != record.get("body_bytes"):
            raise RuntimeError("Captured API response CAS digest or size differs")
        verified_objects += 1
        verified_bytes += record["body_bytes"]
    verification = {"raw_response_objects_verified": verified_objects,
                    "raw_response_bytes_verified": verified_bytes}
    candidates = []
    for scope, value in capture.get("watermark_candidates", {}).items():
        outcome = (capture.get("api") or {}).get("scope_statuses", {}).get(scope, {})
        if (capture["lane"] != "api" or outcome.get("status") != "complete_for_query" or
                outcome.get("query_started_at") != value):
            raise ValueError("Watermark candidate is not bound to a complete captured scope")
        candidates.append(ScopeWatermark(capture["repository_id"], scope, value))
    if capture.get("git"):
        from .checks import _git_namespace, _verify_portable_bundle
        from .gitarchive import verify_portable_archive
        from .gitstore import _verify_advertised_objects, run_git
        git = capture["git"]
        if git["mirror_path_relative"] != f"git/{capture['repository_id']}.git":
            raise ValueError("Unexpected mirror path in captured Git result")
        prefix = _git_namespace({"git": git, "capture_id": capture["capture_id"], "run_id": capture["capture_id"]})
        mirror = config.root / git["mirror_path_relative"]
        actual = dict(line.split(" ", 1) for line in run_git(
            ["-C", str(mirror), "for-each-ref", "--format=%(refname) %(objectname)", prefix]).splitlines())
        intended = {item["local_immutable_ref"]: item["object_id"] for item in git["advertised_refs"]}
        if actual != intended:
            raise RuntimeError("Git capture namespace differs from captured inventory")
        _verify_advertised_objects(mirror, git["advertised_refs"])
        run_git(["-C", str(mirror), "fsck", "--full", "--no-reflogs"], timeout=1800)
        with tempfile.TemporaryDirectory(prefix="icsot-finalize-restore-") as temporary:
            if git.get("portable_archive"):
                verify_portable_archive(config.root, git, Path(temporary) / "restored.git")
            elif git.get("portable_full_bundle"):
                bundle = git["portable_full_bundle"]
                if not store.verify(bundle["sha256"]):
                    raise RuntimeError("Portable full bundle CAS digest differs")
                _verify_portable_bundle(store.location(bundle["sha256"]), git)
            else:
                raise RuntimeError("Git capture has no independently restorable archive")
        verification.update(portable_git_restore="passed_into_empty_repository",
                            git_namespace="matches_captured_inventory", git_mirror_fsck="passed",
                            git_refs_verified=len(intended))
    capture = {**capture, "verification": verification}
    info = append_capture_manifest(config, capture)
    info = attest_manifest(config.root, info, stamp=stamp)
    if stamp and info["attestation"] != "pending_bitcoin_completion":
        raise RuntimeError(info["attestation"])
    policy = capture.get("rfc3161_policy")
    if policy:
        from .attestations import publish_rfc3161_attestation
        if (_file_sha256(Path(policy["ca_file"])) != policy["ca_sha256"] or
                (policy["untrusted_file"] and _file_sha256(Path(policy["untrusted_file"])) != policy["untrusted_sha256"])):
            raise RuntimeError("RFC 3161 trust files differ from frozen timestamp policy")
        source = config.root / "proofs" / "rfc3161" / info["manifest_sha256"]
        info["rfc3161_evidence"] = publish_rfc3161_attestation(
            source, manifest_sha256=info["manifest_sha256"], observation_started_at=capture["started_at"],
            observation_finished_at=capture["finished_at"], endpoint=policy["endpoint"],
            ca_file=Path(policy["ca_file"]), untrusted_file=Path(policy["untrusted_file"]) if policy["untrusted_file"] else None)
        info["rfc3161_source"] = str(source)
    if exporter:
        exporter.export(info)
    return Finalization(info["manifest"], info["manifest_sha256"], candidates)


def run_persistent(config: Config, *, once: bool = False, api_workers: int = 1, git_workers: int = 2,
                   api_interval_seconds: int = 21600, git_interval_seconds: int = 21600,
                   poll_interval_seconds: float = 30, deep_full: bool = False,
                   stamp: bool = True, export_directory: Path | None = None,
                   public_key: Path | None = None,
                   verified_prior_indexes: list[dict[str, Any]] | None = None,
                   verified_legacy_seeds: list[dict[str, Any]] | None = None,
                   expected_repository_ids: dict[str, int] | None = None,
                   observation_key: str | None = None, controller_locked: bool = False,
                   working_state_origin: str | None = None,
                   history_policy: dict | None = None,
                   rfc3161_url: str | None = None, rfc3161_ca: Path | None = None,
                   rfc3161_chain: Path | None = None) -> dict[str, Any]:
    """Run durable independent lanes on an existing trusted persistent root.

    Schedule-slot IDs make restart enqueue idempotent. This function never starts
    a baseline workflow, uploads plaintext, or invents a deployment endpoint.
    """
    from .runtime import ControllerLock, PersistentQueue
    if min(api_interval_seconds, git_interval_seconds, poll_interval_seconds) <= 0:
        raise ValueError("Collection and polling intervals must be positive")
    if min(api_workers, git_workers) < 1:
        raise ValueError("At least one worker is required in each lane")
    if (export_directory is None) != (public_key is None):
        raise ValueError("Encrypted export requires both --export-directory and --public-key")
    if expected_repository_ids and any(slug not in config.repositories or type(repo_id) is not int or repo_id <= 0
                                       for slug, repo_id in expected_repository_ids.items()):
        raise ValueError("Expected repository IDs must bind declared cohort members to positive integers")
    if controller_locked and not ControllerLock.owned(config.root):
        raise ValueError("controller_locked requires ownership of this root's ControllerLock")
    timestamp_policy = _rfc3161_policy(rfc3161_url, rfc3161_ca, rfc3161_chain)
    if config.token_env == "GITHUB_TOKEN" and os.getenv("COLLECTOR_READ_TOKEN", "").strip():
        config = replace(config, token_env="COLLECTOR_READ_TOKEN")
    with nullcontext() if controller_locked else ControllerLock(config.root):
        queue = PersistentQueue(config.root)
        exporter = CaptureExporter(config.root, export_directory, public_key,
                                   verified_prior_indexes=verified_prior_indexes,
                                   verified_legacy_seeds=verified_legacy_seeds) if export_directory else None
        return _persistent_loop(config, queue, exporter=exporter, once=once, api_workers=api_workers,
                                git_workers=git_workers, api_interval_seconds=api_interval_seconds,
                                git_interval_seconds=git_interval_seconds,
                                poll_interval_seconds=poll_interval_seconds, deep_full=deep_full, stamp=stamp,
                                expected_repository_ids=expected_repository_ids or {}, observation_key=observation_key,
                                working_state_origin=working_state_origin,
                                history_policy=history_policy,
                                timestamp_policy=timestamp_policy)


def _persistent_loop(config: Config, queue: Any, *, exporter: CaptureExporter | None, once: bool,
                     api_workers: int, git_workers: int, api_interval_seconds: int,
                     git_interval_seconds: int, poll_interval_seconds: float,
                     deep_full: bool, stamp: bool, expected_repository_ids: dict[str, int],
                     observation_key: str | None, timestamp_policy: dict | None,
                     working_state_origin: str | None = None, history_policy: dict | None = None) -> dict[str, Any]:
    frozen = _public_config(config)
    input_hash = sha256(canonical_json({"config": frozen, "deep_full": deep_full,
                                     "expected_repository_ids": expected_repository_ids,
                                     "timestamp_policy": _public_timestamp_policy(timestamp_policy)}))
    while True:
        now = time.time()
        existing_jobs = queue.jobs()
        known = {(job.slug, job.lane, job.capture_id) for job in existing_jobs}
        pending = {(job.slug, job.lane) for job in existing_jobs if job.state != "complete"}
        for lane, interval in (("api", api_interval_seconds), ("git", git_interval_seconds)):
            slot = int(now // interval)
            # Keep one outstanding capture per repository/lane. A delayed job is
            # resumed, rather than accumulating catch-up full-cohort work.
            for slug in config.repositories:
                if (slug, lane) in pending:
                    continue
                identity = {"slug": slug, "lane": lane, "input_hash": input_hash}
                if observation_key:
                    identity["observation_key"] = observation_key
                else:
                    identity["slot"] = slot
                capture_id = "scheduled-" + sha256(canonical_json(identity))[:32]
                if (slug, lane, capture_id) in known:
                    continue
                extra = {"schedule_slot": slot}
                if working_state_origin:
                    extra["working_state_origin"] = working_state_origin
                if history_policy:
                    extra["history_policy"] = history_policy
                if observation_key:
                    extra["observation_key"] = observation_key
                if slug in expected_repository_ids:
                    extra["expected_repository_id"] = expected_repository_ids[slug]
                if timestamp_policy:
                    extra["rfc3161_policy"] = timestamp_policy
                enqueue_capture(queue, config, slug, lane, capture_id, mode="delta", deep_full=deep_full,
                                input_hash=input_hash, extra_payload=extra)
        result = queue.run_pending(lambda job: capture_lane(config, job, queue),
                                   lambda job: capture_lane(config, job, queue),
                                   lambda job, payload: finalize_lane(config, job, payload, stamp=stamp,
                                                                      exporter=exporter),
                                   api_workers=api_workers, git_workers=git_workers, controller_locked=True)
        completed_ids = {item["job_id"] for item in result["results"]}
        attempted_ids = completed_ids | {item["job_id"] for item in result["errors"]}
        current_jobs, older_attempts = [], []
        for job in queue.jobs():
            expected_slot = int(now // (api_interval_seconds if job.lane == "api" else git_interval_seconds))
            current = (job.input_hash == input_hash and (
                job.payload.get("observation_key") == observation_key if observation_key else
                job.payload.get("schedule_slot") == expected_slot))
            if current:
                current_jobs.append(job)
            elif job.id in attempted_ids:
                older_attempts.append(job)

        def outcome(job):
            captured = job.result if isinstance(job.result, dict) else {}
            return {"capture_id": job.capture_id, "slug": job.slug, "lane": job.lane, "state": job.state,
                    "observation_key": job.payload.get("observation_key"),
                    "schedule_slot": job.payload.get("schedule_slot"),
                    "status": "partial" if captured.get("failures") else job.state,
                    "failure_count": len(captured.get("failures", [])),
                    "started_at": captured.get("started_at"), "finished_at": captured.get("finished_at")}

        partial = [{"capture_id": job.capture_id, "slug": job.slug, "lane": job.lane,
                    "failures": job.result["failures"]} for job in current_jobs
                   if job.state == "complete" and isinstance(job.result, dict) and job.result.get("failures")]
        observed_lanes = {(job.slug, job.lane) for job in current_jobs}
        missing = [{"slug": slug, "lane": lane} for slug in config.repositories for lane in ("api", "git")
                   if (slug, lane) not in observed_lanes]
        current_complete = not missing and not partial and all(job.state == "complete" for job in current_jobs)
        current_observation = {"observation_key": observation_key, "status": "complete" if current_complete else "partial",
                               "lane_outcomes": [outcome(job) for job in current_jobs], "missing_lanes": missing}
        report = {"runtime": result, "queue": queue.status(), "root": str(config.root),
                  "partial_captures": partial, "current_observation": current_observation,
                  "resumed_older_captures": [outcome(job) for job in older_attempts]}
        if once:
            return report
        print(json.dumps({"persistent_cycle": report}, sort_keys=True), flush=True)
        time.sleep(poll_interval_seconds)


def collect_one(config: Config, slug: str, mode: str, *, deep_full: bool = False,
                bundle_full: bool = False, stamp: bool = True) -> dict[str, Any]:
    rid, started = run_id(), utc_iso()
    capture_id = rid
    records: list[dict] = []
    store = ObjectStore(config.root)
    api = GitHubAPI(config, store, records, source_repository=slug)
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
    if mode == "delta" and previous_success and _legacy_api_cursor_qualified(previous_success[0]):
        last = parse_github_time(previous_success[0]["started_at"])
        since = (last - timedelta(hours=config.overlap_hours)).isoformat(timespec="seconds").replace("+00:00", "Z")
    effective_mode = "full" if mode == "delta" and since is None else mode
    try:
        # Avoid collecting a repository that becomes private after the identity fetch.
        result = api.collect(slug, effective_mode, since=since,
                             deep_full=deep_full if effective_mode == "full" else True)
        if result["repository_id"] != repo_id:
            raise RuntimeError("Repository identity changed during collection")
        failures.extend(result.get("failures", []))
    except Exception as e:
        failures.append(f"api: {type(e).__name__}: {e}")
    if effective_mode != "events":
        stage_started = time.monotonic()
        stage_fields = {"status": "interrupted"}
        emit("stage_start", stage="git_capture_and_bundle", repository_id=repo_id, capture_id=capture_id)
        try:
            git_result = collect_git(config.root, slug, repo_id, rid, bundle_full=bundle_full)
        except Exception as e:
            failures.append(f"git: {type(e).__name__}: {e}")
            fields = exception_fields(e)
            fields["failure_category"] = failure_category(failures[-1])
            stage_fields.update(status="failed", **fields)
        else:
            stage_fields["status"] = "captured"
        finally:
            emit("stage_end", stage="git_capture_and_bundle",
                 elapsed_seconds=round(time.monotonic() - stage_started, 3), **stage_fields)
    finished = utc_iso()
    config_for_manifest = {
        "repositories": list(config.repositories),
        "api_version": config.api_version,
        "user_agent": config.user_agent,
        "overlap_hours": config.overlap_hours,
        "max_pages": config.max_pages,
        "max_response_bytes": config.max_response_bytes,
        "primary_rate_wait_seconds": config.primary_rate_wait_seconds,
        "primary_rate_reserve": config.primary_rate_reserve,
        "secondary_rate_wait_seconds": config.secondary_rate_wait_seconds,
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
    with manifest_append_lock(config.root, repo_id):
        # Legacy combined capture remains supported beside finalized lane runs.
        # Its Git pins still use the capture ID allocated before network work.
        previous = prior_manifest(config.root, repo_id)
        allocated_at = utc_now()
        rid, clamped = _next_manifest_id(previous, allocated_at)
        manifest.update(run_id=rid, capture_id=capture_id,
                        previous_manifest_sha256=previous[1] if previous else None,
                        manifest_allocated_at=utc_iso(allocated_at),
                        manifest_namespace_clock_clamped=clamped)
        fn = config.root / "runs" / str(repo_id) / (rid + ".manifest.json")
        contents = canonical_json(manifest)
        write_once(fn, contents)
    info: dict[str, Any] = {"repo": slug, "repository_id": repo_id, "run_id": rid,
                            "status": manifest["status"], "manifest_sha256": sha256(contents),
                            "manifest": str(fn), "failures": failures}
    return attest_manifest(config.root, info, stamp=stamp)


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


def run_github_persistent(config: Config, *, slug: str, repository_id: int,
                          destination_repository: str, state_public_key: Path,
                          state_private_key: Path, evidence_public_key: Path,
                          code_sha: str, config_source_sha256: str,
                          observation_key: str | None = None, deep_full: bool = False,
                          stamp: bool = True, transport: Any = None,
                          allow_bootstrap: bool = True, require_planned_state: bool = False,
                          expected_state_pointer_sha256: str | None = None,
                          max_restored_state_plaintext_bytes: int | None = None,
                          history_policy: dict | None = None,
                          logical_root: Path | None = None, rfc3161_url: str | None = None,
                          rfc3161_ca: Path | None = None, rfc3161_chain: Path | None = None,
                          publication_controller: Any = None) -> dict[str, Any]:
    """Selected-repository hosted run: restore, collect, publish evidence, CAS state.

    The operational state recipient differs from the owner-only evidence recipient.
    Recurring callers additionally bind the planned pointer and explicitly allow
    a fresh public bootstrap; selected manual callers retain their existing path.
    """
    from .core import REPO_RE
    from .encryption import _fingerprint, _load_private_key, public_key_fingerprint
    from .github_state import GhCliStateTransport, GitHubStateStore, StateConflictError, StateError
    from .runtime import ControllerLock
    if slug not in config.repositories or type(repository_id) is not int or repository_id <= 0:
        raise ValueError("Select one declared repository and its positive numeric ID")
    if not REPO_RE.fullmatch(destination_repository):
        raise ValueError("Invalid state/evidence destination repository")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", code_sha):
        raise ValueError("Expected a full collector code commit SHA")
    actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if actual_sha != code_sha:
        raise ValueError("Collector checkout does not match the requested code SHA")
    state_recipient, evidence_recipient = public_key_fingerprint(state_public_key), public_key_fingerprint(evidence_public_key)
    if state_recipient == evidence_recipient:
        raise ValueError("Working state and retained evidence require distinct RSA recipients")
    if _fingerprint(_load_private_key(state_private_key, None).public_key()) != state_recipient:
        raise ValueError("Operational private key does not match the working-state recipient")
    root = Path(logical_root or f"/tmp/icsot-persistent-state/{repository_id}").resolve()
    config = replace(config, root=root, repositories=(slug,))
    if history_policy:
        # Large profiles remain excluded by the recurring planner until the Git
        # and API implementations pass their independent validation.
        if history_policy.get("profile") != "full_history":
            raise ValueError("Recent-history capture profile is not enabled yet")
        config = replace(config, history_profile=history_policy["profile"],
                         history_cutoff_utc=history_policy.get("cutoff_utc"))
    transport = transport or GhCliStateTransport(destination_repository)
    backend = GitHubStateStore(transport, repository_id=repository_id, slug=slug,
                               public_key=state_public_key, private_key=state_private_key, logical_root=root)
    with ControllerLock(root), tempfile.TemporaryDirectory(prefix=f"icsot-transfers-{repository_id}-") as temporary:
        selection = backend.read()
        pointer_digest = sha256(canonical_json(selection.pointer)) if selection.pointer else None
        if require_planned_state and pointer_digest != expected_state_pointer_sha256:
            raise StateConflictError("Selected state changed after immutable recurring planning")
        if selection.pointer is None and not allow_bootstrap:
            raise StateError("bootstrap_pending: fresh public bootstrap was not explicitly selected")
        if max_restored_state_plaintext_bytes is not None:
            if type(max_restored_state_plaintext_bytes) is not int or max_restored_state_plaintext_bytes < 1:
                raise ValueError("Positive selected-state restore limit required")
            state_bytes = sum(item["bytes"] for item in (selection.index or {}).get("files", []))
            if state_bytes > max_restored_state_plaintext_bytes:
                raise StateError("Selected state exceeds the per-job restore limit")
        working_state_origin = "resumed_authenticated_state" if selection.pointer else "fresh_public_bootstrap"
        restore_report = backend.restore(selection)
        catalog_path = root / "transfer-catalog.json"
        catalog = json.loads(catalog_path.read_bytes()) if catalog_path.exists() else {
            "schema_version": 1, "repository_id": repository_id, "slug": slug,
            "evidence_recipient_spki_sha256": evidence_recipient, "exports": [],
        }
        if (catalog.get("schema_version") != 1 or catalog.get("repository_id") != repository_id or
                catalog.get("slug") != slug or catalog.get("evidence_recipient_spki_sha256") != evidence_recipient):
            raise RuntimeError("Authenticated evidence catalog does not match selected repository/recipient")
        exports = Path(temporary) / "exports"
        if publication_controller is not None:
            publication_controller.before_capture(root=root)
        collection = run_persistent(config, once=True, deep_full=deep_full, stamp=stamp,
                                    export_directory=exports, public_key=evidence_public_key,
                                    verified_prior_indexes=[entry["index"] for entry in catalog["exports"]],
                                    verified_legacy_seeds=catalog.get("legacy_seed_packages", []),
                                    expected_repository_ids={slug: repository_id},
                                    observation_key=observation_key or run_id(), controller_locked=True,
                                    working_state_origin=working_state_origin,
                                    history_policy=history_policy,
                                    rfc3161_url=rfc3161_url, rfc3161_ca=rfc3161_ca, rfc3161_chain=rfc3161_chain)
        release_tag = f"collector-observations-r{repository_id}-g{uuid.uuid4().hex}"
        if publication_controller is not None:
            publication_controller.capture_completed(collection=collection, release_tag=release_tag, exports=exports)
        def publish_call(operation, *args, **kwargs):
            if publication_controller is None:
                return operation(*args, **kwargs)
            return publication_controller.perform(operation, *args, **kwargs)

        def upload_asset(name, source):
            if publication_controller is None:
                return transport.upload_asset(release_tag, name, source)
            return publication_controller.upload(transport, release_tag, name, source)

        dependencies, uploaded_evidence_bytes = [], 0
        proof_registration = None
        proof_catalog = None
        uploaded_assets: dict[str, dict] = {}
        publication_observations = []
        known = {entry["index"]["manifest_sha256"] for entry in catalog["exports"]}
        for index_path in sorted(exports.glob("*.index.json")):
            index = json.loads(index_path.read_bytes())
            if index["manifest_sha256"] in known:
                continue
            publish_call(transport.ensure_release, release_tag)
            assets = []
            # Immutable encrypted payloads precede their public index, and every
            # dependency is remotely verified by backend.publish before pointer CAS.
            for asset in [*index["assets"], *index.get("public_sidecars", []),
                          {"name": index_path.name, "sha256": _file_sha256(index_path),
                                             "bytes": index_path.stat().st_size}]:
                source = exports / asset["name"]
                ref = {"release_tag": release_tag, "name": asset["name"],
                       "ciphertext_sha256": asset["sha256"], "ciphertext_bytes": asset["bytes"]}
                if asset["name"] in uploaded_assets:
                    if uploaded_assets[asset["name"]] != ref:
                        raise RuntimeError("Conflicting immutable asset name within evidence generation")
                else:
                    upload_asset(asset["name"], source)
                    uploaded_assets[asset["name"]] = ref
                    dependencies.append(ref)
                    uploaded_evidence_bytes += asset["bytes"]
                assets.append(ref)
            catalog["exports"].append({"index": index, "assets": assets})
            known.add(index["manifest_sha256"])
            publication_observations.append({
                "capture_id": index["capture_id"], "lane": index["lane"],
                "manifest_sha256": index["manifest_sha256"],
                "observation_started_at": index["observation_started_at"],
                "observation_finished_at": index["observation_finished_at"],
                "index": _public_asset_ref(uploaded_assets[index_path.name]),
                "timestamp_evidence": index["timestamp_evidence"],
                "public_sidecars": [_public_asset_ref(uploaded_assets[asset["name"]])
                                    for asset in index.get("public_sidecars", [])],
            })
        if publication_observations:
            # Maintenance reads this last-uploaded barrier, never a half-built
            # release. It needs only public indexes and proof sidecars.
            marker = {"schema_version": 1, "kind": "icsot_evidence_metadata_catalog",
                      "repository_id": repository_id, "slug": slug, "generation_release": release_tag,
                      "publication_recorded_at": utc_iso(), "clock_source": "runner_system_clock",
                      "observations": publication_observations,
                      "indexes": [entry["index"] for entry in publication_observations]}
            marker_path = exports / "metadata-catalog.json"
            write_once(marker_path, canonical_json(marker))
            upload_asset(marker_path.name, marker_path)
            marker_ref = {"release_tag": release_tag, "name": marker_path.name,
                          "ciphertext_sha256": _file_sha256(marker_path), "ciphertext_bytes": marker_path.stat().st_size}
            dependencies.append(marker_ref)
            uploaded_evidence_bytes += marker_ref["ciphertext_bytes"]
            catalog.setdefault("publication_markers", []).append(marker_ref)
            verified_marker = Path(temporary) / "verified-public-marker.json"
            publish_call(transport.download_asset, release_tag, marker_path.name, verified_marker)
            if (_file_sha256(verified_marker) != marker_ref["ciphertext_sha256"] or
                    verified_marker.stat().st_size != marker_ref["ciphertext_bytes"]):
                raise RuntimeError("Public metadata catalog differs from the uploaded completion marker")
            # Validate all public proof bindings before publication, independent
            # of the daily proof-attempt queue. The SAME state-pointer CAS adds
            # this immutable marker to a durable public registration outbox.
            from .proof_maintenance import validate_catalog
            proof_catalog = _public_asset_ref(marker_ref)
            proof_registration = publish_call(validate_catalog, transport, proof_catalog)
        raw_catalog = canonical_json(catalog)
        temporary_catalog = root / (".transfer-catalog-" + uuid.uuid4().hex + ".tmp")
        try:
            with temporary_catalog.open("xb") as output:
                os.chmod(temporary_catalog, 0o600)
                output.write(raw_catalog)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_catalog, catalog_path)
            directory_fd = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary_catalog.unlink(missing_ok=True)
        lane_heads = {}
        for path in sorted((root / "runs" / str(repository_id)).glob("*.manifest.json")):
            manifest = json.loads(path.read_bytes())
            lane_heads[manifest.get("lane", "combined")] = {
                "manifest_sha256": _file_sha256(path), "run_id": manifest["run_id"],
                "capture_id": manifest.get("capture_id", manifest["run_id"]),
                **_observation_metadata(manifest),
            }
        source_dir = Path(__file__).parent
        code_hashes = {path.name: _file_sha256(path) for path in source_dir.glob("*.py")}
        code_hashes["collector_commit"] = code_sha
        publication_options = dict(dependencies=dependencies, quiescent=True,
                                      proof_catalog=proof_catalog,
                                      code_hashes=code_hashes,
                                      config_hashes={"source_sha256": config_source_sha256,
                                                     "selected_public_config_sha256": sha256(canonical_json(_public_config(config))),
                                                     "timestamp_policy_sha256": sha256(canonical_json(_public_timestamp_policy(
                                                         _rfc3161_policy(rfc3161_url, rfc3161_ca, rfc3161_chain))))},
                                      lane_heads=lane_heads,
                                      evidence_heads={"catalog_sha256": sha256(raw_catalog),
                                                      "export_manifest_sha256": sorted(known),
                                                      "proof_registration": proof_registration})
        if publication_controller is None:
            publication = backend.publish(selection, **publication_options)
        else:
            publication = publication_controller.publish_state(backend, selection, publication_options)
    publication_summary = {key: value for key, value in publication.items() if key != "pointer"}
    for field in ("snapshot_started_at", "snapshot_sealed_at", "clock_source"):
        publication_summary[field] = publication["pointer"][field]
    return {"repository_id": repository_id, "slug": slug, "collection": collection,
            "working_state_origin": working_state_origin,
            "restore": restore_report, "publication": publication_summary,
            "new_evidence_upload_bytes": uploaded_evidence_bytes,
            "proof_maintenance_registration": proof_registration or {"status": "no_new_catalog"},
            "monthly_cap_enforced": False,
            "deployment_scope": "one selected repository; scheduling is controlled by the caller"}


def _public_asset_ref(ref: dict) -> dict:
    return {"release_tag": ref["release_tag"], "name": ref["name"],
            "sha256": ref["ciphertext_sha256"], "bytes": ref["ciphertext_bytes"]}
