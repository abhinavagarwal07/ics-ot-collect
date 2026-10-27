"""One-time, per-repository migration of authenticated historical evidence.

Migration is not a new observation. Its fresh operational queue has no invented
historical jobs, and only separately proved original API boundaries may seed it.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from .core import Config, ObjectStore, REPO_RE, canonical_json, sha256, utc_iso, write_once
from .github import APIRequestDeferred, GitHubAPI
from .github_state import GhCliStateTransport, GitHubStateStore, StateConflictError, StateDeferredError, StateError
from .recurrence import BoundedStateTransport, DEFAULT_LIMITS, load_cohort, load_resource_limits
from .runtime import ControllerLock, PersistentQueue

MIGRATION_BRANCH = "collector-migrations"
MAX_METADATA_BYTES = 16 * 1024 ** 2
MAX_CAPSULE_BYTES = 128 * 1024
MIGRATION_STATE_CIPHERTEXT_CAP = 8 * 1024 ** 3
DISPOSITIONS = {"queued", "seed_verified", "state_published", "deferred", "source_repair_pending"}
REPAIR_INVENTORY_SHA256 = "3b39f6a290794a0e6ad763a48ccc9a78b782d1da375658142489238678505d21"
# Explicit reviewed repair authorization, not a failure-triggered fallback.
FRESH_REPAIR_IDENTITIES = {"php/php-src": 1903522, "nodejs/node": 27193779,
                           "zephyrproject-rtos/zephyr": 59771425}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")


class MigrationError(RuntimeError):
    pass


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise MigrationError("Expected an immutable SHA-256 identity")
    return value


def asset_ref(ref: dict, *, published: bool = True) -> dict:
    if not isinstance(ref, dict) or not REPO_RE.fullmatch(ref.get("release_repository", "")):
        raise MigrationError("Invalid source asset repository")
    if any(not isinstance(ref.get(key), str) or not _ASSET.fullmatch(ref[key]) for key in ("name", "release_tag")):
        raise MigrationError("Invalid immutable source asset name")
    _digest(ref.get("sha256"))
    if type(ref.get("bytes")) is not int or ref["bytes"] <= 0:
        raise MigrationError("Invalid immutable source asset size")
    for key in ("asset_id", "release_id"):
        if published and (type(ref.get(key)) is not int or ref[key] <= 0):
            raise MigrationError("Hosted migration requires published capsule/source identities")
    return ref


def read_verified_json(path: Path, expected_sha256: str, *, limit: int = MAX_METADATA_BYTES) -> dict:
    _digest(expected_sha256)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit or sha256(raw) != expected_sha256:
        raise MigrationError("Immutable metadata hash or size differs")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise MigrationError("Expected immutable metadata object")
    return value


def migration_id(catalog: dict) -> str:
    """Capsule publication locations can be filled after fixture-only preparation."""
    rows = []
    for row in catalog.get("repositories", []):
        rows.append({"slug": row["slug"], "repository_id": row["repository_id"],
                     "requested_strategy": row.get("requested_strategy", "legacy_seed"),
                     "fresh_repair_repository_id": row.get("fresh_repair_repository_id"),
                     "source_index": row.get("source_index"), "source_manifest": row.get("source_manifest"),
                     "parts": [{"binding": part["binding"],
                                "capsule_sha256": part["capsule"]["sha256"],
                                "capsule_bytes": part["capsule"]["bytes"]} for part in row.get("parts", [])]})
    return sha256(canonical_json({"inventory_sha256": catalog["inventory_sha256"],
        "operational_recipient_spki_sha256": catalog["operational_recipient_spki_sha256"], "repositories": rows}))


def validate_catalog(catalog: dict, repositories: tuple[str, ...], *, allow_unpublished: bool = False) -> str:
    if catalog.get("schema_version") != 1 or catalog.get("kind") != "icsot_legacy_capsule_catalog":
        raise MigrationError("Unknown legacy capsule catalog")
    if not allow_unpublished and catalog.get("publication_status") != "published":
        raise MigrationError("Hosted migration cannot activate an unpublished capsule catalog")
    _digest(catalog.get("inventory_sha256"))
    _digest(catalog.get("operational_recipient_spki_sha256"))
    rows = catalog.get("repositories", [])
    if tuple(row.get("slug") for row in rows) != repositories:
        raise MigrationError("Migration catalog must retain every cohort entry in order")
    identifiers = set()
    for row in rows:
        requested = row.get("requested_strategy", "legacy_seed")
        if requested not in ("legacy_seed", "fresh_repair"):
            raise MigrationError("Unknown requested migration strategy")
        if requested == "fresh_repair" and (catalog["inventory_sha256"] != REPAIR_INVENTORY_SHA256 or
                row.get("fresh_repair_repository_id") != FRESH_REPAIR_IDENTITIES.get(row.get("slug")) or
                row.get("candidate_kind") == "accepted_baseline" or row.get("candidate_git") is not False):
            raise MigrationError("Fresh repair is outside the reviewed closed authorization")
        repo_id = row.get("repository_id")
        if repo_id is None and row.get("candidate_kind") == "repair_required" and not row.get("parts") and row.get("source_manifest") is None:
            continue
        if type(repo_id) is not int or repo_id <= 0 or repo_id in identifiers:
            raise MigrationError("Migration repository identities must be positive and unique")
        identifiers.add(repo_id)
        if row.get("candidate_kind") not in ("accepted_baseline", "partial_baseline", "repair_required"):
            raise MigrationError("Unknown source candidate disposition")
        if row.get("source_index") is not None:
            asset_ref(row["source_index"])
        if row.get("source_manifest") is not None:
            manifest = row["source_manifest"]
            _digest(manifest.get("sha256"))
            if (not isinstance(manifest.get("run_id"), str) or not _ASSET.fullmatch(manifest["run_id"]) or
                    manifest.get("path") != f"runs/{repo_id}/{manifest['run_id']}.manifest.json"):
                raise MigrationError("Unsafe or unbound original manifest path")
        parts = row.get("parts", [])
        if not isinstance(parts, list):
            raise MigrationError("Ordered source parts are required")
        if parts and (not row.get("source_index") or not row.get("source_manifest")):
            raise MigrationError("Source parts require an exact original index and manifest")
        for ordinal, part in enumerate(parts, 1):
            binding = part["binding"]
            if set(binding) != {"repository_id", "repository", "release_repository", "release_tag", "release_id",
                                "asset_name", "asset_id", "part_number", "part_count", "sealed_index_sha256",
                                "ciphertext_sha256", "ciphertext_bytes"}:
                raise MigrationError("Unexpected capsule binding fields")
            if (binding.get("repository_id") != repo_id or binding.get("repository") != row["slug"] or
                    binding.get("part_number") != ordinal or binding.get("part_count") != len(parts) or
                    binding.get("sealed_index_sha256") != row["source_index"]["sha256"]):
                raise MigrationError("Capsule binding differs from frozen selected source")
            capsule = asset_ref(part["capsule"], published=not allow_unpublished)
            if capsule["bytes"] > MAX_CAPSULE_BYTES:
                raise MigrationError("Capsule metadata exceeds its bound")
            asset_ref({"release_repository": binding.get("release_repository"), "release_tag": binding.get("release_tag"),
                "release_id": binding.get("release_id"), "asset_id": binding.get("asset_id"), "name": binding.get("asset_name"),
                "sha256": binding.get("ciphertext_sha256"), "bytes": binding.get("ciphertext_bytes")})
    derived = migration_id(catalog)
    if catalog.get("migration_id", derived) != derived:
        raise MigrationError("Migration identity differs from its frozen source inputs")
    return derived


def build_migration_plan(config: Config, *, sources: dict, catalog: dict, catalog_sha256: str,
                         code_sha: str, pointer_loader: Callable[[int], bytes | None], now: str | None = None,
                         repair_identity_loader: Callable[[str], dict] | None = None,
                         resource_limits: dict | None = None) -> dict:
    if any(catalog.get(key) != sources.get(key) for key in ("config_source_sha256", "csv_sha256")):
        raise MigrationError("Capsule catalog configuration/CSV differs from current reviewed sources")
    identifier = validate_catalog(catalog, config.repositories)
    _digest(catalog_sha256)
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", code_sha):
        raise MigrationError("Expected a full reviewed importer commit")
    rows, selected = [], []
    for source in catalog["repositories"]:
        row = {**source, "expected_state_pointer_sha256": None, "disposition": "queued", "reason_codes": [],
               "strategy": "legacy_seed"}
        try:
            authorized = (source.get("requested_strategy") == "fresh_repair" and
                          catalog["inventory_sha256"] == REPAIR_INVENTORY_SHA256 and
                          source["slug"] in FRESH_REPAIR_IDENTITIES and
                          source["candidate_kind"] != "accepted_baseline" and source.get("candidate_git") is False)
            if authorized:
                expected_id = FRESH_REPAIR_IDENTITIES[source["slug"]]
                if source["repository_id"] not in (None, expected_id):
                    raise MigrationError("Explicit repair identity differs from the selected original source")
                row.update(strategy="fresh_repair", original_repository_id=source["repository_id"], repository_id=expected_id,
                    repair_observation_key="migration-repair-" + identifier,
                    repair_identity={"repository_id": expected_id, "public_verified_at_plan": False,
                                     "provenance": "operator-frozen current identity; revalidated before fresh collection"},
                    repair_resource_limits=(resource_limits or {}).get(source["slug"], dict(DEFAULT_LIMITS)))
                identity = repair_identity_loader(source["slug"]) if repair_identity_loader else None
                if identity is not None and (identity.get("private") is not False or identity.get("id") != expected_id):
                    raise MigrationError("Current public identity differs from the frozen repair authorization")
                row["repair_identity"]["public_verified_at_plan"] = identity is not None
            if row["repository_id"] is None:
                row.update(disposition="source_repair_pending", reason_codes=["original_repository_identity_unproven"])
                rows.append(row)
                continue
            raw = pointer_loader(row["repository_id"])
            if raw is not None:
                pointer = json.loads(raw)
                if (pointer.get("repository_id") != row["repository_id"] or pointer.get("slug") != row["slug"] or
                        canonical_json(pointer) != raw):
                    raise MigrationError("Operational state does not match selected source identity")
                row.update(strategy="already_operational", disposition="state_published", expected_state_pointer_sha256=sha256(raw),
                           reason_codes=["already_operational"])
            elif row["strategy"] == "fresh_repair":
                selected.append({"slug": row["slug"], "repository_id": row["repository_id"]})
            elif (not row.get("parts") or not row.get("source_index") or not row.get("source_manifest") or
                  row["candidate_kind"] == "repair_required"):
                row.update(disposition="source_repair_pending", reason_codes=["source_material_unavailable"])
            else:
                for part in row["parts"]:
                    asset_ref(part["capsule"])
                selected.append({"slug": row["slug"], "repository_id": row["repository_id"]})
        except (StateDeferredError, APIRequestDeferred) as error:
            row.update(disposition="deferred", reason_codes=["state_metadata_rate_deferred"],
                       retry_not_before=error.retry_not_before)
        rows.append(row)
    return {"schema_version": 1, "kind": "icsot_legacy_state_migration_plan", "migration_id": identifier,
            "planned_at": now or utc_iso(), "code_sha": code_sha, **sources,
            "catalog_sha256": catalog_sha256, "inventory_sha256": catalog["inventory_sha256"],
            "operational_recipient_spki_sha256": catalog["operational_recipient_spki_sha256"],
            "repositories": rows, "matrix": {"include": selected}, "max_parallel": 8,
            "cold_bootstrap_throttle": None,
            "strategy_counts": {strategy: sum(row["strategy"] == strategy for row in rows)
                                for strategy in ("legacy_seed", "fresh_repair", "already_operational")},
            "observation_claim": "legacy_seed_retains_original_intervals_fresh_repair_records_new_actual_observations",
            "monthly_cap_enforced": False}


class GitHubMigrationLedger:
    """Small Git CAS records, separate from authoritative working-state pointers."""

    def __init__(self, transport: GhCliStateTransport):
        self.transport = transport

    def _head(self):
        ref = self.transport._api(f"repos/{self.transport.repository}/git/ref/heads/{MIGRATION_BRANCH}", missing_ok=True)
        return ref["object"]["sha"] if ref else None

    def _read(self, head: str | None, path: str):
        if head is None:
            return None
        obj = self.transport._api(f"repos/{self.transport.repository}/contents/{path}?ref={quote(head, safe='')}", missing_ok=True)
        if obj is None:
            return None
        if obj.get("encoding") != "base64" or obj.get("type") != "file":
            raise MigrationError("Invalid migration disposition record")
        raw = base64.b64decode(obj["content"])
        if len(raw) > MAX_METADATA_BYTES:
            raise MigrationError("Migration disposition metadata exceeds bound")
        value = json.loads(raw)
        if canonical_json(value) != raw:
            raise MigrationError("Noncanonical migration disposition metadata")
        return value

    @staticmethod
    def _path(identifier: str, repo_id: int):
        return f"migrations/{_digest(identifier)}/repos/{repo_id}.json"

    def read(self, identifier: str, repo_id: int):
        return self._read(self._head(), self._path(identifier, repo_id))

    def read_many(self, identifier: str, repo_ids):
        """Read dispositions at one frozen branch head, without per-row ref reads."""
        paths = {repo_id: self._path(identifier, repo_id) for repo_id in repo_ids}
        head = self._head()
        return {repo_id: self._read(head, path) for repo_id, path in paths.items()}

    def active_plan(self):
        return self._read(self._head(), "active-plan.json")

    def _write(self, path: str, value: dict):
        raw = canonical_json(value)
        if len(raw) > MAX_METADATA_BYTES:
            raise MigrationError("Migration disposition metadata exceeds bound")
        api, repo = self.transport._api, self.transport.repository
        for _ in range(8):
            head = self._head()
            current = self._read(head, path)
            if current == value:
                return value
            if (path != "active-plan.json" and current and current.get("disposition") == "state_published"
                    and not (value.get("disposition") == "source_repair_pending" and
                             value.get("reason_code") == "authoritative_state_missing")):
                return current  # A late retry may not downgrade a published state.
            base = api(f"repos/{repo}/git/commits/{head}")["tree"]["sha"] if head else None
            tree = api(f"repos/{repo}/git/trees", method="POST", payload={**({"base_tree": base} if base else {}),
                "tree": [{"path": path, "mode": "100644", "type": "blob", "content": raw.decode()}]})
            commit = api(f"repos/{repo}/git/commits", method="POST", payload={
                "message": "Record legacy state migration disposition", "tree": tree["sha"],
                "parents": [head] if head else []})
            try:
                if head:
                    api(f"repos/{repo}/git/refs/heads/{MIGRATION_BRANCH}", method="PATCH",
                        payload={"sha": commit["sha"], "force": False})
                else:
                    api(f"repos/{repo}/git/refs", method="POST",
                        payload={"ref": f"refs/heads/{MIGRATION_BRANCH}", "sha": commit["sha"]})
                return value
            except StateDeferredError:
                raise
            except StateError:
                # Rebase only metadata for other repositories; no force push.
                if self._read(self._head(), path) == value:
                    return value
        raise StateConflictError("Migration disposition changed concurrently")

    def write(self, record: dict):
        if record.get("disposition") not in DISPOSITIONS:
            raise MigrationError("Unknown durable migration disposition")
        return self._write(self._path(record["migration_id"], record["repository_id"]), record)

    def activate(self, plan_ref: dict):
        asset_ref(plan_ref["plan"])
        return self._write("active-plan.json", plan_ref)


def _blocked_reason_codes(record: dict) -> list[str]:
    reasons = []
    if record.get("external_recovery_required"):
        reasons.append("external_recovery_required")
    if record.get("prepared_generation"):
        reasons.append("prepared_generation_requires_reviewed_recovery")
    if record.get("fresh_capture_attempt_started") or record.get("fresh_capture_publication_started"):
        reasons.append("fresh_capture_requires_reviewed_recovery")
    if record.get("disposition") == "source_repair_pending":
        reasons.append("source_repair_pending")
    code = record.get("reason_code")
    if reasons and isinstance(code, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", code):
        reasons.append(code)
    return list(dict.fromkeys(reasons))


def backlog_plan(plan: dict, *, pointer_loader, ledger) -> dict:
    """Keep every target visible while admitting only work with a safe next step."""
    selected, rows, missing = [], [], []
    for row in plan["repositories"]:
        outcome = {"slug": row["slug"], "repository_id": row["repository_id"]}
        rows.append(outcome)
        raw = pointer_loader(row["repository_id"]) if row["repository_id"] is not None else None
        if raw is not None:
            pointer = json.loads(raw)
            if (pointer.get("repository_id") != row["repository_id"] or pointer.get("slug") != row["slug"] or
                    canonical_json(pointer) != raw):
                raise MigrationError("Operational pointer identity differs from migration plan")
            outcome.update(status="already_operational", reason_codes=["authoritative_state_present"])
            continue
        if row["repository_id"] is None or row["disposition"] == "source_repair_pending":
            reasons = [reason for reason in row.get("reason_codes", [])
                       if isinstance(reason, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", reason)]
            outcome.update(status="blocked", reason_codes=list(dict.fromkeys(["source_repair_pending", *reasons])))
            continue
        missing.append((row, outcome))
    identifiers = [row["repository_id"] for row, _ in missing]
    records = (ledger.read_many(plan["migration_id"], identifiers) if identifiers and hasattr(ledger, "read_many") else
               {repo_id: ledger.read(plan["migration_id"], repo_id) for repo_id in identifiers})
    for row, outcome in missing:
        record = records[row["repository_id"]]
        reasons = _blocked_reason_codes(record or {})
        if record and record.get("disposition") == "state_published":
            reasons.append("authoritative_state_missing")
        if reasons:
            outcome.update(status="blocked", reason_codes=list(dict.fromkeys(reasons)))
            continue
        if row.get("strategy") == "fresh_repair" or row.get("parts") and row.get("source_manifest"):
            selected.append({"slug": row["slug"], "repository_id": row["repository_id"]})
            outcome.update(status="eligible", reason_codes=[])
        else:
            outcome.update(status="blocked", reason_codes=["source_material_unavailable"])
    counts = dict(Counter(row["status"] for row in rows))
    blocked = counts.get("blocked", 0)
    complete = counts.get("already_operational", 0) == len(rows)
    return {"schema_version": 1, "kind": "icsot_legacy_migration_backlog", "migration_id": plan["migration_id"],
            "status": "complete" if complete else "blocked" if not selected else "work_available",
            "migration_complete": complete, "cohort_count": len(rows), "counts": counts,
            "blocked_count": blocked, "blocked_reason_counts": dict(Counter(
                reason for row in rows if row["status"] == "blocked" for reason in row["reason_codes"])),
            "repositories": rows, "matrix": {"include": selected}}


def backlog_matrix(plan: dict, *, pointer_loader, ledger) -> dict:
    return backlog_plan(plan, pointer_loader=pointer_loader, ledger=ledger)["matrix"]


def _record(plan: dict, entry: dict, prior: dict | None, disposition: str, **details):
    now = utc_iso()
    return {"schema_version": 1, "kind": "icsot_legacy_state_migration_disposition",
            "migration_id": plan["migration_id"], "repository_id": entry["repository_id"], "slug": entry["slug"],
            "source_index_sha256": (entry.get("source_index") or {}).get("sha256"),
            "source_manifest_sha256": (entry.get("source_manifest") or {}).get("sha256"),
            "migration_state_ciphertext_cap_bytes": MIGRATION_STATE_CIPHERTEXT_CAP,
            "original_source_status": (entry.get("source_manifest") or {}).get("status"),
            "created_at": (prior or {}).get("created_at", now), "updated_at": now,
            **{key: value for key, value in (prior or {}).items() if key.startswith(("prepared_", "fresh_")) or key in (
                "migration_receipt_sha256", "seed_sha256")},
            "disposition": disposition, "strategy": entry.get("strategy", "legacy_seed"),
            "observation_claim": ("new_observation_for_explicit_source_repair" if entry.get("strategy") == "fresh_repair"
                                  else "not_a_new_observation"), **details}


def commit_legacy_watermarks(queue: PersistentQueue, *, receipt_path: Path, root: Path,
                             manifest_path: Path, source_index_path: Path, entry: dict,
                             api_version: str, validator: Callable) -> dict:
    """A separate import proof path; ordinary manifest cursor validation is unchanged."""
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    if (receipt.get("kind") != "icsot_legacy_state_import_receipt" or
            receipt.get("repository_id") != entry["repository_id"] or receipt.get("slug") != entry["slug"] or
            receipt.get("source_manifest_sha256") != entry["source_manifest"]["sha256"] or
            receipt.get("source_index", {}).get("sha256") != entry["source_index"]["sha256"]):
        raise MigrationError("Import receipt does not bind the selected original source")
    proof = validator(root, manifest_path, expected_manifest_sha256=entry["source_manifest"]["sha256"],
        source_index_path=source_index_path, expected_index_sha256=entry["source_index"]["sha256"],
        repository_id=entry["repository_id"], slug=entry["slug"], api_version=api_version, history_policy=None)
    if proof != receipt.get("api_seed_proof"):
        raise MigrationError("Legacy API seed proof differs from immutable import receipt")
    if sha256(manifest_path.read_bytes()) != entry["source_manifest"]["sha256"]:
        raise MigrationError("Original source manifest changed before cursor import")
    with queue._transaction() as db:
        if db.execute("SELECT count(*) FROM jobs").fetchone()[0]:
            raise MigrationError("Historical seed requires a fresh operational queue")
        db.execute("CREATE TABLE IF NOT EXISTS legacy_seed_imports(receipt_sha256 TEXT PRIMARY KEY,path TEXT NOT NULL,source_manifest_sha256 TEXT NOT NULL)")
        digest = sha256(receipt_raw)
        db.execute("INSERT OR IGNORE INTO legacy_seed_imports VALUES(?,?,?)",
                   (digest, str(receipt_path), entry["source_manifest"]["sha256"]))
        db.execute("INSERT OR IGNORE INTO manifests(digest,path) VALUES(?,?)",
                   (entry["source_manifest"]["sha256"], str(manifest_path)))
        for scope, value in proof["eligible_watermarks"].items():
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise MigrationError("Original query boundary must be explicitly zoned")
            db.execute("""INSERT INTO watermarks VALUES(?,?,?,?,?) ON CONFLICT(repository_id,scope) DO UPDATE SET
                value=excluded.value,observed_at=excluded.observed_at,manifest_digest=excluded.manifest_digest
                WHERE excluded.observed_at>watermarks.observed_at""",
                (entry["repository_id"], scope, value, parsed.timestamp(), entry["source_manifest"]["sha256"]))
    return proof


class _DeadlinePipe:
    """Bound every pipe read by inactivity and one absolute transfer deadline."""

    def __init__(self, pipe, *, deadline: float, inactivity: float, clock=time.monotonic):
        self.pipe, self.deadline, self.inactivity, self.clock = pipe, deadline, inactivity, clock
        self.last_progress = clock()
        self.selector = selectors.DefaultSelector()
        self.selector.register(pipe.fileno(), selectors.EVENT_READ)
        os.set_blocking(pipe.fileno(), False)

    def read(self, maximum: int):
        if type(maximum) is not int or maximum < 0:
            raise MigrationError("Source reads must declare a finite size")
        if maximum == 0:
            return b""
        while True:
            remaining = min(self.deadline - self.clock(), self.last_progress + self.inactivity - self.clock())
            if remaining <= 0:
                raise StateDeferredError("Bounded immutable-source read timed out", reason="source_read_deadline",
                                         retry_not_before=time.time() + 300)
            if not self.selector.select(min(remaining, 1)):
                continue
            try:
                block = os.read(self.pipe.fileno(), min(maximum, 1024 * 1024))
            except BlockingIOError:
                continue
            if block:
                self.last_progress = self.clock()
            return block

    def close(self):
        self.selector.close()


class GitHubSourceReader:
    """Stream public immutable source assets with the shared read credential."""

    def __init__(self, *, inactivity_seconds: float = 90, max_elapsed_seconds: float = 19800,
                 popen: Callable = subprocess.Popen, clock: Callable[[], float] = time.monotonic):
        if inactivity_seconds <= 0 or not 0 < max_elapsed_seconds <= 19800:
            raise MigrationError("Finite positive source read deadlines required")
        self.clock, self.popen, self.inactivity = clock, popen, inactivity_seconds
        self.deadline = clock() + max_elapsed_seconds

    @contextlib.contextmanager
    def open(self, ref: dict):
        asset_ref(ref)
        environment = os.environ.copy()
        token = environment.get("COLLECTOR_READ_TOKEN") or environment.get("GITHUB_TOKEN")
        if token:
            environment["GH_TOKEN"] = token
        child = self.popen(["gh", "api", f"repos/{ref['release_repository']}/releases/assets/{ref['asset_id']}",
            "-H", "Accept: application/octet-stream"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=environment, start_new_session=True)
        stream = _DeadlinePipe(child.stdout, deadline=self.deadline, inactivity=self.inactivity, clock=self.clock)
        failed = False
        try:
            try:
                yield stream
            except StateDeferredError:
                failed = True
                raise
            except Exception as error:
                failed = True
                try:
                    code = child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    code = None
                if code is not None and code != 0:
                    raise StateDeferredError("Immutable source transfer failed", reason="source_transfer_deferred",
                                             retry_not_before=time.time() + 300) from error
                raise
            try:
                code = child.wait(timeout=max(0.01, min(60, self.deadline - self.clock())))
            except subprocess.TimeoutExpired as error:
                raise StateDeferredError("Immutable source transfer timed out", reason="source_transfer_deferred",
                                         retry_not_before=time.time() + 300) from error
            if code != 0:
                raise StateDeferredError("Immutable source transfer failed", reason="source_transfer_deferred",
                                         retry_not_before=time.time() + 300)
        finally:
            stream.close()
            child.stdout.close()
            if failed or child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()

    def metadata(self, ref: dict, *, limit: int = MAX_METADATA_BYTES) -> bytes:
        asset_ref(ref)
        if ref["bytes"] > limit:
            raise MigrationError("Source metadata exceeds its declared bound")
        with self.open(ref) as stream:
            blocks, total = [], 0
            while total <= ref["bytes"]:
                block = stream.read(min(1024 * 1024, ref["bytes"] + 1 - total))
                if not block:
                    break
                blocks.append(block)
                total += len(block)
            raw = b"".join(blocks)
            if len(raw) != ref["bytes"] or sha256(raw) != ref["sha256"]:
                raise MigrationError("Immutable source metadata hash/size differs")
        return raw


@dataclass
class MigrationHelpers:
    archive_import: Callable
    git_import: Callable
    api_validate: Callable
    seed_seal: Callable
    seed_validate: Callable
    capsule_inspect: Callable | None = None

    @classmethod
    def production(cls):
        from .legacy_archive import import_legacy_archive
        from .legacy_git import import_legacy_git
        from .legacy_api import validate_legacy_api_seed
        from .legacy_seed_catalog import seal_legacy_seed, validate_legacy_seed
        from .legacy_capsules import inspect_capsule
        return cls(import_legacy_archive, import_legacy_git, validate_legacy_api_seed,
                   seal_legacy_seed, validate_legacy_seed, inspect_capsule)


def _source_context(entry: dict):
    index, manifest = entry["source_index"], entry["source_manifest"]
    return {"repository_id": entry["repository_id"], "repository": entry["slug"],
            "source_release_repository": index["release_repository"], "source_release_tag": index["release_tag"],
            "source_release_id": index["release_id"], "source_index_asset": index["name"],
            "source_index_asset_id": index["asset_id"], "source_index_sha256": index["sha256"],
            "source_index_bytes": index["bytes"], "manifest_sha256": manifest["sha256"],
            "collector_code_sha": entry["source_collector_code_sha"]}


def _create_identical(path: Path, raw: bytes):
    if path.exists():
        if path.read_bytes() != raw:
            raise MigrationError("Create-only migration artifact differs from prior attempt")
    else:
        write_once(path, raw)


def _restore_limits(entry: dict, index: dict):
    from .legacy_archive import RestoreLimits
    # These finite hosted guards are independently configurable in the sealed
    # catalog. They do not substitute the owner's local inspection ledger.
    configured = entry.get("restore_limits", {})
    observations = (index.get("verification") or {}).get("raw_observations", 0)
    observations = observations if type(observations) is int and observations >= 0 else 0
    refs = (index.get("verification") or {}).get("git_refs_verified", 0)
    refs = refs if type(refs) is int and refs >= 0 else 0
    default_members = (min(200_000, max(512, observations * 4 + refs * 4 + 256))
                       if index.get("archive", {}).get("git_mirror_included") is False else 200_000)
    return RestoreLimits(**{"max_restore_bytes": 8 * 1024 ** 3, "max_tar_stream_bytes": 10 * 1024 ** 3,
        "max_member_bytes": 8 * 1024 ** 3, "max_members": default_members, "max_path_depth": 16,
        **configured})


def admit_restore_limits(entry: dict, index: dict, directory: Path):
    """Admit an explicit decoded-byte ceiling from live disk, never provider KB."""
    from dataclasses import replace
    from .legacy_archive import normalize_legacy_parts
    requested = _restore_limits(entry, index)
    aliases = {part["transport_alias"]["plaintext"]["name"]: part["transport_alias"]
               for part in entry["parts"] if part.get("transport_alias")}
    parts = normalize_legacy_parts(index, aliases or None)
    staged = max(part["plaintext"]["bytes"] for part in parts)
    free = shutil.disk_usage(directory).free
    overhead = (requested.max_members + 8) * (requested.filesystem_allocation_unit_bytes + 4096)
    margin = entry.get("restore_safety_margin_bytes", 256 * 1024 ** 2)
    if type(margin) is not int or margin < 0:
        raise MigrationError("Nonnegative hosted restore margin required")
    cap = min(requested.max_restore_bytes, free - staged - overhead - margin)
    if cap <= 0:
        raise StateDeferredError("Insufficient live disk for admitted source restoration", reason="restore_disk_headroom")
    admitted = replace(requested, max_restore_bytes=cap, max_member_bytes=min(requested.max_member_bytes, cap))
    return admitted, {"requested_limits": asdict(requested), "admitted_limits": asdict(admitted),
        "host_free_bytes_before_transfer": free, "declared_max_staged_part_bytes": staged,
        "allocation_overhead_bytes": overhead, "safety_margin_bytes": margin,
        "qualification": "decoded source size is unknown; exceeding this host-admitted ceiling pauses the repository"}


def _allocated_root(root: Path):
    seen, total, entries = set(), 0, 0
    for path in [root, *root.rglob("*")]:
        info = path.lstat()
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            continue
        seen.add(identity)
        entries += 1
        total += info.st_blocks * 512 if hasattr(info, "st_blocks") else info.st_size
    return {"working_root_allocated_bytes": total, "working_root_entries": entries,
            "host_free_bytes_before_prepare": shutil.disk_usage(root).free}


def _resource_pause_reason(error: Exception):
    if isinstance(error, OSError) and error.errno in (errno.ENOSPC, errno.EDQUOT):
        return "host_disk_exhausted"
    # Existing audited providers use ArchiveError/StateError for these guards.
    # Match only their fixed host-limit diagnostics, never general validation
    # failures, and retain the original source status in the disposition.
    if type(error).__name__ == "ArchiveError" and str(error) in {
        "Compressed part exceeds the staging byte cap", "Tar header count exceeds the bound",
        "Archive path depth exceeds the bound", "Archive member count exceeds the bound",
        "Tar member size exceeds the bound", "Restored payload exceeds the restore byte cap",
        "Host filesystem allocation unit exceeds the reserved bound",
        "Physical filesystem allocation exceeds the reserved import cap",
    }:
        return "archive_host_resource_limit"
    if isinstance(error, StateError) and str(error).startswith("Insufficient disk for "):
        return "state_prepare_disk_headroom"
    return None


def safe_error_location(error: Exception):
    """Return reviewed code coordinates, never exception text or local paths."""
    modules = {"legacy_bootstrap.py", "legacy_archive.py", "archive_reader.py", "legacy_capsules.py",
               "legacy_git.py", "legacy_api.py", "legacy_seed_catalog.py", "github_state.py", "pipeline.py", "runtime.py"}
    location, frame = None, error.__traceback__
    while frame is not None:
        code = frame.tb_frame.f_code
        path = Path(code.co_filename)
        if (path.parent.name == "icsot_observer" and path.name in modules and
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", code.co_name)):
            location = {"module": path.name, "function": code.co_name, "line": frame.tb_lineno}
        frame = frame.tb_next
    return location


def _retry_destination(operation, *, deadline, clock, sleeper):
    """Retry one idempotent metadata boundary within the existing job window."""
    for attempt in range(6):
        if clock() >= deadline:
            raise StateDeferredError("Destination metadata runtime exhausted", reason="destination_metadata_runtime_budget")
        try:
            return operation()
        except StateDeferredError as error:
            retry = error.retry_not_before
            if retry is None or attempt == 5:
                raise
            retry = max(retry, clock() + 1)
            if retry >= deadline:
                raise
            while clock() < retry:
                sleeper(min(60, retry - clock(), deadline - clock()))


def _shared_branch_exhaustion(error):
    # These exact source-authored exhaustion guards exclude identity, slug,
    # recipient and changed-own-pointer conflicts from automatic recovery.
    return isinstance(error, StateConflictError) and str(error) in {
        "Migration disposition changed concurrently", "Too many concurrent state branch updates"}


def _own_pointer_unchanged(backend, expected):
    authoritative = getattr(backend, "_authoritative_pointer", None)
    if callable(authoritative):
        _, current = authoritative()  # Also validates the create-only slug binding.
        return current == (canonical_json(expected) if expected is not None else None)
    return backend.read().pointer == expected


def _publication_preflight(transport, entry: dict, index: dict | None = None):
    """Conservative metadata admission before large source transfer, then exact prepare admission."""
    if not hasattr(transport, "publication_budget"):
        return {}
    # Includes metadata, registry/receipt, bounded state index/CAS operations and
    # group/large-part overhead. Shared rate headers still govern every request.
    source_bytes = sum(part["binding"]["ciphertext_bytes"] for part in entry.get("parts", []))
    bound = max(64, 48 + math.ceil(source_bytes / (64 * 1024 ** 2)) * 4)
    return transport.publication_budget(bound)


def _seed_fields(entry: dict, imported, receipt_path: Path, root: Path, receipt_digest: str,
                 authenticated_owner: str | None = None):
    from .legacy_archive import normalize_legacy_parts
    index_raw = (root / "imports" / "legacy-source" / "index.json").read_bytes()
    index = json.loads(index_raw)
    overrides = {part["transport_alias"]["plaintext"]["name"]: part["transport_alias"]
                 for part in entry["parts"] if part.get("transport_alias")}
    normalized = normalize_legacy_parts(index, overrides)
    parts = []
    for ordinal, (item, source) in enumerate(zip(normalized, entry["parts"]), 1):
        binding = source["binding"]
        parts.append({"ordinal": ordinal, "plaintext": item["plaintext"],
            "ciphertext": {"release_repository": binding["release_repository"], "release_tag": binding["release_tag"],
                "release_id": binding["release_id"], "asset_id": binding["asset_id"], "name": binding["asset_name"],
                "sha256": binding["ciphertext_sha256"], "bytes": binding["ciphertext_bytes"]},
            "capsule": source["capsule"]})
    original_path = "evidence/" + entry["source_manifest"]["path"]
    members = [item for item in imported.files if item["path"].startswith("evidence/objects/sha256/") or item["path"] == original_path]
    manifest = imported.manifest
    return {"schema_version": 1, "kind": "legacy_baseline_package_v1", "repository_id": entry["repository_id"],
        "slug": entry["slug"], "source_index": entry["source_index"],
        "source_manifest": {"path": entry["source_manifest"]["path"], "sha256": entry["source_manifest"]["sha256"],
            "bytes": (root / entry["source_manifest"]["path"]).stat().st_size, "run_id": manifest["run_id"],
            "started_at": manifest["started_at"], "finished_at": manifest["finished_at"]},
        "owner_recipient_spki_sha256": authenticated_owner or entry.get("owner_recipient_spki_sha256") or
            (index.get("results_encryption") or {}).get("recipient_spki_sha256") or
            index["archive"].get("recipient_spki_sha256") or next(
                (part["transport_alias"].get("recipient") for part in entry["parts"] if part.get("transport_alias")), None),
        "transport": {"kind": "migrated_encrypted_baseline" if overrides else "native_encrypted_baseline",
                      "migration_index": entry.get("migration_index"), "parts": parts},
        "members": members,
        "import_receipt": {"path": receipt_path.relative_to(root).as_posix(), "sha256": receipt_digest,
                           "bytes": receipt_path.stat().st_size}}


def public_repair_collection(collection):
    """Expose fixed statuses and identities, never capture exception text."""
    statuses = {"queued", "leased", "captured", "finalizing", "complete", "partial", "pending", "deferred"}
    def count(value):
        return value if type(value) is int and value >= 0 else 0
    def outcomes(values):
        result = []
        for item in values:
            row = {key: item.get(key) for key in ("lane", "state", "status") if item.get(key) in statuses | {"api", "git"}}
            for key in ("capture_id", "run_id"):
                if isinstance(item.get(key), str) and _ASSET.fullmatch(item[key]):
                    row[key] = item[key]
            if isinstance(item.get("manifest_sha256"), str) and _HASH.fullmatch(item["manifest_sha256"]):
                row["manifest_sha256"] = item["manifest_sha256"]
            for key in ("started_at", "finished_at"):
                if isinstance(item.get(key), str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", item[key]):
                    row[key] = item[key]
            row["failure_count"] = count(item.get("failure_count"))
            result.append(row)
        return result
    runtime = collection.get("runtime", {})
    current = collection.get("current_observation", {})
    states = collection.get("queue", {}).get("states", {})
    return {"runtime": {"completed": count(runtime.get("completed")), "deferred": count(runtime.get("deferred")),
                        "error_count": len(runtime.get("errors", [])), "results": outcomes(runtime.get("results", []))},
            "queue": {"states": {state: count(number) for state, number in states.items() if state in statuses}},
            "partial_capture_count": len(collection.get("partial_captures", [])),
            "current_observation": {"status": current.get("status") if current.get("status") in statuses else "partial",
                                    "lane_outcomes": outcomes(current.get("lane_outcomes", []))},
            "resumed_older_captures": outcomes(collection.get("resumed_older_captures", []))}


class RepairPublicationController:
    """Keep one fresh observation and its immutable ciphertexts through quota retries.

    The durable capture marker deliberately blocks automatic recapture after a
    runner is lost. It is not a promise that local prepared bytes survive loss.
    """

    def __init__(self, *, record, entry, plan, directory, deadline, clock=time.time, sleeper=time.sleep):
        self.record, self.entry, self.plan = record, entry, plan
        self.directory, self.deadline, self.clock, self.sleeper = directory, deadline, clock, sleeper

    def before_capture(self, *, root):
        self.record("queued", fresh_capture_attempt_started=True,
                    fresh_observation_key=self.entry["repair_observation_key"],
                    fresh_original_source={key: self.entry.get(key) for key in (
                        "source_index", "source_manifest", "source_capture_status", "original_repository_id")})

    def capture_completed(self, *, collection, release_tag, exports):
        indexes = [{"name": path.name, "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
                   for path in sorted(exports.glob("*.index.json"))]
        self.record("queued", fresh_capture_publication_started=True, fresh_collection=public_repair_collection(collection),
                    fresh_evidence_release_tag=release_tag, fresh_export_indexes=indexes)

    def perform(self, operation, *args, **kwargs):
        for attempt in range(6):
            if self.clock() >= self.deadline:
                raise StateDeferredError("Fresh repair runtime exhausted", reason="fresh_repair_runtime_budget")
            try:
                return operation(*args, **kwargs)
            except StateDeferredError as error:
                # The required capture/prepared marker already exists. A quota
                # refusal of optional retry telemetry must not discard retained
                # ciphertext or prevent waiting for that same quota to reset.
                self.record("deferred", _best_effort=True, reason_code=error.reason,
                            retry_not_before=error.retry_not_before)
                retry = error.retry_not_before
                if retry is None or retry >= self.deadline or attempt == 5:
                    raise
                retry = max(self.clock() + 1, retry)
                while self.clock() < retry:
                    self.sleeper(min(60, retry - self.clock(), self.deadline - self.clock()))

    def upload(self, transport, tag, name, source):
        expected_sha, expected_size, attempted = _file_digest(source), source.stat().st_size, False

        def upload_identical():
            nonlocal attempted
            if attempted:
                found = transport.find_asset(tag, name, refresh=True)
                if found is not None:
                    if found.get("name") != name or found.get("size") != expected_size:
                        raise MigrationError("Uncertain evidence upload has conflicting immutable identity")
                    digest = found.get("digest")
                    if digest is None:
                        verification = self.directory.parent / ("verify-" + sha256((tag + name).encode()) + ".tmp")
                        try:
                            transport.download_asset(tag, name, verification)
                            if verification.stat().st_size != expected_size or _file_digest(verification) != expected_sha:
                                raise MigrationError("Uncertain evidence upload differs from retained ciphertext")
                        finally:
                            verification.unlink(missing_ok=True)
                    elif digest != "sha256:" + expected_sha:
                        raise MigrationError("Uncertain evidence upload has conflicting ciphertext hash")
                    return
            attempted = True
            return transport.upload_asset(tag, name, source)
        return self.perform(upload_identical)

    def publish_state(self, backend, selection, options):
        receipt = {"schema_version": 1, "kind": "icsot_explicit_fresh_repair_receipt",
                   "migration_id": self.plan["migration_id"], "repository_id": self.entry["repository_id"],
                   "slug": self.entry["slug"], "observation_key": self.entry["repair_observation_key"],
                   "original_source_index": self.entry.get("source_index"),
                   "original_source_manifest": self.entry.get("source_manifest"),
                   "original_source_status": self.entry.get("source_capture_status"),
                   "lane_heads": options["lane_heads"], "evidence_heads": options["evidence_heads"],
                   "observation_claim": "new_actual_observation_not_a_legacy_import"}
        receipt_sha = sha256(canonical_json(receipt))
        generation = sha256(canonical_json({"migration_id": self.plan["migration_id"],
            "repository_id": self.entry["repository_id"], "repair_receipt_sha256": receipt_sha}))[:32]
        def prepare_identical():
            if self.directory.exists() and any(self.directory.iterdir()):
                manifest = self.directory / "prepared.json"
                if not manifest.is_file():
                    raise StateDeferredError("Incomplete local preparation requires recovery; refusing re-encryption",
                                             reason="prepared_state_incomplete_local_recovery_required")
                return backend.load_prepared(self.directory, _file_digest(manifest))
            return backend.prepare(selection, directory=self.directory, generation=generation,
                                   source_import_sha256=receipt_sha, **options)
        prepared = self.perform(prepare_identical)
        if prepared.generation != generation or prepared.source_import_sha256 != receipt_sha:
            raise MigrationError("Prepared fresh repair belongs to different frozen source inputs")
        self.perform(self.record, "seed_verified", fresh_repair_receipt=receipt, prepared_generation=prepared.generation,
                    prepared_manifest_sha256=prepared.manifest_sha256, prepared_local_only=True,
                    prepared_release_tags=list(prepared.release_tags), prepared_pointer=prepared.pointer,
                    prepared_assets=list(prepared.assets))
        def publish_identical():
            try:
                return backend.publish_prepared(prepared, source_import_sha256=receipt_sha, quiescent=True)
            except StateConflictError as error:
                if _shared_branch_exhaustion(error) and _own_pointer_unchanged(backend, selection.pointer):
                    raise StateDeferredError("Shared working-state branch contention",
                        reason="working_state_branch_contention", retry_not_before=self.clock() + 2) from error
                raise
        return self.perform(publish_identical)


def _file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _repair_identity(config, slug, scratch):
    records = []
    public_config = replace(config, root=scratch / "identity", token_env="COLLECTOR_READ_TOKEN",
        primary_rate_reserve=40, primary_rate_wait_seconds=0, secondary_rate_wait_seconds=0,
        max_response_bytes=min(config.max_response_bytes, 1024 * 1024))
    return GitHubAPI(public_config, ObjectStore(public_config.root), records, defer_on_rate=True).get_json(
        "/repos/" + slug, "explicit fresh-repair current public identity")


def _initialize_fresh_repair(plan, entry, *, config, code_sha, destination_repository, working_root,
                             scratch, transport, backend, record, prior, deadline, clock, sleeper,
                             operational_private_key_path, state_public_key_path, evidence_public_key_path,
                             repair_runner=None, repair_identity_loader=None, rfc3161_options=None):
    if (plan["inventory_sha256"] != REPAIR_INVENTORY_SHA256 or
            entry["repository_id"] != FRESH_REPAIR_IDENTITIES.get(entry["slug"]) or
            entry.get("requested_strategy") != "fresh_repair" or entry.get("candidate_git") is not False or
            entry.get("candidate_kind") == "accepted_baseline"):
        raise MigrationError("Fresh repair is outside the frozen three-source authorization")
    try:
        with ControllerLock(working_root):
            if getattr(backend, "recipient", plan["operational_recipient_spki_sha256"]) != plan["operational_recipient_spki_sha256"]:
                raise StateDeferredError("Operational recipient differs from frozen migration plan",
                                         reason="operational_recipient_mismatch")
            selection = _retry_destination(backend.read, deadline=deadline, clock=clock, sleeper=sleeper)
            if selection.pointer is not None:
                return record("state_published", reason_code="already_operational", new_observations=0,
                              new_evidence_upload_bytes=0, state_uploaded_ciphertext_bytes=0)
            if prior and prior.get("external_recovery_required"):
                return prior
            if prior and (prior.get("fresh_capture_attempt_started") or prior.get("fresh_capture_publication_started") or
                          prior.get("prepared_generation")):
                return record("deferred", reason_code="fresh_publication_recovery_required", external_recovery_required=True)
        if config.history_profile != "full_history":
            raise StateDeferredError("Fresh repair history profile remains gated", reason="history_profile_requires_independent_baseline")
        record("queued", origin="explicit_fresh_repair_of_unusable_legacy_source")
        preflight = _retry_destination(lambda: _publication_preflight(transport, entry),
                                      deadline=deadline, clock=clock, sleeper=sleeper)
        identity = (repair_identity_loader(entry["slug"]) if repair_identity_loader else
                    _repair_identity(config, entry["slug"], scratch))
        if identity.get("private") is not False or identity.get("id") != entry["repository_id"]:
            raise MigrationError("Current public repository identity differs from explicit repair authorization")
        controller = RepairPublicationController(record=record, entry=entry, plan=plan, directory=scratch / "prepared",
            deadline=deadline, clock=clock, sleeper=sleeper)
        if repair_runner is None:
            from .pipeline import run_github_persistent
            repair_runner = run_github_persistent
        limits = entry["repair_resource_limits"]
        # The ordinary wrapper owns the controller lock through collection and
        # every bounded publication retry; never rerun this wrapper on deferral.
        result = repair_runner(replace(config, token_env="COLLECTOR_READ_TOKEN", primary_rate_reserve=40,
            primary_rate_wait_seconds=0, secondary_rate_wait_seconds=0), slug=entry["slug"],
            repository_id=entry["repository_id"], destination_repository=destination_repository,
            state_public_key=state_public_key_path, state_private_key=operational_private_key_path,
            evidence_public_key=evidence_public_key_path, code_sha=code_sha,
            config_source_sha256=plan["config_source_sha256"], observation_key=entry["repair_observation_key"],
            allow_bootstrap=True, require_planned_state=True, expected_state_pointer_sha256=None,
            max_restored_state_plaintext_bytes=limits["max_restored_state_plaintext_bytes"],
            logical_root=working_root, transport=transport, publication_controller=controller,
            **(rfc3161_options or {}))
        publication = result["publication"]
        return record("state_published", reason_code="explicit_fresh_repair_state_published",
            origin="explicit_fresh_repair_of_unusable_legacy_source",
            new_observations=len(result["collection"].get("runtime", {}).get("results", [])),
            new_evidence_upload_bytes=result["new_evidence_upload_bytes"],
            state_uploaded_ciphertext_bytes=publication["state_uploaded_ciphertext_bytes"],
            state_referenced_ciphertext_bytes=publication["state_referenced_ciphertext_bytes"],
            fresh_collection=public_repair_collection(result["collection"]), state_generation=publication["generation"],
            quota_preflight=preflight, imported_api_scopes=[],
            measurement_description="New main evidence bytes are newly uploaded stored observation assets, including initial full capture and metadata; they are not a count of novel upstream changes. Operational state is additional storage.")
    except (StateDeferredError, APIRequestDeferred) as error:
        return record("deferred", _best_effort=True, reason_code=error.reason, retry_not_before=error.retry_not_before)
    except Exception as error:
        resource = _resource_pause_reason(error)
        return record("deferred" if resource else "source_repair_pending", _best_effort=True,
                      reason_code=resource or type(error).__name__, resource_review_required=bool(resource),
                      error_location=safe_error_location(error))


def import_legacy_seed(plan: dict, entry: dict, *, code_sha: str, config: Config,
                       working_root: Path, scratch: Path, reader,
                       operational_private_key_path: Path, evidence_public_key_path: Path,
                       imported_at: str, helpers: MigrationHelpers | None = None) -> dict | None:
    """Authenticate and derive the exact historical seed under the caller's lock.

    The caller supplies an empty working root and original import time. This
    helper neither changes migration holds nor publishes operational pointers.
    """
    slug = entry["slug"]
    index_raw = reader.metadata(entry["source_index"])
    index = json.loads(index_raw)
    migration_raw = reader.metadata(entry["migration_index"]) if entry.get("migration_index") else None
    from .legacy_archive import LegacyPartRef
    parts = [LegacyPartRef(part["binding"], reader.metadata(part["capsule"], limit=MAX_CAPSULE_BYTES))
             for part in entry["parts"]]
    helpers = helpers or MigrationHelpers.production()
    authenticated_owner = None
    if helpers.capsule_inspect:
        contexts = [helpers.capsule_inspect(part.capsule)["context"] for part in parts]
        owners = {context["owner_key_fingerprint_sha256"] for context in contexts}
        if len(owners) != 1 or any(context["operational_key_fingerprint_sha256"] !=
                plan["operational_recipient_spki_sha256"] for context in contexts):
            raise MigrationError("Ordered capsule recipients differ from the sealed selected policy")
        authenticated_owner = owners.pop()
        if entry.get("owner_recipient_spki_sha256", authenticated_owner) != authenticated_owner:
            raise MigrationError("Declared legacy owner recipient differs from authenticated capsule context")
    aliases = {part["transport_alias"]["plaintext"]["name"]: part["transport_alias"]
               for part in entry["parts"] if part.get("transport_alias")}
    (scratch / "archive").mkdir()
    (scratch / "parts").mkdir()
    limits, restore_admission = admit_restore_limits(entry, index, scratch)
    def open_part(part):
        value = part.binding
        return reader.open({"release_repository": value["release_repository"], "release_tag": value["release_tag"],
            "release_id": value["release_id"], "asset_id": value["asset_id"], "name": value["asset_name"],
            "sha256": value["ciphertext_sha256"], "bytes": value["ciphertext_bytes"]})
    imported = helpers.archive_import(index_raw, parts, expected_index_sha256=entry["source_index"]["sha256"],
        expected_repository=slug, expected_repository_id=entry["repository_id"],
        expected_manifest_sha256=entry["source_manifest"]["sha256"], output_root=scratch / "archive",
        staging_root=scratch / "parts", open_part=open_part, operational_private_key_path=operational_private_key_path,
        limits=limits, transport_overrides=aliases or None)
    if any(path.name != ".collector.lock" for path in working_root.iterdir()):
        raise MigrationError("Migration requires an empty destination working root")
    for child in imported.evidence_root.iterdir():
        if child.name in ("runtime.sqlite3", "runtime.sqlite3-wal", "runtime.sqlite3-shm", "checkpoints", "transfer-catalog.json"):
            raise MigrationError("Source archive contains operational state that cannot be adopted as historical jobs")
        shutil.move(str(child), working_root / child.name)
    # The importer has authenticated the complete archive closure.
    # Provisional reports/staging are not another retained working copy.
    shutil.rmtree(scratch / "archive")
    source_home = working_root / "imports" / "legacy-source"
    _create_identical(source_home / "index.json", index_raw)
    if migration_raw is not None:
        _create_identical(source_home / "migration-index.json", migration_raw)
    manifest_path = working_root / entry["source_manifest"]["path"]
    manifest_raw = manifest_path.read_bytes()
    git_proof = None
    git_error = None
    try:
        git_proof = helpers.git_import(working_root, manifest_raw, index_raw,
            expected_manifest_sha256=entry["source_manifest"]["sha256"],
            expected_index_sha256=entry["source_index"]["sha256"], source_context=_source_context(entry),
            importer_code_sha=code_sha, imported_at_utc=imported_at)
    except (ValueError, RuntimeError) as error:
        git_error = type(error).__name__
        # Only this provisional copy is removed; historical archives are
        # untouched, and a future live Git capture starts in an empty mirror.
        if (working_root / "git").exists():
            shutil.rmtree(working_root / "git")
    api_proof = helpers.api_validate(working_root, manifest_path,
        expected_manifest_sha256=entry["source_manifest"]["sha256"], source_index_path=source_home / "index.json",
        expected_index_sha256=entry["source_index"]["sha256"], repository_id=entry["repository_id"],
        slug=slug, api_version=config.api_version, history_policy=None)
    if not git_proof and not api_proof["eligible_watermarks"]:
        return None
    original = json.loads(manifest_raw)
    receipt = {"schema_version": 1, "kind": "icsot_legacy_state_import_receipt",
        "migration_id": plan["migration_id"], "repository_id": entry["repository_id"], "slug": slug,
        "imported_at": imported_at, "importer_code_sha": code_sha,
        "source_index": entry["source_index"], "source_manifest_sha256": sha256(manifest_raw),
        "source_observation_interval": {"started_at": original["started_at"], "finished_at": original["finished_at"]},
        "source_status": original["status"], "source_mode": original["mode"],
        "authenticated_parts": imported.parts, "archive_members_sha256": sha256(canonical_json(imported.files)),
        "cas_inventory_sha256": sha256(canonical_json(imported.cas)),
        "git_seed_proof": git_proof, "git_repair_reason": git_error, "api_seed_proof": api_proof,
        "observation_claim": "verified_migration_of_original_evidence_not_a_new_observation"}
    receipt["derived_artifacts"] = []
    receipt["derived_artifacts"].append({"path": (source_home / "index.json").relative_to(working_root).as_posix(),
        "sha256": sha256(index_raw), "bytes": len(index_raw)})
    if git_proof:
        descriptor = ObjectStore(working_root).location(_digest(git_proof["descriptor_sha256"]))
        if _file_digest(descriptor) != git_proof["descriptor_sha256"]:
            raise MigrationError("Derived Git archive descriptor differs from verified import")
        receipt["derived_artifacts"].append({"path": descriptor.relative_to(working_root).as_posix(),
            "sha256": git_proof["descriptor_sha256"], "bytes": descriptor.stat().st_size})
        for key in ("receipt", "index"):
            relative = git_proof.get(key + "_path_relative")
            if relative:
                artifact = working_root / relative
                receipt["derived_artifacts"].append({"path": relative, "sha256": sha256(artifact.read_bytes()),
                                                    "bytes": artifact.stat().st_size})
    if migration_raw is not None:
        receipt["derived_artifacts"].append({"path": (source_home / "migration-index.json").relative_to(working_root).as_posix(),
            "sha256": sha256(migration_raw), "bytes": len(migration_raw)})
    receipt_path = working_root / "imports" / "legacy-bootstrap" / (plan["migration_id"] + ".json")
    _create_identical(receipt_path, canonical_json(receipt))
    receipt_digest = sha256(receipt_path.read_bytes())
    queue = PersistentQueue(working_root)
    commit_legacy_watermarks(queue, receipt_path=receipt_path, root=working_root,
        manifest_path=manifest_path, source_index_path=source_home / "index.json", entry=entry,
        api_version=config.api_version, validator=helpers.api_validate)
    seed = helpers.seed_seal(_seed_fields(entry, imported, receipt_path, working_root, receipt_digest, authenticated_owner))
    helpers.seed_validate(seed, repository_id=entry["repository_id"], slug=slug, root=working_root,
                          source_index=index_raw, migration_index=migration_raw)
    from .encryption import public_key_fingerprint
    if public_key_fingerprint(evidence_public_key_path) != seed["owner_recipient_spki_sha256"]:
        raise StateDeferredError("Legacy evidence recipient differs from configured evidence recipient", reason="evidence_recipient_mismatch")
    catalog = {"schema_version": 1, "repository_id": entry["repository_id"], "slug": slug,
        "evidence_recipient_spki_sha256": seed["owner_recipient_spki_sha256"], "exports": [],
        "legacy_seed_packages": [seed]}
    _create_identical(working_root / "transfer-catalog.json", canonical_json(catalog))
    return {"receipt_digest": receipt_digest, "seed": seed, "manifest_raw": manifest_raw,
            "original": original, "git_proof": git_proof, "api_proof": api_proof,
            "imported": imported, "restore_admission": restore_admission}


def initialize_repository(plan: dict, slug: str, *, code_sha: str, config: Config,
                          destination_repository: str, operational_private_key_path: Path,
                          state_public_key_path: Path, evidence_public_key_path: Path,
                          working_root: Path, scratch: Path, transport=None, reader=None, ledger=None,
                          helpers: MigrationHelpers | None = None, backend=None,
                          repair_runner=None, repair_identity_loader=None, rfc3161_options=None,
                          max_runtime_seconds: float = 5.5 * 3600,
                          clock: Callable[[], float] = time.time, sleeper: Callable[[float], None] = time.sleep) -> dict:
    """Authenticate one old package, derive a seed, and publish one prepared generation.

    All network calls and cryptography occur outside SQLite transactions. A
    lost prepared publication is explicitly held for recovery on later runners.
    """
    if plan.get("kind") != "icsot_legacy_state_migration_plan" or plan.get("code_sha") != code_sha:
        raise MigrationError("Reviewed importer commit differs from the immutable migration plan")
    if not 0 < max_runtime_seconds <= 19800:
        raise MigrationError("Migration must fit the bounded six-hour hosted job")
    entries = [row for row in plan["repositories"] if row["slug"] == slug]
    if len(entries) != 1 or slug not in config.repositories:
        raise MigrationError("Select exactly one declared migration source")
    entry = entries[0]
    if type(entry.get("repository_id")) is not int:
        return {"slug": slug, "disposition": "source_repair_pending", "reason_code": "original_identity_unproven"}
    limits = entry.get("repair_resource_limits", entry.get("resource_limits", DEFAULT_LIMITS))
    transport = transport or BoundedStateTransport(destination_repository,
        evidence_bytes=limits["max_new_evidence_ciphertext_bytes"], state_bytes=MIGRATION_STATE_CIPHERTEXT_CAP)
    reader = reader or GitHubSourceReader()
    ledger = ledger or GitHubMigrationLedger(transport)
    prior, expected_pointer, pointer_known = None, None, entry.get("strategy") == "fresh_repair"
    deadline = clock() + max_runtime_seconds
    scratch.mkdir(parents=True, exist_ok=True)
    backend = backend or GitHubStateStore(transport, repository_id=entry["repository_id"], slug=slug,
        public_key=state_public_key_path, private_key=operational_private_key_path, logical_root=working_root)

    def record(disposition, *, _best_effort=False, **details):
        nonlocal prior
        pending = _record(plan, entry, prior, disposition, **details)
        def write_record():
            try:
                return ledger.write(pending)
            except StateConflictError as error:
                expected = ((prior or {}).get("prepared_pointer")
                            if disposition == "state_published" and details.get("state_generation")
                            else expected_pointer)
                if (pointer_known and _shared_branch_exhaustion(error) and
                        _own_pointer_unchanged(backend, expected)):
                    raise StateDeferredError("Shared migration metadata branch contention",
                        reason="migration_ledger_contention", retry_not_before=clock() + 2) from error
                raise
        try:
            prior = (write_record() if _best_effort else
                     _retry_destination(write_record, deadline=deadline, clock=clock, sleeper=sleeper))
        except StateDeferredError:
            if not _best_effort:
                raise
            prior = {**pending, "disposition_recording": "not_confirmed_due_to_shared_destination_quota"}
        return prior

    try:
        prior = _retry_destination(lambda: ledger.read(plan["migration_id"], entry["repository_id"]),
                                   deadline=deadline, clock=clock, sleeper=sleeper)
    except StateDeferredError as error:
        # Unknown prior may contain a prepared-generation hold. Never replace
        # it with a newly constructed record that could discard those refs.
        return _record(plan, entry, None, "deferred", reason_code=error.reason,
                       retry_not_before=error.retry_not_before,
                       disposition_recording="not_attempted_prior_unknown",
                       new_observations=0, new_evidence_upload_bytes=0)
    if entry.get("strategy") == "fresh_repair":
        return _initialize_fresh_repair(plan, entry, config=config, code_sha=code_sha,
            destination_repository=destination_repository, working_root=working_root, scratch=scratch,
            transport=transport, backend=backend, record=record, prior=prior, deadline=deadline,
            clock=clock, sleeper=sleeper, operational_private_key_path=operational_private_key_path,
            state_public_key_path=state_public_key_path, evidence_public_key_path=evidence_public_key_path,
            repair_runner=repair_runner, repair_identity_loader=repair_identity_loader, rfc3161_options=rfc3161_options)
    with ControllerLock(working_root):
        try:
            if getattr(backend, "recipient", plan["operational_recipient_spki_sha256"]) != plan["operational_recipient_spki_sha256"]:
                raise StateDeferredError("Operational recipient differs from sealed capsule catalog", reason="operational_recipient_mismatch")
            if config.history_profile != "full_history":
                raise StateDeferredError("Legacy full state cannot silently seed another history profile", reason="history_profile_requires_independent_baseline")
            selection = _retry_destination(backend.read, deadline=deadline, clock=clock, sleeper=sleeper)
            expected_pointer, pointer_known = selection.pointer, True
            if selection.pointer is not None:
                return record("state_published", reason_code="already_operational",
                              origin="already_operational_state_no_migration",
                              state_pointer_sha256=sha256(canonical_json(selection.pointer)),
                              new_observations=0, new_evidence_upload_bytes=0, state_uploaded_ciphertext_bytes=0,
                              storage_qualification="existing operational state wins; this migration uploads no working copy")
            if prior and prior["disposition"] == "state_published":
                return record("source_repair_pending", reason_code="authoritative_state_missing")
            if prior and prior.get("external_recovery_required"):
                return prior
            if prior and prior.get("prepared_generation"):
                return record("deferred", reason_code="prepared_state_unavailable_after_runner_loss",
                              external_recovery_required=True)
            if entry["disposition"] == "source_repair_pending" or not entry.get("parts"):
                return record("source_repair_pending", reason_code="source_material_unavailable")
            record("queued")
            preflight = _retry_destination(lambda: _publication_preflight(transport, entry),
                                          deadline=deadline, clock=clock, sleeper=sleeper)
            imported_seed = import_legacy_seed(plan, entry, code_sha=code_sha, config=config,
                working_root=working_root, scratch=scratch, reader=reader, helpers=helpers,
                operational_private_key_path=operational_private_key_path,
                evidence_public_key_path=evidence_public_key_path, imported_at=prior["created_at"])
            if imported_seed is None:
                return record("source_repair_pending", reason_code="no_independently_proven_seed_capability")
            receipt_digest, seed, manifest_raw, original, git_proof, api_proof, imported, restore_admission = (
                imported_seed[key] for key in ("receipt_digest", "seed", "manifest_raw", "original", "git_proof",
                                               "api_proof", "imported", "restore_admission"))
            generation = sha256(canonical_json({"migration_id": plan["migration_id"], "repository_id": entry["repository_id"],
                                               "receipt_sha256": receipt_digest}))[:32]
            record("seed_verified", migration_receipt_sha256=receipt_digest, seed_sha256=seed["seed_sha256"])
            if clock() >= deadline:
                raise StateDeferredError("Runtime budget exhausted before state preparation",
                                         reason="runtime_budget_before_prepare", retry_not_before=clock() + 60)
            prepare_disk = _allocated_root(working_root)
            prepared = backend.prepare(selection, directory=scratch / "prepared", generation=generation,
                source_import_sha256=receipt_digest, dependencies=[],
                code_hashes={"importer_commit": code_sha}, config_hashes={"source_sha256": plan["config_source_sha256"]},
                lane_heads={}, evidence_heads={"legacy_seed_sha256": seed["seed_sha256"],
                    "migration_receipt_sha256": receipt_digest, "original_manifest_sha256": sha256(manifest_raw)}, quiescent=True)
            record("seed_verified", prepared_generation=prepared.generation,
                   prepared_manifest_sha256=prepared.manifest_sha256, prepared_local_only=True,
                   prepared_release_tags=list(prepared.release_tags), prepared_pointer=prepared.pointer,
                   prepared_assets=list(prepared.assets))
            def publish_identical():
                try:
                    return backend.publish_prepared(prepared, source_import_sha256=receipt_digest, quiescent=True)
                except StateConflictError as error:
                    if _shared_branch_exhaustion(error) and _own_pointer_unchanged(backend, selection.pointer):
                        raise StateDeferredError("Shared working-state branch contention",
                            reason="working_state_branch_contention", retry_not_before=clock() + 2) from error
                    raise
            for attempt in range(6):
                try:
                    publication = publish_identical()
                    return record("state_published", reason_code="verified_legacy_seed_published",
                        origin="verified_legacy_baseline_migration",
                        state_generation=publication["generation"], state_pointer_commit=publication["pointer_commit"],
                        original_source_status=original["status"], imported_git=bool(git_proof),
                        imported_api_scopes=sorted(api_proof["eligible_watermarks"]),
                        api_fresh_repair_scopes=sorted(scope for scope, decision in api_proof["scope_decisions"].items()
                                                      if decision.get("status") == "fresh_repair"),
                        git_fresh_repair_required=not bool(git_proof), fresh_queue_jobs=0,
                        new_observations=0, new_evidence_upload_bytes=0,
                        state_uploaded_ciphertext_bytes=publication["state_uploaded_ciphertext_bytes"],
                        state_referenced_ciphertext_bytes=publication["state_referenced_ciphertext_bytes"],
                        existing_main_ciphertext_bytes=sum(part["binding"]["ciphertext_bytes"] for part in entry["parts"]),
                        existing_main_accounting_scope="selected original archive only; other retained attempts/metadata excluded",
                        combined_referenced_main_and_state_bytes=publication["state_referenced_ciphertext_bytes"] +
                            sum(part["binding"]["ciphertext_bytes"] for part in entry["parts"]),
                        source_capsule_metadata_bytes=sum(part["capsule"]["bytes"] for part in entry["parts"]),
                        storage_qualification="operational state is an additional encrypted working copy; original main evidence unchanged",
                        measurement_description="New main evidence upload bytes count stored evidence-generation assets, not novel upstream changes. This migration uploads only a separately accounted encrypted operational working copy.",
                        quota_preflight=preflight, restore_resource_admission=restore_admission,
                        verified_archive_allocation=getattr(imported, "allocation_guard", None),
                        disk_before_prepare=prepare_disk)
                except StateDeferredError as error:
                    record("deferred", _best_effort=True, reason_code=error.reason, retry_not_before=error.retry_not_before,
                           prepared_local_only=True, publication_attempts=attempt + 1)
                    retry = error.retry_not_before
                    if retry is None or retry >= deadline or clock() >= deadline or attempt == 5:
                        return prior
                    retry = max(retry, clock() + 1)
                    while clock() < retry:
                        sleeper(min(60, retry - clock(), max(0, deadline - clock())))
        except StateDeferredError as error:
            pending = _record(plan, entry, prior, "deferred", reason_code=error.reason,
                              retry_not_before=error.retry_not_before)
            try:
                return ledger.write(pending)
            except StateDeferredError:
                return {**pending, "disposition_recording": "not_confirmed_due_to_shared_destination_quota"}
        except Exception as error:
            resource = _resource_pause_reason(error)
            if resource:
                return record("deferred", reason_code=resource, resource_review_required=True,
                              restore_resource_admission=locals().get("restore_admission"),
                              error_location=safe_error_location(error))
            return record("source_repair_pending", reason_code=type(error).__name__,
                          external_recovery_required=bool((prior or {}).get("prepared_generation")),
                          error_location=safe_error_location(error))


def operational_pointer_loader(transport):
    head = transport.branch_head()
    if head is None:
        return lambda _: None
    tree = transport._api(f"repos/{transport.repository}/git/trees/{head}")
    if tree.get("truncated") is not False:
        raise MigrationError("Operational pointer tree is incomplete")
    subtrees = [item for item in tree["tree"] if item.get("path") == "repos"]
    if not subtrees:
        return lambda _: None
    if len(subtrees) != 1 or subtrees[0].get("type") != "tree":
        raise MigrationError("Operational pointer subtree is invalid")
    pointers = transport._api(f"repos/{transport.repository}/git/trees/{subtrees[0]['sha']}")
    if pointers.get("truncated") is not False:
        raise MigrationError("Operational pointer subtree is incomplete")
    present = {item["path"] for item in pointers["tree"] if item.get("type") == "blob"}
    return lambda repo_id: transport.read_pointer(head, repo_id) if f"{repo_id}.json" in present else None


def _publish_plan(transport, ledger, plan: dict, path: Path) -> dict:
    suffix = f"{os.environ.get('GITHUB_RUN_ID', 'local')}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", suffix):
        raise MigrationError("Invalid plan publication identity")
    tag = "collector-state-migration-plan-" + suffix
    transport.ensure_release(tag)
    transport.upload_asset(tag, path.name, path)
    release = transport._release(tag)
    asset = transport._assets[tag][path.name]
    ref = {"release_repository": transport.repository, "release_tag": tag, "release_id": release["id"],
           "asset_id": asset["id"], "name": path.name, "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
    asset_ref(ref)
    ledger.activate({"schema_version": 1, "kind": "icsot_active_legacy_migration",
        "migration_id": plan["migration_id"], "code_sha": plan["code_sha"], "plan": ref,
        "covered_slugs": [row["slug"] for row in plan["repositories"]], "activated_at": utc_iso()})
    return ref


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run"):
        child = commands.add_parser(name)
        child.add_argument("--config", required=True, type=Path)
        child.add_argument("--csv", required=True, type=Path)
        child.add_argument("--destination-repository", required=True)
        child.add_argument("--output", required=True, type=Path)
        if name == "plan":
            child.add_argument("--code-sha", required=True)
            child.add_argument("--catalog-ref", help="Published immutable capsule-catalog AssetRef JSON; absent resumes active plan")
            child.add_argument("--activate", action="store_true", help="Publish/activate the reviewed full migration plan")
            child.add_argument("--github-output", type=Path)
        else:
            child.add_argument("--plan", required=True, type=Path)
            child.add_argument("--plan-sha256", required=True)
            child.add_argument("--slug", required=True)
            child.add_argument("--code-sha", required=True)
            child.add_argument("--state-private-key", required=True, type=Path)
            child.add_argument("--state-public-key", required=True, type=Path)
            child.add_argument("--evidence-public-key", required=True, type=Path)
            child.add_argument("--max-runtime-seconds", type=int, default=19800)
            child.add_argument("--rfc3161-url")
            child.add_argument("--rfc3161-ca", type=Path)
            child.add_argument("--rfc3161-chain", type=Path)
    args = parser.parse_args(argv)
    config, sources = load_cohort(args.config, args.csv)
    limits = DEFAULT_LIMITS
    if args.command == "run":
        if not 0 < args.max_runtime_seconds <= 19800:
            raise MigrationError("Migration runtime must fit the bounded six-hour hosted job")
        if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != args.code_sha:
            raise MigrationError("Importer checkout differs from reviewed code commit")
        plan = read_verified_json(args.plan, args.plan_sha256)
        if any(plan.get(key) != value for key, value in sources.items()):
            raise MigrationError("Migration source configuration/CSV changed after planning")
        entries = [row for row in plan["repositories"] if row["slug"] == args.slug]
        if len(entries) != 1:
            raise MigrationError("Select exactly one declared migration source")
        entry = entries[0]
        limits = entry.get("repair_resource_limits", entry.get("resource_limits", DEFAULT_LIMITS))
    transport = BoundedStateTransport(args.destination_repository,
        evidence_bytes=limits["max_new_evidence_ciphertext_bytes"], state_bytes=MIGRATION_STATE_CIPHERTEXT_CAP)
    reader, ledger = GitHubSourceReader(), GitHubMigrationLedger(transport)
    if args.command == "plan":
        if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != args.code_sha:
            raise MigrationError("Planner checkout differs from reviewed code commit")
        active = ledger.active_plan()
        if args.catalog_ref:
            ref = asset_ref(json.loads(args.catalog_ref))
            raw = reader.metadata(ref)
            catalog = json.loads(raw)
            with tempfile.TemporaryDirectory(prefix="icsot-repair-plan-identity-") as identity_temporary:
                plan = build_migration_plan(config, sources=sources, catalog=catalog, catalog_sha256=sha256(raw),
                    code_sha=args.code_sha, pointer_loader=operational_pointer_loader(transport),
                    resource_limits=load_resource_limits(args.config, config.repositories),
                    repair_identity_loader=lambda slug: _repair_identity(config, slug, Path(identity_temporary)))
            _create_identical(args.output, canonical_json(plan))
            if not args.activate:
                raise MigrationError("Hosted migration requires explicit reviewed plan activation")
            plan_ref = _publish_plan(transport, ledger, plan, args.output)
        elif active:
            plan_ref = asset_ref(active["plan"])
            raw = reader.metadata(plan_ref)
            plan = json.loads(raw)
            if any(plan.get(key) != value for key, value in sources.items()):
                raise MigrationError("Active migration configuration/CSV differs from this checkout")
            _create_identical(args.output, raw)
        else:
            plan, plan_ref = None, None
        summary = (backlog_plan(plan, pointer_loader=operational_pointer_loader(transport), ledger=ledger) if plan else
                   {"status": "no_active_migration", "migration_complete": False, "cohort_count": len(config.repositories),
                    "counts": {}, "blocked_count": 0, "blocked_reason_counts": {}, "repositories": [], "matrix": {"include": []}})
        matrix = summary["matrix"]
        _create_identical(args.output.with_suffix(".backlog.json"), canonical_json(summary))
        outputs = {"matrix": json.dumps(matrix, separators=(",", ":")), "planned_count": len(matrix["include"]),
                   "plan_sha256": plan_ref["sha256"] if plan_ref else "", "plan_ref": json.dumps(plan_ref, separators=(",", ":")),
                   "code_sha": plan["code_sha"] if plan else args.code_sha,
                   "blocked_count": summary["blocked_count"], "planning_status": summary["status"]}
        if args.github_output:
            with args.github_output.open("a") as output:
                for key, value in outputs.items():
                    output.write(f"{key}={value}\n")
        public_summary = {key: summary[key] for key in ("status", "migration_complete", "cohort_count", "counts",
                                                       "blocked_count", "blocked_reason_counts")}
        public_summary.update(selected=outputs["planned_count"], cold_bootstrap_throttle=None,
                              destination_github_api_requests_total=transport.request_count,
                              destination_github_graphql_api_requests_total=transport.graphql_request_count,
                              destination_accounting_scope="this_process_shared_destination_transport_only")
        rendered = json.dumps(public_summary, indent=2)
        print(rendered)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as output:
                output.write("\nMigration planning summary\n\n```json\n" + rendered + "\n```\n")
        return 0
    with tempfile.TemporaryDirectory(prefix=f"icsot-legacy-import-{entry['repository_id']}-") as temporary:
        result = initialize_repository(plan, args.slug, code_sha=args.code_sha, config=config,
            destination_repository=args.destination_repository, operational_private_key_path=args.state_private_key,
            state_public_key_path=args.state_public_key, evidence_public_key_path=args.evidence_public_key,
            working_root=Path(f"/tmp/icsot-persistent-state/{entry['repository_id']}").resolve(),
            scratch=Path(temporary), reader=reader, ledger=ledger, transport=transport,
            max_runtime_seconds=args.max_runtime_seconds,
            rfc3161_options={"rfc3161_url": args.rfc3161_url, "rfc3161_ca": args.rfc3161_ca,
                             "rfc3161_chain": args.rfc3161_chain})
    result.update(destination_github_api_requests_total=transport.request_count,
                  destination_github_graphql_api_requests_total=transport.graphql_request_count,
                  destination_github_rest_api_requests_total=transport.request_count - transport.graphql_request_count,
                  destination_accounting_scope="this_process_shared_destination_transport_only")
    _create_identical(args.output, canonical_json(result))
    print(json.dumps(result, indent=2))
    return 0 if result["disposition"] == "state_published" else 75 if result["disposition"] == "deferred" else 2


if __name__ == "__main__":
    raise SystemExit(main())
