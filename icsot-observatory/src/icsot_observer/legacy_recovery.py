"""Explicit, bounded FFmpeg legacy-state recovery; never an ordinary retry.

An encrypted descriptor is durable before any generation-part upload. A lost
runner can resume a complete remote closure, or reimport the same source once
into a new linked generation. Missing randomized ciphertext is never recreated
under its former identity. The original migration hold and all old assets stay.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import time
from pathlib import Path

from .core import canonical_json, sha256, utc_iso
from .encryption import encrypt_file
from .github_state import (GitHubStateStore, RecoveryCandidatePool, StateConflictError,
                           StateDeferredError, StateError, StateReleaseMissingError, StateSelection)
from .legacy_bootstrap import (GitHubMigrationLedger, GitHubSourceReader, MigrationError,
    MigrationHelpers, MIGRATION_BRANCH, MAX_METADATA_BYTES, MIGRATION_STATE_CIPHERTEXT_CAP,
    asset_ref, import_legacy_seed, read_verified_json, safe_error_location)
from .recurrence import BoundedStateTransport, load_cohort
from .runtime import ControllerLock

PILOT_SLUG, PILOT_ID = "FFmpeg/FFmpeg", 1614410
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_EPOCH = re.compile(r"[0-9a-f]{32}\Z")
MAX_GENERATIONS = 2


def _hash(value):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise MigrationError("Pinned recovery SHA-256 required")
    return value


def freeze_manifest(plan: dict, record: dict, census: dict, *, destination_repository: str,
                    epoch: str, source_plan_sha256: str, source_plan_asset: dict) -> dict:
    """Freeze metadata only. Live absence and source-ledger identity are rechecked."""
    if not isinstance(epoch, str) or not _EPOCH.fullmatch(epoch):
        raise MigrationError("Explicit 32-hex audited recovery epoch required")
    entries = [entry for entry in plan.get("repositories", []) if entry.get("slug") == PILOT_SLUG]
    if len(entries) != 1:
        raise MigrationError("Exactly one FFmpeg legacy source required")
    entry = entries[0]
    if (entry.get("repository_id") != PILOT_ID or entry.get("strategy") != "legacy_seed" or
            record.get("repository_id") != PILOT_ID or record.get("slug") != PILOT_SLUG or
            record.get("migration_id") != plan.get("migration_id") or
            record.get("strategy") != "legacy_seed" or record.get("disposition") != "deferred" or
            not record.get("external_recovery_required") or not record.get("prepared_generation") or
            census.get("repository_id") != PILOT_ID or census.get("slug") != PILOT_SLUG or
            census.get("generation") != record["prepared_generation"] or
            census.get("authoritative_pointer_exists") is not False or
            record.get("source_index_sha256") != entry.get("source_index", {}).get("sha256") or
            record.get("source_manifest_sha256") != entry.get("source_manifest", {}).get("sha256")):
        raise MigrationError("Frozen pilot source/hold/absence binding differs")
    checks = {(item["release_tag"], item["name"]): item for item in census["checks"]}
    candidates = []
    for ref in record["prepared_assets"]:
        check = checks.get((ref["release_tag"], ref["name"]))
        if check is None:
            raise MigrationError("Frozen census does not cover every declared old asset")
        if check["status"] == "match" and ref.get("kind") in ("raw", "tar"):
            candidates.append(copy.deepcopy(ref))
    # The import helper needs only this immutable selected entry and plan context.
    selected_plan = {**copy.deepcopy(plan), "repositories": [copy.deepcopy(entry)]}
    asset_ref(source_plan_asset)
    if source_plan_asset["sha256"] != source_plan_sha256:
        raise MigrationError("Original source-plan asset SHA differs")
    return {"schema_version": 1, "kind": "icsot_explicit_legacy_recovery_v1", "recovery_epoch": epoch,
        "repository_id": PILOT_ID, "slug": PILOT_SLUG, "destination_repository": destination_repository,
        "source_plan_sha256": _hash(source_plan_sha256), "source_plan_asset": copy.deepcopy(source_plan_asset),
        "source_plan": selected_plan,
        "source_ledger": copy.deepcopy(record), "source_ledger_sha256": sha256(canonical_json(record)),
        "old_generation": record["prepared_generation"], "original_imported_at": record["created_at"],
        "expected_pointer": None, "expected_slug_binding": None, "candidate_parts": candidates,
        "max_recovery_generations": MAX_GENERATIONS,
        "observation_claim": "verified_migration_of_original_evidence_not_a_new_observation"}


class RecoveryJournal:
    """One CAS-protected recovery record; original migration disposition is untouched."""
    def __init__(self, ledger: GitHubMigrationLedger, manifest: dict, manifest_sha256: str):
        self.ledger, self.transport = ledger, ledger.transport
        self.path = (f"recoveries/{manifest['source_plan']['migration_id']}/{manifest['repository_id']}/"
                     f"{manifest['recovery_epoch']}.json")
        self.identity = {"schema_version": 1, "kind": "icsot_legacy_recovery_journal_v1",
            "recovery_manifest_sha256": manifest_sha256, "recovery_epoch": manifest["recovery_epoch"],
            "repository_id": manifest["repository_id"], "slug": manifest["slug"],
            "source_ledger_sha256": manifest["source_ledger_sha256"]}
        self.current = self.ledger._read(self.ledger._head(), self.path)
        if self.current and any(self.current.get(key) != value for key, value in self.identity.items()):
            raise StateConflictError("Recovery epoch already names another frozen manifest")

    def write(self, value: dict):
        desired = {**self.identity, **copy.deepcopy(value)}
        raw = canonical_json(desired)
        if len(raw) > MAX_METADATA_BYTES:
            raise MigrationError("Recovery journal exceeds metadata bound")
        expected = copy.deepcopy(self.current)
        api, repo = self.transport._api, self.transport.repository
        for _ in range(8):
            head = self.ledger._head()
            actual = self.ledger._read(head, self.path)
            if actual == desired:
                self.current = desired
                return desired
            if actual != expected:
                raise StateConflictError("Recovery journal changed concurrently")
            base = api(f"repos/{repo}/git/commits/{head}")["tree"]["sha"] if head else None
            tree = api(f"repos/{repo}/git/trees", method="POST", payload={**({"base_tree": base} if base else {}),
                "tree": [{"path": self.path, "mode": "100644", "type": "blob", "content": raw.decode()}]})
            commit = api(f"repos/{repo}/git/commits", method="POST", payload={"message": "Record bounded legacy recovery",
                "tree": tree["sha"], "parents": [head] if head else []})
            try:
                if head:
                    api(f"repos/{repo}/git/refs/heads/{MIGRATION_BRANCH}", method="PATCH",
                        payload={"sha": commit["sha"], "force": False})
                else:
                    api(f"repos/{repo}/git/refs", method="POST",
                        payload={"ref": f"refs/heads/{MIGRATION_BRANCH}", "sha": commit["sha"]})
                self.current = desired
                return desired
            except StateDeferredError:
                raise
            except StateError:
                if self.ledger._read(self.ledger._head(), self.path) == desired:
                    self.current = desired
                    return desired
        raise StateConflictError("Too many concurrent recovery metadata updates")


def _available(store, refs):
    """Fresh remote metadata is a candidate filter, never authenticated reuse."""
    result, refreshed, missing = [], set(), set()
    for ref in refs:
        if ref["release_tag"] in missing:
            continue
        try:
            remote = store.transport.find_asset(ref["release_tag"], ref["name"], refresh=ref["release_tag"] not in refreshed)
        except StateReleaseMissingError:
            missing.add(ref["release_tag"])
            continue  # Only exact authorized release absence is a candidate miss.
        refreshed.add(ref["release_tag"])
        if remote is None or remote.get("state") != "uploaded":
            continue
        if (remote.get("name") != ref["name"] or remote.get("size") != ref["ciphertext_bytes"] or
                remote.get("digest") not in (None, "sha256:" + ref["ciphertext_sha256"])):
            raise StateError("Frozen recovery asset identity changed")
        result.append(copy.deepcopy(ref))
    return result


def _descriptor(store, attempt, scratch):
    encrypted, plain = scratch / "descriptor.enc", scratch / "descriptor.json"
    if (attempt["descriptor"].get("plaintext_bytes", MAX_METADATA_BYTES + 1) > MAX_METADATA_BYTES or
            attempt["descriptor"].get("ciphertext_bytes", MAX_METADATA_BYTES + 65537) > MAX_METADATA_BYTES + 65536):
        raise StateError("Recovery descriptor exceeds bounded metadata size")
    store._download_verified(attempt["descriptor"], encrypted)
    store._decrypt(attempt["descriptor"], encrypted, plain)
    raw = plain.read_bytes()
    encrypted.unlink()
    plain.unlink()
    if len(raw) > MAX_METADATA_BYTES or sha256(raw) != attempt["prepared_manifest_sha256"]:
        raise StateError("Recovery descriptor manifest differs")
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise StateError("Noncanonical recovery descriptor")
    if (value.get("repository_id") != store.repository_id or value.get("slug") != store.slug or
            value.get("recipient_spki_sha256") != store.recipient or value.get("generation") != attempt["generation"] or
            value.get("selection", {}).get("pointer") is not None or value.get("selection", {}).get("index") is not None):
        raise StateError("Recovery descriptor target or missing-state lineage differs")
    return value, raw


def _seal_descriptor(store, prepared, scratch):
    """Encrypt once before the retried network operation; retain exact bytes."""
    encrypted, seal = scratch / "recovery-descriptor.enc", scratch / "recovery-descriptor-seal.json"
    if seal.exists():
        value = json.loads(seal.read_bytes())
        if value.get("prepared_manifest_sha256") != prepared.manifest_sha256:
            raise StateConflictError("Local recovery descriptor names another preparation")
        ref = value["ref"]
    else:
        if encrypted.exists():
            raise StateError("Unsealed local recovery descriptor cannot be regenerated")
        record = encrypt_file(prepared.directory / "prepared.json", encrypted, store.public_key)
        ref = {**record, "release_tag": f"collector-state-recovery-r{store.repository_id}-g{prepared.generation}",
               "name": "prepared-descriptor.enc"}
        store._local_record(seal, {"prepared_manifest_sha256": prepared.manifest_sha256, "ref": ref})
    if (ref.get("plaintext_sha256") != prepared.manifest_sha256 or
            ref.get("public_key_fingerprint_sha256") != store.recipient or
            ref.get("release_tag") != f"collector-state-recovery-r{store.repository_id}-g{prepared.generation}" or
            ref.get("name") != "prepared-descriptor.enc" or
            encrypted.stat().st_size != ref["ciphertext_bytes"] or sha256(encrypted.read_bytes()) != ref["ciphertext_sha256"]):
        raise StateError("Local recovery descriptor ciphertext differs")
    return ref, encrypted


def _publish_descriptor(store, prepared, scratch, *, ref, encrypted):
    budget = getattr(store.transport, "publication_budget", None)
    if callable(budget):
        # Descriptor envelope + release discovery, durable journal, and bounded
        # progress writes are additional destination work beyond state uploads.
        budget(2 + 15 + 8 * (len(prepared.assets) + 5))
    store.transport.ensure_release(ref["release_tag"])
    remote = store.transport.find_asset(ref["release_tag"], ref["name"], refresh=True)
    if remote is None:
        try:
            store.transport.upload_asset(ref["release_tag"], ref["name"], encrypted)
        except (StateError, OSError):
            # A write may succeed before its acknowledgement is lost. Only
            # exact readback can resolve that ambiguity; never encrypt again.
            remote = store.transport.find_asset(ref["release_tag"], ref["name"], refresh=True)
            if remote is None:
                raise
    if remote is not None and (remote.get("state") != "uploaded" or remote.get("size") != ref["ciphertext_bytes"] or
            remote.get("digest") not in (None, "sha256:" + ref["ciphertext_sha256"])):
        raise StateConflictError("Existing recovery descriptor identity differs")
    verified, plain = scratch / "descriptor-verified.enc", scratch / "descriptor-verified.json"
    try:
        store._download_verified(ref, verified)
        store._decrypt(ref, verified, plain)
        if sha256(plain.read_bytes()) != prepared.manifest_sha256:
            raise StateError("Authenticated recovery descriptor source differs")
    finally:
        verified.unlink(missing_ok=True)
        plain.unlink(missing_ok=True)
    return ref


def _retry_frozen(operation, *, deadline, clock, sleeper, cleanup_seconds=120):
    """Wait only for explicit retry times, keeping the same local seal alive."""
    for attempt in range(8):
        if clock() >= deadline - cleanup_seconds:
            raise StateDeferredError("Recovery cleanup margin reached", reason="recovery_runtime_budget")
        try:
            return operation()
        except StateDeferredError as error:
            retry = error.retry_not_before
            if retry is None or retry >= deadline - cleanup_seconds or attempt == 7:
                raise
            retry = max(clock() + 1, retry)
            while clock() < retry:
                sleeper(min(60, retry - clock()))


def recover(manifest: dict, manifest_sha256: str, *, code_sha: str, config, backend,
            ledger, reader, working_root: Path, scratch: Path, operational_private_key_path: Path,
            evidence_public_key_path: Path, helpers=None, journal_factory=RecoveryJournal,
            attempt_identity: str = "manual", max_runtime_seconds: float = 19800,
            clock=time.time, sleeper=time.sleep) -> dict:
    """Execute only the frozen legacy pilot. Current state wins before import/write."""
    if not 120 < max_runtime_seconds <= 19800:
        raise MigrationError("Recovery requires a bounded runtime and cleanup margin")
    deadline = clock() + max_runtime_seconds
    if sha256(canonical_json(manifest)) != _hash(manifest_sha256):
        raise MigrationError("Recovery manifest hash differs")
    if (manifest.get("kind") != "icsot_explicit_legacy_recovery_v1" or manifest.get("schema_version") != 1 or
            not isinstance(manifest.get("recovery_epoch"), str) or not _EPOCH.fullmatch(manifest["recovery_epoch"]) or
            manifest.get("repository_id") != PILOT_ID or manifest.get("slug") != PILOT_SLUG or
            manifest.get("destination_repository") != backend.transport.repository or
            manifest.get("max_recovery_generations") != MAX_GENERATIONS or
            manifest.get("expected_pointer", "missing") is not None or
            manifest.get("expected_slug_binding", "missing") is not None or
            sha256(canonical_json(manifest["source_ledger"])) != manifest.get("source_ledger_sha256")):
        raise MigrationError("Invalid explicit FFmpeg recovery authorization")
    plan, original = manifest["source_plan"], manifest["source_ledger"]
    _hash(plan["migration_id"])
    if not isinstance(code_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", code_sha):
        raise MigrationError("Actual recovery checkout SHA required")
    entry = plan["repositories"][0]
    if (len(plan["repositories"]) != 1 or entry.get("slug") != PILOT_SLUG or entry.get("repository_id") != PILOT_ID or
            entry.get("strategy") != "legacy_seed" or config.history_profile != "full_history" or
            PILOT_SLUG not in config.repositories or backend.recipient != plan["operational_recipient_spki_sha256"] or
            working_root.resolve() != backend.root or original.get("fresh_capture_attempt_started")):
        raise MigrationError("Recovery source/operational recipient/history policy differs")
    scratch.mkdir(parents=True, exist_ok=True)
    with ControllerLock(working_root):
        selection = backend.read()
        if selection.pointer is not None:
            return {"status": "current_state_wins", "repository_id": PILOT_ID,
                    "generation": selection.pointer["generation"], "new_observations": 0}
        live = ledger.read(plan["migration_id"], PILOT_ID)
        if live != original:
            raise StateConflictError("Frozen migration source ledger changed before recovery")
        raw_plan = reader.metadata(asset_ref(manifest["source_plan_asset"]))
        if sha256(raw_plan) != manifest["source_plan_sha256"]:
            raise MigrationError("Original immutable source plan SHA differs")
        full_plan = json.loads(raw_plan)
        selected_entries = [entry for entry in full_plan["repositories"] if entry.get("slug") == PILOT_SLUG]
        if len(selected_entries) != 1 or {**full_plan, "repositories": selected_entries} != plan:
            raise MigrationError("Recovery source context differs from original immutable plan")
        journal = journal_factory(ledger, manifest, manifest_sha256)
        attempts = copy.deepcopy((journal.current or {}).get("attempts", []))
        candidates = list(manifest["candidate_parts"])
        lineage = []
        prepared = None
        for prior_attempt in attempts:
            if not prior_attempt.get("descriptor"):
                continue
            value, raw = _descriptor(backend, prior_attempt, scratch)
            lineage.append(prior_attempt["generation"])
            refs = [asset["ref"] for asset in value["assets"]]
            available = _available(backend, refs)
            candidates.extend(ref for ref in available if ref.get("kind") in ("raw", "tar"))
            if prior_attempt is attempts[-1] and len(available) == len(refs):
                directory = scratch / "prepared"
                directory.mkdir(mode=0o700)
                for asset in value["assets"]:
                    target = directory / asset["path"]
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    backend._download_verified(asset["ref"], target)
                (directory / "prepared.json").write_bytes(raw)
                prepared = backend.load_prepared(directory, prior_attempt["prepared_manifest_sha256"])
                # Restore a pending authenticated snapshot for validation only;
                # its real publication predecessor remains the missing pointer.
                backend.restore(StateSelection(selection.head, value["pointer"], value["index"]))
        if prepared is None:
            if len(attempts) >= MAX_GENERATIONS:
                return {"status": "external_recovery_required", "reason": "bounded_recovery_generation_limit",
                        "attempts": len(attempts), "new_observations": 0}
            available = _available(backend, candidates)
            deduplicated = {}
            for ref in available:
                deduplicated[(ref["decoded_sha256"], ref["decoded_bytes"], ref["kind"])] = ref
            pool = RecoveryCandidatePool(backend.transport.repository, PILOT_ID, PILOT_SLUG, backend.recipient,
                manifest["recovery_epoch"], manifest["source_ledger_sha256"], manifest["old_generation"],
                tuple(deduplicated.values()), tuple(lineage))
            backend._recovery_parts(pool, selection)
            if any(path.name != ".collector.lock" for path in working_root.iterdir()):
                raise StateError("Recovery reimport requires an empty working root")
            recovery_started_at = utc_iso()
            imported = import_legacy_seed(plan, entry, code_sha=code_sha, config=config,
                working_root=working_root, scratch=scratch, reader=reader, helpers=helpers,
                operational_private_key_path=operational_private_key_path,
                evidence_public_key_path=evidence_public_key_path, imported_at=recovery_started_at)
            if imported is None:
                raise MigrationError("No independently proven original seed capability")
            lineage_record = {"schema_version": 1, "kind": "icsot_legacy_recovery_revalidation_v1",
                "recovery_epoch": manifest["recovery_epoch"], "recovery_code_sha": code_sha,
                "recovery_started_at": recovery_started_at, "source_importer_code_sha": plan["code_sha"],
                "historical_imported_at": manifest["original_imported_at"],
                "historical_import_receipt_sha256": original["migration_receipt_sha256"],
                "source_observation_interval": {key: imported["original"][key] for key in ("started_at", "finished_at")},
                "source_ledger_sha256": manifest["source_ledger_sha256"],
                "observation_claim": "revalidated_original_evidence_not_a_new_observation"}
            lineage_path = working_root / "imports" / "legacy-recovery" / (manifest["recovery_epoch"] + ".json")
            lineage_path.parent.mkdir(parents=True, exist_ok=True)
            lineage_path.write_bytes(canonical_json(lineage_record))
            generation = sha256(canonical_json({"epoch": manifest["recovery_epoch"], "attempt": len(attempts) + 1,
                "runner": attempt_identity, "source_ledger_sha256": manifest["source_ledger_sha256"]}))[:32]
            if generation in (manifest["old_generation"], *lineage):
                raise StateConflictError("Recovery generation must be new")
            prepared = backend.prepare(selection, directory=scratch / "prepared", generation=generation,
                source_import_sha256=imported["receipt_digest"], dependencies=[],
                code_hashes={"source_importer_commit": plan["code_sha"], "importer_commit": code_sha, "recovery_commit": code_sha},
                config_hashes={"source_sha256": plan["config_source_sha256"]},
                evidence_heads={"legacy_seed_sha256": imported["seed"]["seed_sha256"],
                    "original_manifest_sha256": entry["source_manifest"]["sha256"]},
                recovery_candidates=pool, quiescent=True)
            # The encrypted full descriptor is fetched and authenticated first.
            # Only then is its public identity committed before any part upload.
            descriptor_ref, descriptor_file = _seal_descriptor(backend, prepared, scratch)
            descriptor = _retry_frozen(lambda: _publish_descriptor(backend, prepared, scratch,
                ref=descriptor_ref, encrypted=descriptor_file), deadline=deadline, clock=clock, sleeper=sleeper)
            attempts.append({"generation": generation, "prepared_manifest_sha256": prepared.manifest_sha256,
                "descriptor": descriptor, "status": "descriptor_published", "verified_assets": [],
                "source_import_sha256": prepared.source_import_sha256, "previous_recovery_generation": lineage[-1] if lineage else None,
                "candidate_pool_sha256": sha256(canonical_json(list(pool.parts)))})
            initial_progress = {"status": "publication_pending", "attempts": copy.deepcopy(attempts), "updated_at": utc_iso()}
            _retry_frozen(lambda: journal.write(initial_progress), deadline=deadline, clock=clock, sleeper=sleeper)
        def progress(value):
            attempts[-1].update(status=value["status"], verified_assets=value["verified_assets"],
                                pointer_commit=value.get("pointer_commit"))
            frozen_progress = {"status": value["status"], "attempts": copy.deepcopy(attempts), "updated_at": utc_iso()}
            _retry_frozen(lambda: journal.write(frozen_progress), deadline=deadline, clock=clock, sleeper=sleeper)
        publication = _retry_frozen(lambda: backend.publish_prepared(prepared, quiescent=True, progress_callback=progress,
            progress_requests_reserve=8 * (len(prepared.assets) + 3)), deadline=deadline, clock=clock, sleeper=sleeper)
        return {"status": "complete", "repository_id": PILOT_ID, "recovery_epoch": manifest["recovery_epoch"],
                "generation": prepared.generation, "new_observations": 0, "new_evidence_upload_bytes": 0,
                "publication": publication, "original_hold_preserved": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("--held-preparations", required=True, type=Path)
    freeze.add_argument("--asset-census", required=True, type=Path)
    freeze.add_argument("--epoch", required=True)
    run = commands.add_parser("run")
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--manifest-sha256", required=True)
    run.add_argument("--code-sha", required=True)
    run.add_argument("--state-public-key", required=True, type=Path)
    run.add_argument("--state-private-key", required=True, type=Path)
    run.add_argument("--evidence-public-key", required=True, type=Path)
    run.add_argument("--working-root", type=Path, default=Path(f"/tmp/icsot-persistent-state/{PILOT_ID}"))
    run.add_argument("--scratch", required=True, type=Path)
    run.add_argument("--attempt-identity", required=True)
    for child in (freeze, run):
        child.add_argument("--destination-repository", required=True)
        child.add_argument("--config", required=True, type=Path)
        child.add_argument("--csv", required=True, type=Path)
        child.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    config, sources = load_cohort(args.config, args.csv)
    transport = BoundedStateTransport(args.destination_repository, evidence_bytes=0, state_bytes=MIGRATION_STATE_CIPHERTEXT_CAP)
    ledger, reader = GitHubMigrationLedger(transport), GitHubSourceReader()
    if args.command == "freeze":
        active = ledger.active_plan()
        if not active:
            raise MigrationError("No frozen active migration source")
        raw = reader.metadata(active["plan"])
        plan = json.loads(raw)
        rows = json.loads(args.held_preparations.read_bytes())["preparations"]
        record = next(row["record"] for row in rows if row["record"]["slug"] == PILOT_SLUG)
        census = next(row for row in json.loads(args.asset_census.read_bytes())["prepared_generations"] if row["slug"] == PILOT_SLUG)
        if ledger.read(plan["migration_id"], PILOT_ID) != record:
            raise StateConflictError("Frozen held preparation differs from current migration ledger")
        manifest = freeze_manifest(plan, record, census, destination_repository=args.destination_repository,
                                   epoch=args.epoch, source_plan_sha256=sha256(raw), source_plan_asset=active["plan"])
        backend = GitHubStateStore(transport, repository_id=PILOT_ID, slug=PILOT_SLUG,
            public_key=Path("keys/working-state-rsa-public.pem"), logical_root=f"/tmp/icsot-persistent-state/{PILOT_ID}")
        if backend._authoritative_pointer()[1] is not None:
            raise StateConflictError("Pilot already has authoritative state")
        result = manifest
    else:
        if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != args.code_sha:
            raise MigrationError("Recovery checkout differs from dispatched code SHA")
        manifest = read_verified_json(args.manifest, args.manifest_sha256)
        if any(manifest["source_plan"].get(key) != value for key, value in sources.items()):
            raise MigrationError("Recovery configuration/CSV differs from frozen source")
        backend = GitHubStateStore(transport, repository_id=PILOT_ID, slug=PILOT_SLUG,
            public_key=args.state_public_key, private_key=args.state_private_key, logical_root=args.working_root)
        try:
            result = recover(manifest, args.manifest_sha256, code_sha=args.code_sha, config=config, backend=backend,
                ledger=ledger, reader=reader, working_root=args.working_root, scratch=args.scratch,
                operational_private_key_path=args.state_private_key, evidence_public_key_path=args.evidence_public_key,
                attempt_identity=args.attempt_identity)
        except Exception as error:
            result = {"status": "deferred" if isinstance(error, StateDeferredError) else "external_recovery_required",
                "repository_id": PILOT_ID, "recovery_epoch": manifest["recovery_epoch"],
                "reason_code": type(error).__name__, "error_location": safe_error_location(error),
                "new_observations": 0, "retry_not_before": getattr(error, "retry_not_before", None),
                "original_hold_preserved": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(result))
    print(json.dumps({"status": result.get("status", "frozen"), "manifest_sha256": sha256(canonical_json(result)),
                      "repository_id": PILOT_ID, "new_observations": 0}, sort_keys=True))
    return 0 if result.get("status") in (None, "complete", "current_state_wins") else 75


if __name__ == "__main__":
    raise SystemExit(main())
