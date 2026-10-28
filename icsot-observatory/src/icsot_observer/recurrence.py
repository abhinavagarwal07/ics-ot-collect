"""Bounded six-hour cohort planning around the selected encrypted-state adapter."""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import subprocess
import tempfile
import time
import tomllib
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .core import Config, ObjectStore, REPO_RE, canonical_json, sha256, utc_iso, write_once
from .github import APIRequestDeferred, GitHubAPI
from .github_state import GhCliStateTransport, StateConflictError, StateDeferredError, StateError
from .history import FULL_HISTORY, load_history_settings, repository_history_policy

INTERVAL_SECONDS = 21600
MAX_PARALLEL = 8
MAX_COLD_BOOTSTRAPS = 8
MAX_PLAN_BYTES = 1024 * 1024
EXECUTION_ORDER_POLICY = "slot_seeded_sha256_rank_v1"
GIB = 1024 ** 3
DEFAULT_LIMITS = {"job_timeout_minutes": 180, "max_restored_state_plaintext_bytes": 8 * GIB,
                  "max_new_evidence_ciphertext_bytes": 2 * GIB, "max_new_state_ciphertext_bytes": 2 * GIB}


def load_resource_limits(path: Path, repositories: tuple[str, ...]) -> dict[str, dict]:
    settings = tomllib.loads(path.read_text(encoding="utf-8")).get("recurrence", {})
    defaults = settings.get("limits", {})
    overrides = settings.get("overrides", {})
    if not isinstance(defaults, dict) or not isinstance(overrides, dict) or any(slug not in repositories for slug in overrides):
        raise ValueError("Invalid recurring resource overrides")
    result = {}
    for slug in repositories:
        override = overrides.get(slug, {})
        if not isinstance(override, dict) or (set(defaults) | set(override)) - DEFAULT_LIMITS.keys():
            raise ValueError("Unknown recurring resource limit")
        limits = {**DEFAULT_LIMITS, **defaults, **override}
        if any(type(value) is not int or value <= 0 for value in limits.values()) or limits["job_timeout_minutes"] > 360:
            raise ValueError("Positive recurring resource limits and hosted timeout <=360 minutes required")
        result[slug] = limits
    return result


def load_cohort(config_path: Path, csv_path: Path, *, expected_count: int = 185):
    config = Config.load(config_path)
    raw = csv_path.read_bytes()
    slugs = []
    for row in csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))):
        url = urlsplit(row["Repository_URL"])
        slug = url.path.strip("/")
        if (url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment or
                not REPO_RE.fullmatch(slug)):
            raise ValueError("Invalid cohort repository URL")
        slugs.append(slug)
    if tuple(slugs) != config.repositories or len(slugs) != expected_count:
        raise ValueError("Recurring cohort must match every CSV row in order")
    return config, {"config_source_sha256": sha256(config_path.read_bytes()),
                    "csv_sha256": sha256(raw), "cohort_count": len(slugs)}


def build_plan(config: Config, *, sources: dict, code_sha: str, identity_loader,
               pointer_loader, cold_bootstraps: int = 0, now: float | None = None,
               history_settings: dict | None = None, resource_limits: dict | None = None,
               migration_pending_slugs: set[str] | None = None) -> dict:
    if type(cold_bootstraps) is not int or not 0 <= cold_bootstraps <= MAX_COLD_BOOTSTRAPS:
        raise ValueError("cold_bootstraps must be an integer from 0 through 8")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", code_sha):
        raise ValueError("A full collector code SHA is required")
    now = time.time() if now is None else now
    slot = int(now // INTERVAL_SECONDS)
    rows, seen_ids = [], {}
    source_deferred = False
    history_settings = history_settings or {}
    for slug in config.repositories:
        row = {"slug": slug, "repository_id": None, "slot": slot,
               "reported_size_kb": None,
               "resource_limits": (resource_limits or {}).get(slug, dict(DEFAULT_LIMITS)),
               "observation_key": f"six-hour-slot-{slot}", "code_sha": code_sha, **sources,
               "expected_generation": None, "expected_pointer_sha256": None,
               "allow_bootstrap": False, "plan_status": "paused_identity"}
        rows.append(row)
        if source_deferred:
            row["reason_code"] = "shared_source_rate_deferred"
            continue
        try:
            identity = identity_loader(slug)
            if identity.get("private") is not False or type(identity.get("id")) is not int or identity["id"] <= 0:
                raise ValueError("Source repository is not unambiguously public")
            repo_id = row["repository_id"] = identity["id"]
            row["reported_size_kb"] = identity.get("size")
            if repo_id in seen_ids:
                seen_ids[repo_id]["plan_status"] = "paused_identity"
                seen_ids[repo_id]["reason_code"] = "duplicate_numeric_identity"
                row["reason_code"] = "duplicate_numeric_identity"
                continue
            seen_ids[repo_id] = row
            row["history_policy"] = repository_history_policy(slug, identity.get("size"), slot,
                threshold_kb=history_settings.get("threshold_kb", 5_000_000),
                overrides=history_settings.get("overrides"))
            row["history_policy_sha256"] = sha256(canonical_json(row["history_policy"]))
        except Exception as error:
            source_deferred = isinstance(error, APIRequestDeferred)
            row["reason_code"] = type(error).__name__
            if source_deferred:
                row["retry_not_before"] = error.retry_not_before
            continue
        try:
            raw = pointer_loader(repo_id)
            if raw is None:
                row["plan_status"] = "migration_pending" if slug in (migration_pending_slugs or set()) else "bootstrap_pending"
            else:
                pointer = json.loads(raw)
                if (not isinstance(pointer, dict) or canonical_json(pointer) != raw or
                        pointer.get("repository_id") != repo_id or pointer.get("slug") != slug or
                        not re.fullmatch(r"[0-9a-f]{32}", pointer.get("generation", ""))):
                    raise StateError("State pointer does not match selected public identity")
                row.update(plan_status="ready_incremental", expected_generation=pointer["generation"],
                           expected_pointer_sha256=sha256(raw))
            # Do not silently fall back to a fresh full clone while the bounded
            # recent Git/API profile is undergoing its independent validation.
            if row["history_policy"]["profile"] != FULL_HISTORY:
                row["plan_status"] = "large_profile_pending"
        except Exception as error:
            row.update(plan_status="paused_state", reason_code=type(error).__name__)
            if isinstance(error, StateDeferredError):
                row["retry_not_before"] = error.retry_not_before
    missing = [row for row in rows if row["plan_status"] == "bootstrap_pending"]
    # Rotate cold attempts so one persistently large/unavailable target cannot
    # monopolize the bootstrap wave. No historical baseline bytes are consumed.
    if missing and cold_bootstraps:
        offset = (slot * cold_bootstraps) % len(missing)
        for row in (missing[offset:] + missing[:offset])[:cold_bootstraps]:
            row.update(plan_status="fresh_public_bootstrap", allow_bootstrap=True)
    cohort_hash = sha256(canonical_json([{"slug": row["slug"], "repository_id": row["repository_id"]}
                                        for row in rows]))
    for row in rows:
        row["cohort_identity_sha256"] = cohort_hash
    selected = [row for row in rows if row["plan_status"] in ("ready_incremental", "fresh_public_bootstrap")]
    execution_seed = sha256(canonical_json({"policy": EXECUTION_ORDER_POLICY,
                                          "cohort_identity_sha256": cohort_hash, "slot": slot}))
    # Vary matrix priority across slots without changing the canonical cohort
    # or the eligibility and cold-bootstrap rotation decided above.
    selected.sort(key=lambda row: (sha256(canonical_json({"seed_sha256": execution_seed,
                                                         "repository_id": row["repository_id"]})),
                                   row["repository_id"]))
    return {"schema_version": 1, "kind": "icsot_six_hour_incremental_plan", "planned_at": utc_iso(
        datetime.fromtimestamp(now, timezone.utc)), "slot": slot, "interval_seconds": INTERVAL_SECONDS,
        "code_sha": code_sha, **sources, "cohort_identity_sha256": cohort_hash,
        "execution_order_policy": EXECUTION_ORDER_POLICY, "execution_order_seed_sha256": execution_seed,
        "execution_order_sha256": sha256(canonical_json([row["repository_id"] for row in selected])),
        "execution_order_qualification": "Per-slot matrix priority; hosted job start order and six-hour coverage are not guaranteed.",
        "history_profile_readiness": "recent profile pending Git/API validation; full-history selections only",
        "max_parallel": MAX_PARALLEL, "cold_bootstrap_limit": cold_bootstraps,
        "source_quota": "public-read account allowances, optionally partitioned across two independent accounts; workers and same-account tokens do not create independent allowances",
        "source_rate_reserve": 40, "source_blocking_rate_wait_seconds": 0,
        "monthly_evidence_policy_bytes": 50_000_000_000, "monthly_cap_enforced": False,
        "state_accounting": "operational ciphertext is reported separately from retained evidence",
        "default_resource_limits": dict(DEFAULT_LIMITS),
        "counts": dict(Counter(row["plan_status"] for row in rows)), "repositories": rows,
        "matrix": {"include": selected},
        "claim": "Best-effort six-hour scheduling; cold bootstrap is a new public observation, not historical baseline recovery."}


class BoundedStateTransport(GhCliStateTransport):
    """Per-job physical upload limits; neither this nor matrix concurrency is a monthly cap."""

    def __init__(self, repository: str, *, evidence_bytes: int, state_bytes: int, **options):
        super().__init__(repository, **options)
        self.upload_limits = {"evidence": evidence_bytes, "state": state_bytes}
        self.uploaded_bytes = {"evidence": 0, "state": 0}
        self._counted_uploads = set()

    def upload_asset(self, tag: str, name: str, source: Path) -> None:
        kind = "state" if tag.startswith("collector-state-") else "evidence"
        identity = (tag, name)
        size = source.stat().st_size
        if identity not in self._counted_uploads and self.uploaded_bytes[kind] + size > self.upload_limits[kind]:
            raise StateDeferredError(f"Per-job {kind} upload limit reached", reason=f"{kind}_job_size_limit")
        if identity not in self._counted_uploads:
            # An interrupted response may follow a successful remote write.
            # Reserve before sending and retain that conservative charge.
            self.uploaded_bytes[kind] += size
            self._counted_uploads.add(identity)
        super().upload_asset(tag, name, source)


def select_entry(plan: dict, slug: str, *, config: Config, sources: dict, code_sha: str) -> dict:
    if plan.get("kind") != "icsot_six_hour_incremental_plan" or plan.get("code_sha") != code_sha:
        raise ValueError("Recurring plan does not match the collector checkout")
    if any(plan.get(key) != value for key, value in sources.items()):
        raise ValueError("Recurring configuration/CSV changed after planning")
    rows = plan.get("repositories", [])
    expected = sha256(canonical_json([{"slug": row["slug"], "repository_id": row["repository_id"]} for row in rows]))
    if tuple(row["slug"] for row in rows) != config.repositories or plan.get("cohort_identity_sha256") != expected:
        raise ValueError("Recurring cohort identity lock differs")
    selected = [row for row in plan.get("matrix", {}).get("include", []) if row.get("slug") == slug]
    if len(selected) != 1 or selected[0] not in rows:
        raise ValueError("Repository is not selected by this immutable plan")
    entry = selected[0]
    if entry["observation_key"] != f"six-hour-slot-{plan['slot']}" or entry["slot"] != plan["slot"]:
        raise ValueError("Recurring plan slot is inconsistent")
    if entry["allow_bootstrap"] != (entry["plan_status"] == "fresh_public_bootstrap"):
        raise ValueError("Bootstrap permission differs from planned disposition")
    if entry["plan_status"] not in ("ready_incremental", "fresh_public_bootstrap") or entry.get("history_policy", {}).get("profile") != FULL_HISTORY:
        raise ValueError("Recent-history profile is not enabled for capture yet")
    if entry.get("history_policy_sha256") != sha256(canonical_json(entry["history_policy"])):
        raise ValueError("History policy differs from its immutable plan digest")
    return entry


def public_outcome(result: dict, entry: dict) -> dict:
    collection = result["collection"]
    pending = sum(count for state, count in collection["queue"]["states"].items() if state != "complete")
    return {"schema_version": 1, "kind": "icsot_recurring_outcome", "slug": entry["slug"],
            "repository_id": entry["repository_id"], "slot": entry["slot"],
            "status": "partial" if pending or collection["partial_captures"] or
                collection.get("current_observation", {}).get("status", "complete") != "complete" else "complete",
            "working_state_origin": result["working_state_origin"], "queue": collection["queue"],
            "completed_jobs": collection["runtime"]["completed"], "pending_jobs": pending,
            "partial_capture_count": len(collection["partial_captures"]),
            "current_observation": collection.get("current_observation"),
            "resumed_older_captures": collection.get("resumed_older_captures", []),
            "resource_limits": entry.get("resource_limits"),
            "history_policy": entry.get("history_policy"),
            "new_evidence_upload_bytes": result["new_evidence_upload_bytes"],
            "measurement_description": "Newly uploaded retained evidence-generation asset bytes, including ciphertext and metadata; initial full captures and duplicate bytes count. This is not a measure of novel upstream changes.",
            "new_state_upload_bytes": result["publication"]["state_uploaded_ciphertext_bytes"],
            "state_referenced_ciphertext_bytes": result["publication"]["state_referenced_ciphertext_bytes"],
            "state_generation": result["publication"]["generation"],
            "monthly_cap_enforced": False, "recorded_at": utc_iso()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run"):
        child = commands.add_parser(name)
        child.add_argument("--config", required=True, type=Path)
        child.add_argument("--csv", required=True, type=Path)
        child.add_argument("--code-sha", required=True)
        child.add_argument("--destination-repository", required=True)
        child.add_argument("--output", required=True, type=Path)
        if name == "plan":
            child.add_argument("--cold-bootstraps", type=int, default=0)
            child.add_argument("--github-output", type=Path)
        else:
            child.add_argument("--plan", required=True, type=Path)
            child.add_argument("--plan-sha256", required=True)
            child.add_argument("--slug", required=True)
            for key in ("state-public-key", "state-private-key", "evidence-public-key", "rfc3161-ca", "rfc3161-chain"):
                child.add_argument("--" + key, required=key.endswith("key"), type=Path)
            child.add_argument("--rfc3161-url")
    args = parser.parse_args(argv)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != args.code_sha:
        raise ValueError("Collector checkout differs from the requested full code SHA")
    config, sources = load_cohort(args.config, args.csv)
    history_settings = load_history_settings(args.config, config.repositories)
    resource_limits = load_resource_limits(args.config, config.repositories)
    config = replace(config, primary_rate_reserve=40, primary_rate_wait_seconds=0)
    if args.command == "plan":
        transport = GhCliStateTransport(args.destination_repository)
        head = transport.branch_head()
        from .legacy_bootstrap import GitHubMigrationLedger
        active_migration = GitHubMigrationLedger(transport).active_plan()
        covered_by_migration = set((active_migration or {}).get("covered_slugs", []))
        with tempfile.TemporaryDirectory(prefix="icsot-plan-identity-") as temporary:
            identity_config = replace(config, root=Path(temporary))
            api = GitHubAPI(identity_config, ObjectStore(identity_config.root), [], defer_on_rate=True)
            plan = build_plan(config, sources=sources, code_sha=args.code_sha,
                              identity_loader=lambda slug: api.get_json(f"/repos/{slug}", "recurring_plan_identity"),
                              pointer_loader=lambda repo_id: transport.read_pointer(head, repo_id) if head else None,
                              cold_bootstraps=args.cold_bootstraps, history_settings=history_settings,
                              resource_limits=resource_limits, migration_pending_slugs=covered_by_migration)
        raw = canonical_json(plan)
        if len(raw) > MAX_PLAN_BYTES:
            raise ValueError("Recurring metadata plan exceeds its 1-MiB bound")
        write_once(args.output, raw)
        if args.github_output:
            with args.github_output.open("a") as output:
                for key, value in {"matrix": json.dumps(plan["matrix"], separators=(",", ":")),
                                   "planned_count": len(plan["matrix"]["include"]), "plan_sha256": sha256(raw),
                                   "slot": plan["slot"], "code_sha": args.code_sha}.items():
                    output.write(f"{key}={value}\n")
        print(json.dumps({"counts": plan["counts"], "slot": plan["slot"], "plan_sha256": sha256(raw)}))
        return 0
    raw = args.plan.read_bytes()
    if len(raw) > MAX_PLAN_BYTES or sha256(raw) != args.plan_sha256:
        raise ValueError("Recurring plan digest or size differs")
    plan = json.loads(raw)
    entry = select_entry(plan, args.slug, config=config, sources=sources, code_sha=args.code_sha)
    limits = entry["resource_limits"]
    transport = BoundedStateTransport(args.destination_repository,
        evidence_bytes=limits["max_new_evidence_ciphertext_bytes"], state_bytes=limits["max_new_state_ciphertext_bytes"])
    try:
        from .pipeline import run_github_persistent
        result = run_github_persistent(config, slug=entry["slug"], repository_id=entry["repository_id"],
            destination_repository=args.destination_repository, state_public_key=args.state_public_key,
            state_private_key=args.state_private_key, evidence_public_key=args.evidence_public_key,
            code_sha=args.code_sha, config_source_sha256=sources["config_source_sha256"],
            observation_key=entry["observation_key"], allow_bootstrap=entry["allow_bootstrap"],
            require_planned_state=True, expected_state_pointer_sha256=entry["expected_pointer_sha256"],
            max_restored_state_plaintext_bytes=limits["max_restored_state_plaintext_bytes"], transport=transport,
            history_policy=entry["history_policy"],
            rfc3161_url=args.rfc3161_url, rfc3161_ca=args.rfc3161_ca, rfc3161_chain=args.rfc3161_chain)
        report = public_outcome(result, entry)
        code = 0 if report["status"] == "complete" else 2
    except (StateError, APIRequestDeferred) as error:
        report = {"schema_version": 1, "kind": "icsot_recurring_outcome", "slug": entry["slug"],
                  "repository_id": entry["repository_id"], "slot": entry["slot"], "status": "paused",
                  "reason_code": getattr(error, "reason", type(error).__name__),
                  "retry_not_before_epoch": getattr(error, "retry_not_before", None),
                  "working_state_origin": entry["plan_status"],
                  "new_evidence_upload_bytes": transport.uploaded_bytes["evidence"],
                  "new_state_upload_bytes": transport.uploaded_bytes["state"],
                  "upload_byte_measurement": "attempted ciphertext bytes including uncertain remote writes",
                  "retained_generation_releases": sorted(transport._releases),
                  "state_pointer_outcome": "not confirmed; reconcile the authoritative pointer before retry",
                  "capture_completeness": "not_implied_by_paused_publication", "monthly_cap_enforced": False,
                  "recorded_at": utc_iso()}
        code = 75
    except Exception as error:
        report = {"schema_version": 1, "kind": "icsot_recurring_outcome", "slug": entry["slug"],
                  "repository_id": entry["repository_id"], "slot": entry["slot"], "status": "failed",
                  "reason_code": type(error).__name__, "capture_completeness": "not established",
                  "new_evidence_upload_bytes": transport.uploaded_bytes["evidence"],
                  "new_state_upload_bytes": transport.uploaded_bytes["state"],
                  "upload_byte_measurement": "attempted ciphertext bytes including uncertain remote writes",
                  "retained_generation_releases": sorted(transport._releases), "recorded_at": utc_iso()}
        code = 2
    report.update({key: plan[key] for key in ("execution_order_policy", "execution_order_seed_sha256",
                                            "execution_order_sha256", "execution_order_qualification") if key in plan})
    report["planned_execution_position"] = next(index for index, row in enumerate(plan["matrix"]["include"], 1)
                                                if row["slug"] == entry["slug"])
    write_once(args.output, canonical_json(report))
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
