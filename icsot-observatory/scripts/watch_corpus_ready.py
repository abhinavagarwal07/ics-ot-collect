#!/usr/bin/env python3
"""Persistently wait for the explicitly approved cohort, then audit it once.

This is a local read-only observer.  It never dispatches Actions or starts an
AI session, and never moves private key material off the local machine.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from icsot_observer.core import canonical_json, sha256, utc_iso
from icsot_observer.corpus_audit import (
    GitHubReadOnly, load_cohort, readiness_snapshot, run_audit, save_json,
)
from icsot_observer.localbudget import LocalBudget


def observe_stability(previous: dict, snapshot: dict, *, now: float, stable_seconds: float) -> dict:
    fingerprint = {key: snapshot[key] for key in ("repository", "release_tag", "release_id", "run_id", "inventory_sha256")}
    if previous.get("fingerprint") == fingerprint:
        first = previous["first_seen_unix"]
        count = previous.get("observations", 1) + 1
    else:
        first, count = now, 1
    return {"fingerprint": fingerprint, "first_seen_unix": first, "last_seen_unix": now,
            "observations": count, "stable": count >= 2 and now - first >= stable_seconds}


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    package = root / "icsot-observatory"
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True)
    result.add_argument("--approved-release-tag", action="append", required=True,
                        help="Exact approved lineage, final release first, then ordered explicit parent releases")
    result.add_argument("--private-key", type=Path, help="Local existing codec key path; mandatory for actual audit")
    result.add_argument("--workspace-root", type=Path, default=root)
    result.add_argument("--budget-root", type=Path, default=root / "analysis/local-data-budget")
    result.add_argument("--report-root", type=Path, default=root / "analysis/recovery-audit")
    result.add_argument("--config", type=Path, default=package / "config.corpus.toml")
    result.add_argument("--csv", type=Path, default=root / "public_patch_corpus_185.csv")
    result.add_argument("--poll-seconds", type=float, default=60)
    result.add_argument("--stable-seconds", type=float, default=60)
    result.add_argument("--spot-count", type=int, default=12)
    result.add_argument("--check-only", action="store_true", help="One bounded metadata-only readiness check; no payloads")
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if not 10 <= args.poll_seconds <= 3600 or args.stable_seconds < 0 or not 0 <= args.spot_count <= 64:
        raise ValueError("Invalid polling, stability, or sample bounds")
    if not args.check_only and args.private_key is None:
        raise ValueError("An existing local private-key path is required to execute the audit")
    tags = tuple(args.approved_release_tag)
    cohort = load_cohort(args.config, args.csv)
    budget = LocalBudget(args.budget_root, roots=[args.workspace_root, args.report_root, Path(sys.prefix)])
    args.report_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path, state_path = args.report_root / "watcher.lock", args.report_root / "watcher-state.json"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("An audit watcher already owns this report directory") from None
        previous = json.loads(state_path.read_bytes()) if state_path.exists() else {}
        request = {"repository": args.repository, "approved_release_tags": list(tags), "sources": cohort.sources,
                   "spot_count": args.spot_count}
        if previous and previous.get("request") != request:
            raise ValueError("Existing watcher state belongs to a different explicitly approved request")
        if previous.get("phase") == "mechanical_audit_complete":
            report = args.report_root / "recovery-audit.json"
            if not report.is_file() or sha256(report.read_bytes()) != previous.get("report_sha256"):
                raise ValueError("Completed audit report is missing or differs from the completion marker")
            print(json.dumps({"phase": previous["phase"], "already_completed": True,
                              "report": str(report), "GPT_review": "pending_root_review"}), flush=True)
            return 0
        github = GitHubReadOnly(args.repository)
        stopping = False
        def stop(signum, frame):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not stopping:
            budget.check()
            state = {"schema_version": 1, "request": request, "observed_at": utc_iso()}
            try:
                snapshot = readiness_snapshot(github, cohort, tags)
                stability = observe_stability(previous.get("stability", {}), snapshot, now=time.time(),
                                               stable_seconds=args.stable_seconds)
                state.update(phase="ready_stabilizing", stability=stability,
                             snapshot={key: value for key, value in snapshot.items() if key != "inventory"})
            except (KeyError, ValueError, RuntimeError, OSError) as error:
                state.update(phase="waiting_for_complete_cohort", reason=f"{type(error).__name__}: {error}")
                save_json(state_path, state, budget)
                print(json.dumps({"at": state["observed_at"], "phase": state["phase"], "reason": state["reason"]}), flush=True)
                if args.check_only:
                    return 3
                previous = state
                time.sleep(args.poll_seconds)
                continue
            save_json(state_path, state, budget)
            print(json.dumps({"at": state["observed_at"], "phase": state["phase"],
                              "inventory_sha256": snapshot["inventory_sha256"], "stable": stability["stable"]}), flush=True)
            if args.check_only:
                return 0
            if stability["stable"]:
                state.update(phase="auditing", audit_started_at=utc_iso())
                save_json(state_path, state, budget)
                # No private-key contents are read here; only the existing
                # authenticated codec receives the local key path.
                report = run_audit(github, cohort, snapshot, tags, budget,
                                   args.private_key.expanduser().resolve(), args.report_root, spot_count=args.spot_count)
                if report.get("audit_complete") is not True:
                    state.update(phase="audit_retry_wait", reason="Some indexed payload GETs were unavailable; completed capture checkpoints retained")
                    save_json(state_path, state, budget)
                    previous = state
                    time.sleep(args.poll_seconds)
                    continue
                raw = canonical_json(report)
                state.update(phase="mechanical_audit_complete", audit_finished_at=utc_iso(), report_sha256=sha256(raw),
                             GPT_review="pending_root_review")
                save_json(state_path, state, budget)
                print(json.dumps({"phase": state["phase"], "report": str(args.report_root / "recovery-audit.json"),
                                  "GPT_review": "pending_root_review"}), flush=True)
                return 0
            previous = state
            time.sleep(args.poll_seconds)
    return 130


if __name__ == "__main__":
    raise SystemExit(main())
