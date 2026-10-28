from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .checks import verify_all
from .core import Config, sha256, utc_iso
from .derive import make_observations
from .diff import diff_latest
from .pipeline import collect_all, restore_mirrors, run_github_persistent, run_persistent
from .encryption import encrypt_file, decrypt_file


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="icsot-observe", description="Public GitHub research evidence collector")
    subs = ap.add_subparsers(dest="command", required=True)
    cc = subs.add_parser("collect", help="Collect timestamped public evidence")
    cc.add_argument("--config", required=True)
    cc.add_argument("--mode", choices=("events", "delta", "full"), default="delta")
    cc.add_argument("--deep-full", action="store_true", help="Expensive: fetch all per-issue/per-PR histories on full scan")
    cc.add_argument("--bundle-full", action="store_true", help="Expensive: preserve entire Git bundle in SHA-256 CAS, bound to OTS manifest")
    cc.add_argument("--no-stamp", action="store_true", help="Testing only; NO third-party timestamp evidence")
    pc = subs.add_parser("persistent", aliases=["run"], help="Run durable independent API and incremental Git lanes")
    pc.add_argument("--config", required=True)
    pc.add_argument("--once", action="store_true", help="Enqueue current interval, drain ready jobs, then exit")
    pc.add_argument("--api-workers", type=int, default=1)
    pc.add_argument("--git-workers", type=int, default=2)
    pc.add_argument("--api-interval-seconds", type=int, default=21600)
    pc.add_argument("--git-interval-seconds", type=int, default=21600)
    pc.add_argument("--poll-interval-seconds", type=float, default=30)
    pc.add_argument("--deep-full", action="store_true", help="Resume per-item historical API scopes as well as listings")
    pc.add_argument("--read-token-env", help="Environment variable containing the API read credential")
    pc.add_argument("--export-directory", type=Path, help="Create encrypted incremental transfer packages here")
    pc.add_argument("--public-key", type=Path, help="RSA public recipient required with --export-directory")
    pc.add_argument("--no-stamp", action="store_true", help="Testing: disable OpenTimestamps submission")
    gc = subs.add_parser("github-run", help="One selected repository using authenticated encrypted GitHub working state")
    gc.add_argument("--config", required=True, type=Path)
    gc.add_argument("--slug", required=True)
    gc.add_argument("--repository-id", required=True, type=int)
    gc.add_argument("--destination-repository", required=True)
    gc.add_argument("--state-public-key", required=True, type=Path)
    gc.add_argument("--state-private-key", required=True, type=Path)
    gc.add_argument("--evidence-public-key", required=True, type=Path)
    gc.add_argument("--code-sha", required=True)
    gc.add_argument("--observation-key", help="Stable ID for an idempotent manually requested observation")
    gc.add_argument("--deep-full", action="store_true")
    gc.add_argument("--no-stamp", action="store_true", help="Testing: disable OpenTimestamps submission")
    for parser in (pc, gc):
        parser.add_argument("--freetsa", action="store_true", help="Also request a FreeTSA RFC 3161 proof using the bundled pinned root")
        parser.add_argument("--rfc3161-url", help="Optional RFC 3161 TSA endpoint; only a digest is submitted")
        parser.add_argument("--rfc3161-ca", type=Path, help="Explicit trusted CA PEM for RFC 3161 verification")
        parser.add_argument("--rfc3161-chain", type=Path, help="Optional intermediate certificate PEM for RFC 3161 verification")
    vc = subs.add_parser("verify", help="Check manifests, object bytes, chain, and Git pins")
    vc.add_argument("--root", required=True)
    vc.add_argument("--check-ots", action="store_true", help="Verify completed Bitcoin attestations; pending = failure")
    vc.add_argument("--skip-git", action="store_true")
    rc = subs.add_parser("restore", help="Offline: rebuild omitted Git mirrors from full or incremental CAS archives")
    rc.add_argument("--root", required=True, type=Path)
    dc = subs.add_parser("derive", help="Create an analysis CSV from original evidence")
    dc.add_argument("--root", required=True)
    dc.add_argument("--out", required=True)
    df = subs.add_parser("diff", help="Compare latest two complete metadata/Git runs; never interpret absence as deletion")
    df.add_argument("--root", required=True)
    df.add_argument("--repository-id", required=True, type=int)
    for command in ("encrypt", "decrypt"):
        crypto = subs.add_parser(command, help=f"{command.capitalize()} an archive using an RSA recipient key")
        crypto.add_argument("--input", required=True)
        crypto.add_argument("--output", required=True)
        crypto.add_argument("--public-key" if command == "encrypt" else "--private-key", required=True)
    args = ap.parse_args(argv)
    if args.command == "encrypt":
        print(json.dumps(encrypt_file(args.input, args.output, args.public_key), indent=2))
        return 0
    if args.command == "decrypt":
        print(json.dumps(decrypt_file(args.input, args.output, args.private_key), indent=2))
        return 0
    if args.command == "collect":
        config = Config.load(args.config)
        result = collect_all(config, args.mode, deep_full=args.deep_full,
                             bundle_full=args.bundle_full, stamp=not args.no_stamp)
        print(json.dumps(result, indent=2))
        return 0 if all(r.get("status") == "complete" and r.get("attestation") == "pending_bitcoin_completion"
                        for r in result) or (args.no_stamp and all(r.get("status") == "complete" for r in result)) else 2
    if args.command in ("persistent", "run"):
        config = Config.load(args.config)
        if args.read_token_env:
            config = replace(config, token_env=args.read_token_env)
        try:
            result = run_persistent(config, once=args.once, api_workers=args.api_workers,
                                    git_workers=args.git_workers,
                                    api_interval_seconds=args.api_interval_seconds,
                                    git_interval_seconds=args.git_interval_seconds,
                                    poll_interval_seconds=args.poll_interval_seconds,
                                    deep_full=args.deep_full, stamp=not args.no_stamp,
                                    export_directory=args.export_directory, public_key=args.public_key,
                                    rfc3161_url=args.rfc3161_url, rfc3161_ca=args.rfc3161_ca, rfc3161_chain=args.rfc3161_chain,
                                    freetsa=args.freetsa)
        except KeyboardInterrupt:
            return 130
        print(json.dumps(result, indent=2))
        return 0 if result.get("current_observation", {}).get("status", "complete") == "complete" and not result["partial_captures"] and not any(
            count for state, count in result["queue"]["states"].items() if state != "complete") else 2
    if args.command == "github-run":
        from .github_state import StateDeferredError
        try:
            result = run_github_persistent(Config.load(args.config), slug=args.slug, repository_id=args.repository_id,
                                           destination_repository=args.destination_repository,
                                           state_public_key=args.state_public_key, state_private_key=args.state_private_key,
                                           evidence_public_key=args.evidence_public_key, code_sha=args.code_sha,
                                           config_source_sha256=sha256(args.config.read_bytes()),
                                           observation_key=args.observation_key, deep_full=args.deep_full,
                                           stamp=not args.no_stamp, rfc3161_url=args.rfc3161_url,
                                           rfc3161_ca=args.rfc3161_ca, rfc3161_chain=args.rfc3161_chain, freetsa=args.freetsa)
        except StateDeferredError as error:
            deadline = None
            if error.retry_not_before is not None:
                try:
                    deadline = utc_iso(datetime.fromtimestamp(error.retry_not_before, timezone.utc))
                except (OverflowError, OSError, ValueError):
                    pass
            print(json.dumps({"status": "deferred", "retry_not_before": deadline,
                              "retry_not_before_epoch": error.retry_not_before, "reason": error.reason,
                              "destination_github_api_requests": error.request_count,
                              "remote_state_publication": "not_confirmed; reconcile authoritative pointer on retry",
                              "capture_completeness": "not_implied_by_destination_api_deferral"}, indent=2))
            return 75
        print(json.dumps(result, indent=2))
        collection = result["collection"]
        return 0 if collection.get("current_observation", {}).get("status", "complete") == "complete" and not collection["partial_captures"] and not any(
            count for state, count in collection["queue"]["states"].items() if state != "complete") else 2
    if args.command == "verify":
        result = verify_all(Path(args.root), check_git=not args.skip_git, check_ots=args.check_ots)
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 3
    if args.command == "restore":
        result = restore_mirrors(args.root)
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 3
    if args.command == "diff":
        print(json.dumps(diff_latest(Path(args.root), args.repository_id), indent=2))
        return 0
    if args.command == "derive":
        result = make_observations(Path(args.root), Path(args.out))
        print(json.dumps(result, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
