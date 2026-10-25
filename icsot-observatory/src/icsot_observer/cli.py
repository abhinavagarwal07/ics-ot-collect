from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import verify_all
from .core import Config
from .derive import make_observations
from .diff import diff_latest
from .pipeline import collect_all


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="icsot-observe", description="Public GitHub research evidence collector")
    subs = ap.add_subparsers(dest="command", required=True)
    cc = subs.add_parser("collect", help="Collect timestamped public evidence")
    cc.add_argument("--config", required=True)
    cc.add_argument("--mode", choices=("events", "delta", "full"), default="delta")
    cc.add_argument("--deep-full", action="store_true", help="Expensive: fetch all per-issue/per-PR histories on full scan")
    cc.add_argument("--bundle-full", action="store_true", help="Expensive: preserve entire Git bundle in SHA-256 CAS, bound to OTS manifest")
    cc.add_argument("--no-stamp", action="store_true", help="Testing only; NO third-party timestamp evidence")
    vc = subs.add_parser("verify", help="Check manifests, object bytes, chain, and Git pins")
    vc.add_argument("--root", required=True)
    vc.add_argument("--check-ots", action="store_true", help="Verify completed Bitcoin attestations; pending = failure")
    vc.add_argument("--skip-git", action="store_true")
    dc = subs.add_parser("derive", help="Create an analysis CSV from original evidence")
    dc.add_argument("--root", required=True)
    dc.add_argument("--out", required=True)
    df = subs.add_parser("diff", help="Compare latest two complete metadata/Git runs; never interpret absence as deletion")
    df.add_argument("--root", required=True)
    df.add_argument("--repository-id", required=True, type=int)
    args = ap.parse_args(argv)
    if args.command == "collect":
        config = Config.load(args.config)
        result = collect_all(config, args.mode, deep_full=args.deep_full,
                             bundle_full=args.bundle_full, stamp=not args.no_stamp)
        print(json.dumps(result, indent=2))
        return 0 if all(r.get("status") == "complete" and r.get("attestation") == "pending_bitcoin_completion"
                        for r in result) or (args.no_stamp and all(r.get("status") == "complete" for r in result)) else 2
    if args.command == "verify":
        result = verify_all(Path(args.root), check_git=not args.skip_git, check_ots=args.check_ots)
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
