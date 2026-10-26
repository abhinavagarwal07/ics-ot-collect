#!/usr/bin/env python3
"""Audit a sealed terminal corpus with explicit partials and bounded Git samples.

This leaves the strict 185-accepted watcher unchanged. The new request pins the
terminal inventory and prior metadata audit by exact byte identities. Only
explicitly selected small payloads are downloaded/restored in this pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from icsot_observer.core import canonical_json, sha256, utc_iso
from icsot_observer.corpus_audit import (
    Capture, GitHubReadOnly, audit_capture, asset_identity, identity, load_cohort, save_json,
)
from icsot_observer.localbudget import LocalBudget

MAX_INPUT_BYTES = 16 * 1024 * 1024


def pinned_json(reference: dict, workspace: Path) -> tuple[dict, bytes]:
    identity(reference)
    path = workspace / reference["file"]
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES or len(raw) != reference["bytes"] or sha256(raw) != reference["sha256"]:
        raise ValueError("Pinned local metadata bytes differ from the explicit terminal request")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Pinned terminal metadata must be a JSON object")
    return value, raw


def validate_terminal(request: dict, cohort, inventory: dict, summary: dict, detailed: dict) -> dict:
    tags = request["approved_release_tags"]
    rows = inventory.get("repositories", [])
    if (request.get("profile") != "sealed_terminal_with_declared_partials" or len(tags) != len(set(tags)) or
            inventory.get("release_tag") != tags[0] or inventory.get("parent_release_tags") != tags[1:] or
            tuple(row.get("repository") for row in rows) != cohort.repositories or
            any(inventory.get(key) != value for key, value in cohort.sources.items())):
        raise ValueError("Terminal inventory cohort/config/lineage differs from the explicit request")
    accepted = [row for row in rows if row.get("complete") is True]
    incomplete = [row for row in rows if row.get("complete") is not True]
    if (len(accepted) != request["expected_accepted"] or len(incomplete) != request["expected_incomplete"] or
            inventory.get("complete_repositories") != len(accepted) or
            inventory.get("incomplete_repositories") != len(incomplete) or
            inventory.get("complete") != (not incomplete)):
        raise ValueError("Declared accepted/incomplete counts differ from the sealed terminal request")
    if any(row.get("capture_accepted") is not True or row.get("errors") for row in accepted):
        raise ValueError("A selected accepted inventory row contradicts acceptance")
    for row in rows:
        identity({"sha256": row.get("index_sha256"), "bytes": 0})
        if row.get("source_release_tag", tags[0]) not in tags:
            raise ValueError("Unapproved direct source release")
        for ref in row.get("accepted_parent_references", []):
            if ref.get("source_release_tag") not in tags:
                raise ValueError("Unapproved retained parent reference")
    expected_accepted = {row["repository"] for row in accepted}
    expected_incomplete = {row["repository"] for row in incomplete}
    if (summary.get("accepted_count") != len(accepted) or summary.get("incomplete_count") != len(incomplete) or
            summary.get("missing_count") != 0 or detailed.get("accepted_count") != len(accepted) or
            detailed.get("incomplete_count") != len(incomplete) or detailed.get("missing_count") != 0 or
            {row["repository"] for row in detailed.get("accepted_targets", [])} != expected_accepted or
            {row["repository"] for row in detailed.get("incomplete_cases", [])} != expected_incomplete):
        raise ValueError("Pinned prior metadata audit disagrees with the complete 185-row inventory")
    if (summary.get("run", {}).get("status") != "completed" or summary["run"].get("head_sha") != inventory.get("collector_code_sha") or
            summary.get("source_inventory", {}).get("sha256") != request["sealed_inventory"]["sha256"]):
        raise ValueError("Prior terminal run/source identity differs from the sealed inventory")
    return {"cohort_count": len(rows), "accepted_count": len(accepted), "explicit_incomplete_count": len(incomplete),
            "missing_count": 0, "claim": "terminal accounted-for cohort; not 185 accepted or universally recoverable"}


def verify_seal(github, request, inventory) -> dict:
    seal = request["sealed_inventory"]
    release = github.json(f"repos/{github.repository}/releases/{int(seal['release_id'])}")
    asset = github.json(f"repos/{github.repository}/releases/assets/{int(seal['asset_id'])}")
    if (release.get("id") != seal["release_id"] or release.get("tag_name") != request["approved_release_tags"][0] or
            release.get("draft") is not False or release.get("target_commitish") != inventory["collector_code_sha"]):
        raise ValueError("Sealed terminal release is not published under the expected source identity")
    asset_identity(asset, seal)
    if asset.get("name") != "baseline-inventory.json" or asset.get("digest") != "sha256:" + seal["sha256"]:
        raise ValueError("Published terminal inventory has no matching remote SHA-256 identity")
    return {"observed_at": utc_iso(), "release_id": release["id"], "release_tag": release["tag_name"],
            "published_at": release.get("published_at"), "inventory_asset_id": asset["id"],
            "inventory_sha256": seal["sha256"], "inventory_bytes": seal["bytes"]}


def sample_capture(slug, github, inventory, detailed, cohort, request, budget, report_root):
    row = next(row for row in inventory["repositories"] if row["repository"] == slug)
    prior = next(row for row in detailed["accepted_targets"] + detailed["incomplete_cases"] if row["repository"] == slug)
    source_index = prior["index_asset"]
    asset = github.json(f"repos/{github.repository}/releases/assets/{int(source_index['id'])}")
    asset_identity(asset, source_index)
    index, raw = github.read_asset(asset)
    if (sha256(raw) != row["index_sha256"] or index.get("repository") != slug or
            index.get("release_tag") != prior["source_release_tag"] or index.get("collector_code_sha") != prior["source_commit_oid"] or
            any(index.get(key) != value for key, value in cohort.sources.items())):
        raise ValueError("Selected sample's actual source index differs from pinned prior evidence")
    manifests = index.get("manifests") or []
    bundle = manifests[0].get("portable_full_bundle") if len(manifests) == 1 else None
    if not bundle or bundle["bytes"] > request["maximum_sample_bundle_bytes"]:
        raise ValueError("Selected Git bundle exceeds the explicit bounded sample profile")
    parts = prior["ciphertext_parts"]
    if sum(part["bytes"] for part in parts) > request["maximum_sample_ciphertext_bytes"]:
        raise ValueError("Selected encrypted package exceeds the explicit bounded sample profile")
    assets = {}
    for part in parts:
        remote = github.json(f"repos/{github.repository}/releases/assets/{int(part['id'])}")
        asset_identity(remote, part)
        assets[remote["name"]] = remote
    mapping = {alias["plaintext"]["name"]: alias for alias in row.get("archive_transport_aliases", [])}
    migration_ref = None
    if mapping:
        migration_asset = github.json(f"repos/{github.repository}/releases/assets/{int(row['transport_index_asset_id'])}")
        if migration_asset.get("digest") != "sha256:" + row["transport_index_sha256"]:
            raise ValueError("Selected migration index no longer matches sealed transport reference")
        migration_ref = {"name": row["transport_index_asset"], "asset_id": row["transport_index_asset_id"],
                         "sha256": row["transport_index_sha256"], "bytes": migration_asset["size"]}
    reference = {"repository": github.repository, "release_tag": prior["source_release_tag"],
                 "name": source_index["name"], "asset_id": source_index["id"], "sha256": source_index["sha256"],
                 "bytes": source_index["bytes"], "collector_code_sha": prior["source_commit_oid"]}
    with budget.stage(len(raw), suffix=".index.json", purpose="retain selected public source index") as stage:
        with stage.open_writer() as target:
            target.write(raw)
        destination = report_root / "sources" / source_index["name"]
        destination.parent.mkdir(exist_ok=True, mode=0o700)
        os.replace(stage.path, destination)
    return Capture(slug, cohort.roles[slug], prior["source_release_tag"], reference, index, assets, mapping, migration_ref, selected=True)


def execute(request, *, minimum_stability_seconds=60):
    workspace, report_root = Path(request["workspace_root"]), Path(request["report_root"])
    budget = LocalBudget(request["budget_root"], roots=[workspace, report_root, Path(sys.prefix)])
    report_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cohort = load_cohort(Path(request["config"]), Path(request["csv"]))
    inventory, _ = pinned_json(request["sealed_inventory"], workspace)
    summary, _ = pinned_json(request["terminal_summary"], workspace)
    detailed, _ = pinned_json(request["terminal_detailed_audit"], workspace)
    coverage = validate_terminal(request, cohort, inventory, summary, detailed)
    github = GitHubReadOnly(request["repository"])
    first = verify_seal(github, request, inventory)
    save_json(report_root / "terminal-readiness.json", {"phase": "sealed_terminal_stabilizing", "coverage": coverage,
              "first_observation": first, "GPT_review": "pending_actual_review"}, budget)
    print(json.dumps({"phase": "sealed_terminal_stabilizing", **coverage}), flush=True)
    started = time.monotonic()
    while time.monotonic() - started < minimum_stability_seconds:
        time.sleep(min(10, minimum_stability_seconds - (time.monotonic() - started)))
    second = verify_seal(github, request, inventory)
    save_json(report_root / "terminal-readiness.json", {"phase": "sealed_terminal_ready_with_declared_partials", "coverage": coverage,
              "first_observation": first, "second_observation": second, "GPT_review": "pending_actual_review"}, budget)
    results = []
    for slug in request["samples"]:
        print(json.dumps({"phase": "bounded_sample", "repository": slug}), flush=True)
        capture = sample_capture(slug, github, inventory, detailed, cohort, request, budget, report_root)
        result = audit_capture(capture, github, budget, Path(request["private_key_path"]),
                               git_volume_bytes=request["git_volume_bytes"])
        result["selection_reason"] = request["sample_selection_reasons"][slug]
        save_json(report_root / (capture.key + ".sample.json"), result, budget)
        results.append(result)
    sampled = set(request["samples"])
    report = {"schema_version": 1, "profile": request["profile"], "mechanical_finished_at": utc_iso(), "coverage": coverage,
              "approved_release_tags": request["approved_release_tags"], "seal_observations": [first, second],
              "reused_metadata_evidence": {key: request[key] for key in ("sealed_inventory", "terminal_summary", "terminal_detailed_audit")},
              "sample_results": results, "incomplete_cases": detailed["incomplete_cases"],
              "payloads_not_downloaded_or_restored_in_this_pass": [row["repository"] for row in inventory["repositories"] if row["repository"] not in sampled],
              "prior_libfuse_check": request["prior_libfuse_check"], "retained_source_asset_bytes": summary["retained_asset_bytes"],
              "bitcoin_verification": "not_attempted_no_trusted_Bitcoin_node", "model_review": "pending_actual_review",
              "budget": budget.snapshot().as_dict(), "audit_tool_sha256": sha256(Path(__file__).read_bytes()),
              "limits": ["167 accepted and18 explicit incomplete targets are accounted for; not185 accepted",
                         "Prior full-cohort metadata audit is reused, not independently repeated",
                         "Only two new small packages are decrypted/stream-checked and Git-restored in this pass",
                         "All other payload and large Git recovery is untested/deferred here",
                         "Calendar receipts and Bitcoin attestations are not independently verified Bitcoin timestamps"]}
    save_json(report_root / "terminal-recovery-audit.json", report, budget)
    print(json.dumps({"phase": "mechanical_report_ready", "report": str(report_root / "terminal-recovery-audit.json"),
                      "sample_statuses": {row["repository"]: row["git_graph_verification"] for row in results},
                      "model_review": "pending_actual_review"}), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    options = parser.parse_args()
    with options.request.open("rb") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError("Audit request exceeds its explicit metadata bound")
    execute(json.loads(raw))
