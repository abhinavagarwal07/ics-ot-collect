from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import ObjectStore, canonical_json, sha256


def _entities(root: Path, manifest: dict, kind: str) -> dict[str, dict[str, Any]]:
    store = ObjectStore(root)
    ret: dict[str, dict[str, Any]] = {}
    for r in manifest.get("responses", []):
        if r.get("status") != 200 or r.get("purpose") != kind or not r.get("body_sha256"):
            continue
        data = json.loads(store.get(r["body_sha256"]))
        if not isinstance(data, list):
            continue
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("id"), int):
                ret[str(item["id"])] = {
                    "number": item.get("number"),
                    "source_created_at": item.get("created_at"),
                    "body": item.get("body"),
                    "title": item.get("title"),
                    "state": item.get("state"),
                    "sha256_of_complete_json": sha256(canonical_json(item)),
                    "observed_at": r.get("request_completed_at"),
                    "source": r.get("url"),
                }
    return ret


def diff_latest(root: Path, repo_id: int) -> dict[str, Any]:
    """Newly observed issues/PRs and ref changes, NOT proof of creation/deletion."""
    files = sorted((root / "runs" / str(repo_id)).glob("*.manifest.json"))
    if not files:
        raise ValueError(f"No evidence for repository id {repo_id}")
    mans = [json.loads(p.read_bytes()) for p in files]
    complete = [m for m in mans if m.get("status") == "complete" and m["mode"] != "events"]
    api_runs = [m for m in complete if m.get("lane") in (None, "api")]
    git_runs = [m for m in complete if m.get("lane") in (None, "git") and m.get("git")]
    if len(api_runs) < 2 and len(git_runs) < 2:
        raise ValueError("Require two completed observations in the same API or Git lane to compare")
    old, new = (api_runs if len(api_runs) >= 2 else git_runs)[-2:]
    out: dict[str, Any] = {"repository_id": repo_id,
        "old_run_id": old["run_id"], "new_run_id": new["run_id"],
        "qualification": "Newly observed since earlier captured runs; not necessarily first created, first public, or exhaustively detected.",
        "entity_types": {},
        "api_comparison": {"old_run_id": api_runs[-2]["run_id"], "new_run_id": api_runs[-1]["run_id"]}
                          if len(api_runs) >= 2 else None,
        "git_comparison": {"old_run_id": git_runs[-2]["run_id"], "new_run_id": git_runs[-1]["run_id"]}
                          if len(git_runs) >= 2 else None}
    prior = [m for m in mans if m["run_id"] < new["run_id"] and m.get("lane") in (None, "api")]
    for typ in ("issues", "pulls") if len(api_runs) >= 2 else ():
        before_seen: dict[str, dict] = {}
        for m in prior:
            before_seen.update(_entities(root, m, typ))
        now = _entities(root, new, typ)
        out["entity_types"][typ] = {
            "newly_observed": [dict(id=k, **v) for k, v in now.items() if k not in before_seen],
            "representation_changed": [dict(id=k, previous_sha256=before_seen[k]["sha256_of_complete_json"],
                                            **v) for k, v in now.items()
                                       if k in before_seen and v["sha256_of_complete_json"] != before_seen[k]["sha256_of_complete_json"]],
            "current_scope_count": len(now),
            "warning": "A changed complete JSON representation may reflect counts, label changes or other metadata, not a text edit. Missing from a delta result is NOT deletion.",
        }
    git_old, git_new = git_runs[-2:] if len(git_runs) >= 2 else ({}, {})
    a = {e["published_ref"]: e["object_id"] for e in (git_old.get("git") or {}).get("advertised_refs", [])}
    b = {e["published_ref"]: e["object_id"] for e in (git_new.get("git") or {}).get("advertised_refs", [])}
    out["git_refs"] = {
        "added": [{"ref": ref, "new_sha": b[ref]} for ref in sorted(set(b) - set(a))],
        "not_advertised_now": [{"ref": ref, "prior_sha": a[ref]} for ref in sorted(set(a) - set(b))],
        "moved": [{"ref": ref, "prior_sha": a[ref], "new_sha": b[ref]}
                  for ref in sorted(set(a) & set(b)) if a[ref] != b[ref]],
        "note": "Git refs show what was advertised at each collection interval, not time of commit authorship or universal first public visibility.",
        "comparison_available": len(git_runs) >= 2,
    }
    return out
