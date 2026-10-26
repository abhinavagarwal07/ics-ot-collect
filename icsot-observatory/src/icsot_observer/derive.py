from __future__ import annotations

import csv
import json
from pathlib import Path

from .core import ObjectStore, canonical_json, sha256


def make_observations(root: Path, destination: Path) -> dict:
    """Recomputable analytic index; raw manifests/objects are the sole evidence source."""
    store = ObjectStore(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = 0
    skipped_invalid_responses = []
    with destination.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=[
            "repository_id", "run_id", "run_status", "mode", "scope", "entity_id", "entity_number",
            "body_value_sha256", "raw_response_sha256", "api_url", "request_started_at", "request_completed_at",
            "github_created_at", "github_updated_at", "github_published_at", "raw_status"
        ])
        writer.writeheader()
        for path in sorted((root / "runs").glob("*/*.manifest.json")):
            man = json.loads(path.read_bytes())
            for response in man.get("responses", []):
                if response.get("status") != 200 or not response.get("body_sha256"):
                    continue
                purpose = response["purpose"]
                if purpose.endswith("_first_page_recheck"):
                    continue
                raw = store.get(response["body_sha256"])
                try:
                    obj = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    skipped_invalid_responses.append({
                        "repository_id": man["repository_id"], "run_id": man["run_id"],
                        "manifest": path.relative_to(root).as_posix(), "scope": purpose,
                        "raw_response_sha256": response["body_sha256"],
                        "reason": "invalid_text_encoding" if isinstance(error, UnicodeDecodeError) else "invalid_json",
                        "encoding": getattr(error, "encoding", None),
                    })
                    continue
                objects = obj if isinstance(obj, list) else [obj] if isinstance(obj, dict) else []
                for entry in objects:
                    if not isinstance(entry, dict):
                        continue
                    ent_id = entry.get("id", entry.get("sha", entry.get("ghsa_id", "")))
                    writer.writerow({
                        "repository_id": man["repository_id"], "run_id": man["run_id"],
                        "run_status": man["status"], "mode": man["mode"], "scope": purpose,
                        "entity_id": ent_id, "entity_number": entry.get("number", ""),
                        "body_value_sha256": sha256(canonical_json(entry)),
                        "raw_response_sha256": response["body_sha256"], "api_url": response["url"],
                        "request_started_at": response["request_started_at"],
                        "request_completed_at": response["request_completed_at"],
                        "github_created_at": entry.get("created_at", ""),
                        "github_updated_at": entry.get("updated_at", ""),
                        "github_published_at": entry.get("published_at", ""),
                        "raw_status": response["status"],
                    })
                    records += 1
    return {"records": records, "destination": str(destination),
            "skipped_invalid_response_count": len(skipped_invalid_responses),
            "skipped_invalid_responses": skipped_invalid_responses}
