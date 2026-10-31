"""Explicit, metadata-only runner for one authenticated state compaction."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import github_state
from .core import REPO_RE, canonical_json, utc_iso
from .github_state import GhCliStateTransport, GitHubStateStore, StateConflictError, StateDeferredError, StateError
from .runtime import ControllerLock

MAX_RESTORED = 2 * 1024 ** 3
MAX_INPUT = 512 * 1024 ** 2
MAX_PARTS = 128
MAX_UPLOAD = 544 * 1024 ** 2
MIN_SAVINGS = 16
MAX_RUNTIME = 1800
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CODE_SHA = re.compile(r"[0-9a-f]{40}\Z")


def digest(value: dict) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()



def safe_integrity_detail(detail: object) -> dict | None:
    """Return only the bounded verifier contract; never copy exception text."""
    if not isinstance(detail, dict):
        return None
    stage, subject, field = (detail.get(key) for key in ("stage", "subject", "field"))
    if not isinstance(stage, str) or stage not in {"asset_download", "part_decode", "file_reconstruction", "group_verification", "tar_member"}:
        return None
    if not isinstance(subject, str):
        return None
    token = re.fullmatch(r"(?:asset|part|path-sha256):[0-9a-f]{64}", subject)
    path = (re.fullmatch(r"[A-Za-z0-9._/ -]{1,256}", subject)
            and not subject.startswith("/")
            and all(part not in ("", ".", "..") for part in subject.split("/")))
    if not (token or path):
        return None
    expected, actual = detail.get("expected"), detail.get("actual")
    if field == "sha256":
        if not all(isinstance(value, str) and _SHA256.fullmatch(value) for value in (expected, actual)):
            return None
    elif field == "bytes":
        if not all(type(value) is int and 0 <= value <= 2**63 - 1 for value in (expected, actual)):
            return None
    else:
        return None
    return {"stage": stage, "subject": subject, "field": field, "expected": expected, "actual": actual}


def inspect_pointer(transport, repository_id: int, slug: str, original_sha: str | None,
                    candidate_sha: str | None) -> dict:
    """One bounded, read-only selector inspection after an unsuccessful attempt."""
    probe = transport
    if isinstance(transport, GhCliStateTransport):
        def bounded_runner(*args, **kwargs):
            return subprocess.run(*args, **kwargs, timeout=15)
        probe = GhCliStateTransport(transport.repository, runner=bounded_runner,
                                    rate_reserve=transport.rate_reserve, transient_retries=0)
        transport.copy_runtime_state_to(probe)
    try:
        head = probe.branch_head()
        raw = probe.read_pointer(head, repository_id) if head else None
        if raw is None:
            return {"pointer_inspection": "missing", "publication": "unknown"}
        if not isinstance(raw, bytes) or len(raw) > 65536:
            raise ValueError("Invalid pointer metadata")
        pointer = json.loads(raw)
        if (not isinstance(pointer, dict) or canonical_json(pointer) != raw or
                pointer.get("repository_id") != repository_id or pointer.get("slug") != slug):
            raise ValueError("Invalid selected pointer metadata")
        index_sha = pointer.get("index", {}).get("ciphertext_sha256")
        if not isinstance(index_sha, str) or not _SHA256.fullmatch(index_sha):
            raise ValueError("Invalid pointer index metadata")
        observed = hashlib.sha256(raw).hexdigest()
        publication = "unknown"
        if original_sha is not None and observed == original_sha:
            publication = "unchanged_at_check"
        elif candidate_sha is not None and observed == candidate_sha:
            publication = "confirmed"
        return {"pointer_inspection": "observed", "publication": publication,
                "publication_confirmation_scope": "pointer_digest_only",
                "observed_pointer_sha256": observed, "observed_index_ciphertext_sha256": index_sha}
    except StateDeferredError:
        return {"pointer_inspection": "unavailable", "inspection_failure_category": "rate_or_headroom",
                "publication": "unknown"}
    except subprocess.TimeoutExpired:
        return {"pointer_inspection": "unavailable", "inspection_failure_category": "timeout",
                "publication": "unknown"}
    except Exception:
        return {"pointer_inspection": "unavailable", "inspection_failure_category": "read_failed",
                "publication": "unknown"}
    finally:
        if probe is not transport:
            probe.copy_runtime_state_to(transport)

def execute(*, repository_id: int, slug: str, destination: str, expected_pointer_sha256: str,
            code_sha: str, public_key: Path, private_key: Path, root: Path,
            expected_index_sha256: str = "",
            transport=None, store_factory=GitHubStateStore) -> dict:
    """Run against a newly created root; caller persists the returned metadata.

    The root path is part of the authenticated state identity. Only remove a
    directory created exclusively by this invocation. Never capture upstream.
    """
    from .exclusions import require_collection_repository

    require_collection_repository(slug)
    if (type(repository_id) is not int or repository_id < 1 or not REPO_RE.fullmatch(slug)
            or not REPO_RE.fullmatch(destination) or not _SHA256.fullmatch(expected_pointer_sha256)
            or not _CODE_SHA.fullmatch(code_sha)
            or (expected_index_sha256 and not _SHA256.fullmatch(expected_index_sha256))):
        raise ValueError("Invalid selected identity or SHA")
    plan = {"repository_id": repository_id, "slug": slug, "destination_repository": destination,
            "expected_pointer_sha256": expected_pointer_sha256, "expected_index_sha256": expected_index_sha256 or None,
            "code_sha": code_sha,
            "max_restored_bytes": MAX_RESTORED, "max_input_bytes": MAX_INPUT,
            "max_input_parts": MAX_PARTS, "max_upload_bytes": MAX_UPLOAD,
            "min_part_savings": MIN_SAVINGS, "max_runtime_seconds": MAX_RUNTIME}
    report = {"schema_version": 1, **plan, "plan_sha256": digest(plan), "status": "failed",
              "started_at": utc_iso(), "baseline_evidence_bytes": 0, "new_observations": 0,
              "fresh_remote_reconstruction": "not_completed", "publication": "unknown"}
    started = time.monotonic()
    root = Path(root)
    owned_root = False
    store = None
    transport = transport or GhCliStateTransport(destination)
    try:
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700)
        owned_root = True
        store = store_factory(transport, repository_id=repository_id, slug=slug, public_key=public_key,
                              private_key=private_key, logical_root=root)
        with ControllerLock(root):
            selection = store.read()
            if selection.pointer is None or selection.index is None:
                raise StateError("Authenticated existing state required")
            old_sha = digest(selection.pointer)
            report["old_pointer_sha256"] = old_sha
            old_index_sha = selection.pointer["index"]["ciphertext_sha256"]
            report["old_index_ciphertext_sha256"] = old_index_sha
            if old_sha != expected_pointer_sha256 or (expected_index_sha256 and old_index_sha != expected_index_sha256):
                raise StateConflictError("Reviewed pointer differs")
            index = selection.index
            restored_bytes = sum(item["bytes"] for item in index["files"])
            report.update({"restored_state_bytes": restored_bytes,
                           "before_parts": len(index["parts"]),
                           "before_part_ciphertext_bytes": sum(ref["ciphertext_bytes"] for ref in index["parts"].values())})
            if restored_bytes > MAX_RESTORED:
                raise StateDeferredError("Restored state exceeds hosted bound", reason="restored_state_limit")
            restored = store.restore(selection)
            if not restored.get("restored"):
                raise StateError("State was not restored")
            report["initial_restore_verified"] = True
            result = store.compact(selection, max_input_bytes=MAX_INPUT, max_input_parts=MAX_PARTS,
                                   max_upload_bytes=MAX_UPLOAD, min_part_savings=MIN_SAVINGS,
                                   max_runtime_seconds=MAX_RUNTIME, quiescent=True)
            if result.get("status") not in ("no_op", "complete"):
                raise StateError("Unexpected compaction outcome")
            for key in ("input_parts", "input_bytes", "part_savings", "state_uploaded_ciphertext_bytes",
                        "compaction_peak_additional_disk_bytes_estimate", "after_part_count",
                        "after_referenced_part_ciphertext_bytes", "estimated_api_requests", "pointer_commit",
                        "verification_scope", "predecessor_snapshot_started_at", "predecessor_snapshot_sealed_at",
                        "snapshot_started_at", "snapshot_sealed_at"):
                if key in result:
                    report[key] = result[key]
            if result["status"] == "complete":
                report["publication"] = "confirmed"
                report["new_pointer_sha256"] = digest(result["pointer"])
                report["new_index_ciphertext_sha256"] = result["pointer"]["index"]["ciphertext_sha256"]
                if not result.get("full_remote_reconstruction_verified"):
                    raise StateError("Fresh remote reconstruction was not verified")
                report["after_parts"] = result["after_part_count"]
                report["after_part_ciphertext_bytes"] = result["after_referenced_part_ciphertext_bytes"]
                report["fresh_remote_reconstruction"] = "verified"
                report["status"] = "complete"
                report["publication"] = "confirmed"
            else:
                report.update({"status": "no_op", "new_pointer_sha256": old_sha, "after_parts": report["before_parts"],
                               "after_part_ciphertext_bytes": report["before_part_ciphertext_bytes"],
                               "state_uploaded_ciphertext_bytes": 0,
                               "fresh_remote_reconstruction": "not_required_no_op",
                               "new_index_ciphertext_sha256": old_index_sha, "publication": "unchanged_at_check"})
    except github_state.StateIntegrityError as exc:
        report.update(status="failed", failure_category="integrity_error")
        detail = safe_integrity_detail(exc.detail)
        if detail is not None:
            report["integrity"] = detail
    except StateDeferredError as exc:
        report.update(status="deferred", failure_category=exc.reason if re.fullmatch(r"[a-z0-9_]{1,64}", exc.reason) else "deferred")
    except StateConflictError:
        report.update(status="failed", failure_category="pointer_conflict")
    except (StateError, ValueError, OSError):
        report.update(status="failed", failure_category="state_or_io_error")
    except Exception:
        report.update(status="failed", failure_category="unexpected_error")
    finally:
        if report["status"] not in ("complete", "no_op"):
            report.update(inspect_pointer(transport, repository_id, slug, report.get("old_pointer_sha256"),
                                          getattr(store, "compaction_candidate_pointer_sha256", None)))
        if owned_root:
            try:
                shutil.rmtree(root)
                report["cleanup"] = "complete"
            except OSError:
                report["cleanup"] = "failed"
                report["status"] = "failed"
        report["ended_at"] = utc_iso()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["api_requests"] = getattr(transport, "request_count", 0)
        report["graphql_requests"] = getattr(transport, "graphql_request_count", 0)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-id", type=int, required=True)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--destination-repository", required=True)
    parser.add_argument("--expected-pointer-sha256", required=True)
    parser.add_argument("--code-sha", required=True)
    parser.add_argument("--expected-index-sha256", default="")
    parser.add_argument("--state-public-key", type=Path, required=True)
    parser.add_argument("--state-private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = execute(repository_id=args.repository_id, slug=args.slug, destination=args.destination_repository,
                         expected_pointer_sha256=args.expected_pointer_sha256, code_sha=args.code_sha, expected_index_sha256=args.expected_index_sha256,
                         public_key=args.state_public_key, private_key=args.state_private_key,
                         root=Path("/tmp/icsot-persistent-state") / str(args.repository_id))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(result))
        print(json.dumps({"status": result["status"], "plan_sha256": result["plan_sha256"]}))
        return 0 if result["status"] in ("complete", "no_op") else 1
    except (ValueError, OSError):
        print("Invalid input or could not write metadata outcome", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
