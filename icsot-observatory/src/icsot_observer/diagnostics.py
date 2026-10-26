"""Bounded metadata-only debug events, independent of immutable evidence.

Activate one context around a capture. Unknown fields and unsafe values are
omitted; exception messages, payloads, query strings and locals are never emitted.
"""
from __future__ import annotations

import contextlib
import contextvars
import atexit
import json
import math
import os
import re
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

_EVENTS = frozenset((
    "capture_start", "capture_end", "capture_failure", "stage_start", "stage_end", "stage_heartbeat", "exception",
    "transfer_retry", "plan_start", "plan_end", "finalize_start", "finalize_end", "finalize_target",
    "scope_outcome", "scientific_outcome", "scientific_failure", "summary_write_failed",
    "asset_uploaded", "asset_upload_start", "diagnostic_summary",
    "api_request_start", "api_request_end", "api_request_retry", "api_decode_retry",
    "api_rate_reserve", "api_rate_wait_start", "api_rate_wait_end", "api_rate_wait_heartbeat",
    "api_pagination_page", "api_pagination_check", "api_pagination_restart",
    "api_scope_start", "api_scope_end", "api_scope_unavailable", "api_scope_failure",
))
_CREDENTIAL = re.compile(r"(?:gh[pousr]_|github_pat_|bearer|private.?key|authorization)", re.I)
_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,79}\Z")
_PYTHON_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")
_PUBLIC_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\Z")
_SLUG = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_SCOPE = re.compile(r"(?:repository_identity|repository_metadata|issues|pulls|issue_comments|review_comments|releases|tags|events|deep_issue_timeline|deep_pull_details|(?:issue_timeline|pull_detail|pull_reviews|pull_commits|pull_files):[1-9][0-9]*)(?:_first_page_recheck|_resume_first_page_validation)?\Z")
_ENDPOINT = re.compile(r"/(?:repos/\{owner\}/\{repo\}|repositories/\{repository_id\})(?:/(?:issues|pulls|comments|reviews|commits|files|timeline|releases|tags|events|\{number\}))*\Z")
_HASH = re.compile(r"[0-9a-f]{8,64}\Z")
_CATEGORIES = frozenset(("collection_error", "http_error", "upstream_http_502", "timeout", "io_error",
    "invalid_json", "response_cap", "pagination_drift", "pagination_membership", "pagination_order",
    "pagination_cursor", "pagination_duplicate", "pagination_unknown_identity", "git_ref_churn",
    "primary_reserve_future_reset", "primary_reserve_wait_budget", "expired_reset_cleared",
    "primary_rate_limit", "secondary_rate_limit", "rate_limit", "checkpoint_invalid", "unavailable",
    "request_failed", "stage_failed", "verification_failed", "encryption_failed", "upload_failed",
    "proof_failed", "interrupted", "budget_refused"))
_STAGES = frozenset(("preflight", "collection", "verification", "evidence_inspection", "archive", "encryption",
    "archive_upload", "proof_publication", "proof_receipt", "index_upload", "inventory", "finalization",
    "entrypoint", "github_cli", "asset_upload", "git_capture_and_bundle", "timestamp_request", "timestamp_receipt",
    "diagnostic_heartbeat", "scientific_diagnostics", "scientific", "api", "git", "upload", "plan", "finalize", "capture",
    "plan_selection", "collector_report", "capture_outcome_report", "index_write", "index_digest_diagnostic", "unknown"))
_STATUSES = frozenset(("unknown", "not_run", "not_verified", "not_collected", "ok", "success", "failed", "error",
    "complete", "partial", "incomplete", "unavailable", "verified", "unverified", "passed", "encrypted", "uploaded",
    "pending", "disabled", "unexpected_error", "identity_error", "waiting_primary_reset", "planned", "accepted",
    "reconcile_before_retry", "reused_verified", "pending_bitcoin_completion", "submission_failed", "publication_failed",
    "failed_before_terminal_index", "incomplete_or_failed", "complete_for_declared_shallow_baseline", "captured", "returned",
    "reused_pending_bitcoin_completion", "invalid_receipt", "client_unavailable", "receipt_missing", "published",
    "complete_for_query", "complete_for_requested_items", "complete_for_enumerated_items", "complete_for_enumerated_issues",
    "complete_for_enumerated_pulls", "NOT_COLLECTED", "NOT_REQUESTED", "partial_drift", "checkpoint_invalid", "not_attempted",
    "capped", "deferred", "network_error", "retry", "exhausted", "interrupted", "finished",
    "archive_verified_mirror_unverified"))
_VOCABULARIES = {
    "stage": _STAGES,
    "reason": frozenset(("unknown", "expired_reset_cleared", "network_error", "primary_rate_reset", "secondary_rate_limit",
        "upstream_transient", "cursor_loop", "duplicate_id", "updated_boundary", "next_link", "link_end",
        "membership_changed", "order_changed", "cursor_changed", "representation_changed", "reset_unknown",
        "repository_pull_requests_disabled", "repository_issues_and_pull_requests_disabled", "checkpoint_reuse")),
    "decision": frozenset(("unknown", "defer", "clear_expired", "refuse_wait_budget", "retry", "restart", "exhausted", "wait", "continue")),
    "rate_kind": frozenset(("unknown", "primary", "primary_reserve", "secondary", "server", "network")),
    "asset_id_reason": frozenset(("unknown", "not_returned", "not_probed")),
    "validation": frozenset(("unknown", "ordered_identity_and_next_cursor", "exact_object")),
}
_CURRENT: contextvars.ContextVar[DiagnosticLogger | None] = contextvars.ContextVar("icsot_diagnostics", default=None)

_NUMBERS = frozenset((
    "repository_id", "github_run_id", "github_run_attempt", "attempt", "max_attempts", "page",
    "traversal_attempt", "decode_attempt", "status_code", "returncode", "signal", "part_ordinal",
    "part_count", "bytes", "body_bytes", "asset_id", "count", "pages", "first_count", "check_count",
    "first_difference", "remaining", "limit", "reset", "reserve", "wait_seconds", "elapsed_seconds",
    "wait_used_seconds", "wait_allowance_seconds", "wait_available_seconds", "retry_not_before",
    "primary_wait_used_seconds", "primary_wait_allowance_seconds", "secondary_wait_used_seconds",
    "secondary_wait_allowance_seconds", "scope_attempt", "request_count",
    "reused_count", "remaining_count", "max_parallel", "git_refs_verified", "git_repositories_verified",
    "portable_git_bundles_verified", "raw_observations", "partial_runs",
))
_BOOLS = frozenset(("matches", "membership_changed", "order_changed", "cursor_changed",
                    "identity_comparable", "representation_changed", "reused_from_checkpoint", "deferred",
                    "duplicate_detected"))
_CODES = frozenset(("stage", "status", "capture_status", "scientific_status", "verification_status",
    "git_status", "archive_status", "encryption_status", "upload_status", "proof_status",
    "failure_category", "error_type", "reason", "asset_id_reason", "rate_kind", "decision", "validation"))
_HASHES = frozenset(("sha256", "body_sha256", "request_sha256", "index_sha256", "collector_code_sha",
    "config_source_sha256", "csv_sha256", "scope_sha256", "first_ids_sha256", "check_ids_sha256",
    "first_cursor_sha256", "check_cursor_sha256", "duplicate_id_sha256", "attempt_id_sha256"))
_IDS = frozenset(("capture_id", "run_id", "release_tag", "asset_name"))
_SLUGS = frozenset(("repo", "repository", "release_repository"))
_URLS = frozenset(("asset_url", "index_asset_url"))


def _safe_code(value: Any) -> str | None:
    return value if isinstance(value, str) and _CODE.fullmatch(value) and not _CREDENTIAL.search(value) else None


def _frames(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    clean = []
    for frame in value[-6:]:
        if not isinstance(frame, dict):
            continue
        filename, function, line = frame.get("file"), frame.get("function"), frame.get("line")
        if (not isinstance(filename, str) or len(filename) > 220 or _CREDENTIAL.search(filename) or
                not filename.endswith(".py") or any(not _PUBLIC_ID.fullmatch(part) or part in (".", "..")
                    for part in filename.split("/"))):
            filename = "external.py"
        function = (function if isinstance(function, str) and _PYTHON_IDENTIFIER.fullmatch(function)
                    and not _CREDENTIAL.search(function) else "anonymous")
        if type(line) is int and 0 < line < 10_000_000:
            clean.append({"file": filename, "function": function, "line": line})
    return clean


def _fields(values: dict) -> dict:
    clean = {}
    for name, value in values.items():
        if name in _NUMBERS:
            if type(value) in (int, float) and abs(value) <= 10**15 and math.isfinite(value):
                clean[name] = value
            elif name == "asset_id" and value is None:
                clean[name] = None
        elif name in _BOOLS and type(value) is bool:
            clean[name] = value
        elif name in _CODES:
            code = _safe_code(value)
            if name == "failure_category" and value is not None:
                clean[name] = code if code in _CATEGORIES else "collection_error"
            elif name == "status" or name.endswith("_status"):
                clean[name] = code if code in _STATUSES else "unknown"
            elif name in _VOCABULARIES:
                clean[name] = code if code in _VOCABULARIES[name] else "unknown"
            elif code is not None:
                clean[name] = code  # Constrained runtime exception class names.
        elif name in _HASHES and isinstance(value, str) and _HASH.fullmatch(value):
            clean[name] = value
        elif name in _IDS and isinstance(value, str) and _PUBLIC_ID.fullmatch(value) and not _CREDENTIAL.search(value):
            clean[name] = value
        elif name in _SLUGS and isinstance(value, str) and _SLUG.fullmatch(value) and not _CREDENTIAL.search(value):
            clean[name] = value
        elif name == "scope" and isinstance(value, str):
            clean[name] = value if _SCOPE.fullmatch(value) else "unknown"
        elif name == "method" and value == "GET":
            clean[name] = value
        elif name == "endpoint" and isinstance(value, str) and _ENDPOINT.fullmatch(value):
            clean[name] = value
        elif name == "request_id" and isinstance(value, str) and re.fullmatch(r"[0-9A-Fa-f:]{1,96}", value):
            clean[name] = value
        elif name in _URLS and isinstance(value, str) and len(value) <= 400 and not _CREDENTIAL.search(value):
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            if (parsed.scheme == "https" and parsed.netloc == "github.com" and not parsed.query and
                    not parsed.fragment and not parsed.username and not parsed.password and
                    all(_PUBLIC_ID.fullmatch(part) and part not in (".", "..") for part in parsed.path.split("/") if part)):
                clean[name] = value
        elif name == "traceback_frames":
            clean[name] = _frames(value)
    return clean


def safe_fields(values: dict) -> dict:
    """The identical scalar projection for logs, new public indexes and summaries."""
    return _fields(values)


def failure_category(error: BaseException | str) -> str:
    """Classify existing failures without returning or formatting their messages."""
    if isinstance(error, str):
        text = error[:2048].lower()
        if "pagination" in text or "first page" in text:
            if "repeated id" in text or "duplicate" in text:
                return "pagination_duplicate"
            if "membership" in text:
                return "pagination_membership"
            if "cursor" in text:
                return "pagination_cursor"
            if "order" in text:
                return "pagination_order"
            return "pagination_drift"
        if "reserve" in text or "rate-limit" in text or "rate limit" in text:
            return "primary_reserve_wait_budget" if "reserve" in text else "rate_limit"
        if "502" in text and ("http" in text or "api" in text):
            return "upstream_http_502"
        if re.search(r"\bhttp[_ :]*[1-5][0-9]{2}\b", text):
            return "http_error"
        if "ref" in text and ("churn" in text or "changed" in text):
            return "git_ref_churn"
        if "jsondecodeerror" in text or "unicodedecodeerror" in text:
            return "invalid_json"
        return "collection_error"
    explicit = getattr(error, "diagnostic_category", None)
    if isinstance(explicit, str) and explicit in _CATEGORIES:
        return explicit
    if type(getattr(error, "code", None)) is int and error.code == 502:
        return "upstream_http_502"
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError)):
        return "invalid_json"
    if isinstance(error, TimeoutError) or type(error).__name__ in ("TimeoutExpired", "PhaseDeadlineExceeded"):
        return "timeout"
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return "interrupted"
    if type(error).__name__ == "BudgetError":
        return "budget_refused"
    if isinstance(error, OSError):
        return "io_error"
    return "collection_error"


def exception_fields(error: BaseException, *, source_root: Path | None = None) -> dict:
    root = Path(source_root).resolve() if source_root else Path(__file__).resolve().parents[2]
    frames = []
    tb = error.__traceback__
    while tb is not None:
        filename = "external.py"
        try:
            path = Path(tb.tb_frame.f_code.co_filename).resolve()
            if path.is_file():
                filename = path.relative_to(root).as_posix()
        except (OSError, ValueError):
            pass
        frames.append({"file": filename, "function": tb.tb_frame.f_code.co_name, "line": tb.tb_lineno})
        tb = tb.tb_next
    return {"error_type": _safe_code(type(error).__name__) or "Exception",
            "failure_category": failure_category(error), "traceback_frames": _frames(frames)}


class DiagnosticLogger:
    """A per-capture bounded sink with reserved failure and terminal capacity."""

    def __init__(self, identity: dict | None = None, *, enabled: bool | None = None,
                 stream: TextIO | None = None, source_root: Path | None = None,
                 max_events: int = 2048, max_bytes: int = 524288):
        if max_events < 4 or max_bytes < 4096:
            raise ValueError("Diagnostic bounds must allow at least4 events and4096bytes")
        self.enabled = (os.getenv("ICSOT_DEBUG", "").lower() in ("1", "true", "yes")) if enabled is None else enabled
        self.stream, self.source_root = stream or sys.stderr, source_root
        self.identity = _fields(identity or {})
        self.max_events, self.max_bytes = min(max_events, 4096), min(max_bytes, 1048576)
        self.critical_events = min(256, max(1, self.max_events // 4))
        self.critical_bytes = min(65536, self.max_bytes // 4)
        self.summary_bytes = min(4096, self.max_bytes // 4)
        self.seen = self.written = self.bytes_written = self.dropped = self.sampled_out = 0
        self.normal_written = self.normal_bytes = 0
        self.critical_written = self.critical_bytes_written = self.critical_dropped = 0
        self.categories: Counter[str] = Counter()
        self.last_critical: dict = {}
        self.last_terminal: dict = {}
        self.samples: Counter[str] = Counter()
        self.closed = False
        self.lock = threading.RLock()

    def _write(self, event: str, data: dict, *, byte_allowance: int | None = None,
               include_identity: bool = True) -> bool:
        payload = {"debug_schema": 1, "event": event, "at": datetime.now(timezone.utc).isoformat(),
                   "sequence": self.written + 1,
                   **(self.identity if include_identity else {}), **data}
        line = "ICSOT_DEBUG " + json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        raw_size = len(line.encode("utf-8"))
        if (raw_size > self.summary_bytes or self.bytes_written + raw_size > self.max_bytes or
                self.written >= self.max_events or (byte_allowance is not None and raw_size > byte_allowance)):
            return False
        try:
            self.stream.write(line)
            self.stream.flush()
        except Exception:
            return False  # Debug output must never change evidence/collection disposition.
        self.written += 1
        self.bytes_written += raw_size
        return True

    def emit(self, event: str, *, important: bool = False, sample: bool = False, **metadata) -> bool:
        if not self.enabled or self.closed or event not in _EVENTS or event == "diagnostic_summary":
            return False
        with self.lock:
            if self.closed:
                return False
            self.seen += 1
            safe = _fields(metadata)
            category = safe.get("failure_category")
            if category:
                self.categories[category] += 1
            terminal = event in ("capture_end", "finalize_end", "plan_end")
            critical = terminal or important or bool(category) or any(token in event for token in ("failure", "exception", "retry", "restart", "wait", "reserve"))
            if terminal:
                self.last_terminal = {"event": event, **{key: value for key, value in safe.items()
                    if key in ("stage", "status", "capture_status", "scientific_status", "git_status",
                               "verification_status", "archive_status", "encryption_status", "upload_status", "proof_status")}}
            if sample and not critical:
                key = event + ":" + safe.get("scope", "")
                if key not in self.samples and len(self.samples) >= 128:
                    key = event + ":other"
                self.samples[key] += 1
                if self.samples[key] != 1 and self.samples[key] % 25:
                    self.sampled_out += 1
                    return False
            if critical:
                # Retain bounded last-failure facts and aggregate counts even if
                # an exceptional capture exhausts the critical output reserve.
                self.last_critical = {"event": event, **{k: v for k, v in safe.items()
                    if k in ("scope", "stage", "failure_category", "status_code", "attempt", "page", "remaining", "reset")}}
                if self.critical_written >= self.critical_events or self.critical_bytes_written >= self.critical_bytes:
                    self.critical_dropped += 1
                    self.dropped += 1
                    return False
            elif (self.normal_written >= self.max_events - self.critical_events - 1 or
                  self.normal_bytes >= self.max_bytes - self.critical_bytes - self.summary_bytes):
                self.dropped += 1
                return False
            before = self.bytes_written
            allowance = (self.critical_bytes - self.critical_bytes_written if critical else
                         self.max_bytes - self.critical_bytes - self.summary_bytes - self.normal_bytes)
            if not self._write(event, safe, byte_allowance=allowance):
                self.dropped += 1
                if critical:
                    self.critical_dropped += 1
                return False
            if critical:
                self.critical_written += 1
                self.critical_bytes_written += self.bytes_written - before
            else:
                self.normal_written += 1
                self.normal_bytes += self.bytes_written - before
            return True

    def snapshot(self) -> dict:
        with self.lock:
            return {"events_seen": self.seen, "events_written": self.written, "events_dropped": self.dropped,
                    "sampled_out": self.sampled_out, "critical_events_dropped": self.critical_dropped,
                    "bytes_written": self.bytes_written, "failure_categories": dict(self.categories.most_common(16)),
                    "last_critical": self.last_critical, "terminal_outcome": self.last_terminal}

    def summary(self, **metadata) -> None:
        with self.lock:
            if self.enabled and not self.closed:
                payload = {**_fields(metadata), **self.snapshot()}
                # Small caller-selected bounds still get a terminal summary.
                # Counts remain exact; trim only optional bounded detail.
                if not self._write("diagnostic_summary", payload):
                    payload.pop("last_critical", None)
                    payload["failure_categories"] = dict(self.categories.most_common(4))
                    if not self._write("diagnostic_summary", payload):
                        minimal = {name: payload[name] for name in (
                            "events_seen", "events_written", "events_dropped", "sampled_out",
                            "critical_events_dropped", "bytes_written")}
                        minimal["failure_categories"] = dict(self.categories.most_common(2))
                        minimal["terminal_outcome"] = {name: value for name, value in self.last_terminal.items()
                            if name in ("event", "status", "capture_status")}
                        self._write("diagnostic_summary", minimal, include_identity=False)
            self.closed = True


@contextlib.contextmanager
def diagnostic_context(*, enabled: bool | None = None, stream: TextIO | None = None,
                       source_root: Path | None = None, max_events: int = 2048,
                       max_bytes: int = 524288, **identity):
    logger = DiagnosticLogger(identity, enabled=enabled, stream=stream, source_root=source_root,
                              max_events=max_events, max_bytes=max_bytes)
    token = _CURRENT.set(logger)
    try:
        yield logger
    except BaseException as error:
        logger.emit("exception", important=True, **exception_fields(error, source_root=source_root))
        raise
    finally:
        logger.summary()
        _CURRENT.reset(token)


_DEFAULT_LOGGER: DiagnosticLogger | None = None
_DEFAULT_LOCK = threading.Lock()


def emit(event: str, **metadata) -> bool:
    """Use the active context; explicit ICSOT_DEBUG also enables a process sink.

    ContextVars intentionally do not propagate to new worker threads. Pass the
    returned logger explicitly to heartbeat threads or activate a job context.
    """
    global _DEFAULT_LOGGER
    logger = _CURRENT.get()
    if logger is None and os.getenv("ICSOT_DEBUG", "").lower() in ("1", "true", "yes"):
        with _DEFAULT_LOCK:
            if _DEFAULT_LOGGER is None:
                _DEFAULT_LOGGER = DiagnosticLogger(enabled=True)
                atexit.register(_DEFAULT_LOGGER.summary)
            logger = _DEFAULT_LOGGER
    return logger.emit(event, **metadata) if logger is not None else False


@contextlib.contextmanager
def wait_heartbeat(*, interval_seconds: float = 60.0, **metadata):
    """A diagnostic heartbeat; it never changes the caller's original sleep."""
    logger = _CURRENT.get()
    if logger is None and os.getenv("ICSOT_DEBUG", "").lower() in ("1", "true", "yes"):
        logger = _DEFAULT_LOGGER
    if logger is None or not logger.enabled:
        yield
        return
    stop = threading.Event()
    started = time.monotonic()

    def heartbeat():
        while not stop.wait(interval_seconds):
            logger.emit("api_rate_wait_heartbeat", important=True,
                        **metadata, elapsed_seconds=round(time.monotonic() - started, 3))

    thread = None
    try:
        thread = threading.Thread(target=heartbeat, name="icsot-rate-debug", daemon=True)
        thread.start()
    except Exception:
        thread = None  # Diagnostics may not prevent the original bounded wait.
    try:
        yield
    finally:
        stop.set()
        if thread is not None:
            try:
                thread.join(timeout=1)
            except Exception:
                pass
