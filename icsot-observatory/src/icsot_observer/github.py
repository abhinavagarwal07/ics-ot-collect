from __future__ import annotations

import json
import math
import os
import email.utils
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .core import Config, ObjectStore, canonical_json, parse_github_time, sha256, utc_iso
from .checkpoints import CheckpointError, CheckpointStore
from .diagnostics import emit, exception_fields, failure_category, safe_fields, wait_heartbeat

HEADERS_TO_KEEP = (
    "date", "etag", "last-modified", "link", "x-github-api-version-selected",
    "x-github-media-type", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "x-poll-interval", "retry-after", "content-type",
    "content-length", "x-github-request-id", "cache-control"
)
_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_REPOSITORY_PATH_RE = re.compile(
    r"(?P<repository>/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|/repositories/(?P<id>[1-9][0-9]*))"
    r"(?P<endpoint>(?:/[^/?#]+)*)"
)
BASE_SCOPES = ("repository_metadata", "issues", "pulls", "issue_comments", "review_comments",
               "releases", "tags", "events")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # preserve source identity; never forward bearer token on redirects


@dataclass
class Response:
    body: bytes
    record: dict[str, Any]


class APIRequestDeferred(RuntimeError):
    """A persisted rate refusal which a scheduler can retry without sleeping."""

    def __init__(self, retry_not_before: float, reason: str, *, scope: str | None = None,
                 capture_id: str | None = None):
        super().__init__(reason)
        self.retry_not_before = retry_not_before
        self.reason, self.scope, self.capture_id = reason, scope, capture_id
        self.lane_wide = True


class _ScopeCapped(RuntimeError):
    pass


class _PaginationDrift(RuntimeError):
    def __init__(self, message: str, category: str = "pagination_drift", page: int | None = None):
        super().__init__(message)
        self.diagnostic_category = category
        self.diagnostic_page = page


class GitHubAPI:
    """Captures original HTTP body and a redacted provenance envelope."""

    def __init__(self, config: Config, store: ObjectStore, records: list[dict],
                 checkpoint_store: CheckpointStore | None = None, *, defer_on_rate: bool = False):
        self.config, self.store, self.records = config, store, records
        self.checkpoint_store = checkpoint_store
        self.defer_on_rate = defer_on_rate or checkpoint_store is not None
        self._checkpoint_context: dict | None = None
        self._deferred: APIRequestDeferred | None = None
        self._checkpoint_integrity_errors: dict[str, list[str]] = {}
        self._json_decode_errors: list[dict] = []
        self._scope_observations: dict[str, dict] = {}
        self._debug_context: dict[str, Any] = {}
        if checkpoint_store is not None:
            if (config.root.resolve() != checkpoint_store.root or
                    store.root.resolve() != checkpoint_store.root):
                raise CheckpointError("API object store and checkpoint root differ")
            # Identity may have been fetched before the stable numeric binding was
            # known. Persist those envelopes before any subsequent network call.
            old_records = checkpoint_store.responses()
            self._json_decode_errors = [event["data"] for event in checkpoint_store.events
                                        if event["kind"] == "response_decode_error"]
            for record in old_records:
                try:
                    self._validate_record_body(record)
                except CheckpointError as exc:
                    scope = record.get("checkpoint_provenance", {}).get("scope") or "repository_metadata"
                    self._checkpoint_integrity_errors.setdefault(scope, []).append(str(exc))
            known = {record["checkpoint_provenance"]["event_sequence"] for record in old_records}
            for record in records:
                provenance = record.get("checkpoint_provenance", {})
                if (provenance.get("capture_id") == checkpoint_store.capture_id and
                        provenance.get("event_sequence") in known):
                    continue
                self._validate_record_body(record)
                checkpoint_store.record_response(record)
            present = {record.get("checkpoint_provenance", {}).get("event_sequence") for record in records}
            for record in old_records:
                if record["checkpoint_provenance"]["event_sequence"] not in present:
                    record["checkpoint_provenance"]["reused_from_checkpoint"] = True
                    records.append(record)
        self.token = os.getenv(config.token_env, "").strip()
        self.opener = urllib.request.build_opener(NoRedirect)
        self.requests = 0
        self.primary_rate_waited_seconds = 0.0
        self.secondary_rate_waited_seconds = 0.0
        self._last_rate_record: dict | None = None
        self._repository_ids: dict[str, str] = {}

    def _request_fields(self, url: str | None, purpose: str) -> dict:
        fields = {"scope": purpose, "method": "GET", "page": 1, "scope_attempt": 1,
                  "scope_sha256": sha256(purpose.encode("utf-8", errors="replace"))[:16],
                  **self._debug_context}
        if url is None:
            return fields
        route = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(url).path)
        fields["request_sha256"] = sha256(url.encode("utf-8", errors="replace"))[:16]
        if route:
            if route["id"]:
                base = "/repositories/{repository_id}"
                if len(route["id"]) <= 18:
                    fields["repository_id"] = int(route["id"])
            else:
                base = "/repos/{owner}/{repo}"
                fields["repo"] = route["repository"][len("/repos/"):]
            allowed = {"issues", "pulls", "comments", "reviews", "commits", "files", "timeline", "releases", "tags", "events"}
            parts = route["endpoint"].split("/")[1:]
            # Unknown path components never become arbitrary diagnostic text.
            if all(part in allowed or part.isdigit() for part in parts) and len(parts) <= 4:
                fields["endpoint"] = base + "".join("/{number}" if part.isdigit() else "/" + part for part in parts)
        return fields

    def _rate_fields(self, headers: dict) -> dict:
        fields = {"reserve": self.config.primary_rate_reserve,
                  "primary_wait_used_seconds": self.primary_rate_waited_seconds,
                  "primary_wait_allowance_seconds": self.config.primary_rate_wait_seconds,
                  "secondary_wait_used_seconds": self.secondary_rate_waited_seconds,
                  "secondary_wait_allowance_seconds": self.config.secondary_rate_wait_seconds}
        for header, field in (("x-ratelimit-remaining", "remaining"), ("x-ratelimit-limit", "limit"),
                              ("x-ratelimit-reset", "reset")):
            try:
                fields[field] = int(headers[header])
            except (KeyError, TypeError, ValueError, OverflowError):
                pass
        if isinstance(headers.get("x-github-request-id"), str):
            fields["request_id"] = headers["x-github-request-id"]
        return fields

    def _debug_wait(self, seconds: float, purpose: str, *, url: str | None, headers: dict, rate_kind: str) -> None:
        fields = {**self._request_fields(url, purpose), **self._rate_fields(headers),
                  "rate_kind": rate_kind, "wait_seconds": seconds}
        started = time.monotonic()
        emit("api_rate_wait_start", important=True, **fields)
        try:
            with wait_heartbeat(**fields):
                time.sleep(seconds)
        except BaseException as error:
            emit("api_rate_wait_end", important=True, **fields, status="interrupted",
                 elapsed_seconds=round(time.monotonic() - started, 3), **exception_fields(error))
            raise
        emit("api_rate_wait_end", important=True, **fields, status="finished",
             elapsed_seconds=round(time.monotonic() - started, 3))

    def _validate_record_body(self, record: dict) -> bytes | None:
        if "body_sha256" not in record:
            if record.get("status") is not None:
                raise CheckpointError("HTTP response checkpoint lacks body reference")
            return None
        try:
            body = self.store.get(record["body_sha256"])
        except (OSError, ValueError, RuntimeError) as exc:
            raise CheckpointError(f"Checkpoint CAS missing or corrupt: {record['body_sha256']}") from exc
        if record.get("body_bytes") != len(body):
            raise CheckpointError("Checkpoint response body length changed")
        return body

    def _append_record(self, record: dict) -> None:
        if self.checkpoint_store is not None:
            self.checkpoint_store.record_response(record, self._checkpoint_context)
        self.records.append(record)

    @staticmethod
    def _retry_time(headers: dict, default: float = 60.0, *, include_reset: bool = False) -> float:
        now = time.time()
        deadlines = [now + default]
        try:
            if include_reset or headers.get("x-ratelimit-remaining") == "0":
                deadlines.append(float(headers["x-ratelimit-reset"]) + 1)
        except (KeyError, TypeError, ValueError, OverflowError):
            pass
        retry = headers.get("retry-after")
        if retry:
            try:
                seconds = float(retry)
                if math.isfinite(seconds):
                    deadlines.append(now + max(1, seconds))
            except (TypeError, ValueError, OverflowError):
                try:
                    deadlines.append(email.utils.parsedate_to_datetime(retry).timestamp())
                except (TypeError, ValueError, OverflowError):
                    pass
        return max(value for value in deadlines if math.isfinite(value))

    def _defer_request(self, headers: dict, reason: str, *, include_reset: bool = False,
                       purpose: str | None = None, url: str | None = None) -> None:
        context = self._checkpoint_context or {}
        retry_not_before = self._retry_time(headers, include_reset=include_reset)
        if self.checkpoint_store is not None:
            self.checkpoint_store.append("rate_deferral", {
                **context, "retry_not_before": retry_not_before, "reason": reason, "lane_wide": True,
            })
        category = ("primary_reserve_future_reset" if include_reset else
                    "primary_rate_limit" if headers.get("x-ratelimit-remaining") == "0" else "secondary_rate_limit")
        emit("api_rate_reserve" if include_reset else "api_request_retry", important=True,
             **self._request_fields(url, purpose or context.get("scope", "repository_identity")),
             **self._rate_fields(headers), retry_not_before=retry_not_before,
             deferred=True, decision="defer", failure_category=category)
        error = APIRequestDeferred(retry_not_before, reason, scope=context.get("scope"),
                                   capture_id=self.checkpoint_store.capture_id if self.checkpoint_store else None)
        error.diagnostic_category = category
        raise error

    @staticmethod
    def validate_url(url: str) -> None:
        x = urllib.parse.urlsplit(url)
        if (x.scheme != "https" or x.netloc != "api.github.com" or
                not _REPOSITORY_PATH_RE.fullmatch(x.path) or x.username or x.password or x.fragment or
                any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in x.path or
                any(part in (".", "..") for part in x.path.split("/"))):
            raise ValueError(f"Disallowed API endpoint: {url}")

    @staticmethod
    def url(path: str, params: dict[str, Any] | None = None) -> str:
        if not _REPOSITORY_PATH_RE.fullmatch(path) or "?" in path or "#" in path:
            raise ValueError(f"Disallowed API path: {path}")
        url = "https://api.github.com" + path + ("?" + urllib.parse.urlencode(params) if params else "")
        GitHubAPI.validate_url(url)
        return url

    def _preserve_primary_reserve(self, purpose: str, *, url: str | None = None) -> None:
        record = self._last_rate_record
        if self.config.primary_rate_reserve == 0 or record is None:
            return
        headers = record.get("headers", {})
        try:
            remaining = int(headers["x-ratelimit-remaining"])
        except (KeyError, TypeError, ValueError):
            return
        if remaining > self.config.primary_rate_reserve:
            return
        try:
            if time.time() >= float(headers["x-ratelimit-reset"]) + 1:
                self._last_rate_record = None
                emit("api_rate_reserve", important=True, **self._request_fields(url, purpose),
                     **self._rate_fields(headers), decision="clear_expired", reason="expired_reset_cleared",
                     wait_available_seconds=max(0, self.config.primary_rate_wait_seconds - self.primary_rate_waited_seconds))
                return
        except (KeyError, TypeError, ValueError, OverflowError):
            pass
        if self.defer_on_rate:
            self._defer_request(headers, f"Primary rate-limit reserve reached for {purpose}", include_reset=True,
                                purpose=purpose, url=url)
        try:
            duration = max(1.0, int(headers["x-ratelimit-reset"]) - time.time() + 1.0)
        except (KeyError, TypeError, ValueError, OverflowError):
            duration = None
        available = self.config.primary_rate_wait_seconds - self.primary_rate_waited_seconds
        if duration is None or duration > available:
            emit("api_rate_reserve", important=True, **self._request_fields(url, purpose),
                 **self._rate_fields(headers), decision="refuse_wait_budget", wait_seconds=duration,
                 wait_available_seconds=max(0, available), failure_category="primary_reserve_wait_budget")
            error = RuntimeError(f"Rate-limit reserve reached for {purpose}; preserve transfer capacity and retry later")
            error.diagnostic_category = "primary_reserve_wait_budget"
            try:
                reset = float(headers["x-ratelimit-reset"])
                if math.isfinite(reset):
                    error.retry_not_before = reset + 1
                    error.rate_reset = reset
            except (KeyError, TypeError, ValueError, OverflowError):
                pass
            raise error
        record["primary_rate_reserve_wait_seconds"] = duration
        self.primary_rate_waited_seconds += duration
        self._debug_wait(duration, purpose, url=url, headers=headers, rate_kind="primary_reserve")
        self._last_rate_record = None  # reset elapsed; obtain current headers on the next request

    def get(self, url: str, purpose: str) -> Response:
        self.validate_url(url)
        self._preserve_primary_reserve(purpose, url=url)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.config.api_version,
            "User-Agent": self.config.user_agent,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        # Never store Authorization header, token, private token scopes, or full request environment.
        errors = (urllib.error.URLError, TimeoutError, OSError)
        for attempt in range(4):
            started = utc_iso()
            request_started = time.monotonic()
            request_fields = {**self._request_fields(url, purpose), "attempt": attempt + 1, "max_attempts": 4}
            emit("api_request_start", sample=True, **request_fields)
            try:
                req = urllib.request.Request(url, headers=headers, method="GET")
                with self.opener.open(req, timeout=self.config.http_timeout_seconds) as r:
                    status = r.status
                    response_headers = dict(r.headers.items())
                    body = r.read(self.config.max_response_bytes + 1)
                failure = None
            except urllib.error.HTTPError as e:
                status = e.code
                response_headers = dict(e.headers.items())
                body = e.read(self.config.max_response_bytes + 1)
                failure = f"HTTP_{status}"
            except errors as e:
                completed = utc_iso()
                self._append_record({
                    "purpose": purpose, "url": url, "request_started_at": started,
                    "request_completed_at": completed, "status": None,
                    "error": type(e).__name__, "attempt": attempt + 1,
                })
                emit("api_request_end", important=True, **request_fields, status="network_error",
                     error_type=type(e).__name__, failure_category="request_failed",
                     elapsed_seconds=round(time.monotonic() - request_started, 3))
                if attempt < 3:
                    duration = min(8, (2 ** attempt) + random.random())
                    emit("api_request_retry", important=True, **request_fields,
                         reason="network_error", wait_seconds=duration, failure_category="request_failed")
                    time.sleep(duration)
                    continue
                raise RuntimeError(f"API request failed for {purpose}: {type(e).__name__}") from e

            completed = utc_iso()
            if len(body) > self.config.max_response_bytes:
                # Record truncated diagnostic bytes but NEVER call this an observed complete response.
                failure = "RESPONSE_EXCEEDS_CAP"
            digest = self.store.put(body)
            hdrs = {name: value for key, value in response_headers.items()
                    if (name := key.lower()) in HEADERS_TO_KEEP}
            rec = {
                "purpose": purpose, "url": url, "method": "GET", "api_version": self.config.api_version,
                "request_started_at": started, "request_completed_at": completed,
                "status": status, "headers": hdrs, "body_sha256": digest, "body_bytes": len(body),
                "error": failure, "attempt": attempt + 1, "auth": "token_present" if self.token else "anonymous"
            }
            self._append_record(rec)
            self._last_rate_record = rec
            self.requests += 1
            category = ("response_cap" if failure == "RESPONSE_EXCEEDS_CAP" else
                        "upstream_http_502" if status == 502 else "http_error")
            emit("api_request_end", sample=failure is None and bool(_NEXT_RE.search(hdrs.get("link", ""))),
                 important=failure is not None, **request_fields, **self._rate_fields(hdrs), status_code=status,
                 status="success" if failure is None else "failed", body_bytes=len(body), body_sha256=digest[:16],
                 elapsed_seconds=round(time.monotonic() - request_started, 3),
                 **({"failure_category": category} if failure is not None else {}))
            if failure is None and status == 200:
                return Response(body=body, record=rec)

            throttled = status == 429 or (status == 403 and (
                hdrs.get("x-ratelimit-remaining") == "0" or "retry-after" in hdrs or
                b"rate limit" in body[:4096].lower() or b"abuse" in body[:4096].lower()))
            if self.defer_on_rate and throttled:
                self._defer_request(hdrs, f"Rate-limit deferral for {purpose}: HTTP {status}", purpose=purpose, url=url)
            if self.checkpoint_store is not None and failure == "RESPONSE_EXCEEDS_CAP":
                raise _ScopeCapped(f"Response exceeds byte cap for {purpose} (NOT complete)")

            # Rate-limit and server issues: bounded retry, no invented successful response.
            if status in (403, 429) and hdrs.get("x-ratelimit-remaining") == "0":
                # Hosted jobs may opt into a bounded wait for the shared token
                # bucket. Preserve the refusal and the announced reset as evidence.
                try:
                    reset = int(hdrs.get("x-ratelimit-reset", ""))
                    duration = max(1.0, reset - time.time() + 1.0)
                except (TypeError, ValueError, OverflowError):
                    duration = None
                retry_after = hdrs.get("retry-after")
                if retry_after:
                    try:
                        announced = float(retry_after)
                    except ValueError:
                        try:
                            announced = email.utils.parsedate_to_datetime(retry_after).timestamp() - time.time()
                        except (TypeError, ValueError, OverflowError):
                            announced = 60.0
                    if not math.isfinite(announced) or announced < 0:
                        announced = 60.0
                    duration = max(duration or 0, announced, 1.0)
                available = self.config.primary_rate_wait_seconds - self.primary_rate_waited_seconds
                if attempt < 3 and duration is not None and duration <= available:
                    rec["primary_rate_wait_seconds"] = duration
                    self.primary_rate_waited_seconds += duration
                    emit("api_request_retry", important=True, **request_fields, **self._rate_fields(hdrs),
                         status_code=status, reason="primary_rate_reset", wait_seconds=duration,
                         wait_available_seconds=max(0, available), failure_category="primary_rate_limit")
                    self._debug_wait(duration, purpose, url=url, headers=hdrs, rate_kind="primary")
                    continue
                error = RuntimeError(f"Rate-limit budget exhausted for {purpose}; retry in next scheduled run")
                error.diagnostic_category = "primary_rate_limit"
                emit("api_request_retry", important=True, **request_fields, **self._rate_fields(hdrs),
                     status_code=status, decision="refuse_wait_budget", wait_seconds=duration,
                     wait_available_seconds=max(0, available), failure_category="primary_rate_limit")
                raise error
            throttled = status == 429 or (status == 403 and (
                "retry-after" in hdrs or b"rate limit" in body[:4096].lower() or b"abuse" in body[:4096].lower()))
            if throttled and attempt < 3:
                retry = hdrs.get("retry-after")
                duration = 60.0 * (2 ** attempt)
                if retry:
                    try:
                        duration = float(retry)
                    except ValueError:
                        try:
                            when = email.utils.parsedate_to_datetime(retry)
                            duration = when.timestamp() - time.time()
                        except (TypeError, ValueError, OverflowError):
                            pass  # retain the conservative one-minute exponential delay
                if not math.isfinite(duration) or duration < 0:
                    duration = 60.0 * (2 ** attempt)
                duration = max(1.0, duration)
                available = self.config.secondary_rate_wait_seconds - self.secondary_rate_waited_seconds
                if duration <= available:
                    rec["secondary_rate_wait_seconds"] = duration
                    self.secondary_rate_waited_seconds += duration
                    emit("api_request_retry", important=True, **request_fields, **self._rate_fields(hdrs),
                         status_code=status, reason="secondary_rate_limit", wait_seconds=duration,
                         wait_available_seconds=max(0, available), failure_category="secondary_rate_limit")
                    self._debug_wait(duration, purpose, url=url, headers=hdrs, rate_kind="secondary")
                    continue
            if status in (500, 502, 503, 504) and attempt < 3:
                # Server errors keep a short bounded retry. Long announced
                # deferrals become explicit partial captures instead of early retries.
                duration = (2 ** attempt) + random.random()
                retry = hdrs.get("retry-after")
                if retry:
                    try:
                        duration = float(retry)
                    except ValueError:
                        try:
                            duration = email.utils.parsedate_to_datetime(retry).timestamp() - time.time()
                        except (TypeError, ValueError, OverflowError):
                            duration = 60
                if 0 <= duration <= 30:
                    rec["server_retry_wait_seconds"] = duration
                    emit("api_request_retry", important=True, **request_fields, **self._rate_fields(hdrs),
                         status_code=status, reason="upstream_transient", wait_seconds=duration, failure_category=category)
                    time.sleep(duration)
                    continue
            error = RuntimeError(f"API failure {purpose}: HTTP {status}, {failure or 'unexpected status'}")
            error.diagnostic_category = category
            raise error
        raise AssertionError("unreachable")

    def _request_json(self, url: str, purpose: str, kind: str, *, checkpointed: bool = False,
                      page: int = 1, scope_attempt: int = 1) -> tuple[Response, Any]:
        """Retry malformed 2xx JSON at most twice; retain every original body."""
        for decode_attempt in range(1, 4):
            previous = self._debug_context
            self._debug_context = {"page": page, "scope_attempt": scope_attempt,
                                   "decode_attempt": decode_attempt}
            try:
                response = self._checkpoint_get(url, purpose) if checkpointed else self.get(url, purpose)
                try:
                    return response, self._decode_scope_body(response.body, kind, purpose)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    failure = {"purpose": purpose, "url": url, "decode_attempt": decode_attempt,
                               "body_sha256": response.record.get("body_sha256"),
                               "response_sequence": response.record.get("checkpoint_provenance", {}).get("event_sequence"),
                               "error": type(exc).__name__, "message": str(exc)}
                    self._json_decode_errors.append(failure)
                    if self.checkpoint_store is not None:
                        self.checkpoint_store.append("response_decode_error", failure)
                    emit("api_decode_retry", important=True, **self._request_fields(url, purpose),
                         status="retry" if decode_attempt < 3 else "exhausted", max_attempts=3,
                         body_sha256=response.record.get("body_sha256", "")[:16],
                         failure_category="invalid_json", error_type=type(exc).__name__)
                    if decode_attempt == 3:
                        raise
            finally:
                self._debug_context = previous
        raise AssertionError("unreachable")

    def get_json(self, path: str, purpose: str) -> dict:
        _, obj = self._request_json(self.url(path), purpose, "object")
        route = _REPOSITORY_PATH_RE.fullmatch(path)
        if route and not route["endpoint"] and type(obj.get("id")) is int and obj["id"] > 0:
            self._repository_ids[route["repository"].lower()] = str(obj["id"])
        return obj

    @staticmethod
    def _item_identity(item: dict) -> tuple[str, str] | None:
        for field in ("id", "node_id", "sha", "name", "filename"):
            value = item.get(field)
            if (type(value) is int and value > 0) or (isinstance(value, str) and value):
                return field, str(value)
        return None

    @staticmethod
    def _next_link(response: Response) -> str | None:
        match = _NEXT_RE.search(response.record.get("headers", {}).get("link", ""))
        return match.group(1) if match else None

    @staticmethod
    def _identity_hash(value: Any) -> str:
        # Debug hashing must also tolerate unusual decoded Unicode identities;
        # it cannot introduce a new encoding failure into a valid traversal.
        return sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))[:16]

    @classmethod
    def _first_page_check(cls, first: Response, first_items: list[dict],
                          fresh: Response, fresh_items: list[dict]) -> dict:
        original = [cls._item_identity(item) for item in first_items]
        current = [cls._item_identity(item) for item in fresh_items]
        comparable = bool(original) and all(value is not None for value in original + current)
        duplicate = (len(set(original)) != len(original) or len(set(current)) != len(current)) if comparable else False
        cursor_changed = cls._next_link(first) != cls._next_link(fresh)
        representation_changed = sha256(first.body) != sha256(fresh.body)
        membership_changed = set(original) != set(current) if comparable else None
        order_changed = (original != current and not membership_changed) if comparable else None
        matches = (not cursor_changed and (
            not representation_changed or (comparable and not duplicate and original == current)))
        check = {"matches": matches, "first_count": len(original), "check_count": len(current),
                 "identity_comparable": comparable, "duplicate_detected": duplicate,
                 "cursor_changed": cursor_changed, "membership_changed": membership_changed,
                 "order_changed": order_changed, "representation_changed": representation_changed,
                 "first_ids_sha256": cls._identity_hash(original),
                 "check_ids_sha256": cls._identity_hash(current),
                 "first_cursor_sha256": sha256((cls._next_link(first) or "").encode("utf-8", errors="replace"))[:16],
                 "check_cursor_sha256": sha256((cls._next_link(fresh) or "").encode("utf-8", errors="replace"))[:16]}
        if not matches:
            category = ("pagination_duplicate" if duplicate else
                        "pagination_membership" if membership_changed else
                        "pagination_order" if order_changed else
                        "pagination_cursor" if cursor_changed else "pagination_unknown_identity")
            check["failure_category"] = category
            if comparable:
                check["first_difference"] = next((index for index, pair in enumerate(zip(original, current))
                    if pair[0] != pair[1]), min(len(original), len(current)))
        return check

    @classmethod
    def _first_page_matches(cls, first: Response, first_items: list[dict],
                            fresh: Response, fresh_items: list[dict]) -> bool:
        return cls._first_page_check(first, first_items, fresh, fresh_items)["matches"]

    def list_pages(self, path: str, purpose: str, *, params: dict | None = None,
                   updated_before: datetime | None = None) -> list[dict]:
        """Validate a non-atomic traversal, restarting an actually drifted list once.

        Rechecks compare ordered entity identities and the next cursor. Mutable
        representation fields do not themselves imply missing pagination items.
        Every raw attempt and interval remains archived; this is no atomic snapshot.
        """
        initial_url = self.url(path, {**(params or {}), "per_page": 100})
        first_route = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(initial_url).path)
        assert first_route is not None
        for traversal in range(1, 3):
            attempt_started_at = utc_iso()
            self._scope_observations[purpose] = {"pagination_attempts": traversal,
                "query_started_at": attempt_started_at, "claim_scope": "non_atomic_response_intervals"}
            canonical_id = first_route["id"] or self._repository_ids.get(first_route["repository"].lower())
            url = initial_url
            first_response = None
            first_items: list[dict] = []
            items: list[dict] = []
            seen_urls: set[str] = set()
            seen_ids: set[tuple[str, str]] = set()
            try:
                for page_no in range(1, self.config.max_pages + 1):
                    if url in seen_urls:
                        emit("api_pagination_check", important=True, scope=purpose, page=page_no,
                             scope_attempt=traversal, reason="cursor_loop", failure_category="pagination_cursor")
                        raise _PaginationDrift(f"Pagination loop in {purpose}", "pagination_cursor", page_no)
                    seen_urls.add(url)
                    response, page = self._request_json(url, purpose, "list", page=page_no, scope_attempt=traversal)
                    if first_response is None:
                        first_response, first_items = response, page
                    for item in page:
                        identity = self._item_identity(item)
                        if identity is not None:
                            if identity in seen_ids:
                                emit("api_pagination_check", important=True, scope=purpose, page=page_no,
                                     scope_attempt=traversal, duplicate_detected=True,
                                     duplicate_id_sha256=self._identity_hash(identity),
                                     failure_category="pagination_duplicate", reason="duplicate_id")
                                raise _PaginationDrift(f"Pagination drift: repeated ID {identity[1]} in {purpose}", "pagination_duplicate", page_no)
                            seen_ids.add(identity)
                    items.extend(page)
                    boundary_stop = updated_before is not None and page and all(
                            isinstance(item.get("updated_at"), str) and
                            parse_github_time(item["updated_at"]) < updated_before for item in page)
                    next_url = None if boundary_stop else self._next_link(response)
                    emit("api_pagination_page", sample=next_url is not None, scope=purpose, page=page_no,
                         scope_attempt=traversal, count=len(page), body_sha256=response.record.get("body_sha256", "")[:16],
                         reason="updated_boundary" if boundary_stop else "next_link" if next_url else "link_end")
                    if next_url is None:
                        break
                    self.validate_url(next_url)
                    route = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(next_url).path)
                    assert route is not None
                    if route["endpoint"] != first_route["endpoint"]:
                        raise RuntimeError(f"Unexpected endpoint changed across pagination for {purpose}")
                    if route["id"] is not None:
                        if canonical_id is not None and route["id"] != canonical_id:
                            raise RuntimeError(f"Unexpected repository changed across pagination for {purpose}")
                        canonical_id = route["id"]
                    elif route["repository"].lower() != first_route["repository"].lower():
                        raise RuntimeError(f"Unexpected repository changed across pagination for {purpose}")
                    url = next_url
                else:
                    raise _ScopeCapped(f"Max pages exceeded for {purpose} (NOT complete)")
                representation_changed = False
                if len(seen_urls) > 1:
                    fresh, fresh_items = self._request_json(initial_url, purpose + "_first_page_recheck", "list", page=1, scope_attempt=traversal)
                    assert first_response is not None
                    check = self._first_page_check(first_response, first_items, fresh, fresh_items)
                    emit("api_pagination_check", important=not check["matches"] or check["representation_changed"],
                         scope=purpose, page=1, scope_attempt=traversal, **check)
                    if not check["matches"]:
                        raise _PaginationDrift(f"Pagination non-atomic: first page changed for {purpose}", check["failure_category"], 1)
                    representation_changed = fresh.body != first_response.body
                self._scope_observations[purpose] = {
                    "pagination_attempts": traversal,
                    "query_started_at": attempt_started_at,
                    "pagination_validation": "ordered_identity_and_next_cursor",
                    "representation_changed_during_validation": representation_changed,
                    "claim_scope": "non_atomic_response_intervals",
                }
                return items
            except _PaginationDrift as exc:
                emit("api_pagination_restart", important=True, scope=purpose, scope_attempt=traversal,
                     page=exc.diagnostic_page,
                     max_attempts=2, decision="restart" if traversal == 1 else "exhausted",
                     failure_category=failure_category(exc))
                self._scope_observations[purpose] = {"pagination_attempts": traversal,
                    "query_started_at": attempt_started_at,
                    "claim_scope": "non_atomic_response_intervals", "last_drift": str(exc)}
                if traversal == 2:
                    raise _PaginationDrift(f"Pagination drift restart budget exhausted for {purpose}: {exc}", failure_category(exc), exc.diagnostic_page) from exc
        raise AssertionError("unreachable")

    def _checkpoint_get(self, url: str, purpose: str) -> Response:
        response = self.get(url, purpose)
        assert self.checkpoint_store is not None
        provenance = response.record.get("checkpoint_provenance", {})
        if not provenance:
            # Also supports instrumented transports which implement get().
            if self._validate_record_body(response.record) != response.body:
                raise CheckpointError("Transport body does not match checkpoint CAS reference")
            self.checkpoint_store.record_response(response.record, self._checkpoint_context)
            if not any(record is response.record for record in self.records):
                self.records.append(response.record)
        else:
            durable = self.checkpoint_store.response(provenance["event_sequence"])
            if durable != response.record:
                raise CheckpointError("Transport envelope differs from durable checkpoint")
        return response

    def _page_next(self, query: dict, response: Response, items: list[dict]) -> str | None:
        boundary = query["updated_before"]
        if boundary is not None and items and all(
                isinstance(item.get("updated_at"), str) and
                parse_github_time(item["updated_at"]) < parse_github_time(boundary) for item in items):
            return None
        match = _NEXT_RE.search(response.record.get("headers", {}).get("link", ""))
        if not match:
            return None
        url = match.group(1)
        self._validate_page_url(query["initial_url"], url)
        return url

    def _validate_page_url(self, initial_url: str, url: str) -> None:
        self.validate_url(url)
        first = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(initial_url).path)
        route = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(url).path)
        assert first and route and self.checkpoint_store
        if route["endpoint"] != first["endpoint"]:
            raise CheckpointError("Unexpected endpoint changed across checkpoint pagination")
        if route["id"] is not None:
            if route["id"] != str(self.checkpoint_store.repository_id):
                raise CheckpointError("Unexpected repository changed across checkpoint pagination")
        elif route["repository"].lower() != first["repository"].lower():
            raise CheckpointError("Unexpected repository changed across checkpoint pagination")
        # Link cursors are opaque. Retain them verbatim but reject changed query
        # filters or page sizes before sending a request (including on resume).
        original = urllib.parse.parse_qs(urllib.parse.urlsplit(initial_url).query, keep_blank_values=True)
        current = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
        for name, values in original.items():
            if current.get(name) != values:
                raise CheckpointError(f"Checkpoint pagination query changed: {name}")
        if set(current) - set(original) - {"page", "after", "before", "cursor"}:
            raise CheckpointError("Unexpected checkpoint pagination query parameter")

    @staticmethod
    def _decode_scope_body(body: bytes, kind: str, scope: str) -> Any:
        value = json.loads(body)
        if kind == "object":
            if not isinstance(value, dict):
                raise ValueError(f"Expected JSON object for {scope}")
        elif not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError(f"Unexpected page JSON for {scope}")
        return value

    def _load_scope_pages(self, state: dict, query: dict) -> tuple[Any, list[Response]]:
        assert self.checkpoint_store is not None
        pages: list[Response] = []
        values: Any = {} if query["kind"] == "object" else []
        next_url = query["initial_url"]
        seen_ids: set[tuple[str, str]] = set()
        seen_urls: set[str] = set()
        for expected, page in enumerate(state["pages"], 1):
            if (page["page_no"] != expected or expected > self.config.max_pages or
                    page["url"] != next_url or next_url in seen_urls):
                raise CheckpointError("Checkpoint page order/cap/URL lineage changed")
            self._validate_page_url(query["initial_url"], page["url"])
            record = self.checkpoint_store.response(page["response_sequence"])
            provenance = record.get("checkpoint_provenance", {})
            if (record.get("url") != page["url"] or record.get("api_version") != self.config.api_version or
                    record.get("status") != 200 or record.get("error") is not None or
                    provenance.get("scope") != state["scope"] or
                    provenance.get("attempt_id") != state["attempt_id"]):
                raise CheckpointError("Checkpoint response request/attempt lineage changed")
            body = self._validate_record_body(record)
            assert body is not None
            response = Response(body, record)
            value = self._decode_scope_body(body, query["kind"], state["scope"])
            if query["kind"] == "object":
                if expected != 1 or page["next_url"] is not None:
                    raise CheckpointError("Unexpected object checkpoint pagination")
                values, next_url = value, None
            else:
                for item in value:
                    identity = self._item_identity(item)
                    if identity is not None:
                        if identity in seen_ids:
                            raise CheckpointError("Repeated entity ID in checkpoint pages")
                        seen_ids.add(identity)
                values.extend(value)
                next_url = self._page_next(query, response, value)
                if page["next_url"] != next_url:
                    raise CheckpointError("Checkpoint next-page URL differs from original response")
            pages.append(response)
            seen_urls.add(page["url"])
        return values, pages

    def _begin_scope(self, scope: str, query: dict, *, query_started_at: str | None = None) -> dict:
        assert self.checkpoint_store is not None
        self.checkpoint_store.append("scope_started", {
            "scope": scope, "attempt_id": uuid.uuid4().hex,
            "fingerprint": sha256(canonical_json(query)), "query": query,
            "query_started_at": query_started_at or utc_iso(),
        })
        state = self.checkpoint_store.scope_state(scope)
        assert state is not None
        emit("api_scope_start", scope=scope, scope_attempt=state["restarts"] + 1,
             attempt_id_sha256=sha256(state["attempt_id"].encode())[:16])
        return state

    def _abandon_scope(self, state: dict, reason: str, *, category: str = "pagination_drift", page: int | None = None) -> None:
        assert self.checkpoint_store is not None
        emit("api_pagination_restart", important=True, scope=state["scope"], scope_attempt=state["restarts"] + 1,
             page=page, max_attempts=2, decision="restart" if state["restarts"] < 1 else "exhausted",
             failure_category=category)
        if state["restarts"] >= 1:
            raise _PaginationDrift(f"Pagination drift restart budget exhausted for {state['scope']}: {reason}", category, page)
        self.checkpoint_store.append("scope_abandoned", {
            "scope": state["scope"], "attempt_id": state["attempt_id"], "reason": reason,
            "status": "partial_drift", "abandoned_at": utc_iso(),
        })

    def _run_checkpoint_scope(self, scope: str, query: dict, *, validate=None) -> tuple[Any, dict]:
        """Resume one exact query. A drifted attempt is retained, never stitched."""
        assert self.checkpoint_store is not None
        if scope in self._checkpoint_integrity_errors:
            raise CheckpointError("; ".join(self._checkpoint_integrity_errors[scope]))
        state = self.checkpoint_store.scope_state(scope)
        existing_attempt = state is not None and not state.get("abandoned")
        if state is not None and (state["fingerprint"] != sha256(canonical_json(query)) or state["query"] != query):
            raise CheckpointError(f"Scope query/options changed for {scope}; use a new capture_id")
        if state is not None and state.get("abandoned"):
            state = self._begin_scope(scope, query)
        if state is not None:
            if existing_attempt:
                emit("api_scope_start", scope=scope, scope_attempt=state["restarts"] + 1,
                     attempt_id_sha256=sha256(state["attempt_id"].encode())[:16], reused_from_checkpoint=True)
            values, pages = self._load_scope_pages(state, query)
            if state["outcome"] and state["outcome"]["status"] == "complete_for_query":
                if not pages or state["pages"][-1]["next_url"] is not None:
                    raise CheckpointError("Complete checkpoint scope has unfinished pagination")
                if validate is not None:
                    validate(values)
                return values, {**state["outcome"], "reused_from_checkpoint": True,
                                "claim_scope": "non_atomic_response_intervals"}
            outcome = state["outcome"] or {}
            if outcome.get("status") == "deferred" and outcome["retry_not_before"] > time.time():
                raise APIRequestDeferred(outcome["retry_not_before"], outcome.get("reason", outcome["error"]), scope=scope,
                                         capture_id=self.checkpoint_store.capture_id)
        if self._deferred is not None:
            raise self._deferred
        resumed = state is not None and bool(state["pages"])
        if state is None:
            state = self._begin_scope(scope, query)
        representation_changed = False
        while True:
            self._checkpoint_context = {"scope": scope, "attempt_id": state["attempt_id"]}
            values, pages = self._load_scope_pages(state, query)
            first_items = (self._decode_scope_body(pages[0].body, query["kind"], scope) if pages else None)
            if resumed:
                fresh, fresh_items = self._request_json(query["initial_url"], scope + "_resume_first_page_validation",
                                                         query["kind"], checkpointed=True, page=1, scope_attempt=state["restarts"] + 1)
                check = (self._first_page_check(pages[0], first_items, fresh, fresh_items)
                         if query["kind"] == "list" else {"matches": fresh.body == pages[0].body,
                         "failure_category": "pagination_drift"})
                if check["matches"]:
                    check.pop("failure_category", None)
                matches = check["matches"]
                emit("api_pagination_check", important=not matches or fresh.body != pages[0].body,
                     scope=scope, page=1, scope_attempt=state["restarts"] + 1, **check)
                changed = fresh.body != pages[0].body
                representation_changed |= changed
                self.checkpoint_store.append("scope_validation", {
                    **self._checkpoint_context, "response_sequence": fresh.record["checkpoint_provenance"]["event_sequence"],
                    "matches_first_page": matches, "representation_changed": changed,
                    "validation": "ordered_identity_and_next_cursor" if query["kind"] == "list" else "exact_object",
                })
                resumed = False
                if not matches:
                    self._abandon_scope(state, "First page membership/order/cursor changed before continuation",
                                        category=check.get("failure_category", "pagination_drift"), page=1)
                    state = self._begin_scope(scope, query)
                    representation_changed = False
                    continue
            next_url = state["pages"][-1]["next_url"] if pages else query["initial_url"]
            seen_urls = {page["url"] for page in state["pages"]}
            seen_ids = {identity for item in values if (identity := self._item_identity(item)) is not None} if query["kind"] == "list" else set()
            try:
                while next_url is not None:
                    if next_url in seen_urls:
                        raise _PaginationDrift(f"Pagination loop in {scope}", "pagination_cursor", len(pages) + 1)
                    if len(pages) >= self.config.max_pages:
                        raise _ScopeCapped(f"Max pages exceeded for {scope} (NOT complete)")
                    response, value = self._request_json(next_url, scope, query["kind"], checkpointed=True, page=len(pages) + 1, scope_attempt=state["restarts"] + 1)
                    if first_items is None:
                        first_items = value
                    if query["kind"] == "object":
                        values, following = value, None
                    else:
                        for item in value:
                            identity = self._item_identity(item)
                            if identity is not None:
                                if identity in seen_ids:
                                    emit("api_pagination_check", important=True, scope=scope, page=len(pages) + 1,
                                         scope_attempt=state["restarts"] + 1, duplicate_detected=True,
                                         duplicate_id_sha256=self._identity_hash(identity),
                                         failure_category="pagination_duplicate", reason="duplicate_id")
                                    raise _PaginationDrift(f"Pagination drift: repeated ID {identity[1]} in {scope}",
                                                           "pagination_duplicate", len(pages) + 1)
                                seen_ids.add(identity)
                        values.extend(value)
                        following = self._page_next(query, response, value)
                    self.checkpoint_store.append("scope_page", {
                        **self._checkpoint_context, "page_no": len(pages) + 1,
                        "url": next_url, "next_url": following,
                        "response_sequence": response.record["checkpoint_provenance"]["event_sequence"],
                    })
                    emit("api_pagination_page", sample=following is not None, scope=scope,
                         page=len(pages) + 1, scope_attempt=state["restarts"] + 1,
                         count=1 if query["kind"] == "object" else len(value),
                         body_sha256=response.record.get("body_sha256", "")[:16],
                         reason="next_link" if following else "link_end")
                    pages.append(response)
                    seen_urls.add(next_url)
                    next_url = following
                if query["kind"] == "list" and len(pages) > 1:
                    fresh, fresh_items = self._request_json(query["initial_url"], scope + "_first_page_recheck",
                                                             "list", checkpointed=True, page=1, scope_attempt=state["restarts"] + 1)
                    check = self._first_page_check(pages[0], first_items, fresh, fresh_items)
                    matches = check["matches"]
                    emit("api_pagination_check", important=not matches or check["representation_changed"],
                         scope=scope, page=1, scope_attempt=state["restarts"] + 1, **check)
                    changed = fresh.body != pages[0].body
                    representation_changed |= changed
                    self.checkpoint_store.append("scope_validation", {
                        **self._checkpoint_context, "response_sequence": fresh.record["checkpoint_provenance"]["event_sequence"],
                        "matches_first_page": matches, "representation_changed": changed,
                        "validation": "ordered_identity_and_next_cursor",
                    })
                    if not matches:
                        raise _PaginationDrift("First page membership/order/cursor changed after pagination",
                                               check["failure_category"], 1)
            except _PaginationDrift as exc:
                self._abandon_scope(state, str(exc), category=failure_category(exc), page=exc.diagnostic_page)
                state = self._begin_scope(scope, query)
                representation_changed = False
                continue
            if validate is not None:
                validate(values)
            outcome = {**self._checkpoint_context, "status": "complete_for_query",
                       "count": 1 if query["kind"] == "object" else len(values), "pages": len(pages),
                       "query_started_at": state["query_started_at"], "completed_at": utc_iso(),
                       "claim_scope": "non_atomic_response_intervals"}
            if query["kind"] == "list":
                outcome.update(pagination_attempts=state["restarts"] + 1,
                               pagination_validation="ordered_identity_and_next_cursor",
                               representation_changed_during_validation=representation_changed)
            self.checkpoint_store.append("scope_finished", outcome)
            return values, outcome

    def collect_resumable(self, slug: str, mode: str, since: str | None = None,
                          deep_full: bool = False, *, scope_since: dict[str, str | None] | None = None) -> dict:
        """Collect independent scopes with durable retry state and cursor candidates.

        Candidates are query START times and are never committed here. A caller
        must finalize an immutable manifest before making them scheduling state.
        Rate deferrals are returned after retaining completed scopes; schedulers
        can retry this same capture without repeating successful queries or Git.
        Missing parent cursors select shallow full repairs; deep requests come
        from bounded delta items or explicit deep_full. A requested incomplete
        child withholds its selecting parent's cursor until that work is repaired.
        """
        if self.checkpoint_store is None:
            raise ValueError("collect_resumable requires a bound CheckpointStore")
        return self._collect_scopes(slug, mode, since, deep_full, scope_since=scope_since, checkpointed=True)

    def _collect_scopes(self, slug: str, mode: str, since: str | None, deep_full: bool, *,
                        scope_since: dict[str, str | None] | None = None, checkpointed: bool = False) -> dict:
        """Shared scope policy; preserve good scopes when another one fails."""
        checkpoint = self.checkpoint_store if checkpointed else None
        if mode not in ("full", "delta", "events"):
            raise ValueError("Unknown collection mode")
        self._deferred = None
        for event in reversed(checkpoint.events if checkpoint else []):
            if event["kind"] == "rate_deferral":
                data = event["data"]
                if data["retry_not_before"] > time.time():
                    self._deferred = APIRequestDeferred(data["retry_not_before"], data["reason"],
                        scope=data.get("scope"), capture_id=checkpoint.capture_id)
                break
        scope_since = dict(scope_since or {})
        for boundary in [since, *scope_since.values()]:
            if boundary is not None:
                parse_github_time(boundary)
        if checkpoint is not None:
            checkpoint.bind_options({
                "slug": slug, "mode": mode, "since": since, "scope_since": scope_since,
                "deep_full": deep_full, "api_version": self.config.api_version,
                "max_pages": self.config.max_pages, "max_response_bytes": self.config.max_response_bytes,
                "auth": "token_present" if self.token else "anonymous",
            })
        result: dict[str, Any] = {"mode": mode, "since": since, "scopes": {}, "warnings": [],
                                  "scope_statuses": {}, "failures": [], "watermark_candidates": {},
                                  "repository_id": checkpoint.repository_id if checkpoint else None,
                                  "capture_id": checkpoint.capture_id if checkpoint else None,
                                  "decode_errors": self._json_decode_errors, "unavailable_scopes": {}}
        prefix = f"/repos/{slug}"

        def run(scope, route, params=None, *, kind="list", boundary=None, validate=None):
            query = {"api_version": self.config.api_version, "initial_url": self.url(prefix + route,
                         {**(params or {}), "per_page": 100} if kind == "list" else None),
                     "kind": kind, "updated_before": boundary, "since": scope_since.get(scope, since),
                     "max_pages": self.config.max_pages, "max_response_bytes": self.config.max_response_bytes,
                     "mode": mode, "deep_full": deep_full}
            previous_context = self._checkpoint_context
            record_start, query_started_at = len(self.records), utc_iso()
            scope_started = time.monotonic()
            try:
                if checkpoint is not None:
                    value, outcome = self._run_checkpoint_scope(scope, query, validate=validate)
                else:
                    emit("api_scope_start", scope=scope, scope_attempt=1)
                    if self._deferred is not None:
                        raise self._deferred
                    value = (self.get_json(prefix + route, scope) if kind == "object" else
                             self.list_pages(prefix + route, scope, params=params,
                                             updated_before=parse_github_time(boundary) if boundary else None))
                    if validate is not None:
                        validate(value)
                    outcome = {"scope": scope, "status": "complete_for_query",
                               "count": 1 if kind == "object" else len(value),
                               "query_started_at": query_started_at, "completed_at": utc_iso(),
                               "claim_scope": "non_atomic_response_intervals", **self._scope_observations.get(scope, {})}
                result["watermark_candidates"][scope] = outcome["query_started_at"]
                emit("api_scope_end", scope=scope, status=outcome["status"], count=outcome["count"],
                     pages=outcome.get("pages"), scope_attempt=outcome.get("pagination_attempts", 1),
                     reused_from_checkpoint=outcome.get("reused_from_checkpoint", False),
                     elapsed_seconds=round(time.monotonic() - scope_started, 3))
            except Exception as exc:
                state = checkpoint.scope_state(scope) if checkpoint else None
                context = {"scope": scope, "attempt_id": state["attempt_id"] if state else None,
                           "query_started_at": state["query_started_at"] if state else query_started_at}
                status = "failed"
                if isinstance(exc, APIRequestDeferred):
                    self._deferred = exc
                    status = "deferred"
                elif isinstance(exc, _ScopeCapped):
                    status = "capped"
                elif isinstance(exc, _PaginationDrift):
                    status = "partial_drift"
                elif isinstance(exc, (CheckpointError, FileNotFoundError)):
                    status = "checkpoint_invalid"
                elif len(self.records) > record_start and self.records[-1].get("status") in (404, 410):
                    status = "unavailable"
                outcome = {**context, "status": status, "error": f"{type(exc).__name__}: {exc}"}
                matching = [record for record in self.records[record_start:] if record.get("purpose") in (
                    scope, scope + "_first_page_recheck", scope + "_resume_first_page_validation")]
                last = matching[-1] if matching else {}
                category = ("response_cap" if isinstance(exc, _ScopeCapped) else
                            "checkpoint_invalid" if isinstance(exc, CheckpointError) else failure_category(exc))
                if category == "collection_error" and type(last.get("status")) is int and last["status"] >= 400:
                    category = "upstream_http_502" if last["status"] == 502 else "http_error"
                outcome["failure_category"] = category
                response_fields = safe_fields({"status_code": last.get("status"),
                                               **self._rate_fields(last.get("headers", {}))})
                response_fields.update(safe_fields({"reset": getattr(exc, "rate_reset", None)}))
                retry_not_before = safe_fields({"retry_not_before": getattr(exc, "retry_not_before", None)})
                outcome.update(retry_not_before)
                if "status_code" in response_fields:
                    outcome["status_code"] = response_fields["status_code"]
                if "reset" in response_fields:
                    outcome["reset"] = response_fields["reset"]
                emit("api_scope_failure", important=True, scope=scope, status=status,
                     failure_category=category, error_type=type(exc).__name__,
                     scope_attempt=state["restarts"] + 1 if state else self._scope_observations.get(scope, {}).get("pagination_attempts", 1),
                     request_count=len(matching),
                     page=getattr(exc, "diagnostic_page", None), **response_fields, **retry_not_before,
                     elapsed_seconds=round(time.monotonic() - scope_started, 3))
                if isinstance(exc, APIRequestDeferred):
                    outcome.update(retry_not_before=exc.retry_not_before, lane_wide=exc.lane_wide, reason=exc.reason)
                    result["deferred"] = {"retry_not_before": exc.retry_not_before,
                                          "reason": exc.reason, "lane_wide": exc.lane_wide}
                if checkpoint is not None:
                    checkpoint.append("scope_failed" if state is not None else "scope_not_started", outcome)
                result["failures"].append(f"{scope}: {outcome['error']}")
                value = None
            finally:
                self._checkpoint_context = previous_context
            result["scopes"][scope] = outcome
            result["scope_statuses"][scope] = outcome
            return value

        def public_metadata(metadata):
            if (metadata.get("private") is not False or type(metadata.get("id")) is not int or metadata["id"] <= 0 or
                    (checkpoint is not None and metadata["id"] != checkpoint.repository_id)):
                raise RuntimeError("Repository visibility/identity does not match bound public repository")

        metadata = run("repository_metadata", "", kind="object", validate=public_metadata)
        if metadata is None:
            # Visibility/identity is a prerequisite. Preserve all prior successful
            # records, but do not query new endpoints without that prerequisite.
            names = ("events",) if mode == "events" else BASE_SCOPES[1:]
            for name in names:
                outcome = {"scope": name, "status": "not_attempted",
                           "error": "Public repository identity/visibility prerequisite incomplete"}
                if self._deferred is not None:
                    outcome.update(status="deferred", retry_not_before=self._deferred.retry_not_before,
                                   lane_wide=True)
                if checkpoint is not None:
                    checkpoint.append("scope_not_started", outcome)
                result["scopes"][name] = result["scope_statuses"][name] = outcome
            return result
        result["repository_id"] = metadata["id"]
        result["repository_full_name"] = metadata.get("full_name")
        self._repository_ids[prefix.lower()] = str(metadata["id"])
        pr_disabled = metadata.get("has_pull_requests") is False
        issue_comments_disabled = metadata.get("has_issues") is False and pr_disabled
        metadata_records = [record for record in self.records if record.get("purpose") == "repository_metadata"]
        metadata_record = metadata_records[-1] if metadata_records else {}
        if checkpoint is not None:
            metadata_state = checkpoint.scope_state("repository_metadata")
            metadata_record = checkpoint.response(metadata_state["pages"][0]["response_sequence"])
        metadata_evidence = {key: metadata_record[key] for key in (
            "body_sha256", "request_started_at", "request_completed_at", "checkpoint_provenance") if key in metadata_record}
        metadata_evidence["scope"] = "repository_metadata"
        result["repository_capabilities"] = {"has_issues": metadata.get("has_issues"),
                                               "has_pull_requests": metadata.get("has_pull_requests"),
                                               "metadata_evidence": metadata_evidence}

        def unavailable(scope, *, reason="repository_pull_requests_disabled", capabilities=None):
            outcome = {"scope": scope, "status": "unavailable", "reason": reason,
                       "capability": {**(capabilities or {"has_pull_requests": False}), "metadata_evidence": metadata_evidence},
                       "claim_scope": "API surface unavailable; no inference of historical absence"}
            emit("api_scope_unavailable", scope=scope, status="unavailable", reason=reason)
            if checkpoint is not None:
                checkpoint.append("scope_unavailable", outcome)
            result["scopes"][scope] = result["scope_statuses"][scope] = outcome
            result["unavailable_scopes"][scope] = outcome
            return None
        ordered = {"state": "all", "sort": "updated", "direction": "desc"}
        comments = {"sort": "updated", "direction": "desc"}
        definitions = [("events", "/events", {})] if mode == "events" else [
            ("issues", "/issues", ordered), ("pulls", "/pulls", ordered),
            ("issue_comments", "/issues/comments", comments),
            ("review_comments", "/pulls/comments", comments),
            ("releases", "/releases", {}), ("tags", "/tags", {}), ("events", "/events", {})]
        changed_issues: set[int] = set()
        changed_pulls: set[int] = set()
        parent_issues = {"issues": set(), "pulls": set()}
        parent_pulls = {"issues": set(), "pulls": set()}
        requested_deep_parents: set[str] = set()
        for name, route, original_params in definitions:
            boundary = scope_since.get(name, since) if mode == "delta" else None
            params = dict(original_params)
            if name in ("issues", "issue_comments", "review_comments") and boundary is not None:
                params["since"] = boundary
            def public_release(items):
                if any(item.get("draft") is True for item in items):
                    raise RuntimeError("Nonpublic draft release; refuse collection result")
            if pr_disabled and name in ("pulls", "review_comments"):
                items = unavailable(name)
            elif issue_comments_disabled and name == "issue_comments":
                items = unavailable(name, reason="repository_issues_and_pull_requests_disabled",
                                    capabilities={"has_issues": False, "has_pull_requests": False})
            else:
                items = run(name, route, params, boundary=boundary if name == "pulls" else None,
                            validate=public_release if name == "releases" else None)
            if name in parent_issues:
                deep_requested = deep_full or (mode == "delta" and boundary is not None)
                if deep_requested:
                    requested_deep_parents.add(name)
                parent_outcome = result["scopes"][name]
                parent_outcome.update(
                    query_mode="delta" if boundary is not None else ("full_shallow_repair" if mode == "delta" else "full"),
                    deep_selection="explicit_deep_full" if deep_full else (
                        "bounded_delta_items" if deep_requested else "not_requested_for_full_listing"))
                if items is not None:
                    parent_outcome.update(selected_deep_item_count=0, skipped_historical_deep_count=0)
                    for item in items:
                        number = item.get("number")
                        if type(number) is not int:
                            continue
                        if name == "pulls" and boundary and (
                                not isinstance(item.get("updated_at"), str) or
                                parse_github_time(item["updated_at"]) < parse_github_time(boundary)):
                            continue
                        if not deep_requested:
                            parent_outcome["skipped_historical_deep_count"] += 1
                            continue
                        parent_issues[name].add(number)
                        if name == "pulls" or "pull_request" in item:
                            parent_pulls[name].add(number)
                    parent_outcome["selected_deep_item_count"] = len(parent_issues[name])
                    changed_issues.update(parent_issues[name])
                    changed_pulls.update(parent_pulls[name])
            if items is None:
                continue
            if name == "events":
                result["scopes"][name]["interpretation"] = "OPPORTUNISTIC_NOT_COMPLETE"
                if len(items) >= 300:
                    result["warnings"].append("Events API reached its 300-item observation window")
        if mode != "events" and (mode == "delta" or deep_full):
            timeline_scopes, pull_scopes = [], []
            for number in sorted(changed_issues):
                name = f"issue_timeline:{number}"
                timeline_scopes.append(name)
                if pr_disabled and number in changed_pulls:
                    unavailable(name)
                else:
                    run(name, f"/issues/{number}/timeline")
            for number in sorted(changed_pulls):
                detail_name = f"pull_detail:{number}"
                pull_scopes.append(detail_name)
                detail = (unavailable(detail_name) if pr_disabled else
                          run(detail_name, f"/pulls/{number}", kind="object"))
                for endpoint in ("reviews", "commits", "files"):
                    name = f"pull_{endpoint}:{number}"
                    pull_scopes.append(name)
                    def endpoint_cap(items, endpoint=endpoint, detail=detail):
                        key, cap = ("commits", 250) if endpoint == "commits" else ("changed_files", 3000)
                        if endpoint in ("commits", "files"):
                            if detail is None:
                                raise RuntimeError("PR detail unavailable; cannot establish endpoint cap")
                            if detail.get(key, len(items)) > cap:
                                raise _ScopeCapped(f"PR {number}: {endpoint} endpoint limited to {cap}")
                    if pr_disabled:
                        unavailable(name)
                    else:
                        run(name, f"/pulls/{number}/{endpoint}", validate=endpoint_cap)
            # A parent cursor also selects its deep repair work. Advancing it
            # past an incomplete child could make that unchanged item disappear
            # from all later delta queries once the overlap window expires.
            result["watermark_withheld"] = {}
            for parent in ("issues", "pulls"):
                dependencies = {f"issue_timeline:{number}" for number in parent_issues[parent]}
                dependencies.update(f"pull_{endpoint}:{number}" for number in parent_pulls[parent]
                                    for endpoint in ("detail", "reviews", "commits", "files"))
                incomplete = sorted(name for name in dependencies
                                    if result["scopes"][name]["status"] != "complete_for_query")
                if incomplete and parent in result["watermark_candidates"]:
                    result["watermark_candidates"].pop(parent)
                    result["watermark_withheld"][parent] = {
                        "reason": "Requested deep scopes incomplete; retain parent cursor for repair",
                        "incomplete_scopes": incomplete,
                    }
            enumeration_complete = all(result["scopes"][name]["status"] == "complete_for_query"
                                       for name in requested_deep_parents)
            for name, names, count in (("deep_issue_timeline", timeline_scopes, len(changed_issues)),
                                        ("deep_pull_details", pull_scopes, len(changed_pulls))):
                complete = enumeration_complete and all(result["scopes"][key]["status"] == "complete_for_query" for key in names)
                status = ("NOT_REQUESTED" if not requested_deep_parents else
                          "complete_for_requested_items" if complete else "partial")
                result["scopes"][name] = {
                    "count": count, "status": status,
                    "claim_scope": "requested_delta_or_explicit_deep_full_items",
                    "requested_parent_scopes": sorted(requested_deep_parents),
                }
        elif mode == "full":
            for name in ("deep_issue_timeline", "deep_pull_details"):
                result["scopes"][name] = {"count": 0, "status": "NOT_COLLECTED"}
            result["warnings"].append("Full scan did not include per-item timelines/reviews; use --deep-full")
        if pr_disabled and mode != "events":
            unavailable("deep_pull_details")
        return result

    def collect(self, slug: str, mode: str, since: str | None = None,
                deep_full: bool = False) -> dict:
        """Collect independent scopes; callers must propagate returned failures.

        Successful scopes remain reviewable when a later endpoint fails. A
        declared disabled PR API is capability-unavailable, never an empty list.
        """
        return self._collect_scopes(slug, mode, since, deep_full, checkpointed=False)
