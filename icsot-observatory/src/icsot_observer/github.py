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
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .core import Config, ObjectStore, parse_github_time, sha256, utc_iso

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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # preserve source identity; never forward bearer token on redirects


@dataclass
class Response:
    body: bytes
    record: dict[str, Any]


class GitHubAPI:
    """Captures original HTTP body and a redacted provenance envelope."""

    def __init__(self, config: Config, store: ObjectStore, records: list[dict]):
        self.config, self.store, self.records = config, store, records
        self.token = os.getenv(config.token_env, "").strip()
        self.opener = urllib.request.build_opener(NoRedirect)
        self.requests = 0
        self.primary_rate_waited_seconds = 0.0
        self.secondary_rate_waited_seconds = 0.0
        self._last_rate_record: dict | None = None
        self._repository_ids: dict[str, str] = {}

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

    def _preserve_primary_reserve(self, purpose: str) -> None:
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
            duration = max(1.0, int(headers["x-ratelimit-reset"]) - time.time() + 1.0)
        except (KeyError, TypeError, ValueError, OverflowError):
            duration = None
        available = self.config.primary_rate_wait_seconds - self.primary_rate_waited_seconds
        if duration is None or duration > available:
            raise RuntimeError(f"Rate-limit reserve reached for {purpose}; preserve transfer capacity and retry later")
        record["primary_rate_reserve_wait_seconds"] = duration
        self.primary_rate_waited_seconds += duration
        time.sleep(duration)
        self._last_rate_record = None  # reset elapsed; obtain current headers on the next request

    def get(self, url: str, purpose: str) -> Response:
        self.validate_url(url)
        self._preserve_primary_reserve(purpose)
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
                self.records.append({
                    "purpose": purpose, "url": url, "request_started_at": started,
                    "request_completed_at": completed, "status": None,
                    "error": type(e).__name__, "attempt": attempt + 1,
                })
                if attempt < 3:
                    time.sleep(min(8, (2 ** attempt) + random.random()))
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
            self.records.append(rec)
            self._last_rate_record = rec
            self.requests += 1
            if failure is None and status == 200:
                return Response(body=body, record=rec)

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
                    time.sleep(duration)
                    continue
                raise RuntimeError(f"Rate-limit budget exhausted for {purpose}; retry in next scheduled run")
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
                    time.sleep(duration)
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
                    time.sleep(duration)
                    continue
            raise RuntimeError(f"API failure {purpose}: HTTP {status}, {failure or 'unexpected status'}")
        raise AssertionError("unreachable")

    def get_json(self, path: str, purpose: str) -> dict:
        r = self.get(self.url(path), purpose)
        obj = json.loads(r.body)
        if not isinstance(obj, dict):
            raise ValueError(f"Expected JSON object for {purpose}")
        route = _REPOSITORY_PATH_RE.fullmatch(path)
        if route and not route["endpoint"] and type(obj.get("id")) is int and obj["id"] > 0:
            self._repository_ids[route["repository"].lower()] = str(obj["id"])
        return obj

    def list_pages(self, path: str, purpose: str, *, params: dict | None = None,
                   updated_before: datetime | None = None) -> list[dict]:
        """Follow Link headers; early stop ONLY on PR sort=updated desc boundary.

        Always retains original bytes even if a later page fails. Caller marks run incomplete.
        """
        url = self.url(path, {**(params or {}), "per_page": 100})
        first_page = url
        first_route = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(url).path)
        assert first_route is not None  # self.url validated the initial endpoint.
        canonical_repository_id = first_route["id"] or self._repository_ids.get(first_route["repository"].lower())
        first_digest = None
        all_items: list[dict] = []
        seen_urls: set[str] = set()
        seen_ids: set[str] = set()
        for page_no in range(1, self.config.max_pages + 1):
            if url in seen_urls:
                raise RuntimeError(f"Pagination loop in {purpose}")
            seen_urls.add(url)
            resp = self.get(url, purpose)
            if page_no == 1:
                first_digest = resp.record["body_sha256"]
            obj = json.loads(resp.body)
            if not isinstance(obj, list) or any(not isinstance(item, dict) for item in obj):
                raise ValueError(f"Unexpected page JSON for {purpose}, page {page_no}")
            for item in obj:
                entity_id = item.get("id")
                if entity_id is not None:
                    unique = str(entity_id)
                    if unique in seen_ids:
                        raise RuntimeError(f"Pagination drift: repeated ID {unique} in {purpose}")
                    seen_ids.add(unique)
            all_items.extend(obj)

            # Bound scanning of PR listing (which has no 'since' parameter).
            if updated_before is not None and obj and all(
                isinstance(x.get("updated_at"), str) and
                parse_github_time(x["updated_at"]) < updated_before for x in obj
            ):
                break

            link = resp.record["headers"].get("link", "")
            match = _NEXT_RE.search(link)
            if not match:
                break
            url = match.group(1)
            self.validate_url(url)
            route = _REPOSITORY_PATH_RE.fullmatch(urllib.parse.urlsplit(url).path)
            assert route is not None  # validate_url checked the opaque Link URL.
            if route["endpoint"] != first_route["endpoint"]:
                raise RuntimeError(f"Unexpected endpoint changed across pagination for {purpose}")
            if route["id"] is not None:
                # GitHub legitimately canonicalizes slug routes to stable numeric
                # routes in Link. Bind that ID to known metadata, or to the first
                # authenticated-origin Link if list_pages was used standalone.
                if canonical_repository_id is not None and route["id"] != canonical_repository_id:
                    raise RuntimeError(f"Unexpected repository changed across pagination for {purpose}")
                canonical_repository_id = route["id"]
            elif route["repository"].lower() != first_route["repository"].lower():
                raise RuntimeError(f"Unexpected repository changed across pagination for {purpose}")
        else:
            raise RuntimeError(f"Max pages exceeded for {purpose} (NOT complete)")

        # A second first-page read helps detect moving-window pagination drift.
        if len(seen_urls) > 1:
            check = self.get(first_page, purpose + "_first_page_recheck")
            if check.record["body_sha256"] != first_digest:
                raise RuntimeError(f"Pagination non-atomic: first page changed for {purpose}; retry later")
        return all_items

    def collect(self, slug: str, mode: str, since: str | None = None,
                deep_full: bool = False) -> dict:
        """Report collections by scope. Metadata and per-request times are always archived."""
        prefix = f"/repos/{slug}"
        result: dict[str, Any] = {"mode": mode, "since": since, "scopes": {}, "warnings": []}
        metadata = self.get_json(prefix, "repository_metadata")
        if metadata.get("private") is not False:
            raise RuntimeError("Refusing any non-public repository (or unknown visibility)")
        if not isinstance(metadata.get("id"), int):
            raise RuntimeError("No stable GitHub numeric repository ID")
        result["repository_id"] = metadata["id"]
        result["repository_full_name"] = metadata.get("full_name")
        if mode == "events":
            scopes = [("events", "/events", {})]
        else:
            p = {"state": "all", "sort": "updated", "direction": "desc"}
            if mode == "delta" and since is not None:
                issue_params = {**p, "since": since}
                comment_params = {"sort": "updated", "direction": "desc", "since": since}
            else:
                issue_params = p
                comment_params = {"sort": "updated", "direction": "desc"}
            scopes = [
                ("issues", "/issues", issue_params),
                ("pulls", "/pulls", p),
                ("issue_comments", "/issues/comments", comment_params),
                ("review_comments", "/pulls/comments", comment_params),
                ("releases", "/releases", {}),
                ("tags", "/tags", {}),
                ("events", "/events", {}),
            ]
        changed_issue_nums: set[int] = set()
        changed_pull_nums: set[int] = set()
        for name, route, params in scopes:
            stop_at = parse_github_time(since) if name == "pulls" and mode == "delta" and since else None
            items = self.list_pages(prefix + route, name, params=params, updated_before=stop_at)
            result["scopes"][name] = {"count": len(items), "status": "complete_for_query"}
            if name == "issues":
                for item in items:
                    if isinstance(item.get("number"), int):
                        changed_issue_nums.add(item["number"])
                        if "pull_request" in item:
                            changed_pull_nums.add(item["number"])
            if name == "pulls":
                for item in items:
                    if isinstance(item.get("number"), int):
                        # PR API has no since parameter; the boundary page may contain older items.
                        if mode == "delta" and since is not None and (
                            not isinstance(item.get("updated_at"), str) or
                            parse_github_time(item["updated_at"]) < parse_github_time(since)
                        ):
                            continue
                        changed_pull_nums.add(item["number"])
                        changed_issue_nums.add(item["number"])
            if name == "releases" and any(item.get("draft") is True for item in items):
                raise RuntimeError("Nonpublic draft release in authenticated response; refuse publication/collection result")
            if name == "events":
                result["scopes"][name]["interpretation"] = "OPPORTUNISTIC_NOT_COMPLETE"
                if len(items) >= 300:
                    result["warnings"].append("Events API reached its 300-item observation window")
        if mode != "events" and (mode == "delta" or deep_full):
            # In full mode, deep coverage is explicit and can be expensive.
            for n in sorted(changed_issue_nums):
                self.list_pages(f"{prefix}/issues/{n}/timeline", f"issue_timeline:{n}")
            for n in sorted(changed_pull_nums):
                detail = self.get_json(f"{prefix}/pulls/{n}", f"pull_detail:{n}")
                self.list_pages(f"{prefix}/pulls/{n}/reviews", f"pull_reviews:{n}")
                commits = self.list_pages(f"{prefix}/pulls/{n}/commits", f"pull_commits:{n}")
                files = self.list_pages(f"{prefix}/pulls/{n}/files", f"pull_files:{n}")
                # Documented GitHub endpoint caps; never mark a capped list complete.
                if detail.get("commits", len(commits)) > 250:
                    raise RuntimeError(f"PR {n}: commits endpoint limited to 250; full commit graph required")
                if detail.get("changed_files", len(files)) > 3000:
                    raise RuntimeError(f"PR {n}: files endpoint limited to 3000; alternate evidence required")
            result["scopes"]["deep_issue_timeline"] = {"count": len(changed_issue_nums), "status": "complete_for_enumerated_issues"}
            result["scopes"]["deep_pull_details"] = {"count": len(changed_pull_nums), "status": "complete_for_enumerated_pulls"}
        elif mode == "full":
            result["scopes"]["deep_issue_timeline"] = {"count": 0, "status": "NOT_COLLECTED"}
            result["scopes"]["deep_pull_details"] = {"count": 0, "status": "NOT_COLLECTED"}
            result["warnings"].append("Full scan did not include per-item timelines/reviews; use --deep-full in a rate-budgeted backfill")
        return result
