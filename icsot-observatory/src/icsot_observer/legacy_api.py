"""Conservative, read-only proof for seeding API cursors from a legacy baseline.

The caller authenticates the selected archive/index and owns a separate create-only
import receipt and database operation. This module neither changes old evidence
nor turns a combined baseline into an API lane or a new observation. An absent
proof leaves that scope at a fresh-repair boundary.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlsplit

from .core import ObjectStore, REPO_RE, canonical_json, sha256
from .github import BASE_SCOPES

# These reviewed collector commits emit exact per-scope accepted-attempt starts
# and candidates in legacy collect(). Version 0.1.0 alone is not sufficient.
REVIEWED_SOURCE_COMMITS = frozenset({
    "9ee4e9a666b50787d8bfefb0f75cf3f2e383c064",
    "07c71212f7efd0d68d538a0b4dbe99cf784bb3be",
    "fda152f194c1e1aeb762f89522dd332b6675bd62",
    "82093e67e2b2b89f58dc506c8bf56811f6578dab",
    "b2e1f2999d8d1cad0096a6606da8ed6b78deb0d5",
    "b482eabc5f3ece6cea31f9c5b8b75fc54a10adad",
    "9ca19f00aa6f7b41815ded19588665d8b2479f62",
})
_SHA = re.compile(r"[0-9a-f]{64}")
_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_ROUTE = re.compile(r"(?:/repos/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)|/repositories/(?P<id>[1-9][0-9]*))(?P<endpoint>(?:/[^/?#]+)*)")
_FULL_PARAMS = {
    "issues": {"state": "all", "sort": "updated", "direction": "desc"},
    "pulls": {"state": "all", "sort": "updated", "direction": "desc"},
    "issue_comments": {"sort": "updated", "direction": "desc"},
    "review_comments": {"sort": "updated", "direction": "desc"},
}
_ENDPOINTS = {"repository_metadata": "", "issues": "/issues", "pulls": "/pulls",
              "issue_comments": "/issues/comments", "review_comments": "/pulls/comments",
              "releases": "/releases", "tags": "/tags", "events": "/events"}


class LegacyAPISeedError(ValueError):
    """A selected source binding cannot be authenticated against these inputs."""


class _Unproven(ValueError):
    pass


def _time(value) -> datetime:
    if not isinstance(value, str):
        raise _Unproven("invalid_utc_interval")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise _Unproven("invalid_utc_interval") from error


def _json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("Nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def _source(path: Path, digest: str, maximum: int, *, canonical=False) -> tuple[dict, bytes]:
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise LegacyAPISeedError("Expected an exact source SHA-256")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise LegacyAPISeedError("Source file is absent, linked, or above the validation bound")
    raw = path.read_bytes()
    if len(raw) > maximum or sha256(raw) != digest:
        raise LegacyAPISeedError("Selected source digest differs")
    try:
        value = _json(raw)
        if not isinstance(value, dict) or (canonical and canonical_json(value) != raw):
            raise ValueError()
    except (ValueError, UnicodeError, TypeError) as error:
        raise LegacyAPISeedError("Selected source JSON is invalid or ambiguous") from error
    return value, raw


def _identity(item: dict):
    for field in ("id", "node_id", "sha", "name", "filename"):
        value = item.get(field)
        if (type(value) is int and value > 0) or (isinstance(value, str) and value):
            return field, str(value)
    raise _Unproven("entity_identity_unproven")


def _next(record: dict) -> str | None:
    headers = record.get("headers")
    if not isinstance(headers, dict) or not isinstance(headers.get("link", ""), str):
        raise _Unproven("response_envelope_unproven")
    matches = _NEXT.findall(headers.get("link", ""))
    if len(matches) > 1:
        raise _Unproven("next_cursor_ambiguous")
    return matches[0] if matches else None


def _url(url, endpoint: str, params: dict, slug: str, repository_id: int, *, initial=False):
    if not isinstance(url, str):
        raise _Unproven("page_query_unproven")
    parsed = urlsplit(url)
    route = _ROUTE.fullmatch(parsed.path)
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.fragment or
            not route or route["endpoint"] != endpoint):
        raise _Unproven("page_query_unproven")
    if ((route["id"] is not None and int(route["id"]) != repository_id) or
            (route["slug"] is not None and route["slug"].lower() != slug.lower()) or
            (initial and route["slug"] is None)):
        raise _Unproven("page_repository_unproven")
    query = parse_qs(parsed.query, keep_blank_values=True)
    expected = {key: [str(value)] for key, value in params.items()}
    if any(query.get(key) != value for key, value in expected.items()):
        raise _Unproven("page_query_changed")
    if set(query) - set(expected) - (set() if initial else {"page", "after", "before", "cursor"}):
        raise _Unproven("page_query_changed")


def seed_proof_digest(receipt: dict) -> str:
    """Digest the deterministic validation projection, excluding its own digest."""
    return sha256(canonical_json({key: value for key, value in receipt.items() if key != "proof_sha256"}))


def validate_legacy_api_seed(root: Path, manifest_path: Path, *, expected_manifest_sha256: str,
                             source_index_path: Path, expected_index_sha256: str,
                             repository_id: int, slug: str, api_version: str,
                             history_policy: dict | None = None) -> dict:
    """Return original, proven FULL-query cursors; never write evidence or state.

    Exact selected source bytes bind this proof. They must already be selected
    through the caller's authenticated archive/index workflow. Unknown code,
    historical count-only schemas, delta queries and history-policy changes do
    not create inferred cursors. Import identity/time belong to the caller.
    """
    root, manifest_path, source_index_path = Path(root).resolve(), Path(manifest_path), Path(source_index_path)
    if type(repository_id) is not int or repository_id <= 0 or not isinstance(slug, str) or not REPO_RE.fullmatch(slug):
        raise LegacyAPISeedError("Positive repository identity and declared slug required")
    if not isinstance(api_version, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", api_version):
        raise LegacyAPISeedError("Explicit target API version required")
    source, raw = _source(manifest_path, expected_manifest_sha256, 32 * 1024 * 1024, canonical=True)
    index, _ = _source(source_index_path, expected_index_sha256, 16 * 1024 * 1024)
    rows, result = index.get("manifests"), index.get("collector_result")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or not isinstance(result, dict):
        raise LegacyAPISeedError("Index must bind exactly one original baseline manifest")
    row = rows[0]
    locator = row.get("path")
    if not isinstance(locator, str) or not locator or "\\" in locator:
        raise LegacyAPISeedError("Invalid source manifest locator")
    relative = PurePosixPath(locator)
    if relative.is_absolute() or any(part in (".", "..") for part in relative.parts) or relative.as_posix() != locator:
        raise LegacyAPISeedError("Invalid source manifest locator")
    if ((root / locator).resolve() != manifest_path.resolve() or not manifest_path.resolve().is_relative_to(root) or
            not locator.startswith(f"runs/{repository_id}/") or row.get("bytes") != len(raw) or
            row.get("sha256") != expected_manifest_sha256):
        raise LegacyAPISeedError("Index manifest locator/digest differs from the selected source")
    if (source.get("repository_id") != repository_id or not isinstance(source.get("repository_input_slug"), str) or
            source["repository_input_slug"].lower() != slug.lower() or not isinstance(index.get("repository"), str) or
            index["repository"].lower() != slug.lower() or
            (index.get("repository_id") is not None and index["repository_id"] != repository_id) or
            row.get("repository_id") != repository_id or result.get("repository_id") != repository_id or
            not isinstance(result.get("repo"), str) or result["repo"].lower() != slug.lower() or
            result.get("manifest_sha256") != expected_manifest_sha256):
        raise LegacyAPISeedError("Original source repository identity differs")
    for field in ("run_id", "status"):
        if row.get(field) != source.get(field) or result.get(field) != source.get(field):
            raise LegacyAPISeedError("Index and manifest observation identity differ")
    if row.get("mode") != source.get("mode") or index.get("schema_version") != 1 or source.get("schema_version") != 1:
        raise LegacyAPISeedError("Original source schema/mode differs")
    if any(row.get(field) != source.get(field) for field in ("started_at", "finished_at", "public_config_sha256")):
        raise LegacyAPISeedError("Index and manifest observation metadata differ")
    try:
        started, finished = _time(source.get("started_at")), _time(source.get("finished_at"))
        if finished < started:
            raise _Unproven("invalid_utc_interval")
    except _Unproven as error:
        raise LegacyAPISeedError("Original observation interval is unproven") from error
    policy = history_policy if history_policy is not None else {"profile": "full_history"}
    if not isinstance(policy, dict):
        raise LegacyAPISeedError("Target history policy must be explicit metadata")
    public = source.get("public_config")
    if not isinstance(public, dict) or source.get("public_config_sha256") != sha256(canonical_json(public)):
        raise LegacyAPISeedError("Original public configuration digest differs")
    api = source.get("api") if isinstance(source.get("api"), dict) else {}
    statuses = api.get("scope_statuses") if isinstance(api.get("scope_statuses"), dict) else {}
    candidates = api.get("watermark_candidates") if isinstance(api.get("watermark_candidates"), dict) else {}
    failures = source.get("failures")
    proof = {"schema_version": 1, "kind": "icsot_legacy_api_seed_validation", "repository_id": repository_id, "slug": slug,
        "source_index_sha256": expected_index_sha256, "source_manifest_sha256": expected_manifest_sha256,
        "source_index_manifest_locator": locator, "source_collector_code_sha": index.get("collector_code_sha"),
        "source_public_config_sha256": source["public_config_sha256"], "source_status": source.get("status"),
        "source_mode": source.get("mode"), "source_failure_count": len(failures) if isinstance(failures, list) else None,
        "source_index_status": index.get("status") if index.get("status") in ("complete_for_declared_shallow_baseline", "incomplete") else "unknown",
        "source_index_complete": index.get("complete") if type(index.get("complete")) is bool else None,
        "source_index_capture_accepted": index.get("capture_accepted") if type(index.get("capture_accepted")) is bool else None,
        "source_observation_interval": {"started_at": source["started_at"], "finished_at": source["finished_at"]},
        "history_policy": json.loads(canonical_json(policy)), "eligible_watermarks": {}, "scope_decisions": {},
        "observation_claim": "derived_original_intervals_not_a_new_observation",
        "validation_policy": "reviewed_legacy_full_v1"}
    common_reason = None
    if not isinstance(index.get("collector_code_sha"), str) or index["collector_code_sha"] not in REVIEWED_SOURCE_COMMITS or source.get("collector_version") != "0.1.0":
        common_reason = "source_collector_not_reviewed"
    elif (source.get("lane") is not None or source.get("mode") != "full" or api.get("mode") != "full" or
          source.get("since") is not None or api.get("since") is not None or source.get("scope_since") or api.get("scope_since")):
        common_reason = "source_full_query_unproven"
    elif (source.get("api_version") != api_version or public.get("api_version") != api_version or
          public.get("history_profile", "full_history") != "full_history" or public.get("history_cutoff_utc") is not None or
          api.get("history_policy") is not None or source.get("history_policy") is not None or
          policy.get("profile") != "full_history" or policy.get("cutoff_utc") is not None):
        common_reason = "api_or_history_policy_incompatible"
    elif api.get("repository_id") != repository_id or source.get("status") not in ("complete", "partial"):
        common_reason = "source_scope_schema_unproven"
    if any(not isinstance(api.get(name, {}), dict) for name in ("watermark_withheld", "unavailable_scopes", "scopes")):
        common_reason = common_reason or "source_scope_schema_unproven"
    max_pages, max_bytes = public.get("max_pages"), public.get("max_response_bytes")
    if type(max_pages) is not int or not 1 <= max_pages <= 1_000_000 or type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 * 1024:
        common_reason = common_reason or "source_capture_caps_unproven"
    records = source.get("responses")
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        common_reason = common_reason or "source_responses_unproven"
    store = ObjectStore(root)
    audited = {}

    def body(record):
        if (record.get("status") != 200 or type(record.get("status")) is not int or record.get("error") is not None or
                record.get("method") != "GET" or record.get("api_version") != api_version or record.get("checkpoint_provenance")):
            raise _Unproven("accepted_attempt_response_unproven")
        if (not isinstance(record.get("headers"), dict) or
                record["headers"].get("x-github-api-version-selected", api_version) != api_version):
            raise _Unproven("response_api_version_unproven")
        digest, size = record.get("body_sha256"), record.get("body_bytes")
        if not isinstance(digest, str) or not _SHA.fullmatch(digest) or type(size) is not int or not 0 <= size <= max_bytes:
            raise _Unproven("raw_response_cap_or_digest_unproven")
        path = store.location(digest)
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file() or path.stat().st_size != size:
            raise _Unproven("raw_response_missing_or_corrupt")
        raw_body = path.read_bytes()
        if len(raw_body) != size or sha256(raw_body) != digest:
            raise _Unproven("raw_response_missing_or_corrupt")
        try:
            return _json(raw_body), raw_body
        except (ValueError, UnicodeError) as error:
            raise _Unproven("raw_response_json_unproven") from error

    def audit(scope, endpoint, *, object_kind=False):
        if scope in audited:
            return audited[scope]
        outcome, candidate = statuses.get(scope), candidates.get(scope)
        if not isinstance(outcome, dict) or outcome.get("status") != "complete_for_query":
            raise _Unproven("scope_not_complete_for_query")
        if (api.get("scopes") or {}).get(scope) != outcome:
            raise _Unproven("scope_outcome_ambiguous")
        if scope in (api.get("watermark_withheld") or {}) or scope in (api.get("unavailable_scopes") or {}):
            raise _Unproven("scope_watermark_withheld_or_unavailable")
        if candidate is None or outcome.get("query_started_at") != candidate:
            raise _Unproven("exact_scope_candidate_missing")
        begin, end = _time(candidate), _time(outcome.get("completed_at"))
        if not started <= begin <= end <= finished or outcome.get("claim_scope") != "non_atomic_response_intervals":
            raise _Unproven("accepted_attempt_interval_unproven")
        selected, checks = [], []
        for record in records:
            purpose = record.get("purpose")
            if purpose not in (scope, scope + "_first_page_recheck"):
                continue
            request_start, request_end = _time(record.get("request_started_at")), _time(record.get("request_completed_at"))
            if not started <= request_start <= request_end <= finished:
                raise _Unproven("response_interval_unproven")
            if request_end < begin:
                continue  # An archived abandoned attempt is not a winning page.
            if request_start < begin or request_end > end:
                raise _Unproven("accepted_attempt_ambiguous")
            (selected if purpose == scope else checks).append(record)
        if not selected or (object_kind and (len(selected) != 1 or checks)):
            raise _Unproven("accepted_attempt_pages_unproven")
        # Keep replay bounded even if a source declares very large capture caps.
        if any(type(record.get("body_bytes")) is not int for record in selected + checks) or sum(
                record["body_bytes"] for record in selected + checks) > 128 * 1024 * 1024:
            raise _Unproven("scope_validation_byte_bound")
        params = {} if object_kind else {**_FULL_PARAMS.get(scope, {}), "per_page": 100}
        initial = selected[0].get("url")
        _url(initial, endpoint, params, slug, repository_id, initial=True)
        current, seen_urls, seen_ids, values, pages = initial, set(), set(), [], []
        prior_end = None
        for record in selected:
            if record.get("url") != current or current in seen_urls or len(pages) >= max_pages:
                raise _Unproven("accepted_attempt_page_lineage_unproven")
            _url(current, endpoint, params, slug, repository_id)
            if prior_end is not None and _time(record["request_started_at"]) < prior_end:
                raise _Unproven("accepted_attempt_ambiguous")
            prior_end = _time(record["request_completed_at"])
            value, raw_body = body(record)
            seen_urls.add(current)
            if object_kind:
                if not isinstance(value, dict) or _next(record) is not None:
                    raise _Unproven("object_scope_unproven")
                values = value
            else:
                if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
                    raise _Unproven("page_shape_unproven")
                for item in value:
                    identity = _identity(item)
                    if identity in seen_ids:
                        raise _Unproven("pagination_duplicate")
                    seen_ids.add(identity)
                values.extend(value)
            pages.append((record, value, raw_body))
            current = _next(record)
            if current is not None:
                _url(current, endpoint, params, slug, repository_id)
        if current is not None or outcome.get("count") != (1 if object_kind else len(values)):
            raise _Unproven("scope_end_or_count_unproven")
        if not object_kind:
            if (type(outcome.get("pagination_attempts")) is not int or outcome["pagination_attempts"] not in (1, 2) or
                    outcome.get("pagination_validation") != "ordered_identity_and_next_cursor"):
                raise _Unproven("pagination_validation_unproven")
            if len(checks) != (1 if len(pages) > 1 else 0):
                raise _Unproven("first_page_recheck_unproven")
            if checks:
                check = checks[0]
                if check.get("url") != initial or _time(check["request_started_at"]) < _time(selected[-1]["request_completed_at"]):
                    raise _Unproven("first_page_recheck_unproven")
                fresh, fresh_raw = body(check)
                if not isinstance(fresh, list) or any(not isinstance(item, dict) for item in fresh):
                    raise _Unproven("first_page_recheck_unproven")
                original_ids = [_identity(item) for item in pages[0][1]]
                fresh_ids = [_identity(item) for item in fresh]
                if (_next(check) != _next(pages[0][0]) or
                        (fresh_raw != pages[0][2] and (not original_ids or len(set(fresh_ids)) != len(fresh_ids) or original_ids != fresh_ids))):
                    raise _Unproven("first_page_drift")
        evidence = {"original_query_started_at": candidate, "original_completed_at": outcome["completed_at"],
                    "pages_verified": len(pages), "response_envelopes_sha256": sha256(canonical_json(selected + checks)),
                    "raw_response_bytes_verified": sum(record["body_bytes"] for record in selected + checks)}
        audited[scope] = values, evidence
        return values, evidence

    metadata_reason = None
    if common_reason is None:
        try:
            metadata, _ = audit("repository_metadata", "", object_kind=True)
            if metadata.get("id") != repository_id or type(metadata.get("id")) is not int or metadata.get("private") is not False:
                raise _Unproven("public_identity_unproven")
        except (_Unproven, OSError, TypeError, KeyError, ValueError) as error:
            metadata_reason = str(error) if isinstance(error, _Unproven) else "public_identity_proof_unavailable"
    for scope in BASE_SCOPES:
        reason = common_reason or metadata_reason
        try:
            if reason:
                raise _Unproven(reason)
            values, evidence = audit(scope, _ENDPOINTS[scope], object_kind=scope == "repository_metadata")
            if scope == "releases" and any(item.get("draft") is True for item in values):
                raise _Unproven("public_release_visibility_unproven")
            if scope in ("issues", "pulls"):
                parent = statuses[scope]
                deep_full = public.get("deep_full")
                if parent.get("query_mode") != "full":
                    raise _Unproven("parent_query_mode_unproven")
                if deep_full is False and parent.get("deep_selection") == "not_requested_for_full_listing":
                    evidence["deep_history_coverage"] = "not_collected_by_original_shallow_baseline"
                elif deep_full is True and parent.get("deep_selection") == "explicit_deep_full":
                    children = {}
                    for item in values:
                        number = item.get("number")
                        if type(number) is not int or number <= 0:
                            raise _Unproven("deep_parent_identity_unproven")
                        child = f"issue_timeline:{number}"
                        _, children[child] = audit(child, f"/issues/{number}/timeline")
                        if scope == "pulls" or "pull_request" in item:
                            detail, children[f"pull_detail:{number}"] = audit(f"pull_detail:{number}", f"/pulls/{number}", object_kind=True)
                            for name in ("reviews", "commits", "files"):
                                child = f"pull_{name}:{number}"
                                _, children[child] = audit(child, f"/pulls/{number}/{name}")
                            if (type(detail.get("commits")) is not int or not 0 <= detail["commits"] <= 250 or
                                    type(detail.get("changed_files")) is not int or not 0 <= detail["changed_files"] <= 3000):
                                raise _Unproven("deep_endpoint_cap_unproven")
                    evidence["deep_history_coverage"] = "original_requested_children_verified"
                    evidence["deep_child_proof_sha256"] = sha256(canonical_json(children))
                else:
                    raise _Unproven("parent_deep_selection_unproven")
            if scope == "events":
                evidence["claim_scope"] = "original_native_opportunistic_events_not_complete_history"
            proof["eligible_watermarks"][scope] = candidates[scope]
            proof["scope_decisions"][scope] = {"status": "eligible", "reason": "original_full_query_verified", **evidence}
        except (_Unproven, OSError, TypeError, KeyError, ValueError) as error:
            # File/shape ambiguity is a scope repair, not a fabricated cursor.
            code = str(error) if isinstance(error, _Unproven) else "scope_proof_unavailable"
            proof["scope_decisions"][scope] = {"status": "fresh_repair", "reason": code}
    proof["proof_sha256"] = seed_proof_digest(proof)
    return proof
