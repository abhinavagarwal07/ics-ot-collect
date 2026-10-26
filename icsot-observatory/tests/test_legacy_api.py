"""Import proof tests use generated pages only, without keys, assets, or network."""
import copy
import json
from dataclasses import asdict
from datetime import timedelta
from urllib.parse import urlsplit

import pytest

from icsot_observer.core import Config, ObjectStore, canonical_json, parse_github_time, sha256, utc_iso, utc_now
from icsot_observer.github import BASE_SCOPES, GitHubAPI
from icsot_observer.legacy_api import LegacyAPISeedError, seed_proof_digest, validate_legacy_api_seed

CODE = "fda152f194c1e1aeb762f89522dd332b6675bd62"
META = "https://api.github.com/repos/test/repo"
ISSUES = META + "/issues?state=all&sort=updated&direction=desc&per_page=100"
NEXT = "https://api.github.com/repositories/42/issues?state=all&sort=updated&direction=desc&per_page=100&page=2"


class Reply:
    status = 200
    def __init__(self, value, headers=None):
        self.body, self.headers = json.dumps(value).encode(), headers or {}
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, maximum):
        return self.body[:maximum]


class Source:
    def __init__(self, root, *, deep_full=False, cap=False):
        self.root = root / "evidence"
        config = Config(self.root, ("test/repo",), "2026-03-10", "test", "LEGACY_SEED_TEST_NO_TOKEN", 5, 1_000_000, 48, 20)
        self.store = ObjectStore(self.root)
        api = GitHubAPI(config, self.store, [])
        def handler(request, timeout):
            url, path = request.full_url, urlsplit(request.full_url).path
            if url == META:
                return Reply({"id": 42, "private": False, "full_name": "test/repo", "has_pull_requests": True})
            if url == ISSUES:
                return Reply([{"id": 1, "number": 1}], {"Link": f'<{NEXT}>; rel="next"'})
            if url == NEXT:
                return Reply([{"id": 2, "number": 2}])
            if path == "/repos/test/repo/pulls":
                return Reply([{"id": 3, "number": 3}])
            if path in ("/repos/test/repo/issues/comments", "/repos/test/repo/pulls/comments"):
                return Reply([{"id": 4 if "/issues/" in path else 5}])
            if path.endswith("/releases"):
                return Reply([{"id": 6, "draft": False}])
            if path.endswith("/tags"):
                return Reply([{"name": "v1"}])
            if path.endswith("/events"):
                return Reply([{"id": 7}])
            if path == "/repos/test/repo/pulls/3":
                return Reply({"commits": 251 if cap else 0, "changed_files": 0})
            return Reply([])
        api.opener.open = handler
        started = utc_iso(utc_now() - timedelta(seconds=1))
        result = api.collect("test/repo", "full", deep_full=deep_full)
        public = {key: value for key, value in asdict(config).items() if key not in ("root", "token_env")}
        public["deep_full"] = deep_full
        self.manifest = {"schema_version": 1, "collector_version": "0.1.0", "run_id": "original-run", "capture_id": "original-capture",
            "repository_id": 42, "repository_input_slug": "test/repo", "mode": "full", "since": None,
            "status": "partial" if result["failures"] else "complete", "started_at": started, "finished_at": utc_iso(),
            "api_version": config.api_version, "public_config": public, "api": result, "responses": api.records,
            "failures": result["failures"], "git": {"retained_original": True}}
        self.path = self.root / "runs/42/original-run.manifest.json"
        self.path.parent.mkdir(parents=True)
        self.index_path = root / "original.index.json"
        self.index = {"schema_version": 1, "repository": "test/repo", "collector_code_sha": CODE,
                      "complete": not cap, "capture_accepted": not cap,
                      "status": "incomplete" if cap else "complete_for_declared_shallow_baseline"}
        self.write()

    def write(self):
        self.manifest["public_config_sha256"] = sha256(canonical_json(self.manifest["public_config"]))
        raw = canonical_json(self.manifest)
        self.path.write_bytes(raw)
        self.manifest_sha = sha256(raw)
        self.index["manifests"] = [{"path": self.path.relative_to(self.root).as_posix(), "bytes": len(raw), "sha256": self.manifest_sha,
            **{field: self.manifest[field] for field in ("repository_id", "run_id", "status", "mode", "started_at", "finished_at", "public_config_sha256")}}]
        self.index["collector_result"] = {"repo": "test/repo", "manifest_sha256": self.manifest_sha,
            **{field: self.manifest[field] for field in ("repository_id", "run_id", "status")}}
        self.write_index()

    def write_index(self):
        raw = json.dumps(self.index, indent=2).encode()
        self.index_path.write_bytes(raw)
        self.index_sha = sha256(raw)

    def validate(self, **changes):
        kwargs = {"expected_manifest_sha256": self.manifest_sha, "source_index_path": self.index_path,
                  "expected_index_sha256": self.index_sha, "repository_id": 42, "slug": "test/repo", "api_version": "2026-03-10"}
        return validate_legacy_api_seed(self.root, self.path, **{**kwargs, **changes})

    def record(self, purpose, ordinal=0):
        return [record for record in self.manifest["responses"] if record["purpose"] == purpose][ordinal]

    def rewrite_body(self, record, value):
        raw = json.dumps(value).encode()
        record.update(body_sha256=self.store.put(raw), body_bytes=len(raw))


@pytest.fixture
def source(tmp_path):
    return Source(tmp_path)


def test_modern_full_seed_preserves_original_times_and_deterministic_source_proof(source):
    before = {path.relative_to(source.root).as_posix(): path.read_bytes() for path in source.root.rglob("*") if path.is_file()}
    receipt = source.validate()
    assert receipt["eligible_watermarks"] == {scope: source.manifest["api"]["watermark_candidates"][scope] for scope in BASE_SCOPES}
    assert receipt == source.validate() and receipt["proof_sha256"] == seed_proof_digest(receipt)
    assert receipt["source_index_sha256"] == source.index_sha
    assert receipt["source_manifest_sha256"] == source.manifest_sha
    assert receipt["source_observation_interval"]["started_at"] == source.manifest["started_at"]
    assert receipt["observation_claim"] == "derived_original_intervals_not_a_new_observation"
    assert all(key not in receipt for key in ("imported_at", "lane", "capture_id", "jobs"))
    issue = receipt["scope_decisions"]["issues"]
    assert issue["pages_verified"] == 2 and issue["deep_history_coverage"] == "not_collected_by_original_shallow_baseline"
    assert receipt["scope_decisions"]["events"]["claim_scope"] == "original_native_opportunistic_events_not_complete_history"
    assert before == {path.relative_to(source.root).as_posix(): path.read_bytes() for path in source.root.rglob("*") if path.is_file()}


def test_partial_source_only_seeds_independently_complete_scopes(source):
    source.manifest.update(status="partial", failures=["issues: retained original failure"])
    api = source.manifest["api"]
    api["scope_statuses"]["issues"]["status"] = "partial_drift"
    api["watermark_candidates"].pop("issues")
    source.write()
    receipt = source.validate()
    assert receipt["source_status"] == "partial" and receipt["source_failure_count"] == 1
    assert "issues" not in receipt["eligible_watermarks"] and "pulls" in receipt["eligible_watermarks"]
    assert receipt["scope_decisions"]["issues"]["status"] == "fresh_repair"


def test_transport_incomplete_summary_is_retained_without_replacing_scope_proof(source):
    source.index.update(complete=False, capture_accepted=True, status="incomplete")
    source.write_index()
    receipt = source.validate()
    assert len(receipt["eligible_watermarks"]) == len(BASE_SCOPES)
    assert receipt["source_status"] == "complete"
    assert receipt["source_index_status"] == "incomplete"
    assert receipt["source_index_complete"] is False
    assert receipt["source_index_capture_accepted"] is True


@pytest.mark.parametrize("change", ["old_code", "unknown_code", "old_schema", "delta", "api_version", "recent_target", "recent_source"])
def test_unproven_sources_get_fresh_repair_without_baseline_summary_inference(source, change):
    kwargs = {}
    if change in ("old_code", "unknown_code"):
        source.index["collector_code_sha"] = "a" * 40 if change == "unknown_code" else "ac3458d" + "0" * 33
    elif change == "old_schema":
        source.manifest["api"].pop("scope_statuses")
        source.manifest["api"].pop("watermark_candidates")
    elif change == "delta":
        source.manifest.update(mode="delta", since="2026-10-25T00:00:00Z")
        source.manifest["api"].update(mode="delta", since="2026-10-25T00:00:00Z")
    elif change == "api_version":
        kwargs["api_version"] = "2022-11-28"
    elif change == "recent_target":
        kwargs["history_policy"] = {"profile": "recent_history_shallow_v1", "cutoff_utc": "2024-10-26T00:00:00Z"}
    else:
        source.manifest["api"]["history_policy"] = {"profile": "recent_history_shallow_v1"}
    source.write()
    receipt = source.validate(**kwargs)
    assert receipt["eligible_watermarks"] == {}
    assert all(value["status"] == "fresh_repair" for value in receipt["scope_decisions"].values())


@pytest.mark.parametrize("change", ["candidate_missing", "candidate_mismatch", "candidate_naive", "candidate_future", "withheld", "unavailable", "capped", "deferred"])
def test_invalid_scope_candidates_never_advance_parent(source, change):
    api = source.manifest["api"]
    outcome = api["scope_statuses"]["issues"]
    if change == "candidate_missing":
        api["watermark_candidates"].pop("issues")
    elif change == "candidate_mismatch":
        api["watermark_candidates"]["issues"] = source.manifest["started_at"]
    elif change in ("candidate_naive", "candidate_future"):
        value = "2099-01-01T00:00:00Z" if change == "candidate_future" else outcome["query_started_at"].removesuffix("Z")
        api["watermark_candidates"]["issues"] = outcome["query_started_at"] = value
    elif change == "withheld":
        api["watermark_withheld"] = {"issues": {"incomplete_scopes": ["issue_timeline:1"]}}
    elif change == "unavailable":
        api["unavailable_scopes"] = {"issues": {}}
    else:
        outcome["status"] = change
    source.write()
    receipt = source.validate()
    assert "issues" not in receipt["eligible_watermarks"]
    assert "pulls" in receipt["eligible_watermarks"]


@pytest.mark.parametrize("change", ["missing_cas", "corrupt_cas", "wrong_size", "response_error", "wrong_record_api", "query_changed", "duplicate", "missing_check", "drift", "cap", "overlap"])
def test_raw_page_lineage_failures_repair_only_affected_scope(source, change):
    record = source.record("issues", 1)
    if change == "missing_cas":
        source.store.location(record["body_sha256"]).unlink()
    elif change == "corrupt_cas":
        path = source.store.location(record["body_sha256"])
        path.write_bytes(b"x" * path.stat().st_size)
    elif change == "wrong_size":
        record["body_bytes"] += 1
    elif change == "response_error":
        record["error"] = "RESPONSE_EXCEEDS_CAP"
    elif change == "wrong_record_api":
        record["api_version"] = "2022-11-28"
    elif change == "query_changed":
        source.record("issues")["headers"]["link"] = f'<{NEXT.replace("state=all", "state=closed")}>; rel="next"'
    elif change == "duplicate":
        source.rewrite_body(record, [{"id": 1, "number": 2}])
    elif change == "missing_check":
        source.manifest["responses"].remove(source.record("issues_first_page_recheck"))
    elif change == "drift":
        source.rewrite_body(source.record("issues_first_page_recheck"), [{"id": 99, "number": 99}])
    elif change == "cap":
        source.manifest["public_config"]["max_pages"] = 1
    else:
        record["request_started_at"] = source.record("issues")["request_started_at"]
    source.write()
    receipt = source.validate()
    assert "issues" not in receipt["eligible_watermarks"]
    assert "pulls" in receipt["eligible_watermarks"]


@pytest.mark.parametrize("change", ["selected_version", "query_mode", "outcome_ambiguous", "scope_byte_bound", "source_since_map", "ambiguous_next"])
def test_ambiguous_query_or_response_policy_stays_at_fresh_repair(source, change):
    if change == "selected_version":
        source.record("issues")["headers"]["x-github-api-version-selected"] = "2022-11-28"
    elif change == "query_mode":
        source.manifest["api"]["scope_statuses"]["issues"]["query_mode"] = "delta"
    elif change == "outcome_ambiguous":
        source.manifest["api"]["scopes"] = copy.deepcopy(source.manifest["api"]["scope_statuses"])
        source.manifest["api"]["scopes"]["issues"]["status"] = "partial"
    elif change == "scope_byte_bound":
        source.record("issues")["body_bytes"] = 129 * 1024 * 1024
    elif change == "source_since_map":
        source.manifest["scope_since"] = {"issues": source.manifest["started_at"]}
    else:
        link = source.record("issues")["headers"]["link"]
        source.record("issues")["headers"]["link"] = link + ", " + link
    source.write()
    receipt = source.validate()
    assert "issues" not in receipt["eligible_watermarks"]
    assert receipt["scope_decisions"]["issues"]["status"] == "fresh_repair"
    if change != "source_since_map":
        assert "pulls" in receipt["eligible_watermarks"]


def test_representation_recheck_and_abandoned_raw_attempt_are_not_new_observations(source):
    check = source.record("issues_first_page_recheck")
    source.rewrite_body(check, [{"id": 1, "number": 1, "title": "changed representation"}])
    abandoned = copy.deepcopy(source.record("issues"))
    source.rewrite_body(abandoned, [{"id": 999}, {"id": 999}])
    origin = parse_github_time(source.manifest["started_at"])
    abandoned.update(request_started_at=utc_iso(origin + timedelta(microseconds=1)), request_completed_at=utc_iso(origin + timedelta(microseconds=2)))
    source.manifest["responses"].insert(0, abandoned)
    source.manifest["api"]["scope_statuses"]["issues"]["pagination_attempts"] = 2
    source.write()
    receipt = source.validate()
    assert receipt["scope_decisions"]["issues"]["status"] == "eligible"
    assert receipt["scope_decisions"]["issues"]["pages_verified"] == 2
    assert source.manifest["responses"][0] == abandoned


@pytest.mark.parametrize("change", ["private", "wrong_id", "missing_metadata_cas"])
def test_public_metadata_proof_is_required_for_every_cursor(source, change):
    record = source.record("repository_metadata")
    if change == "missing_metadata_cas":
        source.store.location(record["body_sha256"]).unlink()
    else:
        source.rewrite_body(record, {"id": 99 if change == "wrong_id" else 42, "private": change == "private"})
    source.write()
    assert source.validate()["eligible_watermarks"] == {}


def test_requested_deep_children_must_be_verified_before_parent_seed(tmp_path):
    source = Source(tmp_path, deep_full=True)
    receipt = source.validate()
    assert all(scope in receipt["eligible_watermarks"] for scope in ("issues", "pulls"))
    assert receipt["scope_decisions"]["pulls"]["deep_history_coverage"] == "original_requested_children_verified"
    child = source.manifest["api"]["scope_statuses"]["pull_reviews:3"]
    child["status"] = "unavailable"
    source.write()
    receipt = source.validate()
    assert "pulls" not in receipt["eligible_watermarks"] and "issues" in receipt["eligible_watermarks"]


def test_real_deep_cap_partial_never_seeds_parent_even_if_candidate_is_reinserted(tmp_path):
    source = Source(tmp_path, deep_full=True, cap=True)
    api = source.manifest["api"]
    assert "pulls" not in api["watermark_candidates"]
    assert api["scope_statuses"]["pull_commits:3"]["status"] == "capped"
    api["watermark_candidates"]["pulls"] = api["scope_statuses"]["pulls"]["query_started_at"]
    api["watermark_withheld"] = {}
    source.write()
    receipt = source.validate()
    assert receipt["source_status"] == "partial"
    assert "pulls" not in receipt["eligible_watermarks"] and "issue_comments" in receipt["eligible_watermarks"]


@pytest.mark.parametrize("change", ["manifest_hash", "index_hash", "locator_escape", "locator_other", "row_digest", "row_repo", "result_digest", "index_repo", "row_time"])
def test_source_index_binding_rejects_wrong_or_untrusted_locator(source, change):
    kwargs = {}
    if change == "manifest_hash":
        kwargs["expected_manifest_sha256"] = "a" * 64
    elif change == "index_hash":
        kwargs["expected_index_sha256"] = "a" * 64
    elif change == "locator_escape":
        source.index["manifests"][0]["path"] = "../original-run.manifest.json"
    elif change == "locator_other":
        source.index["manifests"][0]["path"] = "runs/42/other.manifest.json"
    elif change == "row_digest":
        source.index["manifests"][0]["sha256"] = "b" * 64
    elif change == "row_repo":
        source.index["manifests"][0]["repository_id"] = 99
    elif change == "result_digest":
        source.index["collector_result"]["manifest_sha256"] = "b" * 64
    elif change == "index_repo":
        source.index["repository"] = "other/repo"
    else:
        source.index["manifests"][0]["started_at"] = "2099-01-01T00:00:00Z"
    source.write_index()
    with pytest.raises(LegacyAPISeedError):
        source.validate(**kwargs)
