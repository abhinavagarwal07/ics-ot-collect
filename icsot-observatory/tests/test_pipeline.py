import csv
import json
from pathlib import Path
from unittest.mock import patch

from icsot_observer.checks import verify_all
from icsot_observer.core import Config
from icsot_observer.derive import make_observations
from icsot_observer.pipeline import collect_one


def make_config(root: Path) -> Config:
    return Config(root=root, repositories=("test/repo",), api_version="2026-03-10",
                  user_agent="research", token_env="NO_SUCH_TEST_TOKEN", http_timeout_seconds=5,
                  max_response_bytes=1000000, overlap_hours=48, max_pages=1000)


def fake_identity(api, path, purpose):
    assert purpose == "repository_identity"
    b = b'{ "id": 17, "private": false, "full_name": "test/repo" }'
    rec = {"purpose": purpose, "url": "https://api.github.com/repos/test/repo", "status": 200,
           "body_sha256": api.store.put(b), "body_bytes": len(b),
           "request_started_at": "2026-10-20T00:00:00Z", "request_completed_at": "2026-10-20T00:00:01Z"}
    api.records.append(rec)
    return json.loads(b)


def fake_collect(api, slug, mode, since=None, deep_full=False):
    b = b'[{"id":123,"number":3,"updated_at":"2026-10-20T00:00:00Z","body":"hello"}]'
    rec = {"purpose": "issues", "url": "https://api.github.com/repos/test/repo/issues", "status": 200,
           "body_sha256": api.store.put(b), "body_bytes": len(b),
           "request_started_at": "2026-10-20T00:00:00Z", "request_completed_at": "2026-10-20T00:00:01Z"}
    api.records.append(rec)
    return {"repository_id": 17, "scopes": {"issues": {"count": 1, "status": "complete_for_query"}}}


def test_chain_and_restore_from_bytes(tmp_path):
    cfg = make_config(tmp_path)
    with patch("icsot_observer.pipeline.GitHubAPI.get_json", fake_identity), \
         patch("icsot_observer.pipeline.GitHubAPI.collect", fake_collect), \
         patch("icsot_observer.pipeline.collect_git", return_value=None):
        r1 = collect_one(cfg, "test/repo", "full", stamp=False)
        r2 = collect_one(cfg, "test/repo", "delta", stamp=False)
    assert r1["status"] == r2["status"] == "complete"
    assert r1["manifest_sha256"] != r2["manifest_sha256"]
    man2 = json.loads(Path(r2["manifest"]).read_text())
    assert man2["previous_manifest_sha256"] == r1["manifest_sha256"]
    result = verify_all(tmp_path)
    assert result["ok"], result["errors"]
    derived = tmp_path / "analysis" / "observations.csv"
    assert make_observations(tmp_path, derived)["records"] == 4
    with derived.open() as f:
        rows = list(csv.DictReader(f))
    assert any(row["entity_number"] == "3" for row in rows)
    # Deliberately tamper with an immutable manifest. Verification must fail.
    Path(r1["manifest"]).write_bytes(b'{"changed":true}\n')
    assert not verify_all(tmp_path)["ok"]


def test_diff_is_not_deletion_inference(tmp_path):
    from icsot_observer.diff import diff_latest
    cfg = make_config(tmp_path)
    with patch("icsot_observer.pipeline.GitHubAPI.get_json", fake_identity), \
         patch("icsot_observer.pipeline.GitHubAPI.collect", fake_collect), \
         patch("icsot_observer.pipeline.collect_git", return_value=None):
        collect_one(cfg, "test/repo", "full", stamp=False)
        collect_one(cfg, "test/repo", "delta", stamp=False)
    result = diff_latest(tmp_path, 17)
    assert result["entity_types"]["issues"]["newly_observed"] == []
    assert result["entity_types"]["issues"]["representation_changed"] == []
    assert result["git_refs"]["added"] == []


def test_reused_slug_does_not_silently_swap_repo_id(tmp_path):
    cfg = make_config(tmp_path)
    with patch("icsot_observer.pipeline.GitHubAPI.get_json", fake_identity), \
         patch("icsot_observer.pipeline.GitHubAPI.collect", fake_collect), \
         patch("icsot_observer.pipeline.collect_git", return_value=None):
        assert collect_one(cfg, "test/repo", "full", stamp=False)["status"] == "complete"

    def fake_new_identity(api, path, purpose):
        obj = fake_identity(api, path, purpose)
        obj["id"] = 999
        return obj
    with patch("icsot_observer.pipeline.GitHubAPI.get_json", fake_new_identity):
        assert collect_one(cfg, "test/repo", "full", stamp=False)["status"] == "identity_error"
    assert len(list((tmp_path / "runs" / "17").glob("*.manifest.json"))) == 1


def test_legacy_delta_rechecks_full_after_capability_unavailable_then_advances_only_qualified_cursor(tmp_path):
    cfg, calls = make_config(tmp_path), []

    def availability(api, slug, mode, since=None, deep_full=False):
        calls.append((mode, since))
        scopes = {name: {"status": "complete_for_query", "count": 0}
                  for name in ("issues", "pulls", "issue_comments", "review_comments", "releases", "tags", "events")}
        if len(calls) == 1:
            for name in ("pulls", "review_comments"):
                scopes[name] = {"status": "unavailable", "reason": "repository_pull_requests_disabled"}
        return {"repository_id": 17, "scopes": scopes, "scope_statuses": scopes, "failures": []}

    with patch("icsot_observer.pipeline.GitHubAPI.get_json", fake_identity), \
         patch("icsot_observer.pipeline.GitHubAPI.collect", availability), \
         patch("icsot_observer.pipeline.collect_git", return_value=None):
        first = collect_one(cfg, "test/repo", "full", stamp=False)
        second = collect_one(cfg, "test/repo", "delta", stamp=False)
        third = collect_one(cfg, "test/repo", "delta", stamp=False)
    assert all(info["status"] == "complete" for info in (first, second, third))
    assert calls[0] == calls[1] == ("full", None)
    assert calls[2][0] == "delta" and calls[2][1] is not None
    assert json.loads(Path(second["manifest"]).read_bytes())["mode"] == "full"
