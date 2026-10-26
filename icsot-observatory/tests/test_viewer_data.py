"""Small synthetic evidence only: these fixtures do not represent study data."""
import base64
import io
import json
import lzma
import shutil
import subprocess
import time
import threading
import os
import tarfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from icsot_observer.core import ObjectStore, canonical_json, sha256
from icsot_observer.viewer_data import GitHubMetadata, MetadataError, ViewerData


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "public_patch_corpus_185.csv").write_text(
        "ID,Cohort,Repository_URL,Repository_Role\nSAMPLE,Synthetic,https://github.com/example/fixture,primary_git\n")
    return tmp_path


def capture(root, run="sample-1", *, lane=None, items=None, status="complete", scopes=None, responses=None, git=None):
    root.mkdir(parents=True, exist_ok=True)
    store = ObjectStore(root)
    records = list(responses or [])
    for purpose, values in (items or {}).items():
        raw = values if isinstance(values, bytes) else canonical_json(values)
        records.append({"purpose": purpose, "status": 200, "body_sha256": store.put(raw),
            "url": "https://api.github.com/repos/example/fixture/" + purpose,
            "request_started_at": "2026-01-01T01:00:00+01:00", "request_completed_at": "2026-01-01T00:00:01Z"})
    manifest = {"repository_id": 123, "repository_input_slug": "example/fixture", "run_id": run,
        "status": status, "mode": "full" if run == "sample-1" else "delta",
        "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:02Z",
        "responses": records, "failures": [], "api": {"scopes": scopes or {}}}
    if lane:
        manifest["lane"] = lane
        manifest["capture_id"] = "synthetic-capture-" + run
    if git is not None:
        manifest["git"] = {"advertised_refs": [{"published_ref": name, "object_id": oid} for name, oid in git.items()],
            "ls_remote_started_at": "2026-01-01T00:00:00Z", "ls_remote_completed_at": "2026-01-01T00:00:01Z"}
    path = root / "runs" / "123" / (run + ".manifest.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(manifest))
    return path, manifest


def ids(viewer):
    repo = viewer.overview()["repos"][0]
    caps = viewer.repo(repo["id"])["captures"]
    return repo["id"], [c["id"] for c in caps]


def test_combined_and_new_lanes_keep_independent_intervals(workspace):
    root = workspace / "evidence"
    capture(root, items={"issues": [{"id": 1, "title": "Synthetic old", "body": "before"}]}, git={"refs/heads/main": "a" * 40})
    capture(root, "sample-2", lane="api", items={"issues": [{"id": 1, "title": "Synthetic new", "body": "after"}]})
    capture(root, "sample-3", lane="git", git={"refs/heads/main": "b" * 40})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, caps = ids(viewer)
    metadata = viewer.repo(repo)
    assert [c["lane"] for c in metadata["captures"]] == ["combined", "api", "git"]
    assert metadata["captures"][0]["lane_intervals"]["api"]["started_at"] == "2026-01-01T00:00:00Z"
    assert metadata["captures"][0]["lane_intervals"]["git_refs"]["completed_at"] == "2026-01-01T00:00:01Z"
    result = viewer.compare(repo, caps[0], caps[1], "issues")
    assert result["total"] == 1
    assert result["items"][0]["change"] == "representation_changed"
    assert result["items"][0]["changed_fields"] == ["body", "title"]
    assert viewer.compare(repo, caps[1], caps[2], "issues")["entity_types"]["issues"]["status"] == "lane_mismatch"
    assert viewer.compare(repo, caps[0], caps[2], "git_refs")["git_refs"]["moved"][0]["new_sha"] == "b" * 40


def test_missing_entity_is_not_observed_never_deletion(workspace):
    root = workspace / "evidence"
    capture(root, items={"issues": [{"id": 1}, {"id": 2}]}, scopes={"issues": {"status": "complete_for_query"}})
    capture(root, "sample-2", items={"issues": [{"id": 1}]}, scopes={"issues": {"status": "complete_for_query"}})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, caps = ids(viewer)
    result = viewer.compare(repo, *caps, "issues")
    assert result["items"][0]["change"] == "not_observed_right"
    assert "deletion" in result["qualification"]
    assert "deleted" not in json.dumps(result)


def test_unavailable_scope_has_unknown_counts(workspace):
    root = workspace / "evidence"
    capture(root, scopes={"pulls": {"status": "unavailable", "reason": "disabled"}})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.compare(repo, cap, cap, "pulls")
    details = result["entity_types"]["pulls"]
    assert details["status"] == "capability_unavailable"
    assert details["counts"] == {"left": None, "right": None}
    assert result["items"] == []


def test_malformed_utf8_preserved_in_raw_view_not_projected(workspace):
    root = workspace / "evidence"
    capture(root, items={"issues": b'[{"id":1,"body":"\xff"}]'}, scopes={"issues": {"status": "complete_for_query"}})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.compare(repo, cap, cap, "issues")
    assert result["coverage"]["left"]["status"] == "partial"
    assert result["coverage"]["left"]["gaps"]
    assert result["entity_types"]["issues"]["counts"] == {"left": None, "right": None}
    raw = viewer.raw_record(repo, cap, "response-0")
    assert raw["encoding"] == "invalid_utf8_display_replacement"
    assert raw["sha256"] == sha256(b'[{"id":1,"body":"\xff"}]')


def test_accepted_checkpoint_attempt_excludes_abandoned_pages_but_retains_raw(workspace):
    root = workspace / "evidence"
    store = ObjectStore(root)
    records = [{"purpose": "issues", "status": 200,
        "body_sha256": store.put(canonical_json([{"id": identity}])),
        "checkpoint_provenance": {"attempt_id": attempt}}
        for identity, attempt in ((1, "abandoned"), (2, "accepted"))]
    capture(root, responses=records, scopes={"issues": {"status": "complete_for_query", "attempt_id": "accepted"}})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.compare(repo, cap, cap, "issues")
    assert [row["id"] for row in result["items"]] == ["2"]
    assert viewer.compare(repo, cap, cap, "raw_records")["total"] == 2
    assert '"id":1' in viewer.raw_record(repo, cap, "response-0")["text"]


def test_unqualified_retried_legacy_pages_remain_raw_only(workspace):
    root = workspace / "evidence"
    capture(root, items={"issues": [{"id": 1}]}, scopes={"issues": {"status": "complete_for_query", "pagination_attempts": 2}})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.compare(repo, cap, cap, "issues")
    assert result["items"] == []
    assert result["coverage"]["left"]["gaps"]


def test_pagination_excerpts_do_not_repeat_full_change_payloads(workspace):
    root = workspace / "evidence"
    capture(root, items={"issues": [{"id": i, "body": "sample" * 1000} for i in range(20)]})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.compare(repo, cap, cap, "issues", offset=7, limit=3)
    assert result["total"] == 20 and len(result["items"]) == 3
    assert len(result["entity_types"]["issues"]["changes"]) == 3
    assert all("before" not in item for item in result["entity_types"]["issues"]["changes"])
    assert result["items"][0]["before"]["_viewer_preview"]["truncated"] is True
    assert isinstance(result["items"][0]["before"]["body"], str)
    assert len(result["items"][0]["body_before"]) <= 2000
    coverage = viewer.compare(repo, cap, cap, "coverage")
    assert set(coverage["entity_types"]) == {"issues", "pulls", "comments", "releases", "tags", "events"}
    assert coverage["items"] == []


def test_ordinary_three_kb_issue_retains_actual_fields_and_original_hash(workspace):
    root = workspace / "evidence"
    issue = {"id": 1, "number": 17, "title": "Synthetic ordinary issue", "state": "open",
             "body": "Useful captured issue body. " * 105,
             "labels": [{"id": 3, "name": "synthetic-label", "color": "aabbcc"}],
             "user": {"id": 9, "login": "synthetic-user"}, "comments": 2}
    assert 2800 < len(canonical_json(issue)) < 4000
    capture(root, items={"issues": [issue]})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.compare(repo, cap, cap, "issues")
    item = result["items"][0]
    assert item["before"] == issue and item["after"] == issue
    assert "_viewer_excerpt" not in item["before"]
    assert item["body_before"].startswith("Useful captured issue body.")
    assert viewer.entity_detail(repo, cap, "issues", "1")["entity"]["sha256"] == sha256(canonical_json(issue))
    assert len(canonical_json(result)) < 50_000


def test_large_structured_issue_preview_keeps_useful_keys_and_marks_omissions(workspace):
    from icsot_observer.viewer_data import _display_value
    value = {"id": 1, "title": "Synthetic large issue", "state": "closed", "body": "body\n" * 10_000,
             "labels": [{"name": "retained-label"}], **{f"extra_{i}": "detail" * 500 for i in range(80)}}
    preview = _display_value(value)
    assert len(canonical_json(preview)) <= 4000
    assert preview["title"] == value["title"] and preview["state"] == "closed"
    assert preview["body"].startswith("body\n") and "display truncated" in preview["body"]
    assert preview["labels"] == value["labels"]
    assert preview["_viewer_preview"]["omitted_key_count"] > 0


def test_same_capture_browse_tags_comments_releases_events(workspace):
    root = workspace / "evidence"
    capture(root, items={"tags": [{"name": "synthetic-tag", "commit": {"sha": "a" * 40}}],
        "issue_comments": [{"id": 4, "body": "comment"}], "review_comments": [{"id": 4, "body": "review comment"}],
        "releases": [{"id": 8, "tag_name": "v-sample"}], "events": [{"id": "e1", "type": "PushEvent"}]})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    assert viewer.compare(repo, cap, cap, "tags")["items"][0]["id"] == "synthetic-tag"
    comments = viewer.compare(repo, cap, cap, "comments")["items"]
    assert {row["id"] for row in comments} == {"issue_comments:4", "review_comments:4"}
    assert viewer.entity_detail(repo, cap, "releases", "8")["status"] == "observed"
    assert viewer.entity_detail(repo, cap, "events", "events:e1")["status"] == "observed"
    assert viewer.entity_detail(repo, cap, "issues", "missing")["status"] == "not_observed_coverage_unknown"


def test_no_browser_paths_or_cross_repository_capture_access(workspace):
    root = workspace / "evidence"
    path, _ = capture(root, items={"issues": [{"id": 1}]})
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    with pytest.raises(KeyError):
        viewer.repo(str(root))
    with pytest.raises(ValueError):
        viewer.raw_record(repo, cap, "../../private.pem")
    with pytest.raises(KeyError):
        viewer.compare(repo, cap, "c-" + "0" * 64, "issues")
    path.write_text("{}")
    with pytest.raises(ValueError, match="hash"):
        viewer.raw_record(repo, cap, "manifest")


def test_symlink_cas_rejected(workspace):
    root = workspace / "evidence"
    _, manifest = capture(root, items={"issues": [{"id": 1}]})
    digest = manifest["responses"][0]["body_sha256"]
    path = root / "objects" / "sha256" / digest[:2] / digest
    other = workspace / "outside.json"
    other.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(other)
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    assert viewer.raw_record(repo, cap, "response-0")["gaps"]


class FakeMetadata:
    """Synthetic metadata transport, intentionally never a GitHub request."""
    bytes_read = 0

    def __init__(self, responses, assets):
        self.responses, self.assets = responses, assets
        self.requested = []

    def json(self, endpoint, **kwargs):
        self.requested.append(endpoint)
        if endpoint not in self.responses:
            raise MetadataError("Synthetic unavailable endpoint")
        return self.responses[endpoint]

    def asset(self, asset, expected=None):
        self.requested.append("asset:" + str(asset["id"]))
        return self.assets[asset["id"]]


def remote_viewer(workspace, *, native=True):
    repo_slug = "example/fixture"
    base = "repos/abhinavagarwal07/ics-ot-collect"
    tag = "collector-observations-synthetic" if native else "corpus-baseline-synthetic"
    digest = "a" * 64
    index_asset = {"id": 2, "name": "synthetic.index.json", "size": 20, "digest": "sha256:" + "b" * 64}
    catalog_asset = {"id": 1, "name": "metadata-catalog.json" if native else "baseline-inventory.json", "size": 20, "digest": "sha256:" + "c" * 64}
    summary = {"repository_id": 123, "sha256": digest, "run_id": "sample-1", "mode": "full", "status": "complete",
        "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z"}
    observation = {"manifest_sha256": digest, "capture_id": "synthetic", "lane": "api",
        "observation_started_at": summary["started_at"], "observation_finished_at": summary["finished_at"],
        "index": {"name": index_asset["name"], "release_tag": tag, "sha256": "b" * 64}}
    catalog = {"generation_release": tag, "repository_id": 123, "slug": repo_slug, "observations": [observation]}
    index = {**observation, "repository_id": 123, "encrypted": True,
        "members": [{"path": "runs/123/sample-1.manifest.json", "bytes": 5, "sha256": digest}],
        "timestamp_evidence": {"opentimestamps": {"metadata": {"status": "pending_bitcoin_completion"}},
                               "rfc3161": {"metadata": {"status": "verified_chain_and_imprint"}}}}
    if not native:
        catalog = {"release_tag": tag, "repositories": [{"repository": repo_slug, "manifests": [summary],
            "complete": False, "capture_status": "incomplete", "errors": ["synthetic partial capture"],
            "index_asset": index_asset["name"], "index_sha256": "b" * 64}]}
        index = {"repository": repo_slug, "release_tag": tag, "manifests": [summary], "errors": ["synthetic partial capture"]}
    release = {"id": 42, "tag_name": tag}
    remote = FakeMetadata({f"{base}/releases?per_page=100&page=1": [release],
        f"{base}/releases/42/assets?per_page=100&page=1": [catalog_asset, index_asset]}, {1: catalog, 2: index})
    return ViewerData(workspace, roots=[], metadata=remote), remote


@pytest.mark.parametrize("native", [True, False])
def test_remote_metadata_browse_without_key_or_payload_downloads(workspace, native):
    viewer, remote = remote_viewer(workspace, native=native)
    repo, (cap,) = ids(viewer)
    summary = viewer.repo(repo)["captures"][0]
    assert summary["load_state"] == "metadata_only"
    assert summary["run_id"] == "sample-1"
    result = viewer.compare(repo, cap, cap, "issues")
    assert result["entity_types"]["issues"]["status"] == "coverage_unknown"
    assert result["entity_types"]["issues"]["counts"] == {"left": None, "right": None}
    assert viewer.load(repo, cap)["status"] == "key_required"
    assert all("releases/assets/" not in request for request in remote.requested)
    if native:
        assert summary["proof"]["rfc3161"]["status"] == "verified_chain_and_imprint"
    else:
        assert viewer.repo(repo)["attempts"][0]["errors"] == ["synthetic partial capture"]


def test_metadata_asset_exact_hash_and_length_gate(monkeypatch):
    metadata = GitHubMetadata("example/release")
    raw = canonical_json({"synthetic": True})
    monkeypatch.setattr(metadata, "_bytes", lambda *a, **k: raw)
    asset = {"id": 1, "size": len(raw), "digest": "sha256:" + sha256(raw)}
    assert metadata.asset(asset) == {"synthetic": True}
    with pytest.raises(MetadataError):
        metadata.asset({**asset, "id": 2, "digest": "sha256:" + "0" * 64})
    with pytest.raises(MetadataError):
        metadata.asset({**asset, "id": 3, "size": len(raw) + 1})


def test_cached_noncanonical_asset_keeps_original_raw_identity_across_refresh(monkeypatch):
    metadata = GitHubMetadata("example/release")
    raw = b'{ "synthetic" : true }\n'
    calls = []
    def fetch(*args, **kwargs):
        calls.append(args)
        return raw
    monkeypatch.setattr(metadata, "_bytes", fetch)
    digest = sha256(raw)
    asset = {"id": 1, "size": len(raw), "digest": "sha256:" + digest}
    assert metadata.asset(asset, digest) == {"synthetic": True}
    metadata.cache["mutable-listing"] = {"synthetic": "discarded"}
    metadata.clear_mutable()
    assert "mutable-listing" not in metadata.cache
    # Reusing identical historical bytes is valid even though canonical JSON
    # would have a different hash and length.
    assert sha256(canonical_json({"synthetic": True})) != digest
    assert metadata.asset(dict(asset), digest) == {"synthetic": True}
    changed = sha256(b'{ "synthetic" :false }\n')
    with pytest.raises(MetadataError, match="cached metadata identity"):
        metadata.asset({**asset, "digest": "sha256:" + changed}, changed)
    with pytest.raises(MetadataError, match="cached metadata identity"):
        metadata.asset({**asset, "size": len(raw) + 1}, digest)
    with pytest.raises(MetadataError, match="cached metadata identity"):
        metadata.asset({**asset, "digest": "sha256:" + changed})
    with pytest.raises(MetadataError, match="cached metadata identity"):
        metadata.asset(asset, changed)
    assert metadata.asset(asset, digest) == {"synthetic": True}
    assert len(calls) == 1  # Conflicts never trigger an unbounded redownload.


class ObservedTransportLock:
    """Make the competing caller's admission deterministic without sleeps."""
    def __init__(self):
        self.lock = threading.RLock()
        self.second_attempted = threading.Event()
    def __enter__(self):
        if threading.current_thread().name == "second-metadata-caller":
            self.second_attempted.set()
        return self.lock.__enter__()
    def __exit__(self, *args):
        return self.lock.__exit__(*args)


def test_concurrent_asset_cache_miss_fetches_once(monkeypatch):
    metadata = GitHubMetadata("example/release")
    lock = ObservedTransportLock()
    metadata._transport_lock = lock
    entered, release = threading.Event(), threading.Event()
    raw, calls, results, errors = b'{ "synthetic": true }\n', [], [], []
    def fetch(*args, **kwargs):
        calls.append(args)
        entered.set()
        assert release.wait(3)
        return raw
    monkeypatch.setattr(metadata, "_bytes", fetch)
    asset = {"id": 1, "size": len(raw), "digest": "sha256:" + sha256(raw)}
    def read():
        try:
            results.append(metadata.asset(asset))
        except BaseException as error:
            errors.append(error)
    first = threading.Thread(target=read, name="first-metadata-caller")
    second = threading.Thread(target=read, name="second-metadata-caller")
    first.start()
    assert entered.wait(3)
    second.start()
    try:
        assert lock.second_attempted.wait(3)
    finally:
        release.set()
        first.join(3)
        second.join(3)
    assert not first.is_alive() and not second.is_alive() and errors == []
    assert results == [{"synthetic": True}, {"synthetic": True}]
    assert len(calls) == 1


def test_concurrent_metadata_transfers_share_one_remaining_allowance(monkeypatch):
    metadata = GitHubMetadata("example/release", maximum_bytes=6)
    lock = ObservedTransportLock()
    metadata._transport_lock = lock
    entered, release = threading.Event(), threading.Event()
    calls, results, errors = [], [], []
    class Process:
        def __init__(self):
            reader, writer = os.pipe()
            os.write(writer, b"ABCDEF")
            os.close(writer)
            self.stdout = os.fdopen(reader, "rb", buffering=0)
        def wait(self, timeout=None): return 0
        def poll(self): return 0
        def kill(self): pass
    def popen(*args, **kwargs):
        calls.append(args)
        entered.set()
        assert release.wait(3)
        return Process()
    monkeypatch.setattr(subprocess, "Popen", popen)
    def read():
        try:
            results.append(metadata._bytes("rate_limit", 6))
        except BaseException as error:
            errors.append(error)
    first = threading.Thread(target=read, name="first-metadata-caller")
    second = threading.Thread(target=read, name="second-metadata-caller")
    first.start()
    assert entered.wait(3)
    second.start()
    try:
        assert lock.second_attempted.wait(3)
    finally:
        release.set()
        first.join(3)
        second.join(3)
    assert not first.is_alive() and not second.is_alive()
    assert results == [b"ABCDEF"] and len(calls) == 1
    assert len(errors) == 1 and isinstance(errors[0], MetadataError)
    assert metadata.bytes_read == metadata.maximum_bytes == 6
    assert metadata.request_count == 1


def test_baseline_public_timestamp_catalog_uses_per_observation_repository(workspace):
    viewer, remote = remote_viewer(workspace, native=False)
    base = "repos/abhinavagarwal07/ics-ot-collect"
    descriptor = {"id": 3, "name": "metadata-catalog.json", "size": 20, "digest": "sha256:" + "d" * 64}
    remote.responses[base + "/releases/42/assets?per_page=100&page=1"].append(descriptor)
    remote.assets[3] = {"generation_release": "corpus-baseline-synthetic", "observations": [{
        "repository": "example/fixture", "manifest_sha256": "a" * 64,
        "index": {"name": "synthetic.index.json", "sha256": "b" * 64, "release_tag": "corpus-baseline-synthetic"},
        "timestamp_evidence": {"opentimestamps": {"metadata": {"status": "bitcoin_attestation_unverified"}}}}]}
    repo, (cap,) = ids(viewer)
    assert viewer.repo(repo)["captures"][0]["proof"]["opentimestamps"]["status"] == "bitcoin_attestation_unverified"
    assert viewer.repo(repo)["gaps"] == []


def test_current_proof_history_is_read_from_pinned_maintenance_head(workspace):
    viewer, remote = remote_viewer(workspace)
    viewer.overview()
    cap = next(iter(viewer._captures.values()))
    key = "e" * 64
    cap["proof"]["opentimestamps"]["metadata_sha256"] = key
    base = "repos/abhinavagarwal07/ics-ot-collect"
    remote.responses[base + "/git/ref/heads/collector-attestations"] = {"object": {"sha": "d" * 40}}
    record = {"subject_sha256": cap["manifest_sha256"], "history": [{"metadata": {"sha256": key}, "status": "pending_bitcoin_completion"},
        {"metadata": {"sha256": "f" * 64}, "status": "bitcoin_attestation_unverified"}], "maintenance_status": "awaiting_trusted_rpc"}
    remote.responses[base + "/contents/proofs/" + key + ".json?ref=" + "d" * 40] = {
        "content": base64.b64encode(canonical_json(record)).decode()}
    viewer._refresh_proof(cap)
    assert cap["proof"]["opentimestamps"]["status"] == "bitcoin_attestation_unverified"
    assert cap["proof"]["opentimestamps"]["maintenance_status"] == "awaiting_trusted_rpc"
    assert cap["proof"]["checked_by_viewer"] is False


def test_transient_catalog_failure_stays_unknown_until_explicit_allowed_refresh(workspace):
    viewer, remote = remote_viewer(workspace, native=False)
    endpoint = "repos/abhinavagarwal07/ics-ot-collect/releases?per_page=100&page=1"
    response = remote.responses.pop(endpoint)
    local = workspace / "evidence"
    capture(local, items={"issues": [{"id": 3, "title": "Preserved synthetic local observation"}]})
    viewer._index_root(local)
    first = viewer.overview()
    assert first["metadata_status"]["state"] == "unavailable"
    assert first["repos"][0]["capture_count"] == 1
    assert first["repos"][0]["capture_count_known"] is False
    assert first["repos"][0]["remote_discovery"]["state"] == "unknown"
    requests = len(remote.requested)
    remote.responses[endpoint] = response
    viewer.overview()
    viewer.overview(refresh=True)  # Still inside the explicit cooldown.
    assert len(remote.requested) == requests
    viewer._metadata_retry_at = time.time() - 1
    restored = viewer.overview(refresh=True)
    assert restored["metadata_status"]["state"] == "complete"
    assert len(restored["repos"]) == 1 and restored["repos"][0]["capture_count"] == 2
    assert not any(g["reason"] == "remote_metadata_unavailable" for g in restored["gaps"])
    repo = restored["repos"][0]["id"]
    assert any(c["load_state"] == "loaded" for c in viewer.repo(repo)["captures"])
    attempts = len(viewer.repo(repo)["attempts"])
    viewer._metadata_retry_at = time.time() - 1
    viewer.overview(refresh=True)
    assert len(viewer.repo(repo)["attempts"]) == attempts


def test_failed_repository_index_retries_only_after_explicit_refresh(workspace, monkeypatch):
    viewer, remote = remote_viewer(workspace)
    original = remote.asset
    failed = True
    def asset(value, expected=None):
        if value["id"] == 2 and failed:
            remote.requested.append("failed-index:2")
            raise MetadataError("Synthetic transient metadata outage")
        return original(value, expected)
    monkeypatch.setattr(remote, "asset", asset)
    repo = viewer.overview()["repos"][0]["id"]
    unavailable = viewer.repo(repo)
    assert unavailable["repo"]["remote_discovery"]["state"] == "partial"
    assert unavailable["repo"]["capture_count_known"] is False
    requests = len(remote.requested)
    viewer.repo(repo)
    assert len(remote.requested) == requests
    failed = False
    viewer._metadata_retry_at = time.time() - 1
    viewer.overview(refresh=True)
    retried = viewer.repo(repo)
    assert retried["repo"]["remote_discovery"]["state"] == "complete"
    assert retried["captures"][0]["run_id"] == "sample-1"
    assert not any(g["reason"] == "repository_index_unavailable" for g in retried["gaps"])


def test_quota_reset_is_explicit_and_prevents_catalog_requests(workspace):
    viewer, remote = remote_viewer(workspace)
    reset = int(time.time()) + 300
    remote.availability = lambda: {"remaining": 0, "reset": reset}
    result = viewer.overview()
    status = result["metadata_status"]
    assert status["state"] == "rate_limited" and status["retry_allowed"] is False
    assert status["retry_at"] == __import__("datetime").datetime.fromtimestamp(reset, __import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z")
    assert remote.requested == []  # No core catalog or index request was made.
    assert result["repos"][0]["status"] == "metadata_unknown"
    viewer.overview(refresh=True)
    assert viewer._metadata_attempts == 1
    remote.availability = lambda: {"remaining": 10, "reset": reset}
    viewer._metadata_retry_at = time.time() - 1
    assert viewer.overview(refresh=True)["metadata_status"]["state"] == "complete"


def test_metadata_retry_attempt_and_request_caps_remain_session_bounded(workspace):
    viewer, remote = remote_viewer(workspace)
    endpoint = "repos/abhinavagarwal07/ics-ot-collect/releases?per_page=100&page=1"
    remote.responses.pop(endpoint)
    for _ in range(8):
        viewer._metadata_retry_at = time.time() - 1
        viewer.overview(refresh=True)
    assert viewer._metadata_attempts == 5
    assert len(remote.requested) == 5
    assert viewer.overview()["metadata_status"]["retry_allowed"] is False
    transport = GitHubMetadata("example/release")
    transport.request_count = transport.request_limit
    with pytest.raises(MetadataError, match="request limit"):
        transport._bytes("rate_limit", 1000)


def test_budget_uses_one_project_ledger_even_from_package_cwd(workspace):
    package = workspace / "icsot-observatory"
    package.mkdir()
    viewer = ViewerData(package, roots=[], offline=True)
    budget = viewer.budget_status()
    assert viewer.budget.root == workspace / "analysis" / "local-data-budget"
    assert budget["limit_bytes"] == 2_000_000_000
    assert str(workspace) in budget["roots"]


@pytest.mark.parametrize("archive_kind", ["native", "modern_baseline", "migrated_baseline"])
@pytest.mark.parametrize("raw_kind", ["json", "non_json_failure"])
def test_encrypted_capture_projection_authenticates_before_publishing(workspace, monkeypatch, archive_kind, raw_kind):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from icsot_observer.archive_reader import ArchivePart
    from icsot_observer.encryption import encrypt_file

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private, public = workspace / "synthetic-private.pem", workspace / "synthetic-public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    root = workspace / "synthetic-evidence"
    values = [{"id": 1, "title": "Synthetic captured entity"}] if raw_kind == "json" else b"<html>synthetic malformed 2xx response</html>"
    path, manifest = capture(root, lane="api", items={"issues": values})
    raw_manifest = path.read_bytes()
    source = workspace / "synthetic.tar.xz"
    members = []
    with tarfile.open(source, "w:xz") as archive:
        for file in sorted(root.rglob("*")):
            if file.is_file():
                relative = file.relative_to(root).as_posix()
                archive.add(file, arcname="evidence/" + relative, recursive=False)
                members.append({"path": relative, "bytes": file.stat().st_size, "sha256": sha256(file.read_bytes())})
    encrypted = workspace / "synthetic.enc"
    info = encrypt_file(source, encrypted, public)
    viewer, remote = remote_viewer(workspace)
    repo, (cap_key,) = ids(viewer)
    cap = viewer._captures.pop(cap_key)
    repo_obj = viewer._get_repo(repo)
    repo_obj["captures"].remove(cap_key)
    descriptor = cap["remote"]
    index = {"repository_id": 123, "encrypted": True, "members": members,
        "assets": [{"name": encrypted.name, "bytes": info["ciphertext_bytes"], "sha256": info["ciphertext_sha256"], "encryption": info}]}
    if archive_kind == "modern_baseline":
        index = {"repository_id": 123, "archive": {"encrypted": True, "parts": index["assets"]}}
    elif archive_kind == "migrated_baseline":
        plaintext = {"name": "synthetic.tar.xz.part-0001", "bytes": info["plaintext_bytes"], "sha256": info["plaintext_sha256"]}
        index = {"repository_id": 123, "archive": {"parts": [plaintext]}}
        descriptor["aliases"] = [{"plaintext": plaintext,
            "ciphertext": {"name": encrypted.name, "bytes": info["ciphertext_bytes"], "sha256": info["ciphertext_sha256"]}}]
    descriptor["index"] = index
    summary = {**manifest, "sha256": sha256(raw_manifest)}
    cap = viewer._add_capture(repo_obj, summary, remote=descriptor)
    viewer.private_key_path = private
    viewer._releases[descriptor["release_tag"]]["assets"][encrypted.name] = {
        "id": 9, "size": info["ciphertext_bytes"], "digest": "sha256:" + info["ciphertext_sha256"]}
    @contextmanager
    def local_part(asset, description, capture, part_class):
        yield ArchivePart(path=encrypted, **description)
    monkeypatch.setattr(viewer, "_download_part", local_part)
    result = viewer.load(repo, cap["key"])
    assert result["status"] == "loaded", result
    if raw_kind == "json":
        assert viewer.compare(repo, cap["key"], cap["key"], "issues")["items"][0]["title"] == "Synthetic captured entity"
    else:
        assert viewer.raw_record(repo, cap["key"], "response-0")["text"] == values.decode()
        assert viewer.compare(repo, cap["key"], cap["key"], "issues")["entity_types"]["issues"]["counts"] == {"left": None, "right": None}
    assert "synthetic-private" not in json.dumps(viewer.repo(repo))
    # A new session with corrupted retained ciphertext publishes no manifests or
    # JSON projections even if early archive members could otherwise be read.
    content = bytearray(encrypted.read_bytes())
    content[-1] ^= 1
    encrypted.write_bytes(content)
    cap["manifest"] = None
    cap["load_state"] = "metadata_only"
    viewer._objects.clear()
    failed = viewer.load(repo, cap["key"])
    assert failed["status"] == "load_failed"
    assert cap["manifest"] is None and viewer._objects == {}


def test_native_index_can_reference_a_manifest_delivered_in_previous_export(workspace):
    viewer, remote = remote_viewer(workspace)
    index = remote.assets[2]
    index["members"] = []
    # The immutable source index name identifies the run when its manifest was
    # already delivered in a previous export; no capture bytes are fabricated.
    index_asset = remote.responses["repos/abhinavagarwal07/ics-ot-collect/releases/42/assets?per_page=100&page=1"][1]
    index_asset["name"] = "sample-1.index.json"
    remote.assets[1]["observations"][0]["index"]["name"] = index_asset["name"]
    repo, (key,) = ids(viewer)
    result = viewer.repo(repo)["captures"][0]
    assert result["run_id"] == "sample-1"
    assert result["manifest_prerequisite"] is True
    assert result["load_state"] == "metadata_only"
    assert viewer.repo(repo)["gaps"] == []


def synthetic_git_viewer(workspace):
    source = workspace / "synthetic-git-source"
    source.mkdir()
    def git(*args):
        result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
            "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid", *args],
            cwd=source, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    git("init", "-b", "main")
    (source / "synthetic.txt").write_text("before\n")
    git("add", "synthetic.txt")
    git("commit", "-m", "Synthetic before")
    base = git("rev-parse", "HEAD")
    git("branch", "synthetic-base", base)
    (source / "synthetic.txt").write_text("after\n")
    git("commit", "-am", "Synthetic after")
    head = git("rev-parse", "HEAD")
    bundle_path = workspace / "synthetic-full.bundle"
    git("bundle", "create", str(bundle_path), "--branches")
    root = workspace / "evidence"
    path, manifest = capture(root, git={"refs/heads/main": head, "refs/heads/synthetic-base": base})
    digest, length = ObjectStore(root).put_file(bundle_path)
    manifest["git"]["portable_full_bundle"] = {"sha256": digest, "bytes": length}
    path.write_bytes(canonical_json(manifest))
    class FixtureVolume:
        """Tiny known synthetic graph; does not mount or call hdiutil."""
        def __init__(self, budget):
            self.path = workspace / "synthetic-volume"
        def __enter__(self):
            self.path.mkdir()
            return self.path
        def __exit__(self, *args):
            shutil.rmtree(self.path)
    viewer = ViewerData(workspace, roots=[root], offline=True, git_volume_factory=FixtureVolume)
    repo, (cap,) = ids(viewer)
    return viewer, repo, cap, base, head, root


def test_bounded_git_diff_restores_fscks_and_reads_real_synthetic_files(workspace):
    viewer, repo, cap, base, head, root = synthetic_git_viewer(workspace)
    capability = viewer.repo(repo)["captures"][0]["git_file_diff"]
    assert capability["status"] == "available_to_prepare"
    result = viewer.git_diff(repo, cap, base, head)
    assert result["status"] == "complete", result
    assert result["files"] == [{"status": "M", "path": "synthetic.txt", "old_path": None}]
    assert "-before" in result["patch"] and "+after" in result["patch"]
    assert result["verification"]["status"] == "offline_restore_fsck_verified"
    assert result["commits"]["base"]["subject"] == "Synthetic before"
    assert result["commits"]["head"]["subject"] == "Synthetic after"
    selected = viewer.git_diff(repo, cap, base, head, path="synthetic.txt")
    assert selected["status"] == "complete" and selected["path"] == "synthetic.txt"
    assert not (workspace / "synthetic-volume").exists()


def test_git_diff_rejects_uncaptured_oids_and_non_tree_paths(workspace):
    viewer, repo, cap, base, head, root = synthetic_git_viewer(workspace)
    with pytest.raises(ValueError, match="captured ref"):
        viewer.git_diff(repo, cap, "f" * 40, head)
    with pytest.raises(ValueError, match="relative"):
        viewer.git_diff(repo, cap, base, head, path="../../private.pem")
    missing = viewer.git_diff(repo, cap, base, head, path=":(glob)**")
    assert missing["status"] == "unavailable" and missing["files"] is None
    assert not (workspace / "synthetic-volume").exists()


def test_larger_bundle_is_explicitly_unavailable_without_preparation(workspace):
    root = workspace / "evidence"
    path, manifest = capture(root, git={"refs/heads/main": "a" * 40})
    manifest["git"]["portable_full_bundle"] = {"sha256": "b" * 64, "bytes": 33 * 1024 * 1024}
    path.write_bytes(canonical_json(manifest))
    viewer = ViewerData(workspace, roots=[root], offline=True)
    repo, (cap,) = ids(viewer)
    result = viewer.git_diff(repo, cap, "a" * 40, "a" * 40)
    assert result["status"] == "unavailable" and result["files"] is None
    assert "32 MiB" in result["gaps"][0]
