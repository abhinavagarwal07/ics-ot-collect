import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from icsot_observer import gitarchive, gitstore
from icsot_observer.checks import _verify_portable_bundle, verify_all
from icsot_observer.core import ObjectStore, canonical_json, sha256, write_once
from icsot_observer.gitarchive import descriptor_digest, verify_portable_archive
from icsot_observer.gitstore import collect_git, run_git


@pytest.fixture
def incremental_source(tmp_path, monkeypatch):
    source, root = tmp_path / "source", tmp_path / "evidence"
    run_git(["init", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.email", "test@example.invalid"])
    run_git(["-C", str(source), "config", "user.name", "Test"])
    (source / "file.txt").write_text("first state\n")
    (source / "unchanged.bin").write_bytes(b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(4096)))
    run_git(["-C", str(source), "add", "."])
    run_git(["-C", str(source), "commit", "-m", "initial"])
    run_git(["-C", str(source), "tag", "-a", "v1", "-m", "first annotated tag"])

    def local_git(args, **kwargs):
        redirected = list(args)
        if redirected[0] == "ls-remote":
            redirected[1] = str(source)
        elif len(redirected) > 2 and redirected[2] == "fetch" and "origin" in redirected:
            redirected[redirected.index("origin")] = str(source)
        return run_git(redirected, **kwargs)

    monkeypatch.setattr(gitstore, "run_git", local_git)
    return root, source


def capture(root, name):
    info = collect_git(root, "test/repo", 17, name, archive_mode="incremental")
    assert info["portable_full_bundle"] is None
    assert info["archive_ref_prefix"] == f"refs/archive/{name}/"
    return info


def manifest(root, run_id, capture_id, git_info, previous=None):
    raw = canonical_json({"run_id": run_id, "capture_id": capture_id,
                          "repository_id": 17, "status": "complete", "responses": [],
                          "previous_manifest_sha256": previous, "git": git_info})
    write_once(root / "runs" / "17" / f"{run_id}.manifest.json", raw)
    return sha256(raw)


def next_commit(source):
    (source / "file.txt").write_text("second state\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "second"])
    return run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()


def test_incremental_chain_and_refs_only_restore_without_mirror(incremental_source, tmp_path, monkeypatch):
    root, source = incremental_source
    original = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    baseline = capture(root, "capture1")
    first = baseline["portable_archive"]
    assert first["kind"] == "baseline" and first["prerequisites"] == []
    assert first["bundle"]["prerequisite_object_ids"] == []
    later = next_commit(source)
    delta = capture(root, "capture2")
    second = delta["portable_archive"]
    assert second["kind"] == "incremental"
    assert second["parent_archive_sha256"] == descriptor_digest(first)
    assert second["prerequisites"] == [first["bundle"]]
    assert second["bundle"]["prerequisite_object_ids"] == [original]
    assert second["bundle"]["bytes"] < first["bundle"]["bytes"] // 10
    # A new name for an already archived ancestor introduces no object, but the
    # new capture namespace must still restore from its declared prerequisites.
    run_git(["-C", str(source), "branch", "old-state", original])
    ref_only = capture(root, "capture3")
    third = ref_only["portable_archive"]
    assert third["kind"] == "refs-only" and third["bundle"] is None
    assert third["prerequisites"] == [first["bundle"], second["bundle"]]
    no_change = capture(root, "capture4")
    assert no_change["portable_archive"]["kind"] == "refs-only"
    assert no_change["portable_archive"]["prerequisites"] == third["prerequisites"]

    previous = None
    for n, info in enumerate((baseline, delta, ref_only, no_change), 1):
        previous = manifest(root, f"final{n}", f"capture{n}", info, previous)
    verification_calls = []

    def verify_traced(args, **kwargs):
        verification_calls.append(args)
        return run_git(args, **kwargs)

    monkeypatch.setattr(gitarchive, "run_git", verify_traced)
    result = verify_all(root)
    assert result["ok"], result["errors"]
    assert result["portable_git_archives_verified"] == 4
    assert result["portable_git_bundles_verified"] == 0
    # Full acceptance verification replays the baseline and delta once, even
    # though four separate capture manifests declare that same closure.
    assert len([args for args in verification_calls if len(args) > 2 and args[2] == "fetch"]) == 2

    shutil.rmtree(source)
    shutil.rmtree(root / "git")
    calls = []

    def traced(args, **kwargs):
        calls.append(args)
        return run_git(args, **kwargs)

    monkeypatch.setattr(gitarchive, "run_git", traced)
    restored = tmp_path / "offline.git"
    verify_portable_archive(root, no_change, restored)
    assert run_git(["-C", str(restored), "rev-parse", "refs/archive/capture4/heads/main"]).strip() == later
    assert run_git(["-C", str(restored), "rev-parse", "refs/archive/capture4/heads/old-state"]).strip() == original
    fetches = [args for args in calls if len(args) > 2 and args[2] == "fetch"]
    assert len(fetches) == 2
    assert all(args[4].startswith(str(root / "objects" / "sha256")) for args in fetches)


def test_force_push_and_deleted_refs_survive_incremental_closure(incremental_source, tmp_path):
    root, source = incremental_source
    run_git(["-C", str(source), "branch", "to-delete"])
    first = capture(root, "capture1")
    original = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    tag = run_git(["-C", str(source), "rev-parse", "v1"]).strip()
    run_git(["-C", str(source), "checkout", "--orphan", "replacement"])
    run_git(["-C", str(source), "commit", "-a", "-m", "unrelated root"])
    replacement = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    run_git(["-C", str(source), "branch", "-f", "main", replacement])
    run_git(["-C", str(source), "branch", "-D", "to-delete"])
    run_git(["-C", str(source), "tag", "-d", "v1"])
    second = capture(root, "capture2")
    published = {ref["published_ref"] for ref in second["advertised_refs"]}
    assert "refs/heads/to-delete" not in published and "refs/tags/v1" not in published
    restored = tmp_path / "offline.git"
    verify_portable_archive(root, second, restored)
    for ref, expected in (("refs/archive/capture1/heads/to-delete", original),
                          ("refs/archive/capture1/tags/v1", tag),
                          ("refs/archive/capture2/heads/main", replacement)):
        assert run_git(["-C", str(restored), "rev-parse", ref]).strip() == expected
    assert set(first["portable_archive"]["covered_object_tips"]).issubset(second["portable_archive"]["covered_object_tips"])


def test_annotated_tag_only_change_creates_real_object_delta(incremental_source, tmp_path):
    root, source = incremental_source
    baseline = capture(root, "capture1")
    run_git(["-C", str(source), "tag", "-a", "v2", "-m", "new tag, same commit"])
    info = capture(root, "capture2")
    descriptor = info["portable_archive"]
    assert descriptor["kind"] == "incremental"
    assert descriptor["bundle"]["bytes"] < baseline["portable_archive"]["bundle"]["bytes"] // 10
    # Git's own header lists no commit prerequisite for this tag-only pack;
    # explicit archive prerequisites still carry the baseline object closure.
    assert descriptor["bundle"]["prerequisite_object_ids"] == []
    assert descriptor["prerequisites"] == [baseline["portable_archive"]["bundle"]]
    verify_portable_archive(root, info, tmp_path / "restored.git")


def test_controlled_fetches_do_not_launch_detached_maintenance(incremental_source, tmp_path, monkeypatch):
    root, source = incremental_source
    capture(root, "capture1")
    next_commit(source)
    trace = tmp_path / "git-trace.jsonl"
    monkeypatch.setenv("GIT_TRACE2_EVENT", str(trace))
    info = capture(root, "capture2")
    verify_portable_archive(root, info, tmp_path / "restored.git")
    # Cover the independently supported legacy full-bundle verifier too.
    full = tmp_path / "full.bundle"
    run_git(["-C", str(root / info["mirror_path_relative"]), "bundle", "create", str(full), "--all"])
    _verify_portable_bundle(full, info)
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    fetches = [event["argv"] for event in events
               if event["event"] == "start" and "fetch" in event.get("argv", [])]
    assert len(fetches) == 5  # Source, cache, baseline+delta restore, legacy restore.
    assert all("--no-auto-maintenance" in args for args in fetches)
    assert not [event for event in events if event["event"] == "child_start" and
                "maintenance" in event.get("argv", [])]
    mirror = root / info["mirror_path_relative"]
    cache = mirror / "icsot-verified-archive.git"
    for repo in (mirror, cache):
        assert not (repo / "gc.pid").exists()
        assert not (repo / "maintenance.pid").exists()


@pytest.mark.parametrize("corruption", ["missing", "wrong-size", "wrong-header-prerequisites", "wrong-lineage"])
def test_incremental_verification_rejects_incomplete_or_false_prerequisites(incremental_source, tmp_path, corruption):
    root, source = incremental_source
    baseline = capture(root, "capture1")
    next_commit(source)
    info = capture(root, "capture2")
    bad = copy.deepcopy(info)
    descriptor = bad["portable_archive"]
    if corruption == "missing":
        ObjectStore(root).location(baseline["portable_archive"]["bundle"]["sha256"]).unlink()
    elif corruption == "wrong-size":
        descriptor["bundle"]["bytes"] += 1
    elif corruption == "wrong-header-prerequisites":
        descriptor["bundle"]["prerequisite_object_ids"] = []
    else:
        descriptor["prerequisites"] = []
    ObjectStore(root).put(canonical_json(descriptor))
    with pytest.raises((OSError, RuntimeError, ValueError)):
        verify_portable_archive(root, bad, tmp_path / "restored.git")
    manifest(root, "final1", "capture2", bad)
    result = verify_all(root, check_git=False)
    assert not result["ok"] and any("Portable Git archive restore failed" in error for error in result["errors"])


def test_warm_cache_does_not_hide_missing_archived_bundle(incremental_source):
    root, _ = incremental_source
    baseline = capture(root, "capture1")
    mirror = root / baseline["mirror_path_relative"]
    head = (mirror / "icsot-archive-head").read_text()
    ObjectStore(root).location(baseline["portable_archive"]["bundle"]["sha256"]).unlink()
    with pytest.raises(FileNotFoundError):
        capture(root, "capture2")
    assert (mirror / "icsot-archive-head").read_text() == head


def test_refs_only_cannot_claim_new_objects_from_the_live_mirror(incremental_source, monkeypatch):
    root, source = incremental_source
    baseline = capture(root, "capture1")
    mirror = root / baseline["mirror_path_relative"]
    head = (mirror / "icsot-archive-head").read_text()
    next_commit(source)
    original_git = gitarchive.run_git

    def hide_new_object_detection(args, **kwargs):
        if len(args) > 2 and args[2] == "rev-list":
            return ""
        return original_git(args, **kwargs)

    monkeypatch.setattr(gitarchive, "run_git", hide_new_object_detection)
    with pytest.raises(RuntimeError, match="advertised object missing"):
        capture(root, "capture2")
    assert (mirror / "icsot-archive-head").read_text() == head
    assert not (mirror / "icsot-archive-cache-head").exists()


def test_mismatched_cache_pointer_rebuilds_from_archived_closure(incremental_source):
    root, _ = incremental_source
    first = capture(root, "capture1")
    mirror = root / first["mirror_path_relative"]
    cache = mirror / "icsot-verified-archive.git"
    (cache / "sentinel-that-must-be-rebuilt").write_text("stale cache")
    (mirror / "icsot-archive-cache-head").write_text("0" * 64 + "\n")
    second = capture(root, "capture2")
    assert second["portable_archive"]["kind"] == "refs-only"
    assert not (cache / "sentinel-that-must-be-rebuilt").exists()


def test_manifest_cannot_choose_an_unrelated_capture_namespace(incremental_source):
    root, _ = incremental_source
    info = capture(root, "capture1")
    manifest(root, "final1", "other-capture", info)
    result = verify_all(root)
    assert not result["ok"]
    assert any("namespace differs from manifest capture ID" in error for error in result["errors"])


@pytest.mark.parametrize("crash_point", ["before-pin", "after-pin", "after-archive"])
def test_interrupted_capture_replays_original_observation(incremental_source, monkeypatch, crash_point):
    root, source = incremental_source
    original = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    pin = gitstore._pin_refs
    write = gitstore.write_once

    def interrupted_pin(repo, refs):
        if crash_point == "after-pin":
            pin(repo, refs)
        raise RuntimeError("simulated worker interruption")

    def interrupted_write(path, raw):
        if path.name.endswith(".complete.json"):
            raise RuntimeError("simulated worker interruption")
        return write(path, raw)

    if crash_point == "after-archive":
        monkeypatch.setattr(gitstore, "write_once", interrupted_write)
    else:
        monkeypatch.setattr(gitstore, "_pin_refs", interrupted_pin)
    with pytest.raises(RuntimeError, match="simulated worker interruption"):
        capture(root, "capture1")
    mirror = root / "git" / "17.git"
    pending = list((mirror / "icsot-captures").glob("*.pending.json"))
    assert len(pending) == 1
    saved_observation = json.loads(pending[0].read_bytes())["git"]
    accepted_head = (mirror / "icsot-archive-head").read_text() if crash_point == "after-archive" else None
    next_commit(source)
    monkeypatch.setattr(gitstore, "_pin_refs", pin)
    monkeypatch.setattr(gitstore, "write_once", write)
    local_git = gitstore.run_git

    def no_new_observation(args, **kwargs):
        assert args[0] != "ls-remote"
        assert not (len(args) > 2 and args[2] == "fetch" and "origin" in args)
        return local_git(args, **kwargs)

    monkeypatch.setattr(gitstore, "run_git", no_new_observation)
    resumed = capture(root, "capture1")
    assert resumed["advertised_refs"] == saved_observation["advertised_refs"]
    assert resumed["ls_remote_started_at"] == saved_observation["ls_remote_started_at"]
    assert resumed["ls_remote_completed_at"] == saved_observation["ls_remote_completed_at"]
    assert resumed["portable_archive"]["kind"] == "baseline"
    assert resumed["portable_archive"]["parent_archive_sha256"] is None
    assert run_git(["-C", str(mirror), "rev-parse", "refs/archive/capture1/heads/main"]).strip() == original
    if accepted_head is not None:
        assert (mirror / "icsot-archive-head").read_text() == accepted_head


def test_complete_capture_retry_is_source_independent_and_does_not_advance_parent(incremental_source, monkeypatch):
    root, source = incremental_source
    first = capture(root, "capture1")
    mirror = root / first["mirror_path_relative"]
    head = (mirror / "icsot-archive-head").read_text()
    shutil.rmtree(source)
    local_git = gitstore.run_git

    def no_new_observation(args, **kwargs):
        assert args[0] != "ls-remote"
        assert not (len(args) > 2 and args[2] == "fetch" and "origin" in args)
        return local_git(args, **kwargs)

    monkeypatch.setattr(gitstore, "run_git", no_new_observation)
    assert capture(root, "capture1") == first
    assert (mirror / "icsot-archive-head").read_text() == head
