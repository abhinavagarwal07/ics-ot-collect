from pathlib import Path

import pytest

from icsot_observer import checks, gitstore
from icsot_observer.checks import verify_all
from icsot_observer.core import ObjectStore, canonical_json, sha256, write_once
from icsot_observer.gitstore import collect_git, remote_refs, run_git


@pytest.fixture
def local_capture(tmp_path, monkeypatch):
    source = tmp_path / "source"
    run_git(["init", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.email", "test@example.invalid"])
    run_git(["-C", str(source), "config", "user.name", "Test"])
    (source / "file.txt").write_text("original file content\n")
    run_git(["-C", str(source), "add", "file.txt"])
    run_git(["-C", str(source), "commit", "-m", "initial"])
    run_git(["-C", str(source), "tag", "-a", "v1", "-m", "annotated tag"])
    run_git(["-C", str(source), "tag", "v1-light"])
    commit = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    run_git(["-C", str(source), "update-ref", "refs/pull/7/head", commit])
    run_git(["-C", str(source), "update-ref", "refs/pull/7/merge", commit])
    root = tmp_path / "evidence"

    def local_git(args, *, timeout=1200, input_text=None):
        # Keep the production HTTPS-only origin policy intact. This test-only
        # seam redirects just the network commands to the controlled local repo.
        redirected = list(args)
        if redirected[0] == "ls-remote":
            assert redirected[1] == "https://github.com/test/repo.git"
            redirected[1] = str(source)
        elif len(redirected) > 2 and redirected[2] == "fetch" and "origin" in redirected:
            run_git(["-C", redirected[1], "config", "fetch.unpackLimit", "1000"])
            redirected[redirected.index("origin")] = str(source)
        return run_git(redirected, timeout=timeout, input_text=input_text)

    monkeypatch.setattr(gitstore, "run_git", local_git)
    return root, source, commit


def archive_manifest(root, run_id, git_info, previous=None):
    raw = canonical_json({"run_id": run_id, "repository_id": 17, "status": "complete",
                          "previous_manifest_sha256": previous, "responses": [], "git": git_info})
    path = root / "runs" / "17" / f"{run_id}.manifest.json"
    write_once(path, raw)
    return sha256(raw)


def replace_bundle(root, git_info, path):
    digest, size = ObjectStore(root).put_file(path)
    git_info["portable_full_bundle"] = {"sha256": digest, "bytes": size, "scope": "test fixture"}


def test_annotated_tags_pin_real_refs_and_keep_history(local_capture, monkeypatch):
    root, source, original_commit = local_capture
    advertised = remote_refs("https://github.com/test/repo.git")
    assert "refs/tags/v1" in advertised
    assert "refs/tags/v1^{}" not in advertised
    assert "refs/pull/7/head" in advertised and "refs/pull/7/merge" not in advertised
    first = collect_git(root, "test/repo", 17, "run1", bundle_full=True)
    tag = next(ref for ref in first["advertised_refs"] if ref["published_ref"] == "refs/tags/v1")
    tag_object = run_git(["-C", str(source), "rev-parse", "refs/tags/v1"]).strip()
    assert tag["object_id"] == tag_object != original_commit
    assert tag["peeled_object_id"] == original_commit
    assert first["git_ref_count"] == 4
    assert all("^{}" not in ref["local_immutable_ref"] for ref in first["advertised_refs"])
    lightweight = next(ref for ref in first["advertised_refs"] if ref["published_ref"] == "refs/tags/v1-light")
    assert lightweight["object_id"] == original_commit and "peeled_object_id" not in lightweight

    (source / "file.txt").write_text("later file content\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "later"])
    later_commit = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    second = collect_git(root, "test/repo", 17, "run2", bundle_full=True)
    mirror = root / first["mirror_path_relative"]
    assert run_git(["-C", str(mirror), "rev-parse", "refs/archive/run1/heads/main"]).strip() == original_commit
    assert run_git(["-C", str(mirror), "rev-parse", "refs/archive/run2/heads/main"]).strip() == later_commit
    previous = archive_manifest(root, "run1", first)
    archive_manifest(root, "run2", second, previous)

    commands = []

    def traced_git(args, **kwargs):
        commands.append(args)
        return run_git(args, **kwargs)

    monkeypatch.setattr(checks, "run_git", traced_git)
    result = verify_all(root)
    assert result["ok"], result["errors"]
    assert result["git_repositories_verified"] == 1
    assert result["portable_git_bundles_verified"] == 2
    assert result["git_refs_verified"] == 8
    assert len([args for args in commands if args[:3] == ["-C", str(mirror), "fsck"]]) == 1
    # Restore commands fetch exclusively from CAS bundle paths, never GitHub or
    # the source repository; both temporary restore repos start empty.
    fetches = [args for args in commands if len(args) > 2 and args[2] == "fetch"]
    assert len(fetches) == 2
    assert all(args[4].startswith(str(root / "objects" / "sha256")) for args in fetches)


def test_verification_detects_missing_reachable_blob_with_unchanged_ref_ids(local_capture):
    root, _, commit = local_capture
    info = collect_git(root, "test/repo", 17, "run1")
    archive_manifest(root, "run1", info)
    mirror = root / info["mirror_path_relative"]
    blob = run_git(["-C", str(mirror), "rev-parse", f"{commit}:file.txt"]).strip()
    loose_blob = mirror / "objects" / blob[:2] / blob[2:]
    assert loose_blob.exists()
    loose_blob.unlink()
    # The old ref-ID-only verifier would accept these unchanged refs.
    assert run_git(["-C", str(mirror), "rev-parse", "refs/archive/run1/heads/main"]).strip() == commit
    result = verify_all(root)
    assert not result["ok"]
    assert result["git_repositories_verified"] == 0
    assert any("Git object graph integrity failed" in error and "missing blob" in error for error in result["errors"])


def test_fsck_failure_reports_pack_companions_and_git_build(local_capture):
    root, _, _ = local_capture
    info = collect_git(root, "test/repo", 17, "run1")
    mirror = root / info["mirror_path_relative"]
    run_git(["-C", str(mirror), "repack", "-ad"])
    run_git(["-C", str(mirror), "prune-packed"])
    pack = next((mirror / "objects" / "pack").glob("*.pack"))
    index = pack.with_suffix(".idx")
    index.unlink()
    with pytest.raises(RuntimeError) as failure:
        run_git(["-C", str(mirror), "fsck", "--full", "--no-reflogs"])
    message = str(failure.value)
    assert "Git fsck diagnostics:" in message
    assert "Git build: git version " in message
    assert f"{pack.name} bytes=" in message
    assert "read=ok header12=5041434b" in message
    assert f"{index.name} missing" in message
    assert pack.with_suffix(".rev").name in message
    assert "inode=" in message and "nlink=" in message


def test_valid_bundle_without_declared_capture_refs_is_rejected(local_capture, tmp_path):
    root, _, _ = local_capture
    info = collect_git(root, "test/repo", 17, "run1")
    mirror = root / info["mirror_path_relative"]
    incomplete = tmp_path / "wrong-refs.bundle"
    run_git(["-C", str(mirror), "bundle", "create", str(incomplete), "refs/live/heads/main"])
    replace_bundle(root, info, incomplete)
    archive_manifest(root, "run1", info)
    result = verify_all(root)
    assert not result["ok"]
    assert result["git_repositories_verified"] == 1
    assert result["portable_git_bundles_verified"] == 0
    assert any("does not restore declared ref" in error for error in result["errors"])


def test_bundle_requiring_existing_objects_is_not_portable_full(local_capture, tmp_path, monkeypatch):
    root, source, original_commit = local_capture
    collect_git(root, "test/repo", 17, "run1")
    (source / "file.txt").write_text("new version\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "second"])
    info = collect_git(root, "test/repo", 17, "run2")
    mirror = root / info["mirror_path_relative"]
    incremental = tmp_path / "incremental.bundle"
    run_git(["-C", str(mirror), "bundle", "create", str(incremental), "refs/archive/run2/heads/main", f"^{original_commit}"])
    # This succeeds in the populated collector mirror, which supplies the missing
    # prerequisite, but must fail when verified as a full bundle in an empty repo.
    run_git(["-C", str(mirror), "bundle", "verify", str(incremental)])
    replace_bundle(root, info, incremental)
    archive_manifest(root, "run2", info)
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(mirror / "objects"))
    result = verify_all(root)
    assert not result["ok"]
    assert result["portable_git_bundles_verified"] == 0
    assert any("Portable Git bundle restore failed" in error for error in result["errors"])


def test_verification_checks_annotated_tag_peeled_metadata(local_capture):
    root, _, _ = local_capture
    info = collect_git(root, "test/repo", 17, "run1")
    tag = next(ref for ref in info["advertised_refs"] if ref["published_ref"] == "refs/tags/v1")
    tag["peeled_object_id"] = tag["object_id"]  # valid retained object, wrong semantic target
    archive_manifest(root, "run1", info)
    result = verify_all(root)
    assert not result["ok"]
    assert any("peeled target differs" in error for error in result["errors"])


def test_ref_validation_and_pinning_use_constant_git_processes(local_capture, monkeypatch):
    root, source, commit = local_capture
    annotated = run_git(["-C", str(source), "rev-parse", "v1"]).strip()
    names = {f"refs/heads/branch-{n}": commit for n in range(300)}
    names.update({f"refs/tags/tag-{n}": annotated for n in range(100)})
    run_git(["-C", str(source), "update-ref", "--stdin"],
            input_text="".join(f"create {ref} {oid}\n" for ref, oid in names.items()))
    local_git = gitstore.run_git
    calls = []

    def traced(args, **kwargs):
        calls.append((args, kwargs))
        return local_git(args, **kwargs)

    monkeypatch.setattr(gitstore, "run_git", traced)
    info = collect_git(root, "test/repo", 17, "run1")
    assert info["git_ref_count"] == 404
    assert len(calls) == 8
    batches = [(args, kwargs) for args, kwargs in calls if "cat-file" in args]
    updates = [(args, kwargs) for args, kwargs in calls if "update-ref" in args]
    assert len(batches) == len(updates) == 1
    assert batches[0][0][-1] == "--batch-check=%(objectname)"
    assert updates[0][1]["input_text"].startswith("start\ncreate ")
    assert updates[0][1]["input_text"].endswith("prepare\ncommit\n")


def test_archive_ref_namespace_is_create_only_and_transactional(local_capture):
    root, source, original = local_capture
    info = collect_git(root, "test/repo", 17, "run1")
    (source / "file.txt").write_text("new version\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "second"])
    run_git(["-C", str(source), "branch", "a-new-branch"])
    assert collect_git(root, "test/repo", 17, "run1") == info
    mirror = root / info["mirror_path_relative"]
    with pytest.raises(RuntimeError, match="reference already exists"):
        gitstore._pin_refs(mirror, [
            {"local_immutable_ref": "refs/archive/run1/heads/a-new-branch", "object_id": original},
            {"local_immutable_ref": "refs/archive/run1/heads/main", "object_id": original},
        ])
    assert run_git(["-C", str(mirror), "rev-parse", "refs/archive/run1/heads/main"]).strip() == original
    assert run_git(["-C", str(mirror), "for-each-ref", "refs/archive/run1/heads/a-new-branch"]) == ""


@pytest.mark.parametrize("failure", ["missing", "wrong-peel", "conflicting-peels", "changed-refs", "changed-peel"])
def test_capture_rejects_invalid_or_unstable_advertisements(local_capture, monkeypatch, failure):
    root, _, original = local_capture
    advertise = gitstore._remote_ref_advertisement
    count = 0

    def tampered(remote):
        nonlocal count
        count += 1
        refs, peeled = advertise(remote)
        if failure == "missing":
            refs["refs/heads/not-fetched"] = "a" * 40
        elif failure == "wrong-peel":
            peeled["refs/tags/v1"] = refs["refs/tags/v1"]
        elif failure == "conflicting-peels":
            refs["refs/tags/v0-copy"] = refs["refs/tags/v1"]
            peeled["refs/tags/v0-copy"] = refs["refs/tags/v1"]
        elif failure == "changed-refs" and count == 2:
            refs["refs/heads/late"] = original
        elif failure == "changed-peel" and count == 2:
            peeled["refs/tags/v1"] = refs["refs/tags/v1"]
        return refs, peeled

    monkeypatch.setattr(gitstore, "_remote_ref_advertisement", tampered)
    with pytest.raises(RuntimeError):
        collect_git(root, "test/repo", 17, "run1")
    assert run_git(["-C", str(root / "git" / "17.git"), "for-each-ref", "refs/archive/"]) == ""


def test_rejects_run_id_that_would_inject_stdin_commands(local_capture):
    root, _, _ = local_capture
    with pytest.raises(ValueError, match="Invalid immutable Git ref"):
        collect_git(root, "test/repo", 17, "run1\ncommit\n")
    assert not (root / "git").exists()
