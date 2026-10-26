import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from icsot_observer import gitstore, legacy_git
from icsot_observer.core import ObjectStore, canonical_json, sha256, write_once
from icsot_observer.gitarchive import verify_portable_archive
from icsot_observer.gitstore import collect_git, run_git
from icsot_observer.legacy_git import import_legacy_git


@pytest.fixture
def legacy_source(tmp_path, monkeypatch):
    source, root = tmp_path / "source", tmp_path / "evidence"
    run_git(["init", "--template=", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.name", "Generated Fixture"])
    run_git(["-C", str(source), "config", "user.email", "fixture@example.invalid"])
    (source / "file.txt").write_text("original state\n")
    (source / "unchanged.bin").write_bytes(b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(1024)))
    run_git(["-C", str(source), "add", "."])
    run_git(["-C", str(source), "commit", "-m", "original"])
    run_git(["-C", str(source), "tag", "-a", "v1", "-m", "original annotated tag"])

    def redirected(args, **options):
        args = list(args)
        if args[0] == "ls-remote":
            args[1] = str(source)
        elif len(args) > 2 and args[2] == "fetch" and "origin" in args:
            args[args.index("origin")] = str(source)
        return run_git(args, **options)

    monkeypatch.setattr(gitstore, "run_git", redirected)
    info = collect_git(root, "test/repo", 17, "original", bundle_full=True)
    manifest = {"schema_version": 1, "repository_id": 17, "repository_input_slug": "test/repo",
                "run_id": "original", "started_at": info["ls_remote_started_at"],
                "finished_at": info["ls_remote_completed_at"], "status": "complete", "mode": "full",
                "previous_manifest_sha256": None, "responses": [], "git": info,
                "api": {"mode": "full", "scopes": {}}}
    index = {"repository": "test/repo", "release_repository": "owner/collector",
             "release_tag": "corpus-baseline-123-1", "collector_code_sha": "a" * 40,
             "status": "complete_for_declared_shallow_baseline", "capture_accepted": True,
             "archive": {"complete": True, "encrypted": True, "recipient_spki_sha256": "b" * 64,
                         "parts": [{"name": "original.enc", "sha256": "c" * 64, "bytes": 1000,
                                    "plaintext": {"name": "original.xz", "sha256": "d" * 64, "bytes": 500}}]}}
    return {"root": root, "source": source, "manifest": manifest, "index": index}


def inputs(fixture):
    manifest, index = fixture["manifest"], copy.deepcopy(fixture["index"])
    manifest_raw = canonical_json(manifest)
    index["manifests"] = [{"sha256": sha256(manifest_raw), "run_id": manifest["run_id"],
                           "repository_id": manifest["repository_id"], "path": "runs/17/original.manifest.json",
                           "status": manifest["status"], "portable_full_bundle": manifest["git"]["portable_full_bundle"]}]
    index_raw = canonical_json(index)
    context = {"repository_id": 17, "repository": "test/repo", "source_release_repository": "owner/collector",
               "source_release_tag": "corpus-baseline-123-1", "source_release_id": 123,
               "source_index_asset": "test-repo.index.json", "source_index_asset_id": 456,
               "source_index_sha256": sha256(index_raw), "source_index_bytes": len(index_raw),
               "manifest_sha256": sha256(manifest_raw), "collector_code_sha": "a" * 40}
    return manifest_raw, index_raw, {"expected_manifest_sha256": sha256(manifest_raw),
                                    "expected_index_sha256": sha256(index_raw), "source_context": context,
                                    "importer_code_sha": "e" * 40, "imported_at_utc": "2026-10-27T00:00:00Z"}


def imported(fixture, **override):
    manifest, index, options = inputs(fixture)
    options.update(override)
    return import_legacy_git(fixture["root"], manifest, index, **options)


def test_legacy_import_preserves_original_bytes_and_is_idempotent(legacy_source, monkeypatch):
    fixture = legacy_source
    root = fixture["root"]
    raw, _, _ = inputs(fixture)
    original = root / "runs/17/original.manifest.json"
    write_once(original, raw)
    write_once(original.with_suffix(".json.ots"), b"original retained proof fixture")
    bundle = fixture["manifest"]["git"]["portable_full_bundle"]
    bundle_path = ObjectStore(root).location(bundle["sha256"])
    before_bundle = bundle_path.read_bytes()
    commands = []

    def traced(args, **options):
        commands.append(args)
        return run_git(args, **options)

    monkeypatch.setattr(legacy_git, "run_git", traced)
    first = imported(fixture)
    second = imported(fixture, imported_at_utc="2026-10-28T00:00:00Z")
    assert first["created"] is True and second["created"] is False
    assert first["descriptor_sha256"] == second["descriptor_sha256"]
    assert first["receipt_sha256"] == second["receipt_sha256"]
    assert json.loads(Path(first["receipt_path"]).read_bytes())["imported_at_utc"] == "2026-10-27T00:00:00Z"
    assert original.read_bytes() == raw
    assert original.with_suffix(".json.ots").read_bytes() == b"original retained proof fixture"
    assert bundle_path.read_bytes() == before_bundle
    assert first["new_git_bundle_bytes"] == 0
    assert not [args for args in commands if "bundle" in args and "create" in args]
    receipt = json.loads(Path(first["receipt_path"]).read_bytes())
    assert receipt["imported_at_provenance"] == "supplied_frozen_import_context"
    assert receipt["new_source_observation"] is False and receipt["api_scope_imported"] is False
    assert receipt["source"]["source_observation_started_at"] == fixture["manifest"]["started_at"]
    catalog = first["legacy_prior_export_catalog"]
    assert catalog["kind"] == "authenticated_legacy_git_seed_v1"
    assert {member["sha256"] for member in catalog["retained_members"]} == {sha256(raw), bundle["sha256"]}
    assert first["descriptor_sha256"] not in {member["sha256"] for member in catalog["retained_members"]}
    json.dumps(first)  # The orchestrator may persist the complete helper result.


def test_import_default_clock_is_distinct_from_frozen_source_time(legacy_source, monkeypatch):
    monkeypatch.setattr(legacy_git, "utc_iso", lambda: "2026-10-27T10:00:00Z")
    result = imported(legacy_source, imported_at_utc=None)
    receipt = json.loads(Path(result["receipt_path"]).read_bytes())
    assert receipt["imported_at_utc"] == "2026-10-27T10:00:00Z"
    assert receipt["imported_at_provenance"] == "local_system_clock_after_verification"
    assert receipt["source"]["source_observation_started_at"] == legacy_source["manifest"]["started_at"]


def test_legacy_import_seeds_true_next_delta_and_offline_restoration(legacy_source, tmp_path):
    fixture = legacy_source
    root, source = fixture["root"], fixture["source"]
    original = fixture["manifest"]["git"]["portable_full_bundle"]
    shutil.rmtree(root / "git/17.git")
    result = imported(fixture)
    (source / "file.txt").write_text("new prospective state\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "new capture"])
    later = collect_git(root, "test/repo", 17, "later", archive_mode="incremental")
    descriptor = later["portable_archive"]
    assert descriptor["kind"] == "incremental"
    assert descriptor["parent_archive_sha256"] == result["descriptor_sha256"]
    assert descriptor["prerequisites"] == [result["archive_descriptor"]["bundle"]]
    assert descriptor["bundle"]["bytes"] < original["bytes"] // 10
    assert descriptor["bundle"]["sha256"] != original["sha256"]
    shutil.rmtree(root / "git")
    shutil.rmtree(source)
    restored = tmp_path / "offline.git"
    verify_portable_archive(root, later, restored)
    assert run_git(["-C", str(restored), "show", "refs/archive/original/heads/main:file.txt"]) == "original state\n"
    assert run_git(["-C", str(restored), "show", "refs/archive/later/heads/main:file.txt"]) == "new prospective state\n"


def test_api_partial_archive_can_supply_independently_verified_full_git(legacy_source):
    fixture = legacy_source
    fixture["manifest"]["status"] = "partial"
    fixture["manifest"]["api"] = {"failures": [{"scope": "issues", "reason": "rate_deferred"}]}
    fixture["index"].update(status="partial", capture_accepted=False)
    result = imported(fixture)
    assert result["verification"]["full_fsck"] is True
    receipt = json.loads(Path(result["receipt_path"]).read_bytes())
    assert receipt["source"]["source_manifest_status"] == receipt["source"]["source_index_status"] == "partial"
    assert receipt["api_scope_imported"] is False
    assert not (fixture["root"] / "observer.sqlite3").exists()


@pytest.mark.parametrize("tamper", ["manifest-hash", "index-hash", "context-id", "context-hash", "membership"])
def test_import_rejects_unbound_source_identity(legacy_source, tamper):
    fixture = legacy_source
    raw, index, options = inputs(fixture)
    if tamper == "manifest-hash":
        options["expected_manifest_sha256"] = "0" * 64
    elif tamper == "index-hash":
        options["expected_index_sha256"] = "0" * 64
    elif tamper == "context-id":
        options["source_context"]["repository_id"] += 1
    elif tamper == "context-hash":
        options["source_context"]["source_index_sha256"] = "0" * 64
    else:
        value = json.loads(index)
        value["manifests"] = []
        index = canonical_json(value)
        options["expected_index_sha256"] = sha256(index)
        options["source_context"].update(source_index_sha256=sha256(index), source_index_bytes=len(index))
    with pytest.raises(ValueError):
        import_legacy_git(fixture["root"], raw, index, **options)
    assert not (fixture["root"] / "git/17.git/icsot-archive-head").exists()


def test_import_rejects_wrong_declared_tag_peel_despite_public_acceptance(legacy_source):
    fixture = legacy_source
    tag = next(ref for ref in fixture["manifest"]["git"]["advertised_refs"] if ref["published_ref"] == "refs/tags/v1")
    tag["peeled_object_id"] = tag["object_id"]
    with pytest.raises(RuntimeError, match="peeled target differs"):
        imported(fixture)
    assert not (fixture["root"] / "git/17.git/icsot-archive-head").exists()


def test_import_rejects_missing_blob_in_hash_matching_bundle(legacy_source, tmp_path, monkeypatch):
    fixture = legacy_source
    root = fixture["root"]
    mirror = root / "git/17.git"
    blob = run_git(["-C", str(mirror), "rev-parse", "refs/archive/original/heads/main:file.txt"]).strip()
    objects = [line.split(" ", 1)[0] for line in run_git(["-C", str(mirror), "rev-list", "--objects", "--all"]).splitlines()]
    pack_hash = run_git(["-C", str(mirror), "pack-objects", str(tmp_path / "incomplete")],
                        input_text="\n".join(oid for oid in objects if oid != blob) + "\n").strip()
    refs = run_git(["-C", str(mirror), "for-each-ref", "--format=%(objectname) %(refname)"])
    damaged = tmp_path / "missing-blob.bundle"
    damaged.write_bytes(b"# v2 git bundle\n" + refs.encode() + b"\n" + (tmp_path / f"incomplete-{pack_hash}.pack").read_bytes())
    digest, length = ObjectStore(root).put_file(damaged)
    fixture["manifest"]["git"]["portable_full_bundle"].update(sha256=digest, bytes=length)
    # Even a caller's custom init template must not lend the supposedly empty
    # verifier the missing blob from an existing object database.
    template = tmp_path / "external-template"
    (template / "objects/info").mkdir(parents=True)
    (template / "objects/info/alternates").write_text(str(mirror / "objects") + "\n")
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(template))
    with pytest.raises(RuntimeError):
        imported(fixture)
    assert not (mirror / "icsot-archive-head").exists()


@pytest.mark.parametrize("tamper", ["cas-bytes", "declared-size"])
def test_import_rejects_bundle_identity_mismatch(legacy_source, tamper):
    fixture = legacy_source
    bundle = fixture["manifest"]["git"]["portable_full_bundle"]
    if tamper == "cas-bytes":
        path = ObjectStore(fixture["root"]).location(bundle["sha256"])
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
    else:
        bundle["bytes"] += 1
    with pytest.raises(RuntimeError, match="full-bundle bytes"):
        imported(fixture)
    assert not (fixture["root"] / "git/17.git/icsot-archive-head").exists()


def test_import_rejects_incremental_bundle_labeled_full(legacy_source, tmp_path):
    fixture = legacy_source
    root, source = fixture["root"], fixture["source"]
    mirror = root / "git/17.git"
    original = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    (source / "file.txt").write_text("later state\n")
    run_git(["-C", str(source), "commit", "-a", "-m", "later"])
    run_git(["-C", str(mirror), "fetch", "--no-auto-maintenance", str(source), "+refs/heads/main:refs/later/main"])
    thin = tmp_path / "incremental.bundle"
    run_git(["-C", str(mirror), "bundle", "create", str(thin), "refs/later/main", "^" + original])
    run_git(["-C", str(mirror), "bundle", "verify", str(thin)])
    digest, length = ObjectStore(root).put_file(thin)
    fixture["manifest"]["git"]["portable_full_bundle"].update(sha256=digest, bytes=length)
    with pytest.raises(ValueError, match="object prerequisites"):
        imported(fixture)


def test_import_resumes_after_receipt_before_head_without_new_import_time(legacy_source, monkeypatch):
    fixture = legacy_source
    mirror = fixture["root"] / "git/17.git"
    shutil.rmtree(mirror)
    original_write = legacy_git._exact_file

    def interrupted(path, raw):
        if path.name == "icsot-archive-head":
            raise RuntimeError("generated interruption before publishing import head")
        return original_write(path, raw)

    monkeypatch.setattr(legacy_git, "_exact_file", interrupted)
    with pytest.raises(RuntimeError, match="generated interruption"):
        imported(fixture)
    assert mirror.exists() and not (mirror / "icsot-archive-head").exists()
    monkeypatch.setattr(legacy_git, "_exact_file", original_write)
    result = imported(fixture, imported_at_utc="2026-10-28T00:00:00Z")
    receipt = json.loads(Path(result["receipt_path"]).read_bytes())
    assert receipt["imported_at_utc"] == "2026-10-27T00:00:00Z"
    assert (mirror / "icsot-archive-head").read_text().strip() == result["descriptor_sha256"]


@pytest.mark.parametrize("external", ["alternates", "promisor-marker", "promisor-config", "config-include"])
def test_existing_mirror_external_supplies_rejected_before_object_reads(legacy_source, tmp_path, monkeypatch, external):
    fixture = legacy_source
    mirror = fixture["root"] / "git/17.git"
    if external == "alternates":
        (mirror / "objects/info").mkdir(exist_ok=True)
        (mirror / "objects/info/alternates").write_text(str(fixture["source"] / ".git/objects") + "\n")
    elif external == "promisor-marker":
        (mirror / "objects/pack").mkdir(exist_ok=True)
        (mirror / "objects/pack" / ("pack-" + "0" * 40 + ".promisor")).write_bytes(b"")
    elif external == "promisor-config":
        run_git(["-C", str(mirror), "config", "remote.origin.promisor", "true"])
    else:
        external_config = tmp_path / "external-config"
        external_config.write_text("[remote \"outside\"]\n promisor = true\n")
        run_git(["-C", str(mirror), "config", "include.path", str(external_config)])
    commands = []

    def traced(args, **options):
        commands.append(args)
        return run_git(args, **options)

    monkeypatch.setattr(legacy_git, "run_git", traced)
    with pytest.raises(ValueError):
        imported(fixture)
    assert not [args for args in commands if len(args) > 2 and
                args[2] in ("cat-file", "fsck", "fetch", "for-each-ref")]
    assert not (mirror / "icsot-archive-head").exists()


@pytest.mark.parametrize("mismatch", ["namespace", "head"])
def test_import_never_overwrites_existing_different_namespace_or_head(legacy_source, mismatch):
    fixture = legacy_source
    mirror = fixture["root"] / "git/17.git"
    if mismatch == "namespace":
        tag = run_git(["-C", str(mirror), "rev-parse", "refs/archive/original/tags/v1"]).strip()
        run_git(["-C", str(mirror), "update-ref", "refs/archive/original/heads/main", tag])
        before = run_git(["-C", str(mirror), "for-each-ref", "--format=%(refname) %(objectname)"])
    else:
        write_once(mirror / "icsot-archive-head", ("0" * 64 + "\n").encode())
        before = (mirror / "icsot-archive-head").read_bytes()
    with pytest.raises(RuntimeError):
        imported(fixture)
    if mismatch == "namespace":
        assert run_git(["-C", str(mirror), "for-each-ref", "--format=%(refname) %(objectname)"]) == before
    else:
        assert (mirror / "icsot-archive-head").read_bytes() == before
