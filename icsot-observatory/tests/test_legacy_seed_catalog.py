"""Synthetic, tiny offline legacy-to-native recovery; never study observations."""
import copy
import base64
import io
import json
import shutil
import tarfile
import zlib
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer.core import ObjectStore, canonical_json, sha256
from icsot_observer.encryption import encrypt_file, public_key_fingerprint
from icsot_observer.gitarchive import _bundle_header, verify_portable_archive
from icsot_observer.gitstore import run_git
from icsot_observer.legacy_seed_catalog import (
    LegacySeedError, legacy_seed_digest, public_legacy_reference, registerable_members,
    restore_legacy_seeded_capture, seal_legacy_seed, validate_legacy_seed,
)
from icsot_observer.viewer_data import ViewerData


def identity(path):
    raw = path.read_bytes()
    return {"sha256": sha256(raw), "bytes": len(raw)}


def archive(path, files):
    with tarfile.open(path, "w:xz") as output:
        for name, raw in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mtime = len(raw), 1
            output.addfile(item, io.BytesIO(raw))


@pytest.fixture(params=["native", "migrated", "multipart"])
def closure(tmp_path, request):
    """Two source commits, original encrypted baseline, then one native package."""
    mode = request.param
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private, public = tmp_path / "synthetic-private.pem", tmp_path / "synthetic-public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    recipient = public_key_fingerprint(public)
    source, evidence = tmp_path / "synthetic-source", tmp_path / "synthetic-evidence"
    def git(args, **kwargs):
        return run_git(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args], **kwargs)
    git(["init", "-b", "main", str(source)])
    git(["-C", str(source), "config", "user.name", "Synthetic Fixture"])
    git(["-C", str(source), "config", "user.email", "fixture@example.invalid"])
    (source / "synthetic.txt").write_text("before\n")
    git(["-C", str(source), "add", "."])
    git(["-C", str(source), "commit", "-m", "Synthetic original"])
    old_oid = git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    old_ref = "refs/archive/legacy-one/heads/main"
    git(["-C", str(source), "update-ref", old_ref, old_oid])
    bundle = tmp_path / "synthetic-original.bundle"
    git(["-C", str(source), "bundle", "create", str(bundle), "--all"])
    store = ObjectStore(evidence)
    old_bundle_sha, old_bundle_bytes = store.put_file(bundle)
    old_body = canonical_json([{"id": 1, "title": "Synthetic before", "body": "before"}])
    old_body_sha = store.put(old_body)
    old_git = {"remote": "https://github.com/example/fixture.git", "git_object_hash_algorithm": "sha1",
        "advertised_refs": [{"published_ref": "refs/heads/main", "local_immutable_ref": old_ref, "object_id": old_oid}],
        "portable_full_bundle": {"sha256": old_bundle_sha, "bytes": old_bundle_bytes}}
    old_manifest = {"schema_version": 1, "repository_id": 123, "repository_input_slug": "example/fixture",
        "run_id": "legacy-one", "mode": "full", "status": "complete", "previous_manifest_sha256": None,
        "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:02Z",
        "responses": [{"purpose": "issues", "status": 200, "body_sha256": old_body_sha, "body_bytes": len(old_body)}],
        "api": {"scopes": {"issues": {"status": "complete_for_query"}}}, "git": old_git, "failures": []}
    old_raw = canonical_json(old_manifest)
    old_sha = sha256(old_raw)
    old_relative = "runs/123/legacy-one.manifest.json"
    old_path = evidence / old_relative
    old_path.parent.mkdir(parents=True)
    old_path.write_bytes(old_raw)
    original_proof = b"SYNTHETIC unverified proof bytes; no timestamp claim\n"
    Path(str(old_path) + ".ots").write_bytes(original_proof)
    original_files = {"evidence/" + path.relative_to(evidence).as_posix(): path.read_bytes()
                      for path in evidence.rglob("*") if path.is_file()}
    original_files["reports/synthetic-provenance.json"] = canonical_json({"fixture": True})
    original_files["evidence/git/ignored-mirror/sample"] = b"Synthetic unused original mirror bytes" * 1000
    package = tmp_path / "synthetic-original.tar.xz"
    archive(package, original_files)
    compressed = package.read_bytes()
    pieces = [compressed] if mode != "multipart" else [compressed[:len(compressed)//2], compressed[len(compressed)//2:]]
    assets, source_parts, seed_parts, aliases = {}, [], [], {}
    release = {"release_repository": "example/archive", "release_tag": "corpus-baseline-synthetic",
               "release_id": 10}
    for number, raw in enumerate(pieces, 1):
        plain_path = tmp_path / f"original.part-{number:04d}"
        plain_path.write_bytes(raw)
        plain = {"name": plain_path.name, **identity(plain_path)}
        encrypted = tmp_path / (plain_path.name + ".enc")
        encryption = encrypt_file(plain_path, encrypted, public)
        cipher = {"name": encrypted.name, **identity(encrypted)}
        assets[encrypted.name] = encrypted
        native = {**cipher, "plaintext": plain, "encryption": encryption}
        source_parts.append(plain if mode == "migrated" else native)
        aliases[plain["name"]] = {"plaintext": plain, "ciphertext": cipher}
        seed_parts.append({"ordinal": number, "plaintext": plain,
                           "ciphertext": {**release, **cipher, "asset_id": 100 + number}, "capsule": None})
    row = {"path": old_relative, "sha256": old_sha, "bytes": len(old_raw), "run_id": "legacy-one",
           "started_at": old_manifest["started_at"], "finished_at": old_manifest["finished_at"],
           "repository_id": 123, "portable_full_bundle": old_git["portable_full_bundle"]}
    old_index = {"schema_version": 1, "repository": "example/fixture", "release_tag": release["release_tag"],
        "manifests": [row], "archive": {"complete": True, "parts": source_parts}}
    index_path = tmp_path / "original.index.json"
    # Deliberately noncanonical: its original-byte hash must remain authoritative.
    index_path.write_bytes(json.dumps(old_index, indent=2).encode() + b"\n")
    assets[index_path.name] = index_path
    index_ref = {**release, "asset_id": 200, "name": index_path.name, **identity(index_path)}
    migration, migration_ref = None, None
    if mode == "migrated":
        migration = {"schema_version": 1, "repository": release["release_repository"],
                     "release_tag": release["release_tag"], "parts": aliases}
        migration_path = tmp_path / "encryption-migration-index.json"
        migration_path.write_bytes(canonical_json(migration))
        assets[migration_path.name] = migration_path
        migration_ref = {**release, "asset_id": 201, "name": migration_path.name, **identity(migration_path)}
    # Derived receipt is newer metadata, never an originally delivered member.
    receipt_path = evidence / "imports/legacy-synthetic.json"
    receipt_path.parent.mkdir()
    receipt = canonical_json({"kind": "synthetic-import-receipt", "source_index_sha256": index_ref["sha256"],
                              "archive_members_sha256": sha256(canonical_json([
                                  {"path": name, "sha256": sha256(raw), "bytes": len(raw)}
                                  for name, raw in sorted(original_files.items())])),
                              "imported_at": "2026-10-26T00:00:00Z"})
    receipt_path.write_bytes(receipt)
    selected = [{"path": name, "sha256": sha256(raw), "bytes": len(raw)} for name, raw in original_files.items()
                if name.startswith("evidence/") and not name.startswith("evidence/git/")]
    seed = seal_legacy_seed({"schema_version": 1, "kind": "legacy_baseline_package_v1", "repository_id": 123,
        "slug": "example/fixture", "source_index": index_ref, "source_manifest": {k: row[k] for k in
            ("path", "sha256", "bytes", "run_id", "started_at", "finished_at")},
        "owner_recipient_spki_sha256": recipient,
        "transport": {"kind": "migrated_encrypted_baseline" if mode == "migrated" else "native_encrypted_baseline",
                      "migration_index": migration_ref, "parts": seed_parts},
        "members": selected, "import_receipt": {"path": receipt_path.relative_to(evidence).as_posix(), **identity(receipt_path)}})
    baseline = {"schema_version": 1, "kind": "baseline", "repository_id": 123, "remote": old_git["remote"],
        "object_format": "sha1", "archive_ref_prefix": "refs/archive/legacy-one/", "advertised_refs": old_git["advertised_refs"],
        "covered_object_tips": [old_oid], "bundle": {**old_git["portable_full_bundle"], "prerequisite_object_ids": []},
        "prerequisites": [], "parent_archive_sha256": None,
        "legacy_origin": {"source_index_sha256": index_ref["sha256"], "manifest_sha256": old_sha}}
    baseline_sha = store.put(canonical_json(baseline))
    (source / "synthetic.txt").write_text("after\n")
    git(["-C", str(source), "commit", "-a", "-m", "Synthetic new observation"])
    head = git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    new_ref = "refs/archive/new-git/heads/main"
    git(["-C", str(source), "update-ref", new_ref, head])
    delta_path = tmp_path / "synthetic-increment.bundle"
    git(["-C", str(source), "bundle", "create", str(delta_path), "--all", "--stdin"], input_text="^" + old_oid + "\n")
    delta_sha, delta_bytes = store.put_file(delta_path)
    prerequisites, _ = _bundle_header(delta_path)
    child = {"schema_version": 1, "kind": "incremental", "repository_id": 123, "remote": old_git["remote"],
        "object_format": "sha1", "archive_ref_prefix": "refs/archive/new-git/",
        "advertised_refs": [{"published_ref": "refs/heads/main", "local_immutable_ref": new_ref, "object_id": head}],
        "covered_object_tips": [old_oid, head], "bundle": {"sha256": delta_sha, "bytes": delta_bytes,
            "prerequisite_object_ids": prerequisites}, "prerequisites": [baseline["bundle"]], "parent_archive_sha256": baseline_sha}
    child_sha = store.put(canonical_json(child))
    new_body = canonical_json([{"id": 1, "title": "Synthetic after", "body": "after"}])
    new_body_sha = store.put(new_body)
    api = {**old_manifest, "lane": "api", "capture_id": "synthetic-api", "run_id": "new-api", "mode": "delta",
        "started_at": "2026-01-02T00:00:00Z", "finished_at": "2026-01-02T00:00:01Z",
        "previous_manifest_sha256": old_sha, "git": None,
        "responses": [{"purpose": "issues", "status": 200, "body_sha256": new_body_sha},
                      {"purpose": "issue_comments", "status": 200, "body_sha256": old_body_sha}]}
    api_raw, api_relative = canonical_json(api), "runs/123/new-api.manifest.json"
    api_sha = sha256(api_raw)
    native_manifest = {**old_manifest, "lane": "git", "capture_id": "synthetic-git", "run_id": "new-git", "mode": "delta",
        "started_at": "2026-01-02T00:00:01Z", "finished_at": "2026-01-02T00:00:02Z",
        "previous_manifest_sha256": api_sha, "responses": [], "git": {**old_git, "advertised_refs": child["advertised_refs"],
            "archive_ref_prefix": child["archive_ref_prefix"], "portable_full_bundle": None, "portable_archive": child}}
    new_raw, new_relative = canonical_json(native_manifest), "runs/123/new-git.manifest.json"
    new_files = {"evidence/" + name: raw for name, raw in [(api_relative, api_raw), (new_relative, new_raw),
                 (receipt_path.relative_to(evidence).as_posix(), receipt)]}
    for digest in (baseline_sha, child_sha, delta_sha, new_body_sha):
        new_files[f"evidence/objects/sha256/{digest[:2]}/{digest}"] = store.get(digest)
    new_package = tmp_path / "native.tar.xz"
    archive(new_package, new_files)
    native_cipher = tmp_path / "native.tar.xz.part-0001.enc"
    encryption = encrypt_file(new_package, native_cipher, public)
    assets[native_cipher.name] = native_cipher
    native_index = {"schema_version": 1, "encrypted": True, "repository_id": 123, "lane": "git",
        "capture_id": "synthetic-git", "manifest_sha256": sha256(new_raw), "previous_manifest_sha256": api_sha,
        "recipient_spki_sha256": recipient, "legacy_prerequisites": [seed],
        "members": [{"path": name[len('evidence/'):], "sha256": sha256(raw), "bytes": len(raw)} for name, raw in sorted(new_files.items())],
        "requires_cas_sha256": [old_body_sha, old_bundle_sha],
        "assets": [{"name": native_cipher.name, **identity(native_cipher), "encryption": encryption}]}
    native_index_path = tmp_path / "new-git.index.json"
    native_index_path.write_bytes(canonical_json(native_index))
    assets[native_index_path.name] = native_index_path
    native_ref = {**release, "release_tag": "collector-observations-synthetic", "release_id": 11,
                  "asset_id": 300, "name": native_index_path.name, **identity(native_index_path)}
    @contextmanager
    def open_asset(ref):
        path = assets.get(ref["name"])
        if path is None:
            raise LegacySeedError("Synthetic immutable dependency is unavailable")
        yield path
    return dict(root=tmp_path, source=source, evidence=evidence, private=private, public=public, seed=seed, index=old_index,
        index_raw=index_path.read_bytes(), migration=migration, native=native_index, native_path=native_index_path,
        native_ref=native_ref, open_asset=open_asset, assets=assets, child=child, head=head, old_sha=old_sha,
        old_bundle_sha=old_bundle_sha, baseline_sha=baseline_sha, proof=original_proof, api_manifest=api, api_sha=api_sha,
        git_manifest=native_manifest)


def test_truthful_seed_validation_preserves_source_identities(closure):
    c = closure
    seed = validate_legacy_seed(c["seed"], repository_id=123, slug="example/fixture", root=c["evidence"],
                                source_index=c["index_raw"], migration_index=c["migration"])
    assert seed["source_manifest"]["started_at"] == "2026-01-01T00:00:00Z"
    assert "lane" not in seed and "encrypted" not in seed and "capture_id" not in seed
    delivered = {m["sha256"] for m in registerable_members(seed)}
    assert c["old_sha"] in delivered and c["old_bundle_sha"] in delivered
    assert c["baseline_sha"] not in delivered
    assert public_legacy_reference(seed) == seed and legacy_seed_digest(seed) == seed["seed_sha256"]
    new_members = {m["sha256"] for m in c["native"]["members"]}
    assert c["old_bundle_sha"] not in new_members and c["baseline_sha"] in new_members


def test_original_package_plus_new_increment_restores_without_working_state_or_upstream(closure):
    c = closure
    shutil.rmtree(c["source"])
    shutil.rmtree(c["evidence"])
    output = c["root"] / "independent-recovery"
    published_ref = {key: c["native_ref"][key] for key in ("release_tag", "name", "sha256", "bytes")}
    storage = {"kind": "cycle_git_catalog_v1", "logical_release": published_ref["release_tag"], "catalog": {"synthetic": True}}
    published_ref["storage"] = storage
    observed = []
    @contextmanager
    def open_asset(ref):
        if ref["release_tag"] == published_ref["release_tag"]:
            observed.append(ref)
            assert ref["storage"] == storage
        with c["open_asset"](ref) as path:
            yield path
    report = restore_legacy_seeded_capture(c["native_path"].read_bytes(), published_ref,
        open_asset=open_asset, owner_private_key_path=c["private"], output_root=output)
    assert observed
    assert report["status"] == "restored"
    evidence = output / "evidence"
    assert (evidence / "runs/123/legacy-one.manifest.json.ots").read_bytes() == c["proof"]
    assert json.loads((evidence / "runs/123/legacy-one.manifest.json").read_bytes())["started_at"] == "2026-01-01T00:00:00Z"
    assert not (evidence / "git/ignored-mirror").exists()
    restored = c["root"] / "independent.git"
    verify_portable_archive(evidence, {"portable_archive": c["child"], "advertised_refs": c["child"]["advertised_refs"],
        "archive_ref_prefix": c["child"]["archive_ref_prefix"], "remote": c["child"]["remote"],
        "git_object_hash_algorithm": "sha1"}, restored)
    assert run_git(["-C", str(restored), "rev-parse", "refs/archive/new-git/heads/main"]).strip() == c["head"]
    workspace = c["root"] / "viewer-workspace"
    workspace.mkdir()
    (workspace / "public_patch_corpus_185.csv").write_text("ID,Cohort,Repository_URL,Repository_Role\nS,Synthetic,https://github.com/example/fixture,primary_git\n")
    viewer = ViewerData(workspace, roots=[evidence], offline=True)
    repo = viewer.overview()["repos"][0]["id"]
    caps = {m["run_id"]: m["id"] for m in viewer.repo(repo)["captures"]}
    result = viewer.compare(repo, caps["legacy-one"], caps["new-api"], "issues")
    assert result["items"][0]["change"] == "representation_changed"
    assert result["items"][0]["body_before"] == "before" and result["items"][0]["body_after"] == "after"
    assert viewer.entity_detail(repo, caps["new-api"], "comments", "issue_comments:1")["status"] == "observed"


def test_missing_or_mismatched_dependency_never_falls_back_to_recollection(closure):
    c = closure
    part = c["seed"]["transport"]["parts"][0]["ciphertext"]["name"]
    c["assets"].pop(part)
    output = c["root"] / "failed-recovery"
    with pytest.raises(LegacySeedError, match="unavailable"):
        restore_legacy_seeded_capture(c["native_path"].read_bytes(), c["native_ref"], open_asset=c["open_asset"],
            owner_private_key_path=c["private"], output_root=output)
    assert not list(output.rglob("*.manifest.json"))
    bad = copy.deepcopy(c["seed"])
    bad["members"] = [m for m in bad["members"] if m["sha256"] != c["old_bundle_sha"]]
    bad = seal_legacy_seed(bad)
    with pytest.raises(LegacySeedError, match="full bundle"):
        validate_legacy_seed(bad, source_index=c["index_raw"], migration_index=c["migration"])


def test_original_hash_part_order_and_new_receipt_binding_fail_closed(closure):
    c = closure
    with pytest.raises(LegacySeedError, match="metadata bytes"):
        validate_legacy_seed(c["seed"], source_index=canonical_json(c["index"]), migration_index=c["migration"])
    bad = copy.deepcopy(c["seed"])
    bad["transport"]["parts"][0]["plaintext"]["sha256"] = "0" * 64
    bad = seal_legacy_seed(bad)
    with pytest.raises(LegacySeedError, match="part identities"):
        validate_legacy_seed(bad, source_index=c["index_raw"], migration_index=c["migration"])
    bad = copy.deepcopy(c["seed"])
    bad["members"].append({"path": "evidence/" + bad["import_receipt"]["path"],
                           "sha256": bad["import_receipt"]["sha256"], "bytes": bad["import_receipt"]["bytes"]})
    with pytest.raises(LegacySeedError, match="import receipt"):
        seal_legacy_seed(bad)


def test_selected_native_viewer_load_resolves_original_legacy_response_subset(closure, monkeypatch):
    from icsot_observer.archive_reader import ArchivePart
    c = closure
    workspace = c["root"] / "online-viewer-fixture"
    workspace.mkdir()
    (workspace / "public_patch_corpus_185.csv").write_text("ID,Cohort,Repository_URL,Repository_Role\nS,Synthetic,https://github.com/example/fixture,primary_git\n")
    by_id = {c["seed"]["source_index"]["asset_id"]: c["assets"][c["seed"]["source_index"]["name"]]}
    migration = c["seed"]["transport"].get("migration_index")
    if migration:
        by_id[migration["asset_id"]] = c["assets"][migration["name"]]
    class Metadata:
        bytes_read = 0
        def asset(self, asset, expected=None):
            raw = by_id[asset["id"]].read_bytes()
            assert len(raw) == asset["size"] and sha256(raw) == expected
            return json.loads(raw)
    viewer = ViewerData(workspace, roots=[], offline=True, metadata=Metadata(),
                        private_key_path=c["private"], release_repository="example/archive")
    repo = viewer._repository("example/fixture", 123)
    native = {**c["native"], "lane": "api", "capture_id": "synthetic-api", "manifest_sha256": c["api_sha"],
              "previous_manifest_sha256": c["old_sha"]}
    tag = c["native_ref"]["release_tag"]
    viewer._releases[tag] = {"tag": tag, "assets": {part["name"]: {"id": 1000 + i, "size": part["bytes"],
        "digest": "sha256:" + part["sha256"]} for i, part in enumerate(native["assets"])}}
    cap = viewer._add_capture(repo, {**c["api_manifest"], "sha256": c["api_sha"]},
        remote={"release_tag": tag, "name": "new-api.index.json", "index": native}, source=native)
    @contextmanager
    def local_part(asset, description, capture, part_class):
        with c["open_asset"]({"name": description["name"]}) as path:
            yield ArchivePart(path=path, **description)
    monkeypatch.setattr(viewer, "_download_part", local_part)
    result = viewer.load_capture(repo["key"], cap["key"])
    assert result["status"] == "loaded", result
    assert cap["legacy_dependencies_loaded"] == [c["seed"]["seed_sha256"]]
    assert viewer.entity_detail(repo["key"], cap["key"], "comments", "issue_comments:1")["status"] == "observed"
    assert result["capture"]["legacy_prerequisites"][0]["source_manifest"]["started_at"] == "2026-01-01T00:00:00Z"
    # A corrupt original dependency cannot publish even the already authenticated
    # new native package's provisional entity projection.
    part = c["assets"][c["seed"]["transport"]["parts"][0]["ciphertext"]["name"]]
    raw = bytearray(part.read_bytes())
    raw[-1] ^= 1
    part.write_bytes(raw)
    viewer._objects.clear()
    viewer._manifests.clear()
    cap["manifest"] = None
    cap["load_state"] = "metadata_only"
    assert viewer.load_capture(repo["key"], cap["key"])["status"] == "load_failed"
    assert viewer._objects == {} and cap["manifest"] is None


def test_real_exporter_omits_original_bulk_and_offline_recovers_its_explicit_legacy_dependency(closure):
    from icsot_observer.pipeline import CaptureExporter
    c = closure
    root = c["evidence"]
    for manifest in (c["api_manifest"], c["git_manifest"]):
        path = root / "runs/123" / (manifest["run_id"] + ".manifest.json")
        path.write_bytes(canonical_json(manifest))
    exports = c["root"] / "real-native-exports"
    exporter = CaptureExporter(root, exports, c["public"], verified_legacy_seeds=[c["seed"]])
    assert c["old_sha"] not in exporter.known_exports  # Never a fake ordinary capture index.
    selected = root / "runs/123/new-git.manifest.json"
    index = exporter.export({"manifest": str(selected), "manifest_sha256": sha256(selected.read_bytes()),
                             "run_id": "new-git", "repository_id": 123})
    assert index["legacy_prerequisites"] == [c["seed"]]
    members = {item["sha256"] for item in index["members"]}
    assert c["old_bundle_sha"] not in members and c["old_bundle_sha"] in index["requires_cas_sha256"]
    assert c["baseline_sha"] in members and c["seed"]["import_receipt"]["sha256"] in members
    index_path = exports / "new-git.index.json"
    for path in exports.iterdir():
        if path.is_file():
            c["assets"][path.name] = path
    reference = {**c["native_ref"], "name": index_path.name, **identity(index_path)}
    shutil.rmtree(c["source"])
    shutil.rmtree(root)
    output = c["root"] / "real-export-offline-recovery"
    result = restore_legacy_seeded_capture(index_path.read_bytes(), reference, open_asset=c["open_asset"],
        owner_private_key_path=c["private"], output_root=output)
    assert result["status"] == "restored"
    restored_git = c["root"] / "real-export-offline.git"
    verify_portable_archive(output / "evidence", c["git_manifest"]["git"], restored_git)
    assert run_git(["-C", str(restored_git), "rev-parse", "refs/archive/new-git/heads/main"]).strip() == c["head"]


def test_missing_legacy_index_times_remain_unknown_until_original_manifest_is_authenticated(closure):
    c = closure
    source = copy.deepcopy(c["index"])
    source["manifests"][0].pop("started_at")
    source["manifests"][0]["finished_at"] = None
    # A decoded source object here models an independently hash-checked old
    # index. The seed's UTC values still have to match exact old manifest bytes.
    assert validate_legacy_seed(c["seed"], source_index=source, migration_index=c["migration"], root=c["evidence"])
    wrong = copy.deepcopy(c["seed"])
    wrong["source_manifest"]["started_at"] = "2025-12-31T00:00:00Z"
    wrong = seal_legacy_seed(wrong)
    with pytest.raises(LegacySeedError, match="interval changed"):
        validate_legacy_seed(wrong, source_index=source, migration_index=c["migration"], root=c["evidence"])


def test_public_native_catalog_discovers_truthful_original_capture_by_frozen_reference(closure, monkeypatch):
    from icsot_observer.archive_reader import ArchivePart
    c = closure
    workspace = c["root"] / "discovery-fixture"
    workspace.mkdir()
    (workspace / "public_patch_corpus_185.csv").write_text("ID,Cohort,Repository_URL,Repository_Role\nS,Synthetic,https://github.com/example/fixture,primary_git\n")
    tag = c["native_ref"]["release_tag"]
    index_asset = {"id": 300, "name": c["native_path"].name, "size": c["native_ref"]["bytes"],
                   "digest": "sha256:" + c["native_ref"]["sha256"]}
    catalog = {"generation_release": tag, "repository_id": 123, "slug": "example/fixture", "observations": [{
        "capture_id": "synthetic-git", "lane": "git", "manifest_sha256": c["native"]["manifest_sha256"],
        "index": {"release_tag": tag, "name": index_asset["name"], "sha256": c["native_ref"]["sha256"]}}]}
    by_id = {300: c["native"], 301: catalog, c["seed"]["source_index"]["asset_id"]: c["index"]}
    if c["migration"]:
        by_id[c["seed"]["transport"]["migration_index"]["asset_id"]] = c["migration"]
    class Metadata:
        bytes_read = 0
        def json(self, endpoint):
            if "/releases?" in endpoint:
                return [{"id": 11, "tag_name": tag}]
            if "/releases/11/assets?" in endpoint:
                return [index_asset, {"id": 301, "name": "metadata-catalog.json", "size": len(canonical_json(catalog)),
                                     "digest": "sha256:" + sha256(canonical_json(catalog))}]
            raise ValueError("Synthetic unknown metadata endpoint")
        def asset(self, asset, expected=None):
            return by_id[asset["id"]]
    viewer = ViewerData(workspace, roots=[], metadata=Metadata(), private_key_path=c["private"], release_repository="example/archive")
    repo = viewer.overview()["repos"][0]["id"]
    caps = viewer.repo(repo)["captures"]
    original = next(item for item in caps if item["run_id"] == "legacy-one")
    assert original["lane"] == "combined" and original["load_state"] == "metadata_only"
    assert original["interval"]["started_at"] == "2026-01-01T00:00:00Z"
    @contextmanager
    def local_part(asset, description, capture, part_class):
        with c["open_asset"]({"name": description["name"]}) as path:
            yield ArchivePart(path=path, **description)
    monkeypatch.setattr(viewer, "_download_part", local_part)
    assert viewer.load_capture(repo, original["id"])["status"] == "loaded"
    assert viewer.entity_detail(repo, original["id"], "issues", "1")["entity"]["value"]["body"] == "before"


def test_recovery_budget_rejection_precedes_directory_creation_or_source_open(closure):
    from icsot_observer.localbudget import BudgetError
    c = closure
    opened = []
    @contextmanager
    def forbidden(ref):
        opened.append(ref)
        raise AssertionError("No source should open before local admission")
        yield
    class RejectBudget:
        def reserve(self, *args, **kwargs):
            raise BudgetError("Synthetic selected recovery cannot fit")
    output = c["root"] / "not-admitted"
    with pytest.raises(BudgetError):
        restore_legacy_seeded_capture(c["native_path"].read_bytes(), c["native_ref"], open_asset=forbidden,
            owner_private_key_path=c["private"], output_root=output, budget=RejectBudget())
    assert not output.exists() and opened == []


def test_selected_legacy_size_mismatch_is_rejected_before_any_output_write(closure, monkeypatch):
    from types import SimpleNamespace
    import icsot_observer.legacy_seed_catalog as catalog
    c = closure
    member = next(item for item in c["seed"]["members"] if item["path"].startswith("evidence/objects/sha256/"))
    class Stream:
        reads = 0
        remaining = member["bytes"] + 1
        def read(self, size):
            self.reads += 1
            count = min(size, self.remaining)
            self.remaining -= count
            return b"x" * count
    stream = Stream()
    class Reader:
        def __init__(self, *args, **kwargs): pass
        def scan(self, callback):
            callback(SimpleNamespace(path=member["path"], bytes=member["bytes"] + 1), stream)
            raise AssertionError("A misdeclared member must not reach scan completion")
    monkeypatch.setattr(catalog, "VerifiedArchiveReader", Reader)
    output = c["root"] / "size-mismatch"
    with pytest.raises(LegacySeedError, match="admitted output size"):
        restore_legacy_seeded_capture(c["native_path"].read_bytes(), c["native_ref"], open_asset=c["open_asset"],
            owner_private_key_path=c["private"], output_root=output)
    assert stream.reads == 0
    assert output.is_dir() and list(output.iterdir()) == []


def test_every_implicit_selected_path_ancestor_is_admitted(closure):
    from icsot_observer.localbudget import BudgetError
    c = closure
    class Budget:
        def __init__(self):
            self.reserved = None
            self.tracked = None
        def reserve(self, count, **kwargs):
            self.reserved = count
            return self
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def track(self, path):
            self.tracked = path
            raise BudgetError("Stop immediately after recording admission")
    def admitted_for(relative):
        index = copy.deepcopy(c["native"])
        index["members"].append({"path": relative, "sha256": sha256(b"{}"), "bytes": 2})
        raw = canonical_json(index)
        ref = {**c["native_ref"], "sha256": sha256(raw), "bytes": len(raw)}
        output = c["root"] / "new-owned-parent" / "another-parent" / "recovery"
        budget = Budget()
        @contextmanager
        def no_source(ref):
            raise AssertionError("Admission must finish before opening source assets")
            yield
        with pytest.raises(BudgetError, match="recording admission"):
            restore_legacy_seeded_capture(raw, ref, open_asset=no_source, owner_private_key_path=c["private"],
                output_root=output, budget=budget)
        assert not output.exists()
        assert budget.tracked == c["root"] / "new-owned-parent"
        return budget.reserved
    shallow = admitted_for("imports/generated.json")
    for depth in (1, 7, 19):
        deep = admitted_for("imports/" + "/".join(f"level-{i}" for i in range(depth)) + "/generated.json")
        assert deep - shallow >= depth * 16384


def _metadata_only_seed(index_raw, migration_raw, *, index_asset_id=200, migration_asset_id=201, cipher_asset_id=101):
    """A labeled metadata-validation projection; no payload/import is claimed."""
    index, migration = json.loads(index_raw), json.loads(migration_raw)
    row = index["manifests"][0]
    release = {"release_repository": migration["repository"], "release_tag": migration["release_tag"],
               "release_id": migration["release_id"]}
    members = [{"path": "evidence/" + row["path"], "sha256": row["sha256"], "bytes": row["bytes"]}]
    bundle = row.get("portable_full_bundle")
    if bundle:
        members.append({"path": f"evidence/objects/sha256/{bundle['sha256'][:2]}/{bundle['sha256']}",
                        "sha256": bundle["sha256"], "bytes": bundle["bytes"]})
    parts = []
    for ordinal, part in enumerate(index["archive"]["parts"], 1):
        alias = migration["parts"][part["name"]]
        parts.append({"ordinal": ordinal, "plaintext": alias["plaintext"],
                      "ciphertext": {**release, **alias["ciphertext"], "asset_id": cipher_asset_id + ordinal - 1}, "capsule": None})
    return seal_legacy_seed({"schema_version": 1, "kind": "legacy_baseline_package_v1",
        "repository_id": row["repository_id"], "slug": index["repository"],
        "source_index": {**release, "asset_id": index_asset_id, "name": index.get("repository_key", "SYNTHETIC-metadata-only") + ".index.json",
                         "sha256": sha256(index_raw), "bytes": len(index_raw)},
        "source_manifest": {key: row[key] for key in ("path", "sha256", "bytes", "run_id", "started_at", "finished_at")},
        "owner_recipient_spki_sha256": migration["recipient"],
        "transport": {"kind": "migrated_encrypted_baseline",
                      "migration_index": {**release, "asset_id": migration_asset_id, "name": "encryption-migration-index.json",
                                          "sha256": sha256(migration_raw), "bytes": len(migration_raw)}, "parts": parts},
        "members": members,
        "import_receipt": {"path": "imports/SYNTHETIC-metadata-only-validation.json", "sha256": sha256(b"{}"), "bytes": 2}})


@pytest.fixture
def release_wide_migration_metadata():
    """Sixteen synthetic repository aliases; the current index declares one."""
    aliases = {}
    for number in range(16):
        plain = {"name": f"SYNTHETIC-repo-{number:02d}.tar.xz.part-0001", "bytes": 1000 + number,
                 "sha256": sha256(f"synthetic-plaintext-{number}".encode())}
        cipher = {"name": plain["name"] + ".enc", "bytes": 2000 + number,
                  "sha256": sha256(f"synthetic-ciphertext-{number}".encode())}
        aliases[plain["name"]] = {"plaintext": plain, "ciphertext": cipher}
    manifest = {"repository_id": 123, "repository_input_slug": "example/selected", "run_id": "synthetic-legacy",
                "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z", "responses": []}
    row = {"path": "runs/123/synthetic-legacy.manifest.json", "sha256": sha256(canonical_json(manifest)),
           "bytes": len(canonical_json(manifest)), "repository_id": 123,
           **{key: manifest[key] for key in ("run_id", "started_at", "finished_at")}}
    selected = next(iter(aliases.values()))
    index = {"repository": "example/selected", "release_tag": "corpus-baseline-SYNTHETIC", "manifests": [row],
             "archive": {"complete": True, "parts": [selected["plaintext"]]}}
    migration = {"repository": "example/archive", "release_tag": index["release_tag"], "release_id": 10,
                 "recipient": sha256(b"SYNTHETIC owner public key"), "parts": aliases}
    index_raw, migration_raw = canonical_json(index), canonical_json(migration)
    return index, migration, index_raw, migration_raw, _metadata_only_seed(index_raw, migration_raw)


def test_seed_selects_current_repository_from_authenticated_sixteen_alias_migration(release_wide_migration_metadata):
    from icsot_observer.legacy_archive import normalize_legacy_parts
    index, migration, index_raw, migration_raw, seed = release_wide_migration_metadata
    assert len(migration["parts"]) == 16 and len(index["archive"]["parts"]) == 1
    # The shared per-package normalizer deliberately remains strict.
    with pytest.raises(ValueError, match="Unused transport overrides"):
        normalize_legacy_parts(index, migration["parts"])
    assert validate_legacy_seed(seed, source_index=index_raw, migration_index=migration_raw) is seed


@pytest.mark.parametrize("fault,reason", [
    ("missing", "exact frozen transport alias"),
    ("wrong_plaintext", "exact frozen transport alias"),
    ("wrong_ciphertext", "ordered part identities"),
    ("unrelated_alias", "exact frozen transport alias"),
    ("duplicate_source_part", "Duplicate archive part name"),
    ("unrelated_declared_part", "ordered part identities"),
    ("duplicate_declared_part", "ordered part identities"),
])
def test_selected_migration_aliases_remain_exact_and_strict(release_wide_migration_metadata, fault, reason):
    index, migration, index_raw, migration_raw, seed = release_wide_migration_metadata
    index, migration, seed = copy.deepcopy(index), copy.deepcopy(migration), copy.deepcopy(seed)
    name = index["archive"]["parts"][0]["name"]
    other = next(alias for alias_name, alias in migration["parts"].items() if alias_name != name)
    if fault == "missing":
        del migration["parts"][name]
    elif fault == "wrong_plaintext":
        migration["parts"][name]["plaintext"]["sha256"] = "f" * 64
    elif fault == "wrong_ciphertext":
        migration["parts"][name]["ciphertext"]["sha256"] = "f" * 64
    elif fault == "unrelated_alias":
        migration["parts"][name] = other
    elif fault == "duplicate_source_part":
        index["archive"]["parts"].append(copy.deepcopy(index["archive"]["parts"][0]))
    else:
        declared = copy.deepcopy(seed["transport"]["parts"][0])
        declared["ordinal"] = 2
        if fault == "unrelated_declared_part":
            declared["plaintext"] = other["plaintext"]
            declared["ciphertext"].update(other["ciphertext"])
        seed["transport"]["parts"].append(declared)
    index_raw, migration_raw = canonical_json(index), canonical_json(migration)
    seed["source_index"].update(sha256=sha256(index_raw), bytes=len(index_raw))
    seed["transport"]["migration_index"].update(sha256=sha256(migration_raw), bytes=len(migration_raw))
    seed = seal_legacy_seed(seed)
    with pytest.raises(ValueError, match=reason):
        validate_legacy_seed(seed, source_index=index_raw, migration_index=migration_raw)


def test_whole_migration_hash_and_duplicate_json_guard_are_not_relaxed(release_wide_migration_metadata):
    index, migration, index_raw, migration_raw, seed = copy.deepcopy(release_wide_migration_metadata)
    selected = index["archive"]["parts"][0]["name"]
    unrelated = next(name for name in migration["parts"] if name != selected)
    migration["parts"][unrelated]["ciphertext"]["sha256"] = "f" * 64
    with pytest.raises(LegacySeedError, match="Original metadata bytes differ"):
        validate_legacy_seed(seed, source_index=index_raw, migration_index=canonical_json(migration))
    entries = [json.dumps(name) + ":" + json.dumps(alias) for name, alias in migration["parts"].items()]
    entries.insert(1, entries[0])
    raw = ('{"repository":' + json.dumps(migration["repository"]) + ',"release_tag":' + json.dumps(migration["release_tag"]) +
           ',"parts":{' + ",".join(entries) + '}}').encode()
    seed["transport"]["migration_index"].update(sha256=sha256(raw), bytes=len(raw))
    seed = seal_legacy_seed(seed)
    with pytest.raises(LegacySeedError, match="Invalid original metadata JSON"):
        validate_legacy_seed(seed, source_index=index_raw, migration_index=raw)


def test_native_seed_validation_does_not_apply_release_wide_migration_aliases(release_wide_migration_metadata):
    index, migration, _, migration_raw, seed = release_wide_migration_metadata
    index, seed = copy.deepcopy(index), copy.deepcopy(seed)
    alias = migration["parts"][index["archive"]["parts"][0]["name"]]
    index["archive"]["parts"] = [{**alias["ciphertext"], "plaintext": alias["plaintext"]}]
    raw = canonical_json(index)
    seed["source_index"].update(sha256=sha256(raw), bytes=len(raw))
    seed["transport"].update(kind="native_encrypted_baseline", migration_index=None)
    seed = seal_legacy_seed(seed)
    assert validate_legacy_seed(seed, source_index=raw, migration_index=migration_raw) is seed


def test_exact_cached_gdcm_index_and_whole_release_migration_replay_without_payloads():
    from icsot_observer.legacy_archive import normalize_legacy_parts
    index_raw = zlib.decompress(base64.b64decode(GDCM_ORIGINAL_INDEX_ZLIB_BASE64))
    migration_raw = zlib.decompress(base64.b64decode(GDCM_RELEASE_MIGRATION_ZLIB_BASE64))
    assert sha256(index_raw) == GDCM_ORIGINAL_INDEX_SHA256
    assert sha256(migration_raw) == GDCM_RELEASE_MIGRATION_SHA256
    assert len(index_raw) == 3631 and len(migration_raw) == 19762
    index, migration = json.loads(index_raw), json.loads(migration_raw)
    assert index["repository"] == "malaterre/GDCM" and len(migration["parts"]) == 16
    with pytest.raises(ValueError, match="Unused transport overrides"):
        normalize_legacy_parts(index, migration["parts"])
    seed = _metadata_only_seed(index_raw, migration_raw, index_asset_id=676527405,
                               migration_asset_id=676599050, cipher_asset_id=676584527)
    assert validate_legacy_seed(seed, source_index=index_raw, migration_index=migration_raw) is seed


# Exact public JSON metadata from the original GDCM index and its complete
# 16-repository migration index. Lossless compressed literals keep this replay
# portable without network access, payloads, keys, or untracked analysis files.
# These metadata facts are real; the small seed/receipt used below is explicitly
# a metadata-only test projection, not a claimed restored study observation.
GDCM_ORIGINAL_INDEX_SHA256 = '36991eb75bdb6b6099c2a383094b41065abfea86c12d47a139e3a74511781449'
GDCM_ORIGINAL_INDEX_ZLIB_BASE64 = (
    'eNrNV8uO5LYV3ecrCK3rQUqUKPXsHBv2JrFhD4JggkDg46qLHr0iUt3THsy/51BVNV09mGTi2AsvutEieR88PPfe0+8zvdiTf6Ds'
    '7n1mp2HuKeLvuKy0y2i0k/PjfXaXTSOxqBcW4kJ6YOnkQiGQY48+ntjf3+xYmHsfmR9Z70PExrQ4WrJddu9jO/hlmZbWj7ZfHbns'
    'rtN9QIRBv/PDOrSzXmJrniKF7E5wVSgp6lzusrSOpX+8zy6bkvNcNCLfZaMekCg89DrSslDb3js77AutdF3aouhsfkDGh3e/HJKX'
    'PedcIJtw0nlZwbCiuqtrV6imqRTXtZNV1TW2qCuhdVcK5RphDW9caXBS5WWntSJrc13VtSgIvta5n/R2nYTXh3/uMmASpyXl9Tda'
    'fPfESNsTS/F3wGy0SHXEz6co7Vg80cgcXXEFoEyPjtG7uGgbE/QHBHz3S5u2KQKlD7vM6jmuuLm2luZ4zQPr02kCnnZax3SyLtNS'
    '35NFblh11AIF5KiaylZGqkp2FRLNlXFSyg7Q8cpYLYTU0lnOs1t7xF/7mOiiI54k6uinEc5mGhNXWuOjnfzYXsiUNndZp32PTNNT'
    'AiU/DGvUpicQwkeve9xqmjo4OZ6mgY7LOo60HB+n5e3R27Cf4v4S/zOf+JpMoOVBI7unox51/xR8ONppmdewNzpQ70c6/jeiHOnB'
    'O7Cdjlsi4XjJ61h1Qlptii5XriJV5kIIxYlyU/Nc56KsSXLbWFs0UknVOeMqC4ZSrhS5Th4m0DfRfPQdsPoj3BChw1HwWlSVOuY8'
    'rwR+XqOs6lJyUUih3ux5WRphuDlcEz/8HLZ3vH63z2X0GxGC0z/M4///0FzeeaF5uu1Jx2+//vNfLuvBpxRb71KH20JgfR23hewL'
    'wVLfQqGtqJ/nJp0awCcNGy2m8/dtmNbF0s0b1Q3vckBf112jFS8KbUpRKCepKbrS5FY54mWHDldQ4cra1QVaYdVYbouqTOFteHj2'
    'VxeSXIVuVVqlam3LThZOd6Yz2gnOS1xF5cbU1rmmqqVzOUcnERzea22cgj9K8+DSDjpUWziRa3W8QLEXfL+BcZc3dzI/qEbVsnpz'
    'Hian1bQJuNR+hjmZiJcbG6KS57Ipc4WGdsPbF7MEQNfqi+FFdSgrEFam8CcdWkS64j2gl8KmW/s++ziRfm1NzTqeYPab6nJGv98a'
    'akqlNevo+m2iX6dmzsuGSwEa2WmmGxaxfrK6Z88EZWdjNnVM92mjC/iFKZbcM41RdPJYWcdX7OE84kC6qFFkbjt8O2KlcnVjMLJ5'
    'bvAWrjF5WeAyOThmrEBWVMpcFlQ6qyQGaZH+Fk3ZCA2SykTxeTW9t+2V2VfXRIUtVEkgmuKuyR0vjSsJTGwKEI3yHJNLFIaqHFQs'
    'CsVlA35Lw6u8s07+TkX5O3ZBFPgS/wML67tSHlL8ir/5fC/YtEdP6Hft871wQpuTH/WDvtfLo+65+qSHZs9mUd9vHl80zv1NGe3F'
    'C9C+0Ofe0tMX1Nl2Hnrooh9+WPxDkkbf+vjdatiP57SYhsiMgZ30A7FxgiCa/bJxDnSAonDMPJ0pmQZG10+PryCjzroDfBxAzMCQ'
    'VPCg74H9dYL0cpS0CgJDfG2fqQNE2n/Mht2vetFjJEqiK9gT/LRge9gyvami78ck5TapwM5EvaZ/nUqwuGOgSY/MWCpO9uM3P73e'
    'xB/EUtgx7eA4+qSkDWLa0xEPcZxxcn8i7ZK/cxEmOfhciGl5Mj/jCcOB/UDLHhcYGHAA+D5VdPTD9oLhuGC+0SNCfe2DXUO6xNlb'
    '55cQ9+e8t0w3I+wtCerIkrjDXuqNB/b9658Q3pKfY7gAyy6Sj0Fm+p4Fgs7FC/ZPbJ3vlySMtzBbm/Dw8b+RXKhafJbkbQf1iaHT'
    'Iz/XXjBtr0yFxZZ91MPcfrRNWYfVDH67NvL+10pJdr9iV6+OfXUWrJc8L0iAUAmCmRZEHXDqRMvGhttTHztse70jhgpUM5fq5YRL'
    '/wKlR7w5VxT1df1SM/6FH/FiaOFrenudOunfiSSa08TI7vhN90/+zv37E1eLfmxvKAmznN8Cdpa9NzbYhfe0B6wvgT58+NO/Ac4z'
    'qnE='
)

GDCM_RELEASE_MIGRATION_SHA256 = 'eb0a7d48c072bdfe1b36f7092f341a1d07e92357e5fca2cd9f82d462b9d9c3a4'
GDCM_RELEASE_MIGRATION_ZLIB_BASE64 = (
    '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'
)
