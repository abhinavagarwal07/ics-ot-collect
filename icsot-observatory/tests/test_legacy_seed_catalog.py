"""Synthetic, tiny offline legacy-to-native recovery; never study observations."""
import copy
import io
import json
import shutil
import tarfile
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
    report = restore_legacy_seeded_capture(c["native_path"].read_bytes(), published_ref,
        open_asset=c["open_asset"], owner_private_key_path=c["private"], output_root=output)
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
