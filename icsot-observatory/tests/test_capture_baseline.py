import argparse
import hashlib
import importlib.util
import io
import json
import lzma
import subprocess
import tarfile
from pathlib import Path

import pytest

from icsot_observer.core import Config, ObjectStore, canonical_json
from icsot_observer.gitstore import run_git


spec = importlib.util.spec_from_file_location("capture_baseline", Path(__file__).parents[1] / "scripts/capture_baseline.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


def sources(tmp_path, slugs=("example/one", "example/two")):
    config = tmp_path / "config.toml"
    config.write_text(
        '[collector]\nroot = "./evidence"\napi_version = "2026-03-10"\n'
        'user_agent = "test"\ntoken_env = "NO_SUCH_TEST_TOKEN"\n'
        '[cohort]\nrepositories = ' + json.dumps(list(slugs)) + '\n'
    )
    csv = tmp_path / "cohort.csv"
    csv.write_text("Repository_URL\n" + "".join(f"https://github.com/{slug}\n" for slug in slugs))
    config_obj, identities = baseline.load_sources(config, csv, expected_count=len(slugs))
    return config, csv, config_obj, identities


def args_for(tmp_path, config, csv):
    return argparse.Namespace(
        config=config, csv=csv, slug="example/one", code_sha="a" * 40,
        release_tag="corpus-baseline-123-1", release_repository="owner/private",
        work_root=tmp_path / "work",
    )


def unpack_archive(assets, archive, destination):
    combined = bytearray()
    for part in archive["parts"]:
        data = (assets / part["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == part["sha256"]
        assert len(data) == part["bytes"]
        combined.extend(data)
    with tarfile.open(fileobj=io.BytesIO(lzma.decompress(bytes(combined))), mode="r:") as restored:
        names = restored.getnames()
        restored.extractall(destination, filter="data")
    return names


@pytest.mark.parametrize("include_mirror", [False, True])
def test_streamed_split_archive_roundtrip_and_mirror_selection(tmp_path, include_mirror):
    work, assets = tmp_path / "work", tmp_path / "assets"
    (work / "evidence/git/17.git/objects").mkdir(parents=True)
    (work / "evidence/objects/sha256").mkdir(parents=True)
    (work / "reports").mkdir()
    payload = bytes(range(256)) * 8
    (work / "evidence/objects/sha256/original").write_bytes(payload)
    (work / "evidence/git/17.git/objects/pack").write_bytes(b"disposable mirror")
    (work / "reports/result.json").write_bytes(b'{"status":"partial"}\n')
    archive = baseline.package_archive(work, assets, "repo", include_mirror=include_mirror, part_bytes=101)
    assert len(archive["parts"]) > 1
    assert all(0 < part["bytes"] <= 101 for part in archive["parts"])
    assert sorted(path.name for path in assets.iterdir()) == [part["name"] for part in archive["parts"]]
    destination = tmp_path / "restored"
    names = unpack_archive(assets, archive, destination)
    assert (destination / "evidence/objects/sha256/original").read_bytes() == payload
    assert (destination / "reports/result.json").read_bytes() == b'{"status":"partial"}\n'
    assert any(name.startswith("evidence/git") for name in names) == include_mirror


def test_source_identity_requires_entire_csv_order(tmp_path):
    config, csv, _, identities = sources(tmp_path)
    assert identities["cohort_count"] == 2
    assert identities["config_source_sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert identities["csv_sha256"] == hashlib.sha256(csv.read_bytes()).hexdigest()
    csv.write_text("Repository_URL\nhttps://github.com/example/two\nhttps://github.com/example/one\n")
    with pytest.raises(ValueError, match="every CSV repository in order"):
        baseline.load_sources(config, csv, expected_count=2)
    assert baseline.repository_key("a__b/c") != baseline.repository_key("a/b__c")


def test_failed_capture_and_verifier_still_transfer_bytes_and_index_last(tmp_path, monkeypatch):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))

    def broken_collect(config, slug, mode, **kwargs):
        assert config.primary_rate_wait_seconds == 3605
        assert config.primary_rate_reserve == 40
        assert config.repositories == (slug,)
        assert mode == "full" and kwargs == {"deep_full": False, "bundle_full": True, "stamp": True}
        path = config.root / "git/17.git/objects/partial.pack"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"bytes fetched before failure")
        ObjectStore(config.root).put(b"original API bytes fetched before failure")
        raise RuntimeError("synthetic capture interruption")

    monkeypatch.setattr(baseline, "collect_one", broken_collect)
    monkeypatch.setattr(baseline, "verify_all", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("synthetic verifier failure")))
    uploads = []
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: uploads.append(path))
    assert baseline.capture(args) == 2
    assert uploads[-1].name.endswith(".index.json")
    index = json.loads(uploads[-1].read_bytes())
    assert not index["complete"] and not index["capture_accepted"]
    assert index["collector_result"]["status"] == "unexpected_error"
    assert "synthetic capture interruption" in index["collector_result"]["error"]
    assert "synthetic verifier failure" in index["verification"]["errors"][0]
    assert index["archive"]["git_mirror_included"]
    names = unpack_archive(uploads[0].parent, index["archive"], tmp_path / "restored")
    assert "evidence/git/17.git/objects/partial.pack" in names


def make_portable_capture(config, slug, mode, **kwargs):
    """No network: a real Git graph/bundle and canonical collector manifest."""
    source = config.root.parent / "synthetic-origin"
    run_git(["init", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.name", "Test"])
    run_git(["-C", str(source), "config", "user.email", "test@example.invalid"])
    (source / "original.txt").write_text("A preserved object graph\n")
    run_git(["-C", str(source), "add", "original.txt"])
    run_git(["-C", str(source), "commit", "-m", "baseline"])
    oid = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    mirror = config.root / "git/17.git"
    mirror.parent.mkdir(parents=True)
    run_git(["clone", "--bare", str(source), str(mirror)])
    archive_ref = "refs/archive/synthetic/heads/main"
    run_git(["-C", str(mirror), "update-ref", archive_ref, oid])
    bundle = config.root.parent / "synthetic.bundle"
    run_git(["-C", str(mirror), "bundle", "create", str(bundle), "--all"])
    store = ObjectStore(config.root)
    digest, length = store.put_file(bundle)
    body = b'{"id":17,"private":false}\n'
    response = {"body_sha256": store.put(body), "body_bytes": len(body), "purpose": "repository_identity"}
    manifest = {
        "run_id": "synthetic", "repository_id": 17, "repository_input_slug": slug,
        "previous_manifest_sha256": None, "mode": "full", "status": "complete",
        "responses": [response], "public_config_sha256": "f" * 64,
        "git": {
            "mirror_path_relative": "git/17.git", "git_object_hash_algorithm": "sha1",
            "advertised_refs": [{"published_ref": "refs/heads/main", "object_id": oid, "local_immutable_ref": archive_ref}],
            "portable_full_bundle": {"sha256": digest, "bytes": length},
        },
    }
    path = config.root / "runs/17/synthetic.manifest.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(canonical_json(manifest))
    proof = Path(str(path) + ".ots")
    proof.write_bytes(b"synthetic pending receipt; no Bitcoin verification in this test")
    initial = config.root / "proofs/initial/initial.ots"
    initial.parent.mkdir(parents=True)
    initial.write_bytes(proof.read_bytes())
    return {"repo": slug, "status": "complete", "attestation": "pending_bitcoin_completion",
            "manifest": str(path), "proof": str(proof), "immutable_initial_proof": str(initial)}


def test_complete_capture_omits_verified_mirror_and_restores_offline(tmp_path, monkeypatch):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "collect_one", make_portable_capture)
    uploads = []
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: uploads.append(path))
    assert baseline.capture(args) == 0
    index = json.loads(uploads[-1].read_bytes())
    assert index["complete"] and index["verification"]["portable_git_bundles_verified"] == 1
    assert not index["archive"]["git_mirror_included"]
    assert index["csv_sha256"] == identities["csv_sha256"]
    restored = tmp_path / "restored"
    names = unpack_archive(uploads[0].parent, index["archive"], restored)
    assert not any(name.startswith("evidence/git") for name in names)
    manifest = restored / "evidence" / index["manifests"][0]["path"]
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == index["manifests"][0]["sha256"]
    verification = baseline.restore_mirrors(restored / "evidence")
    assert verification["ok"], verification["errors"]
    assert verification["git_repositories_verified"] == 1
    assert verification["portable_git_bundles_verified"] == 1
    assert (restored / "reports/config.corpus.toml").read_bytes() == config.read_bytes()
    assert (restored / "reports/public_patch_corpus_185.csv").read_bytes() == csv.read_bytes()


def test_finalizer_paginates_and_publishes_explicit_missing_index(tmp_path, monkeypatch):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    part = {"name": "part-1", "bytes": 5, "sha256": "e" * 64, "uploaded": True}
    index = {
        **identities, "repository": "example/one", "release_tag": args.release_tag,
        "collector_code_sha": args.code_sha, "status": "complete_for_declared_shallow_baseline",
        "complete": True, "capture_accepted": True, "manifests": [], "errors": [],
        "archive": {"complete": True, "parts": [part]},
    }
    index_raw = canonical_json(index)
    index_asset = {"id": 12, "name": baseline.repository_key("example/one") + ".index.json",
                   "size": len(index_raw), "digest": "sha256:" + hashlib.sha256(index_raw).hexdigest()}
    part_asset = {"id": 13, "name": part["name"], "size": 5, "digest": "sha256:" + part["sha256"]}
    calls = []

    def fake_gh(*arguments, **kwargs):
        calls.append(arguments)
        if arguments[:2] == ("api", f"repos/{args.release_repository}/releases/tags/{args.release_tag}"):
            # Deliberately truncated embedded array: the finalizer must not use it.
            return json.dumps({"id": 10, "draft": True, "assets": []}).encode()
        if arguments[:2] == ("api", f"repos/{args.release_repository}/releases/10/assets?per_page=100"):
            assert arguments[2:] == ("--paginate", "--slurp")
            return json.dumps([[index_asset], [part_asset]]).encode()
        if arguments[:2] == ("api", f"repos/{args.release_repository}/releases/assets/12"):
            return index_raw
        assert arguments[:2] == ("release", "edit")
        return b""

    uploads = []
    monkeypatch.setattr(baseline, "gh", fake_gh)
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: uploads.append(path))
    assert baseline.finalize(args) == 2
    inventory = json.loads(uploads[-1].read_bytes())
    assert inventory["complete_repositories"] == 1
    assert inventory["incomplete_repositories"] == 1
    assert inventory["repositories"][1]["errors"]
    assert calls[-1][:2] == ("release", "edit")
    assert "--draft=false" in calls[-1]


def test_ambiguous_upload_accepts_only_identical_existing_asset(tmp_path, monkeypatch):
    asset = tmp_path / "retained.part"
    asset.write_bytes(b"retained evidence")
    identity = baseline.file_identity(asset)
    calls = []

    def fake_gh(*arguments, **kwargs):
        calls.append(arguments)
        if arguments[:2] == ("release", "upload"):
            raise subprocess.TimeoutExpired(arguments, 5)
        return b'{"id":17}'

    monkeypatch.setattr(baseline, "gh", fake_gh)
    monkeypatch.setattr(baseline, "wait_for_github_reset", lambda: False)
    monkeypatch.setattr(baseline, "release_assets", lambda *args: [{"name": asset.name, "size": identity["bytes"],
                                                                "digest": "sha256:" + identity["sha256"]}])
    baseline.upload_asset("corpus-baseline-123-1", asset, "owner/private")
    assert sum(call[:2] == ("release", "upload") for call in calls) == 1
    monkeypatch.setattr(baseline, "release_assets", lambda *args: [{"name": asset.name, "size": identity["bytes"], "digest": None}])
    with pytest.raises(RuntimeError, match="refusing overwrite"):
        baseline.upload_asset("corpus-baseline-123-1", asset, "owner/private")
