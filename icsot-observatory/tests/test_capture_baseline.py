import argparse
import hashlib
import importlib.util
import io
import json
import lzma
import signal
import subprocess
import tarfile
from pathlib import Path

import pytest

from icsot_observer.core import Config, ObjectStore, canonical_json
from icsot_observer.gitstore import run_git
from icsot_observer.encryption import decrypt_file
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_path, private_path = tmp_path / "results-public.pem", tmp_path / "results-private.pem"
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return argparse.Namespace(
        config=config, csv=csv, slug="example/one", code_sha="a" * 40,
        release_tag="corpus-baseline-123-1", release_repository="owner/private",
        work_root=tmp_path / "work",
        public_key=public_path, test_private_key=private_path,
    )


def accepted_index(identities, args):
    manifest = {"sha256": "b" * 64, "run_id": "baseline", "repository_id": 17,
                "status": "complete", "mode": "full", "has_git": True,
                "portable_full_bundle": {"sha256": "f" * 64, "bytes": 5}}
    return {
        **identities, "repository": args.slug, "release_tag": args.release_tag,
        "collector_code_sha": args.code_sha, "status": "complete_for_declared_shallow_baseline",
        "complete": True, "capture_accepted": True, "manifests": [manifest], "errors": [],
        "collector_result": {"repo": args.slug, "status": "complete", "attestation": "pending_bitcoin_completion",
                             "proof": "pending.ots", "immutable_initial_proof": "initial.ots",
                             "manifest_sha256": manifest["sha256"], "run_id": manifest["run_id"], "repository_id": 17},
        "verification": {"ok": True, "errors": [], "manifests": 1, "portable_git_bundles_verified": 1,
                         "git_repositories_verified": 1, "raw_observations": 1, "partial_runs": 0, "unstamped_runs": 0},
        "archive": {"complete": True, "parts": [{"name": "part-1", "bytes": 5, "sha256": "e" * 64, "uploaded": True}]},
    }


def unpack_archive(assets, archive, destination, private_key=None):
    combined = bytearray()
    for part in archive["parts"]:
        data = (assets / part["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == part["sha256"]
        assert len(data) == part["bytes"]
        if part.get("encryption"):
            assert private_key is not None
            output = assets / (part["name"] + ".decrypted")
            result = decrypt_file(assets / part["name"], output, private_key)
            assert result["plaintext_sha256"] == part["plaintext"]["sha256"]
            data = output.read_bytes()
            output.unlink()
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
    names = unpack_archive(uploads[0].parent, index["archive"], tmp_path / "restored", args.test_private_key)
    assert "evidence/git/17.git/objects/partial.pack" in names


def test_encryption_failure_never_uploads_plaintext(tmp_path, monkeypatch):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "collect_one", lambda *a, **kw: {"repo": args.slug, "status": "partial"})
    monkeypatch.setattr(baseline, "encrypt_file", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("synthetic encryption failure")))
    uploads = []
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: uploads.append(path))
    assert baseline.capture(args) == 2
    assert len(uploads) == 1 and uploads[0].name.endswith(".index.json")
    index = json.loads(uploads[0].read_bytes())
    assert not index["complete"] and index["archive"]["parts"] == []
    assert any("Encryption:" in message for message in index["errors"])


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
    assert index["archive"]["encrypted"] and all(part["name"].endswith(".enc") for part in index["archive"]["parts"])
    names = unpack_archive(uploads[0].parent, index["archive"], restored, args.test_private_key)
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
    index = accepted_index(identities, args)
    index_raw = canonical_json(index)
    index_asset = {"id": 12, "name": baseline.repository_key("example/one") + ".index.json",
                   "size": len(index_raw), "digest": "sha256:" + hashlib.sha256(index_raw).hexdigest(), "state": "uploaded"}
    part_asset = {"id": 13, "name": part["name"], "size": 5, "digest": "sha256:" + part["sha256"], "state": "uploaded"}
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
                                                                "digest": "sha256:" + identity["sha256"], "state": "uploaded"}])
    baseline.upload_asset("corpus-baseline-123-1", asset, "owner/private")
    assert sum(call[:2] == ("release", "upload") for call in calls) == 1
    monkeypatch.setattr(baseline, "release_assets", lambda *args: [{"name": asset.name, "size": identity["bytes"], "digest": None,
                                                                "state": "uploaded"}])
    monkeypatch.setattr(baseline, "downloaded_asset_identity", lambda *args: {"sha256": "0" * 64, "bytes": identity["bytes"]})
    with pytest.raises(RuntimeError, match="refusing overwrite"):
        baseline.upload_asset("corpus-baseline-123-1", asset, "owner/private")


@pytest.mark.parametrize("invalidate", [
    lambda index: index.update(capture_accepted=False),
    lambda index: index.update(status="incomplete"),
    lambda index: index["collector_result"].update(status="partial"),
    lambda index: index["collector_result"].update(attestation="error: no receipt"),
    lambda index: index["collector_result"].update(manifest_sha256="0" * 64),
    lambda index: index["collector_result"].update(run_id="different-run"),
    lambda index: index["collector_result"].update(proof=""),
    lambda index: index["manifests"][0].update(status="partial"),
    lambda index: index["manifests"][0].update(mode="delta"),
    lambda index: index["manifests"][0].update(has_git=False),
    lambda index: index["manifests"][0].update(portable_full_bundle=None),
    lambda index: index["verification"].update(portable_git_bundles_verified=0),
    lambda index: index["verification"].update(git_repositories_verified=0),
    lambda index: index["verification"].update(raw_observations=0),
    lambda index: index["verification"].update(partial_runs=1),
    lambda index: index["verification"].update(unstamped_runs=1),
    lambda index: index["verification"].update(errors=["corruption"]),
    lambda index: index.update(errors=["timestamp failed"]),
])
def test_finalizer_rejects_inconsistent_completion_flags(tmp_path, monkeypatch, invalidate):
    config, csv, config_obj, identities = sources(tmp_path, slugs=("example/one",))
    args = args_for(tmp_path, config, csv)
    index = accepted_index(identities, args)
    invalidate(index)
    raw = canonical_json(index)
    part = index["archive"]["parts"][0]
    assets = [
        {"id": 12, "name": baseline.repository_key(args.slug) + ".index.json", "size": len(raw),
         "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "state": "uploaded"},
        {"id": 13, "name": part["name"], "size": part["bytes"], "digest": "sha256:" + part["sha256"], "state": "uploaded"},
    ]
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "release_assets", lambda *a: assets)
    monkeypatch.setattr(baseline, "gh", lambda *a, **kw: raw if a[1].endswith("/assets/12") else b'{"id":10,"draft":true}')
    inventories = []
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: inventories.append(json.loads(path.read_bytes())))
    assert baseline.finalize(args) == 2
    assert inventories[0]["complete_repositories"] == 0
    assert inventories[0]["repositories"][0]["errors"]


@pytest.mark.parametrize("lost_response", [False, True])
def test_finalizer_recovers_publication_and_reuses_inventory(tmp_path, monkeypatch, lost_response):
    config, csv, config_obj, identities = sources(tmp_path, slugs=("example/one",))
    args = args_for(tmp_path, config, csv)
    args.finalizer_code_sha = "9" * 40
    index_raw = canonical_json(accepted_index(identities, args))
    data = {12: index_raw}
    assets = [
        {"id": 12, "name": baseline.repository_key(args.slug) + ".index.json", "size": len(index_raw),
         "digest": "sha256:" + hashlib.sha256(index_raw).hexdigest(), "state": "uploaded"},
        {"id": 13, "name": "part-1", "size": 5, "digest": "sha256:" + "e" * 64, "state": "uploaded"},
    ]
    release = {"id": 10, "draft": True, "target_commitish": args.code_sha}
    publications, uploads = [], []

    def fake_gh(*arguments, **kwargs):
        if arguments[:2] == ("release", "edit"):
            publications.append(arguments)
            if len(publications) == 1:
                if lost_response:
                    release["draft"] = False
                raise RuntimeError("synthetic publication failure")
            release["draft"] = False
            return b""
        if "/releases/assets/" in arguments[1]:
            return data[int(arguments[1].rsplit("/", 1)[1])]
        return json.dumps(release).encode()

    def upload(tag, path, repository):
        assert not any(asset["name"] == path.name for asset in assets)
        raw = path.read_bytes()
        data[14] = raw
        assets.append({"id": 14, "name": path.name, "size": len(raw), "state": "uploaded",
                       "digest": "sha256:" + hashlib.sha256(raw).hexdigest()})
        uploads.append(raw)

    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "release_assets", lambda *a: assets)
    monkeypatch.setattr(baseline, "gh", fake_gh)
    monkeypatch.setattr(baseline, "upload_asset", upload)
    with pytest.raises(RuntimeError, match="synthetic publication failure"):
        baseline.finalize(args)
    assert json.loads(uploads[0])["finalizer_code_sha"] == args.finalizer_code_sha
    assert baseline.finalize(args) == 0
    assert len(uploads) == 1
    assert (args.work_root / "baseline-inventory.json").read_bytes() == uploads[0]
    assert len(publications) == (1 if lost_response else 2)
    assert baseline.finalize(args) == 0  # Already published: reconcile without a write.
    recorded = json.loads(data[14])
    recorded["complete_repositories"] = 0
    data[14] = canonical_json(recorded)
    assets[-1].update(size=len(data[14]), digest="sha256:" + hashlib.sha256(data[14]).hexdigest())
    with pytest.raises(ValueError, match="differs from verified current capture outcomes"):
        baseline.finalize(args)


def test_missing_release_digest_requires_downloaded_hash(tmp_path, monkeypatch):
    payload = b"remote archive part"
    asset = {"id": 13, "name": "part", "size": len(payload), "state": "uploaded", "digest": None}
    identity = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
    calls = []

    def download(arguments, **kwargs):
        calls.append(arguments)
        kwargs["stdout"].write(payload)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(baseline.subprocess, "run", download)
    baseline.verify_remote_asset("owner/private", asset, identity)
    assert calls[0][2].endswith("/releases/assets/13")
    with pytest.raises(ValueError, match="Downloaded release asset identity mismatch"):
        baseline.verify_remote_asset("owner/private", asset, {**identity, "sha256": "0" * 64})
    asset["state"] = "starter"
    with pytest.raises(ValueError, match="not uploaded"):
        baseline.verify_remote_asset("owner/private", asset, identity)


def test_finalizer_checks_exact_release_target(tmp_path, monkeypatch):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "gh", lambda *a, **kw: json.dumps({"id": 10, "draft": True, "target_commitish": "b" * 40}).encode())
    with pytest.raises(ValueError, match="Release target commit differs"):
        baseline.finalize(args)


def test_new_finalizer_checkout_can_reconcile_old_capture_sha(monkeypatch, tmp_path):
    expected, actual = "a" * 40, "b" * 40
    monkeypatch.setattr(baseline.subprocess, "check_output", lambda *a, **kw: actual + "\n")
    observed = []
    monkeypatch.setattr(baseline, "finalize", lambda args: observed.append(args) or 0)
    arguments = ["--config", "unused", "--csv", "unused", "--release-tag", "corpus-baseline-123-1",
                 "--release-repository", "owner/private", "--code-sha", expected, "--work-root", str(tmp_path)]
    assert baseline.main(["finalize", *arguments]) == 0
    assert observed[0].code_sha == expected and observed[0].finalizer_code_sha == actual
    with pytest.raises(ValueError, match="checkout does not match"):
        baseline.main(["capture", *arguments, "--slug", "example/one"])


def test_phase_deadline_escapes_exception_handlers_and_restores_alarm():
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    assert previous_timer == (0.0, 0.0)
    with pytest.raises(baseline.PhaseDeadlineExceeded, match="test phase exceeded"):
        with baseline.phase_deadline(10, "test phase"):
            try:
                signal.raise_signal(signal.SIGALRM)
            except Exception:
                pytest.fail("An ordinary endpoint handler swallowed the phase deadline")
    assert signal.getsignal(signal.SIGALRM) == previous_handler
    assert signal.getitimer(signal.ITIMER_REAL) == previous_timer


def test_phase_deadline_restores_elapsed_previous_timer(monkeypatch):
    timers, handlers = [], []
    monkeypatch.setattr(baseline.signal, "getsignal", lambda sig: "prior-handler")
    monkeypatch.setattr(baseline.signal, "signal", lambda sig, handler: handlers.append(handler))

    def timer(*arguments):
        timers.append(arguments)
        return (15.0, 3.0) if len(timers) == 1 else (0.0, 0.0)

    monkeypatch.setattr(baseline.signal, "setitimer", timer)
    clock = iter([100.0, 102.0])
    monkeypatch.setattr(baseline.time, "monotonic", lambda: next(clock))
    with baseline.phase_deadline(5, "test"):
        pass
    assert handlers[-1] == "prior-handler"
    assert timers[-1] == (signal.ITIMER_REAL, 13.0, 3.0)


@pytest.mark.parametrize("phase", ["collection", "verification"])
def test_deadline_transfers_partial_outcome_and_index(tmp_path, monkeypatch, phase):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "environment_report", lambda *a: {"diagnostics": "fixture"})

    def timeout(*a, **kw):
        raise baseline.PhaseDeadlineExceeded("synthetic phase deadline")

    if phase == "collection":
        monkeypatch.setattr(baseline, "collect_one", timeout)
    else:
        monkeypatch.setattr(baseline, "collect_one", make_portable_capture)
        monkeypatch.setattr(baseline, "verify_all", timeout)
    uploads = []
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: uploads.append(path))
    assert baseline.capture(args) == 2
    index = json.loads(uploads[-1].read_bytes())
    assert not index["complete"] and not index["capture_accepted"]
    assert any("PhaseDeadlineExceeded" in error for error in index["errors"])
    assert uploads[-1].name.endswith(".index.json")
    assert index["archive"]["complete"] and all(part["uploaded"] for part in index["archive"]["parts"])


def parent_fixture(tmp_path, monkeypatch):
    config, csv, config_obj, identities = sources(tmp_path)
    args = args_for(tmp_path, config, csv)
    args.parent_release_tag = "corpus-baseline-99-1"
    parent_args = argparse.Namespace(**vars(args))
    parent_args.release_tag = args.parent_release_tag
    index = accepted_index(identities, parent_args)
    data = {12: canonical_json(index)}
    assets = [
        {"id": 12, "name": baseline.repository_key(args.slug) + ".index.json", "size": len(data[12]),
         "digest": "sha256:" + hashlib.sha256(data[12]).hexdigest(), "state": "uploaded"},
        {"id": 13, "name": "part-1", "size": 5, "digest": "sha256:" + "e" * 64, "state": "uploaded"},
    ]

    def github(*arguments, **kwargs):
        if "/releases/assets/" in arguments[1]:
            return data[int(arguments[1].rsplit("/", 1)[1])]
        assert arguments[:2] == ("api", f"repos/{args.release_repository}/releases/tags/{args.parent_release_tag}")
        return json.dumps({"id": 10, "draft": True, "target_commitish": parent_args.code_sha}).encode()

    monkeypatch.setattr(baseline, "load_sources", lambda *a, **kw: (config_obj, identities))
    monkeypatch.setattr(baseline, "release_assets", lambda *a: assets)
    monkeypatch.setattr(baseline, "gh", github)
    return args, config_obj, identities, index, data, assets


def test_resume_plan_keeps_full_cohort_but_skips_only_verified_parent(tmp_path, monkeypatch):
    args, _, _, _, _, _ = parent_fixture(tmp_path, monkeypatch)
    args.github_output = tmp_path / "outputs"
    assert baseline.plan(args) == 0
    outputs = dict(line.split("=", 1) for line in args.github_output.read_text().splitlines())
    assert outputs["cohort_count"] == "2" and outputs["inherited_complete_count"] == "1"
    assert outputs["remaining_count"] == "1"
    assert [row["slug"] for row in json.loads(outputs["matrix"])["include"]] == ["example/two"]


@pytest.mark.parametrize("invalid", ["source_hash", "index_hash", "missing_part_hash", "partial"])
def test_resume_does_not_skip_invalid_parent_or_download_archive(tmp_path, monkeypatch, invalid):
    args, config, identities, index, data, assets = parent_fixture(tmp_path, monkeypatch)
    if invalid == "source_hash":
        index["csv_sha256"] = "0" * 64
    elif invalid == "index_hash":
        assets[0]["digest"] = "sha256:" + "0" * 64
    elif invalid == "missing_part_hash":
        assets[1]["digest"] = None
    else:
        index["collector_result"]["status"] = "partial"
    if invalid in ("source_hash", "partial"):
        data[12] = canonical_json(index)
        assets[0].update(size=len(data[12]), digest="sha256:" + hashlib.sha256(data[12]).hexdigest())
    monkeypatch.setattr(baseline, "downloaded_asset_identity", lambda *a: pytest.fail("Resume downloaded archive bytes"))
    outcome = baseline.parent_capture_outcomes(config, identities, args.release_repository, args.parent_release_tag)
    assert not outcome[args.slug]["complete"] and outcome[args.slug]["errors"]


@pytest.mark.parametrize("invalid", [None, "plaintext", "ciphertext"])
def test_resume_accepts_verified_encrypted_parent_transport(tmp_path, monkeypatch, invalid):
    args, config, identities, index, data, assets = parent_fixture(tmp_path, monkeypatch)
    assets.pop()  # Original plaintext has been removed after verified migration.
    alias = {"plaintext": {key: index["archive"]["parts"][0][key] for key in ("name", "sha256", "bytes")},
             "ciphertext": {"name": "part-1.age", "bytes": 101, "sha256": "c" * 64},
             "recipient": "age1test"}
    if invalid == "plaintext":
        alias["plaintext"]["sha256"] = "0" * 64
    data[15] = canonical_json({"schema_version": 1, "parts": {"part-1": alias}})
    assets.extend([
        {"id": 14, "name": "part-1.age", "size": 101, "digest": "sha256:" + ("0" if invalid == "ciphertext" else "c") * 64,
         "state": "uploaded"},
        {"id": 15, "name": "encryption-migration-index.json", "size": len(data[15]),
         "digest": "sha256:" + hashlib.sha256(data[15]).hexdigest(), "state": "uploaded"},
    ])
    row = baseline.parent_capture_outcomes(config, identities, args.release_repository, args.parent_release_tag)[args.slug]
    assert row["complete"] == (invalid is None)
    if invalid is None:
        assert row["archive_transport_aliases"] == [alias]
        assert row["transport_index_sha256"] == hashlib.sha256(data[15]).hexdigest()


def test_finalizer_combines_parent_and_current_capture_with_original_shas(tmp_path, monkeypatch):
    args, _, identities, parent_index, data, parent_assets = parent_fixture(tmp_path, monkeypatch)
    args.code_sha = "b" * 40
    args.slug = "example/two"
    index = accepted_index(identities, args)
    data[22] = canonical_json(index)
    current_assets = [
        {"id": 22, "name": baseline.repository_key(args.slug) + ".index.json", "size": len(data[22]),
         "digest": "sha256:" + hashlib.sha256(data[22]).hexdigest(), "state": "uploaded"},
        {"id": 23, "name": "part-1", "size": 5, "digest": "sha256:" + "e" * 64, "state": "uploaded"},
    ]

    def github(*arguments, **kwargs):
        if arguments[:2] == ("release", "edit"):
            return b""
        if "/releases/assets/" in arguments[1]:
            return data[int(arguments[1].rsplit("/", 1)[1])]
        parent = arguments[1].endswith(args.parent_release_tag)
        return json.dumps({"id": 10 if parent else 20, "draft": True,
                           "target_commitish": parent_index["collector_code_sha"] if parent else args.code_sha}).encode()

    monkeypatch.setattr(baseline, "gh", github)
    monkeypatch.setattr(baseline, "release_assets", lambda repo, release_id: parent_assets if release_id == 10 else current_assets)
    inventories = []
    monkeypatch.setattr(baseline, "upload_asset", lambda tag, path, repo: inventories.append(json.loads(path.read_bytes())))
    assert baseline.finalize(args) == 0
    summary = inventories[0]
    assert summary["complete_repositories"] == 2 and summary["parent_release_tag"] == args.parent_release_tag
    assert summary["collector_code_sha"] == "b" * 40
    inherited = summary["repositories"][0]
    assert inherited["collector_code_sha"] == "a" * 40 and inherited["source_release_tag"] == args.parent_release_tag
    assert inherited["index_sha256"] == hashlib.sha256(data[12]).hexdigest()
