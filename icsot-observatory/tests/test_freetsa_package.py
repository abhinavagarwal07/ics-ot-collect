import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer import pipeline
from icsot_observer.core import Config


PIN = "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
ENDPOINT = "https://freetsa.org/tsr"


def config(root):
    return Config(root, ("test/repo",), "2026-03-10", "research", "NO_TEST_TOKEN", 5,
                  1000000, 48, 100)


def zip_resource(tmp_path, monkeypatch, contents=None):
    if contents is None:
        contents = pipeline.resources.files("icsot_observer").joinpath(
            "certificates", "freetsa-root.pem").read_bytes()
    archive = tmp_path / "resources.zip"
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("icsot_observer/certificates/freetsa-root.pem", contents)
    resource = zipfile.Path(archive, "icsot_observer/")
    monkeypatch.setattr(pipeline.resources, "files", lambda package: resource)
    return resource


def test_builtin_resource_has_unchanged_public_trust_identity():
    with pipeline._freetsa_policy() as policy:
        assert Path(policy["ca_file"]).is_file()
        assert hashlib.sha256(Path(policy["ca_file"]).read_bytes()).hexdigest() == PIN
        assert pipeline._public_timestamp_policy(policy) == {
            "endpoint": ENDPOINT, "ca_sha256": PIN, "untrusted_sha256": None}
        assert policy["untrusted_file"] is None


def test_zip_backed_policy_keeps_extraction_until_context_exit(tmp_path, monkeypatch):
    resource = zip_resource(tmp_path, monkeypatch)
    try:
        with pipeline._freetsa_policy() as policy:
            extracted = Path(policy["ca_file"])
            assert extracted.is_file()
            subprocess.run(["openssl", "x509", "-in", str(extracted), "-noout"], check=True,
                           capture_output=True)
        assert not extracted.exists()
    finally:
        resource.root.close()


def test_modified_packaged_root_is_rejected(tmp_path, monkeypatch):
    resource = zip_resource(tmp_path, monkeypatch, b"changed trust root")
    try:
        with pytest.raises(ValueError, match="provider-published pinned PEM"):
            with pipeline._freetsa_policy():
                pytest.fail("Modified trust root was accepted")
    finally:
        resource.root.close()


def test_persistent_loop_retains_zip_resource_lifetime(tmp_path, monkeypatch):
    resource = zip_resource(tmp_path, monkeypatch)
    paths = []

    def loop(*args, **options):
        path = Path(options["freetsa_policy"]["ca_file"])
        assert path.is_file()
        paths.append(path)
        return {"test": "no network"}

    monkeypatch.setattr(pipeline, "_persistent_loop", loop)
    try:
        assert pipeline.run_persistent(config(tmp_path / "state"), once=True, freetsa=True) == {
            "test": "no network"}
        assert len(paths) == 1 and not paths[0].exists()
    finally:
        resource.root.close()


def capture(policy):
    return {"capture_id": "resumed-free", "slug": "test/repo", "repository_id": 17,
            "lane": "api", "requested_mode": "delta", "mode": "delta",
            "started_at": "2026-10-20T00:00:00.000000Z", "finished_at": "2026-10-20T00:00:01.000000Z",
            "responses": [], "failures": [], "git": None, "api": None,
            "freetsa_policy": policy}


def frozen_builtin(tmp_path):
    return {"endpoint": ENDPOINT, "ca_file": str(tmp_path / "old-process-root.pem"),
            "ca_sha256": PIN, "untrusted_file": None, "untrusted_sha256": None}


def test_resumed_capture_rebinds_missing_root_for_full_publish_operation(tmp_path, monkeypatch):
    policy = frozen_builtin(tmp_path)
    original_policy = dict(policy)
    resource = zip_resource(tmp_path, monkeypatch)
    paths, exported = [], []

    def publish(directory, **options):
        path = options["ca_file"]
        paths.append(path)
        assert path.is_file() and str(path) != policy["ca_file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == PIN
        subprocess.run(["openssl", "x509", "-in", str(path), "-noout"], check=True,
                       capture_output=True)
        return {"metadata": {"status": "verified_chain_and_imprint"}}

    monkeypatch.setattr("icsot_observer.attestations.publish_rfc3161_attestation", publish)
    try:
        result = pipeline.finalize_lane(config(tmp_path / "state"), None, capture(policy), stamp=False,
                                        exporter=SimpleNamespace(export=exported.append))
        assert exported[0]["freetsa_evidence"]["metadata"]["status"] == "verified_chain_and_imprint"
        assert result.manifest_digest == exported[0]["manifest_sha256"]
        assert len(paths) == 1 and not paths[0].exists()
        assert policy == original_policy
    finally:
        resource.root.close()


@pytest.mark.parametrize("changed", [
    {"ca_sha256": "0" * 64},
    {"endpoint": "https://other.example.invalid/tsr"},
    {"untrusted_file": "old-explicit-chain.pem", "untrusted_sha256": "1" * 64},
])
def test_frozen_identity_mismatch_does_not_substitute_builtin(tmp_path, monkeypatch, changed):
    policy = {**frozen_builtin(tmp_path), **changed}
    exported = []
    monkeypatch.setattr(pipeline.resources, "files", lambda package: pytest.fail("Unexpected trust substitution"))
    monkeypatch.setattr("icsot_observer.attestations.publish_rfc3161_attestation",
                        lambda *args, **kwargs: pytest.fail("Missing frozen CA reached publisher"))
    pipeline.finalize_lane(config(tmp_path / "state"), None, capture(policy), stamp=False,
                           exporter=SimpleNamespace(export=exported.append))
    evidence = exported[0]["freetsa_evidence"]
    assert evidence["status"] == "failed" and evidence["retry"] == "not_scheduled"
    assert evidence["provider"]["endpoint"] == policy["endpoint"]
    assert json.loads(Path(exported[0]["freetsa_source"], evidence["failure_asset"]["name"]).read_bytes())["status"] == "failed"


def test_explicit_custom_policy_retains_frozen_file(tmp_path, monkeypatch):
    ca = tmp_path / "custom.pem"
    ca.write_bytes(b"explicit test trust root")
    policy = pipeline._rfc3161_policy("https://custom.example.invalid/tsr", ca, None)
    monkeypatch.setattr(pipeline.resources, "files", lambda package: pytest.fail("Unexpected trust substitution"))
    with pipeline._freetsa_trust_file(policy) as path:
        assert path == ca and pipeline._file_sha256(path) == policy["ca_sha256"]
