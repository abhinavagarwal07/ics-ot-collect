import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


spec = importlib.util.spec_from_file_location(
    "migrate_encrypted_results", Path(__file__).parents[1] / "scripts/migrate_encrypted_results.py"
)
migrate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FakeGitHub:
    def __init__(self):
        self.repository = "owner/private"
        self.payloads = {}
        self.records = {}
        self.uploads = []
        self.deletes = []
        self.downloads = []
        self.fail_upload_number = None
        self.upload_attempts = 0
        self.artifact_payloads = {71: b"legacy successful artifact ZIP"}
        self.artifact_records = {
            71: {"id": 71, "name": "legacy-smoke", "size_in_bytes": len(self.artifact_payloads[71]),
                 "expired": False, "workflow_run": {"id": 9}}
        }
        self.parts = {}
        for number in (1, 2):
            name = f"one.tar.xz.part-{number:04d}"
            data = b"original archive part " + bytes([number]) * 65
            self.parts[name] = {"name": name, "sha256": sha(data), "bytes": len(data)}
            self.add(name, data)
        self.add("one.index.json", json.dumps({"archive": {"parts": list(self.parts.values())}}).encode())
        self.add("inventory.json", b'{"metadata":true}\n')

    def add(self, name, data):
        asset_id = max([0, *(record["id"] for record in self.records.values())]) + 1
        self.payloads[name] = data
        self.records[name] = {"id": asset_id, "name": name, "state": "uploaded", "size": len(data),
                              "digest": "sha256:" + sha(data)}

    def json(self, endpoint):
        if endpoint == "repos/owner/private":
            return {"private": True}
        if endpoint == "repos/owner/private/releases/42":
            return {"draft": True, "id": 42, "tag_name": "baseline"}
        raise AssertionError(endpoint)

    def assets(self, release_id):
        assert release_id == 42
        return {name: value.copy() for name, value in self.records.items()}

    def artifacts(self):
        return self.artifact_records.copy()

    def download_asset(self, asset, destination):
        self.downloads.append(asset["name"])
        destination.write_bytes(self.payloads[asset["name"]])

    def download(self, endpoint, destination):
        assert endpoint == "repos/owner/private/actions/artifacts/71/zip"
        destination.write_bytes(self.artifact_payloads[71])

    def upload(self, tag, path):
        assert tag == "baseline"
        assert path.name not in self.records, "Create only: no overwrite permitted"
        self.upload_attempts += 1
        if self.upload_attempts == self.fail_upload_number:
            raise RuntimeError("Synthetic interrupted upload")
        self.uploads.append(path.name)
        self.add(path.name, path.read_bytes())

    def delete_asset(self, asset_id):
        assert migrate.INDEX_NAME in self.records
        mapping = json.loads(self.payloads[migrate.INDEX_NAME])
        assert len(mapping["parts"]) == 2
        assert len(mapping["legacy_actions_artifacts"]) == 1
        for entry in [*mapping["parts"].values(), *mapping["legacy_actions_artifacts"]]:
            assert entry["ciphertext"]["name"] in self.records
        name = next(name for name, record in self.records.items() if record["id"] == asset_id)
        self.deletes.append(("asset", asset_id))
        del self.records[name]
        del self.payloads[name]

    def delete_artifact(self, artifact_id):
        assert migrate.INDEX_NAME in self.records
        self.deletes.append(("artifact", artifact_id))
        del self.artifact_records[artifact_id]
        del self.artifact_payloads[artifact_id]


@pytest.fixture
def setup(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = tmp_path / "private.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    public = tmp_path / "public.pem"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    work = tmp_path / "work"
    work.mkdir()
    args = argparse.Namespace(repository="owner/private", release_id=42, artifact_id=[71],
                              public_key=public, private_key=private, report=tmp_path / "report.json",
                              work_root=work, remove_plaintext=False, dry_run=False)
    return args, FakeGitHub()


def test_copy_readback_then_explicit_removal_and_idempotent_resume(setup):
    args, github = setup
    original_metadata = {name: data for name, data in github.payloads.items() if name.endswith(".json")}
    result = migrate.Migration(args, github).run()
    assert result["archive_parts"] == 2
    assert result["actions_artifacts"] == 1
    assert not result["plaintext_removed"]
    assert not github.deletes
    assert set(github.parts) <= set(github.records)
    assert 71 in github.artifact_records
    assert github.uploads[-1] == migrate.INDEX_NAME
    mapping = json.loads(github.payloads[migrate.INDEX_NAME])
    assert set(mapping["parts"]) == set(github.parts)
    assert mapping["legacy_actions_artifacts"][0]["run_id"] == 9
    assert mapping["legacy_actions_artifacts"][0]["original_name"] == "legacy-smoke"
    assert all(not name.endswith(".pem") for name in github.uploads)
    assert list(args.work_root.iterdir()) == []

    # All ciphertext is downloaded and decrypted afresh on resumed invocations.
    upload_count = len(github.uploads)
    args.remove_plaintext = True
    github.downloads.clear()
    migrate.Migration(args, github).run()
    assert len(github.uploads) == upload_count
    assert len(github.deletes) == 3
    assert not set(github.parts) & set(github.records)
    assert not github.artifact_records
    assert len([name for name in github.downloads if name.endswith(".enc")]) == 3
    assert all(github.payloads[name] == data for name, data in original_metadata.items())
    audit = json.loads(args.report.read_bytes())["mutation_audit"]
    gate = next(index for index, event in enumerate(audit)
                if event["event"] == "all_copies_and_global_mapping_verified_for_removal")
    assert all(index > gate for index, event in enumerate(audit) if event["event"].endswith("_deleted"))
    # Repeating after original deletion verifies existing copies without reupload.
    migrate.Migration(args, github).run()
    assert len(github.uploads) == upload_count
    assert len(github.deletes) == 3


def test_late_upload_failure_preserves_every_original_and_resumes(setup):
    args, github = setup
    args.remove_plaintext = True
    github.fail_upload_number = 3  # Both archive parts copied; legacy artifact upload fails.
    with pytest.raises(RuntimeError, match="interrupted upload"):
        migrate.Migration(args, github).run()
    assert not github.deletes
    assert set(github.parts) <= set(github.records)
    assert 71 in github.artifact_records
    assert migrate.INDEX_NAME not in github.records
    copied_names = set(github.uploads)
    github.fail_upload_number = None
    migrate.Migration(args, github).run()
    assert copied_names <= set(github.records)
    assert len([name for name in github.uploads if name.endswith(".enc")]) == 3
    assert len(github.deletes) == 3


def test_original_index_hash_mismatch_never_uploads_or_deletes(setup):
    args, github = setup
    args.remove_plaintext = True
    name = next(iter(github.parts))
    github.payloads[name] = b"changed original"
    with pytest.raises(ValueError, match="Original archive hash"):
        migrate.Migration(args, github).run()
    assert not github.uploads
    assert not github.deletes


def test_tampered_remote_ciphertext_prevents_all_removal(setup):
    args, github = setup
    migrate.Migration(args, github).run()
    name = next(name for name in github.records if name.endswith(".enc"))
    github.payloads[name] = github.payloads[name][:-1] + b"x"
    github.records[name]["digest"] = "sha256:" + sha(github.payloads[name])
    args.remove_plaintext = True
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        migrate.Migration(args, github).run()
    assert not github.deletes


def test_missing_github_digest_uses_downloaded_hash(setup):
    args, github = setup
    original_add = github.add

    def no_digest(name, data):
        original_add(name, data)
        github.records[name].pop("digest")

    github.add = no_digest
    migrate.Migration(args, github).run()
    assert len([name for name in github.downloads if name.endswith(".enc")]) >= 3
    assert not github.deletes


@pytest.mark.parametrize("extra", ["unindexed.tar.xz.part-0001", "unknown.zip"])
def test_uninventoried_payload_stops_before_upload(setup, extra):
    args, github = setup
    github.add(extra, b"untracked payload")
    with pytest.raises(ValueError, match="Uninventoried release payloads"):
        migrate.Migration(args, github).run()
    assert not github.uploads
    assert not github.deletes


def test_all_actions_artifacts_must_be_explicitly_declared(setup):
    args, github = setup
    args.artifact_id = []
    with pytest.raises(ValueError, match="Declare all nonexpired Actions artifacts"):
        migrate.Migration(args, github).run()
    assert not github.uploads
    assert not github.deletes


def test_conflicting_existing_index_is_never_overwritten(setup):
    args, github = setup
    github.add(migrate.INDEX_NAME, b'{"schema_version":99}')
    with pytest.raises(ValueError, match="does not match source"):
        migrate.Migration(args, github).run()
    assert github.payloads[migrate.INDEX_NAME] == b'{"schema_version":99}'
    assert not github.uploads
    assert not github.deletes


def test_dry_run_reads_inventory_without_remote_mutations(setup):
    args, github = setup
    args.dry_run = True
    assert migrate.Migration(args, github).run()["dry_run"]
    assert not github.uploads
    assert not github.deletes


def test_private_repository_gate_runs_before_any_upload(setup):
    args, github = setup
    original = github.json
    github.json = lambda endpoint: {"private": False} if endpoint == "repos/owner/private" else original(endpoint)
    with pytest.raises(ValueError, match="requires a private repository"):
        migrate.Migration(args, github).run()
    assert not github.uploads
    assert not github.deletes
