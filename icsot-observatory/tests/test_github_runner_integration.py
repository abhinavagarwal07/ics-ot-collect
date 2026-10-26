import hashlib
import copy
import io
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import pipeline
from icsot_observer.core import Config, ObjectStore, canonical_json, sha256


class MemoryGitHub:
    def __init__(self):
        self.head, self.counter = None, 0
        self.commits, self.assets, self.events = {}, {}, []
        from icsot_observer.proof_maintenance import empty_state
        self.proof_head, self.proof_state, self.proof_records = None, empty_state(), {}
        self.proof_saves, self.fail_registration = 0, False

    def branch_head(self):
        return self.head

    def read_pointer(self, head, repository_id):
        return self.commits[head].get(repository_id)

    def read_slug_binding(self, head, slug):
        return self.commits[head].get("slug:" + slug.lower())

    def commit_pointer(self, parent, repository_id, data):
        self.counter += 1
        commit = hashlib.sha1(str(self.counter).encode()).hexdigest()
        tree = dict(self.commits[parent]) if parent else {}
        tree[repository_id] = data
        pointer = json.loads(data)
        from icsot_observer.github_state import _slug_binding
        tree["slug:" + pointer["slug"].lower()] = canonical_json(_slug_binding(pointer["slug"], repository_id))
        self.commits[commit] = tree
        return commit

    def advance_branch(self, expected, commit):
        if self.head != expected:
            return False
        self.head = commit
        self.events.append(("pointer", commit))
        return True

    def ensure_release(self, tag):
        pass

    def upload_asset(self, tag, name, source):
        assert (tag, name) not in self.assets
        self.assets[tag, name] = source.read_bytes()
        self.events.append(("upload", tag, name))

    def download_asset(self, tag, name, destination):
        destination.write_bytes(self.assets[tag, name])
        self.events.append(("download", tag, name))

    def load(self):
        return self.proof_head, copy.deepcopy(self.proof_state)

    def record(self, head, path):
        assert head == self.proof_head
        return self.proof_records.get(path)

    def fetch(self, ref):
        data = self.assets[ref["release_tag"], ref["name"]]
        assert sha256(data) == ref["sha256"] and len(data) == ref["bytes"]
        self.events.append(("proof_fetch", ref["release_tag"], ref["name"]))
        return data

    def save(self, parent, state, records=None):
        from icsot_observer.github_state import StateConflictError, StateDeferredError
        if self.fail_registration:
            raise StateDeferredError("proof registration quota refusal", retry_not_before=2000000000, reason="rate_limit")
        if parent != self.proof_head:
            raise StateConflictError("concurrent proof queue update")
        self.proof_saves += 1
        self.proof_head = f"proof-{self.proof_saves}"
        self.proof_state = copy.deepcopy(state)
        self.proof_records.update(records or {})
        self.events.append(("proof_registration", self.proof_head))
        return self.proof_head


def keys(tmp_path, prefix):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public, private = tmp_path / f"{prefix}-public.pem", tmp_path / f"{prefix}-private.pem"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return public, private


@pytest.mark.parametrize("stamp,rfc", [(False, False), (True, False), (False, True), (True, True)])
def test_two_hosted_cycles_restore_queue_and_deduplicate_prior_evidence_without_cipher_redownload(tmp_path, monkeypatch, stamp, rfc):
    if stamp:
        pytest.importorskip("opentimestamps.core.timestamp")
    config = Config(tmp_path / "unused", ("test/repo",), "2026-03-10", "research", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    state_public, state_private = keys(tmp_path, "state")
    evidence_public, _ = keys(tmp_path, "evidence")
    transport, root = MemoryGitHub(), tmp_path / "working"
    code_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if stamp:
        original_run = subprocess.run
        monkeypatch.setattr(pipeline.shutil, "which", lambda name: "/test/ots")

        def synthetic_calendar(args, **kwargs):
            if args[0] != "/test/ots":
                return original_run(args, **kwargs)
            from opentimestamps.core.notary import PendingAttestation
            from opentimestamps.core.op import OpSHA256
            from opentimestamps.core.serialize import StreamSerializationContext
            from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
            timestamp = Timestamp(bytes.fromhex(sha256(Path(args[-1]).read_bytes())))
            timestamp.attestations.add(PendingAttestation("https://calendar.example.invalid"))
            output = io.BytesIO()
            DetachedTimestampFile(OpSHA256(), timestamp).serialize(StreamSerializationContext(output))
            Path(args[-1] + ".ots").write_bytes(output.getvalue())
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(pipeline.subprocess, "run", synthetic_calendar)
    body = b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(2000))
    calls = []
    intervals = {
        "api": ("2026-10-20T00:00:00.123456Z", "2026-10-20T00:00:01.234567Z"),
        "git": ("2026-10-20T00:01:00.345678Z", "2026-10-20T00:01:02.456789Z"),
    }
    rfc_options = {}
    if rfc:
        ca, chain = tmp_path / "tsa-root.pem", tmp_path / "tsa-chain.pem"
        ca.write_bytes(b"shared explicit TSA root fixture")
        chain.write_bytes(b"shared explicit TSA intermediate fixture")
        rfc_options = {"rfc3161_url": "http://tsa.example.invalid", "rfc3161_ca": ca, "rfc3161_chain": chain}

        def rfc_receipt(output_dir, **options):
            output_dir.mkdir(parents=True, exist_ok=True)
            digest = options["manifest_sha256"]

            def asset(name, contents):
                path = output_dir / name
                path.write_bytes(contents)
                return {"name": name, "sha256": sha256(contents), "bytes": len(contents)}

            request = asset(f"rfc3161-{digest}.tsq", b"retained request " + digest.encode())
            proof = asset(f"rfc3161-{digest}.tsr", b"signed response fixture " + digest.encode())
            details = asset(f"rfc3161-{digest}.txt", b"signed TSTInfo text fixture " + digest.encode())
            roots = [asset(f"rfc3161-trust-root-{sha256(ca.read_bytes())}.pem", ca.read_bytes()),
                     asset(f"rfc3161-untrusted-{sha256(chain.read_bytes())}.pem", chain.read_bytes())]
            metadata = {"method": "rfc3161", "status": "verified_chain_and_imprint", "subject_sha256": digest}
            sidecar = asset(f"rfc3161-{digest}.attestation.json", canonical_json(metadata))
            return {"metadata": metadata, "request_asset": request, "proof_asset": proof, "details_asset": details,
                    "trust_assets": roots, "metadata_asset": sidecar}

        monkeypatch.setattr("icsot_observer.attestations.publish_rfc3161_attestation", rfc_receipt)

    def capture(config, job, queue):
        calls.append(job.capture_id)
        pipeline._bind_identity(config, job.slug, {"id": 17, "private": False}, "2026-10-20T00:00:00Z")
        return {"capture_id": job.capture_id, "slug": job.slug, "repository_id": 17,
                "lane": job.lane, "requested_mode": "delta", "mode": "delta",
                "started_at": intervals[job.lane][0], "finished_at": intervals[job.lane][1],
                "responses": [{"purpose": "identity", "api_version": config.api_version,
                               "body_sha256": ObjectStore(config.root).put(body), "body_bytes": len(body)}],
                "failures": [], "public_config": pipeline._public_config(config),
                "rfc3161_policy": job.payload.get("rfc3161_policy")}

    monkeypatch.setattr(pipeline, "capture_lane", capture)
    options = dict(slug="test/repo", repository_id=17, destination_repository="owner/collector",
                   state_public_key=state_public, state_private_key=state_private,
                   evidence_public_key=evidence_public, code_sha=code_sha, config_source_sha256="0" * 64,
                   stamp=stamp, transport=transport, logical_root=root)
    options.update(rfc_options)
    first = pipeline.run_github_persistent(config, observation_key="first", **options)
    assert first["collection"]["runtime"]["completed"] == 2
    assert first["monthly_cap_enforced"] is False
    assert first["publication"]["state_uploaded_ciphertext_bytes"] > 0
    assert first["proof_maintenance_registration"]["status"] == "registered"
    first_pointer = json.loads(transport.read_pointer(transport.head, 17))
    assert first_pointer["snapshot_sealed_at"] == first["publication"]["snapshot_sealed_at"]
    assert first_pointer["clock_source"] == "runner_system_clock"
    prior_evidence = {key for key in transport.assets if key[0].startswith("collector-observations-r17-")}
    assert prior_evidence
    # A fresh runner has no working root or prior ciphertext export files.
    shutil.rmtree(root)
    transport.events.clear()
    second = pipeline.run_github_persistent(config, observation_key="second", **options)
    assert second["restore"]["restored"] is True
    assert second["collection"]["runtime"]["completed"] == 2
    assert len(calls) == 4 and len(set(calls)) == 4
    assert second["proof_maintenance_registration"]["status"] == "registered"
    assert second["new_evidence_upload_bytes"] < first["new_evidence_upload_bytes"]
    assert not any(event[0] == "download" and (event[1], event[2]) in prior_evidence for event in transport.events)
    catalog = json.loads((root / "transfer-catalog.json").read_bytes())
    assert len(catalog["exports"]) == 4
    for entry in catalog["exports"]:
        index = entry["index"]
        assert (index["observation_started_at"], index["observation_finished_at"]) == intervals[index["lane"]]
        assert index["clock_source"] == "runner_system_clock"
        if stamp:
            ots = index["timestamp_evidence"]["opentimestamps"]
            assert ots["metadata"]["verification"]["bitcoin_verified"] is False
            assert ots["metadata"]["status"] == "pending_bitcoin_completion"
            for sidecar in index["public_sidecars"]:
                ref = next(ref for ref in entry["assets"] if ref["name"] == sidecar["name"])
                contents = transport.assets[ref["release_tag"], ref["name"]]
                assert sha256(contents) == sidecar["sha256"]
        if rfc:
            assert index["timestamp_evidence"]["rfc3161"]["metadata"]["status"] == "verified_chain_and_imprint"
    from icsot_observer.github_state import GitHubStateStore
    selected = GitHubStateStore(transport, repository_id=17, slug="test/repo", public_key=state_public,
                                private_key=state_private, logical_root=root).read()
    for lane, times in intervals.items():
        head = selected.index["context"]["lane_heads"][lane]
        assert (head["observation_started_at"], head["observation_finished_at"]) == times
        assert head["clock_source"] == "runner_system_clock"
        assert head["observation_finished_at"] != selected.pointer["snapshot_sealed_at"]
    assert all(member["sha256"] != sha256(body) for entry in catalog["exports"][2:]
               for member in entry["index"]["members"])
    pointer_position = next(n for n, event in enumerate(transport.events) if event[0] == "pointer")
    assert all(n < pointer_position for n, event in enumerate(transport.events) if event[0] == "upload")
    registration_position = next(n for n, event in enumerate(transport.events) if event[0] == "proof_registration")
    marker_verification_position = next(n for n, event in enumerate(transport.events)
                                        if event[0] == "download" and event[2] == "metadata-catalog.json")
    assert marker_verification_position < registration_position < pointer_position
    releases = {tag for tag, name in transport.assets if tag.startswith("collector-observations-r17-")}
    for release in releases:
        marker = json.loads(transport.assets[release, "metadata-catalog.json"])
        assert len(marker["indexes"]) == len(marker["observations"]) == 2
        assert {entry["lane"] for entry in marker["observations"]} == {"api", "git"}
        for ref in marker["indexes"]:
            assert sha256(transport.assets[release, ref["name"]]) == ref["sha256"]
        if rfc:
            for prefix in ("rfc3161-trust-root-", "rfc3161-untrusted-"):
                assert len([name for tag, name in transport.assets if tag == release and name.startswith(prefix)]) == 1
    current_evidence_uploads = [event for event in transport.events if event[0] == "upload"
                                and event[1].startswith("collector-observations-r17-")]
    assert current_evidence_uploads[-1][2] == "metadata-catalog.json"
    assert len(catalog["publication_markers"]) == 2
    for ref in catalog["publication_markers"]:
        assert any(item["name"] == ref["name"] and item["release_tag"] == ref["release_tag"]
                   for item in selected.index["dependencies"])
    from icsot_observer.proof_maintenance import register_catalog
    saves = transport.proof_saves
    for ref in catalog["publication_markers"]:
        assert register_catalog(transport, pipeline._public_asset_ref(ref))["status"] == "already_registered"
    assert transport.proof_saves == saves
    assert not any("private" in name for tag, name in transport.assets)
    if stamp and not rfc:
        from icsot_observer.github_state import StateDeferredError
        old_head, old_pointer = transport.head, transport.read_pointer(transport.head, 17)
        old_state_assets = {key for key in transport.assets if key[0].startswith("collector-state-")}
        old_markers = {(ref["release_tag"], ref["name"]) for ref in catalog["publication_markers"]}
        old_proof_records = dict(transport.proof_records)
        shutil.rmtree(root)
        transport.fail_registration = True
        with pytest.raises(StateDeferredError, match="registration quota"):
            pipeline.run_github_persistent(config, observation_key="registration-refusal", **options)
        assert transport.head == old_head and transport.read_pointer(old_head, 17) == old_pointer
        assert transport.proof_records == old_proof_records
        assert {key for key in transport.assets if key[0].startswith("collector-state-")} == old_state_assets
        new_markers = [key for key in transport.assets if key[0].startswith("collector-observations-")
                       and key[1] == "metadata-catalog.json" and key not in old_markers]
        assert len(new_markers) == 1
        marker_tag, marker_name = new_markers[0]
        marker_bytes = transport.assets[new_markers[0]]
        marker_ref = {"release_tag": marker_tag, "name": marker_name,
                      "sha256": sha256(marker_bytes), "bytes": len(marker_bytes)}
        captures_after_refusal = len(calls)
        with pytest.raises(StateDeferredError):
            register_catalog(transport, marker_ref)
        assert transport.head == old_head
        transport.fail_registration = False
        assert register_catalog(transport, marker_ref)["status"] == "registered"
        assert register_catalog(transport, marker_ref)["status"] == "already_registered"
        assert len(calls) == captures_after_refusal
        assert transport.head == old_head and transport.read_pointer(old_head, 17) == old_pointer


def test_github_cli_deferral_reports_retry_utc_without_implying_capture_success(tmp_path, monkeypatch, capsys):
    from icsot_observer import cli
    from icsot_observer.github_state import StateDeferredError
    source = tmp_path / "config.toml"
    source.write_text('[collector]\nroot="./data"\napi_version="2026-03-10"\nuser_agent="test"\ntoken_env="NO_TEST_TOKEN"\n[cohort]\nrepositories=["test/repo"]\n')

    def defer(*args, **kwargs):
        raise StateDeferredError("destination allowance exhausted", retry_not_before=1000, reason="rate_limit", request_count=7)

    monkeypatch.setattr(cli, "run_github_persistent", defer)
    code = cli.main(["github-run", "--config", str(source), "--slug", "test/repo", "--repository-id", "17",
                     "--destination-repository", "owner/collector", "--state-public-key", "state-public.pem",
                     "--state-private-key", "state-private.pem", "--evidence-public-key", "evidence-public.pem",
                     "--code-sha", "a" * 40])
    report = json.loads(capsys.readouterr().out)
    assert code == 75 and report["status"] == "deferred"
    assert report["retry_not_before"] == "1970-01-01T00:16:40.000000Z"
    assert report["destination_github_api_requests"] == 7
    assert report["capture_completeness"] == "not_implied_by_destination_api_deferral"
