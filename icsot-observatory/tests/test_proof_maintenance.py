"""Controlled real OTS operation trees; no calendars, GitHub, or RPC network."""
import base64
import copy
import hashlib
import io
import json
import subprocess
import urllib.request
from pathlib import Path

import pytest

from icsot_observer.attestations import publish_ots_attestation
from icsot_observer.core import canonical_json, sha256
from icsot_observer.github_state import GhCliStateTransport, StateConflictError, StateDeferredError
from icsot_observer.proof_maintenance import (
    BitcoinCoreVerifier, OtsClient, ProofTransport, empty_state, refresh, register_catalog, requeue_catalog,
    validate_catalog,
)

SUBJECT = hashlib.sha256(b"controlled public collector manifest\n").hexdigest()
TAG = "collector-observations-r123-g" + "a" * 32
START, FINISH = "2026-10-25T01:02:03.000000Z", "2026-10-25T01:02:04.000000Z"


def receipt(*, subject=SUBJECT, bitcoin=False):
    pytest.importorskip("opentimestamps")
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    stamp = Timestamp(bytes.fromhex(subject))
    leaf = stamp.ops.add(OpAppend(b"controlled nonce")).ops.add(OpSHA256())
    leaf.attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))
    if bitcoin:
        leaf.attestations.add(BitcoinBlockHeaderAttestation(870000))
    sink = io.BytesIO()
    DetachedTimestampFile(OpSHA256(), stamp).serialize(StreamSerializationContext(sink))
    return sink.getvalue()


class FakeGitHub:
    def __init__(self):
        self.state, self.files, self.head = empty_state(), {}, None
        self.assets, self.pages, self.markers = {}, {}, {}
        self.saves, self.published, self.conflicts = 0, [], 0
        self.conflict_after_upload = False
        self.defer_publish = False

    def load(self):
        return self.head, copy.deepcopy(self.state)

    def record(self, head, path):
        assert head == self.head
        return self.files.get(path)

    def save(self, parent, state, records=None):
        if self.conflicts:
            self.conflicts -= 1
            raise StateConflictError("controlled competing writer")
        if self.conflict_after_upload and self.published:
            self.conflict_after_upload = False
            raise StateConflictError("controlled post-upload conflict")
        if parent != self.head:
            raise StateConflictError("stale fake head")
        self.saves += 1
        self.head = str(self.saves)
        self.state = copy.deepcopy(state)
        for path, data in (records or {}).items():
            if path.startswith("catalogs/") and path in self.files:
                assert self.files[path] == data
            self.files[path] = data
        return self.head

    def releases(self, page, per_page):
        return self.pages.get(page, [])

    def marker(self, tag):
        return self.markers.get(tag)

    def fetch(self, ref):
        data = self.assets[(ref["release_tag"], ref["name"])]
        if sha256(data) != ref["sha256"] or len(data) != ref["bytes"]:
            raise ValueError("controlled tampered asset")
        return data

    def publish(self, ref, data):
        if self.defer_publish:
            raise StateDeferredError("controlled retry-after", retry_not_before=999999,
                                     reason="rate_limit")
        identity = ref["release_tag"], ref["name"]
        if identity in self.assets:
            assert self.assets[identity] == data
        else:
            self.assets[identity] = data
            self.published.append(identity)


class ControlledClient:
    def __init__(self, data=None, fail=False):
        self.data, self.fail, self.calls = receipt(bitcoin=True) if data is None else data, fail, 0

    def upgrade(self, raw, subject):
        self.calls += 1
        if self.fail:
            raise RuntimeError("controlled calendar failure")
        return self.data


class OutboxGitHub(FakeGitHub):
    def __init__(self):
        super().__init__()
        self.source_heads, self.nodes = {}, {}

    def append_outbox(self, catalog, *, repository_id=123, slug="one/repository"):
        previous = self.source_heads.get(repository_id, (slug, None))[1]
        raw = canonical_json({"schema_version": 1, "kind": "icsot_public_proof_outbox",
            "repository_id": repository_id, "slug": slug, "generation": f"{len(self.nodes) + 1:032x}",
            "created_at": FINISH, "catalog": catalog, "previous": previous})
        ref = {"sha256": sha256(raw), "bytes": len(raw)}
        self.nodes[repository_id, ref["sha256"]] = raw
        self.source_heads[repository_id] = slug, ref
        return ref

    def outbox_repositories(self):
        self.frozen_heads = copy.deepcopy(self.source_heads)
        return "frozen-public-state-head", sorted(self.frozen_heads)

    def outbox_head(self, head, repository_id):
        return self.frozen_heads[repository_id]

    def outbox_node(self, head, repository_id, ref):
        return self.nodes[repository_id, ref["sha256"]]


def observation(tmp_path, github, *, tag=TAG, subject=SUBJECT):
    directory = tmp_path / tag
    directory.mkdir()
    source = directory / "initial.ots"
    source.write_bytes(receipt(subject=subject))
    evidence = publish_ots_attestation(directory / "public", manifest_sha256=subject, proof_path=source,
        observation_started_at=START, observation_finished_at=FINISH, received_at=FINISH)
    for ref in (evidence["proof_asset"], evidence["metadata_asset"]):
        github.assets[tag, ref["name"]] = (directory / "public" / ref["name"]).read_bytes()
    index = {"manifest_sha256": subject, "timestamp_evidence": {"opentimestamps": evidence}}
    data = canonical_json(index)
    index_ref = {"release_tag": tag, "name": "capture.index.json", "sha256": sha256(data), "bytes": len(data)}
    github.assets[tag, index_ref["name"]] = data
    marker = canonical_json({"schema_version": 1, "kind": "icsot_evidence_metadata_catalog",
        "generation_release": tag, "observations": [{"manifest_sha256": subject, "index": index_ref}]})
    github.markers[tag] = marker
    github.assets[tag, "metadata-catalog.json"] = marker
    return {"release_tag": tag, "name": "metadata-catalog.json", "sha256": sha256(marker), "bytes": len(marker)}, evidence


def test_registration_is_durable_idempotent_and_cas_retries(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    github.conflicts = 1
    assert register_catalog(github, ref)["status"] == "registered"
    snapshot = copy.deepcopy(github.state)
    assert len(snapshot["pending"]) == 1
    assert len(github.files) == 2
    saves = github.saves
    assert register_catalog(github, ref)["status"] == "already_registered"
    assert github.state == snapshot and github.saves == saves


def test_cycle_registration_retains_pins_for_fresh_proof_readers(tmp_path):
    from test_cycle_release import FakeGitMetadataStore, FakeTransport, upload
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    git = FakeGitMetadataStore()
    writer = FakeTransport(git)
    for (tag, name), raw in github.assets.items():
        descriptor = upload(writer, tmp_path, tag, name, raw)
        if name == "metadata-catalog.json":
            ref["storage"] = descriptor["storage"]
    assert register_catalog(github, ref)["status"] == "registered"
    pending = next(iter(github.state["pending"].values()))
    fresh = ProofTransport("owner/archive")
    fresh._cycle_catalog.store = git
    for kind in ("proof", "metadata"):
        assert pending[kind]["storage"] == ref["storage"]
        assert fresh.fetch(pending[kind]) == github.assets[TAG, pending[kind]["name"]]
    history = json.loads(github.files[f'proofs/{pending["metadata"]["sha256"]}.json'])["history"]
    assert history[0]["proof"]["storage"] == ref["storage"]


def test_catalog_validation_has_no_queue_access_or_capacity_dependency(tmp_path):
    github = FakeGitHub()
    ref, evidence = observation(tmp_path, github)
    github.state["pending"] = {f"{n:064x}": {} for n in range(4096)}
    def forbidden_load():
        raise AssertionError("Validation must not read the attempt queue")
    github.load = forbidden_load
    assert validate_catalog(github, ref)["status"] == "registration_pending"
    assert github.saves == 0 and github.files == {}
    github.assets[TAG, evidence["proof_asset"]["name"]] = b"tampered initial receipt"
    with pytest.raises(ValueError, match="tampered asset"):
        validate_catalog(github, ref)
    assert github.saves == 0 and github.files == {}


@pytest.mark.parametrize("failed", [False, True])
def test_additional_rfc_catalog_binding_does_not_depend_on_ots(failed):
    from icsot_observer.proof_maintenance import _marker_entries
    github = FakeGitHub()

    def asset(name, raw):
        github.assets[TAG, name] = raw
        return {"name": name, "sha256": sha256(raw), "bytes": len(raw)}

    request = asset("free.tsq", b"request")
    if failed:
        metadata = {"schema_version": 1, "method": "rfc3161", "status": "failed",
                    "subject_sha256": SUBJECT, "retry": "not_scheduled", "attempt_assets": [request]}
        metadata_asset = asset("free.failure.json", canonical_json(metadata))
        entry = {**metadata, "failure_asset": metadata_asset, "provider_profile": {"name": "FreeTSA"}}
        assets = [request, metadata_asset]
    else:
        proof = asset("free.tsr", b"signed fixture")
        root = asset("root.pem", b"root fixture")
        metadata = {"status": "verified_chain_and_imprint", "subject_sha256": SUBJECT,
                    "request_asset": request, "receipt": proof, "trust_assets": [root]}
        metadata_asset = asset("free.attestation.json", canonical_json(metadata))
        entry = {"metadata": metadata, "request_asset": request, "proof_asset": proof,
                 "trust_assets": [root], "metadata_asset": metadata_asset}
        assets = [request, proof, root, metadata_asset]
    additional = {"schema_version": 1, "providers": {"freetsa": entry}}
    index = {"manifest_sha256": SUBJECT, "timestamp_evidence": {"additional_rfc3161": additional},
             "public_sidecars": assets}
    raw = canonical_json(index)
    index_ref = {"release_tag": TAG, **asset("free.index.json", raw)}
    row = {"manifest_sha256": SUBJECT, "index": index_ref,
           "timestamp_evidence": {"additional_rfc3161": additional},
           "public_sidecars": [{"release_tag": TAG, **item} for item in assets]}
    marker = {"schema_version": 1, "kind": "icsot_evidence_metadata_catalog", "generation_release": TAG,
              "observations": [row]}
    assert _marker_entries(marker, TAG, github) == []
    row["public_sidecars"].pop()
    with pytest.raises(ValueError, match="absent from public index or catalog"):
        _marker_entries(marker, TAG, github)


def test_full_attempt_queue_keeps_outbox_and_still_drains_then_registers(tmp_path):
    github = OutboxGitHub()
    old_ref, old_evidence = observation(tmp_path, github)
    register_catalog(github, old_ref)
    original = github.assets[TAG, old_evidence["proof_asset"]["name"]]
    for number in range(4095):
        github.state["pending"][f"{number:064x}"] = {"next_attempt_after": 10**12}
    subject = sha256(b"new manifest while proof queue full")
    tag = "collector-observations-r123-g" + "b" * 32
    new_ref, _ = observation(tmp_path, github, tag=tag, subject=subject)
    outbox_head = github.append_outbox(new_ref)
    first = refresh(github, client=ControlledClient(), max_proofs=1, clock=lambda: 10000)
    assert first["outbox_registration_paused_at_capacity"] is True
    assert first["proofs_changed"] == 1 and first["pending_proofs"] == 4095
    row = github.state["discovery"]["proof_outbox"]["repositories"]["123"]
    assert row["cursor"] == outbox_head and row["last_error"] == "proof_attempt_queue_full"
    assert f"catalogs/{new_ref['sha256']}.json" not in github.files
    assert first["oldest_inspected_pending_outbox_at"] == FINISH
    restarted = copy.deepcopy(github)
    second = refresh(restarted, client=ControlledClient(data=receipt(subject=subject, bitcoin=True)),
                     max_proofs=1, clock=lambda: 20000)
    assert second["outbox_nodes_registered"] == 1 and second["proofs_changed"] == 1
    assert restarted.state["discovery"]["proof_outbox"]["repositories"]["123"]["completed_head"] == outbox_head
    assert f"catalogs/{new_ref['sha256']}.json" in restarted.files
    assert restarted.assets[TAG, old_evidence["proof_asset"]["name"]] == original
    assert second["proofs_verified"] == 0


def test_outbox_snapshot_finishes_older_chain_despite_new_heads_and_restart(tmp_path):
    github, catalogs, heads = OutboxGitHub(), [], []
    for number in range(1, 4):
        tag = "collector-observations-r123-g" + f"{number:032x}"
        ref, _ = observation(tmp_path, github, tag=tag, subject=sha256(str(number).encode()))
        catalogs.append(ref)
        heads.append(github.append_outbox(ref))
    first = refresh(github, client=ControlledClient(fail=True), max_markers=1, max_proofs=1, clock=lambda: 10000)
    assert first["outbox_nodes_registered"] == 1
    row = github.state["discovery"]["proof_outbox"]["repositories"]["123"]
    assert row["cursor"] == heads[1] and row["target"] == heads[2]
    ref, _ = observation(tmp_path, github, tag="collector-observations-r123-g" + "4" * 32,
                         subject=sha256(b"new head after first daily checkpoint"))
    newest = github.append_outbox(ref)
    catalogs.append(ref)
    restarted = copy.deepcopy(github)
    for day in range(2, 5):
        report = refresh(restarted, client=ControlledClient(fail=True), max_markers=1, max_proofs=1,
                         clock=lambda day=day: day * 10000)
        assert report["outbox_nodes_registered"] == 1
        if day == 3:
            row = restarted.state["discovery"]["proof_outbox"]["repositories"]["123"]
            assert row["completed_head"] == heads[2] and row["cursor"] is None
    row = restarted.state["discovery"]["proof_outbox"]["repositories"]["123"]
    assert row["completed_head"] == newest and row["cursor"] is None
    assert all(f"catalogs/{ref['sha256']}.json" in restarted.files for ref in catalogs)
    for tag, name in restarted.assets:
        if name.endswith(".attestation.json"):
            metadata = json.loads(restarted.assets[tag, name])
            assert metadata["observation_interval"]["started_at"] == START
            assert metadata["observation_interval"]["finished_at"] == FINISH


def test_outbox_cursor_and_registration_are_one_cas(tmp_path):
    github = OutboxGitHub()
    ref, _ = observation(tmp_path, github)
    outbox_head = github.append_outbox(ref)
    github.conflicts = 1
    first = refresh(github, client=ControlledClient(fail=True), clock=lambda: 10000)
    assert first["status"] == "conflict"
    assert github.files == {} and "proof_outbox" not in github.state["discovery"]
    second = refresh(github, client=ControlledClient(fail=True), clock=lambda: 20000)
    assert second["outbox_nodes_registered"] == 1
    assert github.state["discovery"]["proof_outbox"]["repositories"]["123"]["completed_head"] == outbox_head


def test_malformed_later_outbox_checkpoint_rolls_back_earlier_batch_registration(tmp_path):
    github = OutboxGitHub()
    ref, _ = observation(tmp_path, github)
    github.append_outbox(ref)
    github.source_heads[456] = ("other/repository", None)
    github.state["discovery"]["proof_outbox"] = {"repositories": {"456": []}, "last_repository_id": 0}
    before = copy.deepcopy(github.state)
    report = refresh(github, client=ControlledClient(fail=True), max_markers=2, clock=lambda: 10000)
    assert report["outbox_invalid_registrations"] == 1 and report["outbox_nodes_registered"] == 0
    assert github.state["discovery"]["proof_outbox"] == before["discovery"]["proof_outbox"]
    assert github.state["pending"] == before["pending"] and github.files == {}


def test_invalid_outbox_metadata_is_unacknowledged_while_old_proof_drains(tmp_path):
    github = OutboxGitHub()
    old_ref, _ = observation(tmp_path, github)
    register_catalog(github, old_ref)
    ref, evidence = observation(tmp_path, github, tag="collector-observations-r123-g" + "b" * 32,
                                subject=sha256(b"invalid later public metadata"))
    outbox_head = github.append_outbox(ref)
    github.assets[ref["release_tag"], evidence["metadata_asset"]["name"]] = b"{}"
    report = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert report["outbox_invalid_registrations"] == 1 and report["proofs_changed"] == 1
    row = github.state["discovery"]["proof_outbox"]["repositories"]["123"]
    assert row["cursor"] == outbox_head and row["completed_head"] is None
    assert f"catalogs/{ref['sha256']}.json" not in github.files


def test_outbox_repository_rotation_is_bounded_and_fair():
    github = OutboxGitHub()
    for identifier in range(1, 6):
        tag = f"collector-observations-r{identifier}-g" + "a" * 32
        raw = canonical_json({"schema_version": 1, "kind": "icsot_evidence_metadata_catalog",
                              "generation_release": tag, "observations": []})
        ref = {"release_tag": tag, "name": "metadata-catalog.json", "sha256": sha256(raw), "bytes": len(raw)}
        github.assets[tag, ref["name"]] = raw
        github.append_outbox(ref, repository_id=identifier, slug=f"owner/repo{identifier}")
    for turn, expected in enumerate((2, 4, 5), start=1):
        report = refresh(github, max_markers=2, clock=lambda turn=turn: turn * 10000)
        assert report["outbox_repositories_inspected"] == 2
        assert len([path for path in github.files if path.startswith("catalogs/")]) == expected
    # Carried heads are acknowledged without resurrecting already registered work.
    assert refresh(github, max_markers=2, clock=lambda: 40000)["outbox_nodes_registered"] == 0


@pytest.mark.parametrize("truncated_path", ["root", "pointers", None])
def test_public_outbox_inventory_uses_only_complete_nonrecursive_pointer_trees(truncated_path):
    transport, calls = ProofTransport("owner/repository"), []
    transport.branch_head = lambda: "frozen-state-head"
    def api(path):
        calls.append(path)
        if path.endswith("/git/trees/frozen-state-head"):
            return {"truncated": truncated_path == "root", "tree": [
                {"path": "repos", "type": "tree", "sha": "pointer-tree"},
                {"path": "proof-outbox", "type": "tree", "sha": "never-enumerated-history"}]}
        assert path.endswith("/git/trees/pointer-tree")
        return {"truncated": truncated_path == "pointers", "tree": [
            {"path": "123.json", "type": "blob"}, {"path": "456.json", "type": "blob"}]}
    transport._api = api
    if truncated_path:
        with pytest.raises(ValueError, match="Incomplete public state"):
            transport.outbox_repositories()
    else:
        assert transport.outbox_repositories() == ("frozen-state-head", [123, 456])
    assert not any("recursive" in path or "never-enumerated-history" in path for path in calls)


def test_public_outbox_reader_checks_slug_and_exact_immutable_node():
    from icsot_observer.github_state import _slug_binding
    transport = ProofTransport("owner/repository")
    raw = canonical_json({"controlled": "immutable node"})
    ref = {"sha256": sha256(raw), "bytes": len(raw)}
    transport.read_pointer = lambda head, identifier: canonical_json({
        "repository_id": 123, "slug": "one/repo", "proof_outbox": ref})
    transport.read_slug_binding = lambda head, slug: canonical_json(_slug_binding(slug, 123))
    assert transport.outbox_head("frozen", 123) == ("one/repo", ref)
    transport._read_git_file = lambda head, path: raw
    assert transport.outbox_node("frozen", 123, ref) == raw
    transport._read_git_file = lambda head, path: raw + b" "
    with pytest.raises(ValueError, match="missing or differs"):
        transport.outbox_node("frozen", 123, ref)
    transport.read_slug_binding = lambda head, slug: canonical_json(_slug_binding(slug, 456))
    with pytest.raises(ValueError, match="slug binding differs"):
        transport.outbox_head("frozen", 123)


def test_upgrade_publishes_bound_assets_and_keeps_presence_unverified(tmp_path):
    github = FakeGitHub()
    ref, evidence = observation(tmp_path, github)
    original = github.assets[TAG, evidence["proof_asset"]["name"]]
    register_catalog(github, ref)
    report = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert report["proofs_changed"] == 1 and report["proofs_verified"] == 0
    assert report["pending_proofs"] == 0
    assert len(github.published) == 2
    assert github.assets[TAG, evidence["proof_asset"]["name"]] == original
    status = json.loads(github.files[f"proofs/{evidence['metadata_asset']['sha256']}.json"])
    assert status["maintenance_status"] == "awaiting_trusted_rpc"
    latest = status["history"][-1]
    metadata = json.loads(github.fetch(latest["metadata"]))
    assert metadata["status"] == "bitcoin_attestation_unverified"
    assert metadata["verification"]["bitcoin_verified"] is False
    assert metadata["receipt"]["previous_receipt_sha256"] == evidence["proof_asset"]["sha256"]
    assert metadata["previous_metadata_sha256"] == evidence["metadata_asset"]["sha256"]
    # Re-registering after completion never resurrects completed work.
    assert register_catalog(github, ref)["status"] == "already_registered"
    second = refresh(github, client=ControlledClient(), clock=lambda: 20000)
    assert second["proofs_attempted"] == 0 and len(github.published) == 2


def test_new_catalog_reusing_same_receipt_preserves_completed_history(tmp_path):
    github = FakeGitHub()
    ref, evidence = observation(tmp_path, github)
    register_catalog(github, ref)
    refresh(github, client=ControlledClient(), clock=lambda: 10000)
    path = f"proofs/{evidence['metadata_asset']['sha256']}.json"
    retained = github.files[path]
    new_tag = "collector-observations-r123-g" + "b" * 32
    new_ref, new_evidence = observation(tmp_path, github, tag=new_tag)
    assert new_evidence["metadata_asset"] == evidence["metadata_asset"]
    assert register_catalog(github, new_ref)["status"] == "registered"
    assert github.files[path] == retained and github.state["pending"] == {}
    assert json.loads(github.files[f"catalogs/{new_ref['sha256']}.json"])["proof_keys"] == [evidence["metadata_asset"]["sha256"]]


def test_explicit_rpc_requeue_verifies_archived_completed_upgrade(tmp_path):
    github = FakeGitHub()
    ref, evidence = observation(tmp_path, github)
    register_catalog(github, ref)
    refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert github.state["pending"] == {}
    queued = requeue_catalog(github, ref["sha256"], max_proofs=1)
    assert queued["proofs_requeued"] == 1 and queued["next_after_proof_key"] is None
    class Verifier:
        def verify(self, raw, subject):
            return {"status": "verified", "bitcoin_verified": True, "method": "trusted_bitcoin_core_rpc"}
    offline_calendar = ControlledClient(fail=True)
    result = refresh(github, client=offline_calendar, verifier=Verifier(), clock=lambda: 20000)
    assert result["proofs_verified"] == 1
    assert offline_calendar.calls == 0
    assert requeue_catalog(github, ref["sha256"])["proofs_requeued"] == 0


def test_invalid_later_observation_does_not_partially_register_marker(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    marker = json.loads(github.markers[TAG])
    marker["observations"].append({"index": {"release_tag": TAG, "name": "../unsafe"}})
    github.markers[TAG] = canonical_json(marker)
    github.pages[1] = [{"id": 123, "tag_name": TAG}]
    result = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert result["incomplete_releases"] == 1 and github.state["pending"] == {}
    assert github.files == {} and github.published == []


def test_discovery_capacity_preserves_cursor_and_still_drains_proofs(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    register_catalog(github, ref)
    github.state["discovery"]["historical_page"] = 7
    github.state["discovery"]["incomplete_releases"] = [
        {"id": number, "tag": "collector-observations-r123-g" + f"{number:032x}"}
        for number in range(1, 4097)]
    github.pages[1] = [{"id": 9999, "tag_name": "collector-observations-r123-g" + "f" * 32}]
    result = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert result["discovery_paused_at_capacity"] is True
    assert result["historical_discovery_page"] == 7 and result["incomplete_releases"] == 4096
    assert result["proofs_changed"] == 1 and result["pending_proofs"] == 0


def test_initial_metadata_claim_cannot_bypass_our_verifier(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    register_catalog(github, ref)
    assert len(github.state["pending"]) == 1
    assert refresh(github, client=ControlledClient(), clock=lambda: 10000)["proofs_verified"] == 0


def test_missing_completion_marker_is_durable_and_later_discovered(tmp_path):
    github = FakeGitHub()
    github.pages[1] = [{"id": 12, "tag_name": TAG}]
    first = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert first["incomplete_releases"] == 1 and first["proofs_attempted"] == 0
    observation(tmp_path, github)
    second = refresh(github, client=ControlledClient(), clock=lambda: 20000)
    assert second["markers_processed"] == 1 and second["incomplete_releases"] == 0
    assert second["proofs_changed"] == 1


def test_baseline_marker_fallback_recovers_quota_refused_registration(tmp_path, monkeypatch):
    github = FakeGitHub()
    tag = "corpus-baseline-40246318334-2"
    ref, evidence = observation(tmp_path, github, tag=tag)
    # The baseline index binds its one frozen manifest both at top level and
    # within the original capture result; discovery needs the public top-level
    # subject and never reads an encrypted archive or inherited capture payload.
    index = json.loads(github.assets[tag, "capture.index.json"])
    index.update(schema_version=1, repository="libfuse/libfuse", mode="full",
                 repository_id=123, manifests=[{"sha256": SUBJECT}],
                 collector_result={"manifest_sha256": SUBJECT, "repository_id": 123},
                 public_sidecars=[evidence["proof_asset"], evidence["metadata_asset"]],
                 observation_started_at=START, observation_finished_at=FINISH)
    encoded_index = canonical_json(index)
    github.assets[tag, "capture.index.json"] = encoded_index
    marker = json.loads(github.markers[tag])
    marker["observations"][0].update(repository="libfuse/libfuse", timestamp_evidence=index["timestamp_evidence"])
    marker["observations"][0]["index"].update(sha256=sha256(encoded_index), bytes=len(encoded_index))
    encoded_marker = canonical_json(marker)
    github.markers[tag] = github.assets[tag, "metadata-catalog.json"] = encoded_marker
    ref.update(sha256=sha256(encoded_marker), bytes=len(encoded_marker))
    original_save = github.save
    def refuse(*args, **kwargs):
        raise StateDeferredError("controlled registration quota refusal", retry_not_before=2000000000)
    monkeypatch.setattr(github, "save", refuse)
    with pytest.raises(StateDeferredError, match="quota refusal"):
        register_catalog(github, ref)
    assert github.head is None and github.state["pending"] == {} and github.files == {}
    monkeypatch.setattr(github, "save", original_save)
    github.pages[1] = [{"id": 123, "tag_name": tag}]
    report = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert report["markers_processed"] == 1 and report["proofs_attempted"] == 1
    assert report["proofs_changed"] == 1 and report["proofs_verified"] == 0
    assert f"catalogs/{ref['sha256']}.json" in github.files
    history = json.loads(github.files[f"proofs/{evidence['metadata_asset']['sha256']}.json"])
    assert history["subject_sha256"] == index["manifest_sha256"] == index["collector_result"]["manifest_sha256"]
    assert history["maintenance_status"] == "awaiting_trusted_rpc"


def test_legacy_unmarked_baseline_release_stays_explicit_backfill_gap():
    github = FakeGitHub()
    tag = "corpus-baseline-40246318334-1"
    github.pages[1] = [{"id": 123, "tag_name": tag}]
    report = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert report["status"] == "backlog" and report["incomplete_releases"] == 1
    assert report["markers_processed"] == report["proofs_attempted"] == 0
    assert github.state["discovery"]["incomplete_releases"] == [{"id": 123, "tag": tag}]
    assert github.state["discovery"]["recent_release_ids"] == []
    assert github.files == {} and github.published == []


def test_rolling_cursor_discovers_new_release_outside_recent_page(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    github.pages[1] = [{"id": 999, "tag_name": "unrelated-release"}]
    github.pages[2] = [{"id": 3, "tag_name": TAG}]
    report = refresh(github, client=ControlledClient(), page_size=1, clock=lambda: 10000)
    assert report["markers_processed"] == 1 and report["historical_discovery_page"] == 3
    assert f"catalogs/{ref['sha256']}.json" in github.files
    refresh(github, client=ControlledClient(), page_size=1, clock=lambda: 20000)
    assert github.state["discovery"]["historical_page"] == 2
    assert github.state["discovery"]["completed_cycles"] == 1


@pytest.mark.parametrize("mode", ["tampered_subject", "calendar_failure"])
def test_tampered_upgrade_and_calendar_failure_do_not_publish(tmp_path, mode):
    github = FakeGitHub()
    ref, evidence = observation(tmp_path, github)
    register_catalog(github, ref)
    client = ControlledClient(data=receipt(subject="f" * 64, bitcoin=True)) if mode == "tampered_subject" else ControlledClient(fail=True)
    report = refresh(github, client=client, clock=lambda: 10000)
    assert report["proofs_changed"] == 0 and report["proofs_deferred"] == 1
    assert github.published == []
    assert github.state["pending"][evidence["metadata_asset"]["sha256"]]["attempts"] == 1


def test_rate_defer_keeps_authoritative_queue_and_retry_after(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    register_catalog(github, ref)
    snapshot = copy.deepcopy(github.state)
    github.defer_publish = True
    report = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert report["status"] == "deferred" and report["retry_not_before"] == 999999
    key = next(iter(snapshot["pending"]))
    assert github.state["pending"][key]["proof"] == snapshot["pending"][key]["proof"]
    assert github.state["pending"][key]["prepared_metadata"]["receipt"]["sha256"] == sha256(receipt(bitcoin=True))
    assert report["pending_proofs"] == 1


def test_post_upload_cas_conflict_reloads_authoritative_state(tmp_path):
    github = FakeGitHub()
    ref, _ = observation(tmp_path, github)
    register_catalog(github, ref)
    github.conflict_after_upload = True
    report = refresh(github, client=ControlledClient(), clock=lambda: 10000)
    assert report["status"] == "conflict" and report["pending_proofs"] == 1
    retry = refresh(github, client=ControlledClient(), clock=lambda: 20000)
    assert retry["proofs_changed"] == 1 and retry["pending_proofs"] == 0
    assert len(github.published) == 2  # Prepared acquisition time survives restart.


def test_ots_cli_uses_private_copy_and_accepts_valid_partial_nonzero(tmp_path):
    initial, upgraded = receipt(), receipt(bitcoin=True)
    seen = []
    def runner(args, **kwargs):
        seen.append(args)
        target = Path(args[-1])
        assert target.read_bytes() == initial
        assert kwargs["timeout"] == 7 and kwargs["capture_output"] is True
        target.write_bytes(upgraded)
        return subprocess.CompletedProcess(args, 1, b"", b"partial status")
    assert OtsClient(runner=runner, timeout=7).upgrade(initial, SUBJECT) == upgraded
    assert seen[0][1:-1] == ["-c", "from otsclient.ots import main; main()", "--no-cache", "--no-bitcoin", "upgrade"]
    assert "--wait" not in seen[0]
    def broken(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, b"", b"unavailable")
    with pytest.raises(RuntimeError, match="deferred or failed"):
        OtsClient(runner=broken).upgrade(initial, SUBJECT)


def test_trusted_rpc_configuration_hides_credentials_on_failure():
    def fail(request, **kwargs):
        assert request.headers["Authorization"].startswith("Basic ")
        assert "secret" not in request.full_url
        raise OSError("DO NOT EXPOSE rpc-password-secret")
    verifier = BitcoinCoreVerifier('{"url":"http://127.0.0.1:8332","user":"operator","password":"rpc-password-secret"}', opener=fail)
    with pytest.raises(RuntimeError) as error:
        verifier.verify(receipt(bitcoin=True), SUBJECT)
    assert "secret" not in str(error.value)


def test_rpc_redirect_is_rejected_before_credentials_can_reach_new_origin():
    verifier = BitcoinCoreVerifier('{"url":"http://127.0.0.1:8332","user":"operator","password":"secret"}')
    handler = next(h for h in verifier.opener.__self__.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
    request = urllib.request.Request("http://127.0.0.1:8332", data=b"{}", headers={"Authorization": "Basic secret"})
    with pytest.raises(RuntimeError, match="redirects are not permitted"):
        handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, "http://other-origin.invalid/rpc")
    for configuration in ('{"url":"http://127.0.0.1:8332","password":42}', '["secret"]', 'not JSON'):
        with pytest.raises(ValueError) as error:
            BitcoinCoreVerifier(configuration)
        assert "secret" not in str(error.value)


@pytest.mark.parametrize("valid_header", [True, False])
def test_real_ots_verification_against_controlled_core_rpc_header(valid_header):
    pytest.importorskip("opentimestamps")
    from bitcoin.core import CBlockHeader, b2lx
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    raw = receipt(bitcoin=True)
    stamp = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(raw)))
    message = next(message for message, att in stamp.timestamp.all_attestations()
                   if type(att).__name__ == "BitcoinBlockHeaderAttestation")
    header = CBlockHeader(hashMerkleRoot=message if valid_header else b"\x00" * 32, nTime=1700000000)
    blockhash = b2lx(header.GetHash())
    calls = []
    def opener(request, **kwargs):
        query = json.loads(request.data)
        calls.append((query["method"], query["params"]))
        values = {"getblockchaininfo": {"chain": "main", "initialblockdownload": False, "blocks": 900000},
                  "getblockhash": blockhash, "getblockheader": header.serialize().hex()}
        return io.BytesIO(json.dumps({"result": values[query["method"]], "error": None}).encode())
    verifier = BitcoinCoreVerifier('{"url":"http://127.0.0.1:8332","user":"operator","password":"secret"}', opener=opener)
    if valid_header:
        result = verifier.verify(raw, SUBJECT)
        assert result["bitcoin_verified"] is True and result["block_height"] == 870000
        assert result["block_hash"] == blockhash
    else:
        with pytest.raises(RuntimeError, match="does not match"):
            verifier.verify(raw, SUBJECT)
    assert [method for method, params in calls] == ["getblockchaininfo", "getblockhash", "getblockheader"]


def test_optional_rpc_success_is_the_only_verified_transition(tmp_path):
    github = FakeGitHub()
    ref, evidence = observation(tmp_path, github)
    register_catalog(github, ref)
    class TrustedVerifier:
        def verify(self, raw, subject):
            assert raw == receipt(bitcoin=True) and subject == SUBJECT
            return {"status": "verified", "bitcoin_verified": True, "method": "trusted_bitcoin_core_rpc"}
    report = refresh(github, client=ControlledClient(), verifier=TrustedVerifier(), clock=lambda: 10000)
    assert report["proofs_verified"] == 1 and report["pending_proofs"] == 0
    record = json.loads(github.files[f"proofs/{evidence['metadata_asset']['sha256']}.json"])
    assert record["history"][-1]["status"] == "bitcoin_verified"


def test_gh_transport_creates_public_branch_without_force_or_private_key():
    calls = []
    head = None
    def runner(command, **kwargs):
        nonlocal head
        calls.append((command, kwargs.get("input")))
        endpoint = command[2]
        method = command[command.index("--method") + 1]
        payload = json.loads(kwargs["input"]) if kwargs.get("input") else None
        code = 200
        if endpoint.endswith("git/ref/heads/collector-attestations"):
            response = {"object": {"sha": head}} if head else {}
            code = 200 if head else 404
        elif endpoint.endswith("git/blobs"):
            response = {"sha": "b" * 40}
        elif endpoint.endswith("git/trees"):
            assert payload["tree"][0]["path"] == "state.json"
            response = {"sha": "c" * 40}
        elif endpoint.endswith("git/commits"):
            assert payload["parents"] == []
            response = {"sha": "d" * 40}
        elif endpoint.endswith("git/refs"):
            assert payload["ref"] == "refs/heads/collector-attestations"
            head = payload["sha"]
            response = {"object": {"sha": head}}
        else:
            raise AssertionError(endpoint)
        body = json.dumps(response).encode()
        raw = f"HTTP/2 {code}\r\nx-ratelimit-remaining: 999\r\n\r\n".encode() + body
        return subprocess.CompletedProcess(command, 0 if code == 200 else 1, raw, b"HTTP 404" if code == 404 else b"")
    transport = ProofTransport("owner/repository", runner=runner)
    parent, state = transport.load()
    assert parent is None
    assert transport.save(parent, state) == "d" * 40
    assert all("--force" not in command for command, _ in calls)
    assert all("collector-state" not in " ".join(command) for command, _ in calls)


def test_established_public_branch_missing_queue_fails_closed():
    def runner(command, **kwargs):
        if "git/ref/heads/collector-attestations" in command[2]:
            body = json.dumps({"object": {"sha": "a" * 40}}).encode()
            return subprocess.CompletedProcess(command, 0, b"HTTP/2 200\r\n\r\n" + body, b"")
        return subprocess.CompletedProcess(command, 1, b"HTTP/2 404\r\n\r\n{}", b"HTTP 404")
    from icsot_observer.github_state import StateError
    with pytest.raises(StateError, match="missing state.json"):
        ProofTransport("owner/repository", runner=runner).load()


def test_registration_adapter_preserves_active_repository_bucket_before_request():
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        raise AssertionError("Repository reserve must block every network request")
    transport = GhCliStateTransport("owner/repository", runner=runner, clock=lambda: 1000)
    transport.request_count = 7
    transport._observe_rate({"remaining": 100, "reset": 2000, "resource": "core", "limit": 1000}, scope="repository")
    transport._observe_rate({"remaining": 2513, "reset": 3000, "resource": "core", "limit": 5000}, scope="generic_core")
    transport.last_budget_metrics = {"destination_github_repository_rate_probe": {"remaining": 100, "limit": 1000}}
    windows = copy.deepcopy(transport._rate_windows)
    with pytest.raises(StateDeferredError) as error:
        register_catalog(transport, {"release_tag": TAG, "name": "metadata-catalog.json", "sha256": "a" * 64, "bytes": 123})
    assert calls == [] and transport.request_count == 7
    assert transport._rate_windows == windows
    assert error.value.rate_measurements == transport.last_budget_metrics
    assert error.value.retry_not_before == 2000


def test_registration_adapter_returns_updated_bucket_probe_and_cache_on_error(monkeypatch):
    transport = GhCliStateTransport("owner/repository", clock=lambda: 1000)
    transport.request_count = 3
    transport._observe_rate({"remaining": 110, "reset": 2000, "resource": "core", "limit": 1000}, scope="repository")
    def deferred_load(adapter):
        assert adapter._rate_windows == transport._rate_windows
        adapter.request_count += 4
        measured = {"remaining": 100, "reset": 2000, "resource": "core", "limit": 1000}
        adapter._observe_rate(measured, scope="repository")
        adapter._last_repo_rate_headers = measured
        adapter._last_response_rate_headers = measured
        adapter.last_budget_metrics = {"destination_github_repository_rate_probe": measured}
        adapter._releases["retained-public-release"] = {"id": 123}
        adapter._guard_rate()
        raise AssertionError("Guard must defer")
    monkeypatch.setattr(ProofTransport, "load", deferred_load)
    with pytest.raises(StateDeferredError):
        register_catalog(transport, {"release_tag": TAG, "name": "metadata-catalog.json", "sha256": "a" * 64, "bytes": 123})
    assert transport.request_count == 7 and transport.rate_remaining == 100
    assert transport._rate_windows[("repository", 2000.0, "core", 1000)] == 100
    assert transport._last_repo_rate_headers["remaining"] == 100
    assert transport._last_response_rate_headers["remaining"] == 100
    assert transport.last_budget_metrics["destination_github_repository_rate_probe"]["remaining"] == 100
    assert transport._releases["retained-public-release"]["id"] == 123
