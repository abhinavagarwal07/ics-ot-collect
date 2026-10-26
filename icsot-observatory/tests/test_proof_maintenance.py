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
