"""Offline tests with real receipts serialized by the official OTS library."""
import builtins
import hashlib
import io
import json
import shutil
import subprocess

import pytest

from icsot_observer.attestations import (
    AttestationDependencyError,
    RFC3161Error,
    inspect_ots_receipt,
    publish_ots_attestation,
    publish_rfc3161_attestation,
)
from icsot_observer.core import canonical_json


SUBJECT = hashlib.sha256(b"an exact canonical collector manifest\n").hexdigest()
START = "2026-10-25T01:02:03.123456Z"
FINISH = "2026-10-25T01:02:04.654321Z"
REQUEST = "2026-10-25T01:02:05.000001Z"
RECEIVED = "2026-10-25T01:02:06.000002Z"


def receipt_bytes(*, digest=SUBJECT, bitcoin_height=None, calendar="https://calendar.example.invalid"):
    pytest.importorskip("opentimestamps.core.timestamp", reason="optional pinned OpenTimestamps dependency")
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    # Exercise deserialization of the actual operation tree, not a header stub.
    timestamp = Timestamp(bytes.fromhex(digest))
    leaf = timestamp.ops.add(OpAppend(b"fixed offline test nonce")).ops.add(OpSHA256())
    if calendar is not None:
        leaf.attestations.add(PendingAttestation(calendar))
    if bitcoin_height is not None:
        leaf.attestations.add(BitcoinBlockHeaderAttestation(bitcoin_height))
    detached = DetachedTimestampFile(OpSHA256(), timestamp)
    output = io.BytesIO()
    detached.serialize(StreamSerializationContext(output))
    return output.getvalue()


def publish(tmp_path, contents=None, **kwargs):
    original = tmp_path / "original.ots"
    original.write_bytes(receipt_bytes() if contents is None else contents)
    options = {"manifest_sha256": SUBJECT, "proof_path": original,
               "observation_started_at": START, "observation_finished_at": FINISH,
               "requested_at": REQUEST, "received_at": RECEIVED}
    options.update(kwargs)
    return publish_ots_attestation(tmp_path / "public", **options)


def test_real_pending_receipt_publishes_canonical_bound_immutable_assets(tmp_path):
    contents = receipt_bytes()
    result = publish(tmp_path, contents)
    metadata = result["metadata"]
    proof, sidecar = result["proof_asset"], result["metadata_asset"]
    assert metadata["subject_sha256"] == SUBJECT
    assert metadata["subject_binding"]["status"] == "matched"
    assert metadata["status"] == "pending_bitcoin_completion"
    assert metadata["provider"]["calendar_urls"] == ["https://calendar.example.invalid"]
    assert metadata["observation_interval"] == {
        "started_at": START, "finished_at": FINISH, "clock": "collector_system_clock_utc"}
    assert metadata["request"]["requested_at"] == REQUEST
    assert metadata["request"]["receipt_received_at"] == RECEIVED
    assert metadata["receipt_collected_at"] == RECEIVED
    assert metadata["verification"]["bitcoin_verified"] is False
    assert metadata["verification"]["status"] == "not_performed"
    assert metadata["receipt"] == {**proof, "kind": "initial", "previous_receipt_sha256": None}
    for descriptor in (proof, sidecar):
        path = tmp_path / "public" / descriptor["name"]
        assert "/" not in descriptor["name"]
        assert len(path.read_bytes()) == descriptor["bytes"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == descriptor["sha256"]
    assert (tmp_path / "public" / proof["name"]).read_bytes() == contents
    assert (tmp_path / "original.ots").read_bytes() == contents
    assert (tmp_path / "public" / sidecar["name"]).read_bytes() == canonical_json(metadata)
    assert json.loads((tmp_path / "public" / sidecar["name"]).read_bytes()) == metadata
    assert publish(tmp_path, contents) == result
    assert len(list((tmp_path / "public").iterdir())) == 2


def test_bitcoin_header_presence_stays_unverified():
    contents = receipt_bytes(bitcoin_height=870_000)
    result = inspect_ots_receipt(contents, SUBJECT)
    assert result["bitcoin_block_heights"] == [870_000]
    assert result["status"] == "bitcoin_attestation_unverified"


def test_unsupported_attestation_is_preserved_but_unverified():
    pytest.importorskip("opentimestamps.core.timestamp")
    from opentimestamps.core.notary import UnknownAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    timestamp = Timestamp(bytes.fromhex(SUBJECT))
    timestamp.attestations.add(UnknownAttestation(b"unknown!", b"opaque"))
    output = io.BytesIO()
    DetachedTimestampFile(OpSHA256(), timestamp).serialize(StreamSerializationContext(output))
    result = inspect_ots_receipt(output.getvalue(), SUBJECT)
    assert result["status"] == "unrecognized_attestation_unverified"
    assert result["unrecognized_attestation_types"] == ["UnknownAttestation"]


def test_wrong_subject_cannot_publish(tmp_path):
    with pytest.raises(ValueError, match="subject does not match"):
        publish(tmp_path, receipt_bytes(digest="f" * 64))
    assert not (tmp_path / "public").exists()


def test_other_hash_algorithm_cannot_claim_sha256_subject():
    pytest.importorskip("opentimestamps.core.timestamp")
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA1
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    timestamp = Timestamp(b"\x11" * 20)
    timestamp.attestations.add(PendingAttestation("https://example.invalid"))
    output = io.BytesIO()
    DetachedTimestampFile(OpSHA1(), timestamp).serialize(StreamSerializationContext(output))
    with pytest.raises(ValueError, match="must use SHA-256"):
        inspect_ots_receipt(output.getvalue(), SUBJECT)


@pytest.mark.parametrize("corrupt", [lambda data: data[:-1], lambda data: data + b"junk",
                                    lambda data: b"not an OTS proof" + data])
def test_complete_deserialization_rejects_malformed_receipts(tmp_path, corrupt):
    with pytest.raises(ValueError, match="Invalid OpenTimestamps"):
        publish(tmp_path, corrupt(receipt_bytes()))
    assert not (tmp_path / "public").exists()


def test_missing_dependency_fails_clearly_only_when_inspecting(monkeypatch):
    original_import = builtins.__import__

    def missing_optional_package(name, *args, **kwargs):
        if name.startswith("opentimestamps"):
            raise ImportError("deliberately unavailable optional library")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_optional_package)
    with pytest.raises(AttestationDependencyError, match="opentimestamps-client==0.7.2"):
        inspect_ots_receipt(b"opaque nonempty bytes", SUBJECT)


@pytest.mark.parametrize("bad_digest", ["../escape", "A" * 64, "0" * 63, None])
def test_unsafe_or_invalid_digest_is_rejected_before_dependency_load(bad_digest):
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        inspect_ots_receipt(b"opaque nonempty bytes", bad_digest)


@pytest.mark.parametrize("field,value", [
    ("observation_started_at", "2026-10-25T01:02:03"),
    ("observation_finished_at", "not a date"),
    ("observation_finished_at", "2026-10-25T01:02:02Z"),
    ("received_at", "2026-10-25T01:02:04Z"),
    ("collected_at", "2026-10-25"),
])
def test_invalid_or_reversed_clock_assertions_are_rejected(tmp_path, field, value):
    with pytest.raises(ValueError):
        publish(tmp_path, **{field: value})
    assert not (tmp_path / "public").exists()


def test_utc_conversion_and_unknown_historical_times_are_explicit(tmp_path):
    result = publish(tmp_path, requested_at=None, received_at=None, collected_at="2026-10-24T18:02:09-07:00",
                     observation_started_at="2026-10-24T18:02:03.123456-07:00")
    metadata = result["metadata"]
    assert metadata["observation_interval"]["started_at"] == START
    assert metadata["request"]["requested_at"] is None
    assert metadata["request"]["receipt_received_at"] is None
    assert metadata["receipt_collected_at"] == "2026-10-25T01:02:09.000000Z"


def test_unknown_receipt_time_uses_actual_collection_clock(tmp_path, monkeypatch):
    monkeypatch.setattr("icsot_observer.attestations.utc_iso", lambda: "2026-10-25T01:03:00.000000Z")
    result = publish(tmp_path, requested_at=None, received_at=None)
    assert result["metadata"]["receipt_collected_at"] == "2026-10-25T01:03:00.000000Z"


def test_existing_different_asset_is_never_overwritten(tmp_path):
    result = publish(tmp_path)
    path = tmp_path / "public" / result["proof_asset"]["name"]
    path.write_bytes(b"tampered immutable evidence")
    with pytest.raises(ValueError, match="different contents"):
        publish(tmp_path)
    assert path.read_bytes() == b"tampered immutable evidence"


@pytest.mark.parametrize("symlink_target", ["proof", "asset", "directory"])
def test_symlinks_are_rejected(tmp_path, symlink_target):
    contents = receipt_bytes()
    original = tmp_path / "original.ots"
    original.write_bytes(contents)
    output = tmp_path / "public"
    if symlink_target == "proof":
        target = tmp_path / "source.ots"
        target.write_bytes(contents)
        original.unlink()
        original.symlink_to(target)
    elif symlink_target == "asset":
        output.mkdir()
        (output / f"ots-{SUBJECT}-{hashlib.sha256(contents).hexdigest()}.ots").symlink_to(original)
    else:
        target = tmp_path / "elsewhere"
        target.mkdir()
        output.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        publish_ots_attestation(output, manifest_sha256=SUBJECT, proof_path=original,
                                observation_started_at=START, observation_finished_at=FINISH)


def test_upgraded_receipt_preserves_initial_receipt_and_links_its_hash(tmp_path):
    initial = publish(tmp_path)
    upgraded_contents = receipt_bytes(bitcoin_height=870_000)
    upgraded = publish(tmp_path, upgraded_contents, receipt_kind="upgraded",
                       previous_receipt_sha256=initial["proof_asset"]["sha256"])
    assert initial["proof_asset"]["name"] != upgraded["proof_asset"]["name"]
    assert (tmp_path / "public" / initial["proof_asset"]["name"]).read_bytes() == receipt_bytes()
    assert upgraded["metadata"]["receipt"]["previous_receipt_sha256"] == initial["proof_asset"]["sha256"]
    assert upgraded["metadata"]["status"] == "bitcoin_attestation_unverified"
    assert upgraded["metadata"]["verification"]["bitcoin_verified"] is False


@pytest.mark.parametrize("kind,previous", [("../escape", None), ("upgraded", None), ("initial", "a" * 64)])
def test_receipt_history_inputs_cannot_create_false_initial_records(tmp_path, kind, previous):
    with pytest.raises(ValueError):
        publish(tmp_path, receipt_kind=kind, previous_receipt_sha256=previous)


@pytest.fixture(scope="module")
def local_tsa(tmp_path_factory):
    """Real isolated test CA/TSA; its generated keys never leave this fixture."""
    binary = shutil.which("openssl")
    if binary is None:
        pytest.skip("OpenSSL 3 ts support is required for real RFC 3161 tests")
    if not subprocess.check_output([binary, "version"]).startswith(b"OpenSSL 3."):
        pytest.skip("RFC 3161 helper requires OpenSSL 3")
    home = tmp_path_factory.mktemp("local-test-tsa")

    def run(*args):
        result = subprocess.run([binary, *map(str, args)], capture_output=True)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    root, signer = home / "root.pem", home / "tsa.pem"
    root_key, signer_key = home / "root.key", home / "tsa.key"
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-sha256",
        "-subj", "/CN=Offline Test Timestamp Root", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", root_key, "-out", root)
    run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Offline Test Timestamp Signer",
        "-keyout", signer_key, "-out", home / "tsa.csr")
    extensions = home / "tsa.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                          "extendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run("x509", "-req", "-in", home / "tsa.csr", "-CA", root, "-CAkey", root_key,
        "-CAcreateserial", "-days", "2", "-sha256", "-extfile", extensions, "-out", signer)
    wrong_root = home / "wrong-root.pem"
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-sha256",
        "-subj", "/CN=Untrusted Other Test Root", "-keyout", home / "wrong-root.key", "-out", wrong_root)
    serial = home / "tsaserial"
    serial.write_text("01\n")
    config = home / "tsa.cnf"
    config.write_text(
        f"[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\nserial={serial}\n"
        f"crypto_device=builtin\nsigner_cert={signer}\ncerts={root}\nsigner_key={signer_key}\n"
        "signer_digest=sha256\ndefault_policy=1.3.6.1.4.1.55555.1\ndigests=sha256\n"
        "accuracy=secs:1\nordering=no\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n"
        "clock_precision_digits=3\n")

    def sign(query_bytes):
        query, response = home / "request.tsq", home / "reply.tsr"
        query.write_bytes(query_bytes)
        run("ts", "-reply", "-config", config, "-queryfile", query, "-out", response)
        return response.read_bytes()

    def query(digest):
        path = home / "other-query.tsq"
        run("ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", path)
        return path.read_bytes()

    return {"root": root, "wrong_root": wrong_root, "sign": sign, "query": query, "binary": binary}


def rfc_publish(tmp_path, local_tsa, **kwargs):
    options = {"manifest_sha256": SUBJECT, "observation_started_at": START,
               "observation_finished_at": FINISH, "endpoint": "https://tsa.example.invalid",
               "ca_file": local_tsa["root"], "openssl_binary": local_tsa["binary"]}
    options.update(kwargs)
    return publish_rfc3161_attestation(tmp_path / "rfc3161", **options)


def mock_tsa(monkeypatch, local_tsa, *, query_override=None, response_override=None):
    calls = []

    def urlopen(request, timeout):
        assert request.method == "POST"
        assert request.get_header("Content-type") == "application/timestamp-query"
        assert 0 < timeout <= 180
        calls.append(request.data)
        # This callback is the whole transport: tests never contact any server.
        response = response_override if response_override is not None else local_tsa["sign"](
            query_override if query_override is not None else request.data)
        return io.BytesIO(response)

    monkeypatch.setattr("icsot_observer.attestations.urllib.request.urlopen", urlopen)
    return calls


def test_real_rfc3161_nonce_chain_and_imprint_verification_and_offline_reuse(tmp_path, monkeypatch, local_tsa):
    calls = mock_tsa(monkeypatch, local_tsa)
    result = rfc_publish(tmp_path, local_tsa)
    metadata = result["metadata"]
    assert len(calls) == 1
    assert metadata["status"] == "verified_chain_and_imprint"
    assert metadata["verification"]["nonce_and_query_verified"] is True
    assert metadata["verification"]["certificate_chain_verified"] is True
    assert metadata["verification"]["subject_imprint_verified"] is True
    assert metadata["verification"]["revocation"] == "not_performed"
    assert metadata["tsa_generation_time"]["source"] == "signed_tst_info_gen_time"
    assert metadata["tsa_generation_time"]["utc"].endswith("Z")
    assert metadata["request"]["requested_at"] <= metadata["request"]["receipt_received_at"]
    assert metadata["request"]["receipt_received_at"] <= metadata["verification"]["verified_at"]
    assets = [result["request_asset"], result["proof_asset"], result["metadata_asset"],
              result["details_asset"], *result["trust_assets"]]
    for asset in assets:
        data = (tmp_path / "rfc3161" / asset["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == asset["sha256"]
        assert len(data) == asset["bytes"]
    metadata_path = tmp_path / "rfc3161" / result["metadata_asset"]["name"]
    assert metadata_path.read_bytes() == canonical_json(metadata)
    assert len(metadata["trust"]["ca_certificate_der_sha256"]) == 1
    details = (tmp_path / "rfc3161" / result["details_asset"]["name"]).read_text()
    for signed_field in ("Policy OID:", "Serial number:", "Accuracy:", "Nonce:"):
        assert signed_field in details
    assert metadata["time_accuracy"]["unspecified_accuracy_is_zero"] is False
    assert rfc_publish(tmp_path, local_tsa) == result
    assert len(calls) == 1, "export retry must reuse the original accepted request/receipt"


def test_two_rfc_providers_retain_distinct_receipts_for_same_subject(tmp_path, monkeypatch, local_tsa):
    calls = mock_tsa(monkeypatch, local_tsa)
    first = rfc_publish(tmp_path, local_tsa)
    second = rfc_publish(tmp_path, local_tsa, endpoint="https://second.example.invalid")
    assert len(calls) == 2
    assert first["metadata"]["subject_sha256"] == second["metadata"]["subject_sha256"] == SUBJECT
    assert first["proof_asset"]["name"] != second["proof_asset"]["name"]
    assert len(list((tmp_path / "rfc3161").glob("*.accepted.json"))) == 2
    assert rfc_publish(tmp_path, local_tsa) == first
    assert rfc_publish(tmp_path, local_tsa, endpoint="https://second.example.invalid") == second
    assert len(calls) == 2


def test_rfc_retry_honors_retry_after_and_reuses_query(tmp_path, monkeypatch, local_tsa):
    import urllib.error
    from icsot_observer import attestations
    requests, sleeps = [], []

    def urlopen(request, timeout):
        requests.append(request.data)
        if len(requests) == 1:
            raise urllib.error.HTTPError(request.full_url, 429, "limited", {"Retry-After": "3"}, None)
        return io.BytesIO(local_tsa["sign"](request.data))

    monkeypatch.setattr(attestations.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(attestations.time, "sleep", sleeps.append)
    monkeypatch.setattr(attestations.random, "uniform", lambda a, b: 0.1)
    result = rfc_publish(tmp_path, local_tsa, max_attempts=3)
    assert result["metadata"]["status"] == "verified_chain_and_imprint"
    assert requests[0] == requests[1]
    assert sleeps == [3.1]


def test_rfc_retry_after_longer_than_budget_fails_without_early_retry(tmp_path, monkeypatch, local_tsa):
    import urllib.error
    from icsot_observer import attestations
    calls = []

    def urlopen(request, timeout):
        calls.append(request.data)
        raise urllib.error.HTTPError(request.full_url, 503, "busy", {"Retry-After": "3600"}, None)

    monkeypatch.setattr(attestations.urllib.request, "urlopen", urlopen)
    with pytest.raises(RFC3161Error, match="budget exhausted"):
        rfc_publish(tmp_path, local_tsa, max_attempts=3)
    assert len(calls) == 1


def test_rfc_retry_after_http_date_is_respected(tmp_path, monkeypatch, local_tsa):
    import urllib.error
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime, parsedate_to_datetime
    from icsot_observer import attestations
    calls, sleeps, expected_delays = [], [], []
    retry_at = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=5), usegmt=True)

    def urlopen(request, timeout):
        calls.append(request.data)
        if len(calls) == 1:
            expected_delays.append(max(1.0, (parsedate_to_datetime(retry_at) - datetime.now(timezone.utc)).total_seconds()) + 0.1)
            raise urllib.error.HTTPError(request.full_url, 503, "busy", {"Retry-After": retry_at}, None)
        return io.BytesIO(local_tsa["sign"](request.data))

    monkeypatch.setattr(attestations.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(attestations.time, "sleep", sleeps.append)
    monkeypatch.setattr(attestations.random, "uniform", lambda a, b: 0.1)
    assert rfc_publish(tmp_path, local_tsa, max_attempts=3)["metadata"]["status"] == "verified_chain_and_imprint"
    assert len(calls) == 2 and abs(sleeps[0] - expected_delays[0]) < 0.5


def test_rfc3161_older_accepted_metadata_is_enriched_without_restamping_or_mutation(tmp_path, monkeypatch, local_tsa):
    calls = mock_tsa(monkeypatch, local_tsa)
    original = rfc_publish(tmp_path, local_tsa)
    accepted = next((tmp_path / "rfc3161").glob("*.accepted.json"))
    legacy = dict(original["metadata"])
    for added_field in ("response_details_asset", "time_accuracy", "signer_certificate"):
        del legacy[added_field]
    legacy_bytes = canonical_json(legacy)
    accepted.write_bytes(legacy_bytes)
    assert rfc_publish(tmp_path, local_tsa) == original
    assert len(calls) == 1
    assert accepted.read_bytes() == legacy_bytes


def test_rfc3161_matching_query_and_response_still_require_expected_manifest_digest(tmp_path, monkeypatch, local_tsa):
    from icsot_observer import attestations
    original_openssl = attestations._openssl

    def substitute_wrong_query(binary, arguments, timeout):
        # A saved query/receipt pair can agree with each other yet refer to a
        # different manifest. The independent digest check must catch this.
        if arguments[:2] == ["ts", "-query"]:
            arguments = list(arguments)
            arguments[arguments.index("-digest") + 1] = "f" * 64
        return original_openssl(binary, arguments, timeout)

    monkeypatch.setattr(attestations, "_openssl", substitute_wrong_query)
    mock_tsa(monkeypatch, local_tsa)
    with pytest.raises(RFC3161Error, match="OpenSSL"):
        rfc_publish(tmp_path, local_tsa)
    assert not list((tmp_path / "rfc3161").glob("*.accepted.json"))


@pytest.mark.parametrize("wrong_digest", [False, True])
def test_rfc3161_rejects_validly_signed_different_nonce_or_digest_and_retains_raw_attempt(
        tmp_path, monkeypatch, local_tsa, wrong_digest):
    query = local_tsa["query"]("f" * 64 if wrong_digest else SUBJECT)
    mock_tsa(monkeypatch, local_tsa, query_override=query)
    with pytest.raises(RFC3161Error, match="OpenSSL"):
        rfc_publish(tmp_path, local_tsa)
    assert list((tmp_path / "rfc3161").glob("*.tsq"))
    assert list((tmp_path / "rfc3161").glob("*.tsr"))
    assert list((tmp_path / "rfc3161").glob("*.attempt.json"))
    assert not list((tmp_path / "rfc3161").glob("*.accepted.json"))


def test_rfc3161_embedded_certificates_do_not_supply_a_trusted_root(tmp_path, monkeypatch, local_tsa):
    mock_tsa(monkeypatch, local_tsa)
    with pytest.raises(RFC3161Error, match="OpenSSL"):
        rfc_publish(tmp_path, local_tsa, ca_file=local_tsa["wrong_root"])
    assert not list((tmp_path / "rfc3161").glob("*.accepted.json"))


def test_rfc3161_saved_query_cannot_rebind_subject_via_accepted_metadata(tmp_path, monkeypatch, local_tsa):
    mock_tsa(monkeypatch, local_tsa)
    result = rfc_publish(tmp_path, local_tsa)
    directory = tmp_path / "rfc3161"
    receipt = directory / result["proof_asset"]["name"]
    receipt.write_bytes(b"tampered signed receipt")
    with pytest.raises(RFC3161Error, match="byte/hash binding"):
        rfc_publish(tmp_path, local_tsa)


def test_rfc3161_response_limit_fails_without_accepting_partial_bytes(tmp_path, monkeypatch, local_tsa):
    mock_tsa(monkeypatch, local_tsa, response_override=b"x" * 65)
    with pytest.raises(RFC3161Error, match="size limit"):
        rfc_publish(tmp_path, local_tsa, max_response_bytes=64)
    assert list((tmp_path / "rfc3161").glob("*.tsq"))
    assert not list((tmp_path / "rfc3161").glob("*.tsr"))
    assert not list((tmp_path / "rfc3161").glob("*.accepted.json"))


@pytest.mark.parametrize("endpoint", ["file:///tmp/test", "https://user:pass@example.invalid",
                                      "https://example.invalid/?token=secret", "https://example.invalid/#fragment"])
def test_rfc3161_rejects_endpoints_with_credentials_or_unsafe_schemes(tmp_path, endpoint):
    with pytest.raises(ValueError, match="explicit public HTTP"):
        publish_rfc3161_attestation(tmp_path, manifest_sha256=SUBJECT, observation_started_at=START,
                                   observation_finished_at=FINISH, endpoint=endpoint, ca_file=tmp_path / "absent.pem")
