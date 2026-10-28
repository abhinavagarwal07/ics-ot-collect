"""Publish immutable OTS and configured RFC 3161 attestation evidence.

The optional ``opentimestamps`` library is installed by the pinned
``opentimestamps-client==0.7.2`` CLI dependency. Its complete detached-file
deserializer, rather than a header or an ``ots info`` text search, validates the
receipt and the embedded subject digest without contacting calendars or reading
Bitcoin credentials. The separately configured RFC 3161 helper submits only a
digest query and verifies the result against explicitly supplied trust roots.
"""
from __future__ import annotations

import io
import base64
import json
import random
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .core import canonical_json, sha256, utc_iso, write_once


MAX_RECEIPT_BYTES = 16 * 1024 * 1024


class AttestationDependencyError(RuntimeError):
    """Receipt validation needs the optional supported OpenTimestamps library."""


class RFC3161Error(RuntimeError):
    """A configured RFC 3161 request or trust verification did not succeed."""


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _utc(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an explicit timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an explicit timezone-aware timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must be an explicit timezone-aware timestamp")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def inspect_ots_receipt(contents: bytes, manifest_sha256: str) -> dict[str, Any]:
    """Validate a whole detached receipt and its SHA-256 subject, fully offline.

    A Bitcoin block-header attestation is still unverified here: its presence
    does not establish that it matches an independently validated blockchain.
    """
    _sha256(manifest_sha256, "manifest_sha256")
    if not isinstance(contents, bytes) or not 0 < len(contents) <= MAX_RECEIPT_BYTES:
        raise ValueError("OpenTimestamps receipt is empty or exceeds the size limit")
    try:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import DeserializationError, StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except ImportError as error:
        raise AttestationDependencyError(
            "OpenTimestamps receipt validation requires opentimestamps-client==0.7.2"
        ) from error
    try:
        detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(contents)))
    except (DeserializationError, ValueError, TypeError, RecursionError) as error:
        raise ValueError("Invalid OpenTimestamps detached receipt") from error
    if type(detached.file_hash_op) is not OpSHA256:
        raise ValueError("OpenTimestamps receipt subject must use SHA-256")
    if detached.file_digest.hex() != manifest_sha256:
        raise ValueError("OpenTimestamps receipt subject does not match manifest_sha256")
    calendars: set[str] = set()
    bitcoin_heights: set[int] = set()
    unknown_types: set[str] = set()
    for _, attestation in detached.timestamp.all_attestations():
        if isinstance(attestation, PendingAttestation):
            calendars.add(attestation.uri)
        elif isinstance(attestation, BitcoinBlockHeaderAttestation):
            bitcoin_heights.add(attestation.height)
        else:
            unknown_types.add(type(attestation).__name__)
    if bitcoin_heights:
        status = "bitcoin_attestation_unverified"
    elif calendars:
        status = "pending_bitcoin_completion"
    else:
        status = "unrecognized_attestation_unverified"
    try:
        library_version = version("opentimestamps")
    except PackageNotFoundError:
        library_version = "unknown"
    return {
        "status": status,
        "provider": {"protocol": "OpenTimestamps", "calendar_urls": sorted(calendars)},
        "subject_binding": {"status": "matched", "hash_algorithm": "sha256",
                            "validator": "opentimestamps", "validator_version": library_version},
        "bitcoin_block_heights": sorted(bitcoin_heights),
        "unrecognized_attestation_types": sorted(unknown_types),
    }


def _immutable_asset(directory: Path, name: str, contents: bytes) -> dict[str, Any]:
    # Names are generated from validated digests; never accept receipt filenames
    # or paths from a detached receipt or remote calendar.
    if Path(name).name != name or not re.fullmatch(r"[a-z0-9.-]+", name):
        raise ValueError("Unsafe attestation asset filename")
    destination = directory / name
    if destination.is_symlink():
        raise ValueError("Attestation asset must not be a symlink")
    try:
        write_once(destination, contents)
    except FileExistsError:
        if destination.is_symlink() or not destination.is_file() or destination.read_bytes() != contents:
            raise ValueError("Immutable attestation asset already exists with different contents")
    return {"name": name, "sha256": sha256(contents), "bytes": len(contents)}


def publish_ots_attestation(
    output_dir: Path,
    *,
    manifest_sha256: str,
    proof_path: Path,
    observation_started_at: str,
    observation_finished_at: str,
    requested_at: str | None = None,
    received_at: str | None = None,
    collected_at: str | None = None,
    receipt_kind: str = "initial",
    previous_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    """Copy a bound receipt and canonical metadata beside a public evidence index.

    Return ``metadata``, ``proof_asset`` and ``metadata_asset``. Asset descriptors
    contain only safe basenames, SHA-256 and byte counts, for use by the caller's
    public upload/index code. Repeating the same inputs and collection time is
    idempotent; existing different bytes are never overwritten.

    Unknown historical request/receipt times remain null. ``collected_at`` is
    the local acquisition/publication time of these receipt bytes, defaulting to
    the known receipt-received time or the current collector clock. Persist and
    reuse it when retrying an export. These local times do not establish a
    trusted timestamp; Bitcoin verification is deliberately a separate step.
    """
    _sha256(manifest_sha256, "manifest_sha256")
    if receipt_kind not in {"initial", "upgraded"}:
        raise ValueError("receipt_kind must be initial or upgraded")
    if previous_receipt_sha256 is not None:
        _sha256(previous_receipt_sha256, "previous_receipt_sha256")
    if (receipt_kind == "upgraded") != (previous_receipt_sha256 is not None):
        raise ValueError("Only an upgraded receipt must identify its previous receipt SHA-256")
    started = _utc(observation_started_at, "observation_started_at")
    finished = _utc(observation_finished_at, "observation_finished_at")
    requested = _utc(requested_at, "requested_at")
    received = _utc(received_at, "received_at")
    collected = _utc(collected_at, "collected_at") or received or utc_iso()
    if started is None or finished is None or started > finished:
        raise ValueError("A nondecreasing explicit observation UTC interval is required")
    if requested is not None and received is not None and requested > received:
        raise ValueError("Receipt received_at must not precede requested_at")
    proof_path, output_dir = Path(proof_path), Path(output_dir)
    if proof_path.is_symlink() or not proof_path.is_file():
        raise ValueError("OpenTimestamps proof_path must be a regular file, not a symlink")
    with proof_path.open("rb") as source:
        contents = source.read(MAX_RECEIPT_BYTES + 1)
    inspected = inspect_ots_receipt(contents, manifest_sha256)
    if output_dir.is_symlink():
        raise ValueError("Attestation output directory must not be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True)
    proof_asset = _immutable_asset(
        output_dir, f"ots-{manifest_sha256}-{sha256(contents)}.ots", contents
    )
    metadata = {
        "schema_version": 1,
        "method": "opentimestamps",
        "subject_sha256": manifest_sha256,
        "subject_kind": "collector_manifest",
        "observation_interval": {"started_at": started, "finished_at": finished,
                                 "clock": "collector_system_clock_utc"},
        "request": {"requested_at": requested, "receipt_received_at": received,
                    "clock": "collector_system_clock_utc",
                    "unknown_historical_times_are_null": True},
        "receipt_collected_at": collected,
        "receipt": {**proof_asset, "kind": receipt_kind,
                    "previous_receipt_sha256": previous_receipt_sha256},
        **inspected,
        "verification": {"status": "not_performed", "bitcoin_verified": False,
                         "requirement": "Verify against an independently validated Bitcoin Core node"},
        "limitation": "Collector UTC observation and receipt times are local clock assertions; a pending calendar receipt does not prove a Bitcoin timestamp or GitHub source authenticity.",
    }
    encoded = canonical_json(metadata)
    metadata_asset = _immutable_asset(
        output_dir, f"ots-{manifest_sha256}-{sha256(encoded)}.attestation.json", encoded
    )
    return {"metadata": metadata, "proof_asset": proof_asset, "metadata_asset": metadata_asset}


def _certificate_bundle(path: Path) -> tuple[bytes, list[str]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("RFC 3161 certificate bundle must be a regular file")
    with path.open("rb") as source:
        contents = source.read(1024 * 1024 + 1)
    certificates = re.findall(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----", contents)
    remainder = re.sub(rb"-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", b"", contents)
    if len(contents) > 1024 * 1024 or not certificates or remainder.strip():
        raise ValueError("RFC 3161 trust material must contain only PEM certificates")
    try:
        digests = [sha256(base64.b64decode(re.sub(rb"\s", b"", cert), validate=True)) for cert in certificates]
    except ValueError as error:
        raise ValueError("Invalid PEM certificate bundle") from error
    return contents, digests


def _openssl(binary: str, arguments: list[str], timeout: float) -> bytes:
    try:
        result = subprocess.run([binary, *arguments], capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RFC3161Error("OpenSSL RFC 3161 operation could not complete") from error
    if result.returncode:
        raise RFC3161Error("OpenSSL RFC 3161 verification or request operation failed")
    if len(result.stdout) > MAX_RECEIPT_BYTES:
        raise RFC3161Error("OpenSSL RFC 3161 output exceeds the size limit")
    return result.stdout


def _verify_rfc3161(binary: str, query: Path, response: Path, root: Path, chain: Path | None,
                    subject: str, timeout: float) -> None:
    # The caller's explicit root bundle is the sole trust anchor. Certificates
    # embedded by the TSA and optional intermediates are never trusted roots.
    # OpenSSL ts creates an empty store and loads only explicitly specified
    # CAfile/CApath/CAstore inputs; it has no -no-CApath/-no-CAstore switches.
    trust = ["-CAfile", str(root)]
    if chain is not None:
        trust += ["-untrusted", str(chain)]
    # Query verification checks the saved nonce and query policy. An independent
    # digest verification binds the response to the expected manifest hash.
    _openssl(binary, ["ts", "-verify", "-queryfile", str(query), "-in", str(response), *trust], timeout)
    _openssl(binary, ["ts", "-verify", "-digest", subject, "-in", str(response), *trust], timeout)


def _tsa_time(text: bytes) -> dict[str, str]:
    decoded = text.decode("utf-8", errors="replace")
    match = re.search(r"^Time stamp: (.+)$", decoded, flags=re.MULTILINE)
    if not match:
        raise RFC3161Error("Verified RFC 3161 response has no readable TSA generation time")
    raw = match.group(1).strip()
    parts = re.fullmatch(r"([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2})(\.\d+)? (\d{4}) GMT", raw)
    if not parts:
        raise RFC3161Error("Unrecognized OpenSSL TSA generation time")
    month, day, clock, fraction, year = parts.groups()
    try:
        month_number = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec").index(month) + 1
        iso = f"{year}-{month_number:02d}-{int(day):02d}T{clock}{fraction or ''}Z"
        datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError as error:
        raise RFC3161Error("Invalid TSA generation time") from error
    return {"utc": iso, "openssl_text": raw, "source": "signed_tst_info_gen_time"}


def _retained_asset(directory: Path, descriptor: dict[str, Any]) -> Path:
    name = descriptor.get("name", "")
    if not isinstance(name, str) or Path(name).name != name or not re.fullmatch(r"[a-z0-9.-]+", name):
        raise RFC3161Error("Unsafe retained RFC 3161 asset name")
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise RFC3161Error("Retained RFC 3161 asset is not a regular file")
    if path.stat().st_size != descriptor.get("bytes") or sha256(path.read_bytes()) != descriptor.get("sha256"):
        raise RFC3161Error("Retained RFC 3161 asset failed its byte/hash binding")
    return path


def _post_timestamp(request: urllib.request.Request, timeout: float, max_bytes: int,
                    attempts: int) -> bytes:
    """Bound retries and honor provider delays without extending the request budget."""
    deadline = time.monotonic() + timeout
    for number in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            with urllib.request.urlopen(request, timeout=remaining) as response:
                return response.read(max_bytes + 1)
        except urllib.error.HTTPError as error:
            if error.code not in (429, 503) or number + 1 == attempts:
                raise RFC3161Error("RFC 3161 timestamp request failed") from error
            value = error.headers.get("Retry-After") if error.headers else None
            delay = 0.0
            if value:
                try:
                    delay = float(int(value)) if value.strip().isdigit() else max(
                        0.0, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
                except (ValueError, TypeError, OverflowError):
                    delay = 0.0
            error.close()
        except (OSError, urllib.error.URLError) as error:
            if number + 1 == attempts:
                raise RFC3161Error("RFC 3161 timestamp request failed") from error
            delay = 0.0
        delay = max(1.0, delay) + random.uniform(0.05, 0.25)
        if delay >= deadline - time.monotonic():
            break
        time.sleep(delay)
    raise RFC3161Error("RFC 3161 timestamp request retry budget exhausted")


def publish_rfc3161_attestation(
    output_dir: Path,
    *,
    manifest_sha256: str,
    observation_started_at: str,
    observation_finished_at: str,
    endpoint: str,
    ca_file: Path,
    untrusted_file: Path | None = None,
    openssl_binary: str = "openssl",
    timeout_seconds: float = 35,
    max_response_bytes: int = 1024 * 1024,
    max_attempts: int = 1,
) -> dict[str, Any]:
    """Request and preserve a configured RFC 3161 timestamp for a digest only.

    ``output_dir`` must be persistent (for example proofs/rfc3161/<manifestSHA>).
    A create-only accepted record binds the endpoint and explicit trust bytes.
    Retries reverify and reuse that original receipt without another request.
    Raw requests/responses survive unsuccessful verification, but only a fully
    verified nonce, signature chain and subject imprint produce accepted metadata.

    OpenSSL 3 with ``ts`` support is required. No provider or trust root is
    selected implicitly; revocation checking is not performed by this helper.
    """
    _sha256(manifest_sha256, "manifest_sha256")
    parsed_url = urllib.parse.urlsplit(endpoint)
    if (parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc or
            parsed_url.username is not None or parsed_url.password is not None or parsed_url.query or parsed_url.fragment):
        raise ValueError("RFC 3161 endpoint must be an explicit public HTTP(S) URL without credentials, query or fragment")
    if not 0 < timeout_seconds <= 180 or not 0 < max_response_bytes <= MAX_RECEIPT_BYTES or not 1 <= max_attempts <= 3:
        raise ValueError("RFC 3161 timeout or response limit is outside the allowed bounds")
    started = _utc(observation_started_at, "observation_started_at")
    finished = _utc(observation_finished_at, "observation_finished_at")
    if started is None or finished is None or started > finished:
        raise ValueError("A nondecreasing explicit observation UTC interval is required")
    root_bytes, root_fingerprints = _certificate_bundle(Path(ca_file))
    chain_bytes, chain_fingerprints = _certificate_bundle(Path(untrusted_file)) if untrusted_file else (None, [])
    policy = {"endpoint": endpoint, "ca_bundle_sha256": sha256(root_bytes),
              "untrusted_bundle_sha256": sha256(chain_bytes) if chain_bytes is not None else None}
    output_dir = Path(output_dir)
    if output_dir.is_symlink():
        raise ValueError("Attestation output directory must not be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True)
    accepted_path = output_dir / f"rfc3161-{manifest_sha256}-{sha256(canonical_json(policy))}.accepted.json"
    root_asset = _immutable_asset(output_dir, f"rfc3161-trust-root-{sha256(root_bytes)}.pem", root_bytes)
    chain_asset = _immutable_asset(output_dir, f"rfc3161-untrusted-{sha256(chain_bytes)}.pem", chain_bytes) if chain_bytes is not None else None
    trust_assets = [root_asset] + ([chain_asset] if chain_asset is not None else [])
    root_path = output_dir / root_asset["name"]
    chain_path = output_dir / chain_asset["name"] if chain_asset is not None else None

    def retained_result() -> dict[str, Any]:
        if accepted_path.is_symlink():
            raise RFC3161Error("Accepted RFC 3161 metadata must not be a symlink")
        metadata_bytes = accepted_path.read_bytes()
        metadata = json.loads(metadata_bytes)
        if (metadata.get("subject_sha256") != manifest_sha256 or metadata.get("configuration") != policy or
                metadata.get("observation_interval") != {"started_at": started, "finished_at": finished,
                                                        "clock": "collector_system_clock_utc"} or
                metadata.get("status") != "verified_chain_and_imprint" or metadata.get("trust_assets") != trust_assets):
            raise RFC3161Error("Accepted RFC 3161 metadata does not match the requested subject, interval or trust configuration")
        query_path = _retained_asset(output_dir, metadata["request_asset"])
        response_path = _retained_asset(output_dir, metadata["receipt"])
        _verify_rfc3161(openssl_binary, query_path, response_path, root_path, chain_path, manifest_sha256, timeout_seconds)
        details_bytes = _openssl(openssl_binary, ["ts", "-reply", "-in", str(response_path), "-text"], timeout_seconds)
        if _tsa_time(details_bytes) != metadata["tsa_generation_time"]:
            raise RFC3161Error("Retained RFC 3161 generation time does not match the signed response")
        details_asset = _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(details_bytes)}.response.txt", details_bytes)
        if metadata.get("response_details_asset", details_asset) != details_asset:
            raise RFC3161Error("Retained RFC 3161 response details do not match the signed response")
        # Earlier accepted records did not include the human-readable TSTInfo.
        # Add a derived immutable metadata version without changing the original
        # accepted record, its request, receipt, or original event timestamps.
        metadata["response_details_asset"] = details_asset
        metadata.setdefault("time_accuracy", {"source": "signed_tst_info_in_response_details_asset",
                                               "unspecified_accuracy_is_zero": False})
        metadata.setdefault("signer_certificate", {"status": "retained_in_signed_response_der",
                                                    "identity_extraction": "not_performed"})
        metadata_bytes = canonical_json(metadata)
        descriptor = _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(metadata_bytes)}.attestation.json", metadata_bytes)
        return {"metadata": metadata, "request_asset": metadata["request_asset"],
                "proof_asset": metadata["receipt"], "trust_assets": trust_assets,
                "details_asset": details_asset, "metadata_asset": descriptor}

    if accepted_path.exists() or accepted_path.is_symlink():
        return retained_result()
    with tempfile.TemporaryDirectory(prefix=".rfc3161-", dir=output_dir) as temporary:
        query_path = Path(temporary) / "request.tsq"
        _openssl(openssl_binary, ["ts", "-query", "-sha256", "-digest", manifest_sha256, "-cert", "-out", str(query_path)], timeout_seconds)
        query_bytes = query_path.read_bytes()
    query_asset = _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(query_bytes)}.tsq", query_bytes)
    query_path = output_dir / query_asset["name"]
    requested = utc_iso()
    request_record = {"schema_version": 1, "subject_sha256": manifest_sha256, "configuration": policy,
                      "requested_at": requested, "request_asset": query_asset}
    request_record_bytes = canonical_json(request_record)
    _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(request_record_bytes)}.request.json", request_record_bytes)
    request = urllib.request.Request(endpoint, data=query_bytes, method="POST",
                                     headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"})
    response_bytes = _post_timestamp(request, timeout_seconds, max_response_bytes, max_attempts)
    received = utc_iso()
    if not response_bytes or len(response_bytes) > max_response_bytes:
        raise RFC3161Error("RFC 3161 response is empty or exceeds the configured size limit")
    proof_asset = _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(response_bytes)}.tsr", response_bytes)
    response_path = output_dir / proof_asset["name"]
    attempt_bytes = canonical_json({**request_record, "receipt_received_at": received, "receipt": proof_asset})
    _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(attempt_bytes)}.attempt.json", attempt_bytes)
    _verify_rfc3161(openssl_binary, query_path, response_path, root_path, chain_path, manifest_sha256, timeout_seconds)
    details_bytes = _openssl(openssl_binary, ["ts", "-reply", "-in", str(response_path), "-text"], timeout_seconds)
    generation_time = _tsa_time(details_bytes)
    details_asset = _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(details_bytes)}.response.txt", details_bytes)
    metadata = {
        "schema_version": 1, "method": "rfc3161", "status": "verified_chain_and_imprint",
        "subject_sha256": manifest_sha256, "subject_kind": "collector_manifest",
        "provider": {"endpoint": endpoint}, "configuration": policy,
        "observation_interval": {"started_at": started, "finished_at": finished, "clock": "collector_system_clock_utc"},
        "request": {"requested_at": requested, "receipt_received_at": received, "clock": "collector_system_clock_utc"},
        "receipt_collected_at": received, "tsa_generation_time": generation_time,
        "response_details_asset": details_asset,
        "time_accuracy": {"source": "signed_tst_info_in_response_details_asset", "unspecified_accuracy_is_zero": False},
        "signer_certificate": {"status": "retained_in_signed_response_der", "identity_extraction": "not_performed"},
        "request_asset": query_asset, "receipt": proof_asset, "trust_assets": trust_assets,
        "trust": {"source": "explicit_configured_ca_bundle", "ca_certificate_der_sha256": root_fingerprints,
                  "untrusted_certificate_der_sha256": chain_fingerprints},
        "verification": {"status": "verified_chain_and_imprint", "verified_at": utc_iso(),
                         "nonce_and_query_verified": True, "subject_imprint_verified": True,
                         "certificate_chain_verified": True, "revocation": "not_performed",
                         "openssl_version": _openssl(openssl_binary, ["version"], timeout_seconds).decode("utf-8", errors="replace").strip()},
        "limitation": "TSA generation time is signed by the configured authority; collector observation times remain local clock assertions and do not prove GitHub source authenticity. Revocation was not checked.",
    }
    metadata_bytes = canonical_json(metadata)
    metadata_asset = _immutable_asset(output_dir, f"rfc3161-{manifest_sha256}-{sha256(metadata_bytes)}.attestation.json", metadata_bytes)
    try:
        write_once(accepted_path, metadata_bytes)
    except FileExistsError:
        return retained_result()  # A concurrent successful first receipt wins.
    return {"metadata": metadata, "request_asset": query_asset, "proof_asset": proof_asset,
            "trust_assets": trust_assets, "details_asset": details_asset, "metadata_asset": metadata_asset}
