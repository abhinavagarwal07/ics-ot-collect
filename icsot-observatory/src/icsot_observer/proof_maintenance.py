"""Bounded public OTS refresh, independent of collection and encrypted state.

``collector-attestations:state.json`` stores the discovery cursor and pending
queue; per-catalog/per-proof Git files retain metadata history. Immutable Release assets are uploaded before
a non-forced branch CAS; failed CAS attempts leave safe, reusable orphan assets.
Release ordering and numeric IDs are not used as an exclusion high-water mark:
page one plus a durable, bounded rolling scan eventually finds older-positioned
new releases too. Unmarked releases remain an explicit retry backlog.
"""
from __future__ import annotations

import argparse
import base64
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import Any, Callable

from .attestations import MAX_RECEIPT_BYTES, inspect_ots_receipt, publish_ots_attestation
from .core import canonical_json, sha256, utc_iso
from .github_state import GhCliStateTransport, StateConflictError, StateDeferredError, StateError

BRANCH = "collector-attestations"
MARKER = "metadata-catalog.json"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_INCOMPLETE_RELEASES = 4096
HASH = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
OBSERVATION = re.compile(r"collector-observations-r[1-9][0-9]*-g[0-9a-f]{32}\Z")


def _json(raw: bytes) -> dict:
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Public timestamp metadata exceeds size limit")
    obj = json.loads(raw)
    if not isinstance(obj, dict) or canonical_json(obj) != raw:
        raise ValueError("Public timestamp metadata must be a canonical JSON object")
    return obj


def _ref(ref: Any) -> dict:
    if not isinstance(ref, dict) or any(not isinstance(ref.get(k), str) or
            not NAME.fullmatch(ref[k]) for k in ("release_tag", "name")):
        raise ValueError("Invalid immutable public asset name")
    if not isinstance(ref.get("sha256"), str) or not HASH.fullmatch(ref["sha256"]) or \
            type(ref.get("bytes")) is not int or not 0 < ref["bytes"] <= MAX_RECEIPT_BYTES:
        raise ValueError("Invalid immutable public asset digest or size")
    return {k: ref[k] for k in ("release_tag", "name", "sha256", "bytes")}


def empty_state() -> dict:
    return {"schema_version": 1, "discovery": {"historical_page": 2, "completed_cycles": 0,
            "recent_release_ids": [], "incomplete_releases": []}, "pending": {}}


class ProofTransport(GhCliStateTransport):
    """Rate-aware GH_TOKEN writes; no source PAT substitution or state-key use."""

    def load(self) -> tuple[str | None, dict]:
        ref = self._api(f"repos/{self.repository}/git/ref/heads/{BRANCH}", missing_ok=True)
        head = ref["object"]["sha"] if ref else None
        raw = self._read_git_file(head, "state.json") if head else None
        if head is not None and raw is None:
            raise StateError("Established public proof branch is missing state.json")
        state = _json(raw) if raw is not None else empty_state()
        if state.get("schema_version") != 1 or not isinstance(state.get("pending"), dict) or \
                not isinstance(state.get("discovery"), dict):
            raise ValueError("Unsupported public proof queue")
        return head, state

    def record(self, head: str | None, path: str) -> bytes | None:
        if not re.fullmatch(r"(?:catalogs|proofs)/[0-9a-f]{64}\.json", path):
            raise ValueError("Invalid public proof record path")
        return self._read_git_file(head, path) if head else None

    def save(self, parent: str | None, state: dict, records: dict[str, bytes] | None = None) -> str:
        raw = canonical_json(state)
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("Public proof queue exceeds supported size")
        blob = self._api(f"repos/{self.repository}/git/blobs", method="POST", payload={
            "content": base64.b64encode(raw).decode(), "encoding": "base64"})
        tree_payload = {"tree": [{"path": "state.json", "mode": "100644", "type": "blob", "sha": blob["sha"]}]}
        for path, contents in (records or {}).items():
            previous = self.record(parent, path)
            if path.startswith("catalogs/") and previous is not None and previous != contents:
                raise ValueError("Immutable catalog registration differs")
            if previous == contents:
                continue
            item = self._api(f"repos/{self.repository}/git/blobs", method="POST", payload={
                "content": base64.b64encode(contents).decode(), "encoding": "base64"})
            tree_payload["tree"].append({"path": path, "mode": "100644", "type": "blob", "sha": item["sha"]})
        if parent:
            previous = self._api(f"repos/{self.repository}/git/commits/{parent}")
            tree_payload["base_tree"] = previous["tree"]["sha"]
        tree = self._api(f"repos/{self.repository}/git/trees", method="POST", payload=tree_payload)
        commit = self._api(f"repos/{self.repository}/git/commits", method="POST", payload={
            "message": "Append public timestamp evidence and refresh pending queue",
            "tree": tree["sha"], "parents": [parent] if parent else []})["sha"]
        current, _ = self.load()
        if current != parent:
            raise StateConflictError("Public proof queue changed concurrently")
        try:
            if parent is None:
                self._api(f"repos/{self.repository}/git/refs", method="POST", payload={
                    "ref": f"refs/heads/{BRANCH}", "sha": commit})
            else:
                self._api(f"repos/{self.repository}/git/refs/heads/{BRANCH}", method="PATCH",
                          payload={"sha": commit, "force": False})
        except StateDeferredError:
            raise
        except StateError as error:
            # Never blindly retry a write. The next run rereads authoritative state.
            raise StateConflictError("Public proof queue CAS was not acknowledged") from error
        return commit

    def releases(self, page: int, per_page: int) -> list[dict]:
        result = self._api(f"repos/{self.repository}/releases?per_page={per_page}&page={page}")
        if not isinstance(result, list):
            raise ValueError("Invalid release discovery page")
        return result

    def ensure_release(self, tag: str) -> None:
        if not NAME.fullmatch(tag):
            raise ValueError("Invalid public proof Release tag")
        if tag in self._releases:
            return
        release = self._api(f"repos/{self.repository}/releases/tags/{tag}", missing_ok=True)
        new = release is None
        if new:
            release = self._api(f"repos/{self.repository}/releases", method="POST", payload={
                "tag_name": tag, "prerelease": True, "name": tag,
                "body": "Public immutable timestamp receipts and metadata. Retain original and upgraded proofs."})
        if not isinstance(release, dict) or type(release.get("id")) is not int:
            raise ValueError("Invalid public proof Release response")
        self._releases[tag] = release
        self._assets[tag] = {asset["name"]: asset for asset in release.get("assets", [])}
        if new:
            self._listed.add(tag)

    def marker(self, tag: str) -> bytes | None:
        # Markers are uploaded last. A missing marker is retryable, never complete.
        release = self._api(f"repos/{self.repository}/releases/tags/{tag}", missing_ok=True)
        if release is None:
            return None
        matches = [a for a in release.get("assets", []) if a.get("name") == MARKER]
        if not matches:
            # Release responses may truncate assets; use the bounded existing pager.
            self._releases[tag] = release
            self._assets[tag] = {a["name"]: a for a in release.get("assets", [])}
            try:
                asset = self._asset(tag, MARKER)
            except StateDeferredError:
                raise
            except StateError:
                return None
        elif len(matches) == 1:
            asset = matches[0]
        else:
            raise ValueError("Ambiguous public metadata marker")
        if type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_JSON_BYTES:
            raise ValueError("Public metadata marker exceeds size limit")
        raw = self._run(["api", f"repos/{self.repository}/releases/assets/{asset['id']}",
                         "--method", "GET", "-H", "Accept: application/octet-stream"])
        if len(raw) != asset["size"]:
            raise ValueError("Public metadata marker size mismatch")
        return raw

    def fetch(self, ref: dict) -> bytes:
        ref = _ref(ref)
        asset = self._asset(ref["release_tag"], ref["name"])
        if asset.get("size") != ref["bytes"]:
            raise ValueError("Public timestamp asset advertised size mismatch")
        with tempfile.TemporaryDirectory(prefix="icsot-public-proof-read-") as directory:
            target = Path(directory) / ref["name"]
            self.download_asset(ref["release_tag"], ref["name"], target)
            with target.open("rb") as source:
                raw = source.read(ref["bytes"] + 1)
        if len(raw) != ref["bytes"] or sha256(raw) != ref["sha256"]:
            raise ValueError("Public timestamp asset digest or size mismatch")
        return raw

    def publish(self, ref: dict, raw: bytes) -> None:
        ref = _ref(ref)
        if len(raw) != ref["bytes"] or sha256(raw) != ref["sha256"]:
            raise ValueError("Publication bytes differ from immutable descriptor")
        self.ensure_release(ref["release_tag"])
        try:
            asset = self._asset(ref["release_tag"], ref["name"])
        except StateDeferredError:
            raise
        except StateError:
            asset = None
        if asset is not None:
            if self.fetch(ref) != raw:
                raise ValueError("Immutable public asset has conflicting contents")
            return
        with tempfile.TemporaryDirectory(prefix="icsot-public-proof-upload-") as directory:
            source = Path(directory) / ref["name"]
            source.write_bytes(raw)
            self.upload_asset(ref["release_tag"], ref["name"], source)
        # Read back before a reference becomes authoritative.
        if self.fetch(ref) != raw:
            raise ValueError("Public proof upload was not verified")


class OtsClient:
    def __init__(self, *, runner: Callable = subprocess.run, timeout: float = 75):
        self.runner, self.timeout = runner, timeout

    def upgrade(self, raw: bytes, subject: str) -> bytes:
        inspect_ots_receipt(raw, subject)
        if version("opentimestamps-client") != "0.7.2":
            raise RuntimeError("Proof maintenance requires opentimestamps-client==0.7.2")
        with tempfile.TemporaryDirectory(prefix="icsot-upgrade-") as directory:
            path = Path(directory) / "receipt.ots"
            path.write_bytes(raw)
            try:
                # Only the private copy is mutated. No --wait, BTC wallet or cache.
                result = self.runner([sys.executable, "-c", "from otsclient.ots import main; main()",
                                      "--no-cache", "--no-bitcoin", "upgrade", str(path)],
                                     capture_output=True, timeout=self.timeout, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise RuntimeError("OpenTimestamps upgrade did not complete") from error
            # CLI exit 1 also means a valid but still incomplete partial upgrade.
            # Preserve such proof bytes after independently parsing their subject.
            with path.open("rb") as source:
                upgraded = source.read(MAX_RECEIPT_BYTES + 1)
            inspect_ots_receipt(upgraded, subject)
            if result.returncode and upgraded == raw:
                raise RuntimeError("OpenTimestamps upgrade deferred or failed")
            return upgraded


class _RejectRpcRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise RuntimeError("Trusted Bitcoin RPC redirects are not permitted")


class BitcoinCoreVerifier:
    """Use only an explicitly configured trusted Bitcoin Core RPC, never explorers.

    The optional environment secret is JSON {url,user,password}. Credentials are
    used only in an HTTP Authorization header and never returned in metadata.
    The operator is responsible for the node's independently validated chain.
    """
    def __init__(self, configuration: str, *, timeout: float = 15, opener: Callable | None = None):
        try:
            settings = json.loads(configuration)
        except (ValueError, TypeError):
            raise ValueError("Trusted Bitcoin RPC configuration must be a JSON object") from None
        if not isinstance(settings, dict) or any(not isinstance(settings.get(key, ""), str)
                                                 for key in ("url", "user", "password")):
            raise ValueError("Trusted Bitcoin RPC URL and credentials must be strings")
        url = settings.get("url", "")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or \
                parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Trusted Bitcoin RPC requires a plain HTTP(S) endpoint URL")
        self.url, self.timeout = url, timeout
        self.opener = opener or urllib.request.build_opener(_RejectRpcRedirect()).open
        self.auth = base64.b64encode((settings.get("user", "") + ":" + settings.get("password", "")).encode()).decode()

    def _rpc(self, method: str, params: list) -> Any:
        request = urllib.request.Request(self.url, data=canonical_json({"jsonrpc": "1.0", "id": "icsot",
            "method": method, "params": params}), headers={"Content-Type": "application/json",
            "Authorization": "Basic " + self.auth})
        try:
            with self.opener(request, timeout=self.timeout) as response:
                raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Oversized RPC response")
            result = json.loads(raw)
            if result.get("error") is not None:
                raise ValueError("RPC rejected verification request")
            return result["result"]
        except Exception as error:
            # Upstream exceptions can contain URLs or credentials; never expose them.
            raise RuntimeError("Trusted Bitcoin Core RPC verification failed") from None

    def verify(self, raw: bytes, subject: str) -> dict:
        inspect_ots_receipt(raw, subject)
        from bitcoin.core import CBlockHeader, b2lx
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
        chain = self._rpc("getblockchaininfo", [])
        if chain.get("chain") != "main" or chain.get("initialblockdownload") is not False:
            raise RuntimeError("Trusted Bitcoin Core is not synchronized to mainnet")
        detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(raw)))
        for message, attestation in detached.timestamp.all_attestations():
            if not isinstance(attestation, BitcoinBlockHeaderAttestation):
                continue
            if type(chain.get("blocks")) is not int or chain["blocks"] < attestation.height:
                continue
            blockhash = self._rpc("getblockhash", [attestation.height])
            encoded = self._rpc("getblockheader", [blockhash, False])
            try:
                header = CBlockHeader.deserialize(bytes.fromhex(encoded))
                if b2lx(header.GetHash()) != blockhash:
                    raise ValueError("RPC block hash mismatch")
                timestamp = attestation.verify_against_blockheader(message, header)
            except Exception:
                raise RuntimeError("Bitcoin attestation does not match trusted RPC header") from None
            return {"status": "verified", "bitcoin_verified": True, "method": "trusted_bitcoin_core_rpc",
                    "chain": "main", "block_height": attestation.height, "block_hash": blockhash,
                    "verified_at": utc_iso(),
                    "attested_at": datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")}
        raise RuntimeError("No Bitcoin attestation was verified by trusted RPC")


def _enqueue_marker(state: dict, marker: dict, tag: str, transport: Any, now: str,
                    head: str | None) -> tuple[dict[str, bytes], list[str]]:
    if marker.get("schema_version") != 1 or marker.get("kind") != "icsot_evidence_metadata_catalog" or \
            marker.get("generation_release") != tag or not isinstance(marker.get("observations"), list):
        raise ValueError("Invalid observation completion marker")
    records = {}
    proof_keys = []
    for observation in marker["observations"]:
        index_ref = _ref(observation["index"])
        if index_ref["release_tag"] != tag or not index_ref["name"].endswith(".index.json"):
            raise ValueError("Completion marker index names another release")
        index = _json(transport.fetch(index_ref))
        evidence = index.get("timestamp_evidence", {}).get("opentimestamps", {})
        if "metadata" not in evidence:
            continue
        subject = index.get("manifest_sha256")
        if not isinstance(subject, str) or not HASH.fullmatch(subject) or observation.get("manifest_sha256") != subject:
            raise ValueError("Completion marker manifest subject mismatch")
        metadata_ref = _ref({"release_tag": tag, **evidence["metadata_asset"]})
        proof_ref = _ref({"release_tag": tag, **evidence["proof_asset"]})
        metadata = _json(transport.fetch(metadata_ref))
        if metadata != evidence["metadata"] or metadata.get("subject_sha256") != subject or \
                any(metadata.get("receipt", {}).get(k) != proof_ref[k] for k in ("name", "sha256", "bytes")):
            raise ValueError("Public proof metadata subject or receipt differs from index")
        key = metadata_ref["sha256"]
        proof_keys.append(key)
        prior = transport.record(head, f"proofs/{key}.json")
        if prior is not None:
            previous = _json(prior)
            history = previous.get("history", [])
            if previous.get("subject_sha256") != subject or not history or \
                    any(history[0].get("metadata", {}).get(k) != metadata_ref[k] for k in ("sha256", "bytes")) or \
                    history[0].get("proof", {}).get("sha256") != proof_ref["sha256"]:
                raise ValueError("Initial proof registration differs from retained history")
            continue
        # Initial public metadata never substitutes for our configured RPC check.
        if key not in state["pending"]:
            state["pending"][key] = {"subject_sha256": subject, "proof": proof_ref, "metadata": metadata_ref,
                "status": metadata["status"], "discovered_at": now, "attempts": 0, "next_attempt_after": 0}
        records[f"proofs/{key}.json"] = canonical_json({"schema_version": 1, "subject_sha256": subject,
            "history": [{"proof": proof_ref, "metadata": metadata_ref, "status": metadata["status"]}]})
    if len(state["pending"]) > 4096:
        raise ValueError("Public proof queue capacity reached; registration must be retried")
    return records, sorted(set(proof_keys))


def _register_loaded(transport: Any, head: str | None, state: dict, ref: dict,
                     raw: bytes | None = None) -> tuple[dict[str, bytes], bool]:
    ref = _ref(ref)
    key = ref["sha256"]
    path = f"catalogs/{key}.json"
    existing = transport.record(head, path)
    if existing is not None:
        if _json(existing).get("catalog") != ref:
            raise ValueError("Immutable catalog registration differs")
        return {}, False
    raw = transport.fetch(ref) if raw is None else raw
    if sha256(raw) != ref["sha256"] or len(raw) != ref["bytes"]:
        raise ValueError("Catalog registration bytes differ from verified descriptor")
    trial = copy.deepcopy(state)
    records, proof_keys = _enqueue_marker(trial, _json(raw), ref["release_tag"], transport, utc_iso(), head)
    state["pending"] = trial["pending"]
    records[path] = canonical_json({"schema_version": 1, "catalog": ref,
        "proof_keys": proof_keys})
    return records, True


def register_catalog(transport: Any, ref: dict) -> dict:
    """Durably register a remotely verified completion marker before state CAS.

    Accept a normal ``GhCliStateTransport`` or ``ProofTransport`` and a public
    descriptor {release_tag,name,sha256,bytes}. No encrypted state is inspected.
    Registration is idempotent, retries only branch conflicts (at most three),
    and raises on rate deferral so the collector keeps its old selected state.
    """
    original_transport = None
    if isinstance(transport, GhCliStateTransport) and not isinstance(transport, ProofTransport):
        original_transport = transport
        transport = ProofTransport(transport.repository, runner=transport.runner,
            rate_reserve=transport.rate_reserve, transient_retries=transport.transient_retries,
            clock=transport.clock)
        original_transport.copy_runtime_state_to(transport)
    try:
        ref = _ref(ref)
        for attempt in range(3):
            head, state = transport.load()
            records, added = _register_loaded(transport, head, state, ref)
            if not added:
                return {"status": "already_registered", "catalog_key": ref["sha256"], "pending_proofs": len(state["pending"])}
            try:
                transport.save(head, state, records)
                return {"status": "registered", "catalog_key": ref["sha256"], "pending_proofs": len(state["pending"])}
            except StateConflictError:
                if attempt == 2:
                    raise
        raise StateConflictError("Catalog registration conflict bound reached")
    finally:
        if original_transport is not None:
            transport.copy_runtime_state_to(original_transport)


def requeue_catalog(transport: Any, catalog_sha256: str, *, max_proofs: int = 128,
                    after_proof_key: str | None = None) -> dict:
    """Explicit bounded RPC backfill for a retained catalog, with a resume cursor.

    Call only when a trusted verifier is configured. Completed unverified proofs
    stay archived until this operator action; enabling RPC alone does not scan
    all historical receipts. Nothing is decrypted or recollected.
    """
    if not HASH.fullmatch(catalog_sha256) or not 1 <= max_proofs <= 512 or \
            (after_proof_key is not None and not HASH.fullmatch(after_proof_key)):
        raise ValueError("Invalid bounded catalog requeue policy")
    head, state = transport.load()
    raw = transport.record(head, f"catalogs/{catalog_sha256}.json")
    if raw is None:
        raise ValueError("Requested public timestamp catalog is not registered")
    catalog = _json(raw)
    keys = sorted(k for k in catalog["proof_keys"] if after_proof_key is None or k > after_proof_key)
    selected, queued = keys[:max_proofs], 0
    for key in selected:
        if not isinstance(key, str) or not HASH.fullmatch(key):
            raise ValueError("Registered catalog has an invalid proof key")
        raw = transport.record(head, f"proofs/{key}.json")
        if raw is None:
            raise StateError("Registered catalog proof history is missing")
        record = _json(raw)
        if record.get("maintenance_status") != "awaiting_trusted_rpc" or key in state["pending"]:
            continue
        latest = record["history"][-1]
        state["pending"][key] = {"subject_sha256": record["subject_sha256"],
            "proof": _ref(latest["proof"]), "metadata": _ref(latest["metadata"]),
            "status": latest["status"], "discovered_at": utc_iso(), "attempts": 0,
            "next_attempt_after": 0, "operator_requested_rpc_backfill": True}
        queued += 1
    if len(state["pending"]) > 4096:
        raise ValueError("Public proof queue capacity reached; requeue must be retried")
    if queued:
        transport.save(head, state)
    return {"catalog_key": catalog_sha256, "proofs_requeued": queued,
            "proofs_remaining_to_inspect": max(0, len(keys) - len(selected)),
            "next_after_proof_key": selected[-1] if len(keys) > len(selected) else None}


def refresh(transport: Any, *, client: OtsClient | None = None, verifier: BitcoinCoreVerifier | None = None,
            max_proofs: int = 128, max_pages: int = 2, page_size: int = 30, max_markers: int = 12,
            runtime_seconds: float = 1200, clock: Callable = time.time) -> dict:
    """Checkpoint discovery and every proof; return explicit bounded/backlog counts."""
    if not 1 <= max_proofs <= 512 or not 1 <= max_pages <= 10 or not 1 <= page_size <= 100 or \
            not 1 <= max_markers <= 100 or not 1 <= runtime_seconds <= 1500:
        raise ValueError("Invalid bounded proof refresh policy")
    client = client or OtsClient()
    started = clock()
    report = {"schema_version": 1, "status": "complete", "proofs_attempted": 0, "proofs_changed": 0,
              "proofs_verified": 0, "proofs_deferred": 0, "discovery_pages": 0, "markers_processed": 0,
              "proofs_awaiting_trusted_rpc_archived": 0, "discovery_paused_at_capacity": False}
    head, state = transport.load()
    committed_state = copy.deepcopy(state)
    try:
        if hasattr(transport, "publication_budget"):
            transport.publication_budget(30 + max_markers * 8 + min(max_proofs, 8) * 22)
        original = canonical_json(state)
        discovery = state["discovery"]
        # A recent page plus a persistent rolling historical cursor. IDs dedupe,
        # but never determine whether subsequent pages may contain new releases.
        seen = set(discovery["recent_release_ids"])
        registration_records = {}
        queued = {item["id"] for item in discovery["incomplete_releases"]}
        for step in range(max_pages):
            if clock() - started >= runtime_seconds:
                break
            page = 1 if step == 0 else discovery["historical_page"]
            releases = transport.releases(page, page_size)
            report["discovery_pages"] += 1
            for release in releases:
                tag, identifier = release.get("tag_name", ""), release.get("id")
                if isinstance(tag, str) and OBSERVATION.fullmatch(tag) and type(identifier) is int and \
                        identifier not in seen and identifier not in queued:
                    if len(discovery["incomplete_releases"]) >= MAX_INCOMPLETE_RELEASES:
                        report["discovery_paused_at_capacity"] = True
                        break
                    discovery["incomplete_releases"].append({"id": identifier, "tag": tag})
                    queued.add(identifier)
            if report["discovery_paused_at_capacity"]:
                # Preserve the cursor at this page so no unrecorded release is
                # skipped. Existing queued proofs still drain below.
                break
            if step > 0:
                if len(releases) < page_size:
                    discovery["historical_page"] = 2
                    discovery["completed_cycles"] += 1
                else:
                    discovery["historical_page"] = page + 1
        # Queue rotation keeps permanently unmarked releases from starving peers.
        for _ in range(min(max_markers, len(discovery["incomplete_releases"]))):
            if clock() - started >= runtime_seconds:
                break
            candidate = discovery["incomplete_releases"].pop(0)
            try:
                raw = transport.marker(candidate["tag"])
                if raw is None:
                    discovery["incomplete_releases"].append(candidate)
                    continue
                records, added = _register_loaded(transport, head, state,
                    {"release_tag": candidate["tag"], "name": MARKER, "sha256": sha256(raw), "bytes": len(raw)}, raw)
                registration_records.update(records)
            except StateDeferredError:
                discovery["incomplete_releases"].insert(0, candidate)
                raise
            except (ValueError, KeyError, TypeError):
                candidate["last_error"] = "invalid_public_metadata"
                discovery["incomplete_releases"].append(candidate)
                continue
            seen.add(candidate["id"])
            report["markers_processed"] += 1
        # A bounded acceleration cache only. Per-catalog Git files retain history.
        discovery["recent_release_ids"] = sorted(seen)[-512:]
        if canonical_json(state) != original or registration_records:
            head = transport.save(head, state, registration_records)
            committed_state = copy.deepcopy(state)
        # Oldest attempted items rotate on each durable checkpoint, including failures.
        ready = sorted((key for key, item in state["pending"].items() if item["next_attempt_after"] <= clock()),
                       key=lambda k: (state["pending"][k].get("last_attempt_at", 0), k))
        for key in ready[:max_proofs]:
            if clock() - started >= runtime_seconds:
                report["status"] = "bounded"
                break
            entry = state["pending"][key]
            if entry["next_attempt_after"] > clock():
                continue
            report["proofs_attempted"] += 1
            entry["attempts"] += 1
            entry["last_attempt_at"] = clock()
            entry["next_attempt_after"] = clock() + 3600
            try:
                metadata = _json(transport.fetch(entry["metadata"]))
                raw = transport.fetch(entry["proof"])
                before = inspect_ots_receipt(raw, entry["subject_sha256"])
                if metadata.get("subject_sha256") != entry["subject_sha256"] or \
                        any(metadata.get("receipt", {}).get(k) != entry["proof"][k] for k in ("name", "sha256", "bytes")):
                    raise ValueError("Queued proof metadata binding mismatch")
                # Existing Bitcoin attestations can be checked directly. Their
                # residual calendar URIs must not make RPC backfill depend on a
                # calendar or on another successful CLI invocation.
                upgraded = client.upgrade(raw, entry["subject_sha256"]) if (
                    before["provider"]["calendar_urls"] and not before["bitcoin_block_heights"]) else raw
                inspected = inspect_ots_receipt(upgraded, entry["subject_sha256"])
                verification = {"status": "not_performed", "bitcoin_verified": False,
                                "requirement": "Configure an independently validated trusted Bitcoin Core RPC"}
                if verifier is not None and inspected["bitcoin_block_heights"]:
                    try:
                        verification = verifier.verify(upgraded, entry["subject_sha256"])
                    except RuntimeError:
                        verification["status"] = "trusted_rpc_verification_failed"
                status = "bitcoin_verified" if verification["bitcoin_verified"] else inspected["status"]
                changed = upgraded != raw or status != entry["status"]
                if changed:
                    with tempfile.TemporaryDirectory(prefix="icsot-public-upgraded-") as directory:
                        proof = Path(directory) / "new.ots"
                        proof.write_bytes(upgraded)
                        interval, request = metadata["observation_interval"], metadata["request"]
                        result = publish_ots_attestation(Path(directory) / "public",
                            manifest_sha256=entry["subject_sha256"], proof_path=proof,
                            observation_started_at=interval["started_at"], observation_finished_at=interval["finished_at"],
                            requested_at=request["requested_at"], received_at=request["receipt_received_at"],
                            receipt_kind="upgraded", previous_receipt_sha256=entry["proof"]["sha256"], collected_at=utc_iso())
                        new_metadata = result["metadata"]
                        new_metadata["status"], new_metadata["verification"] = status, verification
                        new_metadata["previous_metadata_sha256"] = entry["metadata"]["sha256"]
                        prepared = entry.get("prepared_metadata")
                        if prepared is not None and prepared.get("receipt", {}).get("sha256") == sha256(upgraded) and \
                                prepared.get("previous_metadata_sha256") == entry["metadata"]["sha256"] and \
                                prepared.get("status") == status:
                            new_metadata = prepared
                        else:
                            # Freeze acquisition metadata before uploads, so an
                            # interrupted write/CAS reuses the exact asset names.
                            entry["prepared_metadata"] = new_metadata
                            head = transport.save(head, state)
                            committed_state = copy.deepcopy(state)
                        encoded = canonical_json(new_metadata)
                        tag = "collector-attestations-" + entry["subject_sha256"][:32]
                        proof_ref = {"release_tag": tag, **result["proof_asset"]}
                        metadata_ref = {"release_tag": tag, "name": f"ots-{entry['subject_sha256']}-{sha256(encoded)}.attestation.json",
                                        "sha256": sha256(encoded), "bytes": len(encoded)}
                        transport.publish(proof_ref, upgraded)
                        transport.publish(metadata_ref, encoded)
                    entry.update(proof=proof_ref, metadata=metadata_ref, status=status)
                    entry.pop("prepared_metadata", None)
                    report["proofs_changed"] += 1
                if verification["bitcoin_verified"]:
                    del state["pending"][key]
                    report["proofs_verified"] += 1
                else:
                    entry["last_result"] = "bitcoin_attestation_unverified" if inspected["bitcoin_block_heights"] else "calendar_pending"
                record_raw = transport.record(head, f"proofs/{key}.json")
                record = _json(record_raw) if record_raw is not None else {"schema_version": 1,
                    "subject_sha256": entry["subject_sha256"], "history": []}
                if changed:
                    record["history"].append({"proof": entry["proof"], "metadata": entry["metadata"], "status": status})
                record["maintenance_status"] = "verified" if verification["bitcoin_verified"] else (
                    "awaiting_trusted_rpc" if inspected["bitcoin_block_heights"] else "calendar_pending")
                record["last_verification_result"] = verification["status"]
                records = {f"proofs/{key}.json": canonical_json(record)}
                # Store completed upgrades in per-proof history; an absent trusted
                # verifier does not cause every completed proof to run every hour.
                if inspected["bitcoin_block_heights"] and verifier is None:
                    state["pending"].pop(key, None)
                    report["proofs_awaiting_trusted_rpc_archived"] += 1
            except StateDeferredError:
                raise
            except StateConflictError:
                raise
            except (RuntimeError, ValueError, KeyError, TypeError, OSError):
                entry["last_result"] = "upgrade_or_binding_check_failed"
                report["proofs_deferred"] += 1
                records = {}
            head = transport.save(head, state, records)
            committed_state = copy.deepcopy(state)
    except StateDeferredError as error:
        report.update(status="deferred", deferred_reason=error.reason, retry_not_before=error.retry_not_before)
        state = committed_state
    except StateConflictError:
        report.update(status="conflict", deferred_reason="branch_changed_reload_next_run")
        # Report authoritative backlog, not an uncommitted local queue.
        _, state = transport.load()
    report.update(pending_proofs=len(state["pending"]), incomplete_releases=len(state["discovery"]["incomplete_releases"]),
                  historical_discovery_page=state["discovery"]["historical_page"],
                  completed_discovery_cycles=state["discovery"]["completed_cycles"],
                  github_requests=getattr(transport, "request_count", 0))
    report["due_proofs"] = sum(item["next_attempt_after"] <= clock() for item in state["pending"].values())
    report["runtime_seconds"] = round(max(0, clock() - started), 3)
    report["discovery_coverage"] = "recent_page_plus_bounded_rolling_history; direct_registration_is_primary"
    if report["status"] == "complete" and (report["pending_proofs"] or report["incomplete_releases"]):
        report["status"] = "backlog"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination-repository", default=os.environ.get("GITHUB_REPOSITORY"), required=False)
    parser.add_argument("--max-proofs", type=int, default=128)
    parser.add_argument("--max-pages", type=int, default=2)
    parser.add_argument("--max-markers", type=int, default=12)
    parser.add_argument("--requeue-catalog", help="Explicitly requeue this registered catalog SHA-256 for trusted-RPC verification")
    parser.add_argument("--after-proof-key", help="Resume a bounded catalog requeue after this proof key")
    args = parser.parse_args(argv)
    if not args.destination_repository:
        parser.error("--destination-repository or GITHUB_REPOSITORY is required")
    verifier = BitcoinCoreVerifier(os.environ["COLLECTOR_BITCOIN_RPC"]) if os.environ.get("COLLECTOR_BITCOIN_RPC") else None
    transport = ProofTransport(args.destination_repository)
    if args.requeue_catalog and verifier is None:
        parser.error("--requeue-catalog requires the configured trusted COLLECTOR_BITCOIN_RPC verifier")
    requeue = requeue_catalog(transport, args.requeue_catalog, max_proofs=args.max_proofs,
                             after_proof_key=args.after_proof_key) if args.requeue_catalog else None
    result = refresh(transport, verifier=verifier,
                     max_proofs=args.max_proofs, max_pages=args.max_pages, max_markers=args.max_markers)
    if requeue is not None:
        result["operator_requeue"] = requeue
    print(canonical_json(result).decode(), end="")
    return 0 if result["status"] in {"complete", "backlog", "bounded", "deferred", "conflict"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
