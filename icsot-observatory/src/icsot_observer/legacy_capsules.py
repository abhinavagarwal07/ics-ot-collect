"""Bounded key capsules for immutable owner-encrypted archive parts.

A capsule wraps only the original 32-byte AES key for an operational RSA key.
Its RSA-OAEP label binds the canonical public context, including the exact
original envelope hashes, sealed-index hash, repository and immutable asset
identity. The original prefix, JSON bytes, ciphertext and tag never change.
Capsules provide recipient encryption and integrity, not sender identity.

Creation needs only a bounded original prefix/header and the independently
verified asset/index metadata; it does not authenticate the original payload.
Payload authentication happens on restoration before any plaintext is published.
Unwrapped keys are never returned, logged or written to disk. Python does not
provide a reliable guarantee of erasing their in-memory representations.

``read_envelope_aad`` reads at most 65,549 bytes and leaves the payload unread.
Callers fetching that header over HTTP must themselves bound the HTTP reader;
this module performs no network requests and cannot constrain a client's own
prefetching or a server ignoring Range. ``decrypt_capsule_stream`` accepts a
non-seekable binary stream, uses bounded reads, and commits a mode-0600 file
only after original GCM authentication and all bound hash/size checks pass.
Callers remain responsible for reserving the plaintext temporary-file space.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import encryption as _envelope

FORMAT = "icsot-legacy-key-capsule-v1"
VERSION = 1
MAX_AAD_BYTES = _envelope._PREFIX.size + _envelope.MAX_HEADER_BYTES
MAX_CAPSULE_BYTES = 64 * 1024
_DOMAIN = b"ICSOT-LEGACY-KEY-CAPSULE-V1\x00"
_WRAP = "RSA-OAEP-SHA256-LABEL-CONTEXT"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
_BINDING_FIELDS = frozenset({
    "repository_id", "repository", "release_repository", "release_tag", "release_id",
    "asset_name", "asset_id", "part_number", "part_count", "sealed_index_sha256",
    "ciphertext_sha256", "ciphertext_bytes",
})
_DERIVED_FIELDS = frozenset({
    "original_header_sha256", "original_aad_sha256", "owner_key_fingerprint_sha256",
    "operational_key_fingerprint_sha256",
})
_CAPSULE_FIELDS = frozenset({
    "format", "version", "original_envelope_format", "payload_cipher", "key_wrap",
    "context", "wrapped_key",
})


class CapsuleError(_envelope.EncryptionError):
    """An invalid capsule, mismatched context, key or original encrypted part."""


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _read_exact(source: BinaryIO, size: int) -> bytes:
    """Handle short stream reads without ever making an unbounded read."""
    blocks = []
    remaining = size
    while remaining:
        requested = min(remaining, _envelope.CHUNK_SIZE)
        block = source.read(requested)
        if not isinstance(block, bytes) or not block or len(block) > requested:
            raise CapsuleError("Truncated or invalid encrypted envelope stream")
        blocks.append(block)
        remaining -= len(block)
    return b"".join(blocks)


def envelope_aad_size(prefix: bytes) -> int:
    """Validate a 13-byte original prefix and return its total prefix/header size."""
    if not isinstance(prefix, bytes) or len(prefix) != _envelope._PREFIX.size:
        raise CapsuleError("Invalid encrypted envelope prefix length")
    magic, version, header_size = _envelope._PREFIX.unpack(prefix)
    if magic != _envelope.MAGIC or version != _envelope.VERSION:
        raise CapsuleError("Unsupported encrypted envelope format or version")
    if not 0 < header_size <= _envelope.MAX_HEADER_BYTES:
        raise CapsuleError("Invalid encrypted envelope header length")
    return _envelope._PREFIX.size + header_size


def _parse_aad(aad: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    if not isinstance(aad, bytes) or not _envelope._PREFIX.size < len(aad) <= MAX_AAD_BYTES:
        raise CapsuleError("Invalid encrypted envelope prefix/header length")
    if envelope_aad_size(aad[:_envelope._PREFIX.size]) != len(aad):
        raise CapsuleError("Encrypted envelope prefix/header length mismatch")
    try:
        return _envelope._parse_header(aad[_envelope._PREFIX.size:])
    except _envelope.EncryptionError as exc:
        raise CapsuleError(str(exc)) from None


def read_envelope_aad(source: BinaryIO) -> bytes:
    """Read and validate only the original prefix/header, with a strict size cap."""
    prefix = _read_exact(source, _envelope._PREFIX.size)
    aad = prefix + _read_exact(source, envelope_aad_size(prefix) - len(prefix))
    _parse_aad(aad)
    return aad


def _validate_binding(binding: Any) -> dict[str, Any]:
    if not isinstance(binding, dict) or binding.keys() != _BINDING_FIELDS:
        raise CapsuleError("Unexpected capsule binding fields")
    for field in ("repository_id", "release_id", "asset_id", "part_number", "part_count"):
        if type(binding[field]) is not int or not 0 < binding[field] < (1 << 63):
            raise CapsuleError(f"Invalid capsule {field}")
    if binding["part_number"] > binding["part_count"]:
        raise CapsuleError("Invalid capsule part ordinal")
    for field in ("repository", "release_repository"):
        if (not isinstance(binding[field], str) or not _REPOSITORY.fullmatch(binding[field]) or
                any(part in (".", "..") for part in binding[field].split("/"))):
            raise CapsuleError(f"Invalid capsule {field}")
    tag = binding["release_tag"]
    try:
        tag_bytes = tag.encode("utf-8") if isinstance(tag, str) else b""
    except UnicodeError:
        raise CapsuleError("Invalid capsule release_tag") from None
    if (not 0 < len(tag_bytes) <= 255 or
            any(ord(character) < 32 or ord(character) == 127 for character in tag)):
        raise CapsuleError("Invalid capsule release_tag")
    if not isinstance(binding["asset_name"], str) or not _ASSET.fullmatch(binding["asset_name"]):
        raise CapsuleError("Invalid capsule asset_name")
    for field in ("sealed_index_sha256", "ciphertext_sha256"):
        if not isinstance(binding[field], str) or not _HASH.fullmatch(binding[field]):
            raise CapsuleError(f"Invalid capsule {field}")
    size = binding["ciphertext_bytes"]
    if (type(size) is not int or not _envelope._PREFIX.size + _envelope._TAG_BYTES < size <=
            _envelope.MAX_PLAINTEXT_BYTES + MAX_AAD_BYTES + _envelope._TAG_BYTES):
        raise CapsuleError("Invalid capsule ciphertext_bytes")
    return dict(binding)


def _validate_context(context: Any) -> dict[str, Any]:
    if not isinstance(context, dict) or context.keys() != _BINDING_FIELDS | _DERIVED_FIELDS:
        raise CapsuleError("Unexpected capsule context fields")
    _validate_binding({field: context[field] for field in _BINDING_FIELDS})
    for field in _DERIVED_FIELDS:
        if not isinstance(context[field], str) or not _HASH.fullmatch(context[field]):
            raise CapsuleError(f"Invalid capsule {field}")
    return context


def _oaep(document: dict[str, Any]) -> padding.OAEP:
    public = {field: value for field, value in document.items() if field != "wrapped_key"}
    label = _DOMAIN + hashlib.sha256(_canonical(public)).digest()
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def _validate_aad_context(aad: bytes, context: dict[str, Any]) -> tuple[dict[str, Any], bytes, bytes]:
    header, nonce, wrapped_key = _parse_aad(aad)
    if context["ciphertext_bytes"] != len(aad) + header["plaintext_bytes"] + _envelope._TAG_BYTES:
        raise CapsuleError("Original encrypted envelope size differs from capsule binding")
    derived = {
        "original_header_sha256": hashlib.sha256(aad[_envelope._PREFIX.size:]).hexdigest(),
        "original_aad_sha256": hashlib.sha256(aad).hexdigest(),
        "owner_key_fingerprint_sha256": header["public_key_fingerprint_sha256"],
    }
    if any(not hmac.compare_digest(context[field], value) for field, value in derived.items()):
        raise CapsuleError("Original encrypted envelope header differs from capsule context")
    return header, nonce, wrapped_key


def create_capsule(aad: bytes, *, binding: dict[str, Any],
                   owner_private_key_path: str | os.PathLike[str],
                   operational_public_key_path: str | os.PathLike[str],
                   password: bytes | None = None) -> bytes:
    """Rewrap an original AES key in memory; return only an encrypted capsule.

    ``binding`` must come from an independently verified original sealed index
    and immutable release/asset metadata. This operation does not read or verify
    the payload; only restoration can authenticate its original GCM tag.
    """
    binding = _validate_binding(binding)
    header, _, wrapped_key = _parse_aad(aad)
    if binding["ciphertext_bytes"] != len(aad) + header["plaintext_bytes"] + _envelope._TAG_BYTES:
        raise CapsuleError("Original encrypted envelope size differs from capsule binding")
    try:
        owner = _envelope._load_private_key(owner_private_key_path, password)
        recipient = _envelope._load_public_key(operational_public_key_path)
    except _envelope.EncryptionError as exc:
        raise CapsuleError(str(exc)) from None
    if not hmac.compare_digest(header["public_key_fingerprint_sha256"],
                               _envelope._fingerprint(owner.public_key())):
        raise CapsuleError("Original encrypted envelope belongs to a different owner RSA key")
    if len(wrapped_key) != (owner.key_size + 7) // 8:
        raise CapsuleError("Invalid original wrapped key length")
    context = {
        **binding,
        "original_header_sha256": hashlib.sha256(aad[_envelope._PREFIX.size:]).hexdigest(),
        "original_aad_sha256": hashlib.sha256(aad).hexdigest(),
        "owner_key_fingerprint_sha256": header["public_key_fingerprint_sha256"],
        "operational_key_fingerprint_sha256": _envelope._fingerprint(recipient),
    }
    document = {"format": FORMAT, "version": VERSION,
                "original_envelope_format": _envelope.FORMAT,
                "payload_cipher": "AES-256-GCM", "key_wrap": _WRAP, "context": context}
    try:
        key = owner.decrypt(wrapped_key, _envelope._oaep())
    except ValueError:
        raise CapsuleError("Unable to unwrap the original envelope key") from None
    if len(key) != 32:
        raise CapsuleError("Invalid original unwrapped AES key length")
    document["wrapped_key"] = base64.b64encode(recipient.encrypt(key, _oaep(document))).decode("ascii")
    result = _canonical(document)
    if len(result) > MAX_CAPSULE_BYTES:
        raise CapsuleError("Encrypted capsule exceeds its supported size")
    return result


def inspect_capsule(raw: bytes) -> dict[str, Any]:
    """Validate a bounded, canonical capsule and return its public JSON fields."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_CAPSULE_BYTES:
        raise CapsuleError("Invalid encrypted capsule size")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_envelope._unique_object)
        if not isinstance(document, dict) or _canonical(document) != raw:
            raise ValueError("noncanonical capsule")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CapsuleError("Invalid or noncanonical capsule JSON") from None
    if document.keys() != _CAPSULE_FIELDS:
        raise CapsuleError("Unexpected capsule fields")
    if (document["format"] != FORMAT or type(document["version"]) is not int or
            document["version"] != VERSION or document["original_envelope_format"] != _envelope.FORMAT or
            document["payload_cipher"] != "AES-256-GCM" or document["key_wrap"] != _WRAP):
        raise CapsuleError("Unsupported capsule format, version or algorithms")
    _validate_context(document["context"])
    try:
        wrapped_key = _envelope._decode_base64(document["wrapped_key"], field="capsule wrapped key")
    except _envelope.EncryptionError as exc:
        raise CapsuleError(str(exc)) from None
    if not 256 <= len(wrapped_key) <= MAX_CAPSULE_BYTES // 2:
        raise CapsuleError("Invalid capsule wrapped key length")
    return document


def decrypt_capsule_stream(source: BinaryIO, output_path: str | os.PathLike[str], capsule: bytes, *,
                           binding: dict[str, Any],
                           operational_private_key_path: str | os.PathLike[str],
                           password: bytes | None = None) -> dict[str, Any]:
    """Authenticate an unchanged original envelope and publish its plaintext.

    The independent ``binding`` must exactly match the capsule's original asset
    identity and metadata. ``source`` need not support seeking, stat or fileno.
    No plaintext is published if capsule unwrap, original GCM authentication,
    exact ciphertext hash/size, plaintext hash/size or stream EOF checks fail.
    Existing outputs, including symlinks, are never replaced. Temporary data is
    removed on failure; removal is not a promise of secure erasure.
    """
    binding = _validate_binding(binding)
    document = inspect_capsule(capsule)
    context = document["context"]
    if any(context[field] != value for field, value in binding.items()):
        raise CapsuleError("Capsule differs from the independently selected asset binding")
    aad = read_envelope_aad(source)
    header, nonce, _ = _validate_aad_context(aad, context)
    try:
        recipient = _envelope._load_private_key(operational_private_key_path, password)
    except _envelope.EncryptionError as exc:
        raise CapsuleError(str(exc)) from None
    if not hmac.compare_digest(context["operational_key_fingerprint_sha256"],
                               _envelope._fingerprint(recipient.public_key())):
        raise CapsuleError("Capsule belongs to a different operational RSA key")
    wrapped_key = _envelope._decode_base64(document["wrapped_key"], field="capsule wrapped key")
    if len(wrapped_key) != (recipient.key_size + 7) // 8:
        raise CapsuleError("Invalid capsule wrapped key length")
    try:
        key = recipient.decrypt(wrapped_key, _oaep(document))
    except ValueError:
        raise CapsuleError("Unable to authenticate or unwrap the capsule key") from None
    if len(key) != 32:
        raise CapsuleError("Invalid capsule unwrapped AES key length")
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
    decryptor.authenticate_additional_data(aad)
    cipher_digest, plain_digest = hashlib.sha256(aad), hashlib.sha256()
    plain_bytes = 0
    output_path = Path(output_path)
    fd, name = tempfile.mkstemp(prefix=".icsot-capsule-decrypt-", suffix=".tmp", dir=output_path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as target:
            os.fchmod(target.fileno(), 0o600)
            remaining = header["plaintext_bytes"]
            while remaining:
                chunk = _read_exact(source, min(_envelope.CHUNK_SIZE, remaining))
                remaining -= len(chunk)
                cipher_digest.update(chunk)
                plaintext = decryptor.update(chunk)
                target.write(plaintext)
                plain_digest.update(plaintext)
                plain_bytes += len(plaintext)
            tag = _read_exact(source, _envelope._TAG_BYTES)
            cipher_digest.update(tag)
            if source.read(1) != b"":
                raise CapsuleError("Trailing bytes in encrypted envelope")
            try:
                final = decryptor.finalize_with_tag(tag)
            except InvalidTag:
                raise CapsuleError("Original encrypted envelope authentication failed") from None
            target.write(final)
            plain_digest.update(final)
            plain_bytes += len(final)
            if (plain_bytes != header["plaintext_bytes"] or
                    not hmac.compare_digest(plain_digest.hexdigest(), header["plaintext_sha256"])):
                raise CapsuleError("Decrypted plaintext size or hash mismatch")
            if not hmac.compare_digest(cipher_digest.hexdigest(), binding["ciphertext_sha256"]):
                raise CapsuleError("Original encrypted envelope ciphertext hash mismatch")
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return _envelope._record(header, cipher_digest.hexdigest(), binding["ciphertext_bytes"])
