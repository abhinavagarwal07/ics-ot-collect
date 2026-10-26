"""Streaming RSA-OAEP/AES-GCM archive encryption, envelope version 1.

The binary envelope is, in order::

    b"ICSOTENC" | version (1 byte, value 1) | header length (4 bytes, big endian)
    | UTF-8 JSON header | AES-256-GCM ciphertext | GCM tag (16 bytes)

The JSON header has exactly the fields produced by ``encrypt_file`` below. It
contains the cipher and wrapping algorithm names, base64-encoded RSA-wrapped
256-bit AES key and 96-bit nonce, plaintext byte count and SHA-256, and SHA-256
of the recipient's canonical DER SubjectPublicKeyInfo. The entire prefix and
header are GCM associated data. Header fields are public metadata; in particular
the plaintext hash and size are deliberately not confidential. The fingerprint
uses lowercase hexadecimal, not the OpenSSH fingerprint encoding.

RSA-OAEP uses SHA-256 for both OAEP and MGF1, with no label. A new random AES key
and nonce are generated for every envelope. Header length is capped at 64 KiB;
payloads are streamed in bounded chunks. A single payload may contain at most
2**36 - 32 bytes, the GCM per-invocation plaintext limit. Split larger archives
before encryption. This format provides recipient encryption and integrity, not
sender identity: anyone with the public key can create a new valid envelope.

Encryption reads a regular input file twice to authenticate its size and hash,
and rejects changes between those passes. Outputs are created exclusively with
mode 0600. Decryption writes to a mode-0600 temporary file in the destination
directory, verifies the GCM tag, size, and hash, fsyncs it, then atomically links
it to the requested output without replacing an existing path. Failed decrypts
remove the temporary file; removal is not a promise of secure erasure. Input
files and key files are never modified, and keys are never logged or exported.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import struct
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"ICSOTENC"
VERSION = 1
FORMAT = "icsot-encrypted-v1"
CHUNK_SIZE = 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_PLAINTEXT_BYTES = (1 << 36) - 32
_MAX_KEY_FILE_BYTES = 1024 * 1024
_PREFIX = struct.Struct(">8sBI")
_TAG_BYTES = 16
_NONCE_BYTES = 12
_CIPHER = "AES-256-GCM"
_KEY_WRAP = "RSA-OAEP-SHA256"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEADER_FIELDS = frozenset({
    "cipher", "key_wrap", "nonce", "wrapped_key", "plaintext_bytes",
    "plaintext_sha256", "public_key_fingerprint_sha256",
})


class EncryptionError(ValueError):
    """An invalid key, changed input, or invalid encrypted envelope."""


def _read_key_file(path: str | os.PathLike[str]) -> bytes:
    with open(path, "rb") as source:
        data = source.read(_MAX_KEY_FILE_BYTES + 1)
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise EncryptionError("Key file exceeds the supported size")
    return data


def _check_rsa_key(key: Any, *, private: bool = False) -> Any:
    expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    if not isinstance(key, expected):
        raise EncryptionError("An RSA key is required")
    if key.key_size < 2048:
        raise EncryptionError("RSA keys must contain at least 2048 bits")
    return key


def _load_public_key(path: str | os.PathLike[str]) -> rsa.RSAPublicKey:
    data = _read_key_file(path)
    try:
        if data.lstrip().startswith(b"ssh-"):
            key = serialization.load_ssh_public_key(data)
        else:
            key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise EncryptionError("Unable to load the RSA public key") from None
    return _check_rsa_key(key)


def _load_private_key(path: str | os.PathLike[str], password: bytes | None) -> rsa.RSAPrivateKey:
    data = _read_key_file(path)
    try:
        if data.lstrip().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = serialization.load_ssh_private_key(data, password=password)
        else:
            key = serialization.load_pem_private_key(data, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise EncryptionError(
            "Unable to load the RSA private key; a correct passphrase may be required"
        ) from None
    return _check_rsa_key(key, private=True)


def _fingerprint(key: rsa.RSAPublicKey) -> str:
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def public_key_fingerprint(public_key_path: str | os.PathLike[str]) -> str:
    """Return SHA-256 hex of an SSH/PEM RSA public key's DER SubjectPublicKeyInfo."""
    return _fingerprint(_load_public_key(public_key_path))


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _regular_file_size(source: BinaryIO) -> int:
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode):
        raise EncryptionError("Input must be a regular file")
    return info.st_size


def _plaintext_digest(source: BinaryIO, expected_size: int) -> str:
    digest = hashlib.sha256()
    count = 0
    while chunk := source.read(CHUNK_SIZE):
        count += len(chunk)
        if count > expected_size:
            raise EncryptionError("Input changed while being read")
        digest.update(chunk)
    if count != expected_size:
        raise EncryptionError("Input changed while being read")
    return digest.hexdigest()


def _record(header: dict[str, Any], ciphertext_sha256: str, ciphertext_bytes: int) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "plaintext_sha256": header["plaintext_sha256"],
        "plaintext_bytes": header["plaintext_bytes"],
        "ciphertext_sha256": ciphertext_sha256,
        "ciphertext_bytes": ciphertext_bytes,
        "public_key_fingerprint_sha256": header["public_key_fingerprint_sha256"],
    }


def encrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str],
                 public_key_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Encrypt a regular file for an SSH/PEM RSA public key; never overwrite.

    Return public metadata containing plaintext/ciphertext SHA-256 and byte
    counts, envelope format, and recipient SPKI fingerprint. Failure removes
    any partial output created by this call. Destination parent must exist.
    Only the public key is loaded; no private key is needed for encryption.
    """
    public_key = _load_public_key(public_key_path)
    output_path = Path(output_path)
    with open(input_path, "rb") as source:
        plaintext_bytes = _regular_file_size(source)
        if plaintext_bytes > MAX_PLAINTEXT_BYTES:
            raise EncryptionError("Input exceeds the GCM single-payload size limit")
        plaintext_sha256 = _plaintext_digest(source, plaintext_bytes)
        source.seek(0)
        key, nonce = os.urandom(32), os.urandom(_NONCE_BYTES)
        header = {
            "cipher": _CIPHER,
            "key_wrap": _KEY_WRAP,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "wrapped_key": base64.b64encode(public_key.encrypt(key, _oaep())).decode("ascii"),
            "plaintext_bytes": plaintext_bytes,
            "plaintext_sha256": plaintext_sha256,
            "public_key_fingerprint_sha256": _fingerprint(public_key),
        }
        raw_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw_header) > MAX_HEADER_BYTES:
            raise EncryptionError("Recipient key produces an oversized envelope header")
        prefix = _PREFIX.pack(MAGIC, VERSION, len(raw_header))
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(prefix + raw_header)
        cipher_digest, plain_digest = hashlib.sha256(), hashlib.sha256()
        cipher_bytes, plain_bytes = 0, 0
        # O_EXCL rejects existing files and symlinks; 0600 applies at creation.
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                os.fchmod(target.fileno(), 0o600)

                def emit(data: bytes) -> None:
                    nonlocal cipher_bytes
                    target.write(data)
                    cipher_digest.update(data)
                    cipher_bytes += len(data)

                emit(prefix)
                emit(raw_header)
                while chunk := source.read(CHUNK_SIZE):
                    plain_bytes += len(chunk)
                    if plain_bytes > plaintext_bytes:
                        raise EncryptionError("Input changed during encryption")
                    plain_digest.update(chunk)
                    emit(encryptor.update(chunk))
                if (plain_bytes != plaintext_bytes or
                        not hmac.compare_digest(plain_digest.hexdigest(), plaintext_sha256)):
                    raise EncryptionError("Input changed during encryption")
                emit(encryptor.finalize())
                emit(encryptor.tag)
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            output_path.unlink(missing_ok=True)
            raise
    return _record(header, cipher_digest.hexdigest(), cipher_bytes)


def _read_exact(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise EncryptionError("Truncated encrypted envelope")
    return data


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EncryptionError("Duplicate envelope header field")
        result[key] = value
    return result


def _decode_base64(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str):
        raise EncryptionError(f"Invalid envelope {field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise EncryptionError(f"Invalid envelope {field}") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise EncryptionError(f"Noncanonical envelope {field}")
    return decoded


def _parse_header(raw_header: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    try:
        header = json.loads(raw_header.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise EncryptionError("Invalid envelope JSON header") from None
    if not isinstance(header, dict) or header.keys() != _HEADER_FIELDS:
        raise EncryptionError("Unexpected envelope header fields")
    if header["cipher"] != _CIPHER or header["key_wrap"] != _KEY_WRAP:
        raise EncryptionError("Unsupported envelope algorithms")
    size = header["plaintext_bytes"]
    if type(size) is not int or not 0 <= size <= MAX_PLAINTEXT_BYTES:
        raise EncryptionError("Invalid envelope plaintext size")
    for field in ("plaintext_sha256", "public_key_fingerprint_sha256"):
        if not isinstance(header[field], str) or not _HEX_SHA256.fullmatch(header[field]):
            raise EncryptionError(f"Invalid envelope {field}")
    nonce = _decode_base64(header["nonce"], field="nonce")
    wrapped_key = _decode_base64(header["wrapped_key"], field="wrapped key")
    if len(nonce) != _NONCE_BYTES:
        raise EncryptionError("Invalid envelope nonce length")
    return header, nonce, wrapped_key


def decrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str],
                 private_key_path: str | os.PathLike[str],
                 password: bytes | None = None) -> dict[str, Any]:
    """Authenticate and decrypt an envelope using a local PEM/OpenSSH RSA key.

    ``password`` is a bytes passphrase for an encrypted private key, or None.
    Return the same public metadata as ``encrypt_file``. No output is committed
    until authentication and all size/hash checks pass. Existing destinations
    (including symlinks) are never replaced. Destination parent must exist.
    """
    private_key = _load_private_key(private_key_path, password)
    output_path = Path(output_path)
    temp_path: Path | None = None
    with open(input_path, "rb") as source:
        total_size = _regular_file_size(source)
        prefix = _read_exact(source, _PREFIX.size)
        magic, version, header_size = _PREFIX.unpack(prefix)
        if magic != MAGIC or version != VERSION:
            raise EncryptionError("Unsupported encrypted envelope format or version")
        if not 0 < header_size <= MAX_HEADER_BYTES:
            raise EncryptionError("Invalid encrypted envelope header length")
        raw_header = _read_exact(source, header_size)
        header, nonce, wrapped_key = _parse_header(raw_header)
        expected_size = _PREFIX.size + header_size + header["plaintext_bytes"] + _TAG_BYTES
        if total_size != expected_size:
            raise EncryptionError("Encrypted envelope length mismatch (truncation or trailing bytes)")
        if not hmac.compare_digest(header["public_key_fingerprint_sha256"],
                                   _fingerprint(private_key.public_key())):
            raise EncryptionError("Encrypted envelope belongs to a different RSA key")
        if len(wrapped_key) != (private_key.key_size + 7) // 8:
            raise EncryptionError("Invalid wrapped key length")
        try:
            key = private_key.decrypt(wrapped_key, _oaep())
        except ValueError:
            raise EncryptionError("Unable to unwrap the envelope key") from None
        if len(key) != 32:
            raise EncryptionError("Invalid unwrapped AES key length")
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        decryptor.authenticate_additional_data(prefix + raw_header)
        cipher_digest = hashlib.sha256(prefix + raw_header)
        plain_digest = hashlib.sha256()
        plain_bytes = 0
        fd, name = tempfile.mkstemp(prefix=".icsot-decrypt-", suffix=".tmp", dir=output_path.parent)
        temp_path = Path(name)
        try:
            with os.fdopen(fd, "wb") as target:
                os.fchmod(target.fileno(), 0o600)
                remaining = header["plaintext_bytes"]
                while remaining:
                    chunk = _read_exact(source, min(CHUNK_SIZE, remaining))
                    remaining -= len(chunk)
                    cipher_digest.update(chunk)
                    plaintext = decryptor.update(chunk)
                    target.write(plaintext)
                    plain_digest.update(plaintext)
                    plain_bytes += len(plaintext)
                tag = _read_exact(source, _TAG_BYTES)
                cipher_digest.update(tag)
                if source.read(1):
                    raise EncryptionError("Trailing bytes in encrypted envelope")
                try:
                    final = decryptor.finalize_with_tag(tag)
                except InvalidTag:
                    raise EncryptionError("Encrypted envelope authentication failed") from None
                target.write(final)
                plain_digest.update(final)
                plain_bytes += len(final)
                if (plain_bytes != header["plaintext_bytes"] or
                        not hmac.compare_digest(plain_digest.hexdigest(), header["plaintext_sha256"])):
                    raise EncryptionError("Decrypted plaintext size or hash mismatch")
                target.flush()
                os.fsync(target.fileno())
            # Same-directory hard linking atomically publishes the authenticated
            # file and fails if any destination entry already exists.
            os.link(temp_path, output_path)
        finally:
            temp_path.unlink(missing_ok=True)
    return _record(header, cipher_digest.hexdigest(), expected_size)
