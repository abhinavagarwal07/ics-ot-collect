import base64
import hashlib
import json
import os
import stat
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from icsot_observer import encryption
from icsot_observer.encryption import EncryptionError, decrypt_file, encrypt_file, public_key_fingerprint


@pytest.fixture(scope="module")
def rsa_keys():
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


@pytest.fixture
def key_files(tmp_path, rsa_keys):
    private_key, other_key = rsa_keys
    private = tmp_path / "private.pem"
    private.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    public = tmp_path / "public.ssh"
    public.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH,
    ) + b" recipient@example.invalid\n")
    wrong = tmp_path / "other-private.pem"
    wrong.write_bytes(other_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return public, private, wrong


def read_header(data):
    magic, version, size = struct.unpack(">8sBI", data[:13])
    assert magic == b"ICSOTENC" and version == 1
    return json.loads(data[13:13 + size]), 13 + size


def mutate_header(data, **updates):
    header, end = read_header(data)
    header.update(updates)
    raw = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return struct.pack(">8sBI", b"ICSOTENC", 1, len(raw)) + raw + data[end:]


@pytest.mark.parametrize("size", [0, 17, 3 * 8192 + 37])
def test_round_trip_is_streamed_and_returns_hashes(tmp_path, key_files, monkeypatch, size):
    monkeypatch.setattr(encryption, "CHUNK_SIZE", 8192)
    public, private, _ = key_files
    plaintext = os.urandom(size)
    source = tmp_path / "archive.tar"
    source.write_bytes(plaintext)
    encrypted = tmp_path / "archive.enc"
    restored = tmp_path / "restored.tar"
    read_sizes = []
    real_open = open

    class BoundedReader:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def read(self, count=-1):
            assert 0 < count <= 8192
            read_sizes.append(count)
            return self.handle.read(count)

    def bounded_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        return BoundedReader(handle) if Path(path) in (source, encrypted) else handle

    monkeypatch.setattr(encryption, "open", bounded_open, raising=False)

    encrypted_record = encrypt_file(source, encrypted, public)
    decrypted_record = decrypt_file(encrypted, restored, private)

    assert restored.read_bytes() == plaintext
    assert source.read_bytes() == plaintext
    assert encrypted_record == decrypted_record
    assert encrypted_record == {
        "format": "icsot-encrypted-v1",
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_bytes": size,
        "ciphertext_sha256": hashlib.sha256(encrypted.read_bytes()).hexdigest(),
        "ciphertext_bytes": encrypted.stat().st_size,
        "public_key_fingerprint_sha256": public_key_fingerprint(public),
    }
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".icsot-decrypt-*"))
    assert read_sizes.count(8192) >= 2


def test_public_formats_have_same_canonical_fingerprint(tmp_path, key_files, rsa_keys):
    public, private, _ = key_files
    key = rsa_keys[0].public_key()
    pem = tmp_path / "public.pem"
    pem.write_bytes(key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    pkcs1 = tmp_path / "public-pkcs1.pem"
    pkcs1.write_bytes(key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1,
    ))
    expected = hashlib.sha256(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()
    assert public_key_fingerprint(public) == public_key_fingerprint(pem) == expected
    assert public_key_fingerprint(pkcs1) == expected
    source = tmp_path / "source"
    source.write_bytes(b"PEM recipient")
    encrypt_file(source, tmp_path / "encrypted", pem)
    decrypt_file(tmp_path / "encrypted", tmp_path / "restored", private)
    assert (tmp_path / "restored").read_bytes() == source.read_bytes()


@pytest.mark.parametrize("key_format", [serialization.PrivateFormat.PKCS8,
                                       serialization.PrivateFormat.OpenSSH])
def test_encrypted_private_keys_accept_passphrase(tmp_path, key_files, rsa_keys, key_format):
    if key_format is serialization.PrivateFormat.OpenSSH:
        pytest.importorskip("bcrypt", reason="encrypted OpenSSH keys require cryptography[ssh]")
    public, _, _ = key_files
    private = tmp_path / "password-private"
    private.write_bytes(rsa_keys[0].private_bytes(
        serialization.Encoding.PEM, key_format,
        serialization.BestAvailableEncryption(b"test-only-passphrase"),
    ))
    source = tmp_path / "source"
    source.write_bytes(b"encrypted private key fixture")
    encrypted, restored = tmp_path / "encrypted", tmp_path / "restored"
    encrypt_file(source, encrypted, public)
    for password in (None, b"wrong-passphrase"):
        with pytest.raises(EncryptionError, match="passphrase"):
            decrypt_file(encrypted, restored, private, password=password)
        assert not restored.exists()
    decrypt_file(encrypted, restored, private, password=b"test-only-passphrase")
    assert restored.read_bytes() == source.read_bytes()


def test_unencrypted_openssh_private_key(tmp_path, key_files, rsa_keys):
    public, _, _ = key_files
    private = tmp_path / "openssh-private"
    private.write_bytes(rsa_keys[0].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ))
    source, encrypted, restored = tmp_path / "source", tmp_path / "encrypted", tmp_path / "restored"
    source.write_bytes(b"OpenSSH private key fixture")
    encrypt_file(source, encrypted, public)
    decrypt_file(encrypted, restored, private)
    assert restored.read_bytes() == source.read_bytes()


def test_every_encryption_has_fresh_randomness(tmp_path, key_files):
    public, private, _ = key_files
    source = tmp_path / "source"
    source.write_bytes(b"same archive")
    first, second = tmp_path / "first.enc", tmp_path / "second.enc"
    first_record = encrypt_file(source, first, public)
    second_record = encrypt_file(source, second, public)
    first_header, _ = read_header(first.read_bytes())
    second_header, _ = read_header(second.read_bytes())
    assert first_header["nonce"] != second_header["nonce"]
    assert first_header["wrapped_key"] != second_header["wrapped_key"]
    assert first_record["ciphertext_sha256"] != second_record["ciphertext_sha256"]
    assert first_record["plaintext_sha256"] == second_record["plaintext_sha256"]
    decrypt_file(first, tmp_path / "first-restored", private)
    decrypt_file(second, tmp_path / "second-restored", private)


def test_wrong_private_key_fails_without_creating_output(tmp_path, key_files):
    public, _, wrong = key_files
    source, encrypted, restored = tmp_path / "source", tmp_path / "encrypted", tmp_path / "restored"
    source.write_bytes(b"private archive")
    encrypt_file(source, encrypted, public)
    before = set(tmp_path.iterdir())
    with pytest.raises(EncryptionError, match="different RSA key"):
        decrypt_file(encrypted, restored, wrong)
    assert set(tmp_path.iterdir()) == before


def altered_envelopes(data):
    _, payload = read_header(data)
    changed = bytearray(data)
    changed[payload] ^= 1
    yield "ciphertext", bytes(changed)
    changed = bytearray(data)
    changed[-1] ^= 1
    yield "tag", bytes(changed)
    yield "authenticated-header", mutate_header(data, plaintext_sha256="0" * 64)
    yield "nonce", mutate_header(data, nonce=base64.b64encode(b"z" * 12).decode())
    yield "wrapped-key", mutate_header(data, wrapped_key=base64.b64encode(b"z" * 256).decode())
    yield "fingerprint", mutate_header(data, public_key_fingerprint_sha256="0" * 64)
    yield "trailing-bytes", data + b"unexpected trailing bytes"
    yield "empty", b""
    yield "truncated-prefix", data[:12]
    yield "truncated-header", data[:payload - 1]
    yield "truncated-payload", data[:payload + 1]
    yield "truncated-tag", data[:-1]
    yield "magic", b"INVALID!" + data[8:]
    yield "version", data[:8] + b"\x02" + data[9:]
    yield "zero-header-size", data[:9] + struct.pack(">I", 0) + data[13:]
    yield "oversized-header", data[:9] + struct.pack(">I", 65537) + data[13:]
    yield "unknown-algorithm", mutate_header(data, cipher="AES-256-CBC")
    yield "bad-size-type", mutate_header(data, plaintext_bytes=True)
    yield "negative-size", mutate_header(data, plaintext_bytes=-1)
    yield "excessive-size", mutate_header(data, plaintext_bytes=encryption.MAX_PLAINTEXT_BYTES + 1)
    yield "changed-size", mutate_header(data, plaintext_bytes=9999)
    yield "bad-hash", mutate_header(data, plaintext_sha256="not-a-sha256")
    yield "bad-base64", mutate_header(data, nonce="not base64!!")
    yield "short-nonce", mutate_header(data, nonce=base64.b64encode(b"short").decode())
    yield "short-wrapped-key", mutate_header(data, wrapped_key=base64.b64encode(b"short").decode())
    yield "extra-field", mutate_header(data, unexpected="field")
    yield "invalid-json", data[:13] + b"!" * (payload - 13) + data[payload:]


def test_tampered_corrupt_and_truncated_envelopes_fail_closed(tmp_path, key_files, monkeypatch):
    monkeypatch.setattr(encryption, "CHUNK_SIZE", 11)
    public, private, _ = key_files
    source, encrypted, restored = tmp_path / "source", tmp_path / "encrypted", tmp_path / "restored"
    source.write_bytes(b"private archive with several chunks of plaintext")
    encrypt_file(source, encrypted, public)
    original = encrypted.read_bytes()
    damaged = tmp_path / "damaged"
    damaged.touch()
    before = set(tmp_path.iterdir())
    for label, data in altered_envelopes(original):
        damaged.write_bytes(data)
        with pytest.raises(EncryptionError):
            decrypt_file(damaged, restored, private)
        assert not restored.exists(), label
        assert set(tmp_path.iterdir()) == before, label


def test_duplicate_header_fields_are_rejected(tmp_path, key_files):
    public, private, _ = key_files
    source, encrypted = tmp_path / "source", tmp_path / "encrypted"
    source.write_bytes(b"test")
    encrypt_file(source, encrypted, public)
    data = encrypted.read_bytes()
    _, end = read_header(data)
    raw_header = b'{"cipher":"AES-256-GCM",' + data[14:end]
    encrypted.write_bytes(struct.pack(">8sBI", b"ICSOTENC", 1, len(raw_header)) + raw_header + data[end:])
    with pytest.raises(EncryptionError, match="JSON header"):
        decrypt_file(encrypted, tmp_path / "restored", private)
    assert not (tmp_path / "restored").exists()


def test_valid_gcm_tag_still_requires_expected_plaintext_hash(tmp_path, key_files, rsa_keys):
    public, private, _ = key_files
    plaintext = b"a valid GCM message with false hash metadata"
    key, nonce = os.urandom(32), os.urandom(12)
    wrapped = rsa_keys[0].public_key().encrypt(key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None,
    ))
    header = {
        "cipher": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256",
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(wrapped).decode(),
        "plaintext_bytes": len(plaintext), "plaintext_sha256": "0" * 64,
        "public_key_fingerprint_sha256": public_key_fingerprint(public),
    }
    raw = json.dumps(header).encode()
    aad = struct.pack(">8sBI", b"ICSOTENC", 1, len(raw)) + raw
    encrypted, restored = tmp_path / "encrypted", tmp_path / "restored"
    encrypted.write_bytes(aad + AESGCM(key).encrypt(nonce, plaintext, aad))
    before = set(tmp_path.iterdir())
    with pytest.raises(EncryptionError, match="plaintext size or hash mismatch"):
        decrypt_file(encrypted, restored, private)
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("symlink", [False, True])
def test_outputs_are_never_overwritten(tmp_path, key_files, symlink):
    public, private, _ = key_files
    source, encrypted = tmp_path / "source", tmp_path / "encrypted"
    source.write_bytes(b"source")
    encrypt_file(source, encrypted, public)
    existing = tmp_path / "existing"
    original = tmp_path / "original"
    original.write_bytes(b"preserve this content")
    if symlink:
        existing.symlink_to(original)
    else:
        existing.write_bytes(original.read_bytes())
    before = set(tmp_path.iterdir())
    with pytest.raises(FileExistsError):
        encrypt_file(source, existing, public)
    with pytest.raises(FileExistsError):
        decrypt_file(encrypted, existing, private)
    assert existing.read_bytes() == b"preserve this content"
    assert original.read_bytes() == b"preserve this content"
    assert existing.is_symlink() == symlink
    assert set(tmp_path.iterdir()) == before


def test_encryption_removes_partial_output_if_input_changes(tmp_path, key_files, monkeypatch):
    public, _, _ = key_files
    source, encrypted = tmp_path / "source", tmp_path / "encrypted"
    source.write_bytes(b"before")
    real_digest = encryption._plaintext_digest

    def mutate_after_hash(handle, size):
        digest = real_digest(handle, size)
        source.write_bytes(b"after!")
        return digest

    monkeypatch.setattr(encryption, "_plaintext_digest", mutate_after_hash)
    with pytest.raises(EncryptionError, match="changed during encryption"):
        encrypt_file(source, encrypted, public)
    assert not encrypted.exists()


def test_fsync_failure_does_not_leave_output(tmp_path, key_files, monkeypatch):
    public, private, _ = key_files
    source, encrypted, restored = tmp_path / "source", tmp_path / "encrypted", tmp_path / "restored"
    source.write_bytes(b"contents")
    encrypt_file(source, encrypted, public)
    before = set(tmp_path.iterdir())

    def failed_fsync(fd):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(encryption.os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="simulated disk failure"):
        decrypt_file(encrypted, restored, private)
    assert set(tmp_path.iterdir()) == before
    with pytest.raises(OSError, match="simulated disk failure"):
        encrypt_file(source, tmp_path / "failed-encryption", public)
    assert set(tmp_path.iterdir()) == before


def test_gcm_size_limit_is_checked_before_reading_payload(tmp_path, key_files, monkeypatch):
    public, _, _ = key_files
    source, encrypted = tmp_path / "source", tmp_path / "encrypted"
    source.write_bytes(b"larger than test limit")
    monkeypatch.setattr(encryption, "MAX_PLAINTEXT_BYTES", 3)
    with pytest.raises(EncryptionError, match="size limit"):
        encrypt_file(source, encrypted, public)
    assert not encrypted.exists()


def test_rejects_non_rsa_and_weak_rsa_public_keys(tmp_path):
    source, encrypted, public = tmp_path / "source", tmp_path / "encrypted", tmp_path / "public"
    source.write_bytes(b"test")
    keys = [ec.generate_private_key(ec.SECP256R1()).public_key(),
            rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()]
    for key in keys:
        public.write_bytes(key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with pytest.raises(EncryptionError, match="RSA"):
            encrypt_file(source, encrypted, public)
        assert not encrypted.exists()
