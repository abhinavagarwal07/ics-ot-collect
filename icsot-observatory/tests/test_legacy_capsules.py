import base64
import hashlib
import io
import json
import os
import stat
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from icsot_observer import encryption, legacy_capsules as capsules


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.fixture(scope="module")
def rsa_keys():
    return tuple(rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3))


@pytest.fixture
def keys(tmp_path, rsa_keys):
    result = {}
    for name, key in zip(("owner", "operational", "wrong"), rsa_keys):
        private = tmp_path / f"{name}-private.pem"
        public = tmp_path / f"{name}-public.pem"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo))
        result[name] = private, public
    return result


@pytest.fixture
def original(tmp_path, keys):
    content = os.urandom(16_421)
    source, encrypted = tmp_path / "part.xz", tmp_path / "part.xz.enc"
    source.write_bytes(content)
    metadata = encryption.encrypt_file(source, encrypted, keys["owner"][1])
    raw = encrypted.read_bytes()
    aad = capsules.read_envelope_aad(io.BytesIO(raw))
    binding = {
        "repository_id": 123, "repository": "source/project", "release_repository": "archive/corpus",
        "release_tag": "sealed-2026-10-26", "release_id": 456, "asset_name": "part-0001.xz.enc",
        "asset_id": 789, "part_number": 1, "part_count": 2, "sealed_index_sha256": "1" * 64,
        "ciphertext_sha256": metadata["ciphertext_sha256"], "ciphertext_bytes": metadata["ciphertext_bytes"],
    }
    capsule = capsules.create_capsule(aad, binding=binding, owner_private_key_path=keys["owner"][0],
                                      operational_public_key_path=keys["operational"][1])
    return content, raw, aad, binding, capsule, metadata


def restore(tmp_path, keys, original, *, raw=None, binding=None, capsule=None):
    _, original_raw, _, original_binding, original_capsule, _ = original
    output = tmp_path / "restored.xz"
    result = capsules.decrypt_capsule_stream(io.BytesIO(original_raw if raw is None else raw), output,
        original_capsule if capsule is None else capsule,
        binding=original_binding if binding is None else binding,
        operational_private_key_path=keys["operational"][0])
    return output, result


def test_round_trip_keeps_original_bytes_and_public_metadata(tmp_path, keys, original):
    content, raw, aad, binding, capsule, metadata = original
    output, result = restore(tmp_path, keys, original)
    assert output.read_bytes() == content
    assert result == metadata
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".icsot-capsule-decrypt-*"))
    document = capsules.inspect_capsule(capsule)
    assert {field: document["context"][field] for field in binding} == binding
    assert document["context"]["original_aad_sha256"] == hashlib.sha256(aad).hexdigest()
    assert document["context"]["original_header_sha256"] == hashlib.sha256(aad[13:]).hexdigest()
    assert document["context"]["operational_key_fingerprint_sha256"] == encryption.public_key_fingerprint(keys["operational"][1])
    assert document["context"]["owner_key_fingerprint_sha256"] == metadata["public_key_fingerprint_sha256"]
    assert hashlib.sha256(raw).hexdigest() == binding["ciphertext_sha256"]
    assert b"plaintext_key" not in capsule


def test_stream_reads_are_bounded_and_support_short_reads(tmp_path, keys, original, monkeypatch):
    monkeypatch.setattr(encryption, "CHUNK_SIZE", 8192)

    class ShortReader:
        def __init__(self, raw):
            self.source, self.counts = io.BytesIO(raw), []

        def read(self, count):
            assert 0 < count <= 8192
            self.counts.append(count)
            return self.source.read(min(count, 17))

    source = ShortReader(original[1])
    output = tmp_path / "restored"
    capsules.decrypt_capsule_stream(source, output, original[4], binding=original[3],
                                   operational_private_key_path=keys["operational"][0])
    assert output.read_bytes() == original[0]
    assert max(source.counts) == 8192
    assert source.source.tell() == len(original[1])


def test_header_reader_never_consumes_payload(original):
    source = io.BytesIO(original[1])
    assert capsules.read_envelope_aad(source) == original[2]
    assert source.tell() == len(original[2]) <= capsules.MAX_AAD_BYTES
    assert source.read() == original[1][len(original[2]):]
    assert capsules.envelope_aad_size(original[1][:13]) == len(original[2])


@pytest.mark.parametrize("header_size", [0, 65537, 2 ** 32 - 1])
def test_header_reader_rejects_unbounded_header_without_reading_body(header_size):
    source = io.BytesIO(struct.pack(">8sBI", b"ICSOTENC", 1, header_size) + b"never read")
    with pytest.raises(capsules.CapsuleError, match="header length"):
        capsules.read_envelope_aad(source)
    assert source.tell() == 13


@pytest.mark.parametrize("raw", [b"", b"ICSOTENC", b"badmagic" + b"\x01" + b"\x00\x00\x00\x01",
                                 struct.pack(">8sBI", b"ICSOTENC", 2, 1),
                                 struct.pack(">8sBI", b"ICSOTENC", 1, 5) + b"{}"])
def test_header_reader_rejects_invalid_or_truncated_input(raw):
    with pytest.raises(capsules.CapsuleError):
        capsules.read_envelope_aad(io.BytesIO(raw))


def test_header_reader_rejects_duplicate_json_fields():
    raw = b'{"cipher":"AES-256-GCM","cipher":"AES-256-GCM"}'
    with pytest.raises(capsules.CapsuleError):
        capsules.read_envelope_aad(io.BytesIO(struct.pack(">8sBI", b"ICSOTENC", 1, len(raw)) + raw))


def test_misbehaving_reader_cannot_supply_oversized_block():
    class IgnoresReadSize:
        def read(self, size):
            return b"x" * (size + 1)

    with pytest.raises(capsules.CapsuleError, match="invalid"):
        capsules.read_envelope_aad(IgnoresReadSize())


@pytest.mark.parametrize("mode", ["payload", "tag", "truncated-prefix", "truncated-header",
                                  "truncated-payload", "truncated-tag", "trailing"])
def test_tampering_and_truncation_never_publish_plaintext(tmp_path, keys, original, mode):
    raw = original[1]
    payload_start = len(original[2])
    if mode in ("payload", "tag"):
        damaged = bytearray(raw)
        damaged[payload_start if mode == "payload" else -1] ^= 1
        raw = bytes(damaged)
    elif mode == "truncated-prefix":
        raw = raw[:12]
    elif mode == "truncated-header":
        raw = raw[:payload_start - 1]
    elif mode == "truncated-payload":
        raw = raw[:payload_start + 2]
    elif mode == "truncated-tag":
        raw = raw[:-1]
    else:
        raw += b"unexpected"
    before = set(tmp_path.iterdir())
    with pytest.raises(capsules.CapsuleError):
        restore(tmp_path, keys, original, raw=raw)
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("field,value", [
    ("repository_id", 124), ("repository", "source/other"), ("release_repository", "archive/other"),
    ("release_tag", "different"), ("release_id", 457), ("asset_name", "different.enc"),
    ("asset_id", 790), ("part_number", 2), ("part_count", 3),
    ("sealed_index_sha256", "2" * 64), ("ciphertext_sha256", "3" * 64), ("ciphertext_bytes", 100),
])
def test_independent_context_must_match_every_identity_field(tmp_path, keys, original, field, value):
    binding = {**original[3], field: value}
    with pytest.raises(capsules.CapsuleError, match="binding"):
        restore(tmp_path, keys, original, binding=binding)
    assert not (tmp_path / "restored.xz").exists()


@pytest.mark.parametrize("field,value", [
    ("repository_id", 124), ("repository", "source/other"), ("release_id", 457),
    ("asset_id", 790), ("sealed_index_sha256", "2" * 64),
    ("original_header_sha256", "4" * 64), ("original_aad_sha256", "5" * 64),
    ("owner_key_fingerprint_sha256", "6" * 64), ("operational_key_fingerprint_sha256", "7" * 64),
])
def test_public_capsule_context_cannot_be_rebound(tmp_path, keys, original, field, value):
    document = capsules.inspect_capsule(original[4])
    document["context"][field] = value
    binding = {**original[3]}
    if field in binding:
        binding[field] = value  # Bypass the external comparison; OAEP still binds it.
    with pytest.raises(capsules.CapsuleError):
        restore(tmp_path, keys, original, capsule=canonical(document), binding=binding)
    assert not (tmp_path / "restored.xz").exists()


def test_capsule_key_ciphertext_tampering_fails(tmp_path, keys, original):
    document = capsules.inspect_capsule(original[4])
    wrapped = bytearray(base64.b64decode(document["wrapped_key"]))
    wrapped[0] ^= 1
    document["wrapped_key"] = base64.b64encode(wrapped).decode()
    with pytest.raises(capsules.CapsuleError, match="unwrap"):
        restore(tmp_path, keys, original, capsule=canonical(document))
    assert not (tmp_path / "restored.xz").exists()


def test_wrong_owner_key_cannot_create_capsule(keys, original):
    with pytest.raises(capsules.CapsuleError, match="different owner"):
        capsules.create_capsule(original[2], binding=original[3], owner_private_key_path=keys["wrong"][0],
                                operational_public_key_path=keys["operational"][1])


def test_wrong_operational_key_cannot_decrypt(tmp_path, keys, original):
    with pytest.raises(capsules.CapsuleError, match="different operational"):
        capsules.decrypt_capsule_stream(io.BytesIO(original[1]), tmp_path / "restored", original[4],
            binding=original[3], operational_private_key_path=keys["wrong"][0])
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("version", [True, 0, 2, "1"])
def test_capsule_rejects_unknown_or_invalid_version(original, version):
    document = capsules.inspect_capsule(original[4])
    document["version"] = version
    with pytest.raises(capsules.CapsuleError, match="version"):
        capsules.inspect_capsule(canonical(document))


@pytest.mark.parametrize("field", ["format", "original_envelope_format", "payload_cipher", "key_wrap"])
def test_capsule_rejects_unknown_format_and_algorithms(original, field):
    document = capsules.inspect_capsule(original[4])
    document[field] = "unsupported"
    with pytest.raises(capsules.CapsuleError, match="algorithms"):
        capsules.inspect_capsule(canonical(document))


@pytest.mark.parametrize("kind", ["empty", "oversized", "truncated", "noncanonical", "duplicate", "extra"])
def test_invalid_capsule_serialization(original, kind):
    raw = original[4]
    if kind == "empty":
        raw = b""
    elif kind == "oversized":
        raw = b"x" * (capsules.MAX_CAPSULE_BYTES + 1)
    elif kind == "truncated":
        raw = raw[:-2]
    elif kind == "noncanonical":
        raw = json.dumps(json.loads(raw)).encode()
    elif kind == "duplicate":
        raw = raw.replace(b'{"context":', b'{"version":1,"context":', 1)
    else:
        raw = canonical({**json.loads(raw), "extra": True})
    with pytest.raises(capsules.CapsuleError):
        capsules.inspect_capsule(raw)


@pytest.mark.parametrize("field,value", [
    ("repository_id", True), ("repository", "../unsafe"), ("release_id", 0), ("asset_id", -1),
    ("part_number", 3), ("part_count", False), ("asset_name", "../payload"),
    ("sealed_index_sha256", "A" * 64), ("ciphertext_sha256", "wrong"), ("ciphertext_bytes", True),
    ("release_tag", "bad\nheader"), ("release_tag", "x" * 256), ("release_tag", "\ud800"),
])
def test_invalid_binding_is_rejected_before_loading_keys(original, field, value):
    binding = {**original[3], field: value}
    with pytest.raises(capsules.CapsuleError):
        capsules.create_capsule(original[2], binding=binding, owner_private_key_path="not-read",
                                operational_public_key_path="not-read")


def test_capsule_creation_has_randomized_rsa_wrapping(keys, original):
    another = capsules.create_capsule(original[2], binding=original[3], owner_private_key_path=keys["owner"][0],
                                      operational_public_key_path=keys["operational"][1])
    first, second = capsules.inspect_capsule(original[4]), capsules.inspect_capsule(another)
    assert first["context"] == second["context"]
    assert first["wrapped_key"] != second["wrapped_key"]


def test_capsule_creation_does_not_create_files(tmp_path, keys, original):
    before = {path: path.read_bytes() for path in tmp_path.iterdir()}
    capsules.create_capsule(original[2], binding=original[3], owner_private_key_path=keys["owner"][0],
                            operational_public_key_path=keys["operational"][1])
    assert {path: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("key_format", [serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.OpenSSH])
def test_encrypted_owner_and_operational_keys(tmp_path, keys, rsa_keys, original, key_format):
    password = b"fixture-passphrase"
    private = []
    for name, key in zip(("owner", "operational"), rsa_keys):
        path = tmp_path / f"{name}-encrypted-private"
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, key_format,
                                          serialization.BestAvailableEncryption(password)))
        private.append(path)
    with pytest.raises(capsules.CapsuleError, match="passphrase"):
        capsules.create_capsule(original[2], binding=original[3], owner_private_key_path=private[0],
                                operational_public_key_path=keys["operational"][1], password=b"wrong")
    capsule = capsules.create_capsule(original[2], binding=original[3], owner_private_key_path=private[0],
                                      operational_public_key_path=keys["operational"][1], password=password)
    output = tmp_path / "restored"
    with pytest.raises(capsules.CapsuleError, match="passphrase"):
        capsules.decrypt_capsule_stream(io.BytesIO(original[1]), output, capsule, binding=original[3],
                                        operational_private_key_path=private[1])
    assert not output.exists()
    capsules.decrypt_capsule_stream(io.BytesIO(original[1]), output, capsule, binding=original[3],
                                    operational_private_key_path=private[1], password=password)
    assert output.read_bytes() == original[0]


def test_existing_destination_and_symlink_are_never_replaced(tmp_path, keys, original):
    output = tmp_path / "restored.xz"
    output.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        restore(tmp_path, keys, original)
    assert output.read_bytes() == b"preserve"
    output.unlink()
    output.symlink_to(tmp_path / "absent")
    with pytest.raises(FileExistsError):
        restore(tmp_path, keys, original)
    assert output.is_symlink() and not (tmp_path / "absent").exists()
    assert not list(tmp_path.glob(".icsot-capsule-decrypt-*"))


@pytest.mark.parametrize("content", [b"", b"exact noncanonical original AAD"])
def test_original_json_bytes_are_used_without_reserialization(tmp_path, keys, rsa_keys, original, content):
    key, nonce = os.urandom(32), os.urandom(12)
    header = {
        "key_wrap": "RSA-OAEP-SHA256", "cipher": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(rsa_keys[0].public_key().encrypt(key, encryption._oaep())).decode(),
        "plaintext_bytes": len(content), "plaintext_sha256": hashlib.sha256(content).hexdigest(),
        "public_key_fingerprint_sha256": encryption.public_key_fingerprint(keys["owner"][1]),
    }
    raw_header = json.dumps(header, indent=2).encode() + b"\n"
    aad = struct.pack(">8sBI", b"ICSOTENC", 1, len(raw_header)) + raw_header
    raw = aad + AESGCM(key).encrypt(nonce, content, aad)
    binding = {**original[3], "ciphertext_bytes": len(raw), "ciphertext_sha256": hashlib.sha256(raw).hexdigest()}
    capsule = capsules.create_capsule(aad, binding=binding, owner_private_key_path=keys["owner"][0],
                                      operational_public_key_path=keys["operational"][1])
    output, _ = restore(tmp_path, keys, original, raw=raw, binding=binding, capsule=capsule)
    assert output.read_bytes() == content
    reserialized = canonical(header).rstrip(b"\n")
    changed_aad = struct.pack(">8sBI", b"ICSOTENC", 1, len(reserialized)) + reserialized
    output.unlink()
    with pytest.raises(capsules.CapsuleError):
        restore(tmp_path, keys, original, raw=changed_aad + raw[len(aad):], binding=binding, capsule=capsule)


def test_exact_cipher_hash_is_verified_even_with_valid_original_gcm(tmp_path, keys, original):
    binding = {**original[3], "ciphertext_sha256": "f" * 64}
    capsule = capsules.create_capsule(original[2], binding=binding, owner_private_key_path=keys["owner"][0],
                                      operational_public_key_path=keys["operational"][1])
    with pytest.raises(capsules.CapsuleError, match="ciphertext hash"):
        restore(tmp_path, keys, original, binding=binding, capsule=capsule)
    assert not (tmp_path / "restored.xz").exists()
    assert not list(tmp_path.glob(".icsot-capsule-decrypt-*"))


def test_plaintext_hash_is_checked_after_original_authentication(tmp_path, keys, rsa_keys, original):
    content, _, aad, binding, _, _ = original
    header = json.loads(aad[13:])
    key = rsa_keys[0].decrypt(base64.b64decode(header["wrapped_key"]), encryption._oaep())
    header["plaintext_sha256"] = "0" * 64
    raw_header = canonical(header).rstrip(b"\n")
    changed_aad = struct.pack(">8sBI", b"ICSOTENC", 1, len(raw_header)) + raw_header
    raw = changed_aad + AESGCM(key).encrypt(base64.b64decode(header["nonce"]), content, changed_aad)
    binding = {**binding, "ciphertext_bytes": len(raw), "ciphertext_sha256": hashlib.sha256(raw).hexdigest()}
    capsule = capsules.create_capsule(changed_aad, binding=binding, owner_private_key_path=keys["owner"][0],
                                      operational_public_key_path=keys["operational"][1])
    with pytest.raises(capsules.CapsuleError, match="plaintext size or hash"):
        restore(tmp_path, keys, original, raw=raw, binding=binding, capsule=capsule)
    assert not (tmp_path / "restored.xz").exists()


def test_invalid_aes_key_lengths_are_rejected(tmp_path, keys, rsa_keys, original):
    document = capsules.inspect_capsule(original[4])
    document["wrapped_key"] = base64.b64encode(rsa_keys[1].public_key().encrypt(b"x" * 31,
                                                                           capsules._oaep(document))).decode()
    with pytest.raises(capsules.CapsuleError, match="AES key length"):
        restore(tmp_path, keys, original, capsule=canonical(document))
    header = json.loads(original[2][13:])
    header["wrapped_key"] = base64.b64encode(rsa_keys[0].public_key().encrypt(b"x" * 31, encryption._oaep())).decode()
    raw_header = canonical(header).rstrip(b"\n")
    aad = struct.pack(">8sBI", b"ICSOTENC", 1, len(raw_header)) + raw_header
    with pytest.raises(capsules.CapsuleError, match="AES key length"):
        capsules.create_capsule(aad, binding={**original[3], "ciphertext_bytes": len(aad) + len(original[0]) + 16},
                                owner_private_key_path=keys["owner"][0], operational_public_key_path=keys["operational"][1])
