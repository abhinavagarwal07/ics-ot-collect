import contextlib
import hashlib
import io
import lzma
import os
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import archive_reader
from icsot_observer.archive_reader import ArchiveError, ArchivePart, VerifiedArchiveReader, verify_encrypted_part
from icsot_observer.encryption import encrypt_file
from icsot_observer.localbudget import LocalBudget


@pytest.fixture(scope="module")
def generated_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def keys(tmp_path, generated_key):
    private, public = tmp_path / "generated-private.pem", tmp_path / "generated-public.pem"
    private.write_bytes(generated_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(private, 0o600)
    public.write_bytes(generated_key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public


def tar_bytes(members):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, payload in members:
            info = tarfile.TarInfo(path)
            if isinstance(payload, tarfile.TarInfo):
                archive.addfile(payload)
            else:
                info.size = len(payload)
                info.pax_headers = {"mtime": "123.456"}
                archive.addfile(info, io.BytesIO(payload))
    return target.getvalue()


def encrypted_parts(tmp_path, public, data, split=513):
    result = []
    for index, start in enumerate(range(0, len(data), split)):
        plain = tmp_path / f"generated-part-{index}"
        plain.write_bytes(data[start:start + split])
        cipher = plain.with_suffix(".enc")
        record = encrypt_file(plain, cipher, public)
        plain.unlink()
        result.append(ArchivePart(cipher, record["ciphertext_sha256"], record["ciphertext_bytes"],
            record["plaintext_sha256"], record["plaintext_bytes"], cipher.name))
    return result


def test_real_crypto_multipart_stream_and_index_hashes(tmp_path, keys):
    private, public = keys
    payload = b"sample CAS response\n" * 200
    digest = hashlib.sha256(payload).hexdigest()
    path = f"evidence/objects/sha256/{digest[:2]}/{digest}"
    members = [(path, payload), ("evidence/runs/one/first.manifest.json", b'{"status":"complete"}\n')]
    expected = {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                for name, data in members}
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes(members)), split=73)
    active, loaded, observed = [], [], {}

    @contextlib.contextmanager
    def provider(part):
        assert not active
        active.append(part.path)
        loaded.append(part.name)
        try:
            yield part
        finally:
            active.remove(part.path)

    def consume(record, stream):
        assert record.sha256 is None  # Provisional until all replay tags pass.
        observed[record.path] = stream.read()

    report = VerifiedArchiveReader((provider(part) for part in parts), private,
        expected_members=expected, allowed_prefixes=("evidence",)).scan(consume)
    assert observed == dict(members)
    assert len(report.parts) == len(parts) == len(loaded)
    assert report.total_bytes == sum(len(value) for value in observed.values())
    assert {row.path: row.sha256 for row in report.members} == {p: v["sha256"] for p, v in expected.items()}
    assert all(row.hash_source == "public_index" for row in report.members)
    assert report.git_validation == "not_restored_or_fscked"
    assert not active
    assert not list(tmp_path.glob(".icsot-decrypt-*"))


def test_bad_first_pass_never_reaches_tar_or_callback(tmp_path, keys):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("evidence/a", b"hello")])) )
    data = bytearray(parts[0].path.read_bytes())
    data[-1] ^= 1
    parts[0].path.write_bytes(data)
    called = []
    with pytest.raises(ArchiveError, match="authentication"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan(
            lambda *_: called.append(True))
    assert not called


def test_replay_source_change_invalidates_scan(tmp_path, keys, monkeypatch):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("evidence/a", b"hello")])) )
    real_pass = archive_reader._part_pass

    def mutate_before_replay(source, part, key, *, emit):
        if emit:
            with part.path.open("r+b") as target:
                target.seek(-1, 2)
                last = target.read(1)
                target.seek(-1, 2)
                target.write(bytes([last[0] ^ 1]))
        yield from real_pass(source, part, key, emit=emit)

    monkeypatch.setattr(archive_reader, "_part_pass", mutate_before_replay)
    with pytest.raises(ArchiveError, match="authentication"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()


@pytest.mark.parametrize("unsafe", ["../outside", "/absolute", "evidence/../outside", "evidence/a\\b", "evidence//a"])
def test_rejects_unsafe_tar_paths(tmp_path, keys, unsafe):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([(unsafe, b"x")])) )
    with pytest.raises(ArchiveError, match="Unsafe"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_rejects_nonregular_tar_members(tmp_path, keys, kind):
    private, public = keys
    member = tarfile.TarInfo("evidence/unsafe")
    member.type, member.linkname = kind, "outside"
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("unused", member)])))
    with pytest.raises(ArchiveError, match="regular"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()


def test_rejects_wrong_cas_digest_and_public_member_identity(tmp_path, keys):
    private, public = keys
    path = "evidence/objects/sha256/00/" + "0" * 64
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([(path, b"wrong")])) )
    with pytest.raises(ArchiveError, match="Content-addressed"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()
    # Reuse the actual CAS file with an explicit wrong size: declaration wins
    # before a callback can stage even a provisional member.
    with pytest.raises(ArchiveError, match="size differs"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",),
            expected_members={path: {"bytes": 999, "sha256": "0" * 64}}).scan()


def test_bounds_metadata_and_member_total(tmp_path, keys):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("evidence/a", b"x" * 4096)])))
    with pytest.raises(ArchiveError, match="metadata limit"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",), max_metadata_bytes=1024).scan(
            lambda record, stream: stream.read())
    with pytest.raises(ArchiveError, match="total"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",), max_total_bytes=1000).scan()
    # A smaller metadata bound must not prevent bounded hashing of a big file.
    assert VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",),
        max_metadata_bytes=1024).scan().total_bytes == 4096


def test_incomplete_attempt_can_authenticate_a_part_without_xz_claim(tmp_path, keys):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, b"a retained incomplete compressed prefix")
    result = verify_encrypted_part(parts[0], private)
    assert result["authentication"] == "authenticated"
    assert result["archive_validation"] == "not_attempted"
    with pytest.raises(ArchiveError, match="XZ"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()


def test_budgeted_downloads_hold_only_one_ciphertext_and_cleanup(tmp_path, keys):
    private, public = keys
    originals = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("evidence/a", os.urandom(16384))])), split=1000)
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=5_000_000)
    peaks = []

    @contextlib.contextmanager
    def download(part):
        assert not list((budget.root / "staging").iterdir())
        with budget.stage(part.ciphertext_bytes, suffix=".enc") as stage:
            with part.path.open("rb") as raw:
                stage.copy_from(raw)
            peaks.append(budget.snapshot().as_dict())
            yield ArchivePart(stage.path, part.ciphertext_sha256, part.ciphertext_bytes,
                              part.plaintext_sha256, part.plaintext_bytes)

    report = VerifiedArchiveReader((download(part) for part in originals), private,
                                   allowed_prefixes=("evidence",)).scan()
    assert len(report.parts) == len(originals)
    assert all(row["admitted_bytes"] <= row["limit_bytes"] for row in peaks)
    assert budget.snapshot().reserved_bytes == 0
    assert not list((budget.root / "staging").iterdir())


@pytest.mark.parametrize("suffix", [b"garbage", lzma.compress(b"second XZ stream")])
def test_rejects_trailing_compressed_streams(tmp_path, keys, suffix):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("evidence/a", b"hello")])) + suffix)
    with pytest.raises(ArchiveError, match="Trailing"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()


def test_rejects_oversized_pax_before_reading_extension(tmp_path, keys):
    private, public = keys
    extension = tarfile.TarInfo("././@PaxHeader")
    extension.type, extension.size = tarfile.XHDTYPE, 16 * 1024 * 1024 + 1
    incomplete_tar = extension.tobuf() + b"\0" * 1024
    parts = encrypted_parts(tmp_path, public, lzma.compress(incomplete_tar))
    with pytest.raises(ArchiveError, match="extension metadata exceeds"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()


def test_duplicate_members_and_undeclared_members_are_rejected(tmp_path, keys):
    private, public = keys
    parts = encrypted_parts(tmp_path, public,
                            lzma.compress(tar_bytes([("evidence/a", b"one"), ("evidence/a", b"two")])))
    with pytest.raises(ArchiveError, match="Duplicate"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",)).scan()
    with pytest.raises(ArchiveError, match="public index"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",), expected_members={}).scan()


def test_public_hash_failure_invalidates_provisional_callback(tmp_path, keys):
    private, public = keys
    parts = encrypted_parts(tmp_path, public, lzma.compress(tar_bytes([("evidence/a", b"one")])))
    provisional = []
    with pytest.raises(ArchiveError, match="hash differs"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",),
            expected_members={"evidence/a": {"bytes": 3, "sha256": "0" * 64}}).scan(
                lambda record, stream: provisional.append(stream.read()))
    assert provisional == [b"one"]  # Caller must discard this on scan failure.


def test_decoded_stream_bound_includes_compressed_zero_tail(tmp_path, keys):
    private, public = keys
    normal_tar = tar_bytes([("evidence/a", b"one")])
    padded_tar = normal_tar + b"\0" * 4096
    parts = encrypted_parts(tmp_path, public, lzma.compress(padded_tar))
    with pytest.raises(ArchiveError, match="Decoded tar stream"):
        VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",),
            max_total_bytes=3, max_tar_stream_bytes=len(normal_tar) + 1024).scan()
    # A sufficient stream bound preserves the separate regular-payload limit.
    assert VerifiedArchiveReader(parts, private, allowed_prefixes=("evidence",),
        max_total_bytes=3, max_tar_stream_bytes=len(padded_tar)).scan().total_bytes == 3
