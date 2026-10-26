"""Authenticate retained envelope parts and inspect tar/XZ without extraction.

Each part is authenticated to a discard sink before its plaintext enters the
XZ parser. The same open encrypted file is then replayed, with its tag and both
identities checked again. No complete plaintext file is staged. Member callback
effects are provisional until ``scan`` returns successfully; a changed source,
later corrupt part, or mismatching member invalidates the entire scan.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import lzma
import os
import re
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, ContextManager, Iterable, Iterator, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import encryption as enc

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CAS = re.compile(r"(?:evidence/)?objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})\Z")
_CHUNK = 1024 * 1024


class ArchiveError(ValueError):
    """An unsafe, corrupt, unbounded, or inconsistent retained archive."""


@dataclass(frozen=True)
class ArchivePart:
    path: Path
    ciphertext_sha256: str
    ciphertext_bytes: int
    plaintext_sha256: str
    plaintext_bytes: int
    name: str = ""

    def __post_init__(self):
        object.__setattr__(self, "path", Path(self.path))
        for value in (self.ciphertext_sha256, self.plaintext_sha256):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ArchiveError("Archive part requires declared SHA-256 identities")
        for value in (self.ciphertext_bytes, self.plaintext_bytes):
            if type(value) is not int or value < 0:
                raise ArchiveError("Archive part requires declared integer byte counts")
        if self.plaintext_bytes > enc.MAX_PLAINTEXT_BYTES:
            raise ArchiveError("Archive part exceeds the encryption format bound")


@dataclass
class MemberRecord:
    path: str
    bytes: int
    sha256: str | None = None
    hash_source: str = "observed"


@dataclass
class ArchiveScan:
    members: list[MemberRecord] = field(default_factory=list)
    parts: list[dict[str, Any]] = field(default_factory=list)
    total_bytes: int = 0
    authentication: str = "authenticated_twice"
    git_validation: str = "not_restored_or_fscked"


def _safe_path(name: str) -> str:
    if (not isinstance(name, str) or not name or len(name.encode("utf-8")) > 4096
            or name.startswith("/") or "\\" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(piece in ("", ".", "..") for piece in name.split("/"))):
        raise ArchiveError("Unsafe archive member path")
    return name


def _part_pass(source: BinaryIO, part: ArchivePart, private_key, *, emit: bool) -> Iterator[bytes]:
    source.seek(0)
    if enc._regular_file_size(source) != part.ciphertext_bytes:
        raise ArchiveError("Encrypted archive part length differs from public index")
    prefix = enc._read_exact(source, enc._PREFIX.size)
    magic, version, header_size = enc._PREFIX.unpack(prefix)
    if magic != enc.MAGIC or version != enc.VERSION or not 0 < header_size <= enc.MAX_HEADER_BYTES:
        raise ArchiveError("Invalid archive encryption envelope")
    raw = enc._read_exact(source, header_size)
    header, nonce, wrapped_key = enc._parse_header(raw)
    if (header["plaintext_bytes"] != part.plaintext_bytes
            or not hmac.compare_digest(header["plaintext_sha256"], part.plaintext_sha256)
            or part.ciphertext_bytes != enc._PREFIX.size + header_size + part.plaintext_bytes + enc._TAG_BYTES):
        raise ArchiveError("Envelope plaintext identity differs from public index")
    if not hmac.compare_digest(header["public_key_fingerprint_sha256"],
                               enc._fingerprint(private_key.public_key())):
        raise ArchiveError("Encrypted archive belongs to a different RSA key")
    if len(wrapped_key) != (private_key.key_size + 7) // 8:
        raise ArchiveError("Invalid wrapped archive key length")
    try:
        key = private_key.decrypt(wrapped_key, enc._oaep())
    except ValueError:
        raise ArchiveError("Unable to unwrap archive key") from None
    if len(key) != 32:
        raise ArchiveError("Invalid unwrapped archive key length")
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
    decryptor.authenticate_additional_data(prefix + raw)
    cipher_digest, plain_digest = hashlib.sha256(prefix + raw), hashlib.sha256()
    remaining, count = part.plaintext_bytes, 0
    while remaining:
        chunk = enc._read_exact(source, min(_CHUNK, remaining))
        remaining -= len(chunk)
        cipher_digest.update(chunk)
        plaintext = decryptor.update(chunk)
        plain_digest.update(plaintext)
        count += len(plaintext)
        if emit and plaintext:
            yield plaintext
    tag = enc._read_exact(source, enc._TAG_BYTES)
    cipher_digest.update(tag)
    if source.read(1):
        raise ArchiveError("Trailing bytes in encrypted archive part")
    try:
        final = decryptor.finalize_with_tag(tag)
    except InvalidTag:
        raise ArchiveError("Encrypted archive part authentication failed") from None
    plain_digest.update(final)
    count += len(final)
    if (count != part.plaintext_bytes
            or not hmac.compare_digest(plain_digest.hexdigest(), part.plaintext_sha256)
            or not hmac.compare_digest(cipher_digest.hexdigest(), part.ciphertext_sha256)):
        raise ArchiveError("Archive part hash differs from declared identity")
    if emit and final:
        yield final


def _plaintext_parts(parts, private_key, report: ArchiveScan) -> Iterator[bytes]:
    count = 0
    for candidate in parts:
        manager = contextlib.nullcontext(candidate) if isinstance(candidate, ArchivePart) else candidate
        with manager as part:
            if not isinstance(part, ArchivePart):
                raise TypeError("Part provider must yield ArchivePart")
            # Reject symlinks; retain this descriptor for both passes so replacing
            # the filename cannot substitute a different file for the replay.
            fd = os.open(part.path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ArchiveError("Archive part must be a regular encrypted file")
                for _ in _part_pass(source, part, private_key, emit=False):
                    pass
                yield from _part_pass(source, part, private_key, emit=True)
            report.parts.append({"name": part.name or part.path.name,
                "ciphertext_sha256": part.ciphertext_sha256, "ciphertext_bytes": part.ciphertext_bytes,
                "plaintext_sha256": part.plaintext_sha256, "plaintext_bytes": part.plaintext_bytes,
                "authentication": "authenticated_twice"})
            count += 1
    if not count:
        raise ArchiveError("Archive requires at least one encrypted part")


def verify_encrypted_part(part: ArchivePart, private_key_path: str | os.PathLike,
                          *, password: bytes | None = None) -> dict[str, Any]:
    """Authenticate one available part without assuming a complete XZ package.

    Suitable for retained incomplete attempts: successful authentication makes
    no claim that other parts, the XZ footer, or the tar archive are present.
    No plaintext is saved or returned.
    """
    try:
        private_key = enc._load_private_key(private_key_path, password)
    except enc.EncryptionError as error:
        raise ArchiveError(str(error)) from None
    fd = os.open(part.path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, "rb") as source:
            for _ in _part_pass(source, part, private_key, emit=False):
                pass
    except enc.EncryptionError as error:
        raise ArchiveError(str(error)) from None
    return {"name": part.name or part.path.name, "ciphertext_sha256": part.ciphertext_sha256,
            "ciphertext_bytes": part.ciphertext_bytes, "plaintext_sha256": part.plaintext_sha256,
            "plaintext_bytes": part.plaintext_bytes, "authentication": "authenticated",
            "archive_validation": "not_attempted"}


def _xz_chunks(chunks: Iterable[bytes], *, memory_limit: int,
               max_output_bytes: int) -> Iterator[bytes]:
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=memory_limit)
    ended, output_bytes = False, 0
    try:
        for chunk in chunks:
            if ended:
                if chunk:
                    raise ArchiveError("Trailing data after the XZ stream")
                continue
            data = chunk
            while True:
                output = decoder.decompress(data, max_length=_CHUNK)
                data = b""
                if output:
                    output_bytes += len(output)
                    if output_bytes > max_output_bytes:
                        raise ArchiveError("Decoded tar stream exceeds its total byte bound")
                    yield output
                if decoder.eof:
                    if decoder.unused_data:
                        raise ArchiveError("Trailing data after the XZ stream")
                    ended = True
                    break
                if decoder.needs_input:
                    break
        if not ended:
            raise ArchiveError("Truncated XZ archive stream")
    except lzma.LZMAError:
        raise ArchiveError("Invalid or memory-limit-exceeding XZ archive stream") from None


class _ChunkReader:
    def __init__(self, chunks: Iterable[bytes]):
        self.chunks, self.buffer, self.eof = iter(chunks), bytearray(), False

    def read(self, size: int) -> bytes:
        if not 0 <= size <= 16 * _CHUNK:
            raise ArchiveError("Archive reads require an explicit bounded size")
        while len(self.buffer) < size and not self.eof:
            try:
                self.buffer.extend(next(self.chunks))
            except StopIteration:
                self.eof = True
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def exact(self, size: int) -> bytes:
        data = self.read(size)
        if len(data) != size:
            raise ArchiveError("Truncated tar archive")
        return data

    def close(self):
        close = getattr(self.chunks, "close", None)
        if close:
            close()


class _MemberReader(io.RawIOBase):
    def __init__(self, source: _ChunkReader, size: int, metadata_limit: int):
        self.source, self.remaining = source, size
        self.metadata_limit, self.digest = metadata_limit, hashlib.sha256()

    def readable(self):
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self.remaining
        size = min(size, self.remaining)
        if size > self.metadata_limit:
            raise ArchiveError("Member read exceeds bounded metadata limit; stream explicit chunks")
        data = self.source.exact(size)
        self.remaining -= len(data)
        self.digest.update(data)
        return data

    def readinto(self, target):
        data = self.read(len(target))
        target[:len(data)] = data
        return len(data)


def _pax_fields(raw: bytes) -> dict[str, str]:
    result, offset = {}, 0
    while offset < len(raw):
        space = raw.find(b" ", offset, offset + 24)
        if space < 0 or not raw[offset:space].isdigit():
            raise ArchiveError("Invalid bounded PAX header")
        length = int(raw[offset:space])
        end = offset + length
        if length < 5 or end > len(raw) or raw[end - 1:end] != b"\n":
            raise ArchiveError("Invalid bounded PAX header")
        key, equals, value = raw[space + 1:end - 1].partition(b"=")
        if not equals or not key:
            raise ArchiveError("Invalid bounded PAX field")
        try:
            key, value = key.decode("utf-8"), value.decode("utf-8")
        except UnicodeError:
            raise ArchiveError("PAX fields must be UTF-8") from None
        if key in result or "sparse" in key.lower() or key in {"linkpath", "hdrcharset"}:
            raise ArchiveError("Unsupported or duplicate PAX field")
        result[key] = value
        offset = end
    return result


class VerifiedArchiveReader:
    def __init__(self, parts: Iterable[ArchivePart | ContextManager[ArchivePart]],
                 private_key_path: str | os.PathLike, *, password: bytes | None = None,
                 expected_members: Mapping[str, Mapping[str, Any]] | None = None,
                 allowed_prefixes: tuple[str, ...], max_members: int = 2_000_000,
                 max_member_bytes: int = 1 << 40, max_total_bytes: int = 1 << 44,
                 max_tar_stream_bytes: int = 1 << 44,
                 max_metadata_bytes: int = 16 * _CHUNK, xz_memory_limit: int = 64 * _CHUNK):
        self.parts, self.private_key_path, self.password = parts, private_key_path, password
        if not allowed_prefixes:
            raise ValueError("An explicit archive path allowlist is required")
        self.allowed_prefixes = tuple(_safe_path(path.rstrip("/")) for path in allowed_prefixes)
        self.max_members, self.max_member_bytes = max_members, max_member_bytes
        self.max_total_bytes, self.max_metadata_bytes = max_total_bytes, max_metadata_bytes
        self.max_tar_stream_bytes = max_tar_stream_bytes
        self.xz_memory_limit = xz_memory_limit
        if any(type(value) is not int or value <= 0 for value in (
                max_members, max_member_bytes, max_total_bytes, max_tar_stream_bytes,
                max_metadata_bytes, xz_memory_limit)):
            raise ValueError("Archive bounds must be positive integers")
        if max_metadata_bytes > 16 * _CHUNK:
            raise ValueError("Metadata bound may not exceed 16 MiB")
        self.expected_members = None
        if expected_members is not None:
            self.expected_members = {}
            for path, identity in expected_members.items():
                path = _safe_path(path)
                if (not isinstance(identity, Mapping) or type(identity.get("bytes")) is not int
                        or identity["bytes"] < 0 or not isinstance(identity.get("sha256"), str)
                        or not _SHA256.fullmatch(identity["sha256"])):
                    raise ArchiveError("Invalid declared archive member identity")
                self.expected_members[path] = dict(identity)

    def _allowed(self, path: str) -> bool:
        return any(path == prefix or path.startswith(prefix + "/") for prefix in self.allowed_prefixes)

    def scan(self, on_member: Callable[[MemberRecord, BinaryIO], None] | None = None) -> ArchiveScan:
        report = ArchiveScan()
        try:
            private_key = enc._load_private_key(self.private_key_path, self.password)
        except enc.EncryptionError as error:
            raise ArchiveError(str(error)) from None
        plaintext = _plaintext_parts(self.parts, private_key, report)
        source = _ChunkReader(_xz_chunks(plaintext, memory_limit=self.xz_memory_limit,
                                        max_output_bytes=self.max_tar_stream_bytes))
        seen, pending_pax, global_pax, longname = set(), {}, {}, None
        extensions, headers = 0, 0
        try:
            while True:
                block = source.exact(512)
                if block == b"\0" * 512:
                    if pending_pax or longname is not None:
                        raise ArchiveError("Unapplied tar extension metadata")
                    if source.exact(512) != b"\0" * 512:
                        raise ArchiveError("Invalid tar end marker")
                    # Drain to force every replay tag check and XZ footer check.
                    while trailing := source.read(_CHUNK):
                        if trailing.strip(b"\0"):
                            raise ArchiveError("Unexpected data after tar end marker")
                    break
                try:
                    member = tarfile.TarInfo.frombuf(block, encoding="utf-8", errors="strict")
                except (tarfile.HeaderError, UnicodeError, ValueError):
                    raise ArchiveError("Invalid tar header") from None
                headers += 1
                if headers > self.max_members * 4:
                    raise ArchiveError("Tar header count exceeds the bound")
                if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
                    extensions += 1
                    if extensions > 16 or not 0 <= member.size <= self.max_metadata_bytes:
                        raise ArchiveError("Tar extension metadata exceeds the bound")
                    raw = source.exact(member.size)
                    source.exact((-member.size) % 512)
                    if member.type == tarfile.GNUTYPE_LONGNAME:
                        if longname is not None:
                            raise ArchiveError("Duplicate tar long-name extension")
                        try:
                            longname = raw.rstrip(b"\0").decode("utf-8", errors="strict")
                        except UnicodeError:
                            raise ArchiveError("Tar long names must be UTF-8") from None
                    else:
                        fields = _pax_fields(raw)
                        target = global_pax if member.type == tarfile.XGLTYPE else pending_pax
                        if member.type == tarfile.XGLTYPE and any(key in fields for key in ("path", "size")):
                            raise ArchiveError("Global PAX path and size overrides are unsupported")
                        if target.keys() & fields.keys():
                            raise ArchiveError("Duplicate tar extension fields")
                        target.update(fields)
                        if sum(len(key.encode("utf-8")) + len(value.encode("utf-8"))
                               for key, value in target.items()) > self.max_metadata_bytes:
                            raise ArchiveError("Accumulated tar extension metadata exceeds the bound")
                    continue
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                    raise ArchiveError("Only regular files and directories are permitted in tar")
                if member.sparse is not None:
                    raise ArchiveError("Sparse tar members are unsupported")
                fields = {**global_pax, **pending_pax}
                name = fields.get("path", longname if longname is not None else member.name)
                path = _safe_path(name.rstrip("/") if member.isdir() else name)
                if not self._allowed(path):
                    raise ArchiveError("Tar member is outside the explicit path allowlist")
                if path in seen:
                    raise ArchiveError("Duplicate tar member path")
                seen.add(path)
                if len(seen) > self.max_members:
                    raise ArchiveError("Archive member count exceeds the bound")
                size = member.size
                if "size" in fields:
                    if not fields["size"].isascii() or not fields["size"].isdigit() or len(fields["size"]) > 20:
                        raise ArchiveError("Invalid PAX member size")
                    size = int(fields["size"])
                pending_pax, longname, extensions = {}, None, 0
                if size < 0 or size > self.max_member_bytes:
                    raise ArchiveError("Tar member size exceeds the bound")
                if member.isdir():
                    if size:
                        raise ArchiveError("Tar directories may not carry payloads")
                    continue
                report.total_bytes += size
                if report.total_bytes > self.max_total_bytes:
                    raise ArchiveError("Tar payload total exceeds the bound")
                declared = self.expected_members.get(path) if self.expected_members is not None else None
                if self.expected_members is not None and (declared is None or declared["bytes"] != size):
                    raise ArchiveError("Tar member path or size differs from public index")
                record, stream = MemberRecord(path, size), _MemberReader(source, size, self.max_metadata_bytes)
                if on_member:
                    on_member(record, stream)
                while stream.remaining:
                    stream.read(min(_CHUNK, self.max_metadata_bytes, stream.remaining))
                source.exact((-size) % 512)
                record.sha256 = stream.digest.hexdigest()
                cas = _CAS.fullmatch(path)
                if path.startswith(("objects/sha256/", "evidence/objects/sha256/")) and cas is None:
                    raise ArchiveError("Invalid content-addressed archive member path")
                if cas and (cas[1] != cas[2][:2] or not hmac.compare_digest(record.sha256, cas[2])):
                    raise ArchiveError("Content-addressed member SHA-256 mismatch")
                if declared and not hmac.compare_digest(record.sha256, declared["sha256"]):
                    raise ArchiveError("Tar member hash differs from public index")
                record.hash_source = "public_index" if declared else "cas_path" if cas else "observed"
                report.members.append(record)
            if self.expected_members is not None and set(self.expected_members) != {row.path for row in report.members}:
                raise ArchiveError("Archive lacks public-index members")
            return report
        except enc.EncryptionError as error:
            raise ArchiveError(str(error)) from None
        finally:
            source.close()
            plaintext.close()
