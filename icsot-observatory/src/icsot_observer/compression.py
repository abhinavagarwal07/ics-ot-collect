"""Bounded, independent tar/XZ groups for native encrypted exports."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

GROUP_LIMIT = 500 * 1024**2
WORKERS = 4
XZ_COMMAND = ("xz", "-T1", "--no-adjust", "--memlimit-compress=2500MiB",
              "--lzma2=preset=8,dict=192MiB", "-c")
PROFILE = {"command": list(XZ_COMMAND)}
FALLBACK_PROFILE = {"format": "XZ", "command": list(XZ_COMMAND),
                    "layout": "single-tar-xz-stream-split-before-encryption", "encoder_processes": 1}
LEGACY_FALLBACK_REASON = "individual member exceeds grouped tar plaintext limit including tar headers and padding"


class OversizedMembers(ValueError):
    """Preflight found one or more whole files that cannot fit a tar group."""
    def __init__(self, count):
        self.count = count
        super().__init__(f"Archive member exceeds tar group limit ({count} total)")


def _tarinfo(member):
    info = tarfile.TarInfo("evidence/" + member["path"])
    info.size = member["bytes"]
    info.mode, info.uid, info.gid, info.mtime = 0o600, 0, 0, 0
    return info


def _tar_size(payload):
    return ((payload + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def plan_groups(members, *, limit=None):
    """Account exactly for PAX headers and the final tar record before writing."""
    if limit is None:
        limit = GROUP_LIMIT
    if type(limit) is not int or limit < tarfile.RECORDSIZE:
        raise ValueError("Tar group limit must fit an empty tar record")
    sizes = []
    for member in members:
        info = _tarinfo(member)
        overhead = len(info.tobuf(format=tarfile.PAX_FORMAT, encoding="utf-8", errors="strict"))
        sizes.append(overhead + ((info.size + 511) // 512) * 512)
    oversized = sum(_tar_size(size) > limit for size in sizes)
    if oversized:
        raise OversizedMembers(oversized)
    result, current, payload = [], [], 0
    for member, size in zip(members, sizes):
        if current and _tar_size(payload + size) > limit:
            result.append((current, _tar_size(payload)))
            current, payload = [], 0
        current.append(member)
        payload += size
    if current or not result:
        result.append((current, _tar_size(payload)))
    return result


class _HashingReader:
    def __init__(self, source):
        self.source, self.digest, self.count = source, hashlib.sha256(), 0

    def read(self, size):
        data = self.source.read(size)
        self.digest.update(data)
        self.count += len(data)
        return data


def write_tar_members(archive, root, members):
    """Write verified whole files into a streaming tar archive."""
    for member in members:
        path = Path(root) / member["path"]
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Archive member must be a regular file")
            reader = _HashingReader(source)
            archive.addfile(_tarinfo(member), reader)
            if (reader.count != member["bytes"] or reader.digest.hexdigest() != member["sha256"]
                    or source.read(1)):
                raise RuntimeError("Archive member changed during export")


def stream_tar_xz(root, members, destination, *, command=None):
    """Stream tar directly to xz; stderr is discarded and never accumulates."""
    with Path(destination).open("xb") as output:
        process = subprocess.Popen(XZ_COMMAND if command is None else command, stdin=subprocess.PIPE,
                                   stdout=output, stderr=subprocess.DEVNULL)
        try:
            with process.stdin as pipe:
                with tarfile.open(fileobj=pipe, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    write_tar_members(archive, root, members)
            if process.wait() != 0:
                raise RuntimeError("XZ compression failed")
        except BaseException:
            process.kill()
            process.wait()
            raise


def stream_tar_xz_to_sink(root, members, sink, *, command=None):
    """Pump one verified tar through one XZ process into a bounded encrypted-parts sink.

    The drain runs concurrently with the tar writer. Either side kills the
    process on failure so neither pipe can remain blocked on its peer.
    """
    process = subprocess.Popen(XZ_COMMAND if command is None else command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    drain_errors = []

    def drain():
        try:
            while chunk := process.stdout.read(1024 * 1024):
                sink.write(chunk)
        except BaseException as error:
            drain_errors.append(error)
            process.kill()
        finally:
            process.stdout.close()

    thread = threading.Thread(target=drain, name="icsot-xz-drain")
    thread.start()
    writer_error = None
    try:
        with process.stdin as pipe:
            with tarfile.open(fileobj=pipe, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                write_tar_members(archive, root, members)
    except BaseException as error:
        writer_error = error
        process.kill()
    finally:
        status = process.wait()
        thread.join()
    if drain_errors:
        raise drain_errors[0]
    if writer_error:
        raise writer_error
    if status:
        raise RuntimeError("XZ compression failed")


def export_groups(root, members, temporary, destination, prefix, public_key, *, limit=None,
                  workers=WORKERS, encoder=stream_tar_xz):
    """Compress and encrypt at most four groups concurrently; no uncompressed tar is staged."""
    from .encryption import encrypt_file
    if type(workers) is not int or not 1 <= workers <= WORKERS:
        raise ValueError("Compression worker count must be between 1 and 4")
    plan = plan_groups(members, limit=limit)  # all oversize failures precede output
    temp, destination = Path(temporary), Path(destination)
    created = []

    def produce(item):
        i, (group, tar_bytes) = item
        name = f"{prefix}.tar.xz.group-{i + 1:04d}.enc"
        plain = temp / f"group-{i + 1:04d}.xz"
        target = destination / name
        try:
            encoder(root, group, plain)
            encryption = encrypt_file(plain, target, public_key)
            asset = {"name": name, "sha256": encryption["ciphertext_sha256"],
                     "bytes": encryption["ciphertext_bytes"], "encryption": encryption}
            return asset, {"asset": {"name": name, "sha256": asset["sha256"]},
                           "members": group, "tar_plaintext_bytes": tar_bytes, "profile": PROFILE}
        finally:
            plain.unlink(missing_ok=True)

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # Batches keep both pending work and scratch-space reservations bounded.
            for offset in range(0, len(plan), workers):
                batch = plan[offset:offset + workers]
                need = sum(2 * (size + 8 * 1024**2) for _, size in batch)
                if shutil.disk_usage(temp).free < need:
                    raise RuntimeError("Insufficient scratch space for bounded XZ group batch")
                futures = [pool.submit(produce, (offset + j, group)) for j, group in enumerate(batch)]
                error = None
                for future in futures:
                    try:
                        result = future.result()
                        created.append(result)
                    except BaseException as exc:
                        error = error or exc
                if error:
                    raise error
        return [row[0] for row in created], [row[1] for row in created]
    except BaseException:
        for asset, _ in created:
            (destination / asset["name"]).unlink(missing_ok=True)
        raise
