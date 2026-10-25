from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tomllib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_github_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def run_id() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def write_once(path: Path, contents: bytes) -> None:
    """Atomic create-only file; raise if path exists. Sync data and directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(contents)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            raise
        # os.link is create-only; os.replace would silently overwrite evidence.
        os.link(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        tmp.unlink(missing_ok=True)


@dataclass(frozen=True)
class Config:
    root: Path
    repositories: tuple[str, ...]
    api_version: str
    user_agent: str
    token_env: str
    http_timeout_seconds: int
    max_response_bytes: int
    overlap_hours: int
    max_pages: int

    @classmethod
    def load(cls, filename: str | Path) -> "Config":
        p = Path(filename).resolve()
        obj = tomllib.loads(p.read_text(encoding="utf-8"))
        c, cohort = obj["collector"], obj["cohort"]
        root = Path(c["root"])
        if not root.is_absolute():
            root = (p.parent / root).resolve()
        repos = tuple(cohort["repositories"])
        if not repos or len(set(x.lower() for x in repos)) != len(repos):
            raise ValueError("Nonempty, unique repository cohort required")
        for slug in repos:
            if not REPO_RE.fullmatch(slug) or slug.endswith(".git"):
                raise ValueError(f"Invalid repository slug: {slug!r}")
        version = c["api_version"]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", version):
            raise ValueError("Explicit GitHub API version YYYY-MM-DD required")
        return cls(root=root, repositories=repos, api_version=version,
                   user_agent=c["user_agent"], token_env=c["token_env"],
                   http_timeout_seconds=int(c.get("http_timeout_seconds", 35)),
                   max_response_bytes=int(c.get("max_response_mib", 32)) * 1024 * 1024,
                   overlap_hours=int(c.get("overlap_hours", 48)),
                   max_pages=int(c.get("max_pages", 10000)))


class ObjectStore:
    """Content-addressed immutable bytes; API bytes are NOT reformatted."""

    def __init__(self, root: Path):
        self.root = root

    def location(self, digest: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid SHA-256")
        return self.root / "objects" / "sha256" / digest[:2] / digest

    def put(self, contents: bytes) -> str:
        digest = sha256(contents)
        dest = self.location(digest)
        if not dest.exists():
            try:
                write_once(dest, contents)
            except FileExistsError:
                pass  # concurrent writer; still verify
        if sha256(dest.read_bytes()) != digest:
            raise RuntimeError(f"CAS corruption: {dest}")
        return digest

    def put_file(self, source: Path) -> tuple[str, int]:
        """Stream large immutable evidence (such as a portable Git bundle) to CAS."""
        h, total = hashlib.sha256(), 0
        with source.open("rb") as inp:
            while chunk := inp.read(4 * 1024 * 1024):
                h.update(chunk)
                total += len(chunk)
        digest = h.hexdigest()
        dest = self.location(digest)
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name("." + dest.name + "." + uuid.uuid4().hex + ".tmp")
            try:
                with source.open("rb") as inp, tmp.open("xb") as output:
                    shutil.copyfileobj(inp, output, length=4 * 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.link(tmp, dest)  # immutable create; cannot overwrite existing
                dfd = os.open(dest.parent, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except FileExistsError:
                pass
            finally:
                tmp.unlink(missing_ok=True)
        if not self.verify(digest):
            raise RuntimeError(f"CAS integrity failure for large file: {digest}")
        return digest, total

    def verify(self, digest: str) -> bool:
        h = hashlib.sha256()
        with self.location(digest).open("rb") as inp:
            while chunk := inp.read(4 * 1024 * 1024):
                h.update(chunk)
        return h.hexdigest() == digest

    def get(self, digest: str) -> bytes:
        data = self.location(digest).read_bytes()
        if sha256(data) != digest:
            raise RuntimeError(f"CAS integrity failure: {digest}")
        return data
