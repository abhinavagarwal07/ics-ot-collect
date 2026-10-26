"""Shared local-disk admission for cooperating audit and viewer processes.

All clients must use the SAME ``state_root``. Existing evidence is counted but
never evicted. Only files created and explicitly preserved by this module may
be evicted. A reservation is admission, not an OS quota for arbitrary child
processes; unbounded subprocess output must not be sent to a reserved path.
"""
from __future__ import annotations

import contextlib
import fcntl
import io
import json
import os
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

DEFAULT_LIMIT_BYTES = 2_000_000_000
_BOOKKEEPING_HEADROOM = 65_536
_FILE_OVERHEAD = 8_192
_STATE_BOUND = 1_048_576
_CHUNK = 1_048_576


class BudgetError(RuntimeError):
    """The shared task allocation cannot be admitted safely."""


def _allocated(info: os.stat_result) -> int:
    # st_blocks is physical allocation, including for sparse files. On systems
    # without it, logical size is the conservative available approximation.
    return int(info.st_blocks * 512) if hasattr(info, "st_blocks") else info.st_size


def _walk_allocations(roots: list[Path], owners: dict[str, list[Path]] | None = None,
                      seen: set[tuple[int, int]] | None = None) -> dict[str | None, int]:
    """Classify one set of inode observations as baseline or reserved work.

    A single walk is essential: independently measuring total bytes and then
    subtracting newer reserved-path measurements can undercount growing opaque
    subprocess output. Each observed inode belongs to at most one bucket.
    """
    seen = seen if seen is not None else set()
    buckets: dict[str | None, int] = {None: 0}
    observations: dict[tuple[int, int], tuple[str | None, int]] = {}
    claims = [(Path(os.path.abspath(path)), token) for token, paths in (owners or {}).items()
              for path in paths]
    # An ancestor root already covers its descendants. Prune nested roots
    # before walking so an explicitly registered directory inside a mounted
    # volume cannot bypass the opaque full-capacity accounting below.
    pending: list[Path] = []
    for root in sorted({Path(os.path.abspath(path)) for path in roots},
                       key=lambda path: (len(path.parts), str(path))):
        if not any(parent == root or parent in root.parents for parent in pending):
            pending.append(root)
    while pending:
        path = pending.pop()
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        identity = (info.st_dev, info.st_ino)
        if identity in seen and identity not in observations:
            continue
        matches = {token for prefix, token in claims if path == prefix or prefix in path.parents}
        if len(matches) > 1:
            raise BudgetError("Materialized reservations may not overlap")
        owner = next(iter(matches), None)
        if stat.S_ISDIR(info.st_mode) and os.path.ismount(path):
            # Mounted filesystems contain protected OS metadata (for example
            # HFS+ .fseventsd). Charge their ENTIRE capacity, including all such
            # metadata, rather than attempting partial recursive accounting.
            # Fixed-image reservations cover both backing image and capacity.
            volume = os.statvfs(path)
            fragment_bytes = volume.f_frsize or volume.f_bsize
            capacity = volume.f_blocks * fragment_bytes
            if fragment_bytes <= 0 or capacity <= 0:
                raise BudgetError("Cannot establish mounted filesystem capacity")
            allocation, opaque = capacity, True
        else:
            allocation, opaque = _allocated(info), False
        previous = observations.get(identity)
        if previous is not None:
            previous_owner, previous_bytes = previous
            # A hardlinked inode observed across ownership boundaries is charged
            # to baseline, retaining every involved full reservation. Use the
            # largest observation if a file grew during the walk.
            owner = owner if owner == previous_owner else None
            allocation = max(allocation, previous_bytes)
            buckets[previous_owner] -= previous_bytes
        buckets[owner] = buckets.get(owner, 0) + allocation
        observations[identity] = (owner, allocation)
        if previous is not None:
            continue
        seen.add(identity)
        if opaque:
            continue
        if stat.S_ISDIR(info.st_mode):
            # Never follow symlinks outside a registered root.
            with os.scandir(path) as entries:
                pending.extend(Path(entry.path) for entry in entries)
    return buckets


def _tree_bytes(roots: list[Path], seen: set[tuple[int, int]] | None = None) -> int:
    return sum(_walk_allocations(roots, seen=seen).values())


@dataclass(frozen=True)
class BudgetSnapshot:
    limit_bytes: int
    allocated_bytes: int
    reserved_bytes: int
    bookkeeping_bytes: int
    roots: tuple[str, ...]

    @property
    def admitted_bytes(self) -> int:
        return self.allocated_bytes + self.reserved_bytes + self.bookkeeping_bytes

    @property
    def available_bytes(self) -> int:
        return max(0, self.limit_bytes - self.admitted_bytes)

    def as_dict(self) -> dict:
        return {**self.__dict__, "admitted_bytes": self.admitted_bytes,
                "available_bytes": self.available_bytes}


class LocalBudget:
    """Cross-process flock-protected task budget with bounded managed writes."""

    def __init__(self, state_root: str | os.PathLike, *, roots=(),
                 limit_bytes: int = DEFAULT_LIMIT_BYTES):
        if type(limit_bytes) is not int or not 0 < limit_bytes <= DEFAULT_LIMIT_BYTES:
            raise ValueError("Local disk limit must be in 1..2,000,000,000 bytes")
        self.root = Path(state_root).resolve()
        roots = tuple(Path(path).resolve() for path in roots)
        missing, parent = 0, self.root
        while not parent.exists():
            missing += 1
            parent = parent.parent
        # Admit bounded control-directory bootstrap before creating anything.
        # The locked ledger subsequently includes concurrent reservations.
        bootstrap = _BOOKKEEPING_HEADROOM + (missing + 2) * _FILE_OVERHEAD
        if _tree_bytes([self.root, *roots]) + bootstrap > limit_bytes:
            raise BudgetError("Insufficient local task disk headroom for budget controls")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("staging", "cache"):
            (self.root / name).mkdir(exist_ok=True, mode=0o700)
        self.lock_path = self.root / "budget.lock"
        self.state_path = self.root / "budget.json"
        self.limit_bytes = limit_bytes
        with self._locked() as state:
            if state["limit_bytes"] != limit_bytes:
                raise BudgetError("Shared budget already uses a different limit")
            state["roots"] = sorted(set(state["roots"]) | {
                str(self.root), *(str(Path(path).resolve()) for path in roots)})
            self._assert_admitted(state)

    def _check_control_paths(self):
        for path in (self.root, self.root / "staging", self.root / "cache"):
            try:
                info = path.lstat()
            except FileNotFoundError:
                raise BudgetError("Managed budget directory is missing") from None
            if not stat.S_ISDIR(info.st_mode):
                raise BudgetError("Managed budget directories must be real directories, not symlinks")
        for path in (self.lock_path, self.state_path):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                raise BudgetError("Budget control files must be regular files, not symlinks")

    @contextlib.contextmanager
    def _locked(self) -> Iterator[dict]:
        self._check_control_paths()
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if self.state_path.exists():
                fd = os.open(self.state_path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    raw = stream.read(_STATE_BOUND + 1)
                if len(raw) > _STATE_BOUND:
                    raise BudgetError("Shared budget state is oversized")
                state = json.loads(raw)
                if state.get("version") != 1:
                    raise BudgetError("Unsupported shared budget state")
            else:
                state = {"version": 1, "limit_bytes": self.limit_bytes,
                         "roots": [str(self.root)], "reservations": {}, "cache": {}}
            # Stale reservations fail closed. A dead parent can leave children
            # still writing, and PID reuse cannot establish safe reclamation.
            # Explicit operator recovery must verify cleanup before releasing.
            yield state
            raw = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if len(raw) > _BOOKKEEPING_HEADROOM // 2:
                raise BudgetError("Too many budget registrations")
            temporary = self.root / (".budget-" + uuid.uuid4().hex)
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as target:
                    target.write(raw)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(temporary, self.state_path)
            finally:
                temporary.unlink(missing_ok=True)

    def _snapshot(self, state: dict) -> BudgetSnapshot:
        roots = [Path(path) for path in state["roots"]]
        owners = {token: [Path(path) for path in entry["paths"]]
                  for token, entry in state["reservations"].items()}
        observed = _walk_allocations(roots, owners)
        allocated = sum(observed.values())
        remaining = sum(max(0, entry["bytes"] - observed.get(token, 0))
                        for token, entry in state["reservations"].items())
        return BudgetSnapshot(state["limit_bytes"], allocated, remaining,
                              _BOOKKEEPING_HEADROOM, tuple(state["roots"]))

    def _assert_admitted(self, state: dict) -> BudgetSnapshot:
        snapshot = self._snapshot(state)
        if snapshot.admitted_bytes > snapshot.limit_bytes:
            raise BudgetError("Local task disk budget exceeded or insufficient headroom")
        return snapshot

    def snapshot(self) -> BudgetSnapshot:
        with self._locked() as state:
            return self._assert_admitted(state)

    check = snapshot

    def register_root(self, path: str | os.PathLike) -> BudgetSnapshot:
        with self._locked() as state:
            state["roots"] = sorted(set(state["roots"]) | {str(Path(path).resolve())})
            return self._assert_admitted(state)

    def reserve(self, max_bytes: int, *, purpose: str = "bounded work") -> "Reservation":
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("Reservation must be nonnegative integer bytes")
        token = uuid.uuid4().hex
        with self._locked() as state:
            state["reservations"][token] = {"bytes": max_bytes, "paths": [],
                "pid": os.getpid(), "purpose": str(purpose)[:160]}
            try:
                self._assert_admitted(state)
            except BudgetError:
                # Only explicitly managed cache files are eligible for eviction.
                for name, entry in sorted(state["cache"].items(), key=lambda item: item[1]["at"]):
                    if entry.get("leases"):
                        continue
                    path = self.root / "cache" / name
                    if path.parent == self.root / "cache" and path.is_file() and not path.is_symlink():
                        path.unlink()
                    del state["cache"][name]
                    if self._snapshot(state).admitted_bytes <= self.limit_bytes:
                        break
                self._assert_admitted(state)
        return Reservation(self, token)

    @contextlib.contextmanager
    def open_cached(self, path: str | os.PathLike) -> Iterator[BinaryIO]:
        """Pin a preserved cache file while reading, preventing unlink eviction.

        Cooperating clients must use this method instead of opening preserved
        paths directly. Ambiguous/crashed-reader leases also fail closed.
        """
        path = Path(path).absolute()
        if path.parent != self.root / "cache":
            raise BudgetError("Path is outside the managed cache")
        token, fd = uuid.uuid4().hex, None
        try:
            with self._locked() as state:
                entry = state["cache"].get(path.name)
                if entry is None:
                    raise BudgetError("Cache file is not registered")
                entry.setdefault("leases", []).append(token)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise BudgetError("Managed cache entry is not a regular file")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                yield stream
        finally:
            if fd is not None:
                os.close(fd)
            with self._locked() as state:
                entry = state["cache"].get(path.name)
                if entry and token in entry.get("leases", []):
                    entry["leases"].remove(token)

    def stage(self, max_bytes: int, *, suffix: str = "", purpose: str = "staged download") -> "Stage":
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("Stage bound must be nonnegative integer bytes")
        if not isinstance(suffix, str) or len(suffix) > 80 or any(c in suffix for c in "/\\\x00"):
            raise ValueError("Unsafe stage suffix")
        reservation = self.reserve(max_bytes + _FILE_OVERHEAD, purpose=purpose)
        path = self.root / "staging" / (uuid.uuid4().hex + suffix)
        try:
            with self._locked() as state:
                self._track(state, reservation.token, [str(path)], managed=True)
        except BaseException:
            reservation.close()
            raise
        return Stage(reservation, path, max_bytes)

    def _track(self, state: dict, token: str, normalized: list[str], *, managed=False):
        entry = state["reservations"][token]
        for name in normalized:
            path = Path(name)
            if not managed and path in (self.root, self.root / "staging", self.root / "cache"):
                raise BudgetError("Shared managed directories cannot be claimed by a reservation")
            if name not in entry["paths"]:
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    info = None
                if info is not None and (not stat.S_ISDIR(info.st_mode) or any(path.iterdir())):
                    raise BudgetError("Track only new paths or empty owned directories")
            for other_token, other in state["reservations"].items():
                if other_token == token:
                    continue
                for existing in other["paths"]:
                    other_path = Path(existing)
                    if path == other_path or path in other_path.parents or other_path in path.parents:
                        raise BudgetError("Materialized reservations may not overlap")
        entry["paths"] = sorted(set(entry["paths"]) | set(normalized))
        # Managed stages and new paths beneath the existing workspace need no
        # permanent per-file root registration. Avoid growing the ledger once
        # for every downloaded corpus part.
        roots = [Path(name) for name in state["roots"]]
        state["roots"] = sorted(set(state["roots"]) | {
            name for name in normalized
            if not any(Path(name) == root or root in Path(name).parents for root in roots)})


class Reservation:
    def __init__(self, budget: LocalBudget, token: str):
        self.budget, self.token, self.closed = budget, token, False

    def __enter__(self):
        return self

    def check(self) -> BudgetSnapshot:
        return self.budget.check()

    def track(self, *paths: str | os.PathLike) -> BudgetSnapshot:
        """Count materialized files/volumes against this reservation.

        Paths are also permanently registered as task roots. This does not
        impose a quota: callers writing outside bounded writers need an actual
        independent upper bound, such as an enforced fixed-size filesystem.
        """
        normalized = [str(Path(path).resolve()) for path in paths]
        with self.budget._locked() as state:
            if self.closed or self.token not in state["reservations"]:
                raise BudgetError("Reservation is no longer active")
            self.budget._track(state, self.token, normalized)
            return self.budget._assert_admitted(state)

    def close(self):
        if not self.closed:
            with self.budget._locked() as state:
                state["reservations"].pop(self.token, None)
            self.closed = True

    def __exit__(self, *args):
        self.close()


class _BoundedWriter(io.BufferedIOBase):
    def __init__(self, stage: "Stage"):
        self.stage, self.count = stage, 0
        with stage.reservation.budget._locked() as state:
            if stage.reservation.closed or stage.reservation.token not in state["reservations"]:
                raise BudgetError("Stage reservation is no longer active")
            stage.reservation.budget._assert_admitted(state)
            fd = os.open(stage.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.target = os.fdopen(fd, "wb", buffering=0)

    def writable(self):
        return True

    def write(self, data):
        if self.closed:
            raise ValueError("Write to closed stage")
        data = memoryview(data)
        if self.count + len(data) > self.stage.max_bytes:
            raise BudgetError("Staged output exceeds its declared byte bound")
        total = 0
        while total < len(data):
            chunk = data[total:total + _CHUNK]
            with self.stage.reservation.budget._locked() as state:
                if self.stage.reservation.token not in state["reservations"]:
                    raise BudgetError("Staged output reservation is no longer active")
                self.stage.reservation.budget._assert_admitted(state)
                written = self.target.write(chunk)
                if not written:
                    raise OSError("Short stage write")
            total += written
            self.count += written
        return total

    def flush(self):
        if not self.closed:
            self.target.flush()

    def close(self):
        if not self.closed:
            try:
                self.target.flush()
                os.fsync(self.target.fileno())
            finally:
                try:
                    super().close()
                finally:
                    self.target.close()


class Stage:
    """Temporary managed file; deletion on exit unless explicitly preserved."""
    def __init__(self, reservation: Reservation, path: Path, max_bytes: int):
        self.reservation, self.path, self.max_bytes = reservation, path, max_bytes
        self.writer: _BoundedWriter | None = None
        self.preserved = False

    def __enter__(self):
        return self

    def open_writer(self) -> BinaryIO:
        if self.writer is not None or self.preserved or self.reservation.closed:
            raise BudgetError("Stage writer can only be opened once")
        self.writer = _BoundedWriter(self)
        return self.writer

    def copy_from(self, source: BinaryIO) -> int:
        with self.open_writer() as target:
            while block := source.read(_CHUNK):
                target.write(block)
            return target.count

    def preserve(self) -> Path:
        if self.reservation.closed or self.writer is None or not self.writer.closed:
            raise BudgetError("Close the stage writer before preserving")
        budget = self.reservation.budget
        with budget._locked() as state:
            budget._assert_admitted(state)
            destination = budget.root / "cache" / self.path.name
            os.rename(self.path, destination)
            self.path = destination
            state["cache"][destination.name] = {"at": time.time(), "leases": []}
            state["reservations"].pop(self.reservation.token, None)
        self.reservation.closed = self.preserved = True
        return self.path

    def __exit__(self, *args):
        try:
            if self.writer is not None:
                self.writer.close()
        finally:
            if not self.preserved:
                self.path.unlink(missing_ok=True)
            self.reservation.close()
