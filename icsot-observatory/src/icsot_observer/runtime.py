"""Durable, independently leased API and Git work on a trusted collector host.

This is operational state, separate from the research metadata schema. Capture
handlers and finalizers run outside SQLite transactions. Finalizers must be
idempotent by capture_id and append immutable manifests under their repo lock.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .core import REPO_RE, canonical_json


class ControllerBusyError(RuntimeError):
    pass


class LeaseLostError(RuntimeError):
    pass


class RetryDeferred(Exception):
    def __init__(self, retry_not_before: float, reason: str, lane_wide: bool = False):
        super().__init__(reason)
        self.retry_not_before = float(retry_not_before)
        self.lane_wide = lane_wide


class ControllerLock:
    """Shares the legacy collector lock; hold for the controller's whole run."""

    _held: set[tuple[int, Path]] = set()

    def __init__(self, root: Path | str):
        self.path = Path(root).resolve() / ".collector.lock"
        self.fd: int | None = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise ControllerBusyError(f"Collector already owns {self.path}") from exc
        self.fd = fd
        self._held.add((os.getpid(), self.path))
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            self._held.discard((os.getpid(), self.path))
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None

    @classmethod
    def owned(cls, root: Path | str) -> bool:
        return (os.getpid(), Path(root).resolve() / ".collector.lock") in cls._held


@dataclass(frozen=True)
class Job:
    id: int
    slug: str
    lane: str
    mode: str
    capture_id: str
    payload: dict[str, Any]
    input_hash: str
    cohort: str | None
    ref: str | None
    state: str
    attempts: int
    finalize_attempts: int
    retry_not_before: float
    lease_token: str | None
    lease_expires: float | None
    captured: bool
    result: Any


@dataclass(frozen=True)
class ScopeWatermark:
    repository_id: int
    scope: str
    value: str


@dataclass(frozen=True)
class Finalization:
    manifest_path: Path | str
    manifest_digest: str
    candidates: Iterable[ScopeWatermark | dict[str, Any]] = ()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
 id INTEGER PRIMARY KEY, slug TEXT NOT NULL, slug_key TEXT NOT NULL,
 repository_key TEXT NOT NULL, lane TEXT NOT NULL CHECK(lane IN ('api','git')),
 mode TEXT NOT NULL, capture_id TEXT NOT NULL, payload_json TEXT NOT NULL,
 input_hash TEXT NOT NULL, cohort TEXT, ref TEXT, spec_json TEXT NOT NULL,
 priority INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'queued',
 created_at REAL NOT NULL, updated_at REAL NOT NULL, retry_not_before REAL NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0, finalize_attempts INTEGER NOT NULL DEFAULT 0,
 lease_token TEXT, lease_expires REAL, result_json TEXT,
 manifest_digest TEXT, last_error TEXT, UNIQUE(slug_key,lane,capture_id)
);
CREATE INDEX IF NOT EXISTS jobs_ready ON jobs(lane,state,retry_not_before,priority,created_at);
CREATE TABLE IF NOT EXISTS attempts (
 id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id),
 phase TEXT NOT NULL, lease_token TEXT NOT NULL, started_at REAL NOT NULL,
 finished_at REAL, outcome TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS manifests (digest TEXT PRIMARY KEY, path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS watermarks (
 repository_id INTEGER NOT NULL, scope TEXT NOT NULL, value TEXT NOT NULL,
 observed_at REAL NOT NULL, manifest_digest TEXT NOT NULL REFERENCES manifests(digest),
 PRIMARY KEY(repository_id,scope)
);
CREATE TABLE IF NOT EXISTS lane_cooldowns (
 lane TEXT PRIMARY KEY CHECK(lane IN ('api','git')), retry_not_before REAL NOT NULL, reason TEXT NOT NULL
);
"""


def _job(row: sqlite3.Row) -> Job:
    return Job(**{key: row[key] for key in (
        "id", "slug", "lane", "mode", "capture_id", "input_hash", "cohort", "ref",
        "state", "attempts", "finalize_attempts", "retry_not_before", "lease_token", "lease_expires"
    )}, payload=json.loads(row["payload_json"]), captured=row["result_json"] is not None,
        result=json.loads(row["result_json"]) if row["result_json"] is not None else None)


def _repository_key(slug: str, payload: dict[str, Any]) -> str:
    repo_id = payload.get("repository_id")
    return f"id:{repo_id}" if isinstance(repo_id, int) else f"slug:{slug.lower()}"


class PersistentQueue:
    def __init__(self, root: Path | str, *, clock: Callable[[], float] = time.time):
        self.root = Path(root).resolve()
        self.path = self.root / "runtime.sqlite3"
        self.clock = clock
        self.root.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(_SCHEMA)
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def enqueue(self, slug: str, lane: str = "api", mode: str = "delta",
                capture_id: str = "", payload: dict[str, Any] | None = None, *,
                priority: int = 0, input_hash: str | None = None,
                cohort: str | None = None, ref: str | None = None) -> Job:
        if not REPO_RE.fullmatch(slug) or slug.endswith(".git"):
            raise ValueError("Invalid repository slug")
        if lane not in ("api", "git") or not mode:
            raise ValueError("Job needs an API/Git lane, immutable capture_id and mode")
        if not isinstance(capture_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", capture_id):
            raise ValueError("capture_id must be a safe immutable path component")
        if payload is not None and not isinstance(payload, dict):
            raise ValueError("Job payload must be a JSON object")
        payload = payload or {}
        spec = canonical_json({"slug": slug, "lane": lane, "mode": mode,
                               "capture_id": capture_id, "payload": payload,
                               "cohort": cohort, "ref": ref}).decode()
        digest = input_hash or hashlib.sha256(spec.encode()).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("input_hash must be a SHA-256 digest")
        repository_key = _repository_key(slug, payload)
        now = self.clock()
        with self._transaction() as db:
            prior = db.execute("SELECT * FROM jobs WHERE slug_key=? AND lane=? AND capture_id=?",
                               (slug.lower(), lane, capture_id)).fetchone()
            if prior:
                if prior["spec_json"] != spec or prior["input_hash"] != digest:
                    raise ValueError("capture_id already has different immutable job inputs")
                return _job(prior)
            job_id = db.execute("""INSERT INTO jobs
                (slug,slug_key,repository_key,lane,mode,capture_id,payload_json,input_hash,
                 cohort,ref,spec_json,priority,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (slug, slug.lower(), repository_key, lane, mode, capture_id,
                 canonical_json(payload).decode(), digest, cohort, ref, spec, int(priority), now, now)).lastrowid
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def get(self, job_id: int) -> Job:
        with self._connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return _job(row)

    def jobs(self, *, state: str | None = None, lane: str | None = None,
             slug: str | None = None, include_complete: bool = True) -> list[Job]:
        where, args = [], []
        for key, value in (("state", state), ("lane", lane), ("slug_key", slug.lower() if slug else None)):
            if value is not None:
                where.append(f"{key}=?")
                args.append(value)
        if not include_complete:
            where.append("state!='complete'")
        query = "SELECT * FROM jobs" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id"
        with self._connection() as db:
            return [_job(row) for row in db.execute(query, args)]

    def status(self) -> dict[str, Any]:
        with self._connection() as db:
            states = {row["state"]: row["n"] for row in db.execute("SELECT state,count(*) AS n FROM jobs GROUP BY state")}
            cooldowns = [dict(row) for row in db.execute("SELECT * FROM lane_cooldowns WHERE retry_not_before>?", (self.clock(),))]
            retry = db.execute("SELECT min(retry_not_before) FROM jobs WHERE state!='complete' AND retry_not_before>?",
                               (self.clock(),)).fetchone()[0]
        return {"states": states, "lane_cooldowns": cooldowns, "next_retry_not_before": retry}

    def job_attempts(self, job_id: int) -> list[dict[str, Any]]:
        with self._connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM attempts WHERE job_id=? ORDER BY id", (job_id,))]

    def lease(self, lane: str, *, lease_seconds: float = 120,
              exclude_job_ids: Iterable[int] = (), exclude_repository_keys: Iterable[str] = (),
              exclude_slug_keys: Iterable[str] = ()) -> Job | None:
        if lane not in ("api", "git") or lease_seconds <= 0:
            raise ValueError("Valid lane and positive lease duration required")
        now = self.clock()
        exclude_sql, excluded = "", []
        for column, values in (("id", exclude_job_ids), ("repository_key", exclude_repository_keys),
                               ("slug_key", exclude_slug_keys)):
            values = tuple(values)
            if values:
                exclude_sql += f" AND j.{column} NOT IN (" + ",".join("?" for _ in values) + ")"
                excluded.extend(values)
        with self._transaction() as db:
            row = db.execute("""SELECT j.* FROM jobs j WHERE lane=? AND state!='complete'
                AND retry_not_before<=? AND (lease_expires IS NULL OR lease_expires<=?)
                AND NOT EXISTS (SELECT 1 FROM lane_cooldowns c WHERE c.lane=j.lane AND c.retry_not_before>?)
                AND NOT EXISTS (SELECT 1 FROM jobs busy WHERE (busy.repository_key=j.repository_key OR busy.slug_key=j.slug_key)
                    AND busy.lane=j.lane AND busy.id!=j.id AND busy.lease_expires>?)
                """ + exclude_sql + " ORDER BY (result_json IS NOT NULL) DESC,priority DESC,created_at,id LIMIT 1",
                (lane, now, now, now, now, *excluded)).fetchone()
            if row is None:
                return None
            if row["lease_token"]:
                db.execute("UPDATE attempts SET finished_at=?,outcome='lease_expired' WHERE job_id=? AND finished_at IS NULL",
                           (now, row["id"]))
            phase = "finalize" if row["result_json"] is not None else "capture"
            counter = "finalize_attempts" if phase == "finalize" else "attempts"
            token = uuid.uuid4().hex
            db.execute(f"UPDATE jobs SET state=?,{counter}={counter}+1,lease_token=?,lease_expires=?,updated_at=? WHERE id=?",
                       ("finalizing" if phase == "finalize" else "capturing", token, now + lease_seconds, now, row["id"]))
            db.execute("INSERT INTO attempts(job_id,phase,lease_token,started_at) VALUES(?,?,?,?)",
                       (row["id"], phase, token, now))
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def _owned(self, db: sqlite3.Connection, job: Job) -> sqlite3.Row:
        row = db.execute("SELECT * FROM jobs WHERE id=? AND lease_token=? AND lease_expires>? AND state!='complete'",
                         (job.id, job.lease_token, self.clock())).fetchone()
        if row is None or job.lease_token is None:
            raise LeaseLostError(f"Lease no longer owns job {job.id}")
        return row

    def renew(self, job: Job, *, lease_seconds: float = 120) -> Job:
        if lease_seconds <= 0:
            raise ValueError("Positive lease duration required")
        with self._transaction() as db:
            self._owned(db, job)
            db.execute("UPDATE jobs SET lease_expires=?,updated_at=? WHERE id=?",
                       (self.clock() + lease_seconds, self.clock(), job.id))
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (job.id,)).fetchone())

    def mark_captured(self, job: Job, result: Any) -> Job:
        encoded = canonical_json(result).decode()
        with self._transaction() as db:
            row = self._owned(db, job)
            if row["result_json"] is not None:
                raise ValueError("Job already has a durable capture result")
            db.execute("UPDATE jobs SET state='finalize_pending',result_json=?,updated_at=? WHERE id=?",
                       (encoded, self.clock(), job.id))
            db.execute("UPDATE attempts SET finished_at=?,outcome='captured' WHERE job_id=? AND finished_at IS NULL",
                       (self.clock(), job.id))
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (job.id,)).fetchone())

    def begin_finalize(self, job: Job) -> Job:
        with self._transaction() as db:
            row = self._owned(db, job)
            if row["state"] != "finalize_pending":
                raise ValueError("Job is not awaiting finalization")
            db.execute("UPDATE jobs SET state='finalizing',finalize_attempts=finalize_attempts+1,updated_at=? WHERE id=?",
                       (self.clock(), job.id))
            db.execute("INSERT INTO attempts(job_id,phase,lease_token,started_at) VALUES(?,?,?,?)",
                       (job.id, "finalize", job.lease_token, self.clock()))
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (job.id,)).fetchone())

    def defer(self, job: Job, retry_not_before: float, reason: str, *, lane_wide: bool = False) -> Job:
        retry = max(self.clock(), float(retry_not_before))
        with self._transaction() as db:
            row = self._owned(db, job)
            db.execute("""UPDATE jobs SET state=?,retry_not_before=?,lease_token=NULL,lease_expires=NULL,
                last_error=?,updated_at=? WHERE id=?""",
                ("finalize_pending" if row["result_json"] is not None else "queued", retry, reason[:5000], self.clock(), job.id))
            db.execute("UPDATE attempts SET finished_at=?,outcome='deferred',error=? WHERE job_id=? AND finished_at IS NULL",
                       (self.clock(), reason[:5000], job.id))
            if lane_wide:
                db.execute("""INSERT INTO lane_cooldowns VALUES(?,?,?) ON CONFLICT(lane) DO UPDATE SET
                    retry_not_before=max(retry_not_before,excluded.retry_not_before),reason=excluded.reason""",
                    (job.lane, retry, reason[:5000]))
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (job.id,)).fetchone())

    @staticmethod
    def _candidates(candidates: Iterable[ScopeWatermark | dict[str, Any]]) -> list[tuple[int, str, str, float]]:
        result = []
        for item in candidates:
            value = item if isinstance(item, ScopeWatermark) else ScopeWatermark(**item)
            if isinstance(value.repository_id, bool) or not isinstance(value.repository_id, int) or value.repository_id <= 0 or not value.scope:
                raise ValueError("Watermark needs a repository ID and scope")
            parsed = datetime.fromisoformat(value.value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("Watermarks must have an explicit timezone")
            result.append((value.repository_id, value.scope, value.value, parsed.timestamp()))
        return result

    def _verify_manifest(self, digest: str, path: Path | str | None) -> tuple[Path, dict[str, Any]]:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid manifest SHA-256")
        if path is None:
            with self._connection() as db:
                row = db.execute("SELECT path FROM manifests WHERE digest=?", (digest,)).fetchone()
            if row is None:
                raise ValueError("Manifest must exist and be supplied before watermark commit")
            path = row["path"]
        path = Path(path).resolve()
        if not path.is_relative_to(self.root / "runs") or not path.name.endswith(".manifest.json"):
            raise ValueError("Manifest must be an immutable runs/*.manifest.json artifact")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Manifest digest verification failed")
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise ValueError("Manifest must be a JSON object")
        return path, manifest

    @staticmethod
    def _commit_watermarks(db: sqlite3.Connection, digest: str, path: Path,
                           manifest: dict[str, Any], candidates: list[tuple[int, str, str, float]]):
        for repo_id, *_ in candidates:
            if manifest.get("repository_id") != repo_id:
                raise ValueError("Watermark repository does not match immutable manifest")
        for _, scope, value, _ in candidates:
            declared = manifest.get("watermark_candidates") or {}
            outcome = ((manifest.get("api") or {}).get("scope_statuses") or {}).get(scope) or {}
            if (manifest.get("lane") != "api" or declared.get(scope) != value or
                    outcome.get("status") != "complete_for_query" or outcome.get("query_started_at") != value):
                raise ValueError("Watermark needs an exact completed API scope in the immutable manifest")
        db.execute("INSERT INTO manifests(digest,path) VALUES(?,?) ON CONFLICT(digest) DO NOTHING", (digest, str(path)))
        for repo_id, scope, value, observed in candidates:
            db.execute("""INSERT INTO watermarks VALUES(?,?,?,?,?) ON CONFLICT(repository_id,scope) DO UPDATE SET
                value=excluded.value,observed_at=excluded.observed_at,manifest_digest=excluded.manifest_digest
                WHERE excluded.observed_at>watermarks.observed_at""", (repo_id, scope, value, observed, digest))

    def scope_watermark(self, repo_id: int, scope: str) -> str | None:
        with self._connection() as db:
            row = db.execute("SELECT value FROM watermarks WHERE repository_id=? AND scope=?", (repo_id, scope)).fetchone()
        return row[0] if row else None

    def commit_scope_watermarks(self, manifest_digest: str,
                                candidates: Iterable[ScopeWatermark | dict[str, Any]], *,
                                manifest_path: Path | str | None = None) -> None:
        path, manifest = self._verify_manifest(manifest_digest, manifest_path)
        values = self._candidates(candidates)
        with self._transaction() as db:
            self._commit_watermarks(db, manifest_digest, path, manifest, values)

    def complete(self, job: Job, finalized: Finalization) -> Job:
        path, manifest = self._verify_manifest(finalized.manifest_digest, finalized.manifest_path)
        values = self._candidates(finalized.candidates)
        with self._transaction() as db:
            row = self._owned(db, job)
            if row["result_json"] is None:
                raise ValueError("Capture result must be durable before completion")
            if manifest.get("capture_id") != row["capture_id"] or manifest.get("lane") != row["lane"]:
                raise ValueError("Manifest does not belong to this capture and lane")
            captured = json.loads(row["result_json"])
            repo_id = captured.get("repository_id") if isinstance(captured, dict) else None
            repo_id = repo_id if repo_id is not None else json.loads(row["payload_json"]).get("repository_id")
            if repo_id is not None and manifest.get("repository_id") != repo_id:
                raise ValueError("Manifest does not belong to this repository")
            self._commit_watermarks(db, finalized.manifest_digest, path, manifest, values)
            db.execute("""UPDATE jobs SET state='complete',manifest_digest=?,lease_token=NULL,lease_expires=NULL,
                updated_at=?,last_error=NULL WHERE id=?""", (finalized.manifest_digest, self.clock(), job.id))
            db.execute("UPDATE attempts SET finished_at=?,outcome='complete' WHERE job_id=? AND finished_at IS NULL",
                       (self.clock(), job.id))
            return _job(db.execute("SELECT * FROM jobs WHERE id=?", (job.id,)).fetchone())

    def run_pending(self, api_handler, git_handler, finalize_handler, **options) -> dict[str, Any]:
        return run_pending(self, api_handler, git_handler, finalize_handler, **options)


def run_pending(queue: PersistentQueue, api_handler: Callable[[Job], Any],
                git_handler: Callable[[Job], Any], finalize_handler: Callable[[Job, Any], Finalization], *,
                api_workers: int = 1, git_workers: int = 2, lease_seconds: float = 120,
                retry_seconds: float = 60, controller_locked: bool = False) -> dict[str, Any]:
    """Drain work eligible now. Deferred jobs remain durable for a later run.

    Pools are independent, so API quota waits cannot consume a Git permit. A
    heartbeat fences crashed workers; finalization retries use stored results.
    """
    if api_workers < 1 or git_workers < 1 or lease_seconds <= 0 or retry_seconds <= 0:
        raise ValueError("Positive worker counts, lease and retry durations required")
    if controller_locked and not ControllerLock.owned(queue.root):
        raise ValueError("controller_locked requires this process to hold ControllerLock(root)")
    summary: dict[str, Any] = {"completed": 0, "deferred": 0, "errors": [], "results": []}
    summary_lock = threading.Lock()
    attempted: set[int] = set()
    active: dict[int, Job] = {}

    def worker(lane: str, handler: Callable[[Job], Any]):
        while True:
            with summary_lock:
                # A lease fences durable mutations but cannot cancel a handler's
                # external side effects. Keep live callbacks mutually exclusive
                # even if their heartbeat fails and their SQLite lease expires.
                running = [job for job in active.values() if job.lane == lane]
                job = queue.lease(lane, lease_seconds=lease_seconds, exclude_job_ids=attempted,
                                  exclude_repository_keys=(_repository_key(job.slug, job.payload) for job in running),
                                  exclude_slug_keys=(job.slug.lower() for job in running))
                if job is not None:
                    attempted.add(job.id)
                    active[job.id] = job
            if job is None:
                return
            stop = threading.Event()
            lease_errors: list[Exception] = []

            def heartbeat():
                while not stop.wait(max(0.01, lease_seconds / 3)):
                    try:
                        queue.renew(job, lease_seconds=lease_seconds)
                    except Exception as exc:
                        lease_errors.append(exc)
                        return

            thread = threading.Thread(target=heartbeat, name=f"lease-{job.id}", daemon=True)
            thread.start()
            try:
                if not job.captured:
                    result = handler(job)
                    job = queue.mark_captured(job, result)
                    job = queue.begin_finalize(job)
                if lease_errors:
                    raise lease_errors[0]
                finalized = finalize_handler(job, job.result)
                queue.complete(job, finalized)
                with summary_lock:
                    summary["completed"] += 1
                    summary["results"].append({"job_id": job.id, "capture_id": job.capture_id,
                                               "lane": lane, "manifest": str(finalized.manifest_path),
                                               "manifest_sha256": finalized.manifest_digest})
            except Exception as exc:
                retry = exc.retry_not_before if isinstance(exc, RetryDeferred) else queue.clock() + retry_seconds
                try:
                    queue.defer(job, retry, f"{type(exc).__name__}: {exc}",
                                lane_wide=isinstance(exc, RetryDeferred) and exc.lane_wide)
                except LeaseLostError:
                    pass  # Another lease owns recovery; an expired worker cannot mutate it.
                with summary_lock:
                    summary["deferred"] += 1
                    summary["errors"].append({"job_id": job.id, "lane": lane, "error": f"{type(exc).__name__}: {exc}",
                                              "retry_not_before": retry})
            finally:
                stop.set()
                thread.join()
                with summary_lock:
                    active.pop(job.id, None)

    with nullcontext() if controller_locked else ControllerLock(queue.root):
        with ThreadPoolExecutor(max_workers=api_workers, thread_name_prefix="capture-api") as api_pool, \
                ThreadPoolExecutor(max_workers=git_workers, thread_name_prefix="capture-git") as git_pool:
            futures = [api_pool.submit(worker, "api", api_handler) for _ in range(api_workers)]
            futures += [git_pool.submit(worker, "git", git_handler) for _ in range(git_workers)]
            for future in futures:
                future.result()
    return summary
