"""Optional retry ledger; this is not the observation/index database.

All records are create-only, hash chained and fsynced. Bodies live in the normal
CAS. A ledger belongs to exactly one local root, repository and capture, and is
never a cache for a later scheduled observation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .core import canonical_json, sha256, write_once

_CAPTURE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")


class CheckpointError(RuntimeError):
    pass


class CheckpointStore:
    def __init__(self, root: Path, repository_id: int, capture_id: str):
        if type(repository_id) is not int or repository_id <= 0:
            raise ValueError("Positive numeric repository_id required")
        if not isinstance(capture_id, str) or not _CAPTURE_RE.fullmatch(capture_id):
            raise ValueError("Safe, explicit capture_id required")
        self.root = Path(root).resolve()
        self.repository_id, self.capture_id = repository_id, capture_id
        self.home = self.root / "checkpoints" / "api" / str(repository_id) / capture_id
        self.binding = {"schema_version": 1, "root": str(self.root),
                        "repository_id": repository_id, "capture_id": capture_id}
        binding_path = self.home / "binding.json"
        try:
            write_once(binding_path, canonical_json(self.binding))
        except FileExistsError:
            if binding_path.read_bytes() != canonical_json(self.binding):
                raise CheckpointError("Checkpoint root/repository/capture binding changed")
        self.events: list[dict[str, Any]] = []
        self._scopes: dict[str, dict] = {}
        self._restart_counts: dict[str, int] = {}
        self._last_digest: str | None = None
        self._load()

    def _load(self) -> None:
        for expected, path in enumerate(sorted(self.home.glob("*.event.json")), 1):
            raw = path.read_bytes()
            try:
                event = json.loads(raw)
                if (not isinstance(event, dict) or raw != canonical_json(event) or
                        event.get("sequence") != expected or
                        path.name != f"{expected:012d}.event.json" or
                        event.get("previous_sha256") != self._last_digest or
                        event.get("binding") != self.binding or
                        not isinstance(event.get("kind"), str) or
                        not isinstance(event.get("data"), dict)):
                    raise ValueError("invalid envelope or lineage")
            except (ValueError, TypeError) as exc:
                raise CheckpointError(f"Corrupt checkpoint ledger: {path.name}") from exc
            self.events.append(event)
            self._apply_scope_event(event)
            self._last_digest = sha256(raw)

    def append(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        event = {"sequence": len(self.events) + 1, "previous_sha256": self._last_digest,
                 "binding": self.binding, "kind": kind, "data": data}
        raw = canonical_json(event)
        path = self.home / f"{event['sequence']:012d}.event.json"
        try:
            write_once(path, raw)
        except FileExistsError as exc:
            raise CheckpointError("Concurrent checkpoint writer; exclusive capture lock required") from exc
        # Round-trip isolates durable data from mutable caller envelopes.
        durable = json.loads(raw)
        self.events.append(durable)
        self._apply_scope_event(durable)
        self._last_digest = sha256(raw)
        return durable

    def bind_options(self, options: dict[str, Any]) -> None:
        for event in self.events:
            if event["kind"] == "capture_options":
                if canonical_json(event["data"]) != canonical_json(options):
                    raise CheckpointError("Capture query/options changed; use a new capture_id")
                return
        self.append("capture_options", options)

    def record_response(self, record: dict, context: dict | None = None) -> dict:
        provenance = {"capture_id": self.capture_id, "repository_id": self.repository_id,
                      "event_sequence": len(self.events) + 1,
                      "scope": (context or {}).get("scope"),
                      "attempt_id": (context or {}).get("attempt_id")}
        record["checkpoint_provenance"] = provenance
        return self.append("response", {"record": record})

    def response(self, sequence: int) -> dict:
        if type(sequence) is not int or not 0 < sequence <= len(self.events):
            raise CheckpointError("Invalid response checkpoint reference")
        event = self.events[sequence - 1]
        if event["kind"] != "response":
            raise CheckpointError("Checkpoint does not reference a response envelope")
        # Do not let manifest decorations mutate the durable ledger in memory.
        return json.loads(canonical_json(event["data"]["record"]))

    def responses(self) -> list[dict]:
        return [self.response(event["sequence"]) for event in self.events if event["kind"] == "response"]

    def _apply_scope_event(self, event: dict) -> None:
        data, kind = event["data"], event["kind"]
        scope = data.get("scope")
        if scope is None:
            return
        state = self._scopes.get(scope)
        if kind == "scope_started":
            self._scopes[scope] = {**data, "pages": [], "outcome": None,
                                   "restarts": self._restart_counts.get(scope, 0)}
        elif kind in ("scope_abandoned", "scope_page", "scope_finished", "scope_failed"):
            if state is None or data.get("attempt_id") != state["attempt_id"]:
                raise CheckpointError("Scope checkpoint attempt lineage changed")
            if kind == "scope_abandoned":
                restarts = self._restart_counts.get(scope, 0) + 1
                self._restart_counts[scope] = restarts
                state["restarts"], state["abandoned"] = restarts, True
            elif kind == "scope_page":
                state["pages"].append(data)
            else:
                state["outcome"] = data

    def scope_state(self, scope: str) -> dict | None:
        # Replaying the entire ledger for each of thousands of deep endpoints
        # would make collection quadratic. Rebuild this index once at load and
        # update it with each durable append instead.
        state = self._scopes.get(scope)
        return json.loads(canonical_json(state)) if state is not None else None
