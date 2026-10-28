"""Content-pinned small metadata stored in an append-only Git branch."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from .core import REPO_RE, canonical_json

BRANCH = "collector-metadata"
MAX_BLOB_BYTES = 64 * 1024 * 1024
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*\Z")


class MetadataError(RuntimeError):
    """Invalid metadata, integrity mismatch, or publication conflict."""


def _path(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 1024 or
            any(not _SEGMENT.fullmatch(segment) or segment in (".", "..")
                for segment in value.split("/"))):
        raise MetadataError("Invalid metadata path")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or not _SHA1.fullmatch(value):
        raise MetadataError("Invalid Git object identifier")
    return value


def _repository(value: object) -> str:
    if not isinstance(value, str) or not REPO_RE.fullmatch(value) or any(
            part in (".", "..") for part in value.split("/")):
        raise MetadataError("Invalid destination repository")
    return value


def validate_locator(locator: object, repository: str) -> dict:
    """Validate an untrusted locator for the exact destination repository."""
    repository = _repository(repository)
    if (not isinstance(locator, dict) or set(locator) != {
            "kind", "repository", "branch", "path", "commit_sha", "blob_sha", "sha256", "bytes"} or
            locator.get("kind") != "github_git_blob_v1" or locator.get("repository") != repository or
            locator.get("branch") != BRANCH):
        raise MetadataError("Invalid metadata locator")
    _path(locator["path"])
    _sha(locator["commit_sha"])
    _sha(locator["blob_sha"])
    if (not isinstance(locator["sha256"], str) or not _SHA256.fullmatch(locator["sha256"]) or
            type(locator["bytes"]) is not int or not 0 <= locator["bytes"] <= MAX_BLOB_BYTES):
        raise MetadataError("Invalid metadata locator digest or size")
    return locator


def _git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


class GitMetadataStore:
    def __init__(self, transport):
        self.transport = transport
        self.repository = _repository(transport.repository)
        self._prefix = f"repos/{self.repository}"
        self._blobs: dict[str, bytes] = {}
        self._trees: dict[str, list] = {}

    def _head(self) -> str | None:
        ref = self.transport._api(f"{self._prefix}/git/ref/heads/{BRANCH}", missing_ok=True)
        if ref is None:
            return None
        try:
            if ref["object"]["type"] != "commit":
                raise MetadataError("Invalid metadata branch head")
            return _sha(ref["object"]["sha"])
        except (KeyError, TypeError):
            raise MetadataError("Invalid metadata branch head") from None

    def _blob(self, sha: str) -> bytes:
        sha = _sha(sha)
        if sha in self._blobs:
            return self._blobs[sha]
        obj = self.transport._api(f"{self._prefix}/git/blobs/{sha}")
        if (not isinstance(obj, dict) or obj.get("sha") != sha or obj.get("encoding") != "base64" or
                type(obj.get("size")) is not int or not 0 <= obj["size"] <= MAX_BLOB_BYTES or
                not isinstance(obj.get("content"), str)):
            raise MetadataError("Invalid Git blob response")
        content = obj["content"]
        encoded_bound = 4 * ((obj["size"] + 2) // 3)
        if len(content) > encoded_bound * 2 + 1024:
            raise MetadataError("Oversized Git blob response")
        try:
            encoded = content.replace("\n", "").replace("\r", "").encode("ascii")
            if len(encoded) != encoded_bound:
                raise ValueError
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            raise MetadataError("Invalid Git blob encoding") from None
        if len(raw) != obj["size"] or _git_blob_sha(raw) != sha:
            raise MetadataError("Git blob integrity mismatch")
        self._blobs[sha] = raw
        return raw

    def _lookup(self, head: str, path: str) -> tuple[str, bytes] | None:
        # Contents API may dereference a symlink. Check every tree mode before
        # consulting it, including parent components, at the pinned commit.
        commit = self.transport._api(f"{self._prefix}/git/commits/{head}")
        try:
            tree_sha = _sha(commit["tree"]["sha"])
        except (KeyError, TypeError):
            raise MetadataError("Invalid metadata commit tree") from None
        segments = path.split("/")
        for index, segment in enumerate(segments):
            if tree_sha not in self._trees:
                tree = self.transport._api(f"{self._prefix}/git/trees/{tree_sha}")
                if (not isinstance(tree, dict) or tree.get("sha") != tree_sha or
                        tree.get("truncated") is not False or not isinstance(tree.get("tree"), list)):
                    raise MetadataError("Invalid or truncated Git tree")
                self._trees[tree_sha] = tree["tree"]
            entries = [entry for entry in self._trees[tree_sha]
                       if isinstance(entry, dict) and entry.get("path") == segment]
            if not entries:
                return None
            if len(entries) != 1:
                raise MetadataError("Invalid duplicate Git tree entry")
            entry = entries[0]
            if index < len(segments) - 1:
                if entry.get("type") != "tree" or entry.get("mode") != "040000":
                    raise MetadataError("Metadata parent is not a directory")
                tree_sha = _sha(entry.get("sha"))
            elif entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755"):
                raise MetadataError("Metadata path is not a regular file")
            else:
                expected_sha = _sha(entry.get("sha"))
        endpoint = f"{self._prefix}/contents/{quote(path, safe='/')}?ref={head}"
        obj = self.transport._api(endpoint, missing_ok=True)
        if obj is None:
            return None
        if not isinstance(obj, dict) or obj.get("type") != "file":
            raise MetadataError("Metadata path is not a regular file")
        sha = _sha(obj.get("sha"))
        if sha != expected_sha:
            raise MetadataError("Metadata tree and file differ")
        raw = self._blob(sha)
        if type(obj.get("size")) is not int or obj["size"] != len(raw):
            raise MetadataError("Metadata file size mismatch")
        return sha, raw

    def _locator(self, path: str, head: str, sha: str, raw: bytes) -> dict:
        return {"kind": "github_git_blob_v1", "repository": self.repository, "branch": BRANCH,
                "path": path, "commit_sha": head, "blob_sha": sha,
                "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}

    def find(self, path: str) -> dict | None:
        path = _path(path)
        head = self._head()
        if head is None:
            return None
        found = self._lookup(head, path)
        return self._locator(path, head, *found) if found is not None else None

    def get(self, locator: object) -> bytes:
        loc = validate_locator(locator, self.repository)
        raw = self._blob(loc["blob_sha"])
        if len(raw) != loc["bytes"] or hashlib.sha256(raw).hexdigest() != loc["sha256"]:
            raise MetadataError("Metadata locator integrity mismatch")
        return raw

    def put(self, path: str, raw: bytes, *, allow_update: bool = False) -> dict:
        path = _path(path)
        if not isinstance(raw, bytes) or len(raw) > MAX_BLOB_BYTES or type(allow_update) is not bool:
            raise MetadataError("Invalid or oversized metadata bytes")
        sha = _git_blob_sha(raw)
        created_blob = False
        for _ in range(8):
            head = self._head()
            found = self._lookup(head, path) if head else None
            if found is not None:
                if found[1] == raw:
                    return self._locator(path, head, found[0], raw)
                if not allow_update:
                    raise MetadataError("Immutable metadata path already contains different bytes")
            if not created_blob:
                blob = self.transport._api(f"{self._prefix}/git/blobs", method="POST", payload={
                    "content": base64.b64encode(raw).decode("ascii"), "encoding": "base64"})
                if not isinstance(blob, dict) or blob.get("sha") != sha:
                    raise MetadataError("Created Git blob identifier mismatch")
                created_blob = True
            tree_payload = {"tree": [{"path": path, "mode": "100644", "type": "blob", "sha": sha}]}
            if head:
                commit = self.transport._api(f"{self._prefix}/git/commits/{head}")
                try:
                    tree_payload["base_tree"] = _sha(commit["tree"]["sha"])
                except (KeyError, TypeError):
                    raise MetadataError("Invalid metadata commit tree") from None
            tree = self.transport._api(f"{self._prefix}/git/trees", method="POST", payload=tree_payload)
            if not isinstance(tree, dict):
                raise MetadataError("Invalid created Git tree")
            tree_sha = _sha(tree.get("sha"))
            commit = self.transport._api(f"{self._prefix}/git/commits", method="POST", payload={
                "message": "Store collector metadata", "tree": tree_sha, "parents": [head] if head else []})
            if not isinstance(commit, dict):
                raise MetadataError("Invalid created Git commit")
            commit_sha = _sha(commit.get("sha"))
            try:
                if head:
                    self.transport._api(f"{self._prefix}/git/refs/heads/{BRANCH}", method="PATCH",
                                        payload={"sha": commit_sha, "force": False})
                else:
                    self.transport._api(f"{self._prefix}/git/refs", method="POST",
                                        payload={"ref": f"refs/heads/{BRANCH}", "sha": commit_sha})
            except Exception:
                # A failed or ambiguous write is retried only after a fresh read
                # proves that another writer moved or created the branch.
                if self._head() == head:
                    raise
                continue
            return self._locator(path, commit_sha, sha, raw)
        raise MetadataError("Too many concurrent metadata branch updates")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    put = commands.add_parser("put")
    put.add_argument("--repository", required=True)
    put.add_argument("--path", required=True)
    put.add_argument("--file", type=Path, required=True)
    put.add_argument("--github-output", type=Path)
    put.add_argument("--output-name", default="plan_locator")
    get = commands.add_parser("get")
    get.add_argument("--repository", required=True)
    get.add_argument("--locator-json", required=True)
    get.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    from .github_state import GhCliStateTransport
    store = GitMetadataStore(GhCliStateTransport(args.repository))
    if args.command == "put":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.output_name):
            raise MetadataError("Invalid output name")
        with args.file.open("rb") as source:
            raw = source.read(MAX_BLOB_BYTES + 1)
        locator = store.put(args.path, raw)
        line = canonical_json(locator).decode("ascii").rstrip("\n")
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                output.write(f"{args.output_name}={line}\n")
        print(line)
    else:
        try:
            locator = json.loads(args.locator_json)
        except (ValueError, TypeError):
            raise MetadataError("Invalid locator JSON") from None
        raw = store.get(locator)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(args.output, flags, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)


if __name__ == "__main__":
    main()
