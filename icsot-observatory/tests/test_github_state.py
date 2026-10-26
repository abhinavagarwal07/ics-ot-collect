"""Offline GitHub-state invariants with the production RSA envelope codec."""
import copy
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer.core import canonical_json
from icsot_observer.encryption import encrypt_file
from icsot_observer.github_state import (
    BRANCH, GhCliStateTransport, GitHubStateStore, StateConflictError, StateDeferredError,
    StateError, StateSelection,
)
from icsot_observer.runtime import ControllerLock


class FakeGitHub:
    def __init__(self):
        self.head = None
        self.commits = {}
        self.bindings = {}
        self.assets = {}
        self.uploads = []
        self.reads = []
        self.events = []
        self.fail_upload = None
        self.on_advance = None
        self.counter = 0

    def branch_head(self):
        return self.head

    def read_pointer(self, head, repository_id):
        self.reads.append(repository_id)
        return self.commits[head].get(repository_id)

    def read_slug_binding(self, head, slug):
        return self.bindings[head].get(slug.lower())

    def commit_pointer(self, parent, repository_id, data):
        self.counter += 1
        commit = hashlib.sha1(str(self.counter).encode()).hexdigest()
        tree = dict(self.commits[parent]) if parent else {}
        tree[repository_id] = data
        self.commits[commit] = tree
        bindings = dict(self.bindings[parent]) if parent else {}
        slug = json.loads(data)["slug"].lower()
        bindings[slug] = canonical_json({"schema_version": 1, "slug_key": slug, "repository_id": repository_id})
        self.bindings[commit] = bindings
        self.events.append(("commit", repository_id, parent))
        return commit

    def advance_branch(self, expected_head, commit):
        if self.on_advance:
            callback, self.on_advance = self.on_advance, None
            callback()
        if self.head != expected_head:
            return False
        self.head = commit
        self.events.append(("advance", commit))
        return True

    def ensure_release(self, tag):
        self.events.append(("release", tag))

    def upload_asset(self, tag, name, source):
        if self.fail_upload and self.fail_upload(name):
            raise StateError("Injected upload failure")
        assert (tag, name) not in self.assets
        self.assets[tag, name] = source.read_bytes()
        self.uploads.append((tag, name))
        self.events.append(("upload", name))

    def download_asset(self, tag, name, destination):
        self.events.append(("download", name))
        destination.write_bytes(self.assets[tag, name])


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def setup(tmp_path, rsa_key):
    public, private = tmp_path / "public.pem", tmp_path / "private.pem"
    public.write_bytes(rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private.write_bytes(rsa_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    transport = FakeGitHub()

    def make(repository_id=7, **kwargs):
        root = tmp_path / "working" / str(repository_id)
        root.mkdir(parents=True, exist_ok=True)
        return GitHubStateStore(transport, repository_id=repository_id,
                                slug=f"owner/repo{repository_id}",
                                logical_root=root, public_key=public, private_key=private, **kwargs)
    return transport, make, tmp_path


def write(store, name, value):
    path = store.root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def clear(store):
    for child in store.root.iterdir():
        if child.name == ".collector.lock":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def publish(store, selection=None, **kwargs):
    return store.publish(selection or store.read(), quiescent=True, **kwargs)


def test_roundtrip_selected_state_preserves_controller_lock_and_provenance(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoints/api/7/capture/binding.json", b'{"root":"frozen"}')
    write(store, "git/7.git/refs/icsot/test/ref", b"abcdef\n")
    data = b"raw API evidence"
    digest = hashlib.sha256(data).hexdigest()
    write(store, f"objects/sha256/{digest[:2]}/{digest}", data)
    executable = write(store, "git/7.git/hooks/custom", b"#!/bin/sh\n")
    executable.chmod(0o700)
    write(store, "git/7.git/icsot-verified-archive.git/objects/cache", b"disposable")
    write(store, "git/7.git/icsot-archive.lock", b"")
    with ControllerLock(store.root):
        inode = (store.root / ".collector.lock").stat().st_ino
        result = publish(store, code_hashes={"commit": "abc"}, config_hashes={"config": "def"},
                         lane_heads={"git": "head"}, evidence_heads={"api": "manifest"})
        assert result["new_parts"] == 2
        selected = store.read()
        assert selected.index["context"]["logical_root"] == str(store.root)
        assert selected.index["context"]["code_hashes"] == {"commit": "abc"}
        clear(store)
        restored = store.restore(selected)
        assert restored["files"] == 4
        assert (store.root / ".collector.lock").stat().st_ino == inode
    assert (store.root / f"objects/sha256/{digest[:2]}/{digest}").read_bytes() == data
    assert (store.root / "git/7.git/hooks/custom").stat().st_mode & 0o777 == 0o700
    assert not (store.root / "git/7.git/icsot-verified-archive.git").exists()
    assert set(transport.reads) == {7}
    assert result["state_referenced_ciphertext_bytes"] > 0


def test_sqlite_snapshot_uses_backup_and_includes_committed_wal(setup):
    _, make, _ = setup
    store = make()
    database = store.root / "runtime.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE committed(value TEXT)")
    connection.execute("INSERT INTO committed VALUES ('from WAL')")
    connection.commit()
    assert Path(str(database) + "-wal").stat().st_size > 0
    publish(store)
    selected = store.read()
    assert [item["path"] for item in selected.index["files"]] == ["runtime.sqlite3"]
    connection.close()
    clear(store)
    store.restore(selected)
    with sqlite3.connect(database) as restored:
        assert restored.execute("SELECT value FROM committed").fetchone() == ("from WAL",)
        assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_unchanged_cas_and_mutable_group_reuse_original_ciphertext(setup):
    transport, make, _ = setup
    store = make()
    data = b"content addressed object"
    digest = hashlib.sha256(data).hexdigest()
    write(store, f"objects/sha256/{digest[:2]}/{digest}", data)
    for number in range(40):
        write(store, f"git/7.git/refs/heads/ref{number}", f"{number}\n".encode())
    first = publish(store)
    selected = store.read()
    second = publish(store, selected)
    assert first["new_parts"] == 2
    assert second["new_parts"] == 0
    assert second["reused_parts"] == 2
    assert len(transport.uploads) == 4  # two payload parts plus two indexes
    again = store.read()
    assert again.index["parts"] == selected.index["parts"]
    assert again.pointer["predecessor_index_sha256"] == selected.pointer["index"]["ciphertext_sha256"]


def test_large_file_is_split_under_plaintext_limit(setup):
    _, make, _ = setup
    store = make(part_bytes=16 * 1024, mutable_group_bytes=1024)
    data = os.urandom(40 * 1024)
    write(store, "large", data)
    report = publish(store)
    selected = store.read()
    assert report["new_parts"] == 3
    assert len(selected.index["files"][0]["segments"]) == 3
    assert max(part["plaintext_bytes"] for part in selected.index["parts"].values()) <= 16 * 1024
    clear(store)
    store.restore(selected)
    assert (store.root / "large").read_bytes() == data


def test_cross_repository_pointer_substitution_fails_before_state_files(setup):
    transport, make, _ = setup
    one, two = make(7), make(8)
    write(one, "checkpoint", b"private working checkpoint")
    publish(one)
    stolen = transport.read_pointer(transport.head, 7)
    commit = transport.commit_pointer(transport.head, 8, stolen)
    transport.advance_branch(transport.head, commit)
    with pytest.raises(StateError, match="selected repository/root|slug binding"):
        two.read()
    assert list(two.root.iterdir()) == []


@pytest.mark.parametrize("field,value", [
    ("generation", "0" * 32),
    ("predecessor_index_sha256", "1" * 64),
    ("logical_root", "/tmp/another-root"),
])
def test_wrong_pointer_context_fails_before_materialization(setup, field, value):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    selected = store.read()
    pointer = copy.deepcopy(selected.pointer)
    pointer[field] = value
    commit = transport.commit_pointer(transport.head, 7, canonical_json(pointer))
    transport.advance_branch(transport.head, commit)
    clear(store)
    with pytest.raises(StateError):
        store.restore(store.read())
    assert not (store.root / "checkpoint").exists()


@pytest.mark.parametrize("truncated", [False, True])
def test_corrupt_or_truncated_payload_rejected_before_materialization(setup, truncated):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    selected = store.read()
    ref = next(iter(selected.index["parts"].values()))
    raw = transport.assets[ref["release_tag"], ref["name"]]
    transport.assets[ref["release_tag"], ref["name"]] = raw[:-10] if truncated else raw[:-1] + bytes([raw[-1] ^ 1])
    clear(store)
    with pytest.raises(StateError, match="hash/size"):
        store.restore(selected)
    assert not (store.root / "checkpoint").exists()


def test_index_ciphertext_corruption_rejected(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    report = publish(store)
    ref = report["pointer"]["index"]
    transport.assets[ref["release_tag"], ref["name"]] = b"truncated"
    with pytest.raises(StateError, match="hash/size"):
        store.read()


def test_upload_failure_never_advances_pointer(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    selected = store.read()
    old_head = transport.head
    write(store, "checkpoint", b"changed")
    transport.fail_upload = lambda name: name == "index.enc"
    with pytest.raises(StateError, match="upload failure"):
        publish(store, selected)
    assert transport.head == old_head
    assert transport.read_pointer(transport.head, 7) == canonical_json(selected.pointer)


def test_evidence_dependencies_verify_first_and_prior_catalog_is_reused(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    evidence = b"immutable machine RSA ciphertext"
    ref = {"release_tag": "observations-7", "name": "evidence.enc",
           "ciphertext_sha256": hashlib.sha256(evidence).hexdigest(), "ciphertext_bytes": len(evidence)}
    transport.assets[ref["release_tag"], ref["name"]] = evidence
    publish(store, dependencies=[ref])
    assert transport.events[0] == ("download", "evidence.enc")
    selected = store.read()
    transport.events.clear()
    publish(store, selected, dependencies=[ref])
    assert ("download", "evidence.enc") not in transport.events
    assert store.read().index["dependencies"] == [ref]


def test_bad_evidence_dependency_prevents_state_upload_and_pointer(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    ref = {"release_tag": "observations-7", "name": "evidence.enc",
           "ciphertext_sha256": "0" * 64, "ciphertext_bytes": 3}
    transport.assets[ref["release_tag"], ref["name"]] = b"bad"
    with pytest.raises(StateError, match="hash/size"):
        publish(store, dependencies=[ref])
    assert transport.head is None
    assert transport.uploads == []


def test_other_repository_conflict_rebases_and_preserves_both_pointers(setup):
    transport, make, _ = setup
    one, two = make(7), make(8)
    selected_one, selected_two = one.read(), two.read()
    write(one, "one", b"one")
    write(two, "two", b"two")
    transport.on_advance = lambda: publish(two, selected_two)
    publish(one, selected_one)
    assert set(transport.commits[transport.head]) == {7, 8}
    assert one.read().index["files"][0]["path"] == "one"
    assert two.read().index["files"][0]["path"] == "two"


def test_same_repository_concurrent_pointer_change_is_rejected(setup):
    transport, make, _ = setup
    store = make()
    stale = store.read()
    write(store, "checkpoint", b"data")
    winner = publish(store, stale)
    winner_head = transport.head
    with pytest.raises(StateConflictError, match="changed"):
        publish(store, stale)
    assert transport.head == winner_head
    assert store.read().pointer == winner["pointer"]


def test_uncertain_update_response_rereads_exact_pointer(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    original = transport.advance_branch

    def uncertain(expected, commit):
        assert original(expected, commit)
        raise OSError("connection lost after success")
    transport.advance_branch = uncertain
    result = publish(store)
    assert store.read().pointer == result["pointer"]


def test_restore_rejects_populated_root_and_private_key_capture(setup):
    _, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    with pytest.raises(StateError, match="empty state root"):
        store.restore(store.read())
    write(store, "leaked.pem", b"-----BEGIN PRIVATE KEY-----\nsecret")
    with pytest.raises(StateError, match="Private key"):
        publish(store)


def test_key_file_must_be_outside_working_root(setup):
    transport, make, tmp_path = setup
    store = make()
    private = write(store, "private.pem", (tmp_path / "private.pem").read_bytes())
    with pytest.raises(ValueError, match="outside"):
        GitHubStateStore(transport, repository_id=7, slug="owner/repo7", logical_root=store.root,
                         public_key=tmp_path / "public.pem", private_key=private)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "traversal", "absolute", "duplicate", "unlisted", "sparse"])
def test_safe_tar_extraction_rejects_unsafe_members(setup, kind):
    transport, make, tmp_path = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    selected = store.read()
    index = copy.deepcopy(selected.index)
    original = next(iter(index["parts"].values()))
    archive = tmp_path / "evil.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("checkpoint")
        info.size = 4
        if kind in ("symlink", "hardlink"):
            info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
            info.linkname = "../../escaped"
            info.size = 0
        elif kind == "traversal":
            info.name = "../escaped"
        elif kind == "absolute":
            info.name = str(tmp_path / "escaped")
        elif kind == "unlisted":
            info.name = "unlisted"
        elif kind == "sparse":
            info.pax_headers = {"GNU.sparse.map": "0,4", "GNU.sparse.size": "4", "GNU.sparse.name": "checkpoint"}
        tar.addfile(info, io.BytesIO(b"data") if info.isfile() else None)
        if kind == "duplicate":
            tar.addfile(info, io.BytesIO(b"data"))
    encrypted = tmp_path / "evil.enc"
    record = encrypt_file(archive, encrypted, store.public_key)
    ref = {**record, "release_tag": original["release_tag"], "name": "evil.enc", "kind": "tar",
           "encoding": "raw", "decoded_sha256": record["plaintext_sha256"],
           "decoded_bytes": record["plaintext_bytes"]}
    transport.assets[ref["release_tag"], ref["name"]] = encrypted.read_bytes()
    index["parts"] = {record["plaintext_sha256"]: ref}
    index["files"][0]["segments"] = [{"part": record["plaintext_sha256"], "member": "checkpoint"}]
    index["context"]["file_map_sha256"] = hashlib.sha256(canonical_json(index["files"])).hexdigest()
    pointer = copy.deepcopy(selected.pointer)
    pointer["context_sha256"] = hashlib.sha256(canonical_json(index["context"])).hexdigest()
    # Install an authentic encrypted malicious archive/index into the fake Git
    # history. Extraction remains safe even for a fully authenticated bad map.
    plaintext, encrypted_index = tmp_path / "evil-index.json", tmp_path / "evil-index.enc"
    plaintext.write_bytes(canonical_json(index))
    metadata = encrypt_file(plaintext, encrypted_index, store.public_key)
    pointer["index"] = {**metadata, "release_tag": ref["release_tag"], "name": "evil-index.enc"}
    transport.assets[ref["release_tag"], "evil-index.enc"] = encrypted_index.read_bytes()
    commit = transport.commit_pointer(transport.head, 7, canonical_json(pointer))
    transport.advance_branch(transport.head, commit)
    clear(store)
    with pytest.raises(StateError):
        store.restore(store.read())
    assert not (tmp_path / "escaped").exists()
    assert not (store.root / "checkpoint").exists()


def test_publish_requires_explicit_callback_quiescence(setup):
    _, make, _ = setup
    store = make()
    with pytest.raises(StateError, match="joined"):
        store.publish(store.read())


def test_cli_transport_never_forces_and_preserves_parent_tree(setup):
    _, _, tmp_path = setup
    calls = []

    def runner(args, **kwargs):
        payload = json.loads(kwargs["input"]) if kwargs["input"] else None
        calls.append((args, payload))
        endpoint = args[2]
        if "/contents/slugs/" in endpoint:
            binding = canonical_json({"schema_version": 1, "slug_key": "owner/source", "repository_id": 7})
            import base64
            result = {"type": "file", "encoding": "base64", "content": base64.b64encode(binding).decode()}
        elif endpoint.endswith("/git/blobs"):
            result = {"sha": "blob"}
        elif endpoint.endswith("/git/commits/old"):
            result = {"tree": {"sha": "old-tree"}}
        elif endpoint.endswith("/git/trees"):
            result = {"sha": "new-tree"}
        elif endpoint.endswith("/git/commits"):
            result = {"sha": "new-commit"}
        elif "/git/ref/heads/" in endpoint:
            result = {"object": {"sha": "old"}}
        else:
            result = {}
        return subprocess.CompletedProcess(args, 0, json.dumps(result).encode(), b"")
    transport = GhCliStateTransport("owner/archive", runner=runner)
    assert transport.commit_pointer("old", 7, canonical_json({"slug": "owner/source"})) == "new-commit"
    assert transport.advance_branch("old", "new-commit")
    tree = next(payload for args, payload in calls if args[2].endswith("/git/trees"))
    commit = next(payload for args, payload in calls if args[2].endswith("/git/commits"))
    update = calls[-1][1]
    assert tree["base_tree"] == "old-tree"
    assert tree["tree"][0]["path"] == "repos/7.json"
    assert commit["parents"] == ["old"]
    assert update == {"sha": "new-commit", "force": False}
    assert BRANCH == "collector-state"


def test_release_shards_reserve_index_room_and_restore_across_shards(setup):
    transport, make, _ = setup
    store = make(max_assets_per_release=3, small_immutable_bytes=0)
    for number in range(7):
        value = f"CAS value {number}".encode()
        digest = hashlib.sha256(value).hexdigest()
        write(store, f"objects/sha256/{digest[:2]}/{digest}", value)
    result = publish(store)
    assert result["new_parts"] == 7
    assert result["state_release_count"] == 4
    counts = {}
    for tag, _ in transport.uploads:
        counts[tag] = counts.get(tag, 0) + 1
    assert max(counts.values()) <= 3
    selected = store.read()
    assert len({part["release_tag"] for part in selected.index["parts"].values()}) == 4
    clear(store)
    store.restore(selected)
    assert len(list((store.root / "objects").rglob("*"))) >= 7


def test_xz_default_preserves_already_compressed_git_pack(setup):
    _, make, _ = setup
    store = make()
    write(store, "checkpoints/api/7/capture/response.json", b"repetitive JSON " * 1000)
    write(store, "git/7.git/objects/pack/pack-abc.pack", b"PACK" + os.urandom(100))
    publish(store)
    selected = store.read()
    assert {part["encoding"] for part in selected.index["parts"].values()} == {"raw", "xz"}
    raw = next(part for part in selected.index["parts"].values() if part["encoding"] == "raw")
    assert raw["decoded_bytes"] == 104
    assert raw["decoded_sha256"] == raw["plaintext_sha256"]


def test_restore_preflight_checks_authenticated_size_before_downloading_parts(setup, monkeypatch):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    selected = store.read()
    clear(store)
    transport.events.clear()
    monkeypatch.setattr(shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(10, 10, 0))
    with pytest.raises(StateError, match="Insufficient disk.*smaller repository"):
        store.restore(selected)
    assert not any(event[0] == "download" for event in transport.events)
    assert not (store.root / "checkpoint").exists()


def test_publish_preflight_fails_before_state_upload(setup, monkeypatch):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    monkeypatch.setattr(shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(10, 10, 0))
    with pytest.raises(StateError, match="Insufficient disk"):
        publish(store)
    assert transport.uploads == []
    assert transport.head is None


def test_reused_slug_with_new_numeric_id_rejected_before_new_pointer_read(setup):
    transport, make, tmp_path = setup
    first = make(7)
    write(first, "checkpoint", b"original repository state")
    publish(first)
    second = GitHubStateStore(transport, repository_id=8, slug=first.slug,
                             public_key=first.public_key, private_key=first.private_key,
                             logical_root=tmp_path / "working" / "8")
    transport.reads.clear()
    with pytest.raises(StateConflictError, match="already bound"):
        second.read()
    assert 8 not in transport.reads


def test_slug_binding_race_rejects_pointer_publish_for_new_identity(setup):
    transport, make, tmp_path = setup
    first = make(7)
    second = GitHubStateStore(transport, repository_id=8, slug=first.slug,
                             public_key=first.public_key, private_key=first.private_key,
                             logical_root=tmp_path / "working" / "8")
    old_first, old_second = first.read(), second.read()
    write(first, "checkpoint", b"original repository state")
    write(second, "checkpoint", b"replacement repository state")
    transport.on_advance = lambda: publish(first, old_first)
    with pytest.raises(StateConflictError, match="already bound"):
        publish(second, old_second)
    assert transport.read_pointer(transport.head, 8) is None
    assert first.read().pointer is not None


def test_mutated_selection_parts_cannot_bypass_authenticated_index_digest(setup):
    _, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    selected = store.read()
    damaged = copy.deepcopy(selected.index)
    next(iter(damaged["parts"].values()))["ciphertext_sha256"] = "0" * 64
    clear(store)
    with pytest.raises(StateError, match="authenticated pointer digest"):
        store.restore(StateSelection(selected.head, selected.pointer, damaged))


def test_existing_slug_binding_without_pointer_fails_closed(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    publish(store)
    transport.commits[transport.head].pop(7)
    with pytest.raises(StateError, match="binding exists.*pointer is missing"):
        store.read()


def test_unchanged_parts_reuse_by_decoded_hash_without_recompression(setup, monkeypatch):
    _, make, _ = setup
    store = make()
    value = b"raw JSON response" * 100
    digest = hashlib.sha256(value).hexdigest()
    write(store, f"objects/sha256/{digest[:2]}/{digest}", value)
    publish(store)
    selected = store.read()
    def unexpected_compress(*args, **kwargs):
        raise AssertionError("Unchanged raw plaintext must reuse its ciphertext without recompression")
    monkeypatch.setattr("icsot_observer.github_state.lzma.open", unexpected_compress)
    result = publish(store, selected)
    assert result["new_parts"] == 0
    assert result["reused_parts"] == 1


class FakeGhApiRunner:
    def __init__(self, *, existing_release=False, remaining=1000):
        self.existing_release = existing_release
        self.remaining = remaining
        self.graphql_remaining = 5000
        self.calls = []
        self.assets = {}
        self.next_id = 10

    def __call__(self, args, **kwargs):
        endpoint = args[2]
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        self.calls.append((method, endpoint))
        if endpoint == "graphql":
            self.graphql_remaining -= 1
            value = graphql_result(None, remaining=self.graphql_remaining)
            headers = (f"HTTP/2.0 200 OK\r\nX-RateLimit-Remaining: {self.graphql_remaining}\r\n"
                       "X-RateLimit-Reset: 4070908800\r\nX-RateLimit-Limit: 5000\r\n"
                       "X-RateLimit-Resource: graphql\r\n\r\n").encode()
            return subprocess.CompletedProcess(args, 0, headers + json.dumps(value).encode(), b"")
        self.remaining -= 1
        code, value = 200, {}
        if endpoint == "rate_limit":
            value = {"resources": {"core": {"remaining": self.remaining, "reset": 5000, "limit": 1000}}}
        elif "/releases/tags/" in endpoint:
            if not self.existing_release:
                code, value = 404, {"message": "Not Found"}
            else:
                value = {"id": 1, "tag_name": endpoint.rsplit("/", 1)[1], "draft": False, "assets": []}
        elif "/releases?per_page=" in endpoint:
            value = []
        elif endpoint.endswith("/releases") and method == "POST":
            self.existing_release = True
            value = {"id": 1, "tag_name": json.loads(kwargs["input"])["tag_name"], "draft": False, "assets": []}
        elif endpoint.startswith("https://uploads.github.com/"):
            from urllib.parse import parse_qs, urlsplit
            name = parse_qs(urlsplit(endpoint).query)["name"][0]
            source = Path(args[args.index("--input") + 1])
            contents = source.read_bytes()
            self.next_id += 1
            value = {"id": self.next_id, "name": name, "size": len(contents), "state": "uploaded",
                     "digest": "sha256:" + hashlib.sha256(contents).hexdigest()}
            self.assets[name] = (value, contents)
        elif "/releases/1/assets?" in endpoint:
            value = [asset for asset, _ in self.assets.values()]
        elif "/releases/assets/" in endpoint:
            asset_id = int(endpoint.rsplit("/", 1)[1])
            contents = next(contents for asset, contents in self.assets.values() if asset["id"] == asset_id)
            kwargs["stdout"].write(contents)
            return subprocess.CompletedProcess(args, 0, None, b"")
        body = json.dumps(value).encode()
        headers = (f"HTTP/2.0 {code} Response\r\nX-RateLimit-Remaining: {self.remaining}\r\n"
                   "X-RateLimit-Reset: 5000\r\n\r\n").encode()
        return subprocess.CompletedProcess(args, int(code >= 400), headers + body,
                                           b"gh: Not Found (HTTP 404)" if code == 404 else b"")


def test_transport_upload_captures_asset_id_without_relisting_and_counts_requests(tmp_path):
    runner = FakeGhApiRunner()
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    transport.ensure_release("snapshot")
    transport.ensure_release("snapshot")
    source = tmp_path / "different-local-name"
    source.write_bytes(b"encrypted payload")
    for number in range(2):
        name = f"part-{number}.enc"
        transport.upload_asset("snapshot", name, source)
        destination = tmp_path / name
        transport.download_asset("snapshot", name, destination)
        assert destination.read_bytes() == source.read_bytes()
    assert transport.request_count == len(runner.calls) == 7
    assert not any("/assets?per_page=" in endpoint for _, endpoint in runner.calls)
    assert sum("/releases/tags/" in endpoint for _, endpoint in runner.calls) == 1


def test_transport_old_release_listing_cached_once_for_all_downloads(tmp_path):
    runner = FakeGhApiRunner(existing_release=True)
    for number in range(3):
        contents = str(number).encode()
        runner.assets[f"part-{number}.enc"] = ({"id": number + 20, "name": f"part-{number}.enc", "size": 1}, contents)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    for number in range(3):
        transport.download_asset("old-snapshot", f"part-{number}.enc", tmp_path / str(number))
    assert transport.request_count == 5  # release + one listing + three direct asset GETs
    assert sum("/assets?per_page=" in endpoint for _, endpoint in runner.calls) == 1


def test_transport_runner_token_headroom_refuses_before_state_publication():
    runner = FakeGhApiRunner(remaining=150)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000, rate_reserve=100)
    with pytest.raises(StateDeferredError, match="headroom") as failure:
        transport.publication_budget(60)
    assert failure.value.retry_not_before == 5000
    assert failure.value.request_count == 2
    assert runner.calls == [("GET", "repos/owner/collector"), ("GET", "rate_limit")]


@pytest.mark.parametrize("primary", [False, True])
def test_transport_rate_headers_defer_without_repeated_requests(primary):
    calls = []
    def runner(args, **kwargs):
        calls.append(args)
        headers = (b"HTTP/2.0 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 5000\r\n\r\n"
                   if primary else b"HTTP/2.0 429 Too Many Requests\r\nRetry-After: 120\r\n\r\n")
        return subprocess.CompletedProcess(args, 1, headers + b'{"message":"API rate limit exceeded"}', b"HTTP 403")
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError) as failure:
        transport.branch_head()
    assert failure.value.retry_not_before == (5000 if primary else 1120)
    with pytest.raises(StateDeferredError):
        transport.branch_head()
    assert len(calls) == transport.request_count == 1


def test_transport_transient_get_retry_bounded_and_writes_never_retry():
    calls = []
    def runner(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, b"HTTP/2.0 503 Unavailable\r\n\r\n{}", b"HTTP 503")
    transport = GhCliStateTransport("owner/collector", runner=runner)
    with pytest.raises(StateError):
        transport.branch_head()
    assert len(calls) == 2
    calls.clear()
    with pytest.raises(StateError):
        transport._api("repos/owner/collector/git/blobs", method="POST", payload={})
    assert len(calls) == 1


def test_budget_deferral_keeps_old_pointer_and_uploads_no_state_assets(setup):
    transport, make, _ = setup
    store = make()
    write(store, "checkpoint", b"old data")
    publish(store)
    selected, old_head, old_uploads = store.read(), transport.head, list(transport.uploads)
    write(store, "checkpoint", b"new data")
    def insufficient(required):
        assert required >= 22
        raise StateDeferredError("not enough runner-token headroom", retry_not_before=5000)
    transport.publication_budget = insufficient
    with pytest.raises(StateDeferredError, match="headroom"):
        publish(store, selected)
    assert transport.head == old_head
    assert transport.uploads == old_uploads


def test_snapshot_utc_interval_roundtrip_and_pointer_context_mismatch(setup, monkeypatch):
    _, make, _ = setup
    store = make()
    write(store, "checkpoint", b"data")
    started, sealed = "2026-10-25T10:00:00.123456Z", "2026-10-25T10:00:02.654321Z"
    values = iter((started, sealed))
    monkeypatch.setattr("icsot_observer.github_state.utc_iso", lambda: next(values))
    publish(store)
    selected = store.read()
    for obj in (selected.pointer, selected.index["context"]):
        assert obj["snapshot_started_at"] == started
        assert obj["snapshot_sealed_at"] == sealed
        assert obj["clock_source"] == "runner_system_clock"
    clear(store)
    changed_pointer = copy.deepcopy(selected.pointer)
    changed_pointer["snapshot_sealed_at"] = "2026-10-25T10:00:03.654321Z"
    with pytest.raises(StateError, match="UTC interval differs"):
        store.restore(StateSelection(selected.head, changed_pointer, selected.index))
    restored = store.restore(selected)
    assert restored["restored"]


def rate_response(args, value, *, remaining, reset=5000, limit=1000, resource="core"):
    raw = (f"HTTP/2.0 200 OK\r\nX-RateLimit-Remaining: {remaining}\r\n"
           f"X-RateLimit-Reset: {reset}\r\nX-RateLimit-Limit: {limit}\r\n"
           f"X-RateLimit-Resource: {resource}\r\n\r\n").encode() + json.dumps(value).encode()
    return subprocess.CompletedProcess(args, 0, raw, b"")


def test_budget_generic_larger_bucket_cannot_increase_repository_headroom():
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        if args[2] == "rate_limit":
            value = {"resources": {"core": {"remaining": 2513, "reset": 6000, "limit": 5000}}}
            return rate_response(args, value, remaining=2513, reset=6000, limit=5000)
        return rate_response(args, {}, remaining=600, reset=5000, limit=1000)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError) as failure:
        transport.publication_budget(600)
    assert transport.rate_remaining == 599  # Repository probe, then conservative local-call charge.
    assert transport.rate_reset == 5000
    assert failure.value.retry_not_before == 5000
    metrics = failure.value.rate_measurements
    assert metrics["destination_github_repository_rate_probe"] == {
        "remaining": 600, "reset": 5000, "limit": 1000, "resource": "core"}
    assert metrics["destination_github_generic_core_rate_probe"]["remaining"] == 2513
    assert metrics["destination_github_generic_rate_response_headers"]["limit"] == 5000
    assert metrics["destination_github_rate_remaining_before_state_upload"] == 599
    assert calls == ["repos/owner/collector", "rate_limit"]


def test_repository_same_reset_cannot_increase_recent_observed_headroom():
    values = iter((400, 700, 800))
    def runner(args, **kwargs):
        return rate_response(args, {}, remaining=next(values))
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    transport._api("repos/owner/collector")
    assert transport.rate_remaining == 400
    transport._api("repos/owner/collector/releases")
    assert transport.rate_remaining == 399
    transport._api("repos/owner/collector/git/ref/heads/collector-state")
    assert transport.rate_remaining == 398
    assert transport.rate_reset == 5000


def test_different_active_resets_expire_independently_before_headroom_increases():
    now = [1000]
    values = iter(((100, 1100), (500, 1200), (700, 1200)))
    def runner(args, **kwargs):
        remaining, reset = next(values)
        return rate_response(args, {}, remaining=remaining, reset=reset)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: now[0], rate_reserve=0)
    transport._api("repos/owner/collector")
    transport._api("repos/owner/collector/releases")
    assert (transport.rate_remaining, transport.rate_reset) == (99, 1100)
    now[0] = 1100
    transport._api("repos/owner/collector/git/ref/heads/collector-state")
    assert (transport.rate_remaining, transport.rate_reset) == (499, 1200)


def test_transport_runtime_clone_preserves_constraints_and_probe_metadata():
    def runner(args, **kwargs):
        if args[2] == "rate_limit":
            value = {"resources": {"core": {"remaining": 2513, "reset": 6000, "limit": 5000}}}
            return rate_response(args, value, remaining=2513, reset=6000, limit=5000)
        return rate_response(args, {}, remaining=600)
    original = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    original.publication_budget(10)
    wrapped = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    original.copy_runtime_state_to(wrapped)
    assert wrapped.last_budget_metrics == original.last_budget_metrics
    assert wrapped._rate_windows == original._rate_windows
    assert wrapped._rate_windows is not original._rate_windows
    wrapped._api("repos/owner/collector/releases")
    assert wrapped.rate_remaining == 598
    wrapped.copy_runtime_state_to(original)
    assert original.rate_remaining == 598
    assert original.request_count == 3
    assert original._last_repo_rate_headers["remaining"] == 600
    with pytest.raises(ValueError, match="cannot cross"):
        original.copy_runtime_state_to(GhCliStateTransport("other/repository"))


def metadata_response(args, value, *, status=200, stderr=b""):
    raw = f"HTTP/2.0 {status} Response\r\n\r\n".encode() + json.dumps(value).encode()
    return subprocess.CompletedProcess(args, int(status >= 400), raw, stderr)


def graphql_result(release, *, repository="owner/collector", remaining=4999):
    return {"data": {"repository": {"nameWithOwner": repository, "release": release},
                     "rateLimit": {"cost": 1, "remaining": remaining, "limit": 5000,
                                   "resetAt": "2099-01-01T00:00:00Z"}}}


def test_draft_release_tag_404_uses_constant_exact_graphql_id_lookup_and_cache():
    calls = []
    draft = {"id": 424020503, "tag_name": "sealed-baseline", "draft": True,
             "assets": [{"id": 1, "name": "inventory.json", "size": 10}]}
    def runner(args, **kwargs):
        endpoint = args[2]
        calls.append((args[args.index("--method") + 1], endpoint))
        if "/releases/tags/" in endpoint:
            return metadata_response(args, {"message": "Not Found"}, status=404)
        if endpoint == "graphql":
            payload = json.loads(kwargs["input"])
            assert payload["variables"] == {"owner": "owner", "name": "collector", "tag": "sealed-baseline"}
            assert "release(tagName:$tag)" in payload["query"]
            return metadata_response(args, graphql_result({"databaseId": 424020503, "tagName": "sealed-baseline", "isDraft": True}))
        if endpoint.endswith("/releases/424020503"):
            return metadata_response(args, draft)
        raise AssertionError("Repository-wide release lists are forbidden")
    transport = GhCliStateTransport("owner/collector", runner=runner)
    assert transport._release("sealed-baseline") == draft
    transport.ensure_release("sealed-baseline")
    assert transport._release("sealed-baseline") == draft
    assert transport._assets["sealed-baseline"]["inventory.json"]["id"] == 1
    assert transport.request_count == 3 and transport.graphql_request_count == 1
    assert calls == [("GET", "repos/owner/collector/releases/tags/sealed-baseline"),
                     ("POST", "graphql"), ("GET", "repos/owner/collector/releases/424020503")]


def test_published_release_tag_fast_path_never_queries_graphql_or_lists_drafts():
    calls = []
    release = {"id": 15, "tag_name": "published", "draft": False, "assets": []}
    def runner(args, **kwargs):
        calls.append(args[2])
        return metadata_response(args, release)
    transport = GhCliStateTransport("owner/collector", runner=runner)
    assert transport._release("published") == release
    assert calls == ["repos/owner/collector/releases/tags/published"]
    assert transport.graphql_request_count == 0


@pytest.mark.parametrize("status", [401, 403, 500])
def test_draft_lookup_does_not_mask_non_404_header_with_misleading_stderr(status):
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        return metadata_response(args, {"message": "denied"}, status=status,
                                 stderr=b"untrusted diagnostic mentions HTTP 404")
    transport = GhCliStateTransport("owner/collector", runner=runner, transient_retries=0)
    with pytest.raises(StateError):
        transport.ensure_release("sealed-baseline")
    assert calls == ["repos/owner/collector/releases/tags/sealed-baseline"]


def test_draft_lookup_rate_response_defers_without_graphql_or_create():
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        raw = b'HTTP/2.0 429 Too Many Requests\r\nRetry-After: 60\r\n\r\n{"message":"rate limit"}'
        return subprocess.CompletedProcess(args, 1, raw, b"")
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError) as failure:
        transport.ensure_release("sealed-baseline")
    assert failure.value.retry_not_before == 1060
    assert len(calls) == 1


@pytest.mark.parametrize("malformation", ["errors", "errors_null", "null_data", "null_repository", "wrong_repository",
                                           "missing_release", "invalid_quota", "invalid_candidate", "wrong_id", "wrong_tag", "changed_draft"])
def test_graphql_draft_lookup_rejects_malformed_or_ambiguous_response_without_create(malformation):
    calls = []
    draft = {"id": 42, "tag_name": "sealed-baseline", "draft": True, "assets": []}
    def runner(args, **kwargs):
        endpoint = args[2]
        calls.append((args[args.index("--method") + 1], endpoint))
        if "/releases/tags/" in endpoint:
            return metadata_response(args, {}, status=404)
        if endpoint == "graphql":
            value = graphql_result({"databaseId": 42, "tagName": "sealed-baseline", "isDraft": True})
            if malformation == "errors":
                value["errors"] = [{"type": "FORBIDDEN", "message": "denied"}]
                value["data"]["repository"]["release"] = None
            elif malformation == "errors_null":
                value["errors"] = None
            elif malformation == "null_data":
                value["data"] = None
            elif malformation == "null_repository":
                value["data"]["repository"] = None
            elif malformation == "wrong_repository":
                value["data"]["repository"]["nameWithOwner"] = "other/repository"
            elif malformation == "missing_release":
                del value["data"]["repository"]["release"]
            elif malformation == "invalid_quota":
                value["data"]["rateLimit"] = None
            elif malformation == "invalid_candidate":
                value["data"]["repository"]["release"] = [{"databaseId": 42}]
            return metadata_response(args, value)
        if endpoint.endswith("/releases/42"):
            result = dict(draft)
            if malformation == "wrong_id":
                result["id"] = 43
            elif malformation == "wrong_tag":
                result["tag_name"] = "another-baseline"
            elif malformation == "changed_draft":
                result["draft"] = False
            return metadata_response(args, result)
        raise AssertionError("Release creation or listing must not happen")
    transport = GhCliStateTransport("owner/collector", runner=runner)
    with pytest.raises(StateError):
        transport.ensure_release("sealed-baseline")
    assert all(method == "GET" or endpoint == "graphql" for method, endpoint in calls)
    assert "sealed-baseline" not in transport._releases


def test_graphql_valid_exact_absence_allows_one_create_independent_of_release_count():
    calls = []
    def runner(args, **kwargs):
        method, endpoint = args[args.index("--method") + 1], args[2]
        calls.append((method, endpoint))
        if "/releases/tags/" in endpoint:
            return metadata_response(args, {}, status=404)
        if endpoint == "graphql":
            return metadata_response(args, graphql_result(None))
        if endpoint == "repos/owner/collector/releases" and method == "POST":
            return metadata_response(args, {"id": 424020504, "tag_name": "new-generation", "draft": False, "assets": []}, status=201)
        raise AssertionError("Cannot enumerate Releases, including repositories with over 1000 Releases")
    transport = GhCliStateTransport("owner/collector", runner=runner)
    transport.ensure_release("new-generation")
    transport.ensure_release("new-generation")
    assert calls == [("GET", "repos/owner/collector/releases/tags/new-generation"),
                     ("POST", "graphql"), ("POST", "repos/owner/collector/releases")]


def test_graphql_http200_rate_errors_defer_without_create_or_rest_bucket_corruption():
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        if args[2] == "graphql":
            raw = (b'HTTP/2.0 200 OK\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 5000\r\n'
                   b'X-RateLimit-Limit: 1000\r\nX-RateLimit-Resource: graphql\r\n\r\n'
                   b'{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}],"data":null}')
            return subprocess.CompletedProcess(args, 0, raw, b"")
        return metadata_response(args, {}, status=404)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError) as failure:
        transport.ensure_release("sealed-baseline")
    assert failure.value.retry_not_before == 5000
    assert transport.graphql_rate_remaining == 0 and transport.rate_remaining is None
    with pytest.raises(StateDeferredError):
        transport._find_release_after_tag_404("sealed-baseline")
    assert len(calls) == 2


def test_graphql_and_rest_primary_buckets_are_independent_but_secondary_wait_is_shared():
    calls = []
    def runner(args, **kwargs):
        endpoint = args[2]
        calls.append(endpoint)
        if endpoint == "graphql":
            raw = (b'HTTP/2.0 200 OK\r\nRetry-After: 60\r\n\r\n'
                   b'{"errors":[{"type":"RATE_LIMITED","message":"secondary rate limit"}],"data":null}')
            return subprocess.CompletedProcess(args, 0, raw, b"")
        return rate_response(args, {}, remaining=800)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    transport._api("repos/owner/collector")
    rest_remaining = transport.rate_remaining
    with pytest.raises(StateDeferredError) as failure:
        transport._find_release_after_tag_404("sealed-baseline")
    assert failure.value.retry_not_before == 1060
    assert transport.rate_remaining == rest_remaining  # GraphQL did not spend a REST request.
    with pytest.raises(StateDeferredError):
        transport._api("repos/owner/collector")
    assert calls == ["repos/owner/collector", "graphql"]


@pytest.mark.parametrize("body", [b"null", b"", b"{malformed"])
def test_draft_lookup_malformed_success_is_not_interpreted_as_404(body):
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        return subprocess.CompletedProcess(args, 0, b"HTTP/2.0 200 OK\r\n\r\n" + body, b"")
    transport = GhCliStateTransport("owner/collector", runner=runner)
    with pytest.raises(StateError):
        transport.ensure_release("sealed-baseline")
    assert calls == ["repos/owner/collector/releases/tags/sealed-baseline"]



def test_graphql_primary_exhaustion_preserves_rest_quota_and_survives_adapter_clone():
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        if args[2] == "graphql":
            raw = (b'HTTP/2.0 200 OK\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 5000\r\n'
                   b'X-RateLimit-Limit: 1000\r\nX-RateLimit-Resource: graphql\r\n\r\n'
                   b'{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}],"data":null}')
            return subprocess.CompletedProcess(args, 0, raw, b"")
        return rate_response(args, {}, remaining=800)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError):
        transport._find_release_after_tag_404("sealed-baseline")
    transport._api("repos/owner/collector")
    assert transport.rate_remaining == 800
    assert transport.graphql_rate_remaining == 0
    assert transport.request_count == 2 and transport.graphql_request_count == 1
    wrapped = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    transport.copy_runtime_state_to(wrapped)
    with pytest.raises(StateDeferredError):
        wrapped._find_release_after_tag_404("sealed-baseline")
    assert wrapped._graphql_rate_windows == transport._graphql_rate_windows
    assert wrapped._last_graphql_rate_headers["resource"] == "graphql"
    assert calls == ["graphql", "repos/owner/collector"]



def test_graphql_http200_rate_error_uses_partial_body_quota_when_headers_omit_it():
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        value = graphql_result(None, remaining=0)
        value["errors"] = [{"type": "RATE_LIMITED", "message": "API rate limit exceeded"}]
        return metadata_response(args, value)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError) as failure:
        transport._find_release_after_tag_404("sealed-baseline")
    assert failure.value.retry_not_before == 4070908800
    assert transport.graphql_rate_remaining == 0
    with pytest.raises(StateDeferredError):
        transport._find_release_after_tag_404("sealed-baseline")
    assert calls == ["graphql"]



def test_graphql_secondary_limit_without_retry_header_defers_one_minute():
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        value = {"errors": [{"type": "RATE_LIMITED", "message": "secondary rate limit"}], "data": None}
        return metadata_response(args, value)
    transport = GhCliStateTransport("owner/collector", runner=runner, clock=lambda: 1000)
    with pytest.raises(StateDeferredError) as failure:
        transport._find_release_after_tag_404("sealed-baseline")
    assert failure.value.retry_not_before == 1060
    with pytest.raises(StateDeferredError):
        transport._api("repos/owner/collector")
    assert calls == ["graphql"]



@pytest.mark.parametrize("distinct_releases,expected", [(False, 37), (True, 50)])
def test_cold_draft_publish_estimate_reserves_thirteen_rest_metadata_requests_per_release(setup, distinct_releases, expected):
    _, make, _ = setup
    store = make()
    refs = {}
    for number in range(2):
        refs[str(number)] = {"release_tag": f"old-draft-{number if distinct_releases else 0}",
                             "name": f"part-{number}.enc", "ciphertext_sha256": str(number) * 64,
                             "ciphertext_bytes": 100}
    # No new payloads: fixed index/control estimate is 22. Each distinct cold
    # draft needs 13 metadata reads, plus one ciphertext GET for each old part.
    assert store._publication_requests_estimate([], {"parts": refs, "files": []}) == expected



def cas_file(store, value):
    digest = hashlib.sha256(value).hexdigest()
    name = f"objects/sha256/{digest[:2]}/{digest}"
    write(store, name, value)
    return name


def test_packing_reuses_legacy_raw_segments_and_adds_only_new_small_block(setup):
    transport, make, _ = setup
    legacy = make(small_immutable_bytes=0)
    originals = {cas_file(legacy, value): value for value in (b"first old CAS", b"second old CAS")}
    pack_name = "git/7.git/objects/pack/pack-abc.pack"
    pack_value = b"PACK" + os.urandom(16 * 1024)
    write(legacy, pack_name, pack_value)
    publish(legacy)
    before = legacy.read()
    old_files = {item["path"]: item for item in before.index["files"]}
    assert all(before.index["parts"][item["segments"][0]["part"]]["kind"] == "raw" for item in old_files.values())
    packed = make()
    added = {cas_file(packed, value): value for value in (b"new CAS one", b"new CAS two")}
    transport.uploads.clear()
    result = publish(packed, before)
    after = packed.read()
    current = {item["path"]: item for item in after.index["files"]}
    for name, old in old_files.items():
        assert current[name]["segments"] == old["segments"]
        for segment in old["segments"]:
            assert after.index["parts"][segment["part"]] == before.index["parts"][segment["part"]]
    assert result["new_parts"] == 1 and result["new_small_immutable_files_packed"] == 2
    assert result["reused_parts"] == 3
    assert len(transport.uploads) == 2  # One new block plus the new encrypted index.
    assert len({current[name]["segments"][0]["part"] for name in added}) == 1
    clear(packed)
    packed.restore(after)
    for name, value in {**originals, **added, pack_name: pack_value}.items():
        assert (packed.root / name).read_bytes() == value


def test_new_small_cas_packing_reduces_state_assets_and_quota_estimate(setup):
    transport, make, _ = setup
    store = make()
    values = {cas_file(store, f"raw API response {number}".encode() * 8): number for number in range(100)}
    result = publish(store)
    selected = store.read()
    assert result["new_parts"] == 1
    assert result["new_small_immutable_files_packed"] == 100
    assert len(transport.uploads) == 2  # Before packing: 101 uploads and 101 verification downloads.
    assert sum(event[0] == "download" and event[1] != "index.enc" for event in transport.events) == 1
    assert len(selected.index["files"]) == len(values)
    assert next(iter(selected.index["parts"].values()))["kind"] == "tar"
    assert store._publication_requests_estimate(selected.index["files"], {"parts": {}, "files": []}) == 24


def test_packed_blocks_respect_decoded_byte_and_member_bounds(setup):
    _, make, _ = setup
    store = make(immutable_group_bytes=10240, immutable_group_members=2)
    expected = {cas_file(store, bytes([number]) * 400): bytes([number]) * 400 for number in range(5)}
    result = publish(store)
    selected = store.read()
    assert result["new_parts"] == 3
    counts = {}
    for item in selected.index["files"]:
        part = item["segments"][0]["part"]
        counts[part] = counts.get(part, 0) + 1
    assert max(counts.values()) == 2
    assert all(part["decoded_bytes"] <= 10240 for part in selected.index["parts"].values())
    clear(store)
    store.restore(selected)
    assert all((store.root / name).read_bytes() == value for name, value in expected.items())


def test_packed_immutable_blocks_retain_original_members_when_new_files_arrive(setup):
    transport, make, _ = setup
    store = make()
    for number in range(5):
        cas_file(store, f"retained {number}".encode())
    publish(store)
    before = store.read()
    old_parts = copy.deepcopy(before.index["parts"])
    old_segments = {item["path"]: copy.deepcopy(item["segments"]) for item in before.index["files"]}
    cas_file(store, b"a later immutable API response")
    result = publish(store, before)
    after = store.read()
    assert result["new_parts"] == 1 and result["reused_parts"] == 1
    assert all(after.index["parts"][digest] == ref for digest, ref in old_parts.items())
    assert all(item["segments"] == old_segments[item["path"]] for item in after.index["files"] if item["path"] in old_segments)
    clear(store)
    store.restore(after)
    assert len(list((store.root / "objects/sha256").glob("*/*"))) == 6


def test_missing_old_packed_immutable_member_fails_before_upload_or_pointer_change(setup):
    transport, make, _ = setup
    store = make()
    names = [cas_file(store, value) for value in (b"keep", b"missing")]
    publish(store)
    before, old_head, upload_count = store.read(), transport.head, len(transport.uploads)
    (store.root / names[1]).unlink()
    with pytest.raises(StateError, match="immutable state file is missing"):
        publish(store, before)
    assert transport.head == old_head and len(transport.uploads) == upload_count


def test_corrupt_new_small_immutable_block_never_materializes_files(setup):
    transport, make, _ = setup
    store = make()
    for number in range(8):
        cas_file(store, f"response {number}".encode())
    publish(store)
    selected = store.read()
    ref = next(iter(selected.index["parts"].values()))
    ciphertext = transport.assets[ref["release_tag"], ref["name"]]
    transport.assets[ref["release_tag"], ref["name"]] = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    clear(store)
    with pytest.raises(StateError, match="hash/size differs"):
        store.restore(selected)
    assert list(store.root.iterdir()) == [store.root / ".collector.lock"]
