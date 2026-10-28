import copy
import hashlib
import json
from pathlib import Path

import pytest

from icsot_observer.core import canonical_json
from icsot_observer.cycle_release import CycleCatalogError
from icsot_observer.git_metadata import MetadataError, validate_locator
from icsot_observer.github_state import (
    GhCliStateTransport, GitHubStateStore, StateDeferredError, StateError,
    StateIntegrityError,
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeGitMetadataStore:
    """Content-addressed pinned snapshots; a subsequent put preserves old pins."""

    def __init__(self):
        self.blobs = {}

    def put(self, path, raw, *, allow_update=False):
        assert allow_update
        sha = hashlib.sha1(raw).hexdigest()
        self.blobs[sha] = raw
        return {"kind": "github_git_blob_v1", "repository": "owner/archive",
                "branch": "collector-metadata", "path": path,
                "commit_sha": sha, "blob_sha": sha,
                "sha256": digest(raw), "bytes": len(raw)}

    def get(self, locator):
        validate_locator(locator, "owner/archive")
        raw = self.blobs[locator["blob_sha"]]
        if len(raw) != locator["bytes"] or digest(raw) != locator["sha256"]:
            raise MetadataError("Pinned metadata integrity mismatch")
        return raw


class FakeTransport(GhCliStateTransport):
    def __init__(self, store, *, slot=123):
        super().__init__("owner/archive", cycle_slot=slot)
        self._cycle_catalog.store = store
        self.physical = {}
        self.tails = {}
        self.calls = []
        self.failure = None
        self._last_http_status = None

    def _release(self, tag, *, create=False):
        self.calls.append(("release", tag))
        return {"id": int(tag.split("-p")[-1]) if "-p" in tag else 1,
                "tag_name": tag, "draft": False, "assets": []}

    def _api(self, endpoint, **kwargs):
        assert endpoint.endswith("assets?per_page=100&page=10")
        shard = int(endpoint.split("/releases/")[1].split("/")[0])
        self.calls.append(("capacity", shard))
        return [{}] * self.tails.get(shard, 0)

    def upload_asset(self, tag, name, source):
        if self._cycle_catalog.writable(tag):
            return super().upload_asset(tag, name, source)
        self.calls.append(("upload", tag, name))
        if self.failure:
            raise self.failure
        assert (tag, name) not in self.physical
        self.physical[tag, name] = source.read_bytes()

    def download_asset(self, tag, name, destination):
        if self._cycle_catalog.known(tag):
            return super().download_asset(tag, name, destination)
        self.calls.append(("download", tag, name))
        Path(destination).write_bytes(self.physical[tag, name])

    def find_asset(self, tag, name, *, refresh=False):
        if self._cycle_catalog.known(tag):
            return super().find_asset(tag, name, refresh=refresh)
        return None if (tag, name) not in self.physical else {"name": name}


def logical(kind, repository=7, generation="a" * 32):
    return f"collector-{kind}-r{repository}-g{generation}"


def ref(tag, name, raw):
    return {"release_tag": tag, "name": name,
            "ciphertext_sha256": digest(raw), "ciphertext_bytes": len(raw)}


def upload(transport, tmp_path, tag, name, raw):
    source = tmp_path / f"input-{len(list(tmp_path.iterdir()))}"
    source.write_bytes(raw)
    transport.ensure_release(tag)
    transport.upload_asset(tag, name, source)
    descriptor = ref(tag, name, raw)
    transport.bind_asset_ref(descriptor)
    return descriptor


def reader(writer, store):
    result = FakeTransport(store, slot=None)
    result.physical = writer.physical
    return result


def test_shared_release_namespaced_and_metadata_is_in_git(tmp_path):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    tags = [logical("observations", 7, "a" * 32), logical("state", 7, "b" * 32),
            logical("state", 8, "a" * 32)]
    refs = [upload(writer, tmp_path, tag, "part.enc", f"cipher-{i}".encode())
            for i, tag in enumerate(tags)]
    metadata = upload(writer, tmp_path, tags[0], "metadata-catalog.json", b'{"schema_version":1}')
    index = upload(writer, tmp_path, tags[1], "index.enc", b"encrypted-index")
    assert len(writer.physical) == 3
    assert {tag for tag, _ in writer.physical} == {"collector-cycle-s123"}
    assert len({name for _, name in writer.physical}) == 3
    for (tag, name), logical_tag in zip(writer.physical, tags):
        assert tag == "collector-cycle-s123"
        assert f"r{logical_tag.split('-r')[1]}-" in name
    fresh = reader(writer, store)
    for number, descriptor in enumerate([*refs, metadata, index]):
        fresh.pin_asset_ref(descriptor)
        dest = tmp_path / f"read-{number}"
        fresh.download_asset(descriptor["release_tag"], descriptor["name"], dest)
        assert digest(dest.read_bytes()) == descriptor["ciphertext_sha256"]
    assert fresh._cycle_catalog.git_downloads == 2


def test_cycle_package_pins_survive_later_version_and_fresh_readers(tmp_path):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    tag = logical("observations")
    old = upload(writer, tmp_path, tag, "part-1.enc", b"one")
    old_locator = copy.deepcopy(old["storage"]["catalog"])
    new = upload(writer, tmp_path, tag, "index.json", b'{"schema_version":2}')
    assert old_locator != new["storage"]["catalog"]
    old_document = json.loads(store.get(old_locator))
    new_document = json.loads(store.get(new["storage"]["catalog"]))
    assert "part-1.enc" in old_document["payloads"]
    assert "index.json" not in old_document["metadata"]
    assert "index.json" in new_document["metadata"]
    fresh = reader(writer, store)
    fresh.pin_asset_ref(new)
    fresh.pin_asset_ref(old)
    assert fresh.find_asset(tag, "part-1.enc")["digest"] == "sha256:" + digest(b"one")
    assert fresh.find_asset(tag, "index.json") is None
    fresh.pin_asset_ref(new)
    assert fresh.find_asset(tag, "index.json")["size"] == len(b'{"schema_version":2}')


@pytest.mark.parametrize("mutation", ["hash", "locator", "logical", "asset_hash", "asset_size", "missing"])
def test_bad_pins_fail_closed(tmp_path, mutation):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    good = upload(writer, tmp_path, logical("state"), "index.enc", b"sealed")
    bad = copy.deepcopy(good)
    if mutation == "hash":
        bad["storage"]["catalog"]["sha256"] = "0" * 64
    elif mutation == "locator":
        bad["storage"]["catalog"]["repository"] = "other/archive"
    elif mutation == "logical":
        bad["storage"]["logical_release"] = logical("state", 8)
    elif mutation == "asset_hash":
        bad["ciphertext_sha256"] = "0" * 64
    elif mutation == "asset_size":
        bad["ciphertext_bytes"] += 1
    else:
        bad["name"] = "missing.json"
    fresh = reader(writer, store)
    with pytest.raises((StateError, MetadataError, CycleCatalogError)):
        fresh.pin_asset_ref(bad)
    assert not fresh.physical or not fresh.calls


@pytest.mark.parametrize("field,value", [("repository", "other/archive"),
                                          ("logical_release", logical("state", 8)),
                                          ("cycle_slot", -1)])
def test_bad_catalog_context_fails_closed(tmp_path, field, value):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    good = upload(writer, tmp_path, logical("state"), "index.enc", b"sealed")
    bad = copy.deepcopy(good)
    document = json.loads(store.get(bad["storage"]["catalog"]))
    document[field] = value
    bad["storage"]["catalog"] = store.put("packages/test.json", canonical_json(document), allow_update=True)
    with pytest.raises((StateError, MetadataError, CycleCatalogError)):
        reader(writer, store).pin_asset_ref(bad)


@pytest.mark.parametrize("tail,expected", [(91, "collector-cycle-s123"),
                                           (92, "collector-cycle-s123-p2"),
                                           (100, "collector-cycle-s123-p2")])
def test_capacity_headroom_before_physical_upload(tmp_path, tail, expected):
    writer = FakeTransport(FakeGitMetadataStore())
    writer.tails[1] = tail
    upload(writer, tmp_path, logical("state"), "part.enc", b"x")
    assert next(iter(writer.physical))[0] == expected


def test_all_overflow_releases_full_fails_without_upload(tmp_path):
    writer = FakeTransport(FakeGitMetadataStore())
    writer.tails = {shard: 92 for shard in range(1, 33)}
    with pytest.raises(CycleCatalogError, match="overflow"):
        upload(writer, tmp_path, logical("state"), "part.enc", b"x")
    assert not writer.physical
    assert not any(call[0] == "upload" for call in writer.calls)


def test_confirmed_full_422_can_overflow_after_absence_check(tmp_path):
    writer = FakeTransport(FakeGitMetadataStore())
    original = writer.upload_asset
    seen = []

    def racing_upload(tag, name, source):
        if tag == "collector-cycle-s123" and not seen:
            seen.append(True)
            writer._last_http_status = 422
            writer.tails[1] = 92
            raise StateError("filled concurrently")
        return original(tag, name, source)

    writer.upload_asset = racing_upload
    upload(writer, tmp_path, logical("state"), "part.enc", b"x")
    assert next(iter(writer.physical))[0] == "collector-cycle-s123-p2"


@pytest.mark.parametrize("error,status", [(StateDeferredError("rate"), 429),
                                         (StateError("transient"), 503),
                                         (StateError("ambiguous"), None),
                                         (StateError("unprocessable"), 422)])
def test_failure_never_retries_ambiguous_upload_elsewhere(tmp_path, error, status):
    writer = FakeTransport(FakeGitMetadataStore())
    writer.failure, writer._last_http_status = error, status
    with pytest.raises(type(error)):
        upload(writer, tmp_path, logical("state"), "part.enc", b"x")
    posts = [call for call in writer.calls if call[0] == "upload"]
    assert len(posts) == 1 and posts[0][1] == "collector-cycle-s123"


def test_corrupt_physical_payload_still_fails_caller_hash_check(tmp_path):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    descriptor = upload(writer, tmp_path, logical("state"), "part.enc", b"ciphertext")
    writer.physical[next(iter(writer.physical))] = b"corruption"
    fresh = reader(writer, store)
    state = object.__new__(GitHubStateStore)
    state.transport, state._verified_downloads = fresh, set()
    with pytest.raises(StateIntegrityError):
        state._download_verified(descriptor, tmp_path / "download")
    assert not state._verified_downloads


def test_corrupt_inline_metadata_rejected_before_delivery(tmp_path):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    descriptor = upload(writer, tmp_path, logical("state"), "index.enc", b"sealed")
    bad = copy.deepcopy(descriptor)
    document = json.loads(store.get(bad["storage"]["catalog"]))
    document["metadata"]["index.enc"]["base64"] = "YmFkeHh4"
    bad["storage"]["catalog"] = store.put("packages/bad.json", canonical_json(document), allow_update=True)
    fresh = reader(writer, store)
    fresh.pin_asset_ref(bad)
    with pytest.raises((StateError, CycleCatalogError)):
        fresh.download_asset(bad["release_tag"], bad["name"], tmp_path / "inline")


def test_decryption_authentication_failure_is_not_bypassed(tmp_path, monkeypatch):
    from icsot_observer import github_state
    state = object.__new__(GitHubStateStore)
    state.private_key = tmp_path / "key-reference-only"

    def reject(*args):
        raise ValueError("authentication failed")

    monkeypatch.setattr(github_state, "decrypt_file", reject)
    with pytest.raises(StateError, match="authenticate"):
        state._decrypt({}, tmp_path / "ciphertext", tmp_path / "plaintext")


def test_shared_release_creation_race_reconciles_exact_tag(monkeypatch):
    transport = GhCliStateTransport("owner/archive")
    tag = "collector-cycle-s123"
    calls = []

    def api(endpoint, *, method="GET", payload=None, missing_ok=False):
        calls.append((endpoint, method))
        if method == "POST":
            raise StateError("concurrent creation")
        return None if len(calls) == 1 else {"id": 7, "tag_name": tag, "draft": False, "assets": []}

    monkeypatch.setattr(transport, "_api", api)
    monkeypatch.setattr(transport, "_find_release_after_tag_404", lambda _: None)
    assert transport._release(tag, create=True)["tag_name"] == tag
    assert [method for _, method in calls] == ["GET", "POST", "GET"]


def test_same_generation_state_and_observation_names_do_not_collide(tmp_path):
    writer = FakeTransport(FakeGitMetadataStore())
    upload(writer, tmp_path, logical("state"), "part.enc", b"state")
    upload(writer, tmp_path, logical("observations"), "part.enc", b"observation")
    assert len(writer.physical) == 2


@pytest.mark.parametrize("field,value", [("release_tag", "collector-cycle-s999"),
                                          ("name", "r8-g" + "a" * 32 + "-part.enc")])
def test_catalog_rejects_misdirected_physical_payload(tmp_path, field, value):
    store = FakeGitMetadataStore()
    writer = FakeTransport(store)
    descriptor = upload(writer, tmp_path, logical("state"), "part.enc", b"cipher")
    bad = copy.deepcopy(descriptor)
    document = json.loads(store.get(bad["storage"]["catalog"]))
    document["payloads"]["part.enc"][field] = value
    bad["storage"]["catalog"] = store.put("packages/bad.json", canonical_json(document), allow_update=True)
    fresh = reader(writer, store)
    with pytest.raises((StateError, CycleCatalogError)):
        fresh.pin_asset_ref(bad)
        fresh.download_asset(bad["release_tag"], bad["name"], tmp_path / "misdirected")
    assert not any(call[0] == "download" for call in fresh.calls)


def test_state_publish_fresh_restore_and_reuse_across_cycles(tmp_path, monkeypatch):
    import shutil
    import tempfile

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from test_github_state import FakeGitHub

    # The state store uses tempfile for decrypted indexes and restored parts.
    # Keep those short-lived files under the test's caller-managed budget root.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.delenv("ICSOT_ARCHIVE_PROFILE", raising=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public, private = tmp_path / "public.pem", tmp_path / "private.pem"
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    root = tmp_path / "root"
    root.mkdir()
    content = b"synthetic immutable state object\n"
    identity = digest(content)
    object_path = root / "objects" / "sha256" / identity[:2] / identity
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(content)
    git, branch = FakeGitMetadataStore(), FakeGitHub()
    physical = {}

    def transport(slot):
        result = FakeTransport(git, slot=slot)
        result.physical = physical
        for method in ("branch_head", "read_pointer", "read_slug_binding", "commit_pointer",
                       "advance_branch", "read_proof_outbox"):
            setattr(result, method, getattr(branch, method))
        result.publication_budget = lambda count: {}
        return result

    def state(connection):
        return GitHubStateStore(connection, repository_id=7, slug="owner/repo7",
                                public_key=public, private_key=private, logical_root=root)

    first = transport(123)
    original = state(first)
    marker = upload(first, tmp_path, logical("observations"), "metadata-catalog.json", b'{"synthetic":true}\n')
    catalog = {"release_tag": marker["release_tag"], "name": marker["name"],
               "sha256": marker["ciphertext_sha256"], "bytes": marker["ciphertext_bytes"],
               "storage": marker["storage"]}
    first_result = original.publish(original.read(), quiescent=True, dependencies=[marker], proof_catalog=catalog)
    pointer = first_result["pointer"]
    assert pointer["index"]["storage"]["kind"] == "cycle_git_catalog_v1"
    index_package = json.loads(git.get(pointer["index"]["storage"]["catalog"]))
    assert "index.enc" in index_package["metadata"]
    assert all(tag == "collector-cycle-s123" for tag, _ in physical)

    shutil.rmtree(root)
    root.mkdir()
    fresh = transport(None)
    restored = state(fresh)
    selection = restored.read()
    assert restored.restore(selection)["restored"]
    restored.validate_compaction_metadata(selection.head, selection.pointer)
    node = json.loads(branch.read_proof_outbox(selection.head, 7, selection.pointer["proof_outbox"]))
    assert node["catalog"] == catalog
    assert object_path.read_bytes() == content
    object_entry = next(row for row in selection.index["files"] if row["path"] == object_path.relative_to(root).as_posix())
    part_id = object_entry["segments"][0]["part"]
    old_part = selection.index["parts"][part_id]
    assert old_part["storage"]["kind"] == "cycle_git_catalog_v1"
    assert old_part["storage"]["catalog"] != pointer["index"]["storage"]["catalog"]
    part_package = json.loads(git.get(old_part["storage"]["catalog"]))
    assert old_part["name"] in part_package["payloads"]
    assert "index.enc" not in part_package["metadata"]
    assert all(call[1].startswith("collector-cycle-") for call in fresh.calls if call[0] in ("release", "download"))

    (root / "new-checkpoint.json").write_bytes(b'{"cycle":2}')
    second = transport(124)
    next_state = state(second)
    next_result = next_state.publish(next_state.read(), quiescent=True)
    assert next_result["reused_parts"] >= 1
    next_selection = state(transport(None)).read()
    assert next_selection.index["parts"][part_id] == old_part
    assert next_selection.pointer["index"]["storage"]["catalog"] != pointer["index"]["storage"]["catalog"]
    assert {tag for tag, _ in physical} == {"collector-cycle-s123", "collector-cycle-s124"}
    shutil.rmtree(root)
    root.mkdir()
    last = state(transport(None))
    assert last.restore(last.read())["restored"]
    assert object_path.read_bytes() == content
    assert (root / "new-checkpoint.json").read_bytes() == b'{"cycle":2}'
