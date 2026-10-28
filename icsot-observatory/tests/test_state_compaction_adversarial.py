"""Adversarial compaction checks using synthetic state and the real envelope codec."""
import copy
import stat

import pytest

from icsot_observer.github_state import StateConflictError, StateError
from test_github_state import clear, publish, rsa_key, setup, write


def _compact(store, selection):
    return store.compact(selection, max_input_bytes=100_000, max_input_parts=100,
                         max_upload_bytes=1_000_000, max_runtime_seconds=120, quiescent=True)


def _file_map(selection):
    return {item["path"]: item for item in selection.index["files"]}


def _restored_map(store):
    result = {}
    for path in sorted(store.root.rglob("*")):
        if path.is_file() and path.name != ".collector.lock":
            result[path.relative_to(store.root).as_posix()] = (
                path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
    return result


def _mixed_predecessor(setup):
    transport, make, _ = setup
    options = dict(part_bytes=10240, immutable_group_bytes=10240)
    legacy = make(small_immutable_bytes=0, **options)
    prefix = "git/7.git/objects/pack/"
    for name, value in (("shared-a.pack", b"shared bytes"),
                        ("shared-b.idx", b"shared bytes"),
                        ("tail.idx", b"tail"), ("single-a.idx", b"one"),
                        ("single-b.idx", b"two"),
                        ("split.pack", b"Z" * 10240 + b"tail")):
        write(legacy, prefix + name, value)
    (legacy.root / (prefix + "shared-a.pack")).chmod(0o700)
    publish(legacy)
    old = legacy.read()
    store = make(small_immutable_bytes=2048, **options)
    write(store, prefix + "new-a.pack", b"new one")
    write(store, prefix + "new-b.idx", b"new two")
    publish(store, old)
    selected = store.read()
    files = _file_map(selected)
    assert files[prefix + "shared-a.pack"]["segments"] == files[prefix + "shared-b.idx"]["segments"]
    split_segments = files[prefix + "split.pack"]["segments"]
    assert len(split_segments) == 2
    assert files[prefix + "tail.idx"]["segments"][0]["part"] == split_segments[1]["part"]
    assert files[prefix + "new-a.pack"]["segments"][0]["part"] == files[prefix + "new-b.idx"]["segments"][0]["part"]
    clear(store)
    store.restore(selected)
    expected = _restored_map(store)
    return transport, store, selected, expected, prefix


def test_compaction_shared_parts_closures_and_split_restore(setup):
    transport, store, before, expected, prefix = _mixed_predecessor(setup)
    old_assets = copy.deepcopy(transport.assets)
    old_files = _file_map(before)
    report = _compact(store, before)
    assert report["status"] == "complete" and report["full_remote_reconstruction_verified"]
    assert report["part_savings"] > 0
    after = store.read()
    new_files = _file_map(after)
    for name in ("tail.idx", "split.pack"):
        assert new_files[prefix + name]["segments"] == old_files[prefix + name]["segments"]
    assert {k: (v["bytes"], v["sha256"], v["mode"]) for k, v in new_files.items()} == {
        k: (v["bytes"], v["sha256"], v["mode"]) for k, v in old_files.items()}
    assert after.index["dependencies"] == before.index["dependencies"]
    assert after.pointer.get("proof_outbox") == before.pointer.get("proof_outbox")
    assert all(transport.assets[k] == value for k, value in old_assets.items())
    clear(store)
    store.restore(before)
    assert _restored_map(store) == expected
    clear(store)
    store.restore(after)
    assert _restored_map(store) == expected
    assert expected[prefix + "shared-a.pack"][1] == 0o700


def test_authenticated_wrong_tar_members_fail_before_pointer_cas(setup, monkeypatch):
    transport, store, before, expected, _ = _mixed_predecessor(setup)
    old_head = transport.head
    original = store._tar_info
    def wrong_name(item):
        info = original(item)
        info.name += ".unexpected"
        return info
    # Simulate a producer defect that escapes the local tar check: the resulting
    # archive is encrypted with a valid GCM tag and named by the true ciphertext.
    monkeypatch.setattr(store, "_tar_info", wrong_name)
    monkeypatch.setattr(store, "_verify_group_files", lambda *args: None)
    uploads_before = len(transport.uploads)
    with pytest.raises(StateError):
        _compact(store, before)
    assert transport.head == old_head
    assert len(transport.uploads) > uploads_before
    clear(store)
    store.restore(before)
    assert _restored_map(store) == expected


def test_remote_tamper_is_rechecked_despite_warm_restore_cache(setup):
    transport, store, before, expected, prefix = _mixed_predecessor(setup)
    # The split file's two-segment part is not a compaction input, and restore
    # already placed its asset identity in this same store's verification cache.
    ref = before.index["parts"][_file_map(before)[prefix + "split.pack"]["segments"][0]["part"]]
    key = (ref["release_tag"], ref["name"])
    original = transport.assets[key]
    old_head = transport.head
    transport.assets[key] = original[:-1] + bytes([original[-1] ^ 1])
    with pytest.raises(StateError, match="hash/size differs"):
        _compact(store, before)
    assert transport.head == old_head
    transport.assets[key] = original
    clear(store)
    store.restore(before)
    assert _restored_map(store) == expected


def test_same_repository_winner_prevents_compaction_cas(setup):
    transport, store, before, expected, _ = _mixed_predecessor(setup)
    def concurrent_winner():
        publish(store, before)
    transport.on_advance = concurrent_winner
    with pytest.raises(StateConflictError):
        _compact(store, before)
    winner = store.read()
    assert winner.pointer != before.pointer
    clear(store)
    store.restore(winner)
    assert _restored_map(store) == expected
    clear(store)
    store.restore(before)
    assert _restored_map(store) == expected


def test_source_drift_after_reconstruction_aborts_before_cas(setup, monkeypatch):
    transport, store, before, expected, prefix = _mixed_predecessor(setup)
    old_head = transport.head
    reconstruct = store._reconstruct
    def drift_after_reconstruction(*args, **kwargs):
        reconstruct(*args, **kwargs)
        write(store, prefix + "single-a.idx", b"mutated after round trip")
    monkeypatch.setattr(store, "_reconstruct", drift_after_reconstruction)
    with pytest.raises(StateError, match="root differs"):
        _compact(store, before)
    assert transport.head == old_head
    monkeypatch.setattr(store, "_reconstruct", reconstruct)
    clear(store)
    store.restore(before)
    assert _restored_map(store) == expected


def test_daily_proof_reader_registers_predecessor_outbox_after_compaction(setup):
    import json

    from icsot_observer.github_state import GitHubStateStore
    from icsot_observer.proof_maintenance import refresh
    from test_github_runner_integration import MemoryGitHub
    from test_proof_maintenance import ControlledClient, observation

    _, _, tmp_path = setup
    transport = MemoryGitHub()
    transport.markers = {}
    tag = "collector-observations-r7-g" + "a" * 32
    catalog, _ = observation(tmp_path, transport, tag=tag)
    dependency = {"release_tag": tag, "name": catalog["name"],
                  "ciphertext_sha256": catalog["sha256"], "ciphertext_bytes": catalog["bytes"]}
    options = dict(transport=transport, repository_id=7, slug="owner/repo7",
                   logical_root=tmp_path / "proof-state", public_key=tmp_path / "public.pem",
                   private_key=tmp_path / "private.pem", part_bytes=10240,
                   immutable_group_bytes=10240)
    legacy = GitHubStateStore(small_immutable_bytes=0, **options)
    for n in range(4):
        write(legacy, f"git/7.git/objects/pack/{n}.idx", f"old part {n}".encode())
    publish(legacy, dependencies=[dependency], proof_catalog=catalog,
            evidence_heads={"observation_started_at": "2026-10-25T01:02:03.000000Z",
                            "observation_finished_at": "2026-10-25T01:02:04.000000Z"})
    before = legacy.read()
    node_ref = copy.deepcopy(before.pointer["proof_outbox"])
    node_raw = transport.outbox_node(transport.head, 7, node_ref)
    node = json.loads(node_raw)
    assert node["generation"] == before.pointer["generation"]
    store = GitHubStateStore(small_immutable_bytes=2048, **options)
    clear(store)
    store.restore(before)
    assert _compact(store, before)["status"] == "complete"
    after = store.read()
    assert after.pointer["proof_outbox"] == node_ref
    assert transport.outbox_node(transport.head, 7, node_ref) == node_raw
    assert after.pointer["generation"] != node["generation"]
    assert after.index["context"]["evidence_heads"] == before.index["context"]["evidence_heads"]
    maintenance = after.index["context"]["maintenance"]
    assert maintenance["predecessor_snapshot_started_at"] == before.pointer["snapshot_started_at"]
    assert maintenance["predecessor_snapshot_sealed_at"] == before.pointer["snapshot_sealed_at"]
    client = ControlledClient(fail=True)
    result = refresh(transport, client=client, max_proofs=1, max_markers=1, clock=lambda: 10000)
    assert result["outbox_nodes_registered"] == 1 and result["outbox_invalid_registrations"] == 0
    assert result["proofs_attempted"] == 1 and client.calls == 1
    row = transport.proof_state["discovery"]["proof_outbox"]["repositories"]["7"]
    assert row["completed_head"] == node_ref and row["cursor"] is None
    assert f"catalogs/{catalog['sha256']}.json" in transport.proof_records
