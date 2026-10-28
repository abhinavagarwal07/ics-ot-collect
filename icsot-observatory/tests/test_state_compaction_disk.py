"""Compaction admission and index lifetimes without large on-disk fixtures."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer import github_state as state
from test_github_state import cas_file, clear, compact_for_test, publish, rsa_key, setup


def _predecessor(setup):
    transport, make, _ = setup
    options = dict(part_bytes=32768, immutable_group_bytes=20480)
    legacy = make(small_immutable_bytes=0, **options)
    for value in (b"alpha", b"beta", b"gamma"):
        cas_file(legacy, value)
    publish(legacy)
    selection = legacy.read()
    store = make(**options)
    clear(store)
    store.restore(selection)
    return transport, store, selection


def test_large_index_admission_covers_copy_fallback_and_remote_lifetimes():
    # These are allocation sizes only: no 300 MiB fixture is materialized.
    mib = 1024 * 1024
    plaintext = 300 * mib
    ciphertext = plaintext + state.ENVELOPE_OVERHEAD
    upload = 544 * mib
    group = 128 * mib
    restored = 8 * mib
    old_part_scratch = 3 * mib
    frozen_parts = upload - ciphertext
    # Each list represents distinct physical allocations. A successful capture
    # hardlink aliases the original ciphertext, while fallback has two inodes.
    phases = {
        "capture_hardlink": [frozen_parts, plaintext, ciphertext],
        "capture_copy": [frozen_parts, plaintext, ciphertext, ciphertext],
        "upload_index_check": [upload, ciphertext],
        "remote_index_decrypt": [upload, ciphertext, plaintext],
        "reconstruct_old_part": [upload, restored, old_part_scratch],
        "reconstruct_new_group": [upload, restored, group + state.ENVELOPE_OVERHEAD, group, group],
    }
    required = state.GitHubStateStore._compaction_disk_bytes(
        max_upload_bytes=upload, index_plaintext_bound=plaintext,
        state_bytes=restored, max_old_part_scratch=old_part_scratch,
        immutable_group_bytes=group)
    assert all(required >= sum(allocations) for allocations in phases.values())
    previous_estimate = upload + restored + old_part_scratch + 4 * (group + 65536)
    assert previous_estimate < sum(phases["capture_copy"])
    assert previous_estimate < sum(phases["remote_index_decrypt"])


@pytest.mark.parametrize("copy_fallback", [False, True])
def test_compaction_releases_index_scratch_and_keeps_frozen_ciphertext(setup, monkeypatch, copy_fallback):
    transport, store, selection = _predecessor(setup)
    old_assets, old_head = dict(transport.assets), transport.head
    link = state.os.link

    def frozen_link(source, target, *args, **kwargs):
        if copy_fallback and "frozen" in Path(target).parts:
            raise OSError("synthetic hardlink failure")
        return link(source, target, *args, **kwargs)

    monkeypatch.setattr(state.os, "link", frozen_link)
    capture = state._PreparedSink.capture
    observed = {}

    def capture_index(sink, ref, source):
        capture(sink, ref, source)
        if ref["name"] == "index.enc":
            frozen = sink.directory / sink.assets[-1]["path"]
            observed.update(directory=source.parent, frozen=frozen, ref=ref)
            assert source.exists() and (source.parent / "index.json").exists()
            same_inode = (source.stat().st_dev, source.stat().st_ino) == (
                frozen.stat().st_dev, frozen.stat().st_ino)
            assert same_inode is (not copy_fallback)

    monkeypatch.setattr(state._PreparedSink, "capture", capture_index)

    def check_frozen():
        frozen = observed["frozen"]
        assert frozen.exists()
        assert hashlib.sha256(frozen.read_bytes()).hexdigest() == observed["ref"]["ciphertext_sha256"]
        assert not (observed["directory"] / "index.json").exists()
        assert not (observed["directory"] / "index.enc").exists()

    upload = transport.upload_asset

    def upload_without_preparation_scratch(tag, name, source):
        check_frozen()
        return upload(tag, name, source)

    monkeypatch.setattr(transport, "upload_asset", upload_without_preparation_scratch)
    compare_map = store._check_compaction_file_map

    def compare_remote(predecessor, candidate):
        if observed:
            directory = observed["directory"]
            assert (directory / "remote-index.enc").exists()
            assert (directory / "remote-index.json").exists()
            observed["remote_index_checked"] = True
            check_frozen()
        return compare_map(predecessor, candidate)

    monkeypatch.setattr(store, "_check_compaction_file_map", compare_remote)
    reconstruct = store._reconstruct

    def reconstruct_without_index_scratch(*args, **kwargs):
        check_frozen()
        assert observed["remote_index_checked"]
        assert not (observed["directory"] / "remote-index.enc").exists()
        assert not (observed["directory"] / "remote-index.json").exists()
        observed["reconstructed"] = True
        return reconstruct(*args, **kwargs)

    monkeypatch.setattr(store, "_reconstruct", reconstruct_without_index_scratch)
    advance = store._advance

    def advance_after_verification(*args, **kwargs):
        check_frozen()
        assert observed["reconstructed"] and transport.head == old_head
        assert all(transport.assets[key] == value for key, value in old_assets.items())
        return advance(*args, **kwargs)

    monkeypatch.setattr(store, "_advance", advance_after_verification)
    result = compact_for_test(store, selection)
    assert result["status"] == "complete" and result["full_remote_reconstruction_verified"]
    assert result["verification_scope"] == "working_state_files_only"
    assert not observed["directory"].exists()


def test_compaction_disk_rejection_precedes_preparation_and_upload(setup, monkeypatch):
    transport, store, selection = _predecessor(setup)
    old_assets, old_uploads, old_head = dict(transport.assets), list(transport.uploads), transport.head
    monkeypatch.setattr(state.shutil, "disk_usage", lambda path: SimpleNamespace(free=0))
    monkeypatch.setattr(store, "_part", lambda *args, **kwargs: pytest.fail("preparation before disk admission"))
    with pytest.raises(state.StateError, match="Insufficient disk for compaction"):
        compact_for_test(store, selection)
    assert transport.assets == old_assets and transport.uploads == old_uploads and transport.head == old_head
    assert store.compaction_candidate_pointer_sha256 is None


def test_compaction_index_must_fit_preliminary_admission_before_upload(setup, monkeypatch):
    transport, store, selection = _predecessor(setup)
    old_assets, old_uploads, old_head = dict(transport.assets), list(transport.uploads), transport.head
    part = store._part

    def oversized_candidate(*args, **kwargs):
        part_id = part(*args, **kwargs)
        # Simulate a producer whose candidate exceeds the preflight's bound.
        args[5][part_id]["synthetic_metadata"] = "x" * (store.part_bytes + 1)
        return part_id

    monkeypatch.setattr(store, "_part", oversized_candidate)
    with pytest.raises(state.StateDeferredError, match="admitted plaintext bound") as failure:
        compact_for_test(store, selection)
    assert failure.value.reason == "compaction_byte_limit"
    assert transport.assets == old_assets and transport.uploads == old_uploads and transport.head == old_head
    assert store.compaction_candidate_pointer_sha256 is None
