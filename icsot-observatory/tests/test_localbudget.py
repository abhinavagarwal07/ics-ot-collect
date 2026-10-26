import io
import errno
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer import localbudget
from icsot_observer.localbudget import BudgetError, LocalBudget, _tree_bytes


def test_stage_is_bounded_private_and_deleted(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    before = budget.snapshot()
    with budget.stage(4096, suffix=".enc") as stage:
        path = stage.path
        with stage.open_writer() as output:
            assert output.write(b"a" * 4096) == 4096
            with pytest.raises(BudgetError, match="declared"):
                output.write(b"b")
        assert path.read_bytes() == b"a" * 4096
        assert path.stat().st_mode & 0o777 == 0o600
        assert budget.snapshot().admitted_bytes <= 2_000_000
    assert not path.exists()
    assert budget.snapshot().reserved_bytes == before.reserved_bytes == 0


def test_failures_release_reservation_and_remove_own_partial_only(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.write_bytes(b"retained study evidence")
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    with pytest.raises(RuntimeError):
        with budget.stage(100) as stage:
            path = stage.path
            stage.open_writer().write(b"partial")
            raise RuntimeError("generated interruption")
    assert not path.exists()
    assert evidence.read_bytes() == b"retained study evidence"
    assert budget.snapshot().reserved_bytes == 0


def test_independent_clients_share_reservations(tmp_path):
    state = tmp_path / "budget"
    first = LocalBudget(state, roots=[tmp_path], limit_bytes=1_000_000)
    with first.reserve(600_000):
        code = """from icsot_observer.localbudget import LocalBudget, BudgetError
import sys
budget=LocalBudget(sys.argv[1],roots=[sys.argv[2]],limit_bytes=1000000)
try:
    with budget.reserve(500000):
        raise AssertionError('second client over-admitted')
except BudgetError:
    pass
"""
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        result = subprocess.run([sys.executable, "-c", code, str(state), str(tmp_path)],
                                env=env, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr.decode()
    assert first.snapshot().reserved_bytes == 0


def test_eviction_is_only_explicit_managed_cache(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.write_bytes(b"keep" * 10_000)
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=1_000_000)
    with budget.stage(200_000) as stage:
        stage.copy_from(io.BytesIO(b"c" * 200_000))
        cached = stage.preserve()
    available = budget.snapshot().available_bytes
    with budget.reserve(available + 100_000):
        assert not cached.exists()
        assert evidence.read_bytes() == b"keep" * 10_000
    assert not list((budget.root / "staging").iterdir())


def test_deduplicates_overlapping_roots_and_hardlinks(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    original = evidence / "one"
    original.write_bytes(b"x" * 8192)
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path, evidence], limit_bytes=2_000_000)
    before = budget.snapshot().allocated_bytes
    os.link(original, evidence / "two")
    after = budget.snapshot().allocated_bytes
    # Adding a hardlink may grow its directory, but never counts content twice.
    assert after - before < 8192
    assert len(budget.snapshot().roots) == 3


def test_open_cache_lease_prevents_unlinked_open_disk_gap(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=1_000_000)
    with budget.stage(200_000) as stage:
        stage.copy_from(io.BytesIO(b"c" * 200_000))
        cached = stage.preserve()
    with budget.open_cached(cached) as stream:
        with pytest.raises(BudgetError):
            budget.reserve(budget.snapshot().available_bytes + 100_000)
        assert cached.exists()
        assert stream.read(5) == b"ccccc"
    with budget.reserve(budget.snapshot().available_bytes + 100_000):
        assert not cached.exists()


def test_sparse_file_counts_allocation_instead_of_logical_size(tmp_path):
    sparse = tmp_path / "sparse"
    try:
        with sparse.open("wb") as output:
            output.seek(3_000_000_000)
            output.write(b"x")
    except OSError as error:
        sparse.unlink(missing_ok=True)
        if error.errno in (errno.ENOSPC, errno.EFBIG):
            pytest.skip("Filesystem cannot create the sparse fixture within its allocation limit")
        raise
    if not hasattr(sparse.stat(), "st_blocks") or sparse.stat().st_blocks * 512 > 100_000:
        sparse.unlink()
        pytest.skip("Filesystem does not support a small sparse fixture")
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    assert budget.snapshot().allocated_bytes < 200_000


def test_tracked_bounded_volume_materialization_is_not_double_reserved(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    image = tmp_path / "bounded-image"
    with budget.reserve(400_000) as reservation:
        reservation.track(image)
        before = budget.snapshot().admitted_bytes
        image.write_bytes(b"x" * 100_000)  # Generated simulated fixed-volume output.
        after = reservation.check().admitted_bytes
        assert abs(after - before) < 16_384
    image.unlink()


def test_rejects_separate_limits_and_unsafe_suffix(tmp_path):
    LocalBudget(tmp_path / "budget", limit_bytes=2_000_000)
    with pytest.raises(BudgetError, match="different limit"):
        LocalBudget(tmp_path / "budget", limit_bytes=1_000_000)
    budget = LocalBudget(tmp_path / "budget", limit_bytes=2_000_000)
    with pytest.raises(ValueError):
        budget.stage(10, suffix="/escape")


@pytest.mark.parametrize("control", ["staging", "cache"])
def test_rejects_symlinked_managed_directories(tmp_path, control):
    root, outside = tmp_path / "budget", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / control).symlink_to(outside, target_is_directory=True)
    with pytest.raises(BudgetError, match="real directories"):
        LocalBudget(root, roots=[tmp_path], limit_bytes=2_000_000)
    assert not list(outside.iterdir())


def test_rejects_symlinked_state_file(tmp_path):
    root, outside = tmp_path / "budget", tmp_path / "outside"
    root.mkdir()
    outside.write_text("private user data")
    (root / "budget.json").symlink_to(outside)
    with pytest.raises(BudgetError, match="regular files"):
        LocalBudget(root, roots=[tmp_path], limit_bytes=2_000_000)
    assert outside.read_text() == "private user data"


def test_cannot_materialize_existing_evidence_or_other_reservation(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    evidence = tmp_path / "evidence"
    evidence.write_bytes(b"existing evidence")
    with budget.reserve(200_000) as first, budget.reserve(200_000) as second:
        with pytest.raises(BudgetError, match="new paths"):
            first.track(evidence)
        first.track(tmp_path / "owned-new-directory")
        with pytest.raises(BudgetError, match="overlap"):
            second.track(tmp_path / "owned-new-directory" / "child")


def test_dead_client_reservation_does_not_expire_by_pid(tmp_path):
    state = tmp_path / "budget"
    code = """from icsot_observer.localbudget import LocalBudget
import os,sys
budget=LocalBudget(sys.argv[1],roots=[sys.argv[2]],limit_bytes=1000000)
budget.reserve(600000)
os._exit(0)
"""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    result = subprocess.run([sys.executable, "-c", code, str(state), str(tmp_path)],
                            env=env, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode()
    budget = LocalBudget(state, roots=[tmp_path], limit_bytes=1_000_000)
    assert budget.snapshot().reserved_bytes == 600_000
    with pytest.raises(BudgetError):
        budget.reserve(500_000)


def test_stage_cannot_be_opened_after_reservation_released(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    with budget.stage(100) as stage:
        pass
    with pytest.raises(BudgetError):
        stage.open_writer()
    assert not stage.path.exists()


def test_unique_managed_staging_child_can_hold_fixed_volume(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    directory = budget.root / "staging" / "generated-owned-volume"
    with budget.reserve(200_000) as reservation:
        reservation.track(directory)
        directory.mkdir(mode=0o700)
        assert reservation.check().admitted_bytes <= 2_000_000
        directory.rmdir()


def test_mount_counts_full_capacity_without_recursion_or_nested_root_bypass(tmp_path, monkeypatch):
    mount = tmp_path / "generated-mount"
    nested = mount / "explicitly-registered-child"
    nested.mkdir(parents=True)
    (nested / "small").write_bytes(b"small")
    capacity = 4 * 1024 * 1024
    real_scandir, real_ismount, real_statvfs = os.scandir, os.path.ismount, os.statvfs
    scanned, volume_queries = [], []

    def guarded_scandir(path):
        path = Path(path)
        scanned.append(path)
        if path == mount or mount in path.parents:
            raise AssertionError("Must not recurse into a fully charged mount")
        return real_scandir(path)

    def volume_info(path):
        if Path(path) == mount:
            volume_queries.append(Path(path))
            return SimpleNamespace(f_blocks=1024, f_frsize=4096, f_bsize=4096)
        return real_statvfs(path)

    monkeypatch.setattr(os.path, "ismount", lambda path: Path(path) == mount or real_ismount(path))
    monkeypatch.setattr(os, "statvfs", volume_info)
    monkeypatch.setattr(os, "scandir", guarded_scandir)
    assert _tree_bytes([nested, mount]) == capacity
    assert volume_queries == [mount]
    assert not scanned
    # A workspace ancestor and an explicit nested root still charge the full
    # mount; its unreadable system directories never need to be opened.
    assert _tree_bytes([nested, tmp_path]) >= capacity
    assert not any(path == mount or mount in path.parents for path in scanned)


def test_unreadable_normal_directory_still_fails_closed(tmp_path, monkeypatch):
    protected = tmp_path / "generated-normal-directory"
    protected.mkdir()
    real_scandir = os.scandir

    def deny_normal_directory(path):
        if Path(path) == protected:
            raise PermissionError("Generated unreadable normal directory")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", deny_normal_directory)
    with pytest.raises(PermissionError, match="Generated unreadable"):
        _tree_bytes([protected])


def test_growth_after_global_observation_never_reduces_fixed_reservation(tmp_path, monkeypatch):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    directory = tmp_path / "generated-opaque-work"
    with budget.reserve(400_000) as reservation:
        reservation.track(directory)
        directory.mkdir()
        growing = directory / "growing"
        growing.touch()
        before = budget.snapshot().admitted_bytes
        real_walk, calls = localbudget._walk_allocations, []

        def expand_after_observation(roots, owners=None, seen=None):
            result = real_walk(roots, owners, seen)
            calls.append(owners)
            # Deterministic old race: grow after the global measurement, before
            # a former independent reserved-subtree rescan could subtract it.
            growing.write_bytes(b"x" * 200_000)
            return result

        monkeypatch.setattr(localbudget, "_walk_allocations", expand_after_observation)
        snapshot = budget.snapshot()
        assert len(calls) == 1
        assert growing.stat().st_blocks * 512 >= 200_000
        assert snapshot.admitted_bytes >= before


def test_owned_allocation_above_maximum_is_fully_charged(tmp_path):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    directory = tmp_path / "generated-oversized-work"
    with budget.reserve(100_000) as reservation:
        reservation.track(directory)
        directory.mkdir()
        before = budget.snapshot()
        (directory / "over-bound").write_bytes(b"x" * 250_000)
        after = budget.snapshot()
        assert after.reserved_bytes == 0
        assert after.admitted_bytes >= before.admitted_bytes + 140_000
