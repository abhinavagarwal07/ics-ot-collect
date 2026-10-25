from pathlib import Path
import subprocess

from icsot_observer.core import ObjectStore
from icsot_observer.gitstore import run_git


def test_portable_full_git_bundle(tmp_path):
    source = tmp_path / "origin"
    source.mkdir()
    run_git(["init", "-b", "main", str(source)])
    run_git(["-C", str(source), "config", "user.email", "test@example.invalid"])
    run_git(["-C", str(source), "config", "user.name", "Test"])
    (source / "file.txt").write_text("an original state\n")
    run_git(["-C", str(source), "add", "file.txt"])
    run_git(["-C", str(source), "commit", "-m", "v1"])
    mirror = tmp_path / "mirror.git"
    run_git(["init", "--bare", str(mirror)])
    run_git(["-C", str(mirror), "remote", "add", "origin", str(source)])
    run_git(["-C", str(mirror), "fetch", "--no-prune", "origin",
             "+refs/heads/*:refs/live/heads/*", "+refs/pull/*/head:refs/live/pull/*/head"])
    sha = run_git(["-C", str(source), "rev-parse", "HEAD"]).strip()
    run_git(["-C", str(mirror), "update-ref", "refs/archive/collection1/heads/main", sha])
    bundle = tmp_path / "full.bundle"
    run_git(["-C", str(mirror), "bundle", "create", str(bundle), "--all"])
    store = ObjectStore(tmp_path / "cas")
    digest, length = store.put_file(bundle)
    assert store.verify(digest)
    assert store.location(digest).stat().st_size == length
    run_git(["-C", str(mirror), "bundle", "verify", str(store.location(digest))])
