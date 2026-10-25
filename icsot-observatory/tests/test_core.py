import json
from pathlib import Path

import pytest

from icsot_observer.core import Config, ObjectStore, canonical_json, sha256, write_once
from icsot_observer.github import GitHubAPI


def test_raw_bytes_not_normalized(tmp_path):
    store = ObjectStore(tmp_path)
    raw = b'{ "a": 1, "b": 2 }\n'
    digest = store.put(raw)
    assert store.get(digest) == raw
    assert digest == sha256(raw)
    assert digest != sha256(canonical_json(json.loads(raw)))


def test_create_only_and_integrity(tmp_path):
    p = tmp_path / "run.json"
    write_once(p, b"first")
    with pytest.raises(FileExistsError):
        write_once(p, b"second")
    assert p.read_bytes() == b"first"
    store = ObjectStore(tmp_path)
    digest = store.put(b"evidence")
    store.location(digest).write_bytes(b"TAMPERED")
    with pytest.raises(RuntimeError, match="integrity"):
        store.get(digest)


def test_url_allowlist_and_slug(tmp_path):
    for url in ("https://evil.example/repos/a/b", "http://api.github.com/repos/a/b",
                "https://api.github.com.evil.example/repos/a/b", "https://api.github.com/users/a"):
        with pytest.raises(ValueError):
            GitHubAPI.validate_url(url)
    GitHubAPI.validate_url("https://api.github.com/repos/open62541/open62541/issues?page=2")
    config = tmp_path / "cfg.toml"
    config.write_text('''[collector]
root="./data"
api_version="2026-03-10"
user_agent="research"
token_env="DO_NOT_EXIST"
[cohort]
repositories=["open62541/open62541"]
''')
    assert Config.load(config).root == tmp_path / "data"
