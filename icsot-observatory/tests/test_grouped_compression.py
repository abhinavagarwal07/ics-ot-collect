import copy
import hashlib
import os
import threading
from pathlib import Path
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import compression
from icsot_observer.archive_reader import ArchiveError, ArchivePart, VerifiedArchiveReader, reader_options


@pytest.fixture
def keys(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private, public = tmp_path / "private", tmp_path / "public"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    os.chmod(private, 0o600)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public


def light_encoder(root, members, destination):
    compression.stream_tar_xz(root, members, destination, command=("xz", "-T1", "-0", "-c"))


@pytest.fixture
def archive(tmp_path, keys):
    root, temp, out = tmp_path / "root", tmp_path / "scratch", tmp_path / "out"
    root.mkdir(); temp.mkdir(); out.mkdir()
    members = []
    for i in range(5):
        data = (f"member {i} ".encode() * 800)[:5500]
        path = f"file-{i}"
        (root / path).write_bytes(data)
        members.append({"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    assets, groups = compression.export_groups(root, members, temp, out, "capture", keys[1],
                                                limit=10240, encoder=light_encoder)
    parts = [ArchivePart(out / asset["name"], asset["sha256"], asset["bytes"],
                         asset["encryption"]["plaintext_sha256"], asset["encryption"]["plaintext_bytes"],
                         asset["name"]) for asset in assets]
    expected = {"evidence/" + m["path"]: {"bytes": m["bytes"], "sha256": m["sha256"]} for m in members}
    index = {"archive_layout": "independent-tar-xz-groups-v2", "assets": assets, "groups": groups}
    return parts, expected, index, keys[0], root


def scan(parts, expected, index, private, callback=None):
    return VerifiedArchiveReader(parts, private, expected_members=expected, allowed_prefixes=("evidence",),
                                 **reader_options(index)).scan(callback)


def test_exact_profile_and_tar_group_bound():
    assert compression.XZ_COMMAND == ("xz", "-T1", "--no-adjust", "--memlimit-compress=2500MiB",
                                      "--lzma2=preset=8,dict=192MiB", "-c")
    member = {"path": "long/" * 30 + "x", "bytes": 1, "sha256": "0" * 64}
    assert compression.plan_groups([member], limit=10240)[0][1] == 10240
    with pytest.raises(ValueError, match="exceeds tar group"):
        compression.plan_groups([{**member, "bytes": 9000}], limit=10240)


def test_independent_group_roundtrip_and_exact_tar_length(archive):
    parts, expected, index, private, root = archive
    assert len(parts) == 5
    observed = {}
    result = scan(parts, expected, index, private, lambda m, s: observed.update({m.path: s.read()}))
    assert observed == {"evidence/" + path.name: path.read_bytes() for path in root.iterdir()}
    assert len(result.parts) == len(result.members) == 5
    assert all(g["tar_plaintext_bytes"] == 10240 for g in index["groups"])
    assert all(p["authentication"] == "authenticated_twice" for p in result.parts)


@pytest.mark.parametrize("fault", ["missing", "extra", "reordered", "duplicate", "group-member", "group-size", "late-corrupt", "unsafe"])
def test_group_failures(archive, fault):
    parts, expected, original, private, _ = archive
    index = copy.deepcopy(original)
    if fault == "missing": parts = parts[:-1]
    if fault == "extra": parts = parts + parts[:1]
    if fault == "reordered": parts = parts[::-1]
    if fault == "duplicate": index["groups"][1]["members"] = index["groups"][0]["members"]
    if fault == "group-member": index["groups"][0]["members"][0]["sha256"] = "0" * 64
    if fault == "group-size": index["groups"][0]["tar_plaintext_bytes"] = 20480
    if fault == "unsafe": index["groups"][0]["members"][0]["path"] = "../unsafe"
    if fault == "late-corrupt":
        path = parts[-1].path
        data = bytearray(path.read_bytes()); data[-1] ^= 1; path.write_bytes(data)
    with pytest.raises(ArchiveError): scan(parts, expected, index, private)


def test_parallel_workers_bounded(tmp_path, keys):
    root, temp, out = tmp_path / "root", tmp_path / "temp", tmp_path / "out"
    root.mkdir(); temp.mkdir(); out.mkdir()
    members = []
    for i in range(8):
        data = bytes([i]) * 5500
        (root / str(i)).write_bytes(data)
        members.append({"path": str(i), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    lock, active, peak = threading.Lock(), [0], [0]
    def encoder(root, group, target):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            time.sleep(.05)
            light_encoder(root, group, target)
        finally:
            with lock: active[0] -= 1
    assets, _ = compression.export_groups(root, members, temp, out, "parallel", keys[1], limit=10240,
                                          encoder=encoder)
    assert len(assets) == 8 and 1 < peak[0] <= 4
    assert not list(temp.iterdir())


def test_oversize_fails_before_output(tmp_path, keys):
    out = tmp_path / "out"; out.mkdir()
    with pytest.raises(ValueError, match="exceeds tar group"):
        compression.export_groups(tmp_path, [{"path": "large", "bytes": 9000, "sha256": "0" * 64}],
                                  out, out, "oversize", keys[1], limit=10240, encoder=light_encoder)
    assert not list(out.iterdir())


def test_concatenated_xz_rejected(archive, tmp_path, keys):
    import lzma
    from icsot_observer.encryption import decrypt_file, encrypt_file
    parts, expected, original, private, _ = archive
    index = copy.deepcopy(original)
    plain = tmp_path / "concat.xz"
    decrypt_file(parts[-1].path, plain, private)
    with plain.open("ab") as stream:
        stream.write(lzma.compress(b"unexpected"))
    cipher = tmp_path / "replacement.enc"
    enc = encrypt_file(plain, cipher, keys[1])
    name = parts[-1].name
    parts[-1] = ArchivePart(cipher, enc["ciphertext_sha256"], enc["ciphertext_bytes"],
                            enc["plaintext_sha256"], enc["plaintext_bytes"], name)
    index["assets"][-1]["sha256"] = enc["ciphertext_sha256"]
    index["groups"][-1]["asset"]["sha256"] = enc["ciphertext_sha256"]
    with pytest.raises(ArchiveError, match="Trailing data"):
        scan(parts, expected, index, private)


def test_capture_exporter_opt_in_and_prior_registration(tmp_path, keys, monkeypatch):
    import json
    from icsot_observer import pipeline
    from icsot_observer.core import Config, ObjectStore
    root, out = tmp_path / "root", tmp_path / "out"
    store = ObjectStore(root)
    body = b"message" * 800
    digest = store.put(body)
    capture = {"capture_id": "grouped", "slug": "test/repo", "repository_id": 17,
               "lane": "api", "requested_mode": "delta", "mode": "delta",
               "started_at": "2026-10-20T00:00:00.000000Z", "finished_at": "2026-10-20T00:00:01.000000Z",
               "responses": [{"body_sha256": digest, "body_bytes": len(body)}],
               "failures": [], "git": None, "api": None}
    cfg = Config(root, ("test/repo",), "2026-03-10", "research", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    actual_export = compression.export_groups
    def lightweight(*args, **kwargs):
        return actual_export(*args, **kwargs, limit=10240, encoder=light_encoder)
    monkeypatch.setenv("ICSOT_ARCHIVE_PROFILE", "grouped-xz-v2")
    monkeypatch.setattr(compression, "export_groups", lightweight)
    exporter = pipeline.CaptureExporter(root, out, keys[1])
    finalized = pipeline.finalize_lane(cfg, None, capture, stamp=False, exporter=exporter)
    manifest = json.loads(Path(finalized.manifest_path).read_bytes())
    index = json.loads((out / (manifest["run_id"] + ".index.json")).read_bytes())
    assert index["archive_layout"] == "independent-tar-xz-groups-v2" and len(index["assets"]) >= 1
    assert pipeline.CaptureExporter(root, out, keys[1]).known_exports[index["manifest_sha256"]] == index
    parts = [ArchivePart(out / a["name"], a["sha256"], a["bytes"], a["encryption"]["plaintext_sha256"],
                         a["encryption"]["plaintext_bytes"], a["name"]) for a in index["assets"]]
    expected = {"evidence/" + m["path"]: {"bytes": m["bytes"], "sha256": m["sha256"]}
                for m in index["members"]}
    assert len(scan(parts, expected, index, keys[0]).members) == len(expected)
    altered = copy.deepcopy(index)
    altered["groups"][0]["members"][0]["sha256"] = "0" * 64
    with pytest.raises(ArchiveError):
        pipeline.CaptureExporter(root, tmp_path / "elsewhere", keys[1], verified_prior_indexes=[altered])


def _capture_for_fallback(tmp_path, keys, monkeypatch, body):
    from icsot_observer import pipeline
    from icsot_observer.core import Config, ObjectStore
    root, out = tmp_path / "root", tmp_path / "out"
    digest = ObjectStore(root).put(body)
    capture = {"capture_id": "fallback", "slug": "test/repo", "repository_id": 17,
               "lane": "api", "requested_mode": "delta", "mode": "delta",
               "started_at": "2026-10-20T00:00:00.000000Z", "finished_at": "2026-10-20T00:00:01.000000Z",
               "responses": [{"body_sha256": digest, "body_bytes": len(body)}],
               "failures": [], "git": None, "api": None}
    cfg = Config(root, ("test/repo",), "2026-03-10", "research", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    monkeypatch.setenv("ICSOT_ARCHIVE_PROFILE", "grouped-xz-v2")
    monkeypatch.setattr(compression, "GROUP_LIMIT", 10240)
    monkeypatch.setattr(compression, "XZ_COMMAND", ("xz", "-T1", "-0", "-c"))
    exporter = pipeline.CaptureExporter(root, out, keys[1], part_bytes=120)
    return pipeline, cfg, capture, exporter, root, out


def test_oversized_member_fallback_is_labeled_and_readable(tmp_path, keys, monkeypatch):
    import json
    from icsot_observer.core import ObjectStore
    pipeline, cfg, capture, exporter, root, out = _capture_for_fallback(tmp_path, keys, monkeypatch, b"x" * 9500)
    monkeypatch.setattr(compression, "export_groups", lambda *a, **kw: pytest.fail("group encoder must not run"))
    finalized = pipeline.finalize_lane(cfg, None, capture, stamp=False, exporter=exporter)
    manifest = json.loads(Path(finalized.manifest_path).read_bytes())
    index = json.loads((out / (manifest["run_id"] + ".index.json")).read_bytes())
    assert index["archive_layout"] == "legacy-large-member-fallback-v1"
    assert index["compression_profile"] == compression.FALLBACK_PROFILE
    assert index["large_member_fallback"] == {"reason": compression.LEGACY_FALLBACK_REASON,
        "oversized_member_count": 1, "group_tar_plaintext_limit_bytes": 10240,
        "requested_archive_profile": "grouped-xz-v2"}
    assert reader_options(index) == {"xz_memory_limit": 256 * 1024**2} and len(index["assets"]) > 1
    assert "groups" not in index
    parts = [ArchivePart(out / a["name"], a["sha256"], a["bytes"], a["encryption"]["plaintext_sha256"],
                         a["encryption"]["plaintext_bytes"], a["name"]) for a in index["assets"]]
    expected = {"evidence/" + m["path"]: {"bytes": m["bytes"], "sha256": m["sha256"]}
                for m in index["members"]}
    observed = {}
    report = scan(parts, expected, index, keys[0], lambda m, stream: observed.update({m.path: stream.read()}))
    body_path = "evidence/" + ObjectStore(root).location(capture["responses"][0]["body_sha256"]).relative_to(root).as_posix()
    assert observed[body_path] == b"x" * 9500
    assert len(report.parts) == len(index["assets"])
    assert pipeline.CaptureExporter(root, out, keys[1]).known_exports[index["manifest_sha256"]] == index
    malformed = copy.deepcopy(index)
    malformed["compression_profile"]["encoder_processes"] = 4
    with pytest.raises(ArchiveError, match="fallback metadata"):
        reader_options(malformed)


def test_group_encoder_failure_does_not_trigger_fallback(tmp_path, keys, monkeypatch):
    pipeline, cfg, capture, exporter, _, out = _capture_for_fallback(tmp_path, keys, monkeypatch, b"small")
    def fail(*args, **kwargs):
        raise RuntimeError("controlled encoder failure")
    monkeypatch.setattr(compression, "export_groups", fail)
    with pytest.raises(RuntimeError, match="controlled encoder failure"):
        pipeline.finalize_lane(cfg, None, capture, stamp=False, exporter=exporter)
    assert not list(out.glob("*.index.json"))
    assert not list(out.glob("*.enc"))


def test_fallback_detects_changed_member_and_removes_partial_parts(tmp_path, keys, monkeypatch):
    pipeline, cfg, capture, exporter, root, out = _capture_for_fallback(tmp_path, keys, monkeypatch, b"x" * 9500)
    original = compression.write_tar_members
    def change_then_write(archive, root_path, members):
        target = next(m for m in members if m["bytes"] == 9500)
        (root / target["path"]).write_bytes(b"y" * 9500)
        return original(archive, root_path, members)
    monkeypatch.setattr(compression, "write_tar_members", change_then_write)
    with pytest.raises(RuntimeError, match="changed during export"):
        pipeline.finalize_lane(cfg, None, capture, stamp=False, exporter=exporter)
    assert not list(out.glob("*.index.json"))
    assert not list(out.glob("*.enc"))


@pytest.mark.parametrize("failure", ["sink", "writer"])
def test_fallback_pipe_stops_on_stream_failure(tmp_path, failure):
    import io
    source = tmp_path / "payload"
    data = os.urandom(512 * 1024)
    source.write_bytes(data)
    member = {"path": source.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if failure == "writer":
        member["sha256"] = "0" * 64
    class Sink(io.BytesIO):
        def write(self, data):
            if failure == "sink":
                raise OSError("controlled sink failure")
            return super().write(data)
    finished, outcome = threading.Event(), []
    def work():
        try:
            compression.stream_tar_xz_to_sink(tmp_path, [member], Sink(), command=("xz", "-T1", "-0", "-c"))
        except BaseException as error:
            outcome.append(error)
        finally:
            finished.set()
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    assert finished.wait(10), "XZ pipeline blocked after a stream failure"
    assert len(outcome) == 1
    assert (isinstance(outcome[0], OSError) and "sink failure" in str(outcome[0])) if failure == "sink" else (
        isinstance(outcome[0], RuntimeError) and "changed during export" in str(outcome[0]))
