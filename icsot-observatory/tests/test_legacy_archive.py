import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
import os
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import legacy_archive as legacy
from icsot_observer.archive_reader import ArchiveError
from icsot_observer.encryption import encrypt_file
from icsot_observer.legacy_capsules import CapsuleError, create_capsule, read_envelope_aad
from icsot_observer.localbudget import LocalBudget


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


LIMITS = legacy.RestoreLimits(max_staging_bytes=16_384, max_restore_bytes=100_000,
    max_tar_stream_bytes=200_000, max_member_bytes=70_000, max_members=40,
    max_path_depth=10, max_metadata_bytes=8192, max_index_bytes=65_536)


@pytest.fixture(scope="module")
def generated_keys():
    return tuple(rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))


@pytest.fixture
def factory(tmp_path, generated_keys):
    owner, operational = [], []
    for name, key, paths in zip(("owner", "operational"), generated_keys, (owner, operational)):
        private, public = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo))
        paths.extend((private, public))
    serial = 0

    def build(*, change_members=None, change_index=None, compressed=None, migrated=False, whole_hash=None, whole_size=None,
              explicit_parents=True, late_parents=False):
        nonlocal serial
        serial += 1
        home = tmp_path / str(serial)
        home.mkdir()
        config, csv, response, bundle = b"[collector]\n", b"project\nsource/project\n", b' { "raw": true }\n', b"generated bundle fixture"
        manifest = {"repository_id": 123, "repository_input_slug": "source/project", "run_id": "capture-original",
            "public_config_sha256": "a" * 64, "status": "complete", "mode": "full",
            "started_at": "2026-10-01T01:02:03Z", "finished_at": "2026-10-01T01:03:04Z",
            "responses": [{"body_sha256": digest(response), "body_bytes": len(response)}],
            "api": {"profile": "original"}, "git": {"history_profile": "full_history",
            "portable_full_bundle": {"sha256": digest(bundle), "bytes": len(bundle)}}}
        manifest_raw = b" \n" + json.dumps(manifest, indent=2).encode() + b"\n"
        manifest_path = "runs/123/capture-original.manifest.json"
        members = {
            "reports/config.corpus.toml": config, "reports/public_patch_corpus_185.csv": csv,
            "reports/capture-request.json": b'{ "frozen": "original" }\n',
            "evidence/" + manifest_path: manifest_raw,
            "evidence/" + manifest_path + ".ots": b"original pending proof bytes",
            "evidence/registry/source__project.json": canonical({"input_slug": "source/project", "repository_id": 123}),
            f"evidence/objects/sha256/{digest(response)[:2]}/{digest(response)}": response,
            f"evidence/objects/sha256/{digest(bundle)[:2]}/{digest(bundle)}": bundle,
            "reports/generated-entropy.bin": os.urandom(1536),
        }
        entries = list(members.items())
        if change_members:
            entries = change_members(entries)
        if compressed is None:
            target = io.BytesIO()
            with tarfile.open(fileobj=target, mode="w", format=tarfile.PAX_FORMAT) as archive:
                parents = set()
                for name, payload in entries:
                    if explicit_parents:
                        components = name.split("/")
                        for depth in range(1, len(components)):
                            parent = "/".join(components[:depth])
                            if parent not in parents:
                                parents.add(parent)
                                info = tarfile.TarInfo(parent)
                                info.type, info.mtime = tarfile.DIRTYPE, 123
                                archive.addfile(info)
                    member = tarfile.TarInfo(name)
                    if isinstance(payload, tarfile.TarInfo):
                        archive.addfile(payload)
                    else:
                        member.size = len(payload)
                        member.pax_headers = {"mtime": "123.456"}
                        archive.addfile(member, io.BytesIO(payload))
                if late_parents:
                    info = tarfile.TarInfo("reports")
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
            compressed = lzma.compress(target.getvalue(), preset=1)
        ciphertexts, parts, aliases = {}, [], {}
        for number, offset in enumerate(range(0, len(compressed), 700), 1):
            plain = compressed[offset:offset + 700]
            name = f"original.tar.xz.part-{number:04d}"
            source, encrypted = home / name, home / (name + ".enc")
            source.write_bytes(plain)
            metadata = encrypt_file(source, encrypted, owner[1])
            cipher = {"name": encrypted.name, "sha256": metadata["ciphertext_sha256"], "bytes": metadata["ciphertext_bytes"]}
            identity = {"name": name, "sha256": digest(plain), "bytes": len(plain)}
            ciphertexts[encrypted.name] = encrypted.read_bytes()
            if migrated:
                parts.append(identity)
                aliases[name] = {"plaintext": identity, "ciphertext": cipher}
            else:
                parts.append({**cipher, "plaintext": identity, "uploaded": True})
        declared = {"path": manifest_path, "bytes": len(manifest_raw), "sha256": digest(manifest_raw),
                    **{key: manifest[key] for key in ("repository_id", "run_id", "public_config_sha256", "status", "mode", "started_at", "finished_at")}}
        archive = {"complete": True, "git_mirror_included": False, "parts": parts}
        if whole_hash is not None:
            archive["sha256"] = whole_hash if whole_hash != "actual" else digest(compressed)
        if whole_size is not None:
            archive["bytes"] = whole_size if whole_size != "actual" else len(compressed)
        index = {"repository": "source/project", "release_repository": "archive/corpus", "release_tag": "frozen-original",
                 "manifests": [declared], "config_source_sha256": digest(config), "csv_sha256": digest(csv),
                 "archive": archive, "verification": {"ok": True, "portable_git_bundles_verified": 1}}
        if change_index:
            change_index(index)
        raw = canonical(index)
        refs = []
        normalized = legacy.normalize_legacy_parts(index, aliases)
        for number, part in enumerate(normalized, 1):
            cipher = part["ciphertext"]
            binding = {"repository_id": 123, "repository": "source/project", "release_repository": "archive/corpus",
                "release_tag": "frozen-original", "release_id": 456, "asset_name": cipher["name"],
                "asset_id": 1000 + number, "part_number": number, "part_count": len(parts),
                "sealed_index_sha256": digest(raw), "ciphertext_sha256": cipher["sha256"], "ciphertext_bytes": cipher["bytes"]}
            capsule = create_capsule(read_envelope_aad(io.BytesIO(ciphertexts[cipher["name"]])), binding=binding,
                owner_private_key_path=owner[0], operational_public_key_path=operational[1])
            refs.append(legacy.LegacyPartRef(binding, capsule))
        output, stage = home / "output", home / "stage"
        output.mkdir()
        stage.mkdir()
        active, calls = [], []

        @contextlib.contextmanager
        def open_part(ref):
            assert not active
            assert not list(stage.rglob("authenticated.xz.part"))
            active.append(ref.binding["asset_id"])
            calls.append(dict(ref.binding))

            class ShortReader:
                def __init__(self, value):
                    self.stream = io.BytesIO(value)

                def read(self, size):
                    assert 0 < size <= 1024 * 1024
                    return self.stream.read(min(113, size))

            try:
                yield ShortReader(ciphertexts[ref.binding["asset_name"]])
            finally:
                active.clear()

        kwargs = {"expected_index_sha256": digest(raw), "expected_repository": "source/project",
            "expected_repository_id": 123, "expected_manifest_sha256": digest(manifest_raw),
            "output_root": output.absolute(), "staging_root": stage.absolute(), "open_part": open_part,
            "operational_private_key_path": operational[0], "limits": LIMITS, "transport_overrides": aliases}
        return {"raw": raw, "refs": refs, "kwargs": kwargs, "output": output, "stage": stage,
                "members": members, "calls": calls, "ciphertexts": ciphertexts, "compressed": compressed,
                "manifest": manifest, "aliases": aliases, "index": index}
    return build


def restore(case, **kwargs):
    return legacy.import_legacy_archive(case["raw"], case["refs"], **{**case["kwargs"], **kwargs})


@pytest.mark.parametrize("migrated", [False, True])
def test_native_multipart_and_migrated_import_preserve_exact_original_bytes(factory, migrated):
    case = factory(migrated=migrated)
    result = restore(case)
    assert len(case["refs"]) >= 3
    assert len(case["calls"]) == len(case["refs"]) == len(result.parts)
    assert result.compressed_sha256 == digest(case["compressed"])
    assert result.compressed_bytes == len(case["compressed"])
    assert result.compressed_hash_source == "derived_at_import"
    assert result.manifest == case["manifest"]
    assert result.git_validation == "caller_must_verify_bundle_and_heads"
    assert {row["path"] for row in result.files} == set(case["members"])
    for path, raw in case["members"].items():
        assert (case["output"] / path).read_bytes() == raw
        assert (case["output"] / path).stat().st_mtime == pytest.approx(123.456)
    assert len(result.cas) == 2
    assert result.restored_entries == len(list(case["output"].rglob("*")))
    assert result.allocation_guard["actual_restored_allocated_bytes"] > 0
    assert result.allocation_guard["actual_peak_staged_allocated_bytes"] < LIMITS.max_staging_bytes + 8192
    assert not list(case["stage"].iterdir())


def test_whole_identity_is_checked_only_when_original_index_has_one(factory):
    good = factory(whole_hash="actual", whole_size="actual")
    assert restore(good).compressed_hash_source == "original_index"
    bad = factory(whole_hash="0" * 64)
    with pytest.raises(ArchiveError, match="Whole original compressed"):
        restore(bad)
    assert not list(bad["output"].iterdir())
    assert not list(bad["stage"].iterdir())


@pytest.mark.parametrize("mode", ["reverse", "missing", "cipherhash", "manifest", "index", "repo", "partordinal"])
def test_frozen_identity_rejects_before_transport(factory, mode):
    case = factory()
    kwargs = {}
    if mode == "reverse":
        case["refs"].reverse()
    elif mode == "missing":
        case["refs"].pop()
    elif mode in {"cipherhash", "partordinal"}:
        key, value = ("ciphertext_sha256", "0" * 64) if mode == "cipherhash" else ("part_number", 2)
        case["refs"][0] = replace(case["refs"][0], binding={**case["refs"][0].binding, key: value})
    else:
        field = {"manifest": "expected_manifest_sha256", "index": "expected_index_sha256", "repo": "expected_repository_id"}[mode]
        kwargs[field] = 124 if mode == "repo" else "0" * 64
    with pytest.raises((ArchiveError, CapsuleError)):
        restore(case, **kwargs)
    assert not case["calls"]
    assert not list(case["output"].iterdir())


@pytest.mark.parametrize("mode", ["tag", "truncation", "trailing"])
def test_bad_later_part_invalidates_and_cleans_entire_import(factory, mode):
    case = factory()
    name = case["refs"][-1].binding["asset_name"]
    raw = case["ciphertexts"][name]
    if mode == "tag":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    elif mode == "truncation":
        raw = raw[:-10]
    else:
        raw += b"extra"
    case["ciphertexts"][name] = raw
    with pytest.raises((ArchiveError, CapsuleError)):
        restore(case)
    assert not list(case["output"].iterdir())
    assert not list(case["stage"].iterdir())


@pytest.mark.parametrize("path", ["../outside", "/absolute", "evidence/../outside", "evidence/a\\b", "evidence//a", "unrelated/extra"])
def test_rejects_unsafe_or_extra_namespaces(factory, path):
    case = factory(change_members=lambda entries: entries + [(path, b"x")])
    with pytest.raises(ArchiveError):
        restore(case)
    assert not list(case["output"].iterdir())


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_rejects_nonregular_members(factory, kind):
    member = tarfile.TarInfo("evidence/unsafe")
    member.type, member.linkname = kind, "outside"
    case = factory(change_members=lambda entries: entries + [(member.name, member)])
    with pytest.raises(ArchiveError, match="regular"):
        restore(case)
    assert not list(case["output"].iterdir())


def test_rejects_duplicate_paths(factory):
    case = factory(change_members=lambda entries: entries + [entries[0]])
    with pytest.raises(ArchiveError, match="Duplicate tar"):
        restore(case)


@pytest.mark.parametrize("mode", ["missing-cas", "bad-cas", "missing-manifest", "manifest-altered", "missing-proof", "registry-altered"])
def test_requires_source_manifest_cas_proof_and_registry_closure(factory, mode):
    def change(entries):
        if mode == "missing-cas":
            return [(p, b) for p, b in entries if not p.startswith("evidence/objects/")]
        if mode == "bad-cas":
            return [(p, b"changed" if p.startswith("evidence/objects/") else b) for p, b in entries]
        if mode == "missing-manifest":
            return [(p, b) for p, b in entries if not p.endswith(".manifest.json")]
        if mode == "manifest-altered":
            return [(p, b + b" " if p.endswith(".manifest.json") else b) for p, b in entries]
        if mode == "missing-proof":
            return [(p, b) for p, b in entries if not p.endswith(".ots")]
        return [(p, canonical({"input_slug": "source/project", "repository_id": 124}) if "/registry/" in p else b) for p, b in entries]
    case = factory(change_members=change)
    with pytest.raises(ArchiveError):
        restore(case)
    assert not list(case["output"].iterdir())


@pytest.mark.parametrize("bound", ["max_staging_bytes", "max_restore_bytes", "max_tar_stream_bytes", "max_member_bytes", "max_members", "max_path_depth"])
def test_each_size_or_count_bound_fails_closed(factory, bound):
    case = factory()
    limits = replace(LIMITS, **{bound: 1})
    with pytest.raises(ArchiveError):
        restore(case, limits=limits)
    assert not list(case["output"].iterdir())
    assert not list(case["stage"].iterdir())


@pytest.mark.parametrize("compressed", [lzma.compress(b"\0" * 1024)[:-1], lzma.compress(b"\0" * 1024) + b"trailing", lzma.compress(b"\0" * 1024) + lzma.compress(b"second")])
def test_requires_exact_xz_footer_and_single_stream(factory, compressed):
    case = factory(compressed=compressed)
    with pytest.raises(ArchiveError):
        restore(case)
    assert not list(case["output"].iterdir())


def test_decompression_bomb_is_stopped_before_restore_cap(factory):
    case = factory(change_members=lambda entries: entries + [("evidence/bomb", b"x" * 300_000)])
    with pytest.raises(ArchiveError, match="size|bound|cap"):
        restore(case)
    assert not list(case["output"].iterdir())


def test_preflight_and_shared_budget_admission_cover_single_stage_and_restore(factory, tmp_path):
    case = factory()
    preflight_kwargs = {key: case["kwargs"][key] for key in ("expected_index_sha256", "expected_repository", "expected_repository_id", "expected_manifest_sha256", "limits", "transport_overrides")}
    plan = legacy.preflight_legacy_archive(case["raw"], case["refs"], **preflight_kwargs)
    assert plan["compressed_bytes"] == len(case["compressed"])
    assert plan["max_staged_part_bytes"] == 700
    assert plan["maximum_required_disk_bytes"] > LIMITS.max_restore_bytes
    assert plan["allocation_overhead_bytes"] == (LIMITS.max_members + 8) * 8192
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=10_000_000)
    result = restore(case, budget=budget)
    assert result.restored_bytes > 0
    assert budget.snapshot().reserved_bytes == 0


def test_rejects_nonempty_and_symlink_output_without_touching_it(factory, tmp_path):
    case = factory()
    sentinel = case["output"] / "sentinel"
    sentinel.write_bytes(b"owned")
    with pytest.raises(ArchiveError, match="empty"):
        restore(case)
    assert sentinel.read_bytes() == b"owned"
    link = tmp_path / "linked-output"
    link.symlink_to(case["output"], target_is_directory=True)
    with pytest.raises(ArchiveError, match="real directories"):
        restore(case, output_root=link)


def test_migration_alias_cannot_relabel_original_plaintext(factory):
    case = factory(migrated=True)
    aliases = dict(case["aliases"])
    name = next(iter(aliases))
    aliases[name] = {**aliases[name], "plaintext": {**aliases[name]["plaintext"], "sha256": "0" * 64}}
    with pytest.raises(ArchiveError, match="exact frozen"):
        restore(case, transport_overrides=aliases)
    assert not case["calls"]


def test_wrong_source_plaintext_size_is_rejected_before_decrypt_or_stage(factory, monkeypatch):
    def alter(index):
        index["archive"]["parts"][0]["plaintext"]["bytes"] += 1
    case = factory(change_index=alter)
    def must_not_decrypt(*args, **kwargs):
        pytest.fail("Decryption must not start with a header above the frozen bound")
    monkeypatch.setattr(legacy, "decrypt_capsule_stream", must_not_decrypt)
    with pytest.raises(ArchiveError, match="Envelope compressed part"):
        restore(case)
    assert len(case["calls"]) == 1
    assert not list(case["output"].iterdir())
    assert not list(case["stage"].iterdir())


def test_invalid_tar_end_marker_is_rejected_after_authenticated_decryption(factory):
    case = factory(compressed=lzma.compress(b"\0" * 512 + b"x" * 512))
    with pytest.raises(ArchiveError, match="end marker"):
        restore(case)


def test_archive_member_bytes_cannot_replace_original_config(factory):
    case = factory(change_members=lambda entries: [(p, b"changed" if p == "reports/config.corpus.toml" else b) for p, b in entries])
    with pytest.raises(ArchiveError, match="source config/CSV"):
        restore(case)
    assert not list(case["output"].iterdir())


@pytest.mark.parametrize("late_parents", [False, True])
def test_missing_or_late_parent_directories_fail_before_implicit_creation(factory, late_parents):
    case = factory(explicit_parents=False, late_parents=late_parents)
    with pytest.raises(ArchiveError, match="parent directory must be declared"):
        restore(case)
    assert not list(case["output"].iterdir())
    assert not list(case["stage"].iterdir())


def test_actual_canonical_baseline_packager_declares_parents_before_children(factory, tmp_path):
    # Only generated bytes enter the production package_archive helper. No
    # retained archive, owner key, remote release or real payload is opened.
    spec = importlib.util.spec_from_file_location("generated_fixture_capture_baseline",
        Path(__file__).resolve().parents[1] / "scripts" / "capture_baseline.py")
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    original = factory()
    work, assets = tmp_path / "generated-work", tmp_path / "generated-assets"
    work.mkdir()
    for name, payload in original["members"].items():
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    archive = capture.package_archive(work, assets, "tiny-generated", include_mirror=False, part_bytes=700)
    # A joined stream is limited to this tiny generated test fixture; the
    # adapter never joins original ciphertext or the decompressed tar on disk.
    compressed = b"".join((assets / row["name"]).read_bytes() for row in archive["parts"])
    case = factory(compressed=compressed)
    result = restore(case)
    assert result.restored_entries == len(list(work.rglob("*")))
    for name, payload in original["members"].items():
        assert (case["output"] / name).read_bytes() == payload


def test_inode_overhead_is_bounded_once_per_member_independent_of_depth(factory):
    case = factory()
    kwargs = {key: case["kwargs"][key] for key in ("expected_index_sha256", "expected_repository", "expected_repository_id", "expected_manifest_sha256", "transport_overrides")}
    shallow = legacy.preflight_legacy_archive(case["raw"], case["refs"], limits=replace(LIMITS, max_path_depth=8), **kwargs)
    deep = legacy.preflight_legacy_archive(case["raw"], case["refs"], limits=replace(LIMITS, max_path_depth=32), **kwargs)
    assert shallow["allocation_overhead_bytes"] == deep["allocation_overhead_bytes"] == (LIMITS.max_members + 8) * 8192
    assert legacy.RestoreLimits().max_members == 200_000


def test_unknown_larger_filesystem_allocation_unit_fails_before_transport(factory, monkeypatch):
    case = factory()
    class LargerAllocation:
        f_frsize, f_bsize = 65_536, 65_536
    monkeypatch.setattr(legacy.os, "statvfs", lambda _: LargerAllocation())
    with pytest.raises(ArchiveError, match="allocation unit exceeds"):
        restore(case)
    assert not case["calls"]
    assert not list(case["output"].iterdir())
