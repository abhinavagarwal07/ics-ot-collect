import base64
import copy
import importlib.util
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import encryption, legacy_bootstrap
from icsot_observer.core import canonical_json, sha256
from icsot_observer.legacy_bootstrap import MigrationError, migration_id, validate_catalog
from icsot_observer.legacy_capsules import inspect_capsule
from icsot_observer.localbudget import LocalBudget

spec = importlib.util.spec_from_file_location("prepare_baseline_state", Path(__file__).parents[1] / "scripts/prepare_baseline_state.py")
prep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prep)


class Response:
    def __init__(self, body, start, end, total, *, status=206, truncate=False, length=None):
        self.status = status
        self.headers = {"Content-Range": f"bytes {start}-{end}/{total}", "Content-Length": str(end - start + 1 if length is None else length)}
        self.stream = io.BytesIO(body[:-1] if truncate else body)
        self.bytes_read, self.reads, self.closed = 0, [], False

    def read(self, count):
        assert count >= 0
        self.reads.append(count)
        value = self.stream.read(count)
        self.bytes_read += len(value)
        return value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class Reader:
    def __init__(self):
        self.refs, self.raw, self.ranges, self.responses, self.failures = {}, {}, [], [], set()

    def add(self, ref, raw):
        self.refs[ref["release_repository"], ref["release_id"], ref["release_tag"], ref["name"]] = ref
        self.raw[ref["asset_id"]] = raw

    def ref(self, repository, release_id, tag, name):
        return copy.deepcopy(self.refs[repository, release_id, tag, name])

    def read_json(self, ref):
        return self.raw[ref["asset_id"]]

    def open_range(self, ref, start, end):
        self.ranges.append((ref["asset_id"], start, end))
        if ref["asset_id"] in self.failures:
            raise RuntimeError("ghp_SECRET_HTTP_BODY_DO_NOT_LOG")
        result = Response(self.raw[ref["asset_id"]][start:end + 1], start, end, ref["bytes"])
        self.responses.append(result)
        return result


class GhProcess:
    def __init__(self, raw):
        self.stdout = io.BytesIO(raw)
        self.terminated = False

    def poll(self):
        return 0 if self.terminated else None

    def terminate(self):
        self.terminated = True

    kill = terminate

    def wait(self, timeout):
        assert timeout == 2
        return 0


def test_draft_asset_uses_existing_gh_auth_and_rejects_ignored_range_before_body_read():
    body = b"unread ciphertext sentinel"
    process = GhProcess(b"HTTP/2.0 200 OK\r\nContent-Length: 1000000000\r\n\r\n" + body)
    original_close = process.stdout.close
    process.stdout.close = lambda: None
    commands = []
    def popen(command, **kwargs):
        assert kwargs == {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                          "stderr": subprocess.DEVNULL, "bufsize": 0}
        commands.append(command)
        return process
    ref = {"release_repository": "owner/data", "release_tag": "corpus-baseline-11-1", "release_id": 11,
           "asset_id": 12, "name": "part.enc", "sha256": "a" * 64, "bytes": 1000000000}
    reader = prep.GitHubReader(popen=popen)
    reader.releases["owner/data", 11] = {"draft": True}
    reader._url = lambda _: "https://github.com/owner/data/releases/download/corpus-baseline-11-1/part.enc"
    with pytest.raises(prep.RangeReadError):
        prep._range(reader, ref, 0, 12)
    assert process.stdout.read() == body and process.terminated
    assert commands == [["gh", "api", "repos/owner/data/releases/assets/12", "--hostname", "github.com", "-H", "Accept: application/octet-stream",
                         "--include", "-H", "Range: bytes=0-12"]]
    original_close()


def test_draft_json_metadata_is_bounded_and_hash_verified_without_auth_values():
    raw = b'{"original":true}\n'
    process = GhProcess(b"HTTP/2.0 200 OK\nContent-Length: " + str(len(raw)).encode() + b"\n\n" + raw)
    ref = {"release_repository": "owner/data", "release_tag": "corpus-baseline-11-1", "release_id": 11,
           "asset_id": 12, "name": "original.index.json", "sha256": sha256(raw), "bytes": len(raw)}
    reader = prep.GitHubReader(popen=lambda *a, **k: process)
    reader.releases["owner/data", 11] = {"draft": True}
    reader._url = lambda _: "https://github.com/owner/data/releases/download/corpus-baseline-11-1/original.index.json"
    assert reader.read_json(ref) == raw and process.terminated


def test_draft_asset_untagged_locator_uses_frozen_numeric_id_for_json_and_ranges():
    raw = b'{"original":true}\n'
    ref = {"release_repository": "owner/data", "release_tag": "corpus-baseline-11-1", "release_id": 11,
           "asset_id": 12, "name": "original.index.json", "sha256": sha256(raw), "bytes": len(raw)}
    def runner(command, **kwargs):
        if command[2].endswith('/assets?per_page=100'):
            value = [[{"id": 12, "name": ref["name"], "size": len(raw), "digest": "sha256:" + ref["sha256"],
                       "state": "uploaded", "browser_download_url": "https://github.com/owner/data/releases/download/untagged-123/original.index.json"}]]
        else:
            value = {"id": 11, "tag_name": ref["release_tag"], "draft": True}
        return SimpleNamespace(returncode=0, stdout=canonical_json(value))
    commands = []
    def popen(command, **kwargs):
        commands.append(command)
        is_range = "Range: bytes=0-12" in command
        headers = b"HTTP/2.0 " + (b"206 Partial Content\r\nContent-Range: bytes 0-12/18\r\nContent-Length: 13\r\n\r\n" if is_range else b"200 OK\r\nContent-Length: 18\r\n\r\n")
        return GhProcess(headers + (raw[:13] if is_range else raw))
    reader = prep.GitHubReader(runner=runner, popen=popen)
    assert len(raw) == 18
    assert reader.ref("owner/data", 11, ref["release_tag"], ref["name"]) == ref
    assert reader.read_json(ref) == raw
    assert prep._range(reader, ref, 0, 12) == raw[:13]
    assert all(command[2] == "repos/owner/data/releases/assets/12" for command in commands)


def fixture(tmp_path, monkeypatch, *, count=2, migrated=False, corrupt_identity=False, header_hash=None, repair=False, partial_indices=()):
    config, csv = tmp_path / "config.toml", tmp_path / "cohort.csv"
    slugs = tuple(f"example/repo{n}" for n in range(count))
    config.write_text('[collector]\nroot="./evidence"\napi_version="2026-03-10"\nuser_agent="test"\ntoken_env="NO_TEST_TOKEN"\n[cohort]\nrepositories=' + json.dumps(slugs) + '\n')
    csv.write_text("Repository_URL\n" + "".join(f"https://github.com/{slug}\n" for slug in slugs))
    owner = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    operational = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    owner_key, owner_pub, operational_pub = (tmp_path / name for name in ("owner-key.pem", "owner-public.pem", "operational-public.pem"))
    owner_key.write_bytes(owner.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for key, path in ((owner.public_key(), owner_pub), (operational.public_key(), operational_pub)):
        path.write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    plain = tmp_path / "compressed-part"
    plain.write_bytes(b"small generated compressed-part fixture; not a payload authentication claim")
    encrypted = tmp_path / "original.enc"
    secret = b"TEST_AES_KEY_NO_DISK_".ljust(32, b"!")
    original_random = encryption.os.urandom
    with monkeypatch.context() as scoped:
        scoped.setattr(encryption.os, "urandom", lambda size: secret if size == 32 else original_random(size))
        encryption_record = encryption.encrypt_file(plain, encrypted, owner_pub)
    cipher_raw = encrypted.read_bytes()
    reader = Reader()
    repository, release_id, tag = "owner/data", 11, "corpus-baseline-11-1"

    def ref(name, identifier, raw):
        value = {"release_repository": repository, "release_id": release_id, "release_tag": tag,
                 "asset_id": identifier, "name": name, "sha256": sha256(raw), "bytes": len(raw)}
        reader.add(value, raw)
        return value

    rows, observed, aliases = [], [], {}
    parts = []
    for n, slug in enumerate(slugs):
        repo_id = 100 + n
        compressed = {"name": f"part-{n}.tar.xz.part-0001", "sha256": sha256(plain.read_bytes()), "bytes": plain.stat().st_size}
        cipher = ref(compressed["name"] + ".enc", 1000 + n, cipher_raw)
        parts.append(cipher)
        alias = {"plaintext": compressed, "ciphertext": {key: cipher[key] for key in ("name", "sha256", "bytes")},
                 "recipient": encryption_record["public_key_fingerprint_sha256"], "source_asset_id": 500 + n}
        alias_map = [alias] if migrated else []
        if migrated:
            aliases[compressed["name"]] = alias
        archive_part = {**compressed, "uploaded": True} if migrated else {
            **{key: cipher[key] for key in ("name", "sha256", "bytes")}, "plaintext": compressed,
            "encryption": {**encryption_record, **({"header_sha256": header_hash} if header_hash else {})}, "uploaded": True}
        manifests = [] if repair and n == count - 1 else [{
            "repository_id": repo_id, "path": f"runs/{repo_id}/original-{repo_id}.manifest.json", "sha256": sha256(slug.encode()),
            "run_id": f"original-{repo_id}", "started_at": "2026-01-01T00:00:00.000001Z",
            "finished_at": "2026-01-01T00:00:01.000001Z", "status": "complete", "mode": "full",
            "portable_full_bundle": {"sha256": "b" * 64, "bytes": 20}, "has_git": True}]
        if manifests and n in partial_indices:
            manifests[0].update(status="partial", portable_full_bundle=None)
        index = {"repository": slug, "release_repository": repository, "release_tag": tag,
            "collector_code_sha": "a" * 40, "config_source_sha256": sha256(config.read_bytes()), "csv_sha256": sha256(csv.read_bytes()),
            "cohort_count": count, "status": "partial" if n in partial_indices else "complete_for_declared_shallow_baseline",
            "complete": bool(manifests) and n not in partial_indices, "capture_accepted": bool(manifests) and n not in partial_indices,
            "manifests": manifests, "collector_result": {"repository_id": 999 if corrupt_identity and n == count - 1 else repo_id},
            "archive": {"complete": True, "parts": [archive_part]},
            "verification": {"raw_observations": 1, "portable_git_bundles_verified": 0 if n in partial_indices else 1}}
        original = ref(f"r{repo_id}.index.json", 2000 + n, canonical_json(index))
        row = {"repository": slug, "repository_id": repo_id if manifests else None, "complete": index["complete"],
               "index_asset": original["name"], "index_sha256": original["sha256"], "manifests": manifests,
               "capture_status": index["status"], "archive_transport_aliases": alias_map}
        rows.append(row)
        observed += [{"id": asset["asset_id"], "name": asset["name"], "size": asset["bytes"], "digest": "sha256:" + asset["sha256"]} for asset in (original, cipher)]
    if migrated:
        transport = ref("encryption-migration-index.json", 8000, canonical_json({"schema_version": 1, "parts": aliases}))
        for row in rows:
            row.update(transport_index_asset=transport["name"], transport_index_asset_id=transport["asset_id"], transport_index_sha256=transport["sha256"])
        observed.append({"id": transport["asset_id"], "name": transport["name"], "size": transport["bytes"], "digest": "sha256:" + transport["sha256"]})
    inventory = {"release_tag": tag, "collector_code_sha": "a" * 40, "config_source_sha256": sha256(config.read_bytes()),
        "csv_sha256": sha256(csv.read_bytes()), "cohort_count": count, "repositories": rows,
        "assets_observed_before_final_inventory": observed}
    inventory_raw = canonical_json(inventory)
    inventory_ref = ref("baseline-inventory.json", 9000, inventory_raw)
    sources_raw = prep.freeze_sources(inventory_raw, sha256(inventory_raw), inventory_ref, config, csv, reader, expected_count=count)
    return SimpleNamespace(config=config, csv=csv, owner_key=owner_key, owner_pub=owner_pub, operational_pub=operational_pub,
        inventory_raw=inventory_raw, inventory_sha=sha256(inventory_raw), inventory_ref=inventory_ref, sources_raw=sources_raw,
        sources_sha=sha256(sources_raw), reader=reader, slugs=slugs, parts=parts, secret=secret, count=count)


def prepare(data, tmp_path, *, ready=None, output=None, fresh=None):
    return prep.prepare(data.inventory_raw, data.inventory_sha, data.sources_raw, data.sources_sha,
        config_path=data.config, csv_path=data.csv, reader=data.reader, owner_private_key_path=data.owner_key,
        operational_public_key_path=data.operational_pub, output_directory=output or tmp_path / "prepared",
        budget=LocalBudget(tmp_path / "budget"), capsule_release_repository="owner/data", capsule_release_tag="legacy-capsules",
        ready_states=ready, fresh_repairs=fresh, expected_count=data.count)


@pytest.mark.parametrize("migrated", [False, True])
def test_native_and_migrated_headers_prepare_bound_encrypted_capsules_without_mutating_sources(tmp_path, monkeypatch, migrated):
    data = fixture(tmp_path, monkeypatch, migrated=migrated)
    frozen = copy.deepcopy(data.reader.raw)
    result = prepare(data, tmp_path)
    assert result["failed_rows"] == 0 and result["catalog"]["publication_status"] == "unpublished"
    assert result["catalog"]["migration_id"] == migration_id(result["catalog"])
    assert data.reader.raw == frozen
    publication = json.loads(result["publication_files_path"].read_bytes())
    assert all(item["relative_path"].startswith("capsules/") and item["asset"]["name"].startswith("capsule-") for item in publication["files"])
    assert not any("receipt.json" in item["relative_path"] or ".index.json" in item["relative_path"] for item in publication["files"])
    for row, source in zip(result["catalog"]["repositories"], json.loads(data.inventory_raw)["repositories"]):
        assert row["source_manifest"]["started_at"] == source["manifests"][0]["started_at"]
        assert row["source_manifest"]["finished_at"] == source["manifests"][0]["finished_at"]
        assert row["candidate_git"] and row["candidate_api"]
        part = row["parts"][0]
        assert part["binding"]["sealed_index_sha256"] == source["index_sha256"]
        raw = next((tmp_path / "prepared/capsules").glob("*/" + part["capsule"]["name"])).read_bytes()
        context = inspect_capsule(raw)["context"]
        assert all(context[key] == value for key, value in part["binding"].items())
        assert sha256(raw) == part["capsule"]["sha256"]
        assert (part["transport_alias"] is not None) is migrated
        assert (row["migration_index"] is not None) is migrated
    for response in data.reader.responses:
        assert response.closed and response.bytes_read == int(response.headers["Content-Length"])
    assert max(end for _, _, end in data.reader.ranges) < prep.MAX_AAD_BYTES
    needles = [data.secret, data.secret.hex().encode(), base64.b64encode(data.secret), data.owner_key.read_bytes()]
    for path in (tmp_path / "prepared").rglob("*"):
        if path.is_file():
            assert all(needle not in path.read_bytes() for needle in needles)
    with pytest.raises(MigrationError):
        validate_catalog(result["catalog"], data.slugs)


def test_full185_row_order_and_already_operational_skips_are_preserved(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=185)
    ready = {100: "c" * 64, 101: "d" * 64, 102: "e" * 64}
    result = prepare(data, tmp_path, ready=ready)
    assert len(result["catalog"]["repositories"]) == 185
    assert tuple(row["slug"] for row in result["catalog"]["repositories"]) == data.slugs
    assert result["prepared_parts"] == 182 and not result["failed_rows"]
    assert not ({data.parts[n]["asset_id"] for n in range(3)} & {identifier for identifier, _, _ in data.reader.ranges})
    for row in result["catalog"]["repositories"][:3]:
        assert row["parts"] == [] and not row["candidate_api"] and not row["candidate_git"]
        assert row["reason_codes"] == ["already_operational"]
        assert row["source_manifest"] is not None


def test_fresh_repairs_require_exact_authorization_and_skip_headers_preserving_original_refs(tmp_path, monkeypatch):
    assert prep._fresh_repairs(prep.FRESH_REPAIR_INVENTORY, prep.FRESH_REPAIR_IDENTITIES) == prep.FRESH_REPAIR_IDENTITIES
    for digest, identities in (("0" * 64, prep.FRESH_REPAIR_IDENTITIES),
                               (prep.FRESH_REPAIR_INVENTORY, {"other/repo": 1}),
                               (prep.FRESH_REPAIR_INVENTORY, {})):
        with pytest.raises(prep.PreparationError):
            prep._fresh_repairs(digest, identities)
    data = fixture(tmp_path, monkeypatch, count=3, partial_indices=(0, 2))
    authorization = {data.slugs[0]: 100, data.slugs[2]: 102}
    monkeypatch.setattr(prep, "FRESH_REPAIR_INVENTORY", data.inventory_sha)
    monkeypatch.setattr(prep, "FRESH_REPAIR_IDENTITIES", authorization)
    # Both independent policy gates use this generated fixture's closed set;
    # production inventory/identity authorization remains unchanged.
    monkeypatch.setattr(legacy_bootstrap, "REPAIR_INVENTORY_SHA256", data.inventory_sha)
    monkeypatch.setattr(legacy_bootstrap, "FRESH_REPAIR_IDENTITIES", authorization)
    result = prepare(data, tmp_path, fresh=authorization)
    rows = result["catalog"]["repositories"]
    assert result["prepared_parts"] == 1
    for n in (0, 2):
        assert rows[n]["requested_strategy"] == "fresh_repair" and rows[n]["fresh_repair_repository_id"] == 100 + n
        assert rows[n]["source_manifest"] is not None and rows[n]["source_index"] is not None
        assert rows[n]["repository_id"] == 100 + n and rows[n]["candidate_kind"] == "partial_baseline"
        assert rows[n]["parts"] == [] and not rows[n]["candidate_git"] and not rows[n]["candidate_api"]
    skipped_ids = {data.parts[n]["asset_id"] for n in (0, 2)}
    assert not any(identifier in skipped_ids for identifier, _, _ in data.reader.ranges)


def test_range_ignored_is_rejected_before_any_body_read(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1)
    response = Response(b"DO_NOT_DRAIN_A_LARGE_RESPONSE", 0, 12, data.parts[0]["bytes"], status=200)
    class Opener:
        def open(self, request, **kwargs):
            assert request.get_header("Range") == "bytes=0-12"
            return response
    reader = prep.GitHubReader(opener=Opener())
    reader.releases["owner/data", 11] = {"draft": False}
    monkeypatch.setattr(reader, "_url", lambda ref: "https://github.com/owner/data/releases/download/tag/p.enc")
    with pytest.raises(prep.RangeReadError):
        prep.envelope_header(reader, data.parts[0])
    assert response.reads == [] and response.closed


@pytest.mark.parametrize("fault", ["oversized_length", "wrong_total", "truncated"])
def test_bad_ranges_fail_closed_without_reading_payload(tmp_path, monkeypatch, fault):
    data = fixture(tmp_path, monkeypatch, count=1)
    original = data.reader.open_range
    def bad(ref, start, end):
        response = original(ref, start, end)
        if fault == "oversized_length":
            response.headers["Content-Length"] = str(end - start + 2)
        elif fault == "wrong_total":
            response.headers["Content-Range"] = f"bytes {start}-{end}/{ref['bytes'] + 1}"
        else:
            response.stream = io.BytesIO(data.reader.raw[ref["asset_id"]][start:end])
        return response
    monkeypatch.setattr(data.reader, "open_range", bad)
    with pytest.raises(prep.RangeReadError):
        prep.envelope_header(data.reader, data.parts[0])
    if fault != "truncated":
        assert data.reader.responses[0].bytes_read == 0


def test_oversized_header_is_rejected_after_only_prefix(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1)
    ref = data.parts[0]
    original = data.reader.raw[ref["asset_id"]]
    data.reader.raw[ref["asset_id"]] = encryption._PREFIX.pack(encryption.MAGIC, encryption.VERSION, encryption.MAX_HEADER_BYTES + 1) + original[13:]
    with pytest.raises(Exception):
        prep.envelope_header(data.reader, ref)
    assert data.reader.ranges == [(ref["asset_id"], 0, 12)]


def test_all_source_identities_are_checked_before_first_key_operation(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=3, corrupt_identity=True)
    monkeypatch.setattr(prep, "create_capsule", lambda *a, **kw: pytest.fail("Identity mismatch reached private key operation"))
    with pytest.raises(prep.PreparationError, match="numeric repository identity"):
        prepare(data, tmp_path)
    assert data.reader.ranges == [] and not (tmp_path / "prepared").exists()


def test_known_header_hash_mismatch_never_unwraps_owner_key(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1, header_hash="0" * 64)
    monkeypatch.setattr(prep, "create_capsule", lambda *a, **kw: pytest.fail("Bad header reached owner-key unwrap"))
    result = prepare(data, tmp_path)
    assert result["failed_rows"] == 1 and result["catalog"]["repositories"][0]["parts"] == []
    assert not list((tmp_path / "prepared").glob("capsules/*/*.json"))


def test_operational_recipient_cannot_reuse_the_owner_recipient(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1)
    data.operational_pub = data.owner_pub
    monkeypatch.setattr(prep, "create_capsule", lambda *a, **kw: pytest.fail("Same-recipient request reached owner unwrap"))
    result = prepare(data, tmp_path)
    assert result["failed_rows"] == 1 and result["catalog"]["repositories"][0]["parts"] == []


def test_capsule_control_symlinks_cannot_escape_admitted_output_directory(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1)
    output, escaped = tmp_path / "prepared", tmp_path / "outside"
    output.mkdir()
    escaped.mkdir()
    (output / "capsules").symlink_to(escaped, target_is_directory=True)
    monkeypatch.setattr(prep, "create_capsule", lambda *a, **kw: pytest.fail("Unsafe directory reached owner-key operation"))
    with pytest.raises(prep.PreparationError, match="control directories"):
        prepare(data, tmp_path)
    assert data.reader.ranges == [] and list(escaped.iterdir()) == []


def test_partial_batch_resumes_create_only_capsules_and_exact_final_catalog(tmp_path, monkeypatch, capsys):
    data = fixture(tmp_path, monkeypatch, count=3)
    data.reader.failures.add(data.parts[1]["asset_id"])
    partial = prepare(data, tmp_path)
    assert partial["failed_rows"] == 1 and len(partial["catalog"]["repositories"]) == 3
    existing = {path: path.read_bytes() for path in (tmp_path / "prepared/capsules").rglob("*.json")}
    assert existing
    data.reader.failures.clear()
    result = prepare(data, tmp_path)
    assert result["failed_rows"] == 0 and result["catalog_path"] != partial["catalog_path"]
    assert all(path.read_bytes() == raw for path, raw in existing.items())
    assert partial["catalog_path"].is_file()
    repeated = prepare(data, tmp_path)
    assert repeated["catalog_path"] == result["catalog_path"] and repeated["catalog_sha256"] == result["catalog_sha256"]
    output = capsys.readouterr()
    assert "ghp_SECRET_HTTP_BODY_DO_NOT_LOG" not in output.out + output.err + partial["catalog_path"].read_text()


def test_existing_outputs_and_input_changes_are_never_overwritten(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1)
    result = prepare(data, tmp_path)
    intent = (tmp_path / "prepared/intent.json").read_bytes()
    with pytest.raises(prep.PreparationError, match="inputs changed"):
        prepare(data, tmp_path, ready={100: "f" * 64})
    assert (tmp_path / "prepared/intent.json").read_bytes() == intent
    capsule = next((tmp_path / "prepared/capsules").glob("*/capsule-*.json"))
    capsule.write_bytes(capsule.read_bytes()[:-2] + b"X\n")
    raw = capsule.read_bytes()
    corrupted = prepare(data, tmp_path)
    assert corrupted["failed_rows"] == 1 and capsule.read_bytes() == raw
    assert result["catalog_path"].is_file()


def test_multipart_failure_never_exposes_a_truncated_seed_and_resume_preserves_ordinals(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=1)
    index_ref = data.reader.ref("owner/data", 11, "corpus-baseline-11-1", "r100.index.json")
    index = json.loads(data.reader.raw[index_ref["asset_id"]])
    second = copy.deepcopy(index["archive"]["parts"][0])
    second["name"] = "second.tar.xz.part-0002.enc"
    second["plaintext"]["name"] = "second.tar.xz.part-0002"
    index["archive"]["parts"].append(second)
    raw = canonical_json(index)
    index_ref.update(sha256=sha256(raw), bytes=len(raw))
    data.reader.add(index_ref, raw)
    second_ref = {**data.parts[0], "name": second["name"], "asset_id": 1001}
    data.reader.add(second_ref, data.reader.raw[data.parts[0]["asset_id"]])
    inventory = json.loads(data.inventory_raw)
    inventory["repositories"][0]["index_sha256"] = index_ref["sha256"]
    for item in inventory["assets_observed_before_final_inventory"]:
        if item["id"] == index_ref["asset_id"]:
            item.update(size=index_ref["bytes"], digest="sha256:" + index_ref["sha256"])
    inventory["assets_observed_before_final_inventory"].append({"id": second_ref["asset_id"], "name": second_ref["name"],
        "size": second_ref["bytes"], "digest": "sha256:" + second_ref["sha256"]})
    data.inventory_raw = canonical_json(inventory)
    data.inventory_sha = sha256(data.inventory_raw)
    data.inventory_ref.update(sha256=data.inventory_sha, bytes=len(data.inventory_raw))
    data.reader.add(data.inventory_ref, data.inventory_raw)
    data.sources_raw = prep.freeze_sources(data.inventory_raw, data.inventory_sha, data.inventory_ref,
                                          data.config, data.csv, data.reader, expected_count=1)
    data.sources_sha = sha256(data.sources_raw)
    data.reader.failures.add(second_ref["asset_id"])
    partial = prepare(data, tmp_path)
    assert partial["failed_rows"] == 1 and partial["prepared_parts"] == 1
    assert partial["catalog"]["repositories"][0]["parts"] == []
    first = next((tmp_path / "prepared/capsules").glob("*/capsule-*.json"))
    first_bytes = first.read_bytes()
    data.reader.failures.clear()
    completed = prepare(data, tmp_path)
    parts = completed["catalog"]["repositories"][0]["parts"]
    assert [part["binding"]["part_number"] for part in parts] == [1, 2]
    assert [part["binding"]["part_count"] for part in parts] == [2, 2]
    assert first.read_bytes() == first_bytes


def test_crash_after_empty_directory_claim_resumes_without_replacing_completed_capsules(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, count=2)
    original_rename = prep.os.rename
    calls = 0
    def crash_on_second(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt()
        return original_rename(source, destination)
    with monkeypatch.context() as scoped:
        scoped.setattr(prep.os, "rename", crash_on_second)
        with pytest.raises(KeyboardInterrupt):
            prepare(data, tmp_path)
    capsules = list((tmp_path / "prepared/capsules").glob("*/capsule-*.json"))
    assert len(capsules) == 1
    preserved = capsules[0].read_bytes()
    assert sum(not any(path.iterdir()) for path in (tmp_path / "prepared/capsules").iterdir()) == 1
    resumed = prepare(data, tmp_path)
    assert resumed["failed_rows"] == 0 and resumed["prepared_parts"] == 2
    assert capsules[0].read_bytes() == preserved


def test_publication_binding_requires_exact_capsule_set_and_keeps_migration_id(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, migrated=True)
    result = prepare(data, tmp_path)
    refs = {}
    for n, row in enumerate(result["catalog"]["repositories"]):
        capsule = row["parts"][0]["capsule"]
        refs[capsule["name"]] = {**capsule, "release_id": 70, "asset_id": 100 + n}
    published = prep.bind_publication(result["catalog_path"].read_bytes(), result["catalog_sha256"], refs)
    catalog = json.loads(published)
    assert catalog["migration_id"] == result["catalog"]["migration_id"]
    assert validate_catalog(catalog, data.slugs) == catalog["migration_id"]
    with pytest.raises(prep.PreparationError):
        prep.bind_publication(result["catalog_path"].read_bytes(), result["catalog_sha256"], {})
    wrong = copy.deepcopy(refs)
    next(iter(wrong.values()))["sha256"] = "0" * 64
    with pytest.raises(prep.PreparationError):
        prep.bind_publication(result["catalog_path"].read_bytes(), result["catalog_sha256"], wrong)


def test_missing_original_manifest_stays_explicit_unbound_repair(tmp_path, monkeypatch):
    data = fixture(tmp_path, monkeypatch, repair=True)
    result = prepare(data, tmp_path)
    row = result["catalog"]["repositories"][-1]
    assert row["repository_id"] is None and row["source_manifest"] is None and row["parts"] == []
    assert row["candidate_kind"] == "repair_required" and row["reason_codes"] == ["source_manifest_unavailable"]
    assert row["source_index"] is not None
