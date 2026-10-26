import importlib.util
import io
import json
import lzma
import plistlib
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icsot_observer import corpus_audit as audit
from icsot_observer.core import canonical_json, sha256
from icsot_observer.encryption import encrypt_file
from icsot_observer.localbudget import BudgetError, LocalBudget


def memory_github(payloads):
    class MemoryGitHub:
        repository = "owner/archive"

        def download(self, asset, target):
            target.write(payloads[asset["id"]])
    return MemoryGitHub()


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    # Generated fixture stays below 100 KiB; the real machine key is never used.
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    # Real OTS receipt semantics are independently exercised by
    # test_attestations with the pinned official library. This fixture isolates
    # archive/provenance wiring without requiring that optional dependency.
    def inspect_fixture_receipt(raw, subject):
        if raw != b"offline-fixture-receipt:" + subject.encode():
            raise ValueError("fixture subject differs")
        return {"status": "pending_bitcoin_completion", "subject_binding": {"status": "matched"}}
    monkeypatch.setattr(audit, "inspect_ots_receipt", inspect_fixture_receipt)

    def build(*, accepted=False, malformed_raw=True, missing_raw=False, incomplete=False, migrated=False,
              bad_prerequisite=False, previous=None, transfer_incomplete=False):
        bundle = (b"# v2 git bundle\n" + (b"-" + b"a" * 40 + b" old\n" if bad_prerequisite else b"") +
                  b"\nPACK\x00\x00\x00\x02\x00\x00\x00\x00")
        body = b'{"truncated":' if malformed_raw else b"[]"
        config, csv = b"fixture config\n", b"Repository_URL\nhttps://github.com/example/one\n"
        bundle_record = {"sha256": sha256(bundle), "bytes": len(bundle)}
        manifest = {"run_id": "run-a", "capture_id": "run-a", "repository_input_slug": "example/one", "repository_id": 17,
                    "mode": "full", "status": "complete" if accepted else "partial", "public_config": {},
                    "public_config_sha256": sha256(canonical_json({})), "previous_manifest_sha256": previous,
                    "failures": [] if accepted else ["api: malformed raw response"],
                    "responses": [{"body_sha256": sha256(body), "body_bytes": len(body), "status": 200,
                                   "error": None, "purpose": "issues"}],
                    "api": {"unavailable_scopes": {"pulls": {"status": "unavailable", "reason": "explicit_disabled"}}},
                    "git": {"archive_ref_prefix": "refs/archive/run-a/", "advertised_refs": [],
                            "git_object_hash_algorithm": "sha1", "portable_full_bundle": bundle_record}}
        raw_manifest = canonical_json(manifest)
        summary = {"sha256": sha256(raw_manifest), "run_id": "run-a", "repository_id": 17, "mode": "full",
                   "status": manifest["status"], "has_git": True, "portable_full_bundle": bundle_record}
        index = {"repository": "example/one", "release_tag": "corpus-baseline-123-1", "collector_code_sha": "a" * 40,
                 "complete": accepted, "capture_accepted": accepted, "errors": [], "manifests": [summary],
                 "status": "complete_for_declared_shallow_baseline" if accepted else "incomplete",
                 "config_source_sha256": sha256(config), "csv_sha256": sha256(csv), "cohort_count": 1,
                 "collector_result": {"repo": "example/one", "status": "complete", "attestation": "pending_bitcoin_completion",
                                      "proof": "run-a.manifest.json.ots", "immutable_initial_proof": "initial.ots",
                                      "manifest_sha256": summary["sha256"], "run_id": "run-a", "repository_id": 17},
                 "verification": {"ok": True, "errors": [], "manifests": 1, "portable_git_bundles_verified": 1,
                                  "git_repositories_verified": 1, "raw_observations": 1, "partial_runs": 0, "unstamped_runs": 0}}
        contents = {f"evidence/objects/sha256/{sha256(bundle)[:2]}/{sha256(bundle)}": bundle,
                    "evidence/runs/17/run-a.manifest.json": raw_manifest,
                    "reports/config.corpus.toml": config, "reports/public_patch_corpus_185.csv": csv}
        receipt = b"offline-fixture-receipt:" + summary["sha256"].encode()
        contents["evidence/runs/17/run-a.manifest.json.ots"] = receipt
        contents[f"evidence/proofs/initial/{summary['sha256']}.ots"] = receipt
        contents[f"evidence/proofs/initial/{summary['sha256']}.stamp.json"] = canonical_json(
            {"manifest_sha256": summary["sha256"], "receipt_sha256": sha256(receipt)})
        if not missing_raw:
            contents[f"evidence/objects/sha256/{sha256(body)[:2]}/{sha256(body)}"] = body
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(contents.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        compressed = lzma.compress(stream.getvalue())
        if incomplete:
            compressed = compressed[:len(compressed) // 2]
        plain = tmp_path / ("fixture-" + str(len(list(tmp_path.iterdir()))) + ".xz")
        plain.write_bytes(compressed)
        encrypted = plain.with_suffix(".enc")
        encryption = encrypt_file(plain, encrypted, public)
        cipher = {"name": encrypted.name, "sha256": encryption["ciphertext_sha256"], "bytes": encryption["ciphertext_bytes"]}
        original = {"name": plain.name, "sha256": encryption["plaintext_sha256"], "bytes": encryption["plaintext_bytes"]}
        mapping = {plain.name: {"plaintext": original, "ciphertext": cipher}} if migrated else {}
        part = {**original, "uploaded": True} if migrated else {
            **cipher, "plaintext": original, "encryption": encryption, "uploaded": True}
        index["archive"] = {"complete": not incomplete, "parts": [part]}
        if transfer_incomplete:
            index.update(complete=False, status="incomplete", errors=["Upload acknowledgement unavailable"])
            part["uploaded"] = False
        asset = {"id": 1, "name": encrypted.name, "state": "uploaded", "size": cipher["bytes"],
                 "digest": "sha256:" + cipher["sha256"]}
        capture = audit.Capture("example/one", "library", index["release_tag"],
                                {"repository": "owner/archive", "release_tag": index["release_tag"], "sha256": sha256(canonical_json(index)),
                                 "name": "one.index.json", "asset_id": 2, "bytes": len(canonical_json(index))},
                                index, {asset["name"]: asset}, mapping)
        budget.check()
        return capture, memory_github({1: encrypted.read_bytes()})

    return build, budget, private


def test_complete_byte_scan_preserves_invalid_raw_json_without_claiming_fsck(fixture):
    build, budget, private = fixture
    capture, github = build()
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "recoverable_partial"
    assert result["errors"] == []
    assert result["cas_objects"] == 2
    assert result["raw_json_statuses"] == {"preserved_invalid_json": 1}
    assert result["raw_failures_preserved"][0]["purpose"] == "issues"
    assert result["git_graph_verification"] == "not_fscked"
    assert result["bitcoin_verification"] == "not_attempted_no_trusted_Bitcoin_node"
    assert result["declared_unavailable_scopes"][0]["scope"] == "pulls"
    assert not list((budget.root / "staging").iterdir())


def test_accepted_capture_requires_complete_invariants_and_payload_agreement(fixture):
    build, budget, private = fixture
    capture, github = build(accepted=True, malformed_raw=False)
    assert capture.accepted
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "accepted_complete"
    capture.index["verification"]["raw_observations"] = 0
    assert not capture.accepted
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "integrity_or_dependency_failure"
    assert any("accepted flag" in error for error in result["errors"])


def test_scientifically_complete_payload_with_incomplete_transfer_stays_distinct(fixture):
    build, budget, private = fixture
    capture, github = build(accepted=True, malformed_raw=False, transfer_incomplete=True)
    result = audit.audit_capture(capture, github, budget, private)
    assert not capture.accepted
    assert result["classification"] == "source_declares_scientifically_complete_transport_incomplete"
    assert result["source_capture_accepted"] is True
    assert result["source_transfer_complete"] is False
    assert result["accepted_by_source_index"] is False
    assert result["errors"] == []
    assert result["index_errors"] == ["Upload acknowledgement unavailable"]


def test_partial_manifest_cannot_claim_capture_acceptance_even_when_transfer_incomplete(fixture):
    build, budget, private = fixture
    capture, github = build()
    capture.index["capture_accepted"] = True
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "integrity_or_dependency_failure"
    assert "Accepted index contains a partial/failing manifest" in result["errors"]


@pytest.mark.parametrize("denied_pass", [1, 2])
def test_main_part_admission_denial_is_retryable_not_ciphertext_corruption(fixture, monkeypatch, denied_pass):
    build, budget, private = fixture
    capture, github = build(accepted=True, malformed_raw=False)
    original, calls = budget.stage, []
    def limited_stage(*args, **kwargs):
        if kwargs.get("purpose") == "one indexed encrypted archive part":
            calls.append(1)
            if len(calls) == denied_pass:
                raise BudgetError("fixture admission denied")
        return original(*args, **kwargs)
    monkeypatch.setattr(budget, "stage", limited_stage)
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "local_admission_unavailable_audit_incomplete"
    assert result["audit_complete"] is False
    assert result["local_admission_unavailable"] is True
    assert all("Encrypted part integrity" not in error for error in result["errors"])
    monkeypatch.setattr(budget, "stage", original)
    assert audit.audit_capture(capture, github, budget, private)["classification"] == "accepted_complete"


def test_selected_git_volume_admission_denial_remains_retryable(fixture, monkeypatch):
    build, budget, private = fixture
    capture, github = build(accepted=True, malformed_raw=False)
    capture.selected = True
    def deny_volume(*args, **kwargs):
        raise BudgetError("fixture active viewer reservation")
    monkeypatch.setattr(audit, "verify_small_bundle", deny_volume)
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "local_admission_unavailable_audit_incomplete"
    assert result["audit_complete"] is False
    assert result["git_graph_verification"] == "sample_restore_unverified"


@pytest.mark.parametrize("options, expected", [({"missing_raw": True}, "CAS dependency"),
                                               ({"bad_prerequisite": True}, "requires objects"),
                                               ({"previous": "b" * 64}, "predecessor dependency")])
def test_dependency_and_full_bundle_prerequisite_failures_are_reported(fixture, options, expected):
    build, budget, private = fixture
    capture, github = build(**options)
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "integrity_or_dependency_failure"
    assert any(expected in error for error in result["errors"])


def test_declared_incomplete_prefix_still_authenticates_every_retained_part(fixture):
    build, budget, private = fixture
    capture, github = build(incomplete=True)
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "declared_missing_or_incomplete_package"
    assert result["parts"][0]["authentication"] == "authenticated"
    assert "XZ" in result["errors"][0] or "tar" in result["errors"][0].lower()


def test_missing_part_does_not_skip_authentication_of_present_ciphertext(fixture):
    build, budget, private = fixture
    capture, github = build()
    capture.index["archive"]["parts"].append({"name": "gone", "sha256": "a" * 64, "bytes": 12, "uploaded": False})
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "declared_missing_or_incomplete_package"
    assert len(result["parts"]) == 1
    assert len(result["part_gaps"]) == 1


def test_migration_alias_is_verified_against_original_and_cipher_identities(fixture):
    build, budget, private = fixture
    capture, github = build(migrated=True)
    result = audit.audit_capture(capture, github, budget, private)
    assert result["errors"] == []
    assert result["classification"] == "recoverable_partial"
    alias = next(iter(capture.migration.values()))
    alias["plaintext"]["sha256"] = "f" * 64
    result = audit.audit_capture(capture, github, budget, private)
    assert result["classification"] == "declared_missing_or_incomplete_package"
    assert "differs from original" in result["part_gaps"][0]["reason"]


def test_sample_selection_is_deterministic_and_covers_roles_formats_outcomes(fixture):
    build, _, _ = fixture
    captures = []
    for number, options in enumerate(({}, {"migrated": True}, {"accepted": True, "malformed_raw": False})):
        capture, _ = build(**options)
        capture.role = ("server", "library", "client")[number]
        capture.source_index = {**capture.source_index, "asset_id": number}
        captures.append(capture)
    selected = audit.select_spotchecks(captures, maximum=3)
    assert selected == audit.select_spotchecks(list(reversed(captures)), maximum=3)
    assert len(selected) == 3
    assert all(capture.selected for capture in captures)
    captures[0].index["manifests"][0]["portable_full_bundle"]["bytes"] = audit.DEFAULT_BUNDLE_LIMIT + 1
    assert captures[0].key not in audit.select_spotchecks(captures, maximum=3)


def small_cohort():
    return audit.Cohort(("example/one",), {"example/one": "library"},
                        {"config_source_sha256": "a" * 64, "csv_sha256": "b" * 64, "cohort_count": 1})


def ready_inventory():
    return {**small_cohort().sources, "release_tag": "corpus-baseline-3-1", "collector_code_sha": "c" * 40,
            "complete": True, "status": "complete_for_declared_shallow_baseline", "complete_repositories": 1,
            "incomplete_repositories": 0, "parent_release_tags": ["corpus-baseline-2-1", "corpus-baseline-1-1"],
            "repositories": [{"repository": "example/one", "complete": True, "capture_accepted": True,
                              "errors": [], "index_sha256": "d" * 64, "source_release_tag": "corpus-baseline-2-1"}]}


@pytest.mark.parametrize("change", [lambda value: value.update(complete=False),
                                    lambda value: value.update(cohort_count=185),
                                    lambda value: value["repositories"].append(value["repositories"][0]),
                                    lambda value: value["repositories"][0].update(source_release_tag="corpus-baseline-999-1"),
                                    lambda value: value.update(parent_release_tags=["corpus-baseline-1-1"])])
def test_readiness_rejects_partial_cohort_or_unapproved_lineage(change):
    value = ready_inventory()
    change(value)
    with pytest.raises(ValueError):
        audit.validate_ready_inventory(value, small_cohort(), "corpus-baseline-3-1",
                                       ("corpus-baseline-3-1", "corpus-baseline-2-1", "corpus-baseline-1-1"))


def test_readiness_needs_completed_workflow_and_published_inventory():
    class GitHub:
        repository = "owner/archive"
        completed, published = False, False

        def release(self, tag):
            return {"id": 3, "draft": not self.published}

        def json(self, endpoint):
            return {"id": 3, "run_attempt": 1, "status": "completed" if self.completed else "in_progress", "head_sha": "c" * 40}

        def assets(self, release_id):
            return {"baseline-inventory.json": {"id": 30}}

        def read_asset(self, asset):
            value = ready_inventory()
            return value, canonical_json(value)
    github = GitHub()
    tags = ("corpus-baseline-3-1", "corpus-baseline-2-1", "corpus-baseline-1-1")
    with pytest.raises(ValueError):
        audit.readiness_snapshot(github, small_cohort(), tags)
    github.completed, github.published = True, True
    assert audit.readiness_snapshot(github, small_cohort(), tags)["inventory_sha256"] == sha256(canonical_json(ready_inventory()))


def test_watcher_stability_requires_identical_digest_and_two_separated_observations():
    path = Path(__file__).parents[1] / "scripts/watch_corpus_ready.py"
    spec = importlib.util.spec_from_file_location("watch_ready_test", path)
    watcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(watcher)
    snapshot = {"repository": "owner/archive", "release_tag": "corpus-baseline-3-1", "release_id": 3,
                "run_id": 3, "inventory_sha256": "a" * 64}
    first = watcher.observe_stability({}, snapshot, now=100, stable_seconds=60)
    assert not first["stable"]
    assert not watcher.observe_stability(first, snapshot, now=159, stable_seconds=60)["stable"]
    assert watcher.observe_stability(first, snapshot, now=160, stable_seconds=60)["stable"]
    snapshot["inventory_sha256"] = "b" * 64
    changed = watcher.observe_stability(first, snapshot, now=1000, stable_seconds=60)
    assert not changed["stable"] and changed["observations"] == 1


def test_fixed_volume_admission_precedes_any_subprocess(tmp_path, monkeypatch):
    budget = LocalBudget(tmp_path / "budget", limit_bytes=1_000_000)
    monkeypatch.setattr(audit.sys, "platform", "darwin")
    monkeypatch.setattr(audit.shutil, "which", lambda name: "/usr/bin/hdiutil")
    called = []
    with pytest.raises(BudgetError):
        with audit.FixedGitVolume(budget, size_bytes=32 * 1024 * 1024, runner=lambda *args, **kwargs: called.append(args)):
            pass
    assert called == []
    assert not list((budget.root / "staging").iterdir())


def volume_fixture(tmp_path, monkeypatch, *, detach_fails=False, wrong_owner=False):
    budget = LocalBudget(tmp_path / "budget", limit_bytes=100_000_000)
    monkeypatch.setattr(audit.sys, "platform", "darwin")
    monkeypatch.setattr(audit.shutil, "which", lambda name: "/usr/bin/hdiutil")
    monkeypatch.setattr(audit.shutil, "disk_usage", lambda path: SimpleNamespace(total=32 * 1024 * 1024))
    calls = []
    volume = None
    def runner(args, **kwargs):
        calls.append(args)
        operation = args[1]
        output = b""
        if operation == "create":
            Path(args[-1]).write_bytes(b"owned fixture image")
        elif operation == "attach":
            output = plistlib.dumps({"system-entities": [{"dev-entry": "/dev/disk99", "mount-point": str(volume.mount)}]})
        elif operation == "info":
            output = plistlib.dumps({"images": [{"image-path": str(volume.image) if not wrong_owner else "/someone/else.dmg",
                                                  "system-entities": [{"dev-entry": "/dev/disk99"}]}]})
        return subprocess.CompletedProcess(args, 1 if operation == "detach" and detach_fails else 0, output)
    volume = audit.FixedGitVolume(budget, size_bytes=32 * 1024 * 1024, runner=runner)
    return volume, budget, calls


def test_fixed_volume_finally_detaches_and_removes_only_owned_image(tmp_path, monkeypatch):
    volume, budget, calls = volume_fixture(tmp_path, monkeypatch)
    sentinel = tmp_path / "source-evidence"
    sentinel.write_bytes(b"never delete")
    with pytest.raises(RuntimeError, match="fixture body failure"):
        with volume as mount:
            assert mount == volume.mount
            raise RuntimeError("fixture body failure")
    assert any(call[1:] == ["detach", "/dev/disk99"] for call in calls)
    assert not volume.directory.exists()
    assert sentinel.read_bytes() == b"never delete"
    assert budget.snapshot().reserved_bytes == 0


def test_fixed_blank_image_uses_create_type_not_source_image_format(tmp_path, monkeypatch):
    volume, _, calls = volume_fixture(tmp_path, monkeypatch)
    with volume:
        pass
    create = next(call for call in calls if call[1] == "create")
    assert "-format" not in create
    assert create[create.index("-type") + 1] == "UDIF"
    assert "-size" not in create
    assert create[create.index("-sectors") + 1] == str((32 * 1024 * 1024) // 512)
    assert create[create.index("-layout") + 1] == "NONE"


def test_fixed_volume_rejects_a_fractional_sector_before_admission(tmp_path):
    budget = LocalBudget(tmp_path / "budget", limit_bytes=100_000_000)
    with pytest.raises(ValueError, match="whole 512-byte sectors"):
        audit.FixedGitVolume(budget, size_bytes=32 * 1024 * 1024 + 1)
    assert budget.snapshot().reserved_bytes == 0


def test_detach_failure_preserves_owned_image_and_reservation(tmp_path, monkeypatch):
    volume, budget, calls = volume_fixture(tmp_path, monkeypatch, detach_fails=True)
    with pytest.raises(RuntimeError, match="Fixed-volume operation failed"):
        with volume:
            pass
    assert volume.image.exists()
    assert volume.reservation is not None
    assert budget.snapshot().reserved_bytes > 0
    # Test fixture only: retry a successful detach, then release our files.
    original = volume.runner
    volume.runner = lambda args, **kwargs: (subprocess.CompletedProcess(args, 0, b"") if args[1] == "detach" else original(args, **kwargs))
    volume.close()


def test_volume_identity_failure_never_detaches_unrelated_device(tmp_path, monkeypatch):
    volume, _, calls = volume_fixture(tmp_path, monkeypatch, wrong_owner=True)
    with pytest.raises(RuntimeError, match="attachment ownership"):
        with volume:
            pass
    assert not any(call[1] == "detach" for call in calls)
    assert volume.image.exists()
    # This is a mock that never mounted a device; clear the mock attempt.
    volume.attach_attempted = volume.attach_succeeded = False
    volume.close()


def test_human_report_explicitly_limits_fsck_and_timestamp_claims():
    report = {"inventory_sha256": "a" * 64, "expected_repositories": 185, "captures": [],
              "releases": [{"orphan_assets": [{"name": "unknown.enc"}]}]}
    text = audit.render_review(report)
    assert "0 deterministic small samples" in text
    assert "Other Git graphs were not fully fscked" in text
    assert "no trusted Bitcoin node" in text
    assert "Orphan assets inventoried without blind payload download: 1" in text


def test_get_silent_child_has_real_deadline(monkeypatch):
    original, children = subprocess.Popen, []
    def silent_child(args, **kwargs):
        child = original([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(audit.subprocess, "Popen", silent_child)
    started = time.monotonic()
    with pytest.raises(audit.ReadOnlyTransferError, match="time bound"):
        audit.GitHubReadOnly("owner/archive")._get("fixture", io.BytesIO(), maximum=100, timeout=0.1)
    assert time.monotonic() - started < 2
    assert children[0].poll() is not None


@pytest.mark.parametrize("script, options, reason", [
    ("import time; time.sleep(10)", {"timeout": 0.1}, "time bound"),
    ("import sys; sys.stdout.write('x'*100000); sys.stdout.flush()", {"max_output_bytes": 1024}, "output bound"),
    ("import time; time.sleep(10)", {"timeout": 0.1, "input_text": "x" * 32768}, "time bound"),
])
def test_bounded_git_deadline_output_and_blocked_stdin(tmp_path, script, options, reason):
    budget = LocalBudget(tmp_path / "budget", roots=[tmp_path], limit_bytes=2_000_000)
    mount = tmp_path / "mock-volume"
    mount.mkdir()
    runner = audit.BoundedGit(mount, budget)
    # Exercise pipe bounds with a controlled process; this fixture never runs
    # a Git restore or mounts a real filesystem.
    runner.prefix = [sys.executable, "-c", script]
    with pytest.raises(RuntimeError, match=reason):
        runner.run([], **options)


def test_malformed_attach_reply_resolves_only_exact_owned_image_before_cleanup(tmp_path, monkeypatch):
    volume, _, calls = volume_fixture(tmp_path, monkeypatch)
    original = volume.runner
    def malformed(args, **kwargs):
        if args[1] == "attach":
            return subprocess.CompletedProcess(args, 0, b"malformed plist after mount")
        if args[1] == "info":
            output = plistlib.dumps({"images": [{"image-path": str(volume.image), "system-entities": [
                {"dev-entry": "/dev/disk99", "mount-point": str(volume.mount)}]}]})
            return subprocess.CompletedProcess(args, 0, output)
        return original(args, **kwargs)
    volume.runner = malformed
    with pytest.raises(plistlib.InvalidFileException):
        with volume:
            pass
    assert any(call[1:] == ["detach", "/dev/disk99"] for call in calls)
    assert not volume.directory.exists()


def test_attach_nonzero_after_mount_detaches_only_exact_owned_image(tmp_path, monkeypatch):
    volume, _, calls = volume_fixture(tmp_path, monkeypatch)
    original = volume.runner
    def partial_attach(args, **kwargs):
        if args[1] == "attach":
            return subprocess.CompletedProcess(args, 1, b"")
        if args[1] == "info":
            return subprocess.CompletedProcess(args, 0, plistlib.dumps({"images": [{"image-path": str(volume.image),
                "system-entities": [{"dev-entry": "/dev/disk99", "mount-point": str(volume.mount)}]}]}))
        return original(args, **kwargs)
    volume.runner = partial_attach
    with pytest.raises(RuntimeError, match="Fixed-volume operation failed"):
        with volume:
            pass
    assert any(call[1:] == ["detach", "/dev/disk99"] for call in calls)
    assert not volume.image.exists()


def test_missing_owner_info_but_mounted_path_preserves_image_and_reservation(tmp_path, monkeypatch):
    volume, budget, calls = volume_fixture(tmp_path, monkeypatch)
    original = volume.runner
    def partial_attach(args, **kwargs):
        if args[1] == "attach":
            return subprocess.CompletedProcess(args, 1, b"")
        if args[1] == "info":
            return subprocess.CompletedProcess(args, 0, plistlib.dumps({"images": []}))
        return original(args, **kwargs)
    volume.runner = partial_attach
    original_is_mount = Path.is_mount
    monkeypatch.setattr(Path, "is_mount", lambda path: path == volume.mount)
    with pytest.raises(RuntimeError, match="remains mounted"):
        with volume:
            pass
    assert volume.image.exists() and budget.snapshot().reserved_bytes > 0
    assert not any(call[1] == "detach" for call in calls)
    monkeypatch.setattr(Path, "is_mount", original_is_mount)
    volume.attach_attempted = volume.attach_succeeded = False
    volume.close()


def test_bundle_header_accepts_standard_HEAD_pseudoref():
    raw = b"# v2 git bundle\n" + b"a" * 40 + b" HEAD\n\nPACK\x00\x00\x00\x02\x00\x00\x00\x00"
    assert audit.read_bundle_header(io.BytesIO(raw))["refs"] == {"HEAD": "a" * 40}


def legacy_fixture(tmp_path, fixture, *, name="safe/file.txt", corrupt_crc=False):
    _, budget, private = fixture
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(name, b"fixture CRC payload")
    raw = data.getvalue()
    if corrupt_crc:
        raw = raw.replace(b"fixture CRC payload", b"fixture BAD payload", 1)
    plain, cipher = tmp_path / "legacy.zip", tmp_path / "legacy.zip.enc"
    plain.write_bytes(raw)
    record = encrypt_file(plain, cipher, private.parent / "public.pem")
    entry = {"id": 9, "run_id": 10, "original_name": "old-smoke", "plaintext": {
        "name": plain.name, "sha256": record["plaintext_sha256"], "bytes": record["plaintext_bytes"]},
        "ciphertext": {"name": cipher.name, "sha256": record["ciphertext_sha256"], "bytes": record["ciphertext_bytes"]}}
    asset = {"id": 1, "name": cipher.name, "state": "uploaded", "size": record["ciphertext_bytes"],
             "digest": "sha256:" + record["ciphertext_sha256"]}
    release = {"tag": "corpus-baseline-123-1", "migration_reference": {"sha256": "a" * 64}}
    return entry, release, {cipher.name: asset}, memory_github({1: cipher.read_bytes()}), budget, private


def test_small_legacy_zip_authenticates_and_hashes_members_without_extraction(tmp_path, fixture):
    arguments = legacy_fixture(tmp_path, fixture)
    result = audit.audit_legacy_zip(*arguments)
    assert result["status"] == "legacy_ZIP_members_CRC_and_SHA256_verified"
    assert result["members"] == 1
    assert result["member_records_first_1000"][0]["sha256"] == sha256(b"fixture CRC payload")
    assert result["nested_payloads"] == "hashed_as_members_not_recursively_restored"
    assert not list((arguments[-2].root / "staging").iterdir())


@pytest.mark.parametrize("options, reason", [({"name": "../escape"}, "Unsafe"),
                                             ({"corrupt_crc": True}, "CRC")])
def test_legacy_zip_rejects_unsafe_paths_and_detects_member_crc_corruption(tmp_path, fixture, options, reason):
    arguments = legacy_fixture(tmp_path, fixture, **options)
    result = audit.audit_legacy_zip(*arguments)
    assert result["status"] == "legacy_ZIP_integrity_or_structure_failure"
    assert reason in result["error"]
    assert not (tmp_path / "escape").exists()


def test_legacy_zip_admission_fails_before_download_when_pair_exceeds_shared_budget(tmp_path, fixture):
    entry, release, assets, github, budget, private = legacy_fixture(tmp_path, fixture)
    entry["plaintext"]["bytes"] = 3_000_000
    entry["ciphertext"]["bytes"] = 3_001_000
    next(iter(assets.values()))["size"] = 3_001_000
    called = []
    github.download = lambda *args: called.append(args)
    result = audit.audit_legacy_zip(entry, release, assets, github, budget, private)
    assert result["status"] == "deferred_local_disk_admission"
    assert called == []


def test_all_present_parts_authenticated_even_if_first_cipher_is_corrupt(fixture):
    build, budget, private = fixture
    capture, github = build()
    part = capture.index["archive"]["parts"][0]
    original = next(iter(capture.assets.values()))
    payload = io.BytesIO()
    github.download(original, payload)
    good = payload.getvalue()
    corrupt = good[:-1] + bytes([good[-1] ^ 1])
    second = {**part, "name": "second.enc"}
    capture.index["archive"]["parts"].append(second)
    capture.assets["second.enc"] = {**original, "id": 2, "name": "second.enc"}
    result = audit.audit_capture(capture, memory_github({1: corrupt, 2: good}), budget, private)
    assert result["classification"] == "encrypted_part_integrity_failure"
    assert result["parts"][0]["name"] == "second.enc"
    assert len(result["parts"]) == 1


def catalog_fixture(fixture):
    build, _, _ = fixture
    accepted, _ = build(accepted=True, malformed_raw=False)
    partial, _ = build()
    indexes = {"accepted.index.json": accepted.index, "partial.index.json": partial.index}
    assets = {**accepted.assets, **partial.assets,
              "orphan.enc": {"name": "orphan.enc", "id": 999, "size": 10, "state": "uploaded"}}
    for number, (name, value) in enumerate(indexes.items(), 100):
        raw = canonical_json(value)
        assets[name] = {"id": number, "name": name, "size": len(raw), "state": "uploaded", "digest": "sha256:" + sha256(raw)}
    class GitHub:
        repository = "owner/archive"
        def release(self, tag):
            return {"id": 123, "tag_name": tag, "target_commitish": "a" * 40, "draft": False}
        def assets(self, release_id):
            return assets
        def read_asset(self, asset):
            value = indexes[asset["name"]]
            return value, canonical_json(value)
    cohort = audit.Cohort(("example/one",), {"example/one": "library"},
                         {key: accepted.index[key] for key in ("config_source_sha256", "csv_sha256", "cohort_count")})
    snapshot = {"inventory": {"collector_code_sha": "a" * 40, "repositories": [{"repository": "example/one", "complete": True,
        "capture_accepted": True, "index_sha256": sha256(canonical_json(accepted.index)),
        "manifests": accepted.index["manifests"]}]}}
    return GitHub(), cohort, snapshot, indexes


def test_lineage_catalog_accounts_for_partial_attempt_and_orphan_metadata(fixture):
    github, cohort, snapshot, _ = catalog_fixture(fixture)
    captures, releases = audit.catalog_lineage(github, cohort, snapshot, ("corpus-baseline-123-1",))
    assert len(captures) == 2
    assert sum(capture.accepted for capture in captures) == 1
    assert releases[0]["orphan_assets"] == [{"id": 999, "name": "orphan.enc", "size": 10, "digest": None, "state": "uploaded"}]


@pytest.mark.parametrize("change", [lambda value: value.update(release_repository="wrong/repository"),
                                    lambda value: value.update(collector_code_sha="b" * 40)])
def test_lineage_catalog_rejects_wrong_destination_or_source_commit_for_partial_index(fixture, change):
    github, cohort, snapshot, indexes = catalog_fixture(fixture)
    change(indexes["partial.index.json"])
    with pytest.raises(ValueError, match="identity"):
        audit.catalog_lineage(github, cohort, snapshot, ("corpus-baseline-123-1",))
