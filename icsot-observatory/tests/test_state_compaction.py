from pathlib import Path
from types import SimpleNamespace

from icsot_observer import state_compaction as runner
from icsot_observer.github_state import StateDeferredError


POINTER = {"repository_id": 123, "slug": "owner/repo", "index": {"ciphertext_sha256": "b" * 64}}
INDEX = {"files": [{"bytes": 4}], "parts": {str(i): {"ciphertext_bytes": 10} for i in range(20)}}


class FakeTransport:
    request_count = 7
    graphql_request_count = 2
    def __init__(self, pointer=POINTER, error=None):
        self.pointer, self.error, self.reads = pointer, error, 0
    def branch_head(self):
        self.reads += 1
        if self.error:
            raise self.error
        return "head"
    def read_pointer(self, head, repository_id):
        return runner.canonical_json(self.pointer)


class FakeStore:
    result = {"status": "complete", "pointer": {"index": {"ciphertext_sha256": "c" * 64}},
              "after_part_count": 3, "after_referenced_part_ciphertext_bytes": 35,
              "full_remote_reconstruction_verified": True, "verification_scope": "working_state_files_only", "part_savings": 17,
              "state_uploaded_ciphertext_bytes": 44,
              "predecessor_snapshot_started_at": "2026-10-27T00:00:00.000000Z",
              "predecessor_snapshot_sealed_at": "2026-10-27T00:00:01.000000Z",
              "snapshot_started_at": "2026-10-27T01:00:00.000000Z",
              "snapshot_sealed_at": "2026-10-27T01:00:01.000000Z"}
    calls = []

    def __init__(self, transport, **kwargs):
        self.transport = transport
        self.calls.append("init")

    def read(self):
        self.calls.append("read")
        return SimpleNamespace(pointer=POINTER, index=INDEX)

    def restore(self, selection):
        self.calls.append("restore")
        return {"restored": True}

    def compact(self, selection, **kwargs):
        self.calls.append(kwargs)
        return self.result


def run(tmp_path, **kwargs):
    FakeStore.calls = []
    args = dict(repository_id=123, slug="owner/repo", destination="owner/destination",
                expected_pointer_sha256=runner.digest(POINTER), expected_index_sha256="b" * 64,
                code_sha="a" * 40, public_key=Path("public"), private_key=Path("private"),
                root=tmp_path / "root", transport=FakeTransport(),
                store_factory=FakeStore)
    args.update(kwargs)
    return runner.execute(**args)


def test_complete_reports_bounds_and_verified_roundtrip(tmp_path):
    result = run(tmp_path)
    assert result["status"] == "complete" and result["publication"] == "confirmed"
    assert result["before_parts"] == 20 and result["after_parts"] == 3
    assert result["before_part_ciphertext_bytes"] == 200 and result["after_part_ciphertext_bytes"] == 35
    assert result["fresh_remote_reconstruction"] == "verified"
    assert result["verification_scope"] == "working_state_files_only"
    assert result["predecessor_snapshot_started_at"] == "2026-10-27T00:00:00.000000Z"
    assert result["snapshot_started_at"] == "2026-10-27T01:00:00.000000Z"
    assert result["baseline_evidence_bytes"] == result["new_observations"] == 0
    assert result["api_requests"] == 7 and result["graphql_requests"] == 2
    assert FakeStore.calls[-1] == dict(max_input_bytes=runner.MAX_INPUT, max_input_parts=128,
                                      max_upload_bytes=runner.MAX_UPLOAD, min_part_savings=16,
                                      max_runtime_seconds=1800, quiescent=True)
    assert not (tmp_path / "root").exists()


def test_stale_pin_stops_before_restore(tmp_path):
    result = run(tmp_path, expected_index_sha256="c" * 64)
    assert result["publication"] == "unchanged_at_check" and result["status"] == "failed"
    assert FakeStore.calls == ["init", "read"]
    assert not (tmp_path / "root").exists()


def test_no_op_reports_unchanged_and_no_remote_reconstruction(tmp_path, monkeypatch):
    monkeypatch.setattr(FakeStore, "result", {"status": "no_op", "input_parts": 2, "part_savings": 0})
    result = run(tmp_path)
    assert result["status"] == "no_op" and result["publication"] == "unchanged_at_check"
    assert result["new_pointer_sha256"] == result["old_pointer_sha256"]
    assert result["after_parts"] == 20 and result["state_uploaded_ciphertext_bytes"] == 0
    assert result["fresh_remote_reconstruction"] == "not_required_no_op"


def test_oversized_state_is_deferred_before_restore(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "MAX_RESTORED", 3)
    result = run(tmp_path)
    assert result["status"] == "deferred" and result["failure_category"] == "restored_state_limit"
    assert result["publication"] == "unchanged_at_check" and FakeStore.calls == ["init", "read"]


def test_deferred_publication_is_unknown_and_hides_exception(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise StateDeferredError("secret-like exception details", reason="compaction_runtime_limit")
    monkeypatch.setattr(FakeStore, "compact", fail)
    result = run(tmp_path)
    assert result["status"] == "deferred" and result["publication"] == "unchanged_at_check"
    assert "secret-like" not in str(result)


def test_existing_root_is_not_removed(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "keep").write_text("original")
    result = run(tmp_path)
    assert result["status"] == "failed" and (root / "keep").read_text() == "original"


def test_integrity_diagnostics_are_allowlisted_and_bounded(tmp_path, monkeypatch):
    detail = {"stage": "file_reconstruction", "subject": "state/file", "field": "sha256",
              "expected": "d" * 64, "actual": "e" * 64, "secret": "do not report"}
    def fail(*args, **kwargs):
        error = runner.github_state.StateIntegrityError(
            "unsafe exception text", stage=detail["stage"], subject=detail["subject"],
            field=detail["field"], expected=detail["expected"], actual=detail["actual"])
        error.detail["secret"] = detail["secret"]
        raise error
    monkeypatch.setattr(FakeStore, "compact", fail)
    result = run(tmp_path)
    assert result["failure_category"] == "integrity_error"
    assert result["integrity"] == {key: detail[key] for key in ("stage", "subject", "field", "expected", "actual")}
    assert "do not report" not in str(result) and "unsafe exception" not in str(result)
    assert runner.safe_integrity_detail({**detail, "subject": "x" * 257}) is None
    assert runner.safe_integrity_detail({**detail, "subject": "../private"}) is None
    assert runner.safe_integrity_detail({**detail, "actual": "short"}) is None
    assert runner.safe_integrity_detail({**detail, "stage": "unknown"}) is None
    assert runner.safe_integrity_detail({**detail, "field": "bytes", "expected": True, "actual": 1}) is None


def test_ambiguous_compare_and_swap_exact_candidate_is_confirmed(tmp_path, monkeypatch):
    candidate = {"repository_id": 123, "slug": "owner/repo", "index": {"ciphertext_sha256": "c" * 64}}
    transport = FakeTransport()
    def ambiguous(self, *args, **kwargs):
        self.compaction_candidate_pointer_sha256 = runner.digest(candidate)
        self.transport.pointer = candidate
        raise runner.StateError("ambiguous compare-and-swap")
    monkeypatch.setattr(FakeStore, "compact", ambiguous)
    result = run(tmp_path, transport=transport)
    assert result["status"] == "failed" and result["publication"] == "confirmed"
    assert result["pointer_inspection"] == "observed"
    assert result["publication_confirmation_scope"] == "pointer_digest_only"
    assert result["observed_pointer_sha256"] == runner.digest(candidate)
    assert result["observed_index_ciphertext_sha256"] == "c" * 64
    assert transport.reads == 1


def test_failure_readback_unavailable_stays_unknown(tmp_path, monkeypatch):
    transport = FakeTransport(error=runner.StateError("sensitive transport detail"))
    def fail(*args, **kwargs):
        raise runner.StateError("sensitive compaction detail")
    monkeypatch.setattr(FakeStore, "compact", fail)
    result = run(tmp_path, transport=transport)
    assert result["publication"] == "unknown" and result["pointer_inspection"] == "unavailable"
    assert result["inspection_failure_category"] == "read_failed" and transport.reads == 1
    assert "sensitive" not in str(result)


def test_failure_readback_does_not_claim_other_candidate(tmp_path, monkeypatch):
    other = {"repository_id": 123, "slug": "owner/repo", "index": {"ciphertext_sha256": "c" * 64}}
    transport = FakeTransport(pointer=other)
    def fail(*args, **kwargs):
        raise runner.StateError("some failed operation")
    monkeypatch.setattr(FakeStore, "compact", fail)
    result = run(tmp_path, transport=transport)
    assert result["publication"] == "unknown" and result["pointer_inspection"] == "observed"
    assert result["observed_pointer_sha256"] == runner.digest(other)

