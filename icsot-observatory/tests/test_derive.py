import csv

from icsot_observer.core import ObjectStore, canonical_json, write_once
from icsot_observer.derive import make_observations


def test_malformed_2xx_attempts_remain_evidence_and_report_gaps_before_later_valid_records(tmp_path):
    store = ObjectStore(tmp_path)
    bodies = [b'\xff{"id":1}', b'{"unfinished":', b'[{"id":42,"number":7,"body":"retained valid item"}]']
    digests = [store.put(body) for body in bodies]
    responses = [{"purpose": "issues", "status": 200, "body_sha256": digest,
                  "url": "https://api.github.com/repos/test/repo/issues", "request_started_at": "2026-10-26T00:00:00Z",
                  "request_completed_at": "2026-10-26T00:00:01Z"} for digest in digests]
    write_once(tmp_path / "runs/17/attempt.manifest.json", canonical_json({
        "repository_id": 17, "run_id": "attempt", "status": "complete", "mode": "full", "responses": responses}))
    destination = tmp_path / "analysis/observations.csv"
    result = make_observations(tmp_path, destination)
    assert result["records"] == 1 and result["skipped_invalid_response_count"] == 2
    assert [(entry["raw_response_sha256"], entry["reason"]) for entry in result["skipped_invalid_responses"]] == [
        (digests[0], "invalid_text_encoding"), (digests[1], "invalid_json")]
    assert result["skipped_invalid_responses"][0]["encoding"] == "utf-8"
    with destination.open() as source:
        rows = list(csv.DictReader(source))
    assert len(rows) == 1 and rows[0]["entity_id"] == "42" and rows[0]["raw_response_sha256"] == digests[2]
    assert [store.get(digest) for digest in digests] == bodies
