import io
import itertools
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from icsot_observer.core import Config, ObjectStore, sha256
from icsot_observer.diagnostics import (
    DiagnosticLogger, diagnostic_context, emit, exception_fields, failure_category,
    safe_fields, wait_heartbeat,
)
from icsot_observer.github import GitHubAPI, Response


def events(stream):
    return [json.loads(line.removeprefix("ICSOT_DEBUG ")) for line in stream.getvalue().splitlines()]


def test_safe_projection_rejects_payload_headers_queries_and_unknown_code_values():
    marker = "sensitive_body_marker"
    clean = safe_fields({"status": marker, "stage": marker, "reason": marker, "scope": marker,
        "failure_category": marker, "response_body": marker, "headers": {"Authorization": marker},
        "url": "https://api.github.com/repos/test/repo/issues?token=" + marker,
        "asset_url": "https://github.com/test/repo/releases/download/tag/a.enc?token=" + marker,
        "index_asset_url": "https://github.com/test/repo/releases/download/tag/a.index.json",
        "remaining": 10**1000, "wait_seconds": float("nan"), "attempt": 2})
    assert marker not in json.dumps(clean)
    assert clean["scope"] == clean["stage"] == clean["status"] == clean["reason"] == "unknown"
    assert clean["failure_category"] == "collection_error"
    assert "asset_url" not in clean and "response_body" not in clean and "url" not in clean
    assert clean["attempt"] == 2 and "remaining" not in clean and "wait_seconds" not in clean
    assert clean["index_asset_url"].endswith("a.index.json")
    assert safe_fields({"asset_url": "https://[invalid"}) == {}


def test_exception_fields_never_formats_message_or_reads_locals():
    class NoMessage(RuntimeError):
        def __str__(self):
            raise AssertionError("formatting an exception is forbidden")
    sensitive_body_marker = "DO_NOT_PRINT_PRIVATE_CONTENT"
    try:
        raise NoMessage(sensitive_body_marker)
    except NoMessage as error:
        fields = exception_fields(error, source_root=Path(__file__).resolve().parents[1])
    assert fields["error_type"] == "NoMessage"
    assert fields["traceback_frames"][-1]["file"] == "tests/test_diagnostics.py"
    encoded = json.dumps(fields)
    assert sensitive_body_marker not in encoded and str(Path.home()) not in encoded
    assert set(fields["traceback_frames"][-1]) == {"file", "line", "function"}


def test_quiet_default_and_disabled_context_override_env(monkeypatch, capsys):
    monkeypatch.delenv("ICSOT_DEBUG", raising=False)
    assert emit("capture_start", stage="collection") is False
    monkeypatch.setenv("ICSOT_DEBUG", "1")
    with diagnostic_context(enabled=False):
        assert emit("capture_start", stage="collection") is False
    assert capsys.readouterr().err == ""


def test_caps_preserve_failure_counts_and_terminal_outcome():
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream, max_events=12, max_bytes=8192, repo="test/repo") as logger:
        for page in range(500):
            emit("api_pagination_page", scope="issues", page=page, count=100)
        for _ in range(20):
            emit("api_scope_failure", scope="issues", failure_category="http_error", status_code=500)
        emit("capture_end", capture_status="partial", status="incomplete")
    rows = events(stream)
    assert len(rows) <= 12 and len(stream.getvalue().encode()) <= 8192
    assert rows[-1]["event"] == "diagnostic_summary"
    assert rows[-1]["failure_categories"]["http_error"] == 20
    assert rows[-1]["events_dropped"] > 0 and rows[-1]["critical_events_dropped"] > 0
    assert rows[-1]["terminal_outcome"]["capture_status"] == "partial"
    assert logger.snapshot()["events_written"] == len(rows)


def test_small_caps_guarantee_terminal_summary_even_with_oversized_identity():
    stream = io.StringIO()
    identity = {name: "x" * 79 for name in ("capture_id", "run_id", "release_tag", "asset_name")}
    with diagnostic_context(enabled=True, stream=stream, max_events=4, max_bytes=4096, **identity):
        for _ in range(30):
            emit("api_scope_failure", failure_category="pagination_duplicate", scope="events")
        emit("capture_end", status="partial")
    rows = events(stream)
    assert rows[-1]["event"] == "diagnostic_summary"
    assert rows[-1]["terminal_outcome"]["status"] == "partial"
    assert len(rows) <= 4 and len(stream.getvalue().encode()) <= 4096


def test_concurrent_heartbeat_and_api_writes_share_one_admission_and_line_lock():
    stream = io.StringIO()
    start = threading.Barrier(9)
    with diagnostic_context(enabled=True, stream=stream, max_events=40, max_bytes=16384) as logger:
        def worker():
            start.wait()
            for page in range(100):
                logger.emit("api_pagination_page", scope="issues", page=page)
                if page % 33 == 0:
                    logger.emit("api_scope_failure", scope="issues", failure_category="http_error")
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join()
        emit("capture_end", status="partial")
    rows = events(stream)
    assert [row["sequence"] for row in rows] == list(range(1, len(rows) + 1))
    assert len(rows) <= 40 and len(stream.getvalue().encode()) <= 16384
    assert rows[-1]["event"] == "diagnostic_summary"
    assert rows[-1]["failure_categories"]["http_error"] == 32
    assert rows[-1]["terminal_outcome"]["status"] == "partial"


def test_sampling_reports_first_every25_and_dropped_sample_count():
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream):
        for page in range(1, 101):
            emit("api_request_end", sample=True, scope="issues", page=page)
    rows = events(stream)
    assert [row["page"] for row in rows if row["event"] == "api_request_end"] == [1, 25, 50, 75, 100]
    assert rows[-1]["sampled_out"] == 95


def test_workflow_commands_cannot_break_out_of_json_lines():
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream, repo="test/repo\n::error::secret"):
        emit("stage_start", stage="collection\r\n::error::secret", response_body="\n::error::secret")
    assert len(stream.getvalue().splitlines()) == 2
    assert all(line.startswith("ICSOT_DEBUG {") for line in stream.getvalue().splitlines())
    assert "::error::" not in stream.getvalue()


def test_heartbeat_thread_uses_same_sink_and_stops_after_context():
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream):
        with wait_heartbeat(interval_seconds=.005, scope="issues", rate_kind="primary", wait_seconds=1):
            time.sleep(.025)
    count = len(events(stream))
    time.sleep(.015)
    assert len(events(stream)) == count
    assert any(row["event"] == "api_rate_wait_heartbeat" for row in events(stream))


def test_heartbeat_start_failure_does_not_prevent_original_operation(monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", lambda self: (_ for _ in ()).throw(RuntimeError("private detail")))
    stream = io.StringIO()
    with diagnostic_context(enabled=True, stream=stream):
        with wait_heartbeat(scope="issues"):
            executed = True
    assert executed and "private detail" not in stream.getvalue()


def test_sink_failure_does_not_change_collection_or_original_exception():
    class Broken:
        def write(self, value):
            raise OSError("secret diagnostic sink path")
        def flush(self):
            raise OSError("secret diagnostic sink path")
    with pytest.raises(ValueError, match="original"):
        with diagnostic_context(enabled=True, stream=Broken()):
            emit("capture_start", stage="collection")
            raise ValueError("original")


ITEMS = ([{"id": 1}, {"id": 2}], [{"id": 1}, {"id": 1}], [{"unknown": 1}], [])
@pytest.mark.parametrize("old,new,pretty,cursor_changed", list(itertools.product(ITEMS, ITEMS, [False, True], [False, True])))
def test_diagnostic_pagination_projection_preserves_preexisting_boolean(old, new, pretty, cursor_changed):
    first = Response(json.dumps(old).encode(), {"headers": {"link": '<https://api.github.com/repositories/42/events?page=2>; rel="next"'}})
    fresh = Response(json.dumps(new, indent=2 if pretty else None).encode(), {"headers": {
        "link": '<https://api.github.com/repositories/42/events?page=' + ('3' if cursor_changed else '2') + '>; rel="next"'}})
    original = [GitHubAPI._item_identity(item) for item in old]
    current = [GitHubAPI._item_identity(item) for item in new]
    expected = (not cursor_changed and (sha256(first.body) == sha256(fresh.body) or (
        bool(original) and all(value is not None for value in original + current) and
        len(set(original)) == len(original) and original == current)))
    check = GitHubAPI._first_page_check(first, old, fresh, new)
    assert check["matches"] is expected


def test_explicit_env_in_actual_subprocess_preserves_stdout_and_redacts_api(tmp_path):
    marker = "sensitive_body_marker"
    code = r'''
import json,sys
from pathlib import Path
from icsot_observer.core import Config,ObjectStore
from icsot_observer.github import GitHubAPI
c=Config(root=Path(sys.argv[1]),repositories=("test/repo",),api_version="2026-03-10",user_agent="test",token_env="FAKE_TOKEN_TEST",http_timeout_seconds=5,max_response_bytes=10000,overlap_hours=48,max_pages=10)
a=GitHubAPI(c,ObjectStore(c.root),[])
class Reply:
 status=200
 headers={"X-GitHub-Request-ID":"ABCD:1234:ABCD:1234","X-RateLimit-Remaining":"100","X-RateLimit-Reset":"1234","Authorization":"Bearer sensitive_body_marker"}
 def __enter__(self): return self
 def __exit__(self,*args): pass
 def read(self,maximum): return b'[{"id":1,"payload":"sensitive_body_marker"}]'
def opened(request,timeout):
 assert request.get_header("Authorization")=="Bearer ghp_sensitive_body_marker"
 return Reply()
a.opener.open=opened
a.get(a.url("/repos/test/repo/issues",{"filter":"sensitive_body_marker"}),"issues")
print(json.dumps({"ok":True,"requests":a.requests}))
'''
    env = dict(os.environ, ICSOT_DEBUG="1", FAKE_TOKEN_TEST="ghp_" + marker,
               PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)], capture_output=True, text=True, env=env, check=True)
    assert json.loads(result.stdout) == {"ok": True, "requests": 1}
    assert marker not in result.stderr and "Bearer" not in result.stderr and "filter=" not in result.stderr
    rows = [json.loads(line.removeprefix("ICSOT_DEBUG ")) for line in result.stderr.splitlines()]
    assert rows[-1]["event"] == "diagnostic_summary"
    response = next(row for row in rows if row["event"] == "api_request_end")
    assert response["status_code"] == 200 and response["request_id"] == "ABCD:1234:ABCD:1234"
    assert response["endpoint"] == "/repos/{owner}/{repo}/issues"
    assert response["attempt"] == response["page"] == 1
    assert response["remaining"] == 100 and response["reset"] == 1234


@pytest.mark.parametrize("source,expected", [("api: HTTP500 secret", "http_error"),
    ("api: HTTP502 secret", "upstream_http_502"), ("git: remote refs changed secret", "git_ref_churn"),
    ("issues: repeated ID pagination", "pagination_duplicate")])
def test_failure_categories_return_codes_only(source, expected):
    assert failure_category(source) == expected


def test_diagnostic_hashing_cannot_introduce_unicode_identity_failure():
    items = [{"name": "\ud800"}]
    first = Response(json.dumps(items).encode(), {"headers": {}})
    fresh = Response(json.dumps(items, indent=2).encode(), {"headers": {}})
    check = GitHubAPI._first_page_check(first, items, fresh, items)
    assert check["matches"] is True and len(check["first_ids_sha256"]) == 16


@pytest.mark.parametrize("name", ["_request", "_preserve_primary_reserve", "__call__", "__init__"])
def test_safe_frame_projection_preserves_ascii_python_identifier_names(name):
    frame = {"file": "src/icsot_observer/github.py", "function": name, "line": 123}
    assert safe_fields({"traceback_frames": [frame]})["traceback_frames"] == [frame]


@pytest.mark.parametrize("name", ["ghp_secret", "_read_private_key", "__authorization__",
                                  "_request\n::error::oops", "<lambda>", "unsafe.name", "x" * 81])
def test_safe_frame_projection_rejects_credentials_nonidentifiers_and_oversize(name):
    frame = {"file": "src/icsot_observer/github.py", "function": name, "line": 123}
    assert safe_fields({"traceback_frames": [frame]})["traceback_frames"][0]["function"] == "anonymous"
    # Function-name usability does not broaden public stage/status vocabularies.
    assert safe_fields({"stage": name, "status": name}) == {"stage": "unknown", "status": "unknown"}
