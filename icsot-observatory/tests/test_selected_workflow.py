"""Execute the manual workflow's bounded selection and outcome wrappers offline."""
import json
import re
import textwrap
from pathlib import Path

import pytest

from icsot_observer.core import Config, canonical_json
from icsot_observer import github, github_state, pipeline, recurrence

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/persistent-selected.yml"
SLUGS = ("one/repo", "two/repo", "three/repo", "four/repo", "five/repo", "six/repo")


def scripts():
    return [textwrap.dedent(code) for code in re.findall(r"python - <<'PY'\n(.*?)          PY", WORKFLOW.read_text(), re.S)]


def setup_selection(tmp_path, monkeypatch, raw, *, pointer=True):
    cfg = Config(tmp_path / "root", SLUGS, "2026-03-10", "test", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    monkeypatch.setattr(Config, "load", lambda _: cfg)
    calls = []
    class API:
        def __init__(self, config, *_args, **options):
            assert options == {"defer_on_rate": True}
            assert config.repositories == tuple(value.strip() for value in re.split(r"[,\r\n]+", raw) if value.strip())
        def get_json(self, path, purpose):
            calls.append(path)
            return {"private": False, "id": SLUGS.index(path.removeprefix("/repos/")) + 1}
    class Destination:
        def __init__(self, repository):
            assert repository == "owner/collector"
        def branch_head(self):
            return "frozen-head"
        def read_pointer(self, head, repository_id):
            assert head == "frozen-head"
            return canonical_json({"repository_id": repository_id, "slug": SLUGS[repository_id-1]}) if pointer else None
    monkeypatch.setattr(github, "GitHubAPI", API)
    monkeypatch.setattr(github_state, "GhCliStateTransport", Destination)
    monkeypatch.setenv("SELECTED_REPOSITORIES", raw)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/collector")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    return calls


@pytest.mark.parametrize("raw,expected", [(SLUGS[0], SLUGS[:1]), (", ".join(SLUGS[:5]), SLUGS[:5]),
                                         ("\n".join(SLUGS[:5]), SLUGS[:5])])
def test_selection_accepts_one_or_five_and_freezes_one_slot(tmp_path, monkeypatch, raw, expected):
    calls = setup_selection(tmp_path, monkeypatch, raw)
    exec(compile(scripts()[0], str(WORKFLOW), "exec"), {})
    output = dict(line.split("=", 1) for line in (tmp_path / "output").read_text().splitlines())
    assert json.loads(output["matrix"]) == {"include": [{"slug": slug, "repository_id": SLUGS.index(slug)+1} for slug in expected]}
    assert output["slot"].isdecimal()
    assert calls == ["/repos/" + slug for slug in expected]


@pytest.mark.parametrize("raw", ["", ",".join(SLUGS), "one/repo,one/repo", "outside/repo", "one/repo,ONE/repo"])
def test_bad_selection_fails_before_source_identity_requests(tmp_path, monkeypatch, raw):
    calls = setup_selection(tmp_path, monkeypatch, raw)
    with pytest.raises(SystemExit):
        exec(compile(scripts()[0], str(WORKFLOW), "exec"), {})
    assert calls == [] and not (tmp_path / "output").exists()


def test_missing_state_never_publishes_a_bootstrap_matrix(tmp_path, monkeypatch):
    calls = setup_selection(tmp_path, monkeypatch, SLUGS[0], pointer=False)
    with pytest.raises(SystemExit, match="no cold bootstraps"):
        exec(compile(scripts()[0], str(WORKFLOW), "exec"), {})
    assert len(calls) == 1 and not (tmp_path / "output").exists()


@pytest.mark.parametrize("outcome,expected", [("complete", 0), ("partial", 2), ("deferred", 75), ("error", 2)])
def test_capture_wrapper_disables_bootstraps_and_keeps_bounded_honest_outcome(tmp_path, monkeypatch, outcome, expected):
    cfg = Config(tmp_path / "root", SLUGS, "2026-03-10", "test", "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    monkeypatch.chdir(tmp_path)
    Path("config.corpus.toml").write_text("# synthetic configuration\n")
    monkeypatch.setattr(Config, "load", lambda _: cfg)
    monkeypatch.setattr(recurrence, "load_resource_limits", lambda *_: {SLUGS[0]: recurrence.DEFAULT_LIMITS})
    calls = []
    def capture(config, **options):
        calls.append(options)
        if outcome == "deferred":
            raise github_state.StateDeferredError("secret-not-for-report", retry_not_before=123)
        if outcome == "error":
            raise RuntimeError("secret-not-for-report")
        return {"restore": {"restored": True, "bytes": 10, "unsafe_text": "secret-not-for-report"},
                "publication": {"state_uploaded_ciphertext_bytes": 20, "unsafe_text": "secret-not-for-report"}}
    monkeypatch.setattr(pipeline, "run_github_persistent", capture)
    monkeypatch.setattr(recurrence, "public_outcome", lambda *_: {"status": outcome})
    for key, value in {"CAPTURE_SLUG": SLUGS[0], "SOURCE_REPOSITORY_ID": "1", "ICSOT_CYCLE_SLOT": "123",
        "GITHUB_REPOSITORY": "owner/collector", "GITHUB_SHA": "a"*40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_TEMP": str(tmp_path), "ICSOT_ARCHIVE_PROFILE": "grouped-xz-v2", "ICSOT_RELEASE_LAYOUT": "cycle-v1"}.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(SystemExit) as stop:
        exec(compile(scripts()[2], str(WORKFLOW), "exec"), {})
    assert stop.value.code == expected
    assert calls[0]["allow_bootstrap"] is False and calls[0]["schedule_slot"] == 123
    assert calls[0]["max_restored_state_plaintext_bytes"] == 8 * 1024**3
    report = json.loads((tmp_path / "selected-runtime-outcome.json").read_bytes())
    assert report["cold_bootstraps_allowed"] is False and report["code_sha"] == "a"*40
    assert "secret-not-for-report" not in json.dumps(report)
    assert (tmp_path / "selected-runtime-outcome.json").stat().st_size <= 1024*1024


def test_batch_keeps_shared_and_repository_locks_without_reenabling_schedules():
    text = WORKFLOW.read_text()
    assert "  group: persistent-collection\n" in text
    assert "group: persistent-selected-id-${{ matrix.repository_id }}" in text
    assert "      fail-fast: false\n      max-parallel: 5\n" in text
    assert "      ICSOT_CYCLE_SLOT: ${{ needs.resolve.outputs.slot }}" in text
    assert ' /usr/bin/time -v -o "$RUNNER_TEMP/selected-runtime-time.txt"' in text
    assert "  schedule:" not in text and "timeout-minutes: 180" in text
