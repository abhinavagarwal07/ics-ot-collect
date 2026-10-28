"""Focused checks of the recurring workflow barriers and shared allowance."""

import os
from pathlib import Path
import re
import subprocess
import textwrap
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
OUTER = ROOT / ".github/workflows/corpus-incremental.yml"
CHILD = ROOT / ".github/workflows/corpus-priority-tier.yml"


def _jobs(path):
    # This narrow indentation parser needs no optional YAML dependency. Fail on
    # an unexpected jobs layout rather than silently ignoring a job.
    content = path.read_text().split("\njobs:\n", 1)[1]
    chunks = re.split(r"(?m)^  ([a-z][a-z0-9_]*):\s*$", content)
    assert chunks[0] == ""
    return dict(zip(chunks[1::2], chunks[2::2], strict=True))


def _scalar(job, key):
    match = re.search(rf"(?m)^    {re.escape(key)}: (.+)$", job)
    assert match, key
    return match.group(1).strip()


def _condition(job, *, cancelled=False, cycle="success", p0="", p1=""):
    expression = _scalar(job, "if")
    assert expression.startswith("${{ ") and expression.endswith(" }}")
    terms = expression[4:-3].split(" && ")
    known = {
        "!cancelled()": not cancelled,
        "needs.cycle.result == 'success'": cycle == "success",
        "needs.p0.outputs.stop_lower_tiers != 'true'": p0 != "true",
        "needs.p1.outputs.stop_lower_tiers != 'true'": p1 != "true",
    }
    # Reject unrecognized syntax so a workflow change cannot pass by accident.
    return all(known[term] for term in terms)


def test_tier_barriers_and_runtime_conditions():
    jobs = _jobs(OUTER)
    assert set(jobs) == {"cycle", "p0", "p1", "p2"}
    assert _scalar(jobs["p0"], "needs") == "cycle"
    assert _scalar(jobs["p1"], "needs") == "[cycle, p0]"
    assert _scalar(jobs["p2"], "needs") == "[cycle, p0, p1]"
    for tier in ("p0", "p1", "p2"):
        assert _scalar(jobs[tier], "uses") == "./.github/workflows/corpus-priority-tier.yml"
        assert _scalar(jobs[tier], "secrets") == "inherit"
        assert f"      priority_tier: {tier.upper()}\n" in jobs[tier]
        assert "      schedule_slot: ${{ needs.cycle.outputs.slot }}\n" in jobs[tier]
    for tier in ("p1", "p2"):
        job = jobs[tier]
        # A completed empty, skipped, or failed higher tier does not itself
        # suppress the lower one; cancellation and the throttle flag do.
        assert _condition(job)
        assert not _condition(job, cancelled=True)
        assert not _condition(job, cycle="failure")
        assert not _condition(job, p0="true")
    assert not _condition(jobs["p2"], p1="true")
    assert _condition(jobs["p2"], p0="false", p1="false")


def test_shared_budget_is_forwarded_and_missing_outputs_fail_closed():
    jobs = _jobs(OUTER)
    assert "fromJSON(needs.cycle.outputs.cold_bootstraps)" in jobs["p0"]
    for tier, previous in (("p1", "p0"), ("p2", "p1")):
        assert f"fromJSON(needs.{previous}.outputs.cold_bootstraps_remaining || '0')" in jobs[tier]
    child = CHILD.read_text()
    for output in ("cold_bootstraps_remaining", "stop_lower_tiers"):
        assert f"value: ${{{{ jobs.plan.outputs.{output} }}}}" in child
        assert f"{output}: ${{{{ steps.plan.outputs.{output} }}}}" in child


def test_child_preserves_limits_and_tier_specific_planning():
    outer = OUTER.read_text()
    child = CHILD.read_text()
    jobs = _jobs(CHILD)
    assert "  group: persistent-collection\n" in outer
    assert "  cancel-in-progress: false\n  queue: max\n" in outer
    assert "\nconcurrency:\n" not in child
    assert _scalar(jobs["observe"], "needs") == "plan"
    assert "needs.plan.outputs.planned_count != '0'" in _scalar(jobs["observe"], "if")
    assert "      max-parallel: 8\n" in jobs["observe"]
    assert "      fail-fast: false\n" in jobs["observe"]
    assert "group: persistent-selected-id-${{ matrix.repository_id }}" in jobs["observe"]
    assert '"--priority-tier", os.environ["PRIORITY_TIER"]' in jobs["plan"]
    assert '"--slot", os.environ["SCHEDULE_SLOT"]' in jobs["plan"]
    assert 'plans/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${PRIORITY_TIER}.json' in jobs["plan"]
    assert 'icsot_observer.git_metadata put' in jobs["plan"]
    assert 'plan_locator: ${{ steps.metadata.outputs.plan_locator }}' in jobs["plan"]
    assert 'icsot_observer.git_metadata get' in jobs["observe"]
    assert 'ICSOT_CYCLE_SLOT: ${{ inputs.schedule_slot }}' in child


@pytest.mark.parametrize("raw,valid", [("", True), ("0", True), ("8", True), ("9", False), ("-1", False), ("1.5", False), ("abc", False)])
def test_cycle_executes_validation_and_freezes_slot(tmp_path, raw, valid):
    job = _jobs(OUTER)["cycle"]
    script = textwrap.dedent(job.split("        run: |\n", 1)[1]).strip() + "\n"
    output = tmp_path / "github-output"
    before = int(time.time() // 21600)
    result = subprocess.run(["bash", "-e", "-c", script], env={
        "PATH": os.environ["PATH"], "COLD_BOOTSTRAPS": raw, "GITHUB_OUTPUT": str(output),
    }, capture_output=True, text=True)
    after = int(time.time() // 21600)
    assert (result.returncode == 0) is valid
    if valid:
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert int(values["slot"]) in {before, after}
        assert values["cold_bootstraps"] == str(int(raw or "0"))
    else:
        assert not output.exists()
