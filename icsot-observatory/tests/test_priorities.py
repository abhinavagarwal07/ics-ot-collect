"""Frozen corpus priority decisions before source quota is consumed."""
import csv
import io
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer.core import Config, canonical_json, sha256
from icsot_observer.github import APIRequestDeferred
from icsot_observer.priorities import FrozenPriorities, initial_priority_rows, load_frozen_priorities
from icsot_observer.recurrence import build_plan, load_cohort, select_entry

CODE = "a" * 40
ORDER = ("medical/first", "medical/second", "industrial/first", "generic/first", "industrial/last")
TIERS = dict(zip(ORDER, ("P0", "P0", "P1", "P2", "P2")))
COHORTS = {"medical/first": "Healthcare", "medical/second": "Healthcare",
           "industrial/first": "ICS_OT_IIoT", "industrial/last": "ICS_OT_IIoT",
           "generic/first": "Cross_sector"}


def fixture(tmp_path):
    repositories = tuple(reversed(ORDER))
    cfg = Config(tmp_path / "unused", repositories, "2026-03-10", "research",
                 "NO_TEST_TOKEN", 5, 1000000, 48, 100)
    identifiers = {slug: number for number, slug in enumerate(repositories, 17)}
    policy = FrozenPriorities(ORDER, TIERS, "d" * 64)
    calls = []
    def identity(slug):
        calls.append(slug)
        return {"id": identifiers[slug], "private": False, "size": 100}
    pointers = {identifier: canonical_json({"repository_id": identifier, "slug": slug,
                                           "generation": "b" * 32}) for slug, identifier in identifiers.items()}
    return cfg, policy, calls, identity, pointers


def write_files(tmp_path, rows=None):
    source = tmp_path / "source.csv"
    with source.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("Repository_URL", "Cohort"))
        writer.writeheader()
        writer.writerows({"Repository_URL": "https://github.com/" + slug, "Cohort": cohort}
                         for slug, cohort in COHORTS.items())
    path = tmp_path / "repository-priorities.csv"
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("repository", "priority", "source_cohort"))
        writer.writeheader()
        writer.writerows(rows if rows is not None else (
            {"repository": slug, "priority": TIERS[slug], "source_cohort": COHORTS[slug]} for slug in ORDER))
    return source, path


def test_checked_in_policy_covers_every_repository_and_all_healthcare():
    root = Path(__file__).resolve().parents[2]
    source = root / "public_patch_corpus_185.csv"
    cfg, _ = load_cohort(root / "icsot-observatory/config.corpus.toml", source)
    policy = load_frozen_priorities(root / "icsot-observatory/repository-priorities.csv",
                                    cfg.repositories, source_csv=source)
    medical = {row["Repository_URL"].removeprefix("https://github.com/")
               for row in csv.DictReader(io.StringIO(source.read_text())) if row["Cohort"] == "Healthcare"}
    assert len(policy.order) == len(set(policy.order)) == 185
    assert set(policy.order) == set(cfg.repositories)
    assert all(policy.tiers[slug] == "P0" for slug in medical)
    assert [policy.tiers[slug] for slug in policy.order] == sorted(policy.tiers.values())


def test_initial_selection_is_reproducible_and_rounds_positive_halves_up(tmp_path):
    source = tmp_path / "source.csv"
    rows = [{"Repository_URL": f"https://github.com/{cohort.lower()}/r{number}", "Cohort": cohort}
            for cohort, count in (("Healthcare", 3), ("ICS_OT_IIoT", 15), ("Cross_sector", 15))
            for number in range(count)]
    def generate(items):
        with source.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("Repository_URL", "Cohort"))
            writer.writeheader()
            writer.writerows(items)
        return initial_priority_rows(source)
    first = generate(rows)
    assert first == generate(reversed(rows))
    counts = Counter((row["source_cohort"], row["priority"]) for row in first)
    assert counts[("Healthcare", "P0")] == 3
    assert counts[("ICS_OT_IIoT", "P1")] == 11
    assert counts[("Cross_sector", "P1")] == 2


def test_loader_preserves_explicit_order_edits_without_reselecting(tmp_path):
    cfg, _, _, _, _ = fixture(tmp_path)
    source, path = write_files(tmp_path)
    first = load_frozen_priorities(path, cfg.repositories, source_csv=source)
    rows = list(csv.DictReader(io.StringIO(path.read_text())))
    rows[0], rows[1] = rows[1], rows[0]
    write_files(tmp_path, rows)
    changed = load_frozen_priorities(path, cfg.repositories, source_csv=source)
    assert changed.order[:2] == tuple(reversed(first.order[:2]))
    assert changed.tiers == first.tiers and changed.sha256 != first.sha256


@pytest.mark.parametrize("mutation", ["duplicate_alias", "missing", "unknown", "bad_tier", "medical_p2", "tier_order", "wrong_cohort"])
def test_invalid_priority_membership_fails_closed(tmp_path, mutation):
    cfg, _, _, _, _ = fixture(tmp_path)
    source, path = write_files(tmp_path)
    rows = list(csv.DictReader(io.StringIO(path.read_text())))
    if mutation == "duplicate_alias":
        rows[1]["repository"] = rows[0]["repository"].upper()
    elif mutation == "missing":
        rows.pop()
    elif mutation == "unknown":
        rows[-1]["repository"] = "other/repository"
    elif mutation == "bad_tier":
        rows[-1]["priority"] = "P3"
    elif mutation == "medical_p2":
        rows[0]["priority"] = "P2"
    elif mutation == "tier_order":
        rows[0], rows[-1] = rows[-1], rows[0]
    else:
        rows[0]["source_cohort"] = "Cross_sector"
    write_files(tmp_path, rows)
    with pytest.raises(ValueError):
        load_frozen_priorities(path, cfg.repositories, source_csv=source)


def test_tier_planning_consumes_source_only_in_frozen_order_and_keeps_other_rows_explicit(tmp_path):
    cfg, policy, calls, identity, pointers = fixture(tmp_path)
    result = build_plan(cfg, sources={}, code_sha=CODE, identity_loader=identity,
                        pointer_loader=pointers.get, frozen_priorities=policy, priority_tier="P0", now=100000)
    assert calls == list(ORDER[:2])
    assert result["planning_order"] == calls
    assert [row["slug"] for row in result["matrix"]["include"]] == calls
    assert tuple(row["slug"] for row in result["repositories"]) == cfg.repositories
    for row in result["repositories"]:
        assert row["priority"] == TIERS[row["slug"]]
        if row["priority"] != "P0":
            assert row["repository_id"] is None and row["plan_status"] == "not_selected_priority"
    for row in result["matrix"]["include"]:
        assert select_entry(result, row["slug"], config=cfg,
                            sources={"priority_policy_sha256": policy.sha256}, code_sha=CODE) == row


def test_frozen_identity_and_execution_order_never_rotate_between_slots(tmp_path):
    cfg, policy, calls, identity, pointers = fixture(tmp_path)
    plans = [build_plan(cfg, sources={}, code_sha=CODE, identity_loader=identity,
                        pointer_loader=pointers.get, frozen_priorities=policy, now=slot * 21600)
             for slot in (4, 5, 99)]
    assert calls == list(ORDER) * 3
    assert {item["execution_order_sha256"] for item in plans} == {plans[0]["execution_order_sha256"]}
    assert {item["execution_order_seed_sha256"] for item in plans} == {plans[0]["execution_order_seed_sha256"]}
    assert all([row["slug"] for row in item["matrix"]["include"]] == list(ORDER) for item in plans)


def test_cold_selection_is_frozen_and_remaining_budget_is_conservative(tmp_path):
    cfg, policy, calls, identity, _ = fixture(tmp_path)
    plans = [build_plan(cfg, sources={}, code_sha=CODE, identity_loader=identity,
                        pointer_loader=lambda _: None, frozen_priorities=policy,
                        priority_tier="P0", cold_bootstraps=3, now=slot * 21600) for slot in (4, 5)]
    assert all([row["slug"] for row in item["matrix"]["include"]] == list(ORDER[:2]) for item in plans)
    assert all(item["cold_bootstraps_remaining"] == 1 for item in plans)
    assert all(sum(row["allow_bootstrap"] for row in item["repositories"]) == 2 for item in plans)


def test_shared_throttle_retains_p0_priority_and_defers_lower_tiers_explicitly(tmp_path):
    cfg, policy, calls, _, _ = fixture(tmp_path)
    def blocked(slug):
        calls.append(slug)
        error = APIRequestDeferred(200000, "shared throttle")
        error.diagnostic_category = "secondary_rate_limit"
        raise error
    result = build_plan(cfg, sources={}, code_sha=CODE, identity_loader=blocked,
                        pointer_loader=lambda _: None, frozen_priorities=policy, priority_tier="P0", now=100000)
    assert calls == [ORDER[0]] and result["stop_lower_tiers"] is True
    assert result["matrix"]["include"] == []
    for row in result["repositories"]:
        assert row["priority"] == TIERS[row["slug"]]
        if row["priority"] != "P0":
            assert row["plan_status"] == "deferred_lower_priority_shared_rate"


def test_later_tier_uses_frozen_cycle_slot_but_real_plan_time(tmp_path):
    cfg, policy, _, identity, pointers = fixture(tmp_path)
    result = build_plan(cfg, sources={}, code_sha=CODE, identity_loader=identity, pointer_loader=pointers.get,
                        frozen_priorities=policy, priority_tier="P1", slot=4, now=9 * 21600)
    assert result["slot"] == 4 and result["repositories"][0]["observation_key"] == "six-hour-slot-4"
    assert result["planned_at"].startswith("1970-01-03T06:00:00")


def test_destination_deferral_stops_identity_planning_and_lower_tiers(tmp_path):
    from icsot_observer.github_state import StateDeferredError
    cfg, policy, calls, identity, _ = fixture(tmp_path)
    def blocked(_):
        raise StateDeferredError("destination reserve", retry_not_before=200000)
    result = build_plan(cfg, sources={}, code_sha=CODE, identity_loader=identity,
                        pointer_loader=blocked, frozen_priorities=policy, priority_tier="P0", now=100000)
    assert calls == [ORDER[0]] and result["stop_lower_tiers"] is True
    assert result["matrix"]["include"] == []
    rows = {row["slug"]: row for row in result["repositories"]}
    assert rows[ORDER[0]]["retry_not_before"] == 200000
    assert rows[ORDER[1]]["plan_status"] == "paused_destination"
    assert all(rows[slug]["plan_status"] == "deferred_lower_priority_shared_rate" for slug in ORDER[2:])


def test_changed_priority_file_rejects_an_old_plan_before_capture(tmp_path):
    cfg, policy, _, identity, pointers = fixture(tmp_path)
    result = build_plan(cfg, sources={}, code_sha=CODE, identity_loader=identity, pointer_loader=pointers.get,
                        frozen_priorities=policy, priority_tier="P0", now=100000)
    with pytest.raises(ValueError, match="changed after planning"):
        select_entry(result, ORDER[0], config=cfg, sources={"priority_policy_sha256": "e" * 64}, code_sha=CODE)


def test_tier_cli_emits_remaining_budget_and_skips_other_tier_identity_calls(tmp_path, monkeypatch):
    from icsot_observer import legacy_bootstrap, recurrence

    cfg, _, calls, identity, _ = fixture(tmp_path)
    source, priorities_path = write_files(tmp_path)
    destination = SimpleNamespace(branch_head=lambda: "head", read_pointer=lambda head, repo_id: None)
    monkeypatch.setattr(recurrence.subprocess, "check_output", lambda *args, **kwargs: CODE)
    monkeypatch.setattr(recurrence, "load_cohort", lambda *args: (cfg, {"cohort_count": 5}))
    monkeypatch.setattr(recurrence, "load_history_settings", lambda *args: {})
    monkeypatch.setattr(recurrence, "load_resource_limits", lambda *args: {})
    monkeypatch.setattr(recurrence, "GhCliStateTransport", lambda *args: destination)
    monkeypatch.setattr(legacy_bootstrap, "GitHubMigrationLedger", lambda *args: SimpleNamespace(active_plan=lambda: None))
    monkeypatch.setattr(recurrence, "GitHubAPI", lambda *args, **kwargs: SimpleNamespace(
        get_json=lambda path, purpose: identity(path.removeprefix("/repos/"))))
    output, github_output = tmp_path / "plan.json", tmp_path / "github-output"
    assert recurrence.main(["plan", "--config", str(tmp_path / "config.toml"), "--csv", str(source),
        "--code-sha", CODE, "--destination-repository", "owner/collector", "--output", str(output),
        "--github-output", str(github_output), "--priority-tier", "P0", "--slot", "4",
        "--cold-bootstraps", "3"]) == 0
    values = dict(line.split("=", 1) for line in github_output.read_text().splitlines())
    result = json.loads(output.read_bytes())
    assert calls == list(ORDER[:2])
    assert values["planned_count"] == "2" and values["cold_bootstraps_remaining"] == "1"
    assert values["stop_lower_tiers"] == "false" and values["slot"] == "4"
    assert result["priority_policy_sha256"] == sha256(priorities_path.read_bytes())


def test_invalid_priority_file_is_rejected_before_any_destination_or_source_api(tmp_path, monkeypatch):
    from icsot_observer import recurrence

    cfg, _, _, _, _ = fixture(tmp_path)
    source, priorities_path = write_files(tmp_path)
    priorities_path.write_text("repository,priority,source_cohort\n")
    monkeypatch.setattr(recurrence.subprocess, "check_output", lambda *args, **kwargs: CODE)
    monkeypatch.setattr(recurrence, "load_cohort", lambda *args: (cfg, {}))
    monkeypatch.setattr(recurrence, "GhCliStateTransport", lambda *args: pytest.fail("Destination API before priority validation"))
    monkeypatch.setattr(recurrence, "GitHubAPI", lambda *args, **kwargs: pytest.fail("Source API before priority validation"))
    with pytest.raises(ValueError, match="every corpus repository"):
        recurrence.main(["plan", "--config", str(tmp_path / "config.toml"), "--csv", str(source),
            "--code-sha", CODE, "--destination-repository", "owner/collector", "--output", str(tmp_path / "plan"),
            "--priority-tier", "P0"])
