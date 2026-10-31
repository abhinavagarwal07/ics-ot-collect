"""Approved removals at collection boundaries without rewriting source evidence."""
import csv
import importlib.util
import json
import tomllib
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer import cli, pipeline, state_compaction
from icsot_observer.core import Config, sha256
from icsot_observer.exclusions import EXCLUDED_REPOSITORIES, EXCLUDED_REPOSITORY_IDS
from icsot_observer.priorities import initial_priority_rows, load_frozen_priorities
from icsot_observer.recurrence import load_cohort

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "public_patch_corpus_185.csv"
CONFIG = ROOT / "icsot-observatory/config.corpus.toml"
PRIORITIES = ROOT / "icsot-observatory/repository-priorities.csv"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "icsot-observatory/scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_original_declarations_survive_but_active_sources_and_priorities_remove_exactly_four(tmp_path):
    original = tuple(tomllib.loads(CONFIG.read_text())["cohort"]["repositories"])
    assert len(original) == 185
    expected = tuple(slug for slug in original if slug not in EXCLUDED_REPOSITORIES)
    local_config = tmp_path / "config.toml"
    local_config.write_bytes(CONFIG.read_bytes())
    for path in (CONFIG, local_config):
        assert Config.load(path).repositories == expected
    cfg, metadata = load_cohort(CONFIG, SOURCE)
    baseline_cfg, baseline_metadata = load_script("capture_baseline").load_sources(CONFIG, SOURCE)
    assert cfg.repositories == baseline_cfg.repositories == expected and len(expected) == 181
    assert metadata == baseline_metadata
    assert metadata["cohort_count"] == 181 and metadata["source_cohort_count"] == 185
    assert set(metadata["excluded_repositories"]) == EXCLUDED_REPOSITORIES
    assert metadata["exclusions_effective_date"] == "2026-10-30"
    assert metadata["csv_sha256"] == sha256(SOURCE.read_bytes())
    original_priorities = list(csv.DictReader(PRIORITIES.open()))
    remaining = [row for row in original_priorities if row["repository"] not in EXCLUDED_REPOSITORIES]
    policy = load_frozen_priorities(PRIORITIES, expected, source_csv=SOURCE)
    assert policy.order == tuple(row["repository"] for row in remaining)
    assert policy.tiers == {row["repository"]: row["priority"] for row in remaining}
    assert Counter(policy.tiers.values()) == {"P0": 42, "P1": 44, "P2": 95}
    assert initial_priority_rows(SOURCE) == remaining
    sizes = ROOT / "icsot-observatory/docs/data/repo-size-outcomes-2026-10-26.csv"
    with sizes.open() as stream:
        assert {int(row["github_repository_id"]) for row in csv.DictReader(stream)
                if row["repository"] in EXCLUDED_REPOSITORIES} == EXCLUDED_REPOSITORY_IDS


def test_unrelated_standalone_config_needs_no_corpus_and_case_aliases_cannot_bypass(tmp_path):
    path = tmp_path / "config.toml"
    raw = ('[collector]\nroot="./evidence"\napi_version="2026-03-10"\n'
           'user_agent="test"\ntoken_env="UNUSED"\n[cohort]\nrepositories=')
    path.write_text(raw + json.dumps(["example/one", "V8/V8", "PYTHON/CPYTHON", "AWS/AWS-LC",
                                     "ENVOYPROXY/ENVOY", "example/two"]))
    assert Config.load(path).repositories == ("example/one", "example/two")
    path.write_text(raw + json.dumps(sorted(EXCLUDED_REPOSITORIES)))
    with pytest.raises(ValueError, match="after explicit exclusions"):
        Config.load(path)


@pytest.mark.parametrize("slug", sorted(EXCLUDED_REPOSITORIES))
def test_selected_cli_refuses_excluded_target_before_tools_keys_or_transport(slug, monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline.subprocess, "check_output", lambda *a, **k: pytest.fail("tool invoked"))
    args = ["github-run", "--config", str(CONFIG), "--slug", slug, "--repository-id", "123",
            "--destination-repository", "example/collector", "--code-sha", "a" * 40]
    for flag in ("state-public-key", "state-private-key", "evidence-public-key"):
        args += ["--" + flag, str(tmp_path / "missing.pem")]
    with pytest.raises(ValueError, match="excluded from collection"):
        cli.main(args)


@pytest.mark.parametrize("slug", sorted(EXCLUDED_REPOSITORIES))
def test_compaction_refuses_removed_targets_before_restoration(slug, tmp_path):
    with pytest.raises(ValueError, match="excluded from collection"):
        state_compaction.execute(repository_id=123, slug=slug.upper(), destination="example/collector",
            expected_pointer_sha256="a" * 64, code_sha="b" * 40, public_key=tmp_path / "missing.pem",
            private_key=tmp_path / "missing.pem", root=tmp_path / "must-not-exist",
            store_factory=lambda *a, **k: pytest.fail("state restoration attempted"))
    assert not (tmp_path / "must-not-exist").exists()


def test_historical_source_validation_retains_original185_rows():
    from icsot_observer.corpus_audit import load_cohort as load_historical_cohort

    declared = tuple(tomllib.loads(CONFIG.read_text())["cohort"]["repositories"])
    inventory = {"repositories": [{"repository": slug} for slug in declared], "cohort_count": 185,
                 "csv_sha256": sha256(SOURCE.read_bytes()), "config_source_sha256": sha256(CONFIG.read_bytes())}
    assert load_script("prepare_baseline_state").cohort(CONFIG, SOURCE, inventory) == declared
    historical = load_historical_cohort(CONFIG, SOURCE)
    assert historical.repositories == declared and historical.sources["cohort_count"] == 185


def test_old_full_catalog_cannot_start_operational_migration():
    from icsot_observer.legacy_bootstrap import MigrationError, build_migration_plan

    cfg, sources = load_cohort(CONFIG, SOURCE)
    catalog = {**sources, "schema_version": 1, "kind": "icsot_legacy_capsule_catalog",
               "publication_status": "published", "inventory_sha256": "a" * 64,
               "operational_recipient_spki_sha256": "b" * 64,
               "repositories": [{"slug": slug} for slug in tomllib.loads(CONFIG.read_text())["cohort"]["repositories"]]}
    with pytest.raises(MigrationError, match="every cohort entry"):
        build_migration_plan(cfg, sources=sources, catalog=catalog, catalog_sha256="c" * 64,
            code_sha="d" * 40, pointer_loader=lambda *a: pytest.fail("historical excluded state queried"))


@pytest.mark.parametrize("slug", sorted(EXCLUDED_REPOSITORIES))
def test_stale_frozen_jobs_and_direct_capture_cannot_bypass_current_exclusions(slug, monkeypatch):
    cfg = Config.load(CONFIG)
    stale = SimpleNamespace(slug=slug, capture_id="old-before-exclusions", payload={"collector_config": {
        "repositories": (slug,), "api_version": cfg.api_version, "user_agent": cfg.user_agent,
        "http_timeout_seconds": cfg.http_timeout_seconds, "max_response_bytes": cfg.max_response_bytes,
        "overlap_hours": cfg.overlap_hours, "max_pages": cfg.max_pages}})
    monkeypatch.setattr(pipeline, "ObjectStore", lambda *a: pytest.fail("excluded job touched storage"))
    with pytest.raises(ValueError, match="excluded from collection"):
        pipeline.capture_lane(cfg, stale, None)
    with pytest.raises(ValueError, match="excluded from collection"):
        pipeline.finalize_lane(cfg, stale, {}, stamp=False)
    with pytest.raises(ValueError, match="excluded from collection"):
        pipeline.collect_one(cfg, slug, "full", stamp=False)
