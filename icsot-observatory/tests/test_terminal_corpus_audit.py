import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

from icsot_observer.core import canonical_json, sha256
from icsot_observer.corpus_audit import Cohort, validate_ready_inventory

spec = importlib.util.spec_from_file_location("terminal_audit_test", Path(__file__).parents[1] / "scripts/audit_terminal_corpus.py")
terminal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal)


def inputs():
    sources = {"config_source_sha256": "a" * 64, "csv_sha256": "b" * 64, "cohort_count": 2}
    cohort = Cohort(("example/accepted", "example/partial"), {}, sources)
    tags = ["corpus-baseline-3-1", "corpus-baseline-2-1"]
    request = {"profile": "sealed_terminal_with_declared_partials", "approved_release_tags": tags,
               "expected_accepted": 1, "expected_incomplete": 1,
               "sealed_inventory": {"sha256": "d" * 64, "bytes": 100, "release_id": 3, "asset_id": 30}}
    inventory = {**sources, "release_tag": tags[0], "parent_release_tags": tags[1:], "collector_code_sha": "c" * 40,
                 "complete": False, "status": "incomplete", "complete_repositories": 1, "incomplete_repositories": 1,
                 "repositories": [{"repository": cohort.repositories[0], "complete": True, "capture_accepted": True,
                                   "errors": [], "index_sha256": "e" * 64},
                                  {"repository": cohort.repositories[1], "complete": False, "capture_accepted": False,
                                   "errors": [], "index_sha256": "f" * 64}]}
    summary = {"accepted_count": 1, "incomplete_count": 1, "missing_count": 0,
               "run": {"status": "completed", "head_sha": "c" * 40}, "source_inventory": {"sha256": "d" * 64}}
    detailed = {"accepted_count": 1, "incomplete_count": 1, "missing_count": 0,
                "accepted_targets": [{"repository": cohort.repositories[0]}],
                "incomplete_cases": [{"repository": cohort.repositories[1]}]}
    return request, cohort, inventory, summary, detailed


def test_explicit_terminal_profile_accounts_for_partial_without_promoting_strict_gate():
    request, cohort, inventory, summary, detailed = inputs()
    coverage = terminal.validate_terminal(request, cohort, inventory, summary, detailed)
    assert coverage["accepted_count"] == 1
    assert coverage["explicit_incomplete_count"] == 1
    assert "not 185 accepted" in coverage["claim"]
    with pytest.raises(ValueError):
        validate_ready_inventory(inventory, cohort, request["approved_release_tags"][0], tuple(request["approved_release_tags"]))


@pytest.mark.parametrize("change", [
    lambda request, inventory, summary, detailed: request.update(profile="strict"),
    lambda request, inventory, summary, detailed: inventory["repositories"].pop(),
    lambda request, inventory, summary, detailed: inventory.update(complete_repositories=2),
    lambda request, inventory, summary, detailed: inventory["repositories"][1].update(complete=True),
    lambda request, inventory, summary, detailed: inventory["repositories"][0].update(source_release_tag="corpus-baseline-999-1"),
    lambda request, inventory, summary, detailed: summary.update(missing_count=1),
    lambda request, inventory, summary, detailed: summary["run"].update(status="in_progress"),
    lambda request, inventory, summary, detailed: detailed.update(incomplete_cases=[]),
])
def test_terminal_gate_rejects_unsealed_or_misaccounted_coverage(change):
    request, cohort, inventory, summary, detailed = inputs()
    change(request, inventory, summary, detailed)
    with pytest.raises(ValueError):
        terminal.validate_terminal(request, cohort, inventory, summary, detailed)


def test_pinned_input_requires_exact_bytes_and_hash(tmp_path):
    raw = canonical_json({"terminal": True})
    (tmp_path / "source.json").write_bytes(raw)
    reference = {"file": "source.json", "bytes": len(raw), "sha256": sha256(raw)}
    assert terminal.pinned_json(reference, tmp_path)[0] == {"terminal": True}
    reference["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="Pinned local metadata bytes"):
        terminal.pinned_json(reference, tmp_path)


def test_seal_requires_published_release_and_matching_server_digest():
    request, _, inventory, _, _ = inputs()
    class GitHub:
        repository = "owner/archive"
        draft = False
        digest = "sha256:" + "d" * 64
        def json(self, endpoint):
            if endpoint.endswith("/releases/3"):
                return {"id": 3, "tag_name": "corpus-baseline-3-1", "draft": self.draft,
                        "target_commitish": "c" * 40, "published_at": "2026-10-26T00:00:00Z"}
            return {"id": 30, "name": "baseline-inventory.json", "size": 100, "state": "uploaded", "digest": self.digest}
    github = GitHub()
    assert terminal.verify_seal(github, request, inventory)["inventory_sha256"] == "d" * 64
    github.draft = True
    with pytest.raises(ValueError):
        terminal.verify_seal(github, request, inventory)
    github.draft, github.digest = False, "sha256:" + "f" * 64
    with pytest.raises(ValueError):
        terminal.verify_seal(github, request, inventory)
