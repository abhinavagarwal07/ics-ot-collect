"""Explicit collection-scope removals; original source rows remain provenance."""
from __future__ import annotations

from collections.abc import Iterable
import re

EXCLUSIONS_EFFECTIVE_DATE = "2026-10-30"
# User-authorized oversized non-healthcare removals. Do not infer other removals
# from repository size, source cohort, priority, or past collection outcomes.
EXCLUDED_REPOSITORIES = frozenset(("v8/v8", "python/cpython", "aws/aws-lc", "envoyproxy/envoy"))
# Frozen identities from docs/data/repo-size-outcomes-2026-10-26.csv. These also
# identify historical per-repository proof references after payload deletion.
EXCLUDED_REPOSITORY_IDS = frozenset((24420506, 81598961, 263967166, 65214191))
# Baseline OTS filenames carry only a subject hash. Ownership was established
# before deletion; see docs/data/removed-assets-2026-10-30.json.
# These are the four deleted baseline proof subjects, not new target removals.
EXCLUDED_BASELINE_OTS_SUBJECTS = frozenset((
    "5aec1dfedf8b562110e830ddb2a1f583f755f9229011ccf9c3b4e01b2696af61",
    "5454b7445fb10d640af7347ae2f7e2727945f85fe9977a7ae290d096ef4ff8d4",
    "c599c7080f63c40af886b5a786d2c1bc2026d61ca1ba3cda2a282e1bd80eebbf",
    "cecc52354c23a18a59e8b952ceb01862a4cfac1c458ec7df0360a1d8bd75b348",
))


def excluded_asset_reference(reference: dict) -> bool:
    tag = reference.get("release_tag", "")
    match = re.fullmatch(r"collector-(?:observations|state)-r([1-9][0-9]*)-g[0-9a-f]{32}", tag)
    if match and int(match[1]) in EXCLUDED_REPOSITORY_IDS:
        return True
    # Baseline Releases are shared. Upgrades use a subject-specific attestation
    # Release; bind its exact tag and the full subject in the filename.
    name = reference.get("name", "")
    if any((tag.startswith("corpus-baseline-") or tag == "collector-attestations-" + subject[:32])
           and name.startswith("ots-" + subject + "-") for subject in EXCLUDED_BASELINE_OTS_SUBJECTS):
        return True
    return any(name.startswith(slug.replace("/", "__") + "-") for slug in EXCLUDED_REPOSITORIES)


def collection_repositories(repositories: Iterable[str]) -> tuple[str, ...]:
    """Keep declared spelling and order while excluding only these four slugs."""
    return tuple(slug for slug in repositories if slug.lower() not in EXCLUDED_REPOSITORIES)


def require_collection_repository(slug: str) -> None:
    if slug.lower() in EXCLUDED_REPOSITORIES:
        raise ValueError(f"Repository excluded from collection effective {EXCLUSIONS_EFFECTIVE_DATE}: {slug}")


def exclusion_metadata(repositories: Iterable[str]) -> dict:
    original = tuple(repositories)
    return {"source_cohort_count": len(original),
            "excluded_repositories": [slug for slug in original if slug.lower() in EXCLUDED_REPOSITORIES],
            "exclusions_effective_date": EXCLUSIONS_EFFECTIVE_DATE}
