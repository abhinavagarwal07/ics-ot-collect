"""Explicit frozen corpus priority membership and order, validated before API use."""
from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .core import REPO_RE
from .exclusions import EXCLUDED_REPOSITORIES

TIERS = ("P0", "P1", "P2")
PRIORITY_FIELDS = ("repository", "priority", "source_cohort")
COHORTS = frozenset(("Healthcare", "ICS_OT_IIoT", "Cross_sector"))


@dataclass(frozen=True)
class FrozenPriorities:
    order: tuple[str, ...]
    tiers: dict[str, str]
    sha256: str


def _source_rows(path: Path) -> list[dict]:
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig"))))
    seen = set()
    for row in rows:
        url = urlsplit(row.get("Repository_URL", ""))
        slug = url.path.strip("/")
        if (url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment or
                not REPO_RE.fullmatch(slug) or slug.lower() in seen or row.get("Cohort") not in COHORTS):
            raise ValueError("Invalid or duplicate priority source repository/cohort")
        seen.add(slug.lower())
        row["repository"] = slug
    return rows


def load_frozen_priorities(path: Path, repositories: tuple[str, ...], *, source_csv: Path) -> FrozenPriorities:
    raw = path.read_bytes()
    if len(raw) > 128 * 1024:
        raise ValueError("Frozen priority file exceeds its bounded size")
    expected = {slug.lower(): slug for slug in repositories}
    if len(expected) != len(repositories):
        raise ValueError("Duplicate normalized corpus repository")
    source = {row["repository"].lower(): row for row in _source_rows(source_csv)
              if row["repository"].lower() not in EXCLUDED_REPOSITORIES}
    if set(source) != set(expected):
        raise ValueError("Priority source does not match the configured corpus")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
    if tuple(reader.fieldnames or ()) != PRIORITY_FIELDS:
        raise ValueError("Frozen priority columns must be repository,priority,source_cohort")
    order, tiers, last_tier = [], {}, "P0"
    for row in reader:
        if set(row) != set(PRIORITY_FIELDS) or not isinstance(row.get("repository"), str):
            raise ValueError("Malformed frozen priority row")
        normalized, tier = row["repository"].strip().lower(), row["priority"]
        if normalized in EXCLUDED_REPOSITORIES:
            continue
        if normalized not in expected or tier not in TIERS or normalized in tiers:
            raise ValueError("Unknown, duplicate or invalid frozen priority member")
        if tier < last_tier:
            raise ValueError("Frozen priorities must group P0 before P1 before P2")
        source_row = source[normalized]
        if row["source_cohort"] != source_row["Cohort"]:
            raise ValueError("Frozen priority source cohort differs from the corpus")
        if source_row["Cohort"] == "Healthcare" and tier != "P0":
            raise ValueError("Every healthcare repository must remain P0")
        canonical = expected[normalized]
        order.append(canonical)
        tiers[normalized] = tier
        last_tier = tier
    if set(tiers) != set(expected):
        raise ValueError("Frozen priorities must list every corpus repository exactly once")
    return FrozenPriorities(tuple(order), {slug: tiers[slug.lower()] for slug in repositories},
                            hashlib.sha256(raw).hexdigest())


def initial_priority_rows(source_csv: Path) -> list[dict[str, str]]:
    """One-time reproducible initial selection; runtime never invokes this."""
    source = _source_rows(source_csv)
    ranked = lambda rows: sorted(rows, key=lambda row: (
        hashlib.sha256(row["repository"].lower().encode("utf-8")).digest(), row["repository"].lower()))
    selected = set()
    for cohort, numerator in (("ICS_OT_IIoT", 7), ("Cross_sector", 1)):
        members = ranked([row for row in source if row["Cohort"] == cohort])
        # Round positive half units up, with no floating point/banker's rounding.
        selected.update(row["repository"] for row in members[:(len(members) * numerator + 5) // 10])
    rows = [{"repository": row["repository"],
             "priority": "P0" if row["Cohort"] == "Healthcare" else
                         "P1" if row["repository"] in selected else "P2",
             "source_cohort": row["Cohort"]} for row in source]
    # Select against the original source first; removals must not select a
    # replacement or change any remaining repository's frozen membership.
    return sorted((row for row in rows if row["repository"].lower() not in EXCLUDED_REPOSITORIES), key=lambda row: (row["priority"],
        hashlib.sha256(row["repository"].lower().encode("utf-8")).digest(), row["repository"].lower()))
