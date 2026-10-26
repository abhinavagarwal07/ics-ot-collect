"""Reported-size selection of a frozen repository observation policy."""
from __future__ import annotations

import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

FULL_HISTORY = "full_history"
RECENT_HISTORY = "recent_history_shallow_v1"
WINDOW_DAYS = 730
DEFAULT_THRESHOLD_KB = 5_000_000


def load_history_settings(path: Path, repositories: tuple[str, ...]) -> dict:
    settings = tomllib.loads(path.read_text(encoding="utf-8")).get("history", {})
    threshold = settings.get("large_repo_threshold_kb", DEFAULT_THRESHOLD_KB)
    if type(threshold) is not int or threshold <= 0:
        raise ValueError("History reported-size threshold must be a positive count of GitHub KB units")
    window = settings.get("window_days", WINDOW_DAYS)
    if type(window) is not int or window != WINDOW_DAYS:
        raise ValueError("The reviewed recent-history window is 730 days")
    overrides = settings.get("overrides", {})
    if not isinstance(overrides, dict) or any(
            slug not in repositories or profile not in (FULL_HISTORY, RECENT_HISTORY)
            for slug, profile in overrides.items()):
        raise ValueError("History overrides must name declared repositories and reviewed profiles")
    return {"threshold_kb": threshold, "window_days": window, "overrides": overrides}


def repository_history_policy(slug: str, reported_size_kb: int, slot: int, *,
                              threshold_kb: int = DEFAULT_THRESHOLD_KB,
                              overrides: dict[str, str] | None = None) -> dict:
    if type(reported_size_kb) is not int or reported_size_kb < 0:
        raise ValueError("A nonnegative reported GitHub repository size is required")
    large = reported_size_kb > threshold_kb
    override = (overrides or {}).get(slug)
    profile = override or (RECENT_HISTORY if large else FULL_HISTORY)
    if profile not in (FULL_HISTORY, RECENT_HISTORY):
        raise ValueError("Unknown repository history profile")
    cutoff = (datetime.fromtimestamp(slot * 21600, timezone.utc) - timedelta(days=WINDOW_DAYS)).isoformat(
        timespec="seconds").replace("+00:00", "Z") if profile == RECENT_HISTORY else None
    return {"profile": profile, "window_days": WINDOW_DAYS if profile == RECENT_HISTORY else None,
            "cutoff_utc": cutoff, "selection_reason": "manual" if override else "reported_size_threshold",
            "reported_size_kb": reported_size_kb, "threshold_kb": threshold_kb,
            "size_classification": "LARGE_REPO" if large else "STANDARD",
            "size_measurement": "raw GitHub reported size KB units; no conversion or measured transfer-size claim"}
