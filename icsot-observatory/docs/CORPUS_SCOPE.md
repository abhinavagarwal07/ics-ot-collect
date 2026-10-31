# Active corpus scope

Effective **2026-10-30**, the user authorized removing exactly these four oversized non-healthcare targets from collection and their associated payload retention:

| Repository | Reason for exclusion | Original frozen priority |
| --- | --- | --- |
| `v8/v8` | Oversized Git history and costly partial capture/finalization | P1 |
| `python/cpython` | Oversized retained Git bundle | P2 |
| `aws/aws-lc` | Oversized retained Git bundle | P2 |
| `envoyproxy/envoy` | Oversized retained Git bundle | P2 |

The bounded evidence supporting this choice is in [the repository-size review](REPO_SIZE_REVIEW.md), its [historical size and bundle CSV](data/repo-size-outcomes-2026-10-26.csv), and the [manual comparison run](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40654322997). No other repository is excluded by size, runtime, cohort or priority. All 42 Healthcare targets remain. The active cohort is **181**: 42 Healthcare, 51 ICS/OT/IIoT and 88 cross-sector repositories. The active frozen tiers are **42 P0, 44 P1 and 95 P2**; P1 retains 36 ICS/OT and eight cross-sector targets.

The original [185-row source](../../public_patch_corpus_185.csv), both TOML cohort declarations and [priority rows](../repository-priorities.csv) remain unchanged for lineage and historical source hashes. The explicit four-slug set in [exclusions.py](../src/icsot_observer/exclusions.py) filters `Config.load` case-insensitively for every collection CLI and the selected manual workflow. Corpus and priority loaders apply the same filter without rotating, replacing or reselecting any remaining member. New plans record the original source count, active count, exclusions and effective date. Standalone configurations for unrelated repositories do not require the source CSV.

Historical 185-row inventories, manifests, indexes, proof metadata and earlier measurements describe their original scope; they are not rewritten as 181-row observations. Historical source validation can inspect the original declarations. An old full-cohort migration catalog or capture plan cannot pass current active-membership checks. Capsule preparation is an indivisible frozen-source batch and refuses a historical batch containing excluded targets; other preparation remains unchanged. Publishing replacement state requires a newly reviewed active-scope plan. Manual state compaction also refuses these four targets before restoration. Read-only archive/viewer access remains available for retained historical evidence.

Proof maintenance skips the four frozen repository IDs, their per-repository Release namespaces and baseline index names. SHA-only pending baseline proof references are matched against the four deleted proof subjects whose ownership was established in the [ownership-validated deletion receipt](data/removed-assets-2026-10-30.json). Historical proof records remain intact; skipped pending entries are separately counted and are not attempted or requeued. Shared metadata catalogs may still be read for the remaining targets. Maintenance cannot reconstruct deleted encrypted MAIN/state payloads.

The completed user-authorized cleanup deleted **503 exclusively owned Release assets (22.426 GB)**; the [deletion receipt](data/removed-assets-2026-10-30.json) records exact identities, hashes, sizes and outcomes. The remaining Release assets total **143.125 GB** from the exhaustive before inventory minus verified deletions; all 15 affected Releases were independently relisted and reconciled. Shared assets and Git history remain. Retaining a manifest does not imply its referenced payload is still available. Automatic schedules remain paused; this change dispatches no workflows.
