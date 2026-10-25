# ICS/OT GitHub Observatory — research starter v0.1

Prospective, **public-only** GitHub observation with raw byte preservation, content-addressed storage, Git ref pinning, SHA-256 hash-chained run manifests, optional OpenTimestamps attestation, and a regenerable CSV index.

**This is a tested prototype + publication-grade protocol, NOT a ready-for-90-day unattended academic data collection deployment.** Read `docs/PROTOCOL.md`, `docs/METHODS.md`, `docs/BUILD_PLAN.md`, and `docs/PRODUCTION_GAPS.md` before using evidence in a publication. In particular: complete sharded backfill, queue-based retries, verified off-site storage, clock measurement, and event polling enforcement are NOT yet implemented.

**Current design work (2026-10-25):** [requirements](../requirements.md), [collector design](docs/DESIGN.md), and the [SQLite schema guide](docs/SCHEMA.md) describe the updated approximately 100-repository scope, GitHub Discussions, SQLite metadata and proposed study Git history. [metadata.sql](schema/metadata.sql) is an executable draft for a fresh database. The existing CLI has not been upgraded to that design.

The first selected target is `libfuse/libfuse`, configured in `config.libfuse.toml`. The workspace-root manual Actions workflow runs a shallow full capture, a delta capture, full-bundle restoration, byte verification and CSV/diff generation. It requests OpenTimestamps receipts but does not equate pending receipts with verified Bitcoin attestations. Artifact downloads are temporary transfer copies, not the indefinite archive.

See [the first live libfuse validation](docs/LIBFUSE_VALIDATION.md) for measured results, preserved failures, evidence digests and remaining implementation limits.

## Quickstart

Requirements: Linux/macOS, Python >=3.11, Git, OpenTimestamps CLI (`ots`) from [official client](https://github.com/opentimestamps/opentimestamps-client). For local development tests `ots` can be omitted using `--no-stamp`. Prefer a narrowly scoped **read-only** GitHub App/token restricted to public repositories; `GITHUB_TOKEN` is read from your environment, never stored in run manifests.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
pip install pytest
pip install opentimestamps-client
cp config.example.toml config.toml
# edit cohort/repositories + collector/root; do not add any token to config
export GITHUB_TOKEN="<read-only-public-GitHub-token>"

icsot-observe collect --config config.toml --mode full
# Optional, potentially large: bind a complete portable Git bundle to SHA-256 manifest
icsot-observe collect --config config.toml --mode delta --bundle-full
icsot-observe collect --config config.toml --mode events
icsot-observe collect --config config.toml --mode delta
icsot-observe verify --root ./evidence
icsot-observe derive --root ./evidence --out ./analysis/observations.csv
icsot-observe diff --root ./evidence --repository-id YOUR_NUMERIC_ID
pytest -q
```

Run `full` for initial baseline, `events` every 15–60 minutes, `delta` every 3–6 hours, and `full` daily (or weekly for high-volume projects). `--deep-full` also enumerates all per-issue timeline and PR detail/review/commit/file endpoints, **which can be very expensive or rate limited**; on an existing large repository do not run it until the backfill queue and budget controls specified in `PRODUCTION_GAPS.md` are built. A delta run without an earlier complete baseline is automatically promoted to a shallow full run.

`collect` returns nonzero if any repo is partial or if OTS stamping is unavailable. **Do not ignore that exit status.** The partial run manifest and any collected raw responses are retained for audit. `verify` always recomputes original-response hashes and manifest chains; optionally use `--check-ots` only after Bitcoin confirmation. `derive` recomputes a CSV from the original manifest+CAS rather than treating derived tables as evidence. `diff` reports newly *observed* issue/PR IDs, representation changes, and Git ref movements; it never labels absent delta-feed records as deleted or a commit as first-public.

For Git objects, `git/<stable-repository-id>.git` is a bare mirror with permanent `refs/archive/<run-id>/...` references for each remotely advertised head, tag, and pull-head observed in that run. **Back up that directory**; the manifest's Git object IDs do not contain the objects themselves. With `--bundle-full`, a self-contained Git bundle is also stored by SHA-256 in the original evidence CAS and its digest is committed into the manifest (expensive for large projects).

## OpenTimestamps proof lifecycle

```bash
# After successful OTS stamp, wait for Bitcoin anchoring to complete.
ots upgrade evidence/runs/REPO_ID/RUN_ID.manifest.json.ots
ots verify evidence/runs/REPO_ID/RUN_ID.manifest.json.ots
icsot-observe verify --root ./evidence --check-ots
```

The original pending `.ots` receipt is copied immutably under `proofs/initial/<manifest-sha256>.ots`; `ots upgrade` may replace/extend the working receipt. Archive both originals and upgraded receipts. To verify independently against Bitcoin headers, configure a trusted local Bitcoin node; without one you rely on verification mechanisms configured in the timestamp client. A Bitcoin block gives an **existence no-later-than** bound, not a trusted wall-clock time for the GitHub API request.

## Data layout

```text
evidence/
  objects/sha256/aa/<sha256>          # original HTTP body bytes, never normalized
  registry/<input-owner__repo>.json   # create-only name-to-stable-ID cohort lock
  runs/<numeric-repo-id>/<run>.manifest.json
  registry/<input-owner__repo>.json   # create-only name-to-stable-ID cohort lock
  runs/<numeric-repo-id>/<run>.manifest.json.ots
  proofs/initial/<manifest-sha256>.ots
  git/<numeric-repo-id>.git/         # bare Git repo + immutable ref namespace
  quarantine/<run>.json              # identity-fetch errors, not baseline runs
  .collector.lock
analysis/
  observations.csv                   # reproducible, derived, not original evidence
```

## Threats and supported claims

This system can establish that its **captured response bytes** match their manifests, and that a Bitcoin-attested manifest existed by the block's time. API response dates, Git commit dates, and GitHub `created_at` values come from source or collector clocks and have different evidentiary status. A complete collection of a documented endpoint is not proof of full public GitHub visibility; rapid edits, deletions, private-to-public changes, pagination churn, and unobserved periods remain possible.

A GitHub repository may change ownership/name. The collector records numeric IDs, fails closed on Git HTTP origin changes, and requires an explicit audited cohort/config amendment on rename. The API client does not follow redirects with credentials.

## Publication and reproducibility

- Preregister the cohort, sampling, sampling-period changes and detection definitions.
- Release your collector commit hash, pinned dependencies, configuration (without token), UTC logs, manifest hashes and verification scripts.
- Distinguish prospective observations from retrospective GitHub metadata and independent third-party archives.
- Preserve raw data privately, release only legally/ethically appropriate derived portions with consent/licensing checks.
- See `docs/METHODS.md` for interval censoring, negative evidence, validation and adjudication.

## Source documentation (checked 2026-10-20)

- [GitHub REST pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)
- [GitHub REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [GitHub best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
- [GitHub Events 300/30-day limitation](https://docs.github.com/en/rest/activity/events)
- [GitHub API version pinning](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [GitHub Issue timeline endpoint](https://docs.github.com/en/rest/issues/timeline)
- [OpenTimestamps official client](https://github.com/opentimestamps/opentimestamps-client)
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html)
- [Software Heritage origin visits/snapshots](https://docs.softwareheritage.org/devel/swh-model/data-model.html)
