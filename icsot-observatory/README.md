# ICS/OT GitHub Observatory — research starter v0.1

Prospective, **public-only** GitHub observation with raw byte preservation, content-addressed storage, Git ref pinning, SHA-256 hash-chained run manifests, optional OpenTimestamps attestation, and a regenerable CSV index.

**This remains a prototype with explicit production gaps.** Read `docs/PROTOCOL.md`, `docs/METHODS.md`, and `docs/PRODUCTION_GAPS.md` before using evidence in a publication. Durable independent API/Git queues, resumable API scopes, incremental Git archives and a manual GitHub-backed state adapter are implemented; independent backup, clock measurement and event polling enforcement remain open. Hosted pilot validation is separate from offline tests. Automatic collection and proof-refresh schedules are paused. The new [cycle archive layout](docs/CYCLE_ARCHIVES.md) is subject to a separately authorized five-repository manual runtime comparison; no broader launch is authorized.

The [persistent collector guide](docs/PERSISTENT.md) describes the implemented `persistent`/`run` command, encrypted incremental transfers, restoration and a deployment template. The [requirements](../requirements.md), [collector design](docs/DESIGN.md), and [SQLite schema guide](docs/SCHEMA.md) also describe future research metadata, Discussions and study Git history. [metadata.sql](schema/metadata.sql) remains a separate draft; `runtime.sqlite3` implements operational scheduling rather than that research schema.

Public observation indexes include the original UTC observation interval and hash-linked timestamp sidecars. OpenTimestamps receipts require independent Bitcoin verification. The selected-repository persistent pilot also requests RFC 3161 receipts with explicit trust-chain, nonce and digest verification; the corpus baseline publishes OTS sidecars. See [UTC and timestamp evidence](docs/PERSISTENT.md#utc-intervals-and-timestamp-evidence).

The [six-hour cohort workflow](docs/PERSISTENT.md#six-hour-cohort-workflow) plans all 181 active repositories, resumes existing authenticated working state and defaults to zero fresh public bootstraps, with an explicit manual range of zero through eight. It shares eight capture slots, uses the separate operational state key and records partial/paused/bootstrap-pending outcomes. The nominal interval does not promise completion of all 181 active targets. A separate manual [proof-maintenance workflow](docs/TIMESTAMPING.md#manual-delayed-proof-maintenance) retrieves delayed OTS evidence and appends immutable receipt/metadata history without recapture or decryption. Its default has no trusted Bitcoin Core node, so Bitcoin attestation presence remains unverified. Full-cohort daily proof throughput is unmeasured.

The active cohort contains 181 repositories after four explicit exclusions effective 2026-10-30. The original 185-row [CSV](../public_patch_corpus_185.csv), [configuration declarations](config.corpus.toml) and frozen priority rows remain provenance; `Config.load` removes exactly the four excluded slugs, including manual selections. Remaining membership, tier assignments and order are preserved. See [scope and exclusion reasons](docs/CORPUS_SCOPE.md). Repository roles and measurement caveats remain in the CSV; observations of mirrors establish availability at those mirrors.

`libfuse/libfuse` remains the smoke target in `config.libfuse.toml`. The workspace-root manual Actions workflow runs a shallow full capture, a delta capture, full-bundle restoration, byte verification and CSV/diff generation. It requests OpenTimestamps receipts but does not equate pending receipts with verified Bitcoin attestations. Artifact downloads are temporary transfer copies, not the indefinite archive.

See [the first live libfuse validation](docs/LIBFUSE_VALIDATION.md) for measured results, preserved failures, evidence digests and remaining implementation limits.

The manual `Corpus baseline (one time)` workflow preserves full bundles, raw evidence and partial outcomes in **encrypted Release assets**. It verifies up to 16 explicit parents in priority order, freezes that ordered set for finalization, and reuses accepted captures with their original code, index and encrypted transport references. New captures publish their UTC interval, immutable `.ots` receipt and canonical attestation sidecar; one finalizer catalog registers them for proof maintenance. Older reused indexes without public proof sidecars remain valid with an explicit backfill gap. The retained-evidence RSA private key stays local; resumable working state uses a separate operational key. See [encryption and restoration](docs/ENCRYPTION.md). The recurring workflow does not rerun this baseline workflow.

Future baseline dispatches accept integer `max_parallel` from 1 through 16, defaulting to 8; only the validated plan output controls the matrix. Existing runs keep their pinned limit. Workers share API/upload quotas. There is no user-imposed GitHub baseline or monthly storage allowance; actual service limits and the shared 2,000,000,000-byte local disk limit still apply. See [storage policy](docs/STORAGE.md) and [Actions operations](docs/ACTIONS_OPERATIONS.md).

The [local capture viewer](docs/VIEWER.md) provides UTC timelines, entity/ref/file comparisons, raw-response provenance, coverage and proof status. Selected encrypted evidence loads explicitly within one shared **2,000,000,000-byte local limit**, including this workspace and temporary files. The [recovery auditor](docs/RECOVERY_AUDIT.md) waits for the complete stable baseline, checks retained payloads and performs bounded Git restoration spot checks. See [local storage controls](docs/LOCAL_DATA.md); no Docker is required.

## Quickstart

Requirements: Linux/macOS, Python >=3.11, Git, OpenTimestamps CLI (`ots`) from [official client](https://github.com/opentimestamps/opentimestamps-client). For local development tests `ots` can be omitted using `--no-stamp`. Prefer a narrowly scoped **read-only** GitHub App/token restricted to public repositories; `GITHUB_TOKEN` is read from your environment, never stored in run manifests.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
pip install pytest
pip install opentimestamps-client
cp config.corpus.toml config.toml
# review collector/root; 181 active repositories; four explicit exclusions apply
# config.toml is machine-local and ignored by Git; never add a token
export GITHUB_TOKEN="<read-only-public-GitHub-token>"

icsot-observe collect --config config.toml --mode full
# Optional, potentially large: bind a complete portable Git bundle to SHA-256 manifest
icsot-observe collect --config config.toml --mode delta --bundle-full
icsot-observe collect --config config.toml --mode events
icsot-observe collect --config config.toml --mode delta
icsot-observe verify --root ./evidence
icsot-observe derive --root ./evidence --out ./analysis/observations.csv
icsot-observe diff --root ./evidence --repository-id YOUR_NUMERIC_ID
# Requires durable working state; first use creates a Git/API baseline.
icsot-observe persistent --config config.toml --once
pytest -q
```

Legacy `collect` keeps combined API/Git behavior and optional full bundles. Use `persistent` for separately scheduled lanes, per-scope cursors and true incremental Git archives; it defaults to six-hour API/Git intervals, one API worker and two Git workers. `--deep-full` enumerates per-item histories and can be expensive despite checkpoints. A delta without prior successful scope state starts with a shallow full API query. No recurring deployment is enabled by this command's existence; restore trusted working state before running on an ephemeral runner.

`collect` returns nonzero if any repo is partial or if OTS stamping is unavailable. **Do not ignore that exit status.** The partial run manifest and any collected raw responses are retained for audit. `verify` always recomputes original-response hashes and manifest chains; optionally use `--check-ots` only after Bitcoin confirmation. `derive` recomputes a CSV from the original manifest+CAS rather than treating derived tables as evidence. `diff` reports newly *observed* issue/PR IDs, representation changes, and Git ref movements; it never labels absent delta-feed records as deleted or a commit as first-public.

For Git objects, `git/<stable-repository-id>.git` is a bare mirror with permanent `refs/archive/<run-id>/...` references for each remotely advertised head, tag, and pull-head observed in that run. **Back up that directory**; the manifest's Git object IDs do not contain the objects themselves. With `--bundle-full`, a self-contained Git bundle is also stored by SHA-256 in the original evidence CAS and its digest is committed into the manifest (expensive for large projects).

New manifests use `capture_id` for Git pin namespaces and allocate their final `run_id` only when appending to the shared repository chain. Persistent Git captures preserve a baseline plus explicit incremental/refs-only descriptors in CAS. `icsot-observe restore --root ...` rebuilds omitted mirrors offline from those prerequisites. API-only and Git-only manifests have independent cursors and comparisons; `diff` reports each lane's comparison IDs.

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
  checkpoints/api/<repo-id>/<capture-id>/ # resumable API response/page ledgers
  runtime.sqlite3                   # durable leases, attempts and scope cursors
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
