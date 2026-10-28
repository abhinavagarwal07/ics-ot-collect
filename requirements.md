# GitHub evidence collector requirements

## Goal

Create local, incremental, independently verifiable records of public GitHub observations. Preserve captured history through upstream deletions and force pushes.

## Collection scope

- Standard profile: public commits and complete reachable history across advertised branches, tags, and PR heads, including ancestors. The separate LARGE recent-history policy below is not active.
- Public issues, PRs, comments, reviews, GitHub Discussions/replies, and release metadata, using GitHub APIs alongside Git fetching.
- Large binaries, external LFS/submodule contents, and additional fork repositories are optional extensions.

## Operating targets

- **185 repositories**, selected from all rows of [public_patch_corpus_185.csv](public_patch_corpus_185.csv) and configured in [config.corpus.toml](icsot-observatory/config.corpus.toml). Preserve repository roles and measurement caveats; observation at a mirror does not establish availability at its upstream origin.
- Execute on a trusted persistent host or **GitHub Actions** with authenticated durable working-state recovery. Recurring collection is scheduled every six hours; baseline initialization and scoped recovery are manual. Report actual per-lane coverage and gaps rather than treating pointer presence or a successful plan as completed collection. A separate daily/manual workflow refreshes public timestamp proofs without repository recapture.
- Target **1–6 hours between observations**, according to measured feasibility. The initial schedule is **`17 */6 * * *` UTC**, best effort: GitHub may delay or drop runs. Report actual gaps; planning all 185 targets does not establish six-hour coverage of every repository.
- **One-time initial 185-repository baseline allowance: 100 GB (100,000,000,000 stored bytes).** Count every retained attempt, partial result, retry and metadata asset across its releases. Do not increase beyond 100 GB automatically or delete evidence to make room. This explicit baseline amendment is separate from the **50 GB (50,000,000,000 bytes) per UTC calendar month** recurring-evidence policy. Runtime monthly budget admission/enforcement is intentionally omitted at the user's direction.
- **Indefinite retention**; no automatic expiration or deletion of captured evidence.
- The source repository is **public**. The one-time baseline uses standard hosted runners and encrypted XZ Release assets; metadata and the RSA public key may remain public. Recurring collection restores authenticated encrypted working state; state storage and evidence-transfer bytes are accounted separately.
- Respect Actions runtime/disk/API limits; preserve explicit partial or missing outcomes and repair only affected targets/scopes. Avoid overwriting prior evidence or repeating the entire cohort to repair one failure.
- An optional second public source-read credential may distribute repository jobs deterministically, pinning each job's identity, pagination and retries to one credential. A primary reserve or exhaustion defers only targets assigned to that account; potentially shared secondary throttling stops further identity planning. Keep primary-rate observations independent, honor secondary limits without credential switching, preserve single-token fallback, and leave destination authentication and concurrency unchanged.
- **Local disk hard limit: 2,000,000,000 bytes at once**, counting this workspace, caches, temporary downloads, decrypted/expanded data and visualization/spot-check files together. Use one shared admission ledger and stream one archive part at a time; defer any check that cannot fit. Do not use Docker locally.

## LARGE policy and measured sizes

- Automatically classify `LARGE_REPO` only when GitHub's **raw reported size is strictly greater than 5,000,000 KB**; keep manual overrides separate. The LARGE policy uses a **frozen 730-day recent-history window**. That implementation remains inactive pending review; standard recurring collection does not activate it.
- The [2026-10-26 size review](icsot-observatory/docs/REPO_SIZE_REVIEW.md) records **167 accepted and 18 incomplete** baseline targets, with maximum reported size **1,914,819 KB**. Five of eight targets reporting at least 1,000,000 KB were accepted. No current target crosses the LARGE threshold, and the observations establish **no size-only failure boundary**. Reported size does not measure complete mirror, bundle, API archive or restore-space requirements.

## Functional requirements

1. Find when a commit was **first observed within each watched repository**, with observation-time branch/ref attribution. Mark baseline commits; do not claim exact first-publication time.
2. Report each repository/lane's original observation start/end in UTC ISO 8601 with microsecond representation and `Z`, labeled `runner_system_clock`, and compare observations including edits and ref changes. Publish state snapshot start/seal UTC separately; collection is an interval, not an atomic instant. Clock precision does not establish externally verified clock accuracy. Distinguish absence from confirmed deletion.
3. Preserve original response bodies, Git objects, manifests, and proofs. Allow independent hash verification and history restoration without contacting upstream.
4. For new captures in the configured persistent workflows, request independent DigiCert and FreeTSA RFC 3161 proofs and OpenTimestamps for each manifest's full SHA-256 digest. Preserve per-repository public indexes, immutable receipts and attestation metadata so each manifest can be audited independently, with original UTC request/receipt times when recorded and explicit trust/verification status. FreeTSA has bounded Retry-After-aware retries with jitter; an exhausted or failed attempt is recorded as failed with no scheduled retry. Pending OTS receipts are not verified Bitcoin evidence; RFC 3161 responses require explicit trusted-chain, nonce and imprint verification. Evidence existence and GitHub provenance remain separate claims.
   Delayed OTS proofs are refreshed once per 24 hours or manually through a bounded queue. Upgrades append hash-linked receipts and metadata without recapturing repositories or replacing original proofs. Without a trusted Bitcoin Core node, Bitcoin attestation presence remains unverified.
5. Record expected observations, attempts, partial results, failures, rate limits, clock uncertainty, and scope/configuration changes to reconstruct gaps and collection bias. Emit bounded metadata-only stage/API diagnostics and terminal Actions summaries that separate scientific coverage from verification, archive/encryption, transfer and proof outcomes. Include identities, timings, selected quota/request-ID metadata, safe failure categories and retained index digests without logging bodies, raw header dumps, credentials or arbitrary exception text.
   Enable the bounded sink in recurring, selected-persistent and baseline-initializer workflows. Recurring terminal summaries report per-lane verification, archive/transfer and provider outcomes plus proof-registration status; collection completeness never implies proof verification.
6. Regenerate measurements and the analysis index from preserved evidence without trusting the working database.
7. Resume safely after interruption; respect primary/secondary limits and pagination/caps without silent truncation or false success. Keep recovery holds explicit without repeatedly scheduling unchanged blocked work. Recovery must retain original evidence and timestamps, authenticate reused parts, and distinguish an exactly recoverable generation from a new linked representation.
8. Encrypt every uploaded evidence payload with AES-256-GCM and RSA-OAEP-SHA256 key wrapping for this machine's RSA key. Keep the private key local. Preserve original and encrypted hashes; reject tampering, wrong keys and truncated files. Migrate and verify existing payloads before exposing the repository publicly.
9. Provide a local, read-only capture browser with UTC timelines, qualified entity/ref/file differences, raw-response provenance, coverage and proof status. Load selected encrypted evidence only on explicit request within the shared local limit.
10. After the complete initial cohort is published and stable, audit retained payload integrity/recoverability and perform bounded offline Git restoration spot checks; record gaps and deferred checks explicitly, followed by independent GPT-6.1-sol xhigh inspection.

GitHub-backed resumption uses a separately generated operational RSA recipient and an explicitly authorized Actions state-key secret. It decrypts working state and, through the published key capsules, the covered baseline archives. The owner's retained-evidence private key remains local; this does not make capsule-covered baseline contents inaccessible to the operational key. State snapshot bytes must be reported separately from evidence-transfer bytes.

Manual working-state compaction is scoped to one explicitly selected authenticated pointer, preserves logical evidence and original observation times, retains old assets, and verifies a complete fresh remote reconstruction before compare-and-swap. It creates no new observations or baseline evidence bytes; see [state compaction operations](icsot-observatory/docs/STATE_COMPACTION.md).

## Design direction

- **SQLite:** metadata, derived indexes, and scheduling. Original evidence lives in content-addressed files and Git archives.
- **Native XZ by default:** stream archive compression/decompression using Python `lzma`. Record original and compressed hashes/sizes separately; measure growth using stored compressed bytes. Study Git text and active SQLite remain directly usable.
- **Proposed study Git history:** one commit per interval containing manifests, refs, coverage/gaps, and evidence hashes; externally timestamp its checkpoint. Keep large payloads and SQLite outside this repository.
- Self-contained baseline plus incremental Git archives, explicit prerequisites, and tested restoration.
- Append-only manifests/attempt records; independent Git and metadata scheduling with durable retries.
- Report evidence growth against the separate baseline/monthly policies and retain explicit pause/gap records. Runtime monthly budget enforcement is intentionally omitted.

## Decisions still open

- Acceptable attestation precision and delay for each configured provider.
- Off-host backups and their separate capacity/accounting policy.
- Always-on host location and deployment; independent archive destination. See [storage decision](icsot-observatory/docs/STORAGE.md).

## Implemented collection path

`icsot-observe persistent` provides independent API/Git worker pools, durable leases and attempt telemetry, resumable raw-response/page checkpoints, frozen per-scope query boundaries, and watermark commits gated by immutable manifest/digest verification. Git storage uses a self-contained initial archive plus incremental or refs-only descriptors with explicit CAS prerequisites. Finalized manifests from both lanes share one append-locked hash chain; original observation times survive namespace clock clamping.

Optional encrypted per-capture exports include only newly required CAS objects and record dependencies on previous packages. The GitHub-backed adapter restores encrypted working state, uploads and validates evidence, then commits a durable public proof-registration outbox with its final state pointer. Daily maintenance registers and refreshes proofs; pending registration is not verification. The six-hour adapter plans all 185 targets, resumes authenticated state, and defaults to **zero fresh cold bootstraps** (explicit manual range **0–8**), with **at most eight concurrent workers**. Manual baseline initialization admits eligible missing states and reports recovery holds separately. Rollout and completed-cohort throughput remain distinct from the requested cadence.

The full-bundle baseline supports verified ordered multi-parent reuse, preserving original accepted capture/transport references; new baseline captures publish UTC and OTS sidecars, while older inherited sidecar gaps remain explicit. Daily proof maintenance uses public sidecars and a bounded queue; cohort-wide daily throughput is unmeasured. Discussions and the LARGE recent-history implementation remain open. See [operation and deployment template](icsot-observatory/docs/PERSISTENT.md).
