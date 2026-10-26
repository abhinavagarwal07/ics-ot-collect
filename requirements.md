# GitHub evidence collector requirements

## Goal

Create local, incremental, independently verifiable records of public GitHub observations. Preserve captured history through upstream deletions and force pushes.

## Collection scope

- Public commits and complete reachable history across advertised branches, tags, and PR heads, including ancestors.
- Public issues, PRs, comments, reviews, GitHub Discussions/replies, and release metadata, using GitHub APIs alongside Git fetching.
- Large binaries, external LFS/submodule contents, and additional fork repositories are optional extensions.

## Operating targets

- **185 repositories**, selected from all rows of [public_patch_corpus_185.csv](public_patch_corpus_185.csv) and configured in [config.corpus.toml](icsot-observatory/config.corpus.toml). Preserve repository roles and measurement caveats; observation at a mirror does not establish availability at its upstream origin.
- Execute on a trusted persistent host or **GitHub Actions** with authenticated durable working-state recovery. Repository observations remain manual. A separate daily/manual workflow refreshes public timestamp proofs without repository recapture. `libfuse/libfuse` remains the validated single-repository smoke target.
- Target **1–6 hours between observations**, according to measured feasibility; report actual gaps.
- **One-time initial 185-repository baseline allowance: 100 GB (100,000,000,000 stored bytes).** Count every retained attempt, partial result, retry and metadata asset across its releases. Do not increase beyond 100 GB automatically or delete evidence to make room. This explicit baseline amendment is separate from the **50 GB (50,000,000,000 bytes) per UTC calendar month** policy for future recurring collection. Runtime budget admission is not implemented.
- **Indefinite retention**; no automatic expiration or deletion of captured evidence.
- The source repository is **public**. The one-time baseline uses standard hosted runners and encrypted XZ Release assets; metadata and the RSA public key may remain public. Incremental collection is implemented, but recurring execution still requires durable working state and operational budget enforcement. Six hours is the initial configurable cadence, not a measured guarantee.
- Respect Actions runtime/disk/API limits; preserve explicit partial or missing outcomes and repair only affected targets/scopes. Avoid overwriting prior evidence or repeating the entire cohort to repair one failure.

## Functional requirements

1. Find when a commit was **first observed within each watched repository**, with observation-time branch/ref attribution. Mark baseline commits; do not claim exact first-publication time.
2. Report each repository/lane's original observation start/end in UTC ISO 8601 with microsecond representation and `Z`, labeled `runner_system_clock`, and compare observations including edits and ref changes. Publish state snapshot start/seal UTC separately; collection is an interval, not an atomic instant. Clock precision does not establish externally verified clock accuracy. Distinguish absence from confirmed deletion.
3. Preserve original response bodies, Git objects, manifests, and proofs. Allow independent hash verification and history restoration without contacting upstream.
4. Externally timestamp manifest digests using **RFC 3161 and/or OpenTimestamps**. Retain immutable receipts and canonical attestation metadata beside public observation indexes, with original UTC request/receipt times when recorded, subject hashes and trust/verification status. Pending OTS receipts are not verified Bitcoin evidence; RFC 3161 responses require explicit trusted-chain, nonce and imprint verification. Evidence existence and GitHub provenance remain separate claims.
   Delayed OTS proofs are refreshed once per 24 hours or manually through a bounded queue. Upgrades append hash-linked receipts and metadata without recapturing repositories or replacing original proofs. Without a trusted Bitcoin Core node, Bitcoin attestation presence remains unverified.
5. Record expected observations, attempts, partial results, failures, rate limits, clock uncertainty, and scope/configuration changes to reconstruct gaps and collection bias.
6. Regenerate measurements and the analysis index from preserved evidence without trusting the working database.
7. Resume safely after interruption; respect primary/secondary limits and pagination/caps without silent truncation or false success.
8. Encrypt every uploaded evidence payload with AES-256-GCM and RSA-OAEP-SHA256 key wrapping for this machine's RSA key. Keep the private key local. Preserve original and encrypted hashes; reject tampering, wrong keys and truncated files. Migrate and verify existing payloads before exposing the repository publicly.

GitHub-backed resumption uses a separately generated operational RSA recipient and an explicitly authorized Actions state-key secret. It encrypts the working API/Git corpus for runner recovery; the retained-evidence recipient and its local private key remain separate. State snapshot bytes must be reported separately from evidence-transfer bytes.

## Design direction

- **SQLite:** metadata, derived indexes, and scheduling. Original evidence lives in content-addressed files and Git archives.
- **Native XZ by default:** stream archive compression/decompression using Python `lzma`. Record original and compressed hashes/sizes separately; measure growth using stored compressed bytes. Study Git text and active SQLite remain directly usable.
- **Proposed study Git history:** one commit per interval containing manifests, refs, coverage/gaps, and evidence hashes; externally timestamp its checkpoint. Keep large payloads and SQLite outside this repository.
- Self-contained baseline plus incremental Git archives, explicit prerequisites, and tested restoration.
- Append-only manifests/attempt records; independent Git and metadata scheduling with durable retries.
- Reserve space within the applicable allowance for manifests, proofs and pause records; log budget-induced gaps. Concurrent admission enforcement remains implementation work.

## Decisions still open

- Timestamp provider and acceptable attestation precision/delay.
- Off-host backups and their separate capacity/accounting policy.
- Always-on host location and deployment; independent archive destination. See [storage decision](icsot-observatory/docs/STORAGE.md).

## Implemented collection path

`icsot-observe persistent` provides independent API/Git worker pools, durable leases and attempt telemetry, resumable raw-response/page checkpoints, frozen per-scope query boundaries, and watermark commits gated by immutable manifest/digest verification. Git storage uses a self-contained initial archive plus incremental or refs-only descriptors with explicit CAS prerequisites. Finalized manifests from both lanes share one append-locked hash chain; original observation times survive namespace clock clamping.

Optional encrypted per-capture exports include only newly required CAS objects and record dependencies on previous packages. A manual selected-repository adapter restores encrypted working state, uploads evidence, registers the verified public proof catalog, then publishes its final state pointer. The full-bundle baseline supports verified ordered multi-parent reuse, preserving original accepted capture/transport references; new baseline captures publish UTC and OTS sidecars, while older inherited sidecar gaps remain explicit. Daily proof maintenance uses public sidecars and a bounded queue; cohort-wide daily throughput is unmeasured. It does not schedule repository observations. Runtime budget admission, recurring repository collection and Discussions remain open. See [operation and deployment template](icsot-observatory/docs/PERSISTENT.md).
