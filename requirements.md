# GitHub evidence collector requirements

## Goal

Create local, incremental, independently verifiable records of public GitHub observations. Preserve captured history through upstream deletions and force pushes.

## Collection scope

- Public commits and complete reachable history across advertised branches, tags, and PR heads, including ancestors.
- Public issues, PRs, comments, reviews, GitHub Discussions/replies, and release metadata, using GitHub APIs alongside Git fetching.
- Large binaries, external LFS/submodule contents, and additional fork repositories are optional extensions.

## Operating targets

- **185 repositories**, selected from all rows of [public_patch_corpus_185.csv](public_patch_corpus_185.csv) and configured in [config.corpus.toml](icsot-observatory/config.corpus.toml). Preserve repository roles and measurement caveats; observation at a mirror does not establish availability at its upstream origin.
- An always-on host is available; **GitHub Actions** is also being evaluated for periodic execution, with durable evidence/state stored separately. `libfuse/libfuse` remains the validated single-repository smoke target.
- Target **1–6 hours between observations**, according to measured feasibility; report actual gaps.
- **Hard cap: 50 GB (50,000,000,000 stored bytes) of new evidence per UTC calendar month.** Pause collection before exceeding it; resume next month or after an explicit policy amendment. No automatic limit increase or deletion. No baseline exemption is assumed.
- **Indefinite retention**; no automatic expiration or deletion of captured evidence.
- Run the collector in a **public GitHub repository** on standard hosted runners. Store main evidence as encrypted XZ archive parts in Releases; metadata and the RSA public key may remain public. Recurring collection is not enabled; six hours remains the recommended starting cadence after incremental archiving is implemented.
- Respect Actions runtime/disk/API limits; preserve explicit partial or missing outcomes and repair only affected targets/scopes. Avoid overwriting prior evidence or repeating the entire cohort to repair one failure.

## Functional requirements

1. Find when a commit was **first observed within each watched repository**, with observation-time branch/ref attribution. Mark baseline commits; do not claim exact first-publication time.
2. Report any collection interval and compare any two observations, including edits and ref changes. Distinguish absence from confirmed deletion.
3. Preserve original response bodies, Git objects, manifests, and proofs. Allow independent hash verification and history restoration without contacting upstream.
4. Externally timestamp evidence digests using **RFC 3161 or OpenTimestamps**; distinguish pending and verified attestations. This is sufficient for v1; independent collection is optional. Evidence existence and GitHub provenance remain separate claims.
5. Record expected observations, attempts, partial results, failures, rate limits, clock uncertainty, and scope/configuration changes to reconstruct gaps and collection bias.
6. Regenerate measurements and the analysis index from preserved evidence without trusting the working database.
7. Resume safely after interruption; respect primary/secondary limits and pagination/caps without silent truncation or false success.
8. Encrypt every uploaded evidence payload with AES-256-GCM and RSA-OAEP-SHA256 key wrapping for this machine's RSA key. Keep the private key local. Preserve original and encrypted hashes; reject tampering, wrong keys and truncated files. Migrate and verify existing payloads before exposing the repository publicly.

## Design direction

- **SQLite:** metadata, derived indexes, and scheduling. Original evidence lives in content-addressed files and Git archives.
- **Native XZ by default:** stream archive compression/decompression using Python `lzma`. Record original and compressed hashes/sizes separately; measure growth using stored compressed bytes. Study Git text and active SQLite remain directly usable.
- **Proposed study Git history:** one commit per interval containing manifests, refs, coverage/gaps, and evidence hashes; externally timestamp its checkpoint. Keep large payloads and SQLite outside this repository.
- Self-contained baseline plus incremental Git archives, explicit prerequisites, and tested restoration.
- Append-only manifests/attempt records; independent Git and metadata scheduling with durable retries.
- Reserve space within the cap for manifests, proofs, and pause records; log budget-induced gaps. Concurrent writers must reserve capacity before admitting new evidence.

## Decisions still open

- Timestamp provider and acceptable attestation precision/delay.
- Off-host backups and their separate capacity/accounting policy.
- Always-on host location and deployment; independent archive destination. See [storage decision](icsot-observatory/docs/STORAGE.md).
