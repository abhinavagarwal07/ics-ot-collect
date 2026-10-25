# GitHub evidence collector requirements

## Goal

Create local, incremental, independently verifiable records of public GitHub observations. Preserve captured history through upstream deletions and force pushes.

## Collection scope

- Public commits and complete reachable history across advertised branches, tags, and PR heads, including ancestors.
- Public issues, PRs, comments, reviews, GitHub Discussions/replies, and release metadata, using GitHub APIs alongside Git fetching.
- Large binaries, external LFS/submodule contents, and additional fork repositories are optional extensions.

## Operating targets

- Approximately **100 repositories** on an **always-on host**.
- First selected target: [`libfuse/libfuse`](https://github.com/libfuse/libfuse).
- Target **1–6 hours between observations**, according to measured feasibility; report actual gaps.
- **Hard cap: 50 GB (50,000,000,000 stored bytes) of new evidence per UTC calendar month.** Pause collection before exceeding it; resume next month or after an explicit policy amendment. No automatic limit increase or deletion. No baseline exemption is assumed.
- **Indefinite retention**; no automatic expiration or deletion of captured evidence.

## Functional requirements

1. Find when a commit was **first observed within each watched repository**, with observation-time branch/ref attribution. Mark baseline commits; do not claim exact first-publication time.
2. Report any collection interval and compare any two observations, including edits and ref changes. Distinguish absence from confirmed deletion.
3. Preserve original response bodies, Git objects, manifests, and proofs. Allow independent hash verification and history restoration without contacting upstream.
4. Externally timestamp evidence digests using **RFC 3161 or OpenTimestamps**; distinguish pending and verified attestations. This is sufficient for v1; independent collection is optional. Evidence existence and GitHub provenance remain separate claims.
5. Record expected observations, attempts, partial results, failures, rate limits, clock uncertainty, and scope/configuration changes to reconstruct gaps and collection bias.
6. Regenerate measurements and the analysis index from preserved evidence without trusting the working database.
7. Resume safely after interruption; respect primary/secondary limits and pagination/caps without silent truncation or false success.

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
