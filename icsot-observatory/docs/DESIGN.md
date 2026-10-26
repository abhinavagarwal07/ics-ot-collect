# Collector design draft

Status: requirements/design work, 2026-10-25. The existing collector does **not** implement this design. The companion SQL schema is a proposed storage contract, not a migration of existing evidence. [Current requirements](../../requirements.md) take precedence over the older research-study templates.

## Confirmed targets

185 public repositories selected in [public_patch_corpus_185.csv](../../public_patch_corpus_185.csv) and configured in [config.corpus.toml](../config.corpus.toml); an always-on host; 1–6 hour target observation gaps; a hard cap of 50 GB of new evidence each UTC calendar month; indefinite retention; native XZ compression/decompression by default for archive payloads. The primary Git question is the earliest observation of a commit anywhere within a particular watched repository, with observation-time branch/ref attribution. Include readily accessible issues, PRs, comments, reviews, GitHub Discussions and replies, and release metadata.

Externally timestamped evidence from the documented collector is sufficient for v1, using RFC 3161 or OpenTimestamps. Independent collection is optional. Backup accounting, timestamp provider and acceptable attestation delay remain open. No baseline exemption from the hard cap is assumed. The earlier 30–50 repository/90-day study and downstream vulnerability analyses are not prerequisites for this collector.

## Storage responsibilities

| Component | Contents | Authority and recovery |
|---|---|---|
| SHA-256 content-addressed archive | Original HTTP bodies, sanitized request descriptors, Git baseline/increment archives, evidence records, checkpoint files and timestamp receipts, normally stored as XZ | Logical and stored hashes are distinct; decompressed evidence must reproduce the original captured bytes |
| Study Git repository | Small interval indexes, repository manifests, observed ref maps, coverage records and configuration history | Versioned audit trail; external checkpoints expose changes to witnessed history |
| SQLite metadata database | Searchable observations, first-seen indexes, archive dependencies, proof status and operational queue/rate state | Evidence/index tables are rebuildable; queue state is operational and recoverable from archived attempt records |
| Working Git mirrors | Fetch cache and convenient access to preserved object graphs | Replaceable from the portable archive; not the only retained copy |

Keep the study repository, archive and database on local storage. Retain captured evidence indefinitely. An independently administered backup is proposed; its destination and accounting need selection. At the stated maximum growth, a year adds at most 600 GB of budgeted stored evidence, including any baseline admitted under that budget, before extra copies and working caches.

### Native XZ and artifact identity

Use Python's `lzma` module with XZ format and streaming compression/decompression; do not depend on invoking an external `xz` executable. Check module availability at startup. Start with preset 6; tune only after measuring throughput and memory. Archive payloads use XZ by default, including portable Git bundles, while small study Git text stays readable and the active SQLite database remains uncompressed. Git bundles already contain compressed packs, so measure their additional savings instead of assuming a fixed compression ratio. [Python lzma documentation](https://docs.python.org/3/library/lzma.html)

Each logical artifact has the SHA-256 and length of its exact original bytes. Each stored representation has a separate SHA-256, compressed length, encoding, path and archive time. Manifests/journal records retain both descriptions. Recompression appends a representation; it does not change the logical evidence identifier or overwrite an attested representation. Timestamp canonical checkpoint bytes, independently of their storage encoding.

Stream bytes through hashing/compression into a temporary file, sync and finalize it before acknowledging capture. On reading, verify the stored hash and the decompressed hash/length. Use bounded decoder memory and output chunks; enforce the declared uncompressed length and reject truncated, corrupt, or unexpected trailing streams. XZ CRC64 is an additional corruption check, not cryptographic authentication. [Incremental decoder](https://docs.python.org/3/library/lzma.html#lzma.LZMADecompressor)

Account monthly growth by unique stored representation bytes first archived during that UTC calendar month, including identity-encoded evidence metadata, proofs and baseline archives. Report original-byte volume and compression ratio separately. Working mirrors, restoration space, SQLite and backups also consume capacity and require separate reporting; their separate capacity policy must be decided. There is no automatic age-based pruning or budget-triggered evidence deletion.

### Hard-cap admission policy

The monthly limit is 50,000,000,000 stored bytes. Before admitting new archive writes, reserve capacity atomically so committed bytes plus outstanding reservations cannot exceed the limit. Reserve bounded headroom **inside** that allowance for manifests, proof maintenance and pause records. Do not assume compression will achieve a particular ratio. Streaming writes need enforceable size bounds; finalize only under a valid reservation for the actual accounting period, and release unused capacity after completion. Recovery must reconcile already persisted files before making fresh reservations.

When a capture cannot fit, pause new collection and record the reason, affected scopes and expected resume period. Previously captured evidence remains untouched. Pauses override the normal 1–6 hour cadence and are reported as collection gaps. Resume in the next UTC calendar month or under an explicit, archived policy amendment; never raise the cap automatically. If even the maintenance reserve is exhausted, defer additional writes rather than exceed the cap; an already archived pause declaration and schedule policy must explain the remaining gap.

The schema records this policy but does not implement admission control. Its rebuildable index must still accept truthful records of imported or historical over-budget evidence. A SQL rejection during replay would conceal facts rather than enforce a capture budget.

### Study Git commits

Proposed: close each configured observation interval with an append-only study commit. Its index identifies every due repository/scope and the evidence actually available, including partial results, failed attempts, outstanding work and known gaps. A commit is a report covering a time window, not an atomic snapshot of all GitHub repositories.

1. Preserve response/object bytes and evidence records before publishing references to them.
2. Finalize repository manifests and an interval index containing their SHA-256 hashes and the relevant attempt-journal boundaries.
3. Commit those small records to the study repository. Do not track SQLite, its WAL, credentials, working mirrors, or large evidence payloads there.
4. Create a separate canonical checkpoint containing the study commit OID/object format, interval-index SHA-256, and previous checkpoint SHA-256.
5. Timestamp the checkpoint digest externally. Archive initial receipts, later upgrades and verification records as separate versions.
6. Include subsequently available receipts and late collection outcomes in later study commits. Never amend an interval commit to conceal late work.

The checkpoint is created **after** the Git commit and lives outside that commit: a commit cannot contain its own final hash. Its interval index commits to the evidence dependency closure. A reviewer needs the referenced archive files as well as the study repository. Git author/committer dates remain collector assertions, and a valid private chain can still have an undisclosed suffix removed unless its expected checkpoints are independently witnessed.

## Capture and archive pipeline

Maintain separate queues for Git observations, REST metadata, GraphQL discussions, historical backfill, proof maintenance and backup verification. A slow metadata endpoint must not prevent timely Git preservation. Per-repository scheduling and short database transactions prevent a large repository from monopolizing the collector.

Archive each scheduled-slot declaration and attempt start before network work; then archive response/completion records. On restart, an attempt with no completion is explicitly interrupted/unknown. An unavailable host cannot write during its outage: persisted schedule policy and the last durable checkpoint allow the missing expected slots to be identified afterward, without fabricating contemporaneous failure records.

Collection success, scope coverage, attestation state and backup state are independent. An HTTP response can be preserved successfully while its query is incomplete. A Git capture can remain useful while metadata or timestamping is unavailable. Rebuilds must preserve these distinctions.

External proof can use an RFC 3161 timestamp authority or OpenTimestamps. Preserve the exact checkpoint bytes and proof material, record verification status, and keep capture time separate from attestation time. For RFC 3161, verify the message imprint, signature, signer certificate/policy and any requested nonce; for OpenTimestamps, preserve pending and upgraded receipts and verify the Bitcoin attestation. Neither mechanism independently authenticates the claim that GitHub served the recorded bytes. This documented collector trust boundary is accepted for v1. [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html), [OpenTimestamps](https://opentimestamps.org/)

Indefinite retention includes verification material and append-only proof renewal. Preserve timestamp requests/tokens, certificates, available revocation evidence and verification results; a future re-attestation supplements the old record. Long-term trust renewal is explicitly contemplated by RFC 3161. [RFC 3161 section 4](https://www.rfc-editor.org/rfc/rfc3161.html#section-4)

### Git

- Fetch complete reachable history for advertised branches, tags and PR heads; record the default-branch symbolic reference separately. Do not use shallow history as a complete baseline.
- Retain ref advertisements and their individual request intervals. A matching before/after ref map is a consistency check, not proof that the remote stayed unchanged throughout the fetch.
- Represent an annotated tag's peeled target as data associated with the tag, never as a local ref ending in `^{}`.
- Preserve successfully obtained objects even when a ref race makes the overall scope partial. Record which advertised objects could not be acquired.
- Archive an independently restorable baseline and incremental bundles with explicit prerequisite artifact hashes. Keep previously captured history after upstream force pushes or deletions.
- Validate object connectivity and restore the archive dependency closure into an empty repository. Surviving ref names/OIDs alone do not establish that source file bytes survived.
- LFS payloads, submodule repositories, unrelated forks and release binaries require separate collection policy. Git pointers do not archive their external contents.

Incremental bundles require their prerequisite object history; this is an archive dependency, not a standalone snapshot. Periodic full checkpoints are optional and must be justified by measured restore time and growth. [Git bundle documentation](https://git-scm.com/docs/git-bundle)

### GitHub metadata

Capture repository identity and visibility, issues, PRs, comments/reviews, Discussions/categories/comments/replies, and release metadata. Keep stable numeric or GraphQL node IDs and parent relationships. Preserve each response body before parsing, plus a sanitized request descriptor, response status, safe headers, request interval and API/query version.

Use REST Link pagination and GraphQL connection cursors. Discussions, comments and nested replies each require their own pagination/checkpoint state. Include open and closed discussions. A successfully observed disabled Discussions feature differs from an empty complete listing or an access failure. GraphQL can return HTTP 200 with errors or partial data; inspect both `data` and `errors`. [Discussions API](https://docs.github.com/en/graphql/guides/using-the-graphql-api-for-discussions), [GraphQL pagination](https://docs.github.com/en/graphql/guides/using-pagination-in-the-graphql-api), [GraphQL limits](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api)

Initial history is a resumable backfill. Forward polling and periodic reconciliation run separately; do not assume every child comment edit changes its parent's update timestamp. Each scope records requested filters, pages, caps, cursors, completeness and the last successful watermark. A 304 references the exact prior body and matching request/auth/representation context, never an unrelated cached page.

The Events API can supply hints but cannot substitute for Git/metadata capture: it is capped at 300 events within 30 days and may lag by up to six hours. [GitHub Events documentation](https://docs.github.com/en/rest/activity/events)

## Queries and reproducibility

For `first_seen(repository, commit_oid)`, return the earliest preserved supporting Git observation, its capture interval and clock qualification, baseline classification, observation-time refs, manifest/checkpoint, coverage, archive dependencies and attestation status. Source-authored Git timestamps are separate fields.

Index a commit once per repository when first observed. Retain ref tips per observation. Determine branch membership by traversing the **preserved observation-time Git graph**, including ancestors; never equate membership with equality to a tip or inspect today's branch state. Do not materialize every commit × ref × interval combination in SQLite.

For metadata, map each entity/version to its original response artifact and JSON locator. Store the extraction/profile version. A changed full JSON representation can reflect counters or labels; it is not automatically a text edit. Comparisons must name the fields and scopes compared.

Support arbitrary observation-pair and interval queries. Report `not_observed_in_scope` separately from confirmed deletion. Rebuild the index from manifests, attempt/schedule records, raw pages and preserved Git graphs, then compare query results with the original index. An initial baseline establishes that old commits were already observed then; it does not date their first publication.

## SQLite and scheduling policy

### GitHub Actions execution

The workspace includes push/PR validation and a manually triggered libfuse smoke workflow. This tests hosted execution of the current prototype, not a recurring deployment of this design. The smoke uploads temporary seven-day artifacts for transfer to local indefinite storage; no cron schedule is enabled.

Scheduled Actions can supply periodic compute, but hosted jobs start on fresh machines and have a six-hour execution limit. Persist the authoritative archive and a consistent state/database snapshot outside the runner, then restore the needed state for each bounded batch. Actions artifacts/caches have retention or eviction policies and are not the indefinite evidence store. [Hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners), [Actions limits](https://docs.github.com/en/actions/reference/limits), [Artifact retention](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization)

Scheduled runs may be delayed or dropped, so 1–6 hours remains a measured target rather than a guaranteed observation gap. Offset scheduling from the start of the hour, serialize state-changing runs without cancelling active capture, and archive gaps derived from the declared schedule. The manually triggered smoke uses only a read-only workflow token; validate credential/API capacity before expanding beyond the initial target. [Scheduled events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

### Local database and rate handling

Use one local SQLite database initially, with clearly separated `idx_*` evidence/index tables and `op_*` operational tables. Keep original payloads outside SQLite. Enable and verify foreign keys on every connection; use short writes, bounded busy retries and explicit queue leases. WAL supports concurrent readers but still only one writer and requires clients on the same host. [SQLite foreign keys](https://www.sqlite.org/foreignkeys.html#fk_enable), [WAL](https://www.sqlite.org/wal.html)

Start with WAL and `synchronous=FULL` for acknowledged operational writes, subject to working filesystem synchronization. Check that the deployed SQLite runtime contains the documented WAL-reset fix (3.51.3+, or the relevant 3.44.6/3.50.7 backport). These are deployment checks, not settings silently applied by the schema. Use SQLite's backup API for live backups rather than copying only an active `.db` file. [Synchronization](https://www.sqlite.org/pragma.html#pragma_synchronous), [WAL-reset fix](https://www.sqlite.org/wal.html#the_wal_reset_bug), [Backup API](https://www.sqlite.org/backup.html)

REST, GraphQL and Git transfer budgets are separate. Standard authenticated REST access normally has 5,000 requests/hour per user; GraphQL normally has a separate 5,000-point/hour user budget. Authentication method and secondary restrictions matter. Persist cooldowns from response headers and error bodies, honor `Retry-After`/reset times and event polling intervals, and reserve capacity for normal collection before backfill. An extra token for the same user does not create a fresh personal REST budget. [REST limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [GraphQL limits](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api), [Retry guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)

At 185 repositories, the target implies roughly 740–4,440 Git observations per day; API requests and bytes depend on repository sizes and activity. Measure baseline size, daily unique archive growth, metadata row growth, queue latency and backup overhead before committing to a fleet-wide cadence. Warn as the allowance approaches exhaustion, then enforce the hard-cap pause. Do not silently delete retained evidence or conceal budget-induced gaps.

## Verification and implementation gates

Before replacing the starter collector, demonstrate:

1. Ordinary branches, annotated tags and PR heads work; newly observed ancestor commits receive correct repository-level first-seen evidence and branch attribution.
2. A force-pushed-away commit and its source files restore from baseline plus increments, with the working mirror absent and GitHub unreachable.
3. Missing or corrupted blobs, archives, manifests and proof dependencies fail verification; an archive with no expected observations cannot be reported as complete.
4. Process interruption, overlapping jobs, rate exhaustion, pagination drift, GraphQL partial errors and disk pressure produce explicit gaps/partials and safe resumption.
5. A late timestamp proof changes proof status without rewriting the captured observation or its study Git commit.
6. A fresh SQLite index rebuilt solely from archived evidence produces the same first-seen and comparison results.
7. An externally checked checkpoint verifies the study commit and complete referenced archive; pending receipts are never presented as verified attestations.
8. Native streaming XZ restores byte-identical payloads; stored/logical hashes and lengths both verify, corruption/truncation/over-expansion are rejected, and accounting uses stored bytes.
9. Concurrent writers, incompressible payloads, crashes and month rollover cannot exceed the hard cap; audit/proof reserves count within it, and budget pauses preserve existing evidence and produce reconstructable gaps.

The prototype still lacks the first-seen commit query, durable scope scheduling and Discussions collection. The initial libfuse validation work repaired two reproduced defects: annotated tag peel entries are now recorded as metadata instead of invalid refs, and verification checks the Git object graph plus independently restored full bundles. Targeted regression tests cover both. The broader SQLite/XZ/scheduling design is not yet integrated into the collector.

## Remaining decisions

- Which RFC 3161 provider or OpenTimestamps verification setup should be used, and what attestation delay/precision is acceptable? Observation frequency and external attestation completion are different quantities.
- Where is the independent backup, and what separate capacity is available for working/restoration space and extra copies?
