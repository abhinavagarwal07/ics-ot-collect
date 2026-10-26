# Implementation status / production readiness audit

A research paper must not misrepresent this starter as a complete, unattended research-grade observatory. The architecture is the intended rigorous protocol; this repository includes a working small-cohort implementation of critical evidence primitives.

## Implemented and offline-tested

- [x] Stable numeric repository ID and explicit `private=false` checks.
- [x] GitHub pinned REST API version, HTTPS-only allowlist, explicit no-redirect behavior for bearer tokens.
- [x] Raw HTTP bodies in SHA-256 CAS; response metadata includes request start/end, safe headers and status.
- [x] Link-header pagination, duplicate-ID detection and first-page recheck on multi-page feeds.
- [x] GitHub's numeric-repository pagination links are accepted while preserving repository and endpoint continuity checks.
- [x] Updated-item delta with configurable 48h overlap and last successful completed run cursor.
- [x] Public Git refs observed and pinned to permanent local `refs/archive/` namespace, with ref-set stability test.
- [x] Annotated tags retain their tag-object and peeled-target IDs without creating invalid peeled pseudo-refs.
- [x] Git verification runs full object-graph checks and restores optional full bundles into empty repositories without upstream access.
- [x] Append-only, create-only canonical run manifests, SHA-256 chain links including partial runs.
- [x] CLI verification and fully regenerable observation CSV.
- [x] Original initial OpenTimestamps proof kept separately when `ots` is present.
- [x] Offline tests for immutable bytes, tamper detection, page drift, URL boundary, manifest chain and reproducible data extraction.
- [x] Legacy API failures become partial runs without advancing their combined cursor. Persistent mode advances only independently successful scope cursors after immutable finalization; deferred captures retain frozen query options.
- [x] Independent durable API/Git queues with leases, attempt telemetry and finalization-only retries; resumable raw-response/page/item checkpoints.
- [x] Baseline plus incremental/refs-only Git CAS archives, explicit prerequisites, crash-safe capture replay, independent offline restoration and encrypted per-capture transfers.

## Blockers before unattended production data collection

**P0 — implement before making strong scientific completeness/timing claims**

- [x] Persistent SQLite repository/lane queue and individual API page/item-scope checkpoints. Deep scopes resume within their durable capture; a separate research metadata database remains future work.
- [ ] Full rate-limit controller: primary/secondary budget, `Retry-After` (seconds AND HTTP-date), `X-RateLimit-Reset`, `X-Poll-Interval`, adaptive polling, separate concurrency caps. Current client has bounded retries, but not a full policy controller.
- [x] Explicit resumable endpoint outcomes, including complete, failed, capped, non-atomic, not attempted and deferred results, with scope-specific watermarks and no false deletion inferences.
- [ ] PR commits/files **cap handling** (PR commit listing 250, files 3000), fallback to validated Git graph/compare. Starter now aborts and flags partial when known PR totals exceed caps; full alternative must be added.
- [ ] NTP/chrony offset/uncertainty collection and wall-clock health gates; host clock alone is insufficient for tight time claims.
- [ ] Automated off-host immutable/WORM replication **and restore audits**, explicit retention and access separation. The baseline transfers encrypted Release assets; persistent mode can emit encrypted local transfers, which alone are not an off-host backup.
- [ ] Scheduled integrity/restore audits, off-host packfile backup verification and race/backfill handling after force pushes. On-demand mirror `fsck` and full-bundle restoration are implemented.
- [ ] Full explicit repository rename/transfer handling by stable numeric ID, with immutable cohort-amendment record. Current implementation fails closed and requires manual config amendment.
- [ ] Immutable publication of checkpoint digests to an independent witness. Private hash-chains can be discarded/replaced until witnessed.
- [ ] Integration fault-injection tests for rate limits, 429, 403, GitHub 301, partial pages, token leakage, crash-before-manifest, and OTS calendar outages.
- [ ] Run in an isolated container/VM with pinned dependencies + image digest; document collector code SHA, clock provider and build provenance in every manifest.

**P1 — required for comprehensive disclosure/patch propagation study**

- [ ] Public-auth scope audit, paired anonymous fetches for a stratified sample; prevent data inadvertently visible only to a privileged logged-in investigator.
- [ ] Separate durable `issue timeline`, `issue events`, `PR reviews/comments`, `PR head edits`, `PR file` and `release asset` completeness ledgers.
- [ ] Preserve release asset **bytes** (not just release metadata) with size caps/permissions, package registry artifact hashes, build configurations, firmware versions, CISA/KEV/GHSA/vendor advisory captures.
- [ ] Independent ingestion from GH Archive, Software Heritage visit snapshots and independent second collector host; record their own sampling gaps.
- [ ] SQL/Parquet versioned entities with explicit stable IDs, reconciliation stats, per-record original raw hash and time interval.
- [ ] Offline third-party verification packaging (manifest, referenced CAS blobs, preserved Git pack, OTS receipts, verification tool, expected results).
- [ ] Stratified cohort registry, frozen preregistration, exclusion and adjudication logs, empirical patch-validation workflow.

**P2 — useful research operations**

- [ ] Dashboard of per-endpoint last complete timestamps, budgets, missing jobs, proof upgrade progress, restoration state and clock errors.
- [ ] Multi-host collector consensus or periodic independent signed checkpoint comparison.
- [ ] Automatic evidence bundles for publication and Zenodo/OSF deposit with ethics/privacy review.
- [ ] Backup key management, signature rotation, retention change audit and recovery of orphaned CAS objects.

## Explicit caveats in current implementation

- `mode=full` collects all current issue/PR lists, repo-level comments, tags and releases, but **does not** retrieve every historical issue timeline/PR detail unless `--deep-full` is passed. This is recorded as NOT_COLLECTED. `mode=delta` retrieves deep details for updated issues/PRs, not an exhaustive past audit.
- `mode=events` collects a bounded GitHub Events API window, NOT a complete event log; the program currently relies on operator scheduling rather than enforcing `X-Poll-Interval` itself.
- No authenticated collaborator/private data should be collected. Use a read-only public-only credential and validate anonymous visibility separately.
- Git advertised refs and fetch occur separately; a mismatch marks collection partial. A `git ls-remote` ref list is not a signed statement from GitHub.
- Manifest timestamps come from the collector host clock; their precision does NOT establish trusted external clock accuracy.
- The current source does not automatically notarize locally failed identity lookup quarantine files; preserve and timestamp these using a future site-wide failure ledger.
