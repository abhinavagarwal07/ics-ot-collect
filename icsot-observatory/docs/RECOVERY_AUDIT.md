# Local one-time recovery audit

The local watcher waits for the complete 185-repository baseline, then performs
one mechanical recovery audit. A completed workflow alone never opens the gate.
The final published inventory must match the exact CSV/config bytes and ordered
cohort, contain 185 accepted rows with no incomplete rows, and reference only the
explicit approved parent lineage. Two observations of the same inventory digest,
at least 60 seconds apart, are required. The final run must have terminated and
its source SHA must match the inventory.

The currently approved order is:

1. `corpus-baseline-40294818409-1` — final eight-worker resume.
2. `corpus-baseline-40275429320-1` — previous collection and first-observation attempts.
3. `corpus-baseline-40253057671-1` — earlier retained parent.
4. `corpus-baseline-40249527444-1` — earliest explicit parent.

The watcher never dispatches workflows, publishes or modifies releases, changes
repository settings, uploads keys, or starts an AI/API session. It performs GETs
through the existing local `gh` authentication. The existing encryption codec
alone receives the local RSA private-key path; the watcher never reads, logs,
copies, or uploads private-key contents. The default machine path is supplied
explicitly by the local launcher as `~/.ssh/id_rsa`.

## Exact coverage

Every capture index in every approved release is inventoried, including failed
API attempts and recoverable partial captures. Selected final rows are checked
against the actual source-index bytes, source collector commit, original release,
manifest summary, and encrypted migration references. Indexes and immutable
migration records are retained as identities in the report; inherited evidence
is never attributed to a later collector checkout.

For every indexed baseline part that has an encrypted transport, the audit
downloads one ciphertext part at a time through the shared bounded writer and
verifies ciphertext length/SHA-256, recipient binding, plaintext length/SHA-256,
and AES-GCM authentication. This independent pass includes all available parts
even if an earlier part is corrupt or its TAR prefix is incomplete. Missing or
unsupported transports remain explicit gaps.

When all required parts are present, a second streaming pass validates the
complete XZ stream and TAR structure without extracting the corpus. Every regular
member is hashed; every CAS object is checked against its content-addressed
filename. The audit checks canonical manifests, source-index identity, predecessor
links, raw-response CAS lengths, full-bundle ref/OID headers and absence of full
bundle object prerequisites, and portable descriptor/prerequisite dependencies.
The report records a deterministic digest of the sorted member/hash inventory.

Malformed raw API JSON, failed HTTP responses, declared unavailable API scopes,
capability reasons, and recorded decode failures remain evidence. They are
reported separately from successful listing coverage. JSON parsing is bounded to
16 MiB per raw object; larger responses remain byte-verified and explicitly
unparsed. Metadata capture and individual Git ref-header parsing each have a
64 MiB bound. Crossing a bound produces an explicit audit failure, never a silent
complete result.

Missing parts or a declared incomplete XZ/TAR prefix are coverage gaps. Their
authenticated surviving ciphertext is preserved as a partial attempt; a known
prefix is never described as accepted-capture corruption. Payload integrity
failures, unavailable GETs, and scientific incompleteness have distinct result
classes. Unavailable GETs retain resumable checkpoints and retry; they cannot
produce the final once-only completion marker.

Orphan release assets are inventoried by name, ID, server digest, size, and state
without speculative payload downloads. Migrated legacy Actions ZIP containers
have a separate inventory with their original migration/ciphertext references.
When both declared ciphertext and seekable plaintext fit the shared budget,
their envelope is authenticated, the existing codec decrypts a temporary ZIP,
and every ZIP member is streamed through CRC and SHA-256 verification without
extraction. The central directory is capped at 16 MiB, paths/duplicates/links and
special files are rejected, and the expanded total is capped at 1 TiB. Nested
payloads are hashed as ZIP members; they are not recursively restored. Containers
that do not fit admission remain explicitly deferred and metadata-only. ZIP64
directory layouts are separately deferred rather than passed to an unbounded
directory loader.

## Hard local disk ceiling

All cooperating viewer/audit processes use exactly:

`/Users/abhinavagarwal/Documents/work/ics-ot-collect/analysis/local-data-budget`

The shared ceiling is **2,000,000,000 bytes**, including existing task evidence,
downloads, caches, report files, temporary files, image storage, and mounted
filesystem allocation. The entire workspace is a registered root. Existing
evidence is counted and never evicted. Only helper-owned temporary/cache copies
are cleanup candidates. The separate initial 100 GB remote corpus allowance does
not raise this local ceiling. No Docker or full corpus extraction is used.

Ordinary Git output cannot be bounded by polling or a file-size limit. Therefore
full restore/fsck samples use an owned, fixed-size **256 MiB** case-sensitive HFS+
UDRW image on macOS. The image plus its mounted allocation and overhead are
reserved before creation. Spotlight is disabled. Attach and cleanup validate the
exact owned image, mount, and device identity. All Git HOME, TMPDIR, cache,
configuration, and restored files stay on that volume; remote protocols and hooks
are disabled. The enforced filesystem capacity produces ENOSPC instead of
unbounded host writes. The image is created only after encrypted part staging has
closed. Cleanup detaches only the verified owned device and removes only the
owned image. Ownership uncertainty or detach failure preserves the image and its
reservation for local review.

The deterministic sample admits full bundles at most 16 MiB and greedily covers
source release, repository role, accepted/partial outcome, native/migrated
transport, and size strata, with an SHA-256 tie-break. The default maximum is 12
samples. Each sample restores into an empty offline repository, verifies the
bundle, fetches it, runs `git fsck --full --no-reflogs`, and checks declared refs,
objects, and annotated-tag peeled targets. A full or failed volume is reported
as an unverified sample. Large Git graphs and all unsampled graphs are explicitly
**not fully restored or fscked**; byte/hash checks are not described as graph
validation.

## Timestamp limits

Archived OTS receipts are hashed and, when the pinned OTS dependency is available,
inspected offline for structure and SHA-256 subject binding. Initial receipt
provenance is checked against its manifest and receipt digest. Pending receipts
remain pending. A Bitcoin block attestation remains unverified without a trusted,
synchronized Bitcoin Core node. The audit performs no Bitcoin network/node
verification and never promotes attestation presence into verified Bitcoin time.
RFC 3161 files are byte-inventoried; no fresh TSA request is sent.

## Run and persistence

Use the already prepared local Python with project encryption dependencies and
`opentimestamps-client==0.7.2`. Root coordinates the persistent launcher after code
review and native-image QA. A metadata-only readiness check needs no key path:

```sh
python scripts/watch_corpus_ready.py \
  --repository abhinavagarwal07/ics-ot-collect \
  --approved-release-tag corpus-baseline-40294818409-1 \
  --approved-release-tag corpus-baseline-40275429320-1 \
  --approved-release-tag corpus-baseline-40253057671-1 \
  --approved-release-tag corpus-baseline-40249527444-1 \
  --report-root ../analysis/recovery-audit-40294818409 \
  --check-only
```

For the standing local watcher, omit `--check-only` and supply
`--private-key ~/.ssh/id_rsa`. The script's default workspace and budget paths are
resolved from its installed checkout, including when launched from the package
directory. Redirect background stdout/stderr to `/dev/null`; persistent status
already lives in bounded JSON files, so an unbounded launcher log is unnecessary.
Do not install or dispatch this private-key workflow in GitHub Actions.

The watcher holds an exclusive local lock, persists its exact approved request,
and refuses to reuse a report directory for a changed request. States distinguish
waiting, stabilizing, auditing, retry waiting, and mechanical completion.
Per-capture JSON checkpoints allow an interrupted process to resume without
discarding completed evidence checks. The completion marker hashes the final
report and is accepted only if those exact report bytes still exist. Completed
results are not automatically rerun. A local service manager may restart the
same approved command after host/app restart.

Outputs under the selected report root are:

- `watcher-state.json`: current gate/audit state and completion identity.
- `captures/<capture-key>.json`: each retained attempt's exact source and result.
- `recovery-audit.json`: complete mechanical report, selection, provenance,
  limitations, and budget snapshot.
- `RECOVERY_REVIEW.md`: concise human review with counts and explicit gaps.

The marker explicitly says **GPT review pending**. Mechanical completion does
not invent an AI review. Root resumes the existing requested GPT-6.1-sol xhigh
delegate to inspect the actual finished report and perform the final evidence
review. If the app restarts, that model review remains pending until resumed;
the local mechanical trigger and reports persist independently.
