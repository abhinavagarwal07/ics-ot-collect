# SQLite metadata schema

Status: executable **draft**, version 1, not connected to the existing collector. [metadata.sql](../schema/metadata.sql) creates a fresh database; it is not a migration. See [DESIGN.md](DESIGN.md) for capture, storage and verification behavior.

## Model

The database indexes an external immutable evidence archive with indefinite retention. Large HTTP bodies, Git bundles, manifests and timestamp proofs are files, normally XZ-compressed, not SQLite BLOBs. Logical SHA-256 identity covers the exact original bytes; stored representations have their own hashes and sizes. `idx_*` rows are reproducible projections of those files and the evidence journal. `op_*` rows are mutable work-management state. Losing the database must not erase original observations, schedule policy, failed-attempt records or proofs.

| Tables | Responsibility |
|---|---|
| `idx_artifact`, `idx_artifact_storage`, `idx_capture_policy` | Original-byte identity, physical compressed representations and immutable collection/budget configuration |
| `idx_repository`, `idx_repository_name` | Stable GitHub identity and observed name/visibility history |
| `idx_journal_record`, `idx_manifest` | Attempt/configuration/failure journal and per-repository manifest chains |
| `idx_schedule_slot`, `idx_capture`, `idx_scope_coverage` | Expected work, actual attempts, clock information and independently qualified coverage |
| `idx_http_response` | REST/GraphQL request descriptors, original responses, safe headers and conditional-body reuse |
| `idx_git_snapshot`, `idx_git_ref`, `idx_commit_first_seen` | Observation-time ref maps and earliest supporting observation per repository/commit |
| `idx_git_archive`, `idx_git_archive_dependency`, `idx_git_snapshot_archive` | Portable baselines/increments, prerequisite objects and snapshot restoration roots |
| `idx_entity`, `idx_entity_observation` | Issues, PRs, comments, reviews, Discussions/replies and releases; stable identity and reproducible response locations |
| `idx_study_checkpoint`, `idx_checkpoint_manifest`, `idx_attestation` | Study Git commits bound to interval indexes/journal cutoffs, member manifests and proof lifecycle events |
| `op_job`, `op_rate_bucket` | Leased work, cursors, retries and persistent service/authentication cooldowns |

The 24 tables separate facts that have different lifetimes and trust properties. A single repository/interval `success` flag would lose necessary information about incomplete metadata, retained Git objects and pending external proofs.

## Key conventions

- Timestamps use integer UTC microseconds. Clock validity and uncertainty remain explicit; unknown uncertainty is `NULL`, never zero. Monotonic elapsed time, when available, measures request duration despite wall-clock changes. Journal ordinals determine record order independently of wall-clock readings.
- Repository IDs are stable GitHub numeric IDs. Names and URLs belong to observations. Entity IDs are typed GitHub database IDs or GraphQL node IDs, not titles or usernames; normalize consistently to avoid duplicate REST/GraphQL representations.
- Git object IDs use their declared `sha1` or `sha256` format. SHA-256 archive hashes are a different identifier type. Annotated-tag peeled targets are fields on tag rows.
- `idx_artifact.sha256` and `byte_length` describe original uncompressed bytes. `idx_artifact_storage` records `stored_sha256`, `stored_byte_length`, encoding (default `xz`), relative path and archive time. Multiple representations may reference one logical artifact; representation rows are immutable. `identity` supports uncompressed study metadata and compatibility.
- A capture is an individual HTTP request or Git observation. A manifest groups captures and scope outcomes; it is not an atomic remote snapshot.
- Scope keys identify the exact endpoint/filter/parent-connection partition. For Discussions, each comments/replies connection needs its own cursor. The full scope descriptor and API/query version are archived.
- `complete` means complete for the declared scope under its documented consistency qualifications. It never means every publicly accessible GitHub object was observed. Disabled features, missing access, caps, partial responses and unpolled scopes remain distinguishable.
- The 50 GB/month hard cap counts unique stored representation bytes by first archive time in each UTC calendar month, including baseline evidence and reserved audit/proof capacity. `idx_capture_policy` requires `budget_mode='hard_cap'` and `budget_exhaustion_action='pause_collection'`. The future archive writer/scheduler must reserve capacity and pause before exceeding the cap; this schema alone does not enforce aggregate admission. Index replay can still record historical/imported oversize evidence truthfully. No schema trigger deletes evidence or imposes a 50 GB per-file limit; backup and working-space capacity are separate decisions.

## First-observed commit query

The first-seen index identifies the earliest supporting observation *within one repository*, including ancestor commits. It is populated by replaying archived snapshots and their preserved graphs, not by trusting author/committer dates.

```sql
SELECT f.commit_oid, f.first_seen_class, f.snapshot_id,
       c.request_started_at_us, c.request_finished_at_us,
       c.clock_validity, c.clock_uncertainty_us,
       c.manifest_sha256, s.object_coverage
FROM idx_commit_first_seen AS f
JOIN idx_git_snapshot AS s ON s.snapshot_id = f.snapshot_id
JOIN idx_capture AS c ON c.capture_id = s.capture_id
WHERE f.repository_id = :repository_id AND f.commit_oid = :commit_oid;
```

Then load candidate observation-time refs:

```sql
SELECT refname, ref_kind, tip_oid, tip_object_type,
       peeled_target_oid, peeled_target_type
FROM idx_git_ref
WHERE snapshot_id = :snapshot_id;
```

Restore the snapshot's archive dependency closure and test reachability from its commit-valued tips in Git. An ancestor can belong to several branches without equaling any tip. Preserve PR-head and tag attribution as such; a PR ref is not automatically a normal branch. Baseline membership means already present at initial observation. Unknown/invalid clocks permit ordinal first-observation reporting but not an unsupported precise UTC ordering.

For issues/discussions, join `idx_entity_observation` to `idx_capture`, ordered by qualified observation time/journal order. The original body hash, JSON pointer and extraction-profile version permit re-extraction. A representation hash indicates a representation change; classification as a body edit requires a defined field projection. Different extraction profiles must not be compared as though they were identical.

## Constraints and verifier responsibilities

SQL enforces key relationships, same-repository associations, ordered manifest/journal/checkpoint predecessors, Git archive dependency ordering, declared prerequisite counts for a complete indexed closure, compatible Git object formats, matching HTTP 304 representation/body references, safe header names, and proof lifecycle field requirements. GraphQL HTTP 200 alone never grants complete coverage.

SQL cannot establish that:

- an external file actually exists, matches its stored hash/size and decompresses to the declared logical hash/size;
- a bundle contains the declared prerequisite/object graph or restores every source blob;
- an indexed first-seen row is truly the earliest supported capture;
- an entity JSON pointer and representation hash match its archived response;
- an interval index names exactly all required records, or no witnessed history was withheld;
- a proof is cryptographically valid, sufficiently confirmed, or authenticates GitHub origin.

Those checks belong to archive replay and verification. Structural `closure_status=complete` is not a successful restoration result. An `idx_attestation` row records a verifier outcome whose underlying proof and verification evidence must be independently checked.

## Write, recovery and upgrade rules

1. Persist archive bytes and immutable journal records before acknowledging an observation. An index transaction follows; replay repairs an index crash. A failed archive write is not a successful capture.
2. Finalized manifests can then be indexed with captures and derived entities. Attempt-start records without final manifests remain represented in the journal; they are not fabricated as completed captures.
3. Update schedule-slot projections only from new archived resolution records. Persist rate-limit evidence before deriving operational cooldowns. On recovery, rebuild applicable cooldowns before resuming requests.
4. Claim jobs with short atomic transactions and expiring leases. A lease expiry permits recovery, not duplicate evidence overwrite. Scope cursors advance only after the relevant page is durably preserved and validated.
5. Finalize the study Git commit first, then archive its SHA-256 checkpoint; proofs and later proof upgrades are appended afterward. Checkpoint/member indexes must agree with the archived interval index and journal cutoff.
6. Rebuild into a fresh database and verify it before replacement. The schema includes selected append-only guards, but the archive/verifier supplies the evidence guarantee; database triggers do not protect against its administrator.

Use foreign keys on **every connection**, JSON1 support and a fixed SQLite runtime. WAL/durability/backup choices are documented in [DESIGN.md](DESIGN.md); loading this schema does not configure a production database or start collection.

## Validation boundary

[test_schema.py](../tests/test_schema.py) exercises synthetic baseline/delta histories, ancestry-based attribution inputs, cross-repository rejection, chain prerequisites, partial collection, conditional responses, entity versions, missed slots, rate state, study checkpoints and logical/compressed artifact accounting. These are relational contract tests, with small native XZ fixtures. They do not replace production streaming-codec, end-to-end Git restoration, archive replay, live GitHub pagination, or timestamp cryptographic verification tests.
