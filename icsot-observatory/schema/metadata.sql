-- DRAFT schema, version 1. NOT connected to the prototype collector or CLI.
-- SQLite is a rebuildable index, never the only evidence store. Original bytes,
-- manifests, sanitized request descriptors, portable Git archives, and timestamp
-- proofs live outside SQLite in a SHA-256 CAS. An external append-only evidence
-- journal records declarations, observations, failures, and later resolutions.
-- Retain archived evidence indefinitely. Native XZ is the default physical
-- encoding; original logical-byte hashes remain stable across recompression.
-- idx_* tables index those immutable archive facts; op_* tables are disposable,
-- mutable scheduling state. Rebuild indexes from the archive/journal on change.
--
-- Every connection MUST execute PRAGMA foreign_keys = ON before a transaction.
-- WAL, synchronous mode, backups, and busy_timeout are deployment settings, not
-- schema settings. Use integer UTC microseconds throughout; NULL clock uncertainty
-- means unknown, never zero. Git OIDs are lowercase SHA-1 or SHA-256, not SHA-256
-- CAS keys. Cryptographic validity and Git reachability require offline verification.
-- Preserve reversed wall-clock readings when the clock is invalid or unknown;
-- monotonic elapsed time, when available, is independent of those UTC readings.
-- JSON1 is required. No table stores raw response, Git, or proof BLOBs.
PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

-- All evidence links elsewhere in this schema target the ORIGINAL logical bytes.
-- Compression is a physical storage concern, never a change to a manifest/body/
-- bundle/proof identity. Cataloging a logical artifact alone does not establish
-- that its physical representation exists or that archive closure is complete.
CREATE TABLE idx_artifact (
    sha256 TEXT PRIMARY KEY NOT NULL CHECK(length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    byte_length INTEGER NOT NULL CHECK(typeof(byte_length) = 'integer' AND byte_length >= 0),
    media_type TEXT
);
CREATE TRIGGER idx_artifact_no_update BEFORE UPDATE ON idx_artifact
BEGIN SELECT RAISE(ABORT, 'logical artifact identity is immutable; rebuild from archived facts'); END;

-- A physical representation is deduplicated by its STORED-byte digest, regardless
-- of how often observations reference its logical artifact. Multiple XZ streams
-- (including recompressions) or an identity copy may represent the same original
-- bytes. Identity is permitted for readable study Git metadata/compatibility.
-- Paths refer to stored bytes; never assume the logical hash is the stored hash.
-- The offline verifier hashes/sizes stored bytes, natively decompresses XZ when
-- needed, then hashes/sizes decoded bytes against idx_artifact. SQL checks only
-- relationships/metadata; it does not validate compression or filesystem contents.
CREATE TABLE idx_artifact_storage (
    stored_sha256 TEXT PRIMARY KEY NOT NULL CHECK(length(stored_sha256) = 64 AND stored_sha256 NOT GLOB '*[^0-9a-f]*'),
    logical_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    stored_byte_length INTEGER NOT NULL CHECK(typeof(stored_byte_length) = 'integer' AND stored_byte_length >= 0),
    encoding TEXT NOT NULL DEFAULT 'xz' CHECK(encoding IN ('xz', 'identity')),
    archive_relpath TEXT NOT NULL UNIQUE CHECK(
        length(archive_relpath) > 0 AND substr(archive_relpath, 1, 1) <> '/'
        AND archive_relpath NOT IN ('.', '..')
        AND instr('/' || archive_relpath || '/', '/../') = 0
        AND instr('/' || archive_relpath || '/', '/./') = 0
        AND instr(archive_relpath, '//') = 0 AND instr(archive_relpath, '\') = 0
        AND instr(archive_relpath, char(0)) = 0),
    first_archived_at_us INTEGER NOT NULL CHECK(typeof(first_archived_at_us) = 'integer' AND first_archived_at_us >= 0),
    CHECK(encoding <> 'identity' OR stored_sha256 = logical_sha256)
);
CREATE INDEX idx_artifact_storage_logical ON idx_artifact_storage(logical_sha256);
CREATE TRIGGER idx_artifact_storage_identity_size BEFORE INSERT ON idx_artifact_storage
WHEN NEW.encoding = 'identity' AND NEW.stored_byte_length <>
    (SELECT byte_length FROM idx_artifact WHERE sha256 = NEW.logical_sha256)
BEGIN SELECT RAISE(ABORT, 'identity representation must preserve logical byte length'); END;
CREATE TRIGGER idx_artifact_storage_no_update BEFORE UPDATE ON idx_artifact_storage
BEGIN SELECT RAISE(ABORT, 'stored representation metadata is immutable; append recompressions as new representations'); END;

-- The complete canonical configuration/policy is the referenced CAS artifact.
-- The budget is an aggregate of newly archived UNIQUE STORED representations
-- under the archived accounting policy, NOT logical/decompressed bytes, an
-- artifact-size CHECK, or a deletion trigger. Retention is indefinite; initial
-- baseline evidence counts unless explicitly amended. Backup capacity is separate.
-- HARD CAP: future scheduler/archive admission reserves bytes before new writes
-- within the UTC calendar month, including its configured maintenance/audit
-- reserve. Exhaustion pauses new collection and records the pause; never delete
-- evidence or automatically raise the limit. Resume next period or under an
-- explicit archived policy amendment. Reserve sizing/admission are not implemented
-- by this schema. Replay/import of existing over-budget facts must remain possible.
CREATE TABLE idx_capture_policy (
    policy_sha256 TEXT PRIMARY KEY NOT NULL REFERENCES idx_artifact(sha256),
    policy_version TEXT NOT NULL CHECK(length(policy_version) > 0),
    declared_at_us INTEGER NOT NULL CHECK(typeof(declared_at_us) = 'integer' AND declared_at_us >= 0),
    git_cadence_us INTEGER NOT NULL CHECK(typeof(git_cadence_us) = 'integer' AND git_cadence_us > 0),
    monthly_new_evidence_budget_bytes INTEGER NOT NULL CHECK(
        typeof(monthly_new_evidence_budget_bytes) = 'integer' AND monthly_new_evidence_budget_bytes > 0),
    budget_mode TEXT NOT NULL DEFAULT 'hard_cap' CHECK(budget_mode = 'hard_cap'),
    budget_exhaustion_action TEXT NOT NULL DEFAULT 'pause_collection' CHECK(budget_exhaustion_action = 'pause_collection'),
    accounting_policy_json TEXT NOT NULL CHECK(json_valid(accounting_policy_json) AND json_type(accounting_policy_json) = 'object')
);

CREATE TABLE idx_repository (
    repository_id INTEGER PRIMARY KEY CHECK(typeof(repository_id) = 'integer' AND repository_id > 0),
    github_node_id TEXT UNIQUE,
    registered_at_us INTEGER NOT NULL CHECK(typeof(registered_at_us) = 'integer' AND registered_at_us >= 0)
);

-- Index of externally archived, append-only journal records. Sequence and prior
-- digest bind an ordered journal, including events with no completed manifest.
CREATE TABLE idx_journal_record (
    record_sha256 TEXT PRIMARY KEY NOT NULL REFERENCES idx_artifact(sha256),
    sequence INTEGER NOT NULL UNIQUE CHECK(typeof(sequence) = 'integer' AND sequence > 0),
    previous_sequence INTEGER,
    previous_record_sha256 TEXT,
    repository_id INTEGER REFERENCES idx_repository(repository_id),
    event_kind TEXT NOT NULL CHECK(length(event_kind) > 0),
    recorded_at_us INTEGER NOT NULL CHECK(typeof(recorded_at_us) = 'integer' AND recorded_at_us >= 0),
    UNIQUE(sequence, record_sha256),
    UNIQUE(record_sha256, repository_id),
    CHECK((sequence = 1 AND previous_sequence IS NULL AND previous_record_sha256 IS NULL)
       OR (sequence > 1 AND previous_sequence IS NOT NULL AND previous_sequence = sequence - 1 AND previous_record_sha256 IS NOT NULL)),
    FOREIGN KEY(previous_sequence, previous_record_sha256)
        REFERENCES idx_journal_record(sequence, record_sha256)
);
CREATE TRIGGER idx_journal_record_no_update BEFORE UPDATE ON idx_journal_record
BEGIN SELECT RAISE(ABORT, 'journal index is append-only; rebuild from archived journal'); END;
CREATE TRIGGER idx_journal_record_no_delete BEFORE DELETE ON idx_journal_record
BEGIN SELECT RAISE(ABORT, 'journal index is append-only; rebuild from archived journal'); END;

CREATE TABLE idx_manifest (
    manifest_sha256 TEXT PRIMARY KEY NOT NULL REFERENCES idx_artifact(sha256),
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    ordinal INTEGER NOT NULL CHECK(typeof(ordinal) = 'integer' AND ordinal > 0),
    previous_ordinal INTEGER,
    previous_manifest_sha256 TEXT,
    policy_sha256 TEXT NOT NULL REFERENCES idx_capture_policy(policy_sha256),
    evidence_record_sha256 TEXT NOT NULL,
    run_id TEXT NOT NULL CHECK(length(run_id) > 0),
    run_started_at_us INTEGER NOT NULL CHECK(typeof(run_started_at_us) = 'integer' AND run_started_at_us >= 0),
    run_finished_at_us INTEGER NOT NULL CHECK(typeof(run_finished_at_us) = 'integer' AND run_finished_at_us >= 0),
    finalized_at_us INTEGER NOT NULL CHECK(typeof(finalized_at_us) = 'integer' AND finalized_at_us >= 0),
    capture_status TEXT NOT NULL CHECK(capture_status IN ('succeeded', 'partial', 'failed')),
    clock_validity TEXT NOT NULL CHECK(clock_validity IN ('valid', 'invalid', 'unknown')),
    clock_uncertainty_us INTEGER CHECK(clock_uncertainty_us IS NULL OR (typeof(clock_uncertainty_us) = 'integer' AND clock_uncertainty_us >= 0)),
    clock_evidence_sha256 TEXT REFERENCES idx_artifact(sha256),
    provenance_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    UNIQUE(repository_id, ordinal),
    UNIQUE(repository_id, ordinal, manifest_sha256),
    UNIQUE(manifest_sha256, repository_id),
    UNIQUE(manifest_sha256, repository_id, policy_sha256),
    UNIQUE(repository_id, run_id),
    CHECK(clock_validity <> 'valid' OR clock_uncertainty_us IS NOT NULL),
    CHECK(clock_validity <> 'valid' OR (run_finished_at_us >= run_started_at_us AND finalized_at_us >= run_finished_at_us)),
    CHECK((ordinal = 1 AND previous_ordinal IS NULL AND previous_manifest_sha256 IS NULL)
       OR (ordinal > 1 AND previous_ordinal IS NOT NULL AND previous_ordinal = ordinal - 1 AND previous_manifest_sha256 IS NOT NULL)),
    FOREIGN KEY(repository_id, previous_ordinal, previous_manifest_sha256)
        REFERENCES idx_manifest(repository_id, ordinal, manifest_sha256),
    FOREIGN KEY(evidence_record_sha256, repository_id)
        REFERENCES idx_journal_record(record_sha256, repository_id)
);

-- Expected slots are archive facts declared under a particular policy. Resolution
-- is derived from a later archived journal record; pending slots have no resolution.
-- A missed slot may have a gap manifest, but does not require a fabricated capture.
CREATE TABLE idx_schedule_slot (
    slot_id TEXT PRIMARY KEY NOT NULL CHECK(length(slot_id) > 0),
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    policy_sha256 TEXT NOT NULL REFERENCES idx_capture_policy(policy_sha256),
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('git', 'http')),
    scope_key TEXT NOT NULL CHECK(length(scope_key) > 0),
    scheduled_at_us INTEGER NOT NULL CHECK(typeof(scheduled_at_us) = 'integer' AND scheduled_at_us >= 0),
    due_by_us INTEGER NOT NULL CHECK(typeof(due_by_us) = 'integer' AND due_by_us >= scheduled_at_us),
    declaration_record_sha256 TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT 'pending' CHECK(resolution IN ('pending', 'attempted', 'missed', 'cancelled')),
    resolution_record_sha256 TEXT,
    resolved_at_us INTEGER CHECK(resolved_at_us IS NULL OR (typeof(resolved_at_us) = 'integer' AND resolved_at_us >= scheduled_at_us)),
    gap_reason TEXT,
    UNIQUE(repository_id, policy_sha256, scope_kind, scope_key, scheduled_at_us),
    UNIQUE(slot_id, repository_id, policy_sha256, scope_kind, scope_key),
    CHECK((resolution = 'pending' AND resolution_record_sha256 IS NULL AND resolved_at_us IS NULL AND gap_reason IS NULL)
       OR (resolution <> 'pending' AND resolution_record_sha256 IS NOT NULL AND resolved_at_us IS NOT NULL)),
    CHECK(resolution NOT IN ('missed', 'cancelled') OR (gap_reason IS NOT NULL AND length(gap_reason) > 0)),
    FOREIGN KEY(declaration_record_sha256, repository_id) REFERENCES idx_journal_record(record_sha256, repository_id),
    FOREIGN KEY(resolution_record_sha256, repository_id) REFERENCES idx_journal_record(record_sha256, repository_id)
);

-- One capture is one attempted Git observation or HTTP request. Retries are new
-- rows. A run can contain many captures with different intervals and outcomes.
-- auth_context is a non-secret public/anonymous or credential-bucket label only.
CREATE TABLE idx_capture (
    capture_id TEXT PRIMARY KEY NOT NULL CHECK(length(capture_id) > 0),
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    manifest_sha256 TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL REFERENCES idx_capture_policy(policy_sha256),
    evidence_record_sha256 TEXT NOT NULL,
    slot_id TEXT,
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('git', 'http')),
    scope_key TEXT NOT NULL CHECK(length(scope_key) > 0),
    collection_phase TEXT NOT NULL CHECK(collection_phase IN ('baseline', 'prospective', 'backfill')),
    source_uri TEXT NOT NULL CHECK(length(source_uri) > 0),
    scheduled_at_us INTEGER CHECK(scheduled_at_us IS NULL OR (typeof(scheduled_at_us) = 'integer' AND scheduled_at_us >= 0)),
    request_started_at_us INTEGER NOT NULL CHECK(typeof(request_started_at_us) = 'integer' AND request_started_at_us >= 0),
    request_finished_at_us INTEGER NOT NULL CHECK(typeof(request_finished_at_us) = 'integer' AND request_finished_at_us >= 0),
    monotonic_elapsed_us INTEGER CHECK(monotonic_elapsed_us IS NULL OR (typeof(monotonic_elapsed_us) = 'integer' AND monotonic_elapsed_us >= 0)),
    capture_status TEXT NOT NULL CHECK(capture_status IN ('succeeded', 'partial', 'failed')),
    error_class TEXT,
    error_detail TEXT,
    auth_context TEXT NOT NULL CHECK(length(auth_context) > 0),
    provenance_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    clock_validity TEXT NOT NULL CHECK(clock_validity IN ('valid', 'invalid', 'unknown')),
    clock_uncertainty_us INTEGER CHECK(clock_uncertainty_us IS NULL OR (typeof(clock_uncertainty_us) = 'integer' AND clock_uncertainty_us >= 0)),
    clock_evidence_sha256 TEXT REFERENCES idx_artifact(sha256),
    UNIQUE(capture_id, repository_id),
    UNIQUE(capture_id, repository_id, scope_kind),
    CHECK(clock_validity <> 'valid' OR clock_uncertainty_us IS NOT NULL),
    CHECK(clock_validity <> 'valid' OR request_finished_at_us >= request_started_at_us),
    CHECK(capture_status <> 'failed' OR (error_class IS NOT NULL AND length(error_class) > 0)),
    FOREIGN KEY(manifest_sha256, repository_id, policy_sha256)
        REFERENCES idx_manifest(manifest_sha256, repository_id, policy_sha256),
    FOREIGN KEY(evidence_record_sha256, repository_id)
        REFERENCES idx_journal_record(record_sha256, repository_id),
    FOREIGN KEY(slot_id, repository_id, policy_sha256, scope_kind, scope_key)
        REFERENCES idx_schedule_slot(slot_id, repository_id, policy_sha256, scope_kind, scope_key)
);
CREATE INDEX idx_capture_repo_interval ON idx_capture(repository_id, request_finished_at_us, request_started_at_us);

CREATE TABLE idx_repository_name (
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    capture_id TEXT NOT NULL,
    owner_name TEXT NOT NULL CHECK(length(owner_name) > 0),
    repository_name TEXT NOT NULL CHECK(length(repository_name) > 0),
    public_url TEXT NOT NULL CHECK(length(public_url) > 0),
    visibility TEXT NOT NULL CHECK(visibility IN ('public', 'unavailable', 'unknown')),
    PRIMARY KEY(repository_id, capture_id),
    FOREIGN KEY(capture_id, repository_id) REFERENCES idx_capture(capture_id, repository_id)
);

-- Scope coverage is separate from request/run success: a 200 can hit a cap, and
-- a successful fetch can observe a non-atomic ls-remote/fetch pair. Null capture
-- permits not-polled scope facts. Scope keys identify endpoint/query partitions.
CREATE TABLE idx_scope_coverage (
    manifest_sha256 TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    policy_sha256 TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('git', 'http')),
    scope_key TEXT NOT NULL CHECK(length(scope_key) > 0),
    capture_id TEXT,
    coverage_status TEXT NOT NULL CHECK(coverage_status IN ('complete', 'partial', 'non_atomic', 'not_polled', 'cap_reached', 'unavailable')),
    availability TEXT NOT NULL DEFAULT 'unknown' CHECK(availability IN ('available', 'disabled', 'not_supported', 'unavailable', 'unknown')),
    reason TEXT,
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json) AND json_type(details_json) = 'object'),
    PRIMARY KEY(manifest_sha256, scope_kind, scope_key),
    CHECK(coverage_status <> 'not_polled' OR capture_id IS NULL),
    CHECK(coverage_status <> 'complete' OR capture_id IS NOT NULL),
    CHECK(availability NOT IN ('disabled', 'not_supported', 'unavailable') OR coverage_status IN ('unavailable', 'not_polled')),
    FOREIGN KEY(manifest_sha256, repository_id, policy_sha256)
        REFERENCES idx_manifest(manifest_sha256, repository_id, policy_sha256),
    FOREIGN KEY(capture_id, repository_id, scope_kind)
        REFERENCES idx_capture(capture_id, repository_id, scope_kind)
);
CREATE TRIGGER idx_scope_capture_manifest BEFORE INSERT ON idx_scope_coverage
WHEN NEW.capture_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM idx_capture c WHERE c.capture_id = NEW.capture_id
        AND c.manifest_sha256 = NEW.manifest_sha256 AND c.scope_key = NEW.scope_key)
BEGIN SELECT RAISE(ABORT, 'coverage capture must belong to the same manifest and scope'); END;
CREATE TRIGGER idx_scope_capture_manifest_update BEFORE UPDATE ON idx_scope_coverage
WHEN NEW.capture_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM idx_capture c WHERE c.capture_id = NEW.capture_id
        AND c.manifest_sha256 = NEW.manifest_sha256 AND c.scope_key = NEW.scope_key)
BEGIN SELECT RAISE(ABORT, 'coverage capture must belong to the same manifest and scope'); END;
CREATE TRIGGER idx_scope_complete_capture BEFORE INSERT ON idx_scope_coverage
WHEN NEW.coverage_status = 'complete' AND EXISTS (
    SELECT 1 FROM idx_capture WHERE capture_id = NEW.capture_id AND capture_status <> 'succeeded')
BEGIN SELECT RAISE(ABORT, 'failed or partial capture cannot establish complete scope coverage'); END;
CREATE TRIGGER idx_scope_complete_capture_update BEFORE UPDATE ON idx_scope_coverage
WHEN NEW.coverage_status = 'complete' AND EXISTS (
    SELECT 1 FROM idx_capture WHERE capture_id = NEW.capture_id AND capture_status <> 'succeeded')
BEGIN SELECT RAISE(ABORT, 'failed or partial capture cannot establish complete scope coverage'); END;

-- request_artifact_sha256 is a sanitized canonical outgoing request descriptor,
-- including HTTP method, URI/query, API version, Accept, GraphQL query+variables,
-- and relevant conditionals; NEVER Authorization/cookies/credential values.
-- representation_key_sha256 indexes the matching representation context, excluding
-- ETag/date conditionals but including public-auth bucket. It prevents wrong-query
-- 304 reuse. Only an original HTTP 200 body from a successful capture is reusable;
-- matching an error body's digest/context does not make it a cached representation.
-- Response headers are lower-case names on an enforced safe allowlist.
CREATE TABLE idx_http_response (
    capture_id TEXT PRIMARY KEY NOT NULL,
    repository_id INTEGER NOT NULL,
    scope_kind TEXT NOT NULL DEFAULT 'http' CHECK(scope_kind = 'http'),
    service TEXT NOT NULL CHECK(service IN ('github_rest', 'github_graphql', 'public_http')),
    method TEXT NOT NULL CHECK(method IN ('GET', 'HEAD', 'POST')),
    request_artifact_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    representation_key_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    status_code INTEGER CHECK(status_code IS NULL OR (typeof(status_code) = 'integer' AND status_code BETWEEN 100 AND 599)),
    body_sha256 TEXT REFERENCES idx_artifact(sha256),
    safe_headers_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(safe_headers_json) AND json_type(safe_headers_json) = 'object'),
    conditional_parent_capture_id TEXT,
    reused_body_sha256 TEXT REFERENCES idx_artifact(sha256),
    UNIQUE(capture_id, repository_id, representation_key_sha256, body_sha256),
    CHECK(service <> 'github_graphql' OR method = 'POST'),
    CHECK(status_code IS NOT NULL OR (body_sha256 IS NULL AND safe_headers_json = '{}')),
    CHECK((status_code = 304 AND body_sha256 IS NULL AND conditional_parent_capture_id IS NOT NULL AND reused_body_sha256 IS NOT NULL)
       OR (status_code IS NOT 304 AND conditional_parent_capture_id IS NULL AND reused_body_sha256 IS NULL)),
    CHECK(conditional_parent_capture_id IS NULL OR conditional_parent_capture_id <> capture_id),
    FOREIGN KEY(capture_id, repository_id, scope_kind) REFERENCES idx_capture(capture_id, repository_id, scope_kind),
    FOREIGN KEY(conditional_parent_capture_id, repository_id, representation_key_sha256, reused_body_sha256)
        REFERENCES idx_http_response(capture_id, repository_id, representation_key_sha256, body_sha256)
);
CREATE TRIGGER idx_http_304_parent_insert BEFORE INSERT ON idx_http_response
WHEN NEW.status_code = 304 AND NOT EXISTS (
    SELECT 1 FROM idx_http_response h JOIN idx_capture c ON c.capture_id = h.capture_id
    WHERE h.capture_id = NEW.conditional_parent_capture_id AND h.status_code = 200 AND c.capture_status = 'succeeded')
BEGIN SELECT RAISE(ABORT, '304 reuse requires a successful prior HTTP 200 capture'); END;
CREATE TRIGGER idx_http_304_parent_update BEFORE UPDATE ON idx_http_response
WHEN NEW.status_code = 304 AND NOT EXISTS (
    SELECT 1 FROM idx_http_response h JOIN idx_capture c ON c.capture_id = h.capture_id
    WHERE h.capture_id = NEW.conditional_parent_capture_id AND h.status_code = 200 AND c.capture_status = 'succeeded')
BEGIN SELECT RAISE(ABORT, '304 reuse requires a successful prior HTTP 200 capture'); END;
CREATE TRIGGER idx_http_reused_parent_status BEFORE UPDATE OF status_code ON idx_http_response
WHEN NEW.status_code IS NOT 200 AND EXISTS (
    SELECT 1 FROM idx_http_response WHERE conditional_parent_capture_id = OLD.capture_id AND status_code = 304)
BEGIN SELECT RAISE(ABORT, 'cannot invalidate the successful HTTP 200 parent of a 304'); END;
CREATE TRIGGER idx_http_reused_parent_capture BEFORE UPDATE OF capture_status ON idx_capture
WHEN NEW.capture_status <> 'succeeded' AND EXISTS (
    SELECT 1 FROM idx_http_response WHERE conditional_parent_capture_id = OLD.capture_id AND status_code = 304)
BEGIN SELECT RAISE(ABORT, 'cannot invalidate the successful capture parent of a 304'); END;
CREATE TRIGGER idx_http_safe_headers_insert BEFORE INSERT ON idx_http_response
WHEN EXISTS (SELECT 1 FROM json_each(NEW.safe_headers_json) WHERE type <> 'text' OR key NOT IN (
    'date', 'etag', 'last-modified', 'content-type', 'content-length', 'content-encoding',
    'link', 'x-github-request-id', 'x-ratelimit-limit', 'x-ratelimit-remaining',
    'x-ratelimit-used', 'x-ratelimit-reset', 'x-ratelimit-resource', 'x-poll-interval',
    'retry-after', 'vary', 'cache-control'))
BEGIN SELECT RAISE(ABORT, 'response header is not a safe allowlisted string'); END;
CREATE TRIGGER idx_http_safe_headers_update BEFORE UPDATE OF safe_headers_json ON idx_http_response
WHEN EXISTS (SELECT 1 FROM json_each(NEW.safe_headers_json) WHERE type <> 'text' OR key NOT IN (
    'date', 'etag', 'last-modified', 'content-type', 'content-length', 'content-encoding',
    'link', 'x-github-request-id', 'x-ratelimit-limit', 'x-ratelimit-remaining',
    'x-ratelimit-used', 'x-ratelimit-reset', 'x-ratelimit-resource', 'x-poll-interval',
    'retry-after', 'vary', 'cache-control'))
BEGIN SELECT RAISE(ABORT, 'response header is not a safe allowlisted string'); END;

CREATE TABLE idx_git_snapshot (
    snapshot_id TEXT PRIMARY KEY NOT NULL CHECK(length(snapshot_id) > 0),
    capture_id TEXT NOT NULL UNIQUE,
    repository_id INTEGER NOT NULL,
    scope_kind TEXT NOT NULL DEFAULT 'git' CHECK(scope_kind = 'git'),
    is_baseline INTEGER NOT NULL CHECK(is_baseline IN (0, 1)),
    object_format TEXT NOT NULL CHECK(object_format IN ('sha1', 'sha256')),
    advertised_refs_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    head_symref TEXT CHECK(head_symref IS NULL OR (substr(head_symref, 1, 11) = 'refs/heads/' AND length(head_symref) > 11)),
    head_oid TEXT CHECK(head_oid IS NULL OR (head_oid NOT GLOB '*[^0-9a-f]*' AND length(head_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END)),
    default_branch TEXT,
    object_coverage TEXT NOT NULL CHECK(object_coverage IN ('complete', 'partial', 'unavailable')),
    UNIQUE(snapshot_id, repository_id),
    UNIQUE(snapshot_id, repository_id, object_format),
    UNIQUE(snapshot_id, repository_id, is_baseline, object_format),
    FOREIGN KEY(capture_id, repository_id, scope_kind) REFERENCES idx_capture(capture_id, repository_id, scope_kind)
);

-- Only real advertised refs. HEAD/symref is snapshot metadata. Annotated-tag
-- peeling is a field on a tag row; refs/tags/v1^{} is never a synthetic ref row.
CREATE TABLE idx_git_ref (
    snapshot_id TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    object_format TEXT NOT NULL CHECK(object_format IN ('sha1', 'sha256')),
    refname TEXT NOT NULL CHECK(instr(refname, '^') = 0 AND instr(refname, char(0)) = 0),
    ref_kind TEXT NOT NULL CHECK(ref_kind IN ('branch', 'tag', 'pr_head')),
    tip_oid TEXT NOT NULL CHECK(tip_oid NOT GLOB '*[^0-9a-f]*' AND length(tip_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END),
    tip_object_type TEXT NOT NULL CHECK(tip_object_type IN ('commit', 'tag', 'tree', 'blob', 'unknown')),
    peeled_target_oid TEXT CHECK(peeled_target_oid IS NULL OR (peeled_target_oid NOT GLOB '*[^0-9a-f]*' AND length(peeled_target_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END)),
    peeled_target_type TEXT CHECK(peeled_target_type IN ('commit', 'tree', 'blob', 'unknown')),
    PRIMARY KEY(snapshot_id, refname),
    CHECK((ref_kind = 'branch' AND substr(refname, 1, 11) = 'refs/heads/' AND length(refname) > 11)
       OR (ref_kind = 'tag' AND substr(refname, 1, 10) = 'refs/tags/' AND length(refname) > 10)
       OR (ref_kind = 'pr_head' AND substr(refname, 1, 10) = 'refs/pull/' AND substr(refname, -5) = '/head'
           AND length(refname) > 15 AND substr(refname, 11, length(refname) - 15) NOT GLOB '*[^0-9]*'
           AND CAST(substr(refname, 11, length(refname) - 15) AS INTEGER) > 0)),
    CHECK((peeled_target_oid IS NULL AND peeled_target_type IS NULL)
       OR (ref_kind = 'tag' AND tip_object_type = 'tag' AND peeled_target_oid IS NOT NULL AND peeled_target_type IS NOT NULL)),
    FOREIGN KEY(snapshot_id, repository_id, object_format) REFERENCES idx_git_snapshot(snapshot_id, repository_id, object_format)
);

-- One row per commit/repository, not per ancestor/ref/snapshot. This is a derived
-- candidate first observation: the replay verifier must establish reachability in
-- the preserved Git graph and check preceding snapshots. Ref attribution uses
-- graph traversal from the first snapshot's tips, never tip-equality for ancestors.
CREATE TABLE idx_commit_first_seen (
    repository_id INTEGER NOT NULL,
    commit_oid TEXT NOT NULL CHECK(commit_oid NOT GLOB '*[^0-9a-f]*' AND length(commit_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END),
    snapshot_id TEXT NOT NULL,
    object_format TEXT NOT NULL CHECK(object_format IN ('sha1', 'sha256')),
    baseline_snapshot INTEGER NOT NULL CHECK(baseline_snapshot IN (0, 1)),
    first_seen_class TEXT NOT NULL CHECK(first_seen_class IN ('baseline_left_censored', 'prospective_first_observation')),
    PRIMARY KEY(repository_id, commit_oid),
    CHECK((baseline_snapshot = 1 AND first_seen_class = 'baseline_left_censored')
       OR (baseline_snapshot = 0 AND first_seen_class = 'prospective_first_observation')),
    FOREIGN KEY(snapshot_id, repository_id, baseline_snapshot, object_format)
        REFERENCES idx_git_snapshot(snapshot_id, repository_id, is_baseline, object_format)
);

-- Portable Git archives are CAS artifacts. Baselines must be self-contained;
-- incremental bundles declare explicit prerequisite commits and the earlier
-- same-repository archive that supplies each prerequisite. Archive ordinal is a
-- topological order, not wall-clock evidence. Actual object supply is verified
-- with Git offline; SQL cannot infer it from an object ID.
CREATE TABLE idx_git_archive (
    archive_sha256 TEXT PRIMARY KEY NOT NULL REFERENCES idx_artifact(sha256),
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    ordinal INTEGER NOT NULL CHECK(typeof(ordinal) = 'integer' AND ordinal > 0),
    archive_kind TEXT NOT NULL CHECK(archive_kind IN ('baseline_bundle', 'incremental_bundle')),
    object_format TEXT NOT NULL CHECK(object_format IN ('sha1', 'sha256')),
    bundle_version INTEGER NOT NULL CHECK(bundle_version IN (2, 3)),
    prerequisite_count INTEGER NOT NULL CHECK(typeof(prerequisite_count) = 'integer' AND prerequisite_count >= 0),
    evidence_record_sha256 TEXT NOT NULL,
    UNIQUE(repository_id, ordinal),
    UNIQUE(archive_sha256, repository_id, object_format),
    CHECK(archive_kind <> 'baseline_bundle' OR prerequisite_count = 0),
    CHECK(object_format <> 'sha256' OR bundle_version = 3),
    FOREIGN KEY(evidence_record_sha256, repository_id) REFERENCES idx_journal_record(record_sha256, repository_id)
);
CREATE TABLE idx_git_archive_dependency (
    child_archive_sha256 TEXT NOT NULL,
    parent_archive_sha256 TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    object_format TEXT NOT NULL CHECK(object_format IN ('sha1', 'sha256')),
    prerequisite_oid TEXT NOT NULL CHECK(prerequisite_oid NOT GLOB '*[^0-9a-f]*' AND length(prerequisite_oid) = CASE object_format WHEN 'sha1' THEN 40 ELSE 64 END),
    PRIMARY KEY(child_archive_sha256, prerequisite_oid),
    CHECK(child_archive_sha256 <> parent_archive_sha256),
    FOREIGN KEY(child_archive_sha256, repository_id, object_format) REFERENCES idx_git_archive(archive_sha256, repository_id, object_format),
    FOREIGN KEY(parent_archive_sha256, repository_id, object_format) REFERENCES idx_git_archive(archive_sha256, repository_id, object_format)
);
CREATE TRIGGER idx_git_dependency_order BEFORE INSERT ON idx_git_archive_dependency
WHEN EXISTS (SELECT 1 FROM idx_git_archive child, idx_git_archive parent
    WHERE child.archive_sha256 = NEW.child_archive_sha256 AND parent.archive_sha256 = NEW.parent_archive_sha256
      AND (parent.ordinal >= child.ordinal OR child.archive_kind = 'baseline_bundle'))
BEGIN SELECT RAISE(ABORT, 'Git dependencies must precede an incremental child in the same repository'); END;
CREATE TRIGGER idx_git_dependency_no_update BEFORE UPDATE ON idx_git_archive_dependency
BEGIN SELECT RAISE(ABORT, 'rebuild archive dependencies rather than mutate evidence edges'); END;
CREATE TRIGGER idx_git_dependency_no_delete BEFORE DELETE ON idx_git_archive_dependency
BEGIN SELECT RAISE(ABORT, 'rebuild archive dependencies rather than remove evidence edges'); END;
CREATE TRIGGER idx_git_dependency_count BEFORE INSERT ON idx_git_archive_dependency
WHEN (SELECT COUNT(*) FROM idx_git_archive_dependency WHERE child_archive_sha256 = NEW.child_archive_sha256)
    >= (SELECT prerequisite_count FROM idx_git_archive WHERE archive_sha256 = NEW.child_archive_sha256)
BEGIN SELECT RAISE(ABORT, 'Git dependency exceeds the declared prerequisite count'); END;
CREATE TRIGGER idx_git_archive_no_update BEFORE UPDATE ON idx_git_archive
BEGIN SELECT RAISE(ABORT, 'rebuild Git archive facts rather than mutate them'); END;

CREATE TABLE idx_git_snapshot_archive (
    snapshot_id TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    object_format TEXT NOT NULL CHECK(object_format IN ('sha1', 'sha256')),
    root_archive_sha256 TEXT NOT NULL,
    closure_status TEXT NOT NULL CHECK(closure_status IN ('complete', 'incomplete')),
    PRIMARY KEY(snapshot_id, root_archive_sha256),
    FOREIGN KEY(snapshot_id, repository_id, object_format) REFERENCES idx_git_snapshot(snapshot_id, repository_id, object_format),
    FOREIGN KEY(root_archive_sha256, repository_id, object_format) REFERENCES idx_git_archive(archive_sha256, repository_id, object_format)
);
CREATE TRIGGER idx_git_archive_closure_insert BEFORE INSERT ON idx_git_snapshot_archive
WHEN NEW.closure_status = 'complete' AND EXISTS (
    WITH RECURSIVE closure(sha256) AS (
        SELECT NEW.root_archive_sha256 UNION
        SELECT d.parent_archive_sha256 FROM idx_git_archive_dependency d JOIN closure c ON d.child_archive_sha256 = c.sha256
    )
    SELECT 1 FROM closure c JOIN idx_git_archive a ON a.archive_sha256 = c.sha256
    WHERE a.prerequisite_count <> (SELECT COUNT(*) FROM idx_git_archive_dependency d WHERE d.child_archive_sha256 = a.archive_sha256))
BEGIN SELECT RAISE(ABORT, 'complete Git closure requires every declared prerequisite edge'); END;
CREATE TRIGGER idx_git_archive_closure_update BEFORE UPDATE ON idx_git_snapshot_archive
BEGIN SELECT RAISE(ABORT, 'rebuild snapshot archive closure rather than mutate it'); END;
CREATE TRIGGER idx_git_dependency_after_complete BEFORE INSERT ON idx_git_archive_dependency
WHEN EXISTS (
    WITH RECURSIVE protected(sha256) AS (
        SELECT root_archive_sha256 FROM idx_git_snapshot_archive WHERE closure_status = 'complete' UNION
        SELECT d.parent_archive_sha256 FROM idx_git_archive_dependency d JOIN protected p ON d.child_archive_sha256 = p.sha256
    ) SELECT 1 FROM protected WHERE sha256 = NEW.child_archive_sha256)
BEGIN SELECT RAISE(ABORT, 'cannot add prerequisites to a finalized complete Git closure'); END;

-- Every row is a new archived lifecycle event. A pending receipt survives failed
-- collection, and upgrading/verifying stores new proof artifacts/events without
-- overwriting initial receipts. Verification time is local; anchor time is an
-- existence bound, not a GitHub publication or response time.
CREATE TABLE idx_attestation (
    attestation_id TEXT PRIMARY KEY NOT NULL CHECK(length(attestation_id) > 0),
    subject_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    previous_attestation_id TEXT,
    scheme TEXT NOT NULL CHECK(scheme IN ('ots', 'rfc3161', 'witness')),
    state TEXT NOT NULL CHECK(state IN ('pending', 'upgraded', 'verified', 'failed')),
    proof_sha256 TEXT REFERENCES idx_artifact(sha256),
    evidence_record_sha256 TEXT NOT NULL REFERENCES idx_journal_record(record_sha256),
    recorded_at_us INTEGER NOT NULL CHECK(typeof(recorded_at_us) = 'integer' AND recorded_at_us >= 0),
    issuer TEXT NOT NULL CHECK(length(issuer) > 0),
    verified_at_us INTEGER CHECK(verified_at_us IS NULL OR (typeof(verified_at_us) = 'integer' AND verified_at_us >= 0)),
    anchor_time_us INTEGER CHECK(anchor_time_us IS NULL OR (typeof(anchor_time_us) = 'integer' AND anchor_time_us >= 0)),
    block_height INTEGER CHECK(block_height IS NULL OR (typeof(block_height) = 'integer' AND block_height >= 0)),
    block_hash TEXT CHECK(block_hash IS NULL OR (length(block_hash) = 64 AND block_hash NOT GLOB '*[^0-9a-f]*')),
    certificate_sha256 TEXT REFERENCES idx_artifact(sha256),
    verification_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(verification_metadata_json) AND json_type(verification_metadata_json) = 'object'),
    failure_reason TEXT,
    UNIQUE(attestation_id, subject_sha256, scheme),
    CHECK(previous_attestation_id IS NULL OR previous_attestation_id <> attestation_id),
    CHECK(state NOT IN ('upgraded', 'verified') OR proof_sha256 IS NOT NULL),
    CHECK((state = 'verified' AND verified_at_us IS NOT NULL) OR (state <> 'verified' AND verified_at_us IS NULL)),
    CHECK(state <> 'failed' OR (failure_reason IS NOT NULL AND length(failure_reason) > 0)),
    CHECK((block_height IS NULL AND block_hash IS NULL) OR (scheme = 'ots' AND block_height IS NOT NULL AND block_hash IS NOT NULL)),
    FOREIGN KEY(previous_attestation_id, subject_sha256, scheme) REFERENCES idx_attestation(attestation_id, subject_sha256, scheme)
);
CREATE TRIGGER idx_attestation_no_update BEFORE UPDATE ON idx_attestation
BEGIN SELECT RAISE(ABORT, 'attestation lifecycle is append-only'); END;
CREATE TRIGGER idx_attestation_no_delete BEFORE DELETE ON idx_attestation
BEGIN SELECT RAISE(ABORT, 'attestation lifecycle is append-only'); END;

-- A study Git commit contains small indexes/manifests/ref maps; the CAS and this
-- database remain external. AFTER the commit, a canonical checkpoint artifact
-- binds that commit OID, interval-index artifact, prior checkpoint, and journal
-- cutoff. Timestamp the checkpoint SHA-256; never make the commit refer to its
-- own digest/proof or amend it to add a later timestamp receipt. The interval
-- index is authoritative for full member/closure replay; this mapping is derived.
-- Membership always obeys the journal cutoff. Wall-clock finalization ordering
-- is checked only for manifests whose collector clock was classified as valid.
CREATE TABLE idx_study_checkpoint (
    checkpoint_sha256 TEXT PRIMARY KEY NOT NULL REFERENCES idx_artifact(sha256),
    study_id TEXT NOT NULL CHECK(length(study_id) > 0),
    ordinal INTEGER NOT NULL CHECK(typeof(ordinal) = 'integer' AND ordinal > 0),
    previous_ordinal INTEGER,
    previous_checkpoint_sha256 TEXT,
    study_object_format TEXT NOT NULL CHECK(study_object_format IN ('sha1', 'sha256')),
    study_commit_oid TEXT NOT NULL CHECK(study_commit_oid NOT GLOB '*[^0-9a-f]*' AND length(study_commit_oid) = CASE study_object_format WHEN 'sha1' THEN 40 ELSE 64 END),
    interval_index_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    interval_started_at_us INTEGER NOT NULL CHECK(typeof(interval_started_at_us) = 'integer' AND interval_started_at_us >= 0),
    interval_finished_at_us INTEGER NOT NULL CHECK(typeof(interval_finished_at_us) = 'integer' AND interval_finished_at_us >= interval_started_at_us),
    created_at_us INTEGER NOT NULL CHECK(typeof(created_at_us) = 'integer' AND created_at_us >= interval_finished_at_us),
    journal_cutoff_sequence INTEGER NOT NULL CHECK(typeof(journal_cutoff_sequence) = 'integer' AND journal_cutoff_sequence > 0),
    journal_cutoff_sha256 TEXT NOT NULL,
    UNIQUE(study_id, ordinal),
    UNIQUE(study_id, ordinal, checkpoint_sha256),
    UNIQUE(study_id, study_commit_oid),
    CHECK((ordinal = 1 AND previous_ordinal IS NULL AND previous_checkpoint_sha256 IS NULL)
       OR (ordinal > 1 AND previous_ordinal IS NOT NULL AND previous_ordinal = ordinal - 1 AND previous_checkpoint_sha256 IS NOT NULL)),
    FOREIGN KEY(study_id, previous_ordinal, previous_checkpoint_sha256)
        REFERENCES idx_study_checkpoint(study_id, ordinal, checkpoint_sha256),
    FOREIGN KEY(journal_cutoff_sequence, journal_cutoff_sha256)
        REFERENCES idx_journal_record(sequence, record_sha256)
);
CREATE TABLE idx_checkpoint_manifest (
    checkpoint_sha256 TEXT NOT NULL REFERENCES idx_study_checkpoint(checkpoint_sha256),
    manifest_sha256 TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    PRIMARY KEY(checkpoint_sha256, manifest_sha256),
    FOREIGN KEY(manifest_sha256, repository_id) REFERENCES idx_manifest(manifest_sha256, repository_id)
);
CREATE TRIGGER idx_checkpoint_manifest_cutoff BEFORE INSERT ON idx_checkpoint_manifest
WHEN EXISTS (
    SELECT 1 FROM idx_study_checkpoint c, idx_manifest m
    JOIN idx_journal_record j ON j.record_sha256 = m.evidence_record_sha256
    WHERE c.checkpoint_sha256 = NEW.checkpoint_sha256 AND m.manifest_sha256 = NEW.manifest_sha256
      AND (j.sequence > c.journal_cutoff_sequence OR (m.clock_validity = 'valid' AND m.finalized_at_us > c.created_at_us)))
BEGIN SELECT RAISE(ABORT, 'checkpoint member must exist at its journal cutoff and creation time'); END;
CREATE TRIGGER idx_checkpoint_manifest_cutoff_update BEFORE UPDATE ON idx_checkpoint_manifest
WHEN EXISTS (
    SELECT 1 FROM idx_study_checkpoint c, idx_manifest m
    JOIN idx_journal_record j ON j.record_sha256 = m.evidence_record_sha256
    WHERE c.checkpoint_sha256 = NEW.checkpoint_sha256 AND m.manifest_sha256 = NEW.manifest_sha256
      AND (j.sequence > c.journal_cutoff_sequence OR (m.clock_validity = 'valid' AND m.finalized_at_us > c.created_at_us)))
BEGIN SELECT RAISE(ABORT, 'checkpoint member must exist at its journal cutoff and creation time'); END;

-- Generic identities cover readily available public issues, PRs, comments,
-- reviews, Discussions/replies, and release metadata. Prefer GitHub node IDs;
-- typed database IDs remain usable where the API lacks node IDs. Entity keys are
-- internal stable IDs; never key an entity by a mutable title, URL, or username.
CREATE TABLE idx_entity (
    entity_id TEXT PRIMARY KEY NOT NULL CHECK(length(entity_id) > 0),
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    entity_kind TEXT NOT NULL CHECK(entity_kind IN ('issue', 'pull_request', 'issue_comment', 'review', 'review_comment', 'discussion', 'discussion_comment', 'release')),
    platform_id_scheme TEXT NOT NULL CHECK(platform_id_scheme IN ('github_node_id', 'github_database_id')),
    platform_entity_id TEXT NOT NULL CHECK(length(platform_entity_id) > 0),
    parent_entity_id TEXT,
    number INTEGER CHECK(number IS NULL OR (typeof(number) = 'integer' AND number > 0)),
    UNIQUE(repository_id, entity_kind, platform_id_scheme, platform_entity_id),
    UNIQUE(entity_id, repository_id),
    CHECK(parent_entity_id IS NULL OR parent_entity_id <> entity_id),
    FOREIGN KEY(parent_entity_id, repository_id) REFERENCES idx_entity(entity_id, repository_id)
);
CREATE TABLE idx_entity_observation (
    entity_id TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    capture_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL DEFAULT 'http' CHECK(scope_kind = 'http'),
    raw_body_sha256 TEXT NOT NULL REFERENCES idx_artifact(sha256),
    json_pointer TEXT NOT NULL CHECK(json_pointer = '' OR substr(json_pointer, 1, 1) = '/'),
    extraction_profile TEXT NOT NULL CHECK(length(extraction_profile) > 0),
    representation_sha256 TEXT NOT NULL CHECK(length(representation_sha256) = 64 AND representation_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY(entity_id, capture_id, extraction_profile),
    FOREIGN KEY(entity_id, repository_id) REFERENCES idx_entity(entity_id, repository_id),
    FOREIGN KEY(capture_id, repository_id, scope_kind) REFERENCES idx_capture(capture_id, repository_id, scope_kind)
);
CREATE INDEX idx_entity_observation_capture ON idx_entity_observation(capture_id);
CREATE TRIGGER idx_entity_observation_body BEFORE INSERT ON idx_entity_observation
WHEN NOT EXISTS (SELECT 1 FROM idx_http_response h WHERE h.capture_id = NEW.capture_id AND h.repository_id = NEW.repository_id
    AND NEW.raw_body_sha256 = COALESCE(h.body_sha256, h.reused_body_sha256))
BEGIN SELECT RAISE(ABORT, 'entity observation must locate the captured or explicitly reused response body'); END;
CREATE TRIGGER idx_entity_observation_body_update BEFORE UPDATE ON idx_entity_observation
WHEN NOT EXISTS (SELECT 1 FROM idx_http_response h WHERE h.capture_id = NEW.capture_id AND h.repository_id = NEW.repository_id
    AND NEW.raw_body_sha256 = COALESCE(h.body_sha256, h.reused_body_sha256))
BEGIN SELECT RAISE(ABORT, 'entity observation must locate the captured or explicitly reused response body'); END;

-- Disposable operational state. Git transport, REST, and GraphQL have independent
-- buckets; GraphQL's primary counters are points. Secondary cooldown, Retry-After,
-- polling minima, and primary-reset times are independent gates, not alternatives.
-- A worker must satisfy ALL applicable gates before leasing a job.
CREATE TABLE op_rate_bucket (
    service TEXT NOT NULL CHECK(service IN ('github_git', 'github_rest', 'github_graphql', 'public_http', 'ots', 'rfc3161', 'archive')),
    auth_bucket TEXT NOT NULL CHECK(length(auth_bucket) > 0),
    primary_limit INTEGER CHECK(primary_limit IS NULL OR (typeof(primary_limit) = 'integer' AND primary_limit >= 0)),
    primary_remaining INTEGER CHECK(primary_remaining IS NULL OR (typeof(primary_remaining) = 'integer' AND primary_remaining >= 0)),
    primary_reset_at_us INTEGER CHECK(primary_reset_at_us IS NULL OR (typeof(primary_reset_at_us) = 'integer' AND primary_reset_at_us >= 0)),
    secondary_cooldown_until_us INTEGER CHECK(secondary_cooldown_until_us IS NULL OR (typeof(secondary_cooldown_until_us) = 'integer' AND secondary_cooldown_until_us >= 0)),
    retry_after_until_us INTEGER CHECK(retry_after_until_us IS NULL OR (typeof(retry_after_until_us) = 'integer' AND retry_after_until_us >= 0)),
    min_poll_interval_us INTEGER NOT NULL DEFAULT 0 CHECK(typeof(min_poll_interval_us) = 'integer' AND min_poll_interval_us >= 0),
    last_request_at_us INTEGER CHECK(last_request_at_us IS NULL OR (typeof(last_request_at_us) = 'integer' AND last_request_at_us >= 0)),
    updated_at_us INTEGER NOT NULL CHECK(typeof(updated_at_us) = 'integer' AND updated_at_us >= 0),
    PRIMARY KEY(service, auth_bucket),
    CHECK(primary_remaining IS NULL OR (primary_limit IS NOT NULL AND primary_remaining <= primary_limit)),
    CHECK(service <> 'github_git' OR (primary_limit IS NULL AND primary_remaining IS NULL AND primary_reset_at_us IS NULL))
);
CREATE TABLE op_job (
    job_id TEXT PRIMARY KEY NOT NULL CHECK(length(job_id) > 0),
    repository_id INTEGER NOT NULL REFERENCES idx_repository(repository_id),
    policy_sha256 TEXT NOT NULL REFERENCES idx_capture_policy(policy_sha256),
    slot_id TEXT,
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('git', 'http')),
    scope_key TEXT NOT NULL CHECK(length(scope_key) > 0),
    service TEXT NOT NULL,
    auth_bucket TEXT NOT NULL,
    source_uri TEXT NOT NULL CHECK(length(source_uri) > 0),
    request_artifact_sha256 TEXT REFERENCES idx_artifact(sha256),
    state TEXT NOT NULL CHECK(state IN ('queued', 'leased', 'done', 'failed', 'cancelled')),
    priority INTEGER NOT NULL DEFAULT 0 CHECK(typeof(priority) = 'integer'),
    not_before_us INTEGER NOT NULL CHECK(typeof(not_before_us) = 'integer' AND not_before_us >= 0),
    lease_owner TEXT,
    lease_expires_at_us INTEGER CHECK(lease_expires_at_us IS NULL OR (typeof(lease_expires_at_us) = 'integer' AND lease_expires_at_us >= 0)),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempt_count) = 'integer' AND attempt_count >= 0),
    cursor_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(cursor_json) AND json_type(cursor_json) = 'object'),
    last_error TEXT,
    created_at_us INTEGER NOT NULL CHECK(typeof(created_at_us) = 'integer' AND created_at_us >= 0),
    updated_at_us INTEGER NOT NULL CHECK(typeof(updated_at_us) = 'integer' AND updated_at_us >= created_at_us),
    CHECK((state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at_us IS NOT NULL)
       OR (state <> 'leased' AND lease_owner IS NULL AND lease_expires_at_us IS NULL)),
    CHECK((scope_kind = 'git' AND service = 'github_git') OR (scope_kind = 'http' AND service <> 'github_git')),
    FOREIGN KEY(service, auth_bucket) REFERENCES op_rate_bucket(service, auth_bucket),
    FOREIGN KEY(slot_id, repository_id, policy_sha256, scope_kind, scope_key)
        REFERENCES idx_schedule_slot(slot_id, repository_id, policy_sha256, scope_kind, scope_key)
);
CREATE INDEX op_job_ready ON op_job(state, not_before_us, priority);
