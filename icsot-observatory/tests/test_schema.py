"""Relational-contract tests for the DRAFT schema, not collector integration tests.

Fixtures use small synthetic SHA-256 artifacts and an explicit Git DAG. They do
not claim to verify bundle bytes, timestamps, GitHub access, or OTS cryptography.
"""

import hashlib
import json
import lzma
from pathlib import Path
import sqlite3

import pytest


SCHEMA = Path(__file__).resolve().parents[1] / "schema" / "metadata.sql"
A, B, C, D, E, F, TAG = (c * 40 for c in "abcdef9")
GRAPH = {A: (), B: (A,), C: (B,), D: (C,), E: (C,), F: (B,)}


class Archive:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA.read_text())
        self.sequence = 0
        self.previous_record = None
        self.manifests = {}
        self.provenance = self.artifact("public-only collector build and host provenance")
        self.policy = self.artifact("canonical configuration and policy version 1")
        self.insert(
            "idx_capture_policy", policy_sha256=self.policy, policy_version="draft-1",
            declared_at_us=1, git_cadence_us=3_600_000_000,
            monthly_new_evidence_budget_bytes=50_000_000_000,
            accounting_policy_json=json.dumps({"baseline": "included", "backups": "unresolved", "retention": "indefinite"}),
        )
        for repo in (101, 202):
            self.insert("idx_repository", repository_id=repo, github_node_id=f"R_{repo}", registered_at_us=1)

    def insert(self, table, **values):
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        self.db.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values()))

    def artifact(self, label, size=None, stored_size=None, archived_at=1):
        payload = label.encode()
        digest = hashlib.sha256(payload).hexdigest()
        if not self.db.execute("SELECT 1 FROM idx_artifact WHERE sha256 = ?", (digest,)).fetchone():
            self.insert("idx_artifact", sha256=digest, byte_length=len(payload) if size is None else size)
            compressed = lzma.compress(payload)
            stored_digest = hashlib.sha256(compressed).hexdigest()
            # Omit encoding to exercise the SQL XZ default on every fixture artifact.
            self.insert("idx_artifact_storage", stored_sha256=stored_digest, logical_sha256=digest,
                        stored_byte_length=len(compressed) if stored_size is None else stored_size,
                        archive_relpath=f"objects/sha256/{stored_digest[:2]}/{stored_digest}.xz", first_archived_at_us=archived_at)
        return digest

    def journal(self, repo, kind, at=1):
        self.sequence += 1
        digest = self.artifact(f"journal:{self.sequence}:{repo}:{kind}")
        self.insert("idx_journal_record", record_sha256=digest, sequence=self.sequence,
                    previous_sequence=self.sequence - 1 if self.sequence > 1 else None,
                    previous_record_sha256=self.previous_record, repository_id=repo,
                    event_kind=kind, recorded_at_us=at)
        self.previous_record = digest
        return digest

    def manifest(self, repo, ordinal, start, previous=None, status="succeeded", clock="valid", **extra):
        digest = self.artifact(f"manifest:{repo}:{ordinal}:{previous}:{status}")
        record = self.journal(repo, "manifest", start + 100)
        values = dict(manifest_sha256=digest, repository_id=repo, ordinal=ordinal,
                    previous_ordinal=ordinal - 1 if ordinal > 1 else None, previous_manifest_sha256=previous,
                    policy_sha256=self.policy, evidence_record_sha256=record, run_id=f"run:{repo}:{ordinal}",
                    run_started_at_us=start, run_finished_at_us=start + 90, finalized_at_us=start + 100,
                    capture_status=status, clock_validity=clock,
                    clock_uncertainty_us=100 if clock == "valid" else None, provenance_sha256=self.provenance)
        values.update(extra)
        self.insert("idx_manifest", **values)
        result = {"digest": digest, "repo": repo, "record": record, "start": start}
        self.manifests[digest] = result
        return result

    def capture(self, manifest, name, kind="git", status="succeeded", phase="prospective", **extra):
        values = dict(capture_id=name, repository_id=manifest["repo"], manifest_sha256=manifest["digest"],
                      policy_sha256=self.policy, evidence_record_sha256=manifest["record"],
                      scope_kind=kind, scope_key="advertised-refs" if kind == "git" else "issues",
                      collection_phase=phase, source_uri=f"https://github.com/example/repo-{manifest['repo']}",
                      scheduled_at_us=manifest["start"], request_started_at_us=manifest["start"] + 10,
                      request_finished_at_us=manifest["start"] + 20, capture_status=status,
                      auth_context="public-readonly:study", provenance_sha256=self.provenance,
                      clock_validity="valid", clock_uncertainty_us=100)
        if status == "failed":
            values["error_class"] = "transport_error"
        values.update(extra)
        self.insert("idx_capture", **values)
        return name

    def snapshot(self, manifest, name, baseline=False, fmt="sha1", **extra):
        self.capture(manifest, name, phase="baseline" if baseline else "prospective")
        values = dict(snapshot_id=name, capture_id=name, repository_id=manifest["repo"],
                      is_baseline=int(baseline), object_format=fmt,
                      advertised_refs_sha256=self.artifact(f"advertised ref map:{name}"),
                      head_symref="refs/heads/main", default_branch="main", object_coverage="complete")
        values.update(extra)
        self.insert("idx_git_snapshot", **values)
        return name

    def ref(self, snapshot, refname, oid, kind="branch", repo=101, fmt="sha1", **extra):
        self.insert("idx_git_ref", snapshot_id=snapshot, repository_id=repo, object_format=fmt,
                    refname=refname, ref_kind=kind, tip_oid=oid, tip_object_type=extra.pop("tip_object_type", "commit"), **extra)

    def first_seen(self, snapshot, oid, baseline=False, repo=101, fmt="sha1"):
        self.insert("idx_commit_first_seen", repository_id=repo, commit_oid=oid, snapshot_id=snapshot,
                    object_format=fmt, baseline_snapshot=int(baseline),
                    first_seen_class="baseline_left_censored" if baseline else "prospective_first_observation")

    def git_archive(self, manifest, ordinal, prerequisites=0, fmt="sha1"):
        digest = self.artifact(f"git bundle:{manifest['repo']}:{ordinal}")
        self.insert("idx_git_archive", archive_sha256=digest, repository_id=manifest["repo"], ordinal=ordinal,
                    archive_kind="baseline_bundle" if ordinal == 1 else "incremental_bundle", object_format=fmt,
                    bundle_version=2 if fmt == "sha1" else 3, prerequisite_count=prerequisites,
                    evidence_record_sha256=manifest["record"])
        return digest

    def root(self, snapshot, archive, closure="complete", repo=101, fmt="sha1"):
        self.insert("idx_git_snapshot_archive", snapshot_id=snapshot, repository_id=repo,
                    object_format=fmt, root_archive_sha256=archive, closure_status=closure)

    def http(self, manifest, name, body=None, context=None, status=200, service="github_rest", **extra):
        self.capture(manifest, name, kind="http", **extra.pop("capture_extra", {}))
        values = dict(capture_id=name, repository_id=manifest["repo"], service=service,
                      method="POST" if service == "github_graphql" else "GET",
                      request_artifact_sha256=self.artifact(f"sanitized method+URI+query+variables:{name}"),
                      representation_key_sha256=context or self.artifact("GET issues public-readonly context"),
                      status_code=status, body_sha256=body,
                      safe_headers_json='{"etag":"v1","x-ratelimit-resource":"core"}')
        values.update(extra)
        self.insert("idx_http_response", **values)
        return name


@pytest.fixture
def archive():
    a = Archive()
    yield a
    a.db.close()


@pytest.fixture
def history(archive):
    a = archive
    baseline = a.manifest(101, 1, 1_000_000)
    delta = a.manifest(101, 2, 2_000_000, previous=baseline["digest"], status="partial")
    s0 = a.snapshot(baseline, "baseline", baseline=True, head_oid=B)
    s1 = a.snapshot(delta, "delta", head_oid=E)
    a.ref(s0, "refs/heads/main", B)
    a.ref(s0, "refs/heads/later-deleted", B)
    a.ref(s1, "refs/heads/main", E)
    a.ref(s1, "refs/heads/feature", D)
    a.ref(s1, "refs/pull/7/head", F, kind="pr_head")
    a.ref(s1, "refs/tags/v1", TAG, kind="tag", tip_object_type="tag", peeled_target_oid=B, peeled_target_type="commit")
    for oid in (A, B):
        a.first_seen(s0, oid, baseline=True)
    for oid in (C, D, E, F):
        a.first_seen(s1, oid)
    base_bundle = a.git_archive(baseline, 1)
    delta_bundle = a.git_archive(delta, 2, prerequisites=1)
    a.root(s0, base_bundle)
    a.insert("idx_git_archive_dependency", child_archive_sha256=delta_bundle,
             parent_archive_sha256=base_bundle, repository_id=101, object_format="sha1", prerequisite_oid=B)
    a.root(s1, delta_bundle)
    return a, baseline, delta, base_bundle, delta_bundle


def test_load_and_baseline_delta_chain(history):
    a, baseline, delta, base_bundle, delta_bundle = history
    assert a.db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert a.db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert a.db.execute("PRAGMA foreign_key_check").fetchall() == []
    chain = a.db.execute("SELECT previous_manifest_sha256, capture_status FROM idx_manifest WHERE manifest_sha256 = ?",
                         (delta["digest"],)).fetchone()
    assert tuple(chain) == (baseline["digest"], "partial")
    closure = a.db.execute("""WITH RECURSIVE closure(sha) AS (
        SELECT ? UNION SELECT d.parent_archive_sha256 FROM idx_git_archive_dependency d
        JOIN closure c ON d.child_archive_sha256 = c.sha) SELECT sha FROM closure""", (delta_bundle,)).fetchall()
    assert {row[0] for row in closure} == {base_bundle, delta_bundle}
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_artifact", sha256=None, byte_length=0)


def test_repository_first_observation_and_graph_based_ref_attribution(history):
    a, *_ = history
    other = a.manifest(202, 1, 500_000)
    a.snapshot(other, "other-baseline", baseline=True)
    a.first_seen("other-baseline", C, baseline=True, repo=202)
    row = a.db.execute("""SELECT f.snapshot_id, f.first_seen_class,
        c.request_started_at_us, c.request_finished_at_us, c.clock_uncertainty_us
        FROM idx_commit_first_seen f JOIN idx_git_snapshot s ON s.snapshot_id = f.snapshot_id
        JOIN idx_capture c ON c.capture_id = s.capture_id
        WHERE f.repository_id = ? AND f.commit_oid = ?""", (101, C)).fetchone()
    assert tuple(row) == ("delta", "prospective_first_observation", 2_000_010, 2_000_020, 100)
    refs = a.db.execute("SELECT refname, tip_oid, peeled_target_oid FROM idx_git_ref WHERE snapshot_id = ?", (row[0],)).fetchall()

    def reachable(tip, target):
        todo, seen = [tip], set()
        while todo:
            oid = todo.pop()
            if oid == target:
                return True
            if oid not in seen:
                seen.add(oid)
                todo.extend(GRAPH.get(oid, ()))
        return False

    # C is an ancestor of BOTH branch tips; equal-tip attribution would find none.
    assert all(ref[1] != C for ref in refs)
    assert {ref[0] for ref in refs if reachable(ref[2] or ref[1], C)} == {"refs/heads/main", "refs/heads/feature"}
    assert {ref[0] for ref in refs if reachable(ref[2] or ref[1], F)} == {"refs/pull/7/head"}
    assert a.db.execute("SELECT COUNT(*) FROM idx_commit_first_seen WHERE repository_id = 101").fetchone()[0] == 6
    with pytest.raises(sqlite3.IntegrityError):
        a.first_seen("delta", B)  # repository+OID is unique across branches/runs.


def test_cross_repository_and_invalid_git_relationships_rejected(history):
    a, _, delta, base_bundle, _ = history
    other = a.manifest(202, 1, 3_000_000)
    other_bundle = a.git_archive(other, 1)
    child = a.git_archive(delta, 3, prerequisites=1)
    for parent in (other_bundle, "0" * 64):
        with pytest.raises(sqlite3.IntegrityError):
            a.insert("idx_git_archive_dependency", child_archive_sha256=child,
                     parent_archive_sha256=parent, repository_id=101, object_format="sha1", prerequisite_oid=B)
    with pytest.raises(sqlite3.IntegrityError):
        a.root("delta", child)  # declared prerequisite is missing.
    a.root("delta", child, closure="incomplete")
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_git_archive_dependency", child_archive_sha256=base_bundle,
                 parent_archive_sha256=child, repository_id=101, object_format="sha1", prerequisite_oid=B)
    for kwargs in ({"repo": 202}, {"fmt": "sha256"}, {"oid": "A" * 40}):
        values = {"snapshot": "delta", "refname": "refs/heads/invalid", "oid": C, **kwargs}
        with pytest.raises(sqlite3.IntegrityError):
            a.ref(**values)
    with pytest.raises(sqlite3.IntegrityError):
        a.ref("delta", "refs/tags/v1^{}", B, kind="tag")
    with pytest.raises(sqlite3.IntegrityError):
        a.first_seen("delta", "1" * 40, baseline=True)


def test_manifest_and_journal_parent_association_is_enforced(history):
    a, baseline, delta, *_ = history
    with pytest.raises(sqlite3.IntegrityError):
        a.manifest(202, 2, 3_000_000, previous=baseline["digest"])
    with pytest.raises(sqlite3.IntegrityError):
        a.manifest(101, 3, 3_000_000, previous="0" * 64)
    with pytest.raises(sqlite3.IntegrityError):
        a.manifest(101, 3, 3_000_000, previous=baseline["digest"])
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_journal_record SET event_kind = 'changed' WHERE record_sha256 = ?", (delta["record"],))
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_artifact", sha256="Q" * 64, byte_length=1)
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_artifact_storage", stored_sha256="0" * 64, logical_sha256=baseline["digest"],
                 stored_byte_length=1, archive_relpath="../escape", first_archived_at_us=1)


def test_failed_capture_partial_coverage_and_pending_proof_are_independent(archive):
    a = archive
    manifest = a.manifest(101, 1, 1_000_000, status="failed", clock="unknown")
    a.capture(manifest, "failed-http", kind="http", status="failed", clock_validity="unknown", clock_uncertainty_us=None)
    a.insert("idx_scope_coverage", manifest_sha256=manifest["digest"], repository_id=101,
             policy_sha256=a.policy, scope_kind="http", scope_key="issues", capture_id="failed-http",
             coverage_status="partial", reason="page 2 unavailable")
    a.insert("idx_scope_coverage", manifest_sha256=manifest["digest"], repository_id=101,
             policy_sha256=a.policy, scope_kind="git", scope_key="advertised-refs", coverage_status="not_polled",
             reason="global new-byte budget exhausted")
    receipt = a.artifact("original pending receipt")
    a.insert("idx_attestation", attestation_id="pending", subject_sha256=manifest["digest"], scheme="ots",
             state="pending", proof_sha256=receipt, evidence_record_sha256=manifest["record"],
             recorded_at_us=1_000_101, issuer="calendar.example")
    states = a.db.execute("""SELECT m.capture_status, a.state, c.coverage_status FROM idx_manifest m
        JOIN idx_attestation a ON a.subject_sha256 = m.manifest_sha256
        JOIN idx_scope_coverage c ON c.manifest_sha256 = m.manifest_sha256 ORDER BY c.scope_kind""").fetchall()
    assert [tuple(r) for r in states] == [("failed", "pending", "not_polled"), ("failed", "pending", "partial")]
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_scope_coverage SET coverage_status='complete' WHERE capture_id='failed-http'")


def test_http_304_requires_matching_context_body_and_safe_headers(archive):
    a = archive
    m = a.manifest(101, 1, 1_000_000)
    body, context = a.artifact('[{"id":1}]'), a.artifact("GET /issues?state=all Accept:v1 public-readonly")
    a.http(m, "http200", body=body, context=context)
    a.http(m, "http304", context=context, status=304,
           conditional_parent_capture_id="http200", reused_body_sha256=body)
    for name, extra in (("wrong-context", {"context": a.artifact("GET /issues?state=open")}),
                        ("wrong-body", {"reused_body_sha256": a.artifact("other bytes")})):
        values = dict(context=context, status=304, conditional_parent_capture_id="http200", reused_body_sha256=body)
        values.update(extra)
        with pytest.raises(sqlite3.IntegrityError):
            a.http(m, name, **values)
    with pytest.raises(sqlite3.IntegrityError):
        a.http(m, "secret-header", body=body, safe_headers_json='{"set-cookie":"secret"}')
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_http_response SET safe_headers_json = ? WHERE capture_id = 'http200'", ('{"authorization":"secret"}',))
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_http_response SET status_code=500 WHERE capture_id='http200'")
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_capture SET capture_status='partial' WHERE capture_id='http200'")


@pytest.mark.parametrize("status,capture_status", [(500, "succeeded"), (200, "failed"), (200, "partial")])
def test_http_304_rejects_unsuccessful_original_even_with_matching_body_context(archive, status, capture_status):
    a = archive
    m = a.manifest(101, 1, 1_000_000)
    body, context = a.artifact("original bytes"), a.artifact("same representation context")
    a.http(m, "bad-original", body=body, context=context, status=status, capture_extra={"status": capture_status})
    with pytest.raises(sqlite3.IntegrityError, match="successful prior HTTP 200"):
        a.http(m, "invalid-304", context=context, status=304,
               conditional_parent_capture_id="bad-original", reused_body_sha256=body)
    a.http(m, "candidate-update", context=context, body=body)
    with pytest.raises(sqlite3.IntegrityError, match="successful prior HTTP 200"):
        a.db.execute("""UPDATE idx_http_response SET status_code=304, body_sha256=NULL,
            conditional_parent_capture_id='bad-original', reused_body_sha256=? WHERE capture_id='candidate-update'""", (body,))


@pytest.mark.parametrize("clock", ["invalid", "unknown"])
def test_clock_rollback_preserves_original_readings_and_monotonic_elapsed(archive, clock):
    a = archive
    m = a.manifest(101, 1, 2_000_000, clock=clock,
                   run_finished_at_us=1_900_000, finalized_at_us=1_800_000)
    for name, elapsed in (("measured-elapsed", 25_000), ("unavailable-elapsed", None)):
        a.capture(m, name, request_started_at_us=2_000_000, request_finished_at_us=1_900_000,
                  clock_validity=clock, clock_uncertainty_us=None, monotonic_elapsed_us=elapsed)
    rows = a.db.execute("""SELECT request_started_at_us, request_finished_at_us, monotonic_elapsed_us
        FROM idx_capture ORDER BY capture_id""").fetchall()
    assert [tuple(row) for row in rows] == [(2_000_000, 1_900_000, 25_000), (2_000_000, 1_900_000, None)]
    # Journal order still permits the bad-clock manifest in a later checkpoint,
    # even though its recorded finalization wall time lies ahead of that checkpoint.
    checkpoint = a.artifact(f"bad-clock-checkpoint:{clock}")
    a.insert("idx_study_checkpoint", checkpoint_sha256=checkpoint, study_id="clock-test", ordinal=1,
             study_object_format="sha1", study_commit_oid="1" * 40, interval_index_sha256=a.artifact("bad-clock interval index"),
             interval_started_at_us=1_500_000, interval_finished_at_us=1_600_000, created_at_us=1_700_000,
             journal_cutoff_sequence=a.sequence, journal_cutoff_sha256=a.previous_record)
    a.insert("idx_checkpoint_manifest", checkpoint_sha256=checkpoint, manifest_sha256=m["digest"], repository_id=101)
    with pytest.raises(sqlite3.IntegrityError):
        a.capture(m, "negative-elapsed", clock_validity=clock, monotonic_elapsed_us=-1)
    with pytest.raises(sqlite3.IntegrityError):
        a.capture(m, "claimed-valid-rollback", request_started_at_us=2_000_000, request_finished_at_us=1_900_000)
    with pytest.raises(sqlite3.IntegrityError):
        a.manifest(202, 1, 2_000_000, run_finished_at_us=1_900_000)
    with pytest.raises(sqlite3.IntegrityError):
        a.manifest(202, 1, 2_000_000, finalized_at_us=2_000_001)


def test_entity_first_seen_and_changed_content_replay_inputs(archive):
    a = archive
    baseline = a.manifest(101, 1, 1_000_000)
    delta = a.manifest(101, 2, 2_000_000, previous=baseline["digest"], status="partial")
    body0 = a.artifact('{"data":{"repository":{"discussion":{"id":"D_1","body":"before"}}}}')
    body1 = a.artifact('{"data":{"repository":{"discussion":{"id":"D_1","body":"after"}}},"errors":[{"message":"comments unavailable"}]}')
    a.http(baseline, "discussion0", body=body0, service="github_graphql", capture_extra={"scope_key": "discussions", "collection_phase": "baseline"})
    a.http(delta, "discussion1", body=body1, service="github_graphql", capture_extra={"scope_key": "discussions"})
    a.insert("idx_entity", entity_id="discussion:1", repository_id=101, entity_kind="discussion",
             platform_id_scheme="github_node_id", platform_entity_id="D_1", number=1)
    for capture, body, version in (("discussion0", body0, "before"), ("discussion1", body1, "after")):
        a.insert("idx_entity_observation", entity_id="discussion:1", repository_id=101, capture_id=capture,
                 raw_body_sha256=body, json_pointer="/data/repository/discussion", extraction_profile="discussion-v1",
                 representation_sha256=hashlib.sha256(version.encode()).hexdigest())
    a.insert("idx_scope_coverage", manifest_sha256=delta["digest"], repository_id=101,
             policy_sha256=a.policy, scope_kind="http", scope_key="discussions", capture_id="discussion1",
             coverage_status="partial", reason="GraphQL HTTP 200 contains errors")
    a.insert("idx_scope_coverage", manifest_sha256=baseline["digest"], repository_id=101,
             policy_sha256=a.policy, scope_kind="http", scope_key="discussions-comments",
             coverage_status="unavailable", availability="disabled", reason="feature explicitly disabled")
    rows = a.db.execute("""SELECT o.raw_body_sha256, o.json_pointer, o.representation_sha256,
        c.collection_phase, h.status_code FROM idx_entity_observation o
        JOIN idx_capture c ON c.capture_id = o.capture_id JOIN idx_http_response h ON h.capture_id = c.capture_id
        WHERE o.entity_id = ? ORDER BY c.request_finished_at_us, c.capture_id""", ("discussion:1",)).fetchall()
    assert len(rows) == 2 and rows[0][2] != rows[1][2]
    assert (rows[0][0], rows[0][1], rows[0][3]) == (body0, "/data/repository/discussion", "baseline")
    assert rows[1][4] == 200  # response success never implies complete GraphQL data.
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_entity_observation SET raw_body_sha256 = ? WHERE capture_id = 'discussion1'", (body0,))
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_entity", entity_id="foreign-reply", repository_id=202, entity_kind="discussion_comment",
                 platform_id_scheme="github_node_id", platform_entity_id="DC_2", parent_entity_id="discussion:1")


def test_schedule_gaps_and_independent_service_cooldowns(archive):
    a = archive
    declaration = a.journal(101, "schedule-declaration")
    resolution = a.journal(101, "missed-slot", at=2_000_000)
    a.insert("idx_schedule_slot", slot_id="missed", repository_id=101, policy_sha256=a.policy,
             scope_kind="git", scope_key="advertised-refs", scheduled_at_us=1_000_000, due_by_us=1_500_000,
             declaration_record_sha256=declaration, resolution="missed", resolution_record_sha256=resolution,
             resolved_at_us=2_000_000, gap_reason="host unavailable")
    for service, remaining in (("github_rest", 0), ("github_graphql", 4999), ("github_git", None)):
        a.insert("op_rate_bucket", service=service, auth_bucket="public-readonly:study", primary_remaining=remaining,
                 primary_limit=5000 if remaining is not None else None, updated_at_us=2_000_000,
                 secondary_cooldown_until_us=3_000_000 if service == "github_rest" else None)
    a.insert("op_job", job_id="retry-git", repository_id=101, policy_sha256=a.policy, slot_id="missed",
             scope_kind="git", scope_key="advertised-refs", service="github_git", auth_bucket="public-readonly:study",
             source_uri="https://github.com/example/repo.git", state="queued", not_before_us=3_000_000,
             created_at_us=2_000_000, updated_at_us=2_000_000)
    a.db.execute("UPDATE op_job SET state='leased', lease_owner='worker-1', lease_expires_at_us=4000000 WHERE job_id='retry-git'")
    assert a.db.execute("SELECT primary_remaining FROM op_rate_bucket WHERE service='github_graphql'").fetchone()[0] == 4999
    assert a.db.execute("SELECT resolution, gap_reason FROM idx_schedule_slot WHERE slot_id='missed'").fetchone()[0] == "missed"
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE op_job SET repository_id=202 WHERE job_id='retry-git'")


def test_study_checkpoint_binds_commit_members_cutoff_and_proof(history):
    a, baseline, delta, *_ = history
    checkpoint = a.artifact("canonical checkpoint: study commit + interval index + cutoff")
    index = a.artifact("interval index containing both repository manifests and archive roots")
    a.insert("idx_study_checkpoint", checkpoint_sha256=checkpoint, study_id="public-ics-ot-study", ordinal=1,
             study_object_format="sha1", study_commit_oid="1" * 40, interval_index_sha256=index,
             interval_started_at_us=1_000_000, interval_finished_at_us=2_000_100, created_at_us=2_000_200,
             journal_cutoff_sequence=a.sequence, journal_cutoff_sha256=a.previous_record)
    for manifest in (baseline, delta):
        a.insert("idx_checkpoint_manifest", checkpoint_sha256=checkpoint,
                 manifest_sha256=manifest["digest"], repository_id=101)
    pending = a.artifact("checkpoint pending OTS receipt")
    upgraded = a.artifact("checkpoint upgraded OTS proof")
    for ident, state, proof, previous in (("p", "pending", pending, None), ("u", "upgraded", upgraded, "p"), ("v", "verified", upgraded, "u")):
        a.insert("idx_attestation", attestation_id=ident, subject_sha256=checkpoint, previous_attestation_id=previous,
                 scheme="ots", state=state, proof_sha256=proof, evidence_record_sha256=delta["record"],
                 recorded_at_us=3_000_000, issuer="calendar.example", verified_at_us=3_000_000 if state == "verified" else None,
                 block_height=1_000_000 if state == "verified" else None, block_hash="2" * 64 if state == "verified" else None)
    result = a.db.execute("""SELECT c.study_commit_oid, a.proof_sha256 FROM idx_study_checkpoint c
        JOIN idx_attestation a ON a.subject_sha256=c.checkpoint_sha256 WHERE a.state='verified'""").fetchone()
    assert tuple(result) == ("1" * 40, upgraded)
    later = a.manifest(101, 3, 3_000_000, previous=delta["digest"])
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_checkpoint_manifest", checkpoint_sha256=checkpoint, manifest_sha256=later["digest"], repository_id=101)
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_attestation", attestation_id="wrong-subject", subject_sha256=baseline["digest"],
                 previous_attestation_id="p", scheme="ots", state="pending", evidence_record_sha256=baseline["record"],
                 recorded_at_us=3_000_001, issuer="calendar.example")


def test_monthly_byte_budget_is_aggregate_and_never_deletes_evidence(archive):
    a = archive
    policy = a.db.execute("SELECT monthly_new_evidence_budget_bytes, budget_mode, budget_exhaustion_action FROM idx_capture_policy").fetchone()
    budget = policy[0]
    assert tuple(policy) == (50_000_000_000, "hard_cap", "pause_collection")
    for column, unsupported in (("budget_mode", "soft_cap"), ("budget_exhaustion_action", "warn_only"),
                                ("budget_exhaustion_action", "delete_evidence"), ("budget_exhaustion_action", "raise_limit")):
        with pytest.raises(sqlite3.IntegrityError):
            a.db.execute(f"UPDATE idx_capture_policy SET {column}=?", (unsupported,))
    # These are historical/imported facts, NOT new writes admitted by a running
    # collector. Replay must retain true sizes even when history exceeds the hard
    # cap. Metadata-only sizes avoid allocating giant payloads. Each stored
    # representation is below 50 GB; their aggregate compressed growth exceeds it.
    a.artifact("large-new-evidence-a", size=90_000_000_000, stored_size=30_000_000_000, archived_at=1_000_000)
    a.artifact("large-new-evidence-b", size=80_000_000_000, stored_size=25_000_000_000, archived_at=2_000_000)
    # A repeat reference deduplicates to its already indexed physical representation.
    a.artifact("large-new-evidence-a", archived_at=2_500_000)
    total = a.db.execute("SELECT SUM(stored_byte_length) FROM idx_artifact_storage WHERE first_archived_at_us >= ? AND first_archived_at_us < ?",
                         (1_000_000, 3_000_000)).fetchone()[0]
    assert total == 55_000_000_000 and total > budget
    assert a.db.execute("SELECT COUNT(*) FROM idx_artifact_storage WHERE first_archived_at_us >= 1000000").fetchone()[0] == 2
    logical = a.db.execute("""SELECT SUM(a.byte_length) FROM idx_artifact a JOIN idx_artifact_storage s
        ON s.logical_sha256 = a.sha256 WHERE s.first_archived_at_us >= 1000000""").fetchone()[0]
    assert logical == 170_000_000_000 and logical != total
    # Hard enforcement belongs to future admission/reservation before writes,
    # with preserved pause/gap facts. The index must also accept a single already
    # captured historical artifact larger than the limit without deleting history.
    a.artifact("already-captured-oversize", size=budget * 2, stored_size=budget + 1, archived_at=3_000_000)
    assert a.db.execute("SELECT COUNT(*) FROM idx_artifact_storage WHERE first_archived_at_us >= 1000000").fetchone()[0] == 3


def test_xz_default_recompression_and_identity_preserve_logical_identity(archive):
    a = archive
    payload = ('{"repository":101,"scope":"public study metadata"}\n' * 1000).encode()
    logical = a.artifact(payload.decode(), archived_at=1_000_000)
    default = a.db.execute("SELECT * FROM idx_artifact_storage WHERE logical_sha256=?", (logical,)).fetchone()
    compressed = lzma.compress(payload)
    assert default["encoding"] == "xz"
    assert default["stored_sha256"] == hashlib.sha256(compressed).hexdigest()
    assert default["stored_byte_length"] == len(compressed)
    assert lzma.decompress(compressed) == payload
    assert hashlib.sha256(lzma.decompress(compressed)).hexdigest() == logical
    assert default["stored_byte_length"] < len(payload)

    # Recompression creates a second physical representation of the SAME logical
    # artifact; the original compressed stream remains retained and addressable.
    recompressed = lzma.compress(payload, preset=0)
    recompressed_sha = hashlib.sha256(recompressed).hexdigest()
    assert recompressed_sha != default["stored_sha256"] and lzma.decompress(recompressed) == payload
    a.insert("idx_artifact_storage", stored_sha256=recompressed_sha, logical_sha256=logical,
             stored_byte_length=len(recompressed), archive_relpath=f"objects/{recompressed_sha}.xz", first_archived_at_us=2_000_000)
    a.insert("idx_artifact_storage", stored_sha256=logical, logical_sha256=logical, encoding="identity",
             stored_byte_length=len(payload), archive_relpath="study/interval-metadata.json", first_archived_at_us=3_000_000)
    assert a.db.execute("SELECT COUNT(*) FROM idx_artifact WHERE sha256=?", (logical,)).fetchone()[0] == 1
    stored = a.db.execute("SELECT SUM(stored_byte_length), COUNT(*) FROM idx_artifact_storage WHERE logical_sha256=?", (logical,)).fetchone()
    assert tuple(stored) == (len(compressed) + len(recompressed) + len(payload), 3)
    assert a.db.execute("SELECT byte_length FROM idx_artifact WHERE sha256=?", (logical,)).fetchone()[0] == len(payload)

    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_artifact_storage", stored_sha256=recompressed_sha, logical_sha256=logical,
                 stored_byte_length=1, archive_relpath="conflicting-representation.xz", first_archived_at_us=4_000_000)
    with pytest.raises(sqlite3.IntegrityError):
        a.db.execute("UPDATE idx_artifact_storage SET stored_byte_length=1 WHERE stored_sha256=?", (recompressed_sha,))
    other = a.artifact("other logical bytes")
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_artifact_storage", stored_sha256="0" * 64, logical_sha256=other, encoding="identity",
                 stored_byte_length=len("other logical bytes"), archive_relpath="wrong-identity-hash", first_archived_at_us=4_000_000)
    with pytest.raises(sqlite3.IntegrityError):
        a.insert("idx_artifact_storage", stored_sha256=other, logical_sha256=other, encoding="identity",
                 stored_byte_length=1, archive_relpath="wrong-identity-size", first_archived_at_us=4_000_000)
