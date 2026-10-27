"""Bounded recovery uses the real envelope codec and an empty-runner restart."""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from icsot_observer.core import canonical_json, sha256
from icsot_observer.github_state import (GitHubStateStore, RecoveryCandidatePool,
    StateConflictError, StateDeferredError, StateError)
from icsot_observer.legacy_recovery import (PILOT_ID, PILOT_SLUG, RecoveryJournal,
    freeze_manifest, recover)
from icsot_observer.legacy_bootstrap import MigrationError
from test_github_state import setup, rsa_key, write, clear, cas_file


def pool_for(store, old, parts):
    return RecoveryCandidatePool(store.transport.repository, store.repository_id, store.slug, store.recipient,
                                 "c" * 32, "d" * 64, old.generation, tuple(parts))


def old_preparation(store, directory):
    return store.prepare(store.read(), directory=directory, generation="a" * 32,
                         source_import_sha256="b" * 64, quiescent=True)


def test_recovery_candidates_are_authenticated_captured_and_linked_without_prior_index(setup):
    transport, make, temporary = setup
    transport.repository = "owner/archive"
    store = make(small_immutable_bytes=0)
    name = cas_file(store, b"PACK" + os.urandom(24000))
    old = old_preparation(store, temporary / "old")
    raw = json.loads((old.directory / "prepared.json").read_bytes())
    part = raw["assets"][0]
    transport.upload_asset(part["ref"]["release_tag"], part["ref"]["name"], old.directory / part["path"])
    original_assets = copy.deepcopy(transport.assets)
    candidate = pool_for(store, old, [part["ref"]])
    prepared = store.prepare(store.read(), directory=temporary / "recovery", generation="e" * 32,
        source_import_sha256="f" * 64, recovery_candidates=candidate, quiescent=True)
    value = json.loads((prepared.directory / "prepared.json").read_bytes())
    assert prepared.pointer["predecessor_index_sha256"] is None
    assert value["selection"]["pointer"] is None and value["selection"]["index"] is None
    assert value["index"]["parts"][part["ref"]["plaintext_sha256"]] == part["ref"]
    assert (prepared.directory / part["path"]).read_bytes() == original_assets[part["ref"]["release_tag"], part["ref"]["name"]]
    assert value["index"]["context"]["evidence_heads"]["recovery"]["source_ledger_sha256"] == "d" * 64
    estimates = []
    transport.publication_budget = lambda required: estimates.append(required) or {}
    result = store.publish_prepared(prepared, quiescent=True)
    assert estimates == [49]  # New index plus fresh, read-only historical verification.
    assert result["reused_parts"] == 1 and result["new_parts"] == 0
    assert result["state_upload_bytes_acknowledged_this_attempt"] == prepared.pointer["index"]["ciphertext_bytes"]
    assert result["state_generation_new_ciphertext_bytes"] == prepared.pointer["index"]["ciphertext_bytes"]
    assert all(transport.assets[key] == contents for key, contents in original_assets.items())
    assert sum(ref["name"] != "index.enc" for ref in prepared.assets) == 1
    clear(store)
    store.restore(store.read())
    assert (store.root / name).read_bytes().startswith(b"PACK")


@pytest.mark.parametrize("field,value", [("repository_id", 8), ("recipient_spki_sha256", "0" * 64),
    ("destination_repository", "another/archive"), ("old_generation", "9" * 32)])
def test_wrong_target_recipient_destination_or_generation_is_rejected_before_new_ciphertext(setup, field, value):
    transport, make, temporary = setup
    transport.repository = "owner/archive"
    store = make(small_immutable_bytes=0)
    cas_file(store, b"original source")
    old = old_preparation(store, temporary / "old")
    part = old.assets[0]
    candidate = replace(pool_for(store, old, [part]), **{field: value})
    with pytest.raises(StateError, match="Recovery candidate|frozen target"):
        store.prepare(store.read(), directory=temporary / "new", generation="e" * 32,
            source_import_sha256="f" * 64, recovery_candidates=candidate, quiescent=True)
    assert transport.uploads == [] and transport.head is None


def test_candidate_ciphertext_content_cannot_be_relabelled_as_matching_plaintext(setup):
    transport, make, temporary = setup
    transport.repository = "owner/archive"
    store = make(small_immutable_bytes=0)
    original_path = cas_file(store, b"PACK" + os.urandom(12000))
    old = old_preparation(store, temporary / "old")
    asset = json.loads((old.directory / "prepared.json").read_bytes())["assets"][0]
    transport.upload_asset(asset["ref"]["release_tag"], asset["ref"]["name"], old.directory / asset["path"])
    new_content = b"PACK" + os.urandom(12000)
    (store.root / original_path).unlink()
    cas_file(store, new_content)
    forged = copy.deepcopy(asset["ref"])
    forged["plaintext_sha256"] = forged["decoded_sha256"] = sha256(new_content)
    forged["name"] = "part-" + forged["plaintext_sha256"] + ".enc"
    transport.assets[forged["release_tag"], forged["name"]] = transport.assets[asset["ref"]["release_tag"], asset["ref"]["name"]]
    with pytest.raises(StateError, match="metadata differs"):
        store.prepare(store.read(), directory=temporary / "new", generation="e" * 32,
            source_import_sha256="f" * 64, recovery_candidates=pool_for(store, old, [forged]), quiescent=True)
    assert transport.head is None


def test_candidate_pool_estimate_accounts_for_authenticated_existing_raw_parts(setup):
    transport, make, _ = setup
    store = make(small_immutable_bytes=0)
    content = b"original Git pack"
    files = [{"path": "objects/sha256/aa/example", "bytes": len(content), "sha256": sha256(content), "mode": 0o600}]
    ref = {"release_tag": "old", "name": "part.enc", "ciphertext_sha256": "c" * 64,
           "ciphertext_bytes": 100, "decoded_sha256": sha256(content), "decoded_bytes": len(content), "kind": "raw"}
    parts = {(sha256(content), len(content), "raw"): ref}
    prior = {"parts": {}, "files": []}
    assert store._publication_requests_estimate(files, prior) == 24
    assert store._publication_requests_estimate(files, prior, parts) == 36  # GET + bounded cold-release metadata, no upload.
    from icsot_observer.github_state import _asset_identity
    store._verified_parts.add(_asset_identity(ref))
    assert store._publication_requests_estimate(files, prior, parts) == 22


class MemoryJournal:
    values = {}
    events = []
    def __init__(self, ledger, manifest, digest):
        self.key = manifest["recovery_epoch"]
        self.current = copy.deepcopy(self.values.get(self.key))
    def write(self, value):
        self.current = copy.deepcopy(value)
        self.values[self.key] = self.current
        self.events.append(copy.deepcopy(value))
        return self.current


@pytest.fixture
def pilot(setup, monkeypatch):
    transport, make, temporary = setup
    transport.repository = "owner/archive"
    store = make(PILOT_ID, small_immutable_bytes=0)
    store.slug = PILOT_SLUG
    values = [b"PACK" + os.urandom(12000) for _ in range(3)]
    for value in values:
        cas_file(store, value)
    old = old_preparation(store, temporary / "original-prepared")
    old_raw = json.loads((old.directory / "prepared.json").read_bytes())
    for asset in old_raw["assets"][:2]:
        transport.upload_asset(asset["ref"]["release_tag"], asset["ref"]["name"], old.directory / asset["path"])
    record = {"repository_id": PILOT_ID, "slug": PILOT_SLUG, "strategy": "legacy_seed", "disposition": "deferred",
        "external_recovery_required": True, "migration_id": "1" * 64, "prepared_generation": old.generation,
        "prepared_assets": list(old.assets), "created_at": "2026-10-27T00:00:00.000000Z",
        "source_index_sha256": "2" * 64, "source_manifest_sha256": "3" * 64, "migration_receipt_sha256": "4" * 64}
    entry = {"repository_id": PILOT_ID, "slug": PILOT_SLUG, "strategy": "legacy_seed",
             "source_index": {"sha256": "2" * 64}, "source_manifest": {"sha256": "3" * 64}}
    plan = {"migration_id": "1" * 64, "repositories": [entry], "code_sha": "5" * 40,
            "operational_recipient_spki_sha256": store.recipient, "config_source_sha256": "6" * 64}
    census = {"repository_id": PILOT_ID, "slug": PILOT_SLUG, "generation": old.generation,
        "authoritative_pointer_exists": False, "checks": [{"release_tag": ref["release_tag"], "name": ref["name"],
        "status": "match" if number < 2 else "missing"} for number, ref in enumerate(old.assets)]}
    manifest = freeze_manifest(plan, record, census, destination_repository=transport.repository,
        epoch="7" * 32, source_plan_sha256=sha256(canonical_json(plan)), source_plan_asset={
            "release_repository": transport.repository, "release_tag": "source-plan", "name": "migration-plan.json",
            "sha256": sha256(canonical_json(plan)), "bytes": len(canonical_json(plan)), "release_id": 1, "asset_id": 2})
    ledger = SimpleNamespace(transport=transport, read=lambda migration, rid: copy.deepcopy(record))
    config = SimpleNamespace(history_profile="full_history", repositories=(PILOT_SLUG,))
    imports = []
    def importer(plan, entry, **options):
        imports.append(options)
        for value in values:
            cas_file(store, value)
        write(store, "new-import.json", canonical_json({"code_sha": options["code_sha"], "at": options["imported_at"]}))
        return {"receipt_digest": sha256((store.root / "new-import.json").read_bytes()),
                "seed": {"seed_sha256": "9" * 64}, "original": {
                    "started_at": "2026-10-20T00:00:00.000000Z", "finished_at": "2026-10-20T00:01:00.000000Z"}}
    monkeypatch.setattr("icsot_observer.legacy_recovery.import_legacy_seed", importer)
    MemoryJournal.values, MemoryJournal.events = {}, []
    clear(store)
    def run(attempt="one", current_store=store, scratch=None, journal_factory=MemoryJournal, **retry_options):
        return recover(manifest, sha256(canonical_json(manifest)), code_sha="a" * 40, config=config,
            backend=current_store, ledger=ledger, reader=SimpleNamespace(metadata=lambda ref: canonical_json(plan)), working_root=store.root,
            scratch=scratch or temporary / "scratch", operational_private_key_path=store.private_key,
            evidence_public_key_path=store.public_key, journal_factory=journal_factory, attempt_identity=attempt, **retry_options)
    return SimpleNamespace(transport=transport, store=store, run=run, imports=imports, temporary=temporary,
                           record=record, manifest=manifest, ledger=ledger, config=config)


def test_interrupted_partial_generation_reimports_on_empty_runner_and_preserves_old_refs(pilot):
    p = pilot
    old_assets = copy.deepcopy(p.transport.assets)
    p.transport.fail_upload = lambda name: name == "index.enc"
    with pytest.raises(StateError, match="Injected"):
        p.run()
    first = copy.deepcopy(MemoryJournal.values["7" * 32])
    assert first["status"] == "upload_unacknowledged"
    assert first["attempts"][0]["descriptor"] and p.transport.head is None
    assert all(item["status"] != "remote_prepared" for item in MemoryJournal.events)
    first_generation = first["attempts"][0]["generation"]
    clear(p.store)
    shutil.rmtree(p.temporary / "scratch")
    p.transport.fail_upload = None
    fresh = GitHubStateStore(p.transport, repository_id=PILOT_ID, slug=PILOT_SLUG,
        public_key=p.store.public_key, private_key=p.store.private_key, logical_root=p.store.root, small_immutable_bytes=0)
    result = p.run("two", current_store=fresh)
    assert result["status"] == "complete" and result["generation"] != first_generation
    assert len(p.imports) == 2
    assert all(option["code_sha"] == "a" * 40 and option["imported_at"] != p.record["created_at"] for option in p.imports)
    assert p.ledger.read(None, None) == p.record  # Original hold is never cleared or replaced.
    current = fresh.read()
    assert current.pointer["predecessor_index_sha256"] is None
    assert first_generation in current.index["context"]["evidence_heads"]["recovery"]["lineage_generations"]
    assert all(p.transport.assets[key] == content for key, content in old_assets.items())
    assert MemoryJournal.values["7" * 32]["status"] == "complete"


def test_empty_runner_resumes_fully_uploaded_generation_without_reimport(pilot, monkeypatch):
    p = pilot
    def deferred(*args, **kwargs):
        raise StateDeferredError("Interrupted before CAS")
    monkeypatch.setattr(p.store, "_advance", deferred)
    with pytest.raises(StateDeferredError):
        p.run()
    first = MemoryJournal.values["7" * 32]
    assert first["status"] == "remote_prepared"
    original_generation = first["attempts"][0]["generation"]
    clear(p.store)
    shutil.rmtree(p.temporary / "scratch")
    fresh = GitHubStateStore(p.transport, repository_id=PILOT_ID, slug=PILOT_SLUG,
        public_key=p.store.public_key, private_key=p.store.private_key, logical_root=p.store.root, small_immutable_bytes=0)
    result = p.run("two", current_store=fresh)
    assert result["generation"] == original_generation and len(p.imports) == 1


def test_current_state_wins_before_any_recovery_import_or_journal_write(pilot):
    p = pilot
    write(p.store, "current.json", b"current state")
    p.store.publish(p.store.read(), quiescent=True)
    before = list(p.transport.uploads)
    result = p.run()
    assert result["status"] == "current_state_wins"
    assert p.imports == [] and MemoryJournal.events == [] and p.transport.uploads == before


def test_changed_frozen_source_ledger_rejects_recovery_before_import(pilot):
    p = pilot
    p.ledger.read = lambda *args: {**p.record, "created_at": "changed"}
    with pytest.raises(StateConflictError, match="source ledger changed"):
        p.run()
    assert p.imports == [] and MemoryJournal.events == []


def test_recovery_journal_cas_refuses_another_writer():
    old, other = {"version": 1}, {"version": 2}
    ledger = SimpleNamespace(transport=SimpleNamespace(repository="owner/archive"), _head=lambda: "head")
    values = iter([None, other])
    ledger._read = lambda *args: next(values)
    manifest = {"source_plan": {"migration_id": "a" * 64}, "repository_id": PILOT_ID, "slug": PILOT_SLUG,
                "recovery_epoch": "b" * 32, "source_ledger_sha256": "c" * 64}
    journal = RecoveryJournal(ledger, manifest, "d" * 64)
    ledger.transport._api = lambda *args, **kwargs: pytest.fail("CAS conflict must not mutate")
    with pytest.raises(StateConflictError, match="journal changed"):
        journal.write(old)


def test_descriptor_and_durable_identity_precede_first_new_generation_part_upload(pilot):
    p = pilot
    original_upload = p.transport.upload_asset
    checked = []
    def upload(tag, name, source):
        if tag.startswith(f"collector-state-r{PILOT_ID}-g") and name.startswith("part-"):
            journal = MemoryJournal.values["7" * 32]
            assert journal["attempts"][-1]["descriptor"]
            descriptor = journal["attempts"][-1]["descriptor"]
            assert (descriptor["release_tag"], descriptor["name"]) in p.transport.assets
            assert journal["attempts"][-1]["generation"] in tag
            checked.append(name)
        return original_upload(tag, name, source)
    p.transport.upload_asset = upload
    p.run()
    assert checked


def test_two_lost_partial_generations_remain_held_without_third_import(pilot):
    p = pilot
    p.transport.fail_upload = lambda name: name == "index.enc"
    for attempt in ("one", "two"):
        with pytest.raises(StateError, match="Injected"):
            p.run(attempt)
        clear(p.store)
        shutil.rmtree(p.temporary / "scratch")
    result = p.run("three")
    assert result["reason"] == "bounded_recovery_generation_limit" and len(p.imports) == 2
    assert p.transport.head is None and len(MemoryJournal.values["7" * 32]["attempts"]) == 2


def test_tampered_candidate_with_updated_cipher_hash_still_fails_gcm_authentication(setup):
    transport, make, temporary = setup
    transport.repository = "owner/archive"
    store = make(small_immutable_bytes=0)
    cas_file(store, b"PACK" + os.urandom(12000))
    old = old_preparation(store, temporary / "old")
    asset = json.loads((old.directory / "prepared.json").read_bytes())["assets"][0]
    ref = copy.deepcopy(asset["ref"])
    data = (old.directory / asset["path"]).read_bytes()
    damaged = data[:-1] + bytes([data[-1] ^ 1])
    ref["ciphertext_sha256"] = sha256(damaged)
    transport.assets[ref["release_tag"], ref["name"]] = damaged
    with pytest.raises(StateError, match="authenticate"):
        store.prepare(store.read(), directory=temporary / "new", generation="e" * 32,
            source_import_sha256="f" * 64, recovery_candidates=pool_for(store, old, [ref]), quiescent=True)
    assert transport.head is None


def test_embedded_recovery_source_context_is_rechecked_against_pinned_original_plan(pilot):
    p = pilot
    p.manifest['source_plan']['config_source_sha256'] = '0' * 64
    with pytest.raises(MigrationError, match='original immutable plan'):
        p.run()
    assert p.imports == [] and MemoryJournal.events == []


def test_full_remote_closure_recovers_in_fresh_python_process_without_parent_state(pilot, monkeypatch):
    p = pilot
    def interrupted_cas(*args, **kwargs):
        raise StateDeferredError('Stop after complete remote closure')
    monkeypatch.setattr(p.store, '_advance', interrupted_cas)
    with pytest.raises(StateDeferredError):
        p.run()
    journal = copy.deepcopy(MemoryJournal.values['7' * 32])
    assert journal['status'] == 'remote_prepared'
    expected_generation = journal['attempts'][-1]['generation']
    remote = p.temporary / 'serialized-remote'
    remote.mkdir()
    assets = []
    for number, ((tag, name), contents) in enumerate(p.transport.assets.items()):
        path = remote / f'ciphertext-{number}'
        path.write_bytes(contents)
        assets.append({'release_tag': tag, 'name': name, 'path': str(path)})
    source_plan = p.manifest['source_plan_asset']
    source_plan_path = remote / 'original-plan.json'
    source_plan_path.write_bytes(canonical_json(p.manifest['source_plan']))
    assets.append({'release_tag': source_plan['release_tag'], 'name': source_plan['name'], 'path': str(source_plan_path)})
    refs_path, journal_path = remote / 'refs.json', remote / 'journal.json'
    refs_path.write_bytes(canonical_json({'head': None, 'commits': {}, 'bindings': {}}))
    journal_path.write_bytes(canonical_json(journal))
    inputs = {'assets': assets, 'refs': str(refs_path), 'journal': str(journal_path),
              'manifest': p.manifest, 'public_key': str(p.store.public_key), 'private_key': str(p.store.private_key),
              'working_root': str(p.store.root), 'scratch': str(p.temporary / 'fresh-process-scratch')}
    input_path = remote / 'inputs.json'
    input_path.write_bytes(canonical_json(inputs))
    # The new process receives only a simulated remote service and key paths.
    # No retained local plaintext or prepared ciphertext remains to rescue it.
    clear(p.store)
    shutil.rmtree(p.temporary / 'scratch')
    shutil.rmtree(p.temporary / 'original-prepared')
    assert list(p.store.root.iterdir()) == [p.store.root / '.collector.lock']
    child = r'''
import hashlib,json,shutil,sys
from pathlib import Path
from types import SimpleNamespace
from icsot_observer.core import canonical_json,sha256
from icsot_observer.github_state import GitHubStateStore
import icsot_observer.legacy_recovery as recovery
options=json.loads(Path(sys.argv[1]).read_bytes())
manifest=options['manifest']
class FreshRemote:
    repository=manifest['destination_repository']
    def __init__(self):
        self.refs_path=Path(options['refs'])
        self.storage={(a['release_tag'],a['name']):Path(a['path']) for a in options['assets']}
        self.request_count=0
        self.rate_remaining=None
        self._assets={}
        self._releases={}
        self.events=[]
    def state(self): return json.loads(self.refs_path.read_bytes())
    def save(self,value): self.refs_path.write_bytes(canonical_json(value))
    def branch_head(self): self.request_count+=1;return self.state()['head']
    def read_pointer(self,head,repo_id): return self.state()['commits'][head].get(str(repo_id))
    def read_slug_binding(self,head,slug): return self.state()['bindings'][head].get(slug.lower())
    def ensure_release(self,tag): self.request_count+=1
    def find_asset(self,tag,name,refresh=False):
        self.request_count+=1
        path=self.storage.get((tag,name))
        return None if path is None else {'name':name,'size':path.stat().st_size,'state':'uploaded',
            'digest':'sha256:'+sha256(path.read_bytes())}
    def download_asset(self,tag,name,target):
        self.request_count+=1;self.events.append(('download',tag,name))
        shutil.copyfile(self.storage[tag,name],target)
    def upload_asset(self,*args,**kwargs): raise AssertionError('Exact resume must not upload or regenerate ciphertext')
    def publication_budget(self,required): return {'required_requests':required}
    def commit_pointer(self,parent,repo_id,data):
        state=self.state();assert state['head']==parent
        commit=sha256(data)[:40]
        pointer=json.loads(data)
        tree=dict(state['commits'].get(parent,{}));tree[str(repo_id)]=data.decode()
        binding=dict(state['bindings'].get(parent,{}));binding[pointer['slug'].lower()]=canonical_json(
            {'schema_version':1,'slug_key':pointer['slug'].lower(),'repository_id':repo_id}).decode()
        state['commits'][commit]=tree;state['bindings'][commit]=binding;self.save(state)
        self.events.append(('commit',commit));return commit
    def advance_branch(self,expected,commit):
        state=self.state()
        if state['head']!=expected:return False
        state['head']=commit;self.save(state);self.events.append(('advance',commit));return True
transport=FreshRemote()
# Git pointer transport returns byte strings, whereas its serialized service uses JSON strings.
read_pointer=transport.read_pointer
transport.read_pointer=lambda head,rid: (raw.encode() if (raw:=read_pointer(head,rid)) is not None else None)
read_binding=transport.read_slug_binding
transport.read_slug_binding=lambda head,slug: (raw.encode() if (raw:=read_binding(head,slug)) is not None else None)
store=GitHubStateStore(transport,repository_id=recovery.PILOT_ID,slug=recovery.PILOT_SLUG,
    public_key=options['public_key'],private_key=options['private_key'],logical_root=options['working_root'],small_immutable_bytes=0)
assert transport.request_count==0 and transport.rate_remaining is None and not transport._assets and not transport._releases
assert not store._verified_parts and not store._verified_downloads and not store._prepared_verified
class FreshJournal:
    def __init__(self,*args):self.current=json.loads(Path(options['journal']).read_bytes())
    def write(self,value):
        self.current=value;Path(options['journal']).write_bytes(canonical_json(value));return value
ledger=SimpleNamespace(transport=transport,read=lambda *args:manifest['source_ledger'])
reader=SimpleNamespace(metadata=lambda ref:transport.storage[ref['release_tag'],ref['name']].read_bytes())
def forbidden(*args,**kwargs):raise AssertionError('Fresh process must not reimport legacy source')
recovery.import_legacy_seed=forbidden
result=recovery.recover(manifest,sha256(canonical_json(manifest)),code_sha='a'*40,
    config=SimpleNamespace(history_profile='full_history',repositories=(recovery.PILOT_SLUG,)),backend=store,
    ledger=ledger,reader=reader,working_root=Path(options['working_root']),scratch=Path(options['scratch']),
    operational_private_key_path=Path(options['private_key']),evidence_public_key_path=Path(options['public_key']),
    journal_factory=FreshJournal,attempt_identity='fresh-os-process')
selected=store.read()
assert selected.pointer['generation']==result['generation']
assert selected.pointer['predecessor_index_sha256'] is None
assert store._verified_parts and store._verified_downloads
assert json.loads(Path(options['journal']).read_bytes())['status']=='complete'
assert sum(e[0]=='advance' for e in transport.events)==1
print(json.dumps({'status':result['status'],'generation':result['generation'],
                  'authenticated_parts':len(store._verified_parts),'requests':transport.request_count}))
'''
    environment = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
    outcome = subprocess.run([sys.executable, '-c', child, str(input_path)], cwd=remote,
                             env=environment, text=True, capture_output=True, timeout=60)
    assert outcome.returncode == 0, outcome.stderr
    report = json.loads(outcome.stdout)
    assert report['status'] == 'complete' and report['generation'] == expected_generation
    assert report['authenticated_parts'] > 0 and report['requests'] > 0
    refs = json.loads(refs_path.read_bytes())
    assert json.loads(refs['commits'][refs['head']][str(PILOT_ID)])['generation'] == expected_generation
    assert len(p.imports) == 1


def test_nonuploaded_candidate_is_not_admitted_as_remote_reuse(pilot):
    p = pilot
    original_find = p.transport.find_asset
    p.transport.find_asset = lambda *args, **kwargs: ({**ref, 'state': 'new'}
        if (ref := original_find(*args, **kwargs)) is not None else None)
    from icsot_observer.legacy_recovery import _available
    assert _available(p.store, p.manifest['candidate_parts']) == []


def test_real_provider_confirmed_missing_generation_release_is_unavailable():
    from icsot_observer.github_state import GhCliStateTransport
    from icsot_observer.legacy_recovery import _available
    from test_github_state import graphql_result, metadata_response
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        if '/releases/tags/' in args[2]:
            return metadata_response(args, {}, status=404)
        if args[2] == 'graphql':
            value = graphql_result(None)
            value['data']['repository']['nameWithOwner'] = 'owner/archive'
            return metadata_response(args, value)
        raise AssertionError('Missing generation must never create or list releases')
    transport = GhCliStateTransport('owner/archive', runner=runner)
    ref = {'release_tag': 'collector-state-r1614410-g' + 'a' * 32, 'name': 'index.enc',
           'ciphertext_sha256': 'b' * 64, 'ciphertext_bytes': 100}
    assert _available(SimpleNamespace(transport=transport), [ref]) == []
    assert len(calls) == 2


@pytest.mark.parametrize('failure', ['auth403', 'quota429', 'malformed_json', 'graphql_error', 'graphql_partial'])
def test_real_provider_candidate_errors_are_never_classified_as_absence(failure):
    from icsot_observer.github_state import GhCliStateTransport, StateReleaseMissingError
    from icsot_observer.legacy_recovery import _available
    from test_github_state import graphql_result, metadata_response
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        if failure == 'auth403':
            return metadata_response(args, {'message': 'Forbidden'}, status=403)
        if failure == 'quota429':
            return subprocess.CompletedProcess(args, 1,
                b'HTTP/2.0 429 Too Many Requests\r\nRetry-After: 120\r\n\r\n{"message":"secondary rate limit"}', b'')
        if failure == 'malformed_json':
            return subprocess.CompletedProcess(args, 0, b'HTTP/2.0 200 OK\r\n\r\n{broken', b'')
        if '/releases/tags/' in args[2]:
            return metadata_response(args, {}, status=404)
        value = graphql_result(None, repository='owner/archive')
        if failure == 'graphql_error':
            value['errors'] = [{'type': 'FORBIDDEN', 'message': 'denied'}]
        else:
            value['data']['repository'] = None
        return metadata_response(args, value)
    transport = GhCliStateTransport('owner/archive', runner=runner, clock=lambda: 1000)
    ref = {'release_tag': 'collector-state-r1614410-g' + 'a' * 32, 'name': 'index.enc',
           'ciphertext_sha256': 'b' * 64, 'ciphertext_bytes': 100}
    with pytest.raises(StateError) as error:
        _available(SimpleNamespace(transport=transport), [ref])
    assert not isinstance(error.value, StateReleaseMissingError)
    assert len(calls) <= 2 and all('/releases' not in call or '/tags/' in call for call in calls)


def test_restart_after_descriptor_journal_and_before_main_release_creation(pilot):
    from icsot_observer.github_state import GhCliStateTransport
    from test_github_state import graphql_result, metadata_response
    p = pilot
    original_assets = copy.deepcopy(p.transport.assets)
    def stop_before_release(required):
        if MemoryJournal.values:
            raise StateDeferredError('Stopped before creating generation release')
        return {}
    p.transport.publication_budget = stop_before_release
    with pytest.raises(StateDeferredError):
        p.run()
    first = copy.deepcopy(MemoryJournal.values['7' * 32])
    missing_tag = f"collector-state-r{PILOT_ID}-g{first['attempts'][0]['generation']}"
    assert not any(tag == missing_tag for tag, name in p.transport.assets)
    clear(p.store)
    shutil.rmtree(p.temporary / 'scratch')
    calls = []
    def runner(args, **kwargs):
        calls.append(args[2])
        if '/releases/tags/' in args[2]:
            return metadata_response(args, {}, status=404)
        return metadata_response(args, graphql_result(None, repository='owner/archive'))
    real = GhCliStateTransport('owner/archive', runner=runner)
    ordinary_find = p.transport.find_asset
    def release_aware(tag, name, *, refresh=False):
        if tag == missing_tag:
            return real.find_asset(tag, name, refresh=refresh)
        return ordinary_find(tag, name, refresh=refresh)
    p.transport.find_asset = release_aware
    p.transport.publication_budget = lambda required: {}
    result = p.run('new-runner')
    assert result['status'] == 'complete' and result['generation'] != first['attempts'][0]['generation']
    assert len(p.imports) == 2 and calls and 'graphql' in calls
    assert all(p.transport.assets[key] == value for key, value in original_assets.items())


def test_headerless_provider_quota_mid_upload_waits_with_same_prepared_ciphertext(pilot, monkeypatch):
    from icsot_observer.github_state import GhCliStateTransport
    from test_github_state import rate_response
    import icsot_observer.legacy_recovery as recovery_module
    p = pilot
    now, sleeps, requests, attempted_ciphers, encryptions = [1000], [], [], [], []
    def runner(args, **kwargs):
        requests.append(args[2])
        if args[2] == 'rate_limit':
            return rate_response(args, {'resources': {'core': {'remaining': 0, 'reset': 1120, 'limit': 5000}}},
                                 remaining=0, reset=1120, limit=5000)
        return subprocess.CompletedProcess(args, 1,
            b'HTTP/2.0 403 Forbidden\r\n\r\n{"message":"API rate limit exceeded for installation"}', b'HTTP 403')
    real = GhCliStateTransport('owner/archive', runner=runner, clock=lambda: now[0])
    ordinary_upload = p.transport.upload_asset
    deferred = [False]
    def upload(tag, name, source):
        if tag.startswith(f'collector-state-r{PILOT_ID}-g'):
            attempted_ciphers.append((tag, name, sha256(source.read_bytes())))
            if not deferred[0]:
                deferred[0] = True
                real._api(f'repos/owner/archive/releases/assets', method='POST', payload={})
        return ordinary_upload(tag, name, source)
    p.transport.upload_asset = upload
    encrypt = recovery_module.encrypt_file
    def count_encrypt(*args, **kwargs):
        encryptions.append(1)
        return encrypt(*args, **kwargs)
    monkeypatch.setattr(recovery_module, 'encrypt_file', count_encrypt)
    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds
    result = p.run(clock=lambda: now[0], sleeper=sleep, max_runtime_seconds=600)
    assert result['status'] == 'complete' and len(p.imports) == len(encryptions) == 1
    assert len(MemoryJournal.values['7' * 32]['attempts']) == 1
    assert attempted_ciphers[0] == attempted_ciphers[1]
    assert sum(sleeps) == 120 and max(sleeps) <= 60
    assert requests == ['repos/owner/archive/releases/assets', 'rate_limit']


def test_descriptor_ack_loss_reconciles_same_ciphertext_without_reencryption(pilot, monkeypatch):
    import icsot_observer.legacy_recovery as recovery_module
    p = pilot
    ordinary_upload, encrypted = p.transport.upload_asset, []
    encrypt = recovery_module.encrypt_file
    def count_encrypt(*args, **kwargs):
        encrypted.append(1)
        return encrypt(*args, **kwargs)
    monkeypatch.setattr(recovery_module, 'encrypt_file', count_encrypt)
    def upload(tag, name, source):
        ordinary_upload(tag, name, source)
        if name == 'prepared-descriptor.enc':
            raise OSError('Descriptor acknowledgement lost')
    p.transport.upload_asset = upload
    result = p.run()
    assert result['status'] == 'complete' and len(encrypted) == len(p.imports) == 1
    assert sum(name == 'prepared-descriptor.enc' for tag, name in p.transport.uploads) == 1


def test_quota_reset_beyond_absolute_recovery_budget_preserves_durable_attempt(pilot):
    p = pilot
    original_upload = p.transport.upload_asset
    def upload(tag, name, source):
        if tag.startswith(f'collector-state-r{PILOT_ID}-g'):
            raise StateDeferredError('Reset beyond runtime', retry_not_before=1600)
        original_upload(tag, name, source)
    p.transport.upload_asset = upload
    with pytest.raises(StateDeferredError):
        p.run(clock=lambda: 1000, sleeper=lambda seconds: pytest.fail('Must leave cleanup margin'), max_runtime_seconds=300)
    journal = MemoryJournal.values['7' * 32]
    assert len(journal['attempts']) == len(p.imports) == 1
    assert journal['attempts'][0]['descriptor'] and journal['status'] == 'upload_unacknowledged'
    assert p.transport.head is None and (p.temporary / 'scratch' / 'prepared' / 'prepared.json').exists()


def test_ambiguous_journal_write_retries_identical_frozen_record(pilot):
    p = pilot
    now, writes, failed = [1000], [], [False]
    class AmbiguousJournal(MemoryJournal):
        def write(self, value):
            writes.append(canonical_json(value))
            if not failed[0]:
                failed[0] = True
                self.values[self.key] = copy.deepcopy(value)
                raise StateDeferredError('Journal acknowledgement lost', retry_not_before=1060)
            if len(writes) == 2:
                assert value == self.values[self.key]
            return super().write(value)
    result = p.run(journal_factory=AmbiguousJournal, clock=lambda: now[0],
                   sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds), max_runtime_seconds=600)
    assert result['status'] == 'complete' and writes[0] == writes[1]
    assert len(p.imports) == len(MemoryJournal.values['7' * 32]['attempts']) == 1


def test_descriptor_uncertain_upload_with_corrupt_readback_fails_closed(pilot):
    p = pilot
    ordinary_upload = p.transport.upload_asset
    def upload(tag, name, source):
        ordinary_upload(tag, name, source)
        if name == 'prepared-descriptor.enc':
            data = p.transport.assets[tag, name]
            p.transport.assets[tag, name] = data[:-1] + bytes([data[-1] ^ 1])
            raise OSError('Acknowledgement lost')
    p.transport.upload_asset = upload
    with pytest.raises(StateConflictError, match='descriptor identity differs'):
        p.run()
    assert p.transport.head is None and MemoryJournal.events == [] and len(p.imports) == 1


def test_descriptor_quota_wait_keeps_single_encryption_and_generation(pilot, monkeypatch):
    import icsot_observer.legacy_recovery as recovery_module
    p = pilot
    now, encryptions, failed = [1000], [], [False]
    encrypt = recovery_module.encrypt_file
    def count_encrypt(*args, **kwargs):
        encryptions.append(1)
        return encrypt(*args, **kwargs)
    monkeypatch.setattr(recovery_module, 'encrypt_file', count_encrypt)
    def budget(required):
        if (p.temporary / 'scratch' / 'recovery-descriptor-seal.json').exists() and not failed[0]:
            failed[0] = True
            raise StateDeferredError('Quota before descriptor upload', retry_not_before=1120)
        return {}
    p.transport.publication_budget = budget
    result = p.run(clock=lambda: now[0], sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds), max_runtime_seconds=600)
    assert result['status'] == 'complete' and len(encryptions) == len(p.imports) == 1
    assert now[0] == 1120 and len(MemoryJournal.values['7' * 32]['attempts']) == 1


@pytest.mark.parametrize('fresh_store', [False, True], ids=['warm-verification-cache', 'cold-store'])
def test_deleted_historical_candidate_is_never_published_or_recreated(setup, fresh_store):
    transport, make, temporary = setup
    transport.repository = 'owner/archive'
    store = make(small_immutable_bytes=0)
    cas_file(store, b'PACK' + os.urandom(16000))
    old = old_preparation(store, temporary / 'original')
    asset = json.loads((old.directory / 'prepared.json').read_bytes())['assets'][0]
    ref = asset['ref']
    transport.upload_asset(ref['release_tag'], ref['name'], old.directory / asset['path'])
    prepared = store.prepare(store.read(), directory=temporary / 'replacement', generation='e' * 32,
        source_import_sha256='f' * 64, recovery_candidates=pool_for(store, old, [ref]), quiescent=True)
    # The captured local ciphertext still exists; it must never repair a deleted
    # historical remote identity or be mistaken for fresh remote verification.
    assert (prepared.directory / asset['path']).is_file()
    del transport.assets[ref['release_tag'], ref['name']]
    if fresh_store:
        store = make(small_immutable_bytes=0)
        prepared = store.load_prepared(prepared.directory, prepared.manifest_sha256)
        assert not store._verified_parts
    transport.events.clear()
    prior_uploads = list(transport.uploads)
    with pytest.raises(StateError, match='Historical prepared asset is missing'):
        store.publish_prepared(prepared, quiescent=True)
    assert transport.head is None and transport.uploads == prior_uploads
    assert (ref['release_tag'], ref['name']) not in transport.assets
    assert not any(event[0] in ('release', 'upload', 'commit', 'advance') for event in transport.events)
