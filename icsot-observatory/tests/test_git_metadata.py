import base64
import json
from urllib.parse import unquote

import pytest
from icsot_observer import git_metadata as gm


class FakeGit:
    repository = 'owner/repo'
    def __init__(self):
        self.head = None
        self.blobs, self.trees, self.commits, self.parents, self.calls = {}, {}, {}, {}, []
        self.serial, self.race = 0, False
        self.subtrees = {}
    def ident(self):
        self.serial += 1
        return f'{self.serial:040x}'
    def _api(self, endpoint, *, method='GET', payload=None, missing_ok=False):
        self.calls.append((endpoint, method, payload))
        path = endpoint.removeprefix('repos/owner/repo/')
        if path == 'git/ref/heads/collector-metadata':
            return {'object': {'type': 'commit', 'sha': self.head}} if self.head else None
        if path.startswith('contents/'):
            name, head = path[9:].split('?ref=')
            sha = self.trees[self.commits[head]].get(unquote(name))
            return {'type': 'file', 'sha': sha, 'size': len(self.blobs[sha])} if sha else None
        if path == 'git/blobs' and method == 'POST':
            raw = base64.b64decode(payload['content'], validate=True)
            sha = gm._git_blob_sha(raw)
            self.blobs[sha] = raw
            return {'sha': sha}
        if path.startswith('git/blobs/'):
            sha = path.rsplit('/', 1)[-1]
            raw = self.blobs[sha]
            return {'sha': sha, 'size': len(raw), 'encoding': 'base64', 'content': base64.encodebytes(raw).decode()}
        if path.startswith('git/commits/'):
            return {'tree': {'sha': self.commits[path.rsplit('/', 1)[-1]]}}
        if path.startswith('git/trees/') and method == 'GET':
            sha = path.rsplit('/', 1)[-1]
            if sha in self.subtrees:
                root, prefix = self.subtrees[sha]
            else:
                root, prefix = sha, ''
            grouped = {}
            for name, blob in self.trees[root].items():
                if not name.startswith(prefix):
                    continue
                rest = name[len(prefix):]
                part, separator, _ = rest.partition('/')
                if separator:
                    child_prefix = prefix + part + '/'
                    child_sha = __import__('hashlib').sha1((root + child_prefix).encode()).hexdigest()
                    self.subtrees[child_sha] = (root, child_prefix)
                    grouped[part] = {'path': part, 'type': 'tree', 'mode': '040000', 'sha': child_sha}
                else:
                    grouped[part] = {'path': part, 'type': 'blob', 'mode': '100644', 'sha': blob}
            return {'sha': sha, 'truncated': False, 'tree': list(grouped.values())}
        if path == 'git/trees' and method == 'POST':
            tree = dict(self.trees[payload['base_tree']]) if 'base_tree' in payload else {}
            for item in payload['tree']:
                tree[item['path']] = item['sha']
            sha = self.ident()
            self.trees[sha] = tree
            return {'sha': sha}
        if path == 'git/commits' and method == 'POST':
            sha = self.ident()
            self.commits[sha], self.parents[sha] = payload['tree'], payload['parents']
            return {'sha': sha}
        if path in ('git/refs', 'git/refs/heads/collector-metadata'):
            if self.race:
                self.race = False
                raw = b'parallel'
                blob = gm._git_blob_sha(raw)
                self.blobs[blob] = raw
                tree = dict(self.trees[self.commits[self.head]]) if self.head else {}
                tree['other/path.json'] = blob
                tid = self.ident()
                self.trees[tid] = tree
                cid = self.ident()
                self.commits[cid] = tid
                self.head = cid
                raise RuntimeError('simulated conflict')
            if path == 'git/refs' and self.head is not None:
                raise RuntimeError('branch exists')
            new = payload['sha']
            if path != 'git/refs' and self.parents[new] != [self.head]:
                raise RuntimeError('non-fast-forward')
            self.head = new
            return {'object': {'sha': new}}
        raise AssertionError((path, method))


def test_immutable_update_preserves_pins():
    api = FakeGit()
    store = gm.GitMetadataStore(api)
    old = store.put('a/data.json', b'old')
    assert store.get(old) == b'old' and store.find('a/data.json') == old
    assert store.put('a/data.json', b'old') == old
    with pytest.raises(gm.MetadataError):
        store.put('a/data.json', b'different')
    new = store.put('a/data.json', b'different', allow_update=True)
    assert store.get(old) == b'old' and store.get(new) == b'different'
    assert api.parents[new['commit_sha']] == [old['commit_sha']]


@pytest.mark.parametrize('existing', [False, True])
def test_race_retries_preserving_other_paths(existing):
    api = FakeGit()
    store = gm.GitMetadataStore(api)
    if existing:
        store.put('original/file', b'original')
    api.race = True
    result = store.put('new/file', b'new')
    assert store.get(result) == b'new'
    assert store.get(store.find('other/path.json')) == b'parallel'
    if existing:
        assert store.get(store.find('original/file')) == b'original'
    assert sum(method == 'POST' and path.endswith('git/blobs') for path, method, _ in api.calls) == (2 if existing else 1)


@pytest.mark.parametrize('path', ['', '/absolute', 'a/../b', 'a//b', './a', 'a\\b', 'é', '.hidden'])
def test_unsafe_path_before_api(path):
    api = FakeGit()
    with pytest.raises(gm.MetadataError):
        gm.GitMetadataStore(api).put(path, b'ok')
    assert not api.calls


def test_oversize_and_locator_validation(monkeypatch):
    api = FakeGit()
    store = gm.GitMetadataStore(api)
    monkeypatch.setattr(gm, 'MAX_BLOB_BYTES', 3)
    with pytest.raises(gm.MetadataError):
        store.put('a', b'abcd')
    assert not api.calls
    loc = store.put('a', b'abc')
    for key, value in [('repository', 'other/repo'), ('branch', 'main'), ('path', '../bad'),
                       ('commit_sha', '1'), ('blob_sha', 'x' * 40), ('sha256', '0' * 64),
                       ('bytes', 2), ('bytes', True)]:
        with pytest.raises(gm.MetadataError):
            store.get({**loc, key: value})
    assert store.get(loc) == b'abc'


def test_untrusted_blob_rejected_without_branch_fallback():
    api = FakeGit()
    loc = gm.GitMetadataStore(api).put('a', b'abc')
    api.blobs[loc['blob_sha']] = b'bad'
    api.calls.clear()
    with pytest.raises(gm.MetadataError):
        gm.GitMetadataStore(api).get(loc)
    assert len(api.calls) == 1 and '/git/blobs/' in api.calls[0][0]


def test_cli_and_exclusive_output(monkeypatch, tmp_path, capsys):
    import icsot_observer.github_state as state
    api = FakeGit()
    monkeypatch.setattr(state, 'GhCliStateTransport', lambda repository: api)
    source = tmp_path / 'source'
    source.write_bytes(b'raw\x00bytes')
    github_output = tmp_path / 'output'
    gm.main(['put', '--repository', api.repository, '--path', 'plans/a', '--file', str(source),
             '--github-output', str(github_output)])
    line = capsys.readouterr().out.strip()
    assert github_output.read_text() == 'plan_locator=' + line + '\n'
    assert json.loads(line)['bytes'] == len(source.read_bytes())
    dest = tmp_path / 'dest'
    args = ['get', '--repository', api.repository, '--locator-json', line, '--output', str(dest)]
    gm.main(args)
    assert dest.read_bytes() == source.read_bytes()
    with pytest.raises(FileExistsError):
        gm.main(args)


def test_symlinks_are_rejected_before_contents_lookup():
    api = FakeGit()
    gm.GitMetadataStore(api).put('plans/file', b'data')
    original = api._api
    def symlink(endpoint, *, method='GET', payload=None, missing_ok=False):
        result = original(endpoint, method=method, payload=payload, missing_ok=missing_ok)
        if '/git/trees/' in endpoint and result and any(e['path'] == 'file' for e in result['tree']):
            result['tree'][0]['mode'] = '120000'
        return result
    api._api = symlink
    api.calls.clear()
    with pytest.raises(gm.MetadataError):
        gm.GitMetadataStore(api).find('plans/file')
    assert not any('/contents/' in call[0] for call in api.calls)


def test_repeated_conflicts_are_bounded():
    api = FakeGit()
    original = api._api
    def race(endpoint, *, method='GET', payload=None, missing_ok=False):
        if method in ('POST', 'PATCH') and ('/git/refs' in endpoint):
            api.race = True
        return original(endpoint, method=method, payload=payload, missing_ok=missing_ok)
    api._api = race
    with pytest.raises(gm.MetadataError, match='Too many'):
        gm.GitMetadataStore(api).put('data', b'data')
    assert sum(method in ('POST', 'PATCH') and '/git/refs' in endpoint for endpoint, method, _ in api.calls) == 8
    assert sum(method == 'POST' and endpoint.endswith('/git/blobs') for endpoint, method, _ in api.calls) == 1
