"""Small offline checks for pinned cycle viewer discovery and payload lookup."""
import base64
import copy
import hashlib

import pytest

from icsot_observer.core import canonical_json, sha256
from icsot_observer.viewer_data import GitHubMetadata, MetadataError, ViewerData


def test_cycle_discovery_pins_catalog_and_resolves_physical_payload(tmp_path, monkeypatch):
    (tmp_path / "public_patch_corpus_185.csv").write_text(
        "ID,Cohort,Repository_URL,Repository_Role\nS,Synthetic,https://github.com/example/fixture,primary_git\n")
    repo = "example/fixture"
    dest = "owner/archive"
    tag = "collector-observations-r123-g" + "a" * 32
    physical = "collector-cycle-s44"
    digest = "b" * 64
    part_digest = "c" * 64
    index = {"schema_version": 1, "encrypted": True, "repository_id": 123, "repository": repo,
             "release_tag": tag, "manifest_sha256": digest,
             "members": [{"path": "runs/123/run.manifest.json", "bytes": 3, "sha256": digest}],
             "assets": [{"name": "part.enc", "sha256": part_digest, "bytes": 4,
                         "encryption": {"plaintext_sha256": "d" * 64, "plaintext_bytes": 5}}]}
    index["archive_layout"] = "independent-tar-xz-groups-v2"
    index["groups"] = [{"asset": {"name": "part.enc", "sha256": part_digest}, "members": []}]
    index_raw = canonical_json(index)
    marker = {"generation_release": tag, "repository_id": 123, "slug": repo,
              "observations": [{"manifest_sha256": digest, "index": {"release_tag": tag,
                                "name": "run.index.json", "sha256": sha256(index_raw), "bytes": len(index_raw)}}]}
    marker_raw = canonical_json(marker)
    def inline(raw):
        return {"bytes": len(raw), "sha256": sha256(raw), "base64": base64.b64encode(raw).decode()}
    doc = {"schema_version": 1, "kind": "icsot_cycle_asset_catalog_v1", "repository": dest,
           "logical_release": tag, "cycle_slot": 44, "metadata": {"metadata-catalog.json": inline(marker_raw),
           "run.index.json": inline(index_raw)}, "payloads": {"part.enc": {"release_tag": physical,
           "name": "r123-gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-observations-part.enc", "bytes": 4, "sha256": part_digest}}}
    raw = canonical_json(doc)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    locator = {"kind": "github_git_blob_v1", "repository": dest, "branch": "collector-metadata",
               "path": "packages/aa/bb/catalog.json", "commit_sha": "e" * 40, "blob_sha": blob,
               "sha256": sha256(raw), "bytes": len(raw)}
    storage = {"kind": "cycle_git_catalog_v1", "logical_release": tag, "catalog": locator}
    marker_ref = {"release_tag": tag, "name": "metadata-catalog.json", "sha256": sha256(marker_raw),
                  "bytes": len(marker_raw), "storage": storage}
    class Remote:
        def outbox_catalogs(self, slug):
            assert slug == repo
            return 123, [marker_ref], True
        def json(self, endpoint, **kwargs):
            if endpoint.endswith("/git/blobs/" + blob):
                return {"sha": blob, "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()}
            if endpoint.endswith("/releases/tags/" + physical):
                return {"id": 42, "tag_name": physical}
            if endpoint.endswith("/releases/42/assets?per_page=100&page=1"):
                return [{"id": 7, "name": "r123-gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-observations-part.enc", "size": 4, "digest": "sha256:" + part_digest}]
            raise AssertionError(endpoint)
    viewer = ViewerData(tmp_path, roots=[], release_repository=dest, metadata=Remote())
    repo_obj = next(iter(viewer._repos.values()))
    viewer._metadata_state = "complete"
    viewer._index_remote_repository(repo_obj)
    assert len(repo_obj["captures"]) == 1
    capture = viewer._captures[repo_obj["captures"][0]]
    assert capture["remote"]["storage"] == storage
    monkeypatch.setattr(viewer, "_download_part", lambda asset, description, capture, cls: asset)
    reader, loaded_index = viewer._remote_reader(repo_obj, capture)
    assert loaded_index == index
    assert reader.parts == [{"id": 7, "name": "r123-gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-observations-part.enc", "size": 4, "digest": "sha256:" + part_digest}]
    assert reader.groups == index["groups"]
    assert reader.xz_memory_limit == 256 * 1024 * 1024
    altered = copy.deepcopy(marker_ref)
    altered["storage"]["catalog"]["sha256"] = "f" * 64
    with pytest.raises(RuntimeError):
        viewer._cycle_metadata(altered)


def test_public_outbox_chain_checks_digest_and_source():
    remote = GitHubMetadata("owner/archive")
    head = "1" * 40
    tag = "collector-observations-r123-g" + "a" * 32
    node = {"schema_version": 1, "kind": "icsot_public_proof_outbox", "repository_id": 123,
            "slug": "example/fixture", "generation": "a" * 32, "previous": None,
            "catalog": {"release_tag": tag, "name": "metadata-catalog.json"}}
    raw = canonical_json(node)
    ref = {"sha256": sha256(raw), "bytes": len(raw)}
    binding = {"schema_version": 1, "slug_key": "example/fixture", "repository_id": 123}
    pointer = {"repository_id": 123, "slug": "example/fixture", "proof_outbox": ref}
    def file(value):
        data = canonical_json(value)
        return {"type": "file", "encoding": "base64", "size": len(data), "content": base64.b64encode(data).decode()}
    def json_response(endpoint, **kwargs):
        if "/git/ref/" in endpoint: return {"object": {"sha": head}}
        if "/contents/slugs/" in endpoint: return file(binding)
        if "/contents/repos/" in endpoint: return file(pointer)
        if "/contents/proof-outbox/" in endpoint: return file(node)
        raise AssertionError(endpoint)
    remote.json = json_response
    assert remote.outbox_catalogs("example/fixture") == (123, [node["catalog"]], True)
    node["slug"] = "other/repo"
    with pytest.raises(MetadataError):
        remote.outbox_catalogs("example/fixture")
