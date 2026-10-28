"""Content-pinned Git catalogs for one physical Release per collection slot.

Logical generation names and original metadata bytes stay intact. A pinned
catalog locates their uniquely named payloads and retained Git metadata.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from .core import canonical_json

_LOGICAL = re.compile(r"collector-(?:state|observations)-r([1-9][0-9]*)-g([0-9a-f]{32})(-p(?:[2-9]|[1-9][0-9]+))?\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_INLINE = 32 * 1024 ** 2


class CycleCatalogError(RuntimeError):
    pass


class CycleReleaseCatalog:
    def __init__(self, transport, slot=None):
        self.transport, self.slot = transport, slot
        self.documents, self.locators, self.dirty = {}, {}, set()
        self.git_downloads = self.git_bytes = 0

    def _store(self):
        from .git_metadata import GitMetadataStore
        if not hasattr(self, "store"):
            self.store = GitMetadataStore(self.transport)
        return self.store

    def writable(self, tag):
        return self.slot is not None and bool(_LOGICAL.fullmatch(tag))

    def known(self, tag):
        return tag in self.documents

    def ensure(self, tag):
        if tag not in self.documents:
            self.documents[tag] = {"schema_version": 1, "kind": "icsot_cycle_asset_catalog_v1",
                "repository": self.transport.repository, "logical_release": tag,
                "cycle_slot": self.slot, "payloads": {}, "metadata": {}}
        return self.documents[tag]

    def _physical(self, shard=1):
        return f"collector-cycle-s{self.slot}" + (f"-p{shard}" if shard > 1 else "")

    @staticmethod
    def _physical_name(tag, name):
        match = _LOGICAL.fullmatch(tag)
        if match is None or not _NAME.fullmatch(name):
            raise CycleCatalogError("Invalid logical payload namespace")
        kind = tag.split("-r", 1)[0].removeprefix("collector-")
        return f"r{match[1]}-g{match[2]}{match[3] or ''}-{kind}-" + name

    def _validate_payload(self, document, tag, name, row):
        base = f"collector-cycle-s{document['cycle_slot']}"
        if (not isinstance(row, dict) or
                not re.fullmatch(re.escape(base) + r"(?:-p(?:[2-9]|[12][0-9]|3[0-2]))?", row.get("release_tag", "")) or
                row.get("name") != self._physical_name(tag, name)):
            raise CycleCatalogError("Physical payload is outside its cycle/generation namespace")

    def _room(self, tag):
        release = self.transport._release(tag, create=True)
        if release["draft"] is not False:
            raise CycleCatalogError("Cycle release must be published")
        # Only eight collection jobs can upload simultaneously, each serially.
        # Leave eight slots of headroom and recheck before every payload POST.
        tail = self.transport._api(f"repos/{self.transport.repository}/releases/{release['id']}/assets?per_page=100&page=10")
        if not isinstance(tail, list) or len(tail) > 100:
            raise CycleCatalogError("Invalid cycle release capacity response")
        return len(tail) < 92

    def upload(self, tag, name, source):
        document = self.ensure(tag)
        if name in document["metadata"] or name in document["payloads"]:
            raise CycleCatalogError("Immutable logical asset already exists")
        size = source.stat().st_size
        digest = hashlib.sha256(source.read_bytes()).hexdigest() if size <= MAX_INLINE else None
        inline = (not name.endswith(".enc") or name == "index.enc") and size <= MAX_INLINE
        if inline:
            raw = source.read_bytes()
            document["metadata"][name] = {"bytes": size, "sha256": digest,
                                          "base64": base64.b64encode(raw).decode("ascii")}
        else:
            actual_name = self._physical_name(tag, name)
            if not _NAME.fullmatch(actual_name):
                raise CycleCatalogError("Namespaced payload name exceeds the asset bound")
            for shard in range(1, 33):
                actual_tag = self._physical(shard)
                if not self._room(actual_tag):
                    continue
                try:
                    self.transport.upload_asset(actual_tag, actual_name, source)
                except Exception as error:
                    from .github_state import StateDeferredError
                    if isinstance(error, StateDeferredError):
                        raise
                    # Never repeat an ambiguous upload at another location.
                    # Only a confirmed full release permits the overflow path.
                    if getattr(self.transport, "_last_http_status", None) == 422 and not self._room(actual_tag):
                        existing = self.transport.find_asset(actual_tag, actual_name, refresh=True)
                        if existing is None:
                            continue
                    raise
                break
            else:
                raise CycleCatalogError("Cycle release overflow bound exceeded")
            if digest is None:
                from .github_state import _digest
                digest = _digest(source)
            document["payloads"][name] = {"release_tag": actual_tag, "name": actual_name,
                                          "bytes": size, "sha256": digest}
        self.dirty.add(tag)

    def seal(self, tag):
        document = self.documents[tag]
        if tag in self.dirty or tag not in self.locators:
            token = hashlib.sha256(tag.encode()).hexdigest()
            path = f"packages/{token[:2]}/{token[2:4]}/{tag}.json"
            raw = canonical_json(document)
            locator = self._store().put(path, raw, allow_update=True)
            if self._store().get(locator) != raw:
                raise CycleCatalogError("Remote Git catalog differs from publication")
            self.locators[tag] = locator
            self.dirty.discard(tag)
        return {"kind": "cycle_git_catalog_v1", "logical_release": tag, "catalog": self.locators[tag]}

    def bind(self, ref):
        if ref.get("storage") is not None:
            self.pin(ref)
        elif self.writable(ref["release_tag"]) and self.known(ref["release_tag"]):
            ref["storage"] = self.seal(ref["release_tag"])
        return ref

    def pin(self, ref):
        hint = ref.get("storage")
        if hint is None:
            return
        if (not isinstance(hint, dict) or hint.get("kind") != "cycle_git_catalog_v1" or
                hint.get("logical_release") != ref.get("release_tag") or not _LOGICAL.fullmatch(ref["release_tag"])):
            raise CycleCatalogError("Invalid pinned cycle catalog")
        locator = hint.get("catalog")
        if self.locators.get(ref["release_tag"]) != locator:
            raw = self._store().get(locator)
            try:
                document = json.loads(raw)
            except (ValueError, UnicodeError):
                raise CycleCatalogError("Invalid cycle catalog JSON") from None
            if (canonical_json(document) != raw or document.get("kind") != "icsot_cycle_asset_catalog_v1" or
                    document.get("schema_version") != 1 or document.get("repository") != self.transport.repository or
                    document.get("logical_release") != ref["release_tag"] or
                    type(document.get("cycle_slot")) is not int or document["cycle_slot"] < 0 or
                    not isinstance(document.get("metadata"), dict) or not isinstance(document.get("payloads"), dict) or
                    set(document["metadata"]) & set(document["payloads"])):
                raise CycleCatalogError("Pinned cycle catalog context differs")
            self.documents[ref["release_tag"]], self.locators[ref["release_tag"]] = document, locator
        asset = self.asset(ref["release_tag"], ref["name"])
        document = self.documents[ref["release_tag"]]
        if ref["name"] in document["payloads"]:
            self._validate_payload(document, ref["release_tag"], ref["name"], document["payloads"][ref["name"]])
        digest, size = ref.get("ciphertext_sha256", ref.get("sha256")), ref.get("ciphertext_bytes", ref.get("bytes"))
        if asset is None or asset["size"] != size or not isinstance(digest, str) or asset["digest"] != "sha256:" + digest:
            raise CycleCatalogError("Pinned logical asset differs from trusted descriptor")

    def asset(self, tag, name):
        document = self.documents[tag]
        row = document["metadata"].get(name) or document["payloads"].get(name)
        if row is None:
            return None
        if (not _NAME.fullmatch(name) or type(row.get("bytes")) is not int or row["bytes"] < 0 or
                not isinstance(row.get("sha256"), str) or not _HASH.fullmatch(row["sha256"])):
            raise CycleCatalogError("Invalid catalog asset identity")
        return {"id": 1, "name": name, "size": row["bytes"], "digest": "sha256:" + row["sha256"], "state": "uploaded"}

    def download(self, tag, name, destination):
        document = self.documents[tag]
        if name in document["metadata"]:
            if tag in self.dirty:
                self.seal(tag)
            row = document["metadata"][name]
            try:
                raw = base64.b64decode(row["base64"], validate=True)
            except (ValueError, TypeError):
                raise CycleCatalogError("Invalid Git metadata payload") from None
            if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise CycleCatalogError("Git metadata payload hash or size differs")
            with Path(destination).open("xb") as target:
                target.write(raw)
            self.git_downloads += 1
            self.git_bytes += len(raw)
        else:
            row = document["payloads"].get(name)
            self._validate_payload(document, tag, name, row)
            self.transport.download_asset(row["release_tag"], row["name"], destination)
