#!/usr/bin/env python3
"""Copy release payloads and legacy Actions ZIPs into verified RSA envelopes.

Requires ``gh`` authentication and the project's encryption dependencies. Run
while the repository is private and no collector is writing to this release.
The default operation only creates encrypted assets and the migration index.
``--remove-plaintext`` additionally removes the precisely inventoried sources,
but only after every encrypted copy and the complete index have been verified.
No release is published and no repository visibility is changed by this tool.

Large downloads go directly from ``gh api`` to mode-0600 temporary files. Only
one payload is processed at a time. Keys are never copied or uploaded. A local
checkpoint under the ignored ``analysis/`` directory makes interrupted uploads
resumable without overwriting an existing remote asset.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Permit direct execution from a checkout without an editable installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from icsot_observer.encryption import decrypt_file, encrypt_file, public_key_fingerprint

INDEX_NAME = "encryption-migration-index.json"
ROOT = Path(__file__).resolve().parents[2]
MAX_JSON_BYTES = 16 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PART_NAME = re.compile(r".+\.tar\.xz(?:\.part-\d+)?\Z")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def identity(path: Path) -> dict:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while block := stream.read(4 * 1024 * 1024):
            digest.update(block)
            size += len(block)
    return {"sha256": digest.hexdigest(), "bytes": size}


def require_identity(value: Any) -> dict:
    if (not isinstance(value, dict) or not isinstance(value.get("sha256"), str)
            or not SHA256.fullmatch(value["sha256"])
            or type(value.get("bytes")) is not int or value["bytes"] < 0):
        raise ValueError("Invalid payload identity")
    return {key: value[key] for key in ("sha256", "bytes")}


def safe_name(name: Any) -> str:
    if (not isinstance(name, str) or not name or name in {".", ".."}
            or any(c in name for c in ("/", "\\", "\x00", "\r", "\n"))):
        raise ValueError("Invalid asset name")
    return name


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".migration-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class GitHub:
    def __init__(self, repository: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Expected an owner/repository slug")
        self.repository = repository

    def _run(self, arguments: list[str], *, output=None, timeout=3600) -> bytes:
        process = subprocess.run(["gh", *arguments], stdout=output or subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=timeout)
        if process.returncode:
            # Do not echo process environments, auth tokens, or arbitrary API errors.
            raise RuntimeError(f"GitHub {arguments[0]} failed (exit {process.returncode})")
        return process.stdout if output is None else b""

    def json(self, endpoint: str, *, paginate=False):
        arguments = ["api", endpoint]
        if paginate:
            arguments += ["--paginate", "--slurp"]
        raw = self._run(arguments)
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("GitHub metadata response exceeds the supported bound")
        return json.loads(raw)

    def assets(self, release_id: int) -> dict[str, dict]:
        pages = self.json(f"repos/{self.repository}/releases/{release_id}/assets?per_page=100", paginate=True)
        assets = [asset for page in pages for asset in page]
        names = [safe_name(asset["name"]) for asset in assets]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate remote asset names")
        return dict(zip(names, assets))

    def artifacts(self) -> dict[int, dict]:
        pages = self.json(f"repos/{self.repository}/actions/artifacts?per_page=100", paginate=True)
        return {artifact["id"]: artifact for page in pages for artifact in page["artifacts"]}

    def download(self, endpoint: str, destination: Path) -> None:
        with destination.open("xb") as stream:
            os.chmod(destination, 0o600)
            self._run(["api", endpoint, "-H", "Accept: application/octet-stream"], output=stream)

    def download_asset(self, asset: dict, destination: Path) -> None:
        self.download(f"repos/{self.repository}/releases/assets/{asset['id']}", destination)

    def upload(self, tag: str, path: Path) -> None:
        # gh refuses duplicate names unless --clobber is supplied. Never supply it.
        self._run(["release", "upload", tag, str(path), "--repo", self.repository])

    def delete_asset(self, asset_id: int) -> None:
        self._run(["api", "--method", "DELETE", f"repos/{self.repository}/releases/assets/{asset_id}"])

    def delete_artifact(self, artifact_id: int) -> None:
        self._run(["api", "--method", "DELETE", f"repos/{self.repository}/actions/artifacts/{artifact_id}"])


class Migration:
    def __init__(self, args, github=None, password=None):
        self.args = args
        self.github = github or GitHub(args.repository)
        self.password = password
        self.fingerprint = public_key_fingerprint(args.public_key)
        self.report_path = args.report
        self.report = json.loads(self.report_path.read_bytes()) if self.report_path.exists() else {
            "schema_version": 1, "repository": args.repository, "release_id": args.release_id,
            "recipient": self.fingerprint, "mutation_audit": [],
        }
        if any(self.report.get(key) != expected for key, expected in (
            ("schema_version", 1), ("repository", args.repository),
            ("release_id", args.release_id), ("recipient", self.fingerprint),
        )):
            raise ValueError("Local checkpoint does not match the requested migration")
        if not isinstance(self.report.get("mutation_audit"), list):
            raise ValueError("Invalid local mutation audit")
        self.mapping = None
        self.verified = set()

    def checkpoint(self, event=None, **fields):
        if event:
            self.report["mutation_audit"].append({"at": now(), "event": event, **fields})
        if self.mapping is not None:
            self.report["mapping"] = self.mapping
        atomic_json(self.report_path, self.report)

    def private_release(self):
        repo = self.github.json(f"repos/{self.args.repository}")
        release = self.github.json(f"repos/{self.args.repository}/releases/{self.args.release_id}")
        if repo.get("private") is not True or release.get("draft") is not True:
            raise ValueError("Migration requires a private repository and a draft release")
        if release.get("id") != self.args.release_id:
            raise ValueError("Release identity mismatch")
        return release

    def read_json_asset(self, asset):
        if asset.get("state") != "uploaded" or not 0 <= asset.get("size", -1) <= MAX_JSON_BYTES:
            raise ValueError("Invalid or oversized JSON release asset")
        with tempfile.TemporaryDirectory(prefix="migration-json-", dir=self.args.work_root) as directory:
            path = Path(directory) / "metadata.json"
            self.github.download_asset(asset, path)
            observed = identity(path)
            self.check_asset_metadata(asset, observed)
            result = json.loads(path.read_bytes())
        if not isinstance(result, dict):
            raise ValueError("Expected a JSON object asset")
        return result, observed

    @staticmethod
    def check_asset_metadata(asset, expected):
        require_identity(expected)
        if asset.get("state") != "uploaded" or asset.get("size") != expected["bytes"]:
            raise ValueError("Remote asset is not uploaded or has the wrong size")
        if asset.get("digest") and asset["digest"] != "sha256:" + expected["sha256"]:
            raise ValueError("Remote asset SHA-256 mismatch")

    def verify_asset(self, asset, expected):
        self.check_asset_metadata(asset, expected)
        if not asset.get("digest"):
            with tempfile.TemporaryDirectory(prefix="migration-hash-", dir=self.args.work_root) as directory:
                path = Path(directory) / "remote"
                self.github.download_asset(asset, path)
                if identity(path) != require_identity(expected):
                    raise ValueError("Downloaded remote asset identity mismatch")

    def inventory(self, assets):
        parts, metadata = {}, []
        for name, asset in sorted(assets.items()):
            if not name.endswith(".json") or name == INDEX_NAME:
                continue
            index, observed = self.read_json_asset(asset)
            metadata.append({"name": name, "id": asset["id"], **observed})
            archive = index.get("archive")
            if not isinstance(archive, dict):
                continue
            for part in archive.get("parts", []):
                part_name = safe_name(part["name"])
                if not PART_NAME.fullmatch(part_name):
                    raise ValueError("Unexpected archive part name")
                expected = {"name": part_name, **require_identity(part)}
                if part_name in parts and parts[part_name] != expected:
                    raise ValueError("Conflicting plaintext identities in original indexes")
                parts[part_name] = expected
        if not parts:
            raise ValueError("No archive parts declared by original metadata indexes")
        # JSON metadata is allowed to remain public. Every other unencrypted
        # release asset must be a declared archive payload.
        unexpected = [name for name in assets if not name.endswith((".json", ".enc")) and name not in parts]
        if unexpected:
            raise ValueError(f"Uninventoried release payloads: {unexpected}")
        return parts, metadata

    def artifacts(self):
        current = self.github.artifacts()
        requested = set(self.args.artifact_id)
        unexpected = sorted(aid for aid, value in current.items() if not value.get("expired") and aid not in requested)
        if unexpected:
            raise ValueError(f"Declare all nonexpired Actions artifacts with --artifact-id: {unexpected}")
        return current

    def validate_entry(self, entry, plaintext):
        if not isinstance(entry, dict) or entry.get("plaintext") != plaintext:
            raise ValueError("Migration plaintext mapping does not match original metadata")
        if entry.get("recipient") != self.fingerprint:
            raise ValueError("Migration recipient fingerprint mismatch")
        cipher = entry.get("ciphertext")
        require_identity(cipher)
        if not safe_name(cipher.get("name")).endswith(".enc") or cipher["name"] == plaintext["name"]:
            raise ValueError("Invalid encrypted asset name")

    def reconcile(self, assets, parts, metadata, artifacts):
        remote = None
        if INDEX_NAME in assets:
            remote, _ = self.read_json_asset(assets[INDEX_NAME])
        local = self.report.get("mapping")
        self.mapping = remote or local or {
            "schema_version": 1, "repository": self.args.repository,
            "release_id": self.args.release_id, "release_tag": self.release["tag_name"],
            "created_at": now(), "format": "icsot-encrypted-v1", "recipient": self.fingerprint,
            "metadata_indexes": metadata, "parts": {}, "legacy_actions_artifacts": [],
        }
        for key, expected in (("schema_version", 1), ("repository", self.args.repository),
                              ("release_id", self.args.release_id), ("release_tag", self.release["tag_name"]),
                              ("recipient", self.fingerprint), ("metadata_indexes", metadata)):
            if self.mapping.get(key) != expected:
                raise ValueError(f"Migration index does not match source {key}")
        mapped_parts = self.mapping.get("parts")
        legacy = self.mapping.get("legacy_actions_artifacts")
        if not isinstance(mapped_parts, dict) or not isinstance(legacy, list):
            raise ValueError("Invalid migration payload collections")
        if set(mapped_parts) - set(parts):
            raise ValueError("Migration contains undeclared archive parts")
        ids = [entry.get("id") for entry in legacy]
        if len(ids) != len(set(ids)) or set(ids) - set(self.args.artifact_id):
            raise ValueError("Migration contains duplicate or undeclared Actions artifacts")
        for name, entry in mapped_parts.items():
            self.validate_entry(entry, parts[name])
        for entry in legacy:
            self.validate_entry(entry, entry.get("plaintext"))
            if entry.get("original_name") is None or type(entry.get("run_id")) is not int:
                raise ValueError("Invalid legacy Actions artifact metadata")
        names = [entry["ciphertext"]["name"] for entry in [*mapped_parts.values(), *legacy]]
        if len(names) != len(set(names)):
            raise ValueError("Ciphertext asset is reused for multiple plaintext payloads")
        if remote and (set(mapped_parts) != set(parts) or set(ids) != set(self.args.artifact_id)):
            raise ValueError("Remote migration index is incomplete; refusing to overwrite it")
        if remote and local:
            for key, value in local.get("parts", {}).items():
                if remote["parts"].get(key) != value:
                    raise ValueError("Local and remote migration checkpoints disagree")
            for value in local.get("legacy_actions_artifacts", []):
                if value not in remote["legacy_actions_artifacts"]:
                    raise ValueError("Local and remote legacy checkpoints disagree")
        for name in parts:
            if name not in assets and (not remote or name not in mapped_parts):
                raise ValueError(f"Original archive part missing without a complete remote mapping: {name}")
        for aid in self.args.artifact_id:
            entry = next((e for e in legacy if e["id"] == aid), None)
            if aid not in artifacts and (not remote or entry is None):
                raise ValueError(f"Original Actions artifact missing without a complete remote mapping: {aid}")
            if aid in artifacts:
                artifact = artifacts[aid]
                if artifact.get("expired"):
                    raise ValueError(f"Cannot preserve expired Actions artifact {aid}")
                if entry and (entry["original_name"] != artifact["name"]
                              or entry["run_id"] != artifact["workflow_run"]["id"]
                              or entry["plaintext"]["bytes"] != artifact["size_in_bytes"]):
                    raise ValueError("Actions artifact metadata changed")
        self.remote_index_exists = remote is not None
        self.checkpoint("inventory_verified", parts=len(parts), artifacts=len(self.args.artifact_id))

    def roundtrip(self, encrypted, plaintext, cipher_expected=None):
        decrypted = encrypted.parent / "decrypted-verification"
        record = decrypt_file(encrypted, decrypted, self.args.private_key, password=self.password)
        if identity(decrypted) != require_identity(plaintext):
            raise ValueError("Local decrypt verification did not reproduce the original payload")
        if record["public_key_fingerprint_sha256"] != self.fingerprint:
            raise ValueError("Envelope recipient fingerprint mismatch")
        if cipher_expected and identity(encrypted) != require_identity(cipher_expected):
            raise ValueError("Encrypted payload does not match the migration mapping")
        decrypted.unlink()

    def process(self, plaintext, source, entry=None, *, artifact=None):
        assets = self.github.assets(self.args.release_id)
        if entry and entry["ciphertext"]["name"] in assets:
            self.validate_entry(entry, plaintext)
            cipher = entry["ciphertext"]
            asset = assets[cipher["name"]]
            self.check_asset_metadata(asset, cipher)
            with tempfile.TemporaryDirectory(prefix="migration-resume-", dir=self.args.work_root) as directory:
                encrypted = Path(directory) / "payload.enc"
                self.github.download_asset(asset, encrypted)
                self.roundtrip(encrypted, plaintext, cipher)
            self.verified.add(cipher["name"])
            self.checkpoint("existing_ciphertext_verified", name=cipher["name"], asset_id=asset["id"])
            return entry
        if self.remote_index_exists:
            raise ValueError("A ciphertext named by the immutable remote migration index is missing")
        if source is None:
            raise ValueError("Original source is unavailable")
        # Enough room for the source, envelope, and decrypted verification copy.
        needed = plaintext["bytes"] * 3 + 64 * 1024 * 1024
        if shutil.disk_usage(self.args.work_root).free < needed:
            raise ValueError("Insufficient space for one payload and its verification copies")
        with tempfile.TemporaryDirectory(prefix="migration-payload-", dir=self.args.work_root) as directory:
            work = Path(directory)
            original = work / "original"
            if artifact:
                self.github.download(f"repos/{self.args.repository}/actions/artifacts/{artifact['id']}/zip", original)
                observed = identity(original)
                if observed["bytes"] != artifact["size_in_bytes"]:
                    raise ValueError("Downloaded Actions artifact byte count differs from its metadata")
                if entry and observed != require_identity(plaintext):
                    raise ValueError("Actions artifact bytes changed since the saved checkpoint")
                plaintext = {"name": plaintext["name"], **observed}
            else:
                self.github.download_asset(source, original)
                if identity(original) != require_identity(plaintext):
                    raise ValueError("Original archive hash differs from the unchanged per-repository index")
            encrypted = work / (safe_name(plaintext["name"]) + "." + uuid.uuid4().hex + ".enc")
            record = encrypt_file(original, encrypted, self.args.public_key)
            if (record["plaintext_sha256"] != plaintext["sha256"]
                    or record["plaintext_bytes"] != plaintext["bytes"]
                    or record["public_key_fingerprint_sha256"] != self.fingerprint):
                raise ValueError("Encryption metadata does not match its source")
            cipher = {"name": encrypted.name, "sha256": record["ciphertext_sha256"],
                      "bytes": record["ciphertext_bytes"]}
            self.roundtrip(encrypted, plaintext, cipher)
            entry = {"plaintext": plaintext, "ciphertext": cipher, "recipient": self.fingerprint}
            if artifact:
                entry.update({"id": artifact["id"], "run_id": artifact["workflow_run"]["id"],
                              "original_name": artifact["name"]})
                self.mapping["legacy_actions_artifacts"] = [e for e in self.mapping["legacy_actions_artifacts"]
                                                            if e["id"] != artifact["id"]] + [entry]
            else:
                entry["source_asset_id"] = source["id"]
                self.mapping["parts"][plaintext["name"]] = entry
            # Persist the exact random envelope identity before a create-only upload.
            self.checkpoint("ciphertext_upload_intent", name=encrypted.name)
            if encrypted.name in self.github.assets(self.args.release_id):
                raise ValueError("New encrypted asset name already exists; refusing overwrite")
            self.github.upload(self.release["tag_name"], encrypted)
            uploaded = self.github.assets(self.args.release_id).get(encrypted.name)
            if uploaded is None:
                raise ValueError("Encrypted upload is absent from the release")
            self.verify_asset(uploaded, cipher)
            self.verified.add(cipher["name"])
            self.checkpoint("ciphertext_upload_verified", name=encrypted.name, asset_id=uploaded["id"])
        return entry

    def verify_all(self, parts, metadata):
        assets = self.github.assets(self.args.release_id)
        current_parts, current_metadata = self.inventory(assets)
        if current_parts != parts or current_metadata != metadata:
            raise ValueError("Source metadata changed during migration")
        entries = [*self.mapping["parts"].values(), *self.mapping["legacy_actions_artifacts"]]
        if set(self.mapping["parts"]) != set(parts):
            raise ValueError("Not all archive parts have encrypted mappings")
        if {e["id"] for e in self.mapping["legacy_actions_artifacts"]} != set(self.args.artifact_id):
            raise ValueError("Not all Actions artifacts have encrypted mappings")
        for entry in entries:
            cipher = entry["ciphertext"]
            if cipher["name"] not in self.verified:
                raise ValueError("Ciphertext was not locally decrypt-verified in this invocation")
            if cipher["name"] not in assets:
                raise ValueError("Verified ciphertext asset disappeared")
            self.verify_asset(assets[cipher["name"]], cipher)
        return assets

    def publish_index(self, assets):
        self.mapping["legacy_actions_artifacts"].sort(key=lambda entry: entry["id"])
        if INDEX_NAME not in assets:
            with tempfile.TemporaryDirectory(prefix="migration-index-", dir=self.args.work_root) as directory:
                path = Path(directory) / INDEX_NAME
                atomic_json(path, self.mapping)
                self.checkpoint("migration_index_upload_intent", name=INDEX_NAME)
                self.github.upload(self.release["tag_name"], path)
        current = self.github.assets(self.args.release_id)
        if INDEX_NAME not in current:
            raise ValueError("Complete migration index is missing")
        remote, observed = self.read_json_asset(current[INDEX_NAME])
        if remote != self.mapping:
            raise ValueError("Remote migration index differs from the verified complete mapping")
        self.report["remote_index"] = {"asset_id": current[INDEX_NAME]["id"], **observed}
        self.checkpoint("migration_index_readback_verified", **self.report["remote_index"])

    def remove_plaintext(self, parts, metadata):
        # This is deliberately a separate final phase. An error above leaves all
        # original release assets and Actions artifacts untouched.
        self.private_release()
        assets = self.verify_all(parts, metadata)
        remote, _ = self.read_json_asset(assets[INDEX_NAME])
        if remote != self.mapping:
            raise ValueError("Migration index changed before removal")
        artifacts = self.artifacts()
        for name, entry in self.mapping["parts"].items():
            if name not in assets:
                continue
            source = assets[name]
            if source["id"] != entry.get("source_asset_id"):
                raise ValueError("Plaintext source asset identity changed before removal")
            self.verify_asset(source, entry["plaintext"])
        for entry in self.mapping["legacy_actions_artifacts"]:
            source = artifacts.get(entry["id"])
            if source and (source["name"] != entry["original_name"]
                           or source["workflow_run"]["id"] != entry["run_id"]
                           or source["size_in_bytes"] != entry["plaintext"]["bytes"]):
                raise ValueError("Plaintext Actions artifact identity changed before removal")
        self.checkpoint("all_copies_and_global_mapping_verified_for_removal")
        for name in sorted(parts):
            if name in assets:
                asset_id = assets[name]["id"]
                self.checkpoint("plaintext_asset_delete_intent", name=name, asset_id=asset_id)
                self.github.delete_asset(asset_id)
                self.checkpoint("plaintext_asset_deleted", name=name, asset_id=asset_id)
        for aid in sorted(self.args.artifact_id):
            if aid in artifacts:
                self.checkpoint("plaintext_artifact_delete_intent", artifact_id=aid)
                self.github.delete_artifact(aid)
                self.checkpoint("plaintext_artifact_deleted", artifact_id=aid)
        remaining_assets = self.github.assets(self.args.release_id)
        remaining_artifacts = self.github.artifacts()
        if set(parts) & set(remaining_assets) or set(self.args.artifact_id) & set(remaining_artifacts):
            raise ValueError("Some plaintext sources remain after removal")
        self.verify_all(parts, metadata)
        self.checkpoint("plaintext_removal_verified")

    def run(self):
        self.release = self.private_release()
        assets = self.github.assets(self.args.release_id)
        parts, metadata = self.inventory(assets)
        artifacts = self.artifacts()
        self.reconcile(assets, parts, metadata, artifacts)
        if self.args.dry_run:
            return {"dry_run": True, "archive_parts": len(parts), "actions_artifacts": len(self.args.artifact_id)}
        for name, plain in sorted(parts.items()):
            print(f"Verifying encrypted copy for {name}", flush=True)
            self.process(plain, assets.get(name), self.mapping["parts"].get(name))
        for aid in sorted(self.args.artifact_id):
            entry = next((e for e in self.mapping["legacy_actions_artifacts"] if e["id"] == aid), None)
            source = artifacts.get(aid)
            plain = entry["plaintext"] if entry else {
                "name": f"legacy-actions-artifact-{aid}.zip", "sha256": "0" * 64,
                "bytes": source["size_in_bytes"],
            }
            print(f"Verifying encrypted copy for Actions artifact {aid}", flush=True)
            self.process(plain, source, entry, artifact=source)
        assets = self.verify_all(parts, metadata)
        self.publish_index(assets)
        if self.args.remove_plaintext:
            self.remove_plaintext(parts, metadata)
        self.checkpoint("migration_complete", plaintext_removed=self.args.remove_plaintext)
        return {"archive_parts": len(parts), "actions_artifacts": len(self.args.artifact_id),
                "plaintext_removed": self.args.remove_plaintext, "index": INDEX_NAME,
                "report": str(self.report_path)}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="owner/repository")
    parser.add_argument("--release-id", required=True, type=int)
    parser.add_argument("--artifact-id", action="append", type=int, default=[],
                        help="Repeat for every existing nonexpired Actions artifact to preserve")
    parser.add_argument("--public-key", type=Path, default=ROOT / "icsot-observatory/keys/results-rsa-public.pem")
    parser.add_argument("--private-key", type=Path, default=Path.home() / ".ssh/id_rsa",
                        help="Local decryption verification only; never uploaded")
    parser.add_argument("--ask-passphrase", action="store_true")
    parser.add_argument("--report", type=Path, help="Resume checkpoint, restricted to ignored analysis/")
    parser.add_argument("--work-root", type=Path, help="Temporary working directory under ignored analysis/")
    parser.add_argument("--remove-plaintext", action="store_true",
                        help="Delete inventoried originals only after all copies and index are verified")
    parser.add_argument("--dry-run", action="store_true", help="Inspect inventory and checkpoint without remote writes")
    args = parser.parse_args(argv)
    if args.release_id <= 0 or any(aid <= 0 for aid in args.artifact_id):
        parser.error("Release and artifact IDs must be positive")
    if len(set(args.artifact_id)) != len(args.artifact_id):
        parser.error("Artifact IDs must be unique")
    if args.dry_run and args.remove_plaintext:
        parser.error("--dry-run cannot be combined with --remove-plaintext")
    analysis = (ROOT / "analysis").resolve()
    args.report = (args.report or analysis / f"encryption-migration-{args.release_id}.json").expanduser().resolve()
    args.work_root = (args.work_root or analysis / "encryption-migration-work").expanduser().resolve()
    if not args.report.is_relative_to(analysis) or not args.work_root.is_relative_to(analysis):
        parser.error("Report and temporary work paths must be under ignored analysis/")
    args.public_key, args.private_key = args.public_key.expanduser().resolve(), args.private_key.expanduser().resolve()
    args.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return args


def main(argv=None):
    args = parse_args(argv)
    password = getpass.getpass("Local RSA key passphrase: ").encode() if args.ask_passphrase else None
    migration = None
    try:
        migration = Migration(args, password=password)
        print(json.dumps(migration.run(), indent=2))
        return 0
    except Exception as error:
        if migration:
            migration.checkpoint("migration_failed", error_type=type(error).__name__, error=str(error))
        print(f"Migration stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
