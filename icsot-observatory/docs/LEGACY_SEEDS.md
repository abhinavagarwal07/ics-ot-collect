# Original baseline prerequisites for native increments

`legacy_seed_catalog.py` describes an authenticated original baseline package as `kind: legacy_baseline_package_v1`. It is deliberately separate from an ordinary encrypted capture index. It introduces no capture ID, lane, source observation or replacement timestamp.

The operational transfer catalog may add `legacy_seed_packages`; `CaptureExporter` accepts them through `verified_legacy_seeds`. Ordinary prior native indexes retain their existing contract. The exporter marks only the original authenticated member subset as delivered. A new Git adoption descriptor, migration receipt and other derived metadata remain new artifacts and are included in the first native increment. The original full bundle and original response CAS objects are referenced rather than uploaded again. The legacy manifest must not be inserted into `known_exports` as a synthetic native export.

The seed contains:

- The original source index's release repository/tag/numeric IDs, name, original-byte SHA-256 and size.
- The original manifest path, hash, size, run ID and original UTC interval. Missing times in an old index remain missing there; the seed's values must come from the authenticated original manifest, never asset upload or migration time.
- Ordered original plaintext/ciphertext identities and immutable asset references. Migrated plaintext-era indexes also retain the exact frozen encryption-migration mapping reference. Optional capsule references remain recorded for hosted operational-key access; an owner's local decoder can use the original machine key without uploading it.
- A sorted `members` inventory with original `evidence/...` / `reports/...` archive paths. `membership_scope: authenticated_subset` makes its limits explicit. It contains the original manifest and all required authenticated CAS/bundle members; unverified or unused old working mirrors are not silently promoted to delivered evidence.
- A hash of that inventory, a new import receipt reference, and a SHA-256 of the canonical seed excluding its own digest. The receipt is written first and binds the original archive/import result; it must not circularly bind the later seed hash.

`seal_legacy_seed` orders members and computes the inventory/seed digests. `validate_legacy_seed` checks the type, repository, safe paths, source manifest/part bindings and, when given an evidence root, exact member and receipt bytes. Exact original index bytes may be supplied for hash validation; an already hash-checked decoded index is supported for the viewer's metadata transport. `registerable_members` filters `evidence/` and removes that archive prefix. New native indexes embed the typed source references under `legacy_prerequisites`; `requires_cas_sha256` continues to name the actual missing CAS identities.

`restore_legacy_seeded_capture` independently restores a native package plus its declared original baseline prerequisites. The caller supplies the native index bytes and published hash/size reference, an `open_asset` resolver for the exact frozen references, a local owner-key path and an owned output directory. No working-state snapshot or upstream repository is used. The helper:

1. Checks the exact original index and migration-map bytes and ordered transport identities.
2. Authenticates the complete original multipart GCM/XZ/TAR streams through `VerifiedArchiveReader`, checking the declared original member subset while discarding unselected mirror/report bytes.
3. Restores the native members without overwriting existing immutable bytes and checks required CAS and manifest-chain identities.
4. Checks original manifest times against original bytes and the newly included import receipt. When the receipt declares the complete original archive inventory hash, the independently scanned inventory must agree.

Selected output bytes and total archive-stream bytes have separate bounds. A caller-supplied shared `LocalBudget` admits the declared output and filesystem overhead before recovery. Missing, corrupt, unbound or over-budget dependencies fail explicitly; recovery never falls back to recollection or historical bundle reupload. Files created by a failed recovery are removed.

The viewer recognizes these references without treating a legacy package as a new capture. It can discover the original combined observation from its frozen source manifest reference, load it using the ordinary original-owner decoder, and resolve only required legacy response CAS objects for a selected native increment. A dependency is authenticated completely before any provisional projection is published. Original times and migration provenance remain visible in capture metadata. Existing memory, transfer and 2 GB local disk bounds still apply.

Synthetic tests cover native encrypted, migrated plaintext-era and multipart original packages; a real first export that omits the old bundle; restoration and Git graph verification after deleting the working state/upstream; offline field comparison; reused original response bodies; original proof-byte preservation; absent legacy index times; and missing/corrupt dependency rejection. They do not read real keys or download real archives.
