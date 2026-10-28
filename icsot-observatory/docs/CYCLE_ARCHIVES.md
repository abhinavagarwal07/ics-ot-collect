# Cycle archives and compatibility

Automatic schedules remain paused. The user authorized one bounded manual comparison of five existing repositories using this layout; broader launches require separate authorization. Earlier hosted validation applies to the previous layout. Production-profile memory, disk and runtime remain unproven until the comparison completes.

## Publication

`ICSOT_RELEASE_LAYOUT=cycle-v1` routes new persistent state and MAIN payloads into `collector-cycle-s<SLOT>`, where `SLOT=floor(UTC Unix seconds / 21600)`. The corpus freezes the slot before P0 planning and passes it through P0/P1/P2, even if execution crosses a six-hour boundary. Actual observation/snapshot UTC times remain unchanged. A selected manual capture freezes its transport's slot once.

Logical `collector-state-r<ID>-g<GEN>` and `collector-observations-r<ID>-g<GEN>` identities remain intact. Physical ciphertext names include numeric repository ID, generation, state/observations kind and original asset name. Distinct repositories, lanes and retries retain unique generations; published payloads are immutable.

Small metadata, encrypted state indexes, plans and outcomes are retained as Git blobs/commits on `collector-metadata`. A trusted reference's additive `storage` field pins a canonical catalog by its Git blob ID, full SHA-256 and byte count, with repository/branch/path/commit context. The catalog preserves original metadata bytes and maps logical payload references to physical Release assets with their exact hashes/sizes. Catalog updates append commits; earlier blob pins remain reachable through branch history. State parts are pinned before encrypting the state index, then the final pointer pins a catalog containing that encrypted index. This avoids a circular hash dependency.

Back up and retain `collector-metadata` with `collector-state`, `collector-attestations`, all referenced Release assets and key material. A mutable branch tip or a Release listing alone is insufficient for reconstruction. New readers use pinned blobs directly and fail closed on context, namespace, size or hash mismatch. Old clients cannot resolve the new storage field and must be upgraded before reading new generations. Historical references without it continue to use their original Releases; no historical data is rewritten or claimed migrated.

GitHub permits [at most 1,000 assets per Release and files strictly below 2 GiB](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases). Before each payload upload, the collector checks the last asset page and leaves eight slots of headroom for the existing eight workers. A full Release uses `-p2` through `-p32` only when necessary. Rate failures and ambiguous uploads do not cause blind overflow retries. Metadata does not consume Release asset slots. There may therefore be more than one physical Release for an unusually large cycle; capture is not silently truncated at 1,000 assets.

Baseline initialization, recovery, manual compaction and delayed proof upgrades retain their existing publication layouts. Cycle transport explicitly rejects prepared-state/compaction publication, whose frozen historical indexes use the existing layout. Initial DigiCert, FreeTSA and OTS requests remain inline; pending OTS Bitcoin completion remains best effort. The authenticated outbox remains the discovery path for new catalogs. The historical baseline audit's Release enumeration does not enumerate new native cycle generations; use their state/outbox pins and the updated reader/viewer.

## Compression

`ICSOT_ARCHIVE_PROFILE=grouped-xz-v2` is enabled explicitly in the configured corpus-tier and selected-persistent workflows. It is not inferred from running in Actions. Other callers retain the legacy profile unless selected explicitly.

Eligible whole files are packed into independent tar inputs at most **524,288,000 bytes including tar headers and padding**, then compressed, then encrypted. The command is:

```sh
xz -T1 --no-adjust --memlimit-compress=2500MiB --lzma2=preset=8,dict=192MiB -c
```

Up to four groups run in parallel, each using one encoder process. MAIN streams tar into the encoder without staging a tar; working state stages bounded tar groups. API/Git MAIN finalizers share the exporter lock, and state publication follows collection, avoiding two independent four-encoder pools. The 500 MiB target is an input upper bound, not a required output size: compression ratios vary and no padding is added. Unchanged immutable state parts retain their original ciphertext. New state indexes are XZ-compressed before encryption and record both encoded and decoded hashes/sizes; old raw encrypted JSON indexes remain readable.

An individual MAIN member too large for a group selects the compatible single-tar/XZ-stream layout, using the same requested command with **one encoder** and splitting compressed bytes before encryption. The index records `legacy-large-member-fallback-v1`, its reason and the exact profile. Oversized state members use the existing raw chunk representation: eligible chunks use the requested XZ command, while already-compressed Git/pack/bundle/XZ/gzip data retains the raw bypass. Each reference records its actual encoding/profile; oversized encoded parts or insufficient scratch space defer publication. These are explicit format exceptions, not forced segmentation or silent data loss.

New readers allow 256 MiB of XZ decoder memory for this profile; legacy readers retain their previous 64 MiB bound. Source/ciphertext hashes, AEAD, complete member/part maps and reconstruction checks remain mandatory. Encoder failure does not select a cheaper compression profile. The exact flags are recorded; this profile is not described as plain `xz -9`.

The local XZ parser estimates about 2,082 MiB per requested encoder and 193 MiB per decoder; four encoders total about 8.13 GiB before application/runner overhead. GitHub documents [four CPUs, 16 GB RAM and 14 GB storage](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) for the standard public Linux runner. The 2,500 MiB option limits encoder settings, not total process RSS. Local tests use lightweight injected encoders and check the exact production arguments; no heavy four-process profile run has been performed. Measure actual hosted memory, disk, compression time and ratio before claiming throughput or resource fit. The [XZ manual](https://tukaani.org/xz/man/xz.1.html) explains `--no-adjust` and memory accounting.

## Retention and cleanup

No historical payloads, proofs, metadata, tags or Releases were deleted. Even an empty Release can be an active writer/recovery target or a retained binding. The bounded metadata inventory found five empty candidates, but did not prove absence of these dependencies, so they remain held. Cleaning future publication layout does not imply migrating or deleting earlier evidence.
