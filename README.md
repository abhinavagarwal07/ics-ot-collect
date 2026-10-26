# Public GitHub observation study

Incremental preservation of public repository observations, with independently verifiable evidence and external timestamps.

- [Current requirements](requirements.md)
- [Collector and usage](icsot-observatory/README.md)
- [Design](icsot-observatory/docs/DESIGN.md)
- [SQLite schema](icsot-observatory/docs/SCHEMA.md)
- [Storage and launch decision](icsot-observatory/docs/STORAGE.md)
- [Actions limits, errors and recovery](icsot-observatory/docs/ACTIONS_OPERATIONS.md)
- [Durable split-lane collection and incremental transfers](icsot-observatory/docs/PERSISTENT.md)

The selected cohort is all **185 repositories** in [public_patch_corpus_185.csv](public_patch_corpus_185.csv), configured in [config.corpus.toml](icsot-observatory/config.corpus.toml): 42 healthcare, 51 ICS/OT/IIoT and 92 cross-sector projects. CSV order and all selections are preserved, regardless of pilot or priority labels. The CSV retains repository roles, source links and measurement caveats.

Main evidence payloads are encrypted before upload using AES-256-GCM with RSA-OAEP-SHA256 key wrapping. Metadata and the recipient public key are public; the private RSA key stays on the owner's machine. See [encryption and restoration](icsot-observatory/docs/ENCRYPTION.md).

The [replacement encrypted baseline](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40275429320) retains **109 verified complete captures**—94 from the [preceding resumed run](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40253057671) and 15 from the [original run](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40249527444)—and schedules only the **76 unresolved repositories**. Accepted evidence remains in its original releases. The original 16 archive parts and nine historical Actions artifacts were migrated into verified encrypted replacements before this repository became public.

[`libfuse/libfuse`](https://github.com/libfuse/libfuse) remains the single-repository smoke target in [config.libfuse.toml](icsot-observatory/config.libfuse.toml).

[The first live validation](icsot-observatory/docs/LIBFUSE_VALIDATION.md) passed in GitHub Actions, with a full capture, delta capture, two independently restored Git bundles, and byte-identical local CSV regeneration. Timestamp receipts remain pending verification.

The collector includes durable split API/Git lanes, resumable checkpoints, per-scope watermarks and encrypted incremental archives. Selected-repository `github-run` observations stay manual and recover working state with a separate operational key. A separate daily/manual workflow refreshes public OpenTimestamps proofs and appends linked metadata without recapture or decryption; Bitcoin attestations remain unverified without a trusted node. Daily cohort-wide proof throughput is unmeasured. Budget enforcement, research metadata, per-object XZ, first-observed queries, Discussions and study Git commits remain open. The baseline retains full bundles and verified ordered multi-parent reuse. See [storage allowances](icsot-observatory/docs/STORAGE.md) and [timestamp maintenance](icsot-observatory/docs/TIMESTAMPING.md).
