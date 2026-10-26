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

The [encrypted resumed baseline](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40253057671) reuses 15 verified complete captures and attempts the remaining 170 targets. The original 16 archive parts and nine historical Actions artifacts were migrated into verified encrypted replacements before this repository became public.

[`libfuse/libfuse`](https://github.com/libfuse/libfuse) remains the single-repository smoke target in [config.libfuse.toml](icsot-observatory/config.libfuse.toml).

[The first live validation](icsot-observatory/docs/LIBFUSE_VALIDATION.md) passed in GitHub Actions, with a full capture, delta capture, two independently restored Git bundles, and byte-identical local CSV regeneration. Timestamp receipts remain pending verification.

The collector includes independent durable API/Git queues, resumable scope checkpoints, per-scope watermarks, incremental Git archives and encrypted transfers through `icsot-observe persistent`. The new manual selected-repository `github-run` path restores encrypted working state using a separate operational key; hosted pilot validation is pending and no recurring schedule is enabled. The monthly storage cap, research metadata schema, native per-object XZ, first-observed queries, Discussions and study Git interval commits remain implementation work. Source control excludes evidence and credentials. The existing manual baseline retains full bundles and accepted-parent reuse; later code changes do not alter a running checkout.
