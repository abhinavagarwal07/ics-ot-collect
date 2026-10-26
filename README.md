# Public GitHub observation study

Incremental preservation of public repository observations, with independently verifiable evidence and external timestamps.

- [Current requirements](requirements.md)
- [Collector and usage](icsot-observatory/README.md)
- [Design](icsot-observatory/docs/DESIGN.md)
- [SQLite schema](icsot-observatory/docs/SCHEMA.md)
- [Storage and launch decision](icsot-observatory/docs/STORAGE.md)
- [Actions limits, errors and recovery](icsot-observatory/docs/ACTIONS_OPERATIONS.md)

The selected cohort is all **185 repositories** in [public_patch_corpus_185.csv](public_patch_corpus_185.csv), configured in [config.corpus.toml](icsot-observatory/config.corpus.toml): 42 healthcare, 51 ICS/OT/IIoT and 92 cross-sector projects. CSV order and all selections are preserved, regardless of pilot or priority labels. The CSV retains repository roles, source links and measurement caveats.

Main evidence payloads are encrypted before upload using AES-256-GCM with RSA-OAEP-SHA256 key wrapping. Metadata and the recipient public key are public; the private RSA key stays on the owner's machine. See [encryption and restoration](icsot-observatory/docs/ENCRYPTION.md).

[`libfuse/libfuse`](https://github.com/libfuse/libfuse) remains the single-repository smoke target in [config.libfuse.toml](icsot-observatory/config.libfuse.toml).

[The first live validation](icsot-observatory/docs/LIBFUSE_VALIDATION.md) passed in GitHub Actions, with a full capture, delta capture, two independently restored Git bundles, and byte-identical local CSV regeneration. Timestamp receipts remain pending verification.

The collector is a prototype. SQLite integration, native per-object XZ storage, first-observed commit queries, GitHub Discussions and interval commits in a study Git repository remain implementation work. Source control excludes collected evidence and credentials. The manual corpus baseline workflow preserves encrypted XZ archive parts and public outcome indexes in Releases; the separate libfuse smoke test uploads encrypted temporary Actions artifacts. No recurring collection schedule is enabled yet.
