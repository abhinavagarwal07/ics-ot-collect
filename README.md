# Public GitHub observation study

Incremental preservation of public repository observations, with independently verifiable evidence and external timestamps.

- [Current requirements](requirements.md)
- [Collector and usage](icsot-observatory/README.md)
- [Design](icsot-observatory/docs/DESIGN.md)
- [SQLite schema](icsot-observatory/docs/SCHEMA.md)
- [Storage and launch decision](icsot-observatory/docs/STORAGE.md)
- [Actions limits, errors and recovery](icsot-observatory/docs/ACTIONS_OPERATIONS.md)
- [Repository sizes and baseline outcomes](icsot-observatory/docs/REPO_SIZE_REVIEW.md)
- [Durable split-lane collection and incremental transfers](icsot-observatory/docs/PERSISTENT.md)
- [Local capture and diff viewer](icsot-observatory/docs/VIEWER.md)
- [Bounded recovery audit](icsot-observatory/docs/RECOVERY_AUDIT.md) and [shared 2-GB local disk limit](icsot-observatory/docs/LOCAL_DATA.md)

The active cohort contains **181 repositories**: 42 healthcare, 51 ICS/OT/IIoT and 88 cross-sector projects. Effective 2026-10-30, collection excludes exactly `v8/v8`, `python/cpython`, `aws/aws-lc` and `envoyproxy/envoy`, including manual selections. The original 185-row [CSV](public_patch_corpus_185.csv), [configuration declarations](icsot-observatory/config.corpus.toml) and frozen priority rows remain provenance; the remaining membership and order are preserved. See [scope and exclusion reasons](icsot-observatory/docs/CORPUS_SCOPE.md).

Main evidence payloads are encrypted before upload using AES-256-GCM with RSA-OAEP-SHA256 key wrapping. Metadata and the recipient public key are public; the private RSA key stays on the owner's machine. See [encryption and restoration](icsot-observatory/docs/ENCRYPTION.md).

The [eight-worker resumed baseline](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40294818409) finished with **167 accepted captures and 18 incomplete targets**, including 142 accepted captures reused from three verified parent releases. [Its evidence release](https://github.com/abhinavagarwal07/ics-ot-collect/releases/tag/corpus-baseline-40294818409-1) is published after metadata-only finalizer recovery; the original sealed inventory and timestamp catalog remain unchanged. Accepted evidence stays in its original releases with original observation times. The original 16 archive parts and nine historical Actions artifacts were migrated into verified encrypted replacements before this repository became public.

[`libfuse/libfuse`](https://github.com/libfuse/libfuse) remains the single-repository smoke target in [config.libfuse.toml](icsot-observatory/config.libfuse.toml).

[The first live validation](icsot-observatory/docs/LIBFUSE_VALIDATION.md) passed in GitHub Actions, with a full capture, delta capture, two independently restored Git bundles, and byte-identical local CSV regeneration. Timestamp receipts remain pending verification.

The collector includes durable split API/Git lanes, resumable checkpoints, per-scope watermarks and encrypted incremental archives. The [six-hour cohort workflow](icsot-observatory/docs/PERSISTENT.md#six-hour-cohort-workflow) is manual-only with automatic schedules paused. It plans all 181 active entries, resumes existing authenticated working state and performs no automatic fresh bootstraps by default (explicit manual range zero to eight), using eight shared capture slots and the existing separate operational key. Other missing-state entries remain bootstrap-pending; the nominal interval does not promise a completed cohort sweep. A separate manual workflow refreshes public OpenTimestamps proofs without recapture or decryption; Bitcoin attestations remain unverified without a trusted node. Research metadata, first-observed queries, Discussions and study Git commits remain open; runtime monthly budget enforcement is intentionally omitted. The baseline retains full bundles and verified ordered multi-parent reuse. See [storage allowances](icsot-observatory/docs/STORAGE.md) and [timestamp maintenance](icsot-observatory/docs/TIMESTAMPING.md).
