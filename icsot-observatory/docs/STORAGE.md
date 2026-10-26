# Storage and launch decision

The 185-target baseline uses **encrypted GitHub Release assets**, with XZ-compressed archives split into plaintext parts of at most 1 GiB and encrypted for the machine's RSA recipient. Keep large evidence outside ordinary Git. Retain the original CSV, collector configuration and small documentation in Git; a PR can review future observation indexes. See [encryption](ENCRYPTION.md).

The [original baseline](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40249527444) was canceled; its retained results are migrated into encrypted replacements. The resumed workflow reuses verified complete captures. See [Actions limits, errors and recovery](ACTIONS_OPERATIONS.md) for execution limits, cost bounds, remaining failure modes and the first downloaded-archive restore check.

This choice starts capture without a new provider account. Releases have no automatic expiry configured by this project. Owner deletion remains possible, and an independent backup is still an open requirement.

The initial 185-repository baseline has an explicitly approved one-time allowance of **100,000,000,000 stored bytes**, covering all retained attempts, partial outcomes, retries and metadata across its releases. The 2026-10-26 audit observed approximately **48.93 GB of Release assets across three baseline releases**; that measurement excludes other working copies and Git storage. GitHub documents no additional total-size limit for Releases, alongside its 1,000-assets-per-release and under-2-GiB-per-asset limits. This does not authorize automatic growth beyond the baseline allowance. Future recurring collection retains its separate 50,000,000,000-byte UTC-month policy. Runtime admission enforcement is not implemented; indefinite retention and no automatic deletion remain unchanged. [GitHub Release storage quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

## Alternatives reviewed

| Storage | Decision |
| --- | --- |
| Git branch / PR | Small manifests and checkpoints. A PR points to ordinary Git objects and adds no storage allowance. GitHub enforces a 100 MiB file limit and a 2 GB push limit. |
| Git LFS | Paid storage and downloads; changed archives retain another complete version. Little benefit over an object store here. |
| GitHub Releases | Selected for the baseline: up to 1,000 assets per release, each under 2 GiB, with no documented aggregate release-size or bandwidth limit. |
| Actions artifacts / cache | Temporary staging; retention and eviction conflict with indefinite evidence retention. |
| Cloudflare R2 Standard | Preferred independent store when download volume is uncertain: approximately $8.85/month for 600 GB after the storage allowance; direct egress is free. |
| Backblaze B2 | Approximately $4.10/month for 600 GB after the storage allowance; free downloads up to three times average monthly storage, then charges apply. |
| S3 Standard, us-east-1 | Approximately $13.80/month for 600 GB; internet egress can dominate. Attractive if the collection host is EC2 in the same region. |

Prices checked 2026-10-25, for storage only; operation charges, transfer limits, taxes and later growth may change the comparison. Future recurring growth of 50 GB per month would add approximately 600 GB after twelve months; the initial baseline has its separate one-time 100-GB allowance. Additional copies and operational state need separate accounting.

Sources: [repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits), [large files](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github), [release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [LFS billing](https://docs.github.com/en/billing/concepts/product-billing/git-lfs), [Actions artifacts](https://docs.github.com/en/actions/tutorials/store-and-share-data), [R2 pricing](https://developers.cloudflare.com/r2/pricing/), [B2 pricing](https://www.backblaze.com/cloud-storage/pricing), [S3 pricing](https://aws.amazon.com/s3/pricing/).

## Baseline workflow

The manual `Corpus baseline (one time)` workflow plans all 185 repositories in CSV order. Future dispatches validate integer `max_parallel` from 1 through 16, defaulting to 8; the matrix consumes that validated value. Run `40275429320` keeps its pinned limit of 4. Each target attempts shallow full REST collection, advertised branch/tag/PR-head Git history, a portable full bundle, integrity verification and pending OpenTimestamps receipts. Shared API/upload quotas and the applicable storage allowance still apply; concurrency does not multiply capacity or enforce budget admission.

Each archive contains source/configuration hashes, request and outcome reports, raw evidence, manifests, receipts and the portable bundle. Verified bundles replace the disposable mirror in the retained package. Archive parts carry individual SHA-256 digests; a per-repository index is uploaded after its parts. The aggregate inventory lists all 185 dispositions. A draft release is published after all capture jobs terminate, including when some captures are incomplete.

XZ here is the **transport/archive format**. Individual CAS files still use original bytes; native per-object XZ and the proposed research metadata schema remain implementation work. Operational queue/lease/cursor SQLite storage is implemented. Pending OTS receipts are not completed Bitcoin attestations.

To restore a downloaded target, verify each part against its index, concatenate the parts in the listed order, then decompress and extract the tar archive. Reconstruct the omitted mirror and run full offline verification from the collector directory:

```sh
python scripts/capture_baseline.py restore --root /path/to/extracted/evidence
```

## Recurring collection

**No recurring interval is enabled yet.** The implemented `persistent` command defaults to independent six-hour API/Git intervals with durable mirrors, queue and state. Execution may use a persistent host or a GitHub-backed adapter that restores authenticated working state before each bounded run; a host has not been deployed. Hosted Actions cron is best effort and can be delayed or dropped. [Scheduled events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

Genuine incremental Git archives with explicit prerequisites and encrypted per-capture transfers are now implemented and tested offline. Legacy `--bundle-full` still rewrites the full Git history; the active one-time baseline keeps that behavior. Recurring execution must retain and restore prior working state to avoid another baseline, enforce the monthly storage cap, and verify remote retention. See [durable collection](PERSISTENT.md).

Record proof upgrades in later append-only checkpoints rather than replacing original receipts. Keep the evidence backend replaceable so Release assets can be copied unchanged into an independent object store and verified by digest.
