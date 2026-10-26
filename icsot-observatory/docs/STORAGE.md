# Storage and launch decision

The 185-target baseline uses **encrypted GitHub Release assets**, with XZ-compressed archives split into plaintext parts of at most 1 GiB and encrypted for the machine's RSA recipient. Keep large evidence outside ordinary Git. Retain the original CSV, collector configuration and small documentation in Git; a PR can review future observation indexes. See [encryption](ENCRYPTION.md).

The [original baseline](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40249527444) was canceled; its retained results are migrated into encrypted replacements. The resumed workflow reuses verified complete captures. See [Actions limits, errors and recovery](ACTIONS_OPERATIONS.md) for execution limits, cost bounds, remaining failure modes and the first downloaded-archive restore check.

This choice starts capture without a new provider account. Releases have no automatic expiry configured by this project. Owner deletion remains possible, and an independent backup is still an open requirement.

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

Prices checked 2026-10-25, for storage only; operation charges, transfer limits, taxes and later growth may change the comparison. At 50 GB of actual new stored bytes per month, 600 GB is the approximate footprint after twelve months, rather than the average first-year footprint. The baseline is counted within the monthly evidence allowance.

Sources: [repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits), [large files](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github), [release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [LFS billing](https://docs.github.com/en/billing/concepts/product-billing/git-lfs), [Actions artifacts](https://docs.github.com/en/actions/tutorials/store-and-share-data), [R2 pricing](https://developers.cloudflare.com/r2/pricing/), [B2 pricing](https://www.backblaze.com/cloud-storage/pricing), [S3 pricing](https://aws.amazon.com/s3/pricing/).

## Baseline workflow

The manual `Corpus baseline (one time)` workflow plans all 185 repositories in CSV order and captures at most four simultaneously. Each target attempts shallow full REST collection, advertised branch/tag/PR-head Git history, a portable full bundle, integrity verification and pending OpenTimestamps receipts. The workflow preserves partial outcomes and marks missing transfers explicitly.

Each archive contains source/configuration hashes, request and outcome reports, raw evidence, manifests, receipts and the portable bundle. Verified bundles replace the disposable mirror in the retained package. Archive parts carry individual SHA-256 digests; a per-repository index is uploaded after its parts. The aggregate inventory lists all 185 dispositions. A draft release is published after all capture jobs terminate, including when some captures are incomplete.

XZ here is the **baseline transport/archive format**. The current collector's individual CAS files still use original bytes; native per-object XZ and SQLite integration remain implementation work. Pending OTS receipts are not completed Bitcoin attestations.

To restore a downloaded target, verify each part against its index, concatenate the parts in the listed order, then decompress and extract the tar archive. Reconstruct the omitted mirror and run full offline verification from the collector directory:

```sh
python scripts/capture_baseline.py restore --root /path/to/extracted/evidence
```

## Recurring collection

**No recurring interval is enabled yet.** Recommend an initial six-hour timer on the available always-on host, with persistent mirrors and durable queue/state. Actions can validate or trigger recovery. Hosted Actions cron is best effort and can be delayed or dropped. [Scheduled events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

Before recurrence, implement genuine incremental Git archives with explicit prerequisites, retain only new CAS objects, and test restoration of the complete dependency chain. The current `--bundle-full` rewrites essentially the whole Git history, including new observation refs; repeating it four times daily would exceed the intended growth budget. Fresh runners also require prior state to avoid turning a requested delta into another baseline.

Record proof upgrades in later append-only checkpoints rather than replacing original receipts. Keep the evidence backend replaceable so Release assets can be copied unchanged into an independent object store and verified by digest.
