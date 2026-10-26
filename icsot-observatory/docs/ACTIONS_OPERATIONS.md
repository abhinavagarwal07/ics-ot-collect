# Actions limits, errors and recovery

## Active baseline

[Run 40249527444](https://github.com/abhinavagarwal07/ics-ot-collect/actions/runs/40249527444) started at 2026-10-26 00:28 UTC from collector commit `796c6b4764f6eac27bd444f3fc06bca114a4dc00`. It queues the complete 185-target cohort, with four captures at a time. Captures have a 180-minute job timeout; finalization has 90 minutes. **No recurring interval is enabled.** A code fix pushed afterward does not change this run's checkout.

The first four completed captures took 63–183 seconds. These small early targets do not establish an ETA for large repositories. The CSV's approximately 30.88 GiB is a declared GitHub repository-size metric, not a measured archive or peak-disk bound.

## Limits that matter

| Limit | Consequence |
| --- | --- |
| Included minutes/spend and account concurrency | These belong to the repository owner's user/organization account and are shared across its repositories. The triggering actor and the 185 public targets do not supply separate allowances. |
| Six hours per hosted job; 35 days per workflow | A multi-job baseline may exceed six hours overall. Each configured job remains below the hosted ceiling. |
| 256 jobs per matrix | 185 capture jobs fit. Four-way parallelism shares account capacity with other workflows. |
| Private standard Ubuntu: 2 CPUs, 8 GB RAM, 14 GB SSD | Process one repository per runner. Mirrors, temporary bundles, CAS objects, restore scratch space and XZ parts can coexist. |
| `GITHUB_TOKEN`: 1,000 REST calls/hour per source workflow repository | Four jobs share this allowance; adding workers does not multiply it. Release operations also need capacity. |
| Secondary limits, including content-generating requests | Bound upload concurrency and obey server deferrals; primary capacity remaining does not exclude secondary throttling. |
| Release: 1,000 assets, each under 2 GiB | Use at most 1 GiB per archive part and count indexes/inventory as assets too. |

The documented 24-hour queued-job limit appears under **self-hosted runners**; it is not evidence of a 24-hour expiry for this hosted matrix. [Actions limits](https://docs.github.com/en/actions/reference/limits), [private runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [API limits and backoff](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [Release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

Even empty targets require at least nine source reads each before rechecks, retries and transfers: 1,665 for 185 repositories. Busy repositories require thousands of pages. A per-job one-hour primary wait is bounded, but does not coordinate the shared allowance or guarantee complete metadata. The 40-request transfer reserve is a local precaution, not an atomic global reservation.

## Compute cost

Public target repositories do not make execution free in this **private collector repository**. Standard Linux x64 costs $0.006 per billed minute beyond included usage; each job is rounded up to a whole minute. Account plan, remaining included minutes and billing stop limits have not been verified. [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [runner pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing).

The owner reports no billing setup. GitHub documents that **without a valid payment method, Actions usage is blocked after the included allowance is exhausted**. The amounts below describe hypothetical paid usage, not a debt that this no-payment setup is accruing. Usage belongs to the repository owner's [personal billing account](https://github.com/settings/billing). [No-payment behavior](https://docs.github.com/en/billing/concepts/product-billing/github-actions#using-more-than-your-included-quota).

- Five minutes per capture implies approximately 925 runner-minutes, or $5.55 gross before included usage.
- Ten minutes implies approximately 1,850 minutes, or $11.10 gross.
- The configured timeout ceiling is `(185 × 180 + 90 + 10) × $0.006 = $200.40`, excluding separate validation workflows. This is a ceiling, **not a forecast**.

API waits consume runner minutes. Increasing parallelism reduces elapsed time only when useful work can proceed; it does not reduce aggregate billable time.

Standard Ubuntu runners in a **public execution repository** have free compute usage; runtime, API, concurrency and acceptable-use limits still apply. Making this existing repository public would expose its source history, cohort CSV and evidence releases. A separate public execution repository could retain private evidence here, using a separate narrowly scoped upload credential: its automatic `GITHUB_TOKEN` cannot write into this private repository. Larger runners remain paid even for public repositories. [Public runner billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [workflow token scope](https://docs.github.com/en/actions/concepts/security/github_token).

## Failure handling and remaining gaps

| Failure | Handling / limitation |
| --- | --- |
| Primary API allowance or bounded wait exhausted | Mark metadata partial, preserve response records and attempt Git capture. A successful Git archive does not make incomplete metadata complete. |
| Secondary API throttling | The hardened Python client respects `Retry-After`, or waits at least one minute with exponential backoff, within a cumulative allowance. The original active checkout predates this fix. |
| Release transfer throttling or uncertain upload | Never overwrite an asset. Reconcile an existing name by SHA-256 and size before accepting it. CLI upload retry alone does not handle all secondary limits; transfer recovery can still fail explicitly. |
| Git refs change during fetch | Record a partial observation. Preserve available fetched evidence; do not claim an atomic snapshot. |
| OTS unavailable or proof missing | Retain the data, report incomplete attestation and avoid a successful complete-capture disposition. Pending receipts require later Bitcoin verification. |
| Missing/wrong archive part or inconsistent index | Fail acceptance. A target's self-reported success flag is insufficient without semantic and remote-integrity checks. |
| Deadline, disk full, OOM, cancellation or runner loss | A process can be killed before cleanup/upload. Missing indexes remain missing/incomplete; `finally` is not a durability guarantee. |
| Finalizer failure after inventory upload or publication | Recover by reconciling the existing inventory and source identities, reusing its bytes and completing publication idempotently. Never replace evidence with a freshly generated conflicting inventory. |

Durable per-scope pagination, resumable large metadata backfills, a shared API controller and recovery from arbitrary runner loss remain implementation work. A six-hour cron would not resolve these gaps. Keep persistent Git state and use incremental archive dependencies before enabling recurrence.

The hardened helper limits collection to 120 minutes and verification to 20 minutes, leaving approximately 40 minutes within the 180-minute job for packaging and transfer. Disk capacity and tool versions are recorded. This improves orderly timeout handling; all compressed parts still stage locally, and additional transfer waits or forced termination can exceed that remaining window. These changes apply to later captures, not the already-running original checkout.

## Recovery policy

Do not blindly rerun failed capture jobs into the same release. A fresh observation produces different bytes under the original deterministic asset names, and overwrite refusal is intentional. Preserve successful indexes and payloads. Retry only missing or incomplete scopes in a separate repair generation, link its original source configuration and parent release, and publish an aggregate index referencing both generations. An OTS-only failure should be repaired with a proof supplement; it does not require recapturing every repository.

The active release remains a draft until the matrix reaches terminal states. Its final inventory must list every target, including partial, failed and missing transfers. A red workflow is compatible with useful retained evidence; a green disposition must require the declared coverage and integrity checks.

## Downloaded archive validation

The first GDCM release archive was downloaded and independently restored offline. Its omitted mirror was reconstructed using only the retained bundle. Full verification passed: 20 raw response observations, 8,114,047 response bytes, 338 refs, one mirror and one portable bundle; no partial or unstamped runs. Bitcoin verification was not performed.

- Archive: 40,021,912 bytes; SHA-256 `6e8f88d3799670a8d466f9c3861aaf517d91cb09d5be8f725faa7ecc2a68813e`.
- Index SHA-256: `36991eb75bdb6b6099c2a383094b41065abfea86c12d47a139e3a74511781449`.
- Capture manifest SHA-256: `6f14cab3f27d6e75211170ee2b802a2158e40c9cc394747fdbd6c021e277edf4`.
