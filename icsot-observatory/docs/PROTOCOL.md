# Evidence protocol (proposed v1)

This document specifies a **target protocol**. The starter implementation covers the main primitives, but does not yet meet all MUSTs. Implementation status is tracked in `PRODUCTION_GAPS.md`. Treat departures from the protocol as measurable limitations, not concealed exceptions.

## A. Unit of observation

1. Repository: GitHub numeric `repository.id` (not its mutable owner/name), plus its observation-time public URL and classification.
2. Public API observation: request start `t0`, response completion `t1` in UTC, HTTPS endpoint + query, API version, response status, content SHA-256, original body bytes, safe response headers, public-auth context, and collector version.
3. Git observation: `git ls-remote` query interval, observed refname -> object ID map, fetched and retained Git object graph, and archived local refs mapping to observed refs. No claim that every Git object in a mirror was public by its author date.
4. Snapshot/run: collection window `[t0_min, t1_max]`, **not an instantaneous state**. One run contains multiple independently timed observations. A per-response interval is canonical for temporal analysis.
5. External anchor: SHA-256 over canonical, finalized immutable run manifest; OpenTimestamps receipt and, optionally, a signed RFC 3161 timestamp token from an independently administered TSA.
6. A success record names exactly which endpoints completed, which were skipped, and whether a pagination/rate/event-window caveat applies.

## B. Identity and access

- Only public GitHub repositories. Use public-only or minimally privileged read-only credentials; **do not** collect private vulnerabilities or drafts using an account with privileged access.
- Independent anonymous checks should validate that sampled included records are accessible without authentication at collection time. An authenticated 200 from a public repository is not proof that every resource in the response was public to everyone.
- Repository name changes, redirects, transfers, and privatization produce explicit cohort-amendment or censoring events; do not silently swap namesakes.
- Never record access tokens, cookies, SSH keys, proxy credentials or authenticated response secrets. API headers are on a strict safe allowlist, not a dump of all headers.

## C. Collection tiers (distinct from completeness claims)

| Tier | Target cadence | Observed surfaces | Notes |
|---|---|---|---|
| E0 | 15–60 min | Repository public Events API | Capped at 300 events / last 30 days. Not an event-completeness guarantee; obey `X-Poll-Interval`. |
| G1 | 1–6 h | Advertised Git heads/tags/pull heads and object graph | Retain force-pushed-away states if caught. `ls-remote`/fetch are not atomic. |
| M1 | 3–6 h | Updated issues/PRs, issue comments, review comments, releases, tags | Use `since`+overlap where supported, explicit updated sort for PRs. |
| M2 | Daily | All current issues/PR metadata and comments; published releases and release assets | Detect missed edits, deletions; non-atomic pagination. |
| M3 | Weekly/sharded | All item timelines, reviews, PR commits/files, issue events, published advisories | The full crawl is a backfill job with durable per-item cursor, not one giant transaction. |
| X1 | Daily/weekly | GH Archive, Software Heritage visits, public advisories, releases in package registries | Corroborating sources; do not claim independent ground truth where they share source failures. |

Metadata layer must preserve both per-issue `/timeline` and per-PR `/reviews`/`/commits`/`/files`; issues and PRs are not disjoint in GitHub's Issues API. Preserve release metadata and exact published binary artifacts if investigating deployable fixes; a tag is not a fixed release.

## D. Durable fetch algorithm

1. Enqueue `(repository_id, endpoint, scope, cursor, auth_context)` in persistent durable queue; allocate a bounded rate budget for every group.
2. Write per-attempt request interval and response metadata even for failures. Read original bytes **before** parsing and hash them, storing in CAS. Do not normalize JSON until derivative analysis.
3. Follow REST `Link` pagination only; retain every page, including duplicates, changed pages, and error responses. Detect if the first page changes across a multi-page walk; classify as non-atomic and retry from a new checkpoint, rather than asserting completeness.
4. For delta, query since the **last successfully completed scope** minus a documented overlap (48 h initial), not the most recent attempted run; only advance watermark after all expected pages and requested details complete. If a subset fails, retry exactly that subset.
5. For endpoints with conditional ETags, a 304 is a new observation of unchanged resource under the request conditions, **not a new copy of body bytes**. Bind it explicitly to the previous 200 body hash with the same endpoint/query/Accept/API-version/credential context. A 304 must never accidentally make a failed prior crawl 'complete'.
6. Run scope reconciliation after delta ingestion. If a prior ID is missing from a *full successful, stable* enumeration, classify `not_observed_currently`, and investigate before coding it as deletion. Disappearance can reflect GitHub access/visibility changes, network/data inconsistency or deletion.
7. Check caps: GitHub Events 300; GitHub search 1,000 if search is used (avoid it for primary enumeration); GitHub PR file-list cap where applicable. Preserve a `CAP_REACHED` state. Heavy repos require sharding.
8. Strict per-repository and global rate budgets; respect primary/secondary limits, `Retry-After`, `X-RateLimit-Reset`, and `X-Poll-Interval`. Do not spin-retry on persistent 403/429.

## E. Append-only evidence and chain of custody

For completed run R:

1. Freeze each original HTTP body (`raw_sha256 = SHA256(bytes)`), archive Git objects and an observation-time advertised ref map.
2. Complete a deterministic JSON manifest including the ID, requested scope, response digests/byte sizes, UTC intervals, Git ref map, errors, collection flags, code/config identifiers, previous manifest SHA-256 and local clock health.
3. Store manifest as an immutable, create-only object. The chain includes **partial runs**, failures and coverage gaps, not only successful runs. Avoid backfilling under a past timestamp.
4. Persist manifest+raw CAS+Git mirror to a second failure domain with write-once or Object Lock retention. Independently spot-check reading copied bytes.
5. Create OTS receipt for the frozen manifest. Store the initial receipt without modification; later store the upgraded proof as a *new* immutable version. Record proof-creation time, anchoring status and Bitcoin block height when verified.
6. Publish manifest digests to at least one independent witness (e.g. separately administered transparency log or signed periodic digest release). A privately held hash chain does not guarantee detection of withheld/deleted runs.
7. Archive externally issued RFC 3161 tokens if tighter trusted-clock evidence is required. Cryptographic verification must check TSA signature, certificate path, policy, nonce/message imprint and stated timestamp accuracy.
8. Audit by replay: reload manifests, check chains, verify each body SHA-256 and Git archived refs/objects, verify OTS independently, then regenerate analytic tables from raw objects.

OTS proves `manifest existed no later than anchored block`, not the API request's absolute completion time. Honest traceability additionally depends on collector honesty, verifiable access constraints, robust clocks, and corroboration.

## F. Clock and identity provenance

- Operate synchronized UTC hosts. Record NTP/chrony offset, dispersion/uncertainty and sync status **at each run**; alert and mark time data unusable outside a preregistered acceptable offset.
- Preserve both API `Date` header and local request start/end; neither is a source-signed receipt that bytes were public at a specified minute. HTTP TLS authenticates a connection to the endpoint subject to local trust assumptions, not an archived content signature.
- Record collector build digest/container image, Git binary version and digest, GitHub API version, known endpoint behavior, host/container identity, and configuration changes.
- If obtaining timestamp attestations from an external TSA, do not reuse TSA clock as 'first public exposure' evidence; it validates evidence existence only.

## G. Failure and negative-evidence rules

- **No full-run success on HTTP error, pagination drift, max page cap, object integrity failure, missing Git refs, or missed scheduled collection.** Preserve partial evidence and an explicit failure classification.
- **Never infer no issue/PR existed from a 304 on the wrong query, a narrow `since` query, the event feed alone, a failed response, or a partial enumeration.**
- An object first captured at `t1` has only a first-observed bound. A well-documented prior successful enumeration without that object may support a weaker interval statement (`not visible in specified endpoint then`), subject to endpoint semantics and pagination stability.
- Baseline pre-existing commits, tickets and releases are left-censored: observed by the first crawl, not first published then.
- Deletion, toggled visibility and force pushes between polls can remain forever unobservable. Measure the proportion of missed scheduled runs and report collection-delay distribution rather than describing collection as exhaustive.

## H. Data products

- **Private evidence archive:** raw bytes, Git objects, run manifests, receipts, errors, identity and timing metadata.
- **Replication bundle:** public manifests, verifying tools, collector source, study protocol, sample raw pages where licensable, non-sensitive derived records, timestamps, checksums.
- **Analysis:** parquet/CSV tables keyed by stable repository id, issue/PR id, `entity_id`, and version digest. Every derived record retains exact `raw_response_sha256`, run id, original URL and observation interval.
- Independent investigator must be able to produce the same observation tables with an offline verifier (no dependency on a mutable external SQL service).
