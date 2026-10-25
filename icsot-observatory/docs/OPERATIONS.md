# Operations runbook and acceptance tests

This runbook applies to the **intended production system**. The starter CLI supports scheduled polling and integrity checks but does not yet implement queue-based deep backfills, managed immutable cloud storage or NTP error measurements.

## 1. Host and storage

- Dedicated Linux VM with stable identity, synchronized UTC via chrony, unattended security updates, minimum inbound ports, read-only GitHub credential and monitored outbound TLS/Git.
- Disk sized by first-week measured raw bytes and Git pack growth. Preserve raw data and full Git objects. Use separate failure domain for object-locked replication; size per actual churn, not repository default-branch size alone.
- `chmod 700` on evidence root; token via secrets manager/systemd credentials, never in unit file or CLI arguments. Separate operator, auditor, and deletion credentials.
- Capture host metrics (uptime, disk, NTP offset/dispersion, time sync failures, `git --version`, collector container digest) in each run. Reject data from unsynchronized intervals for minute-scale claims.

## 2. Example scheduling (NOT a guarantee of complete coverage)

Simple cron starting point for small initial cohort (use systemd timers + job queue at scale):

```cron
# Hourly public activity observation; official X-Poll-Interval still takes precedence
11 * * * * cd /srv/icsot-observatory && /srv/venv/bin/icsot-observe collect --config /srv/config.toml --mode events >> /srv/log/events.log 2>&1
# Every 6 hours update Git and changed metadata
19 0,6,12,18 * * * cd /srv/icsot-observatory && /srv/venv/bin/icsot-observe collect --config /srv/config.toml --mode delta >> /srv/log/delta.log 2>&1
# Nightly full listing refresh (shallow; full item backfill must be sharded)
47 2 * * * cd /srv/icsot-observatory && /srv/venv/bin/icsot-observe collect --config /srv/config.toml --mode full >> /srv/log/full.log 2>&1
```

**These overlapping cron jobs contend for the starter's global lock.** This is expected and is a reason to replace cron with a single queued scheduler before production. A conflicting lock fails; missed scheduled observations must be logged as gaps. Also, a broad full fetch can exceed an hourly GitHub rate budget. Test cadence on two small repositories first.

## 3. Backup and timestamp retention

After each finalized run, replicate manifest, raw objects, Git objects, and receipts; verify the remote copy is readable. Choose restic over an encrypted off-host repository and/or S3 Object Lock in **compliance mode** where appropriate. A normal writable object-store bucket or same-host restic store does not independently prevent deletion by the administrator. Freeze retention policy and change log before collecting study evidence.

A daily integrity audit must verify CAS and manifest chain; weekly, perform Git object integrity audit and restore sample objects; monthly, restore a whole repository run (all CAS, Git refs/objects, proof) in an isolated machine with **no authenticated GitHub access** and reproduce derived hashes.

When an OTS proof is pending, schedule `ots upgrade <file>.ots` in a later run, then `ots verify <file>.ots` against an independently trusted Bitcoin source; keep both pending and upgraded receipts (the working `.ots` is upgradable, not immutable). Do not mark pending receipts as verified. Monitor if the remote calendar never provides a complete proof.

For higher-precision legal/evidentiary requirements, query an independent RFC 3161 TSA on the **same frozen manifest hash**, retain signed token and certificate chain, and independently validate signature, hash imprint, nonce, certificate validity and time accuracy. Choose an operational TSA with documented availability/certificates, not an arbitrary unverified public HTTP service.

## 4. Run health and alerting

Page immediately / mark measurement gap on: auth failure, private repo, identity mismatch, all repos failing, clock unsynchronized, Git object corruption, hash-chain mismatch, no stable ref capture, or failure to persist to immutable off-host storage. Alert on: pending OTS older than retry window, repeated pagination churn, unanswered PR backfill, rate throttling, REST API upgrade warnings, storage growth, and suspicious missing data.

A failed run is part of the scientific record. Never backdate a late retry to make it look as if data were collected at the originally scheduled time.

## 5. Evidence acceptance exercise (perform before cohort launch)

1. Create local test repo with initial commit; capture refs. Create second commit and force-push; confirm old object remains reachable through archived ref, despite live ref moving.
2. Replace an observed comment body in a **test response fixture**; verify CAS and/or manifest integrity check fails when bytes differ.
3. Simulate two-page API crawl, mutate first page between requests; confirm run marked partial and existing bytes remain accessible.
4. Simulate 429, 403, 500, broken Link, premature endpoint cap, timeout; confirm no success watermark changes and errors are retained.
5. Simulate GitHub numeric repo ID changing while slug remains; block capture and quarantine.
6. Verify correct distinction between issue/PR id, review-comment id and timeline id; reproduce a content-version history from raw bytes.
7. Disconnect collector mid-run; restart without data loss or silently advancing a queue cursor.
8. Destroy primary storage in a test environment; restore from remote WORM and prove original manifest hash, Git objects and OTS receipt match.
9. Independently verify a complete Bitcoin proof; explain explicitly what it does **not** prove.
10. Run two machines independently for a sampled time interval; compare observed item digest counts and investigate disagreements, rather than treating one as ground truth.

## 6. Budget calculation

For a repo/day, record: `R = R_meta + R_list_pages + R_issue_details + R_PR_details + R_timeline_pages + R_reviews + R_assets + R_verification`. Estimate actual calls using a pilot and include retries, pagination rechecks and failed responses. Standard authenticated personal REST requests are generally limited to 5,000/hour, with secondary limits and different app limits; a 30–50-repo pilot should maintain headroom and degrade to explicitly incomplete coverage rather than violate limits.

Source: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api

## 7. Downstream software and advisory captures

The GitHub collector is only one instrument. A security supply-chain paper also needs timestamped evidence for:

- Published package/version: registry metadata, immutable tarball/artifact digest and observed publication time; differentiate upload and later edits.
- Reproducible fix-state test: exact source commit, build flags, dependencies/toolchain digest, CI/PoC test result, and whether binary actually contains the fix.
- Advisory: CISA/ICSMA/ICSA advisory revisions, GHSA/OSV/NVD records and vendor PSIRTs, each with first-observed interval and source-stated publication date.
- Downstream adoption: exact source/binary/firmware diff or vendor attestation. A dependency declaration bump is insufficient proof for compiled products.

Capture these with separate versioned clients and the same CAS+manifest+OTS protocol. For already published advisories, capture changed pages and published text as observed; avoid unapproved private PSIRT portals or coordinated undisclosed information.
