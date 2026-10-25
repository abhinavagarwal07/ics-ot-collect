# Recommended implementation plan and non-negotiable exit gates

This timeline is a **development sequence**, not a promise of when software will be finished. Avoid deploying a large cohort while essential invariants are still missing.

| Stage | Engineering deliverables | Gate for advancement |
|---|---|---|
| 0. Freeze instrument | Repo registry with stable numeric IDs, declared cohort/controls, timestamps definitions, inclusion amendments, immutable study protocol | A second researcher can explain the construct and denominator from protocol alone |
| 1. Hard acquisition | Raw CAS, Git pinning, all principal endpoints, per-response UTC intervals, fixed version headers, secure public-only auth | Fault-injection tests show zero silent missing/partial successes and no credential leaks |
| 2. Scheduling | Durable queue, separate scope watermarks, adaptive event/metadata cadence, API cap/rate treatment, restart/resume after interruption | Repeated outage/backfill tests produce correct gaps and no overwritten historical evidence |
| 3. Provenance | Manifest hashes and chain, portable Git bundle/delta pack archival, OTS, optional RFC3161, immutable off-host replication | Offline audit reconstructs exact source bytes/code from an independently restored archive |
| 4. Verification | Two independent collector instances for sampled intervals; SWH / GH Archive checks; lineage and temporal inference tests | Disagreements reproducible and documented; first-seen vs source timestamps kept separate |
| 5. Security-specific enrichments | Official advisory snapshots, published release assets, package/firmware builds, patch classification, source/binary proof of fix | Two coders can reproduce each selected vulnerability event from evidence with bounded ambiguity |
| 6. Pilot freeze | 90-day 30–50 repo primary cohort; fixed analysis plan; corpus coverage dashboard; preregistered control analyses | No unsupported exact-date claims, full denominator and censoring metrics, replication artifact ready |
| 7. Expand | 6–12 month 100–300 repo cohort with matched downstream consumers and domain subgroups | Meaningful outcomes beyond an archiving tool: reproducibility errors, time lags or downstream exposure evidence |

## Minimum scientific proof exercise

Pick a test PR and create a controlled public timeline (in your own test repo) with a branch commit, PR creation, body edit, review comment edit, force push, PR merge, release tag and a later published GitHub Release. Poll deliberately at different intervals and show:

1. The Git SHA/author date is not automatically the first-public time.
2. Archived ref pointers and objects preserve an overwritten branch state only if the previous state was fetched while reachable.
3. PR body edits are identified from separate captured content versions; an edit and its complete history are *not* guaranteed observable.
4. The GitHub API's own created/updated fields and independently collected observation intervals remain separately typed data.
5. A final OTS receipt verifies the frozen manifest's SHA-256. Another machine can verify the manifest+raw data+Git objects with no GitHub connectivity.
6. Simulated outages produce honest intervals/gaps, not invented negative evidence.

## Success versus publication novelty

The pipeline itself is reproducible measurement infrastructure, not a research finding. The actual novel claims to test are **how often and how consequentially reconstructing history later differs from observing it prospectively**, and whether discrepancies change downstream ICS/OT remediation judgments. Preregister zero-effect/null outcomes as legitimate. Avoid optimizing cohort selection for already-known incidents.
