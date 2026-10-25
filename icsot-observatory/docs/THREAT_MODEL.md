# Threat model, claim boundaries, and investigator responsibilities

## Adversaries / failure classes

| Risk | Mitigation | Residual uncertainty |
|---|---|---|
| Commit date backdating / force push | Observe remote refs frequently; preserve archived refs + Git object graph | Unobserved transient refs remain invisible |
| Issue, PR or comment edits/deletions | Repeated raw snapshots and content version hashes | Changes between polls may be irrecoverable |
| GitHub API pagination churn | Preserve every page, link cursor and first-page recheck; retry partials | No GitHub REST atomic snapshot facility |
| GitHub API time/metadata error | Store raw responses + local UTC request intervals, independent cross-checks | API bytes are not signed by GitHub as archival evidence |
| Tampering with local evidence | SHA-256 CAS, immutable final manifests, linked hashes and OTS | An attacker may withhold data or falsify inputs before signing |
| Dishonest collector | Published open-source reproducible code, independent collection host, public digest witness | OTS alone cannot prove collector was honest |
| Compromised or unsynchronized system clock | NTP/chrony offsets and third-party TSA | UTC capture intervals may still have uncertainty |
| Storage failure/ransomware | Offsite WORM/Object Lock, independent backup credentials, restore drills | Cloud admins/keyholders and service outages remain risks |
| Wrong/renamed/private repository | Stable numeric repo ID, explicit public checks and audited rename decisions | Public/private toggles and provider inconsistencies persist |
| API credentials expose private records | Minimal public-read-only token; redacted allowlisted headers; anonymous sampling checks | A privileged token could still expose data if misconfigured |
| Archival privacy or disclosure harm | Minimize exported fields, raw archive access policy, consent/legal/IRB review | Public accessibility does not settle republication rights |
| Prior work / selection bias | Protocol registration, controls, unbiased cohort, negative results | No method eliminates confounding entirely |

## Strongest supportable statements

- "Collector X received bytes with SHA-256 H from URL U during a logged interval [t0,t1]."
- "The stored raw bytes hash to H and the run manifest includes H."
- "Bitcoin anchor B verifies that manifest bytes existed by B's blockchain timestamp bound." This establishes a coarse external upper bound, not that GitHub served them at the claimed local t0.
- "The Git ref HEAD of branch `main` was observed pointing to SHA S during this specific ls-remote interval."
- "No matching issue was returned in successful enumeration of endpoint E with scope Q at observation time T" (not "the issue did not exist anywhere").

## Unsupported without additional evidence

- "This was the moment GitHub first made the fix public."
- "OpenTimestamps proves the issue existed on GitHub at the manifest's local datetime."
- "A first-appearing Git commit was authored or exposed that day."
- "A patch tagged by the vendor was deployed or protected downstream operators."
- "The complete history of every deleted issue/comment is known."
- "A later lack of evidence proves an earlier absence or privacy state."

## Key custody and audit

Never embed token keys in logs/config, never publish raw GitHub response bodies without review, and keep OTS initial and upgraded receipts. Sign daily manifest digest lists with a separately held signing key (minisign or equivalent) if identifying the collector is important; key-signing proves possession of that key, not correctness of collected contents. Publish digests to a witness outside the storage provider/admin domain so deletion/backdating of an entirely private hash chain is harder to hide.
