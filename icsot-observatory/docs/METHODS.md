# Proposed empirical research methods (pre-registration template)

## 1. Study questions

RQ1. How often do GitHub retrospective timestamps/records yield materially different estimates of first public security-fix visibility from prospective observation?

RQ2. Conditional on first observed public fix, how long until a numbered fixed release, advisory and representative downstream consumer updates are first observed?

RQ3. What kinds of earlier repository states (force-pushed PR heads, edits, deleted comments, withdrawn releases) would be irrecoverable from a later GitHub-only reconstruction, and do such losses affect operational conclusions?

This protocol **does not presuppose** that retrospective methods systematically underestimate or overestimate delay. Test direction, effect magnitude and null results.

## 2. Define the measured construct before observing results

Unit: `(repository_id, candidate vulnerability/fix, observed public surface, collection window)`.

**Timeline clocks (different variables, never collapse without qualification):**

- `t_author`: Git author timestamp, source asserted, mutable.
- `t_committer`: Git committer timestamp, source asserted, mutable.
- `t_platform_created`: platform API created timestamp, source asserted.
- `t_platform_updated`: platform API last-updated timestamp, source asserted; need not be an edit audit trail.
- `t_seen`: first **successful capture** of exact evidence on a named endpoint; interval `[request_started_at, request_completed_at]` with collector clock uncertainty.
- `t_last_absent`: last valid complete observation not containing a specified object within a specified query scope; cannot in general prove universal non-availability.
- `t_block`: independent OTS Bitcoin anchoring block upper bound on existence of the timestamped manifest.
- `t_release_api`: first observed release metadata and downloadable artifact; distinguish Git tag and release page creation, assets, and whether payload is actually fixed.
- `t_advisory`: publication date claimed by CISA/GHSA/vendor, separately from the first observation of the published page.

**Temporal reasoning:** if an item is observed in request interval `[a,b]`, it was returned during that request and was present as represented no later than `b` under the assumed honest collector+HTTPS model. If a complete valid previous request at interval `[c,d]` did not return the item, narrow the endpoint-specific appearance to `(c,b]` only under explicit no-pagination-lag/no-scope-change assumptions. If those assumptions fail, record only first observation. If the item existed at baseline, treat first-publication time as **left censored**. If no release appears by study end, treat release time as **right censored**. Edit times are **interval censored** between content versions. Report clock uncertainty alongside collector UTC readings and do not elevate unsigned source timestamps to cryptographic fact.

## 3. Sampling and cohort

- Publish a prospective inclusion algorithm before collection. Stratify by language, governance (foundation/vendor/community), industrial protocol/ecosystem, contributor activity, release cadence, and repository age.
- Prespecified primary cohort: 30–50 repositories in a 90-day pilot; expand to 100–300 only after coverage/cost evaluation. Preserve a separate set of downstream GitHub consumers and non-GitHub vendor firmware sources.
- Do not select solely on vulnerabilities discovered by the investigator; if own discoveries are included, mark them as an **investigator-involved stratum** and analyze separately. Require a control cohort not chosen for already-known disclosures.
- Identify and preserve `repository.id` (stable numeric ID), recorded owner/name, fork/archival status, transfers and eligibility dates. Define rules for repo removals, new projects and non-GitHub migrations before seeing results.
- Record complete denominator: all eligible repositories and all candidate security fixes (including ambiguous cases, unmerged PRs, unassigned CVEs, and releases that prove not to be fixed).

## 4. How a candidate vulnerability fix is determined

Use a two-step coding process independent of timestamp outcome:

1. Candidate identification from CISA/GHSA/CVE/OSV/vendor disclosures, release notes, code-level security changes and project discussions, using preregistered filters. Do **not** use an LLM security label alone as ground truth.
2. Fix validation using patch review and, where safe/ethical, the behavior of vulnerable vs fixed versions (unit tests, targeted PoCs, bounded differential testing). Categorize as `verified_fix`, `claimed_fix_unverified`, `partial_fix`, `regression`, `not_a_fix`, or `ambiguous`.

Two independent coders annotate `vulnerability_id`, `fix_commit_set`, `earliest_observed_public_surface`, `merge/release/advisory` events, downstream relation and whether build conditions enable the vulnerable path. Disagreements are adjudicated against evidence and logged. Publish inter-rater agreement (and raw confusion where possible).

## 5. Main outcomes

- `D_retrospective`: dates inferred using Git timestamps, presently accessible GitHub issue/PR metadata and surviving refs only, analyzed later with a documented reconstruction algorithm.
- `D_prospective`: dates/intervals from timestamped observation evidence.
- Primary discrepancy: how often `D_retrospective` falls outside a defensible prospective observation bound, plus the magnitude/range of disagreement. When bounds overlap, **do not** claim contradiction.
- Release lag: prospective first-observed public fix to first **validated fixed release**; treat unresolved release dates as censored.
- Downstream adoption: source or binary version with fix demonstrably present; GitHub dependency bump or vendor disclosure alone is not proof of remediation.
- Misclassification rate: how often a retrospectively inferred `patched` conclusion disagrees with a verified code, build, or binary behavior outcome.

Report medians and uncertainty with repo-clustered bootstrap intervals; for lags with censoring, use an interval-/right-censoring-aware method, rather than dropping unresolved cases. Stratified analyses account for repo activity and collection completeness. Multiple endpoints for one vulnerability are nested, not independent observations.

## 6. Sensitivity analyses

- Observation cadence (15 min, 1h, 6h, daily) and missed-run simulation.
- Lower-quality histories excluded vs included.
- Different definitions of fix availability: PR, branch commit, default-branch merge, tagged release, installed artifact.
- Author time vs committer time vs created_at vs first-observed interval.
- Projects with high vs low event volume, forks, migrations and changed visibility.
- Investigator-involved vs independently selected projects.
- Survival, bootstrap and control comparisons clustered by repository and vulnerability family.
- Independently witnessed GitHub state (Software Heritage visits, GH Archive, separate collectors) vs self-collected evidence; quantify archive blind spots instead of treating them as complete.

## 7. Data quality metrics and acceptance criteria

Define and report **by repository/day/scope**, not only as a fleet average:

- Scheduled runs, attempted runs, completed-scope runs, partial runs, skipped runs, and delayed runs.
- Actual observation interval width; p50/p95 gap between successful observations; clock synchronization error distributions.
- API primary/secondary limit encounters, retried calls, HTTP 304 cache matches, 403/404/410 rates and pagination drift.
- Git ref set consistency before/after fetch; orphan/unfetched objects, successful backup restoration and `git fsck` errors.
- SHA-256 verification for every manifest/CAS object; OTS submission, upgraded, and independently verified counts.
- Coverage of PR timelines, review/comments and release artifact downloads; explicit GitHub endpoint caps and unavailable history.
- Cross-source corroboration rates; discrepancies and documented follow-up decisions.

Hard exclusion from point-timestamp comparisons when relevant endpoints were incomplete, non-atomic or clocks unbounded. Preserve excluded cases and reasons, then give sensitivity analyses. **Do not define a universal '99% complete' quota as proof of historical completeness**: an observed success ratio is a collection-operation metric, not coverage of short-lived events.

## 8. Reproducibility and ethics

- Register design, frozen cohort, hypothesized endpoints, observation cadence and coding rules before measuring outcome differences (OSF or equivalent). Keep a signed amendment log.
- Release scripts, container lockfile digests, source commit, config minus credentials, sanitized manifests and a documented data dictionary. Freeze each analysis release with a digest/DOI and rerunnable pipeline.
- Raw JSON can contain developer emails, names, deleted sensitive content and security PoCs. Evaluate GitHub terms, licenses, privacy norms, ethical review/IRB applicability and coordinated disclosure before redistributing. Default to restricted original-data retention plus responsibly redacted public derivative datasets.
- For public patches revealing actively exploitable bugs before advisories, avoid announcing vulnerability-specific details or mass-notifying operators automatically; use proportionate coordinated handling.

## 9. Pre-registration decision rules

Proceed to larger measurement if the pilot yields (a) demonstrable cases of currently irrecoverable states or material timeline disagreements *and* (b) sufficient independent verification to exclude collector error. If disagreements are rare, treat the collector as infrastructure and publish negative results or a replication dataset, not exaggerated novelty. State all inclusion changes and unpublished negative findings.
