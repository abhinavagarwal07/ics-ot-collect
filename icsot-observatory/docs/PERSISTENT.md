# Durable split-lane collection

`icsot-observe persistent` (alias `run`) runs the implemented durable collector against a trusted working root. API and Git queues have independent worker pools and intervals. A Git fetch can finish while API work waits for its quota reset. The first Git archive is a complete baseline; later captures contain only newly reachable objects or a refs-only descriptor. This command does not dispatch or alter the one-time baseline Actions workflow.

Execution can live on a persistent host or use the GitHub-backed adapter, which restores and saves the same selected repository's working root. The separate `Corpus incremental (six hourly)` workflow configures the recurring hosted path; invoking the standalone command does not install a schedule.

## Commands

Set an absolute `collector.root` in a machine-local copy of the cohort configuration. Keep credentials in the process environment; no key values belong in TOML or Git. `COLLECTOR_READ_TOKEN` takes precedence over the default `GITHUB_TOKEN` API variable when present. `--read-token-env NAME` selects another configured variable. Git fetches use anonymous public HTTPS and disable credential helpers.

An optional `COLLECTOR_READ_TOKEN_SECONDARY` partitions source REST jobs deterministically by repository, with one credential pinned through identity, scopes, pages and retries. Each credential has separate primary-rate observations; throttling never switches credentials. Missing or duplicate secondary credentials preserve the single-token path, custom token variables remain single-token, and destination `GH_TOKEN` publication and worker concurrency are unchanged. See [source credential behavior](SOURCE_TOKENS.md).

```sh
# One bounded drain of currently ready work. Deferred jobs remain for next time.
icsot-observe persistent --config /srv/icsot/config.toml --once

# Continuous controller: one API worker, two Git workers, independent intervals.
icsot-observe persistent --config /srv/icsot/config.toml \
  --api-workers 1 --git-workers 2 \
  --api-interval-seconds 21600 --git-interval-seconds 21600 \
  --export-directory /srv/icsot/encrypted-transfers \
  --public-key /srv/icsot/results-rsa-public.pem
```

Each repository/lane has at most one unfinished capture. Restarting in the same interval does not enqueue another copy; missed intervals are recorded through actual observation gaps rather than replayed as a catch-up cohort. A changed configuration creates new immutable job inputs. Already queued jobs retain their original public configuration and scope boundaries.

`--deep-full` enables resumable historical item scopes and can be expensive. The default initial API listing remains shallow. A missing parent cursor in a later delta is a shallow full repair; it does not implicitly enumerate every historical item's deep endpoints. Failed requested child scopes withhold their selecting issue/PR cursors so those items remain eligible for repair. Public Discussions and their replies remain outside the implemented REST collector. `--no-stamp` is for tests and produces no third-party timestamp evidence.

## Manual GitHub-backed execution

The `Persistent selected repository (manual)` workflow invokes `icsot-observe github-run` for one cohort member, defaulting to `libfuse/libfuse`. The cohort workflow uses the same state adapter and operational key, with additional immutable planning and explicit bootstrap checks.

### Six-hour cohort workflow

`.github/workflows/corpus-incremental.yml` uses the same planning and capture path for cron (`17 */6 * * *`, UTC) and manual dispatch. Once this workflow is on the default branch, GitHub schedules it on a best-effort basis. Each public metadata plan freezes all 185 CSV entries, public numeric identities, source/configuration/CSV hashes, the six-hour UTC slot and selected authoritative state-pointer digests. Capture checks the plan hash and code checkout, then rechecks the authoritative selected pointer before restoring any working files. A newer pointer pauses that stale plan rather than replacing newer state.

Every repository with an authenticated working-state pointer and an enabled profile is eligible each cycle. Missing-state entries can be explicitly selected for a `fresh_public_bootstrap`; `cold_bootstraps` defaults to **0** and can be set from 0 through 8 at manual dispatch. Only an explicit manual request starts fresh cold attempts; those attempts rotate by slot. Retained baseline-state initialization is manual-only and considers every eligible missing state with up to eight concurrent jobs. Unchanged prepared-state or fresh-publication recovery holds are reported separately and require scoped recovery; they are not retried as normal initialization. Other missing-state entries remain `bootstrap_pending`. Fresh bootstraps fetch new public observations: they do not decrypt the owner's historical evidence archives, inherit their cursors or claim their observation times. Both manifests and outcomes identify fresh bootstrap versus resumed authenticated state. The one-time baseline workflow is separate and is not dispatched by recurrence.

The plan also freezes GitHub's raw reported repository size, threshold, effective history profile and selection reason. Automatic `LARGE_REPO` classification uses only **reported size >5,000,000 GitHub KB units**, with no conversion into a claimed measured clone size. It can be set explicitly under `[history]` as `large_repo_threshold_kb`. A `[history.overrides]` table can map a declared slug to `full_history` or `recent_history_shallow_v1`. The proposed recent profile covers 730 days. Until its Git/API implementations are validated, those entries are `large_profile_pending` and are excluded from capture; other ready/small entries continue. A proposed cold-bootstrap cutoff is recorded but is not an observed-history claim. Existing retained history is not removed or silently downscoped. Timeout observations are review signals and do not change classification automatically.

The selected jobs share eight matrix slots and one workflow concurrency group with the manual pilot. The same numeric-repository lock serializes publishers. Inside each selected job, API and Git retain separate durable lanes and retry deadlines. Outstanding jobs resume before new slot work is enqueued. A stable `six-hour-slot-<n>` observation key prevents completed same-slot lanes from being recaptured by manual/cron retries; missed ticks do not create a catch-up queue.

Execution priority uses `slot_seeded_sha256_rank_v1`, a deterministic rank derived from the cohort identity, six-hour slot and numeric repository ID, to break the fixed CSV prefix in the matrix. Canonical cohort order, eligibility and same-slot idempotency remain unchanged; plans and outcomes record the policy, seed and order digest. This temporary shuffle does not select oldest-due work or perform quota admission. Scheduling, actual job start order and observation cadence remain best effort.

Eight slots share the configured source-read account allowances and the destination repository token's shared quota. With a distinct second account configured, repository jobs partition across its independent primary allowance; same-account tokens do not create independent allowances. Source API rate refusal defers work without a one-hour sleep or a credential switch, preserving successful checkpoints and API incompleteness while Git can finish. New recurring jobs preserve a 40-request source reserve. The cohort and initializer keep the same concurrency group with `queue: max`, preserving the eight-worker ceiling and avoiding the default single-pending replacement. Schedules can still be delayed or dropped, and queue capacity is finite; six hours is a nominal trigger interval, not measured completion of all 185 repositories. A full 185-job sweep would require average slot occupancy below roughly 15.6 minutes to fit six hours before overhead.

Capture defaults are a 180-minute timeout, an 8-GiB selected-state plaintext restore limit and separate 2-GiB limits for new evidence and operational-state uploads. These are hosted per-job guards, separate from the owner's shared 2-GB local inspection ledger. `[recurrence.limits]` can override defaults; `[recurrence.overrides."owner/repo"]` can override them for one declared repository. The positive integer keys are `job_timeout_minutes` (at most 360), `max_restored_state_plaintext_bytes`, `max_new_evidence_ciphertext_bytes` and `max_new_state_ciphertext_bytes`. The immutable plan and outcome report the selected limits. Oversized or quota-deferred work has an explicit partial/paused outcome; previously published state remains authoritative. Immutable metadata plans and per-job outcome JSON are published separately from encrypted evidence. The 50-GB UTC-month retained-evidence policy remains in force; runtime monthly admission is not implemented and does not gate this authorized launch. Operational-state ciphertext is reported separately.

The adapter resolves the public numeric ID and checks the authoritative create-once slug-to-ID binding on `collector-state`. Reusing a name for another repository fails before choosing its working root; rename/transfer amendments require separate review. It restores authenticated state into `/tmp/icsot-persistent-state/<id>`, joins both capture/finalizer pools, uploads new encrypted evidence parts and indexes, then publishes an encrypted working-state generation. The final branch pointer and first slug binding commit atomically with compare-and-swap semantics only after dependency verification. State publication preserves other repositories' pointers and does not use a force push. Evidence releases are sharded by selected repository and publication generation; earlier assets remain prerequisites. Restored authenticated catalogs let new exports omit old CAS bytes without downloading old evidence ciphertext.

The RSA recipients have separate purposes:

- `keys/results-rsa-public.pem` encrypts retained evidence transfers. Its existing private key stays on the owner's machine.
- `keys/working-state-rsa-public.pem` encrypts the resumable operational snapshot. The separately generated `COLLECTOR_STATE_PRIVATE_KEY` Actions secret is materialized as a protected temporary runner file and removed afterward. This authorized key recovers the working API/Git corpus and decrypts baseline archives covered by operational key capsules. A capsule rewraps the original archive AES key without changing its ciphertext. Envelopes without such a capsule remain addressed only to their declared recipient; the owner's evidence private key stays local.

`COLLECTOR_READ_TOKEN` supplies public API reads; workflow `GH_TOKEN=github.token` performs destination Release/state-branch writes. The state key is outside the captured root and never enters a snapshot. Restoring into an already populated working root fails closed. A manual invocation uses a fresh observation key so two deliberate smoke runs exercise a baseline followed by an incremental or refs-only capture; unfinished captures still resume their original checkpoints.

Working-state ciphertext is additional physical storage, accounted separately from retained evidence upload bytes in the JSON report. State parts use XZ by default while already compressed Git packs/bundles remain raw; unchanged parts reuse their original ciphertext. Reports include referenced/uploaded state bytes, release count and restore/publication disk estimates. Public indexes, proofs, encryption envelopes and branch metadata add retained overhead. The initial 185-repository baseline has a one-time 100-GB allowance, including retained attempts/partials/retries and metadata; recurring collection has a separate 50-GB UTC-month policy. Runtime admission for either is not implemented.

## UTC intervals and timestamp evidence

Every new public export index records `observation_started_at`, `observation_finished_at` and `clock_source=runner_system_clock`, copied from its immutable manifest. Per-lane state provenance carries the same original interval. The public state pointer and authenticated state index separately record `snapshot_started_at` and `snapshot_sealed_at`. Finalizer retries preserve capture times; upload time never substitutes for observation time. Microsecond UTC representation provides serialization precision, without establishing microsecond clock accuracy or an atomic repository snapshot.

The manual GitHub path publishes timestamp receipts beside the public index and retains copies inside encrypted evidence. `timestamp_evidence` records the manifest digest, local observation/request/receipt intervals, immutable asset hashes and verification status. OpenTimestamps preserves its original `.ots` plus canonical `.attestation.json` metadata. The actual first `ots stamp` call's UTC interval is recorded once; historical request times remain null when unknown. A pending calendar receipt is not a verified Bitcoin timestamp. Later Bitcoin verification needs an independently validated Bitcoin source; original receipts remain immutable and upgraded receipts need new linked metadata.

Each completed evidence-generation release uploads immutable `metadata-catalog.json` last. The collector verifies the remote marker hash/size and public index/proof bindings before atomically committing a registration-outbox node with its encrypted working-state pointer. Registration remains pending until daily proof maintenance records it idempotently through compare-and-swap on `collector-attestations`; deferral preserves the durable outbox handoff. The marker lists final public index/proof references and remains a bounded discovery fallback. Releases missing it remain incomplete retry candidates. Shared trust sidecars are uploaded once per generation and referenced by both lanes.

Capture validates the public marker, indexes and proof bindings before publication. Its state-pointer transaction also commits an immutable public registration-outbox node; the encrypted state index binds that outbox reference. A full daily proof-attempt queue therefore does not block capture or erase its registration handoff. New outcomes report pending registration rather than completed proof verification.

The separate `Refresh delayed public timestamp proofs` workflow is scheduled once per 24 hours at 04:43 UTC and supports manual dispatch. It consumes public indexes/receipts, queries calendars and appends immutable upgraded proofs plus linked metadata; it does not decrypt working state, use the evidence private key, or recapture repositories. It walks frozen per-repository outbox chains and commits registration plus traversal progress atomically on `collector-attestations`; failed or capacity-limited registrations retain their cursor. Bounded release discovery also remains for older or orphaned completion markers. Each run permits up to 12 outbox inspections, 12 legacy marker registrations and 128 proof attempts within its runtime and quota bounds. Backlog counts and age observations are explicitly qualified when inspection is incomplete; this is not a claim that all proofs complete within 24 hours. Without a configured trusted Bitcoin Core node, a received Bitcoin attestation remains explicitly unverified. See [timestamp verification and maintenance](TIMESTAMPING.md).

The manual [legacy recovery pilot](LEGACY_RECOVERY.md) freezes one selected source and its old recovery hold, authenticates reusable encrypted parts, and publishes a new linked working-state generation. It preserves original observation times and does not recapture accepted main evidence.

RFC 3161 configuration uses `--rfc3161-url`, `--rfc3161-ca` and `--rfc3161-chain` for DigiCert; `--freetsa` adds FreeTSA with its separately pinned root. The selected persistent, recurring, and baseline-state initialization workflows configure both alongside OpenTimestamps. Only each finalized manifest's SHA-256 digest and protocol request are sent. Each provider's request, signed response, signed TSTInfo text, trust certificates and canonical metadata are retained as distinct sidecars linked from the public index and catalog; the viewer displays their statuses separately. Verification checks the nonce/query, subject imprint and configured certificate chain. A TSA's signed generation time is separate from the runner's observation clock, and revocation is not checked.

FreeTSA retries bounded transient failures with jitter and honors Retry-After within its request budget. An exhausted or failed attempt is recorded as `failed`, with no scheduled retry; it does not by itself block export. Existing OTS and DigiCert failures can still defer finalization before FreeTSA is attempted. Accepted RFC receipts are reverified and reused on finalization replay. This adds no historical backfill, and the older one-time corpus baseline and smoke workflows retain their existing timestamp behavior. See [timestamp evidence](TIMESTAMPING.md) for provider limits and audit steps.

Manual [working-state compaction](STATE_COMPACTION.md) targets one reviewed existing pointer, reconstructs the entire candidate state from remote assets before publication, and never creates source observations or deletes prior assets. It shares the collection queue and is not scheduled.

## Crash and evidence semantics

- `runtime.sqlite3` stores leases, attempts, delayed retries, captured results and successful scope watermarks. Handlers run outside database transactions. A captured result is committed before finalization starts, so a timestamp/export/finalization failure retries the finalizer without recapturing.
- API checkpoint ledgers preserve raw response hashes, original request intervals, page progress, failure attempts and completed scopes. A transient rate refusal delays the same capture and freezes its query options. It does not advance a watermark. Bounded endpoint failures finalize a partial manifest; only independently completed scopes advance. A later capture queries a failed scope from its previous successful boundary.
- Capture IDs identify work and Git pin namespaces. Final run IDs are allocated only while holding the short per-repository append lock. Reverse lane completion therefore produces one ordered manifest chain. Clock rollback clamps this filename namespace and records a flag; original observation and allocation times remain unchanged.
- A controller holds the whole-root `.collector.lock`, shared with legacy `collect`, throughout execution. Network capture and timestamp requests do not hold the manifest append lock or a SQLite transaction. Worker counts limit this process; they do not multiply the token's shared quota.
- Git finalization independently restores the complete declared archive closure into an empty repository, runs object checks and compares the captured mirror namespace before accepting/exporting it. This verification can dominate large-repository runtime even when the new transfer contains few objects.

`--once` returns nonzero for outstanding/deferred jobs or newly finalized partial captures. JSON telemetry reports job IDs, lanes, timing, attempts, retry boundaries and failures; response bodies and authorization headers are not logged.

## Encrypted incremental transfers

The paired `--export-directory` and `--public-key` options create encrypted per-capture tar/XZ packages plus public integrity indexes. XZ streams into plaintext parts of at most 1 GiB, each independently encrypted using the existing AES-256-GCM/RSA-OAEP-SHA256 envelope and only the evidence RSA public key. At most one plaintext transfer part stages at a time; the trusted working root retains original evidence. The owner's retained-evidence private key is never needed on a collection runner; GitHub-backed state recovery uses its separate operational key described above.

New exports omit CAS objects already present in earlier packages in the same export directory. Each index lists its members, encrypted hash/size, manifest digest and required earlier CAS hashes. Git descriptors retain explicit parent descriptors and bundle prerequisites. An incremental package requires those earlier packages; it is not labeled as a portable full bundle. Preserve every package and index indefinitely. A first export also includes earlier unexported manifest links and their referenced evidence.

`persistent` creates local transfer artifacts. `github-run` uploads each encrypted `.tar.xz.part-*.enc` and then its `.index.json`, verifies dependencies, and publishes authenticated encrypted working state. An external uploader can use the same indexes for another backend. The plaintext working root is never a public upload candidate. Monthly-cap admission and independent backup verification remain open. The baseline helper retains its separate split-part implementation.

To restore, verify every encrypted asset against its index, decrypt using the owner's local RSA private key, concatenate each package's plaintext parts in listed order, and extract every dependency package into the same destination. Then run:

```sh
icsot-observe restore --root /path/to/restored/evidence
icsot-observe verify --root /path/to/restored/evidence
```

Restoration uses only retained CAS bundles/descriptors and reconstructs all declared Git pins without contacting upstream. Pending `.ots` receipts still require later `ots upgrade` and `ots verify`; they are not verified Bitcoin timestamps.

## Persistent-host deployment template

This optional systemd example requires an actual host, sufficient disk, a protected environment file, an installed collector and an absolute-root configuration. It is a template, not a deployed service. GitHub-backed execution can use the same `--once` command after restoring its authenticated working state.

```ini
[Unit]
Description=Public GitHub evidence collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=icsot
WorkingDirectory=/srv/icsot/collector/icsot-observatory
EnvironmentFile=/etc/icsot/collector.env
UMask=0077
ExecStart=/srv/icsot/venv/bin/icsot-observe persistent --config /srv/icsot/config.toml --export-directory /srv/icsot/encrypted-transfers --public-key /srv/icsot/results-rsa-public.pem
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

The environment file contains only the selected API read credential. Keep upload credentials separate if an external uploader is configured. The baseline and smoke Actions workflows select `${{ secrets.COLLECTOR_READ_TOKEN || github.token }}` for future API reads; release writes keep their separate workflow `GH_TOKEN`. An already running workflow keeps its original checkout and environment.

Monthly-cap admission, independent backups, clock measurements and completed proof upgrades remain separate operational work. A six-hour interval is an initial configuration, not a verified cohort-wide performance guarantee.
