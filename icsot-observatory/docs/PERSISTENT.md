# Durable split-lane collection

`icsot-observe persistent` (alias `run`) runs the implemented durable collector against a trusted working root. API and Git queues have independent worker pools and intervals. A Git fetch can finish while API work waits for its quota reset. The first Git archive is a complete baseline; later captures contain only newly reachable objects or a refs-only descriptor. This command does not dispatch or alter the one-time baseline Actions workflow.

Execution can live on a persistent host or use the implemented GitHub-backed adapter, which restores and saves the same working root. A fresh hosted runner without restored state starts a baseline. Neither command enables a recurring schedule.

## Commands

Set an absolute `collector.root` in a machine-local copy of the cohort configuration. Keep credentials in the process environment; no key values belong in TOML or Git. `COLLECTOR_READ_TOKEN` takes precedence over the default `GITHUB_TOKEN` API variable when present. `--read-token-env NAME` selects another configured variable. Git fetches use anonymous public HTTPS and disable credential helpers.

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

The `Persistent selected repository (manual)` workflow invokes `icsot-observe github-run` for one cohort member, defaulting to `libfuse/libfuse`. It has no cron and no all-cohort matrix. Hosted smoke validation is still required before claiming a deployed recurring collector.

The adapter resolves the public numeric ID and checks the authoritative create-once slug-to-ID binding on `collector-state`. Reusing a name for another repository fails before choosing its working root; rename/transfer amendments require separate review. It restores authenticated state into `/tmp/icsot-persistent-state/<id>`, joins both capture/finalizer pools, uploads new encrypted evidence parts and indexes, then publishes an encrypted working-state generation. The final branch pointer and first slug binding commit atomically with compare-and-swap semantics only after dependency verification. State publication preserves other repositories' pointers and does not use a force push. Evidence releases are sharded by selected repository and publication generation; earlier assets remain prerequisites. Restored authenticated catalogs let new exports omit old CAS bytes without downloading old evidence ciphertext.

The RSA recipients have separate purposes:

- `keys/results-rsa-public.pem` encrypts retained evidence transfers. Its existing private key stays on the owner's machine.
- `keys/working-state-rsa-public.pem` encrypts the resumable operational snapshot. The separately generated `COLLECTOR_STATE_PRIVATE_KEY` Actions secret is materialized as a protected temporary runner file and removed afterward. This authorized key lets the runner recover the working API/Git corpus. It cannot decrypt the retained evidence envelopes addressed to the other recipient.

`COLLECTOR_READ_TOKEN` supplies public API reads; workflow `GH_TOKEN=github.token` performs destination Release/state-branch writes. The state key is outside the captured root and never enters a snapshot. Restoring into an already populated working root fails closed. A manual invocation uses a fresh observation key so two deliberate smoke runs exercise a baseline followed by an incremental or refs-only capture; unfinished captures still resume their original checkpoints.

Working-state ciphertext is additional physical storage, accounted separately from retained evidence upload bytes in the JSON report. State parts use XZ by default while already compressed Git packs/bundles remain raw; unchanged parts reuse their original ciphertext. Reports include referenced/uploaded state bytes, release count and restore/publication disk estimates. Public indexes, proof files, encryption envelopes and branch metadata add retained overhead; the evidence upload counter includes its public indexes, while the Git branch's own storage overhead is separate. No 50-GB monthly admission cap is implemented. This workflow is a selected-repository pilot and must not be described as a budget-enforced recurring cohort deployment.

## UTC intervals and timestamp evidence

Every new public export index records `observation_started_at`, `observation_finished_at` and `clock_source=runner_system_clock`, copied from its immutable manifest. Per-lane state provenance carries the same original interval. The public state pointer and authenticated state index separately record `snapshot_started_at` and `snapshot_sealed_at`. Finalizer retries preserve capture times; upload time never substitutes for observation time. Microsecond UTC representation provides serialization precision, without establishing microsecond clock accuracy or an atomic repository snapshot.

The manual GitHub path publishes timestamp receipts beside the public index and retains copies inside encrypted evidence. `timestamp_evidence` records the manifest digest, local observation/request/receipt intervals, immutable asset hashes and verification status. OpenTimestamps preserves its original `.ots` plus canonical `.attestation.json` metadata. The actual first `ots stamp` call's UTC interval is recorded once; historical request times remain null when unknown. A pending calendar receipt is not a verified Bitcoin timestamp. Later Bitcoin verification needs an independently validated Bitcoin source; original receipts remain immutable and upgraded receipts need new linked metadata.

Each completed evidence-generation release uploads immutable `metadata-catalog.json` last. It lists the final public index and proof-sidecar references, creating a discovery barrier for a separate proof-refresh worker without decrypting or recapturing repositories. Releases missing the marker are incomplete and must remain retry candidates. The marker is also retained in the authenticated working-state dependency catalog. Shared trust sidecars are uploaded once per generation and referenced by both lanes.

Optional RFC 3161 configuration uses `--rfc3161-url`, `--rfc3161-ca` and `--rfc3161-chain`. The manual pilot configures DigiCert's endpoint with the tracked explicit trust root/intermediate. Only the manifest SHA-256 digest and protocol request are sent. The collector retains the request, signed response, signed TSTInfo text, trust certificates and canonical metadata, verifies the nonce/query, subject imprint and configured certificate chain, then publishes those sidecars with the index. A signed TSA generation time is separate from the runner's observation clock. Certificate revocation is not checked. A timestamp failure leaves finalization retryable; an already accepted receipt is reverified and reused without another request. Live TSA success must be reported separately from offline tests.

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

Before unattended use, the 50-GB monthly admission cap, storage headroom policy, remote persistence/backup, clock measurements and proof upgrades still need operational enforcement. A six-hour interval is an initial configuration, not a verified cohort-wide performance guarantee.
