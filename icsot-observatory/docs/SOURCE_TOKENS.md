# Public source API credentials

`COLLECTOR_READ_TOKEN_SECONDARY` is an optional second source-read secret. The
existing primary remains `COLLECTOR_READ_TOKEN`, supplied directly or through
the configured `GITHUB_TOKEN` source variable. Use credentials restricted to
public repository reads. Token values stay in the environment and are never
written into configuration, observation records, plans or outcomes.

With two distinct, nonempty credentials, source REST jobs choose slot
`int(SHA256(lowercase owner/repo), 16) % 2`: zero selects the primary and one
selects the secondary. The configured repository at job start pins that choice
for identity, scopes, retries and pages. Observed numeric IDs and rename aliases
inherit it; restored jobs accept their authenticated checkpoint's numeric ID.
Unknown or conflicting bindings fail before another credential is used. Shared
cohort planners apply the same partition per repository. Later jobs choose from
their current configured repository, independently of historical evidence.

An absent, empty or duplicate secondary preserves the original single-token
behavior. An explicitly configured custom `--read-token-env` remains single-token.
The secondary is unused when the primary is absent. Keep the same credential
configuration while resuming a logical job.

Each source slot retains its own primary-rate observation; a healthy response
from one does not erase a refusal on the other. Existing reserves, cumulative
wait budgets, secondary-limit backoff and deferred/partial outcomes still apply.
A refusal never selects another token. This is a fixed allocation of repositories,
not extra concurrency or a guarantee of pooled capacity: credentials belonging
to the same account can share an allowance, and secondary limits still apply.

Destination publication and state/Release operations continue using the existing
`GH_TOKEN` workflow credential. Public Git fetches remain anonymous HTTPS. The
six source workflows pass the optional secret only to their existing source-read
steps; workflow parallelism is unchanged. Legacy retained-archive downloads keep
their existing transport and do not join this source REST partition.
