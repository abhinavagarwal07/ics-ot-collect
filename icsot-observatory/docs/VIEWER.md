# Local capture viewer

The viewer compares preserved repository observations in a local browser. It uses
the Python standard library and bundled HTML, CSS and JavaScript. It needs no
Docker, Node installation, frontend build, browser download, CDN or telemetry.

From the `icsot-observatory` directory, using the project's Python environment:

```sh
PYTHONPATH=src python -m icsot_observer.viewer \
  --workspace .. --bind 127.0.0.1 --port 8765 --offline
```

Open `http://127.0.0.1:8765` in the existing browser. `--workspace` identifies the
task workspace, including the cohort CSV and the local disk-budget scope.
Existing roots under `evidence` are discovered by the adapter. Add other existing
capture roots explicitly:

```sh
PYTHONPATH=src python -m icsot_observer.viewer \
  --workspace .. --root /absolute/path/to/capture-root --offline
```

Use `--port 0` to choose an available port; the server prints its actual URL.
Press Ctrl-C in the launching terminal to stop it. Shutdown waits for active
bounded operations to release their temporary staging and Git volume.

## Browsing evidence

The repository sidebar is searchable and can be filtered by role and availability.
Remote catalog failures and rate-limit resets remain visible in a persistent
banner while local evidence stays browsable. `?` means an unknown remote capture
count; `4+`, for example, means four registered captures with an unknown remote
total. The “No captures” filter includes only repositories whose available
catalog is known. Initial browsing does not retry a failed remote request;
the Refresh control explicitly retries when the backend's reset time and bounded
metadata session budgets permit it.
The timeline preserves capture lanes and recorded UTC times. Choose A and B from
the selectors, click a timeline capture to choose B, or Shift-click to choose A.
Selecting the same capture on both sides browses its observed entities.

Issues, pull requests, comments, releases, tags and events have separate views.
Choose an observation to inspect changed fields, body text side by side, or the
entity JSON diff. Captured bodies are plain text; HTML and Markdown never execute.
The original-response disclosure retrieves bounded read-only excerpts from the
preserved response records. A displayed excerpt is not a replacement for the
original content-addressed bytes.

Git refs show captured OIDs and changes in ref advertisements. The Git tab also
offers bounded file differences when capture B has a loaded, sufficiently small
full Git bundle. Choose two of B's captured ref tips and click **Compare files**;
preparation happens only after that explicit action. Choose a changed file to
read its text patch and expand the base/head commit metadata. File-diff selectors
currently show at most 500 captured refs, with the total disclosed. Large, missing,
incremental or unloaded bundles remain
unavailable, and large or binary patches can be incomplete previews. Git OIDs
are selected from captured advertisements; there is no free-form revision field.
`Coverage & proofs` reports capture lanes, endpoint
coverage, gaps and timestamp/proof state. Collector UTC time is distinct from a
verified TSA timestamp or a pending Bitcoin attestation.

An item missing from a later observation is qualified as **not observed later**;
it is not established to be deleted. Empty, incomplete, disabled, unavailable and
not-loaded categories must be interpreted with their capture coverage.

## Selected encrypted captures

Without `--offline`, the adapter can inspect configured GitHub release metadata.
Evidence payloads are not automatically loaded when a repository or timeline is
opened. **Load selected evidence** requests only the selected captures and checks
the shared local disk budget before materialization. No UI link bypasses the
budget to fetch a large asset. Concurrent evidence loads are serialized by the
adapter; browsing remains available while a load runs.

For local decryption, specify `--private-key /absolute/path/to/private-key` when
starting the server. The key path is a server-side option. The browser has no
key-upload form or key-path API. Never put private keys or plaintext credentials
in the repository or a browser URL. Authentication, archive validation and
budgeted staging are owned by the capture adapter and shared archive reader.

The task's hard disk limit is **2,000,000,000 bytes** across the counted workspace,
configured roots, caches, staging and temporary payloads, including pre-existing
files. It is not an allowance per capture. The header displays the budget's
current snapshot; a selection that cannot fit is rejected with a bounded message.
No automatic corpus synchronization or eviction occurs from opening this page.

## Local HTTP boundary

The server binds only to a numeric loopback address (default `127.0.0.1`; `::1` is
supported explicitly). Host validation blocks arbitrary DNS names. Requests with
an Origin must match the viewer's exact HTTP origin for all API routes; cross-site
and same-site data fetches are rejected. The fixed public HTML, CSS and JavaScript
bootstrap assets also allow browser-initiated cross-site navigation after Host
validation; they contain no evidence or session token. A load additionally requires a same-origin Origin and a
per-server token. File-diff preparation requires the same explicit POST protections.
There is no CORS permission, arbitrary filesystem route,
arbitrary remote URL route, shell-command API, or Git revision-command API.

All responses use `Cache-Control: no-store`, a restrictive content-security
policy, frame denial and MIME-sniffing protection. API errors omit exception
text, paths, keys and tracebacks. Responses and raw excerpts are bounded; compare
pages contain at most 100 entries. The server changes only viewer-managed local
loading state and temporary staging, and has no GitHub write operation.

The loopback boundary is intended for a single local user and an existing browser.
Do not expose it through a reverse proxy or port forward.

## Verification

```sh
PYTHONPATH=src python -m pytest tests/test_viewer_http.py
```

HTTP fixtures are synthetic, clearly confined to tests, and require no network or
archive downloads. They cover Host/Origin/CSRF rejection, explicit loading,
bounded queries/responses, safe errors, static security headers and concurrent
metadata access. Adapter and shared archive-reader tests cover evidence semantics,
authentication and disk-budget enforcement separately.

A live macOS check on 2026-10-26 loaded the encrypted libfuse Git capture ending
at `2026-10-26T04:40:26.338786Z`. Its 8,505,697-byte bundle restored offline,
passed full `git fsck`, and matched all 1,130 captured refs across 26,082 objects.
Comparing two captured branch tips produced a two-file text diff in the browser.
The owned 256-MiB image and ciphertext staging were removed afterward. This
selected-capture check does not establish full-cohort recovery.
