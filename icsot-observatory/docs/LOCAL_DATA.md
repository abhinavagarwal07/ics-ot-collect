# Local archive inspection under the task disk limit

Audit and viewer code share one ledger at
`<workspace>/analysis/local-data-budget`. The limit is **2,000,000,000 bytes**
for the entire task, including existing project data, downloads, managed caches,
and registered external task directories. A separate ledger per component is
not a valid way to use this limit. Tests use isolated ledgers with small fixtures
inside the workspace.

`LocalBudget(state_root, roots=[workspace, ...])` counts physical allocation
(`st_blocks`, or logical bytes where unavailable), does not follow symlinks,
and deduplicates hardlinked inodes and overlapping roots. Additional task
directories must be registered before use. File enumeration fails closed on
unreadable normal directories. An encountered real mount point is charged at
its **entire filesystem capacity** without recursion, including protected OS
metadata; fixed-image admission covers both its backing file and mounted
capacity. Nested registered roots cannot bypass that charge.
`snapshot().as_dict()` reports allocation, outstanding
reservation capacity, conservative control-file headroom, and available bytes.
One global walk classifies each observed inode as baseline or one reservation's
work. Admission charges baseline plus the larger of each reservation's maximum
and its observed allocation. It never subtracts a later subtree measurement
from an earlier global measurement, so bounded subprocess growth cannot reduce
admitted bytes between separate scans.

`with budget.stage(declared_bytes, suffix='.enc') as stage` reserves the complete
maximum output plus file overhead. Pipe downloads into `stage.open_writer()` or
`stage.copy_from(binary_stream)`; the writer refuses excess bytes and creates
only an exclusive mode-0600 file. Do not pass `stage.path` to an unbounded
downloader or use generic temporary files alongside it. The context closes and
deletes its own file before releasing admission. No existing study evidence or
user cache is an eviction candidate.

`stage.preserve()` explicitly marks a closed stage as disposable managed cache.
Read preserved files only through `with budget.open_cached(path) as source`.
That lease prevents eviction from hiding allocation in an unlinked, open file.
Only unleased files registered by `preserve()` can be evicted. Stale reservations
and stale cache-reader leases do not expire by PID or elapsed time: recovery
requires checking that the original operation and its child processes have
ended and that owned files/volumes have been cleaned up.

`budget.reserve(maximum_bytes)` with `reservation.track(paths...)` supports work
that has an independently enforced total bound. The reservation remains admitted
at its maximum even when a tracked image is sparse or compressed. It is **not an
operating-system quota** for arbitrary Git or other subprocess output. Such work
needs an enforceable fixed-size filesystem, or must remain an explicitly labeled
streaming hash audit. A polling size monitor and per-file `RLIMIT_FSIZE` do not
enforce an aggregate directory limit. Unrelated applications writing outside the
cooperating task are outside this ledger; every task-owned allocation must use
the shared admission mechanism.

## Authenticated streaming archive reader

Construct `ArchivePart` values from the original public part indexes and, for
legacy migrated payloads, the encryption-migration mappings. Each part requires
both ciphertext and plaintext SHA-256 and byte counts. The reader accepts lazy
context-manager providers, enabling the following lifecycle for each part:

1. Admit and download one encrypted part through a budgeted stage.
2. Authenticate the complete AES-GCM envelope, ciphertext identity, and plaintext
   identity while discarding decrypted bytes.
3. Rewind the **same open encrypted file** and replay bounded decrypted chunks
   directly into an XZ decoder and a bounded tar parser. Recheck the GCM tag and
   both identities on this pass.
4. Close and delete that encrypted stage before requesting the next part.

No complete plaintext part is written. This avoids staging a roughly 1-GiB
encrypted part and another roughly 1-GiB plaintext part simultaneously. The XZ
decoder has a 64-MiB default memory limit and bounded output chunks. The tar
stream has a separate `max_tar_stream_bytes` limit covering every decoded byte,
including headers, PAX metadata, padding, and zero tails; `max_total_bytes`
separately limits regular-member payload bytes. The tar
parser supports normal regular files, directories, bounded PAX metadata, and
GNU long names. It rejects links, device files, sparse formats, unsafe paths,
duplicate paths, unallowlisted paths, excessive metadata, and trailing streams.

`VerifiedArchiveReader(..., allowed_prefixes=(...), expected_members=...)`
hashes every regular member. Valid CAS paths must match their content SHA-256;
when supplied, the public member inventory must match every path, byte count,
and hash. Persistent indexes name paths relative to the evidence root, while
their tar members begin with `evidence/`; callers must normalize that explicit
prefix before supplying `expected_members`.

The optional `scan(on_member)` callback receives `(MemberRecord, BinaryIO)`.
Read small JSON with `stream.read()` only below the metadata bound; stream
larger members in explicit chunks. The reader drains and hashes any unread
remainder. Callback records initially have `sha256=None`; the final report has
the verified digest and its verification source. **Every callback effect is
provisional until `scan` returns successfully**, because a source could change
before replay or a later part could fail. Keep temporary callback output private
and publish or serve it only after success. Discard callback output on failure.

`verify_encrypted_part(part, private_key_path)` authenticates one available part
without attempting XZ or tar. This is appropriate for retained incomplete
attempts: it makes no assertion that missing siblings or archive footers exist.
Reader results explicitly say Git was not restored or fscked. Neither successful
envelope authentication nor a full streaming member audit implies Git object
closure validation.
