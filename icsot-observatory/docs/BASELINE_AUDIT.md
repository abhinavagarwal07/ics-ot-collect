# First-corpus bounded audit

The [first corpus release](https://github.com/abhinavagarwal07/ics-ot-collect/releases/tag/corpus-baseline-40294818409-1) (release ID `424020503`) was published on 2026-10-26 at 16:49:17 UTC. Its sealed inventory accounts for all 185 targets: **167 accepted, 18 explicitly incomplete, 0 missing**. This does not establish 185 accepted captures or universal payload recoverability.

Sealed source identities:

- `baseline-inventory.json`: 877092 bytes, SHA-256 `3b39f6a290794a0e6ad763a48ccc9a78b782d1da375658142489238678505d21`.
- Timestamp catalog: 164520 bytes, SHA-256 `c62520eb1027692d8e6871d75a3d5783bd1855dae1b33704d5fe8d6cc16a757b`.

The new terminal-declared audit reused the pinned 185-target metadata audit. Two additional independent full-bundle restores into empty offline repositories passed `git fsck --full --no-reflogs`, declared refs/objects and annotated-tag peel checks:

| Repository | Packed objects | Declared capture refs | Result |
| --- | ---: | ---: | --- |
| mz-automation/lib60870 |8107|72|PASS|
| JoelBender/BACpypes3 |2289|84|PASS|

Both packages are **native-encrypted**. The initial BACpypes3 selection rationale incorrectly called its envelope migrated; the reviewed report corrects that rationale and preserves the original report hash. No migrated-envelope payload restore is claimed for this pass.

For these two packages, ciphertext/plaintext identities, GCM authentication, XZ/TAR structure, all member/CAS hashes, manifest dependencies and OTS subject binding passed. The 183 other selected-corpus payloads were not decrypted/restored here; prior libfuse QA was reused separately. The 18 incomplete cases retain their exact gaps, including two deadline cases without finalized manifests/OTS and Zephyr's unverified mirror. No independent Bitcoin timestamp verification was performed.

Each native image was 96 MiB with a 200 MiB image-plus-mount reservation under the aggregate 2,000,000,000-byte local ceiling. Owned images/staging were cleaned and the superseded strict watcher stopped. Actual GPT-6.1-sol xhigh evidence review is complete: **PASS for bounded samples with declared corpus limits**.

Local reports are retained under `analysis/recovery-audit-terminal-40294818409/`:

- [Original mechanical report](../../analysis/recovery-audit-terminal-40294818409/terminal-recovery-audit.json): SHA-256 `662763fd1018d88bdd04e76d3defd3ca547d598f57acfd3b2e0fe31442b1b7fb`.
- [Reviewed report](../../analysis/recovery-audit-terminal-40294818409/terminal-recovery-audit.reviewed.json): SHA-256 `c1d0c9094f5f8456165dd323927c26c24e0dbb4feb200f81cfd0015b4d94907b`.
- [Actual model review record](../../analysis/recovery-audit-terminal-40294818409/model-review.json): SHA-256 `ad9b8ecc71589d6b1800b93f84db13deb787cc3dc36210f84597329dab3c3f5e`.
- [Human review](../../analysis/recovery-audit-terminal-40294818409/GPT_REVIEW.txt): SHA-256 `19e58ab892d741eec39fb4f6280ef31c4e99faad0f08faeaf2ea1ac624c14944`.

Original analysis evidence remains unchanged. The documented 183 deferred payloads, declared scientific partials, source-authenticity/first-publication limits and unverified Bitcoin time remain limits of this result.
