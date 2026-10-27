# Bounded legacy-state recovery pilot

The manual `legacy-state-recovery.yml` workflow currently permits **FFmpeg/FFmpeg only**. It is a recovery pilot, not permission to reset every held target. Node and Zephyr require reconciliation of their original fresh captures; CPython has a separate seed-validation failure.

Recovery keeps the original migration disposition, partial releases and ciphertext. It verifies an explicit frozen manifest, current source-ledger bytes, source-plan/configuration hashes, operational recipient and missing authoritative pointer/slug binding. A newer authoritative state wins.

The original source observation interval stays unchanged. New import/recovery receipts identify their actual current execution time and code, with the historical import receipt and code retained as lineage.

## Freeze a reviewable manifest

After committing the reviewed recovery code, run from `icsot-observatory/` using the installed collector environment:

```sh
python -m icsot_observer.legacy_recovery freeze \
  --held-preparations ../analysis/reliability-review-20261027/latest-held-preparations.json \
  --asset-census ../analysis/reliability-review-20261027/held-asset-completeness.json \
  --epoch <new-32-hex-recovery-epoch> \
  --destination-repository abhinavagarwal07/ics-ot-collect \
  --config config.corpus.toml --csv ../public_patch_corpus_185.csv \
  --output ../analysis/reliability-review-20261027/ffmpeg-recovery-manifest.json
```

This command reads metadata only. Review the selected source entry, exact old generation/record hash, expected missing state, candidate references and two-generation bound. The workflow accepts the canonical manifest JSON plus SHA-256 of its exact canonical bytes, including the final newline. Dispatch the workflow at the reviewed commit SHA; it checks out that revision and uses only the existing `COLLECTOR_STATE_PRIVATE_KEY` secret. The owner's evidence private key remains local.

## Interruption and publication

The importer reads the authenticated retained baseline rather than querying or cloning upstream again. Matching old parts are downloaded, hash checked, decrypted/authenticated and matched by decoded hash, length and archive role. They retain their original references inside a new state index. Recovery does not invent an authoritative predecessor.

An encrypted full prepared descriptor is uploaded and verified before part uploads, then recorded in a separate durable recovery journal. Verified upload progress is checkpointed. On restart:

- A complete remote ciphertext set can restore and resume its exact prepared generation.
- Missing randomized ciphertext requires a new linked generation reconstructed from the same original source, reusing authenticated available parts. It cannot be recreated under the old ciphertext identity.
- At most two recovery generations are admitted for one reviewed epoch. Further interruption remains explicitly blocked and needs a new reviewed recovery decision.

The final pointer uses the existing non-force compare-and-swap and identity checks. The hosted runner retains explicit recovery outcomes and removes its temporary operational key.

## Acceptance

Publication alone does not establish ordinary readiness. After recovery succeeds, run `persistent-selected.yml` for `FFmpeg/FFmpeg` at the reviewed code revision. Confirm authenticated restoration and a new incremental observation, including its API/Git outcomes and resource admission, before expanding the recovery pilot. Preserve explicit partials; do not infer complete scientific coverage from a green planning job or pointer presence.
