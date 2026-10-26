# Evidence encryption

The repository and its metadata may be public. Main evidence payloads are **encrypted before upload**, including baseline archives and smoke-test artifacts. Public files include repository selections, observation counts, manifests of hashes/sizes, verification outcomes and the RSA recipient public key. Anyone can download ciphertext; opening the evidence requires the corresponding private key.

The recipient is this machine's existing 2048-bit RSA key. Only [results-rsa-public.pem](../keys/results-rsa-public.pem) is committed. Its canonical DER SubjectPublicKeyInfo SHA-256 is:

`8c147570a5ef701202a2966db2b55d8b4d02236908578108b473c97eb18a49ee`

The matching private key is `~/.ssh/id_rsa` on the owner's machine. It is never sent to GitHub or the runners. Retaining that private key and a secure backup is necessary for future decryption.

## Envelope

Each archive part gets an independent random 256-bit AES key and 96-bit nonce. AES-256-GCM encrypts and authenticates the part; RSA-OAEP-SHA256 wraps the AES key. The versioned header is authenticated and contains the original SHA-256/size, algorithms and public-key fingerprint. The binary format and size limits are documented in [encryption.py](../src/icsot_observer/encryption.py).

Encryption streams bounded chunks. Decryption authenticates the complete file, verifies its original hash/size, and publishes an output only after successful verification. Existing output files are never overwritten. Wrong recipients, altered headers, corrupt ciphertext, truncation and trailing bytes fail closed. Encryption failure never falls back to a plaintext upload.

This protects stored payload contents. Metadata remains public by design, and the collection runner processes source data before encryption. Encryption alone does not prove GitHub provenance or sender identity; retained manifests and external timestamp receipts supply their separate evidence claims.

## Decrypt and restore

From the collector directory, after downloading an encrypted part and its metadata:

```sh
icsot-observe decrypt \
  --input library.tar.xz.part-0001.enc \
  --output library.tar.xz.part-0001 \
  --private-key ~/.ssh/id_rsa
```

Decrypt each part, verify its original hash, and concatenate the plaintext parts in the index's listed order. Decompress/extract the XZ tar archive, then reconstruct omitted Git mirrors and verify offline:

```sh
python scripts/capture_baseline.py restore --root /path/to/extracted/evidence
```

The CLI above handles the machine's unencrypted PEM RSA key. The Python decryption API also accepts a passphrase for encrypted PEM/OpenSSH keys; the project installs the SSH dependency extra for that support.

## Existing evidence migration

The original baseline's JSON indexes remain unchanged. `encryption-migration-index.json` links their original part names, sizes and hashes to verified encrypted replacements. It also identifies preserved copies of older Actions artifacts. The migration runs while private, verifies decryption locally and the uploaded ciphertext identity, then removes the exact plaintext asset/artifact IDs only after the complete mapping verifies.

A resumed baseline references verified complete parent captures through that migration map and captures the remaining targets. Historical partial evidence stays retained; a new attempt never overwrites it.
