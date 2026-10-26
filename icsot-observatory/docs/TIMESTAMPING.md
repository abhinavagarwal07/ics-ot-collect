# Timestamp evidence

Timestamp the SHA-256 of the exact finalized manifest bytes before packaging and encryption. Publish the manifest digest and small proof sidecars alongside the public index; keep the manifest and collected payload encrypted. A reader can verify a proof against the digest without receiving the plaintext, then compare the decrypted manifest later. Do not timestamp the hexadecimal digest as a new text file: that would attest a different hash.

Preserve the original receipt, every upgraded proof, RFC 3161 request/response, certificate material, hashes, and verification result as separate immutable records. Proof maintenance must not rewrite the frozen manifest or replace the original receipt. A later successful verification supplements the earlier result.

## OpenTimestamps

The pinned [OpenTimestamps client 0.7.2](https://github.com/opentimestamps/opentimestamps-client/tree/opentimestamps-client-v0.7.2) supports digest-only verification:

```sh
# Use a fresh candidate path; upgrade can create candidate.ots.bak.
cp initial.ots candidate.ots
ots info candidate.ots
ots upgrade candidate.ots
# Requires a configured, trusted Bitcoin Core RPC node; a pruned node is sufficient.
ots verify -d "$manifest_sha256" candidate.ots
```

Check that the detached proof identifies SHA-256 and the expected 32-byte digest. The CLI's `-d` option compares the supplied digest with the detached proof's digest. The [versioned argument definitions](https://github.com/opentimestamps/opentimestamps-client/blob/opentimestamps-client-v0.7.2/otsclient/args.py) document that option.

Keep these outcomes distinct: pending calendar receipt; Bitcoin attestation present but unverified; Bitcoin proof verified against a trusted node. In 0.7.2, successful `upgrade` only establishes that a Bitcoin attestation is present; it does not validate the block header. Successful `verify` performs that check. There is no block-explorer fallback in this CLI, and `--no-bitcoin` does not verify Bitcoin evidence. See the [versioned implementation](https://github.com/opentimestamps/opentimestamps-client/blob/opentimestamps-client-v0.7.2/otsclient/cmds.py) and [node requirement](https://github.com/opentimestamps/opentimestamps-client/blob/opentimestamps-client-v0.7.2/README.md#requirements).

Record proof hash, verification time, Bitcoin network, block height/hash, and verification method when available. A Bitcoin block supplies an existence bound; its header time is approximate. The CLI's success message prints a date in the local timezone, so do not parse it as an exact UTC anchoring time. Collector observation intervals remain separate from timestamp evidence, which does not authenticate GitHub as the source.

## RFC 3161

A configured TSA can return an immediately verifiable signed timestamp without a code-signing private key. Configure the endpoint, accepted trust roots, optional intermediate certificates and acceptable TSA policy. Do not silently select a different provider or treat certificates supplied by a response as trust anchors. Missing configuration, request failure, received-but-unverified response, and verified response are separate outcomes.

The following commands use only the manifest digest. Query creation includes a nonce by default; retain it and never add `-no_nonce`. `-cert` requests the signer certificate. Set `-tspolicy OID` when an expected TSA policy is configured.

```sh
openssl ts -query -sha256 -digest "$manifest_sha256" -cert -out proof.tsq
# Submission is a separate operation. Set tsa_url explicitly for the selected provider.
curl --fail --silent --show-error --max-time 30 \
  -H 'Content-Type: application/timestamp-query' \
  -H 'Accept: application/timestamp-reply' \
  --data-binary @proof.tsq "$tsa_url" -o proof.tsr

# Check the response against its original query, including algorithm and nonce.
openssl ts -verify -queryfile proof.tsq -in proof.tsr \
  -CAfile keys/digicert-trusted-root-g4.pem \
  -untrusted keys/digicert-timestamp-2025-intermediate.pem
# Independently bind the same response to the public manifest digest.
openssl ts -verify -digest "$manifest_sha256" -in proof.tsr \
  -CAfile keys/digicert-trusted-root-g4.pem \
  -untrusted keys/digicert-timestamp-2025-intermediate.pem
openssl ts -reply -in proof.tsr -text
```

Both verification commands must succeed; `-digest` and `-queryfile` are mutually exclusive. Preserve the DER query and response, not just their text renderings. OpenSSL checks the signature and certificate path; the query binds the algorithm, imprint, nonce and any requested TSA policy. Additional certificates belong in `-untrusted`, not the root CA file. See [OpenSSL ts](https://docs.openssl.org/3.0/man1/openssl-ts/), [request verification context](https://github.com/openssl/openssl/blob/openssl-3.0/crypto/ts/ts_verify_ctx.c), and [response verification](https://github.com/openssl/openssl/blob/openssl-3.0/crypto/ts/ts_rsp_verify.c).

Default verification does **not** check revocation. Record that limitation explicitly, together with the signer/chain fingerprints, trust-root hash, verification time/tool version, signed `genTime`, stated accuracy (or absence), policy and nonce result. Do not report unspecified accuracy as zero. Preserve available CRL/OCSP evidence for later review; certificate expiration and historical validation need an explicit policy, not `-no_check_time`. [OpenSSL verification options](https://docs.openssl.org/3.0/man1/openssl-verification-options/) describe certificate-time and CRL checks. [RFC 3161 sections 2.2, 2.4.2 and 4](https://www.rfc-editor.org/rfc/rfc3161.html) describe response validation, accuracy and trust renewal. TSA `genTime` attests evidence existence under that TSA's clock/policy; it is not the collector's observation time or proof of first publication.

## Bundled DigiCert public certificates

DigiCert's [RFC 3161 service page](https://knowledge.digicert.com/general-information/rfc3161-compliant-time-stamp-authority-server) documents `http://timestamp.digicert.com` and links the current chain. This is an explicit selectable profile, not a reason to trust an arbitrary endpoint. Only a digest request is sent; the returned signature, imprint and nonce must still validate. No TSA request was submitted while preparing these certificate files.

Fetched from the linked official HTTPS sources and verified on **2026-10-26 UTC**, using OpenSSL 3.6.3. The root's DER SHA-256 matches DigiCert's [published root fingerprint](https://knowledge.digicert.com/general-information/digicert-trusted-root-authority-certificates). Root self-signature, intermediate chain, and the current public responder's chain with `-purpose timestampsign` all passed. The responder has critical `timeStamping` EKU and digital-signature key usage. This validates the certificate material, not a timestamp response. DigiCert rotates responder certificates; retain each response's actual signer material.

| File | Official HTTPS source | DER certificate SHA-256 | Stored PEM SHA-256 |
| --- | --- | --- | --- |
| `keys/digicert-trusted-root-g4.pem` | [DigiCert Trusted Root G4](https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem) | `552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988` | `ce7d6b44f5d510391be98c8d76b18709400a30cd87659bfebe1c6f97ff5181ee` |
| `keys/digicert-timestamp-2025-intermediate.pem` | [DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1](https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem) | `ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd` | `5e13de210e735b614d6ec948361aadef9dd6c0ef575382a75f57fd59e183b90e` |

The root expires 2038-01-15 12:00:00 UTC; the intermediate expires 2038-01-14 23:59:59 UTC. The checked [SHA-256 responder certificate](https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20261.cer) has DER SHA-256 `2da09da7f4131f9fe72db6c5e6e9c9656755af043f1ea742cc0d2120e141ebfc` and validity 2026-08-05 through 2037-11-04 23:59:59 UTC; it is not bundled or pinned as a trust anchor.
