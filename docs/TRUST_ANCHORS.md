# Where trust anchors come from

proofbundle verifies offline, so it never *fetches* a key or a root — every trust anchor is an
input the relying party supplies out of band, or an in-band value the relying party must pin. This
table is the whole trust surface. If you do not control where an anchor comes from, that layer
proves nothing to you.

| Anchor | Where it lives | Who must supply / pin it | If you don't |
|---|---|---|---|
| **Bundle issuer key** (`signature.public_key_b64`) | IN-BAND in the bundle — self-asserting | The relying party MUST pin the expected key out of band (e.g. a known lab key). The receipt only proves "signed by *this* key"; it cannot tell you the key is *the right one*. | You've verified an internally-consistent signature by an unknown party — attribution to nobody. |
| **SD-JWT issuer key** (`sd_jwt_vc.issuer_public_key_b64`) | IN-BAND optional; the real anchor is your expectation | Supply/pin the expected issuer key. Since v1.6 a `cnf`-bound SD-JWT with **no** issuer key is refused (fail-closed) — no silent bearer downgrade. | The SD-JWT's issuer signature and any holder binding are unverifiable → refused. |
| **Holder key** (`cnf.jwk`, RFC 7800) | IN-BAND inside the issuer-signed SD-JWT | Nothing extra — it is authenticated by the (pinned) issuer signature; the KB-JWT proves possession. | n/a (bound transitively to the issuer key). |
| **Log key** (`verify_tlog_proof(log_vkey=…)`, checkpoint vkey) | OUT-OF-BAND | Supply the log's C2SP vkey and, optionally, `expected_origin`. | A validly-signed checkpoint from an *unexpected* log would be accepted — pass `expected_origin`. |
| **Witness keys** (cosignatures) | OUT-OF-BAND | Supply the witness vkeys + a k-of-n `threshold`. Quorum is deduped by **key material**, not name. | No split-view resistance; witness count means nothing. |
| **Status-list issuer key** (`verify_status_snapshot(issuer_pubkey=…)`) | OUT-OF-BAND | Supply it, and it **SHOULD be a distinct anchor from the receipt issuer** — a self-issued status list carries no independent revocation assurance. | An issuer can sign its own "still valid" state; freshness without `exp`/`ttl` is reported as `None`, not judged. |
| **Samples root** (`claim.samples.root_b64`) | IN-BAND, **signed** | Nothing extra — it is covered by the bundle signature; the verifier re-checks `samples.n == n`. Audit challenges use a **fresh nonce you choose** (or a public beacon). | A self-challenge (no nonce) is grindable by re-salting — use a fresh nonce for real audits. |
| **TEE Verifier key** (`verify_enclave_attestation(verifier_pubkey=…)`, v2.0 preview) | OUT-OF-BAND | Supply the RATS Verifier's key; you also implicitly trust that its appraisal of the raw TEE evidence is sound. | An enclave attestation is only as good as the Verifier you trust; proofbundle checks its signature + receipt binding, not the raw hardware quote. |
| **Pre-registration protocol** (`prereg_sha256`) | Hash IN-BAND signed; the protocol FILE is out of band | You must obtain the protocol file to check it hashes to the committed value. | You have a commitment to a plan you can't see — ask for the file. |

Rule of thumb: **in-band, self-asserting anchors (the bundle/SD-JWT issuer key, the samples root)
prove internal consistency; out-of-band anchors (log, witness, status keys, the protocol file) are
where *your* trust decision actually lives.** The signature binds who claimed what; pinning the
right keys is what makes "who" mean someone you trust.
