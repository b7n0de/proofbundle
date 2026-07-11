# Where trust anchors come from

proofbundle verifies offline, so it never *fetches* a key or a root — every trust anchor is an
input the relying party supplies out of band, or an in-band value the relying party must pin. This
table is the whole trust surface. If you do not control where an anchor comes from, that layer
proves nothing to you.

| Anchor | Where it lives | Who must supply / pin it | If you don't |
|---|---|---|---|
| **Bundle issuer key** (`signature.public_key_b64`) | IN-BAND in the bundle — self-asserting | The relying party MUST pin the expected key out of band (e.g. a known lab key). The receipt only proves "signed by *this* key"; it cannot tell you the key is *the right one*. | You've verified an internally-consistent signature by an unknown party — attribution to nobody. |
| **SD-JWT issuer key** (`sd_jwt_vc.issuer_public_key_b64`) | IN-BAND optional; the real anchor is your expectation | Supply/pin the expected issuer key. Since rev 2026-07-11 (WP-C2) **any** `sd_jwt_vc` with no issuer key is refused (fail-closed, reason `unsigned`) — not only `cnf`-bound ones. The verifying key is bound to the disclosed `issuer` (WP-C1, reason `issuer-key-mismatch`), and for an eval-claim bundle the disclosures + receipt root are bound to the bundle (reason `unbound`). | The SD-JWT's disclosures are unauthenticated → refused. Still pin the expected key out of band: a valid self-signature under an *unknown* key names nobody you trust. |
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

## Making the pinning machine-readable — a trust policy (v0.1)

The table above is the trust surface; a **trust policy** is where a relying party writes that pinning
down as a file `verify` can enforce, instead of remembering to pass the right flags by hand. Without
a policy, `verify` makes NO trust decision and says so (`POLICY: NOT_EVALUATED`); with one
(`verify receipt.json --policy trust_policy.json`) the policy is evaluated OVER the crypto result and
its outcome is a separate `POLICY:` line, a separate `policy_ok` JSON field, and exit code **3** on
failure — distinct from a crypto failure (exit 1), so "crypto fine but not the signer/level I trust"
is never conflated with "crypto broken".

The policy format (`schema: proofbundle/trust-policy/v0.1`, `schemas/trust_policy_v0_1.schema.json`)
is snake_case, versioned, **fail-closed** (an unknown field is a parse error — a typo cannot silently
weaken a policy) and **offline** (trust comes only from the file; no key is ever fetched). A worked
example is `examples/trust_policy_strict.json`. What it can pin today, mapping onto the anchors above:

| Policy field | Pins | Maps to anchor |
|---|---|---|
| `allowed_issuers[].public_key_b64` + `signature.require_expected_signer` | the bundle issuer key — matched by **public key** (kid is a display hint only) | Bundle issuer key |
| `signature.allowed_algs` | the signature algorithm (e.g. `ed25519`) | Bundle issuer key |
| `allowed_schema_versions` | the bundle `schema` version | — |
| `merkle.required_hash_alg` | the Merkle hashing algorithm (anti-alg-confusion) | Samples/Merkle |
| `sd_jwt.expected_aud` / `require_nonce` / `require_key_binding_when_cnf_present` | RFC 9901 audience / replay / holder binding on the KB-JWT | Holder key |
| `sd_jwt.max_iat_age_seconds` | freshness of the signed eval-claim timestamp (judged at verify time) | (replay) |
| `assurance.minimum_level` / `reject_self_attested_without_prereg` | the issuer's signed assurance level and the weakest self-attested-without-pre-registration case | Pre-registration protocol |

**Inspecting a policy (`policy explain` / `policy lint`, TP1):** `proofbundle policy explain
<policy>` lists the effective pins a policy makes (what a green `POLICY: OK` will actually mean);
`proofbundle policy lint <policy>` fails (exit 1) on a policy that pins NOTHING — such a policy
would produce a vacuous `POLICY: OK` with zero checks evaluated. `--strict` additionally fails a
policy that pins no signer. In `verify` itself, a PASSING policy that pins no signer prints
`POLICY: OK (WARNING: attributes to nobody)` and carries the machine-readable `policy_warnings[]`
— the exit code stays 0 (a warning, not a failure), but the attribution gap is never silent.

**Honest boundaries (v0.1):**

- The `status` section (`reject_self_issued`, `allowed_status_authorities`) is accepted so a policy
  can declare its revocation intent, but `verify --policy` has **no status snapshot input** in v0.1 —
  a policy that ENABLES a status requirement fails closed with a clear reason rather than silently
  passing. Evaluate revocation separately with `verify_status_snapshot` until a later phase wires a
  snapshot input.
- `sd_jwt.require_nonce` enforces that a nonce is present in a **verified** Key Binding JWT (an
  unauthenticated nonce is refused, fail-closed). It does NOT by itself bind the nonce *value* to your
  transaction — that is a challenge you supply with `--nonce`, exactly as `sd_jwt.expected_aud` /
  `--aud` bind the audience. Use `--nonce` for real challenge-response.
- If `--aud` and the policy's `sd_jwt.expected_aud` are both set and differ, that is an ambiguity, not
  a silent override: `verify` exits 2.
- There is **no key-rotation or root-of-trust delegation** (no TUF-like signed root/targets roles with
  `expires`, see `INTEROP.md`). `allowed_issuers[]` is a static pinned list; rotating a signer means
  re-distributing the policy file. A trust policy pins keys; it does not manage their lifecycle.
