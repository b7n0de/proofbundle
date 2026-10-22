# Verifying TRACE Trust Records

`proofbundle verify-trace` and `proofbundle.adapters.trace_record.verify_trace_record` check a
TRACE v0.2 Trust Record against trust material that the relying party supplies. They were written
from the TRACE specification alone. They import no code from the TRACE reference library or its
conformance suite, and the comparison with that reference lives in `interop/trace/`.

## What it reads

Revision: agentrust-io/trace-spec at `a131c6400eaa95007b16b84a96331ccf37a93b73`,
`spec/trace-v0.2.md` and `schema/trace-claim.json` (SHA-256
`289293315d5a480cebcb8962b4d2937738421040e4bb8dcd13c1540073443ae5`). Every verdict repeats this
revision in its `specification` field.

Two binding forms, both from section 3.2.2:

- **compact JWS**: the payload is the record. `alg` is `ES256`, `ES384` or `EdDSA`, and `none`
  and every other value are refused. The protected header may carry only `alg`, `typ` and
  `kid`. Any other member is refused and named, `crit`, `b64`, `jwk` and `x5c` included. The
  payload bytes must be the RFC 8785 form of the record, and the record carries no `signature`.
- **embedded**: a JSON object whose `signature` member is an Ed25519 signature, in canonical
  unpadded base64url, over the RFC 8785 form of the record without that member. The
  specification fixes no encoding for an embedded ECDSA signature. A relying party that holds
  only EC keys is therefore told that the form is unsupported for its keys (exit 2).

Parsing refuses duplicate members at any depth, a byte sequence that is not UTF-8, `NaN`,
`Infinity`, and every integer outside the RFC 8785 safe range. Numbers are judged by value, so
`1785000000.0` is the integer 1785000000 (section 3.2.2). Every member the schema does not define
is reported by path and refused. The one exception is `cnf.jwk`, which the schema leaves open:
there an extra member is reported and permitted.

## Where trust comes from

Trust comes only from the relying party. It supplies the public keys (`--key`, JWK or JWK Set),
the verification instant and window (`--now`, `--max-age`, `--max-future-skew`, defaulting to
the clock, 86400 s and 300 s), and optional expectations: a challenge nonce (`--nonce`), accepted
policy bundle hashes (`--policy-hash`), accepted subjects (`--subject`), and the hash of the
transcript it holds (`--transcript-hash`).

The window values are whole seconds, bounded like every integer of the record: `--now` within
plus or minus 2**53 - 1, the two maxima from 0 to 2**53 - 1. A value outside is unusable trust
material (exit 2).

The record's `cnf.jwk` never supplies trust. The signature must verify under a trusted key, and
`cnf.jwk` must then name that same key by RFC 7638 thumbprint. The age check cannot be switched
off.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Verified: well formed, signed by a trusted key, `cnf` names that key, fresh, and every supplied expectation holds |
| 1 | A cryptographic or structural failure: signature, `cnf` binding, canonical payload, profile, schema, a record member the schema does not define |
| 2 | Unreadable input under this profile, a JWS header member other than `alg`, `typ` and `kid` included, or unusable trust material |
| 3 | A sound record that misses a relying-party requirement: window, nonce, policy hash, subject, transcript hash |

## What a pass does not say

A pass is evidence for a relying party's policy. It is never a decision of its own, and
`automation.safeForAutomation` is never true for a TRACE record. Section 3.3 lists eight
verification steps, and steps 3, 4, 6, 7 and 8 need evidence that a record does not carry: a
silicon root, reference integrity manifests, a SCITT receipt, SLSA provenance and a revocation
bundle. This verifier performs none of them, and every verdict lists them under `not_checked`.
It reports revocation as `NOT_EVALUATED`, which is what section 3.2.3 requires of a verifier that
holds no revocation bundle. It resolves no delegation parent and no `references` entry.

The limits of TRACE itself apply unchanged. They are stated in `LIMITATIONS.md` of trace-spec and
trace-tests at the pinned commits, and these are among them:

- A software-only record can be forged by an operator who can read the key.
- A genuine old record can be replayed within the window.
- `policy.bundle_hash` names a policy and says nothing about its quality.
- A key compromised after issuance leaves its records valid offline.
- Platform state is not appraised.
- No level is legal compliance.

## A gap in the specification

Section 3.1 says that all fields are required unless marked OPTIONAL, and it does not mark
`tool_transcript` OPTIONAL. The pinned `schema/trace-claim.json` does not require it. The two texts
decide a record without `tool_transcript` differently, and this verifier follows the schema: such a
record is accepted, as the reference accepts it. The comparison in `interop/trace/` carries the case
as `E-CONTESTED-tool_transcript-absent` with the expectation `n/a`, because no single text decides it.

## No Rust counterpart

The Rust second verifier in `tools/pb_verify_rs` has no TRACE path. The registry
`scripts/rust_parity_registry.json` records `verify_trace_record` as `PENDING`. It does the same
for `signature.verify_ecdsa_p384`, the ES384 primitive the verifier uses, which verifies and never
signs.
