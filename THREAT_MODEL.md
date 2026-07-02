# Threat model — what a proofbundle receipt catches, and what it structurally cannot

A proofbundle receipt is a **tamper-evident, signed statement of authorship and integrity** over an eval or
test result. It is deliberately *not* a proof that the number is true or that the evaluation was well
designed. This document states the boundary precisely, so a strong signature is never mistaken for a strong
assurance. (Terminology: we say *tamper-evident signed evidence*, not *proof*; *authenticity and integrity*,
not *correctness of the computation*.)

## What `verify` catches

| Threat | Caught by | Result |
|---|---|---|
| **Payload tampering** — any byte of the claim changed after signing | Ed25519 signature over the canonical payload | `verify` → FAIL |
| **Merkle-root / inclusion tampering** | RFC 6962 inclusion + consistency proofs | FAIL |
| **Issuer swap** — re-signing with a different key while keeping the stated `issuer` | `decode_eval_claim` binds the claim `issuer` to the signing key | FAIL |
| **Model / dataset swap** — a claim silently attributing a result to a different model | salted commitment + `verify_commitment(identifier, salt, commitment)` | mismatch is visible |
| **Filtered disclosure** — hiding claims behind SD-JWT `_sd` digests | `sd_jwt_hidden_count` surfaces the number of withheld fields | omission is visible |
| **Replay** — presenting an old receipt as new | `check_freshness` reports age; a bound flags stale receipts | not-fresh is visible |
| **Weak assurance masked by a strong signature** — a self-attested PASS shown as if reproduced | `assurance_level` is signed into the claim (tamper-evident, issuer-declared); `show-eval` displays it; `claim_warnings` warns on self_attested + no pre-registration | a third party cannot alter the level; a dishonest issuer can still self-declare a higher one |

## What it structurally does NOT catch

- **A dishonest self-attested issuer.** A `self_attested` receipt is only as trustworthy as its issuer. A
  valid signature binds *who said it*, not *whether it is true*. The receipt does not stop someone signing an
  invented number — it only makes that number **attributable and tamper-evident**, and (v1.1) it warns when
  the weakest combination (self_attested + no pre-registration) is used.
- **Publish-best-of-many.** Without a pre-registered protocol, an issuer can run an eval many times and
  publish only the best result. `prereg_sha256` (a commitment to the protocol *before* the run) is the
  defence; without it, `claim_warnings` flags the receipt. A higher `assurance_level` (`reproduced`,
  `enclave_attested`) is the structural fix — that is the road from *authorship* to *truth*.
- **Whether the suite measures what it claims.** That the eval is well designed, unbiased, or
  contamination-free is a human judgement the receipt does not encode.
- **Forced random sub-sampling of individual samples.** proofbundle binds at the *claim* level (the reported
  metrics + sample count), not per-sample. A verifier-forced random sample check would need a per-sample
  Merkle binding; that does not exist yet and is on the roadmap — it is **not** claimed as done.

## Assurance levels (weakest → strongest)

| Level | Meaning |
|---|---|
| `self_attested` | The issuer ran it and signed the result. Default. Trust rests on the issuer. |
| `third_party` | A third party checked the result before signing. |
| `reproduced` | The result was independently re-run and matched. |
| `enclave_attested` | Produced inside an attested trusted execution environment. |

The level is a **signed field** of the claim: tamper-evident and bound to the issuer, so a *third party*
cannot alter it. But it is **issuer-declared** — a dishonest issuer can sign `reproduced` on a self-run eval;
the signature attributes that claim to them, it does not make it true (exactly like the score). `show-eval`
always prints the level, and `claim_warnings` flags the honest self_attested-without-pre-registration case.

## Related work (fair demarcation)

proofbundle attests eval/test *run* results, offline, via the standards stack (Ed25519 + RFC 6962 + optional
SD-JWT / in-toto). [ai-audit-trail](https://pypi.org/project/ai-audit-trail/) records *runtime* agent
Decision Receipts (a different layer). [ValiChord](https://github.com/topeuph-ai/ValiChord) builds
attestation bundles from inspect_ai logs post-hoc (its v1 library is unsigned — signatures are v2 scope).
Challenge-response / key-binding for forced fresh disclosure follows RFC 9901 (SD-JWT Key Binding).
