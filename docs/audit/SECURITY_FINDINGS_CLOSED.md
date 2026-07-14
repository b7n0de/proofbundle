# Security Findings Closed — 3.2.0 release-review

A pre-release adversarial audit of the two new 3.2.0 trust primitives (O2 Trust Pack, O7 SD-JWT VC)
found four CRITICAL fail-opens — each on exactly the property the primitive's name promises, each
missed by the happy-path test suite. All are closed with a bidirectional tamper test; two independent
adversarial re-reviews plus a delta re-review returned "HÄLT" (holds), and the original attack PoCs
re-confirm every break is now blocked. Nothing here is published (human-release).

## CRITICAL (all closed)

| # | Finding | Fix | Regression test |
|---|---|---|---|
| C1 | Trust Pack root threshold defeated by key aliasing (one key under N keyIds counted as N signers — Sybil) | count DISTINCT decoded key material, and `validate` rejects aliased keys (mirrors `checkpoint.py::witness_quorum`) | aliasing → validate error + sign raises; distinct keys still valid |
| C2 | Trust Pack rotation was documentation-only (`prevVersionDigest` is a public hash → anyone mints a "v2") | `verify_trust_pack(prev_root_keys, prev_root_threshold)` enforces a threshold of the OLD root signed the new pack; guarded `>= 1` | hijack (self-owned keys) → rejected; genuine vouch → ok; threshold 0 → rejected |
| C3 | `verify_sdjwt_vc` never verified the issuer signature ("full check" only parsed it) | `verify_sdjwt_vc(issuer_pubkey=…)` + `requireIssuerSignature` default True calls the real `verify_sd_jwt`; missing anchor → fail-closed | wrong issuer key → rejected; missing key → fail-closed; correct key → ok |
| C4 | Outcome subject rehang undetected (`subject_binding` never wired into `verify_outcome_receipt`) | classify the subject always, warn on EXTERNAL_ATTESTED, `require_derived_subject` hard gate | rehang → warned; require+rehang → rejected; derived → ok |

## Follow-up hardening (RESTRISIKO closed for a clean release)

- Public-transparency aggregate now REQUIRES a cryptographic anchor (`CHECKPOINT_SIGNATURE` or
  `WITNESS_QUORUM` == PASS) — origin/root/tree-size alone are plaintext claims from an unsigned note.
- `check_vc_profile` none-alg guard is case-insensitive + rejects a non-string alg.
- `require_derived_subject` fail-closes explicitly when subject classification raises.
- `verify_trust_pack` warns when a pack declares a `prevVersionDigest` but is verified without the
  previous root (a standalone verify proves self-signing, not an authorized rotation).

## Gates

pytest **1121 passed**, ruff clean, claims-hygiene clean (41 docs), mypy clean. The independent Rust
cross-implementation verifier (O8) reproduces the full 14/14 conformance corpus.

## Honest residual (out of scope for this release, documented)

- The independent security review (O9) is a governance requirement met by CODEOWNERS + required
  reviews on the security paths; an EXTERNAL third-party audit before the `Stable` classifier is a
  separate, still-open milestone (Classifier stays `4 - Beta`).
- The Rust O8 verifier reproduces the corpus but does not yet parse the OTS binary proof / verify a
  real Bitcoin block header (only needed to CONFIRM a genuine relying-party-supplied anchor).
