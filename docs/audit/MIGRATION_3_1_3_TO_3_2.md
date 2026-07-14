# Migration 3.1.3 → 3.2.0

3.2.0 is **additive**. Every 3.1.3 verify path, bundle, and predicate keeps working unchanged; the new
surfaces are EXPERIMENTAL and opt-in. Nothing here is tagged or published yet (human-release).

## No breaking changes to existing 3.1.3 behaviour

- The native bundle format, DSSE/in-toto statements, Merkle inclusion, and the CLI verify exit-code
  contract (0/1/2/3) are unchanged. All prior P0 hardening (atomic root/tree context, policy-lifecycle
  fail-closed, aud/nonce, policyPurpose, metadata) stays green.
- The full pre-3.2.0 test suite continues to pass; 3.2.0 only ADDS tests and modules.

## New in 3.2.0 (EXPERIMENTAL, opt-in)

| Surface | How to adopt | Default if unused |
|---|---|---|
| `action-outcome/v0.1` (O1) + `outcome` CLI | emit/verify outcome receipts; pass `--decision-maker-id` to enforce role separation, `--expected-decision-ref` to bind the decision | not emitted; existing bundles unaffected |
| `trust-pack/v0.1` (O2) | build/verify a Trust Pack; for a rotation pass `prev_root_keys` + `prev_root_threshold` to `verify_trust_pack` | no trust pack consulted |
| public-transparency (O3) | supply a policy with `requireSignedCheckpoint` (or a witness quorum) — the aggregate now REQUIRES a cryptographic anchor | dormant, not wired into the bundle aggregate |
| `verification-summary/v0.1` (O4), `run-ledger/v0.1` (O5) | emit as standalone artifacts | not emitted |
| subject binding (O6) | pass `require_derived_subject=True` to `verify_outcome_receipt` for a hard gate | classified + warned, not hard-failed |
| SD-JWT VC (O7) | call `verify_sdjwt_vc(issuer_pubkey=…)`; `requireIssuerSignature` defaults True | the bundle-level SD-JWT check already fail-closes on an unauthenticated `sd_jwt_vc` |

## Behaviour changes a careful integrator should note (all fail-closed, more strict only)

- **SD-JWT in a bundle**: a present `sd_jwt_vc` with no `issuer_public_key_b64` was already rejected
  (WP-C2); 3.2.0 keeps that and adds the case-insensitive none-alg guard.
- **public-transparency aggregate**: now FAILs when neither `CHECKPOINT_SIGNATURE` nor `WITNESS_QUORUM`
  verified (origin/root/tree-size alone are plaintext claims). Only affects the EXPERIMENTAL O3 module.
- No change relaxes any check; every 3.2.0 delta is equal-or-stricter.

## Cross-implementation

The independent Rust verifier (`tools/pb_verify_rs`, O8) reproduces the full 14/14 conformance corpus —
see `CROSS_IMPLEMENTATION_REPORT.md`. It is a read-only checker, not part of the published Python wheel.
