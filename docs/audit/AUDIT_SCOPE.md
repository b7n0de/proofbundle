# Audit Scope — external independent security review (pre-Stable)

proofbundle stays classifier `4 - Beta` until an EXTERNAL, independent security audit completes (O9 +
the Stable gate). This file defines the scope that audit should cover, so the review is bounded and the
findings map to concrete modules. It is a scope document, not a claim of having been audited.

## In scope (the security-load-bearing surface)

| Area | Modules | What to attack |
|---|---|---|
| Canonicalization | `canonical.py`, `_strict_json.py` | RFC 8785 correctness, duplicate-key parser differentials, number/string edge cases |
| Signatures / DSSE | `signature.py`, `dsse.py`, `intoto.py` | PAE byte rule, predicate-type confusion, algorithm confusion, signature-over-base64 mistakes |
| Merkle / anchors | `merkle.py`, `checkpoint.py`, `anchors*.py` | RFC 6962 inclusion/consistency, atomic root/tree-size trust (P0-A), witness-quorum key-material dedup, OTS own-frozen trust (WP-A1) |
| Receipt chain | `decision.py`, `outcome.py`, `run_ledger.py`, `verification_summary.py` | role separation, decisionRef/replay binding, subject rehang, eval-root graft, budget/chain invariants |
| Trust primitives (new, 3.2.0) | `trust_pack.py`, `sdjwt.py`, `sdjwt_vc.py`, `kbjwt.py`, `subject_binding.py`, `public_transparency.py` | threshold-of-root Sybil, two-stage rotation, issuer authenticity, holder binding (cnf/KB-JWT), transparency crypto-anchor requirement |
| Policy / exit codes | `policy.py`, `bundle.py`, `cli.py` | the 0/1/2/3 verify contract, fail-closed on every requested-but-unenforceable check |

## Out of scope (documented non-goals)

- Whether a signed claim is TRUE (integrity is not truth — No-Overclaim).
- Availability / DoS of external calendar or TSA services (the offline verifier never depends on them).
- The independent Rust cross-implementation verifier (`tools/pb_verify_rs`) is a conformance aid, not part
  of the published wheel; it should be reviewed for AGREEMENT, not as production trust.

## Method expectation

Red-team-first: a failing regression test before each fix, adversarial substitution across a
relying-party matrix, cross-implementation checks, and lifecycle/replay. The 3.2.0 release-review
already applied this internally (see `SECURITY_FINDINGS_CLOSED.md`); the external audit is the
independent second pair of eyes that the internal review cannot substitute for.

## Evidence the auditor can start from

- `SECURITY_FINDINGS_CLOSED.md`, `THREAT_MODEL_DELTA.md`, `CROSS_IMPLEMENTATION_REPORT.md`.
- The conformance corpus (`conformance/`, 14 pinned cases) and the full test suite (1121 tests).
- SPEC.md + the predicate docs for the normative contract.
