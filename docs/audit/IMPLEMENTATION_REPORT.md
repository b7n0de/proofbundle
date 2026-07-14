# Implementation Report — 3.2.0 (in progress on `feat/3.2.0-outcome-receipt`)

What 3.2.0 adds on top of the re-verified 3.1.3 baseline (see `BASELINE_3_1_3.md`). Every item is
EXPERIMENTAL and graduates individually (Reifegradpolitik §1.6). Nothing here is tagged or published —
that is a human-release action.

## TEIL 2 — receipt-chain O-item predicates (the core of 3.2.0)

| # | Deliverable | State | Evidence |
|---|---|---|---|
| O1 | `action-outcome/v0.1` Outcome Receipt + CLI (`outcome init\|emit\|verify\|inspect`) | built | vendored predicate + hand-validator parity; role separation, decisionRef binding, policyPurpose=outcome |
| O2 | `trust-pack/v0.1` Trust Pack (TUF-inspired threshold-of-root) | built + **hardened** | see release-review hardening below |
| O3 | Public Transparency profile | built (EXPERIMENTAL, dormant/unwired) | aggregate now requires a cryptographic anchor (hardening #5) |
| O4 | `verification-summary/v0.1` | built | signed, machine-readable verification summary |
| O5 | `run-ledger/v0.1` | built | monotone seq + digest chain, run budget |
| O6 | Subject Binding + Nested Schema Closure | built | DERIVED subject default, EXTERNAL_ATTESTED classified |
| O7 | SD-JWT VC minimal profile | built + **hardened** | issuer signature now verified; see below |
| O9 | CODEOWNERS for the new security modules | built | `.github/CODEOWNERS` covers the 7 new modules |

## Release-review hardening (pre-release adversarial audit, 4 CRITICAL closed)

A full 6-lens audit + two independent adversarial re-reviews + a delta re-review (all "HÄLT") found and
closed four fail-opens on exactly the property the two new trust primitives promise, each with a
bidirectional tamper test:

1. Trust Pack key aliasing (Sybil): the root threshold counts distinct decoded key material, and
   validate rejects aliased keys.
2. Trust Pack rotation: `verify_trust_pack(prev_root_keys, prev_root_threshold)` enforces that a
   threshold of the OLD root signed the new pack (two-stage rotation), previously documentation-only.
3. SD-JWT VC issuer authenticity: `verify_sdjwt_vc(issuer_pubkey=…)` + `requireIssuerSignature`
   (default true) cryptographically verifies the issuer; a self-issued garbage-signed credential no
   longer returns ok.
4. Outcome subject rehang: `verify_outcome_receipt` classifies the subject (never zero-signal), warns
   on EXTERNAL_ATTESTED, and offers `require_derived_subject`.

Plus a follow-up pass (public-transparency crypto-anchor requirement, case-insensitive none-alg guard,
explicit fail-closed subject classify, rotation footgun warning) and a No-Overclaim doc/governance sweep.

Gate battery: **pytest 1121 passed, ruff clean, claims-hygiene clean (41 docs), mypy clean**. CI on the
PR is green.

## O8 — independent cross-implementation verifier

`tools/pb_verify_rs` (Rust): a read-only second verifier sharing no canonicalization or parser code with
Python. Reproduces **13 of the 14** conformance-corpus cases independently (`crosscheck.py`, exit 0):
content roots, DSSE/Ed25519, RFC 6962 merkle, native-bundle exit-code contract (sig + inclusion +
root/tree-size), SD-JWT issuer authenticity + holder-binding fail-closed, and the eval-root-graft check.
The one remaining case (`forged-anchor-own-frozen`) needs an OpenTimestamps subsystem and is honestly
documented as a pending slice — see `CROSS_IMPLEMENTATION_REPORT.md`.

## Open for the 3.2.0 release (per the prompt §7 acceptance)

- O8 case 14/14 (OpenTimestamps anchor verification) — pending slice.
- Technical Note 3.2.0 + Zenodo version (TEIL 3) — the Note is finalized after 3.2.0 ships and describes
  the shipped state; the Zenodo deposit is a human-release action.
- The 3.2.0 tag + PyPI publish + GitHub release — all human-release actions (§1).
