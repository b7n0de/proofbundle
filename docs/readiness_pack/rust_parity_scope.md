# Rust second-verifier scope — what is differentially covered, what is deliberately PENDING (No-Fake)

The independent Rust verifier (`tools/pb_verify_rs`) is a differential HONESTY instrument, not a
completeness mandate. It covers the core verifier primitives and the relation surface end to end; the
rest of the ~4000-line Python security surface is honestly PENDING, declared here so "Rust parity" is
never read as a fake 100%.

Regenerate the live numbers with:

```
export PYTHONPATH=src
python3 scripts/rust_parity_gate.py --markdown        # the full per-surface table, live
python3 tools/pb_verify_rs/crosscheck.py --matrix audit_artifacts/360/rust_differential_matrix.json
```

## Covered differentially (Python == Rust on positive AND negative vectors)

- Content root (RFC 8785 / JCS-SHA-256) of a signed statement
- DSSE / Ed25519 signature verify over the exact PAE bytes (authentic + tampered)
- Strict JSON parse (duplicate-key rejection, parser-differential)
- RFC 6962 Merkle tree head
- Trust-Pack root-of-trust THRESHOLD (Ed25519 leg): threshold-met and threshold-NOT-met
- The full relation/v0.1 and relation-statement/v0.1 surface: 45 conformance vectors (`find conformance/relation -name case.json | wc -l`, measured 2026-09-20: 38 without and 7 with `statement` in the path; the line said 40 and nothing re-derived it), positive and
  negative (decoy-parent, subject-mismatch, signer, lineage tiers), Python == Rust on exit-class +
  lineage on every one

At v3.7.0 the conformance corpus held 57 cases and the `make conformance-crossimpl` gate reproduced 56 of them independently by the Rust binary. **That figure is bound to that corpus, not to this one.** The corpus holds 130 cases today, and the Rust build the previous wording said this needed has now been run: `cd tools/pb_verify_rs && cargo build --release` followed by `PYTHONPATH=src python tools/pb_verify_rs/crosscheck.py`, on this tree, 2026-09-20.

MEASURED: **61 of 130** corpus cases are reproduced independently, 45 of them relation vectors compared differentially on exit class and lineage. The gate names the remainder itself rather than folding it into the ratio — 69 cases are NOT RUN DIFFERENTIALLY, by kind: `agent_review_predicate` (35), `cap1_document` (15), `envelope_profile_rule` (9), `provenance_version_status` (10). Run it and it prints that block before the verdict.

So the honest statement is neither the old "the whole corpus" nor "not measured": **47 per cent of the corpus is not differentially reproduced, and every one of those cases is accounted for by kind with a reason.** The largest single item, `cap1_document`, is not a missing Rust side — `tools/cap1_unabhaengige_umsetzung/rs/` exists and carries the same nine rules — but a Rust side that is not wired to this differential.

The sentence above used to read "The whole conformance corpus ... is reproduced independently by the Rust binary". `CROSS_IMPLEMENTATION_REPORT.md` rejected exactly that form on 2026-09-08 — a count true of a smaller, older corpus placed next to the word *whole* reads as coverage of the current one. This file kept the rejected form for twelve more days because the fix there never swept its neighbours.

## Deliberately PENDING (honestly not Rust-covered, never silently accepted)

The registry (`scripts/rust_parity_registry.json`) records each PENDING surface with a reason. The
large majority of the Python verify surface is PENDING by design; the notable ones a reviewer will ask
about:

- Full SD-JWT / SD-JWT-VC verify (only the issuer-signature + eval-root-graft slice is Rust-covered,
  inside verify-bundle)
- ES256 / ECDSA-P256 issuer-signature primitive
- Status-list snapshot verify, tlog-proof inclusion verify
- Verification-summary DSSE structure validation (the content-root primitive IS shared/covered)
- Trust-Pack: mldsa65 / hybrid root keys, not_expired, version-monotone / prevVersionDigest chaining,
  two-stage rotation authorization, full predicate-shape validation (PARTIAL: the Ed25519 threshold
  leg is covered)

## Why this is honest and not a gap to "fix"

The Rust leg's job is to catch a Python-side parser-differential or canonicalization bug on the CORE
primitives every receipt type funnels through, and on the full relation ladder. Porting the entire
surface to Rust is a completeness goal for a later release, not an audit-candidate blocker; the
`rust_parity_gate.py --strict` integrity check fails only on a FALSE claim (a COVERED entry whose
evidence does not exist), never on an honestly-declared PENDING.
