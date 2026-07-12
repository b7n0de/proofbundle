# ADR 0005 — Eval semantics: score vs threshold verdict

Status: Accepted (3.1.0, non-breaking)
Date: 2026-07-12
Context: Hardening 3.0.1 audit finding P0-B (§7); §19 deliverable

## Context

An eval receipt's payload is a `proofbundle/eval-claim/v0.1` claim. The frozen v0.1
schema (`schemas/eval_claim_v0_1.schema.json`) has **no `score` field** — it carries
`comparator`, `threshold`, `passed`, `n`. `build_eval_claim` uses the caller's score
only to COMPUTE `passed` and then DISCARDS it. A receipt therefore proves a **threshold
verdict** (`passed` for the signed comparator/threshold), never an exact score. Output
that implied "a benchmark score you can check" over-claimed.

## Decision (3.1.0, non-breaking)

1. **Declare the evidence class.** `proofbundle.evalclaim.eval_evidence_class(claim)`
   returns one of `THRESHOLD_VERDICT_VERIFIED` (the ONLY class the frozen v0.1 schema can
   produce), `EXACT_SCORE_VERIFIED`, `SCORE_COMMITMENT_PRESENT` (a binding, NOT a range
   proof), `SCORE_WITHHELD`, plus the always-present `METHODOLOGY_NOT_EVALUATED`. `show-eval`
   prints an `evidence` + `note` line; no output claims an exact score.
2. **Options considered for an exact score.**
   - **A — Threshold verdict only** (what ships). No score in the payload; the receipt proves
     `passed` vs a signed threshold. Zero schema change. **Chosen for 3.1.0.**
   - **B — Optional exact-score profile**: an additive, signed decimal-string `score` the
     verifier re-checks against comparator/threshold (contradiction → FAIL; reject NaN /
     Infinity / exponent / Unicode digits). Additive and backward-compatible, but a NEW signed
     field starts EXPERIMENTAL (maturity policy) — **DEFERRED**, not shipped here. The
     classifier is forward-compatible with it.
   - **C — Score commitment** (a salted commitment to the score): a binding, NOT a range proof;
     it does not prove the hidden score crossed the threshold. Documented as such; a research ADR,
     not an own ZK construction.

## Consequences

- Non-breaking: the classifier is a read-side addition; no schema/wire/API change.
- The exact-score profile (option B) and any ZK range proof (option C) are future, EXPERIMENTAL
  work, gated behind the maturity policy. `EVAL_CLAIM.md` §1a is the user-facing statement.
