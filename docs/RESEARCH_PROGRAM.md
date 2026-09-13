# Research program

**What this file is.** A measurement sheet, not a prospectus. Every line either names a path in the
tree at a named head, or says in one of three words why it does not: `NOT MEASURED`,
`NOT MEASURABLE` with a reason, `NOT APPLICABLE` with a reason. A claim without a path is not a
claim here.

**What this file is not.** It is not a plan, not a promise, and not a positioning statement. The
external note that prompted it (`Betreiber/02_proofbundle_berichte/WISSENSCHAFTLICHE_EINORDNUNG_extern_20260912/`,
sha256 `d28af81d…`) is a structural proposal without a named author. **None of its scales, scores or
verdicts are adopted here.** It supplied the questions; the answers below are measured in this tree.

- Order: `QITEM-PROOFBUNDLE-610-SAMMELRELEASE-01-N6`, 2026-09-12T17:12Z
- Measurement head: **`origin/main` = `27c17fcf2d5a42dd8949c94337065cc89f346a39`** unless a line says otherwise
- Model: Claude Opus 5 (1M context)

> **Head discrepancy, named rather than smoothed over.** The order states „main 1ea7e523". That
> commit is a merge of PR #185 dated **2026-09-05** — a week before the `v6.0.0` tag. Measured
> 2026-09-12: `origin/main` = `27c17fcf`, local `main` = `4e32e83` (= the tag). The reference check
> in the order („all nine named files present") therefore describes an older tree. Nothing below
> relies on it; every line names its own head.

---

## Theses as measurement questions

Six theses from section 24 of the external note. Each line: **the measurement that would decide it**,
and **the state**. Only one has evidence in the tree today.

### T1 — Cryptographic integrity alone is not sufficient to use AI evaluation evidence for automated decisions

- **Deciding measurement:** a verifying surface that returns `ok` on a cryptographically valid
  receipt while withholding an automation verdict, plus a case where a relying party that reads only
  `ok` would act wrongly. The property is *separation*, not *strength*.
- **State:** `NOT MEASURED`. Candidate surfaces exist (`policy_decision` stays `None` without a named
  policy; `safeForAutomation` is a separate field), but no measurement binds the two into one
  falsifiable case in this tree.

### T2 — Evidence strength must be modelled along independent axes instead of collapsing into a single trust score

- **Deciding measurement:** show two receipts that are equal on one axis and differ on another, and a
  consumer that distinguishes them. Then show that any single scalar ordering loses one of the two.
- **State:** `NOT MEASURED`. The axes exist in the code (four separate time axes in
  `verify_agent_review_v02`), but the *loss* a scalar would cause is not measured.

### T3 — Typed lineage permits a change of knowledge without mutating historical evidence

- **Deciding measurement:** a retraction or correction that changes the current verdict while leaving
  every historical byte and digest intact — and a check that fails if the history moved.
- **State:** `NOT MEASURED` in the sense of this thesis. Relation and retraction surfaces are
  exercised by the conformance corpus, but no measurement is framed as „the history did not move".

### T4 — Negative conformance vectors plus mutation testing give stronger evidence for verifier properties than positive unit tests alone

- **Deciding measurement:** the comparative form — one defect class caught by negative vectors or a
  planted mutant and *not* by the positive suite. Without the negative case the claim is a preference,
  not a finding.
- **State:** `NOT MEASURED` **as a comparison**. Both mechanisms exist and run; what is missing is a
  case measured under both regimes.

### T5 — Cross-implementation agreement reduces the risk that a specification only describes the accidental behaviour of a reference implementation

- **Deciding measurement:** an independent second implementation runs the same negative vectors and
  agrees, plus an honesty gate that turns red when a coverage claim is not backed.
- **State:** **NOT MEASURED** in the run cited below, and this correction is the point:
  the aggregate `23 passed, 1 skipped` hides which test was skipped, and the skipped one is
  the only one that measures agreement. The thesis has the most machinery of any here, but
  machinery is not a measurement.

  | Path (head `4e32e83b647235bfedf23b55cebe69fdf14fd6f5`, tag `v6.0.0`) | Lines | What it measures |
  |---|---|---|
  | `tests/test_relation_statement_rust_parity.py` | 53 | `test_crosscheck_relation_differential_green` — the Python↔Rust differential on the relation surface. **Skipped unless `tools/pb_verify_rs` has been cargo-built**, and a standard checkout has not built it |
  | `tests/test_rust_parity_gate.py` | 462 | the **honesty of the coverage bookkeeping**: a claimed subcommand missing from `main.rs` or from the built binary is `stale`, an untracked Python verify function is `untracked`, an orphaned registry entry is `orphaned` |

  Measured run, both files, on a standard checkout: **23 passed, 1 skipped** — and the single
  skip is `test_crosscheck_relation_differential_green`, with the reason
  `pb_verify_rs not cargo-built`. None of the 23 passing cases measures Python-Rust
  agreement, so that run does not support the claim.

  Measured again after `cargo build --release` in `tools/pb_verify_rs` (toolchain 1.95.0, the
  pinned channel): **24 passed, 0 skipped**. The agreement therefore holds when it is actually
  run. What was missing was the evidence, not the property — and an aggregate that does not
  name its skip cannot tell those two apart.

  Origin of this correction: an automated review comment on the pull request that introduced
  this section, reproduced here at the head before it was accepted.

  **What this does NOT show, and the distinction carries the thesis.** The two files measure
  different things. Agreement itself is measured on **one** surface (relation). The parity gate does
  not measure agreement at all — it measures that a *claim* about agreement is backed. A green gate
  with one agreeing surface is evidence for the thesis; it is not evidence that the specification is
  free of reference-implementation accidents elsewhere. The remaining surfaces are `NOT MEASURED`
  against this thesis.

### T6 — Offline-verifiable AI evidence can interoperate with existing supply-chain standards without replicating their infrastructure

- **Deciding measurement:** an artefact produced here is consumed by an unmodified external tool, and
  a verification that runs with no network. Both halves are needed: interoperation without offline
  verification is not this thesis, and offline verification alone says nothing about interoperation.
- **State:** `NOT MEASURED`. The in-toto predicate PR is open and unmerged at the time of writing;
  no measurement of an **unmodified external consumer** exists in this tree.

---

## Honest reading of this section

**One of six theses has evidence, and that one only partially.** That is the measured state, not a
starting position to be improved before it is shown. The five `NOT MEASURED` lines each name the
measurement that would decide them — which is the useful part: they are falsifiable, and none of
them is waiting on an opinion.

---

## Contribution candidates

Six candidates from sections 10–15 of the external note. Each carries exactly four lines: **Claim**,
**Non-claim**, **Evidence in tree** with path and head, **State of external review**. The head is
`origin/main` = `27c17fcf2d5a42dd8949c94337065cc89f346a39` unless the line says otherwise.

**The non-claim line is not decoration.** Every one of these candidates has a neighbouring statement
that the evidence does *not* support, and naming it is what keeps the claim falsifiable.

### C1 — Evidence taxonomy

- **Claim:** the statements derivable from a receipt are separable into named classes, and the code
  keeps them separate rather than collapsing them into one verdict.
- **Non-claim:** that the class set is complete, or that the separation has been shown to be the
  *right* one. Twelve classes are proposed in the note; the tree does not carry twelve.
- **Evidence in tree:** `src/proofbundle/assurance.py` (231 lines) · `tests/test_assurance.py`
  (193 lines) · `SPEC.md` (787 lines).
- **State of external review:** `NOT MEASURED`. No external party has reviewed the class separation.

### C2 — Portable AI eval evidence

- **Claim:** an evaluation result can be emitted as a receipt that a third party verifies offline,
  without the model or the dataset.
- **Non-claim:** that the receipt says anything about the *semantic truth* of the evaluation. It
  binds authorship and integrity, not correctness — and that limit is stated in the shipped text.
- **Evidence in tree:** `src/proofbundle/evalclaim.py` (618 lines) · `tests/test_evalclaim.py`
  (224 lines) · `src/proofbundle/emit.py` (143 lines) · `paper.md` (129 lines).
- **State of external review:** `NOT MEASURED`. The in-toto predicate PR is open and unmerged; no
  unmodified external consumer has been measured against it.

### C3 — Verifier assurance

- **Claim:** the defect classes a verifier claims to catch can be shown empirically to be caught —
  by planted defects, mutation, negative conformance vectors and a never-raise contract.
- **Non-claim:** that the measured detection rate generalises to *unknown* attacks. A planted defect
  proves sensitivity to its own class and to nothing beyond it.
- **Evidence in tree:** `conformance/run_conformance.py` (874 lines) · `scripts/mutation_check.py`
  (1273 lines) · `tests/test_never_raise_surface_family_property.py` (654 lines) ·
  `tests/test_rust_parity_gate.py` (462 lines) · `THREAT_MODEL.md` (160 lines).
- **State of external review:** `NOT MEASURED`. The strongest candidate of the six by volume of
  evidence, and the one with no external reading at all.

### C4 — Evidence evolution

- **Claim:** a later change of knowledge can be expressed without mutating a historical receipt —
  through typed relations rather than edits.
- **Non-claim:** that the relation vocabulary is complete, or that consumers are obliged to follow
  it. A relation a reader ignores changes nothing for that reader.
- **Evidence in tree:** `src/proofbundle/relation.py` (758 lines) ·
  `tests/test_relation_profile.py` (736 lines) · `src/proofbundle/renewal.py` (1178 lines).
- **State of external review:** `NOT MEASURED`.

### C5 — Multi-party evidence

- **Claim:** attestations by parties other than the producer change what a receipt supports, and the
  code keeps the parties distinguishable.
- **Non-claim:** that more signatures mean a stronger statement. Which combinations actually
  strengthen a claim is exactly the open question; the tree carries the mechanism, not the model.
- **Evidence in tree:** `src/proofbundle/public_transparency.py` (343 lines) ·
  `src/proofbundle/checkpoint.py` (1065 lines) · `src/proofbundle/trust_pack.py` (648 lines) ·
  `src/proofbundle/experimental/attested_inference.py` (334 lines).
- **State of external review:** `NOT MEASURED`.

### C6 — Coverage

- **Claim:** a verifier can distinguish *fully checked*, *partially checked* and *not checked at
  all*, and can say which of the unchecked remainder is deliberately out of scope.
- **Non-claim:** that this distinction is available in the shipped tree today. It is not.
- **Evidence in tree:** **NOT MEASURED at `origin/main`.** `src/proofbundle/cap1.py`,
  `tests/test_cap1_regeln.py` and `tests/test_cap1_im_predicate.py` exist **only** on the unmerged
  branch `feat/cap1-abdeckung` (`bda71b2158b08e78e678940acea4f63ebe6bbece`); measured 2026-09-12,
  that head is **not** an ancestor of `origin/main`. A claim resting on an unmerged branch is not a
  claim about the tree.
- **State of external review:** `NOT MEASURED`.

### What the six lines say together

**Six candidates, six times `NOT MEASURED` for external review.** Five have substantial evidence in
the tree; one (C6) has none at the measured head. The volume of code is not the finding here — the
finding is that nothing in this list has been read by anyone outside this project, and that is a
single, nameable gap rather than six separate ones.
