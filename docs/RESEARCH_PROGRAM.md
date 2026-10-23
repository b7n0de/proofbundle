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
- Measurement head: **tag `v6.3.1` = `07b6122cd59b7cccee6cd4d59fb8eda28aec1991`**, every line re-measured
  there on 2026-10-23, unless a line says otherwise. The first measurement, on 2026-09-12, was at
  `origin/main` = `27c17fcf2d5a42dd8949c94337065cc89f346a39`. By owner decision every line is measured
  again at the release head; the six `NOT MEASURED` lines for external review stay as they are.
- Model: Claude Opus 5 (1M context) for the first measurement, Claude Opus 5.5 for the re-measurement

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
- **State:** `NOT MEASURED`. Candidate surfaces exist at `07b6122c` (`policy_decision` stays `None`
  without a named policy; `safeForAutomation` is a separate field), but no measurement binds the two
  into one falsifiable case in this tree.

### T2 — Evidence strength must be modelled along independent axes instead of collapsing into a single trust score

- **Deciding measurement:** show two receipts that are equal on one axis and differ on another, and a
  consumer that distinguishes them. Then show that any single scalar ordering loses one of the two.
- **State:** `NOT MEASURED`. The axes exist in the code at `07b6122c` (four separate time axes in
  `verify_agent_review_v02`, `src/proofbundle/agent_review.py`: event, observation, signature and
  external time status), but the *loss* a scalar would cause is not measured.

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
- **State:** **NOT MEASURED** in the first run cited below, and this correction is the point:
  the aggregate `23 passed, 1 skipped` hid which test was skipped, and the skipped one is
  the only one that measures agreement. The thesis has the most machinery of any here, but
  machinery is not a measurement.

  | Path (head `07b6122cd59b7cccee6cd4d59fb8eda28aec1991`, tag `v6.3.1`) | Lines | What it measures |
  |---|---|---|
  | `tests/test_relation_statement_rust_parity.py` | 59 | `test_crosscheck_relation_differential_green` — the Python↔Rust differential on the relation surface. It takes the binary through `tests/_pb_verify_rs.py`, which builds `tools/pb_verify_rs` itself when a cargo that can build it is on the path, and skips with the reason otherwise |
  | `tests/test_rust_parity_gate.py` | 487 | the **honesty of the coverage bookkeeping**: a claimed subcommand missing from `main.rs` or from the built binary is `stale`, an untracked Python verify function is `untracked`, an orphaned registry entry is `orphaned` |

  Measured at `v6.3.1` on 2026-10-23, both files, each on a fresh checkout without a build:

  | cargo on the path | Result | What happened |
  |---|---|---|
  | the pinned toolchain, cargo 1.95.0 | **25 passed, 0 skipped** | the seam built the binary itself, and the differential ran |
  | the system cargo 1.75.0 of the measuring machine, which cannot read lock file version 4 | **24 passed, 1 skipped** | `cargo build --release` failed with exit 101, and the skip of `test_crosscheck_relation_differential_green` names that reason |

  A run without any cargo on the path is `NOT MEASURED` here; by the seam's code it skips the same case
  with the reason `cargo is not on PATH`.

  First measured at `4e32e83b647235bfedf23b55cebe69fdf14fd6f5` (tag `v6.0.0`), where the two files
  had 53 and 462 lines: on a standard checkout **23 passed, 1 skipped**, the skip being
  `test_crosscheck_relation_differential_green` with the reason `pb_verify_rs not cargo-built`, and
  after `cargo build --release` with the pinned toolchain 1.95.0 **24 passed, 0 skipped**. The
  agreement held when it was actually run. What was missing was the evidence, not the property —
  and an aggregate that does not name its skip cannot tell those two apart.

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
- **State:** `NOT MEASURED`. The in-toto predicate PR, in-toto/attestation#575, is open and unmerged,
  measured through the GitHub API on 2026-10-23; no measurement of an **unmodified external consumer**
  exists in this tree.

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
tag `v6.3.1` = `07b6122cd59b7cccee6cd4d59fb8eda28aec1991`, measured on 2026-10-23, unless the line
says otherwise; the line counts below are those of that head.

**The non-claim line is not decoration.** Every one of these candidates has a neighbouring statement
that the evidence does *not* support, and naming it is what keeps the claim falsifiable.

### C1 — Evidence taxonomy

- **Claim:** the statements derivable from a receipt are separable into named classes, and the code
  keeps them separate rather than collapsing them into one verdict.
- **Non-claim:** that the class set is complete, or that the separation has been shown to be the
  *right* one. Twelve classes are proposed in the note; the tree does not carry twelve.
- **Evidence in tree:** `src/proofbundle/assurance.py` (429 lines) · `tests/test_assurance.py`
  (254 lines) · `SPEC.md` (884 lines).
- **State of external review:** `NOT MEASURED`. No external party has reviewed the class separation.

### C2 — Portable AI eval evidence

- **Claim:** an evaluation result can be emitted as a receipt that a third party verifies offline,
  without the model or the dataset.
- **Non-claim:** that the receipt says anything about the *semantic truth* of the evaluation. It
  binds authorship and integrity, not correctness — and that limit is stated in the shipped text.
- **Evidence in tree:** `src/proofbundle/evalclaim.py` (1267 lines) · `tests/test_evalclaim.py`
  (229 lines) · `src/proofbundle/emit.py` (166 lines) · `paper.md` (129 lines).
- **State of external review:** `NOT MEASURED`. The in-toto predicate PR is open and unmerged
  (in-toto/attestation#575, measured 2026-10-23); no unmodified external consumer has been measured
  against it.

### C3 — Verifier assurance

- **Claim:** the defect classes a verifier claims to catch can be shown empirically to be caught —
  by planted defects, mutation, negative conformance vectors and a never-raise contract.
- **Non-claim:** that the measured detection rate generalises to *unknown* attacks. A planted defect
  proves sensitivity to its own class and to nothing beyond it.
- **Evidence in tree:** `conformance/run_conformance.py` (1337 lines) · `scripts/mutation_check.py`
  (2351 lines) · `tests/test_never_raise_surface_family_property.py` (783 lines) ·
  `tests/test_rust_parity_gate.py` (487 lines) · `THREAT_MODEL.md` (167 lines).
- **State of external review:** `NOT MEASURED`. The strongest candidate of the six by volume of
  evidence, and the one with no external reading at all.

### C4 — Evidence evolution

- **Claim:** a later change of knowledge can be expressed without mutating a historical receipt —
  through typed relations rather than edits.
- **Non-claim:** that the relation vocabulary is complete, or that consumers are obliged to follow
  it. A relation a reader ignores changes nothing for that reader.
- **Evidence in tree:** `src/proofbundle/relation.py` (1172 lines) ·
  `tests/test_relation_profile.py` (738 lines) · `src/proofbundle/renewal.py` (1490 lines).
- **State of external review:** `NOT MEASURED`.

### C5 — Multi-party evidence

- **Claim:** attestations by parties other than the producer change what a receipt supports, and the
  code keeps the parties distinguishable.
- **Non-claim:** that more signatures mean a stronger statement. Which combinations actually
  strengthen a claim is exactly the open question; the tree carries the mechanism, not the model.
- **Evidence in tree:** `src/proofbundle/public_transparency.py` (454 lines) ·
  `src/proofbundle/checkpoint.py` (1275 lines) · `src/proofbundle/trust_pack.py` (1018 lines) ·
  `src/proofbundle/experimental/attested_inference.py` (410 lines).
- **State of external review:** `NOT MEASURED`.

### C6 — Coverage

- **Claim:** a verifier can distinguish *fully checked*, *partially checked* and *not checked at
  all*, and can say which of the unchecked remainder is deliberately out of scope.
- **Non-claim:** that this distinction is available in the shipped tree today. It is not.
- **Evidence in tree:** present at `07b6122c` (tag `v6.3.1`), re-measured 2026-10-23.
  `src/proofbundle/cap1.py` (19925 B), `tests/test_cap1_regeln.py` (9905 B) and
  `tests/test_cap1_im_predicate.py` (11230 B) are all three in that tree. On 2026-09-19 they were
  re-measured on `main` at `d0afab0adfc1f61f650cf46436e7eb67af769f7b` with 16386 B, 5613 B and
  11230 B. The reading of 2026-09-12 said they existed **only** on the unmerged branch
  `feat/cap1-abdeckung`, and that reading was correct on its day.
  One detail of how they arrived is worth keeping, because it would otherwise read as a merge that
  never happened: the branch head named then, `bda71b2158b08e78e678940acea4f63ebe6bbece`, is still
  **not** an ancestor of `v6.3.1` (measured 2026-10-23: diverged, the tag 1031 ahead and 9 behind).
  The work landed by another route, not by merging that commit. A branch of that name exists again on
  the remote, at `4b0b450a`; on 2026-09-19 it was gone.
  What is **not** measured here: whether the distinction the claim describes actually works in the
  shipped tree. This line says the files are there, at a named head, and nothing more.
- **State of external review:** `NOT MEASURED`.

### What the six lines say together

**Six candidates, six times `NOT MEASURED` for external review.** All six now have evidence in the
tree; C6 was the exception until `cap1` landed, and its line was re-measured on 2026-09-19 and again at `v6.3.1` on 2026-10-23. The volume of code is not the finding here — the
finding is that nothing in this list has been read by anyone outside this project, and that is a
single, nameable gap rather than six separate ones.
