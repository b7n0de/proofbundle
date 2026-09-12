# Research program

**What this file is.** A measurement sheet, not a prospectus. Every line either names a path in the
tree at a named head, or says in one of three words why it does not: `NOT MEASURED`,
`NOT MEASURABLE` with a reason, `NOT APPLICABLE` with a reason. A claim without a path is not a
claim here.

**What this file is not.** It is not a plan, not a promise, and not a positioning statement. The
external note that prompted it (`kraxo/02_proofbundle_berichte/WISSENSCHAFTLICHE_EINORDNUNG_extern_20260912/`,
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
- **State:** **MEASURED, partially** — the only thesis with evidence in the tree today.

  | Path (head `4e32e83b647235bfedf23b55cebe69fdf14fd6f5`, tag `v6.0.0`) | Lines | What it measures |
  |---|---|---|
  | `tests/test_relation_statement_rust_parity.py` | 53 | `test_crosscheck_relation_differential_green` — the Python↔Rust differential **agrees**, on the relation surface |
  | `tests/test_rust_parity_gate.py` | 462 | the **honesty of the coverage bookkeeping**: a claimed subcommand missing from `main.rs` or from the built binary is `stale`, an untracked Python verify function is `untracked`, an orphaned registry entry is `orphaned` |

  Measured run, both files: **23 passed, 1 skipped**.

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
