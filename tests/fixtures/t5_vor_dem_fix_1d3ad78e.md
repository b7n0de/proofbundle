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
