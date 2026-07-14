# Run Ledger predicate `run-ledger/v0.1`

Status: EXPERIMENTAL in proofbundle 3.2.0 (vendored under the b7n0de namespace; API and wire format may change
without deprecation). A Run Ledger is a signed, tamper-evident history of every run of a study — completed,
aborted, or failed — built specifically to defeat **best-of-many cherry-picking**: you cannot silently run an
eval twenty times and publish only the good one, because the ledger makes the dropped runs' absence detectable.

Schema: [`schemas/run-ledger-v0.1.schema.json`](../../schemas/run-ledger-v0.1.schema.json) (docs-only; the
executable contract is `src/proofbundle/run_ledger.py`).

## 1. Purpose

It answers: *how many runs of this study happened, in what order, with what result each, and against what
budget declared up front.* A single published eval receipt says nothing about how many attempts preceded it; a
Run Ledger binds the published result to a complete, ordered, gap-free history.

## 2. Non-goals

It does **not** prove the runs were fair, the study well-designed, or the results meaningful — only that this
is a complete monotone chain with no silently dropped runs, within a pre-declared budget. `nonClaims` records
that.

## 3. Fields

| field | required | meaning |
|---|---|---|
| `schemaVersion` | yes | `0.1.0` |
| `studyId` | yes | stable id of the study |
| `runBudget` | yes | integer ≥ 1 declared UP FRONT (runs may not exceed it) |
| `runs` | yes | ordered array of `{seq, status, resultDigest, prevDigest, startedAt?, note?}` |
| `nonClaims` | yes | mandatory No-Overclaim block |

Per run: `status` ∈ `completed` / `aborted` / `failed` (aborted/failed runs are KEPT VISIBLE, never dropped),
`resultDigest` (content root of that run's result), `prevDigest` (links the previous run).

## 4. Ledger invariants (enforced at validate time, fail-closed)

- `seq` starts at 1 and is **strictly monotone with no gaps** — a missing seq is a dropped run.
- the first run's `prevDigest` is `null`; every later run's `prevDigest` **equals the previous run's
  `resultDigest`** (the chain — a silently removed run breaks the digest link and is detectable).
- runs never exceed `runBudget`.

`link_runs()` builds a correct chain; `verify` surfaces `chain_intact` and `within_budget`. A best-of-many
selection that drops the bad runs cannot produce an intact chain — that is the whole point.
