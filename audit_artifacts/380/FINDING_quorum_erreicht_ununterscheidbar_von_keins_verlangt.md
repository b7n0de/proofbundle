# Finding — `witnesses_ok: true` with zero confirming witnesses, and no way to tell why

**Pre-existing (`main`). Reported first, then CLOSED IN THIS RELEASE** under the Owner's
instruction that all gaps be closed inside 3.8.0. The classification does not change — its subject
exists at `v3.7.0`, so it stays an Altbefund in the index count — but its state does. The section
"Why it is not fixed in this release" is kept below, because its stated reason ("a third change to
the output shape in one release") was overtaken by events rather than being wrong: the third change
had already been made and announced by the time this was closed, so the argument no longer applied.

`verify-proof` and its `--threshold` default predate 3.8.0. Recorded because a lens on the 3.8.0
candidate surfaced it and because it is the same *shape* as the gap this release closed.

**Nothing in this file asserts that a pre-tag audit ran.**

## Measured

Against the frozen `markovianprotocol.com/log` leaf-7271 fixture, with a live control at the end so
an always-true reading would be visible:

| Run | `ok` | `witnesses_ok` | confirming witnesses | exit |
|---|---|---|---|---|
| default (`--threshold` omitted, no witness keys) | true | **true** | **0** | 0 |
| one witness key supplied | true | true | 1 | 0 |
| `--threshold 4`, five witness keys | true | true | 5 | 0 |
| `--threshold 9` (unfulfillable) — the control | false | false | — | 1 |

The control flips, so the measurement is not vacuous.

**`threshold` does not appear in the `--json` output.** The nine reported keys are `ok`, `log_ok`,
`witnesses_ok`, `inclusion_ok`, `origin`, `tree_size`, `index`, `witnesses`, `expected_origin`.

## What that means for a consumer

`witness_quorum` returns `len(confirmed) >= threshold`, and with the default `threshold=0` that is
true unconditionally. So a program reading `witnesses_ok` sees the same `true` for

- **a quorum that was demanded and met**, and
- **a quorum that was never demanded at all**,

and there is no field in the output that separates them. Counting `witnesses` does not settle it
either: zero confirming witnesses is a legitimate state under `threshold=0`, and the same zero under
a demanded threshold would have made `witnesses_ok` false — but by then the field is already gone.

**The verdict is correct.** `threshold=0` means no witness requirement, and `ok=true` on a proof
whose log signature and inclusion both verify is the right answer. What is missing is not a defence
but the *legibility* of the answer on the machine path — exactly the shape of the gap 3.8.0 closed
for the origin, one field over.

The human path is better off but not clean: it prints
`[PASS] witness-quorum: N valid of M known (threshold T)`, which does name the threshold. A relying
party automating on `--json` gets less than one reading the terminal.

## The class

- **class_id:** `boolean_verdict_true_because_nothing_was_required_reads_as_true_because_something_was_met`
- **invariant:** a reported boolean whose truth can come either from a satisfied requirement or from
  an absent requirement must ship the requirement alongside it, or the boolean is not a verdict.
- **surface_family_query:** every `*_ok` field in a `--json` verdict whose computation includes a
  configurable bound (threshold, minimum, expiry window, required count).
- **oracle_predicate:** set the bound to its permissive extreme and produce the weakest possible
  evidence. If the field is still `true` and no other field records the bound, the two cases are
  indistinguishable.
- **outcome:** `class_closed` — the bound now ships with its boolean.

## How it is closed, and the family sweep that came with it

`verify-proof --json` carries `threshold`, always present because it always has a value. That is
enough: with the bound alongside, counting `witnesses` settles the question the boolean alone could
not. The human path already named it (`threshold {T}`), so this removes an asymmetry rather than
inventing a field — a relying party automating on `--json` no longer gets less than one reading the
terminal.

**The family was measured, not guessed.** The class is "every `*_ok` in a `--json` verdict whose
computation includes a configurable bound", and the population is every value-taking CLI flag:

| Flag | Feeds | State |
|---|---|---|
| `--threshold` | `witnesses_ok` | **the member** — bound was entirely absent from the output |
| `--expected-tree-size` | `treeSizeExpectation` | already in the rich `status`/`expected`/`actual` form |
| `--verification-time` | `policy_ok` | appears in the JSON once set; its absence means "now", which is a different requirement, not an absent one |
| `--n` / `--k` (`verify-opening`) | opening verdict | required arguments — there is no absent-requirement case to confuse |

One member, and it is this one. Rollback probes: removing the key turns three guards red; wiring it
to a constant `0` — which *looks* filled — turns one red. The baseline returns to exactly 27 passed.

## Why it was not fixed in this release — the reasoning at the time, overtaken

Adding `threshold` to the JSON is a third change to the output shape in one release, and this
release already had to correct its own CHANGELOG twice for understating how many there were. The
right place is a release that announces it. `verify-proof` is not in the shipped delta except for
the origin flag, so this is a `main` finding under the rule this release follows.

## Honest boundary

Whether any consumer is actually misled is not measured here — that depends on whether anyone
automates on `witnesses_ok` without also pinning `--threshold` themselves, which a repository
measurement cannot see. What is measured is that the output does not let them tell.
