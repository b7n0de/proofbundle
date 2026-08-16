# Finding — the machine path still cannot tell three different failure causes apart

**Status: open, not fixed in 3.8.0, and deliberately so.** The fix is a new public output field, and a
new public output surface is not something to add under release pressure. It is recorded here rather
than left in a commit message because a known gap without a written record becomes a legend.

**Superseded claim.** The commit that introduced `expected_origin` into the `--json` output, and the
first version of the test class `DasVerdiktNenntDieErwartungAuchMaschinell`, both read as if this
gap were closed by that field. It is not. The correction is the substance of this file.

## What was measured

A delta counter-read on 2026-08-16 ran the three causes against the frozen `markovianprotocol.com/log`
leaf-7271 fixture, **with** `--expected-origin` set, and hashed the JSON:

| Cause | with `--expected-origin` | without |
|---|---|---|
| foreign origin | `sha=d4d6a953ea033c72` | distinct |
| wrong `--log-vkey` | `sha=d4d6a953ea033c72` | identical to (3) |
| tampered signature in the proof | `sha=d4d6a953ea033c72` | identical to (2) |

All three are byte-identical with the flag set. The reason is simple once stated: `expected_origin`
echoes **the verifier's own input**, which is the same string in all three runs. It adds a fact about
the question, not about the answer.

Without the flag, cause (1) does separate from (2)/(3) — because `log_ok` flips for a different
reason — but (2) and (3) remain identical to each other. So the count was never three-to-one; it was
at best one-to-two, and with the flag set it is one-to-one-to-one collapsed into a single output.

## Why the first record got it wrong

The measurement that produced the original claim compared "foreign origin" against "no expectation
given". Those two were **never** identical, before or after the change: `log_ok` differs. Measuring a
pair that was already distinct and reporting it as evidence that a previously-indistinguishable set is
now distinguishable is the class this release has hit repeatedly — a number measured over one
population and reported over another. The test that carried the claim was green at the state *without*
the fix, which is the executable form of the same error.

## The class

- **class_id:** `field_echoes_the_query_and_is_read_as_separating_the_answers`
- **invariant:** a field that reports what the caller asked cannot distinguish why the answer is no.
  Distinguishing causes requires a field derived from the *evaluation*, not from the *input*.
- **surface_family_query:** every `--json` verdict surface that reports a boolean `*_ok` whose false
  value has more than one possible cause.
- **oracle_predicate:** produce two distinct causes for the same false flag; if the JSON is
  byte-identical, the surface does not separate them.
- **outcome:** `class_open` — recorded, not closed.

## What holds

The narrower property is real and is now the one the test asserts: the JSON distinguishes **asked**
from **not asked** (`null` versus the value), and the two runs are otherwise identical field for
field. The text path does separate cause (1) via `(expected …)`. Neither of those was true before.

## Honest boundary

This finding says nothing about whether the verdict itself is correct — it is, and `ok=False` is
reached in all three cases. What is missing is *legibility of the reason on the machine path*. A
relying party that automates on the JSON can tell that verification failed and cannot tell whether to
suspect its own configuration (wrong key, wrong origin pinned) or the artifact (tampered signature).

A guard is in place so this cannot quietly heal into a legend either way:
`tests/test_verify_proof_expected_origin.py::test_die_drei_ursachen_bleiben_ununterscheidbar` asserts
the *measured* state. If a later change really does separate the causes, that test goes red and forces
this file to be closed rather than forgotten.
