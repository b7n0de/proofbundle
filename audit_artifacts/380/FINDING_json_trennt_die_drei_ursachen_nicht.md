# Finding — the machine path still cannot tell three different failure causes apart

**Status: open, not fixed in 3.8.0, and deliberately so.** The fix is a new public output field, and a
new public output surface is not something to add under release pressure. It is recorded here rather
than left in a commit message because a known gap without a written record becomes a legend.

**Superseded claim.** The commit that introduced `expected_origin` into the `--json` output, and the
first version of the test class `DasVerdiktNenntDieErwartungAuchMaschinell`, both read as if this
gap were closed by that field. It is not. The correction is the substance of this file.

## What was measured

**Corrected 2026-08-16 after a second counter-read: the first version of this section claimed too
much, and the correction narrows the finding rather than widening it.** It said all three causes are
byte-identical "with `--expected-origin` set". That holds only for one particular way of setting it —
the way the original measurement happened to use.

Both constructions, measured against the frozen `markovianprotocol.com/log` leaf-7271 fixture, with
the positive control run first so the harness is known to produce a passing verdict:

| Construction | foreign origin | wrong `--log-vkey` | tampered signature |
|---|---|---|---|
| **A** — all three runs pin the *same foreign* origin | `d4d6a953ea033c72` | `d4d6a953ea033c72` | `d4d6a953ea033c72` |
| **B** — pin the origin one actually trusts (the documented use) | `cee36aea781d760b` | `a0f6b7c4f659e397` | `a0f6b7c4f659e397` |

In construction A all three collapse — but there `log_ok` is already false *because of the pinned
origin*, in every run. The identity is real and says nothing about the three causes.

**Construction B is the one that matters, and it is the honest form of this finding:** a relying
party pins the origin it trusts. Then a foreign origin **is** machine-readable — `expected_origin`
differs from `origin` — and the collapse is between **wrong key** and **tampered signature**, which
produce byte-identical output. That is a two-into-one collapse, not three-into-one.

The corrected claim is therefore narrower and still real: `expected_origin` echoes the verifier's own
input, so it adds a fact about the *question*, never about the *answer*. It separates the one cause
that is visible in the question (a pinned origin that does not match) and cannot separate the two
that are not.

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
`tests/test_verify_proof_expected_origin.py::test_falscher_schluessel_und_verfaelschte_signatur_bleiben_ununterscheidbar`
asserts the *measured* state. If a later change really does separate the causes, that test goes red
and forces this file to be closed rather than forgotten. Its sibling
`test_der_fremde_origin_ist_bei_richtigem_pin_sehr_wohl_lesbar` pins the other half — the part that
**is** readable — so the finding cannot silently grow back into the over-wide form it started as.

**Both of those guards replaced one that measured nothing, and how it failed is worth recording.**
The first version compared "foreign origin" against "tampered signature" with the *same foreign*
origin pinned in both — construction A above, where the identity holds for an unrelated reason. And
its "tampered signature" was not one: the helper picked the last line matching `— <origin> `, and the
fixture has **two** such lines (index 18, length 120 — the log's note signature; index 28, length
3272 — a witness cosignature under the same name). It corrupted the second, which leaves `log_ok`
true. A counter-read felled it decisively by handing the test a **byte-identical** copy: still green.
The helper now selects by **measured effect** rather than by position or shape — it returns only a
copy for which `log_ok` actually flips — and the test asserts that flip before comparing anything.

## CLOSED 2026-08-16 — `signer_present`

**This was a different kind of gap from the others in this record, and the difference is the whole
point.** Everywhere else the information existed and was dropped one layer before the output. Here
it looked as though it did not exist at all: a signature check is a **two-input predicate**, and a
mismatch does not attribute blame to either input. The verifier cannot know whether the key is
wrong or the signature is.

**The key ID can.** A C2SP signature line carries the signer's key ID. If no line in the note
carries the ID of the supplied vkey, that key did not sign this note; if one does and the check
still fails, the bytes do not match. `verify_checkpoint` made exactly that distinction inside its
loop — `kid != kid_v` means *this line is not for your key* — and collapsed it into a single
`ok=False`.

Measured, with the good run as the control:

```
guter Lauf              ok=True   log_ok=True   signer_present=True
falscher Schluessel     ok=False  log_ok=False  signer_present=False
verfaelschte Signatur   ok=False  log_ok=False  signer_present=True
```

The two outputs are no longer byte-identical. Rollback probes: never setting the flag turns four
guards red, wiring it to a constant `True` turns three red, and dropping the JSON key turns five
red; the baseline returns exactly.

**The guard that predicted its own replacement.** `test_falscher_schluessel_und_verfaelschte_signatur_bleiben_ununterscheidbar`
pinned the collision as a *measured state* and carried the message: "if these become
distinguishable — good! then the finding is closed and this guard belongs replaced by a positive
assurance." It went red the moment the flag landed, and it now asserts the separation instead of
observing the collision. That is the difference between pinning a gap and pinning a property: the
first **must** go red when the work is done, or it holds an old state after it has stopped being
true.

**HONEST LIMIT, and it is not a weakness of the field.** A tamper that hits exactly the four keyID
bytes is indistinguishable from a wrong key — at that point the note carries no evidence that this
key ever signed. That is a true statement about the situation, not a measurement error.
