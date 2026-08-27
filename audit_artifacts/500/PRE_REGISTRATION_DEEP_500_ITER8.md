# Pre-registration — DEEP 6L/7I, release 5.0.0, **iteration 8**

Frozen 2026-08-26T12:05:30Z, BEFORE anything ran (the iteration-8 section of the run record may
only cite what is fixed here).

## Why an eighth

Iteration 7 returned **`FIX_FIRST`** on `d8ec901` with one confirmed finding,
`L3-500-DSSEB64-02`. The Owner decided (`OA-2591904f69`, 2026-08-26) to fix it **in 5.0.0 as a
class over all lax sites**, and that fix is `d478882`. A verdict binds to exactly one digest, so
the re-gate runs over the new one and gets its own frozen document. E1–E12 are reproduced verbatim
from [PRE_REGISTRATION_DEEP_500_ITER7.md](PRE_REGISTRATION_DEEP_500_ITER7.md); **E9 is again
untouched, word for word**; E13 is new and grades the fix itself.

## The graded object

```
graded commit      d4788826be69e6b868c1ef0125b1b71fa8bb4ca0   (release/v5.0.0, worktree clean)
graded src tree    f5148088bc1c4e87ba7e9d7386ba65e38d2e7e6d
mode               [DEEP-GATE: DEEP 6L/7I]   (MAJOR / external release)

anti-parity oracle 89d4fb90ca395f59843aa840910dbb7c4cda635a   (= tag v4.0.0)
oracle src tree    8c124b527ede58fa6333a09d38704588095b976d
                   commit and tag identical, src trees identical, both re-measured this round;
                   driven over PYTHONPATH without installation, so 4.0.0 and 5.0.0 import
                   side by side in one minimal environment
```

The oracle is named with its tree digest here rather than only in prose — the requirement from the
field form of `OA-402697f73e`, which the iteration-7 document met only by half.

```
never graded by any iteration   9bc179e..d478882    11 commits
                                under src/:         24 files, 413 insertions, 57 deletions

the fix itself                  d8ec901..d478882    16 files, 137 insertions, 39 deletions

what the PR moves               origin/main..d478882   15 commits  (FAST-FORWARD, re-measured)
                                under src/:         28 files, 563 insertions, 70 deletions

what the TAG will cover         v4.0.0..d478882     33 commits
                                under src/:         30 files, 743 insertions, 91 deletions
                                overall:            89 files, 3567 insertions, 170 deletions
```

## Two declared findings, and exactly how they bind the verdict

Both are named, reproduced and deliberately deferred **before** this run. Fixing the wording after
seeing a lens report would be the failure this whole sequence exists to avoid.

**(a) `capture_mechanism` accepts any string into signed evidence** — deferred to 5.1.0 by Owner
decision, because `capture` is a call parameter of a **public** adapter function and fencing it
changes acceptance behaviour on a public surface. Finding
`CAPTURE-MECHANISM-NIMMT-JEDEN-STRING-DER-NACHBAR-ERZWINGT-SEINE-MENGE-01`, P3.

**(b) `decode_b64url` also accepts `+` and `/`** — `altchars` translates before validating, so a
character of the other alphabet passes. Same FAMILY as the finding just fixed, **different
property**: that one was "characters outside every alphabet", this one is "one alphabet per field".
The gate measured the first and not the second, and folding it in would widen a gated change beyond
what was measured. Finding
`B64URL-AKZEPTIERT-BEIDE-ALPHABETE-EINE-ZWEITE-KANONIKALITAETSFRAGE-01`, P3, written out in the
module docstring so it reads as a decision rather than an oversight.

**The binding, fixed here and not afterwards:**

1. A refutation of **E9 at exactly instance (a)** is EXPECTED and does **NOT** withhold
   `WITHSTANDS_DEEPGATE`.
2. A refutation of **E13 at exactly instance (b)** is EXPECTED and does **NOT** withhold it.
3. **Any OTHER refutation of E9 or E13 DOES withhold the verdict.** The exemption covers two
   measured instances, not two targets.
4. **Neither target may be narrowed** so its declared instance falls out. Both stand in the wording
   under which they were written.
5. The run record and the release recommendation carry both as **open P3**.

## Falsification targets

E1–E12 verbatim from the iteration-7 pre-registration; **no wording changed**. Reproduced as text
rather than by reference, so this verdict does not hang on an older document.

| # | Target | Falsified by |
|---|---|---|
| E1 | **The cap removes work, not acceptance.** Running the `merkle_path` cap before the decoding it bounds changes no verdict. | a proof/bundle/sample-opening input whose verdict DIFFERS between v4.0.0 and this tree — in either direction |
| E2 | **Exactly TWO externally observable contracts change, and they are the two the CHANGELOG names as MAJOR triggers** (exit 2 → exit 1 for one input class; the Inspect hook and pytest plugin stop emitting without `PROOFBUNDLE_THRESHOLD`). No third moved unnoticed. | any other input class whose exit code differs from v4.0.0; any other externally observable contract that differs and is not one of these two; or either named change not actually occurring |
| E3 | **`expected_origin_wellformed` is purely additive.** | a pin value for which `inclusion_ok` differs from v4.0.0; the new field raising; or a fail-closed path omitting it despite the "every invocation" claim |
| E4 | **Nothing loosens an existing check; every shipped external vector keeps its verdict.** | a Go-sumdb / Rekor / rootcommit / Colin vector whose verdict changed, or an input refused before and accepted now |
| E5 | **The two fail-closed additions refuse only unusable states.** | a producer call that worked under 4.0.0, produced something a verifier ACCEPTED, and is refused now |
| E6 | **The record's and CHANGELOG's numbers and claims match the tree**, including the MAJOR justification and the `SPEC.md` citation. | a claimed count / file / line a fresh measurement contradicts; or a citation that does not say what the record says it says |
| E7 | **The threshold obligation refuses only the vacuous verdict.** Unset → both integrations skip emission with a clear message, no raise. Set → byte-equivalent to 4.0.0 for the same run. | a receipt emitted with the variable unset; the skip path raising; a run WITH it set whose receipt differs from 4.0.0 in a field this release does not claim to change; or a third code path still defaulting to `"0"` |
| E8 | **`--expect-issuer` is opt-in, backwards compatible, and compares the VERIFIED signer.** | `show-eval` without the flag differing from 4.0.0; the forgery passing WITH a pin; the comparison reading an unverified field; a repeated flag not behaving as the documented union; or a mismatch exiting anything but 1 |
| E9 | **The other two gaps of `d9913a6` are additive and invent nothing.** `capture_mechanism` takes one of exactly three named values; the lm-eval adapter binds `harness_version` only from `lm_eval_version`. No 4.0.0 receipt becomes invalid. | a 4.0.0-produced receipt now rejected; `capture_mechanism` taking or accepting a value outside the three; `harness_version` on an lm-eval receipt whose results file carries none; or the published claim schema having moved |
| E10 | **The reported-version status is additive, never derived, and its verifier judges only its own class.** | a legacy receipt rejected; a finding on a non-member field; a value invented into a version field; a writer output its own verifier rejects; a non-dict or mixed-key provenance raising; `not_reported` folding to PASS; writer and verifier disagreeing about the member set |
| E11 | **Cross-adapter version binding is symmetric and still honest.** | `harness_version` written when promptfoo reported none; `promptfoo_version` dropped; or a fourth adapter still asymmetric |
| E12 | **The iteration-6 fix changed no behaviour.** | any output, verdict, exit code or provenance field differing between `6065815` and `d8ec901` for the same input; or a new test that passes for a reason other than the one it names |

**E13 is new, and it grades the fix that this iteration exists because of.** A fix is not exempt
from the gate that demanded it — the ledger already shows this exact class surviving one closure.

| # | Target | Falsified by |
|---|---|---|
| E13 | **Wire decoding is total-or-reject across the whole family, and the narrowing refuses only what was never conforming.** For any artefact a public verify accepts, no single-character non-alphabet insertion, whitespace substitution or extra-padding perturbation of any base64-typed field yields an accepting verdict unless the bytes are identical. And, in the other direction: **every input that a conforming producer could make under 4.0.0 still decodes** — padding tolerance is unchanged, only junk is refused. | any perturbed artefact still accepted on any exported `verify_*`/`load_*` or CLI verify subcommand; **or** a 4.0.0-produced artefact, fixture or conformance vector that this tree now refuses (a narrowing beyond the measured property); or a remaining decode of an attacker-supplied base64 field that does not go through the named strict helper; or the property test passing while a planted lax fallback is present |

## Standing regression targets

RT-01..RT-08 apply unchanged and are not removable. RT-01..RT-04 are attacked again against the
moved tree.

## Method (fixed here)

Six lenses — correctness · No-Fake · adversarial · SOTA · regression · fidelity — each attempting
to **REFUTE** with an executable probe. Negative state including **absent**. Minimal environment,
as shipped, without the `[experimental]` / `[pq]` extras. Ledger replay first; one red learned
class aborts the round, and this round reports its own coverage rather than inheriting one.

**Gate-meta-test, of the E13 class specifically:** planting the lax fallback back into the strict
helper must turn the corpus red, and the same run must be green before and green again after a
byte-identical restore. Measured in the fix round as green (5 passed, 18 subtests) → red (15
failed) → green; iteration 8 re-runs it rather than citing that measurement.

**Anti-parity, non-negotiable:** every probe first asserts that the clean form is ACCEPTED. Without
it, a decoder that refuses everything satisfies every other assertion — which is the exact shape in
which a strictness fix goes wrong.

## Declared NOT RUN

```
mutation_check                  not run  — multi-hour job, measured 2.2–2.4 h
fuzz_soak (full 24 h)           not run
readiness_pack_manifest --check not run
Rust wire-bytes differential    NOT PLANTED — the remaining half of the fixed class. Its test
                                skips itself rather than reporting green (TestRustAgreement).
audit_candidate_matrix          runs, expected exit 1 (version pin drift, Owner: do not raise;
                                its CI job carries continue-on-error)
```

## Honest boundary

This is a pre-registration. It asserts **no verdict**. `WITHSTANDS_DEEPGATE`, if reached, means
*"ready for the Owner's tag"* — not "released", not "proven secure". The tag, the merge to main,
the GitHub release, the PyPI publish and the deposit remain five separate Owner acts.

`pre_tag_audit_gate --strict` currently returns **exit 0** for version 5.0.0, granted by
`DEEP_RUN_RECORD_500.md`, which attests `9bc179e` — now **eleven commits** behind this head. That
gate is version-scoped and not digest-bound, and its own source says so. It therefore does **not**
attest this digest, and nothing in this file should be read as if it did. Recorded as
`VOR-TAG-TOR-IST-VERSIONS-GESCHNITTEN-NICHT-DIGEST-GEBUNDEN-UND-STEHT-HEUTE-AUF-GRUEN-01`.
