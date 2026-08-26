# Pre-registration — DEEP 6L/7I, release 5.0.0, **iteration 7**

Frozen 2026-08-26T10:36:43Z, BEFORE anything ran (the iteration-7 section of the run record may
only cite what is fixed here).

## Why there is a third file, and what it does not do

[PRE_REGISTRATION_DEEP_500.md](PRE_REGISTRATION_DEEP_500.md) carried iterations 1–4 (verdict on
`9bc179e`). [PRE_REGISTRATION_DEEP_500_ITER6.md](PRE_REGISTRATION_DEEP_500_ITER6.md) carried
iteration 6 on `6065815`. Neither is amended here. Iteration 6's deterministic pre-sweep was **not
green**, which is `FIX_FIRST` by the runbook, and the fix moved the head — so iteration 7 grades a
new object and gets its own frozen document. **E1–E11 below are reproduced verbatim from the
iteration-6 file**, deliberately as text and not as a cross-reference.

**E9 IS REPRODUCED WITHOUT A SINGLE WORD CHANGED**, including the half a probe already refuted.
Narrowing it so the refutation falls out is excluded (Owner, 2026-08-26). What that means for the
verdict is fixed below, before the run, rather than decided after it.

## The graded object

```
graded commit      d8ec90125ee0ebeecabd676c17c18947a1697d3f   (release/v5.0.0, worktree clean)
graded src tree    5fc2310b9697879b813f03cc59e8708fb79d8255
mode               [DEEP-GATE: DEEP 6L/7I]   (MAJOR / external release)
```

```
never graded by any iteration   9bc179e..d8ec901    10 commits
                                under src/:         9 files, 276 insertions, 18 deletions

what the PR moves               origin/main..d8ec901   14 commits  (FAST-FORWARD, re-measured)
                                under src/:         15 files, 426 insertions, 31 deletions

what the TAG will cover         v4.0.0..d8ec901     32 commits
                                under src/:         19 files, 606 insertions, 52 deletions
                                overall:            77 files, 3213 insertions, 131 deletions
```

Every figure above was measured in the round that froze this file, against `origin/<branch>` and
not against a local `main` (the local one is 134 commits behind and carries no commit of its own —
measuring against it produced a wrong number once already).

## What iteration 6 was, and what it found

Iteration 6 ran the deterministic pre-sweep on `6065815` and stopped before the jury, because the
runbook's step 4 says a non-green pre-sweep is `FIX_FIRST` and a jury on a tree about to change
would be stale before its record was written. That has now happened twice in this release —
iteration 4 bound `9bc179e` while the head stood nine commits further, and iteration 5 graded
`5e3084e` and was overtaken. It is not paid a third time.

```
ledger replay          pass — 161 tests, 156 nodes, 80 of 141 classes (0.5674), 0 regressed
full suite (minimal)   2262 passed, 123 skipped, 555 subtests, 0 failed
E7 threshold           HOLDS — 4.0.0 signs passed=true on an all-red run, 5.0.0 emits nothing;
                       with the variable set the two receipts differ only in four per-run nonces,
                       proved by a 5.0.0-against-5.0.0 control that differs in the same four
E8 --expect-issuer     HOLDS — a payload re-signed with a fresh key passes rc=0 unpinned, rc=1
                       pinned; green control on the genuine receipt; rotation behaves as a union
E9 lm-eval half        HOLDS
E9 capture half        REFUTED  (see below — the one finding that binds this file)
E10 status class       HOLDS — 11 probes, including a genuinely 4.0.0-produced provenance that
                       passes the 5.0.0 verifier unchanged
E11 promptfoo symmetry HOLDS — anti-parity confirms the asymmetry in 4.0.0 and its closure here
```

Four findings, all recorded in the append-only queue. Three are closed in `d8ec901`:

* the comment above the membership check argued for the suffix rule `6065815` rejected — replaced
  by what the code does, with the reason the literal list is right;
* the status class shipped across four adapters with one producer path tested — now both
  directions per adapter, plus a guard binding every named field to a real adapter. Plant-and-must-
  catch: three planted defects, three runs each (green → red → green), byte-identical restore;
* **`ruff check .` exited 1 on the unmodified `6065815`** (F841 from `bed147b`, in the ungraded
  delta). `.github/workflows/ci.yml:81` runs it in the `Lint` step **without** `continue-on-error`,
  so the preparation PR would have gone red on a binding job. Fixed; `ruff check .` now exits 0.

## The one finding this file binds, before the run

**`capture_mechanism` accepts any string into signed evidence.** `from_inspect_ai_log` writes
`provenance["capture_mechanism"] = str(capture)` with no check; measured, `'live_hook_trust_me'`,
`''`, `'lifecycle_hook '` (trailing space, byte-distinct from the named value) and `'None'` all go
through. The three named values live only in a docstring. One function over, `bind_reported_version`
enforces its named set at the writer and raises on a typo — the same invariant, unswept.

**Deferred to 5.1.0 by Owner decision, 2026-08-26**, together with the audit-matrix version pin.
The reason is the feature stop and it is a real one: `capture` is a call parameter of a **public**
adapter function, and fencing it changes acceptance behaviour on a public surface. Measured, nothing
in `src/` reads the value — three non-comment occurrences, all write-side
(`adapters/inspect_ai.py:41` and `:91`, `inspect_hook.py:72`); two tests do read it, so it is
asserted but not enforced. Finding
`CAPTURE-MECHANISM-NIMMT-JEDEN-STRING-DER-NACHBAR-ERZWINGT-SEINE-MENGE-01`, severity P3.

**How that binds the verdict — fixed here, not afterwards:**

1. A refutation of **E9 at exactly this instance** is **EXPECTED**. It does **NOT** withhold
   `WITHSTANDS_DEEPGATE`, because the instance is named, reproduced and deliberately deferred
   before the run rather than discovered and explained away after it.
2. **Any OTHER refutation of E9 DOES withhold the verdict.** The exemption covers one measured
   instance, not the target.
3. **E9 must not be narrowed** so the refutation falls out. It stands in the wording under which it
   was refuted; that is the whole reason this paragraph exists instead of an edit.
4. The run record and the release recommendation carry the finding as an **open P3**, the way the
   iteration-4 record carried the register candidate that did not survive its refute-to-kill.

## Scope rule, unchanged from iteration 6: FEATURE STOP on `release/v5.0.0`

Findings are fixed **as a class**. A finding whose fix would require a **new public promise** — a
new flag, a new field, a newly raising call on a public function — is **recorded and deferred to
5.1.0**. A `FIX_FIRST` may be discharged by such a deferral, and the record must say which findings
were discharged that way. Iteration 6 discharged exactly one (above) and fixed the other three.

## Falsification targets

E1–E11 reproduced verbatim from the iteration-6 pre-registration. **No wording is changed.**

| # | Target (the invariant the release asserts) | Falsified by |
|---|---|---|
| E1 | **The cap removes work, not acceptance.** Running the `merkle_path` cap before the decoding it bounds changes no verdict: anything that verified under 4.0.0 still verifies, anything that failed still fails. | a proof/bundle/sample-opening input whose verdict DIFFERS between v4.0.0 and this tree — in either direction |
| E2 | **Exactly TWO externally observable contracts change, and they are the two the CHANGELOG names as MAJOR triggers.** Trigger 1: one input class moves exit 2 → exit 1 (over the cap AND invalid base64). Trigger 2: the Inspect lifecycle hook and the pytest plugin stop emitting a receipt when `PROOFBUNDLE_THRESHOLD` is unset. No third contract moved unnoticed. | any other input class whose CLI exit code differs between v4.0.0 and this tree; any other externally observable contract (emission, field presence, verdict) that differs and is not one of these two; or either named change NOT actually occurring |
| E3 | **`expected_origin_wellformed` is purely additive.** The comparison itself is untouched: a malformed pin still yields a verdict, never an exception, and `inclusion_ok` is unchanged by the new field. | a pin value for which `inclusion_ok` differs from v4.0.0; or the new field raising; or a fail-closed path where `verify-proof --json` omits it despite the claim of "every invocation" |
| E4 | **Nothing this release loosens an existing check; every shipped external vector keeps its verdict.** | a Go-sumdb / Rekor / rootcommit / Colin vector whose verdict changed, or an input refused before and accepted now |
| E5 | **The two fail-closed additions refuse only unusable states.** `checkpoint_note` refusing an empty root, and `save_signer`'s path type floor, reject nothing a valid producer could previously use. | a producer call that worked under 4.0.0, produced something a verifier ACCEPTED, and is refused now |
| E6 | **The record's and CHANGELOG's numbers and claims match the tree** (fidelity), including the MAJOR justification: `SPEC.md` really does document the exit-code contract normatively at the cited lines. | a claimed count / file / line reference that a fresh measurement contradicts; or a SPEC.md citation that does not say what the record says it says |
| E7 | **The threshold obligation refuses only the vacuous verdict** (`d9913a6`, MAJOR trigger 2). With `PROOFBUNDLE_THRESHOLD` unset, both the Inspect lifecycle hook and the pytest plugin **skip emission with a clear message** — they do not emit, and they do not raise. With it set, behaviour is byte-equivalent to 4.0.0 for the same run. | a receipt still emitted with the variable unset; or the skip path raising instead of messaging; or a run WITH the variable set whose receipt differs from 4.0.0's in any field this release does not claim to change; or a third integration or code path still defaulting the threshold to `"0"` |
| E8 | **`--expect-issuer` is opt-in, backwards compatible, and compares the VERIFIED signer** (`bed147b`). Without the flag, `show-eval` behaves exactly as 4.0.0. With it, the comparison is against the signer bound by `decode_eval_claim`, never against a caller-supplied or unverified field; a mismatch exits 1 with a message; the flag is repeatable for rotation. | `show-eval` without the flag differing from 4.0.0; the forgery scenario passing WITH a pinned issuer; the comparison reading an unverified field; a repeated flag not behaving as the documented union; or a mismatch exiting anything other than 1, or raising |
| E9 | **The other two gaps of `d9913a6` are additive and invent nothing.** `capture_mechanism` takes one of exactly three named values (`lifecycle_hook`, `lifecycle_hook_log_reread`, `persisted_log_reader`); the lm-eval adapter binds `harness_version` **only** from the results file's `lm_eval_version`. No receipt valid under 4.0.0 becomes invalid. | a 4.0.0-produced receipt this tree's verifier now rejects; `capture_mechanism` taking or accepting a value outside the three; `harness_version` appearing on an lm-eval receipt whose results file carries no `lm_eval_version`; or the published claim schema (`threshold` / `passed` required) having moved |
| E10 | **The reported-version status is additive, never derived, and its verifier judges only its own class.** `<field>_status` ∈ {`reported`, `not_reported`, `not_bound`} with a mandatory reason whenever not `reported`; the version field itself is untouched; a provenance with no status at all stays valid; `version_status_issues` raises findings only for members of `REPORTED_VERSION_FIELDS`; writer and verifier share that one set. | a legacy receipt rejected; a finding raised on a non-member field (`schema_version_status`, `run_status`, `scorer_status`); a value invented into a version field; a writer output its own verifier rejects; a non-dict provenance or one with mixed key types raising instead of reporting; `not_reported` folding to PASS; or writer and verifier disagreeing about the member set |
| E11 | **Cross-adapter version binding is symmetric and still honest** (`529cd20`). promptfoo writes **both** `harness_version` and `promptfoo_version`, and only when promptfoo actually reports a version. | `harness_version` written when promptfoo reported none; `promptfoo_version` dropped or renamed; or a fourth adapter still binding asymmetrically |

**E12 is new and exists because iteration 6's own fix could have introduced it.** The three
adapter fixes and the comment rewrite are themselves part of the graded tree now.

| # | Target | Falsified by |
|---|---|---|
| E12 | **The iteration-6 fix changed no behaviour.** `d8ec901` touches one comment block, one test file and one dead assignment; no receipt, verdict, exit code or emitted field differs between `6065815` and `d8ec901`. | any output, verdict, exit code or provenance field that differs between the two trees for the same input; or a new test that passes for a reason other than the one it names (a green test that stays green under its own planted defect) |

## Standing regression targets

RT-01..RT-08 apply unchanged and are not removable. RT-01..RT-04 are attacked again against the
moved tree; a verdict for an earlier digest does not carry to a later one.

## A gap in the existing record, still open and still pre-registered as work

`DEEP_RUN_RECORD_500.md` documents four iterations. **Iteration 5 ran and left no record** — its
existence is measurable only from commit messages (`529cd20`, `66e72f4`), as are two further jury
rounds on `66e72f4` and `df2b353`. The record written for iteration 7 must therefore also carry
iterations **5 and 6**, marked as reconstructed from the commit record where that is what they are.
A record that jumps from 4 to 7 would imply a completeness it does not have.

## Method (fixed here)

Six lenses — correctness · No-Fake · adversarial · SOTA (SemVer 2.0.0 / RFC 2119 normative-spec
reading) · regression · fidelity — each attempts to **REFUTE** its target with an executable probe.
Negative state including **absent** (no pin supplied; empty proof list; zero cap; canonicalizer
missing; threshold variable unset; provenance without any status).

**Independent oracle and anti-parity:** the 4.0.0 comparison runs against an actual v4.0.0
checkout (`89d4fb9`), driven over `PYTHONPATH` so `4.0.0` and `5.0.0` import side by side in one
minimal environment without installation. Verified in the freezing round: the same interpreter
reports `4.0.0` and `5.0.0` depending only on the path.

**Minimal environment:** as-shipped, without the `[experimental]` / `[pq]` extras. The minimal lane
skips 123 tests and that number is reported, not rounded away.

**Ledger replay first:** one red learned class aborts the round. This round reports its own
coverage number and inherits none.

**Gate-meta-test — planted defects of NEW classes, each with a green control.** A meta-test that
only plants the class the previous round caught proves nothing about the surface this round exists
for. Iteration 6 planted three (constant placeholder, status dropped, hole-next-door) and all three
turned the corpus red with a green control before and a green control after the byte-identical
restore. Iteration 7 plants at least one defect of the **E12** class: a green test made green for
the wrong reason must be caught.

**Generator hardening over point fixtures**, subject to the feature stop above.

## Declared NOT RUN (so the record cannot imply them)

```
mutation_check                  not run  — multi-hour job, measured 2.2–2.4 h
fuzz_soak (full 24 h)           not run  — short soak only, and the record says which
readiness_pack_manifest --check not run
audit_candidate_matrix          runs, and is EXPECTED to exit 1 — VERSION PIN DRIFT (matrix
                                pinned 3.6.0, package 5.0.0). Owner decision: do NOT raise the pin
                                for 5.0.0; a bump turns a withheld judgement into a real FAIL
                                because release_evidence_slots end at 3.6.0. The CI job carries
                                continue-on-error, so the PR does not go red on it. Binding the pin
                                to __version__ plus two slots is deferred to after 5.1.0.
```

## Honest boundary of this file

This is a pre-registration. It asserts **no verdict**. `WITHSTANDS_DEEPGATE`, if iteration 7 reaches
it, would mean *"ready for the Owner's tag"* — not "released" and not "proven secure". The tag, the
merge to main, the GitHub release, the PyPI publish and the deposit remain five separate Owner acts,
and none is granted by anything written here. No push, no PR and no merge happens without its own GO.

`pre_tag_audit_gate --strict` reads `DEEP_RUN_RECORD_500.md` for the line
`pre-tag-adversarial-audit: RUN | version=5.0.0`. That line exists there for the **iteration-4** run
and attests a digest that is now ten commits behind the branch head. **This file does not extend it
to `d8ec901`** and must not be read as doing so.
