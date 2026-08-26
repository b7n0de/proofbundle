# Pre-registration — DEEP 6L/7I, release 5.0.0, **iteration 6**

Frozen 2026-08-26T09:01:45Z, BEFORE anything ran (the iteration-6 section of the run record may
only cite what is fixed here).

## Why a second pre-registration exists, and what it does not do

[PRE_REGISTRATION_DEEP_500.md](PRE_REGISTRATION_DEEP_500.md) froze its graded object at
`c669d39` and carried the run through iterations 1–4 to `WITHSTANDS_DEEPGATE` on `9bc179e`.
Nine commits have landed since that verdict. Two of them entered through a **merge**
(`1a9a6ce`) and are therefore not visible as "later" in a date-ordered log — measured,
`d9913a6` and `bed147b` are **not** ancestors of `9bc179e`.

This file is **additive**. The first pre-registration is untouched and remains the record of what
iterations 1–4 graded. It is not amended, extended or reinterpreted here; a pre-registration that
its own author edits after seeing results is worth nothing, and that is precisely the reason a
second file exists instead of a longer first one.

**E1 and E3–E6 below are reproduced verbatim** from the first file, deliberately as text and not as
a cross-reference, so that the iteration-6 verdict does not hang on a document written for a
different tree. **E2 is restated** — see the correction below. E7–E11 are new and cover the delta
that has never been graded.

## The correction that made this file necessary

The first pre-registration's **E2 asserts "exactly ONE input class changes its exit code"**. The
CHANGELOG for this release names **two independent MAJOR triggers**. Measured, three ways:

```
CHANGELOG 5.0.0    "MAJOR (SemVer), and there are TWO independent triggers"
                   Trigger 1 — exit-code class: an input class exiting 2 now exits 1
                   Trigger 2 — a threshold is now required for a verdict

git log -S 'PROOFBUNDLE_THRESHOLD' c669d39..6065815 -- src   →  d9913a6
git merge-base --is-ancestor d9913a6 9bc179e                 →  false (came via merge 1a9a6ce)
grep -ci threshold PRE_REGISTRATION_DEEP_500.md              →  0
```

So the second trigger is the **threshold obligation**, it entered the release **after** the run
record was written, and the word does not occur in the first pre-registration even once. The
three-valued reported-version status is **not** the second trigger — its own commit states it is
additive and that 5.0.0 stands without a further bump. E2 is restated accordingly.

## The graded object

```
graded commit      6065815907e45cd8a1cfd7535f33d5b79ee11f26   (release/v5.0.0, worktree clean)
graded src tree    ae07ab3ed8ae29625926555ad71564f0921eefaf
mode               [DEEP-GATE: DEEP 6L/7I]   (MAJOR / external release)
```

**Three deltas, measured separately, because they answer three different questions.** A number
carried from one range into another is a defect this project has already paid for once (L6-01,
iteration 1: readiness attested for 5.0.0 out of 3.6.0 evidence).

```
what has NEVER been graded      9bc179e..6065815   9 commits
                                under src/:        9 files, 264 insertions, 18 deletions

what the PR moves               origin/main..release/v5.0.0   13 commits  (FAST-FORWARD)
                                under src/:        15 files, 414 insertions, 31 deletions

what the TAG will cover         v4.0.0..6065815    31 commits
                                under src/:        19 files, 594 insertions, 52 deletions
                                overall:           77 files, 3057 insertions, 131 deletions
```

**A correction to the instruction that commissioned this file, stated rather than quietly
absorbed:** the figure *"delta `v4.0.0..6065815`, 15 files and 414 insertions under src"* pairs a
range with the count of a different one. Measured, `15 / 414` belongs to `c669d39..6065815`;
`v4.0.0..6065815` is `19 / 594`. The number was correct where it was first written (it was labelled
"in between" there) and travelled to the wrong range afterwards. All three ranges are given above
so no reader has to guess which one a later sentence means.

**Iteration 6 grades the whole tree at `6065815`**, not only the ungraded delta. The delta decides
which *new* falsification targets exist; the standing targets RT-01..RT-08 and E1–E6 apply to the
tree as shipped.

## A gap in the existing record, pre-registered as work

`DEEP_RUN_RECORD_500.md` documents four iterations. **Iteration 5 ran and left no record.** Its
existence is measurable only from commit messages (`529cd20` "Deep-gate T1/iter5 (2026-08-25)";
`66e72f4` "deep-gate iteration 5, finding F-C"), and two further jury rounds on `66e72f4` and
`df2b353` are likewise recorded only in commit bodies. A search of `audit_artifacts/` for an
iteration-5 artifact returns nothing.

The iteration-6 run record must therefore **also** carry iteration 5 and the two jury rounds after
it — from the commit record, marked as reconstructed and not as fresh gate evidence. A record that
jumps from 4 to 6 would imply a completeness it does not have.

## Scope rule for this iteration (Owner, 2026-08-26): FEATURE STOP on `release/v5.0.0`

Findings are still fixed **as a class**, per the standing procedure. But a finding whose fix would
require a **new public promise** — a new flag, a new field, a new documented behaviour — is
**recorded as a finding and deferred to 5.1.0**, not built here.

This is a convergence rule with a measured cause: iteration 5 closed its finding with a `feat`
(`66e72f4`), that feature drew two further jury rounds (`df2b353`, `6065815`), and each of those
moved the graded digest again. A gate whose fixes enlarge the graded object does not terminate.
Under this rule a `FIX_FIRST` verdict may be discharged by a deferral-with-finding where the fix
would be additive public surface — and the record must say which findings were discharged that way.

## Falsification targets

E1 and E3–E6 are reproduced verbatim from the first pre-registration. E2 is restated. E7–E11 are new.

| # | Target (the invariant the release asserts) | Falsified by |
|---|---|---|
| E1 | **The cap removes work, not acceptance.** Running the `merkle_path` cap before the decoding it bounds changes no verdict: anything that verified under 4.0.0 still verifies, anything that failed still fails. | a proof/bundle/sample-opening input whose verdict DIFFERS between v4.0.0 and this tree — in either direction |
| E2 | **RESTATED. Exactly TWO externally observable contracts change, and they are the two the CHANGELOG names as MAJOR triggers.** Trigger 1: one input class moves exit 2 → exit 1 (over the cap AND invalid base64). Trigger 2: the Inspect lifecycle hook and the pytest plugin stop emitting a receipt when `PROOFBUNDLE_THRESHOLD` is unset. No third contract moved unnoticed. | any other input class whose CLI exit code differs between v4.0.0 and this tree; any other externally observable contract (emission, field presence, verdict) that differs and is not one of these two; or either named change NOT actually occurring (a claimed breaking change being fictional) |
| E3 | **`expected_origin_wellformed` is purely additive.** The comparison itself is untouched: a malformed pin still yields a verdict, never an exception, and `inclusion_ok` is unchanged by the new field. | a pin value for which `inclusion_ok` differs from v4.0.0; or the new field raising; or a fail-closed path where `verify-proof --json` omits it despite the claim of "every invocation" |
| E4 | **Nothing this release loosens an existing check; every shipped external vector keeps its verdict.** | a Go-sumdb / Rekor / rootcommit / Colin vector whose verdict changed, or an input refused before and accepted now |
| E5 | **The two fail-closed additions refuse only unusable states.** `checkpoint_note` refusing an empty root, and `save_signer`'s path type floor, reject nothing a valid producer could previously use. | a producer call that worked under 4.0.0, produced something a verifier ACCEPTED, and is refused now |
| E6 | **The record's and CHANGELOG's numbers and claims match the tree** (fidelity), including the MAJOR justification: `SPEC.md` really does document the exit-code contract normatively at the cited lines. | a claimed count / file / line reference that a fresh measurement contradicts; or a SPEC.md citation that does not say what the record says it says |
| E7 | **NEW. The threshold obligation refuses only the vacuous verdict** (`d9913a6`, MAJOR trigger 2). With `PROOFBUNDLE_THRESHOLD` unset, both the Inspect lifecycle hook and the pytest plugin **skip emission with a clear message** — they do not emit, and they do not raise. With it set, behaviour is byte-equivalent to 4.0.0 for the same run. | a receipt still emitted with the variable unset (the vacuous `passed: true` surviving); or the skip path raising instead of messaging; or a run WITH the variable set whose receipt differs from 4.0.0's in any field this release does not claim to change; or a third integration or code path still defaulting the threshold to `"0"` |
| E8 | **NEW. `--expect-issuer` is opt-in, backwards compatible, and compares the VERIFIED signer** (`bed147b`). Without the flag, `show-eval` behaves exactly as 4.0.0. With it, the comparison is against the signer bound by `decode_eval_claim` (issuer == signature key), never against a caller-supplied or unverified field; a mismatch exits 1 with a message; the flag is repeatable for rotation. | `show-eval` without the flag differing from 4.0.0 in exit code or output; the forgery scenario (a claim re-signed with a fresh key) passing WITH a pinned issuer; the comparison reading an unverified field; a repeated flag not behaving as the documented union; or a mismatch exiting anything other than 1, or raising |
| E9 | **NEW. The other two gaps of `d9913a6` are additive and invent nothing.** `capture_mechanism` takes one of exactly three named values (`lifecycle_hook`, `lifecycle_hook_log_reread`, `persisted_log_reader`); the lm-eval adapter binds `harness_version` **only** from the results file's `lm_eval_version`. No receipt valid under 4.0.0 becomes invalid. | a 4.0.0-produced receipt this tree's verifier now rejects; `capture_mechanism` taking or accepting a value outside the three; `harness_version` appearing on an lm-eval receipt whose results file carries no `lm_eval_version`; or the published claim schema (`threshold` / `passed` required) having moved |
| E10 | **NEW. The reported-version status is additive, never derived, and its verifier judges only its own class** (`66e72f4` · `df2b353` · `6065815`). `<field>_status` ∈ {`reported`, `not_reported`, `not_bound`} with a **mandatory** reason whenever not `reported`; the version field itself is untouched (absent stays absent); a provenance with **no** status at all stays valid; `version_status_issues` raises findings only for members of the named `REPORTED_VERSION_FIELDS` set; writer and verifier share that one set. | a legacy (pre-5.0.0) receipt rejected; a finding raised on a non-member field (`schema_version_status`, `run_status`, `scorer_status`); a value invented into a version field the harness never reported; a writer output that its own verifier rejects; a non-dict provenance or one with mixed key types raising instead of reporting; `not_reported` folding to PASS; or writer and verifier disagreeing about the member set |
| E11 | **NEW. Cross-adapter version binding is symmetric and still honest** (`529cd20`). promptfoo writes **both** `harness_version` and `promptfoo_version`, and only when promptfoo actually reports a version. No adapter is left binding under a name the others do not use. | `harness_version` written when promptfoo reported none (a value invented into evidence); `promptfoo_version` dropped or renamed (existing readers breaking); or a fourth adapter still binding asymmetrically |

## Standing regression targets

RT-01..RT-08 apply unchanged and are not removable. RT-01..RT-04 were each explicitly attacked in
the iteration-4 record; they are attacked again here against the moved tree, because a verdict for
an earlier digest does not carry to a later one.

## Method (fixed here)

Six lenses — correctness · No-Fake · adversarial · SOTA (SemVer 2.0.0 / RFC 2119 normative-spec
reading) · regression · fidelity — each attempts to **REFUTE** its target with an executable probe,
not to confirm it. Negative state including **absent** (no pin supplied; empty proof list; zero cap;
canonicalizer missing; threshold variable unset; provenance without any status).

**Independent oracle and anti-parity:** the 4.0.0 comparison runs against an actual v4.0.0 checkout,
not against this tree's own expectations. Both checkouts are driven over `PYTHONPATH` without
installation, so `4.0.0` and `5.0.0` import side by side in one minimal environment.

**Minimal environment:** as-shipped, without the `[experimental]` / `[pq]` extras.

**Ledger replay first:** `scripts/b7_berkeley_pre_sweep.py` replays every learned `class_closed`
class before any new work; one red learned class aborts the round. The iteration-4 round replayed
80 of 140 (0.5714) — this round reports its own coverage number and does not inherit that one.

**Gate-meta-test — two planted defects, both of NEW classes**, because a meta-test that only plants
the class the previous round already caught proves nothing about the surface this round exists for:

1. an **E7-class** defect — the threshold default silently restored to `"0"` — must turn the corpus red;
2. an **E10-class** defect — the member-set check widened back to a suffix rule, so
   `schema_version_status` is judged again — must turn the corpus red.

Each planted run carries a **green control**: the same isolated tree, the same battery, without the
mutation. If the control is not green the measurement is void, however many mutants report caught.

**Generator hardening over point fixtures:** every confirmed finding closes as a class (property ·
generator · oracle · neighbour sweep in the same pass · ledger append), subject to the feature-stop
rule above.

## Declared NOT RUN (so the record cannot imply them)

```
mutation_check                  not run  — multi-hour job, measured 2.2–2.4 h
fuzz_soak (full 24 h)           not run  — short soak only, and the record says which
readiness_pack_manifest --check not run
audit_candidate_matrix          runs, and is EXPECTED to exit 1 — VERSION PIN DRIFT
                                (matrix pinned 3.6.0, package 5.0.0). Owner decision 2026-08-26:
                                do NOT raise the pin for 5.0.0; a bump turns a withheld judgement
                                into a real FAIL, because release_evidence_slots end at 3.6.0.
                                The CI job carries continue-on-error, so the PR does not go red.
                                Binding the pin to __version__ plus two slots is deferred to
                                after 5.1.0, on the condition that the anti-parity half of
                                tests/test_audit_matrix_version_pin_binding.py does not become
                                meaningless.
```

## Honest boundary of this file

This is a pre-registration and nothing more. It asserts **no verdict**. `WITHSTANDS_DEEPGATE`, if
iteration 6 reaches it, would mean *"ready for the Owner's tag"* — not "released" and not "proven
secure". The tag, the merge to main, the GitHub release, the PyPI publish and the deposit remain
five separate Owner acts, and none of them is granted by anything written here.

`pre_tag_audit_gate --strict` reads `DEEP_RUN_RECORD_500.md` for the line
`pre-tag-adversarial-audit: RUN | version=5.0.0`. That line already exists there for the iteration-4
run. **This file does not extend it to `6065815`**, and it must not be read as doing so: the
existing line attests the run that ended at `9bc179e`. Until the iteration-6 section is written, the
attestation on disk covers a digest that is nine commits behind the branch head — which is the
condition this file was written to end, not one it resolves by existing.
