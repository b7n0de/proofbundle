# Residual risk, release 6.1.0 — the record before the closing gate round

This file lands before the closing round, not after it. The owner fixed that order on 2026-09-05
for 6.0.0 and it holds here: this file goes on `main` first, the head that carries it is the frozen
tree, and the closing round runs on exactly that head.

**Nothing in this file claims the release is defect free.** It is the list of what was known and
open when the tree was frozen, and why each item was judged not to block.

## What makes 6.1.0 different from its own scope of 2026-09-12

6.1.0 was cut on 2026-09-19. Owner word, order `QITEM-PROOFBUNDLE-610-SCHNITT-LANDEN-KETTE-01`,
option A: 6.1.0 is the substance that has been on `main` since `v6.0.0`, plus the two P1 of the
2026-09-19 audit, R7 and the cheap documentation findings. Everything else moves to 6.2.0
unchanged.

The reason is measured and it is the whole point of this file. The scope of 2026-09-12 listed 56
lines. Two of them are delivered, P19 and R7. The owner names the same order of magnitude from a
different source, the landing card, one of 47. Two independent derivations, one statement. The
remaining 54 lines are weeks of work at today's rate.

**A moved line is an open line.** That is what this section exists for. The cut takes away their
due date, not their entry in the books.

## Open — the 54 lines moved out of 6.1.0

THEY NO LONGER LIVE IN ONE FILE, and this section said they did until 2026-09-24. The cast of
2026-09-19 moved all 54 into `docs/release_scope/6.2.0.md` unchanged, because the cut had to happen
faster than the reading; byte equality was checked then, 54 expected, 54 present, none missing, none
foreign. The recast of 2026-09-23 read them against the code and the register and split them, so the
full text now stands in `docs/release_scope/6.2.0.md` AND `docs/release_scope/6.3.0.md`, each moved
line carrying the sentence that says why it went where it did.

Counted from the rows of those files rather than asserted: **24** scope rows in 6.2.0 and **34** in
6.3.0, carrying 18 and 35 of the identifiers below, plus S62 which has no row of its own because it
was delivered in 6.1.0. 18 + 35 + 1 = 54. Seven rows are new and not part of the 54: P29, P30 and
Z146 from the four outcomes, and R-B1 to R-B4 from the entries this file targets at 6.2.0 by name.

THE SPLIT IS ENFORCED, not just written down. `tests/test_release_scope_title_gate.py` reads the
identifier list BELOW out of this file and requires each one to sit in a scope row of exactly one of
the two files, or to be named as a rider in BOTH of their accounting tables. A line in two scopes
and a line in none are the two failures the release rule of 2026-09-09 asks about, and they are the
two the guard reports by name rather than as a count that got smaller.

Identifiers, so this file can be read without a second one:

`A1`, `A2`, `A3`, `A5.1–A5.4`, `B1`, `B2`, `B3`, `C1`, `C2`, `N1-1a`, `N1-1c`, `N1-2a–2c`, `N2-1`, `N2-2`, `N2-3a–d`, `N3-1`, `N3-2`, `N3-3`, `N3-5`, `N3-4`, `B-2`, `B-3`, `B-7`, `B-8`, `B-9`, `Z.278`, `Z.715`, `R1`, `R2`, `R3`, `N14`, `N15`, `N17`, `N18`, `N20`, `R-A1`, `R-A2`, `R-A3`, `S5`, `S20`, `S22`, `S26`, `S27`, `S29`, `S30`, `S31`, `S32`, `S33`, `S59`, `S62`, `S64`, `S65-5`, `S76`, `S106`

Funnel verdict for the block: none of them reaches a user of the published package as a wrong
verdict. They are hardening of the gate machinery, of the register and of the measurement surface.
That is a judgement about the class and it is stated as such, not as a per-line measurement.

## Open — the P3 findings of the 2026-09-19 audit

These were measured on the candidate and are not fixed in 6.1.0. The order places section B of the
audit after the tag.

| Id | Finding | Class |
|---|---|---|
| A-13 | `automation_verdict.py:145` appends `RECEIPT_NOT_OK`; neither reason map knows the code and no document names it | vocabulary not closed |
| A-14 | `validate_summary_predicate` takes `strict` and never reads it; emit sets True, verify False, both without effect | dead parameter |
| A-19 | `build_eval_claim` runs `str()` over `ci95` BEFORE the float ban, so `[nan, inf]` becomes `["nan", "inf"]` inside the signed claim | order of check and conversion |
| A-18 | `save_signer` writes in place with `O_TRUNC`, no temp plus `os.replace`, no unlink on failure | non-atomic key write |
| A-03 | `sdjwt.py:267-268` writes "N disclosure(s)" as the detail on every result without one, including a failed one | one cause per path |
| A-06 | `signature.py:77` converts r and s without a low-s check, so `(r, s)` and `(r, n-s)` both verify; two tokens for one receipt in `hf_evals.py:58` | signature malleability |
| A-11 | `merkle.py` docstring names three functions as the stable API, `__all__` exports seven | stated surface vs exported surface |

A-06 is the one to weigh first after the tag. `docs/readiness_pack/AUDITOR_OPEN_POINTS.md:10`
already names the class as open, so it is disclosed rather than hidden, but disclosed is not fixed.

## Closed during the cut, and named because two paths found it

**A-17** is not in the OPEN list above, because it is closed and this section is where the
closures stand. Saying only "not in the list above" was ambiguous enough that a counter-reading
of this file took it for a claim that A-17 is not closed at all. It said `commit_alg` must be
present but its value is never
compared against `COMMIT_ALG`, so `"sha1-unsalted"` decodes. An external review lens reported the
same defect independently as part of a wider P2 about value domains. One fix closes both. Measured
after the fix with a clean control arm: `sha1-unsalted` rejected, `md5-plain` rejected,
`sha256-salted-v1` accepted.

Two independent paths converging on one defect is the useful part of that story, and it is the
reason this entry is here instead of quietly absent.

**WHERE THAT FIX LIVES, and it now lives here.** The enforcement line
(`if claim.get("commit_alg") != COMMIT_ALG: return None`) and the file that carries its cases,
`tests/test_eval_claim_domains_are_enforced.py`, arrived with the evalclaim verify-boundary change,
which landed as `#231` on 2026-09-20. MEASURED over the three trees this section has described,
counting that line in `src/proofbundle/evalclaim.py` and looking for that file:

| tree | the enforcement | the test file |
|---|---|---|
| `main` before that landing | absent | absent |
| this branch | present | present |
| `main` after that landing | present | present |

The middle row is the one that can go wrong without anyone noticing, and it is NOT asserted here:
`tests/test_restrisiko_610_says_which_tree_it_measured.py` derives it from the tree this document
sits in. While the verify-boundary change was open, that row read `absent`, and the closure
sentence above was true of a tree this document was not in. The landing order closed the gap; the
derived row is what keeps it closed, because an order is not a gate.

A counter-reading found the gap by running the claim rather than by reading it: it emitted a
receipt with `commit_alg: "sha1-unsalted"` on the then-current tree and the CLI answered `=> OK`.
That is the honest way round -- the document was ahead of its own branch, not wrong about the fix.

## Open — the two commitment patterns at the verify boundary

`schemas/eval_claim_v0_1.schema.json` documents `^sha256:[0-9a-f]{64}$` for `model_id_commit` and
`dataset_id_commit`. The verify boundary does not enforce it; a signed claim with an arbitrary
string in either field decodes.

Not fixed in 6.1.0, and the reason is measured rather than a preference. The check is three lines
and works, but it turns five existing cases in `tests/test_cli_eval.py` red, because they sign
claims with placeholder commitments such as `sha256:x`. Isolated by measurement: 5 of 5 green
without the two patterns, 4 red with them. Rewriting five house tests so a new check passes is its
own change with its own measurement of what else signs placeholders.

Carried in `tests/test_eval_claim_domains_are_enforced.py` as `BEKANNTE_LUECKEN` -- which,
like the A-17 fix above, arrives with the verify-boundary pull request and is not in this
tree -- and that list
fails in both directions — an entry whose gap has since been closed turns the test red and asks to
be deleted. Verified with a planted closure. Register entry
`COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01`, target 6.2.0.

## Open — two findings this cut made and deliberately did not close

Both were found while repairing something else, both are real, and both would have lived only in a
docstring and a commit message if this section did not exist. That is the failure mode this file is
against, so they are written down where a reader of the release looks for open risk.

**A small-order key at the carrier's signature block is accepted.** `_signatur_lage`
(`scripts/gen_findings_register.py`) delegates verification to `cryptography`, and this project's
Ed25519 profile ACCEPTS small-order components, which SPEC section 4a states and pins byte-exact
against the "Taming the Many EdDSAs" vectors. Consequence, measured 2026-09-20: 32 zero bytes as a
public key and 64 as a signature verify over roughly one body in four. The order is computed, not
inferred from that rate: the bytes decompress to a curve point with `y = 0` and `x` non-zero, and
the SMALLEST multiple reaching the identity is the fourth — `1P`, `2P` and `3P` are each measured
NOT to be the identity, and `4P` is. That wording is deliberate. An earlier draft said only that
four self-additions reach the identity, which establishes that the order DIVIDES four and leaves
one and two open; a counter-reading caught the sentence, the underlying measurement had already
excluded them, and the text now says what was measured.

What this does NOT mean is that a forged carrier passes the release path: the carrier is
`signature.state: UNSIGNED` and goes through no signing path, and a real signature is what the
anti-case now uses. What it DOES mean reaches further than a first draft of this entry admitted,
and the correction is the same counter-reading's. `_signaturzeile` and `pruefe_v2` share ONE exit,
`_signatur_lage`, by explicit design (`gen_findings_register.py`, the function's own docstring says
changing it changes both). So the generated views — `audit_artifacts/600/views/uebersicht.md` and
`uebersicht.html` — report whatever that exit returns. A carrier carrying a zero key would be shown
to a REVIEWER as signed. The release path is not the only thing a signature state feeds; the audit
trail is the other, and a reviewer reading a wrong line is the cheaper failure only until someone
relies on it.

Refusing small-order keys at this one block is a code change with its own catch proof, not a
documentation edit, so it is not in this cut. Register entry
`SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`, target 6.2.0.

**A shipped tool verdict is quoted but not re-run.** `pyproject.toml` states that eight mypy
versions and six ruff versions exit 0 over this tree. `tests/test_shipped_comment_numbers.py` binds
the number of FILES each claim ranges over; it does not re-run the tools, because that means eight
interpreter-bound toolchains and minutes per run. The split is stated in the case's docstring
rather than blurred: bound is the size of the set, unbound is the verdict over it. Register entry
`SHIPPED-TOOL-VERDICT-NOT-RE-RUN-01`, target 6.2.0.

## Open — three public exporters coerce the verdict field, and A-15 fixes the boundary, not them

A-15 typed `passed`, `n` and `metric` at `decode_eval_claim`. That closes every path that goes
THROUGH the boundary, and `src/proofbundle/intoto.py` holds three that a library caller can reach
without it. All three were measured on 2026-09-19 at `99d89a8` by an adversarial review lens whose
falsification target was exactly this question, and all three are reproduced by an executable
case, not asserted:

| Where | Line | What it does with the field |
|---|---|---|
| `to_test_result_statement` | `intoto.py:246`, `:251` | `_RESULT_ENUM[bool(claim["passed"])]`, then `if claim["passed"]` |
| `to_eval_result_predicate` | `intoto.py:424` | `"passed": bool(claim["passed"])` |
| `svr_properties` | `intoto.py:551` | `if claim.get("passed")` sets `PROOFBUNDLE_THRESHOLD_MET` |

With a genuinely failing claim (`score 0.10`, `threshold 0.80`, `passed` set to the string
`"false"`, correctly signed), `decode_eval_claim` returns `None` as it should, and the three
functions called directly return `"PASSED"`, `passed: true`, and the threshold-met property.
`_require_export_fields` does not catch it: it tests for `None` and empty, and a non-empty string
passes that.

**Only the first of the three was documented before this file.** `tests/test_evalclaim_verify_boundary_types.py`
names it and measures that it stays open -- and that file, like the A-17 carrier above, arrives with
the evalclaim verify-boundary pull request and is not in this tree. The other two were carried
by nobody. Writing them down
here is the point of the entry — the earlier text would have read as if one hole were the whole
set, which is a claim of completeness that was never measured.

Why this does not block the tag: every path the shipped CLI takes goes through the boundary.
`cli.py:1685` decodes before `export_eval_result_dsse`, `intoto.py:584` decodes before
`export_svr_dsse`, and `hf_evals` and `policy.evaluate_policy` decode before their own coercions —
each of those checked in the same pass. What stays open is the direct library caller, which is a
real exposure for a published package and is stated as one, not minimised.

Target 6.2.0, and as a CLASS fix rather than three guards: one check that every public exporter
passes through, with the catch-proof at the public functions instead of at the CLI. Register entry
`DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01`.

## Named state, not a backlog item — the tool binding ships without its door

Owner word of 2026-09-20, option C: the due date for the tool binding falls without replacement,
card `OA-24e41ca200` is closed, there is no click, 6.1.0 ships without that door, and PARTIAL stays
PARTIAL.

What PARTIAL means here, because a reader should not have to reconstruct it. The card's answer of
2026-09-12 stands unchanged: the checking mechanism may be read from the tool repository, but only
from a committed head, never from a dirty worktree, and the receipt has to carry head and digest of
pre-sweep, class ledger and lens store in its gate line. A receipt without that line stays PARTIAL.
The component that would produce the line is rolled out through a privileged door, and that door is
gone.

Measured on 2026-09-20 before the card was closed: the door `runner_code_update` stands with zero
hits in the waiting set of the privileged-request file and was struck out on 2026-09-19; the commit
that struck it exists. So the click the card waited for cannot arrive. That is why the due date was
dropped, and it is not a missed step.

The consequence is a state with a name rather than an open work item: PARTIAL is the durable and
correct verdict over any commit of this repository, and the 68 classes that depend on the same
structural fact stay environment-blocked. Reading this as a backlog of 68 items would be the
mistake the card was closed to prevent.

WHERE THE 68 COMES FROM, because a number without a source is the defect this file is about.
It is not derived in this repository and cannot be: the class ledger it counts lives in the
tooling repository, not here. It is quoted from the card itself, whose subject text records the
measurement of 2026-09-12 — of 108 open proofbundle classes in that ledger, 68 are
environment-blocked, and their reason is the one structural fact this section describes: the
subject under test, the regression test or the evidence nodes live in this repository while the
ledger checks against the other one. A reader of this file alone cannot recompute the number,
and that limit is stated rather than papered over.

## Named state, not a backlog item — N16 is fixed on main and open in the published Action tag

`action/action.yml` on `main` passes `version` and `extras` through `env:` with a form check, the
way `command` already did, and `tests/test_action_input_injection.py` holds the rule: no file may
interpolate an externally controlled value into a shell body, all three inputs travel through
`env:`, and a planted injection has to be caught. That landed with the cut.

WHAT SHIPS TODAY IS OLDER. The published Action tag is `v6.0.0`, and there `action/action.yml`
still splices both inputs straight into the script text:

```
spec="proofbundle${{ inputs.version }}"
if [ -n "${{ inputs.extras }}" ]; then spec="proofbundle[${{ inputs.extras }}]${{ inputs.version }}"; fi
```

Only `command` travelled through `env:` at that tag. So anyone pinning `b7n0de/proofbundle@v6.0.0`
runs the unfixed form, and will keep running it until a new Action tag exists. Measured 2026-09-20
by reading the file at that ref, not inferred from the changelog.

This is stated as a named state rather than filed as open work because the remedy is not a code
change: the fix exists. What is missing is a published tag carrying it, and a new Action tag is an
outward act that falls behind the 6.1.0 tag and needs its own go-ahead. Until then the honest
sentence is the one in this heading, and a reader pinning the action should know which half they
have.

## Open — the cut points version-derived tooling at a cut that does not exist yet

The advisory audit-candidate matrix is RED on the head that carries this cut, and it is green
everywhere else. Measured on 2026-09-20 over the open pull requests and the trunk: FAILURE on this
branch, SUCCESS on `fix/610-evalclaim-verify-boundary` and on `fix/n16-action-input-injection`, and
SUCCESS on the last three runs of `main`. The difference between those heads is the version.

The mechanism is measured rather than inferred. `scripts/audit_candidate_matrix.py` sets
`VERSION_UNDER_TEST` from `pyproject.toml`, and this cut moved that value from 6.0.0 to 6.1.0. The
audit artefacts in the tree carry the cuts 360, 370, 380, 400, 500, 510 and 600; there is no 610,
neither on this branch nor on `main`, because the pre-tag round that produces it has not run. So
evidence that was bound to the previous version is no longer bound to the version under test, and
the matrix says so.

**This is the expected shape of a version cut, not a defect introduced by it**, and the job is
advisory for a related reason its own workflow comment gives: a full run needs a soak box, so a
non-green outcome is its ordinary CI state. What would have been dishonest is leaving a red context
on the release candidate without a sentence saying why it is red.

WHAT IS NOT MEASURED, and it is the part a reader should not assume: WHICH cell of the matrix went
to FAIL rather than to NOT_MEASURED. The run that carries that job is still open, and GitHub
releases job logs only when the run completes, so the log could not be read at the time of writing.
The mechanism above is measured; the specific cell is not.

## Named state, not a backlog item — the closing gate round does not run for 6.1.0

Owner word of 2026-09-21 (card `OA-ac65eda888`, option B): no deep-gate run on the frozen head.
The reason is measured, not a preference. The DEEP mode of the gate requires three qualified model
families; the operator's qualification register carries two, measured on 2026-09-21 with the
register's own reading. Running the six lenses below that floor and calling
the result `WITHSTANDS_DEEPGATE` would pass the word and miss its meaning, and the owner struck
that option as never having been on the table. Qualifying a third family is work after the tag,
not before it.

What that means for the audit-candidate matrix on the tagged head, stated before the tag rather
than discovered after it:

- **C6.2, C6.3 and C8.2 stay red**, as they did for 6.0.0. The soak artefact
  (`audit_artifacts/360/fuzz_soak_latest.json`) and the differential matrix
  (`audit_artifacts/360/rust_differential_matrix.json`) are re-run against the head that carries
  the signed pre-tag receipt and are signed by the owner, so the measurements themselves are bound
  to the candidate. Their gate line names the run that did not happen, and the matrix refuses a
  gate line without a `WITHSTANDS_DEEPGATE` verdict. That refusal is the correct reading of the
  state, not a defect in the matrix, and no code at the matrix changes for it (owner boundary of
  2026-09-07).
- **C6.3 additionally lacks the 24-hour soak** at the candidate head, exactly as S21 recorded for
  6.0.0. The short soak at the receipt head is the evidence C6.2 binds to; its duration and
  iteration count are in the signed artefact and in the ceremony report. The 24-hour run starts
  when the tree is frozen, runs beside the release, and is recorded after the tag in a dated
  addendum file next to this one, never as an edit to this file.
- **The pre-tag receipt binds this file** through its subject tree digest, so the state is in the
  tree the receipt attests; the receipt's own signed fields carry a command, digests and a runner
  line, not this text, and whether the runner line repeats the state is decided at the ceremony.

What this does NOT mean: no claim that the six lenses would have found nothing. A round that did
not run makes no statement about the tree, and this section exists so that nobody reads its
absence as a clean result.

## Honest limits of this file

- **No gate of the three release documents is evidenced by a run on the candidate head.**
  The figures in this file are derived from the register rather than retyped, and each one
  names exactly one head, so a reader can re-measure any of them. What that does NOT give
  is a gate run on the head being tagged: until S4 drives them, the three release documents
  carry numbers that were true where they were measured and are unproven here. That is a
  statement about the evidence, not a suspicion about the numbers, and it stops being true
  the moment S4 runs — which is the point of naming it now rather than after.

- **The funnel verdict on the 54 moved lines is a class judgement**, not 54 measurements. It is
  written that way on purpose; claiming 54 individual verdicts would be the more precise-looking
  and less true statement.
- **The P3 list is the audit's, re-read but not re-measured here.** Each entry names its file and
  line so a reader can check rather than trust.
- **`RESTRISIKO_600.md` stays untouched.** It is frozen at its tag and bound by the pre-tag
  receipt; the version assignment lives in the scope files and here, never there.
- **The three exporters above were measured in `intoto.py` only.** The lens read `intoto.py` and
  `evalclaim.py` end to end and the others in excerpts; `docs/`, `examples/` and
  `.github/workflows/` were excluded as non-executing. A fourth site elsewhere is not ruled out.
- **This file is written before the closing round**, so it cannot contain that round's findings. A
  finding of the closing round is a new iteration with a new freeze, never an edit to this file.
