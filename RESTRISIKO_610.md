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

## Open — the 54 lines moved to 6.2.0

Full text with its origin section in `docs/release_scope/6.2.0.md`, taken over word for word from
the 6.1.0 scope at `79f66a2`; byte equality checked, 54 expected, 54 present, none missing, none
foreign. Identifiers, so this file can be read without a second one:

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

**A-17** is not in the list above. It said `commit_alg` must be present but its value is never
compared against `COMMIT_ALG`, so `"sha1-unsalted"` decodes. An external review lens reported the
same defect independently as part of a wider P2 about value domains. One fix closes both. Measured
after the fix with a clean control arm: `sha1-unsalted` rejected, `md5-plain` rejected,
`sha256-salted-v1` accepted.

Two independent paths converging on one defect is the useful part of that story, and it is the
reason this entry is here instead of quietly absent.

## Open — the two commitment patterns at the verify boundary

`schemas/eval_claim_v0_1.schema.json` documents `^sha256:[0-9a-f]{64}$` for `model_id_commit` and
`dataset_id_commit`. The verify boundary does not enforce it; a signed claim with an arbitrary
string in either field decodes.

Not fixed in 6.1.0, and the reason is measured rather than a preference. The check is three lines
and works, but it turns five existing cases in `tests/test_cli_eval.py` red, because they sign
claims with placeholder commitments such as `sha256:x`. Isolated by measurement: 5 of 5 green
without the two patterns, 4 red with them. Rewriting five house tests so a new check passes is its
own change with its own measurement of what else signs placeholders.

Carried in `tests/test_eval_claim_domains_are_enforced.py` as `BEKANNTE_LUECKEN`, and that list
fails in both directions — an entry whose gap has since been closed turns the test red and asks to
be deleted. Verified with a planted closure. Register entry
`COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01`, target 6.2.0.

## Honest limits of this file

- **The funnel verdict on the 54 moved lines is a class judgement**, not 54 measurements. It is
  written that way on purpose; claiming 54 individual verdicts would be the more precise-looking
  and less true statement.
- **The P3 list is the audit's, re-read but not re-measured here.** Each entry names its file and
  line so a reader can check rather than trust.
- **`RESTRISIKO_600.md` stays untouched.** It is frozen at its tag and bound by the pre-tag
  receipt; the version assignment lives in the scope files and here, never there.
- **This file is written before the closing round**, so it cannot contain that round's findings. A
  finding of the closing round is a new iteration with a new freeze, never an edit to this file.
