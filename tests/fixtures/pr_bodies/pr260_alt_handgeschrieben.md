The house deep-gate ran two lenses over the landed R-B4 fix (237bb07ae4) against three pre-registered
falsification targets. An independent lens REFUTED the third one, with executed proof, and the sentence
it refuted is in this repository, written by the session that wrote the fix:

  sdjwt_issue._require_bool_verdict, as landed: "BundleFormatError and not ValueError: issue_sd_jwt
  already raises ValueError for a malformed status and a wrong-length holder key … so a caller that
  guards one guards all five with one except."

Its second half is true and is kept: all five R-B4 sites raise BundleFormatError, so one
except BundleFormatError covers those five. What it left out is what a reader takes from the first
half. Measured: issubclass(BundleFormatError, ValueError) is False, while the same function raises a
genuine ValueError for a malformed status and a wrong-length holder key. So issue_sd_jwt has TWO
DISJOINT refusal families and no single except covers all of its refusals — except ValueError lets the
R-B4 refusal through, and except ProofBundleError lets the status refusal through. Both directions are
now executed, not argued.

A third form exists one layer out and is not an exception at all: decode_eval_claim refuses a non-bool
passed by RETURNING None, its documented contract, so a caller guarding either family gets a bare
TypeError from the following subscript. Measured: issubclass(EvalClaimError, ProofBundleError) is
False and issubclass(EvalClaimError, ValueError) is True — the two families cross there.

Why a contract and not only a corrected sentence: the lens measured the types with issubclass and found
no test in this repository that does. A promise about exception types belongs in a contract, because
prose about types goes stale without anything breaking — this docstring was wrong on the day it landed
and nothing failed.

tests/test_abweisungsformen_sind_drei.py, 12 cases and 7 subtests, 0.14 s. It carries three guards
rather than catch proofs alone, because a file that only proved "these two excepts do not overlap"
would also pass if the refusals stopped happening: a valid claim still decodes with a bool verdict, a
valid claim is still issued as a compact SD-JWT, and one case pins the half of the docstring that was
right. Neighbouring R-B4 contracts re-measured over the final tree: 59 passed, 241 subtests, ruff clean.

This is a documentation defect, not a hole. Every refusal fires; only their FORM differs, and a caller
who believed the sentence would route the R-B4 refusal into the wrong error path.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>

Head of this branch: `d76d1f9e0346ee3a939db744f69b8bd3b9df6e13`, on top of `237bb07ae4`. The lens that
produced this finding is filed at
`office/governance/berkeley_gate/runs/lenses/rb4_verdikt_muss_bool_sein/LINSE_02_*.md` in the house
repository, alongside a second-family lens whose verdict agreed on all three targets while two of its
three reasons were wrong — which is why the agreeing verdict was not counted as corroboration and the
independent run happened at all.

Register line: `DREI-DISJUNKTE-ABWEISUNGSFORMEN-UND-EIN-DOCSTRING-DER-EINE-EINZIGE-BEHAUPTET-01`.

Still open from the same lens, deliberately not folded in here: `intoto._require_bool_verdict` and
`sdjwt_issue._require_bool_verdict` are two independent implementations with no shared import and the
same intent. That is "instance fixed, class open" on my own fix, and R-B4 had a sixth site for exactly
that reason — it needs its own change rather than a rider on a documentation fix.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

