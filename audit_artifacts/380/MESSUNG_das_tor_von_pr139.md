# Measurement — what PR #139 changes about the release gate, run against both versions

**This file deliberately carries no discipline marker word.** The vectors it reports would flip the
CURRENT gate to a pass, which is the very defect being reported; writing them out here would
reproduce it inside the release record. They live in the run's scratch evidence instead, and this
file states the counts and the shapes.

**Nothing here asserts that a pre-tag audit ran.** The gate is red at the time of writing and must be.

## Why this measurement exists

The pre-tag gate is wired with `--strict` as the FIRST step of the release workflow. It is the last
blocking check between a tag and PyPI. A lens measured that it does not correlate with the thing it
is named for — in either direction — so the question "can this release be cut honestly" turns on
whether the gate can be satisfied by a true statement and only by a true statement.

## What was measured

Both versions of `scripts/pre_tag_audit_gate.py` — the one on this branch and the one in PR #139 —
were loaded side by side and evaluated against the same throwaway repository tree, one record file
per vector. Control first, because a gate that always says MISSING would look perfect on the
false-pass axis: **with an empty record, both versions report MISSING.** The measurement is live.

| Vector class | current gate | PR #139 |
|---|---|---|
| **A** — twelve sentences that assert an audit did **not** run, in several languages and markup forms (comment, fence, front matter, strikethrough, question, URL) | **0 of 12** correct — every one grants a pass | **12 of 12** correct |
| **B** — four honest attestations in this project's own house style | 0 of 4 | 0 of 4 |
| **C** — the canonical attesting line carrying this version | correct | correct |
| **D** — the canonical line carrying a **previous** version | grants a pass — wrong | correctly refused |

## Reading it

**Class A is the release blocker, and #139 closes it completely.** The current gate's marker/negation
pair is an enumeration: it lists the ways a sentence can deny something, and every way not on the
list reads as an assertion. Twelve of twelve got through. #139 inverts the polarity — there is one
closed full-line form, and a denial cannot live inside a closed form, so no vocabulary has to be
enumerated.

**Class D is a hole nobody had reported.** Until #139 the version-scoped folder was the only anchor,
so a record copied from an earlier release attested the new one by sitting in the right directory.
#139 puts the version inside the attested line, and the line must name the version being tagged.

**Class B looks unchanged and is not a defect.** Both versions refuse an honest prose attestation —
because in #139 prose is explicitly *presentational* and cannot move the verdict in either direction.
The category dissolves rather than being fixed: an attestation is made with the canonical line, not
with a sentence. That is the right shape. Under the current gate the same four sentences are refused
for the opposite reason — each contains a word the negation list treats as a denial — which means a
truthful record written in this project's own style is rejected while twelve untruthful ones pass.

## What this does and does not establish

It establishes that the merge order already chosen for these pull requests is load-bearing rather
than cosmetic: without #139, satisfying the gate means writing a sentence that carries a marker word
and avoids a list of others, which is an incentive to write around a check instead of attesting to a
fact.

It establishes nothing about whether an audit has been run. #139's own comment states its honest
limit plainly — the canonical line is provenance-*shaped*, not provenance. The end state is a
runner-signed record whose subject digest equals the artifact being tagged, and this repository does
not have that signing path. What #139 closes is that prose can no longer move the verdict.
