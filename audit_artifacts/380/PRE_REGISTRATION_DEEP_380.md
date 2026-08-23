# Pre-registration — the DEEP run for 3.8.0, frozen before anything ran

**Nothing in this file asserts that the run completed.** It states what will be tried, against which
bytes, and what would count as a failure. It is written first so the targets cannot be chosen after
seeing the results.

## The graded object, named before grading

```
HEAD            e0208e31c5b42969b8df2784485401038e10a4fb
tree src/       203644c61eff8851c2efb48e3d520ece54f000ef
tree tests/     a4fe5be47066fc332f311e9da9647d8e338d8f06
tree scripts/   5c4b8876d197bfffaa0e8688eec047093f65d332
working tree    clean
```

**Why this block exists at all, in this file, at the top.** §9 of the 3.8.0 pre-registration has
required a named digest since the round began. Measured on 2026-08-16: three of the six finding
records named none, and two of the hex strings that *looked* like anchors were sha256 prefixes of
stdout, not commits. On 2026-08-17 that omission cost 5 h 48 min of duplicated work — a finding
record said `class_open`, the fix had landed on the trunk five hours earlier, and nothing in the
record pointed at the trunk. A rule that nobody executes is an intention. So: the object first,
then the grading.

## Scope, and the honest boundary of it

The delta this run grades is `v3.7.0..e0208e3` under `src/`: **14 files, 489 insertions, 19
deletions**. It does NOT re-grade the parts of the tree that 3.7.0 already shipped unchanged, and it
does not claim to. A DEEP run that says "everything is fine" about code it never opened is the
false-PASS this project spends most of its pages preventing.

## Mode

`[DEEP-GATE: DEEP 6L/7I]` — release-adjacent, so six lenses and up to seven iterations, per the
standing anchor. NORMAL 3L/3I is what this round has been running for individual increments; a tag
is outward-facing and gets the full depth.

**Executed by one agent, sequentially, not by a fan-out.** That is a real difference from the
methodology's assumption of independent reviewers and it is written here rather than left implicit:
a single reader is worse at catching its own blind spot than six independent ones, which is exactly
why every lens below must terminate in an EXECUTABLE probe rather than an opinion. Where a lens
cannot produce a probe, it reports NICHT MESSBAR and that is not a pass.

## Falsification targets, frozen

Each target states what would REFUTE it. A target that cannot be refuted by any input is not a
target, it is a slogan.

| # | Target | What refutes it |
|---|---|---|
| D1 | The new origin bindings are exact on every surface that has one | any near-miss (prefix, case, whitespace, full-width, NFD) accepted as the pinned origin |
| D2 | Every new output field reports the QUESTION, not just the answer | two runs with different causes producing byte-identical output on a field the release added |
| D3 | No new public surface can terminate with a raw exception on hostile input | a `_FORBIDDEN` termination from any surface in the discovered family |
| D4 | The pre-tag gate cannot be satisfied by a file that is not an attestation | a `.md` in `audit_artifacts/380/` other than the record granting the gate |
| D5 | Nothing added this release loosens an existing check | a guard that stays green after its defence is removed |
| D6 | The record's own numbers match the tree they describe | any count in `audit_artifacts/380/` that a fresh measurement contradicts |

## What a PASS here does and does not mean

It means: ready to be put in front of the Owner for the tag decision. It does **not** mean released,
and it does **not** mean the code is correct — six lenses over one delta is a bounded search, and
this file names its bound above. The Owner-GO for the tag remains a separate act.

## The record this run may write

Only if every target above survives may the canonical attestation line be written into this folder.
Writing it earlier would be the exact defect this round measured on 2026-08-16, when a documentation
edit satisfied the gate for a release with no audit at all.
