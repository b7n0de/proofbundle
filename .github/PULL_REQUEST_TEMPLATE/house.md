<!--
The house form, for pull requests a b7n0de session opens. Outside contributors keep the light
default template; this one is selectable with ?template=house.md or gh pr create --template house.md.

Bodies written by a session come out of scripts/render_pr_body.py and a data source under pr_bodies/,
not out of this skeleton. This file exists so the same shape is reachable in the browser, and so a
reader who sees it in one place recognises it in the other. One paragraph is one line: no hard wraps.
-->

Head of this branch: `<commit>`, on top of `<base commit>`. <files and lines, measured, not typed.>

## Where this came from

<One to three paragraphs, each on a single line. What prompted the change, and how it was found.>

## The defect

<What is wrong, stated so a reader can disagree with it. For a feature, rename this block to "The change".>

## The fix

<What changed and why that is the right level to fix it at. A code block if the core fits in ten lines.>

## Measured

| What | Value | Source | Commit |
|---|---|---|---|
| <what was measured> | <the value> | <file, command or run> | `<commit>` |

## Not changed

<What was deliberately left alone, and anything the change does not claim.>

## Marking

Written by an AI session of b7n0de under owner review.

Measurement, not certification.
