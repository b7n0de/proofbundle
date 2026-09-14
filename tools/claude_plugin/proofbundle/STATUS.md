# Status of this plugin — NOT ready, scope re-cut on 2026-09-14

**Do not publish, do not submit, do not treat as evidence of anything.**

## What this directory currently is

A minimal plugin with one skill that explains how to verify a proofbundle agent-review
receipt. It was built for an earlier cut of stage 1 and that cut has been replaced.

## What stage 1 now requires, and this does not do

Stage 1 is the **agent-review receipt for a Codex answer, end to end** — the same procedure as
Z47: capture the exact answer text with its reference state, sign it with the fixed local
profile, have an **independent offline check by a different session in a fresh environment**, and
cover three negative cases: altered subject, wrong reference state, inadmissible quality claim.

This directory contains none of that. It contains a skill that describes a verification; the
procedure itself, its negative cases and its independent check do not exist here.

## What was measured, and what that measurement is worth

`claude plugin validate --strict` passes, twice, and a planted-defect probe fails as it should.
**That is a structure check of the manifest and the frontmatter — it is not a cryptographic
proof and must not count as evidence of the receipt path anywhere.** Two reviews read the text of
the skill (one Claude lens, one foreign family) and found four real defects, since fixed. Reading
a text is not measuring a behaviour.

So: for its actual purpose, this plugin has **no evidence at all**.

## Corrections carried in from the external review

- `dependencies` in a plugin manifest names **other plugins**, not a Python dependency. The
  documented, isolated install path for proofbundle 6.0.0 belongs in a README and has to be
  measured on a fresh environment before anything is handed over.
- A `Stop` hook **can** block; an earlier list of blocking hook events here was wrong. It does
  not take back what has already run.
- No claim of a general technical lead over neighbouring plugins. Catalogue state and project
  state are named separately or not at all.

## Open

Stage 1 per the new cut, then stages 3 to 5 against that subject. Owner word before any
submission. The pin on 6.0.0 and the location under the plugin path are confirmed and unchanged.
