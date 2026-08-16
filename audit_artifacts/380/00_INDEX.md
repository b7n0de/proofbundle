# 3.8.0 pre-tag record — index

**There is no verdict for 3.8.0.** The gate (`scripts/pre_tag_audit_gate.py --strict`) is red, and it
must be: nothing in this directory attests a completed run. Read that as the state, not as an
omission.

**This file carries no discipline marker word**, on purpose. The gate on this branch grants a pass to
any non-negated marker line in any `.md` here, so an index that named the vocabulary would attest the
release by describing it. That property is itself one of the records below.

The 3.7.0 record was a single file. This one is eight, because the run kept finding things about its
own instruments. The order below is the order a reader needs, not the order they were written.

## Start here

| File | What it is |
|---|---|
| `PRE_REGISTRATION_380.md` | the targets, frozen before anything ran — plus four appended sections (§8–§11) correcting the run's own rules while it ran. §11 carries the current binding set and the rule that replaced an enumeration |
| `FALSIFICATION_F1_F7.md` | one lens: falsification-first with executable exploits. Seven targets stated, four hold, **three fell** — all three grading errors of mine, not defects in the release |
| `MESSUNG_das_tor_von_pr139.md` | why the release cannot be cut honestly on this branch's gate, and what PR #139 changes. Both gate versions measured side by side |

## Open findings — each is a decision, not a note

| File | State | What it needs |
|---|---|---|
| `FINDING_erwartungsvergleich_klasse.md` | `class_open`, 1 of 7 members closed | **six** neighbouring comparison surfaces have no near-miss evidence; each was loosened individually and the full suite stayed green. `main`, outside this release's delta |
| `FINDING_nachbarflaeche_ohne_origin_bindung.md` | `class_open` | `verify --trusted-checkpoint` accepts a checkpoint from any log and the subcommand has no option to bind the origin. The heaviest open item of the round |
| `FINDING_json_trennt_die_drei_ursachen_nicht.md` | open, narrowed twice | the `--json` path cannot separate a wrong key from a tampered signature. Two executable guards hold the measured state, one per half |
| `FINDING_quorum_erreicht_ununterscheidbar_von_keins_verlangt.md` | `class_open` | `witnesses_ok: true` with zero confirming witnesses, and `threshold` is not in the output |
| `FINDING_never_raise_population.md` | `class_open`, pre-existing | the never-raise family property walks a hand-maintained module list; 11 surfaces across 7 modules are outside it |

All five are on `main` and predate this release. The rule this run follows is that a `main` finding is
**reported**, not folded into a release that did not cause it.

## What this run changed about itself

Worth stating because it is the honest summary: the subject held every measurement, and the
*instruments* did not. Two guards built during the run were shown by counter-reads to measure
nothing — one selected the wrong line of a fixture, one was bypassable by three rewrites. Both are
rebuilt and each carries a rollback probe. Five numbers in these records were wrong and are corrected
in place with the measurement that replaced them, rather than quietly amended.

The pattern behind most of it has one shape: **a number measured over one population and reported
over another.** It appears in the suite count (wrong environment), the file counts (wrong endpoint),
the sdist member count (no counting reproduces it), the violation count (one case not counted), and
the wrapped-call-site count (an enumeration read as complete).

## Reading order for an auditor

1. `PRE_REGISTRATION_380.md` §1–§7 — what was promised before anything ran.
2. `FALSIFICATION_F1_F7.md` — what was tried and what fell.
3. `PRE_REGISTRATION_380.md` §8–§11 — what the run had to correct about its own rules, in order.
4. The five findings, in the table above.
5. `MESSUNG_das_tor_von_pr139.md` — why the gate is red for the right reason only after #139.
