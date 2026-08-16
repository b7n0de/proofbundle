# 3.8.0 pre-tag record — index

**There is no verdict for 3.8.0.** The gate (`scripts/pre_tag_audit_gate.py --strict`) is red, and it
must be: nothing in this directory attests a completed run. Read that as the state, not as an
omission.

**This file carries no discipline marker word**, on purpose. The gate on this branch grants a pass to
any non-negated marker line in any `.md` here, so an index that named the vocabulary would attest the
release by describing it. That property is itself one of the records below.

The 3.7.0 record was a single file. This one is ten files, because the run kept finding things about
its own instruments. The order below is the order a reader needs, not the order they were written.

The count in that sentence read "eight" until it was measured. It is stated as "ten **files**" rather
than as a bare number so that the guard can check it: the number is now attached to the noun it
counts, which is the difference between a claim a test can hold and one only a careful reader can.

## Start here

| File | What it is |
|---|---|
| `PRE_REGISTRATION_380.md` | the targets, frozen before anything ran — plus four appended sections (§8–§11) correcting the run's own rules while it ran. §11 carries the current binding set and the rule that replaced an enumeration |
| `FALSIFICATION_F1_F7.md` | one lens: falsification-first with executable exploits. Seven targets stated, four hold, **three fell** — all three grading errors of mine, not defects in the release |
| `MESSUNG_das_tor_von_pr139.md` | why the release cannot be cut honestly on this branch's gate, and what PR #139 changes. Both gate versions measured side by side |

## Findings — each is a decision, not a note

Four of the six were closed inside this release: two by Owner order (`OA-714ae03760`,
`OA-a41a514b63`, both answered "noch in 3.8.0") and two under the Owner's standing
instruction that all gaps be closed inside 3.8.0 — each against this record's own
recommendation to defer them. The
recommendation is kept in each file rather than overwritten: the Owner overruled a judgement call,
not an error of fact, and a record that silently adopts the decision it argued against is less
useful to the next reader than one that shows both.

| File | State | What it needs |
|---|---|---|
| `FINDING_erwartungsvergleich_klasse.md` | **closed** by `OA-714ae03760`, 7 of 7 members | was: six neighbouring comparison surfaces with no near-miss evidence. All six now run the shared corpus `tests/_beinahe_treffer.py`; each was verified by a rollback probe, and the pre-existing tests were measured to stay green under the same loosening — which is why the class was open |
| `FINDING_nachbarflaeche_ohne_origin_bindung.md` | **closed** by `OA-a41a514b63` | was: `verify --trusted-checkpoint` accepts a checkpoint from any log with no option to bind the origin. Now `--expected-origin` on the CLI and `expected_origin=` on `verify_witnessed_checkpoint`, six rollback probes. Closing it measured something the finding had not: a pinned *key* does not bind the origin either |
| `FINDING_json_trennt_die_drei_ursachen_nicht.md` | open, narrowed twice — **and this one is THIS release's**, see below | the `--json` path cannot separate a wrong key from a tampered signature. Two executable guards hold the measured state, one per half |
| `FINDING_quorum_erreicht_ununterscheidbar_von_keins_verlangt.md` | **closed** | was: `witnesses_ok: true` with zero confirming witnesses and no `threshold` in the output. The bound now ships with its boolean; the family was measured over every value-taking flag and this was its one member. Its deferral reason was overtaken, not wrong |
| `FINDING_never_raise_population.md` | `class_open`, pre-existing | the never-raise family property walks a hand-maintained module list; 11 surfaces across 7 modules are outside it |
| `FINDING_pruefer_fehler_liest_sich_wie_artefakt_fehler.md` | **closed** | was: a typo in the verifier's own command line produced output byte-identical to "this file is not a proof". `detail` now reaches both output paths; all four causes separate. Re-measuring while closing moved the count from three colliding causes to two — an effect of this release's `threshold` field, written out rather than silently renumbered |

**FIVE of the six findings are on `main` and predate this release — exactly one is ours.** Two drafts of this
paragraph were wrong before this one: the first said "all five" (it was four of five), the second was
correct at the time and went stale the moment a sixth finding was added. That is the same error this
record spends most of its pages correcting — a summary label checked once and then carried — and it
is written out here rather than quietly renumbered. The second time it was caught by a counter-count
before the paragraph was published; the first time it was not.

Measured, per finding, by asking whether its subject exists at `v3.7.0`:

```
erwartungsvergleich (kbjwt: expected_aud != aud)      v3.7.0 ja   -> Altbefund
nachbarflaeche (verify --trusted-checkpoint)          v3.7.0 ja   -> Altbefund
json trennt drei ursachen (out["expected_origin"])    v3.7.0 NEIN -> THIS RELEASE
quorum (witnesses_ok)                                 v3.7.0 ja   -> Altbefund
never-raise population (_MODULES)                     v3.7.0 ja   -> Altbefund
pruefer-fehler (--threshold, _tlog_failclosed)        v3.7.0 ja   -> Altbefund
```

The difference is not bookkeeping. For the five, the rule this run follows is that a `main` finding is
**reported**, not folded into a release that did not cause it. The third is different: `expected_origin`
in the JSON output is new **here**, the over-wide claim about what it separates was made **here**, and
its correction therefore belongs to this release rather than to a later one. It is corrected in place,
in the CHANGELOG and in the finding, with two guards that hold the measured state.

## What this run changed about itself

Worth stating because it is the honest summary: the subject held every measurement, and the
*instruments* did not. Two guards built during the run were shown by counter-reads to measure
nothing — one selected the wrong line of a fixture, one was bypassable by three rewrites. Both are
rebuilt and each carries a rollback probe. Seven numbers in these records were wrong and are
corrected in place with the measurement that replaced them, rather than quietly amended.

Two of the seven were in **this index**, and both survived the guard written to catch exactly this:
"the five findings" (there were six) and "this one is eight" (there were ten). The guard matched only
the phrasing `N of the M` — one grammatical form of the invariant — while two neighbours of that form
sat in the same file. That is the round's own lesson applied to the round's own instrument: fixing the
instance and not sweeping the neighbours. The guard now checks any count attached to `findings` or
`files`, and the sentences were rewritten to attach their numbers to those nouns.

The pattern behind most of it has one shape: **a number measured over one population and reported
over another.** It appears in the suite count (wrong environment), the file counts (wrong endpoint),
the sdist member count (no counting reproduces it), the violation count (one case not counted), and
the wrapped-call-site count (an enumeration read as complete).

## Reading order for an auditor

1. `PRE_REGISTRATION_380.md` §1–§7 — what was promised before anything ran.
2. `FALSIFICATION_F1_F7.md` — what was tried and what fell.
3. `PRE_REGISTRATION_380.md` §8–§11 — what the run had to correct about its own rules, in order.
4. The six findings, in the table above — two open, four closed.
5. `MESSUNG_das_tor_von_pr139.md` — why the gate is red for the right reason only after #139.
