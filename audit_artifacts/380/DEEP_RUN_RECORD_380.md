# DEEP run record — 3.8.0

pre-tag-adversarial-audit: RUN | version=3.8.0

The line above is the attestation. Everything below is what stands behind it, including what it does
**not** cover.

## The graded object

```
graded code        src/ tree 203644c61eff8851c2efb48e3d520ece54f000ef
frozen at          e0208e31c5b42969b8df2784485401038e10a4fb
record written at  a later commit on release/v3.8.0
src/ since freeze  UNCHANGED (measured: git diff --quiet e0208e3 HEAD -- src/)
tests/ since freeze CHANGED — the run's own findings added evidence, see D1
delta graded       v3.7.0..e0208e3 under src/: 14 files, 489 insertions, 19 deletions
```

The digest is named because §9 requires it, and because on 2026-08-17 the omission cost 5 h 48 min:
a finding record said `class_open`, the fix had landed on the trunk five hours earlier, and nothing
in the record pointed at the trunk. `scripts/finding_base_drift.py` now exists so the next reader
does not repeat it.

Mode `[DEEP-GATE: DEEP 6L/7I]`. Targets were frozen in `PRE_REGISTRATION_DEEP_380.md` **before**
anything ran.

## Results, per target

| # | Target | Result |
|---|---|---|
| D1 | origin/expectation comparisons are exact on every surface | **REFUTED, then fixed** |
| D2 | every new output field reports the question, not just the answer | holds over the corpus run |
| D3 | no public surface terminates with a raw exception on hostile input | holds, both directions |
| D4 | the pre-tag gate cannot be satisfied by a non-attestation file | holds against the real folder |
| D5 | nothing this release adds loosens an existing check | holds, both directions |
| D6 | the record's numbers match the tree | holds after the probe was corrected twice |

### D1 — refuted, and this is the run's substantive result

The question was not "do the corpus tests pass" (that only confirms) but "which comparison sites
exist, and which is uncovered". Measured: **14 sites at 10 parameters, 8 covered, 3 string
comparisons uncovered** — `expected_decision_ref`, `expected_profile`, `expected_root_b64`. Each was
tested only against a *wholly foreign* value, which cannot show a comparison is exact, because a
foreign value fails under `startswith`, `casefold` and `strip` too.

`FINDING_erwartungsvergleich_klasse.md` had been closed as "7 of 7 members". The member set was
hand-picked. That is the second time in two days the same shape appeared — the never-raise
population was the first — so the fix is not a third hand-added entry but a guard that derives the
population from the tree (`tests/test_erwartungsvergleich_population_guard.py`), plus the three
corpora. Its exemption is derived too: a parameter whose annotation admits no `str` is out, because
a near-miss corpus over case and whitespace has no subject on an integer. A parameter with no
readable annotation counts as uncovered — when in doubt, demand.

Rollback probes, anchors read from the original first: `decision_ref` → `startswith` turns 2 guards
red; `profile` → `startswith` turns 3 red; `root_b64` → `strip` turns 4 red; the baseline returns.

### D2 — holds over the corpus run

Eleven distinct failure causes, stdout hashed, control first: **11 causes, 11 distinct outputs, zero
collisions**. Both halves of the collision this release started with — a wrong `--log-vkey` against a
tampered signature — now separate. **This is not a proof of absence:** only this corpus was run.

### D3 — holds, both directions

A raw `raise` planted in `experimental.enclave.verify_enclave_attestation` — the member that entered
the population *the same day* — turns the property red, as does the same plant in the long-covered
`statuslist`. The baseline returns. The newest surface is the least-questioned one, which is why it
was chosen rather than a convenient one.

### D4 — holds against the real folder

All 11 files of this record were fed to the gate's own detector: **none grants it**. The detector is
alive (the canonical line returns True), and the overall verdict was `ok=False` with the honest
reason — right up until this file was written.

### D5 — holds, both directions

The sharp spot is `_ACCEPTED` in the never-raise property. This session added `OSError` there, which
is the base class of `PermissionError`, `TimeoutError` and `BrokenPipeError` — a fail-open on the
very axis the property defends. `main` had already made and corrected that mistake; the merge took
the narrow `FileNotFoundError`. Measured: a planted `PermissionError` goes **red** (not swallowed), a
planted `FileNotFoundError` stays green (the one deliberate admission).

### D6 — holds, after the probe was corrected twice

The first probe reported four contradictions. All four were **its own** false positives: "2 files
changed", "two files under `src/`" and "two files in this same directory" count the `src/` delta or
are a turn of phrase, not this folder. The probe had assumed "N files" always means the record.

That assumption was also in a guard shipped earlier the same day, where it had only been working by
luck. It is now bound to an explicit self-reference, with the false-positive cases pinned in its
meta-test. A second defect fell out of that: the word-number list ended at "ten", so the moment the
record grew to **eleven** files and the sentence was dutifully corrected, the guard silently stopped
checking it. A word list that does not contain the occurring value turns a checked number into an
unchecked one.

## What this attestation does NOT claim

- **Not "the code is correct."** Six targets over one delta is a bounded search, and the bound is
  named above.
- **Not "released."** The tag and the publish remain Owner acts.
- **Not "six independent reviewers."** This run was executed by one agent sequentially. That is
  weaker than the methodology's assumption, which is exactly why every target terminates in an
  executable probe with a control, and why the one refutation (D1) is reported as the main result
  rather than buried.
- **Not "the record is complete."** `audit_artifacts/` is pruned from the sdist; the CHANGELOG
  carries the limits that survive this run.

## Battery at the time of writing

2241 passed, 9 skipped, 417 subtests, ruff clean, mypy clean. The two tests that were red — both
demanding this very line — are the reason this file exists, and they were red for the right reason
until the run that justifies the line had actually happened.
