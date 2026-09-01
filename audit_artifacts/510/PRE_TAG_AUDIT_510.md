# Pre-tag adversarial audit — proofbundle 5.1.0

**Six-lens internal audit per `docs/PRE_TAG_AUDIT.md`, run on the release candidate before the tag.**

- Version: **5.1.0**
- Tree at audit time: `88831cd5f523`
- HEAD: `0cf529b` (merge of #165)
- Date: 2026-09-01
- Method: falsification-first — each claim of the CHANGELOG section was MEASURED, not read.

## Verdict

**One finding.** The release itself holds; a causal attribution in the CHANGELOG does not.

---

## L1 — correctness: do the CHANGELOG numbers hold?

**Claimed:** "23 commits, 41 files, 2071 insertions, 32 deletions, 0 files removed".

**Measured against `v5.0.0` at audit time:**

    63 commits · 131 files changed · 9350 insertions(+) · 84 deletions(-)
    deleted files: 0

**FINDING (documentation, not code):** the counts are stale. They were written on 2026-08-31 and
23 further commits (the deep-gate fixes, #165) landed after. The numbers are presented as a
measurement of the release, and a reader cannot tell they describe an earlier moment.

**The load-bearing claim survives**, and it is the one the MINOR decision rests on:

    -def / -class lines in the diff across src/ : 0
    deleted files                               : 0
    new public name                             : classify_eval_claim (added, measured)

Nothing removed, no signature changed → MAJOR is ruled out. New shipped material → PATCH is ruled
out. **MINOR remains correct**; only its stated arithmetic is out of date.

## L2 — no-fake: is the profile really in the distribution?

**Claimed:** 1 occurrence in the sdist, readable at its full 240 lines, docs entries 19 → 20,
wheel still 0.

**Measured** (fresh `python -m build --sdist`):

    occurrences of RECEIPT_ENVELOPE_PROFILE.md in the sdist : 1
    lines readable from inside the archive                  : 240
    docs entries in the sdist                               : 20
    conformance/envelope_profile entries                     : 32

Every number holds exactly as written.

## L3 — adversarial: try to REFUTE the fix

**Claim under attack:** "One `include docs/RECEIPT_ENVELOPE_PROFILE.md` line fixes it."

**Attack:** remove that line, rebuild, look.

    with the line     : 1 occurrence
    without the line  : 1 occurrence

Repeated in a CLEAN tree (`git archive HEAD` into a fresh directory, no `*.egg-info` cache
present, both builds run there): **the same result — the document ships either way.**

**FINDING — the attribution does not hold.** The document IS in the sdist (L2 measured it), but
not demonstrably *because of* that MANIFEST line. No other rule in `MANIFEST.in` covers the path
(there is no `graft docs`, no `recursive-include docs`; `graft docs/readiness_pack` and
`include docs/adr/renewal_policy.example.json` are different paths), and
`[tool.setuptools.package-data]` lists only `py.typed`, `eee_eval_schema.json`, `policies/*.json`.

**HONEST LIMIT:** the audit establishes that the stated cause does not produce the stated effect
on its own. It does NOT establish what does. The line is harmless and should stay — an allowlist
entry that names a file the distribution must carry is correct regardless of what else happens to
carry it. What needs correcting is the CHANGELOG's causal sentence, not the packaging.

**No release-blocking consequence:** the shipped artifact is correct (L2). The defect is in the
explanation, and an explanation that a stranger cannot reproduce is exactly what the profile
document exists to prevent.

## L4 — completeness of the shipped vectors

**Claimed:** 21 of 21 files, 10 of 10 `case.json`.

    conformance/envelope_profile files      : 21
    conformance/envelope_profile case.json  : 10

Holds.

## L5 — regression

    PYTHONPATH=src python -m pytest tests/ -q
    2637 passed, 169 skipped, 721 subtests passed in 405.44s

No failures, no collection errors. (A bare `python -m pytest` without `PYTHONPATH=src` aborts with
`ModuleNotFoundError: No module named 'proofbundle'` — an environment condition, not a defect; the
repo carries no venv.)

## L6 — fidelity: one version everywhere

    check_version_and_changelog.py: OK — source version 5.1.0, single-sourced across
    pyproject.toml / __init__.py / CITATION.cff, tracked places current, changelog carries the
    section, no undelivered post-tag drift.

**Limit stated by the tool itself:** external surfaces were NOT checked (neither `--external` nor
`--require-external` was given). RELEASE.md requires `--require-external` at release time; that
check belongs to the release run, not to this audit.

---

## Named findings

| # | Lens | Severity | Finding | Status |
|---|---|---|---|---|
| 510-F1 | L1 | documentation | CHANGELOG diff counts are stale (23/41/2071 vs measured 63/131/9350); the MINOR justification rests on numbers that no longer describe the release | open — correct the sentence |
| 510-F2 | L3 | documentation | "One `include` line fixes it" is not reproducible: the document ships with and without the line in a clean tree | open — correct the causal claim; keep the line |

Neither finding blocks the tag: the shipped artifact was measured correct (L2, L4), the suite is
green (L5), and the version is consistent (L6). Both are claims a stranger could check and would
find wanting — which is the standard this release's own profile document sets.
