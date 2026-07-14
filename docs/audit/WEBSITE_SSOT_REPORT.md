# Website SSOT Report (G1)

The proofbundle website's factual claims are generated from a single source of truth (SSOT), not
hand-edited, and a CI drift gate blocks a merge when any surface disagrees. This is the G1 deliverable;
it records the SSOT relationship and its verification. No release is claimed here (human-release).

## The SSOT chain

```
proofbundle source (a tagged release) ──► release-manifest SSOT ──► website + technical note
        (code, tests, SPEC)              (proofbundle_facts.json,     (product page, deep dive,
                                          computed, never typed)        PDF label)
```

- The release-manifest SSOT carries the load-bearing facts: `version`, `specRevision`, `testCount`,
  `mutationCount`, `releaseCommit`, `supportedVersions`, `evidenceClasses`.
- It is **computed** from the real source at a ref (never hand-typed), so the website and note cannot
  drift from the shipped code without the manifest also changing.

## CI drift gate

A blocking CI gate compares, and fails the merge on any drift between: `pyproject` version, PyPI latest,
`CHANGELOG`, `SPEC`, the deployed website (both the directory URL and `index.html` individually — the
cache-split is checked), the technical note, the test report, the mutation report, and the support
matrix. A scheduled run also catches a drift introduced by a downstream release even without repository
activity.

## Verification (re-checked 2026-07-14, see BASELINE_3_1_3.md)

| Surface | State | Evidence |
|---|---|---|
| PyPI latest | 3.1.3 | pypi.org/pypi/proofbundle/3.1.3/json resolves |
| Website product + deep-dive | 3.1.3 (not 3.1.0) | version labels 3.1.3; `v3.2.0` appears only as planned/target, never as the current PyPI package |
| SSOT facts manifest | 3.1.3, real test count | computed; the homepage-sync doctor PASSes with 0 findings |
| GitHub latest release | v3.1.3 | `gh release list` shows `v3.1.3 Latest` |
| Drift gate | active + blocking | scheduled + pull_request triggers |

Result: **Website = PyPI = GitHub-Latest = SPEC = SSOT, all 3.1.3, one real test count, no cache split,
drift gate active.** The 3.2.0 surfaces (this branch) are additive and unreleased; when 3.2.0 ships the
same SSOT computes the new facts and the website + note are regenerated from it in the same increment.
