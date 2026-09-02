# What the Scorecard badge says, including the parts that are low

The badge is live, so it moves. This file is the measurement behind it, not a summary of it.

**Measured 2026-09-02T11:12:23Z** against `api.scorecard.dev`, the JSON endpoint for `github.com/b7n0de/proofbundle`. Overall score **7 / 10**.

Where a value differs from an earlier reading, the new value stands with its date and the old one
is not carried forward.

| Check | Score |
|---|---|
| Binary-Artifacts | 10 |
| CI-Tests | 10 |
| Dangerous-Workflow | 10 |
| Dependency-Update-Tool | 10 |
| Fuzzing | 10 |
| License | 10 |
| Packaging | 10 |
| SAST | 10 |
| Security-Policy | 10 |
| Token-Permissions | 10 |
| Vulnerabilities | 10 |
| Signed-Releases | 6 |
| Branch-Protection | 3 |
| Pinned-Dependencies | 3 |
| CII-Best-Practices | 0 |
| Code-Review | 0 |
| Contributors | 0 |
| Maintained | 0 |

## The four zeros, one sentence each

- **Maintained (0/10)** — The check wants sustained activity on the default branch across a 90 day window. This repository is younger than that window. It resolves itself with time and is not worth chasing.
- **Code-Review (0/10)** — Most commits are not reviewed by a second person. That is structural for a single maintainer, and the zero is an accurate description of it rather than a defect to hide. It moved from 1 to 0 since the 2026-08-10 reading.
- **CII-Best-Practices (0/10)** — The OpenSSF Best Practices badge has not been applied for. The criteria were walked through honestly first, in [docs/openssf_best_practices_self_assessment.md](openssf_best_practices_self_assessment.md).
- **Contributors (0/10)** — The check counts contributors from two or more organisations. This is a one person project, and the zero says exactly that.

## The three in between

- **Signed-Releases (6/10)** — the check reads GitHub release assets looking for a signature file.
  It read 0 on 2026-08-10 and reads 6 today; the release signing path changed in between.
- **Branch-Protection (3/10)** — the check cannot see every setting through the API it uses, and
  the ruleset in force is stricter than the value suggests. This is the value as measured, not as
  argued.
- **Pinned-Dependencies (3/10)** — workflow actions are pinned by commit SHA; the deduction comes
  from unpinned dependencies elsewhere in the toolchain.

## Honest limit

A Scorecard number measures what the checks can see from outside. It is evidence about the
repository's posture, not about whether the code is correct. Nothing in this file should be read
as a claim about the latter.
