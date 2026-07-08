<!--
proofbundle PR template (OSS-Maintainer-Cockpit B1). Keep it light — a first-time contributor
should not be scared off. "Not sure" is a fine answer to any checkbox.
-->

## What & why

<!-- One or two sentences: what does this change and why. Link the issue it addresses. -->

Closes #

## Scope

- [ ] The change stays within the scope of the linked issue (no unrelated drive-by edits)
- [ ] I did **not** change build/release plumbing (`pyproject.toml`, `.github/workflows/`,
      lockfiles) — or, if I did, I explain why below and it is the point of this PR
- [ ] No new binary/blob/large test-fixture files (or explained below)

## Checks

- [ ] `ruff check .` and `mypy src` pass locally (or CI will tell me)
- [ ] Tests pass (`python -m unittest discover -s tests`) and I added a test if this fixes a bug
      or adds behaviour
- [ ] The library keeps its core promise: it proves authorship and integrity, deliberately **not**
      that a number is true — I did not add a claim it cannot back

## Notes for the maintainer

<!-- Anything that helps review: trade-offs, open questions, "not sure about X". -->

<!--
Security: please do NOT report a suspected vulnerability in a public PR/issue — use the private
channel in SECURITY.md (GitHub security advisory). Thank you for contributing.
-->
