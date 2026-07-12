# Release checklist

proofbundle ships supply-chain provenance for itself (the same idea the tool verifies). The one
non-negotiable invariant: **the artifact published to PyPI is the exact artifact that was
attested** — the release workflow builds once, attests those bytes, and gates the PyPI upload on
a sha256 match. This checklist covers the human steps around that.

## Release ordering (the tag comes last)

The order below is the convention, not a suggestion. A release is a fact about `main` (or a
`release/*` branch), never about an open feature branch.

1. **Land the code first.** Feature/fix branch → PR → **the Owner merges** to `main`. For a stable
   patch on an older line, merge to `release/v1.9.x` first, then merge that branch back into `main`
   so the two never diverge. **Fork the branch from `main` (or `release/v1.9.x`), never from a release
   tag** — a tag-based branch predates every later `## [Unreleased]` CHANGELOG section and re-conflicts
   on `CHANGELOG.md` on every PR (this happened twice on 2026-07-05 with branches cut from `v1.9.1`).
   A non-blocking CI check (`scripts/branch_base_check.py`) warns when a PR forks from a tag. See
   [CONTRIBUTING.md](CONTRIBUTING.md#branch-base-fork-from-main-never-from-a-release-tag).
2. **Tag the merged commit on the target branch — never the open feature branch.** Check out the
   merged `main` (or `release/*`) HEAD, confirm its CI is green, then `git tag vX.Y.Z` there and
   push the tag. Tagging an unmerged feature branch opens a window in which the release workflow
   ships a version to PyPI that `main` does not yet contain: an outside installer gets bytes the
   canonical branch cannot reproduce. This happened once, on **2026-07-05** (v1.9.2 was tagged from
   `stabilize-v1-public-trust` and released to PyPI before PR #8 merged). It is documented here as a
   one-time exception under explicit Owner-GO and is **excluded going forward** — the existing
   v1.9.2 tag is history and is left untouched.
3. **The release workflow runs from the tag.** `release.yml` builds once, attests those bytes, and
   gates the PyPI upload on the sha256 match (the invariant above). Release-notes automation and the
   GitHub Release page are populated after the workflow succeeds, from the tagged commit.

## One-time setup (before the first tag)

- [ ] Configure PyPI **Trusted Publishing**: pypi.org → the `proofbundle` project → Settings →
      Publishing → add publisher `b7n0de/proofbundle`, workflow `release.yml`, environment `pypi`.
- [ ] Create the GitHub **`pypi` Environment** (repo Settings → Environments → `pypi`) and add
      **required reviewers** — so pushing a `v*` tag cannot publish to PyPI without human approval.
- [ ] Enable **branch protection** on `main`: required CI (`test`, `crypto-floor`, `mutation`),
      required review, no force-push. Consider required signed commits.
- [ ] Verify the README assets exist (`assets/b7n0de-logo.svg`, `-dark.svg`, `demo.svg`) — the repo
      references them; a release with broken image links reads as abandonment. (They ship today; keep them present.)
- [ ] Turn the aspirational badges (PyPI version, Python versions, Downloads, SLSA, PEP 740) live
      only AFTER the first successful publish (they render broken/false before that).

## Beta / pre-release (any future pre-release line)

Historical note: the 2.0.0b1–b3 line shipped this way until **2.0.0 final** (2026-07-09); since
then the 2.x line is the stable default and the `[experimental]` extra ships with normal releases.
The checklist below is the convention for any FUTURE pre-release: `pip install proofbundle` never
pulls a PEP 440 pre-release, so the current stable stays the default while a preview stabilizes.

- [ ] Version string is the **PyPI** form, never the SemVer hyphen form: publish `2.0.0b1`
      (alpha `2.0.0a1`, rc `2.0.0rc1`) — `2.0.0-beta.1` is invalid on PyPI (PEP 440).
- [ ] The experimental bridge is behind the `[experimental]` extra AND under
      `proofbundle.experimental` (import-warns) — double-gated.
- [ ] Rehearse on TestPyPI, then tag the **merged** `main` HEAD (see *Release ordering*):
      `git tag v2.0.0b1 && git push --tags` (the hardened release workflow builds once + attests ==
      publishes, same as stable).
- [ ] Announce as a preview; invite the external audit before promoting toward `2.0.0`.
- [ ] `pip install --pre "proofbundle[experimental]==2.0.0b1" && python examples/experimental_enclave.py`
      from a clean env → exit 0.

## Per release

The version bump, changelog, and doc edits happen **on the branch, inside the PR** — the tag comes
after the merge (see *Release ordering* above).

- [ ] Bump `version` in `pyproject.toml` **and** `__version__` in `src/proofbundle/__init__.py`
      (they must match — CI/pitch cite the version).
- [ ] Update `CHANGELOG.md` (Keep-a-Changelog + SemVer; note any breaking change explicitly).
- [ ] Update the test-count and version strings in `README.md` if they changed.
- [ ] `make all` green locally (lint + typecheck + tests); `make tamper-demo` exits 0;
      `make mutation` reports all operators killed (documented-equivalent survivor excepted).
- [ ] Open the PR; confirm the CI matrix is green on all supported Pythons **and** the
      `crypto-floor` job; **the Owner merges** the PR to the target branch (`main`, or `release/*`
      then merge-back).
- [ ] On the **merged** target-branch HEAD (never the feature branch), confirm CI is green, then
      `git tag vX.Y.Z` there and push the tag.
- [ ] Watch the `build-and-attest` job: note the printed attested wheel/sdist sha256.
- [ ] Approve the `pypi` environment when prompted (required reviewer).
- [ ] Confirm the `publish-pypi` **digest gate** passed (published == attested) in the job log.
- [ ] After publish: verify the PyPI page shows the **PEP 740 attestation**, and that the wheel's
      sha256 on PyPI equals the attested subject digest and the `SHA256SUMS` on the GitHub Release.
- [ ] `pip install proofbundle==X.Y.Z && proofbundle demo` from a clean environment → exit 0.

## Verifying a published release (anyone)

```bash
pip download proofbundle==X.Y.Z --no-deps -d /tmp/pb
sha256sum /tmp/pb/*            # compare against the GitHub Release SHA256SUMS
gh attestation verify /tmp/pb/proofbundle-X.Y.Z-py3-none-any.whl --repo b7n0de/proofbundle
```
