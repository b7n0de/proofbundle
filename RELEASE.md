# Release checklist

proofbundle ships supply-chain provenance for itself (the same idea the tool verifies). The one
non-negotiable invariant: **the artifact published to PyPI is the exact artifact that was
attested** — the release workflow builds once, attests those bytes, and gates the PyPI upload on
a sha256 match. This checklist covers the human steps around that.

## One-time setup (before the first tag)

- [ ] Configure PyPI **Trusted Publishing**: pypi.org → the `proofbundle` project → Settings →
      Publishing → add publisher `b7n0de/proofbundle`, workflow `release.yml`, environment `pypi`.
- [ ] Create the GitHub **`pypi` Environment** (repo Settings → Environments → `pypi`) and add
      **required reviewers** — so pushing a `v*` tag cannot publish to PyPI without human approval.
- [ ] Enable **branch protection** on `main`: required CI (`test`, `crypto-floor`, `mutation`),
      required review, no force-push. Consider required signed commits.
- [ ] Provide the real README assets (`assets/b7n0de-logo.svg`, `-dark.svg`, `demo.svg`) — the repo
      currently references them; a release with broken image links reads as abandonment.
- [ ] Turn the aspirational badges (PyPI version, Python versions, Downloads, SLSA, PEP 740) live
      only AFTER the first successful publish (they render broken/false before that).

## Beta / pre-release (v2.0 line)

The v2.0 line ships as a PEP 440 pre-release while the experimental TEE-attestation bridge
stabilizes. `pip install proofbundle` never pulls a pre-release, so v1.x stays the default.

- [ ] Version string is the **PyPI** form, never the SemVer hyphen form: publish `2.0.0b1`
      (alpha `2.0.0a1`, rc `2.0.0rc1`) — `2.0.0-beta.1` is invalid on PyPI (PEP 440).
- [ ] The experimental bridge is behind the `[experimental]` extra AND under
      `proofbundle.experimental` (import-warns) — double-gated.
- [ ] Rehearse on TestPyPI, then `git tag v2.0.0b1 && git push --tags` (the hardened release
      workflow builds once + attests == publishes, same as stable).
- [ ] Announce as a preview; invite the external audit before promoting toward `2.0.0`.
- [ ] `pip install --pre "proofbundle[experimental]==2.0.0b1" && python examples/experimental_enclave.py`
      from a clean env → exit 0.

## Per release

- [ ] Bump `version` in `pyproject.toml` **and** `__version__` in `src/proofbundle/__init__.py`
      (they must match — CI/pitch cite the version).
- [ ] Update `CHANGELOG.md` (Keep-a-Changelog + SemVer; note any breaking change explicitly).
- [ ] Update the test-count and version strings in `README.md` if they changed.
- [ ] `make all` green locally (lint + typecheck + tests); `make tamper-demo` exits 0;
      `make mutation` reports all operators killed (documented-equivalent survivor excepted).
- [ ] Confirm the CI matrix is green on all supported Pythons **and** the `crypto-floor` job.
- [ ] Tag `vX.Y.Z` and push the tag.
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
