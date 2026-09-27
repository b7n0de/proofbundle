# Release checklist

proofbundle ships supply-chain provenance for itself (the same idea the tool verifies). The one
non-negotiable invariant: **the artifact published to PyPI is the exact artifact that was
attested** — the release workflow builds once, attests those bytes, and gates the PyPI upload on
a sha256 match. This checklist covers the human steps around that.

## Release gate (answer this before asking for the Owner-GO)

**No calendar, no cadence, no waiting period.** A release happens when it can answer the questions
below, not because a date arrived. What is slowed down is vagueness, not speed — whoever can answer
this list today releases today.

Every line is checkable by someone else. "I think so" is not an answer.

- [ ] **A written scope list exists** for this version: what is in, and what is explicitly out, with
      one reason per line. For a PATCH the reason must survive the SemVer question: no semantic
      change, no new obligation, no changed behaviour at a public interface. In doubt, leave it out
      and say so in the list. Scope lists live in `docs/release_scope/<version>.md`.
- [ ] **`scripts/check_version_and_changelog.py --external --require-external` is green.** Source
      (`pyproject.toml`), the two derived files, the tracked prose places, PyPI and the project page
      all state the same version. `--require-external` is deliberate here: at release time,
      "we could not reach it" must block, because that is exactly when the number matters.
- [ ] **No security-relevant work exists only locally**, in a stash or under `/tmp`. Measure it, do
      not remember it: `git stash list` plus `git branch -r --contains <sha>` per entry.
      `git rev-list --all --not --remotes` alone is NOT sufficient — it only sees `refs/stash`, i.e.
      `stash@{0}`; older stash entries live in that ref's reflog and stay invisible to it.
- [ ] **The CHANGELOG entry says explicitly whether semantics change.** For a PATCH the expected
      sentence is that they do not.
- [ ] **An adversarial deep-gate run holds a valid verdict on exactly this digest.** A verdict for an
      earlier digest is not a verdict for this one (`scripts/pre_tag_audit_gate.py --strict` blocks
      the build without the record).
- [ ] **The budget cost axis was measured ON THE REFERENCE MACHINE and the artifact says so.**
      Owner card `OA-dc37e26295` (2026-09-08) took this axis out of the CI verdict: a runner is
      roughly twice as slow as the reference machine, its factor runs into the derived cap (1.925 on
      the KOMBI surface), and what comes out there is a statement about the machine, not about the
      code. On a build host the axis is therefore skipped VISIBLY, with the measured machine factor
      as the reason. That is only half a decision — the other half is this line, and without it the
      axis would be silent in CI and unevidenced in the bundle, i.e. nowhere.
      Run `python3 scripts/budget_axis_measurement.py` on the reference machine and check the
      artifact it writes (`audit_artifacts/360/budget_axis_latest.json`):
      `ist_referenzmessung` must be `true` (no build-host marker was set), `bauhost_marke` empty,
      `achsen_uebersprungen` must be `0` — an abstention is not a pass — and `ok` must be `true`.
      `maschinenfaktor_schnellstes_ende` says how far the measuring machine stood from the
      recording; `latte_aus_der_klammer` says which lath position was in force (`schnellstes_ende`
      since `OA-133b901337`). Both numbers belong in the release notes, because the same measured
      seconds mean different verdicts under the two positions.
      Honest limit, stated rather than glossed: this artifact is written and checked by hand today.
      `scripts/audit_candidate_matrix.py` knows the soak and the differential artifact, not this
      one — so nothing yet notices if it is simply not produced. Until it is wired there, this
      checklist line IS the mechanism, and a checklist line is a person, not a gate.
- [ ] **The external surfaces that must follow are named**, each with who pulls it: at minimum PyPI,
      the README badge, the project page (version *and* the "checked on" line), and the description
      of any open upstream pull request that states the version.

The Owner-GO is asked for after this list is answered, not before. The release itself is a one-way
door; the list is what makes it a decision instead of a habit.

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
- [ ] Verify the README assets exist (`assets/b7n0de-hase-logo.png`, `-dark.png` — the Hase lockup the
      README links; plus `demo.svg`) — the repo references them; a release with broken image links reads
      as abandonment. (They ship today; the old `b7n0de-logo.svg`/`-dark.svg` are kept as a fallback.)
- [ ] Turn the aspirational badges (PyPI version, Python versions, Downloads, SLSA, PEP 740) live
      only AFTER the first successful publish (they render broken/false before that).

## Beta / pre-release (any future pre-release line)

Historical note: the 2.0.0b1–b3 line shipped this way until **2.0.0 final** (2026-07-09); the
stable default has since moved on to the 5.x line (current: 6.1.0) and the `[experimental]` extra
ships with normal releases.
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

- [ ] Bump `version` in `pyproject.toml`, `__version__` in `src/proofbundle/__init__.py` **and**
      `version:` in `CITATION.cff` (all three must match — `scripts/check_version_and_changelog.py`
      and the release-integrity CI job enforce the three-file single-sourcing).
- [ ] Update `CHANGELOG.md` (Keep-a-Changelog + SemVer; note any breaking change explicitly).
- [ ] README.md deliberately hard-codes no test-count or version strings (live badges + CI output are the source); only touch README claims that the release genuinely changes.
- [ ] `make all` green locally (lint + typecheck + tests); `make tamper-demo` exits 0;
      `make mutation` reports all operators killed (documented-equivalent survivor excepted).
      **N20, named residual risk: this criterion has a THIRD state and the line above names two.** Killed and survived are not exhaustive — a run that does not finish reports neither, and a gate that cannot produce a verdict is not the same as a gate that produced a clean one. Read `NICHT MESSBAR` as its own outcome and treat it as unmet, never as passed.
- [ ] Open the PR; confirm the CI matrix is green on all supported Pythons **and** the
      `crypto-floor` job; **the Owner merges** the PR to the target branch (`main`, or `release/*`
      then merge-back).
- [ ] Pre-tag adversarial audit (docs/PRE_TAG_AUDIT.md): run the six-lens internal audit on the
      release candidate and land the real record as `audit_artifacts/<XYZ>/*.md` — the
      `scripts/pre_tag_audit_gate.py --strict` step in `release.yml` **blocks the build without it**,
      and the version-coupled F7 test requires the record as soon as the version is bumped (so the
      audit belongs in the release-prep PR, not after the merge).
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
# or, with SHA256SUMS downloaded next to the artifacts, let the tool do the comparing.
# --ignore-missing is required, not cosmetic: the command above fetches only the WHEEL, while
# SHA256SUMS lists the wheel AND the sdist, so a plain `-c` reports the sdist line as
# "No such file or directory / FAILED" on a perfectly good download. Measured, both failure
# modes still fail: a wrong digest exits 1, and an empty directory exits 1 with
# "no file was verified" — it does not pass silently when there is nothing to check.
( cd /tmp/pb && sha256sum --ignore-missing -c SHA256SUMS )
# to check both artifacts, fetch the sdist as well:
#   pip download proofbundle==X.Y.Z --no-deps --no-binary :all: -d /tmp/pb
gh attestation verify /tmp/pb/proofbundle-X.Y.Z-py3-none-any.whl --repo b7n0de/proofbundle
```

### What these commands establish, and what they do not

They establish two things and leave a third open. Stated here rather than in a footnote, because
this is the page where a reader decides they have checked the release.

**Established.** The bytes you downloaded are the bytes listed in `SHA256SUMS`, and
`gh attestation verify` shows that this wheel was built by this repository's release workflow from
a specific commit, signed through Sigstore with a short-lived keyless certificate. The publish step
additionally refuses to upload anything whose digest differs from the attested subject, so the
artifact on PyPI is the artifact that was attested.

**Not established: that an adversarial audit holds a verdict for that commit.** The release workflow
does gate on one — `scripts/pre_tag_audit_gate.py --strict` is its first blocking check, and it
verifies an ed25519-signed receipt bound to the tree digest, not a prose line. But that receipt is
**not something you receive**. It lives in `audit_artifacts/` in the repository, which `MANIFEST.in`
deliberately prunes from the sdist, and it is not among the release assets. Its trust root is a
public key committed in the same repository whose release you are assessing.

So the audit gate is a control **we** run on ourselves, and the receipt is evidence **for us**.

Be precise about what is missing, because it is not the arithmetic. If you clone the repository you
*can* check the signature — it is an ordinary ed25519 verification against a key in the tree. What
you cannot do from outside is establish the **authority** behind it: the key that vouches for the
verdict is published by the same party whose release the verdict concerns, so verifying it tells you
the statement was made by whoever controls that repository, and nothing further. And if you only
installed from PyPI, you never received the receipt at all.

"You can check the signature" is a command, not a promise. From a clone, at the commit that
`gh attestation verify` names as the source of the wheel:

```bash
git clone https://github.com/b7n0de/proofbundle && cd proofbundle
git checkout <the source commit named by the attestation>
python scripts/verify_pre_tag_receipt.py --commit <that commit> --version X.Y.Z
```

It reads the receipt, the pinned key and the gate source **from the commit**, never from the
working tree, takes the tree digest over the checked-out commit with the same library the release
gate uses, and verifies the ed25519 signature. Exit 0 means: the holder of the pinned key signed a
receipt over exactly this tree and this version, and the receipt records an audit run that exited 0.
Exit 1 means it did not — no receipt in the commit, a receipt made for another commit, or a receipt
whose signature is right and whose subject is not this tree; each is a contract with a test that
plants the defect. Exit 2 means the question could not be measured: the checkout is not at the named
commit, or it carries local modifications or untracked files under `scripts/` or `src/`. The second
refusal exists because the verifier code runs from your checkout, not from the commit — a review
measured that one uncommitted edit to the receipt library turned a garbage receipt into a pass while
`HEAD` stayed put — so the script refuses to judge from code that nobody pinned. The limit of the
previous paragraph is printed with every verdict, the passing one included, because the script and
the library it calls are themselves files of the tree they verify.

A bytecode cache next to the sources is not code the verifier runs. Python would execute a
`.pyc` under `__pycache__` in place of an unmodified `.py` whose header it matches, and git never
lists ignored paths, so the checkout guard above cannot see one. The verifier therefore points
Python's cache at a fresh temporary directory for the whole run: nothing under the judged tree's
`__pycache__` is read or written. What stays trusted, and is not measured: the interpreter you
run and its standard library.

This is the same boundary the project states about its own gate: provenance-shaped, not provenance.
It is written here so that "I verified the release" means what it actually means — the artifact's
origin and bytes are verifiable by you today; the audit verdict behind it rests on trusting this
repository.
