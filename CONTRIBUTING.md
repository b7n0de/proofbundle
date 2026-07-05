# Contributing to proofbundle

Thanks for your interest. This project deliberately stays small, dependency-light
and correct. Contributions that keep it that way are very welcome.

## Principles

- The trusted verification core stays minimal and easy to audit.
- No custom cryptography. Signature math comes from `cryptography`; Merkle hashing
  follows RFC 6962 exactly.
- Every behaviour is covered by a test. Correctness beats features.

## Development

```bash
git clone https://github.com/b7n0de/proofbundle
cd proofbundle
python -m pip install -e ".[dev]"

# run the tests (no pytest required, standard library works too)
python -m unittest discover -s tests
# or, with pytest installed
pytest -q

# regenerate the example bundle
python examples/make_example.py

# lint
ruff check .
```

## Branch base (fork from `main`, never from a release tag)

Fork every feature/fix branch from the current `main` HEAD:

```bash
git switch -c <type>/<scope>/<slug> main      # e.g. fix/verify/kb-jwt
```

For a stable patch to an older line, fork from the corresponding `release/v1.9.x`
branch instead, then merge that branch back into `main`.

**Never branch from a release tag (`vX.Y.Z`).** A tag-based branch predates the
`## [Unreleased]` section that every later release adds to `CHANGELOG.md`, so it
re-conflicts on `CHANGELOG.md` on every single PR. `CHANGELOG.md` is structured
newest-first: `## [Unreleased]` at the top, then released versions in descending
order — a branch cut from an old tag always collides there.

A non-blocking CI check (`scripts/branch_base_check.py`) warns if a PR branch was
forked from a release tag; it is advisory only and never fails the build. To fix a
branch that was cut from a tag:

```bash
git rebase --onto origin/main <tag-it-was-cut-from> <your-branch>
```

## Good first issues

- Add a `proofbundle consistency` CLI subcommand around `verify_consistency`.
- Add SHA-384 and SHA-512 Merkle variants behind an explicit `hash_alg`.
- Add Key Binding JWT verification to the SD-JWT path.
- Add more external RFC 6962 / SD-JWT reference vectors under `tests/fixtures/`.

Open an issue before large changes so we can agree on scope. By contributing you
agree that your contributions are licensed under the MIT License.
