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

## Good first issues

- Add a `proofbundle consistency` CLI subcommand around `verify_consistency`.
- Add SHA-384 and SHA-512 Merkle variants behind an explicit `hash_alg`.
- Add Key Binding JWT verification to the SD-JWT path.
- Add a JSON Schema for the bundle format under `schemas/`.

Open an issue before large changes so we can agree on scope. By contributing you
agree that your contributions are licensed under the MIT License.
