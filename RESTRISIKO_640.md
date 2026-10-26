# Residual risk, release 6.4.0

This file records findings for the 6.4.0 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.3.1](RESTRISIKO_631.md) and the records before it.

## The record of 6.3.1 in this release

The findings that stay open after 6.3.1 are listed in [the 6.3.1 record](RESTRISIKO_631.md). This record does not measure them again. Where a line of the 6.4.0 changelog touches one of them, its state stays as the 6.3.1 record gives it until a measurement on the release candidate records another one here.

## Open after this release

### The 24-hour soak runs beside the release

By the owner decision of 2026-09-08 recorded in [the residual-risk record of 6.0.0](RESTRISIKO_600.md#s21--c63-verlangt-einen-24-stunden-soak-den-es-zum-kandidatenkopf-nicht-gibt), the full 24-hour fuzz soak runs in parallel with the release and does not hold the tag. The soak evidence of 6.4.0 is the short soak at the release candidate, signed and bound to that candidate (audit matrix row C6.2). Until the 24-hour run reports, row C6.3 is a named residual risk of this release. A crash the 24-hour run finds is a new finding under the usual rules.

### A startup module of a uv environment runs before the third-party receipt verifier

R640-B10-1, open. In the measurement of 2026-10-26, an environment made by uv 0.12.24 with Python 3.10.12 carried `_virtualenv.pth`, whose startup module imported `contextlib`. The environment made by virtualenv 21.14.13 with Python 3.10.12 did not carry that file. Without `-I`, and with `PYTHONPATH` naming a checkout directory, a planted `contextlib` ran before the first line of `scripts/verify_pre_tag_receipt.py`. The marker-only plant caused a traceback and exit 1, which is also the verifier's NOT VERIFIED exit code; it did not produce exit 0. This probe does not bound what other code executed before the verifier could do. With the documented `python -I` command, the same plant did not run. The result concerns these measured environments, not every uv or virtualenv environment. Two cases of `tests/test_verify_pre_tag_receipt_third_party.py` failed in the measured uv environment because they assumed that startup did not import `contextlib`. The release workflow uses `actions/setup-python` and does not create this uv environment. The verifier documents that checks inside the script cannot inspect execution before its first line. Changes to those tests and to the verifier's exit-code distinction for this case remain outside 6.4.0. Register entry `R640-B10-1`.

### Repository tools

- The release workflows in `release.yml`, `published-artifact-gate.yml` and `reusable-build-attest.yml` select versions of the build frontend and backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`. The wheel-producing release steps read back only the recorded setuptools Generator from the wheel. The other tool versions are constrained during installation and are not read back from an artefact; no build-tool version is read back from the sdist. These constraints name versions, not dependency archive hashes. The build interpreter is selected from the Python 3.12 line by `actions/setup-python`; its patch version and the hosted runner image are not fixed. Whether a change in the interpreter, its zlib or the resolved dependency files changes the output bytes has not been measured here. These settings do not by themselves establish equality between a candidate build and a later tag build; that requires comparison of the actual distribution files.
- `tests/test_every_build_path_pins_its_backend.py` inspects recognised run-step text in `.yml` and `.yaml` workflow files. The contract tests cover the supported command forms; `uv build` and `pipx run build` are refused until their build paths are measured. Other forms, including `pyproject-build`, `pip wheel` and `setup.py bdist_wheel`, remain outside this recognition. The tests do not establish that a conditional step runs, that a failed step stops publication, or that every reusable-workflow call has been resolved. Register entry `BUILD-PATH-TEST-READS-WORKFLOW-TEXT-01`.
- The local equality-check commands in `docs/readiness_pack/REPRODUCTION_RUNBOOK.md` do not set `PIP_CONSTRAINT` or read back a backend version. Their results alone do not establish the release candidate's pinned build inputs or its frozen artifact hashes. The hint in `scripts/audit_candidate_matrix.py` now names the pinned frontend installation and a build of both distributions with the wheel's generator checked. The remaining gap is in the local equality-check instructions. Register entry `LOCAL-BUILD-COMMANDS-WITHOUT-PIN-01`.
- The comparison before upload in `release.yml` takes its expectation from the signed candidate block of the short soak and of the Rust differential. It checks the signature, the version, the kind and the pair; it does not read the gate line, the counters or the age of that evidence, which the audit matrix judges before the tag. The canonicalizer it checks the signature over is installed at a fixed version without a hash pin, as `cryptography` is in the same job. `reusable-build-attest.yml` attests without such a comparison; it is called only with `dry_run: true` in this release.
- As the changelog states, `pb_verify_rs` links the RustCrypto crate `rsa`, which carries RUSTSEC-2023-0071, a timing leak of a private key; the verifier links only its public-key verification.

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
