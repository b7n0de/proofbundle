# Residual risk, release 6.4.0

This file records findings for the 6.4.0 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.3.1](RESTRISIKO_631.md) and the records before it.

## The record of 6.3.1 in this release

The findings that stay open after 6.3.1 are listed in [the 6.3.1 record](RESTRISIKO_631.md). This record does not measure them again. Where a line of the 6.4.0 changelog touches one of them, its state stays as the 6.3.1 record gives it until a measurement on the release candidate records another one here.

## Open after this release

### The 24-hour soak runs beside the release

By the owner decision of 2026-09-08 recorded in [the residual-risk record of 6.0.0](RESTRISIKO_600.md), the full 24-hour fuzz soak runs in parallel with the release and does not hold the tag. The soak evidence of 6.4.0 is the short soak at the release candidate, signed and bound to that candidate (audit matrix row C6.2). Until the 24-hour run reports, row C6.3 is a named residual risk of this release. A crash the 24-hour run finds is a new finding under the usual rules.

### A startup module of a uv environment runs before the third-party receipt verifier

R640-B10-1, small, measured on 2026-10-26 with Python 3.10.12 and uv 0.12.24. An environment made by uv carries `_virtualenv.pth`, whose module imports `contextlib` when the interpreter starts. One made by virtualenv 21.14.13 with Python 3.10.12 carries no such file. Run without `-I` and with `PYTHONPATH` naming a directory of the checkout, a `contextlib` planted there runs before the first line of `scripts/verify_pre_tag_receipt.py`; with a plant that only leaves a marker, the run stopped with a traceback and exit 1, the exit code the verifier gives a receipt that is NOT VERIFIED. No run gave exit 0. Under the documented command, `python -I`, the plant did not run. The verifier's docstring already states that code which runs before the first line is beyond what a check inside the script can see. Two cases of `tests/test_verify_pre_tag_receipt_third_party.py` assume that the start of the interpreter does not load `contextlib`, and they fail in such an environment; CI and the release runner use no such environment. A change of the tests and of the verifier's exit code for this case is not part of this release.

### Repository tools

- The release workflows pin the build frontend and the build backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`. Only the setuptools version is read back from the built wheel; the other pins are applied and not read back. The pins name versions, not hashes. The Python interpreter of the build is the newest 3.12 release that `actions/setup-python` selects, and it is not pinned; whether another 3.12 release or its zlib changes the bytes is not measured.
- `tests/test_every_build_path_pins_its_backend.py` reads the text of the workflow files. It does not see every way to build, for example `pyproject-build`, `pip wheel` or `setup.py bdist_wheel`, and it does not see a build step that is skipped or allowed to fail.
- The local build commands in `docs/readiness_pack/REPRODUCTION_RUNBOOK.md` and in the hint of `scripts/audit_candidate_matrix.py` do not set `PIP_CONSTRAINT`, so a local candidate build takes the setuptools of the day unless the reader sets it.
- As the changelog states, `pb_verify_rs` links the RustCrypto crate `rsa`, which carries RUSTSEC-2023-0071, a timing leak of a private key; the verifier links only its public-key verification.

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
