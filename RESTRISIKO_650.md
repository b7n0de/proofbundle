# Residual risk, release 6.5.0

This file records findings for the 6.5.0 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.4.0](RESTRISIKO_640.md) and the records before it.

## The record of 6.4.0 in this release

The findings that stay open after 6.4.0 are listed in [the 6.4.0 record](RESTRISIKO_640.md). This record does not measure them again. Where a line of the 6.5.0 changelog touches one of them, its state stays as the 6.4.0 record gives it until a measurement on the release candidate records another one here.

## Open after this release

### The 24-hour soak runs beside the release

Under the 2026-09-08 addendum to the release standard, the full 24-hour fuzz soak runs in parallel with the release and does not block the tag. The short soak at the 6.5.0 release candidate, audit matrix row C6.2, is still pending at this preparation snapshot. The release evidence is to include its signed result bound to that candidate; this snapshot does not establish that the result exists. Until the 24-hour run reports, row C6.3 remains a named residual risk of this release. Any crash found by that run is recorded as a new finding under the usual rules.

### An expired receipt with a policy failure returns exit 3

Open. In the measurement on 2026-11-05 at an unpublished local candidate that merged pull request 482 at `28bce567` into `main` at `43544e21`, `proofbundle decision verify` was called on vector F3 of Appendix A.5 of draft-gruszka-audit-decision-receipts-06 with `--strict` and `--policy`, but without `--verification-time`. The receipt had expired at the evaluation time, and its `decisionMaker.id` did not match the identity bound to the signing key by the test policy. The command reported both errors, set `freshness_ok` to false and returned exit 3, both with and without `--json`.

A caller that branches only on the exit code sees the policy-failure code and must not infer that the receipt passed the freshness check. The full output still reports the expiry failure. Both exit 2 and exit 3 are non-zero, so neither result accepts the receipt. This measurement does not define a general precedence rule for every combination of failures. Defining and documenting that general rule remains outside 6.5.0. Register entry `EXPIRED-RECEIPT-OUTSIDE-POLICY-EXITS-3-01`.

### main fails the plugin pin case from the tag until the pin commit

Open by design. By the owner choice of 2026-11-05, the plugin keeps pinning 6.4.0 until 6.5.0 is on PyPI, and the plugin pin case reads the release in preparation so until the tag. Once the tag v6.5.0 stands, the case reads 6.5.0 as the newest release and fails on main, in every checkout that holds the tag, until the commit that moves the plugin's pins to 6.5.0 lands. That commit is a pull request of its own, outside 6.5.0, prepared before the tag and landed directly after the upload to PyPI. A checkout without tags, such as a job of depth one, reads the release as in preparation and passes with a warning, so it does not show this window. Register entry `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-01`.

### Repository tools

- The release workflows pin the build frontend and the build backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`, unchanged since 6.4.0. Only the setuptools version is read back from the built wheel; the other pins are applied and not read back. The pins name versions, not hashes. The Python interpreter of the build is the newest 3.12 release that `actions/setup-python` selects, and it is not pinned.

### Not measured at this snapshot

The deep gate, the canonical mutation run and the pre-tag audit at the release candidate of 6.5.0 have not run at this preparation snapshot. Their findings are recorded here before the tag.

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
