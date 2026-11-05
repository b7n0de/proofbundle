# Residual risk, release 6.5.0

This file records findings for the 6.5.0 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.4.0](RESTRISIKO_640.md) and the records before it.

## The record of 6.4.0 in this release

The findings that stay open after 6.4.0 are listed in [the 6.4.0 record](RESTRISIKO_640.md). This record does not measure them again. Where a line of the 6.5.0 changelog touches one of them, its state stays as the 6.4.0 record gives it until a measurement on the release candidate records another one here.

## Open after this release

### The 24-hour soak runs beside the release

By the addendum of 2026-09-08 to the release standard, the full 24-hour fuzz soak runs in parallel with the release and does not hold the tag. The soak evidence of 6.5.0 is the short soak at the release candidate, signed and bound to that candidate (audit matrix row C6.2). Until the 24-hour run reports, row C6.3 is a named residual risk of this release. A crash the 24-hour run finds is a new finding under the usual rules.

### An expired receipt outside the policy exits 3

Open. In the measurement of 2026-11-05 at the release candidate, `proofbundle decision verify` on vector F3 of Appendix A.5 of draft-gruszka-audit-decision-receipts, called with `--strict` and `--policy` but without `--verification-time`, so that `validity.expiresAt` lies before the evaluation time, reported both errors, the expired receipt and the `decisionMaker.id` that the policy does not bind to the signing key, and exited 3. Section 7 of `docs/predicates/decision-receipt.md` gives exit 2 for an expired receipt and exit 3 for crypto-OK bytes whose policy is not satisfied, and does not say which code applies when both hold. Both codes are non-zero, so the receipt is not accepted either way; a caller that tells the two codes apart reads such a receipt as a policy failure only. The code keeps exit 3 on purpose, as the Rust verifier does, but neither section 7 nor the help of --verification-time states that order; documenting it remains outside 6.5.0.

### main fails the plugin pin case from the tag until the pin commit

Open by design. By the owner choice of 2026-11-05, the plugin keeps pinning 6.4.0 until 6.5.0 is on PyPI, and the plugin pin case reads the release in preparation so until the tag. Once the tag v6.5.0 stands, the case reads 6.5.0 as the newest release and fails on main, in every checkout that holds the tag, until the commit that moves the plugin's pins to 6.5.0 lands. That commit is a pull request of its own, outside 6.5.0, prepared before the tag and landed directly after the upload to PyPI. A checkout without tags, such as a job of depth one, reads the release as in preparation and passes with a warning, so it does not show this window.

### Repository tools

- The release workflows pin the build frontend and the build backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`, unchanged since 6.4.0. Only the setuptools version is read back from the built wheel; the other pins are applied and not read back. The pins name versions, not hashes. The Python interpreter of the build is the newest 3.12 release that `actions/setup-python` selects, and it is not pinned.

### Not measured at this snapshot

The deep gate, the canonical mutation run and the pre-tag audit at the release candidate of 6.5.0 have not run at this preparation snapshot. Their findings are recorded here before the tag.

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
