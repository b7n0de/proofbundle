# Audit artefacts for 6.3.0

## Purpose and status

This page identifies the audit records for 6.3.0 and explains their limits. It describes the preparation snapshot at `cea2fcfa`, not a completed audit of the final release tree. The final pre-tag audit and its signed receipt are pending at this snapshot. Records for release 6.2.1 remain in [the 6.2.1 audit directory](../621/).

## Records

The [findings register](../findings_register_361.json) is maintained separately from this directory. The release record reports that its canonical body is signed for version `6.3.0`. The signed findings-register check reads that register, rather than the counts displayed on this page.

The pre-tag receipt is to be produced from a fresh checkout of the final release-preparation head with `scripts/pre_tag_receipt.py`, version `6.3.0` and `--out audit_artifacts/630/pre_tag_receipt_v6.3.0.json`. The configured audit command runs while the receipt context is produced. Its command and exit status are recorded before signing.

## Recorded findings

The release record dated 2026-10-13 reports 36 register entries for version `6.3.0`, with 19 closed, 17 open and no open P0 or P1 entries under the maintainer's classifications. K1 and K2 are recorded as closed through pull requests 346 and 347. K3 to K10 remain open and are targeted for 6.3.1. Their original review classification was P1; the maintainer assigned P2 during the release assessment. These findings affect code outside the installed Python package.

These totals count register entries only. They exclude the four additional P2 groups listed in [the 6.3.0 residual-risk record](../../RESTRISIKO_630.md), which include limitations in the installed intoto CLI and the v0.2 timestamp check. That record lists the open findings and their planned target release. A target release is not a completed fix.

| Record | Status in this preparation snapshot |
|---|---|
| Findings-register totals | Reported above from the release record; no final-head audit verdict is asserted here |
| Final pre-tag audit and signed receipt | Pending |

## Verification and limits

For the published release, follow [the verification instructions](../../RELEASE.md#verifying-a-published-release-anyone) from a clone at the source commit identified by the build attestation. Check the receipt's signature, version, tree binding and recorded audit result. This page does not establish those facts by itself.

The signed receipt records the configured audit command and its exit status for the release tree covered by the receipt. Verification uses a key published in the same repository. The receipt is not an independent audit certificate and does not prove that the release is free of defects.
