# Audit artefacts for 6.3.1

## Purpose and status

This page identifies the audit records for 6.3.1 and explains their limits. It describes the preparation snapshot of `chore/prepare-6.3.1`, not a completed audit of the final release tree. The final pre-tag audit and its signed receipt are pending at this snapshot. Records for release 6.3.0 remain in [the 6.3.0 audit directory](../630/).

## Records

The [findings register](../findings_register_361.json) is maintained separately from this directory. The signed findings-register check reads that register, rather than any count displayed on this page.

The pre-tag receipt is to be produced from a fresh checkout of the final release-preparation head with `scripts/pre_tag_receipt.py`, version `6.3.1` and `--out audit_artifacts/631/pre_tag_receipt_v6.3.1.json`. The configured audit command runs while the receipt context is produced. Its command and exit status are recorded before signing.

## Recorded findings

[The 6.3.1 residual-risk record](../../RESTRISIKO_631.md) lists the targets of 6.3.0 that this release carries, the findings that stay open after it and the limits of the fixes it carries. A target release is not a completed fix.

| Record | Status in this preparation snapshot |
|---|---|
| Final pre-tag audit and signed receipt | Pending |
| Reference measurement of the budget cost axis | Pending |
| Paths named twice at the final release head | The final-tree check must be recorded before the pre-tag receipt is produced; its completion is not established by this page. |

## Verification and limits

For the published release, follow [the verification instructions](../../RELEASE.md#verifying-a-published-release-anyone) from a clone at the source commit identified by the build attestation. Check the receipt's signature, version, tree binding and recorded audit result. This page does not establish those facts by itself.

The signed receipt records the configured audit command and its exit status for the release tree covered by the receipt. Verification uses a key published in the same repository. The receipt is not an independent audit certificate and does not prove that the release is free of defects.
