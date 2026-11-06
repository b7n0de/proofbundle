# Audit artefacts for 6.5.0

## Purpose and status

This page identifies the audit records for 6.5.0 and explains their limits. It describes the preparation snapshot of `chore/prepare-6.5.0`, not a completed audit of the final release tree. The final pre-tag audit and its signed receipt are pending at this snapshot. Records for release 6.4.0 remain in [the 6.4.0 audit directory](../640/).

## Records

The [findings register](../findings_register_361.json) is maintained separately from this directory. Its canonical body is signed for version `6.5.0`. The signed findings-register check reads that register, rather than the counts displayed on this page.

The signed register reports 41 register entries for version `6.5.0`, with 27 closed, 14 open and no open P0 or P1 entries under the maintainer's classifications. Against 6.4.0 it adds two entries, `EXPIRED-RECEIPT-OUTSIDE-POLICY-EXITS-3-01` and `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-01`, removes none and changes the content of none. These totals count register entries only.

The pre-tag receipt is to be produced from a fresh checkout of the final release-preparation head with `scripts/pre_tag_receipt.py`, version `6.5.0` and `--out audit_artifacts/650/pre_tag_receipt_v6.5.0.json`. The configured audit command runs while the receipt context is produced. Its command and exit status are recorded before signing.

## Recorded findings

[The 6.5.0 residual-risk record](../../RESTRISIKO_650.md) lists the findings that stay open after this release and the limits of the changes it carries. A target release is not a completed fix.

| Record | Status in this preparation snapshot |
|---|---|
| Final pre-tag audit and signed receipt | Pending |
| Reference measurement of the budget cost axis | Recorded; measured on the reference machine on 2026-11-06 using the code at `14fe3390`. [The measurement record](../360/budget_axis_latest.json) identifies a reference measurement in which all 12 expected axes and all 7 expected combinations passed and no axis was skipped |
| Short soak at the release candidate (C6.2) and Rust differential (C8.2), signed and bound to the candidate | Pending |
| Findings register signed for 6.5.0 | Recorded; its canonical body is signed for version `6.5.0` |
| Paths named twice at the final release head | The final-tree check must be recorded before the pre-tag receipt is produced; its completion is not established by this page. |

## Verification and limits

For the published release, follow [the verification instructions](../../RELEASE.md#verifying-a-published-release-anyone) from a clone at the source commit identified by the build attestation. Check the receipt's signature, version, tree binding and recorded audit result. This page does not establish those facts by itself.

The signed receipt records the configured audit command and its exit status for the release tree covered by the receipt. Verification uses a key published in the same repository. The receipt is not an independent audit certificate and does not prove that the release is free of defects.
