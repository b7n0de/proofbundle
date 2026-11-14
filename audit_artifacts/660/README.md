# Audit artefacts for 6.6.0

## Purpose and status

This page identifies the audit records for 6.6.0 and explains their limits. It describes the preparation snapshot of the branch `chore/prepare-6.6.0`, not a completed audit of the final release tree. The final pre-tag audit and its signed receipt are pending at this snapshot. Records for release 6.5.0 remain in [the 6.5.0 audit directory](../650/).

## Records

The [findings register](../findings_register_361.json) is maintained separately from this directory. Its canonical body is signed for version `6.6.0`. The signed findings-register check reads that register, rather than the counts displayed on this page.

The signed register reports 42 register entries for version `6.6.0`, with 28 closed, 14 open and no open P0 or P1 entries under the maintainer's classifications. Against 6.5.0 it adds one entry, `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-02`, removes none and changes the content of one, `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-01`, whose window closed with pull request 494. These totals count register entries only.

The pre-tag receipt is to be produced from a fresh checkout of the final release-preparation head with `scripts/pre_tag_receipt.py`, version `6.6.0` and `--out audit_artifacts/660/pre_tag_receipt_v6.6.0.json`. The configured audit command runs while the receipt context is produced. Its command and exit status are recorded before signing. Since 6.6.0 the release gate rejects a receipt folder that holds a rejected candidate beside a valid receipt, so this directory holds no other file named like a receipt.

## Recorded findings

[The 6.6.0 residual-risk record](../../RESTRISIKO_660.md) lists the findings that stay open after this release and the limits of the changes it carries. A target release is not a completed fix.

| Record | Status in this preparation snapshot |
|---|---|
| Final pre-tag audit and signed receipt | Pending |
| Reference measurement of the budget cost axis | Measured on the reference machine on 2026-11-14 using the code at 397f5171, while the one-minute load average of the machine was between 6.47 and 8.84; all 12 expected axes and all 7 expected combinations passed and no axis was skipped, from [the measurement record](../360/budget_axis_latest.json). Two further runs directly after it, until 05:37:06Z, gave the same verdict for every axis and combination, with the factor 1.0 at the fastest end in both and 1.0 and 1.0031 at the median |
| Short soak at the release candidate (C6.2) and Rust differential (C8.2), signed and bound to the candidate | Pending |
| Full 24-hour soak (C6.3) | Informative since 6.6.0; it runs beside the release and does not withhold readiness |
| Findings register signed for 6.6.0 | Recorded; its canonical body is signed for version `6.6.0` |
| Paths named twice at the final release head | The final-tree check must be recorded before the pre-tag receipt is produced; its completion is not established by this page. |

## Verification and limits

For the published release, follow [the verification instructions](../../RELEASE.md#verifying-a-published-release-anyone) from a clone at the source commit identified by the build attestation. Check the receipt's signature, version, tree binding and recorded audit result. This page does not establish those facts by itself.

The signed receipt records the configured audit command and its exit status for the release tree covered by the receipt. Verification uses a key published in the same repository. The receipt is not an independent audit certificate and does not prove that the release is free of defects.
