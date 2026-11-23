# Audit artefacts for 6.6.1

## Purpose and status

This page identifies the audit records for 6.6.1 and explains their limits. It describes the preparation snapshot of the branch `chore/prepare-6.6.1`, not a completed audit of the final release tree. The final pre-tag audit and its signed receipt are pending at this snapshot. Records for release 6.6.0 remain in [the 6.6.0 audit directory](../660/).

## Records

The [findings register](../findings_register_361.json) is maintained separately from this directory. Its canonical body is signed for version `6.6.1`. The signed findings-register check reads that register, rather than the counts displayed on this page.

The signed register reports 45 register entries for version `6.6.1`, with 29 closed, 16 open and no open P0 or P1 entries under the maintainer's classifications. Against 6.6.0 it adds three entries, `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-03`, `RUST-SDJWT-ISSUER-ES256-REFUSED-01` and `RUST-TRUST-PACK-PQ-ROOT-NOT-COUNTED-01`, removes none and changes the content of one, `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-02`, whose window closed with pull request 533. These totals count register entries only. R620-ABA-1 (RESTRISIKO_620.md lines 1579 to 1592) is a P1 by the line of 2026-09-27 that stays open by the owner's choice of 2026-10-01 and is not a register entry, so the statement above does not cover it.

The pre-tag receipt is to be produced from a fresh checkout of the final release-preparation head with `scripts/pre_tag_receipt.py`, version `6.6.1` and `--out audit_artifacts/661/pre_tag_receipt_v6.6.1.json`. The configured audit command runs while the receipt context is produced. Its command and exit status are recorded before signing. Since 6.6.1 the audit output the receipt names is a tracked file beside it, `audit_artifacts/661/pre_tag_audit_output_v6.6.1.txt`, and the release stops before the build when that file is missing or carries other bytes ([RELEASE.md](../../RELEASE.md)). This directory holds no other file named like a receipt.

## Recorded findings

[The 6.6.1 residual-risk record](../../RESTRISIKO_661.md) lists the findings that stay open after this release and the limits of the changes it carries. A target release is not a completed fix.

| Record | Status in this preparation snapshot |
|---|---|
| Final pre-tag audit and signed receipt, with the tracked audit output | Pending |
| Mutation run | Running at bb018ea6, the last commit before this preparation: 60 of the 118 operators in four parts on the reference machine, the other 58 one each in separate containers, where the 20 tests bound to the reference machine are skipped and an operator that survives runs again on the reference machine; not finished at this snapshot. Its result is stated in the message of the tag, not in this tree ([the 6.6.1 residual-risk record](../../RESTRISIKO_661.md)). Since then the preparation changes four modules the run mutates and files under `tests/`, and the list holds 134 operators; the 28 that mutate those modules run again at dc13aa70, each as one part, as that record describes |
| Reference measurement of the budget cost axis | PLACEHOLDER: measured on the reference machine on DATE using the code at COMMIT; the counts of expected axes and combinations that passed and of skipped axes, from [the measurement record](../360/budget_axis_latest.json) |
| Short soak at the release candidate (C6.2) and Rust differential (C8.2), signed and bound to the candidate | Pending |
| Full 24-hour soak (C6.3) | Informative since 6.6.0; it runs beside the release and does not withhold readiness |
| Findings register signed for 6.6.1 | Recorded; its canonical body is signed for version `6.6.1` |
| Paths named twice at the final release head | The final-tree check must be recorded before the pre-tag receipt is produced; its completion is not established by this page. |

## Verification and limits

For the published release, follow [the verification instructions](../../RELEASE.md#verifying-a-published-release-anyone) from a clone at the source commit identified by the build attestation. Check the receipt's signature, version, tree binding and recorded audit result. This page does not establish those facts by itself.

The signed receipt records the configured audit command and its exit status for the release tree covered by the receipt. Verification uses a key published in the same repository. The receipt is not an independent audit certificate and does not prove that the release is free of defects.
