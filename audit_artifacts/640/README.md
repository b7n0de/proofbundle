# Audit artefacts for 6.4.0

## Purpose and status

This page identifies the audit records for 6.4.0 and explains their limits. It describes the preparation snapshot of `chore/prepare-6.4.0`, not a completed audit of the final release tree. The final pre-tag audit and its signed receipt are pending at this snapshot. Records for release 6.3.1 remain in [the 6.3.1 audit directory](../631/).

## Records

The [findings register](../findings_register_361.json) is maintained separately from this directory. Its canonical body is signed for version `6.4.0`. The signed findings-register check reads that register, rather than the counts displayed on this page.

The pre-tag receipt is to be produced from a fresh checkout of the final release-preparation head with `scripts/pre_tag_receipt.py`, version `6.4.0` and `--out audit_artifacts/640/pre_tag_receipt_v6.4.0.json`. The configured audit command runs while the receipt context is produced. Its command and exit status are recorded before signing.

## Recorded findings

The signed register reports 39 register entries for version `6.4.0`, with 27 closed, 12 open and no open P0 or P1 entries under the maintainer's classifications. Against 6.3.1 it adds BUILD-PATH-TEST-READS-WORKFLOW-TEXT-01, LOCAL-BUILD-COMMANDS-WITHOUT-PIN-01 and R640-B10-1, each open at P3, and no entry is removed or changes content.

These totals count register entries only. [The 6.4.0 residual-risk record](../../RESTRISIKO_640.md) lists the findings that stay open after this release and the limits of the changes it carries. A target release is not a completed fix.

| Record | Status in this preparation snapshot |
|---|---|
| Final pre-tag audit and signed receipt | Pending |
| Findings register whose signed body names version 6.4.0 | Recorded; its canonical body is signed for version `6.4.0` |
| Reference measurement of the budget cost axis | Pending |
| Short soak at the release candidate (C6.2) and Rust differential (C8.2), signed and bound to the candidate | Pending |
| Paths named twice at the final release head | The final-tree check must be recorded before the pre-tag receipt is produced; its completion is not established by this page. |

## Verification and limits

For the published release, follow [the verification instructions](../../RELEASE.md#verifying-a-published-release-anyone) from a clone at the source commit identified by the build attestation. Check the receipt's signature, version, tree binding and recorded audit result. This page does not establish those facts by itself.

The signed receipt records the configured audit command and its exit status for the release tree covered by the receipt. Verification uses a key published in the same repository. The receipt is not an independent audit certificate and does not prove that the release is free of defects.
