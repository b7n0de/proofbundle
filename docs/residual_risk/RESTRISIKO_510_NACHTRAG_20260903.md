# Residual risk, release 5.1.0 — addendum of 2026-09-03

## Why this is a separate file and not an edit

`RESTRISIKO_510.md` is bound. Its sha256 sits inside `audit_artifacts/510/pre_tag_receipt_v5.1.0.json`
as `audit_output_digest`, so the residual risk cannot be detached from the attestation. Measured on
2026-09-03 before writing this file, the two agree byte for byte:

    audit_output_digest              0ac518170eabbb24c547fe0bd7969f5790db8c06a9f4c19ff0414f75a5010db2
    sha256(RESTRISIKO_510.md)        0ac518170eabbb24c547fe0bd7969f5790db8c06a9f4c19ff0414f75a5010db2

Editing that file would have broken the binding for the sake of a paragraph. The bound file
therefore stays exactly as it was signed, and this addendum carries its own name and date. A reader
who wants the attested residual risk reads the bound file; a reader who wants the full picture as
of 2026-09-03 reads both.

## What was missing

**A-P0-2, expired eval policy now FAILS the policy evaluation (security).** It is described in the
5.1.0 release notes and it was not carried into the residual risk file. That is an omission of the
kind the bound file itself names in its opening lines: a residual risk that is not written down is
not a residual risk.

## The finding, in the form the bound file uses

    Class            security, lifecycle enforcement, path parity
    Funnel verdict   reaches a user of the shipped package — FIXED in 5.1.0, not open
    Reason           the decision path already rejected an expired policy (exit 3); the EVAL path
                     did not. An expired eval policy still produced POLICY: OK and exit 0, and only
                     safeForAutomation went false. A relying party reading the exit code alone
                     would have accepted a policy that had run out.

What 5.1.0 changed: lifecycle is part of `evaluate_policy` itself. `policy:not_template`,
`policy:not_expired` and `policy:not_before` (the new additive `valid_from` field) produce
`POLICY: FAIL` and exit 3 on both paths, so the two paths agree.

Historical verification stays explicit only. `verify --verification-time <ISO-8601> --policy ...`
evaluates the lifecycle as of that instant and labels the output (`VERIFICATION_TIME: HISTORICAL`,
`CURRENT_POLICY_STATUS`, `HISTORICAL_POLICY_STATUS`). A policy that is expired today keeps
`safeForAutomation: false` even in historical mode. No silent backdating, no silent acceptance.

## Honest limit of this addendum

A-P0-2 is listed here because it belongs in the residual risk record of this release, not because
it is still open. It is fixed in the shipped 5.1.0. What remains open is only that the bound file
does not mention it, and that is what this file repairs, by addition, without touching a signature.
