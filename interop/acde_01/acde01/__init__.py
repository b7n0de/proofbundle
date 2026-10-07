"""Independent reading of draft-abak-agent-control-delivery-evidence-01 (verification side).

Derived from the text of the draft alone (plain-text copy, SHA-256
2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf, 2576 lines). This package is an
interop experiment. It is not part of the proofbundle library, defines no proofbundle format, and
its JSON shapes are this implementation's own descriptive representation, not a wire format.

Entry points:

* :func:`acde01.profile.validate_profile` - the declarations the draft requires a profile to make.
* :func:`acde01.reconcile.reconcile` - one bounded reconciliation run over a frozen input.
* :func:`acde01.reconcile.reconcile_versions` - the same input reconciled at several cutoffs.
* :func:`acde01.report_check.check_report` - conformance checks on a report object.
* :func:`acde01.reconcile.render_summary` - a text rendering that keeps the claim context.
"""

DRAFT = "draft-abak-agent-control-delivery-evidence-01"
DRAFT_SHA256 = "2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf"
IMPLEMENTATION_VERSION = "0.1.0"
