"""Independent reading of draft-abak-agent-control-delivery-evidence-02 (verification side).

Derived from the text of the draft alone (plain-text copy, SHA-256
fe3baeb08c8e0979ca64efece098c972827fab483debe0b2bcbfd697bb714782, 2856 lines). Release 0.1.0 read
revision -01 (SHA-256 2f0356fc...fabf); the changes are listed in README.md. This package is an
interop experiment. It is not part of the proofbundle library, defines no proofbundle format, and
its JSON shapes are this implementation's own descriptive representation, not a wire format.

Entry points:

* :func:`acde01.profile.validate_profile` - the declarations the draft requires a profile to make.
* :func:`acde01.reconcile.reconcile` - one bounded reconciliation run over a frozen input.
* :func:`acde01.reconcile.reconcile_versions` - the same input reconciled at several cutoffs.
* :func:`acde01.report_check.check_report` - conformance checks on a report object.
* :func:`acde01.reconcile.render_summary` - a text rendering that keeps the claim context.
"""

DRAFT = "draft-abak-agent-control-delivery-evidence-02"
DRAFT_SHA256 = "fe3baeb08c8e0979ca64efece098c972827fab483debe0b2bcbfd697bb714782"
IMPLEMENTATION_VERSION = "0.2.0"
