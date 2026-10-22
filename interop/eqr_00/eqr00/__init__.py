"""Independent reading of draft-watts-agent-evidence-boundary-00 (verification side).

Derived from the text of the draft alone (plain-text copy, SHA-256
e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d, 1064 lines). This package is an
interop experiment. It is not part of the proofbundle library and defines no proofbundle format. It
reads Evidence Qualification Receipts (EQR) and reports, separately, whether the receipt is valid,
what evaluation it carries, and whether it qualifies for a policy that requires PASS. It never makes
an authorization decision.

Entry points:

* :func:`eqr00.verify.verify` - Section 8 for one receipt, fail-closed.
* :func:`eqr00.verify.verify_set` - several receipts, with the append-only rules of Section 10.
"""

DRAFT = "draft-watts-agent-evidence-boundary-00"
DRAFT_SHA256 = "e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d"
IMPLEMENTATION_VERSION = "0.1.0"
