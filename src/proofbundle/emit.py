"""Evidence receipt emitter, ROADMAP STUB.

v0.1 ships only the verifier. Emission is intentionally not implemented yet, so
that the verification core can be reviewed, tested and trusted on its own first.

Planned (see README roadmap):
  v0.2  emit_bundle(): sign an arbitrary payload with Ed25519 and anchor it in a
        local RFC 6962 Merkle log, producing a verify_bundle-compatible bundle.
  v0.3  emit_eval_receipt(): wrap one eval framework run (Inspect AI or
        lm-evaluation-harness) into a signed receipt whose payload is a minimal,
        RFC 8785 canonicalized claim, for example
            {"suite": "...", "metric": "...", "threshold": 0.8, "passed": true}
        optionally wrapped as an SD-JWT VC so the holder can selectively disclose
        "passed above threshold" without revealing the model, weights or dataset,
        and carrying a cluster-bootstrap confidence interval, a multiple-testing
        correction and a preregistration hash inside the claim.

This is the differentiator identified by the competitive audit: no existing
project turns a reproducible eval result into a signed, third-party-verifiable,
selectively disclosable receipt.
"""

from __future__ import annotations


class NotYetImplemented(NotImplementedError):
    """Raised by roadmap functions that are planned but not part of v0.1."""


def emit_bundle(*args, **kwargs):  # pragma: no cover - roadmap stub
    raise NotYetImplemented(
        "emit_bundle lands in v0.2. v0.1 is verify-only. "
        "Generate a real example with examples/make_example.py."
    )


def emit_eval_receipt(*args, **kwargs):  # pragma: no cover - roadmap stub
    raise NotYetImplemented(
        "emit_eval_receipt lands in v0.3 and is the core differentiator. "
        "See the roadmap in this module and the README."
    )
