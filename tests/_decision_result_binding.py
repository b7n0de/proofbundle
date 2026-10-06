"""Test helper for Nachtrag 48/48b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309).

evaluate_decision_policy now refuses a verify result that was not produced by this process's
verify_decision_receipt for exactly the statement and signer it judges (crypto_ok must be True, and the
result's captured signer, payload digest and origin token must bind this statement). A test that exercises
the decision policy rules in isolation (not through a full verify) uses this to build a result stand-in that
carries that binding, exactly as a passing verify_decision_receipt stamps one — an honest simulation of the
verifier's output (in-process stamping is out of the review's threat model for a result hand-off).
"""
from __future__ import annotations

import hashlib

from proofbundle.decision import _DECISION_ORIGIN_DOMAIN, _rfc8785_bytes
from proofbundle.errors import _origin_token


def bound_decision_result(statement: dict, signer_public_key_b64: str, **extra) -> dict:
    """A verify-result stand-in BOUND to ``statement`` and ``signer_public_key_b64``, as a passing
    verify_decision_receipt returns one. ``extra`` overrides or adds result fields."""
    digest = hashlib.sha256(_rfc8785_bytes(statement)).hexdigest()
    result = {
        "crypto_ok": True,
        "verified_signer_pub_b64": signer_public_key_b64,
        "verified_payload_digest": digest,
        "verified_origin": _origin_token(_DECISION_ORIGIN_DOMAIN, (signer_public_key_b64, digest)),
    }
    result.update(extra)
    return result
