"""Test helper for Nachtrag 48/48b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309, F3).

svr_properties now derives a property only when the VerificationResult it is handed came from this process's
verify_bundle (an authentic origin token, not a hand-built result with matching checks) AND its recorded payload
digest equals the passed claim's digest under the fixed JCS encoding. A test that checks svr_properties earns a
property for a valid claim builds a real (result, claim) pair from one eval receipt, exactly as export_svr_dsse
derives them — an honest simulation of the exporter's inputs.
"""
from __future__ import annotations


def bound_svr_result(claim: dict, signer):
    """A (real VerificationResult, decoded claim) pair from one eval receipt built from ``claim``."""
    from proofbundle.bundle import verify_bundle
    from proofbundle.evalclaim import decode_eval_claim, emit_eval_receipt
    rec = emit_eval_receipt(claim, signer)
    return verify_bundle(rec), decode_eval_claim(rec)


def svr_result_for(claim: dict, checks=(("ed25519-signature", True), ("merkle-inclusion", True))):
    """A VerificationResult BOUND to exactly ``claim`` (its payload digest = sha256 of the claim's JCS encoding)
    and stamped with this process's origin token, with the given checks. Works for any claim shape without
    emitting a receipt; in-process stamping is out of the review's threat model for a result hand-off."""
    import hashlib

    from proofbundle.decision import _rfc8785_bytes
    from proofbundle.errors import Check, VerificationResult
    result = VerificationResult([Check(name, ok) for name, ok in checks])
    result.verified_signer_pub = b"\x00" * 32
    result.verified_payload_digest = hashlib.sha256(_rfc8785_bytes(claim)).hexdigest()
    result.stamp_origin()
    return result
