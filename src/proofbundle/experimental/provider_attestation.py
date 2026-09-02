"""Provider attestation evidence -> the EAT this package already verifies. EXPERIMENTAL.

**What this closes.** :mod:`proofbundle.experimental.enclave` already verifies a Verifier-signed
EAT Attestation Result and its ``eat_nonce`` binding to a receipt, offline, fail-closed. What it
could not do was start from what a *confidential inference provider* returns per answer: a receipt
id, a runtime attestation, and hashes of the request and the response. This module is the shim
between the two, and nothing more.

**What it deliberately is not.** It does not verify a raw TDX quote or a GPU report; that belongs
to the hardware vendor's verifier. It does not decide trust. It maps provider-shaped evidence into
the RATS Attestation Result shape, states plainly which of the required parts were present, and
hands the result to :func:`~proofbundle.experimental.enclave.verify_enclave_attestation`.

**The rule that carries it.** Evidence that is absent, or that fails its check, yields
``assurance="self_reported"``. There is no middle value and no override. A response whose
attestation cannot be checked is a response like any other — the danger is not that it is
untrustworthy, it is that a half-verified label reads like a verified one.

**Five parts, named after what they establish** (an answer counts as provider-attested only when
the first three are present — see :data:`REQUIRED_PARTS`):

===================  =========================================================================
``runtime_quote``    a signed statement about the runtime the answer was produced in
``response_binding`` request and response hashes *inside* the signed structure, not beside it
``model_identity``   a runtime or model hash *inside* the signed structure, not a name in JSON
``verifiable``       we can check it ourselves: a documented format or a verifier key
``client_nonce``     we were able to supply our own nonce
===================  =========================================================================

``response_binding`` and ``model_identity`` are separate on purpose. An attestation without a
binding says *something* trustworthy ran, not that *this* answer came from it. A model name beside
a signed structure is a claim with a signature nearby. Both look like attestation from the outside
and are not.

.. warning::
   Experimental. The API and the wire shape may change or be removed in any release without
   deprecation. This module has no provider-measured fixtures yet: what it maps is derived from
   published provider documentation, not from a live response.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

__all__ = [
    "PARTS", "REQUIRED_PARTS", "evidence_completeness", "provider_evidence_digest",
    "to_attestation_result_input", "assurance_for",
]

#: The five parts, in the order they are established.
PARTS: tuple[str, ...] = (
    "runtime_quote", "response_binding", "model_identity", "verifiable", "client_nonce",
)

#: Without these three the term is empty. ``verifiable`` and ``client_nonce`` strengthen the claim
#: but their absence is reported rather than fatal.
REQUIRED_PARTS: tuple[str, ...] = ("runtime_quote", "response_binding", "model_identity")

_ABSENT = "absent"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonable(value: Any) -> Any:
    """Bytes as hex, everything else as its repr — so the digest never raises.

    Provider evidence legitimately carries raw key material and quotes as ``bytes``; a digest
    helper that dies on them would push callers into hand-rolling their own, and two digests over
    the same evidence is the drift this function exists to prevent. Found by the module's own
    first run: the verifier key is bytes.
    """
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return repr(value)


def provider_evidence_digest(evidence: Any) -> str:
    """A stable digest over the provider's raw evidence, for binding it into a receipt.

    Computed over the canonical JSON form so that key order cannot move it. A receipt that names
    this digest binds the evidence it was issued against.
    """
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           default=_jsonable)
    return _sha256_hex(canonical.encode("utf-8"))


def evidence_completeness(evidence: dict) -> dict:
    """Which of the five parts the provider's evidence actually carries.

    Three states per part — ``present``, ``absent``, ``unverifiable`` — and never two. A part is
    ``unverifiable`` when it is there but we cannot check it; that is different from missing, and
    collapsing the two loses the distinction a reviewer needs.
    """
    if not isinstance(evidence, dict):
        return {"parts": {p: _ABSENT for p in PARTS}, "complete": False,
                "detail": "evidence is not a mapping"}
    parts: dict[str, str] = {}
    parts["runtime_quote"] = "present" if evidence.get("runtime_quote") else _ABSENT
    binding = evidence.get("response_binding") or {}
    parts["response_binding"] = (
        "present" if isinstance(binding, dict)
        and binding.get("request_hash") and binding.get("response_hash") else _ABSENT)
    parts["model_identity"] = (
        "present" if evidence.get("attested_model_hash") or evidence.get("attested_runtime_hash")
        else _ABSENT)
    parts["verifiable"] = (
        "present" if evidence.get("verifier_key") or evidence.get("documented_format")
        else "unverifiable")
    parts["client_nonce"] = "present" if evidence.get("client_nonce") else _ABSENT
    missing_required = [p for p in REQUIRED_PARTS if parts[p] != "present"]
    return {"parts": parts, "complete": not missing_required,
            "missing_required": missing_required,
            "detail": ("all required parts present" if not missing_required
                       else f"missing required: {', '.join(missing_required)}")}


def to_attestation_result_input(evidence: dict, *, expected_binding: str) -> dict:
    """Map provider evidence onto the inputs :mod:`enclave` needs, without deciding anything.

    Returns ``{eat_jws, verifier_pubkey, expected_binding, ready, detail}``. ``ready`` is False
    whenever a required part is missing or the provider's own binding does not match
    ``expected_binding`` — the caller must not fall back to calling the verifier anyway.

    ``expected_binding`` comes from :func:`~proofbundle.experimental.enclave.enclave_binding_for`.
    Passing anything else defeats the point: the binding is what ties the attestation to *this*
    receipt.
    """
    completeness = evidence_completeness(evidence)
    out: dict[str, Any] = {
        "eat_jws": evidence.get("attestation_result_jws") if isinstance(evidence, dict) else None,
        "verifier_pubkey": evidence.get("verifier_key") if isinstance(evidence, dict) else None,
        "expected_binding": expected_binding,
        "completeness": completeness,
        "ready": False,
    }
    if not completeness["complete"]:
        out["detail"] = completeness["detail"]
        return out
    if not out["eat_jws"]:
        out["detail"] = ("no Attestation Result in EAT form — the provider evidence cannot be "
                         "checked by this package's verifier")
        return out
    if not out["verifier_pubkey"]:
        out["detail"] = "no verifier key supplied — an unchecked signature is not a signature"
        return out
    claimed = (evidence.get("response_binding") or {}).get("receipt_binding")
    if claimed and claimed != expected_binding:
        out["detail"] = ("the provider's binding does not match the expected receipt binding — "
                         "this evidence belongs to a different answer")
        return out
    out["ready"] = True
    out["detail"] = "ready for verify_enclave_attestation"
    return out


def assurance_for(evidence: Optional[dict], *, verification_ok: Optional[bool]) -> dict:
    """``provider_attested`` or ``self_reported`` — fail-closed downward, with no middle value.

    ``verification_ok=None`` means *not checked* and counts as not passed. The difference between
    "the signature does not hold" and "nobody looked" is real, and neither is attestation.
    """
    if not isinstance(evidence, dict):
        return {"assurance": "self_reported", "reason": "no provider evidence"}
    completeness = evidence_completeness(evidence)
    if not completeness["complete"]:
        return {"assurance": "self_reported", "reason": completeness["detail"]}
    if verification_ok is not True:
        return {"assurance": "self_reported",
                "reason": ("verification did not pass" if verification_ok is False
                           else "verification NOT PERFORMED — that is not attestation")}
    return {"assurance": "provider_attested",
            "evidence_digest": provider_evidence_digest(evidence),
            "parts": completeness["parts"]}
