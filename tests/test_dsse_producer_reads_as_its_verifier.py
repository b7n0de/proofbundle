"""`dsse.sign_envelope` signs only an envelope that `verify_envelope` reads within its budget.

Deep gate 6.6.0 at d8881edc, iteration 1, finding Z7: the DSSE primitive every statement producer signs through
wrote a caller's `keyid` of 1,000,001 characters, and a decision receipt whose statement encodes to more than
1,000,000 base64 characters, into envelopes that `verify_envelope` then refused with `string_len`. The producer now
reads the envelope as the verifier reads it before the signer is asked.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.errors import BundleFormatError, ProofBundleError

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x03" * 32)
_PUB = _KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_OCTET = "application/octet-stream"
_INTOTO = "application/vnd.in-toto+json"


class _CountingSigner:
    """An Ed25519 signer that counts how often it is asked."""

    def __init__(self) -> None:
        self.calls = 0

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return _KEY.sign(message)

    def public_key(self):
        return _KEY.public_key()


def _verifies(envelope: dict, payload_type: str) -> bool:
    try:
        return dsse.verify_envelope(envelope, _PUB, payload_type=payload_type) is True
    except ProofBundleError:
        return False


def test_a_keyid_at_the_string_bound_is_signed_and_verifies():
    envelope = dsse.sign_envelope(b"x", _KEY, payload_type=_OCTET, keyid="k" * 1_000_000)
    assert _verifies(envelope, _OCTET)


def test_a_keyid_past_the_string_bound_is_refused_before_the_signer_is_asked():
    signer = _CountingSigner()
    with pytest.raises(BundleFormatError, match="verification budget"):
        dsse.sign_envelope(b"x", signer, payload_type=_OCTET, keyid="k" * 1_000_001)
    assert signer.calls == 0


def test_a_payload_type_past_the_string_bound_is_refused():
    with pytest.raises(BundleFormatError, match="verification budget"):
        dsse.sign_envelope(b"x", _KEY, payload_type="t" * 1_000_001, keyid="")


def test_a_body_whose_base64_is_at_the_string_bound_is_signed_and_verifies():
    body = b"\x00" * 750_000  # 1,000,000 base64 characters
    envelope = dsse.sign_envelope(body, _KEY, payload_type=_OCTET)
    assert len(envelope["payload"]) == 1_000_000
    assert _verifies(envelope, _OCTET)


def test_a_body_whose_base64_is_past_the_string_bound_is_refused():
    with pytest.raises(BundleFormatError, match="verification budget"):
        dsse.sign_envelope(b"\x00" * 750_001, _KEY, payload_type=_OCTET)


def _statement_reader_accepts(body: bytes) -> bool:
    """The reading the statement verifiers apply to a `+json` payload."""
    from proofbundle._strict_json import loads_strict
    try:
        loads_strict(body.decode("utf-8"))
    except ProofBundleError:
        return False
    return True


@pytest.mark.parametrize("payload_type", [_INTOTO, "application/vnd.in-toto.test-result+json"])
def test_a_json_payload_past_the_depth_or_node_bound_is_refused(payload_type):
    """A string past the bound inside the payload cannot get under the envelope's own bound once base64 grows it
    by a third; depth and the node count can, and the statement verifiers refuse them."""
    deep = ("[" * 65 + "]" * 65).encode("ascii")
    wide = json.dumps([0] * 200_001).encode("ascii")
    for body in (deep, wide):
        assert not _statement_reader_accepts(body)
        with pytest.raises(BundleFormatError, match="verification budget"):
            dsse.sign_envelope(body, _KEY, payload_type=payload_type)
    for body in (("[" * 64 + "]" * 64).encode("ascii"), json.dumps([0] * 199_999).encode("ascii")):
        assert _statement_reader_accepts(body)
        assert _verifies(dsse.sign_envelope(body, _KEY, payload_type=payload_type), payload_type)


def test_a_payload_type_without_the_json_suffix_is_not_parsed():
    deep = ("[" * 65 + "]" * 65).encode("ascii")
    assert _verifies(dsse.sign_envelope(deep, _KEY, payload_type=_OCTET), _OCTET)


def test_a_body_that_is_not_json_is_left_to_the_verifier():
    envelope = dsse.sign_envelope(b"not json", _KEY, payload_type=_INTOTO)
    assert _verifies(envelope, _INTOTO)


def _decision(code: str) -> dict:
    return {"schemaVersion": "0.1.0", "decisionId": "urn:test:p", "decisionType": "preActionAuthorization",
            "decidedAt": "2026-01-01T00:00:00Z", "decisionMaker": {"id": "urn:test:m"}, "agent": {"id": "urn:test:a"},
            "principal": {"id": "urn:test:p"},
            "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
            "inputSnapshot": [], "policyBoundary": {"policyEngine": "t", "policyId": "urn:t", "decisionPath": "allow"},
            "evidenceRefs": [], "decision": {"verdict": "DENY", "reasonCodes": [code]}}


def test_a_decision_receipt_its_verifier_refuses_for_size_is_not_emitted():
    """Measured at d8881edc: a reason code of 1,000,000 characters was emitted, and `verify_decision_receipt`
    answered ok False because the envelope exceeded its budget."""
    with pytest.raises(ProofBundleError):
        emit_decision_receipt(_decision("x" * 1_000_000), _KEY, strict=False)
    control = emit_decision_receipt(_decision("x"), _KEY, strict=False)
    assert verify_decision_receipt(control, _PUB)["ok"] is True


def test_a_json_body_with_a_lone_surrogate_is_left_to_the_verifier():
    """Only the budget is judged before signing. A lone surrogate is a question of form: the statement verifiers refuse
    it as malformed, and tests build such envelopes on purpose (tests/test_sibling_never_raise_361.py)."""
    body = json.dumps({"s": "\ud800"}).encode("ascii")
    assert not _statement_reader_accepts(body)
    assert _verifies(dsse.sign_envelope(body, _KEY, payload_type=_INTOTO), _INTOTO)
