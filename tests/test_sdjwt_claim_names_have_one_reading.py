"""A1 of CODEX-KLASSENSUCHE-631-01 (class A, at f6ea5cc3): a claim name stands once in its object.

Measured at f6ea5cc3: two disclosures ``[salt0, "passed", false]`` and ``[salt1, "passed", true]``, both committed
by one issuer-signed ``_sd`` block, passed ``verify_sdjwt_vc`` in both orders (``ok=True``, also with holder binding),
and ``verify_bundle`` passed the same credential. A merge where the last value wins reads another ``passed`` after the
order is swapped while both presentations verify. RFC 9901 section 7.1 resolves each disclosure at its own place and
rejects a claim name that already stands in that object. The controls: one disclosure passes; a digest the payload
does not commit and a foreign issuer anchor fail as before.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, verify_bundle
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import present_with_key_binding
from proofbundle.sdjwt_vc import verify_sdjwt_vc

VCT = "https://b7n0de.com/vct/eval-credential/v1"
POLICY = {"vctAllowlist": [VCT], "requireKeyBinding": False}
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))          # the repository's test seed
HOLDER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
AUD, NONCE, IAT = "verifier.example", "n-1", 1_700_000_000


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _disclosure(*items) -> tuple[str, str]:
    encoded = _b64url(json.dumps(list(items)).encode())
    return encoded, _b64url(hashlib.sha256(encoded.encode("ascii")).digest())


def _issue(payload: dict, signer=ISSUER) -> str:
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii")))


def _compact(payload: dict, disclosures: list[str], signer=ISSUER) -> str:
    return _issue(payload, signer) + "~" + "".join(d + "~" for d in disclosures)


D_FALSE = _disclosure("c2FsdDA", "passed", False)
D_TRUE = _disclosure("c2FsdDE", "passed", True)


def _two_passed(order: str, cnf: bool = False) -> str:
    payload = {"vct": VCT, "_sd_alg": "sha-256", "_sd": [D_FALSE[1], D_TRUE[1]]}
    if cnf:
        payload["cnf"] = {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(_raw(HOLDER))}}
    first, second = (D_FALSE, D_TRUE) if order == "false first" else (D_TRUE, D_FALSE)
    return _compact(payload, [first[0], second[0]])


@pytest.mark.parametrize("order", ["false first", "true first"])
def test_two_disclosures_of_one_claim_name_are_refused_in_both_orders(order):
    compact = _two_passed(order)
    r = verify_sdjwt_vc(compact, POLICY, issuer_pubkey=_raw(ISSUER))
    assert r["ok"] is False, r
    assert r["issuer"]["sig_ok"] is True and r["issuer"]["structure_ok"] is False
    assert "'passed' stands more than once in one object" in r["issuer"]["detail"]


@pytest.mark.parametrize("order", ["false first", "true first"])
def test_the_same_with_the_required_holder_binding(order):
    presented = present_with_key_binding(_two_passed(order, cnf=True), HOLDER, aud=AUD, nonce=NONCE, iat=IAT)
    r = verify_sdjwt_vc(presented, {"vctAllowlist": [VCT]}, issuer_pubkey=_raw(ISSUER), holder_pubkey=None,
                        expected_aud=AUD, expected_nonce=NONCE)
    assert r["binding"]["ok"] is True, r["binding"]
    assert r["ok"] is False and r["issuer"]["structure_ok"] is False


@pytest.mark.parametrize("order", ["false first", "true first"])
def test_the_bundle_check_refuses_the_same_credential(order):
    vc = {"compact": _two_passed(order), "issuer_public_key_b64": base64.b64encode(_raw(ISSUER)).decode()}
    bundle = emit_bundle(b'{"generic":"vc"}', ISSUER, sd_jwt_vc=vc)
    r = verify_bundle(bundle)
    checks = {c.name: c.ok for c in r.checks}
    assert r.ok is False and checks["sd-jwt-disclosures"] is False, checks


def test_a_disclosure_beside_an_open_claim_of_the_same_name_is_refused():
    payload = {"vct": VCT, "passed": False, "_sd": [D_TRUE[1]]}
    r = verify_sdjwt_vc(_compact(payload, [D_TRUE[0]]), POLICY, issuer_pubkey=_raw(ISSUER))
    assert r["ok"] is False and "'passed' stands more than once" in r["issuer"]["detail"]


def test_two_disclosures_of_one_name_inside_a_nested_and_a_disclosed_object_are_refused():
    inner_false, inner_true = _disclosure("c2FsdDI", "flag", False), _disclosure("c2FsdDM", "flag", True)
    nested = {"vct": VCT, "result": {"_sd": [inner_false[1], inner_true[1]]}}
    assert verify_sd_jwt(_compact(nested, [inner_false[0], inner_true[0]]), _raw(ISSUER))["structure_ok"] is False
    holder_obj = _disclosure("c2FsdDQ", "result", {"_sd": [inner_false[1], inner_true[1]]})
    recursive = {"vct": VCT, "_sd": [holder_obj[1]]}
    r = verify_sd_jwt(_compact(recursive, [holder_obj[0], inner_true[0], inner_false[0]]), _raw(ISSUER))
    assert r["structure_ok"] is False, r


@pytest.mark.parametrize("name", ["_sd", "..."])
def test_a_disclosure_that_names_no_valid_claim_is_refused(name):
    bad = _disclosure("c2FsdDU", name, ["x"])
    r = verify_sd_jwt(_compact({"vct": VCT, "_sd": [bad[1]]}, [bad[0]]), _raw(ISSUER))
    assert r["structure_ok"] is False and "names no valid claim" in r["detail"]


def test_a_disclosure_at_a_place_of_the_other_form_is_refused():
    element = _disclosure("c2FsdDY", "only a value")
    in_object = verify_sd_jwt(_compact({"vct": VCT, "_sd": [element[1]]}, [element[0]]), _raw(ISSUER))
    assert in_object["structure_ok"] is False and "array-element disclosure" in in_object["detail"]
    in_array = verify_sd_jwt(_compact({"vct": VCT, "list": [{"...": D_TRUE[1]}]}, [D_TRUE[0]]), _raw(ISSUER))
    assert in_array["structure_ok"] is False and "object-property disclosure" in in_array["detail"]


def test_one_disclosure_committed_at_two_places_is_refused():
    payload = {"vct": VCT, "a": {"_sd": [D_TRUE[1]]}, "b": {"_sd": [D_TRUE[1]]}}
    r = verify_sd_jwt(_compact(payload, [D_TRUE[0]]), _raw(ISSUER))
    assert r["structure_ok"] is False and "more than one place" in r["detail"]


# --- controls -----------------------------------------------------------------------------------------------------

def test_control_one_disclosure_of_the_name_passes():
    payload = {"vct": VCT, "_sd_alg": "sha-256", "_sd": [D_TRUE[1]]}
    r = verify_sdjwt_vc(_compact(payload, [D_TRUE[0]]), POLICY, issuer_pubkey=_raw(ISSUER))
    assert r["ok"] is True, r


def test_control_one_name_in_two_different_objects_passes():
    inner = _disclosure("c2FsdDc", "passed", True)
    payload = {"vct": VCT, "passed": False, "detail": {"_sd": [inner[1]]}}
    r = verify_sdjwt_vc(_compact(payload, [inner[0]]), POLICY, issuer_pubkey=_raw(ISSUER))
    assert r["ok"] is True, r


def test_control_array_elements_and_a_repeated_presented_disclosure_pass():
    element = _disclosure("c2FsdDg", "x")
    payload = {"vct": VCT, "list": [{"...": element[1]}, "open"], "_sd": [D_TRUE[1]]}
    r = verify_sdjwt_vc(_compact(payload, [element[0], D_TRUE[0], D_TRUE[0]]), POLICY, issuer_pubkey=_raw(ISSUER))
    assert r["ok"] is True, r


def test_control_an_uncommitted_disclosure_and_a_foreign_anchor_still_fail():
    payload = {"vct": VCT, "_sd": [D_TRUE[1]]}
    missing = verify_sdjwt_vc(_compact(payload, [D_TRUE[0], D_FALSE[0]]), POLICY, issuer_pubkey=_raw(ISSUER))
    assert missing["ok"] is False and missing["issuer"]["structure_ok"] is False
    foreign = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    wrong = verify_sdjwt_vc(_compact(payload, [D_TRUE[0]]), POLICY, issuer_pubkey=_raw(foreign))
    assert wrong["ok"] is False and wrong["issuer"]["sig_ok"] is False
