"""A trust policy that pins an SD-JWT issuer key means that key.

Until 6.6.0 ``sd_jwt.issuer_key_pin`` was read only by the rules that trust a value of the SD-JWT (``expected_vct``,
``require_nonce``, ``expected_aud`` and a key binding verdict). A policy that pinned an issuer and set none of them, or
only ``require_key_binding_when_cnf_present``, passed for an SD-JWT without ``cnf`` that anyone had signed with a key
of their own and written into the bundle as ``sd_jwt_vc.issuer_public_key_b64``. Measured on 2026-11-23 on the tree
that prepares 6.6.1: ``policy_ok`` True for the pin alone and for the pin beside the key binding rule, False beside
``expected_vct`` and beside ``require_nonce``.

The pin is a rule of its own now: where the bundle carries an SD-JWT, the key that verified it must be the pin
(``policy:sd_jwt_issuer_pinned``). Without a pin this rule adds nothing, and the ``verify_bundle`` argument
``sd_jwt_issuer_key_pin`` still judges a key binding verdict only; both are held here as they are.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.policy import evaluate_policy, explain_policy, lint_policy

_VCT = "https://example.test/vct"
_PIN_CHECK = "policy:sd_jwt_issuer_pinned"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _pin(key) -> str:
    return "ed25519:" + base64.b64encode(_raw(key)).decode("ascii")


_PRESENTER = ed25519.Ed25519PrivateKey.generate()    # signs the SD-JWT and names itself as its issuer key in the bundle
_PINNED = ed25519.Ed25519PrivateKey.generate()       # the issuer the relying party trusts; it signs nothing here


def _sd_jwt(signer) -> str:
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "dc+sd-jwt"}).encode())
    payload = _b64u(json.dumps({"iss": "https://issuer.example.test", "vct": _VCT}).encode())
    return f"{header}.{payload}.{_b64u(signer.sign(f'{header}.{payload}'.encode('ascii')))}~"


def _bundle(with_sd_jwt: bool = True) -> dict:
    """A bundle with a generic payload. Its SD-JWT carries no ``cnf`` and no Key Binding JWT and is validly signed
    under the presenter's own key, which the bundle names as the issuer key."""
    if not with_sd_jwt:
        return emit_bundle(b'{"generic":"vc"}', generate_signer())
    sd = {"compact": _sd_jwt(_PRESENTER), "issuer_public_key_b64": base64.b64encode(_raw(_PRESENTER)).decode("ascii")}
    return emit_bundle(b'{"generic":"vc"}', generate_signer(), sd_jwt_vc=sd)


def _policy(**sd_jwt) -> dict:
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "issuer-pin", "sd_jwt": sd_jwt}


def _judge(policy: dict, bundle: dict | None = None):
    bundle = _bundle() if bundle is None else bundle
    result = verify_bundle(bundle)
    assert result.ok is True, [(c.name, c.ok, c.detail) for c in result.checks]
    verdict = evaluate_policy(bundle, result, policy)
    pinned = [c["ok"] for c in verdict["checks"] if c["name"] == _PIN_CHECK]
    return verdict["policy_ok"], pinned, verdict["checks"]


# --- a pin for another key ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("beside", [{}, {"require_key_binding_when_cnf_present": True}, {"expected_vct": _VCT},
                                    {"require_nonce": True}],
                         ids=["alone", "key-binding-rule", "expected-vct", "require-nonce"])
def test_a_pin_for_another_key_fails_the_policy(beside):
    policy_ok, pinned, checks = _judge(_policy(issuer_key_pin=_pin(_PINNED), **beside))
    assert policy_ok is False, checks
    assert pinned == [False], checks


def test_beside_the_key_binding_rule_it_is_the_pin_that_refuses():
    """The key binding rule itself still passes for a credential without ``cnf``: it reads no issuer. The verdict
    turns on the pin."""
    _ok, pinned, checks = _judge(_policy(issuer_key_pin=_pin(_PINNED), require_key_binding_when_cnf_present=True))
    rule = [(c["ok"], c["detail"]) for c in checks if c["name"] == "policy:key_binding_present"]
    assert rule == [(True, "no cnf holder key bound; KB not required")], checks
    assert pinned == [False], checks


# --- a pin for the key that signed ---------------------------------------------------------------------------------

@pytest.mark.parametrize("beside", [{}, {"require_key_binding_when_cnf_present": True}, {"expected_vct": _VCT}],
                         ids=["alone", "key-binding-rule", "expected-vct"])
def test_a_pin_for_the_key_that_signed_passes(beside):
    policy_ok, pinned, checks = _judge(_policy(issuer_key_pin=_pin(_PRESENTER), **beside))
    assert policy_ok is True, checks
    assert pinned == [True], checks


# --- no pin: nothing changes ---------------------------------------------------------------------------------------

def test_without_a_pin_the_key_binding_rule_passes_as_before():
    policy_ok, pinned, checks = _judge(_policy(require_key_binding_when_cnf_present=True))
    assert policy_ok is True and pinned == [], checks


def test_without_a_pin_the_vct_rule_fails_as_before():
    policy_ok, pinned, checks = _judge(_policy(expected_vct=_VCT))
    assert policy_ok is False and pinned == [], checks


def test_a_pin_judges_no_bundle_without_an_sd_jwt():
    """The pin names the issuer of an SD-JWT. A bundle that carries none gives it nothing to judge."""
    policy_ok, pinned, checks = _judge(_policy(issuer_key_pin=_pin(_PINNED)), _bundle(with_sd_jwt=False))
    assert policy_ok is True and pinned == [], checks


# --- what stays as it was, named so that a change shows --------------------------------------------------------

def test_the_verify_bundle_argument_still_judges_a_key_binding_verdict_only():
    """``verify_bundle(sd_jwt_issuer_key_pin=...)`` reports ``sd-jwt-issuer-trust`` only after a key binding that was
    performed and passed (SPEC, verification order 7a). This presentation carries no Key Binding JWT, so the argument
    changes nothing here; the rule of this file is the policy's."""
    bundle = _bundle()
    for pin in (_pin(_PINNED), _pin(_PRESENTER)):
        result = verify_bundle(bundle, sd_jwt_issuer_key_pin=pin)
        assert result.ok is True, [(c.name, c.ok, c.detail) for c in result.checks]
        assert [c.name for c in result.checks if c.name == "sd-jwt-issuer-trust"] == []


# --- what is enforced is explained -----------------------------------------------------------------------------

def test_the_pin_is_listed_among_the_pins_of_a_policy():
    policy = _policy(issuer_key_pin=_pin(_PINNED))
    lines = [line for line in explain_policy(policy) if _PIN_CHECK in line]
    assert len(lines) == 1, explain_policy(policy)
    report = lint_policy(policy)
    assert not any("pins nothing" in e for e in report["errors"]), report
    assert lines[0] in report["pins"], report
