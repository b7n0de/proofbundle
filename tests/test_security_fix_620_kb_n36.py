"""Nachtrag 36 (Z309, 6.2.0 security fix): the KB-JWT / SD-JWT policy checks bind to a TRUSTED issuer, as a class.

PR 311 review 5406815856, P1 "Bind KB-JWT policy checks to the signed payload". A KB-JWT hangs on the ``cnf``
holder key inside the issuer-signed SD-JWT payload, whose verifying key (``sd_jwt_vc.issuer_public_key_b64``) is
supplied OUTSIDE the bundle's signed payload. So a self-signed generic SD-JWT with any ``cnf`` and a matching
KB-JWT makes ``sd-jwt-key-binding`` pass and the whole bundle verify (a generic VC carries no eval root commitment,
so the bundle-binding check is out of scope) — yet its audience, nonce and "key binding present" claim are
attacker-chosen. The Nachtrag 32 Critical fix closed this only at ``expected_vct``. Here the same test becomes the
shared helper ``_sd_jwt_issuer_trusted`` and every issuer-trusting ``sd_jwt`` rule applies it:
``require_key_binding_when_cnf_present``, ``require_nonce``, ``expected_aud`` and (refactored) ``expected_vct``.

Secure behaviour only, per rule (no attack rebuilds beyond these fail-closed cases):
  - no pin and not bound to the signed payload  → fails  (the vulnerability: a PASS at 94f6dd3e for the first three)
  - a pin that is a foreign key                 → fails
  - a pin equal to the verifying key            → passes
  - bound to the signed payload                 → passes

The untrusted/pin cases use a generic self-signed SD-JWT + cnf + KB-JWT (crypto passes, issuer untrusted); the
payload-bound case uses an eval SD-JWT committed to this bundle's root (``sd-jwt-bundle-binding`` passes → trusted).
Red at 94f6dd3e for the three KB-JWT rules (expected_vct was already closed by Nachtrag 32 and is only refactored
here). Green after. Catch proof in scratchpad/n36/fang.
"""
from __future__ import annotations

import base64
import datetime
import json
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import _SDJWT_KEYS, evaluate_policy
try:   # the classification is Nachtrag 36; at 94f6dd3e it does not exist yet, so the class test fails red there
    from proofbundle.policy import _SDJWT_KEYS_NEED_ISSUER_TRUST, _SDJWT_KEYS_NO_ISSUER_TRUST
except ImportError:
    _SDJWT_KEYS_NEED_ISSUER_TRUST = _SDJWT_KEYS_NO_ISSUER_TRUST = frozenset()
from proofbundle.sdjwt_issue import _b64url, _jwt_payload, issue_sd_jwt, present_with_key_binding

_IAT = 1_780_000_000
_NOW = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
_AUD = "v.example"
_NONCE = "n-123"
_FOREIGN_PIN = "ed25519:" + base64.b64encode(b"\x09" * 32).decode("ascii")


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign_generic_sd_jwt(signer, payload: dict) -> str:
    """A minimal signed, disclosure-free generic SD-JWT with an arbitrary always-open payload (mirrors the
    verify-binding test's builder): no eval root commitment, so verify_bundle treats it as a generic VC."""
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    sig = signer.sign(signing_input.encode("ascii"))
    return signing_input + "." + _b64url(sig) + "~"


def _generic_bundle():
    """A generic self-signed SD-JWT (iss/vct, a cnf holder key) with a KB-JWT, in a non-eval bundle. The issuer
    key is supplied in sd_jwt_vc (attacker-chosen) and nothing pins it or binds it to the payload → untrusted,
    yet the whole bundle verifies and sd-jwt-key-binding passes. Returns (bundle, issuer_pub_b64, vct)."""
    issuer = generate_signer()
    holder = generate_signer()
    vct = "https://issuer.example/vct/membership/v1"
    payload = {"iss": "https://issuer.example", "vct": vct, "iat": _IAT,
               "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(_raw_pub(holder))}}}
    compact = _sign_generic_sd_jwt(issuer, payload)
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    issuer_pub_b64 = base64.b64encode(_raw_pub(issuer)).decode("ascii")
    vc = {"compact": presented, "issuer_public_key_b64": issuer_pub_b64}
    bundle = emit_bundle(b'{"generic":"vc"}', issuer, sd_jwt_vc=vc)
    return bundle, issuer_pub_b64, vct


def _bound_bundle():
    """An eval SD-JWT committed to THIS bundle's merkle root, with a KB-JWT → sd-jwt-bundle-binding passes, so the
    issuer is trusted via the payload binding (no pin needed). Returns (bundle, vct)."""
    signer = generate_signer()
    holder = generate_signer()
    ev_claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
    plain = emit_eval_receipt(ev_claim, signer)
    real_root = (plain.get("merkle") or {}).get("root_b64")
    sd_claim = json.loads(base64.b64decode(plain["payload_b64"]))
    compact = issue_sd_jwt(sd_claim, signer, root_b64=real_root, exact_score="0.9",
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw_pub(signer)).decode("ascii")}
    bundle = emit_eval_receipt(ev_claim, signer, sd_jwt=vc)
    return bundle, _jwt_payload(bundle["sd_jwt_vc"]["compact"]).get("vct")


def _verify(bundle, sdj):
    """Verify, threading the rule's issuer_key_pin into the crypto layer (Nachtrag 38: the shared issuer-trust
    gate now lives in verify_bundle, so an untrusted KB-JWT fails crypto before the policy runs)."""
    return verify_bundle(bundle, sd_jwt_issuer_key_pin=(sdj or {}).get("issuer_key_pin"))


def _issuer_trust_ok(result):
    return next((c.ok for c in result.checks if c.name == "sd-jwt-issuer-trust"), None)


def _policy_rule(bundle, result, sdj, name):
    """Evaluate the sd_jwt policy rule over an already-trusted crypto result; returns (policy_ok, rule_ok)."""
    policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "n36",
              "sd_jwt": {"require_key_binding_when_cnf_present": False, "require_nonce": False, **sdj}}
    res = evaluate_policy(bundle, result, policy, now=_NOW)
    chk = [c for c in res["checks"] if c["name"] == name]
    assert len(chk) == 1, (name, res["reason"], [c["name"] for c in res["checks"]])
    return res["policy_ok"], chk[0]["ok"]


class _RuleClassMixin:
    """Each KB-JWT/SD-JWT rule, four outcomes. Since Nachtrag 38 the untrusted and foreign-pin cases fail at the
    crypto layer (sd-jwt-issuer-trust) before the policy runs; the matching-pin and payload-bound cases reach the
    policy and pass. Either way: a KB-JWT verdict is positive only under a trusted issuer."""
    check_name = ""

    def _rule(self, *, vct=None):
        raise NotImplementedError

    def test_untrusted_issuer_fails_closed(self):
        bundle, _pub, vct = _generic_bundle()
        result = _verify(bundle, self._rule(vct=vct))
        self.assertFalse(result.ok, f"{self.check_name}: crypto must fail closed under an untrusted self-signed "
                                    "issuer (N38)")
        self.assertIs(_issuer_trust_ok(result), False)

    def test_a_foreign_pin_fails_closed(self):
        bundle, _pub, vct = _generic_bundle()
        result = _verify(bundle, {**self._rule(vct=vct), "issuer_key_pin": _FOREIGN_PIN})
        self.assertFalse(result.ok, f"{self.check_name}: crypto must fail closed when the pin is not the "
                                    "verifying key")
        self.assertIs(_issuer_trust_ok(result), False)

    def test_a_matching_pin_passes(self):
        bundle, pub, vct = _generic_bundle()
        sdj = {**self._rule(vct=vct), "issuer_key_pin": "ed25519:" + pub}
        result = _verify(bundle, sdj)
        self.assertTrue(result.ok, f"{self.check_name}: crypto must pass when the issuer key matches the pin")
        policy_ok, ok = _policy_rule(bundle, result, sdj, self.check_name)
        self.assertTrue(ok, f"{self.check_name} must pass when the issuer key matches the pin")
        self.assertIs(policy_ok, True)

    def test_bound_to_the_signed_payload_passes(self):
        bundle, vct = _bound_bundle()
        sdj = self._rule(vct=vct)
        result = _verify(bundle, sdj)
        self.assertTrue(result.ok, f"{self.check_name}: crypto must pass when the SD-JWT binds to the payload")
        policy_ok, ok = _policy_rule(bundle, result, sdj, self.check_name)
        self.assertTrue(ok, f"{self.check_name} must pass when the SD-JWT binds to the signed payload")
        self.assertIs(policy_ok, True)


class RequireKeyBindingWhenCnfPresent(_RuleClassMixin, unittest.TestCase):
    check_name = "policy:key_binding_present"

    def _rule(self, *, vct=None):
        return {"require_key_binding_when_cnf_present": True}


class RequireNonce(_RuleClassMixin, unittest.TestCase):
    check_name = "policy:nonce_present"

    def _rule(self, *, vct=None):
        return {"require_nonce": True}


class ExpectedAud(_RuleClassMixin, unittest.TestCase):
    check_name = "policy:expected_aud"

    def _rule(self, *, vct=None):
        return {"expected_aud": _AUD}


class ExpectedVct(_RuleClassMixin, unittest.TestCase):
    # expected_vct was already closed by Nachtrag 32; here it only routes through the shared helper, so it keeps
    # the same four outcomes (green at 94f6dd3e and after).
    check_name = "policy:expected_vct"

    def _rule(self, *, vct=None):
        return {"expected_vct": vct}


class TheClassIsHeldClosed(unittest.TestCase):
    """Point 4: every sd_jwt policy key is classified, and no 'needs issuer trust' rule bypasses the helper."""

    def test_the_classification_partitions_every_sd_jwt_key(self):
        self.assertEqual(_SDJWT_KEYS_NEED_ISSUER_TRUST | _SDJWT_KEYS_NO_ISSUER_TRUST, set(_SDJWT_KEYS),
                         "a new sd_jwt policy key must be classified as needing issuer trust or not")
        self.assertEqual(_SDJWT_KEYS_NEED_ISSUER_TRUST & _SDJWT_KEYS_NO_ISSUER_TRUST, set(),
                         "a key cannot be in both groups")

    def test_no_needs_trust_rule_passes_under_an_untrusted_issuer(self):
        # If any rule in the first group bypassed the helper, it would pass here → this test goes red.
        bundle, _pub, vct = _generic_bundle()
        value_for = {
            "require_key_binding_when_cnf_present": (True, "policy:key_binding_present"),
            "require_nonce": (True, "policy:nonce_present"),
            "expected_aud": (_AUD, "policy:expected_aud"),
            "expected_vct": (vct, "policy:expected_vct"),
        }
        self.assertEqual(set(value_for), set(_SDJWT_KEYS_NEED_ISSUER_TRUST),
                         "every 'needs issuer trust' key must have an untrusted-issuer case here")
        for key, (value, name) in value_for.items():
            result = _verify(bundle, {key: value})
            self.assertFalse(result.ok, f"{key} ({name}) must fail closed under an untrusted issuer (N38 gate)")
            self.assertIs(_issuer_trust_ok(result), False,
                          f"{key} ({name}) must fail closed via sd-jwt-issuer-trust, not a helper bypass")


if __name__ == "__main__":
    unittest.main()
