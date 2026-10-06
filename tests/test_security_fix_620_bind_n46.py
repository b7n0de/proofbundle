"""Nachtrag 46 (KRAXO-CLOUD-N46-BINDUNG-NUR-AN-VERIFIZIERTEN-SIGNIERER-01), Z309 / 6.2.0 security fix.

Nachbesserung zu Nachtrag 44. Two findings of the Codex defect search at b28c4217, measured by this session:

F1 (bundle.py): the binding gate received the bundle's claimed public key as the bundle signer even when the
    bundle's ed25519 signature FAILED. A control bundle with a flipped signature byte (public_key_b64 unchanged)
    kept the SD-JWT single fields positive — sd-jwt-key-binding True and, in the CLI, key_binding_ok / audience_ok
    / nonce_ok True — although nothing was signed. Fix: the binding path gets a signer only when sig_ok is exactly
    True; otherwise the signer is None, the binding path fails closed, and sd-jwt-issuer-trust is reported False.

F2 (policy.py): evaluate_policy took the crypto result and the bundle as separate arguments and never bound them.
    A good result of bundle A combined with a different, unsigned bundle B gave policy_ok True and every sd_jwt
    rule positive (the signer was re-decoded from B and B's self-signed SD-JWT verified under it). Fix: the result
    must carry the signer and payload digest verify_bundle actually verified (set only on a passing signature), and
    evaluate_policy evaluates a policy only when those equal this bundle's signer and payload digest.

Only fail-closed behaviour is tested, no further attack rebuilds (the attack inputs come from the Nachtrag 44
test helpers with their test keys). Red at b28c42175282df31629ecf05b1e2d4bf7e87a793, green after.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import unittest

from proofbundle import verify_bundle
from proofbundle.policy import evaluate_policy

# The Nachtrag 44 fixtures (test keys only): a control eval receipt whose one key signs both the bundle and the
# SD-JWT, and an attack bundle whose SD-JWT is signed by a different key than the bundle, plus CLI helpers.
from test_security_fix_620_bind_n44 import (  # type: ignore
    _attack_bundle, _cli_json, _control_bundle, _write, _AUD, _NONCE,
)


def _flip_first_b64(s: str) -> str:
    return ("A" if s[0] != "A" else "B") + s[1:]


def _checks(result) -> dict:
    return {c.name: c.ok for c in result.checks}


def _broken_signature_bundle() -> dict:
    """The control bundle with a flipped signature byte; public_key_b64 unchanged, so the bundle is NOT signed
    by its stated key but still names it (the exact shape of F1)."""
    b = copy.deepcopy(_control_bundle())
    b["signature"]["sig_b64"] = _flip_first_b64(b["signature"]["sig_b64"])
    return b


class F1AnInvalidBundleSignatureGatesTheSdJwtFields(unittest.TestCase):
    """F1 counter-probe + control, adapted per the Nachtrag 46b review (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-
    REVIEW-01`, point 3): a failed bundle signature closes the BUNDLE-BINDING path and the KB / audience /
    nonce fields that depend on it, at verify_bundle and at the CLI. A genuinely successful SD-JWT
    issuer-signature check is a separate crypto finding and may stay positive — the earlier "no positive field
    from the SD-JWT" was broader than the contract. The independent pin path stays unchanged (class F2)."""

    def test_verify_bundle_reports_the_kb_verdict_gated(self):
        r = verify_bundle(_broken_signature_bundle(), expected_aud=_AUD, expected_nonce=_NONCE)
        ch = _checks(r)
        self.assertIs(ch.get("ed25519-signature"), False)
        self.assertIs(r.ok, False)
        # the bundle-binding trust verdict is explicitly gated closed, not silently left positive
        self.assertIs(ch.get("sd-jwt-issuer-trust"), False)
        # review point 3: the SD-JWT's own issuer signature is a separate crypto fact; a genuinely valid one
        # stays a positive finding (the flipped byte is the BUNDLE signature, not the SD-JWT issuer signature).
        self.assertIs(ch.get("sd-jwt-issuer-signature"), True)

    def test_cli_single_fields_are_not_positive(self):
        rc, j = _cli_json(["verify", _write(_broken_signature_bundle()), "--aud", _AUD, "--nonce", _NONCE, "--json"])
        self.assertNotEqual(rc, 0)
        for field in ("ok", "crypto_ok", "key_binding_ok", "audience_ok", "nonce_ok"):
            self.assertIsNot(j.get(field), True, f"{field} must not read positive on an unsigned bundle")

    def test_control_a_valid_bundle_is_positive(self):
        r = verify_bundle(_control_bundle(), expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertIs(r.ok, True)
        # a trusted binding path adds no failing sd-jwt-issuer-trust check (absent == not gated closed)
        self.assertIsNot(_checks(r).get("sd-jwt-issuer-trust"), False)


class F2APolicyResultMustBeBoundToTheBundle(unittest.TestCase):
    """F2 counter-probe + controls: a result not produced from the judged bundle confers no policy verdict; a
    matching result does; the pin path is unchanged."""

    _POLICY = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n46",
               "sd_jwt": {"require_key_binding_when_cnf_present": True, "require_nonce": True, "expected_aud": _AUD}}

    def test_a_good_result_of_bundle_A_does_not_validate_bundle_B(self):
        good = verify_bundle(_control_bundle(), expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertIs(good.ok, True)
        attack, pin = _attack_bundle()
        attack = copy.deepcopy(attack)
        # set the bundle signer to the SD-JWT issuer key -> the bundle's own signature is now invalid, but the
        # binding path's re-decoded signer would equal the SD-JWT issuer (the F2 shape).
        attack["signature"]["public_key_b64"] = pin.split("ed25519:", 1)[1]
        out = evaluate_policy(attack, good, copy.deepcopy(self._POLICY))
        self.assertIsNot(out["policy_ok"], True)
        for c in out["checks"]:
            self.assertIsNot(c["ok"], True, f"no rule may be positive on an unbound result: {c['name']}")

    def test_control_a_matching_bundle_and_result_is_positive(self):
        b = _control_bundle()
        out = evaluate_policy(b, verify_bundle(b, expected_aud=_AUD, expected_nonce=_NONCE),
                              copy.deepcopy(self._POLICY))
        self.assertIs(out["policy_ok"], True)

    def test_control_the_pin_path_with_a_different_bundle_signer_still_trusts(self):
        # unchanged by N46: a result produced from THIS bundle, plus a relying-party pin on the SD-JWT key, trusts
        # the KB-JWT even though the SD-JWT signer is not the bundle signer (an explicit out-of-band anchor).
        bundle, pin = _attack_bundle()
        pol = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n46",
               "sd_jwt": {"require_key_binding_when_cnf_present": True, "issuer_key_pin": pin, "expected_aud": _AUD}}
        out = evaluate_policy(bundle, verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE,
                                                    sd_jwt_issuer_key_pin=pin), pol)
        self.assertIs(out["policy_ok"], True)


class AResultRecordsWhatItActuallyVerified(unittest.TestCase):
    """Nachtrag 46 point 2 (additive): a verify_bundle result records the signer and payload digest it verified,
    and only on a passing signature."""

    def test_a_passing_result_records_the_signer_and_payload_digest(self):
        b = _control_bundle()
        r = verify_bundle(b)
        self.assertIs(r.ok, True)
        self.assertEqual(r.verified_signer_pub, base64.b64decode(b["signature"]["public_key_b64"]))
        self.assertEqual(r.verified_payload_digest,
                         hashlib.sha256(base64.b64decode(b["payload_b64"])).hexdigest())

    def test_a_failed_signature_records_nothing(self):
        r = verify_bundle(_broken_signature_bundle())
        self.assertIs(next(c.ok for c in r.checks if c.name == "ed25519-signature"), False)
        self.assertIsNone(r.verified_signer_pub)
        self.assertIsNone(r.verified_payload_digest)


if __name__ == "__main__":
    unittest.main()
