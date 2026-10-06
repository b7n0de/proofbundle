"""Nachtrag 44 (Z309, 6.2.0 security fix): the N38 binding path confers trust only when the key that
VERIFIES the SD-JWT is the BUNDLE SIGNER, as a class, at the shared gate (bundle._sd_jwt_issuer_is_trusted).

PR 311 review 5409929917 thread 4180654934 P1 "Require the bundle signer to authorize payload binding". The
Nachtrag 38 binding path reported a KB-JWT verdict (holder binding / audience / nonce) positive whenever the
SD-JWT was bound to the signed payload. But sd-jwt-bundle-binding only matches the SD-JWT's disclosed always-open
fields (incl. the `issuer` STRING) to the signed eval-claim, and sd-jwt-issuer-identity ties that disclosed
issuer to the SD-JWT's OWN verifying key — nothing tied that verifying key to the key that signed the bundle.
So a payload signed by K_bundle whose `issuer` field names K_issuer, carrying an SD-JWT self-signed by
K_issuer != K_bundle, read the KB-JWT verdict positive although the bundle signer never authorized it
(decode_eval_claim already rejects such a bundle: its claim.issuer != bundle signer).

The fix requires, on the binding path, fingerprint(SD-JWT verifying key) == fingerprint(bundle signer) — the
SAME binding decode_eval_claim enforces on the claim's issuer. It lives in the shared gate, so every surface of
the N38 gate honours it: verify_bundle (expected_aud/expected_nonce), the holder binding without aud/nonce, the
CLI verify, the hf_evals receipt-token and eval_results surfaces, and the trust-policy path.

Secure behaviour only, per surface:
  - counter-probe: SD-JWT signer != bundle signer, no pin  -> NOT positive (binding-signer-mismatch)
  - control:       SD-JWT signer == bundle signer          -> positive
  - the pin path is unchanged: a pin on the SD-JWT key still trusts it (an explicit out-of-band anchor).

Red at e37e872bbe03e349ae14f6dc70eff0f4572ce6fb for every surface; green after. Catch proof in scratchpad/n44.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import cli, emit_bundle, generate_signer, verify_bundle
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, decode_eval_claim, issuer_fingerprint
from proofbundle.hf_evals import receipt_token, verify_receipt_token, verify_eval_results_entry
from proofbundle.policy import evaluate_policy
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

_IAT = 1_780_000_000
_AUD = "v.example"
_NONCE = "n-123"


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _eval_claim(issuer_fp: str) -> dict:
    claim, _ = build_eval_claim(suite="safety", suite_version="1", metric="acc", comparator=">=",
                               threshold="0.8", score="0.9", n=100, model_id="m", dataset_id="d",
                               issuer=issuer_fp, timestamp="2026-07-09T10:00:00Z",
                               assurance_level="reproduced")
    return claim


def _attack_bundle():
    """Payload signed by K_bundle; SD-JWT (cnf + KB-JWT) signed by K_issuer != K_bundle; the eval-claim's
    `issuer` field names K_issuer. Same merkle root (same payload, no prior leaves), so sd-jwt-bundle-binding
    and sd-jwt-issuer-identity both pass — but the bundle signer is NOT the SD-JWT signer."""
    k_bundle, k_issuer, holder = generate_signer(), generate_signer(), generate_signer()
    claim = _eval_claim(issuer_fingerprint(k_issuer))
    issuer_receipt = emit_eval_receipt(claim, k_issuer)          # payload carries issuer == fingerprint(k_issuer)
    payload_bytes = base64.b64decode(issuer_receipt["payload_b64"])
    real_root = (issuer_receipt.get("merkle") or {}).get("root_b64")
    compact = issue_sd_jwt(json.loads(payload_bytes), k_issuer, root_b64=real_root, exact_score="0.9",
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw_pub(k_issuer)).decode("ascii")}
    # Re-sign the SAME payload bytes with K_bundle: same merkle root, but signature.public_key_b64 = K_bundle.
    bundle = emit_bundle(payload_bytes, k_bundle, sd_jwt_vc=vc)
    issuer_pin = "ed25519:" + base64.b64encode(_raw_pub(k_issuer)).decode("ascii")
    return bundle, issuer_pin


def _control_bundle():
    """Honest eval receipt: ONE key signs both the bundle and the SD-JWT -> binding path trusts it."""
    signer, holder = generate_signer(), generate_signer()
    claim = _eval_claim("placeholder")                           # emit overwrites issuer with fingerprint(signer)
    plain = emit_eval_receipt(claim, signer)
    real_root = (plain.get("merkle") or {}).get("root_b64")
    compact = issue_sd_jwt(json.loads(base64.b64decode(plain["payload_b64"])), signer, root_b64=real_root,
                           exact_score="0.9", holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw_pub(signer)).decode("ascii")}
    return emit_eval_receipt(claim, signer, sd_jwt=vc)


def _check(result):
    """(crypto_ok, kb_positive): kb_positive is True only when a key-binding verdict was reported AND the
    issuer was trusted (sd-jwt-issuer-trust not False)."""
    kb = next((c.ok for c in result.checks if c.name == "sd-jwt-key-binding"), None)
    trust = next((c.ok for c in result.checks if c.name == "sd-jwt-issuer-trust"), None)
    return result.ok, (kb is True and trust is not False)


def _trust_ok(result):
    return next((c.ok for c in result.checks if c.name == "sd-jwt-issuer-trust"), None)


def _cli_json(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(args)
    try:
        return rc, json.loads(buf.getvalue())
    except json.JSONDecodeError:
        return rc, {}


def _write(obj):
    p = tempfile.mktemp(suffix=".json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return p


# --- surface 1: verify_bundle(expected_aud, expected_nonce) -------------------------------------------------------
class VerifyBundleAudNonce(unittest.TestCase):
    def test_sdjwt_signer_not_bundle_signer_fails_closed(self):
        bundle, _pin = _attack_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE))
        self.assertFalse(crypto_ok)
        self.assertFalse(positive)
        self.assertIs(_trust_ok(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)), False)

    def test_same_key_control_passes(self):
        crypto_ok, positive = _check(verify_bundle(_control_bundle(), expected_aud=_AUD, expected_nonce=_NONCE))
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)

    def test_a_pin_on_the_sdjwt_key_still_trusts_it(self):
        # the pin path is an explicit out-of-band anchor, unchanged by Nachtrag 44 (which fixes only the
        # payload-binding path): a relying party that pins the SD-JWT issuer key trusts it even though it is
        # not the bundle signer.
        bundle, pin = _attack_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE,
                                                   sd_jwt_issuer_key_pin=pin))
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)


# --- surface 2: the holder binding WITHOUT aud/nonce (key_binding_ok itself must be gated) ------------------------
class HolderBindingWithoutAudNonce(unittest.TestCase):
    def test_sdjwt_signer_not_bundle_signer_fails_closed(self):
        bundle, _pin = _attack_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle))
        self.assertFalse(crypto_ok)
        self.assertFalse(positive)

    def test_same_key_control_passes(self):
        crypto_ok, positive = _check(verify_bundle(_control_bundle()))
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)


# --- surface 3: CLI verify --aud/--nonce (JSON field contract + exit code) ----------------------------------------
class CliVerifyAudNonce(unittest.TestCase):
    def test_attack_fails_closed(self):
        bundle, _pin = _attack_bundle()
        rc, j = _cli_json(["verify", _write(bundle), "--aud", _AUD, "--nonce", _NONCE, "--json"])
        self.assertNotEqual(rc, 0)
        for field in ("ok", "key_binding_ok", "audience_ok", "nonce_ok"):
            self.assertIsNot(j.get(field), True, f"{field} must not read positive")

    def test_control_passes(self):
        rc, j = _cli_json(["verify", _write(_control_bundle()), "--aud", _AUD, "--nonce", _NONCE, "--json"])
        self.assertEqual(rc, 0)
        self.assertIs(j.get("ok"), True)
        self.assertIs(j.get("audience_ok"), True)
        self.assertIs(j.get("nonce_ok"), True)

    def test_policy_pin_on_the_sdjwt_key_still_trusts_it(self):
        bundle, pin = _attack_bundle()
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n44",
                  "sd_jwt": {"issuer_key_pin": pin}}
        rc, j = _cli_json(["verify", _write(bundle), "--aud", _AUD, "--nonce", _NONCE,
                           "--policy", _write(policy), "--json"])
        self.assertEqual(rc, 0, f"a policy pinning the SD-JWT key must verify; got {j.get('error')}")
        self.assertIs(j.get("audience_ok"), True)


# --- surface 4: hf_evals receipt token (verify_receipt_token) ----------------------------------------------------
class HfReceiptToken(unittest.TestCase):
    def test_attack_fails_closed(self):
        bundle, _pin = _attack_bundle()
        result, _b = verify_receipt_token(receipt_token(bundle))
        crypto_ok, positive = _check(result)
        self.assertFalse(crypto_ok)
        self.assertFalse(positive)

    def test_control_passes(self):
        result, _b = verify_receipt_token(receipt_token(_control_bundle()))
        crypto_ok, positive = _check(result)
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)

    def test_pin_on_the_sdjwt_key_still_trusts_it(self):
        bundle, pin = _attack_bundle()
        result, _b = verify_receipt_token(receipt_token(bundle), sd_jwt_issuer_key_pin=pin)
        crypto_ok, positive = _check(result)
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)


# --- surface 5: hf_evals eval_results entry (verify_eval_results_entry) ------------------------------------------
class HfEvalResultsEntry(unittest.TestCase):
    def test_attack_fails_closed(self):
        bundle, _pin = _attack_bundle()
        out = verify_eval_results_entry({"verifyToken": receipt_token(bundle), "value": 0.9})
        self.assertFalse(out["ok"])
        self.assertFalse(out["crypto_ok"])

    def test_control_passes(self):
        out = verify_eval_results_entry({"verifyToken": receipt_token(_control_bundle()), "value": 0.9})
        self.assertTrue(out["crypto_ok"])
        self.assertTrue(out["ok"])

    def test_pin_restores_crypto_trust_claim_binding_stays_separate(self):
        # The SD-JWT issuer pin restores the token's crypto/KB issuer trust (crypto_ok True). The entry's overall
        # ok ALSO needs value<->claim consistency via decode_eval_claim, which binds the eval-claim's issuer to the
        # BUNDLE signer; the attack bundle names a different issuer, so value_consistent / ok stay False even under
        # a correct SD-JWT pin (an orthogonal, correct refusal). The honest end-to-end positive is the same-key
        # control above.
        bundle, pin = _attack_bundle()
        out = verify_eval_results_entry({"verifyToken": receipt_token(bundle), "value": 0.9},
                                        sd_jwt_issuer_key_pin=pin)
        self.assertTrue(out["crypto_ok"])
        self.assertFalse(out["ok"])


# --- surface 6: the trust-policy path (evaluate_policy -> _sd_jwt_issuer_trusted) --------------------------------
class PolicyPath(unittest.TestCase):
    _POLICY = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n44",
               "sd_jwt": {"require_key_binding_when_cnf_present": True}}

    def _policy_ok(self, bundle):
        result = verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)
        return evaluate_policy(bundle, result, self._POLICY).get("policy_ok")

    def test_attack_policy_not_ok(self):
        # verify_bundle already fails sd-jwt-issuer-trust (SD-JWT signer != bundle signer), so the policy's crypto
        # gate does not pass and the verdict is not positive. (The policy layer also threads the same gate via
        # _sd_jwt_issuer_trusted(bundle_signer_pub=...), defence in depth.)
        bundle, _pin = _attack_bundle()
        self.assertIsNot(self._policy_ok(bundle), True)

    def test_control_policy_ok(self):
        self.assertIs(self._policy_ok(_control_bundle()), True)


# --- the asymmetry the finding names: verify_bundle must not accept what decode_eval_claim rejects ---------------
class VerifyBundleAgreesWithDecodeEvalClaim(unittest.TestCase):
    def test_attack_rejected_by_both(self):
        bundle, _pin = _attack_bundle()
        # decode_eval_claim already rejects it (claim.issuer != bundle signer)
        self.assertIsNone(decode_eval_claim(bundle))
        # verify_bundle's binding path now agrees: not a positive KB-JWT verdict
        self.assertIs(_trust_ok(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)), False)

    def test_control_accepted_by_both(self):
        bundle = _control_bundle()
        self.assertIsNotNone(decode_eval_claim(bundle))
        self.assertIsNot(_trust_ok(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)), False)


if __name__ == "__main__":
    unittest.main()
