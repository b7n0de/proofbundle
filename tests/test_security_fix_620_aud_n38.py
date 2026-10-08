"""Nachtrag 38 (Z309, 6.2.0 security fix): a KB-JWT verdict — holder binding, audience, nonce — is reported
positive only under a TRUSTED issuer, as a class, at the bundle.py level.

PR 311 review 5407950418, P1 "Gate direct audience and nonce checks on issuer trust". The Nachtrag 36 fix bound
the KB-JWT/SD-JWT *policy* checks to a trusted issuer, but the DIRECT paths bypassed it: ``verify_bundle`` with
``expected_aud``/``expected_nonce`` and ``verify --aud``/``--nonce`` without a policy accepted audience and nonce
under the artifact's own (attacker-chosen) ``sd_jwt_vc.issuer_public_key_b64`` — a self-signed generic SD-JWT with a
matching KB-JWT reported ``audience_ok``/``nonce_ok``/``key_binding_ok`` true, ``ok`` true, exit 0. The holder
binding itself (``key_binding_ok``) had the same gap even without ``--aud``/``--nonce``.

The fix moves the issuer-trust gate into ``verify_bundle`` (``_sd_jwt_issuer_is_trusted``), the shared successor of
the Nachtrag 36 policy helper, so the crypto verdict, the single-field contract (``key_binding_ok`` / ``audience_ok``
/ ``nonce_ok``) and the exit code all honour one rule. The issuer is trusted when the SD-JWT is bound to the signed
payload (an eval receipt) OR its key matches the relying party's pin (``sd_jwt.issuer_key_pin`` in a policy, or the
``verify_bundle`` ``sd_jwt_issuer_key_pin`` argument). Without an anchor, fail-closed.

Secure behaviour only, per surface (no attack rebuilds beyond the fail-closed cases):
  - no anchor (self-signed, no pin, not bound)  → fails
  - a pin that is a foreign key                 → fails
  - a pin equal to the verifying key            → passes
  - bound to the signed payload                 → passes

Red at e5b00d7d14587cf1299226f105103d1d1507804b for the direct surfaces (verify_bundle + CLI); green after. Catch
proof in scratchpad/n38/fang.
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
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.sdjwt_issue import _b64url, issue_sd_jwt, present_with_key_binding

_IAT = 1_780_000_000
_AUD = "v.example"
_NONCE = "n-123"
_FOREIGN_PIN = "ed25519:" + base64.b64encode(b"\x09" * 32).decode("ascii")


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign_generic_sd_jwt(signer, payload: dict) -> str:
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii"))) + "~"


def _generic_bundle():
    """A generic self-signed SD-JWT (iss/vct, a cnf holder key) with a KB-JWT, in a non-eval bundle: the issuer
    key is attacker-chosen and nothing pins it or binds it to the payload → untrusted. Returns (bundle, pub_b64)."""
    issuer, holder = generate_signer(), generate_signer()
    payload = {"iss": "https://issuer.example", "vct": "https://issuer.example/vct/v1", "iat": _IAT,
               "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(_raw_pub(holder))}}}
    compact = _sign_generic_sd_jwt(issuer, payload)
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    pub_b64 = base64.b64encode(_raw_pub(issuer)).decode("ascii")
    bundle = emit_bundle(b'{"generic":"vc"}', issuer,
                         sd_jwt_vc={"compact": presented, "issuer_public_key_b64": pub_b64})
    return bundle, pub_b64


def _bound_bundle():
    """An eval SD-JWT committed to THIS bundle's merkle root, with a KB-JWT → sd-jwt-bundle-binding passes, so the
    issuer is trusted via the payload binding (no pin needed)."""
    signer, holder = generate_signer(), generate_signer()
    ev_claim, _ = build_eval_claim(suite="safety", suite_version="1", metric="acc", comparator=">=",
                                   threshold="0.8", score="0.9", n=100, model_id="m", dataset_id="d",
                                   issuer="placeholder", timestamp="2026-07-09T10:00:00Z",
                                   assurance_level="reproduced")
    plain = emit_eval_receipt(ev_claim, signer)
    real_root = (plain.get("merkle") or {}).get("root_b64")
    sd_claim = json.loads(base64.b64decode(plain["payload_b64"]))
    compact = issue_sd_jwt(sd_claim, signer, root_b64=real_root, exact_score="0.9",
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    vc = {"compact": presented, "issuer_public_key_b64": base64.b64encode(_raw_pub(signer)).decode("ascii")}
    return emit_eval_receipt(ev_claim, signer, sd_jwt=vc)


def _check(result):
    """(crypto_ok, kb_positive): kb_positive is True only when a key-binding verdict was reported AND the issuer
    was trusted (sd-jwt-issuer-trust not False)."""
    kb = next((c.ok for c in result.checks if c.name == "sd-jwt-key-binding"), None)
    trust = next((c.ok for c in result.checks if c.name == "sd-jwt-issuer-trust"), None)
    return result.ok, (kb is True and trust is not False)


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


# --- surface 1: the verify_bundle library API (expected_aud / expected_nonce) -------------------------------------
class VerifyBundleAudNonce(unittest.TestCase):
    """verify_bundle(expected_aud=…, expected_nonce=…): the direct library surface the review names."""

    def test_untrusted_issuer_fails_closed(self):
        bundle, _pub = _generic_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE))
        self.assertFalse(crypto_ok)
        self.assertFalse(positive)

    def test_a_foreign_pin_fails_closed(self):
        bundle, _pub = _generic_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE,
                                                   sd_jwt_issuer_key_pin=_FOREIGN_PIN))
        self.assertFalse(crypto_ok)
        self.assertFalse(positive)

    def test_a_matching_pin_passes(self):
        bundle, pub = _generic_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE,
                                                   sd_jwt_issuer_key_pin="ed25519:" + pub))
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)

    def test_bound_to_the_signed_payload_passes(self):
        crypto_ok, positive = _check(verify_bundle(_bound_bundle(), expected_aud=_AUD, expected_nonce=_NONCE))
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)


# --- surface 2: the holder binding itself, WITHOUT --aud/--nonce (key_binding_ok must also be gated) --------------
class HolderBindingWithoutAudNonce(unittest.TestCase):
    def test_untrusted_issuer_holder_binding_fails_closed(self):
        bundle, _pub = _generic_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle))
        self.assertFalse(crypto_ok, "a KB-JWT under an untrusted issuer must not read key_binding_ok positive")
        self.assertFalse(positive)

    def test_a_matching_pin_passes(self):
        bundle, pub = _generic_bundle()
        crypto_ok, positive = _check(verify_bundle(bundle, sd_jwt_issuer_key_pin="ed25519:" + pub))
        self.assertTrue(crypto_ok)
        self.assertTrue(positive)


# --- surface 3: the CLI verify --aud/--nonce (JSON field contract + exit code) ------------------------------------
class CliVerifyAudNonce(unittest.TestCase):
    def test_untrusted_no_policy_fails_closed(self):
        bundle, _pub = _generic_bundle()
        rc, j = _cli_json(["verify", _write(bundle), "--aud", _AUD, "--nonce", _NONCE, "--json"])
        self.assertNotEqual(rc, 0, "exit must be non-zero")
        self.assertIsNot(j.get("ok"), True)
        self.assertIsNot(j.get("audience_ok"), True)
        self.assertIsNot(j.get("nonce_ok"), True)
        self.assertIsNot(j.get("key_binding_ok"), True)

    def test_bound_passes(self):
        rc, j = _cli_json(["verify", _write(_bound_bundle()), "--aud", _AUD, "--nonce", _NONCE, "--json"])
        self.assertEqual(rc, 0)
        self.assertIs(j.get("ok"), True)
        self.assertIs(j.get("audience_ok"), True)
        self.assertIs(j.get("nonce_ok"), True)

    def test_policy_matching_pin_passes(self):
        bundle, pub = _generic_bundle()
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n38", "sd_jwt": {"issuer_key_pin": "ed25519:" + pub}}
        rc, j = _cli_json(["verify", _write(bundle), "--aud", _AUD, "--nonce", _NONCE,
                           "--policy", _write(policy), "--json"])
        self.assertEqual(rc, 0, f"a policy pinning the verifying key must verify; got {j.get('error')}")
        self.assertIs(j.get("audience_ok"), True)
        self.assertIs(j.get("nonce_ok"), True)

    def test_policy_foreign_pin_fails_closed(self):
        bundle, _pub = _generic_bundle()
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "n38", "sd_jwt": {"issuer_key_pin": _FOREIGN_PIN}}
        rc, j = _cli_json(["verify", _write(bundle), "--aud", _AUD, "--nonce", _NONCE,
                           "--policy", _write(policy), "--json"])
        self.assertNotEqual(rc, 0)
        self.assertIsNot(j.get("audience_ok"), True)


# --- the class is held closed: a positive KB-JWT verdict never reads true without issuer trust --------------------
class TheClassIsHeldClosed(unittest.TestCase):
    def test_every_direct_surface_fails_closed_under_an_untrusted_issuer(self):
        """One place, every surface: a self-signed KB-JWT presentation is never reported positive. Goes red if any
        direct surface regains a positive KB verdict without issuer trust."""
        bundle, _pub = _generic_bundle()
        # library, with and without the requested aud/nonce binding
        for result in (verify_bundle(bundle),
                       verify_bundle(bundle, expected_aud=_AUD, expected_nonce=_NONCE)):
            crypto_ok, positive = _check(result)
            self.assertFalse(crypto_ok)
            self.assertFalse(positive)
            self.assertIs(next((c.ok for c in result.checks if c.name == "sd-jwt-issuer-trust"), None), False)
        # CLI
        rc, j = _cli_json(["verify", _write(bundle), "--aud", _AUD, "--nonce", _NONCE, "--json"])
        self.assertNotEqual(rc, 0)
        for field in ("ok", "key_binding_ok", "audience_ok", "nonce_ok"):
            self.assertIsNot(j.get(field), True, f"{field} must not read positive under an untrusted issuer")


if __name__ == "__main__":
    unittest.main()
