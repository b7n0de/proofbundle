"""WP-C1/C2 — the verify PATH binds an sd_jwt_vc to its bundle and refuses unauthenticated disclosures.

check_binds_bundle is unit-tested in test_sdjwt_issue.py; here we test that verify_bundle actually WIRES
it (C-1) and that an unsigned sd_jwt_vc fails crypto (C-2). Effect-grounded: we run the real CLI verify
and assert the exit code, the named check, its reason string, and the derived sd_jwt_ok summary field.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

_IAT = 1_780_000_000


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _eval_bundle_with_sd_jwt(*, bind_root: bool, signed: bool):
    """An eval-claim bundle carrying an sd_jwt_vc. ``bind_root`` commits the SD-JWT to THIS bundle's
    merkle root (bound) or to a wrong root (unbound); ``signed`` supplies the issuer key or not."""
    signer = generate_signer()
    holder = generate_signer()
    ev_claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
    # Ed25519 is deterministic (RFC 8032) → re-emitting the same payload yields the same merkle root.
    plain = emit_eval_receipt(ev_claim, signer)
    real_root = (plain.get("merkle") or {}).get("root_b64")
    payload_claim = json.loads(base64.b64decode(plain["payload_b64"]))
    sd_claim = {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "safety",
                "issuer": payload_claim["issuer"]}
    commit_root = real_root if bind_root else "d3Jvbmc="   # "wrong"
    compact = issue_sd_jwt(sd_claim, signer, root_b64=commit_root, exact_score="0.9",
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud="v.example", nonce="n", iat=_IAT)
    vc = {"compact": presented}
    if signed:
        vc["issuer_public_key_b64"] = base64.b64encode(_raw_pub(signer)).decode("ascii")
    bundle = emit_eval_receipt(ev_claim, signer, sd_jwt=vc)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _verify_json(path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(["verify", "--json", path])
    return rc, json.loads(out.getvalue())


class TestSdJwtVerifyBinding(unittest.TestCase):
    def _checks(self, data):
        return {c["name"]: c for c in data["checks"]}

    def test_signed_and_bound_passes(self):   # C-1 positive control
        path = _eval_bundle_with_sd_jwt(bind_root=True, signed=True)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        checks = self._checks(data)
        self.assertTrue(checks["sd-jwt-bundle-binding"]["ok"])
        self.assertTrue(data["sd_jwt_ok"])

    def test_signed_but_unbound_fails_with_reason(self):   # C-1: cross-receipt substitution
        path = _eval_bundle_with_sd_jwt(bind_root=False, signed=True)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)                                # crypto fail, not a pass-with-warning
        checks = self._checks(data)
        self.assertTrue(checks["sd-jwt-issuer-signature"]["ok"])   # signature IS valid…
        self.assertFalse(checks["sd-jwt-bundle-binding"]["ok"])    # …but it binds the wrong bundle
        self.assertIn("unbound", checks["sd-jwt-bundle-binding"]["detail"])
        self.assertFalse(data["sd_jwt_ok"])                    # summary must NOT read True (No-Fake, WP-C1)

    def test_unsigned_fails_with_reason(self):   # C-2: unauthenticated disclosures
        path = _eval_bundle_with_sd_jwt(bind_root=True, signed=False)
        try:
            rc, data = _verify_json(path)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)
        checks = self._checks(data)
        self.assertFalse(checks["sd-jwt-issuer-signature"]["ok"])
        self.assertIn("unsigned", checks["sd-jwt-issuer-signature"]["detail"])
        self.assertFalse(data["sd_jwt_ok"])
        self.assertFalse(data["sd_jwt_issuer_verified"])


if __name__ == "__main__":
    unittest.main()
