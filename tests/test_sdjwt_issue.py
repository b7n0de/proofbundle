"""SD-JWT issuance (v0.5, RFC 9901) — own verifier + reference interop + red-tests. No-Fake."""
import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import (
    _make_disclosure,
    check_binds_bundle,
    issue_sd_jwt,
)

FX = Path(__file__).resolve().parent / "fixtures"
TS = "2026-07-01T12:00:00Z"
ROOT_B64 = "cm9vdA=="


def _claim(signer):
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
        threshold="0.65", score="0.92", n=500, model_id="acme/model-x", dataset_id="acme/set",
        issuer=issuer_fingerprint(signer), timestamp=TS, model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


def _raw_pub(signer):
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class TestSdJwtIssue(unittest.TestCase):
    def test_own_verifier_accepts(self):
        signer = generate_signer()
        compact = issue_sd_jwt(_claim(signer), signer, root_b64=ROOT_B64, exact_score="0.92", ci95=["0.90", "0.94"])
        res = verify_sd_jwt(compact, _raw_pub(signer))
        self.assertTrue(res["structure_ok"], res)
        self.assertTrue(res["sig_ok"], res)

    def test_reference_verifier_accepts(self):
        try:
            from jwcrypto.jwk import JWK
            from sd_jwt.verifier import SDJWTVerifier
        except ImportError:
            self.skipTest("sd-jwt-python not installed (dev extra)")
        signer = generate_signer()
        compact = issue_sd_jwt(_claim(signer), signer, root_b64=ROOT_B64, exact_score="0.92")
        jwk = JWK(kty="OKP", crv="Ed25519", x=base64.urlsafe_b64encode(_raw_pub(signer)).rstrip(b"=").decode())
        payload = SDJWTVerifier(compact, lambda *_a, **_k: jwk).get_verified_payload()
        self.assertEqual(payload["passed"], True)          # always-open
        self.assertEqual(payload["exact_score"], "0.92")   # selectively disclosed

    def test_digest_byte_chain_vector(self):
        # RFC 9901 §4.2.4.1: digest over the base64url-ENCODED disclosure string, not the JSON bytes.
        v = json.loads((FX / "sdjwt_disclosure_vector.json").read_text(encoding="utf-8"))
        d_b64, dig = _make_disclosure(v["name"], v["value"], v["salt_b64url"])
        self.assertEqual(d_b64, v["disclosure_b64url"])
        self.assertEqual(dig, v["expected_digest_b64url"])

    def test_always_open_vs_selective(self):
        signer = generate_signer()
        compact = issue_sd_jwt(_claim(signer), signer, root_b64=ROOT_B64, exact_score="0.92")
        jwt_payload = json.loads(base64.urlsafe_b64decode(
            compact.split("~")[0].split(".")[1] + "==").decode("utf-8"))
        # passed/threshold are plaintext; exact_score is NOT (only its digest is in _sd)
        self.assertEqual(jwt_payload["passed"], True)
        self.assertIn("threshold", jwt_payload)
        self.assertNotIn("exact_score", jwt_payload)
        self.assertIn("_sd", jwt_payload)

    def test_binds_bundle(self):
        signer = generate_signer()
        claim = _claim(signer)
        compact = issue_sd_jwt(claim, signer, root_b64=ROOT_B64, exact_score="0.92")
        self.assertTrue(check_binds_bundle(compact, claim, ROOT_B64))

    def test_divergence_red(self):  # SD-JWT claims diverge from bundle → rejected
        signer = generate_signer()
        claim = _claim(signer)
        compact = issue_sd_jwt(claim, signer, root_b64=ROOT_B64, exact_score="0.92")
        diverged = dict(claim, passed=False)            # bundle says passed=False, SD-JWT says True
        self.assertFalse(check_binds_bundle(compact, diverged, ROOT_B64))
        self.assertFalse(check_binds_bundle(compact, claim, "d3Jvbmc="))   # wrong root

    def test_tamper_disclosure_red(self):  # tampered disclosure → digest mismatch → own verifier fails
        signer = generate_signer()
        compact = issue_sd_jwt(_claim(signer), signer, root_b64=ROOT_B64, exact_score="0.92")
        jwt, *disc = compact.rstrip("~").split("~")
        tampered_d, _ = _make_disclosure("exact_score", "0.99", "AAAAAAAAAAAAAAAAAAAAAA")  # not committed in _sd
        tampered = "~".join([jwt, tampered_d]) + "~"
        res = verify_sd_jwt(tampered, _raw_pub(signer))
        self.assertFalse(res.get("structure_ok") and res.get("sig_ok") and "1 disclosure" in res.get("detail", ""))


if __name__ == "__main__":
    unittest.main()
