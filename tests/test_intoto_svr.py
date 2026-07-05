"""in-toto SVR (Summary Verification Result, svr/v0.1) export — passing-only, real-verify-gated.
Paket 3 / test 11. SVR carries ONLY passing properties; there is no FAILED form (no SVR on FAIL)."""
import base64
import json
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.intoto import SVR_PREDICATE_TYPE, export_svr_dsse, verify_svr_dsse

_FIXED_SALT = b"\x11" * 16


def _receipt(signer, *, score: str, threshold: str = "0.98"):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
        comparator=">=", threshold=threshold, score=score, n=500,
        model_id="acme/secret-model", dataset_id="acme/secret-set",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-05T12:00:00Z",
        model_salt=_FIXED_SALT, dataset_salt=_FIXED_SALT)
    return emit_eval_receipt(claim, signer)


def _raw_pub(signer) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _statement(env) -> dict:
    return json.loads(base64.b64decode(env["payload"]))


class TestSVRPassingOnly(unittest.TestCase):
    def test_emits_for_a_passing_receipt_with_passing_properties(self):
        s = generate_signer()
        env = export_svr_dsse(_receipt(s, score="0.99"), s, time_created="2026-07-05T12:34:56Z")
        stmt = _statement(env)
        self.assertEqual(stmt["predicateType"], SVR_PREDICATE_TYPE)
        props = stmt["predicate"]["properties"]
        # only genuinely passing checks, type-generic prefix, no vendor/service name
        self.assertIn("PROOFBUNDLE_SIGNATURE_VALID", props)
        self.assertIn("PROOFBUNDLE_RECEIPT_UNCHANGED", props)
        self.assertIn("PROOFBUNDLE_THRESHOLD_MET", props)
        # no samples/prereg/anchor were verified → those properties are ABSENT (never placeholders)
        self.assertNotIn("PROOFBUNDLE_SAMPLE_ROOT_VALID", props)
        self.assertNotIn("PROOFBUNDLE_PREREG_BOUND", props)
        self.assertNotIn("PROOFBUNDLE_ANCHOR_VALID", props)
        self.assertEqual(stmt["predicate"]["timeCreated"], "2026-07-05T12:34:56Z")
        self.assertEqual(stmt["predicate"]["verifier"]["id"], "https://b7n0de.com/proofbundle")

    def test_no_svr_when_eval_did_not_pass(self):
        # Paket 3 test 11: a receipt whose eval FAILED the threshold gets NO SVR.
        s = generate_signer()
        failing = _receipt(s, score="0.50")   # 0.50 >= 0.98 is False → passed=False
        with self.assertRaises(BundleFormatError):
            export_svr_dsse(failing, s)

    def test_no_svr_when_receipt_does_not_verify(self):
        # A tampered receipt does not verify → NO SVR (SVR has no FAILED form).
        s = generate_signer()
        receipt = _receipt(s, score="0.99")
        receipt["payload_b64"] = base64.b64encode(b"tampered").decode()
        with self.assertRaises(BundleFormatError):
            export_svr_dsse(receipt, s)

    def test_no_svr_for_a_non_eval_bundle(self):
        s = generate_signer()
        with self.assertRaises(BundleFormatError):
            export_svr_dsse({"not": "an eval receipt"}, s)


class TestSVRShape(unittest.TestCase):
    def test_subject_is_the_receipt_digest(self):
        s = generate_signer()
        stmt = _statement(export_svr_dsse(_receipt(s, score="0.99"), s))
        self.assertEqual(stmt["subject"][0]["name"], "eval-receipt")
        self.assertEqual(len(stmt["subject"][0]["digest"]["sha256"]), 64)

    def test_policy_field_optional(self):
        s = generate_signer()
        env0 = export_svr_dsse(_receipt(s, score="0.99"), s)
        self.assertNotIn("policy", _statement(env0)["predicate"]["verifier"])
        env1 = export_svr_dsse(_receipt(s, score="0.99"), s,
                               policy={"uri": "https://b7n0de.com/proofbundle/verify",
                                       "digest": {"sha256": "ab" * 32}})
        self.assertEqual(_statement(env1)["predicate"]["verifier"]["policy"]["uri"],
                         "https://b7n0de.com/proofbundle/verify")

    def test_no_secret_in_svr(self):
        s = generate_signer()
        body = json.dumps(_statement(export_svr_dsse(_receipt(s, score="0.99"), s)))
        for forbidden in ("acme/secret-model", "acme/secret-set", "salt"):
            self.assertNotIn(forbidden, body)

    def test_sample_and_conditional_properties_are_earned_not_placeholders(self):
        # svr_properties emits a conditional property ONLY when its check genuinely holds.
        from proofbundle.errors import VerificationResult
        from proofbundle.intoto import svr_properties
        result = VerificationResult()
        result.add("ed25519-signature", True, "")
        result.add("merkle-inclusion", True, "")
        base = {"passed": True}
        self.assertNotIn("PROOFBUNDLE_SAMPLE_ROOT_VALID", svr_properties(result, base))
        with_samples = {"passed": True, "samples": {"root_b64": "x", "n": 5, "leaf_alg": "sha256"}}
        self.assertIn("PROOFBUNDLE_SAMPLE_ROOT_VALID", svr_properties(result, with_samples))
        # prereg/anchor only when the caller confirms a real offline verification happened
        with_prereg = {"passed": True, "prereg_sha256": "e5" * 32}
        self.assertNotIn("PROOFBUNDLE_PREREG_BOUND", svr_properties(result, with_prereg))
        self.assertIn("PROOFBUNDLE_PREREG_BOUND",
                      svr_properties(result, with_prereg, prereg_verified=True))
        self.assertIn("PROOFBUNDLE_ANCHOR_VALID",
                      svr_properties(result, base, anchor_verified=True))
        # a failing signature check → no SIGNATURE_VALID property
        bad = VerificationResult()
        bad.add("ed25519-signature", False, "")
        self.assertNotIn("PROOFBUNDLE_SIGNATURE_VALID", svr_properties(bad, base))


class TestSVRVerify(unittest.TestCase):
    def test_verify_roundtrip_and_tamper(self):
        s = generate_signer()
        env = export_svr_dsse(_receipt(s, score="0.99"), s)
        res = verify_svr_dsse(env, _raw_pub(s))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["predicate_type"], SVR_PREDICATE_TYPE)
        self.assertFalse(verify_svr_dsse(env, _raw_pub(generate_signer()))["ok"])
        tampered = dict(env)
        stmt = _statement(env)
        stmt["predicate"]["properties"].append("PROOFBUNDLE_ANCHOR_VALID")   # inject an unearned property
        tampered["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
        self.assertFalse(verify_svr_dsse(tampered, _raw_pub(s))["ok"])


if __name__ == "__main__":
    unittest.main()
