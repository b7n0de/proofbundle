"""Adversarial No-Fake-PASS suite (v1.1): actively try to FORGE a passing receipt, and pin down exactly what
verify catches and what it structurally cannot. Each test documents the honest boundary — a green here means
the defence held OR the limitation is named, never a hidden false PASS.
"""
import base64
import json
import unittest

from proofbundle import verify_bundle
from proofbundle.evalclaim import (
    build_eval_claim, check_freshness, claim_warnings, decode_eval_claim, emit_eval_receipt,
    sd_jwt_hidden_count, verify_commitment,
)
from proofbundle.emit import generate_signer


def _receipt(score="0.99", threshold="0.80", prereg=None, assurance="self_attested", ts="2020-01-01T00:00:00Z"):
    signer = generate_signer()
    claim, salts = build_eval_claim(
        suite="mmlu", suite_version="1", metric="accuracy", comparator=">=", threshold=threshold,
        score=score, n=1000, model_id="secret-model", dataset_id="secret-data", issuer="",
        timestamp=ts, prereg_sha256=prereg, assurance_level=assurance)
    return emit_eval_receipt(claim, signer), salts


class TestAdversarial(unittest.TestCase):
    def test_a_invented_numbers_with_valid_signature_pass_is_expected(self):
        # A receipt binds AUTHORSHIP + INTEGRITY, not TRUTH. A signed but invented score verifies — this is
        # EXPECTED and documented. The honesty gate is the self_attested-without-prereg WARNING.
        bundle, _ = _receipt(score="0.99")
        self.assertTrue(verify_bundle(bundle).ok)                 # signature/integrity hold
        claim = decode_eval_claim(bundle)
        self.assertIsNotNone(claim)
        self.assertTrue(claim["passed"])                          # invented pass, cryptographically fine
        self.assertTrue(claim_warnings(claim), "self_attested+no-prereg MUST warn")   # the honest counter

    def test_a_prereg_or_higher_assurance_removes_the_warning(self):
        self.assertFalse(claim_warnings(decode_eval_claim(_receipt(prereg="a" * 64)[0])))
        self.assertFalse(claim_warnings(decode_eval_claim(_receipt(assurance="reproduced")[0])))

    def test_b_tampered_payload_fails(self):
        bundle, _ = _receipt()
        tampered = json.loads(json.dumps(bundle))
        payload = json.loads(base64.b64decode(tampered["payload_b64"]))
        payload["passed"] = True
        payload["threshold"] = "0.10"                             # forge an easier bar
        tampered["payload_b64"] = base64.b64encode(
            json.dumps(payload).encode("utf-8")).decode("ascii")
        self.assertFalse(verify_bundle(tampered).ok)              # signature no longer matches
        self.assertIsNone(decode_eval_claim(tampered))

    def test_c_omitted_sd_jwt_fields_are_counted(self):
        # Selective disclosure hides claims behind _sd digests; the count makes OMISSION visible.
        hdr = base64.urlsafe_b64encode(b'{"alg":"ES256"}').decode().rstrip("=")
        pl = base64.urlsafe_b64encode(
            json.dumps({"_sd": ["d1", "d2", "d3"], "iss": "x"}).encode()).decode().rstrip("=")
        bundle = {"sd_jwt_vc": f"{hdr}.{pl}.sig~"}
        self.assertEqual(sd_jwt_hidden_count(bundle), 3)          # 3 withheld fields surfaced
        self.assertIsNone(sd_jwt_hidden_count({"schema": "x"}))   # no sd-jwt → None (nothing hidden)

    def test_d_model_swap_against_commitment_is_a_mismatch(self):
        bundle, salts = _receipt()
        claim = decode_eval_claim(bundle)
        self.assertTrue(verify_commitment("secret-model", salts["model_salt"], claim["model_id_commit"]))
        self.assertFalse(verify_commitment("swapped-model", salts["model_salt"], claim["model_id_commit"]))
        self.assertFalse(verify_commitment("secret-model", b"\x00" * 16, claim["model_id_commit"]))

    def test_e_replay_of_old_receipt_is_detectable(self):
        claim = decode_eval_claim(_receipt(ts="2020-01-01T00:00:00Z")[0])
        fresh = check_freshness(claim, max_age_seconds=3600)
        self.assertTrue(fresh["parsed"])
        self.assertFalse(fresh["fresh"])                          # years old → not fresh (replay/skew)
        self.assertGreater(fresh["age_seconds"], 3600)

    def test_f_honest_receipt_still_verifies_end_to_end(self):
        # The hardening must not break a legitimate receipt (guards against over-tightening).
        bundle, _ = _receipt(prereg="b" * 64, assurance="reproduced")
        self.assertTrue(verify_bundle(bundle).ok)
        self.assertIsNotNone(decode_eval_claim(bundle))


if __name__ == "__main__":
    unittest.main()
