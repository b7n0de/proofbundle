"""WP-I1 — predicateType enforcement on the in-toto verify paths (predicate-confusion defense).

Before this: `verify_eval_result_dsse` / `verify_svr_dsse` / `verify_intoto_dsse` only RETURNED the
statement's `predicateType`; they never checked it. So a validly-signed envelope of ONE predicate
type verified `ok=True` through the verify function of ANOTHER — a swapped SVR accepted as an
eval-result, a test-result accepted as an SVR, etc. (The decision-receipt layer already enforced
its type; the eval/SVR/test-result layer did not.) Now each verify function pins its own type by
default, `ok=False` on a foreign type, with a clear "confusion attack?" detail.

The cross-matrix below signs a genuine envelope of every emitted type and runs it through every
verify function: only the diagonal (matching type) verifies; every off-diagonal cell is `ok=False`.
"""
import unittest

from proofbundle import generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.intoto import (
    EVAL_RESULT_PREDICATE_TYPE, SVR_PREDICATE_TYPE, TEST_RESULT_PREDICATE_TYPE,
    export_eval_result_dsse, export_intoto_dsse, export_svr_dsse,
    verify_eval_result_dsse, verify_intoto_dsse, verify_svr_dsse,
)


def _claim():
    claim, _ = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.5",
        score="0.9", n=10, model_id="m", dataset_id="d", issuer="", timestamp="2026-07-11T00:00:00Z")
    return claim


class TestCrossPredicateMatrix(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        claim = _claim()
        receipt = emit_eval_receipt(claim, self.signer)
        # three genuinely-signed envelopes, one per emitted in-toto predicate type
        self.envelopes = {
            EVAL_RESULT_PREDICATE_TYPE: export_eval_result_dsse(claim, self.signer),
            TEST_RESULT_PREDICATE_TYPE: export_intoto_dsse(claim, self.signer),
            SVR_PREDICATE_TYPE: export_svr_dsse(receipt, self.signer),
        }
        self.verifiers = {
            EVAL_RESULT_PREDICATE_TYPE: verify_eval_result_dsse,
            TEST_RESULT_PREDICATE_TYPE: verify_intoto_dsse,
            SVR_PREDICATE_TYPE: verify_svr_dsse,
        }

    def test_only_the_matching_type_verifies(self):
        for env_type, envelope in self.envelopes.items():
            for verify_type, verify_fn in self.verifiers.items():
                res = verify_fn(envelope, self.pub)
                if env_type == verify_type:
                    self.assertTrue(res["ok"], f"{env_type} must verify under its own function")
                    self.assertTrue(res["predicate_type_ok"])
                else:
                    self.assertFalse(
                        res["ok"],
                        f"CONFUSION: a {env_type} envelope verified ok=True under the "
                        f"{verify_type} verifier")
                    self.assertFalse(res["predicate_type_ok"])
                    self.assertIn("confusion attack", res["content_root_detail"])

    def test_diagonal_reports_type_ok_true(self):
        for t, envelope in self.envelopes.items():
            res = self.verifiers[t](envelope, self.pub)
            self.assertEqual(res["predicate_type"], t)
            self.assertIs(res["predicate_type_ok"], True)


class TestExplicitExpectedType(unittest.TestCase):
    def test_explicit_expected_type_pins_a_specific_value(self):
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        env = export_eval_result_dsse(_claim(), signer)
        # pin the SVR type against an eval-result envelope → mismatch
        res = verify_eval_result_dsse(env, pub, expected_predicate_type=SVR_PREDICATE_TYPE)
        self.assertFalse(res["ok"])
        self.assertFalse(res["predicate_type_ok"])

    def test_opt_out_restores_legacy_return_only_behavior(self):
        # expected_predicate_type=None → the type is REPORTED, not enforced (ok ignores it).
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        env = export_svr_dsse(emit_eval_receipt(_claim(), signer), signer)
        res = verify_eval_result_dsse(env, pub, expected_predicate_type=None)
        self.assertIsNone(res["predicate_type_ok"])
        self.assertTrue(res["ok"], "opt-out: an SVR verifies under eval-result when type check is off")
        self.assertEqual(res["predicate_type"], SVR_PREDICATE_TYPE)

    def test_wrong_signature_still_fails_even_with_matching_type(self):
        signer = generate_signer()
        other = generate_signer().public_key().public_bytes_raw()
        env = export_eval_result_dsse(_claim(), signer)
        res = verify_eval_result_dsse(env, other)   # right type, wrong key
        self.assertFalse(res["ok"])
        # type is fine; the signature is what fails — ok must still be False
        self.assertIs(res["predicate_type_ok"], True)


if __name__ == "__main__":
    unittest.main()
