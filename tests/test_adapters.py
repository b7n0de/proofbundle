"""Adapters map real exported eval JSON to a valid claim (file-based, no framework import)."""
import unittest
from pathlib import Path

from proofbundle.adapters import from_inspect_ai_log, from_lm_eval_results

FX = Path(__file__).resolve().parent / "fixtures"
TS = "2026-07-01T12:00:00Z"


class TestAdapters(unittest.TestCase):
    def test_lm_eval(self):
        claim, salts = from_lm_eval_results(FX / "lm_eval_results.json", "hellaswag", "acc",
                                            comparator=">=", threshold="0.70", timestamp=TS,
                                            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.assertEqual(claim["suite"], "hellaswag")
        self.assertEqual(claim["threshold"], "0.70")
        self.assertTrue(claim["passed"])              # 0.7534 >= 0.70
        self.assertNotIn("acme/model-x", str(claim))  # id only as salted commitment
        self.assertEqual(claim["n"], 10042)

    def test_inspect_ai(self):
        claim, salts = from_inspect_ai_log(FX / "inspect_ai_log.json", "accuracy",
                                           comparator=">=", threshold="0.80", timestamp=TS,
                                           model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.assertEqual(claim["suite"], "safety_refusal")
        self.assertTrue(claim["passed"])              # 0.92 >= 0.80
        self.assertEqual(claim["n"], 500)


if __name__ == "__main__":
    unittest.main()
