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

    def test_inspect_ai_stable_api(self):
        # Real .eval log fixture, read via the stable inspect_ai.log.read_eval_log API (proofbundle[inspect]).
        try:
            import inspect_ai.log  # noqa: F401
        except ImportError:
            self.skipTest("inspect_ai not installed (pip install proofbundle[inspect])")
        claim, salts = from_inspect_ai_log(FX / "inspect_logs" / "safety_refusal_demo.eval", "accuracy",
                                           comparator=">=", threshold="0.00", timestamp=TS,
                                           model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.assertEqual(claim["suite"], "safety_refusal_demo")
        self.assertTrue(claim["passed"])                    # accuracy 0.0 >= 0.00
        self.assertNotIn("mockllm/model", str(claim))       # model id only as salted commitment

    def test_inspect_ai_missing_metric_clear_error(self):
        from proofbundle.adapters.inspect_ai import InspectAdapterError
        try:
            import inspect_ai.log  # noqa: F401
        except ImportError:
            self.skipTest("inspect_ai not installed")
        with self.assertRaises(InspectAdapterError):
            from_inspect_ai_log(FX / "inspect_logs" / "safety_refusal_demo.eval", "nonexistent_metric",
                                comparator=">=", threshold="0.5", timestamp=TS,
                                model_salt=b"0" * 16, dataset_salt=b"1" * 16)


if __name__ == "__main__":
    unittest.main()
