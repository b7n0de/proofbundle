"""Adapters map real exported eval JSON to a valid claim (file-based, no framework import)."""
from copy import deepcopy
import json
import tempfile
import unittest
from pathlib import Path

from proofbundle.adapters import from_inspect_ai_log, from_lm_eval_results

FX = Path(__file__).resolve().parent / "fixtures"
TS = "2026-07-01T12:00:00Z"


class TestAdapters(unittest.TestCase):
    def test_lm_eval_real_acc_none_format(self):
        # REAL lm-evaluation-harness 0.4.12 export: metric key is "acc,none", stderr sibling "acc_stderr,none".
        claim, salts = from_lm_eval_results(FX / "lm_eval_arc_easy_real.json", "arc_easy", "acc",
                                            comparator=">=", threshold="0.30", timestamp=TS,
                                            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.assertEqual(claim["suite"], "arc_easy")
        self.assertTrue(claim["passed"])                       # acc 0.5 >= 0.30
        self.assertEqual(claim["provenance"]["matched_metric_key"], "acc,none")  # suffix handled
        self.assertIn("git_hash", claim["provenance"])         # provenance captured
        self.assertEqual(claim["provenance"]["n_shot"], "0")
        self.assertIn("stderr", claim["provenance"])           # sibling stderr, not nested
        self.assertEqual(claim["n"], 2)
        self.assertEqual(claim["provenance"]["effective_samples"], 2)
        self.assertEqual(claim["provenance"]["original_samples"], 2376)
        self.assertEqual(claim["provenance"]["skipped_samples"], 2374)

    def test_lm_eval_sample_drop_count_changes_signed_provenance(self):
        data = json.loads((FX / "lm_eval_arc_easy_real.json").read_text())
        changed = deepcopy(data)
        changed["n-samples"]["arc_easy"]["original"] = 3
        common = dict(task="arc_easy", metric="acc", comparator=">=", threshold="0.30",
                      timestamp=TS, model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        with tempfile.TemporaryDirectory() as raw:
            base_path = Path(raw) / "base.json"
            changed_path = Path(raw) / "changed.json"
            base_path.write_text(json.dumps(data))
            changed_path.write_text(json.dumps(changed))
            base_claim, _ = from_lm_eval_results(base_path, **common)
            changed_claim, _ = from_lm_eval_results(changed_path, **common)
        self.assertEqual(base_claim["n"], changed_claim["n"])
        self.assertNotEqual(base_claim["provenance"], changed_claim["provenance"])
        self.assertEqual(base_claim["provenance"]["skipped_samples"], 2374)
        self.assertEqual(changed_claim["provenance"]["skipped_samples"], 1)

    def test_lm_eval_missing_metric_lists_available(self):
        with self.assertRaises(ValueError):
            from_lm_eval_results(FX / "lm_eval_arc_easy_real.json", "arc_easy", "nonexistent",
                                 comparator=">=", threshold="0.5", timestamp=TS,
                                 model_salt=b"0" * 16, dataset_salt=b"1" * 16)

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
        self.assertEqual(claim["provenance"]["harness"], "inspect_ai")  # provenance parity with lm-eval
        self.assertIn("harness_version", claim["provenance"])
        self.assertEqual(claim["provenance"]["scorer"], "includes")
        self.assertEqual(claim["provenance"]["scored_samples"], 2)
        self.assertEqual(claim["provenance"]["unscored_samples"], 0)

    def test_inspect_ai_uses_metric_scored_sample_count(self):
        try:
            from inspect_ai.log import read_eval_log
        except ImportError:
            self.skipTest("inspect_ai not installed")
        log = read_eval_log(str(FX / "inspect_logs" / "safety_refusal_demo.eval"), header_only=True)
        log = deepcopy(log)
        score = log.results.scores[0]
        score.scored_samples = 1
        score.unscored_samples = 1
        claim, _ = from_inspect_ai_log(log, "accuracy", comparator=">=", threshold="0.00",
                                       timestamp=TS, model_salt=b"0" * 16,
                                       dataset_salt=b"1" * 16)
        self.assertEqual(claim["n"], 1)
        self.assertEqual(claim["provenance"]["scored_samples"], 1)
        self.assertEqual(claim["provenance"]["unscored_samples"], 1)

    def test_inspect_ai_scorer_change_changes_signed_provenance(self):
        try:
            from inspect_ai.log import read_eval_log
        except ImportError:
            self.skipTest("inspect_ai not installed")
        log = read_eval_log(str(FX / "inspect_logs" / "safety_refusal_demo.eval"), header_only=True)
        changed = deepcopy(log)
        changed.results.scores[0].scorer = "model_graded_fact"
        changed.results.scores[0].params = {"model": "mockllm/judge", "rubric": "opaque"}
        common = dict(metric="accuracy", comparator=">=", threshold="0.00", timestamp=TS,
                      model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        base_claim, _ = from_inspect_ai_log(log, **common)
        changed_claim, _ = from_inspect_ai_log(changed, **common)
        self.assertNotEqual(base_claim["provenance"], changed_claim["provenance"])
        self.assertEqual(changed_claim["provenance"]["scorer"], "model_graded_fact")
        self.assertIn("scorer_params_hash", changed_claim["provenance"])

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
