"""v1.8 provenance hardening: config-hash + run-id + log-native timestamp in adapters."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from proofbundle.adapters._provenance import add_provenance, config_hash
from proofbundle.adapters import from_lm_eval_results, from_promptfoo_results

FIXTURES = Path(__file__).parent / "fixtures"


class TestConfigHash(unittest.TestCase):
    def test_deterministic_and_labeled(self):
        a = config_hash({"b": 1, "a": 2})
        b = config_hash({"a": 2, "b": 1})            # key order must not matter
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("sha256-jcs:") or a.startswith("sha256-sortkeys:"))
        self.assertEqual(len(a.split(":")[1]), 64)

    def test_empty_is_none(self):
        self.assertIsNone(config_hash(None))
        self.assertIsNone(config_hash({}))
        self.assertIsNone(config_hash([]))

    def test_change_changes_hash(self):
        self.assertNotEqual(config_hash({"seed": 1}), config_hash({"seed": 2}))

    def test_add_provenance_skips_absent(self):
        prov = {}
        add_provenance(prov, run_id=None, config=None, log_timestamp=None)
        self.assertEqual(prov, {})
        add_provenance(prov, run_id="r1", config={"x": 1}, log_timestamp=123)
        self.assertEqual(prov["run_id"], "r1")
        self.assertEqual(prov["run_timestamp"], "123")
        self.assertIn("config_hash", prov)


class TestPromptfooProvenance(unittest.TestCase):
    def test_run_id_and_config_hash_present(self):
        claim, _ = from_promptfoo_results(
            FIXTURES / "promptfoo_results_v3.json", comparator=">=", threshold="0.5",
            timestamp="2026-07-02T00:00:00Z")
        prov = claim["provenance"]
        self.assertEqual(prov["run_id"], "eval-Xa3-2026-07-02T14:03:11")
        self.assertIn("config_hash", prov)
        self.assertIn("run_timestamp", prov)


class TestLmEvalProvenance(unittest.TestCase):
    def _fixture_with_config(self):
        data = json.loads((FIXTURES / "lm_eval_arc_easy_real.json").read_text())
        return data

    def test_config_hash_and_timestamp(self):
        data = self._fixture_with_config()
        data.setdefault("config", {"model": "hf", "seed": 1234})
        data["date"] = 1780000000.5
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(data, handle)
        handle.close()
        try:
            task = next(iter(data["results"]))
            metric = next(k.split(",")[0] for k in data["results"][task] if "," in k)
            claim, _ = from_lm_eval_results(handle.name, task=task, metric=metric,
                                            comparator=">=", threshold="0.1",
                                            timestamp="2026-07-02T00:00:00Z")
        finally:
            os.unlink(handle.name)
        prov = claim["provenance"]
        self.assertIn("config_hash", prov)
        self.assertEqual(prov["run_timestamp"], "1780000000.5")   # log-native, not caller ts


if __name__ == "__main__":
    unittest.main()
