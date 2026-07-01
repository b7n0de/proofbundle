"""EEE→receipt converter (v0.9): field mapping, privacy (no plaintext model), levels, validation."""
import json
import unittest
from pathlib import Path

from proofbundle import verify_bundle
from proofbundle.adapters import from_eee_dataset
from proofbundle.adapters.eee import EEEAdapterError
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import decode_eval_claim, emit_eval_receipt

FX = Path(__file__).resolve().parent / "fixtures" / "eee_arc_easy.json"


class TestEEE(unittest.TestCase):
    def _claim(self, **kw):
        base = dict(comparator=">=", threshold="0.30", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        base.update(kw)
        claim, _ = from_eee_dataset(FX, **base)
        return claim

    def test_mapping(self):
        claim = self._claim()
        self.assertEqual(claim["suite"], "arc_easy")
        self.assertEqual(claim["metric"], "acc")
        self.assertTrue(claim["passed"])                       # 0.5567 >= 0.30
        self.assertEqual(claim["provenance"]["harness"], "lm-evaluation-harness")
        self.assertEqual(claim["provenance"]["stderr"], "0.0102")

    def test_no_plaintext_model_leak(self):
        # the model id (openai-community/gpt2) must never appear in cleartext — it is a salted commitment,
        # and the EEE evaluation_id (which embeds it) must NOT be copied into provenance.
        cj = json.dumps(self._claim())
        self.assertNotIn("gpt2", cj)
        self.assertNotIn("openai-community", cj)

    def test_roundtrip_verifies(self):
        b = emit_eval_receipt(self._claim(), generate_signer())
        self.assertTrue(verify_bundle(b).ok)
        self.assertTrue(decode_eval_claim(b)["passed"])

    def test_validate_true_on_clean_fixture(self):
        # validate=True must pass on the committed fixture (it is a real, schema-valid EEE 0.2.2 record)
        claim, _ = from_eee_dataset(FX, comparator=">=", threshold="0.30", validate=True)
        self.assertEqual(claim["suite"], "arc_easy")

    def test_levels_unknown_rejected(self):
        rec = json.loads(FX.read_text())
        rec["evaluation_results"][0]["metric_config"] = {
            "lower_is_better": False, "score_type": "levels", "level_names": ["a", "b"], "has_unknown_level": True}
        rec["evaluation_results"][0]["score_details"] = {"score": -1}
        with self.assertRaises(EEEAdapterError):
            from_eee_dataset(rec, comparator=">=", threshold="0", validate=False)

    def test_missing_model_id_clear_error(self):
        rec = json.loads(FX.read_text())
        rec["model_info"] = {"name": "x"}
        with self.assertRaises(EEEAdapterError):
            from_eee_dataset(rec, comparator=">=", threshold="0", validate=False)

    def test_uncertainty_null_no_crash(self):
        import json as _json
        rec = _json.loads(FX.read_text())
        rec["evaluation_results"][0]["score_details"] = {"score": 0.9, "uncertainty": None}
        claim, _ = from_eee_dataset(rec, comparator=">=", threshold="0.3", validate=False)
        self.assertTrue(claim["passed"])
        self.assertEqual(claim["n"], 0)
