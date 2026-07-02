"""promptfoo results.json adapter — green fixture roundtrip + red matrix (v1.4).

Fixture: tests/fixtures/promptfoo_results_v3.json — a minimal OutputFile matching the shape of
promptfoo main (2026-07): summary version 3, stats.successes/failures/errors, per-result
provider ids, config.tests. Field names verified against src/types/index.ts.
"""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from proofbundle import generate_signer, verify_bundle
from proofbundle.adapters import from_promptfoo_results
from proofbundle.evalclaim import emit_eval_receipt

FIXTURE = Path(__file__).parent / "fixtures" / "promptfoo_results_v3.json"
KW = {"comparator": ">=", "threshold": "0.600000", "timestamp": "2026-07-02T14:04:00Z"}


def _write(data) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, handle)
    handle.close()
    return handle.name


class TestPromptfooAdapter(unittest.TestCase):
    def test_green_fixture_to_verified_receipt(self):
        # Data minimization: the exact score never ships in the claim — it only feeds `passed`.
        claim, salts = from_promptfoo_results(FIXTURE, **KW)
        self.assertEqual(claim["metric"], "pass_rate")
        self.assertNotIn("score", claim)
        self.assertTrue(claim["passed"])                        # 2/3 = 0.666667 >= 0.600000
        strict = from_promptfoo_results(FIXTURE, comparator=">=", threshold="0.700000",
                                        timestamp=KW["timestamp"])[0]
        self.assertFalse(strict["passed"])                      # 0.666667 < 0.700000
        self.assertEqual(claim["n"], 3)
        self.assertEqual(claim["suite"], "translation smoke test")
        self.assertEqual(claim["provenance"]["eval_id"], "eval-Xa3-2026-07-02T14:03:11")
        self.assertEqual(claim["provenance"]["promptfoo_version"], "0.118.3")
        # both providers pinned into the model commitment input (sorted, deduped)
        self.assertNotIn("model_id", claim)                     # only the salted commitment ships
        self.assertIn("model_id_commit", claim)
        # a promptfoo claim is a normal receipt
        signer = generate_signer()
        bundle = emit_eval_receipt(claim, signer)
        self.assertTrue(verify_bundle(bundle).ok)

    def test_dataset_commitment_derives_from_tests(self):
        data = json.loads(FIXTURE.read_text())
        claim_a, _ = from_promptfoo_results(FIXTURE, **KW)
        data2 = copy.deepcopy(data)
        data2["config"]["tests"][0]["vars"]["input"] = "DIFFERENT"
        path = _write(data2)
        try:
            claim_b, _ = from_promptfoo_results(path, **KW)
        finally:
            os.unlink(path)
        self.assertNotEqual(claim_a["dataset_id_commit"], claim_b["dataset_id_commit"],
                            "changing the test suite must change the dataset commitment")

    def test_dataset_commitment_scope_is_honest(self):
        # HIGH (release review): inline tests bind content; a file:// reference binds only the reference —
        # provenance must state which, so the binding is never overstated. Fixture uses inline tests.
        claim_inline, _ = from_promptfoo_results(FIXTURE, **KW)
        self.assertEqual(claim_inline["provenance"]["dataset_commitment_scope"],
                         "config.tests_inline_content")
        self.assertEqual(claim_inline["provenance"]["pass_rate_formula"],
                         "successes/(successes+failures+errors)")
        data = json.loads(FIXTURE.read_text())
        data["config"]["tests"] = "file://tests.yaml"   # the documented file-reference pattern
        path = _write(data)
        try:
            claim_ref, _ = from_promptfoo_results(path, **KW)
        finally:
            os.unlink(path)
        self.assertEqual(claim_ref["provenance"]["dataset_commitment_scope"],
                         "config.tests_reference_only")

    def test_model_commitment_uses_observed_providers(self):
        # #6: a config-only provider that produced no result must not enter the commitment set. Fixed salt so
        # the commitments are comparable (same observed provider set → identical commit input → identical commit).
        salt = b"\x11" * 16
        data = json.loads(FIXTURE.read_text())
        data.setdefault("config", {})["providers"] = ["openai:gpt-4o", "phantom:never-ran"]
        base, _ = from_promptfoo_results(FIXTURE, model_salt=salt, **KW)
        path = _write(data)
        try:
            with_phantom, _ = from_promptfoo_results(path, model_salt=salt, **KW)
        finally:
            os.unlink(path)
        # the phantom provider changes config.providers but NOT the observed results → same commitment input
        self.assertEqual(base["model_id_commit"], with_phantom["model_id_commit"])

    def test_red_version_2_rejected_with_clear_message(self):
        data = json.loads(FIXTURE.read_text())
        data["results"]["version"] = 2
        path = _write(data)
        try:
            with self.assertRaises(ValueError) as ctx:
                from_promptfoo_results(path, **KW)
        finally:
            os.unlink(path)
        self.assertIn("version 2", str(ctx.exception))
        self.assertIn("version 3", str(ctx.exception))

    def test_red_missing_stats(self):
        data = json.loads(FIXTURE.read_text())
        del data["results"]["stats"]
        path = _write(data)
        try:
            with self.assertRaises(ValueError):
                from_promptfoo_results(path, **KW)
        finally:
            os.unlink(path)

    def test_red_zero_outcomes(self):
        data = json.loads(FIXTURE.read_text())
        data["results"]["stats"].update(successes=0, failures=0, errors=0)
        path = _write(data)
        try:
            with self.assertRaises(ValueError):
                from_promptfoo_results(path, **KW)
        finally:
            os.unlink(path)

    def test_red_negative_or_bool_counts(self):
        for bad in (-1, True):
            data = json.loads(FIXTURE.read_text())
            data["results"]["stats"]["failures"] = bad
            path = _write(data)
            try:
                with self.assertRaises(ValueError):
                    from_promptfoo_results(path, **KW)
            finally:
                os.unlink(path)

    def test_red_not_a_promptfoo_file(self):
        path = _write({"schema": "proofbundle/v0.1"})
        try:
            with self.assertRaises(ValueError):
                from_promptfoo_results(path, **KW)
        finally:
            os.unlink(path)

    def test_errors_count_toward_n_not_passes(self):
        data = json.loads(FIXTURE.read_text())
        data["results"]["stats"].update(successes=2, failures=0, errors=1)
        path = _write(data)
        try:
            claim, _ = from_promptfoo_results(path, **KW)
            strict, _ = from_promptfoo_results(path, comparator=">=", threshold="0.700000",
                                               timestamp=KW["timestamp"])
        finally:
            os.unlink(path)
        self.assertTrue(claim["passed"])                        # 2/3 vs 0.6 — errors NOT successes
        self.assertFalse(strict["passed"])                      # 2/3 < 0.7 proves errors count in n
        self.assertEqual(claim["n"], 3)


if __name__ == "__main__":
    unittest.main()
