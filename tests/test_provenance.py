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


class TestBenchmarkHackingVisibilityFields(unittest.TestCase):
    """Finding 17 (P17, additive VISIBILITY only — no anti-hacking guarantee is built or implied;
    see THREAT_MODEL.md / BenchJack arXiv:2605.12673): run_attempts/aborted_runs/methodology_sha256/
    benchjack_audit_report_sha256 are new, optional, well-known provenance sub-keys. Because
    `provenance` is already a free-form `"type": "object"` in the eval-claim schema (no
    additionalProperties:false, no nested `required`), these need NO schema change — the whole
    provenance dict is part of the signed claim payload, so anything placed in it is automatically
    tamper-evident (bidirectionally tested here + via the full claim round trip in
    test_evalclaim.py-style emit/decode elsewhere)."""

    def test_run_attempts_and_aborted_runs_present(self):
        prov = {}
        add_provenance(prov, run_attempts=3, aborted_runs=2)
        self.assertEqual(prov["run_attempts"], 3)
        self.assertEqual(prov["aborted_runs"], 2)

    def test_zero_is_a_valid_value_not_treated_as_absent(self):
        # 0 attempts/aborts is meaningful (a clean single run) — must not be dropped like a falsy
        # "absent" value the way run_id (a truthy-checked str) is.
        prov = {}
        add_provenance(prov, run_attempts=0, aborted_runs=0)
        self.assertEqual(prov["run_attempts"], 0)
        self.assertEqual(prov["aborted_runs"], 0)

    def test_absent_by_default(self):
        prov = {}
        add_provenance(prov)
        self.assertNotIn("run_attempts", prov)
        self.assertNotIn("aborted_runs", prov)
        self.assertNotIn("methodology_sha256", prov)
        self.assertNotIn("benchjack_audit_report_sha256", prov)

    def test_negative_run_attempts_rejected(self):
        with self.assertRaises(ValueError):
            add_provenance({}, run_attempts=-1)

    def test_negative_aborted_runs_rejected(self):
        with self.assertRaises(ValueError):
            add_provenance({}, aborted_runs=-1)

    def test_bool_rejected_as_int(self):
        # isinstance(True, int) is True in Python — an explicit bool must not sneak past the
        # non-negative-int guard as 0/1.
        with self.assertRaises(ValueError):
            add_provenance({}, run_attempts=True)

    def test_non_int_rejected(self):
        with self.assertRaises(ValueError):
            add_provenance({}, run_attempts="3")

    def test_methodology_and_benchjack_digest_present(self):
        prov = {}
        add_provenance(prov, methodology_sha256="ab" * 32, benchjack_audit_report_sha256="cd" * 32)
        self.assertEqual(prov["methodology_sha256"], "ab" * 32)
        self.assertEqual(prov["benchjack_audit_report_sha256"], "cd" * 32)

    def test_new_fields_flow_through_the_signed_claim_round_trip(self):
        # No-Fake, effect-grounded (not just a dict-shape check): build a REAL claim carrying the
        # new provenance keys, sign it, decode it back through the verify path, and confirm the
        # values survived byte-for-byte — proving they are genuinely part of the tamper-evident
        # signed payload, not merely accepted by a lax builder.
        from proofbundle.emit import generate_signer
        from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, emit_eval_receipt, \
            issuer_fingerprint
        signer = generate_signer()
        prov = add_provenance({"harness": "inspect_ai"}, run_attempts=5, aborted_runs=2,
                              methodology_sha256="11" * 32, benchjack_audit_report_sha256="22" * 32)
        claim, _ = build_eval_claim(
            suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80",
            score="0.92", n=10, model_id="m", dataset_id="d", issuer=issuer_fingerprint(signer),
            timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16,
            provenance=prov)
        bundle = emit_eval_receipt(claim, signer)
        decoded = decode_eval_claim(bundle)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["provenance"]["run_attempts"], 5)
        self.assertEqual(decoded["provenance"]["aborted_runs"], 2)
        self.assertEqual(decoded["provenance"]["methodology_sha256"], "11" * 32)
        self.assertEqual(decoded["provenance"]["benchjack_audit_report_sha256"], "22" * 32)

    def test_new_fields_flow_into_intoto_test_result_annotations(self):
        # Regression proof of the "mechanically additive" design: to_test_result_statement already
        # copies the WHOLE provenance dict verbatim into the model descriptor's annotations
        # (src/proofbundle/intoto.py) — no intoto.py code change was needed for these new keys.
        from proofbundle.intoto import to_test_result_statement
        claim = {
            "schema": "proofbundle/eval-claim/v0.1", "suite": "s", "suite_version": "v1",
            "metric": "acc", "comparator": ">=", "threshold": "0.80", "passed": True, "n": 10,
            "model_id_commit": "sha256:" + "a1" * 32, "dataset_id_commit": "sha256:" + "b2" * 32,
            "commit_alg": "sha256-salted-v1", "issuer": "ed25519:AAAA",
            "timestamp": "2026-07-05T12:00:00Z", "assurance_level": "self_attested",
            "provenance": {"run_attempts": 4, "aborted_runs": 1, "methodology_sha256": "33" * 32},
        }
        stmt = to_test_result_statement(claim, subject_digest={"sha256": "cc" * 32})
        annotations = stmt["predicate"]["configuration"][0]["annotations"]
        self.assertEqual(annotations["provenance"]["run_attempts"], 4)
        self.assertEqual(annotations["provenance"]["aborted_runs"], 1)
        self.assertEqual(annotations["provenance"]["methodology_sha256"], "33" * 32)


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
