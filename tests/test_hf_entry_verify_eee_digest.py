"""WP-I2 / WP-I3 — HF entry verifier-side binding + EEE source-record digest."""
import copy
import json
import unittest

from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.hf_evals import to_eval_results_entry, verify_eval_results_entry


def _receipt(score="0.9", threshold="0.8", comparator=">="):
    claim, _ = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=comparator, threshold=threshold,
        score=score, n=10, model_id="m", dataset_id="d", issuer="",
        timestamp="2026-07-11T00:00:00Z")
    return emit_eval_receipt(claim, generate_signer())


class TestVerifyEvalResultsEntry(unittest.TestCase):
    def test_honest_entry_verifies(self):
        entry = to_eval_results_entry(_receipt(), dataset_id="d/x", task_id="t", value=0.9)
        res = verify_eval_results_entry(entry)
        self.assertTrue(res["ok"])
        self.assertTrue(res["crypto_ok"])
        self.assertTrue(res["value_consistent"])
        self.assertEqual(res["claim"]["passed"], True)

    def test_value_edited_after_minting_fails(self):
        # The WP-I2 acceptance case: the token stays valid, only the DISPLAYED value was doctored
        # to contradict the signed verdict — emit-side checks never see this.
        entry = to_eval_results_entry(_receipt(score="0.9", threshold="0.8"),
                                      dataset_id="d/x", task_id="t", value=0.9)
        entry["value"] = 0.5   # below the >= 0.8 threshold, but claim says passed=True
        res = verify_eval_results_entry(entry)
        self.assertTrue(res["crypto_ok"], "the token itself is untouched")
        self.assertFalse(res["value_consistent"])
        self.assertFalse(res["ok"])
        self.assertIn("contradicts", res["detail"])

    def test_tampered_token_fails_crypto(self):
        entry = to_eval_results_entry(_receipt(), dataset_id="d/x", task_id="t", value=0.9)
        entry["verifyToken"] = entry["verifyToken"][:-6] + "AAAAAA"
        with self.assertRaises(BundleFormatError):
            verify_eval_results_entry(entry)   # not valid zlib/json anymore → malformed

    def test_missing_token_is_fail_closed_not_a_raise(self):
        # verifyToken is OPTIONAL in the HF schema (six-lens review): a batch verifier over a mixed
        # list must not crash — a token-less entry is "nothing to verify", fail-closed ok=False.
        entry = to_eval_results_entry(_receipt(), dataset_id="d/x", task_id="t", value=0.9)
        no_token = {k: v for k, v in entry.items() if k != "verifyToken"}
        res = verify_eval_results_entry(no_token)
        self.assertFalse(res["ok"])
        self.assertFalse(res["crypto_ok"])
        self.assertIn("nothing to verify", res["detail"])

    def test_bad_value_and_bool_value_fail_closed(self):
        entry = to_eval_results_entry(_receipt(), dataset_id="d/x", task_id="t", value=0.9)
        bad = copy.deepcopy(entry)
        bad["value"] = "not-a-number"
        res = verify_eval_results_entry(bad)
        self.assertFalse(res["ok"])
        self.assertIn("not a number", res["detail"])
        # six-lens review: a bool must NOT be coerced to 1.0/0.0 (the builder rejects bool too)
        boolean = copy.deepcopy(entry)
        boolean["value"] = True
        res2 = verify_eval_results_entry(boolean)
        self.assertFalse(res2["ok"])
        self.assertIn("boolean", res2["detail"])

    def test_non_eval_bundle_and_crypto_fail_are_fail_closed(self):
        # explicitly-claimed fail-closed branches (six-lens review: previously untested).
        from proofbundle import emit_bundle
        # (1) a genuinely non-eval bundle → value cannot be judged → value_consistent False
        signer = generate_signer()
        non_eval = emit_bundle(b'{"schema":"other/v1"}', signer)
        from proofbundle.hf_evals import receipt_token
        entry = {"dataset": {"id": "d", "task_id": "t"}, "value": 0.5,
                 "verifyToken": receipt_token(non_eval)}
        res = verify_eval_results_entry(entry)
        self.assertTrue(res["crypto_ok"])            # the bundle itself verifies
        self.assertFalse(res["value_consistent"])    # but it is not a decodable eval receipt
        self.assertFalse(res["ok"])
        # (2) a tampered token → crypto fails → fail-closed
        good = to_eval_results_entry(_receipt(), dataset_id="d/x", task_id="t", value=0.9)
        good["verifyToken"] = good["verifyToken"][:-8] + "AAAAAAAA"
        try:
            r2 = verify_eval_results_entry(good)
            self.assertFalse(r2["ok"])
        except BundleFormatError:
            pass   # a token that is no longer valid zlib/json is malformed — either fail-closed path is ok

    def test_replay_boundary_is_stated_not_hidden(self):
        # The check binds value<->verdict, NOT dataset/task identity (salted commitments). A
        # replayed-but-consistent entry still verifies — the result must SAY so in warnings.
        entry = to_eval_results_entry(_receipt(), dataset_id="d/x", task_id="t", value=0.9)
        replayed = dict(entry, dataset=dict(entry["dataset"], id="OTHER/repo"))
        res = verify_eval_results_entry(replayed)
        self.assertTrue(res["ok"], "identity replay is OUT of scope by design — documented")
        self.assertTrue(any("NOT bound" in w for w in res["warnings"]))


class TestEeeRecordDigest(unittest.TestCase):
    def _record(self):
        return {
            "schema_version": "0.2.2",
            "evaluation_id": "suite/model-x/2026",
            "model_info": {"id": "model-x"},
            "retrieved_timestamp": "2026-07-11T00:00:00Z",
            "evaluation_results": [{
                "evaluation_name": "suite",
                "evaluation_result_id": "res-123",
                "metric_config": {"metric_name": "acc"},
                "score_details": {"score": 0.9},
                "source_data": {"dataset_name": "ds"},
            }],
        }

    def test_provenance_carries_labeled_record_digest_and_result_id(self):
        from proofbundle.adapters import from_eee_dataset
        claim, _ = from_eee_dataset(self._record(), comparator=">=", threshold="0.8", validate=False)
        prov = claim["provenance"]
        self.assertRegex(prov["eee_record_sha256"], r"^sha256-(jcs|sortkeys):[0-9a-f]{64}$")
        self.assertEqual(prov["run_id"], "res-123")
        self.assertNotIn("suite/model-x/2026", json.dumps(prov),
                         "top-level evaluation_id (cleartext model id) must stay excluded")

    def test_digest_binds_the_exact_record(self):
        from proofbundle.adapters import from_eee_dataset
        rec = self._record()
        claim1, _ = from_eee_dataset(copy.deepcopy(rec), comparator=">=", threshold="0.8",
                                     validate=False)
        rec2 = copy.deepcopy(rec)
        rec2["evaluation_results"][0]["score_details"]["score"] = 0.91   # tamper the source
        claim2, _ = from_eee_dataset(rec2, comparator=">=", threshold="0.8", validate=False)
        self.assertNotEqual(claim1["provenance"]["eee_record_sha256"],
                            claim2["provenance"]["eee_record_sha256"])
        claim3, _ = from_eee_dataset(copy.deepcopy(rec), comparator=">=", threshold="0.8",
                                     validate=False)
        self.assertEqual(claim1["provenance"]["eee_record_sha256"],
                         claim3["provenance"]["eee_record_sha256"], "digest is deterministic")

    def test_result_id_with_embedded_model_id_is_dropped(self):
        from proofbundle.adapters import from_eee_dataset
        rec = self._record()
        rec["evaluation_results"][0]["evaluation_result_id"] = "suite/model-x/run-1"
        claim, _ = from_eee_dataset(rec, comparator=">=", threshold="0.8", validate=False)
        self.assertNotIn("run_id", claim["provenance"],
                         "a result id embedding the cleartext model id must be dropped, not leaked")

    def test_run_id_bare_name_and_slug_variant_are_dropped(self):
        # six-lens review: the exact full-repo-id substring test missed the bare name and slug forms.
        from proofbundle.adapters import from_eee_dataset
        for rid in ("arc/model-x/run1",           # bare name 'model-x'
                    "eval-modelx-2026",            # slug variant (dash removed)
                    "MODEL-X-benchmark"):          # case-insensitive
            rec = self._record()
            rec["evaluation_results"][0]["evaluation_result_id"] = rid
            claim, _ = from_eee_dataset(rec, comparator=">=", threshold="0.8", validate=False)
            self.assertNotIn("run_id", claim["provenance"], f"leak via {rid!r}")
        # a genuinely model-id-free id survives
        rec = self._record()
        rec["evaluation_results"][0]["evaluation_result_id"] = "run-abc123"
        claim, _ = from_eee_dataset(rec, comparator=">=", threshold="0.8", validate=False)
        self.assertEqual(claim["provenance"].get("run_id"), "run-abc123")

    def test_record_digest_is_not_a_model_id_oracle(self):
        # six-lens review (P1): the digest must NOT let an attacker who knows/guesses the record
        # confirm the model id — it is computed over a model-id-STRIPPED record.
        from proofbundle.adapters.eee import _model_id_stripped, _record_digest
        rec = self._record()
        stripped = _model_id_stripped(rec)
        self.assertNotIn("id", stripped.get("model_info", {}))
        self.assertNotIn("evaluation_id", stripped)
        # two records that differ ONLY in the model id yield the SAME digest (no oracle)
        rec2 = self._record()
        rec2["model_info"]["id"] = "some-other-model"
        rec2["evaluation_id"] = "suite/some-other-model/2026"
        self.assertEqual(_record_digest(rec), _record_digest(rec2))
        # M2 (6-lens review): the per-result evaluation_result_id (a provenance id that can embed the
        # model id) must ALSO be stripped from the digest — else two records differing only in that id
        # yield different digests = a model-id confirmation oracle.
        self.assertNotIn("evaluation_result_id", stripped["evaluation_results"][0])
        rec4 = self._record()
        rec4["evaluation_results"][0]["evaluation_result_id"] = "suite/some-other-model/run-9"
        self.assertEqual(_record_digest(rec), _record_digest(rec4),
                         "evaluation_result_id must not change the digest (M2: no id oracle)")
        # but a tampered SCORE still changes the digest (tamper-evidence preserved)
        rec3 = self._record()
        rec3["evaluation_results"][0]["score_details"]["score"] = 0.91
        self.assertNotEqual(_record_digest(rec), _record_digest(rec3))


if __name__ == "__main__":
    unittest.main()
