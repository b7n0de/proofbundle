"""in-toto test-result DSSE export (v0.9): PAE byte-rules, round-trip, tamper, payloadType pinning."""
import base64
import copy
import json
import unittest

from proofbundle import dsse, intoto
from proofbundle.emit import _raw_pub, generate_signer
from proofbundle.evalclaim import build_eval_claim

TS = "2026-07-02T00:00:00Z"


def _claim(passed_score="0.55"):
    claim, _ = build_eval_claim(suite="arc_easy", suite_version="1", metric="acc", comparator=">=",
                                threshold="0.30", score=passed_score, n=100, model_id="m", dataset_id="d",
                                issuer="", timestamp=TS, model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class TestDSSE(unittest.TestCase):
    def test_pae_exact_bytes(self):
        # DSSEv1 SP LEN(type) SP type SP LEN(body) SP body; LEN is byte length, no leading zeros.
        self.assertEqual(dsse.pae("ab", b"hello"), b"DSSEv1 2 ab 5 hello")
        pt = intoto.TEST_RESULT_PAYLOAD_TYPE
        self.assertEqual(dsse.pae(pt, b"x"), b"DSSEv1 " + str(len(pt)).encode() + b" " + pt.encode() + b" 1 x")

    def test_roundtrip_and_predicate(self):
        signer = generate_signer()
        env = intoto.export_intoto_dsse(_claim(), signer, root_b64="AAAA",
                                        harness={"name": "lm-eval", "version": "0.4.12"})
        r = intoto.verify_intoto_dsse(env, _raw_pub(signer))
        self.assertTrue(r["ok"])
        self.assertEqual(r["predicate_type"], "https://in-toto.io/attestation/test-result/v0.1")
        st = r["statement"]
        self.assertEqual(st["predicate"]["result"], "PASSED")
        self.assertIn("digest", st["subject"][0])
        self.assertTrue(all("digest" in c for c in st["predicate"]["configuration"]))
        # metrics live in annotations, not as a native predicate field
        self.assertNotIn("metric", st["predicate"])
        self.assertIn("metric", st["predicate"]["configuration"][0]["annotations"])

    def test_failed_result(self):
        signer = generate_signer()
        env = intoto.export_intoto_dsse(_claim("0.10"), signer)   # 0.10 < 0.30 → FAILED
        self.assertEqual(intoto.verify_intoto_dsse(env, _raw_pub(signer))["statement"]["predicate"]["result"], "FAILED")

    def test_tamper_rejected(self):
        signer = generate_signer()
        env = intoto.export_intoto_dsse(_claim(), signer)
        bad = copy.deepcopy(env)
        st = json.loads(base64.b64decode(bad["payload"]))
        st["predicate"]["result"] = "FAILED"
        bad["payload"] = base64.b64encode(json.dumps(st, sort_keys=True, separators=(",", ":")).encode()).decode()
        self.assertFalse(intoto.verify_intoto_dsse(bad, _raw_pub(signer))["ok"])

    def test_payload_type_pinned(self):
        signer = generate_signer()
        env = intoto.export_intoto_dsse(_claim(), signer)
        env["payloadType"] = "application/vnd.in-toto+json"      # wrong type → PAE differs → reject
        self.assertFalse(intoto.verify_intoto_dsse(env, _raw_pub(signer))["ok"])

    def test_wrong_key_rejected(self):
        env = intoto.export_intoto_dsse(_claim(), generate_signer())
        self.assertFalse(intoto.verify_intoto_dsse(env, _raw_pub(generate_signer()))["ok"])

    def test_urlsafe_base64_accepted(self):
        # DSSE spec: a verifier MUST accept url-safe base64 too (not only standard)
        import base64
        signer = generate_signer()
        env = intoto.export_intoto_dsse(_claim(), signer)
        body = base64.b64decode(env["payload"])
        env["payload"] = base64.urlsafe_b64encode(body).decode().rstrip("=")   # url-safe, no padding
        self.assertTrue(intoto.verify_intoto_dsse(env, _raw_pub(signer))["ok"])

    def test_non_json_payload_is_format_error_not_crash(self):
        # RE-GATE never-raise: a non-JSON payload is a fail-closed VERDICT (ok=False), never a raw crash and
        # (mirroring decision/outcome/run_ledger) no longer a raised BundleFormatError out of this surface.
        import base64
        signer = generate_signer()
        env = intoto.export_intoto_dsse(_claim(), signer)
        env["payload"] = base64.b64encode(b"not json at all").decode()
        r = intoto.verify_intoto_dsse(env, _raw_pub(signer))
        self.assertIs(r["ok"], False)
