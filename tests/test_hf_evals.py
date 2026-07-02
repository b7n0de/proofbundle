"""HF Community Evals bridge — pb1. token roundtrip, YAML emitter, red matrix (v1.4)."""
import base64
import json
import unittest
import zlib

from proofbundle import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.hf_evals import (TOKEN_PREFIX, eval_results_yaml, receipt_token,
                                  to_eval_results_entry, verify_receipt_token)


def _bundle():
    return emit_bundle(b'{"suite": "demo", "passed": true}', generate_signer())


class TestReceiptToken(unittest.TestCase):
    def test_green_roundtrip(self):
        bundle = _bundle()
        token = receipt_token(bundle)
        self.assertTrue(token.startswith(TOKEN_PREFIX))
        result, unpacked = verify_receipt_token(token)
        self.assertTrue(result.ok, result.as_dict())
        self.assertEqual(unpacked, bundle)

    def test_token_is_compact(self):
        # Honest bound: a tiny bundle is mostly high-entropy base64 (zlib gains little there),
        # so the guarantee is "smaller than plain base64url of the JSON", not "smaller than JSON".
        bundle = _bundle()
        plain_b64 = base64.urlsafe_b64encode(json.dumps(bundle).encode())
        self.assertLess(len(receipt_token(bundle)), len(plain_b64))

    def test_red_tampered_payload_inside_token(self):
        bundle = _bundle()
        bundle["payload_b64"] = base64.b64encode(b'{"forged": 1}').decode()
        result, _ = verify_receipt_token(receipt_token(bundle))
        self.assertFalse(result.ok)                      # unpacks fine, verifies FAILED

    def test_red_garbage_tokens(self):
        for bad in ("", "pb1.", "pb1.!!!!", "pb2." + "AAAA", "eyJhbGciOi.fake.jwt"):
            with self.assertRaises(BundleFormatError, msg=repr(bad)):
                verify_receipt_token(bad)

    def test_red_zip_bomb_capped(self):
        bomb = TOKEN_PREFIX + base64.urlsafe_b64encode(
            zlib.compress(b'{"a":"' + b"A" * 1_000_000 + b'"}', 9)).rstrip(b"=").decode()
        with self.assertRaises(BundleFormatError):
            verify_receipt_token(bomb)

    def test_red_non_dict_content(self):
        token = TOKEN_PREFIX + base64.urlsafe_b64encode(
            zlib.compress(b'[1,2,3]', 9)).rstrip(b"=").decode()
        with self.assertRaises(BundleFormatError):
            verify_receipt_token(token)


class TestEvalResultsEntry(unittest.TestCase):
    def test_green_entry_and_yaml(self):
        bundle = _bundle()
        entry = to_eval_results_entry(
            bundle, dataset_id="Idavidrein/gpqa", task_id="gpqa_diamond", value=0.412,
            date="2026-07-02", source_url="https://example.com/receipt", source_name="receipt",
            notes="pass_rate over 3 tests")
        self.assertEqual(entry["dataset"], {"id": "Idavidrein/gpqa", "task_id": "gpqa_diamond"})
        self.assertEqual(entry["value"], 0.412)
        self.assertTrue(entry["verifyToken"].startswith(TOKEN_PREFIX))
        yaml_doc = eval_results_yaml([entry])
        # spot-check the block structure against the HF spec example shape
        self.assertIn('- dataset:', yaml_doc)
        self.assertIn('    id: "Idavidrein/gpqa"', yaml_doc)
        self.assertIn('    task_id: "gpqa_diamond"', yaml_doc)
        self.assertIn("  value: 0.412", yaml_doc)
        self.assertIn('  date: "2026-07-02"', yaml_doc)      # dates stay quoted strings
        self.assertIn("  source:", yaml_doc)
        self.assertIn('    url: "https://example.com/receipt"', yaml_doc)
        # the token in the YAML round-trips to a verifying receipt
        token_line = next(ln for ln in yaml_doc.splitlines() if "verifyToken" in ln)
        token = json.loads(token_line.split(": ", 1)[1])
        result, _ = verify_receipt_token(token)
        self.assertTrue(result.ok)

    def test_yaml_is_parseable_as_json_scalars(self):
        # Every scalar we emit is JSON-encoded — a strict subset of YAML — so no YAML parser
        # ambiguity (dates, tokens with special chars, booleans) can occur.
        entry = to_eval_results_entry(_bundle(), dataset_id="d/x", task_id="t", value=1.0,
                                      notes='tricky: "quotes" & — dashes')
        doc = eval_results_yaml([entry])
        note_line = next(ln for ln in doc.splitlines() if ln.startswith("  notes:"))
        self.assertEqual(json.loads(note_line.split(": ", 1)[1]), 'tricky: "quotes" & — dashes')

    def test_red_broken_bundle_refused(self):
        bundle = _bundle()
        bundle["payload_b64"] = base64.b64encode(b"forged").decode()
        with self.assertRaises(BundleFormatError) as ctx:
            to_eval_results_entry(bundle, dataset_id="d/x", task_id="t", value=1.0)
        self.assertIn("does not verify", str(ctx.exception))

    def test_red_source_without_url(self):
        with self.assertRaises(BundleFormatError):
            to_eval_results_entry(_bundle(), dataset_id="d/x", task_id="t", value=1.0,
                                  source_name="nameless source")

    def test_red_missing_identity(self):
        with self.assertRaises(BundleFormatError):
            to_eval_results_entry(_bundle(), dataset_id="", task_id="t", value=1.0)

    def test_token_optional(self):
        entry = to_eval_results_entry(_bundle(), dataset_id="d/x", task_id="t", value=1.0,
                                      include_token=False)
        self.assertNotIn("verifyToken", entry)

    def test_red_unknown_field_in_yaml(self):
        with self.assertRaises(BundleFormatError):
            eval_results_yaml([{"dataset": {"id": "d", "task_id": "t"}, "value": 1,
                                "injected": "x"}])


if __name__ == "__main__":
    unittest.main()
