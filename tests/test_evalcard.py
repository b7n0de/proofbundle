"""Evaluation Card digest — bind a receipt to an external, human-readable Eval Card document.

Mirrors tests/test_prereg.py: mechanically identical hash/verify pattern, additive optional claim
field `evaluation_card_sha256` (Hugging Face EvalEval Coalition Evaluation Cards, arXiv:2606.09809 —
see README.md's neighbourhood table and src/proofbundle/evalcard.py)."""
import hashlib
import json
import os
import tempfile
import unittest

from proofbundle.cli import main
from proofbundle.emit import generate_signer
from proofbundle.evalcard import evaluation_card_hash, verify_evaluation_card
from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, emit_eval_receipt, issuer_fingerprint


class TestEvalCard(unittest.TestCase):
    def _file(self, content: bytes) -> str:
        h = tempfile.NamedTemporaryFile("wb", delete=False)
        h.write(content)
        h.close()
        return h.name

    def test_hash_is_sha256_of_raw_bytes(self):
        content = b"# Eval Card\nbias: low\nprovenance: full\ndecision rule: acc >= 0.8\n"
        path = self._file(content)
        try:
            self.assertEqual(evaluation_card_hash(path), hashlib.sha256(content).hexdigest())
        finally:
            os.unlink(path)

    def test_evaluation_card_digest_resolves_and_matches(self):
        # The exact mechanical pair the finding asks for: hash a real card document, place the
        # digest in a claim, decode the SIGNED claim, then resolve+verify the card against it.
        content = b"eval card: bias=low, comparability=high, provenance=full"
        path = self._file(content)
        try:
            h = evaluation_card_hash(path)
            signer = generate_signer()
            claim, _ = build_eval_claim(
                suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80",
                score="0.92", n=10, model_id="m", dataset_id="d", issuer=issuer_fingerprint(signer),
                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16,
                evaluation_card_sha256=h)
            bundle = emit_eval_receipt(claim, signer)
            decoded = decode_eval_claim(bundle)
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded["evaluation_card_sha256"], h)
            res = verify_evaluation_card(path, decoded)
            self.assertTrue(res["ok"], res)
            self.assertTrue(res["present"])
            self.assertEqual(res["actual"], h)
        finally:
            os.unlink(path)

    def test_verify_mismatch_is_caught(self):
        path = self._file(b"the ACTUAL card")
        try:
            claim = {"evaluation_card_sha256": hashlib.sha256(b"a DIFFERENT card").hexdigest()}
            res = verify_evaluation_card(path, claim)
            self.assertFalse(res["ok"])
            self.assertIn("does NOT match", res["detail"])
        finally:
            os.unlink(path)

    def test_no_card_referenced_reports_absent(self):
        path = self._file(b"x")
        try:
            res = verify_evaluation_card(path, {})           # no evaluation_card_sha256
            self.assertFalse(res["ok"])
            self.assertFalse(res["present"])
        finally:
            os.unlink(path)

    def test_trailing_byte_change_breaks_match(self):
        # tamper-evidence: a single appended newline changes the commitment (by design).
        path = self._file(b"card\n")
        try:
            claim = {"evaluation_card_sha256": hashlib.sha256(b"card").hexdigest()}   # committed without \n
            self.assertFalse(verify_evaluation_card(path, claim)["ok"])
        finally:
            os.unlink(path)

    def test_cli_roundtrip(self):
        proto = self._file(b"card: benchmark=mmlu; bias=low; comparability=high")
        try:
            h = evaluation_card_hash(proto)
            claim, _ = build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
                score="0.9", n=10, model_id="m", dataset_id="d", issuer="",
                timestamp="2026-07-02T00:00:00Z", evaluation_card_sha256=h)
            receipt = emit_eval_receipt(claim, generate_signer())
            rp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            json.dump(receipt, rp)
            rp.close()
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["evalcard", proto, "--check", rp.name]), 0)
                # a different card fails
                other = self._file(b"a different card entirely")
                self.assertEqual(main(["evalcard", other, "--check", rp.name]), 1)
            os.unlink(rp.name)
            os.unlink(other)
        finally:
            os.unlink(proto)


class TestEvalCardCheckVerifies(unittest.TestCase):
    def test_check_rejects_forged_unsigned_bundle(self):
        # Mirrors TestPreregCheckVerifies: --check MUST verify the receipt's signature before
        # trusting its evaluation_card_sha256 — a forged/unsigned bundle with a doctored digest
        # must NOT get a PASS.
        with tempfile.TemporaryDirectory() as d:
            card = os.path.join(d, "card.md")
            with open(card, "wb") as f:
                f.write(b"eval card v1")
            h = evaluation_card_hash(card)
            signer = generate_signer()
            claim, _ = build_eval_claim(
                suite="s", suite_version="v1", metric="m", comparator=">=", threshold="0.80",
                score="0.92", n=10, model_id="a/b", dataset_id="c/d",
                issuer=issuer_fingerprint(signer), timestamp="2026-07-01T12:00:00Z",
                model_salt=b"0" * 16, dataset_salt=b"1" * 16, evaluation_card_sha256=h)
            bundle = emit_eval_receipt(claim, signer)
            bundle["signature"]["signature_b64"] = "AA==" * 22    # corrupt the Ed25519 signature
            fp = os.path.join(d, "forged.json")
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(bundle, f)
            rc = main(["evalcard", card, "--check", fp])
            self.assertNotEqual(rc, 0, "a forged/unsigned receipt must FAIL evalcard --check")


if __name__ == "__main__":
    unittest.main()
