"""v1.8 pre-registration helper: commit to a protocol before the run, verify after."""
import hashlib
import os
import tempfile
import unittest

from proofbundle.prereg import prereg_hash, verify_prereg


class TestPrereg(unittest.TestCase):
    def _file(self, content: bytes) -> str:
        h = tempfile.NamedTemporaryFile("wb", delete=False)
        h.write(content)
        h.close()
        return h.name

    def test_hash_is_sha256_of_raw_bytes(self):
        content = b"protocol: fixed seeds 1..5\ndecision: acc >= 0.8\n"
        path = self._file(content)
        try:
            self.assertEqual(prereg_hash(path), hashlib.sha256(content).hexdigest())
        finally:
            os.unlink(path)

    def test_verify_match(self):
        content = b"the plan"
        path = self._file(content)
        try:
            claim = {"prereg_sha256": hashlib.sha256(content).hexdigest()}
            res = verify_prereg(path, claim)
            self.assertTrue(res["ok"])
            self.assertTrue(res["present"])
        finally:
            os.unlink(path)

    def test_verify_mismatch_is_caught(self):
        path = self._file(b"the ACTUAL plan")
        try:
            claim = {"prereg_sha256": hashlib.sha256(b"a DIFFERENT plan").hexdigest()}
            res = verify_prereg(path, claim)
            self.assertFalse(res["ok"])
            self.assertIn("does NOT match", res["detail"])
        finally:
            os.unlink(path)

    def test_not_preregistered_reports_absent(self):
        path = self._file(b"x")
        try:
            res = verify_prereg(path, {})           # no prereg_sha256
            self.assertFalse(res["ok"])
            self.assertFalse(res["present"])
        finally:
            os.unlink(path)

    def test_trailing_byte_change_breaks_match(self):
        # tamper-evidence: a single appended newline changes the commitment (by design).
        path = self._file(b"plan\n")
        try:
            claim = {"prereg_sha256": hashlib.sha256(b"plan").hexdigest()}   # committed without \n
            self.assertFalse(verify_prereg(path, claim)["ok"])
        finally:
            os.unlink(path)

    def test_cli_roundtrip(self):
        import json
        from proofbundle.cli import main
        from proofbundle import generate_signer
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        import contextlib
        import io
        proto = self._file(b"suite=mmlu; seeds=1..5; rule=acc>=0.8")
        try:
            h = prereg_hash(proto)
            claim, _ = build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
                score="0.9", n=10, model_id="m", dataset_id="d", issuer="",
                timestamp="2026-07-02T00:00:00Z", prereg_sha256=h)
            receipt = emit_eval_receipt(claim, generate_signer())
            rp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            json.dump(receipt, rp)
            rp.close()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["prereg", proto, "--check", rp.name]), 0)
                # a different protocol fails
                other = self._file(b"a different plan")
                self.assertEqual(main(["prereg", other, "--check", rp.name]), 1)
            os.unlink(rp.name)
            os.unlink(other)
        finally:
            os.unlink(proto)


if __name__ == "__main__":
    unittest.main()
