"""CLI emit-eval + show-eval end-to-end (round-trip through the process boundary)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _run(*args, **kw):
    return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args],
                          capture_output=True, text=True, cwd=REPO,
                          env={"PYTHONPATH": str(REPO / "src"), **kw.get("env", {})})


class TestCliEval(unittest.TestCase):
    def test_emit_eval_then_verify_and_show(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as d:
            claim = os.path.join(d, "claim.json")
            Path(claim).write_text(json.dumps({
                "schema": "proofbundle/eval-claim/v0.1", "suite": "s", "suite_version": "v1",
                "metric": "acc", "comparator": ">=", "threshold": "0.80", "passed": True, "n": 100,
                "model_id_commit": "sha256:x", "dataset_id_commit": "sha256:y",
                "commit_alg": "sha256-salted-v1", "issuer": "ed25519:z",
                "timestamp": "2026-07-01T12:00:00Z"}), encoding="utf-8")
            out = os.path.join(d, "receipt.json")
            key = os.path.join(d, "k.key")
            self.assertEqual(_run("emit-eval", "--claim", claim, "--out", out, "--new-key", key).returncode, 0)
            self.assertEqual(_run("verify", out).returncode, 0)
            show = _run("show-eval", out)
            self.assertEqual(show.returncode, 0)
            self.assertIn("passed", show.stdout)

    def test_show_eval_malformed_no_raw_traceback(self):
        # F3 (v1.9.2): show-eval honors the no-raw-traceback contract. A hand-signed receipt missing a
        # required field is now rejected by decode_eval_claim (SH1), so show-eval prints a clean FAILED
        # and exits 1 — it never reaches the claim[<required>] field access that previously raised a
        # raw KeyError outside the try block.
        import os
        import tempfile

        from proofbundle import evalclaim as ec
        from proofbundle.emit import emit_bundle, generate_signer
        signer = generate_signer()
        c, _ = ec.build_eval_claim(
            suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80",
            score="0.90", n=100, model_id="m", dataset_id="d", issuer="x",
            timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        good = ec.decode_eval_claim(ec.emit_eval_receipt(c, signer))
        malformed = {k: v for k, v in good.items() if k != "suite"}   # drop a required field, re-sign by hand
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            Path(p).write_text(json.dumps(emit_bundle(ec.canonicalize(malformed), signer)), encoding="utf-8")
            r = _run("show-eval", p)
            self.assertEqual(r.returncode, 1, "malformed receipt must exit 1, not crash")
            self.assertNotIn("Traceback", r.stderr, "show-eval must never emit a raw traceback")
            self.assertIn("FAILED", r.stderr)


if __name__ == "__main__":
    unittest.main()
