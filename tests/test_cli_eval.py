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


if __name__ == "__main__":
    unittest.main()
