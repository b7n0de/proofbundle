"""WP4 tests: `proofbundle decision {init,emit,verify,inspect}` CLI + --version predicates line.

Exercises the exit-code contract (0 ok / 1 crypto fail / 2 malformed / 3 policy) end to end through cli.main().
unittest-style to match the repo's `python -m unittest discover`."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle.cli import main
from proofbundle.emit import generate_signer, load_signer, save_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _run(argv):
    """Run cli.main(argv), returning (rc_or_SystemExit_code, stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, buf.getvalue()


class TestDecisionCli(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.keyfile = self.tmp / "signer.bin"
        save_signer(generate_signer(), str(self.keyfile))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pub_b64(self) -> str:
        s = load_signer(str(self.keyfile))
        return base64.b64encode(s.public_key().public_bytes_raw()).decode()

    def _emit(self, example: str) -> Path:
        receipt = self.tmp / "r.json"
        rc, _ = _run(["decision", "emit", str(EXAMPLES / example), "--out", str(receipt), "--key", str(self.keyfile)])
        self.assertEqual(rc, 0)
        return receipt

    def test_version_lists_predicates(self):
        _, out = _run(["--version"])
        self.assertIn("predicates: eval-result/v0.1 decision-receipt/v0.1", out)

    def test_init_emits_valid_template(self):
        rc, out = _run(["decision", "init"])
        self.assertEqual(rc, 0)
        from proofbundle.decision import validate_decision_predicate
        self.assertEqual(validate_decision_predicate(json.loads(out), strict=True), [])

    def test_emit_verify_roundtrip(self):
        receipt = self._emit("decision_receipt_deny.json")
        rc, out = _run(["decision", "verify", str(receipt), "--pub", self._pub_b64(), "--strict"])
        self.assertEqual(rc, 0)
        self.assertIn("CRYPTO: OK", out)
        self.assertIn("POLICY: NOT_EVALUATED", out)
        self.assertIn("STRUCTURE: OK", out)

    def test_verify_wrong_key_exit_1(self):
        receipt = self._emit("decision_receipt_deny.json")
        other = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode()
        rc, _ = _run(["decision", "verify", str(receipt), "--pub", other])
        self.assertEqual(rc, 1)

    def test_verify_malformed_exit_2(self):
        bad = self.tmp / "bad.json"
        bad.write_text("{ not json", encoding="utf-8")
        rc, _ = _run(["decision", "verify", str(bad), "--pub", "AAAA"])
        self.assertEqual(rc, 2)

    def test_inspect_prints_predicate(self):
        receipt = self._emit("decision_receipt_escalate.json")
        rc, out = _run(["decision", "inspect", str(receipt)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["decision"]["verdict"], "ESCALATE")

    def test_cli_receipt_verifies_via_library(self):
        receipt = self._emit("decision_receipt_allow.json")
        from proofbundle.decision import verify_decision_receipt
        env = json.loads(receipt.read_text())
        pub = base64.b64decode(self._pub_b64())
        self.assertIs(verify_decision_receipt(env, pub, strict=True)["crypto_ok"], True)


if __name__ == "__main__":
    unittest.main()
