"""The pip-only `proofbundle demo` is itself a fail-closed smoke test (v1.6.1)."""
import contextlib
import io
import json
import unittest

from proofbundle.demo import run_demo


class TestDemo(unittest.TestCase):
    def test_demo_all_guarantees_hold(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_demo()
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("=> OK", out)
        self.assertIn("honest receipt verifies", out)
        # exactly six tampers, all caught, none missed
        self.assertEqual(out.count("[caught]"), 6)
        self.assertNotIn("*** MISSED ***", out)

    def test_demo_json_shape(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_demo(as_json=True)
        data = json.loads(buf.getvalue())
        self.assertEqual(rc, 0)
        self.assertTrue(data["overall_ok"])
        self.assertTrue(data["honest_receipt_ok"])
        self.assertTrue(data["persample_audit_ok"])
        self.assertEqual(len(data["tampers"]), 6)
        self.assertTrue(all(t["caught"] for t in data["tampers"]))

    def test_demo_cli_exit_zero(self):
        from proofbundle.cli import main
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["demo", "--json"]), 0)

    def test_demo_is_not_tautological(self):
        # Anti-tautology (release review #4): if the underlying verifier regressed to accept EVERYTHING, the demo
        # MUST fail (rc != 0). This proves the green run is real — the tamper matrix depends on genuine verification,
        # not a rigged always-pass. Without a check like this, a broken verify_bundle could still make the demo "pass".
        from unittest import mock

        import proofbundle.demo as demo
        with mock.patch.object(demo, "_verifies", lambda b: True):   # broken verifier: every tamper "verifies OK"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = demo.run_demo()
        self.assertNotEqual(rc, 0, "a broken always-accept verifier must make the demo FAIL (non-tautological)")


if __name__ == "__main__":
    unittest.main()
