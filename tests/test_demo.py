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


if __name__ == "__main__":
    unittest.main()
