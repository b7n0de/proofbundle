"""pytest plugin (v1.0): opt-in safety + signed receipt of the test run from terminalreporter.stats."""
import json
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from proofbundle import verify_bundle
from proofbundle.evalclaim import decode_eval_claim
from proofbundle.pytest_plugin import pytest_terminal_summary


def _reporter(passed=3, failed=0, error=0):
    stats = {}
    if passed:
        stats["passed"] = [object()] * passed
    if failed:
        stats["failed"] = [object()] * failed
    if error:
        stats["error"] = [object()] * error
    return types.SimpleNamespace(stats=stats)


def _config(flag, rootpath="myproj"):
    return types.SimpleNamespace(getoption=lambda name, default=False: flag,
                                 rootpath=types.SimpleNamespace(name=rootpath, __str__=lambda self: rootpath))


class TestPytestPlugin(unittest.TestCase):
    def test_opt_in_off_no_receipt(self):
        with TemporaryDirectory() as d:
            import os
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            os.environ["PROOFBUNDLE_OUT"] = d
            pytest_terminal_summary(_reporter(), 0, _config(False))
            self.assertEqual([f for f in Path(d).iterdir()], [])

    def test_opt_in_flag_emits_receipt(self):
        with TemporaryDirectory() as d:
            import os
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ["PROOFBUNDLE_THRESHOLD"] = "0.5"
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            pytest_terminal_summary(_reporter(passed=3, failed=1), 1, _config(True))
            files = list(Path(d).glob("*.json"))
            self.assertEqual(len(files), 1)
            b = json.loads(files[0].read_text())
            self.assertTrue(verify_bundle(b).ok)
            d2 = decode_eval_claim(b)
            self.assertEqual(d2["suite"], "pytest")
            self.assertEqual(d2["metric"], "pass_rate")
            self.assertTrue(d2["passed"])                       # 3/4 = 0.75 >= 0.5
            self.assertEqual(d2["provenance"]["n_failed"], 1)

    def test_no_tests_no_receipt(self):
        with TemporaryDirectory() as d:
            import os
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            pytest_terminal_summary(_reporter(passed=0), 5, _config(False))
            self.assertEqual(list(Path(d).glob("*.json")), [])
            os.environ.pop("PROOFBUNDLE_EMIT", None)
