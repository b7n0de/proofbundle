"""The one-key-leg module where cryptography has no ML-DSA, as on the floor of the crypto-floor job, measured in every job.

Codex on pull request 543, round 1, P1: the module skips its cases on the floor through `pytestmark`, and nothing showed
that this holds. Its stand-in keys refuse to sign, but several cases sign nothing and could pass on stand-in values; a
lost or broken mark would then turn an unmeasured case green, and no test said so. This test runs the floor path for
real: in a process of its own, `generate_mldsa` raises `PQUnavailable` as it does under cryptography 42, the module is
collected and run under pytest, and every case must be skipped with the reason, none passed and none failed. The same
process shows that `unittest discover` builds no stand-in for the module, which is what turned part 5 of 5 red.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
MODUL = "tests/test_trust_pack_one_key_leg_counts_once.py"

#: Runs in a process of its own from the top of the checkout: ML-DSA is made unavailable before the module is imported,
#: then pytest runs the module and unittest loads it, and both outcomes are printed as one JSON line.
_LAUF = r"""
import json, os, sys, unittest
sys.path[:0] = [os.path.join(os.getcwd(), "src"), os.getcwd()]
import proofbundle.pqsig as pq

def ohne_ml_dsa(*_a, **_k):
    raise pq.PQUnavailable("simulated for the floor: no ML-DSA in this cryptography build")

pq.generate_mldsa = ohne_ml_dsa
import pytest

class Sammler:
    def __init__(self):
        self.ergebnis = {"passed": 0, "failed": 0, "skipped": 0, "gruende": set(), "gesammelt": 0}
    def pytest_collection_modifyitems(self, items):
        self.ergebnis["gesammelt"] = len(items)
    def pytest_runtest_logreport(self, report):
        if report.when == "call" or report.outcome != "passed":
            self.ergebnis[report.outcome] += 1
            if report.skipped and isinstance(report.longrepr, tuple):
                self.ergebnis["gruende"].add(str(report.longrepr[2]))

# unittest first, so it imports the module itself and would build the stand-in of a skip at import.
def flat(x):
    for t in x:
        if isinstance(t, unittest.TestSuite):
            yield from flat(t)
        else:
            yield t

ids = [t.id() for t in flat(unittest.TestLoader().discover("tests", os.path.basename(sys.argv[1]), None))]

s = Sammler()
rc = pytest.main(["-q", "-p", "no:cacheprovider", "-p", "no:warnings", sys.argv[1]], plugins=[s])
e = dict(s.ergebnis, gruende=sorted(s.ergebnis["gruende"]), rc=int(rc), unittest_ids=ids)
print("ERGEBNIS " + json.dumps(e))
"""


def _lauf() -> dict:
    r = subprocess.run([sys.executable, "-c", _LAUF, MODUL], cwd=REPO, capture_output=True, text=True, timeout=900,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    zeilen = [z for z in r.stdout.splitlines() if z.startswith("ERGEBNIS ")]
    if not zeilen:
        raise AssertionError(f"the floor run printed no result (rc {r.returncode}): {r.stdout[-1500:]}{r.stderr[-1500:]}")
    return json.loads(zeilen[-1][len("ERGEBNIS "):])


class TheModuleWithoutMlDsaSkipsEveryCaseAndNoStandIn(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.e = _lauf()

    def test_every_case_is_collected_and_skipped_with_the_reason(self):
        e = self.e
        # A sweep over nothing is green and says nothing: the module holds 94 cases with ML-DSA.
        self.assertGreater(e["gesammelt"], 50, e)
        self.assertEqual((e["passed"], e["failed"], e["skipped"]), (0, 0, e["gesammelt"]), e)
        self.assertTrue(e["gruende"], e)
        for grund in e["gruende"]:
            self.assertIn("NOT MEASURABLE without ML-DSA", grund)
        self.assertEqual(e["rc"], 0, e)

    def test_unittest_builds_no_stand_in_for_the_module(self):
        self.assertEqual([i for i in self.e["unittest_ids"] if i.startswith("unittest.loader.")], [], self.e)


if __name__ == "__main__":
    unittest.main()
