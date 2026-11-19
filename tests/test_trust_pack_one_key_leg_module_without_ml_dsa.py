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

if sys.argv[2] == "simuliert":
    pq.generate_mldsa = ohne_ml_dsa
import pytest

class Sammler:
    def __init__(self):
        self.ergebnis = {"passed": 0, "failed": 0, "skipped": 0, "je_skip": [], "gesammelt": 0, "ids": []}
    def pytest_collection_modifyitems(self, items):
        self.ergebnis["gesammelt"] = len(items)
        self.ergebnis["ids"] = sorted(i.nodeid for i in items)
    def pytest_runtest_logreport(self, report):
        if report.when == "call" or report.outcome != "passed":
            self.ergebnis[report.outcome] += 1
            if report.skipped:
                lang = report.longrepr
                self.ergebnis["je_skip"].append(str(lang[2]) if isinstance(lang, tuple) and len(lang) > 2 else "")

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
e = dict(s.ergebnis, rc=int(rc), unittest_ids=ids)
print("ERGEBNIS " + json.dumps(e))
"""


#: The number of cases the module holds. A change of the module that adds or removes cases changes this number on
#: purpose; a stand-in key that silently dropped a parametrised form would change it by accident (Codex on pull request
#: 543, round 2, P1).
_ERWARTET = 94


def _ml_dsa_da() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def _lauf(art: str = "simuliert") -> dict:
    r = subprocess.run([sys.executable, "-c", _LAUF, MODUL, art], cwd=REPO, capture_output=True, text=True, timeout=900,
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
        # A sweep over nothing is green and says nothing, and a smaller sweep hides the cases it lost.
        self.assertEqual(e["gesammelt"], _ERWARTET, e)
        self.assertEqual((e["passed"], e["failed"], e["skipped"]), (0, 0, e["gesammelt"]), e)
        # The reason of EVERY skipped case, one per case (Codex on pull request 543, round 5, P1): a skip without the
        # reason, or of another form, is no measured floor path.
        self.assertEqual(len(e["je_skip"]), e["skipped"], e)
        ohne = [g for g in e["je_skip"] if "NOT MEASURABLE without ML-DSA" not in g]
        self.assertEqual(ohne, [], e)
        self.assertEqual(e["rc"], 0, e)

    def test_unittest_builds_no_stand_in_for_the_module(self):
        self.assertEqual([i for i in self.e["unittest_ids"] if i.startswith("unittest.loader.")], [], self.e)

    def test_the_floor_collects_the_same_cases_as_a_build_with_ml_dsa(self):
        """Where ML-DSA is there, the run without the simulation collects the cases a build with ML-DSA runs; the floor
        run must collect exactly the same ids, so no stand-in value drops or adds a parametrised case."""
        if not _ml_dsa_da():
            self.skipTest("NOT MEASURABLE without ML-DSA in this cryptography build: no run with ML-DSA to compare with")
        echt = _lauf("echt")
        self.assertEqual(echt["ids"], self.e["ids"])
        self.assertEqual((echt["passed"], echt["failed"]), (_ERWARTET, 0), echt)


if __name__ == "__main__":
    unittest.main()
