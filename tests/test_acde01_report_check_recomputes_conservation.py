"""K10 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K10): the stand-alone report checker of
ACDE-01 recomputes the conservation equations instead of trusting the report's own booleans.

`check_report` compared some counters with known classes, accepted an instruction of an unknown class and then
trusted `draft_equation_holds` from the report it checks. A report with I = 1, the instruction's class UNKNOWN
and the partial counts 0 + 0 got no violation while it still stated PASS (measured at 98b168b9 and f6ea5cc3).
That breaks S6.4-3 and the condition of S6.5-5 that a population-conservation failure prevents PASS (draft -01
numbering; since the reader follows -02 the same sentences are S6.4-3 and S6.5-9, the receiver equation is S6.4-7 and
the instruction equation has the third class target_resolution_unclosed). The class vocabularies are now closed and
the equations are recomputed from the numbers the report publishes.
"""
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ACDE = REPO / "interop" / "acde_01"
TOOL = ACDE / "tools" / "make_run_record.py"


def _tool():
    """make_run_record.py, imported without calling its main, as the finding did."""
    spec = importlib.util.spec_from_file_location("_k10_make_run_record", TOOL)
    module = importlib.util.module_from_spec(spec)
    before = list(sys.path)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = before
    return module


class TheReportCheckRecomputesConservation(unittest.TestCase):

    def setUp(self):
        if not TOOL.is_file():
            self.skipTest("interop/acde_01 is not in this tree")
        self.tool = _tool()
        self.good = self.tool.acde01.reconcile.reconcile(self.tool.build.base_run())
        self.check = self.tool.acde01.report_check.check_report
        self.assertEqual(self.good["structural"]["structural_result"], "PASS", "precondition")

    def test_CONTROL_the_report_as_reconciled_has_no_violation(self):
        self.assertEqual(self.check(self.good), [])

    def test_RED_an_instruction_of_an_unknown_class_breaks_the_equation(self):
        """T10: I = 1, partial counts 0 + 0 + 0, equation_holds still true in the report."""
        bad = copy.deepcopy(self.good)
        bad["instructions"][0]["class"] = "UNKNOWN"
        bad["conservation"]["instructions"]["with_obligations"] = 0
        self.assertIs(bad["conservation"]["instructions"]["equation_holds"], True, "precondition")
        found = {v["requirement"] for v in self.check(bad)}
        self.assertIn("S6.4-3", found)
        self.assertIn("S6.5-9", found)

    def test_RED_a_receiver_count_of_an_unknown_class_is_refused(self):
        """The receiver equation counted whatever keys the report published; R balanced a class nobody defines."""
        bad = copy.deepcopy(self.good)
        records = bad["conservation"]["receiver_records"]
        records["counts"]["foreign"] = 1
        records["R"] += 1
        found = {v["requirement"] for v in self.check(bad)}
        self.assertIn("S6.4-7", found)

    def test_RED_a_stated_equation_the_counts_refute_is_a_violation(self):
        """The report states equation_holds false while its own instruction entries balance: what the
        report says about its equation must be what its numbers give."""
        bad = copy.deepcopy(self.good)
        bad["conservation"]["instructions"]["equation_holds"] = False
        bad["structural"]["structural_result"] = "INCONCLUSIVE"
        found = {v["requirement"] for v in self.check(bad)}
        self.assertIn("S6.4-3", found)


if __name__ == "__main__":
    unittest.main()
