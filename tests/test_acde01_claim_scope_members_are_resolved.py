"""K9 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K9): an instruction a claim asks for and the
population does not hold prevents a positive claim result.

The interop path keeps the requested ids in the claim scope, but filtered the instructions and evidence it judges
to the population that exists, and did not check that the mapping is complete. A scope of only unknown ids passed
over empty checks, and ["ctrl-1", "not-present"] passed although only ctrl-1 has evidence: PASS,
FULLY_SUPPORTED, assertable (measured at 98b168b9 and f6ea5cc3). An unresolved member now makes the claim
NOT_SUPPORTED and not assertable, and its structural result is not PASS.
"""
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "interop" / "acde_01" / "tools" / "make_run_record.py"


def _tool():
    spec = importlib.util.spec_from_file_location("_k9_make_run_record", TOOL)
    module = importlib.util.module_from_spec(spec)
    before = list(sys.path)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = before
    return module


class AClaimOverUnresolvedMembersIsNotSupported(unittest.TestCase):

    def setUp(self):
        if not TOOL.is_file():
            self.skipTest("interop/acde_01 is not in this tree")
        self.tool = _tool()

    def _claim(self, instructions: list) -> tuple[dict, dict]:
        claim = {"claim_id": "claim", "kind": "complete_delivery", "scope": {"instructions": instructions}}
        report = self.tool.acde01.reconcile.reconcile(self.tool.build.base_run(claims=[claim]))
        return next(c for c in report["claims"] if c["claim_id"] == "claim"), report

    def test_RED_a_scope_of_an_unknown_member_alone_is_not_supported(self):
        """T9: complete_delivery over instructions = ["not-present"]."""
        c, _report = self._claim(["not-present"])
        self.assertNotEqual(c["structural_result"], "PASS", c)
        self.assertEqual((c["claim_support"], c["assertable"]), ("NOT_SUPPORTED", False), c)
        self.assertIn("scope_resolved", [m["predicate"] for m in c["missing_predicates"]])

    def test_RED_a_known_and_an_unknown_member_is_not_supported(self):
        c, _report = self._claim(["ctrl-1", "not-present"])
        self.assertNotEqual(c["structural_result"], "PASS", c)
        self.assertEqual((c["claim_support"], c["assertable"]), ("NOT_SUPPORTED", False), c)

    def test_CONTROL_the_known_member_alone_passes_and_the_report_checks_clean(self):
        c, report = self._claim(["ctrl-1"])
        self.assertEqual((c["structural_result"], c["claim_support"], c["assertable"]),
                         ("PASS", "FULLY_SUPPORTED", True), c)
        self.assertEqual(self.tool.acde01.report_check.check_report(report), [])

    def _failure_claim(self, target: str) -> dict:
        """The run of vector R-22 (EP-B fails verification) with a scoped failure claim on ctrl-1/<target>."""
        b = self.tool.build
        records = [b.issuer(), b.receiver("rcv-a", "EP-A"), b.receiver("rcv-b", "EP-B", event="verification_failed")]
        claim = {"claim_id": "fb", "kind": "scoped_failure",
                 "scope": {"instructions": ["ctrl-1"], "obligation": ["ctrl-1", target],
                           "fact": f"{target} did not accept ctrl-1 attempt a1"}}
        report = self.tool.acde01.reconcile.reconcile(b.base_run(records, claims=[claim]))
        return next(c for c in report["claims"] if c["claim_id"] == "fb")

    def test_RED_a_named_obligation_the_population_does_not_hold_is_not_supported(self):
        """The same class one level down in the same file: a scope naming one obligation that does not exist fell
        back to any failing obligation in scope, so EP-B's failure supported a claim about EP-X."""
        c = self._failure_claim("EP-X")
        self.assertEqual((c["claim_support"], c["assertable"]), ("NOT_SUPPORTED", False), c)
        self.assertIn("scope_resolved", [m["predicate"] for m in c["missing_predicates"]])

    def test_CONTROL_the_named_failing_obligation_is_supported(self):
        c = self._failure_claim("EP-B")
        self.assertEqual((c["claim_support"], c["structural_result"]), ("FULLY_SUPPORTED", "FAIL"), c)

    def test_RED_a_path_the_population_does_not_hold_is_not_supported_under_a_conditional_profile(self):
        """The same class for the path of a preserved_disposition claim: under a valid profile that declares
        lossless_path conditional, a path that does not exist left the claim CONDITIONALLY_SUPPORTED and
        assertable."""
        b = self.tool.build
        profile = copy.deepcopy(b.example_profile())
        profile["claims"]["conditional_predicates"] = ["observer_authority_verified", "coverage_verified",
                                                       "lossless_path"]
        profile["claims"]["mandatory_predicates"]["preserved_disposition"] = []
        claim = {"claim_id": "pd", "kind": "preserved_disposition",
                 "scope": {"instructions": ["ctrl-1"], "path_id": "not-present"}}
        report = self.tool.acde01.reconcile.reconcile(b.base_run(claims=[claim], profile=profile))
        self.assertEqual(report["profile"]["errors"], [], "precondition: the profile is valid")
        c = next(x for x in report["claims"] if x["claim_id"] == "pd")
        self.assertEqual((c["claim_support"], c["assertable"]), ("NOT_SUPPORTED", False), c)
        self.assertIn("scope_resolved", [m["predicate"] for m in c["missing_predicates"]])

    def test_CONTROL_the_report_of_an_unresolved_claim_checks_clean(self):
        _c, report = self._claim(["ctrl-1", "not-present"])
        self.assertEqual(self.tool.acde01.report_check.check_report(report), [])


if __name__ == "__main__":
    unittest.main()
