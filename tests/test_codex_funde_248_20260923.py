"""Catch proofs for the three Codex findings on PR #248 (review of 2026-09-23 on `a8b93ca`).

All three are one shape of defect at three sites: a check looks at the CONTAINER and not at what
is inside it, or takes a branch that silences the invariants beside it. Each case reproduces the
reported document against the real entry point, and each carries the neighbours that the reported
value was only one of, because fixing the reported spelling alone leaves the class open.
"""
from __future__ import annotations

import unittest

from proofbundle.agent_review import _COVERAGE_FIELDS_V02, _validate_coverage
from proofbundle.cap1 import check_cap1_document


def _doc(**stratum):
    """A PV-01-shaped, otherwise conformant document; each case changes one place."""
    s = {
        "id": "S1", "eligible": 6, "examined": 4,
        "basis": {"kind": "declared"}, "supports": ["absence-of-secret"],
        "unexamined": [{"unit": "a.ts", "disposition": "out_of_scope"},
                       {"unit": "b.ts", "disposition": "out_of_scope"}],
    }
    s.update(stratum)
    return {"profile": "cap/1", "subject": {"ref": "sha256:abc"}, "strata": [s],
            "integrity": {"complete": True}, "absence_assertions": [{"stratum": "S1"}]}


def _cap_block():
    return {"strata": [{"id": "S1", "eligible": 4, "examined": 4,
                        "basis": {"kind": "declared"}, "supports": ["absence-of-secret"],
                        "unexamined": []}],
            "integrity": {"complete": True}}


class R1CountsUnitsNotRows(unittest.TestCase):
    """R1 accounts for UNITS. Counting rows measures the length of a list."""

    def test_control_the_unchanged_document_is_conformant(self):
        """Without this the catches below would also pass for a rule that refuses everything."""
        self.assertEqual(check_cap1_document(_doc()), [])

    def test_catch_two_rows_naming_the_same_unit(self):
        """The reported case. Before the fix this returned [].

        `eligible: 6` and `examined: 4` worked out against two ROWS, while only ONE unit was
        accounted for, so a second eligible unit could disappear and R1 still read as satisfied.
        """
        errs = check_cap1_document(_doc(unexamined=[
            {"unit": "pdf.ts", "disposition": "out_of_scope"},
            {"unit": "pdf.ts", "disposition": "out_of_scope"}]))
        self.assertTrue(errs, "two rows over one unit passed")
        gruende = " ".join(e["reason"] for e in errs)
        self.assertIn("mehrfach", gruende, "the duplicate itself is not named")
        self.assertIn("plus 1", gruende, "the count does not use distinct units")

    def test_the_arithmetic_still_holds_when_the_units_differ(self):
        """The counter-direction for the same numbers: two rows, two units, no complaint."""
        self.assertEqual(check_cap1_document(_doc()), [])


class R8ValidatesTheElementsNotOnlyTheList(unittest.TestCase):
    """R8 asks the stratum to NAME classes. A non-empty list of nothing is a list, not a naming."""

    def test_catch_supports_with_a_null_element(self):
        """The reported case. Before the fix this returned []."""
        errs = check_cap1_document(_doc(supports=[None]))
        self.assertTrue(errs, "supports [null] passed")
        self.assertTrue(any(e["rule"] == "R8-supports-bounds-citation" for e in errs))

    def test_catch_the_neighbours_the_reported_value_was_one_of(self):
        """Measured before the fix: five values passed, not one.

        Fixing `null` alone would have left four of them open, which is the difference between
        closing a defect and closing its class.
        """
        for wert in ([""], [7], [[]], [{}], ["absence-of-secret", None]):
            with self.subTest(supports=wert):
                errs = check_cap1_document(_doc(supports=wert))
                self.assertTrue(errs, f"supports {wert!r} passed")

    def test_counter_direction_a_real_naming_passes(self):
        """A list of non-empty strings is what the rule asks for, and it must stay quiet."""
        self.assertEqual(check_cap1_document(_doc(supports=["absence-of-secret", "no-pii"])), [])


class LegacyAliasesMayNotContradictThemselves(unittest.TestCase):
    """With a CAP block present, the old fields are not DEMANDED. What is read must still hold."""

    ZUSATZ = _COVERAGE_FIELDS_V02

    def test_catch_complete_with_zero_of_a_hundred_and_a_gap(self):
        """The reported case. Before the fix this produced no error at all.

        The early return handed the section to CAP-1 and took the legacy fields out of every check
        on the way, so a signed, self-contradicting coverage block could change the policy verdict.
        """
        cov = {**_cap_block(), "status": "COMPLETE", "observedRuns": 0, "expectedRuns": 100,
               "knownGaps": ["96 runs were not observed"], "sources": ["ci"], "window": "2026-09",
               "collectionMethod": "replay"}
        errs = _validate_coverage(cov, zusatz=self.ZUSATZ)
        self.assertTrue(errs, "a contradicting coverage block passed")
        text = " ".join(errs)
        self.assertIn("observedRuns 0 < expectedRuns 100", text)
        self.assertIn("knownGaps", text)

    def test_both_paths_answer_the_same(self):
        """The compatibility promise is that the aliases KEEP THEIR MEANING.

        A meaning that holds in one branch and not in the other is not kept, it is dropped. The
        property bound here is therefore the EQUALITY of the two verdicts, not the wording of
        either.
        """
        gemeinsam = {"status": "COMPLETE", "observedRuns": 0, "expectedRuns": 100,
                     "knownGaps": ["96 runs were not observed"], "sources": ["ci"],
                     "window": "2026-09", "collectionMethod": "replay"}
        mit = {**_cap_block(), **gemeinsam}
        widersprueche = lambda errs: sorted(  # noqa: E731
            e for e in errs if "observedRuns" in e or "knownGaps" in e)
        self.assertEqual(
            widersprueche(_validate_coverage(mit, zusatz=self.ZUSATZ)),
            widersprueche(_validate_coverage(dict(gemeinsam), zusatz=self.ZUSATZ)),
            "the same legacy contradiction is judged differently with and without a CAP block")

    def test_catch_complete_over_an_empty_expectation(self):
        """A neighbour of the same class, also silent before the fix."""
        cov = {**_cap_block(), "status": "COMPLETE", "observedRuns": 0, "expectedRuns": 0,
               "sources": ["ci"], "window": "w", "collectionMethod": "m"}
        self.assertTrue(_validate_coverage(cov, zusatz=self.ZUSATZ))

    def test_the_cap_block_still_governs_what_is_demanded(self):
        """THE DESIGN MUST SURVIVE THE FIX, and this is the case that holds it.

        With strata present nothing demands `observedRuns`, `expectedRuns`, `sources`, `window`
        or `collectionMethod`. A repair that started demanding them would have turned a silence
        into a wall and broken every conformant CAP-1 document.
        """
        cov = {**_cap_block(), "status": "COMPLETE"}
        self.assertEqual(_validate_coverage(cov, zusatz=self.ZUSATZ), [],
                         "a plain CAP block with a matching status was refused")


if __name__ == "__main__":
    unittest.main()
