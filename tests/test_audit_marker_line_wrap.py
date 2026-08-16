"""RT10-PRETAG-03: the audit-marker negation guard must not be defeated by ordinary line wrapping.

`_positive_audit_marker` decides whether a release has recorded its pre-tag adversarial audit. It looks
for a discipline marker (`N-lens`, `adversarial`, `master-prompt`, `Linsen`) that is not negated. The
scope of "not negated" used to be the physical LINE.

HOW IT WAS FOUND, which matters more than the fix: by triggering it. While writing an honest retraction
into a release candidate's CHANGELOG — a paragraph whose whole point is that the audit had NOT finished —
the gate flipped to `ok: true, changelog_records_audit: true` and stayed there for about two minutes.
Nothing was crafted. Prose wrapped at 110 columns put the word `adversarial` at the start of a line, and
the words that take it back stayed on the line above.

That is the sharp edge of the class: the guard was most easily defeated by exactly the kind of careful,
self-critical text the project requires of itself. A release could have been tagged on the strength of a
sentence admitting it was not ready.
"""
from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load(mod_name: str, rel: str):
    """Same loader shape the rest of the suite uses for `scripts/` (see test_roadmap_frontload_foundations)."""
    spec = importlib.util.spec_from_file_location(mod_name, REPO / rel)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


gate = _load("marker_wrap_pretag_gate", "scripts/pre_tag_audit_gate.py")


def _line_scoped(text: str) -> bool:
    """The rule as it stood before this fix, kept so both directions can be measured, not asserted."""
    for line in text.splitlines():
        if gate._AUDIT_MARKERS.search(line) and not gate._AUDIT_NEGATION.search(line):
            return True
    return False


# The exact two lines that flipped the live gate. Reproduced verbatim rather than described, so this
# test fails for the reason it names if the wrapping ever stops mattering.
DER_LIVE_FALL = (
    "…never shipped a user-facing CLI flag in a patch release. That claim was falsified during the pre-tag\n"
    "adversarial audit and is retracted here rather than quietly deleted: four patch releases have shipped"
)


class TestWrappedNegationNoLongerGrantsPass(unittest.TestCase):

    def test_the_live_case_is_now_rejected(self):
        self.assertFalse(gate._positive_audit_marker(DER_LIVE_FALL),
                         "a wrapped retraction still certifies the audit it retracts")

    def test_counter_check_the_old_rule_really_did_accept_it(self):
        """Without this, the test above could be green because the corpus is harmless.

        A fix test that never demonstrates the defect is a test that measures nothing. This one shows the
        previous rule saying yes to the same bytes.
        """
        self.assertTrue(_line_scoped(DER_LIVE_FALL),
                        "the pre-fix rule does not reproduce the defect — the fixture no longer discriminates")

    def test_a_genuine_record_is_still_accepted(self):
        """A stricter gate that rejects real records would just be a different defect.

        The committed 3.7.0 record is the house style: its opening paragraph pairs the claim with a
        "NOT a substitute for the external audit" disclaimer, and a later paragraph carries the marker
        cleanly. Paragraph scope must count the second and not the first.
        """
        echt = REPO / "audit_artifacts" / "370" / "pre_tag_adversarial_audit_370.md"
        if not echt.is_file():
            self.skipTest(f"reference record absent: {echt} — measuring nothing is not a pass")
        text = echt.read_text(encoding="utf-8")
        self.assertTrue(gate._positive_audit_marker(text),
                        "the fix rejects a real, committed pre-tag audit record")

    def test_the_original_single_line_negation_still_holds(self):
        """RT10-PRETAG-02 must not regress: a negated marker on one line stays a non-attestation."""
        for text in ("the adversarial audit did NOT run",
                     "adversarial review pending",
                     "the 6-lens jury has not completed",
                     "master-prompt audit skipped for this release",
                     "Linsen-Lauf noch nicht durchgefuehrt"):
            with self.subTest(text=text):
                self.assertFalse(gate._positive_audit_marker(text), f"negated marker granted a pass: {text}")

    def test_the_new_scope_is_strictly_stricter(self):
        """The property that makes this a safe change: accepted(new) is a SUBSET of accepted(old).

        A paragraph contains its own lines, so widening the scope can only bring more negation tokens into
        view. Anything the old rule rejected must stay rejected. Asserted over a corpus rather than argued,
        because "obviously monotone" is how a loosening slips in.
        """
        korpus = [
            DER_LIVE_FALL,
            "six-lens adversarial audit run before the tag",
            "adversarial audit\nnot completed",                 # wrap, negation AFTER the marker
            "not completed\nadversarial audit",                 # wrap, negation BEFORE the marker
            "clean prose with no marker at all",
            "adversarial\n\nnot completed",                     # separate paragraphs: marker survives
            "| F7 | target | holds | a 6-lens pass |\n| F8 | other | fell | not run |",
            "",
            "adversarial audit run.\n\nA later paragraph says the release is not ready.",
        ]
        for text in korpus:
            with self.subTest(text=text[:48]):
                if gate._positive_audit_marker(text):
                    self.assertTrue(_line_scoped(text),
                                    "the new rule accepts text the old rule rejected — this is a LOOSENING, "
                                    "not a hardening")

    def test_a_separate_paragraph_still_carries_its_own_attestation(self):
        """Paragraph scope must not become file scope, or one disclaimer anywhere would kill every record.

        This is the boundary the fix has to hit exactly: strict enough that a wrapped retraction cannot
        certify itself, loose enough that an unrelated caveat elsewhere in the document does not suppress a
        genuine attestation. It is the same intent RT10-PRETAG-02 stated for lines, moved up one level.
        """
        text = ("A six-lens adversarial audit ran on this candidate.\n"
                "\n"
                "This is not a substitute for the external human audit.\n")
        self.assertTrue(gate._positive_audit_marker(text),
                        "an unrelated caveat in a DIFFERENT paragraph suppressed a genuine attestation")

    def test_meta_reverting_the_fix_makes_this_file_fail(self):
        """PLANT-AND-MUST-CATCH: with the line-scoped rule restored, the live case must go red again.

        Without this, a future refactor could quietly restore line scope and every test above would still
        pass on its own terms — the file would keep asserting a property it no longer measures.
        """
        gemessen = _line_scoped(DER_LIVE_FALL)
        self.assertTrue(gemessen,
                        "the restored pre-fix rule no longer accepts the live case, so this file can no "
                        "longer tell the two rules apart")
        self.assertNotEqual(gemessen, gate._positive_audit_marker(DER_LIVE_FALL),
                            "the two rules agree on the defect case — the fix has no effect")


class TestParagraphSplitIsTheDocumentedOne(unittest.TestCase):
    """The split must be blank-line separated paragraphs, measured rather than assumed from the docstring."""

    def test_a_blank_line_separates_scopes(self):
        verbunden = "adversarial audit\nnot completed"
        getrennt = "adversarial audit\n\nnot completed"
        self.assertFalse(gate._positive_audit_marker(verbunden), "same paragraph: negation must apply")
        self.assertTrue(gate._positive_audit_marker(getrennt), "different paragraph: negation must not apply")

    def test_whitespace_only_lines_also_separate(self):
        """A line of spaces looks blank in an editor and must behave that way, or the scope depends on
        invisible characters."""
        self.assertTrue(gate._positive_audit_marker("adversarial audit\n   \nnot completed"),
                        "a whitespace-only line did not separate paragraphs")
        self.assertTrue(re.split(r"\n\s*\n", "a\n \nb").__len__() == 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
