"""RESTRISIKO_610.md states which tree a closure was measured in. That statement is derived here.

A-17 was listed under "Closed during the cut" while the code that closes it and the file named as
its carrier were both on a different branch. A counter-reading found it by RUNNING the claim: it
emitted a receipt with `commit_alg: "sha1-unsalted"` on this tree and the CLI answered `=> OK`,
while the section said `sha1-unsalted rejected`.

The document was corrected to name where the fix lives and to carry the measurement as a table.
That correction was prose about a tree, and nothing read it back -- the exact shape this cut has
been closing all day, one level up. So the row of that table describing THIS tree is derived from
this tree.

It is deliberately only that row. The other two rows describe `main` and another branch, and a test
that reaches for a foreign ref answers about whatever the checkout happens to carry (an
already-measured defect of the English gate in this same cut). The row about the tree the reader is
standing in is the one that can be wrong without anyone noticing.
"""
from __future__ import annotations

import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
DOKUMENT = REPO / "RESTRISIKO_610.md"
QUELLE = REPO / "src" / "proofbundle" / "evalclaim.py"
TRAEGER = REPO / "tests" / "test_eval_claim_domains_are_enforced.py"

#: The enforcement the A-17 section is about, as it reads in the tree that has it.
DURCHSETZUNG = 'claim.get("commit_alg") != COMMIT_ALG'

#: The one wording that marks a named file as living on another branch.
#: The one line in which the document declares the set. A declaration is a set, not a
#: phrase near a word: a marker in a paragraph covers whatever else that paragraph
#: happens to name, which a counter-reading demonstrated with two missing files and
#: one marker between them.
ERKLAERUNG = "**Named here but not in this tree:**"


class TestTheRiskDocumentSaysWhichTreeItIsIn(unittest.TestCase):

    def setUp(self):
        if not DOKUMENT.is_file():
            self.skipTest(f"{DOKUMENT.name} is not in this tree — a distributed artefact prunes it")

    def _zeile_ueber_diesen_baum(self) -> str:
        text = DOKUMENT.read_text(encoding="utf-8")
        treffer = [z for z in text.splitlines() if z.strip().startswith("| this branch")]
        self.assertEqual(len(treffer), 1,
                         "the table row describing the tree this document sits in is gone or "
                         f"duplicated ({len(treffer)} matches) — if the table was removed on "
                         "purpose, remove this test with it")
        return treffer[0]

    def test_the_row_about_this_tree_matches_this_tree(self):
        """`absent` and `present` in that row are checked against the files they talk about."""
        zeile = self._zeile_ueber_diesen_baum()
        felder = [f.strip() for f in zeile.strip().strip("|").split("|")]
        self.assertEqual(len(felder), 3, f"expected three columns, got {felder}")
        _, gesagt_durchsetzung, gesagt_traeger = felder

        hat_durchsetzung = QUELLE.is_file() and DURCHSETZUNG in QUELLE.read_text(encoding="utf-8")
        hat_traeger = TRAEGER.is_file()

        for gesagt, wirklich, was in ((gesagt_durchsetzung, hat_durchsetzung, "the enforcement"),
                                      (gesagt_traeger, hat_traeger, "the carrier file")):
            with self.subTest(was=was):
                self.assertIn(gesagt, ("absent", "present"),
                              f"the table says {gesagt!r} about {was}, and only `absent` or "
                              f"`present` can be checked")
                self.assertEqual(gesagt == "present", wirklich,
                                 f"RESTRISIKO_610.md says {was} is {gesagt} in this tree, and it "
                                 f"is {'present' if wirklich else 'absent'}")

    def test_the_files_named_but_absent_are_declared_as_a_set(self):
        """THE SET, derived -- not a marker phrase read out of the surrounding prose.

        The first version of this rule required the paragraph naming a missing file to contain
        `is not in this tree`. A counter-reading took it apart with two executed cases:

            one paragraph naming TWO missing files and carrying the marker once covered BOTH,
            because the marker belongs to the paragraph and not to the file it was written for

            the pattern required backticks, so `**tests/x.py**`, a markdown link and a bare
            mention all walked past it

Both are the same defect: a rule about prose, written against the shape prose happened to have
        that day. So the document declares the set instead, this derives the set, and the two are
        compared. A file named in any form is found, and a declaration covers exactly the file it
        names.
        """
        text = DOKUMENT.read_text(encoding="utf-8")
        if "sha1-unsalted` rejected" not in text:
            self.skipTest("the A-17 closure sentence is gone, and with it the section this "
                          "declaration serves; there is no set left to declare")
        genannt = set(re.findall(r"tests/[A-Za-z0-9_][A-Za-z0-9_./-]*\.py", text))
        gemessen = {t for t in genannt if not (REPO / t).exists()}

        zeile = [z for z in text.splitlines() if z.startswith(ERKLAERUNG)]
        self.assertEqual(len(zeile), 1,
                         f"the document declares the set of files it names but does not carry "
                         f"exactly once ({len(zeile)} lines start with {ERKLAERUNG!r})")
        erklaert = set(re.findall(r"tests/[A-Za-z0-9_][A-Za-z0-9_./-]*\.py", zeile[0]))

        # EMPTY AGAINST EMPTY IS NOT AGREEMENT. Both sides are the same regex over the same text,
        # so an edit that turns the paths into prose empties BOTH and the comparison stays green
        # while the line still announces a set. A counter-reading did exactly that: it replaced
        # every path in the document with a phrase, and the declaration went on saying "Named here
        # but not in this tree:" about nothing. A declaration that declares nothing is the state
        # this rule exists to catch, not a state it may pass.
        self.assertTrue(
            erklaert,
            f"the document carries {ERKLAERUNG!r} and names no file after it — either it declares "
            f"a set or the line goes when the section does")

        self.assertEqual(
            erklaert, gemessen,
            "RESTRISIKO_610.md declares which of the test files it names are not in this tree, and "
            f"the tree disagrees.\n  declared but present: {sorted(erklaert - gemessen)}"
            f"\n  absent but undeclared: {sorted(gemessen - erklaert)}")

    def test_the_section_does_not_claim_the_closure_without_naming_where_it_lives(self):
        """The sentence and its condition have to travel together, or the sentence travels alone."""
        text = DOKUMENT.read_text(encoding="utf-8")
        if "sha1-unsalted` rejected" not in text:
            self.skipTest("the A-17 closure sentence is gone; nothing left to bind")
        self.assertRegex(
            text, r"WHERE THAT FIX LIVES",
            "the section states the closure but no longer says which tree it was measured in — "
            "that is the defect this file exists against")


if __name__ == "__main__":
    unittest.main()
