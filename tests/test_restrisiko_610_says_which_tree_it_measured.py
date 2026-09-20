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
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
DOKUMENT = REPO / "RESTRISIKO_610.md"
QUELLE = REPO / "src" / "proofbundle" / "evalclaim.py"
TRAEGER = REPO / "tests" / "test_eval_claim_domains_are_enforced.py"

#: The enforcement the A-17 section is about, as it reads in the tree that has it.
DURCHSETZUNG = 'claim.get("commit_alg") != COMMIT_ALG'

#: The one wording that marks a named file as living on another branch.
MARKE = "is not in this tree"


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

    def test_every_named_test_file_either_exists_here_or_says_it_does_not(self):
        """THE CLASS, not the two instances of it that were found by hand.

        A sweep over 119 documents and 352 named source paths turned up ten that are not in this
        tree. Seven of those are honest: six name tooling that lives in another repository or a
        path a checker emitted, and one says in its own sentence that the file is deliberately not
        shipped. Three were this document naming test files that arrive with another pull request,
        and two of them had just been annotated by hand -- which is how the third was still
        sitting there.

        So the rule is derived instead of applied twice: a test file this document names is either
        in this tree, or the document says within the same paragraph that it is not.
        """
        import re
        text = DOKUMENT.read_text(encoding="utf-8")
        absaetze = text.split("\n\n")
        ungedeckt = []
        for absatz in absaetze:
            for treffer in re.findall(r"`(tests/[A-Za-z0-9_./-]+\.py)`", absatz):
                if (REPO / treffer).exists():
                    continue
                # ONE marker, not a list of paraphrases. The first version also accepted the
                # word `absent`, which is in the table and not in the sentence -- a rule that takes
                # several wordings is a pattern over prose, which is the shape this whole cut has
                # been replacing. The document says it one way and this reads that one way.
                #
                # WHITESPACE IS COLLAPSED FIRST, and that is not cosmetic. The marker sat across a
                # line break in one paragraph (`is not in this` / `tree`), so a literal substring
                # search missed a sentence that says exactly the right thing. A rule about WORDS
                # that is written against CHARACTERS is the same defect one more time.
                if MARKE in " ".join(absatz.split()):
                    continue
                ungedeckt.append(treffer)
        self.assertEqual(sorted(set(ungedeckt)), [],
                         "RESTRISIKO_610.md names these test files, they are not in this tree, and "
                         "the paragraph naming them does not say so: "
                         f"{sorted(set(ungedeckt))}")

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
