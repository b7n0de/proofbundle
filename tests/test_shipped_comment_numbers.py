"""Three numbers in shipped artefacts, re-derived instead of remembered (RESTRISIKO_600 R7).

R7 is not "three typos". It is a class: a precise-looking number written into a file that ships,
which no code path and no test ever reads again. Nothing can notice when the thing it counts moves,
so it does not stay wrong, it gets *wronger*, and each correction is itself a fresh snapshot that
starts drifting the moment it lands.

Measured history of exactly these three numbers:

    pyproject.toml   `test_adapters.py` cases    19 written, 10 real at 5.1.0, 10 real at 79f66a2
    MANIFEST.in      conformance cases           14 written, 30 real at 658ed063, 35 real at 79f66a2
    pyproject.toml   `mypy src` source files     63 written, 67 at 658ed063, 68 at the 6.0.0
                                                 candidate, 70 at 79f66a2

The register entry for R7 fell into its own class while describing it: it said "67 source files",
correct at the head it named and already wrong at the release candidate, and an independent lens
found that, not the author. Two of the three numbers drifted AGAIN between the register and 6.1.0.
Correcting them a third time without binding them to a derivation would only schedule a fourth.

So the fix is this file. The numbers are now derived from the tree on every run, and a comment that
disagrees with what it counts fails here instead of shipping. From a distributed sdist the module is
skipped by conftest's derived rule, because the paths below are root-relative.
"""
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]


class TestAShippedCommentNumberIsDerivedNotRemembered(unittest.TestCase):

    def test_the_adapter_case_count_in_pyproject_matches_the_test_file(self):
        gemessen = len(re.findall(r"^\s*def test_", (REPO / "tests" / "test_adapters.py").read_text(),
                                  re.M))
        treffer = re.search(r"`test_adapters\.py` (\d+) of (\d+)",
                            (REPO / "pyproject.toml").read_text())
        self.assertIsNotNone(treffer, "the pyproject comment naming test_adapters.py is gone — if it "
                                      "was removed on purpose, remove this assertion with it")
        behauptet_links, behauptet_rechts = int(treffer.group(1)), int(treffer.group(2))
        self.assertEqual(behauptet_rechts, gemessen,
                         f"pyproject.toml claims {behauptet_rechts} cases in tests/test_adapters.py, "
                         f"the file defines {gemessen}")
        # "N of N" is a pass ratio, so a claim of 10 of 12 is a different failure than a stale total.
        self.assertEqual(behauptet_links, behauptet_rechts,
                         "the comment claims fewer passing cases than it counts")

    def test_the_conformance_case_count_in_the_manifest_matches_the_corpus(self):
        gemessen = len(list((REPO / "conformance" / "agent_review").rglob("case.json")))
        treffer = re.search(r"(\d+) conformance cases under\s*\n?#?\s*conformance/agent_review/",
                            (REPO / "MANIFEST.in").read_text())
        self.assertIsNotNone(treffer, "the MANIFEST comment naming the conformance case count is gone")
        self.assertEqual(int(treffer.group(1)), gemessen,
                         f"MANIFEST.in claims {treffer.group(1)} conformance cases, the corpus holds "
                         f"{gemessen}")

    def test_the_mypy_file_count_in_pyproject_matches_the_source_tree(self):
        # mypy's own figure is what the comment quotes, and mypy counts the .py files it checks under
        # src. Deriving it from the tree keeps this test free of a mypy run, which is minutes.
        gemessen = len(list((REPO / "src").rglob("*.py")))
        treffer = re.search(r"exits 0 over `src` \((\d+) files", (REPO / "pyproject.toml").read_text())
        self.assertIsNotNone(treffer, "the pyproject comment naming the mypy file count is gone")
        self.assertEqual(int(treffer.group(1)), gemessen,
                         f"pyproject.toml claims mypy covers {treffer.group(1)} files under src, the "
                         f"tree holds {gemessen}")


if __name__ == "__main__":
    unittest.main()
