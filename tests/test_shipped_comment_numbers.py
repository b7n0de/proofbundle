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
import sys
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
        self.assertEqual(behauptet_links, behauptet_rechts,
                         "the comment claims fewer passing cases than it counts")

    def test_the_pass_ratio_is_measured_by_running_the_cases_not_by_counting_lines(self):
        """`N of N` is a PASS RATIO, and a line count is not one.

        An external review lens caught the first version of this file doing exactly what the finding
        it fixes is about: substituting a structural proxy for the property. Reproduced at `b7e5705`
        — add a skipped case to tests/test_adapters.py, write "11 of 11" in the comment, and the
        guard passed while the run reported 10 passed and 1 skipped. A skipped case was certified as
        a pass.

        A first repair forbade skip markers outright, and measuring said no. Both files carry
        CONDITIONAL skips (`inspect_ai not installed`) that are correct and do not fire where the
        claim applies. Forbidding them would turn a true comment red, which is the mirror-image
        error.

        So the ratio is measured by running the cases. That costs about a second per file and it is
        the only thing that answers the question the comment asks. The environment matters and is
        named: this is the surface where `inspect_ai` is installed, which is the surface the comment
        is about.
        """
        import os
        import subprocess
        umgebung = dict(os.environ, PYTHONPATH="src")
        for rel, feld in (("tests/test_adapters.py", r"`test_adapters\.py` (\d+) of (\d+)"),
                          ("tests/test_inspect_hook.py", r"`test_inspect_hook\.py` (\d+) of (\d+)")):
            with self.subTest(datei=rel):
                treffer = re.search(feld, (REPO / "pyproject.toml").read_text())
                self.assertIsNotNone(treffer, f"the comment naming {rel} is gone")
                bestanden_behauptet, gesamt_behauptet = int(treffer.group(1)), int(treffer.group(2))
                r = subprocess.run([sys.executable, "-m", "pytest", "-q", rel],
                                   capture_output=True, text=True, cwd=str(REPO), env=umgebung)
                zeile = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
                bestanden = int(m.group(1)) if (m := re.search(r"(\d+) passed", zeile)) else -1
                uebersprungen = int(m2.group(1)) if (m2 := re.search(r"(\d+) skipped", zeile)) else 0
                self.assertEqual(bestanden, bestanden_behauptet,
                                 f"{rel}: the comment claims {bestanden_behauptet} passing, the run "
                                 f"reports {bestanden} ({zeile})")
                self.assertEqual(uebersprungen, 0,
                                 f"{rel}: {uebersprungen} case(s) skipped here, so the comment's "
                                 f"'{bestanden_behauptet} of {gesamt_behauptet}' is not a pass ratio "
                                 f"on this surface ({zeile})")

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
