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
import importlib.util
import pathlib
import re
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Every outcome word a pytest summary can carry besides `passed`. `N of N` is a RATIO, so a case
#: that neither passed nor is absent has to appear here. The first version of this file counted
#: `skipped` alone, because a planted skip was the defect that started it -- and `10 passed,
#: 2 xfailed` or `10 passed, 2 deselected` would have sailed straight through the same assertion.
#: Same class, different word, which is why the set is a set and not one name.
NICHT_BESTANDEN = ("skipped", "xfailed", "xpassed", "deselected", "failed", "error", "errors")

#: The claims this file guards, each as (file, pattern). ONE list, so a claim cannot be checked by
#: one case and missed by the other. The ratio case and the structural case walk the same list.
BEHAUPTUNGEN = (
    ("tests/test_adapters.py", r"`test_adapters\.py` (\d+) of (\d+)"),
    ("tests/test_inspect_hook.py", r"`test_inspect_hook\.py` (\d+) of (\d+)"),
)


def flaeche_traegt_die_behauptung() -> bool:
    """Is this the surface the comment's ratio is about?

    The docstring of the ratio case already named the surface. It did not say it to the code.
    MEASURED 2026-09-19 in the hermetic cleanroom, where `inspect_ai` is deliberately absent:
    test_adapters.py reported 6 passed and 4 skipped against a comment that says 10, and
    test_inspect_hook.py 2 passed and 7 skipped against 9. The guard went red over a tree that
    was behaving exactly as intended. A ratio defined on one surface and asserted on every
    surface is this file's own defect wearing the other face: not a number that drifted from its
    tree, but a number applied to a tree it was never about.
    """
    return importlib.util.find_spec("inspect_ai") is not None


def lauf_bilanz(rel: str, wurzel: pathlib.Path) -> tuple[int, dict]:
    """Run one file and read its outcome. Returns (passed, everything that did not pass).

    Named so the gate-meta test below can point it at a planted tree. A reading that only exists
    inside the case that uses it cannot be turned against a planted defect, and a gate nobody can
    aim at a planted defect is a gate nobody has tested.
    """
    import os
    import subprocess
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", rel], capture_output=True, text=True,
                       cwd=str(wurzel), env=dict(os.environ, PYTHONPATH="src"))
    zeile = bilanzzeile(r.stdout)
    bestanden = int(m.group(1)) if (m := re.search(r"(\d+) passed", zeile)) else -1
    andere = {w: int(m2.group(1)) for w in NICHT_BESTANDEN
              if (m2 := re.search(rf"(\d+) {w}\b", zeile))}
    return bestanden, andere


def zeilen_zaehlung(datei: pathlib.Path) -> int:
    """The OLD reading: count `def test_` lines. Kept because the meta test needs both."""
    return len(re.findall(r"^\s*def test_", datei.read_text(), re.M))


def bilanzzeile(stdout: str) -> str:
    """The summary line, SEARCHED FOR rather than assumed to be the last one.

    A counter-reading named the cases: a collection error ends on a traceback line, a missing file
    ends on `ERROR: file or directory not found`, and a plugin may write after the summary. Taking
    the last line turns any of those into "no match", which is red -- fail-closed, but red for the
    wrong reason, and a gate that goes red for the wrong reason is one people learn to re-run.
    """
    return next((z for z in reversed(stdout.splitlines())
                 if re.search(r"\d+ (passed|failed|error|skipped)", z)), "")


class TestAShippedCommentNumberIsDerivedNotRemembered(unittest.TestCase):

    def test_the_case_count_in_pyproject_matches_each_named_test_file(self):
        """BOTH files, and an adversarial reading is the reason it says both.

        The first version checked this for `test_adapters.py` only. `test_inspect_hook.py` carried
        the same shape of claim in the same file and had no structural anchor anywhere: its
        right-hand N was asserted by nothing. A ratio case that measures a RUN cannot see a total
        that changed without changing the run's outcome, so the right-hand number needs its own
        derivation, and one of the two claims did not have one. That is the R7 class turning up
        inside the fix for R7, which is exactly the shape this file is about.
        """
        for rel, muster in BEHAUPTUNGEN:
            with self.subTest(datei=rel):
                gemessen = zeilen_zaehlung(REPO / rel)
                treffer = re.search(muster, (REPO / "pyproject.toml").read_text())
                self.assertIsNotNone(treffer, f"the pyproject comment naming {rel} is gone — if it "
                                              f"was removed on purpose, remove this claim with it")
                behauptet_links, behauptet_rechts = int(treffer.group(1)), int(treffer.group(2))
                self.assertEqual(behauptet_rechts, gemessen,
                                 f"pyproject.toml claims {behauptet_rechts} cases in {rel}, "
                                 f"the file defines {gemessen}")
                self.assertEqual(behauptet_links, behauptet_rechts,
                                 f"{rel}: the comment claims fewer passing cases than it counts")

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
        if not flaeche_traegt_die_behauptung():
            self.skipTest("inspect_ai is absent here, so the conditional skips in both files fire "
                          "by design; the comment's ratio is about the surface where it is "
                          "installed and says nothing about this one")
        for rel, feld in BEHAUPTUNGEN:
            with self.subTest(datei=rel):
                treffer = re.search(feld, (REPO / "pyproject.toml").read_text())
                self.assertIsNotNone(treffer, f"the comment naming {rel} is gone")
                bestanden_behauptet, gesamt_behauptet = int(treffer.group(1)), int(treffer.group(2))
                bestanden, andere = lauf_bilanz(rel, REPO)
                uebersprungen = sum(andere.values())
                zeile = f"{bestanden} passed, {andere}"
                self.assertEqual(bestanden, bestanden_behauptet,
                                 f"{rel}: the comment claims {bestanden_behauptet} passing, the run "
                                 f"reports {bestanden} ({zeile})")
                self.assertEqual(uebersprungen, 0,
                                 f"{rel}: {andere} on this surface, so the comment's "
                                 f"'{bestanden_behauptet} of {gesamt_behauptet}' is not a pass ratio "
                                 f"here ({zeile})")

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


class TestDieBeidenLesungenSelbst(unittest.TestCase):
    """The ratio case cannot check these two on the surface it runs on, so they are checked here."""

    def test_die_flaechenfrage_faellt_wenn_inspect_ai_fehlt(self):
        from unittest import mock
        echt = importlib.util.find_spec
        self.assertTrue(flaeche_traegt_die_behauptung(),
                        "inspect_ai is installed here, so the claim's surface is this one")
        with mock.patch("importlib.util.find_spec",
                        side_effect=lambda n, p=None: None if n.startswith("inspect_ai")
                        else echt(n, p)):
            self.assertFalse(flaeche_traegt_die_behauptung())

    def test_die_bilanzzeile_wird_gesucht_nicht_die_letzte_genommen(self):
        """Each of these ends on something that is not the summary. `[-1]` would miss all four."""
        for schwanz in ("Traceback (most recent call last):",
                        "ERROR: file or directory not found: tests/weg.py",
                        "-- generated xml file: /tmp/x.xml --",
                        ""):
            with self.subTest(schwanz=schwanz):
                aus = "collected 10 items\n\n10 passed in 0.31s\n" + schwanz
                self.assertEqual(bilanzzeile(aus), "10 passed in 0.31s")

    def test_die_bilanz_ohne_ergebniswort_gibt_keine_zeile(self):
        """An output that never reported must not silently read as zero findings."""
        self.assertEqual(bilanzzeile("collected 0 items\n\nno tests ran in 0.01s\n"), "")

    def test_jedes_ergebniswort_wird_gezaehlt_nicht_nur_skipped(self):
        """`10 passed, 2 xfailed` is not a 10-of-10 surface either, and neither is deselected."""
        for wort in ("xfailed", "xpassed", "deselected", "failed"):
            with self.subTest(wort=wort):
                zeile = f"10 passed, 2 {wort} in 0.4s"
                gezaehlt = {w: int(m.group(1)) for w in NICHT_BESTANDEN
                            if (m := re.search(rf"(\d+) {w}\b", zeile))}
                self.assertEqual(sum(gezaehlt.values()), 2,
                                 f"{wort} is not counted, so the ratio would pass over it")


class TestDasTorFaengtEinenGEPFLANZTENSkip(unittest.TestCase):
    """THE ANTI-PARITY, RUN INSTEAD OF ASSERTED. A counter-reading found it was only prose.

    The commit that replaced the line count with a pass ratio said, in its message and in a
    docstring, that a planted skip plus a comment raised to match passes the line count and fails
    the ratio. Nothing in the tree ran that. A later simplification back to counting lines would
    have been caught by nothing, and the claim would have gone on being quoted.

    So it is planted here, in a throwaway tree, and both readings are pointed at it.
    """

    def test_die_zeilenzaehlung_nimmt_ihn_an_die_quote_weist_ihn_ab(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            baum = pathlib.Path(d)
            (baum / "tests").mkdir()
            datei = baum / "tests" / "gepflanzt.py"
            datei.write_text(
                "import unittest\n\n"
                "class T(unittest.TestCase):\n"
                "    def test_a(self):\n        pass\n"
                "    def test_b(self):\n        pass\n"
                "    def test_c(self):\n        self.skipTest('planted')\n",
                encoding="utf-8")
            # A comment writer who counts definitions arrives at three and writes `3 of 3`.
            behauptet = zeilen_zaehlung(datei)
            self.assertEqual(behauptet, 3, "the planted file defines three cases")

            bestanden, andere = lauf_bilanz("tests/gepflanzt.py", baum)

            # THE OLD READING accepts it, and this assertion has to stand INSIDE the block: after
            # it the throwaway tree is gone, and a check written outside would have compared a
            # fallback constant with itself. A tautology reads exactly like a passing case.
            self.assertEqual(zeilen_zaehlung(datei), behauptet,
                             "the line count sees three definitions and agrees with the comment, "
                             "which is precisely why it is not a pass ratio")

        # THE NEW READING refuses it, and says why.
        self.assertEqual(bestanden, 2, f"the run passes two, not three ({andere})")
        self.assertEqual(sum(andere.values()), 1, f"one case did not pass ({andere})")
        self.assertNotEqual(bestanden, behauptet,
                            "the ratio must refuse exactly what the line count accepted — if these "
                            "agree, the anti-parity this file claims does not hold")


if __name__ == "__main__":
    unittest.main()
