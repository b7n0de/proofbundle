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
import json
import pathlib
import re
import shutil
import sys
import tempfile
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


#: A pytest plugin, written to a throwaway directory at call time, that records the outcome of
#: every case FROM PYTEST'S OWN REPORTS and writes the counts as JSON.
#:
#: WHY NOT THE JUNIT REPORT, which this file used for exactly one commit. MEASURED 2026-09-20 on a
#: planted file carrying one of every outcome: stdout said `2 passed, 1 skipped, 1 deselected,
#: 1 xfailed, 1 xpassed, 1 error` while the JUnit attributes said `tests=6 failures=0 errors=1
#: skipped=2`. JUnit folds `xfailed` into `skipped` and counts `xpassed` as a passing test, so
#: `tests - failures - errors - skipped` returned THREE where two cases passed. `xpassed` is the
#: precise word this file's vocabulary was written for -- a case that was expected to fail and did
#: not is not a pass -- and the structured channel silently dropped it. A report format is a proxy
#: too if it cannot express the distinction the question is about.
#:
#: `--report-log` would carry it, and this pytest does not have the option (measured: zero hits in
#: `--help`). So the outcomes are taken where they are decided, in `pytest_runtest_logreport`.
ZAEHLER_PLUGIN = '''
import json, os
_z = {}


def pytest_runtest_logreport(report):
    if report.when == "call":
        wx = getattr(report, "wasxfail", None) is not None
        art = ("xpassed" if (wx and report.outcome == "passed")
               else "xfailed" if wx else report.outcome)
    elif report.outcome == "failed":
        art = "error"
    else:
        return
    _z[art] = _z.get(art, 0) + 1


def pytest_sessionfinish(session, exitstatus):
    # THE EXIT STATUS TRAVELS WITH THE COUNTS. Without it an aborted run is indistinguishable
    # from a complete one: the file holds whatever was counted before the abort, and the number
    # depends on the order the cases happened to run in.
    _z["_exitstatus"] = int(exitstatus)
    # ONLY THE CONTROLLER WRITES. Under xdist every worker runs this plugin and every worker would
    # write the same path, so the file would hold whichever partial set finished last. The
    # controller receives every worker's report through the same hook, so its set is the complete
    # one; a worker carries `workerinput` on its config and the controller does not.
    #
    # THIS GUARD IS UNBOUND, and saying so is the point of this paragraph. MEASURED 2026-09-20 on
    # a twelve-case file, four configurations: guard present and guard removed, at `-n 2` and at
    # `-n 4`. All four wrote `passed: 12`. With xdist 3.8.0 the controller's `sessionfinish` runs
    # after the workers', so its complete set overwrites their partial ones and the guard changes
    # nothing observable. No case in this file fails if this guard is deleted.
    #
    # It stays because the ordering it relies on is not promised anywhere, and a race that
    # happens to fall the right way is not a result. But an unobservable safeguard is reasoning,
    # not a measured invariant, and a reader who mistakes the one for the other will trust it
    # further than it has earned. A counter-reading found this by looking for the negative control
    # and not finding one.
    if hasattr(session.config, "workerinput"):
        return
    ziel = os.environ.get("PB_ZAEHLER_ZIEL")
    if ziel:
        with open(ziel, "w", encoding="utf-8") as f:
            json.dump(_z, f)
'''


def _pytest(wurzel: pathlib.Path, *args: str, zaehler: pathlib.Path | None = None) -> tuple[int, str]:
    import os
    import subprocess
    umgebung = dict(os.environ, PYTHONPATH="src")
    zusatz: list[str] = []
    if zaehler is not None:
        plugdir = zaehler.parent / "plug"
        plugdir.mkdir(exist_ok=True)
        (plugdir / "pb_zaehler.py").write_text(ZAEHLER_PLUGIN, encoding="utf-8")
        umgebung["PYTHONPATH"] = f"src{os.pathsep}{plugdir}"
        umgebung["PB_ZAEHLER_ZIEL"] = str(zaehler)
        zusatz = ["-p", "pb_zaehler"]
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", *zusatz, *args],
                       capture_output=True, text=True, cwd=str(wurzel), env=umgebung)
    return r.returncode, r.stdout


def lauf_bilanz(rel: str, wurzel: pathlib.Path) -> tuple[int, dict]:
    """Run one file and read its outcome from pytest's reports. Returns (passed, everything else).

    Three readings of this stood here before, and the first two were rules over stdout. Both were
    defeated by ordinary constructs that print a complete summary line AFTER pytest's own -- an
    `atexit` hook in a conftest, a `pytest_sessionfinish` wrapper printing after its yield. The
    third read the JUnit report and dropped `xpassed`, which is the one word this file's vocabulary
    exists for. See ZAEHLER_PLUGIN above for the measurement.
    """
    with tempfile.TemporaryDirectory() as d:
        ziel = pathlib.Path(d) / "zaehler.json"
        rc, _aus = _pytest(wurzel, rel, zaehler=ziel)
        if not ziel.is_file():
            return -1, {"kein_bericht": 1}
        z = json.loads(ziel.read_text(encoding="utf-8"))

    # A RUN THAT DID NOT FINISH IS NOT A RESULT, and this is the third channel in this file to
    # need saying so. MEASURED 2026-09-20: one file whose first case calls `pytest.exit()` gave
    # `bestanden=1` and `bestanden=0` across five runs of the SAME file -- `pytest-randomly`
    # decides which case ran before the abort, and nothing in the answer said the run stopped.
    # The counts were real; what was missing was that they were partial.
    #
    # 0 and 1 are the two codes that mean the session ran to the end (all passed, some failed).
    # 2 interrupted, 3 internal error, 4 usage error, 5 nothing collected -- for a ratio over a
    # named file every one of those is a refusal, not a number.
    status = z.pop("_exitstatus", None)
    if status not in (0, 1) or rc not in (0, 1):
        return -1, {"lauf_unvollstaendig": 1, "exitstatus": status, "rc": rc}

    bestanden = z.pop("passed", 0)
    return bestanden, {k: v for k, v in sorted(z.items()) if v}


def gesammelte_faelle(rel: str, wurzel: pathlib.Path) -> int:
    """How many cases this file HAS -- asked of the collector, not derived from the source.

    THIS REPLACES A PROXY THAT LEAKED TWICE. A syntax-tree counter was written because the ratio
    case skips where `inspect_ai` is absent and something had to hold the right-hand number there.
    It was wrong about a class carrying `__init__`, about `def test_` inside a docstring and about
    `parametrize`; each was fixed, and a counter-reading then produced FIVE more shapes it still
    got wrong, all counting MORE than the run -- the direction that reads green:

        a class whose name does not match `python_classes`   counted 2, the run passed 1
        `__test__ = False` on a class                        counted 3, the run passed 1
        `__test__ = False` on a function                     counted 2, the run passed 1
        a `Test*` class nested inside another                counted 2, the run passed 1
        `async def test_` with no async backend              counted 2, the run passed 1

    Every one is pytest collection semantics a syntax tree does not carry. A proxy that needs a new
    exception each time somebody reads it harder is not cheaper than the thing it stands for.

    MEASURED 2026-09-20, and it is what makes the replacement possible: `--collect-only` returns
    9 and 10 for the two claimed files BOTH with and without `inspect_ai` installed. Collection
    does not run conditional skips, so the reason the proxy existed does not survive the
    measurement.

    THE `N/M` FORM IS THE COUNT AFTER DESELECTION. Measured: with one case deselected the line
    reads `6/7 tests collected (1 deselected)`, and a pattern anchored on `(\d+) tests? collected`
    returns SEVEN -- the total before deselection, which is not what ran and not what the comment
    is about.
    """
    rc, aus = _pytest(wurzel, rel, "--collect-only")
    treffer = re.search(r"(?:(\d+)/)?(\d+) tests? collected", aus)
    if treffer is None:
        raise AssertionError(f"the collector reported no count for {rel} (rc={rc}):\n{aus[-600:]}")
    return int(treffer.group(1) or treffer.group(2))


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
                gemessen = gesammelte_faelle(rel, REPO)
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

    def test_the_corpus_size_in_the_cross_implementation_report_matches_the_manifest(self):
        """A fourth claim, added because a neighbour sweep found the third correction already stale.

        MEASURED 2026-09-20: `conformance/manifest.json` lists 130 cases and the tree holds 130
        `case.json` files -- two readings, one number. CROSS_IMPLEMENTATION_REPORT.md said `57 of
        107`, and that document itself records how the same sentence was corrected on 2026-09-08
        after a lens found it. Twelve days later the correction was wrong again, and two further
        documents under docs/readiness_pack/ still carry the form the report had already rejected.

        Correcting a number a third time without binding it schedules the fourth, which is this
        file's whole thesis. So the report's figure is derived here. The two readiness_pack
        neighbours are NOT bound here: `docs/readiness_pack/MANIFEST.sha256` carries their hashes
        and another change is in flight against that manifest, so touching them from here would
        collide. They are carried in the register instead.
        """
        faelle = json.loads((REPO / "conformance" / "manifest.json").read_text())["cases"]
        # THE TYPE, not just the length. `len` of a dict counts its keys and says nothing, so a
        # migration from a list to an id-keyed mapping would pass here whenever the key count
        # happened to match -- a silent agreement between two different things.
        self.assertIsInstance(faelle, list,
                              f"conformance/manifest.json `cases` is {type(faelle).__name__}, and "
                              f"only a list is a corpus this number can be taken from")
        gemessen = len(faelle)
        text = (REPO / "CROSS_IMPLEMENTATION_REPORT.md").read_text()
        # EVERY occurrence, not the first. A counter-reading planted a second, stale sentence
        # further down ("an earlier revision said ... 999 cases") and `re.search` never looked at
        # it: the document contradicted itself and the gate was green. A document that says a
        # number twice has to say it the same way twice.
        alle = re.findall(r"\*\*The corpus holds (\d+) cases today\*\*", text)
        self.assertTrue(alle, "the sentence naming the corpus size is gone — if it was "
                              "removed on purpose, remove this claim with it")
        self.assertEqual(sorted(set(alle)), [str(gemessen)],
                         f"CROSS_IMPLEMENTATION_REPORT.md states the corpus size as {alle}, "
                         f"conformance/manifest.json lists {gemessen}")
        dateien = len(list((REPO / "conformance").rglob("case.json")))
        self.assertEqual(dateien, gemessen,
                         f"the manifest lists {gemessen} cases and the tree holds {dateien} "
                         f"case.json files — the two readings must agree before either is quoted")

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

    def test_die_flaechenfrage_antwortet_auf_beide_lagen(self):
        """BOTH answers, and neither is assumed from the surface this runs on.

        The first version asserted that inspect_ai IS installed here, and then checked the absent
        case by patching. In the hermetic cleanroom, where the package is deliberately absent, that
        first assertion failed — a test ABOUT surface dependence that was itself surface dependent.
        Measured there, woertlich: `AssertionError: False is not true : inspect_ai is installed
        here, so the claim's surface is this one`.

        So both answers are produced by patching, and the surface this runs on decides nothing.
        """
        from unittest import mock
        echt = importlib.util.find_spec
        with mock.patch("importlib.util.find_spec",
                        side_effect=lambda n, p=None: None if n.startswith("inspect_ai")
                        else echt(n, p)):
            self.assertFalse(flaeche_traegt_die_behauptung(),
                             "absent means the claim's surface is not this one")
        with mock.patch("importlib.util.find_spec",
                        side_effect=lambda n, p=None: echt("unittest") if n.startswith("inspect_ai")
                        else echt(n, p)):
            self.assertTrue(flaeche_traegt_die_behauptung(),
                            "present means the claim's surface IS this one")

    def test_ein_abgebrochener_lauf_ist_kein_ergebnis(self):
        """A run that stopped early looks exactly like a complete one -- until it says so.

        MEASURED 2026-09-20 on one file whose first case calls `pytest.exit()`: five runs of the
        SAME file returned `bestanden=1` twice and `bestanden=0` three times. `pytest-randomly`
        decides which case runs before the abort, and nothing in the answer said the session had
        stopped. The counts were real; what was missing was that they were partial.

        The subprocess return code was discarded and the plugin took `exitstatus` and ignored it,
        so the one fact that separates a result from a fragment never left the run. This is the
        same class as the two stdout readings and the JUnit report before it, through a fourth
        channel: the carrier held the numbers but not whether they were finished.
        """
        d = tempfile.mkdtemp(prefix="shipped-numbers-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        baum = pathlib.Path(d)
        (baum / "tests").mkdir()
        (baum / "tests" / "x.py").write_text(
            "import pytest, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_a(self):\n        pytest.exit('planted')\n"
            "    def test_b(self): pass\n", encoding="utf-8")

        # Repeated on purpose: the defect was that the ANSWER varied between runs of one file.
        for lauf in range(3):
            with self.subTest(lauf=lauf):
                bestanden, andere = lauf_bilanz("tests/x.py", baum)
                self.assertEqual(bestanden, -1, f"an interrupted run must not report a count "
                                                f"({bestanden}, {andere})")
                self.assertIn("lauf_unvollstaendig", andere, andere)
                self.assertEqual(andere.get("exitstatus"), 2, andere)

    def test_jeder_ausgang_wird_als_der_gezaehlt_der_er_ist(self):
        """One file carrying every outcome, and `xpassed` is the one that decides the reading.

        MEASURED 2026-09-20 against the JUnit report this file used for exactly one commit: stdout
        said `2 passed, 1 skipped, 1 deselected, 1 xfailed, 1 xpassed, 1 error` while the report
        attributes said `tests=6 failures=0 errors=1 skipped=2`. JUnit folds `xfailed` into
        `skipped` and counts `xpassed` as a passing test, so the arithmetic returned THREE where
        two cases passed. A case that was expected to fail and did not is not a pass -- that is the
        whole reason this file keeps a vocabulary of outcome words instead of one.
        """
        d = tempfile.mkdtemp(prefix="shipped-numbers-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        baum = pathlib.Path(d)
        (baum / "tests").mkdir()
        (baum / "tests" / "x.py").write_text(
            "import pytest, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_pass_a(self): pass\n"
            "    def test_pass_b(self): pass\n"
            "    def test_skip(self): self.skipTest('planted')\n"
            "@pytest.mark.xfail(reason='planted')\n"
            "def test_xfail(): assert False\n"
            "@pytest.mark.xfail(reason='planted')\n"
            "def test_xpass(): assert True\n"
            "@pytest.fixture\n"
            "def kaputt(): raise RuntimeError('planted')\n"
            "def test_fixture_error(kaputt): pass\n", encoding="utf-8")
        bestanden, andere = lauf_bilanz("tests/x.py", baum)
        self.assertEqual(bestanden, 2, f"only two cases passed ({andere})")
        self.assertEqual(andere, {"error": 1, "skipped": 1, "xfailed": 1, "xpassed": 1}, andere)
        self.assertEqual(gesammelte_faelle("tests/x.py", baum), bestanden + sum(andere.values()),
                         "the collector and the run must account for the same set")

    def test_der_bericht_ueberlebt_eine_zeile_die_wie_eine_bilanz_aussieht(self):
        """The shape that defeated two stdout readings, run for real against the report.

        A conftest registering an `atexit` hook prints a complete summary line AFTER pytest's own.
        Any rule over the terminal text reads the tail; the JUnit report does not have a tail.
        """
        import tempfile
        d = tempfile.mkdtemp(prefix="shipped-numbers-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        baum = pathlib.Path(d)
        (baum / "tests").mkdir()
        (baum / "tests" / "x.py").write_text(
            "import unittest\n\nclass T(unittest.TestCase):\n"
            "    def test_a(self):\n        pass\n"
            "    def test_b(self):\n        pass\n"
            "    def test_c(self):\n        self.skipTest('planted')\n", encoding="utf-8")
        (baum / "conftest.py").write_text(
            "import atexit\natexit.register(lambda: print('5 failed in 0.03s'))\n",
            encoding="utf-8")
        bestanden, andere = lauf_bilanz("tests/x.py", baum)
        self.assertEqual(bestanden, 2, f"the appended line must not be read as the result ({andere})")
        self.assertEqual(andere, {"skipped": 1}, andere)


class TestDieZaehlungSiehtNurWasPytestAuchSammelt(unittest.TestCase):
    """The count and the run must not disagree in the direction that reads GREEN.

    A counter-reading refuted the unconditional form of this file's claim: the right-hand number is
    bound only on the surface where `inspect_ai` is installed, because elsewhere the ratio case
    skips and the structural case is alone. Alone, a TEXT regex over `def test_` counted things
    pytest never collects, so a comment raised to match it passed.

    Both planted files below make the old reading count MORE than the run passes. That is the
    direction that goes green; the opposite direction (`parametrize`) makes the assertions
    contradict each other and is red by construction.
    """

    GESPENST = ("import unittest\n\n"
                "class TestEcht(unittest.TestCase):\n"
                "    def test_eins(self):\n        pass\n"
                "    def test_zwei(self):\n        pass\n\n"
                "class TestGespenst:\n"
                "    def __init__(self):\n        self.x = 1\n"
                "    def test_gespenst(self):\n        assert True\n")

    IM_DOCSTRING = ('"""An example in the module docstring:\n\n'
                    'def test_example_pattern():\n'
                    '    pass\n"""\n'
                    "import unittest\n\n"
                    "class T(unittest.TestCase):\n"
                    "    def test_eins(self):\n        pass\n")

    def _baue(self, inhalt: str):
        """A throwaway tree that is REMOVED again. Measured: the first version leaked two per run.

        `mkdtemp` without a cleanup is a directory that outlives the process, and a test suite that
        leaks two per run leaks them for as long as the suite exists. `addCleanup` runs even when
        the case fails, which a `with` block around the assertions would not.
        """
        import shutil
        import tempfile
        d = tempfile.mkdtemp(prefix="shipped-numbers-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        baum = pathlib.Path(d)
        (baum / "tests").mkdir()
        datei = baum / "tests" / "gepflanzt.py"
        datei.write_text(inhalt, encoding="utf-8")
        return baum, datei

    def test_eine_klasse_die_pytest_nicht_instanziieren_kann_zaehlt_nicht(self):
        baum, datei = self._baue(self.GESPENST)
        bestanden, andere = lauf_bilanz("tests/gepflanzt.py", baum)
        self.assertEqual(bestanden, 2, f"pytest cannot collect a class with __init__ ({andere})")
        self.assertEqual(gesammelte_faelle("tests/gepflanzt.py", baum), bestanden,
                         "the collector must not see a case the run can never reach — a comment "
                         "raised to that number would pass the structural check")

    def test_ein_def_test_im_docstring_zaehlt_nicht(self):
        baum, datei = self._baue(self.IM_DOCSTRING)
        bestanden, andere = lauf_bilanz("tests/gepflanzt.py", baum)
        self.assertEqual(bestanden, 1, f"only one real case exists here ({andere})")
        self.assertEqual(gesammelte_faelle("tests/gepflanzt.py", baum), bestanden,
                         "text inside a docstring is not a case, and a reading that cannot tell "
                         "them apart is the proxy this file exists against")


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
            behauptet = gesammelte_faelle("tests/gepflanzt.py", baum)
            self.assertEqual(behauptet, 3, "the planted file defines three cases")

            bestanden, andere = lauf_bilanz("tests/gepflanzt.py", baum)

            # THE OLD READING accepts it, and this assertion has to stand INSIDE the block: after
            # it the throwaway tree is gone, and a check written outside would have compared a
            # fallback constant with itself. A tautology reads exactly like a passing case.
            self.assertEqual(gesammelte_faelle("tests/gepflanzt.py", baum), behauptet,
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
