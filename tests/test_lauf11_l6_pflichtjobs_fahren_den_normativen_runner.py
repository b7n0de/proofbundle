"""Die required CI-Jobs fahren den Runner, der die ganze Suite sammelt — nicht einen, der ein Drittel nicht sieht.

WAS HIER GESCHLOSSEN WIRD. Deep Gate Lauf 11, Fund `LAUF11-L6`: die fünf required Matrix-Jobs
(`.github/workflows/ci.yml`, Job `test`, Python 3.10–3.14) fuhren
`python -m unittest discover -s tests -v`. `unittest discover` sammelt NUR `TestCase`-Klassen; eine
Testdatei aus reinen pytest-Funktionen ist dort unsichtbar.

GEMESSEN am Kandidatenkopf `e95e72f`, beide Seiten:

    unittest.TestLoader().discover('tests')  ->  2711 Tests / 209 Module
    Vollsuite unter pytest                    ->  4080 Tests (4055 passed + 25 skipped)
    Lücke                                     ->  1369 Tests / 71 Module

In der Lücke liegt die Freigabeflaeche selbst: `test_renewal*.py`,
`test_audit_candidate_ready_logic.py`, `test_audit_matrix_version_pin_binding.py`,
`test_freigabe_evidenz_provenienz_l5_g7_02.py`, `test_ausfuehrung_aus_quelltext_l5_g7_04.py`.

WAS DEN FUND VON EINER BLINDHEIT UNTERSCHEIDET, und es steht hier, damit niemand die Schwere
überschätzt: `coverage` ist ebenfalls required (`ci.yml`: "ruleset protect-main requires guard,
coverage and the five test matrix jobs") und fährt pytest auf 3.12. Das Gate als GANZES fing den
Defekt also — die Lücke war Einfach- statt Fünffachabdeckung für ein Drittel der Suite. Für ein
Release, das 3.10–3.14 verspricht, reicht das nicht: ein Defekt, der nur auf 3.10 oder 3.14
auftritt und in den 1369 Tests sitzt, käme durch.

DER ZUSTAND STAND IM CODE. `ci.yml` sagte ihn im eigenen Kommentar ("the unittest-discover CI job
runs only TestCase classes, so this counts the pytest-function tests too"), und
`scripts/test_manifest_gate.py` nennt pytest "the normative runner". Der normative Runner lief auf
einer Version, fünf Pflicht-Jobs fuhren einen anderen — die CI-Ausprägung der Klasse dieses
Registers: eine Prüfung bindet an die FORM (der Job heisst "Test" und ist required) statt an die
EIGENSCHAFT (misst er, was der normative Runner misst?).
"""
from __future__ import annotations

import os
import sys
import unittest
import unittest.loader
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CI = REPO / ".github" / "workflows" / "ci.yml"

#: Die Jobs, die das Ruleset als required führt (ci.yml nennt sie im Wortlaut).
REQUIRED_JOBS = ("test", "coverage", "guard")


def _lade_ci():
    try:
        import yaml  # noqa: PLC0415
    except ImportError:  # pragma: no cover
        raise unittest.SkipTest("NOT MEASURABLE: PyYAML fehlt — die Workflow-Datei ist nicht parsbar")
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


def _testschritte(job: dict) -> list[str]:
    """Die `run`-Zeilen eines Jobs, die einen Testlauf starten."""
    aus = []
    for schritt in job.get("steps", []) or []:
        run = schritt.get("run")
        if not isinstance(run, str):
            continue
        if "unittest" in run or "pytest" in run:
            aus.append(" ".join(run.split()))
    return aus


#: Optionen, die die Sammlung VERENGEN. Eine Zeile mit einer davon faehrt nicht die Suite, sondern
#: einen Ausschnitt — und "der Job faehrt pytest" waere fuer sie trotzdem wahr gewesen.
_VERENGENDE_OPTIONEN = ("-k", "-m", "--collect-only", "--co", "--lf", "--last-failed", "--ff",
                        "--failed-first", "--deselect", "--ignore", "--ignore-glob", "--noconftest",
                        "--confcutdir", "--pyargs", "--rootdir")
#: Positionsargumente, die die GANZE Suite meinen (der Wurzelordner oder das Testverzeichnis).
_GANZE_SUITE = {".", "./", "tests", "tests/", "./tests", "./tests/"}
#: ini-Schluessel, deren Ueberschreibung (`-o`, `--override-ini`) die Sammlung verengt. Gegenlesung
#: un_turbov1 (Lauf 13, Stelle 3b): `-o` stand in der Ueberspringliste, sein Argument wurde nie gelesen.
_VERENGENDE_INI = ("testpaths", "python_files", "python_classes", "python_functions", "addopts",
                   "norecursedirs", "collect_ignore", "collect_ignore_glob")
#: Optionen, die eine ANDERE Konfiguration laden — was die laedt, sieht dieser Riegel nicht.
_FREMDE_KONFIG = ("-c", "--config-file", "--rootdir")


def _addopts_aus_umgebung(ci: dict, job: dict) -> list[tuple[str, str]]:
    """(Quelle, Wert) fuer jedes `PYTEST_ADDOPTS`, das den Matrix-Lauf erreicht: `env:` auf Workflow-,
    Job- und Schritt-Ebene — und ein `run:`-Schritt, der es nach `$GITHUB_ENV` schreibt (statisch nicht
    auswertbar, deshalb gemeldet). Stelle 3b der Gegenlesung: die `run:`-Zeile zeigt eine Verengung
    ueber die Umgebung nicht."""
    aus = []
    for quelle, block in (("workflow", ci.get("env")), ("job", job.get("env"))):
        if isinstance(block, dict) and "PYTEST_ADDOPTS" in block:
            aus.append((quelle, str(block["PYTEST_ADDOPTS"])))
    for i, schritt in enumerate(job.get("steps", []) or []):
        env = schritt.get("env") if isinstance(schritt, dict) else None
        if isinstance(env, dict) and "PYTEST_ADDOPTS" in env:
            aus.append((f"step {i}", str(env["PYTEST_ADDOPTS"])))
        run = schritt.get("run") if isinstance(schritt, dict) else None
        if isinstance(run, str) and "PYTEST_ADDOPTS" in run and "GITHUB_ENV" in run:
            aus.append((f"step {i} (GITHUB_ENV)", "<nicht statisch auswertbar>"))
    return aus


def _pytest_aufrufe(run: str) -> list[list[str]]:
    """Die pytest-AUFRUFE einer `run`-Zeile als Argumentlisten (was NACH `pytest` steht), aus jeder
    Teilkette (Zeile, `&&`, `;`) einzeln. `python -m pytest -q` und `coverage run ... -m pytest -q`
    und ein nacktes `pytest` sind dieselbe Sache; `pip install pytest` ist keiner."""
    import re  # noqa: PLC0415
    import shlex  # noqa: PLC0415
    aufrufe = []
    for teil in re.split(r"\n|&&|;|\|\|", run):
        try:
            tokens = shlex.split(teil)
        except ValueError:
            tokens = teil.split()
        for i, tok in enumerate(tokens):
            # `pytest ...`, `python -m pytest ...`, `coverage run ... -m pytest ...` sind Aufrufe;
            # `pip install pytest` ist keiner (das Wort steht als Paketname, nicht als Befehl).
            if tok in ("pytest", "py.test") and (i == 0 or tokens[i - 1] == "-m"):
                aufrufe.append(tokens[i + 1:])
                break
    return aufrufe


def _verengung(run: str) -> list[str]:
    """Jeder Grund, aus dem diese `run`-Zeile NICHT die ganze Suite sammelt — leer heisst: sie tut es.

    LAUF12-L6 (P1, Gate-Blindheit ausgefuehrt): der Vorgaenger fragte `"pytest" in s` und war fuer
    `python -m pytest -q -k smoke` (ein Ausschnitt), `python -m pytest tests/test_one.py` (eine
    Datei) und `pip install pytest` (gar kein Lauf) gleichermassen gruen. Das Wort ist kein Beleg
    fuer die Eigenschaft "sammelt, was der normative Runner sammelt". Hier wird die Argumentliste
    strukturell gelesen; die Zahl der gesammelten Tests misst `test_die_ci_zeile_sammelt_die_ganze_suite`
    dann noch einmal ausfuehrbar."""
    aufrufe = _pytest_aufrufe(run)
    if not aufrufe:
        return [f"kein pytest-Aufruf in {run!r}"]
    gruende = []
    for args in aufrufe:
        i = 0
        while i < len(args):
            a = args[i]
            name = a.split("=", 1)[0]
            if name in _VERENGENDE_OPTIONEN or (name.startswith("-k") and not name.startswith("--")) \
                    or (name.startswith("-m") and len(name) > 2 and not name.startswith("--")):
                gruende.append(f"verengende Option {a!r}")
            elif name in _FREMDE_KONFIG:
                gruende.append(f"fremde Konfiguration {a!r} — was sie sammelt, ist hier nicht sichtbar")
            elif name in ("-o", "--override-ini"):
                wert = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
                if wert.split("=", 1)[0].strip() in _VERENGENDE_INI:
                    gruende.append(f"ini-Ueberschreibung {wert!r} verengt die Sammlung")
            elif name in ("-p",) and i + 1 < len(args) and args[i + 1].startswith("no:") \
                    and args[i + 1] not in ("no:randomly", "no:cacheprovider"):
                gruende.append(f"deaktiviertes Plugin {args[i + 1]!r}")
            elif not a.startswith("-") and a not in _GANZE_SUITE:
                gruende.append(f"Pfadauswahl {a!r} statt der ganzen Suite")
            if a in ("-k", "-m", "--deselect", "--ignore", "--ignore-glob", "-p", "-o", "-c",
                     "--confcutdir", "--rootdir"):
                i += 1  # das Argument der Option ist kein Pfad
            i += 1
    return gruende


_SAMMLUNGEN: dict = {}


def _gesammelt(args: tuple, umgebung: tuple) -> "int | None":
    """Zahl der von `pytest --collect-only` gesammelten Tests fuer diese Argumente — EINMAL je
    Argumentliste gefahren und gemerkt, weil eine Sammlung der ganzen Suite ~40 s kostet."""
    import subprocess  # noqa: PLC0415
    schluessel = (args, umgebung)
    if schluessel not in _SAMMLUNGEN:
        p = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:randomly", *args],
            capture_output=True, text=True, timeout=900, cwd=str(REPO),
            env={**os.environ, "PYTHONPATH": str(REPO / "src"), **dict(umgebung)})
        letzte = [z for z in p.stdout.strip().splitlines() if "test" in z and "collected" in z]
        _SAMMLUNGEN[schluessel] = int(letzte[-1].split()[0]) if letzte else None
    return _SAMMLUNGEN[schluessel]


class TestPflichtjobsFahrenDenNormativenRunner(unittest.TestCase):

    def test_kein_required_job_faehrt_unittest_discover(self):
        ci = _lade_ci()
        jobs = ci.get("jobs", {})
        verstoesse = []
        for name in REQUIRED_JOBS:
            job = jobs.get(name)
            if not job:
                continue
            for run in _testschritte(job):
                if "unittest discover" in run:
                    verstoesse.append(f"{name}: {run}")
        self.assertEqual(
            verstoesse, [],
            "ein REQUIRED Job fährt `unittest discover` und sammelt damit nur TestCase-Klassen — "
            "jede Testdatei aus reinen pytest-Funktionen ist dort unsichtbar, darunter die "
            "Freigabeflaeche:\n  " + "\n  ".join(verstoesse))

    def test_der_matrix_job_faehrt_pytest(self):
        """ANTI-PARITÄT: die Abwesenheit von `unittest discover` allein genügt nicht — ein Job ganz
        ohne Testschritt bestünde die Zusicherung oben. Und STRUKTURELL (LAUF12-L6): ein Aufruf, der
        die Sammlung verengt, ist kein Lauf der Suite, auch wenn das Wort pytest darin steht."""
        ci = _lade_ci()
        job = ci.get("jobs", {}).get("test")
        self.assertIsNotNone(job, "der Job `test` fehlt — dann misst dieser Test nichts")
        schritte = [s for s in _testschritte(job) if _pytest_aufrufe(s)]
        self.assertTrue(schritte, f"der Matrix-Job hat keinen pytest-Aufruf: {_testschritte(job)}")
        gruende = [g for s in schritte for g in _verengung(s)]
        for quelle, wert in _addopts_aus_umgebung(ci, job):
            if wert.startswith("<"):
                gruende.append(f"PYTEST_ADDOPTS wird in {quelle} gesetzt — {wert}")
            else:
                gruende += [f"PYTEST_ADDOPTS ({quelle}): {g}" for g in _verengung("pytest " + wert)]
        self.assertEqual(gruende, [],
                         "der Matrix-Job faehrt pytest, aber nicht die ganze Suite:\n  "
                         + "\n  ".join(gruende))

    def test_meta_eine_verengte_zeile_wird_erkannt(self):
        """GATE-META (LAUF12-L6): die drei Formen, fuer die der Vorgaenger blind war, und drei
        Formen, die die ganze Suite meinen — jede auf der richtigen Seite."""
        verengt = ("python -m pytest -q -k smoke", "python -m pytest tests/test_one.py",
                   "pip install pytest", "python -m pytest -q --lf", "python -m pytest -q -m 'not slow'",
                   "python -m pytest -q --deselect tests/test_a.py::test_b",
                   "python -m pytest --ignore=tests/test_renewal.py -q", "pytest -q --co",
                   # Stelle 3b der Gegenlesung: -o/-c/--rootdir
                   "python -m pytest -q -o testpaths=tests/test_one.py", "python -m pytest -q -c other.ini",
                   "python -m pytest -q --override-ini=addopts=-k\\ x", "python -m pytest -q --rootdir=tests/sub",
                   "python -m pytest -q -o python_files=test_one.py")
        ganz = ("python -m pytest -q", "python -m pytest", "pytest -q tests",
                "python -m coverage run --source=src/proofbundle -m pytest -q\n"
                "python -m coverage report -m --fail-under=83",
                "python -m pytest -q -p no:randomly -x --maxfail=3 tests/",
                "python -m pytest -q -o log_cli=true")
        for zeile in verengt:
            with self.subTest(zeile=zeile):
                self.assertTrue(_verengung(zeile), f"verengte Zeile nicht erkannt: {zeile!r}")
        for zeile in ganz:
            with self.subTest(zeile=zeile):
                self.assertEqual(_verengung(zeile), [], f"ganze Suite als verengt gemeldet: {zeile!r}")

    def test_meta_addopts_aus_der_umgebung_wird_gesehen(self):
        """Stelle 3b: `env: PYTEST_ADDOPTS` auf Workflow-, Job- oder Schrittebene und ein
        `$GITHUB_ENV`-Schreiber erreichen den Lauf, ohne in der `run:`-Zeile zu stehen."""
        job = {"env": {"PYTEST_ADDOPTS": "-k smoke"},
               "steps": [{"run": "python -m pytest -q"},
                         {"run": "echo 'PYTEST_ADDOPTS=-m slow' >> $GITHUB_ENV"},
                         {"run": "python -m pytest -q", "env": {"PYTEST_ADDOPTS": "-p no:randomly"}}]}
        gefunden = _addopts_aus_umgebung({"env": {"PYTEST_ADDOPTS": "--lf"}}, job)
        self.assertEqual([q for q, _ in gefunden], ["workflow", "job", "step 1 (GITHUB_ENV)", "step 2"])
        self.assertEqual(_addopts_aus_umgebung({}, {"steps": [{"run": "python -m pytest -q"}]}), [])

    def test_die_ci_zeile_sammelt_die_ganze_suite(self):
        """AUSFUEHRBAR, nicht strukturell: GENAU die Argumente der CI-Zeile (samt PYTEST_ADDOPTS des
        Jobs), mit `--collect-only`, muessen DIESELBE Zahl sammeln wie der kanonische Aufruf ueber
        `tests/` — nicht nur den Manifest-Boden. Stelle 3c der Gegenlesung: der Boden (1750) faengt bei
        4124 gesammelten Tests nur eine Verengung um mehr als die Haelfte; Gleichheit faengt jede."""
        import json  # noqa: PLC0415
        ci = _lade_ci()
        job = ci.get("jobs", {}).get("test")
        self.assertIsNotNone(job)
        aufrufe = [a for s in _testschritte(job) for a in _pytest_aufrufe(s)]
        self.assertTrue(aufrufe, "kein pytest-Aufruf im Matrix-Job")
        args = tuple(a for a in aufrufe[0] if a not in ("-q", "--quiet", "-v", "--verbose"))
        umgebung = {}
        for _, wert in _addopts_aus_umgebung(ci, job):
            if not wert.startswith("<"):
                umgebung["PYTEST_ADDOPTS"] = wert
        manifest = json.loads((REPO / "tests" / "test_manifest_lock.json").read_text(encoding="utf-8"))
        boden = int(manifest["min_collected_tests"])
        self.assertGreater(boden, 0, "das Manifest nennt keinen Boden")
        n_ci = _gesammelt(args, tuple(sorted(umgebung.items())))
        n_kanonisch = _gesammelt(("tests",), ())
        if n_ci is None or n_kanonisch is None:
            self.skipTest("NOT MEASURABLE: pytest --collect-only lieferte keine Zählzeile")
        self.assertGreaterEqual(n_ci, boden, f"die CI-Zeile sammelt {n_ci} < Manifest-Boden {boden}")
        self.assertEqual(
            n_ci, n_kanonisch,
            f"die CI-Zeile des Matrix-Jobs ({' '.join(['pytest', *aufrufe[0]])!r}"
            f"{' mit PYTEST_ADDOPTS=' + umgebung['PYTEST_ADDOPTS'] if umgebung else ''}) sammelt {n_ci} Tests, "
            f"der kanonische Aufruf ueber tests/ {n_kanonisch} — der Pflichtjob misst nicht die Suite")

    def test_die_luecke_ist_gemessen_nicht_behauptet(self):
        """Der Beleg für die Zahl im Kopf dieser Datei, bei jedem Lauf neu erhoben: `unittest
        discover` sieht WENIGER als die Suite hat. Diese Zusicherung dreht sich nie um — sie ist
        die Begründung, warum der Runner gewechselt wurde, und sie soll rot werden, wenn jemand die
        Suite auf TestCase-Klassen zurückbaut und den Fund damit ungültig macht."""
        gesammelt = unittest.TestLoader().discover(str(REPO / "tests"))

        def zaehle(s):
            return sum(zaehle(t) for t in s) if isinstance(s, unittest.TestSuite) else 1

        n_unittest = zaehle(gesammelt)
        self.assertGreater(n_unittest, 1000, "die unittest-Sammlung ist unplausibel klein")
        # Die Untergrenze der Gesamtsuite steht im Manifest, das WP-B pflegt — eine zweite,
        # unabhängig gepflegte Zahl, statt hier eine dritte zu tippen.
        import json  # noqa: PLC0415
        manifest = json.loads((REPO / "tests" / "test_manifest_lock.json").read_text(encoding="utf-8"))
        boden = int(manifest["min_collected_tests"])
        self.assertGreater(
            boden, 0, "das Manifest nennt keinen Boden — dann ist der Vergleich unten leer")
        # Die Aussage: unittest sieht nicht die ganze Suite. Wäre das falsch, wäre der Fund erledigt
        # und diese Datei überflüssig — dann soll sie rot werden und das sagen.
        n_pytest = _gesammelt(("tests",), ())
        if n_pytest is None:
            self.skipTest("NOT MEASURABLE: pytest --collect-only lieferte keine Zählzeile")
        self.assertGreater(
            n_pytest, n_unittest,
            f"unittest discover sammelt {n_unittest}, pytest {n_pytest} — wären sie gleich, hätte "
            "der Runner-Wechsel keinen Gegenstand mehr")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
