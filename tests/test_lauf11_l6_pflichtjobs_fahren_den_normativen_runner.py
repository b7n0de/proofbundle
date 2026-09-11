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
        ohne Testschritt bestünde die Zusicherung oben."""
        ci = _lade_ci()
        job = ci.get("jobs", {}).get("test")
        self.assertIsNotNone(job, "der Job `test` fehlt — dann misst dieser Test nichts")
        schritte = _testschritte(job)
        self.assertTrue(schritte, "der Matrix-Job hat gar keinen Testschritt mehr")
        self.assertTrue(any("pytest" in s for s in schritte),
                        f"der Matrix-Job fährt keinen pytest-Lauf: {schritte}")

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
        import subprocess  # noqa: PLC0415
        p = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:randomly",
             str(REPO / "tests")],
            capture_output=True, text=True, timeout=900, cwd=str(REPO),
            env={**os.environ, "PYTHONPATH": str(REPO / "src")})
        letzte = [z for z in p.stdout.strip().splitlines() if "test" in z and "collected" in z]
        if not letzte:
            self.skipTest("NOT MEASURABLE: pytest --collect-only lieferte keine Zählzeile")
        n_pytest = int(letzte[-1].split()[0])
        self.assertGreater(
            n_pytest, n_unittest,
            f"unittest discover sammelt {n_unittest}, pytest {n_pytest} — wären sie gleich, hätte "
            "der Runner-Wechsel keinen Gegenstand mehr")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
