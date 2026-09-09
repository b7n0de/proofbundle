"""Der Riegel gegen NACHGEREICHTE Fangnachweise (Befund
NACHGEREICHTE-FANGNACHWEISE-WERDEN-NICHT-NEU-GEGEN-DEN-ALTEN-STAND-GEFAHREN-01).

VIERMAL an einem Tag ist derselbe Fehler passiert: ein Testfall kommt NACH der Ruecknahmeprobe
dazu, steht als Beweis im Baum und ist nie gegen den unreparierten Stand gelaufen. Einmal davon
war es eine ganze Testklasse mit vier Faellen, einmal ein Eigenschaftstest, der am ungefixten
Dekoder EBENFALLS gruen war.

Die Regel dagegen kann kein Vorsatz sein, sie muss ein Riegel sein. Dieser Test vergleicht die
Knoten der Fangnachweis-Datei gegen ein committetes Manifest, in dem je Knoten steht, wie er sich
OHNE den Fix verhalten hat. Ein neuer Knoten ohne Eintrag bricht den Lauf, und der einzige Weg
zurueck zu Gruen ist, die Ruecknahmeprobe zu wiederholen und das Ergebnis einzutragen.

WAS DIESER RIEGEL NICHT KANN, ausgeschrieben statt verschwiegen: er prueft die ANWESENHEIT eines
gemessenen Verhaltens, nicht dessen Wahrheit. Wer 'rot' eintraegt, ohne gemessen zu haben, kommt
durch. Die Messung selbst bleibt Handarbeit; der Riegel sorgt nur dafuer, dass sie nicht
VERGESSEN wird.
"""
from __future__ import annotations

import ast
import json
import pathlib
import unittest

_HIER = pathlib.Path(__file__).resolve().parent
_NACHWEIS = _HIER / "test_lauf8_klassenfixes_600.py"
_MANIFEST = _HIER / "ruecknahme_belegte_knoten.json"


def _knoten_der_datei(pfad: pathlib.Path) -> set[str]:
    """Alle Testknoten einer Datei, aus dem AST statt aus einem Lauf — der Riegel darf nicht
    davon abhaengen, dass die Suite gerade laeuft."""
    baum = ast.parse(pfad.read_text(encoding="utf-8"), filename=str(pfad))
    raus: set[str] = set()
    for knoten in baum.body:
        if not isinstance(knoten, ast.ClassDef):
            continue
        for glied in knoten.body:
            if isinstance(glied, (ast.FunctionDef, ast.AsyncFunctionDef)) and glied.name.startswith("test"):
                raus.add(f"tests/{pfad.name}::{knoten.name}::{glied.name}")
    return raus


class JederFangnachweisIstRuecknahmebelegt(unittest.TestCase):
    def setUp(self):
        # FEHLENDE DATEI IST EIN ZUSTAND, KEIN ABSTURZ (beim ersten Probelauf selbst erlebt: der
        # Riegel starb mit FileNotFoundError, weil der Wegwerf-Baum die Nachweisdatei nicht trug).
        # Ein Riegel, der mit einem Stacktrace endet, sagt nicht, WAS fehlt.
        if not _NACHWEIS.is_file():
            self.skipTest(f"{_NACHWEIS.name} liegt in diesem Baum nicht — nicht messbar, "
                          "und nicht messbar ist keine Freigabe")
        if not _MANIFEST.is_file():
            self.fail(f"{_MANIFEST.name} fehlt: die Nachweisdatei existiert, ihr Ruecknahme-Beleg "
                      "nicht. Genau der Zustand, den dieser Riegel verhindern soll.")
        self.manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
        self.belegt = self.manifest["knoten"]

    def test_kein_knoten_ohne_gemessenes_verhalten(self):
        fehlend = sorted(_knoten_der_datei(_NACHWEIS) - set(self.belegt))
        self.assertEqual(
            fehlend, [],
            "Diese Fangnachweise sind NICHT gegen den Kopf ohne die Fixes gelaufen:\n  "
            + "\n  ".join(fehlend)
            + "\nRuecknahmeprobe ueber die VOLLSTAENDIGE Datei wiederholen und das Ergebnis in "
            + _MANIFEST.name + " eintragen. Ein Beweis, der nie rot war, beweist nichts.")

    def test_kein_eintrag_ohne_knoten(self):
        """Die andere Richtung: ein Manifest, das auf geloeschte Knoten zeigt, taeuscht Deckung vor."""
        verwaist = sorted(set(self.belegt) - _knoten_der_datei(_NACHWEIS))
        self.assertEqual(verwaist, [], f"Manifest nennt Knoten, die es nicht mehr gibt: {verwaist}")

    def test_die_angesagte_rotzahl_stimmt_mit_dem_manifest_ueberein(self):
        """Anti-Tautologie: ohne diesen Fall koennte jemand ALLE Knoten als 'gruen' eintragen und
        der Riegel bliebe gruen, waehrend nichts mehr etwas beweist."""
        rot = sum(1 for v in self.belegt.values() if v == "rot")
        self.assertGreater(rot, 0, "kein einziger Knoten faellt ohne den Fix — die Datei beweist nichts")
        self.assertEqual(
            rot, self.manifest["gemessen_rot_in_dieser_datei"],
            "die Zahl der rot belegten Knoten weicht von der gemessenen ab")


if __name__ == "__main__":
    unittest.main()
