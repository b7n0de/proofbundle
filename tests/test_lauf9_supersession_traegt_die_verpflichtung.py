"""L5-600-REG-SUPERSEDE-01 (P1, deep gate Lauf 9): eine Abloesung muss die Verpflichtung tragen.

DER DEFEKT: `_resolve_current` liess einen Befund aus der Zaehlung fallen, sobald sein
`superseded_by` auf einen VORHANDENEN, VERSCHIEDENEN Eintrag zeigte. Mehr nicht — keine Bedingung
an Rang oder Zustand des Nachfolgers. Ein OFFENER P0 mit `superseded_by` auf einen beliebigen
GESCHLOSSENEN P3 verschwand damit lautlos, ohne eine einzige Anomalie, und ein gueltig signiertes
Register meldete 0 offene P0/P1.

Die Bilanz `accounted == population` hielt dabei — sie ist genau die Groesse, die den Verlust
MASKIERT, statt ihn zu zeigen: der Befund war ja gezaehlt, nur eben als "rechtmaessig abgeloest".

WARUM DIE VOLLE MATRIX. Der vorhandene Klassentest fuhr genau EINE Paarung (P1 -> P1) und war
deshalb gruen, waehrend die Klasse offen stand. Ein Klassentest, der einen Punkt prueft, prueft
keine Klasse. Hier laufen alle 5x5 Rangpaarungen ueber drei Zustaende — 75 Faelle, davon genau 15
legitim.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


def _register_modul():
    spec = importlib.util.spec_from_file_location("fr", REPO / "scripts" / "findings_register.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class AbloesungTraegtDieVerpflichtung(unittest.TestCase):
    def setUp(self):
        self.fr = _register_modul()

    def _fall(self, sev_v, sev_n, status_n):
        return self.fr._resolve_current([
            {"id": "V", "severity": sev_v, "status": "open", "superseded_by": "N"},
            {"id": "N", "severity": sev_n, "status": status_n},
        ])

    def test_der_defektfall_ein_p0_wird_nicht_von_einem_p3_erledigt(self):
        eff, _, anomalien, abgeloest = self._fall("P0", "P3", "closed")
        self.assertIn("V", eff, "der offene P0 darf nicht aus der Zaehlung fallen")
        self.assertNotIn("V", abgeloest)
        self.assertTrue(any("downgrades-severity" in a for a in anomalien), anomalien)

    def test_eine_kette_die_offen_endet_ist_verschoben_nicht_erledigt(self):
        eff, _, anomalien, abgeloest = self._fall("P1", "P1", "open")
        self.assertIn("V", eff)
        self.assertTrue(any("ends-open" in a for a in anomalien), anomalien)

    def test_volle_matrix_75_faelle_genau_15_legitim(self):
        """Die EIGENSCHAFT ueber die ganze Flaeche, nicht an einem Punkt."""
        sev = ["P0", "P1", "P2", "P3", "INFO"]
        rang = self.fr._SEVERITY_RANG
        legitim = 0
        for sv in sev:
            for sn in sev:
                for stn in ("open", "closed", "in_progress"):
                    _, _, anomalien, abgeloest = self._fall(sv, sn, stn)
                    ist = "V" in abgeloest and not anomalien
                    soll = rang[sn] >= rang[sv] and stn == "closed"
                    self.assertEqual(ist, soll,
                                     f"{sv} -> {sn}@{stn}: legitim={ist}, erwartet={soll}")
                    legitim += ist
        self.assertEqual(legitim, 15)

    def test_gegenrichtung_gleichrangig_und_geschlossen_bleibt_legitim(self):
        """Der bisherige Klassentest muss weiter halten — sonst ist der Fix ein Denial."""
        _, _, anomalien, abgeloest = self._fall("P1", "P1", "closed")
        self.assertIn("V", abgeloest)
        self.assertEqual(anomalien, [])

    def test_gegenrichtung_hoeherer_rang_darf_ebenfalls_abloesen(self):
        """Ein P2, den ein geschlossener P0 beerbt, ist erledigt — die Verpflichtung wuchs."""
        _, _, anomalien, abgeloest = self._fall("P2", "P0", "closed")
        self.assertIn("V", abgeloest)
        self.assertEqual(anomalien, [])

    def test_jede_bekannte_severity_hat_einen_rang(self):
        """Ohne diesen Gleichheitstest waere eine neu hinzugefuegte Marke rangfrei — und jede
        Abloesung auf sie hin ungeprueft."""
        self.assertEqual(set(self.fr._SEVERITY_RANG), self.fr._KNOWN_SEVERITIES)


if __name__ == "__main__":
    unittest.main()
