"""Identität wird auf derselben Achse entschieden wie alles andere, was diese Funktion adjudiziert.

DIE KLASSE (deep gate wf_cfe249d0-ee8, Fund L5-01, **P0**, jury-bestätigt): `_norm()` — NFKC plus
Entfernen der Kategorien Cc/Cf — lief in `_resolve_current` über `severity` und `status`, aber
**nicht** über `id` und `superseded_by`. Nachbar-Felder in derselben Funktion, ungleich behandelt.

Der Angriff, gemessen gegen die Vor-Fix-Fassung aus git: ein offener P0 mit
`superseded_by = "PB-X<unsichtbar>"` plus ein geschlossener Köder mit `id = "PB-X<unsichtbar>"`. Roh
sind die beiden Zeichenketten verschieden, der Verweis liest sich als legitime Supersession auf einen
vorhandenen, ANDEREN Eintrag, der P0 fällt aus der Zählung — und das Gate meldet PASS. Für einen
menschlichen Prüfer sehen beide Kennungen gleich aus. Alle sechs geprüften unsichtbaren Zeichen
kamen durch.

KEINE SPERRLISTE. Der Fund sagt es ausdrücklich: eine Liste verbotener Zeichen ist die Bauart, die im
Nachbarbefund L5-02 versagt hat — sie kann nur benennen, woran jemand schon gedacht hat. Geprüft wird
deshalb die Eigenschaft, nicht das Zeichen.

DER META-TEST ist hier kein Beiwerk. Der Fund verlangt: nimmt man `_norm()` von der Severity, muss
DIESELBE Prüfung dort ebenfalls feuern — eine Suite, die nur die Kennungs-Achse fängt, hat die Klasse
neu aufgezählt statt sie zu schliessen.
"""
from __future__ import annotations

import importlib.util
import unicodedata
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_fr", REPO / "scripts" / "findings_register.py")
fr = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fr)

# Korpus statt Sperrliste: unsichtbare Zeichen (Cf/Cc), ein weiches Trennzeichen und
# NFKC-zerlegbare Formen. Die Prüfung darf an KEINEM davon hängen.
UNSICHTBAR = ("​", "‌", "‍", "﻿", "­", "⁠")
NFKC_PAARE = (("Ｐ０", "P0"), ("①", "1"))   # Vollbreite / eingekreist -> NFKC


def _offene_p0(effective: dict) -> list[str]:
    return [i for i, f in effective.items()
            if fr._norm(str(f.get("severity", ""))).upper() in fr._GATING_SEVERITIES
            and fr._norm(str(f.get("status", ""))).lower() != "closed"]


def _kommt_durch(findings: list) -> bool:
    """True heisst: der offene P0 ist unsichtbar geworden — kein Fund, keine Anomalie, kein Widerspruch."""
    eff, contra, anom, _ = fr._resolve_current(findings)
    return not anom and not contra and not _offene_p0(eff)


class IdentitaetAufDerselbenAchse(unittest.TestCase):

    def test_kein_unsichtbares_zeichen_versteckt_einen_offenen_p0(self):
        """Der Angriff selbst, über den ganzen Korpus — nicht über ein Beispiel."""
        for c in UNSICHTBAR:
            with self.subTest(zeichen=f"U+{ord(c):04X}"):
                findings = [
                    {"id": "PB-X", "severity": "P0", "status": "open", "superseded_by": f"PB-X{c}"},
                    {"id": f"PB-X{c}", "severity": "P0", "status": "closed"},
                ]
                self.assertFalse(
                    _kommt_durch(findings),
                    f"U+{ord(c):04X} versteckt einen offenen P0 hinter einer Schein-Supersession")

    def test_kollidierende_kennungen_sind_fail_closed(self):
        """Zwei Kennungen, die normalisiert zusammenfallen, sind nie eine stille Supersession."""
        for c in UNSICHTBAR:
            with self.subTest(zeichen=f"U+{ord(c):04X}"):
                eff, contra, anom, _ = fr._resolve_current([
                    {"id": "PB-Y", "severity": "P0", "status": "open"},
                    {"id": f"PB-Y{c}", "severity": "P0", "status": "closed"},
                ])
                self.assertTrue(anom or contra,
                                "kollidierende Kennungen ohne Anomalie und ohne Widerspruch")

    def test_eine_kennung_nur_aus_unsichtbaren_zeichen_ist_eine_anomalie(self):
        """Sonst kollabierten mehrere solcher Kennungen still auf denselben leeren Schluessel."""
        _, _, anom, _ = fr._resolve_current([
            {"id": "​‌", "severity": "P0", "status": "open"},
            {"id": "PB-Z", "severity": "P2", "status": "closed"},
        ])
        self.assertTrue(any("empty" in a for a in anom), f"leere Kennung nicht beanstandet: {anom}")

    def test_selbstverweis_ueber_ein_unsichtbares_zeichen(self):
        """`superseded_by` zeigt normalisiert auf die eigene Kennung — ein Selbstverweis in Tarnung."""
        for c in UNSICHTBAR:
            with self.subTest(zeichen=f"U+{ord(c):04X}"):
                _, _, anom, sup = fr._resolve_current([
                    {"id": "PB-S", "severity": "P0", "status": "open", "superseded_by": f"PB-S{c}"},
                ])
                self.assertTrue(anom, "getarnter Selbstverweis nicht beanstandet")
                self.assertNotIn("PB-S", sup, "getarnter Selbstverweis liess den Fund fallen")

    def test_meta_die_severity_achse_traegt_dieselbe_pruefung(self):
        """META-TEST, vom Fund verlangt: die Prüfung darf nicht NUR die Kennungs-Achse fangen.

        Nähme man `_norm()` von der Severity, müsste eine getarnte Severity dort genauso auffallen.
        Geprüft wird das ohne Codeänderung, indem der Angriff auf die Severity-Achse gefahren wird:
        eine Severity, die als P0 rendert, aber ein unsichtbares Zeichen trägt, darf NIE als
        nicht-gatend durchgehen.
        """
        for c in UNSICHTBAR:
            with self.subTest(zeichen=f"U+{ord(c):04X}"):
                eff, _, anom, _ = fr._resolve_current([
                    {"id": "PB-M", "severity": f"P{c}0", "status": "open"},
                ])
                versteckt = not anom and not _offene_p0(eff)
                self.assertFalse(versteckt,
                                 f"getarnte Severity 'P{{U+{ord(c):04X}}}0' wurde nicht-gatend")

    def test_meta_nfkc_zerlegbare_formen_auf_beiden_achsen(self):
        """Die zweite Hälfte des Korpus: nicht nur unsichtbar, auch aequivalent zerlegbar."""
        voll, schmal = NFKC_PAARE[0]
        self.assertEqual(unicodedata.normalize("NFKC", voll), schmal,
                         "die Testannahme über NFKC stimmt nicht mehr — dann prüft der Fall nichts")
        eff, _, anom, _ = fr._resolve_current([{"id": "PB-N", "severity": voll, "status": "open"}])
        self.assertTrue(anom or _offene_p0(eff),
                        "eine vollbreite Severity ging als nicht-gatend durch")

    def test_gegenrichtung_ein_sauberes_register_bleibt_unbeanstandet(self):
        """Ohne diese Zeile wäre jede Verschärfung 'erfolgreich': ein Riegel, der alles ablehnt.

        Gemessen am 2026-08-08: das echte Register trägt 17 Findings, deren Kennungen roh UND
        normalisiert eindeutig sind und sich beim Normalisieren nicht ändern.
        """
        eff, contra, anom, sup = fr._resolve_current([
            {"id": "PB-1", "severity": "P0", "status": "closed"},
            {"id": "PB-2", "severity": "P1", "status": "open", "superseded_by": "PB-3"},
            {"id": "PB-3", "severity": "P1", "status": "closed"},
        ])
        self.assertEqual(anom, [], f"sauberes Register beanstandet: {anom}")
        self.assertEqual(contra, [], f"sauberes Register als widerspruechlich gewertet: {contra}")
        self.assertEqual(sup, {"PB-2"}, "die legitime Supersession wurde nicht erkannt")
        self.assertEqual(_offene_p0(eff), [], "sauberes Register meldet offene P0/P1")

    def test_gegenrichtung_ein_echter_offener_p0_wird_weiterhin_gemeldet(self):
        """Die andere Gegenrichtung: der Riegel darf den Normalfall nicht verschlucken."""
        eff, _, anom, _ = fr._resolve_current([
            {"id": "PB-OPEN", "severity": "P0", "status": "open"},
            {"id": "PB-OTHER", "severity": "P3", "status": "closed"},
        ])
        self.assertEqual(anom, [], f"unerwartete Anomalie: {anom}")
        self.assertEqual(_offene_p0(eff), ["PB-OPEN"], "ein echter offener P0 wurde nicht gemeldet")


if __name__ == "__main__":
    unittest.main()
