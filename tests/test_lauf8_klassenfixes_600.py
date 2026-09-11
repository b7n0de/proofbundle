"""Deep-Gate Lauf 8 (DEEP 6L/7I) ueber `434e3a34`: die vier Code-Funde, an der KLASSE gepruefT.

Vier von fuenf bestaetigten Funden des Laufs sind DIESELBE Klasse: eine Pruefung bindet an eine
FORM statt an die EIGENSCHAFT, meist als Fallunterscheidung ohne Sonst-Zweig. Zwei davon sind
Nachbarn von Fixes, die ich im Lauf davor selbst gesetzt habe — der Schluss-Arm im Strukturbudget
schloss die WERT-Achse und liess die SCHLUESSEL-Achse als Aufzaehlung stehen.

Jede Klasse steht hier mit BEIDEN Richtungen: der Fall, der ohne den Fix falsch durchkommt, UND
der gewoehnliche Fall, der weiter durchkommen muss. Ein Fix, der alles abweist, ist so falsch wie
einer, der nichts abweist.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import tempfile
import unittest

from proofbundle import dsse
from proofbundle._strict_json import enforce_structural_budget, loads_strict
from proofbundle._wire_b64 import decode_b64_c2sp
from proofbundle.budget import DEFAULT_BUDGET, BudgetExceeded
from proofbundle.cli import _load_related
from proofbundle.emit import generate_signer
from proofbundle.relation_statement import RELATION_STATEMENT_PREDICATE_TYPE
from _lastdeckel import gedeckelt  # LAUF11-L3: Testlast am Speicher gedeckelt


class SchluesselLaufenDurchDieselbeSchranke(unittest.TestCase):
    """L2-600-KEYS-01: der Strukturlauf band die Schluessel-Achse an eine Aufzaehlung aus `str`
    und `int`, waehrend der Schluss-Arm die Wert-Achse laengst schloss. Ein bytes-, tuple- oder
    frozenset-Schluessel bekam WEDER Schranke NOCH Abweisung."""

    def setUp(self):
        self.b = DEFAULT_BUDGET
        self.gross = "x" * (self.b.string_len + 1000)
        self.viele = self.b.json_nodes + 10

    def test_ein_zu_langer_bytes_schluessel_faellt_wie_ein_zu_langer_wert(self):
        with self.assertRaises(BudgetExceeded):
            enforce_structural_budget({self.gross.encode(): 1}, budget=self.b)

    def test_ein_container_schluessel_wird_gezaehlt_und_betreten(self):
        for schluessel in (tuple(range(self.viele)), frozenset(range(self.viele))):
            with self.subTest(typ=type(schluessel).__name__):
                with self.assertRaises(BudgetExceeded):
                    enforce_structural_budget({schluessel: 1}, budget=self.b)

    def test_der_massstab_haelt(self):
        """Ohne diesen Fall misst der Test oben nichts: der WERT faellt schon vorher."""
        with self.assertRaises(BudgetExceeded):
            enforce_structural_budget({"a": self.gross}, budget=self.b)

    def test_GEGENRICHTUNG_gewoehnliche_schluessel_kommen_durch(self):
        for name, obj in (("JSON-Dict", {"a": 1, "b": ["x", None, True], "c": {"d": 2.5}}),
                          ("int-Schluessel", {7: "ok"}),
                          ("erlaubte Laenge", {"k": "y" * (gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=1) - 1)}),
                          ("verschachtelt", {"a": {"b": {"c": [1, 2, 3]}}})):
            with self.subTest(fall=name):
                enforce_structural_budget(obj, budget=self.b)   # darf nicht werfen


class DieGrenzeMisstBytesNichtZeichen(unittest.TestCase):
    """L3-600-BYTESUNIT-01: `input_bytes` verglich `len(text)`, und das zaehlt auf einem `str`
    Codepoints. Mit vierbyteigen Zeichen war die Schranke bis zum Vierfachen zu weit."""

    def _dokument(self, element: str, n: int = 150000) -> str:
        return '{"a":[' + ",".join('"' + element + '"' for _ in range(n)) + "]}"

    def test_gleiche_zeichenzahl_verschiedene_bytezahl_entscheidet_verschieden(self):
        g = DEFAULT_BUDGET.input_bytes
        laenge = (g - 40) // 150000 - 4
        schmal = self._dokument("x" * laenge)
        breit = self._dokument("\U0001F600" * laenge)
        self.assertEqual(len(schmal), len(breit), "die Probe misst nicht, was sie soll")
        self.assertLess(len(schmal.encode("utf-8")), g)
        self.assertGreater(len(breit.encode("utf-8")), g)
        loads_strict(schmal)                       # unter der Bytegrenze, kommt durch
        with self.assertRaises(BudgetExceeded):
            loads_strict(breit)                    # ueber der Bytegrenze, faellt

    def test_GEGENRICHTUNG_kleine_dokumente_mit_umlauten_und_emoji_kommen_durch(self):
        for text in ('{"a":"hallo"}', '{"a":"Gruesse ueber Oel"}', '{"a":"\U0001F600\U0001F600"}'):
            with self.subTest(text=text[:24]):
                loads_strict(text)


def _statement(signer, praedikat, predicate_type=RELATION_STATEMENT_PREDICATE_TYPE,
               weglassen: bool = False) -> dict:
    st = {"_type": "https://in-toto.io/Statement/v1",
          "subject": [{"name": "s", "digest": {"sha256": "a" * 64}}],
          "predicateType": predicate_type}
    if not weglassen:
        st["predicate"] = praedikat
    body = json.dumps(st, separators=(",", ":"), sort_keys=True).encode()
    return dsse.sign_envelope(body, signer, payload_type="application/vnd.in-toto+json")


class EinNichtLesbaresPraedikatIstNichtSchweigen(unittest.TestCase):
    """L4-800-01: der `--with-related`-Aufloeser las das Praedikat nur, wenn es zufaellig ein
    Objekt war, ohne Sonst-Zweig. Ein signiertes Statement mit einer Liste als Praedikat galt als
    geprueft und stumm, waehrend dieselben Bytes allein geprueft durchfallen.

    ENG GEFASST nach der Jury: nur EIGENE Praedikattypen mit einem positiv falschen Wert. Ein
    fehlendes oder ausdruecklich leeres Praedikat bleibt unberuehrt (in-toto v1 erlaubt es), und
    eine fremde Attestation wird nicht beurteilt."""

    def _lauf(self, praedikat, **kw):
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "nachbar.json")
            pathlib.Path(p).write_text(json.dumps(_statement(sk, praedikat, **kw)),
                                       encoding="utf-8")
            related, fehler = _load_related([p], pub)
        self.assertEqual(fehler, [], f"Aufloeser meldete Fehler: {fehler}")
        (eintrag,) = related.values()
        return eintrag

    def test_eine_liste_als_praedikat_ist_ein_formfehler(self):
        e = self._lauf([1, 2, 3])
        self.assertTrue(e["payload_malformed"])
        self.assertFalse(e["verified"])

    def test_eine_zeichenkette_als_praedikat_ist_ein_formfehler(self):
        e = self._lauf("boese")
        self.assertTrue(e["payload_malformed"])
        self.assertFalse(e["verified"])

    def test_GEGENRICHTUNG_null_und_fehlend_bleiben_unberuehrt(self):
        """Die Jury hat meine erste Fassung hier widerlegt: sie wies auch `null` ab."""
        for name, kw in (("null", {}), ("fehlt", {"weglassen": True})):
            with self.subTest(fall=name):
                e = self._lauf(None, **kw)
                self.assertIsNone(e["payload_malformed"])
                self.assertTrue(e["verified"])

    def test_GEGENRICHTUNG_eine_fremde_attestation_wird_nicht_beurteilt(self):
        e = self._lauf([1, 2, 3], predicate_type="https://example.org/fremd/v1")
        self.assertIsNone(e["payload_malformed"])
        self.assertTrue(e["verified"])

    def test_GEGENRICHTUNG_ein_objekt_als_praedikat_wird_gelesen(self):
        e = self._lauf({"relationships": []})
        self.assertIsNone(e["payload_malformed"])
        self.assertEqual(e["relationships"], [])


class EinUnlesbarerNachbarMaskiertKeineRuecknahme(unittest.TestCase):
    """Nachbar-Arm von L4-800-01, beim Schliessen des Kantenziel-Arms gefunden.

    `successor_warning` uebersprang jeden Nachbarn mit `verified is not True`. Der Aufloeser setzt
    dieses Feld seit dem L4-01-Fix vom 05.09. AUCH fuer einen unlesbaren Payload — ein Flag, zwei
    Bedeutungen. Ein Nachbar mit kaputtem Payload fiel damit stumm heraus, und mit ihm die
    Ruecknahme, die er ueber uns erklaert. Genau der Fehlermodus, den der Absatz in derselben
    Funktion ausschliesst.
    """

    SUBJ = "b" * 64

    def _kante(self, hexd, rel):
        return {"relation": rel,
                "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": hexd}}

    def _warnung(self, eintrag):
        from proofbundle.relation import successor_warning
        return successor_warning(None, {"a" * 64: eintrag}, subject_hex=self.SUBJ)

    def test_ein_unlesbarer_payload_meldet_sich(self):
        self.assertIsNotNone(self._warnung(
            {"verified": False, "relationships": None,
             "payload_malformed": "predicate is list, not an object"}))

    def test_er_maskiert_keine_echte_ruecknahme(self):
        """Der schwerste Fall: die Verformung darf die Ruecknahme nicht unsichtbar machen."""
        self.assertIsNotNone(self._warnung(
            {"verified": False, "relationships": [self._kante(self.SUBJ, "retracts")],
             "payload_malformed": "predicate is list, not an object"}))

    def test_GEGENRICHTUNG_eine_gebrochene_signatur_bleibt_uebersprungen(self):
        """Eine unsignierte Behauptung ist keine Aussage ueber uns — sonst blockt jeder Fremde."""
        self.assertIsNone(self._warnung(
            {"verified": False, "relationships": [self._kante(self.SUBJ, "retracts")]}))

    def test_GEGENRICHTUNG_ein_gewoehnlicher_stiller_nachbar_bleibt_still(self):
        self.assertIsNone(self._warnung(
            {"verified": True, "relationships": [self._kante("c" * 64, "amends")]}))


class EinArtefaktEineSchreibweise(unittest.TestCase):
    """L1-C2SPPAD-01: `decode_b64_c2sp` nannte GENAU EINE geduldete Abweichung (die Pad-Bits) und
    duldete stillschweigend eine zweite, ueberzaehliges Padding. Go's StdEncoding, in der
    Begruendung als Massstab genannt, weist ueberzaehliges Padding ab."""

    #: Die sechs Materiallaengen, die auf dieser Flaeche wirklich vorkommen.
    LAENGEN = (33, 68, 32, 1313, 2432, 76)

    def test_ueberzaehliges_padding_faellt(self):
        for n in self.LAENGEN:
            with self.subTest(laenge=n):
                kanon = base64.b64encode(b"\x5a" * n).decode()
                with self.assertRaises(binascii.Error):
                    decode_b64_c2sp(kanon + "=")

    def test_GEGENRICHTUNG_die_kanonische_form_kommt_durch(self):
        for n in self.LAENGEN:
            with self.subTest(laenge=n):
                roh = b"\x5a" * n
                self.assertEqual(decode_b64_c2sp(base64.b64encode(roh).decode()), roh)

    def test_GEGENRICHTUNG_die_dokumentierte_pad_bit_duldung_bleibt(self):
        """Die Ausnahme, die der Docstring nennt, darf der Fix NICHT mitnehmen."""
        self.assertEqual(decode_b64_c2sp("QUJ="), b"AB")   # Pad-Bits ungleich null
        self.assertEqual(decode_b64_c2sp("QUI="), b"AB")   # kanonisch


if __name__ == "__main__":
    unittest.main()
