"""Die Werkzeugschicht dekodiert so streng wie die Bibliothek — die KLASSE, nicht die elf Instanzen.

WAS HIER GESCHLOSSEN WIRD. Deep Gate Lauf 11 (2026-09-11), Fund `LAUF11-L2`: die Pre-Tag-Quittung
nimmt Muell in ihren Signaturfeldern an. Ausgefuehrt gemessen am Kandidatenkopf `e95e72f`: 35 von 35
Mutanten der Felder `signature`/`signer_pubkey` verifizierten weiter als `True`; der erste Fall war
`junk='!'` an Position 0 mit `Bytes verschieden=True · dekodiert identisch=True`.

WARUM `validate=True` NICHT DER FIX IST, obwohl der Fund so heisst. `tests/test_wire_bytes_strict.py`
und `src/proofbundle/_wire_b64.py` haben diese Frage am 2026-09-05 schon einmal beantwortet und die
Antwort gemessen: `validate=True` weist ein Zeichen ausserhalb des Alphabets und ein FEHLENDES
Polsterzeichen ab, aber NICHT die von null verschiedenen Pad-Bits —
`base64.b64decode(b"QUJ=", validate=True) == b"AB"`, dieselben Bytes wie das kanonische `QUI=`.
Ein Fix mit `validate=True` haette die Klasse `canonicity_preserving_perturbation_accepted` (RT-08)
in der Werkzeugschicht neu eroeffnet, die in der Bibliothek geschlossen ist. Deshalb rufen die
Werkzeuge denselben strikten Wrapper wie die Bibliothek.

DIE ASYMMETRIE, DIE DIESEN FUND ERST MOEGLICH MACHTE. Der Waechter von 2026-08-26 prueft
`SRC = src/proofbundle` — eine Scanwurzel, kein Kriterium. `scripts/` und `tools/` tragen
Signaturpruefungen der Freigabekette (`pre_tag_receipt_lib.verify_receipt`,
`findings_register.verify_and_count`, `sign_readiness_artifact.assemble`) und lagen ausserhalb.
AST-gemessen am Kopf `e95e72f`: `src/` 4 Aufrufe / 0 ohne `validate`, `scripts/` 14 / **11 ohne**,
`tools/` 1 / 1 ohne. Die Regel galt, die Flaeche war zu klein — dieselbe Klasse wie ein Pruefer,
der an eine FORM statt an die EIGENSCHAFT bindet.

`tests/` bleibt ausserhalb: dort wird base64 ERZEUGT, um Eingaben zu bauen, und ein Test, der
absichtlich eine zweite Schreibweise herstellt, muss das duerfen.
"""
from __future__ import annotations

import base64
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
TOOLS = REPO / "tools"

# Die Generatoren des bestehenden Waechters werden BENUTZT, nicht kopiert: zwei Populationen mit
# demselben Namen sind zwei Wahrheiten, und die zweite altert unbemerkt.
_spec = importlib.util.spec_from_file_location(
    "_wire_bytes_strict_helfer", REPO / "tests" / "test_wire_bytes_strict.py")
_wbs = importlib.util.module_from_spec(_spec)
sys.modules["_wire_bytes_strict_helfer"] = _wbs
_spec.loader.exec_module(_wbs)
JUNK = _wbs.JUNK
canonicity_preserving_variants = _wbs.canonicity_preserving_variants
laxe_dekodierstellen = _wbs.laxe_dekodierstellen


def _quittungs_lib():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import pre_tag_receipt_lib as lib  # noqa: PLC0415
    return lib


def _keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, base64.b64encode(priv.public_key().public_bytes_raw()).decode()


_VER, _TREE, _GATE = "6.0.0", "a" * 64, "b" * 64


def _gueltige_quittung(lib, priv, pub_b64):
    r = {
        "schema": lib.RECEIPT_SCHEMA, "version": _VER, "subject_tree_digest": _TREE,
        "gate_source_digest": _GATE, "audit_command": "pytest -q",
        "audit_exit_code": 0, "audit_output_digest": "c" * 64, "runner_identity": "ci",
        "produced_at": "2026-09-11T09:00:00Z",
    }
    r["signature"] = base64.b64encode(priv.sign(lib.canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub_b64
    return r


class TestEineQuittungEineSchreibweise(unittest.TestCase):
    """Der ausgefuehrte Fall des Fundes: kein Mutant der Signaturfelder ueberlebt bis zum Verdikt."""

    def setUp(self):
        self.lib = _quittungs_lib()
        self.priv, self.pub = _keypair()
        self.quittung = _gueltige_quittung(self.lib, self.priv, self.pub)

    def _pruefe(self, quittung):
        return self.lib.verify_receipt(
            quittung, trusted_pubkeys=[quittung.get("signer_pubkey")], expected_version=_VER,
            subject_tree_digest=_TREE, gate_source_digest=_GATE)

    def test_anti_paritaet_die_saubere_quittung_verifiziert(self):
        """ZUERST und nicht verhandelbar: ohne diese Zeile besteht ein Pruefer, der ALLES abweist,
        jede Zusicherung darunter."""
        ok, grund = self._pruefe(self.quittung)
        self.assertTrue(ok, f"Kontrolle gefallen, die Proben darunter waeren leer-wahr: {grund}")

    def test_kein_mutant_der_signaturfelder_verifiziert(self):
        gesehen = 0
        for feld in ("signature", "signer_pubkey"):
            orig = self.quittung[feld]
            schreibweisen = {f"junk:{j!r}@{stelle}": orig[:stelle] + j + orig[stelle:]
                             for j in JUNK
                             for stelle in (0, 1, len(orig) // 2, len(orig) - 1, len(orig))}
            schreibweisen.update(canonicity_preserving_variants(orig, alphabet="std"))
            for name, wert in schreibweisen.items():
                if wert == orig:
                    continue
                gesehen += 1
                with self.subTest(feld=feld, variante=name):
                    q = dict(self.quittung)
                    q[feld] = wert
                    try:
                        ok, _ = self._pruefe(q)
                    except Exception:  # noqa: BLE001 — eine typisierte Abweisung ist ein Ergebnis
                        ok = False
                    self.assertFalse(
                        ok, f"{feld} {name} verifiziert weiter — dieselbe Quittung hat dann mehr als "
                            "eine angenommene Drahtform, und genau das setzt die Bindung an EINEN Baum "
                            "voraus, die diese Quittung behauptet")
        self.assertGreater(gesehen, 30, "die Population ist kleiner als die Klasse, die sie deckt")

    def test_der_gemessene_erstfall_des_fundes(self):
        """Der Fall aus dem Verdikt woertlich: junk='!' an Position 0, Bytes verschieden, dekodiert
        identisch. Er steht einzeln da, weil er der Fall ist, den der Bericht nennt."""
        q = dict(self.quittung)
        mutant = "!" + q["signature"]
        self.assertNotEqual(mutant, q["signature"])
        self.assertEqual(base64.b64decode(mutant), base64.b64decode(q["signature"]),
                         "Vorbedingung verfehlt: der Mutant dekodiert nicht mehr identisch")
        q["signature"] = mutant
        ok, _ = self._pruefe(q)
        self.assertFalse(ok, "der im Verdikt genannte Erstfall verifiziert weiter")


class TestWerkzeugschichtDekodiertNichtSelbst(unittest.TestCase):
    """Der Klassen-Riegel: die Scanwurzel folgt der EIGENSCHAFT (wer prueft Signaturen?), nicht
    einem Verzeichnisnamen."""

    def test_kein_werkzeug_ruft_den_stdlib_decoder(self):
        offen = sorted([f"scripts/{t}" for t in laxe_dekodierstellen(SCRIPTS)]
                       + [f"tools/{t}" for t in laxe_dekodierstellen(TOOLS)])
        self.assertEqual(
            offen, [],
            "diese Werkzeuge dekodieren unvertraute base64 durch die stdlib statt durch "
            "proofbundle._wire_b64 — dort gilt die Kanonizitaet nicht, und ein signiertes Artefakt "
            "gewinnt mehrere angenommene Drahtformen: " + ", ".join(offen))

    def test_meta_eine_gepflanzte_verletzung_im_werkzeugbaum_wird_gefangen(self):
        """PLANT-AND-MUST-CATCH, in einer Dateiform, die der Sweep so nie gesehen hat — samt der
        Form MIT `validate=True`, die genau der halbe Fix waere."""
        with tempfile.TemporaryDirectory() as d:
            fremd = Path(d) / "werkzeug"
            (fremd / "tief").mkdir(parents=True)
            (fremd / "tief" / "neu.py").write_text(
                "import base64\n"
                "class Pruefer:\n"
                "    def lies(self, s):\n"
                "        return base64.b64decode(s)\n"
                "def halber_fix(s):\n"
                "    return base64.b64decode(s, validate=True)\n")
            gefunden = laxe_dekodierstellen(fremd)
            self.assertEqual(len(gefunden), 2, f"nicht alle gepflanzten Verletzungen gefangen: {gefunden}")

    def test_anti_tautologie_der_geblendete_scanner_faellt_still(self):
        """Die andere Richtung, und sie macht die erste erst aussagekraeftig: findet der geblendete
        Scanner dieselbe Pflanzung weiter, kam der Fang nicht aus dem Scan."""
        with tempfile.TemporaryDirectory() as d:
            fremd = Path(d) / "werkzeug"
            fremd.mkdir(parents=True)
            (fremd / _wbs.DER_WRAPPER).write_text(
                "import base64\ndef lies(s):\n    return base64.b64decode(s, validate=True)\n")
            self.assertEqual(laxe_dekodierstellen(fremd), [],
                             "der geblendete Scanner meldet weiter — dann beweist der Fang oben nichts")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
