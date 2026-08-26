"""NON_JSON-Wireform-Deckung (iter8, dritter Teil des Klassenfixes): die Typ-Konfusion HINTER der
SD-JWT-Kompaktform.

WARUM DIESER TEST EXISTIERT, gemessen: `scripts/type_confusion_gate.py` stuft `sdjwt.verify_sd_jwt`
und `kbjwt.verify_key_binding` als NON_JSON ein, weil ihr Primaerargument ein Kompakt-STRING ist
(`compact: str`), kein JSON-Objekt. Die Blatt-Matrix des Gates (`{feld: verdorbenes_blatt}`) erreicht
sie deshalb nie — der Absturz sitzt aber HINTER der Dekodierung: `verify_sd_jwt` macht
`payload = loads_strict(_b64url_decode(payload_b64))` und danach `is_member(payload.get("_sd_alg"), …)`.
Ein unhashbares Blatt an dieser Stelle hashte (vor dem `is_member`-Klassenfix) roh und stuerzte ab —
genau eine der vier P1-Klassen von iter8, nur eine Kodierungsschicht tiefer als die JSON-Flaechen.

Dieser Test GIBT den zwei NON_JSON-Flaechen die Deckung, die die Matrix nicht liefern kann: er baut
eine FORM-GUELTIGE SD-JWT-Drahtform mit GENAU EINEM verdorbenen inneren Blatt und prueft, dass die
Flaeche ein VERDIKT liefert statt roh zu stuerzen. Drei Richtungen (Fang / Plant / Kontrolle), damit
das Gruen nicht tautologisch ist.

Absturz sitzt VOR der Signaturpruefung und `issuer_pubkey`/`holder_pubkey` default `None` (gemessen im
Koerper) — die Drahtform braucht deshalb KEINE gueltige Signatur, nur ein gueltiges b64url
(`_wire_b64` ist strikt, `validate=True`).
"""
from __future__ import annotations

import base64
import json
import unittest

from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.kbjwt import verify_key_binding


def _b64url(obj) -> str:
    """b64url ohne Padding — die Umkehr von `_b64url_decode`/`loads_strict` der Flaechen."""
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Dieselben Korruptionswerte wie `_LEAF_CONFUSIONS` des Gates: die unhashbaren fuehren zum Roh-Absturz
# eines Mitgliedstests, das hashbare tuple passiert ihn und verwirrt erst spaeter.
_LEAF_CONFUSIONS = [[], [1], {}, {"a": 1}, set(), {1, 2}, (), (1, 2)]


def _sdjwt_wireform(payload: dict, disclosures=None) -> str:
    """Eine form-gueltige SD-JWT-Kompaktform: <header_b64>.<payload_b64>.<sig>~<disclosure>~…

    Header/Payload sind gueltige JSON-Objekte, die Signatur ist leer (kein pubkey -> keine Pruefung).
    `set()`/`{1,2}` sind in JSON nicht serialisierbar; fuer die traegt der Aufrufer sie als Liste in
    die Wireform und ersetzt sie erst NACH dem Dekodieren nicht — hier wird stattdessen ein
    JSON-serialisierbares Surrogat gewaehlt, das im DEKODIERTEN payload trotzdem unhashbar ist: eine
    Liste/Dict. Fuer `set`/`tuple` deckt die JSON-Grenze sie ohnehin nicht ab (sie koennen aus
    `json.loads` nie entstehen) — die relevante, aus einer echten Drahtform ERREICHBARE Korruption ist
    list/dict, und genau die wird hier gefahren."""
    header = {"alg": "EdDSA", "typ": "sd+jwt"}
    parts = [f"{_b64url(header)}.{_b64url(payload)}."]
    for d in (disclosures or []):
        parts.append(d)
    return "~".join(parts) if len(parts) > 1 else parts[0] + "~"


# Aus einer echten JSON-Drahtform erreichbar sind list/dict (json.loads erzeugt nie set/tuple). Das ist
# die ehrliche Teilmenge von _LEAF_CONFUSIONS, die dieser Weg wirklich testen kann.
_JSON_REACHABLE = [[], [1], {}, {"a": 1}]


class TestSdJwtWireformNeverRaises(unittest.TestCase):
    def test_corrupted_sd_alg_leaf_returns_verdict(self):
        """FANG: ein unhashbares `_sd_alg` (der gemessene Absturzpunkt) liefert ein Verdikt, kein Crash."""
        for corrupt in _JSON_REACHABLE:
            compact = _sdjwt_wireform({"_sd_alg": corrupt})
            with self.subTest(corrupt=type(corrupt).__name__):
                r = verify_sd_jwt(compact)  # issuer_pubkey=None -> keine Signaturpruefung
                self.assertIsInstance(r, dict, "verify_sd_jwt muss immer ein dict-Verdikt liefern")
                self.assertFalse(r.get("structure_ok"), "verdorbenes _sd_alg darf nicht structure_ok=True ergeben")

    def test_corrupted_leaf_in_arbitrary_field_returns_verdict(self):
        """FANG breit: ein verdorbenes Blatt in einem beliebigen Payload-Feld — Verdikt statt Crash."""
        for feld in ("_sd_alg", "_sd", "cnf", "vct", "iss", "sub"):
            for corrupt in _JSON_REACHABLE:
                compact = _sdjwt_wireform({feld: corrupt})
                with self.subTest(feld=feld, corrupt=type(corrupt).__name__):
                    self.assertIsInstance(verify_sd_jwt(compact), dict)

    def test_corrupted_leaf_in_disclosure_returns_verdict(self):
        """FANG zweite Achse: das verdorbene Blatt in einer DISCLOSURE statt im payload."""
        for corrupt in _JSON_REACHABLE:
            disclosure = _b64url(["salt", "claim", corrupt])
            compact = _sdjwt_wireform({"_sd_alg": "sha-256"}, disclosures=[disclosure])
            with self.subTest(corrupt=type(corrupt).__name__):
                self.assertIsInstance(verify_sd_jwt(compact), dict)

    def test_kontrolle_valid_wireform_no_false_alarm(self):
        """KONTROLLE: eine gueltige Drahtform OHNE Korruption liefert ein sauberes Verdikt — kein
        Fehlalarm aus kaputter Drahtform statt aus der Korruption."""
        compact = _sdjwt_wireform({"_sd_alg": "sha-256"})
        r = verify_sd_jwt(compact)
        self.assertIsInstance(r, dict)
        self.assertIn("disclosure", r.get("detail", ""))  # "0 disclosure(s)"

    def test_plant_reverted_membership_would_crash(self):
        """PLANT-AND-MUST-CATCH: mit dem Klassenfix zurueckgenommen (rohes `in` statt `is_member`) MUSS
        die verdorbene Drahtform roh stuerzen — sonst wuerde der Test die Klasse nicht binden.

        Gepatcht wird die EINE Stelle des Fixes im sdjwt-Modul; die Kontrolle beweist, dass der Fang
        oben nicht schon von selbst gruen war."""
        import proofbundle.sdjwt as _sd
        original = _sd.is_member
        _sd.is_member = lambda x, container: x in container  # der Vor-Fix-Zustand
        try:
            compact = _sdjwt_wireform({"_sd_alg": []})  # unhashbares Blatt an der Membership-Stelle
            with self.assertRaises(TypeError):
                _sd.verify_sd_jwt(compact)
        finally:
            _sd.is_member = original
        # und nach der Ruecklage ist der Fang wieder gruen (Drei-Lauf-Disziplin: gruen -> rot -> gruen)
        self.assertIsInstance(_sd.verify_sd_jwt(_sdjwt_wireform({"_sd_alg": []})), dict)


class TestKbJwtWireformNeverRaises(unittest.TestCase):
    def test_corrupted_kb_returns_verdict(self):
        """FANG fuer die zweite NON_JSON-Flaeche: eine kb+jwt-Drahtform mit verdorbenem Blatt liefert
        ein Verdikt-Tupel/-dict, kein Roh-Crash. verify_key_binding(holder_pubkey=None) prueft keine Sig."""
        for corrupt in _JSON_REACHABLE:
            kb_header = {"typ": "kb+jwt", "alg": "EdDSA"}
            kb_payload = {"iat": corrupt, "aud": "x", "nonce": "n"}
            kb = f"{_b64url(kb_header)}.{_b64url(kb_payload)}."
            sd_part = _sdjwt_wireform({"_sd_alg": "sha-256"})
            compact = sd_part + kb
            with self.subTest(corrupt=type(corrupt).__name__):
                r = verify_key_binding(compact)
                self.assertTrue(isinstance(r, (dict, tuple)), "verify_key_binding muss ein Verdikt liefern")


if __name__ == "__main__":
    unittest.main()
