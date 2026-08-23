"""Der Vor-Tag-Eintrag als signierte Attestierung — Prüferseite (ADR 0008).

WARUM. Am 2026-08-16 hat eine Dokumentations-Bearbeitung das Vor-Tag-Tor erfüllt: ein Messbericht
zitierte zwei Sätze, die das Tor als Attestierung liest, und die Suite meldete grün — für ein
Release ohne Audit-Eintrag. Eine Signatur kann eine Doku-Bearbeitung nicht erzeugen. Diese Datei
prüft, dass der Prüfer das auch wirklich leistet, und zwar in BEIDE Richtungen: kein Fehlschlag,
der durchkommt, und kein wahrhaftiger Eintrag, der abgelehnt wird.

DIE DREI EIGENSCHAFTEN AUS `test_pre_tag_gate_eigenschaften.py` fallen hier NEBENBEI heraus, und
das ist der Punkt: P1 (eine Datei ÜBER den Audit) hat keine Signatur, P2 (eine andere Version) und
P3 (ein Satz, der das Gegenteil sagt) scheitern an Feldern, die im signierten Rumpf stehen. Nicht
ein Regex mehr, sondern eine andere ART von Beleg.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer

_REPO = pathlib.Path(__file__).resolve().parents[1]
_MODUL = _REPO / "scripts" / "pre_tag_attestation.py"
_COMMIT = "0123456789abcdef0123456789abcdef01234567"
_VERSION = "3.8.0"


def _pta():
    if str(_REPO / "src") not in sys.path:
        sys.path.insert(0, str(_REPO / "src"))
    spec = importlib.util.spec_from_file_location("_pta_test", _MODUL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@unittest.skipUnless(_MODUL.is_file(), "scripts/pre_tag_attestation.py nicht vorhanden")
class SignierterVorTagEintrag(unittest.TestCase):

    def setUp(self) -> None:
        self.pta = _pta()
        self.key = generate_signer()
        self.pubkey = _pub(self.key)

    def _huelle(self, **ueberschreiben):
        felder = dict(commit=_COMMIT, version=_VERSION,
                      verifier_id="https://b7n0de.com/proofbundle/pre-tag",
                      time_verified="2026-08-16T21:00:00Z",
                      policy_uri="https://b7n0de.com/proofbundle/policy/pre-tag-audit/v1")
        felder.update(ueberschreiben)
        return self.pta.sign_statement(self.pta.build_statement(**felder), self.key)

    def _pruefe(self, huelle, key=None, **kw):
        felder = dict(expected_version=_VERSION, expected_commit=_COMMIT)
        felder.update(kw)
        return self.pta.verify(huelle, key if key is not None else self.pubkey, **felder)

    # ---- die Gegenrichtung zuerst: ein Prüfer, der NICHTS annimmt, ist keine Prüfung ----

    def test_ein_wahrhaftiger_eintrag_wird_angenommen(self) -> None:
        r = self._pruefe(self._huelle())
        self.assertTrue(r["ok"], r["reason"])
        for feld in ("signature_ok", "predicate_type_ok", "result_ok", "version_ok", "commit_ok"):
            self.assertTrue(r[feld], f"{feld} ist falsch bei einem gueltigen Eintrag")
        self.assertIsNone(r["reason"])

    # ---- und jetzt jede Richtung einzeln, mit BENANNTEM Grund ----

    def test_fremder_schluessel_faellt_und_sagt_es(self) -> None:
        r = self._pruefe(self._huelle(), key=_pub(generate_signer()))
        self.assertFalse(r["ok"])
        self.assertIn("signature_ok", r["reason"])

    def test_andere_version_faellt_und_sagt_es(self) -> None:
        r = self._pruefe(self._huelle(), expected_version="3.7.0")
        self.assertFalse(r["ok"])
        self.assertIn("version_ok", r["reason"])
        self.assertTrue(r["signature_ok"], "die Signatur ist gueltig — nur die Version passt nicht; "
                                           "wer das zusammenwirft, meldet den falschen Defekt")
        self.assertEqual(r["observed_version"], _VERSION)

    def test_anderer_commit_faellt_und_sagt_es(self) -> None:
        r = self._pruefe(self._huelle(), expected_commit="f" * 40)
        self.assertFalse(r["ok"])
        self.assertIn("commit_ok", r["reason"])
        self.assertEqual(r["observed_commit"], _COMMIT)

    def test_ein_FAILED_ergebnis_attestiert_nichts(self) -> None:
        """Ein signierter Eintrag, der sagt der Audit sei GESCHEITERT, ist keine Freigabe.

        Das ist die signierte Entsprechung von P3: der Satz, der das Gegenteil sagt. Hier kann er
        nicht durch eine Wortliste rutschen — das Feld ist zweiwertig und steht im signierten Rumpf.
        """
        r = self._pruefe(self._huelle(result="FAILED"))
        self.assertFalse(r["ok"])
        self.assertIn("result_ok", r["reason"])
        self.assertEqual(r["observed_result"], "FAILED")

    def test_eine_kaputte_huelle_faellt_geschlossen_ohne_traceback(self) -> None:
        for kaputt in ({}, {"payload": "x"}, {"payloadType": "text/plain", "payload": "x",
                                              "signatures": []}):
            with self.subTest(huelle=str(kaputt)[:40]):
                r = self._pruefe(kaputt)
                self.assertFalse(r["ok"])
                self.assertIsInstance(r["reason"], str)

    # ---- die Vergleiche sind EXAKT, auf BEIDEN Stellen ----

    def test_version_wird_EXAKT_verglichen(self) -> None:
        """Korpus aus `tests/_beinahe_treffer.py` — dieselbe Quelle wie kbjwt, statuslist, intoto,
        evalclaim, policy, cosignature und die CLI. Zwei Vergleichsstellen in `verify()` heissen
        zwei Stellen, die sich lockern lassen; deshalb laeuft das Korpus gegen beide."""
        from _beinahe_treffer import pruefe_exakt  # noqa: PLC0415

        huelle = self._huelle()
        pruefe_exakt(lambda v: self._pruefe(huelle, expected_version=v)["ok"], _VERSION, self)

    def test_commit_wird_EXAKT_verglichen(self) -> None:
        from _beinahe_treffer import pruefe_exakt  # noqa: PLC0415

        huelle = self._huelle()
        pruefe_exakt(lambda v: self._pruefe(huelle, expected_commit=v)["ok"], _COMMIT, self)

    # ---- die Aussage selbst lehnt Mehrdeutiges ab, BEVOR sie signiert wird ----

    def test_ein_abgekuerzter_commit_wird_nicht_signiert(self) -> None:
        """Eine Attestierung ueber einen mehrdeutigen Gegenstand ist keine Attestierung."""
        with self.assertRaises(ValueError):
            self.pta.build_statement(commit=_COMMIT[:12], version=_VERSION, verifier_id="x",
                                     time_verified="t", policy_uri="p")

    def test_es_gibt_keinen_dritten_ergebniswert(self) -> None:
        """`teilweise` wuerde als Bestehen gelesen — VSAs zweiwertige Form ist Absicht."""
        with self.assertRaises(ValueError):
            self.pta.build_statement(commit=_COMMIT, version=_VERSION, verifier_id="x",
                                     time_verified="t", policy_uri="p", result="PARTIAL")

    def test_eine_fremde_aussageform_wird_abgelehnt(self) -> None:
        """Prädikat-Verwechslung: eine GÜLTIG SIGNIERTE Aussage anderen Typs ist keine Attestierung
        über einen Vor-Tag-Audit.

        NACHGETRAGEN, nachdem die Rücknahme-Probe es gemessen hat: `predicate_type_ok` liess sich
        aus der Konjunktion entfernen, ohne dass ein einziger Test rot wurde — ein toter Zweig. Der
        Grund war, dass die vorhandene Prüfung die KONSTANTE und die gebaute Aussage ansah, aber nie
        eine fremde Hülle durch `verify()` schickte. Gestalt statt Verhalten; genau die Klasse, die
        `verify_eval_result_dsse` als WP-I1 dokumentiert.
        """
        st = self.pta.build_statement(commit=_COMMIT, version=_VERSION, verifier_id="x",
                                      time_verified="t", policy_uri="p")
        st["predicateType"] = "https://slsa.dev/verification_summary/v1"   # gueltig, aber fremd
        r = self._pruefe(self.pta.sign_statement(st, self.key))
        self.assertFalse(r["ok"], "eine fremde Aussageform wurde als Vor-Tag-Attestierung genommen")
        self.assertFalse(r["predicate_type_ok"])
        self.assertIn("predicate_type_ok", r["reason"])
        # Gegenprobe im selben Test: die Signatur ist gueltig — es scheitert NUR am Typ.
        self.assertTrue(r["signature_ok"], "Vorbedingung: die Huelle ist echt signiert, sonst misst "
                                           "dieser Test die Typpruefung gar nicht")

    def test_der_praedikat_typ_ist_unser_eigener_nicht_der_von_SLSA(self) -> None:
        """ADR 0008: VSAs Typ ist ueber SLSA-STUFEN definiert. Ihn fuer ein anderes Urteil zu
        benutzen hiesse, die Autoritaet eines Standards fuer eine Aussage zu borgen, die er nicht
        definiert. Die FORM folgt VSA, der TYP nicht — und das haelt ein Test fest, weil es sonst
        beim naechsten Aufraeumen wie eine Inkonsistenz aussieht."""
        self.assertNotIn("slsa.dev", self.pta.PREDICATE_TYPE)
        st = self.pta.build_statement(commit=_COMMIT, version=_VERSION, verifier_id="x",
                                      time_verified="t", policy_uri="p")
        self.assertEqual(st["predicateType"], self.pta.PREDICATE_TYPE)
        # die Form folgt VSA: Pruefer, Zeit, Politik, zweiwertiges Ergebnis
        for feld in ("verifier", "timeVerified", "policy", "verificationResult"):
            self.assertIn(feld, st["predicate"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
