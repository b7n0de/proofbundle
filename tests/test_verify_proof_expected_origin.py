"""`verify-proof` must let a relying party pin the checkpoint ORIGIN from the command line.

`verify_tlog_proof` has taken `expected_origin` since the release-review origin-acceptance fix, but
the argparse parser carried no flag and the command never passed one. A command-line verifier could
therefore not reject a validly signed checkpoint issued by a DIFFERENT log than the one it meant to
trust: the signature check passes, and without the origin constraint nothing else looks wrong. The
library-level path is already covered by tests/test_anchors_markovian_log.py; these tests pin the
CLI pass-through so the gap cannot silently reopen.

Vectors are the frozen markovianprotocol.com/log leaf 7271 fixture. Nothing is fetched, and no
optional extra is needed: Ed25519 verification rides on `cryptography`, a hard dependency.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import unittest

_FIXDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "markovian_log" / "proof_7271"
_PROOF = _FIXDIR / "proof_7271.tlog-proof"
_LEAF = _FIXDIR / "leaf_7271.raw"
_KEYS = _FIXDIR / "keys_unabhaengig.txt"
_ORIGIN = "markovianprotocol.com/log"
_WRONG_ORIGIN = "example.invalid/some-other-log"


def _log_vkey() -> str:
    """The log's verifier key, read from the fixture's key list, not from the audited log."""
    for line in _KEYS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.startswith(_ORIGIN + "+"):
            return line
    raise AssertionError("log vkey not found in keys_unabhaengig.txt")


def _run(*extra: str) -> tuple[int, str]:
    """Run the CLI in-process and return (exit code, stdout)."""
    from proofbundle.cli import main
    argv = ["verify-proof", str(_PROOF), "--payload-file", str(_LEAF),
            "--log-vkey", _log_vkey(), "--json", *extra]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


@unittest.skipUnless(_PROOF.is_file(), "markovian_log fixture not vendored")
class TestVerifyProofExpectedOrigin(unittest.TestCase):

    def test_flag_is_discoverable(self) -> None:
        """A capability nobody can find is not a capability."""
        from proofbundle.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            main(["verify-proof", "--help"])
        self.assertIn("--expected-origin", buf.getvalue())

    def test_default_leaves_origin_unconstrained(self) -> None:
        """Omitting the flag keeps the documented default, so existing invocations keep their verdict."""
        rc, out = _run()
        self.assertEqual(rc, 0)
        res = json.loads(out)
        self.assertTrue(res["ok"])
        self.assertEqual(res["origin"], _ORIGIN)

    def test_matching_origin_still_passes(self) -> None:
        """Pinning the origin the checkpoint actually carries must not change the verdict."""
        rc, out = _run("--expected-origin", _ORIGIN)
        self.assertEqual(rc, 0)
        res = json.loads(out)
        self.assertTrue(res["ok"])
        self.assertTrue(res["log_ok"])

    def test_mismatching_origin_fails_closed(self) -> None:
        """A validly signed checkpoint from the wrong log is rejected, and the reason is the origin."""
        rc, out = _run("--expected-origin", _WRONG_ORIGIN)
        self.assertEqual(rc, 1)
        res = json.loads(out)
        self.assertFalse(res["ok"])
        self.assertFalse(res["log_ok"])
        # the crypto is untouched: inclusion still holds and the reported origin is the real one
        self.assertTrue(res["inclusion_ok"])
        self.assertEqual(res["origin"], _ORIGIN)

    def test_text_output_names_the_expectation(self) -> None:
        """On the human path a FAIL must not read like a broken signature."""
        from proofbundle.cli import main
        buf = io.StringIO()
        argv = ["verify-proof", str(_PROOF), "--payload-file", str(_LEAF),
                "--log-vkey", _log_vkey(), "--expected-origin", _WRONG_ORIGIN]
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        self.assertEqual(rc, 1)
        self.assertIn(_WRONG_ORIGIN, buf.getvalue())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


# Der Origin-Vergleich muss EXAKT sein, und das war bis hierher unbelegt.
#
# GEMESSEN im Gate-Meta-Test der DEEP-Runde (2026-08-16): zwei eingepflanzte Lockerungen des
# Vergleichs -- `==` durch `.startswith()` ersetzt, und ein case-insensitiver Vergleich -- wurden
# von KEINEM der 2030 Tests gefangen. Der Grund steht in der Datei darueber: beide Origin-Tests
# pruefen ausschliesslich einen VOELLIG FREMDEN Wert (`example.invalid/some-other-log`). Gegen einen
# fremden Wert verhaelt sich ein gelockerter Vergleich genau wie ein exakter.
#
# Was fehlte, ist der BEINAHE-Treffer. Er ist der einzige Fall, der eine Lockerung sichtbar macht --
# und im Feld der gefaehrliche: wer einen eigenen Log betreibt, waehlt dessen Namen selbst.
class OriginVergleichIstExakt(unittest.TestCase):
    """Jeder Beinahe-Treffer MUSS fehlschlagen. Ein Praefix ist kein Treffer."""

    # Jede Zeile faengt eine bestimmte Lockerung.
    BEINAHE = [
        ("praefix",            _ORIGIN[:-4]),                    # startswith() in die eine Richtung
        ("suffix_angehaengt",  _ORIGIN + "-evil"),               # startswith() in die andere
        ("gross",              _ORIGIN.upper()),                 # casefold
        ("gemischt",           _ORIGIN.capitalize()),            # casefold
        ("fuehrendes_leer",    " " + _ORIGIN),                   # strip()
        ("folgendes_leer",     _ORIGIN + " "),                   # strip()
        ("zeilenumbruch",      _ORIGIN + "\n"),                  # strip()
        ("schraegstrich",      _ORIGIN + "/"),                   # rstrip("/")
        ("schema_davor",       "https://" + _ORIGIN),            # `in` statt `==`
        ("nur_domain",         _ORIGIN.split("/")[0]),           # startswith
        ("leer",               ""),                              # falsy-Kurzschluss
    ]

    def test_kein_beinahe_treffer_wird_akzeptiert(self) -> None:
        for name, kandidat in self.BEINAHE:
            with self.subTest(fall=name):
                rc, out = _run("--expected-origin", kandidat)
                res = json.loads(out)
                self.assertEqual(rc, 1, f"{name}: {kandidat!r} wurde akzeptiert")
                self.assertFalse(res["log_ok"], f"{name}: log_ok blieb wahr")
                # die Krypto bleibt unberuehrt: der Fehlschlag kommt vom Origin, nicht von der Signatur
                self.assertTrue(res["inclusion_ok"], f"{name}: inclusion_ok gekippt")
                self.assertEqual(res["origin"], _ORIGIN)

    def test_der_echte_wert_geht_weiterhin_durch(self) -> None:
        """Die Gegenrichtung, ohne die das Korpus oben auch bei einem IMMER-FALSCH-Vergleich gruen waere.

        Ein Test, der nur Ablehnungen prueft, wird von der schaerfsten moeglichen Lockerung -- gar
        nichts akzeptieren -- nicht rot. Dieselbe Falle wie ein Riegel, der alles blockt.
        """
        rc, out = _run("--expected-origin", _ORIGIN)
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["log_ok"])

    def test_unicode_normalform_zaehlt_als_unterschied(self) -> None:
        """NFC und NFD sehen gleich aus und sind verschiedene Bytes.

        Der Fixture-Origin ist reines ASCII, also ist er hier sein eigener Kandidat: die
        Normalisierung darf ihn nicht veraendern. Faellt die erste Zusicherung je, ist entweder die
        Fixture nicht mehr ASCII oder der Vergleich normalisierend geworden -- beides gehoert bemerkt,
        und ohne diese Zeile waere der Rest des Tests still gegenstandslos.
        """
        import unicodedata
        self.assertEqual(unicodedata.normalize("NFD", _ORIGIN), _ORIGIN,
                         "die Fixture ist nicht mehr reines ASCII — dieser Test misst dann etwas anderes")
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            with self.subTest(form=form):
                rc, _ = _run("--expected-origin", unicodedata.normalize(form, _ORIGIN))
                self.assertEqual(rc, 0, f"{form} des eigenen Origins wurde abgelehnt")


class DerTrefferZweigHatEinenWaechter(unittest.TestCase):
    """Der `" (expected)"`-Zweig war von keiner Zusicherung gedeckt.

    Gemessen (Linse 6 der DEEP-Runde): `cli.py` hat drei Zweige — kein Flag -> `""`, Treffer ->
    `" (expected)"`, Fehlschlag -> `f" (expected {…})"`. Der einzige Text-Modus-Test fuhr den
    FEHLSCHLAG; alle anderen liefen mit `--json`. Der Treffer-Zweig war damit die einzige
    Verhaltenszeile dieses Release ohne Waechter.
    """

    def _text(self, *extra: str) -> str:
        from proofbundle.cli import main
        buf = io.StringIO()
        argv = ["verify-proof", str(_PROOF), "--payload-file", str(_LEAF),
                "--log-vkey", _log_vkey(), *extra]
        with contextlib.redirect_stdout(buf):
            main(argv)
        return buf.getvalue()

    def test_bei_treffer_steht_expected_ohne_wiederholung(self) -> None:
        aus = self._text("--expected-origin", _ORIGIN)
        self.assertIn("(expected)", aus)
        self.assertNotIn(f"(expected {_ORIGIN})", aus,
                         "bei einem Treffer wird der Origin doppelt genannt — unnoetig laut")

    def test_ohne_flag_steht_gar_kein_zusatz(self) -> None:
        self.assertNotIn("(expected", self._text(),
                         "ohne Flag erscheint ein Erwartungs-Zusatz — der Default ist unconstrained")


class DasVerdiktNenntDieErwartungAuchMaschinell(unittest.TestCase):
    """Drei verschiedene Ursachen lieferten byte-identisches JSON.

    Gemessen (Linse 2): fremder Origin, falscher log-vkey und eine im Beweis verfaelschte Signatur
    ergaben denselben sha256 der JSON-Ausgabe. `inclusion_ok` bleibt in allen dreien True und trennt
    deshalb nichts. Der Textpfad trennte sie ueber `(expected …)`; dem JSON-Pfad fehlte das Feld.
    """

    def test_json_traegt_die_erwartung(self) -> None:
        rc, out = _run("--expected-origin", _WRONG_ORIGIN)
        res = json.loads(out)
        self.assertEqual(rc, 1)
        self.assertEqual(res["expected_origin"], _WRONG_ORIGIN)
        # und damit ist die Ursache maschinell lesbar: Origin gesetzt und != origin
        self.assertNotEqual(res["expected_origin"], res["origin"])

    def test_ohne_flag_ist_das_feld_None_nicht_leerstring(self) -> None:
        """`None` heisst 'nicht gefragt'. Ein leerer String hiesse 'gefragt und leer' — zwei
        verschiedene Lagen, und der Unterschied ist genau der, den dieses Feld tragen soll."""
        _, out = _run()
        self.assertIsNone(json.loads(out)["expected_origin"])

    def test_die_drei_ursachen_sind_jetzt_unterscheidbar(self) -> None:
        """Die Gegenprobe zum gemessenen Befund: zwei Faelle, die vorher gleich aussahen."""
        _, a = _run("--expected-origin", _WRONG_ORIGIN)     # fremder Origin
        _, b = _run()                                        # gar keine Erwartung
        self.assertNotEqual(a, b, "die JSON-Ausgaben sind weiterhin ununterscheidbar")
