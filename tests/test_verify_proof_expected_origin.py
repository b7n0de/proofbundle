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
import hashlib
import io
import json
import pathlib
import re
import unicodedata
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
    return _run_gegen(_PROOF, *extra)


def _run_gegen(proof: pathlib.Path, *extra: str) -> tuple[int, str]:
    """Wie `_run`, aber gegen eine BELIEBIGE Beweisdatei — fuer manipulierte Kopien."""
    from proofbundle.cli import main
    argv = ["verify-proof", str(proof), "--payload-file", str(_LEAF),
            "--log-vkey", _log_vkey(), "--json", *extra]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def _kopie_mit(ersatz: bytes, ziel: str, roh: bytes | None = None) -> "pathlib.Path | None":
    """Eine Wegwerf-Kopie der Fixture, in der `roh` durch `ersatz` getauscht ist.

    Die eingefrorene Fixture wird NIE geschrieben — sie ist der Bezugspunkt mehrerer Akten. Die
    Kopie liegt in einem tempdir, den der Aufrufer per addCleanup aufraeumt. Rueckgabe `None`, wenn
    das Muster nicht vorkommt: dann ist die Fixture eine andere geworden und der Test soll SKIPpen
    statt an einer stillschweigend falschen Annahme gruen zu werden.
    """
    import tempfile
    roh = roh if roh is not None else _ORIGIN.encode()
    daten = _PROOF.read_bytes()
    if roh not in daten:
        return None
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="pb-ctl-"))
    p = tmp / ziel
    p.write_bytes(daten.replace(roh, ersatz, 1))
    return p


def _mit_verfaelschter_signatur() -> "pathlib.Path | None":
    """Kippt ein Base64-Zeichen in der Signaturzeile des LOGS — und WEIST DIE WIRKUNG NACH.

    KORRIGIERT 2026-08-16, nachdem zwei unabhaengige Gegenlesungen denselben Defekt massen. Die
    erste Fassung nahm per `reversed()` die LETZTE Zeile mit dem Praefix `— <origin> ` und
    behauptete im Docstring, das sei "die Signaturzeile des LOGS selbst (nicht der Zeugen)".
    Gemessen gibt es ZWEI solche Zeilen: Index 18 (Laenge 120, die Notensignatur des Logs) und
    Index 28 (Laenge 3272, eine Zeugen-Cosignatur unter demselben Namen). Der Helfer traf die
    zweite. Ihre Verfaelschung laesst `log_ok` auf True — die Kopie war byte-gleich wirksam wie
    gar keine, und der Test darueber war gruen, egal ob verfaelscht wurde oder nicht.
    Entscheidprobe der Gegenlesung: mit einer byte-identischen Kopie lief er ebenfalls gruen.

    Deshalb waehlt der Helfer die Zeile jetzt nicht mehr nach POSITION oder LAENGE, sondern nach
    GEMESSENER WIRKUNG: er probiert jede Kandidatenzeile und gibt nur eine Kopie zurueck, bei der
    `log_ok` wirklich auf False faellt. Eine Heuristik ueber die Gestalt hat hier schon einmal die
    falsche Zeile gewaehlt; die Eigenschaft, um die es geht, ist messbar, also wird sie gemessen.
    Faellt bei keiner Kandidatenzeile `log_ok`, gibt er `None` zurueck und der Test SKIPpt, statt
    an einer stillschweigend falschen Annahme gruen zu werden.
    """
    import shutil
    praefix = "— " + _ORIGIN + " "
    for zeile in _PROOF.read_text(encoding="utf-8", errors="replace").split("\n"):
        if not (zeile.startswith(praefix) and len(zeile) > 10):
            continue
        kaputt = zeile[:-1] + ("A" if zeile[-1] != "A" else "B")
        kandidat = _kopie_mit(kaputt.encode(), "badsig.tlog-proof", roh=zeile.encode())
        if kandidat is None:
            continue
        try:
            _, aus = _run_gegen(kandidat)
            if json.loads(aus).get("log_ok") is False:
                return kandidat
        except Exception:      # noqa: BLE001 — eine unbrauchbare Kandidatenzeile ist kein Fehler
            pass
        shutil.rmtree(kandidat.parent, ignore_errors=True)   # kein tempdir-Leck je Versuch
    return None


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
def _vollbreite(s: str) -> str:
    """Die Vollbreiten-Form derselben Zeichenkette: NFKC(ergebnis) == s, die Bytes sind andere.

    Das macht sie zum einzigen Beinahe-Treffer, der eine NORMALISIERENDE Vergleichsform sichtbar
    macht — ein reiner ASCII-Origin ist unter allen vier Normalformen sein eigenes Bild und kann
    das prinzipiell nicht.
    """
    aus = []
    for ch in s:
        o = ord(ch)
        if 0x21 <= o <= 0x7E:
            aus.append(chr(o - 0x21 + 0xFF01))    # ! .. ~  ->  Vollbreiten-Block
        else:
            aus.append(ch)
    return "".join(aus)


@unittest.skipUnless(_PROOF.is_file(), "markovian_log fixture not vendored")
class OriginVergleichIstExakt(unittest.TestCase):
    """Jeder Beinahe-Treffer MUSS fehlschlagen. Ein Praefix ist kein Treffer."""

    # Jede Zeile faengt eine bestimmte Lockerung.
    BEINAHE = [
        # ERGAENZT 2026-08-16. Eine Delta-Gegenlesung hat gemessen, dass VIER Lockerungs-Klassen das
        # Korpus darunter ueberleben: NFKC-Normalisierung, ein gestrippter Punkt am Hostende,
        # `//` -> `/`, und Prozent-Dekodierung. Jede davon ist eine Form, in der ein fremder Log
        # denselben Namen tragen kann wie der gemeinte. Die Kandidaten hier sind nicht ausgedacht:
        # zu jedem hat die Gegenlesung die ueberlebende Mutante konkret benannt.
        ("vollbreite_zeichen",  _vollbreite(_ORIGIN)),           # NFKC-Normalisierung
        ("nfkd_kompatibel",     _vollbreite(_ORIGIN[:6]) + _ORIGIN[6:]),   # dieselbe Klasse, teilweise
        ("punkt_am_host",       _ORIGIN.replace(".com/", ".com./")),       # DNS-Wurzelpunkt gestrippt
        ("doppelter_strich",    _ORIGIN.replace(".com/", ".com//")),       # `//` -> `/`
        ("prozent_kodiert",     _ORIGIN.replace("/", "%2F")),              # Prozent-Dekodierung
        ("prozent_im_pfad",     _ORIGIN.replace("log", "lo%67")),          # dieselbe Klasse, im Pfad
        ("praefix",            _ORIGIN[:-1]),                    # startswith() in die eine Richtung
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

    def test_vollbreite_form_ist_nicht_derselbe_origin(self) -> None:
        """ERSETZT einen Test, der seinen eigenen Namen nicht pruefen konnte.

        Hier stand `test_unicode_normalform_zaehlt_als_unterschied`: er fuhr NFC/NFD/NFKC/NFKD des
        Fixture-Origins durch und erwartete `rc == 0`. Weil dieser Origin reines ASCII ist, sind alle
        vier Normalformen DIESELBE Zeichenkette — vier subTests, ein einziger Wert, und derselbe, den
        der Nachbartest schon prueft. Vor allem aber sicherte er die Annahme zu (`rc == 0`) und
        konnte einen NORMALISIERENDEN Vergleich damit strukturell nicht roeten. Genau diese Lockerung
        (NFKC) hat die Gegenlesung als ueberlebend gemessen — der Test trug den Namen des Defekts,
        den er nicht finden konnte.

        Die Vollbreiten-Form ist der Kandidat, der es kann: NFKC bildet sie auf den echten Origin ab,
        die Bytes sind verschieden. Ein exakter Vergleich lehnt sie ab, ein normalisierender nicht.
        """
        import unicodedata
        kandidat = _vollbreite(_ORIGIN)
        # Die zwei Eigenschaften, die den Fall UEBERHAUPT erst zu einem Beinahe-Treffer machen. Ohne
        # sie misst der Test unten etwas anderes als er behauptet.
        self.assertNotEqual(kandidat, _ORIGIN, "die Vollbreiten-Abbildung hat nichts veraendert")
        self.assertEqual(unicodedata.normalize("NFKC", kandidat), _ORIGIN,
                         "NFKC bildet den Kandidaten nicht auf den Origin ab — kein Beinahe-Treffer")
        rc, out = _run("--expected-origin", kandidat)
        self.assertEqual(rc, 1, "die Vollbreiten-Form wurde akzeptiert — der Vergleich normalisiert")
        self.assertFalse(json.loads(out)["log_ok"])


@unittest.skipUnless(_PROOF.is_file(), "markovian_log fixture not vendored")
class DieSchrankeStehtNebenIhremBoolean(unittest.TestCase):
    """`witnesses_ok` allein ist kein Verdikt — ohne die Schranke ist es nicht lesbar.

    GEMESSEN (Befund `FINDING_quorum_erreicht_ununterscheidbar_von_keins_verlangt.md`):
    `witness_quorum` gibt `len(confirmed) >= threshold` zurueck, und die Voreinstellung ist 0.
    `witnesses_ok` war damit BEDINGUNGSLOS true, wenn niemand ein Quorum verlangt hat — dasselbe
    `true` fuer "verlangt und erreicht" wie fuer "nie verlangt", und kein Feld trennte die beiden.
    Zeugen zaehlen half nicht: null bestaetigende Zeugen sind unter threshold=0 ein legitimer
    Zustand, und derselbe Nullwert unter einer verlangten Schranke haette `witnesses_ok` auf false
    gesetzt — nur weiss man das ohne die Schranke eben nicht.

    Der TEXTPFAD nannte sie immer ("threshold {T}"). Wer `--json` automatisierte, bekam weniger als
    wer ins Terminal sah; das ist die eigentliche Schieflage.

    KLASSE, nicht Instanz: die Familie ist "jedes `*_ok` in einem JSON-Verdikt, dessen Berechnung
    eine einstellbare Schranke enthaelt". Gemessen wurde sie ueber alle wertnehmenden CLI-Flaggen:
    `--expected-tree-size` steht bereits in der reichen Form (`treeSizeExpectation`),
    `--verification-time` erscheint im JSON sobald gesetzt (und seine Abwesenheit heisst "jetzt",
    nicht "keine Anforderung"), `--n`/`--k` sind Pflichtargumente ohne Abwesenheitsfall. Ein
    Mitglied, und das ist dieses.
    """

    def test_die_schranke_steht_im_json(self) -> None:
        _, out = _run()
        d = json.loads(out)
        self.assertIn("threshold", d, "der Boolean kommt ohne seine Schranke — nicht lesbar")
        self.assertEqual(d["threshold"], 0, "die dokumentierte Voreinstellung")

    def test_verlangt_und_erreicht_ist_von_nie_verlangt_unterscheidbar(self) -> None:
        """Die EINE Eigenschaft, um die es geht — beide Laeufe sind gruen und trotzdem verschieden."""
        _, ohne = _run()
        _, mit = _run("--threshold", "0")
        # Gegenprobe des Messaufbaus: ohne Zeugenschluessel bestaetigt niemand, beide sind true.
        self.assertTrue(json.loads(ohne)["witnesses_ok"])
        self.assertTrue(json.loads(mit)["witnesses_ok"])
        bestaetigt = sum(1 for w in json.loads(ohne)["witnesses"].values() if w["ok"])
        self.assertEqual(bestaetigt, 0, "Vorbedingung: es bestaetigt wirklich niemand")
        # ... und genau deshalb muss die Schranke danebenstehen, sonst ist das true nicht deutbar.
        self.assertEqual(json.loads(ohne)["threshold"], 0)

    def test_eine_unerfuellbare_schranke_meldet_sich_mit_ihrem_wert(self) -> None:
        rc, out = _run("--threshold", "9")
        d = json.loads(out)
        self.assertEqual(rc, 1)
        self.assertFalse(d["witnesses_ok"])
        self.assertEqual(d["threshold"], 9,
                         "der Fehlschlag nennt die Schranke nicht, an der er scheiterte")


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

    def test_der_leerstring_bekommt_im_textpfad_seinen_zusatz(self) -> None:
        """Die dritte Lage des Textpfads, und sie war ungedeckt.

        GEMESSEN von einer Gegenlesung: `cli.py:988` mit `if args.expected_origin:` statt
        `is not None` — also der Zusammenfall von "nicht gefragt" und "gefragt und leer" — liess
        ALLE 2086 Tests gruen. Der Mutant aendert weder rc noch JSON; er verschweigt nur im
        Textpfad, dass eine Erwartung GESETZT und verletzt wurde. Ein Pruefer, der `--expected-origin
        "$VAR"` mit leerem VAR faehrt, saehe ein nacktes `[FAIL] log-signature: <origin>` und
        suchte den Fehler beim Artefakt statt bei seiner eigenen Zeile.

        Der Zusatz `(expected )` ist optisch mager — aber er ist der EINZIGE Unterschied zwischen
        den beiden Lagen auf diesem Pfad, und genau deshalb steht er hier fest.
        """
        aus = self._text("--expected-origin", "")
        self.assertIn("(expected", aus,
                      "ein leerer Erwartungswert erscheint im Textpfad gar nicht — 'gefragt und "
                      "leer' ist damit von 'nicht gefragt' nicht zu unterscheiden")
        self.assertIn("[FAIL]", aus)


@unittest.skipUnless(_PROOF.is_file(), "markovian_log fixture not vendored")
class DasVerdiktNenntDieErwartungAuchMaschinell(unittest.TestCase):
    """Der JSON-Pfad meldet jetzt, WONACH gefragt wurde. Mehr nicht — und das stand hier falsch.

    KORRIGIERT 2026-08-16 nach einer Delta-Gegenlesung, die den Fix gegen den Stand OHNE ihn
    ausgefuehrt hat. Hier stand: "Drei verschiedene Ursachen lieferten byte-identisches JSON …
    dem JSON-Pfad fehlte das Feld", mit der Lesart, das Feld schliesse die Luecke. Gemessen ist das
    FALSCH: mit `--expected-origin` sind fremder Origin, falscher log-vkey und verfaelschte Signatur
    **weiterhin** byte-identisch, weil das Feld die EINGABE des Pruefers echot und in allen drei
    Faellen dieselbe ist. Was das Feld wirklich trennt, ist `gefragt` von `nicht gefragt` -- eine
    echte, aber schmalere Eigenschaft als der alte Text behauptete.

    Der Unterschied ist nicht kosmetisch: wer den alten Satz liest, haelt die Ursachen-Trennung fuer
    erledigt und baut darauf. Sie ist es nicht. Die offene Luecke steht als Befund in
    `audit_artifacts/380/FINDING_json_trennt_die_drei_ursachen_nicht.md`; ihr Fix waere ein eigenes
    Ursachen-Feld, und das ist eine neue oeffentliche Ausgabeflaeche, die nicht unter Release-Druck
    entsteht.
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
        verschiedene Lagen, und der Unterschied ist genau der, den dieses Feld tragen soll.

        ERGAENZT 2026-08-16. Der Test trug die Eigenschaft im NAMEN und prueft in seiner ersten
        Fassung nur das JSON-ECHO-Feld. Ein Gate-Meta-Test hat das ausgeloest: mit der Pflanzung
        `not expected_origin` statt `is not None` — also genau dem Zusammenfall von "nicht gefragt"
        und "gefragt und leer" — blieb dieser Test GRUEN. Rot wurde nur ein einziger Untertest des
        Korpus (`("leer", "")`). Die Eigenschaft haengt jetzt dort, wo ihr Name steht.
        """
        _, out = _run()
        self.assertIsNone(json.loads(out)["expected_origin"])
        # der Leerstring ist eine GESTELLTE Frage und muss fehlschlagen, nicht uebersprungen werden
        rc, leer = _run("--expected-origin", "")
        d = json.loads(leer)
        self.assertEqual(rc, 1, "ein leerer Origin wurde wie 'nicht gefragt' behandelt")
        self.assertFalse(d["log_ok"])
        self.assertEqual(d["expected_origin"], "", "'gefragt und leer' meldet sich nicht als solches")

    def test_das_feld_trennt_gefragt_von_nicht_gefragt(self) -> None:
        """Die EINE Eigenschaft, die das Feld wirklich traegt — und ein Waechter, der sie messen kann.

        ERSETZT `test_die_drei_ursachen_sind_jetzt_unterscheidbar`, der wirkungslos war: er verglich
        "fremder Origin" mit "gar keine Erwartung", also zwei Faelle, die auch VOR dem Fix
        verschieden waren (`log_ok` kippt im einen und nicht im anderen). Am Stand ohne den Fix
        gemessen: die Zusicherung war dort bereits gruen. Ein Test, der den Defekt seines eigenen
        Namens nicht roeten kann, ist keine Zusicherung, sondern eine Dekoration.
        """
        _, ohne = _run()
        _, mit = _run("--expected-origin", _ORIGIN)          # TREFFER, damit `log_ok` gleich bleibt
        a, b = json.loads(ohne), json.loads(mit)
        self.assertIsNone(a["expected_origin"])
        self.assertEqual(b["expected_origin"], _ORIGIN)
        # Gegenprobe des Messaufbaus: die beiden Laeufe unterscheiden sich SONST in nichts. Waere das
        # nicht so, koennte der Test durch irgendeine andere Abweichung gruen werden.
        self.assertEqual({k: v for k, v in a.items() if k != "expected_origin"},
                         {k: v for k, v in b.items() if k != "expected_origin"},
                         "die beiden Laeufe unterscheiden sich in mehr als dem Erwartungs-Feld")

    def test_falscher_schluessel_und_verfaelschte_signatur_bleiben_ununterscheidbar(self) -> None:
        """Haelt den GEMESSENEN Stand fest — und zwar das richtige Paar.

        KORRIGIERT 2026-08-16 nach zwei Gegenlesungen, die BEIDE Konstruktionsfehler massen.

        (1) Das Paar war falsch gewaehlt. Verglichen wurden "fremder Origin" und "verfaelschte
        Signatur", beide mit demselben FREMDEN Origin gepinnt — dann ist `log_ok` schon aus dem
        Origin-Grund False, und die Gleichheit galt aus einem Grund, der mit der benannten
        Eigenschaft nichts zu tun hat. Bei BESTIMMUNGSGEMAESSER Nutzung (der Pruefer pinnt den
        Origin, dem er traut) ist der fremde Origin sehr wohl maschinell lesbar: `expected_origin`
        weicht dann von `origin` ab. Ununterscheidbar sind die ANDEREN beiden — falscher
        log-vkey und verfaelschte Signatur. Genau die vergleicht dieser Test jetzt, mit dem
        RICHTIGEN Origin gepinnt.

        (2) Die "verfaelschte Signatur" war keine, siehe `_mit_verfaelschter_signatur`.

        Der Test haelt den offenen Befund ausfuehrbar fest: wird die Luecke je geschlossen, wird er
        rot und zwingt dazu, den Befund zu schliessen statt ihn zu vergessen. Ein bekannter Mangel
        ohne Waechter wird still zur Legende.
        """
        import shutil

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from proofbundle.checkpoint import vkey as mach_vkey

        # (a) falscher log-vkey: RICHTIGER Name, fremdes Schluesselmaterial. Ein fremder NAME traefe
        #     einen malformed-Pfad und maesse etwas anderes.
        fremd = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        falscher_vkey = mach_vkey(_ORIGIN, fremd)

        from proofbundle.cli import main
        def lauf(vk: str, proof: pathlib.Path) -> str:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                main(["verify-proof", str(proof), "--payload-file", str(_LEAF),
                      "--log-vkey", vk, "--json", "--expected-origin", _ORIGIN])
            return buf.getvalue()

        a_txt = lauf(falscher_vkey, _PROOF)

        # (b) verfaelschte Signatur, mit nachgewiesener Wirkung
        verfaelscht = _mit_verfaelschter_signatur()
        # KEIN skipTest hier — eine Gegenlesung hat das zu Recht als Defekt benannt. Die Klasse ist
        # bereits `skipUnless(_PROOF.is_file())`; wenn die Fixture DA ist und trotzdem keine Zeile
        # wirkt, hat sich ihr Format geaendert und dieser Test misst nichts mehr. Ein SKIP waere
        # dann die stille Variante von "nichts gefunden = alles gut" und ginge in einer Suite mit
        # 2000 Tests unter. Drei Zustaende: Fixture fehlt -> SKIP (die Klasse) · Fixture da, keine
        # Zeile wirkt -> FAIL (etwas hat sich geaendert) · Zeile wirkt -> messen.
        self.assertIsNotNone(
            verfaelscht,
            "keine Signaturzeile der Fixture kippt log_ok — das Format hat sich geaendert und "
            "dieser Waechter misst nichts mehr. Er darf hier nicht schweigen.")
        self.addCleanup(shutil.rmtree, verfaelscht.parent, True)
        b_txt = lauf(_log_vkey(), verfaelscht)

        a, b = json.loads(a_txt), json.loads(b_txt)
        # Gegenprobe des Aufbaus: BEIDE Ursachen muessen wirklich gefallen sein, und zwar an
        # `log_ok`. Ohne diese zwei Zeilen waere der Vergleich unten auch dann wahr, wenn eine der
        # beiden Konstruktionen gar nichts bewirkt haette — genau der Fehler, der hier stand.
        self.assertFalse(a["log_ok"], "der falsche Schluessel hat log_ok nicht gekippt")
        self.assertFalse(b["log_ok"], "die verfaelschte Signatur hat log_ok nicht gekippt")

        self.assertEqual(
            hashlib.sha256(a_txt.encode()).hexdigest(),
            hashlib.sha256(b_txt.encode()).hexdigest(),
            "falscher Schluessel und verfaelschte Signatur sind maschinell unterscheidbar geworden "
            "— gut! Dann ist audit_artifacts/380/FINDING_json_trennt_die_drei_ursachen_nicht.md "
            "geschlossen und dieser Waechter gehoert durch eine positive Zusicherung ersetzt.")

    def test_der_fremde_origin_ist_bei_richtigem_pin_sehr_wohl_lesbar(self) -> None:
        """Die Gegenrichtung zum Test darueber — und die Korrektur einer zu weiten Behauptung.

        Die erste Fassung des Befunds sagte pauschal, mit gesetztem Flag seien ALLE DREI Ursachen
        byte-identisch. Gemessen gilt das nur, wenn der Pin selbst schon nicht passt. Pinnt der
        Pruefer den Origin, dem er traut — der dokumentierte Gebrauch —, dann trennt sich der
        fremde Origin sehr wohl: `expected_origin` weicht von `origin` ab.
        """
        _, fremd = _run("--expected-origin", _WRONG_ORIGIN)
        d = json.loads(fremd)
        self.assertNotEqual(d["expected_origin"], d["origin"],
                            "die Abweichung ist im JSON nicht sichtbar")
        self.assertFalse(d["log_ok"])


@unittest.skipUnless(_PROOF.is_file(), "markovian_log fixture not vendored")
class SteuerzeichenKoennenKeineZeileFaelschen(unittest.TestCase):
    """Die Sicherheits-Haelfte dieses Release hatte KEINEN Waechter — gemessen, nicht vermutet.

    Eine Delta-Gegenlesung hat alle vier neuen `_safe_line`-Umwicklungen zurueckgenommen und die
    volle Suite gefahren: unveraendert, derselbe eine rote Test. Der einzige vorhandene Test prueft
    die FUNKTION isoliert; keine Zusicherung prueft eine ihrer AUFRUFSTELLEN. Die andere Haelfte
    desselben Commits (das JSON-Feld, der Treffer-Zweig) bekam drei neue Testklassen, ausdruecklich
    weil ihre Zweige ungedeckt waren. Die Kontrollzeichen-Haelfte bekam null — und sie ist die
    sicherheitsrelevante.

    Der Angriff braucht KEINE Signatur: `verify_checkpoint` gibt den geparsten Origin auch bei
    `ok=False` zurueck, und die CLI druckt ihn auf einer beschrifteten Zeile. Wer einen Beweis
    ausliefert, waehlt dessen Origin-Bytes frei und kann mit `\\x1b[2K\\x1b[G` die gedruckte
    FAIL-Zeile ueberschreiben und durch eine gefaelschte PASS-Zeile ersetzen.
    """

    def _text_gegen(self, proof: pathlib.Path, *extra: str) -> str:
        from proofbundle.cli import main
        buf = io.StringIO()
        argv = ["verify-proof", str(proof), "--payload-file", str(_LEAF),
                "--log-vkey", _log_vkey(), *extra]
        with contextlib.redirect_stdout(buf):
            main(argv)
        return buf.getvalue()

    def test_origin_aus_der_beweisdatei_kann_die_ausgabe_nicht_ueberschreiben(self) -> None:
        """Aufrufstelle 1: `log-signature: {origin}` — der Wert kommt aus der Datei des Angreifers."""
        import shutil
        boese = ("evil.example/log\x1b[2K\x1b[G[PASS] log-signature: " + _ORIGIN).encode()
        kopie = _kopie_mit(boese, "ctl_origin.tlog-proof")
        if kopie is None:
            self.skipTest("Origin-Zeichenkette in der Fixture nicht auffindbar")
        self.addCleanup(shutil.rmtree, kopie.parent, True)
        aus = self._text_gegen(kopie)
        self.assertNotIn("\x1b", aus, "eine ANSI-Sequenz aus der Beweisdatei erreicht das Terminal")
        # Gegenprobe des Messaufbaus: der boesartige Wert kommt sehr wohl AN, nur entschaerft. Ohne
        # diese Zeile waere der Test auch dann gruen, wenn der Origin gar nicht gedruckt wuerde.
        self.assertIn("evil.example/log", aus, "der manipulierte Origin wird gar nicht ausgegeben — "
                                               "dieser Test misst dann nicht mehr, was er behauptet")

    # ZWOELF ZEICHENKLASSEN, nicht eine. Eine Gegenlesung hat benannt, dass die zwei
    # Verhaltenstests je GENAU EIN Zeichen fuettern (ESC bzw. LF): eine Haertung, die etwa CR
    # durchliesse, waere hier gruen geblieben und nur vom isolierten `_safe_line`-Test gefangen
    # worden. Die Funktion ist per Konstruktion eine Whitelist (`isprintable()`) und deckt alle
    # zwoelf ab — gedeckt war bisher die FUNKTION, nicht die AUFRUFSTELLE.
    STEUERZEICHEN = [
        ("ESC",  "\x1b"),   # der eigentliche Angriff: Loeschsequenz + gefaelschte Zeile
        ("LF",   "\n"),     # eine zweite Zeile erfinden
        ("CR",   "\r"),     # Cursor an den Zeilenanfang, ueberschreibt ohne Loeschsequenz
        ("NUL",  "\x00"),
        ("TAB",  "\t"),
        ("BS",   "\x08"),   # rueckwaerts loeschen
        ("VT",   "\x0b"),
        ("FF",   "\x0c"),
        ("DEL",  "\x7f"),
        ("CSI",  "\x9b"),   # die 8-Bit-Form von ESC[
        ("ZWSP", "​"), # unsichtbar, kann Namen optisch verschmelzen
        ("NBSP", " "),
    ]

    def test_erwartungs_zusatz_aus_der_kommandozeile_kann_keine_zeile_faelschen(self) -> None:
        """Aufrufstelle 2: `(expected {…})` — der Wert kommt aus argv, ueber alle zwoelf Klassen.

        GEPRUEFT WIRD DIE EIGENSCHAFT, NICHT DAS ZEICHEN. Die erste Fassung dieser Schleife verbot
        das Zeichen im GANZEN stdout — und fiel prompt am Zeilenumbruch, den die Ausgabe zwischen
        ihren eigenen Zeilen voellig legitim traegt. Das war mein Denkfehler, kein Defekt am Code:
        die Eigenschaft heisst "der Wert kann seine Zeile nicht verlassen", nicht "das Zeichen kommt
        nirgends vor". Gemessen wird deshalb an der ZEILE, die den Wert traegt.
        """
        for name, ch in self.STEUERZEICHEN:
            with self.subTest(zeichen=name):
                boese = f"evil.example/log{ch}CRYPTO: OK"
                aus = self._text_gegen(_PROOF, "--expected-origin", boese)
                traeger = [z for z in aus.split("\n") if "evil.example/log" in z]
                # Gegenprobe je Fall: der Wert kommt SEHR WOHL an, nur entschaerft. Ohne sie waere
                # alles darunter auch dann wahr, wenn gar nichts gedruckt wuerde.
                self.assertEqual(len(traeger), 1,
                                 f"{name}: der Erwartungswert steht auf {len(traeger)} Zeilen statt "
                                 "auf genau einer — dieser Untertest misst dann etwas anderes")
                zeile = traeger[0]
                self.assertIn("CRYPTO: OK", zeile,
                              f"{name} (U+{ord(ch):04X}): die Nutzlast hat die Zeile VERLASSEN — "
                              "genau der Ausbruch, den die Umwicklung verhindern soll")
                self.assertNotIn(ch, zeile,
                                 f"{name} (U+{ord(ch):04X}) erreicht das Terminal roh")
                self.assertFalse(any(z.lstrip().startswith("CRYPTO:") for z in aus.split("\n")),
                                 f"{name}: eine erfundene CRYPTO-Zeile steht am Zeilenanfang")

    def test_die_vier_neuen_aufrufstellen_bleiben_umwickelt(self) -> None:
        """Ein Verhaltenstest deckt zwei der vier Stellen; diese Zusicherung haelt alle vier fest.

        Nicht als Ersatz fuer die Verhaltenstests oben, sondern gegen die andere Fehlerart: eine
        spaetere Umformung, die eine Umwicklung entfernt, ohne dass eine der beiden erreichbaren
        Stellen betroffen ist. `sample-opening` und `enclave-attestation` sind aus einer
        tlog-proof-Fixture nicht erreichbar — ihre Deckung ist hier bewusst eine Gestaltpruefung,
        und das steht hier, damit niemand sie fuer mehr haelt.
        """
        import ast
        import pathlib as _pl
        import proofbundle.cli as _cli
        quelle = _pl.Path(_cli.__file__).read_text(encoding="utf-8")
        baum = ast.parse(quelle)

        # VERSCHAERFT 2026-08-16. Die erste Fassung fragte nur, ob IRGENDWO im selben f-String ein
        # `_safe_line` vorkommt und ob der Beschriftungstext das Wort enthaelt. Eine Gegenlesung hat
        # drei Umgehungen GEMESSEN, jede mit rohem ESC in stdout und gruenem Test:
        #   (a) `_safe_line = lambda s: s` lokal davor  — der Name stimmt, die Funktion nicht
        #   (b) `{str(res['detail'])}{_safe_line('')}`  — ein Alibi-Aufruf auf einer Konstante
        #   (c) ein UNBETEILIGTER f-String mit `_safe_line` und dem Wort uebernimmt die Deckung
        # Deshalb bindet der Waechter jetzt an die STELLE statt an das Wort: die Einsetzung, die
        # direkt hinter der Beschriftung steht, MUSS selbst der `_safe_line`-Aufruf sein, und sein
        # Argument darf keine Konstante sein.
        beschriftung = re.compile(r"([a-z-]+):\s*$")
        ERWARTET = {"log-signature", "expected", "sample-opening", "enclave-attestation"}
        gefunden: set[str] = set()

        def _ist_echte_umwicklung(fv: ast.FormattedValue) -> bool:
            """Der eingesetzte Ausdruck IST ein _safe_line(...) mit nicht-konstantem Argument."""
            k = fv.value
            if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                    and k.func.id == "_safe_line" and k.args):
                return False
            return not isinstance(k.args[0], ast.Constant)     # schliesst (b) aus

        for arg in ast.walk(baum):
            if not isinstance(arg, ast.JoinedStr):
                continue
            vorher = ""
            for teil in arg.values:
                if isinstance(teil, ast.Constant) and isinstance(teil.value, str):
                    vorher += teil.value
                    continue
                if isinstance(teil, ast.FormattedValue):
                    m = beschriftung.search(vorher)
                    if m and m.group(1) in ERWARTET and _ist_echte_umwicklung(teil):
                        gefunden.add(m.group(1))
                    # `expected` steht als `(expected {…})`, nicht als `expected:`
                    if "(expected " in vorher and _ist_echte_umwicklung(teil):
                        gefunden.add("expected")
                    vorher = ""
        fehlend = ERWARTET - gefunden
        self.assertFalse(fehlend, f"nicht mehr durch _safe_line gefuehrt: {sorted(fehlend)}")

        # DIE UMKEHRUNG, und sie ist der eigentliche Klassen-Fix. Die vier Marken oben sind eine
        # AUFZAEHLUNG — sie faengt nicht, woran niemand gedacht hat, und genau das ist passiert:
        # ein Sweep dieser Runde fand `anchor verify-pack` und `anchor upgrade`, zwei beschriftete
        # stdout-Zeilen derselben Form, deren `detail` drei Anker-Module aus einem Ausnahmetext
        # bauen. Deshalb gilt ab hier die Regel statt der Liste: JEDE Einsetzung, die ein
        # `detail`- oder `origin`-Feld liest, geht durch `_safe_line` — ausser den hier NAMENTLICH
        # und mit Grund ausgenommenen. Eine neue Zeile bindet damit automatisch.
        AUSGENOMMEN = {
            # (Zeile ist nicht stabil — Schluessel ist der Ausdruck, wie ast.unparse ihn schreibt)
            "res['detail']":     "prereg/evalcard: die detail-Werte sind Literale (prereg.py:78-94, "
                                 "evalcard.py:78-96), kein fremdkontrollierter Text",
            "binding['detail']": "geht nach stderr, nicht auf eine beschriftete stdout-Zeile",
            "ev['detail']":      "eval_evidence_class berechnet den Wert, er stammt nicht aus einer Datei",
        }
        offen = []
        for arg in ast.walk(baum):
            if not isinstance(arg, ast.JoinedStr):
                continue
            for teil in arg.values:
                if not isinstance(teil, ast.FormattedValue):
                    continue
                q = ast.unparse(teil.value)
                # BEIDE Zugriffsformen. Eine Gegenlesung hat gemessen, dass die erste Fassung nur
                # `x['detail']` sah: `res.get('detail')` liest denselben Wert und ging durch. Heute
                # kommt die zweite Form in cli.py 0x vor — ein Waechter existiert aber fuer morgen,
                # und die Umgehung waere eine Zeichenaenderung.
                if not re.search(r"\['(?:detail|origin)'\]|\.get\(\s*['\"](?:detail|origin)['\"]", q):
                    continue
                if "_safe_line" in q:
                    continue
                # `!r` ist eine GLEICHWERTIGE Verteidigung, keine Ausnahme. Die Eigenschaft, um
                # die es geht, ist "der Wert kann keine Zeile faelschen" — und `repr()` leistet
                # das: gemessen wird ESC zu `\x1b`, ein Zeilenumbruch zu `\n`, ZWSP zu `​`,
                # kein rohes Steuerzeichen bleibt uebrig. Wer hier nur `_safe_line` zaehlte,
                # wuerde die Sache am Mechanismus messen statt an der Eigenschaft — genau der
                # Fehler, den dieser Waechter schon einmal gemacht hat.
                if teil.conversion == ord("r"):
                    continue
                if any(a in q for a in AUSGENOMMEN):
                    continue
                offen.append((getattr(teil.value, "lineno", "?"), q[:70]))
        self.assertFalse(
            offen,
            "beschriftete Zeile(n) mit einem detail/origin-Wert ohne _safe_line, und ohne "
            f"dokumentierte Ausnahme: {offen}. Entweder umwickeln oder mit Grund in AUSGENOMMEN "
            "aufnehmen — stillschweigend offen lassen ist die Variante, die diese Klasse erzeugt hat.")

        # (a) schliessen: der NAME `_safe_line` darf nirgends neu gebunden werden. Ohne das kann
        # eine lokale Zuweisung die Funktion aushebeln, waehrend jede Aufrufstelle formal steht.
        neubindungen = []
        for n in ast.walk(baum):
            ziele = []
            if isinstance(n, ast.Assign):
                ziele = n.targets
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)):
                ziele = [n.target]
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_safe_line":
                continue          # die eine echte Definition
            for z in ziele:
                if isinstance(z, ast.Name) and z.id == "_safe_line":
                    neubindungen.append(getattr(n, "lineno", "?"))
        self.assertFalse(neubindungen,
                         f"_safe_line wird neu gebunden (Zeile {neubindungen}) — eine Umwicklung "
                         "kann formal dastehen und trotzdem wirkungslos sein")

        # DER WAECHTER SIEHT NUR f-STRINGS, und das ist eine Annahme, keine Eigenschaft. Eine
        # Gegenlesung hat sie benannt: `print("log-signature: " + res['origin'])` oder
        # `print("...%s" % res['origin'])` traegt keinen `JoinedStr` und ginge unbemerkt durch.
        # Gemessen kommt beides in cli.py heute 0x vor — deshalb wird die ANNAHME hier festgehalten
        # statt der Sonderfall behandelt: solange jede Ausgabe ein f-String ist, deckt die Regel
        # oben alles ab. Faellt diese Zeile, ist nicht sie das Problem, sondern die neue Ausgabeform,
        # die dann selbst eine Regel braucht.
        andere_formen = []
        for n in ast.walk(baum):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"):
                continue
            for a in n.args:
                if isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod)):
                    andere_formen.append((getattr(a, "lineno", "?"), ast.unparse(a)[:60]))
                elif isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) \
                        and a.func.attr == "format":
                    andere_formen.append((getattr(a, "lineno", "?"), ast.unparse(a)[:60]))
        self.assertFalse(
            andere_formen,
            "print() benutzt Konkatenation, %-Formatierung oder .format() statt eines f-Strings: "
            f"{andere_formen}. Die Regel darueber sieht nur f-Strings — eine solche Zeile waere "
            "ungedeckt. Entweder auf einen f-String umstellen oder die Regel erweitern.")


class KanonischeNormalformZaehltAlsUnterschied(unittest.TestCase):
    """Die Luecke, die `test_vollbreite_form_ist_nicht_derselbe_origin` NICHT deckt.

    GEMESSEN von einem Gate-Meta-Test auf dem Vorgaengerstand: eine eingepflanzte
    NFC-Normalisierung des Origin-Vergleichs wurde von KEINEM der 2088 Tests gefangen — auch
    nicht vom Vollbreiten-Kandidaten, denn `NFC(vollbreite) != Origin` (nur `NFKC` bildet ihn
    ab). Die KOMPATIBILITAETS-Normalisierung ist gedeckt, die KANONISCHE nicht. Das sind zwei
    verschiedene Lockerungen, und die kanonische ist die naheliegendere: `unicodedata.normalize`
    wird meist mit NFC aufgerufen.

    Der Fixture-Origin ist reines ASCII und kann das prinzipiell nicht ausdruecken — aus ihm
    laesst sich kein NFC-empfindlicher Kandidat ableiten. Deshalb wird hier ein EIGENER
    Checkpoint gebaut, mit der ausgelieferten oeffentlichen API und einem Wegwerf-Schluessel.
    Die eingefrorene Fixture wird nicht angefasst; sie ist der Bezugspunkt mehrerer Akten.

    Der Angriff, den das abbildet: ein Log fuehrt seinen Namen in ZERLEGTER Form, der Pruefer
    pinnt die zusammengesetzte (oder umgekehrt). Beide sehen auf dem Bildschirm identisch aus
    und sind verschiedene Bytes. Normalisiert der Vergleich, akzeptiert der Pruefer einen
    Checkpoint aus einem Log, das er nicht gemeint hat.
    """

    ORIGIN_NFC = unicodedata.normalize("NFC", "café.example/log")   # é als EIN Zeichen
    ORIGIN_NFD = unicodedata.normalize("NFD", "café.example/log")   # e + Combining Acute
    KEYNAME = "cafe.example"          # ASCII: sign_checkpoint verbietet Leerraum und '+'

    @classmethod
    def _baue(cls, origin: str) -> "tuple[str, str]":
        """Ein signierter tlog-proof ueber genau einen Blatt-Eintrag. Rueckgabe (proof, vkey)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from proofbundle.checkpoint import sign_checkpoint, vkey as mach_vkey
        from proofbundle.tlogproof import format_tlog_proof

        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
        nutzlast = b"leaf-0"
        blatt = hashlib.sha256(b"\x00" + nutzlast).digest()      # RFC 6962 leaf hash
        note = sign_checkpoint(origin, 1, blatt, sk, cls.KEYNAME)  # tree_size 1 -> root == leaf
        return format_tlog_proof(0, [], note), mach_vkey(cls.KEYNAME, pub)

    def _pruefe(self, gebaut_mit: str, erwartet: "str | None") -> dict:
        import tempfile
        from proofbundle.tlogproof import verify_tlog_proof
        proof, vk = self._baue(gebaut_mit)
        with tempfile.TemporaryDirectory() as t:
            p = pathlib.Path(t) / "p.tlog-proof"
            p.write_text(proof, encoding="utf-8")
            return verify_tlog_proof(p.read_text(encoding="utf-8"), b"leaf-0", vk,
                                     expected_origin=erwartet)

    def test_die_zwei_formen_sind_wirklich_verschiedene_bytes(self) -> None:
        """Die Vorbedingung. Ohne sie misst der Rest der Klasse nichts."""
        self.assertNotEqual(self.ORIGIN_NFC, self.ORIGIN_NFD,
                            "die Fixture-Zeichenkette ist nicht zerlegbar — kein Kandidat")
        self.assertEqual(unicodedata.normalize("NFC", self.ORIGIN_NFD), self.ORIGIN_NFC,
                         "NFC bildet die zerlegte Form nicht auf die zusammengesetzte ab")

    def test_positivkontrolle_der_eigene_aufbau_verifiziert(self) -> None:
        """Zuerst der Gutfall — sonst waere jedes NEIN unten auch ohne den Vergleich erklaerbar."""
        res = self._pruefe(self.ORIGIN_NFC, None)
        self.assertTrue(res["ok"], f"der selbstgebaute Beweis verifiziert nicht: {res}")
        self.assertTrue(res["log_ok"])

    def test_nfd_erwartung_gegen_nfc_checkpoint_faellt(self) -> None:
        res = self._pruefe(self.ORIGIN_NFC, self.ORIGIN_NFD)
        self.assertFalse(res["log_ok"], "die zerlegte Form wurde als derselbe Origin akzeptiert "
                                        "— der Vergleich normalisiert kanonisch")
        self.assertFalse(res["ok"])

    def test_nfc_erwartung_gegen_nfd_checkpoint_faellt(self) -> None:
        """Die Gegenrichtung. Eine einseitige Normalisierung faellt nur in einer der beiden."""
        res = self._pruefe(self.ORIGIN_NFD, self.ORIGIN_NFC)
        self.assertFalse(res["log_ok"], "die zusammengesetzte Form wurde als derselbe Origin "
                                        "akzeptiert — der Vergleich normalisiert kanonisch")
        self.assertFalse(res["ok"])

    def test_jede_form_passt_zu_sich_selbst(self) -> None:
        """Ohne diese Zeile waere die Klasse auch bei einem IMMER-FALSCH-Vergleich gruen."""
        for name, form in (("NFC", self.ORIGIN_NFC), ("NFD", self.ORIGIN_NFD)):
            with self.subTest(form=name):
                res = self._pruefe(form, form)
                self.assertTrue(res["log_ok"], f"{name} passt nicht zu sich selbst")
