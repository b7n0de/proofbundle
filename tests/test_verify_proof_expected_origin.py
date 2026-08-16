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
    """Kippt ein Base64-Zeichen in der Signaturzeile des LOGS selbst (nicht der Zeugen).

    Die Notensignaturen stehen als `— <origin> <base64>`; die Zeile des Logs ist die mit
    `_ORIGIN`. Verfaelscht wird das letzte Zeichen — damit faellt genau `log_ok`, waehrend Merkle
    und Inklusion unberuehrt bleiben. Das ist die Ursache, die im JSON von einem fremden Origin
    ununterscheidbar ist.
    """
    for zeile in reversed(_PROOF.read_text(encoding="utf-8", errors="replace").split("\n")):
        if zeile.startswith("— " + _ORIGIN + " ") and len(zeile) > 10:
            kaputt = zeile[:-1] + ("A" if zeile[-1] != "A" else "B")
            return _kopie_mit(kaputt.encode(), "badsig.tlog-proof", roh=zeile.encode())
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
        verschiedene Lagen, und der Unterschied ist genau der, den dieses Feld tragen soll."""
        _, out = _run()
        self.assertIsNone(json.loads(out)["expected_origin"])

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

    def test_die_drei_ursachen_bleiben_ununterscheidbar(self) -> None:
        """Haelt den GEMESSENEN Stand fest, nicht den erhofften — damit die Luecke nicht verschwindet.

        Fremder Origin und verfaelschte Signatur liefern mit gesetzter Erwartung dasselbe JSON. Diese
        Zusicherung dokumentiert das ausfuehrbar: wird die Luecke spaeter wirklich geschlossen (etwa
        durch ein Ursachen-Feld), wird DIESER Test rot und zwingt dazu, den Befund zu schliessen
        statt ihn zu vergessen. Ein bekannter Mangel ohne Waechter wird still zur Legende.
        """
        import hashlib
        _, fremder_origin = _run("--expected-origin", _WRONG_ORIGIN)
        verfaelscht = _mit_verfaelschter_signatur()
        if verfaelscht is None:
            self.skipTest("Signatur-Zeile in der Fixture nicht auffindbar")
        _, sig_kaputt = _run_gegen(verfaelscht, "--expected-origin", _WRONG_ORIGIN)
        a, b = json.loads(fremder_origin), json.loads(sig_kaputt)
        self.assertFalse(a["ok"])
        self.assertFalse(b["ok"])
        gleich = (hashlib.sha256(fremder_origin.encode()).hexdigest()
                  == hashlib.sha256(sig_kaputt.encode()).hexdigest())
        self.assertTrue(
            gleich,
            "die beiden Ursachen sind maschinell unterscheidbar geworden — gut! Dann ist der Befund "
            "audit_artifacts/380/FINDING_json_trennt_die_drei_ursachen_nicht.md geschlossen und "
            "dieser Waechter gehoert durch eine positive Zusicherung ersetzt.")


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

    def test_erwartungs_zusatz_aus_der_kommandozeile_kann_keine_zeile_faelschen(self) -> None:
        """Aufrufstelle 2: `(expected {…})` — der Wert kommt aus argv."""
        boese = "evil.example/log\nCRYPTO: OK"
        aus = self._text_gegen(_PROOF, "--expected-origin", boese)
        self.assertNotIn("\n" + "CRYPTO: OK", aus, "der Erwartungswert hat eine eigene Zeile erzeugt")
        self.assertIn("evil.example/log", aus, "der Erwartungswert erscheint gar nicht — "
                                               "dieser Test misst dann etwas anderes")

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

        ERWARTET = {"log-signature", "expected", "sample-opening", "enclave-attestation"}
        gefunden: set[str] = set()
        # ALLE f-Strings, nicht nur die direkt in `print(...)`. Die erste Fassung dieses Tests sah
        # nur print-Argumente und fiel deshalb an `expected` — zu Recht: dort steht die Umwicklung
        # in der Zuweisung an `origin_note`, und der `print` bekommt nur noch die Variable. Ein
        # Waechter, der die Gestalt statt die Sache misst, findet die Sache dort nicht, wo sie
        # zufaellig anders geformt ist.
        for arg in ast.walk(baum):
            if not isinstance(arg, ast.JoinedStr):
                continue
            text = "".join(t.value for t in arg.values
                           if isinstance(t, ast.Constant) and isinstance(t.value, str))
            umwickelt = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                            and n.func.id == "_safe_line" for n in ast.walk(arg))
            if not umwickelt:
                continue
            for marke in ERWARTET:
                if marke in text:
                    gefunden.add(marke)
        fehlend = ERWARTET - gefunden
        self.assertFalse(fehlend, f"nicht mehr durch _safe_line gefuehrt: {sorted(fehlend)}")
