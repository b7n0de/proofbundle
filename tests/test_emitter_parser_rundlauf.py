"""Was ein Emitter dieser Bibliothek baut, darf ihr eigener Parser nicht malformed nennen.

WOHER DIE EIGENSCHAFT KOMMT (2026-08-18): beim Nachmessen des Befunds
PB-CHECKPOINT-CONSTRUCTOR-TYPEERROR-01 stellte sich heraus, dass dessen Kern (roher `TypeError` aus
den Konstruktoren bei Nicht-bytes) durch das 4.0.0-Re-Gate iter5 laengst geschlossen war — alle acht
genannten Flaechen werfen typisiert. Die Messung legte dafuer einen NACHBARN derselben Klasse frei,
den niemand gesucht hatte: `checkpoint_note(root=b"")` kam durch, denn `b""` IST bytes. Die dritte
Notenzeile wurde damit leer, `sign_checkpoint` signierte das anstandslos, und `verify_checkpoint`
wie `_note_text_of` lehnten die frisch signierte Note danach als "at least 3 non-empty lines" ab.
Der realistische Weg dorthin ist kein Tippfehler, sondern `root_bytes_from_b64("")` -> `b""`.

WARUM DAS EINE KLASSE IST UND KEIN EINZELFALL: die Bibliothek haelt Emit- und Verify-Regeln an
ZWEI Stellen — `checkpoint_note`/`cosign_*` bauen, `verify_checkpoint`/`_note_text_of`/`_parse_*key`
pruefen. Jede Regel, die nur die Pruefseite kennt, erzeugt genau diesen Riss. Ein Punktfixture auf
den leeren Root haette den einen Fall geschlossen und die naechste Asymmetrie wieder dem Zufall
ueberlassen; deshalb steht hier die generative Eigenschaft ueber ALLE Emitter dieses Moduls.

DIE GEGENPROBE IST TEIL DES TESTS: eine Rundlauf-Eigenschaft ist ueber einer leeren Menge
angenommener Eingaben wahr, ohne irgendetwas gemessen zu haben. Jeder Emitter muss deshalb
nachweisen, dass er ueberhaupt etwas angenommen hat (`self.assertGreaterEqual(angenommen, ...)`) —
sonst ist der gruene Balken die Abwesenheit einer Messung, nicht ihr Ergebnis.
"""
from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import checkpoint as C
from proofbundle.errors import BundleFormatError

_LOG_NAME = "k"
_WITNESS_NAME = "w"

# Eingaben, die ein Aufrufer wirklich baut: gueltige, grenzwertige und kaputte durcheinander. Was der
# Emitter typisiert ABLEHNT, ist kein Befund — nur was er ANNIMMT und der eigene Parser dann verwirft.
_ORIGINS = ["example.com/log", "go.sum database tree", "a", "x" * 200, "", " lead", "trail ",
            "hat+plus", "zwei  spaces", "zero​width", "nbsp hier", None, 7]
_TREE_SIZES = [0, 1, 3, 2**63, 2**64 - 1, -1, True, "3", None]
_ROOTS = [b"r" * 32, b"12345", b"\x00" * 32, b"", None, "nicht-bytes", bytearray(b"r" * 32)]
_TIMESTAMPS = [0, 1, 2**63 - 1, 2**63, -1, True, "1", None]


def _schluessel():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class WasGebautWirdMussDerEigeneParserAkzeptieren(unittest.TestCase):
    """Fuer jede Eingabe, die ein Emitter ANNIMMT: sein Parser darf die Ausgabe nicht verwerfen."""

    @classmethod
    def setUpClass(cls):
        cls.log_sk, cls.log_pk = _schluessel()
        cls.wit_sk, cls.wit_pk = _schluessel()
        cls.log_vkey = C.vkey(_LOG_NAME, cls.log_pk)
        cls.wit_vkey = C.cosign_vkey(_WITNESS_NAME, cls.wit_pk)

    def _rundlauf(self, name, bauen, pruefen, eingaben, mindestens):
        """bauen(eingabe) -> Ausgabe · pruefen(Ausgabe) -> wirft BundleFormatError bei malformed."""
        angenommen = 0
        for eingabe in eingaben:
            with self.subTest(emitter=name, eingabe=repr(eingabe)[:60]):
                try:
                    ausgabe = bauen(eingabe)
                except BundleFormatError:
                    continue                    # typisiert abgelehnt — die gewollte Antwort
                angenommen += 1
                try:
                    pruefen(ausgabe)
                except BundleFormatError as exc:
                    self.fail(f"{name} hat {eingabe!r} ANGENOMMEN, aber der eigene Parser nennt die "
                              f"Ausgabe malformed: {exc}")
        self.assertGreaterEqual(
            angenommen, mindestens,
            f"{name} hat nur {angenommen} Eingaben angenommen — unter dieser Schwelle misst die "
            f"Rundlauf-Eigenschaft nichts mehr, sie ist ueber der leeren Menge wahr")

    def test_checkpoint_note_gegen_den_geteilten_notenparser(self):
        def bauen_root(root):
            return C.sign_checkpoint("example.com/log", 3, root, self.log_sk, _LOG_NAME)

        self._rundlauf("sign_checkpoint(root=…)", bauen_root, C._note_text_of, _ROOTS, mindestens=2)

        def bauen_origin(origin):
            return C.sign_checkpoint(origin, 3, b"r" * 32, self.log_sk, _LOG_NAME)

        self._rundlauf("sign_checkpoint(origin=…)", bauen_origin, C._note_text_of, _ORIGINS,
                       mindestens=4)

        def bauen_size(size):
            return C.sign_checkpoint("example.com/log", size, b"r" * 32, self.log_sk, _LOG_NAME)

        self._rundlauf("sign_checkpoint(tree_size=…)", bauen_size, C._note_text_of, _TREE_SIZES,
                       mindestens=3)

    def test_checkpoint_note_gegen_die_eigene_verifikation(self):
        def bauen(root):
            return C.sign_checkpoint("example.com/log", 3, root, self.log_sk, _LOG_NAME)

        def pruefen(note):
            res = C.verify_checkpoint(note, self.log_vkey)
            self.assertTrue(res["ok"], "die eigene frisch signierte Note verifiziert nicht")

        self._rundlauf("sign_checkpoint -> verify_checkpoint", bauen, pruefen, _ROOTS, mindestens=2)

    def test_cosign_checkpoint_gegen_die_eigene_verifikation(self):
        note = C.sign_checkpoint("example.com/log", 3, b"r" * 32, self.log_sk, _LOG_NAME)

        def bauen(ts):
            return C.cosign_checkpoint(note, self.wit_sk, _WITNESS_NAME, ts)

        def pruefen(cosigned):
            res = C.verify_cosignature(cosigned, self.wit_vkey)
            self.assertTrue(res["ok"], "die eigene frisch gesetzte Cosignatur verifiziert nicht")

        self._rundlauf("cosign_checkpoint(timestamp=…)", bauen, pruefen, _TIMESTAMPS, mindestens=3)

    def test_vkey_emitter_gegen_ihre_eigenen_parser(self):
        namen = [_LOG_NAME, "example.com/log", "a" * 100, "", "hat+plus", "hat leer", None, 7]

        self._rundlauf("vkey", lambda n: C.vkey(n, self.log_pk), C._parse_vkey, namen, mindestens=3)
        self._rundlauf("cosign_vkey", lambda n: C.cosign_vkey(n, self.wit_pk),
                       C._parse_witness_vkey, namen, mindestens=3)


class DerLeereRootIstNamentlichGepinnt(unittest.TestCase):
    """Regressions-Pin auf die INSTANZ, die die Eigenschaft oben gefunden hat.

    Der generative Test faende ihn wieder — aber nur, solange `b""` im Korpus steht. Ein namentlicher
    Pin sagt zusaetzlich, WELCHER Fall das war, und ueberlebt eine Umgestaltung des Korpus.
    """

    def test_leerer_root_wird_typisiert_abgelehnt(self):
        with self.assertRaises(BundleFormatError) as ctx:
            C.checkpoint_note("example.com/log", 3, b"")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_leerer_root_kommt_auch_ueber_sign_checkpoint_nicht_durch(self):
        sk, _pk = _schluessel()
        with self.assertRaises(BundleFormatError):
            C.sign_checkpoint("example.com/log", 3, b"", sk, _LOG_NAME)

    def test_der_realistische_weg_dorthin_bleibt_benannt(self):
        """`root_bytes_from_b64("")` liefert `b""`, nicht `None` — leer ist gueltiges base64.

        Das ist die Stelle, an der ein leeres Root-Feld eines Bundles zum leeren Root wird, ohne am
        `isinstance(bytes)`-Riegel haengenzubleiben. Der Decoder bleibt absichtlich unveraendert (er
        dekodiert korrekt); gefangen wird es dort, wo die Note entsteht.
        """
        self.assertEqual(C.root_bytes_from_b64(""), b"")
        with self.assertRaises(BundleFormatError):
            C.checkpoint_note("example.com/log", 0, C.root_bytes_from_b64(""))


if __name__ == "__main__":
    unittest.main()
