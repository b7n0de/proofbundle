"""Eine signierte C2SP-Note hat GENAU EINE akzeptierte Drahtform — die Klasse, nicht die Instanz.

WAS DAS SCHLIESST. Fund L1-600-NOTE-FRAMING-01 (deep gate 6.0.0, P1), nachreproduziert auf 917edc69:
``checkpoint.verify_checkpoint`` trennte Notentext und Signaturblock an der ERSTEN Leerzeile und
UEBERSPRANG danach still jede Blockzeile ohne EM DASH + Leerzeichen; dieselbe Erst-Trennung lag in
``_note_text_of`` und in der Cosignatur-Schleife. Die Referenz des Formats
(``golang.org/x/mod/sumdb/note.Open``) trennt an der LETZTEN Leerzeile und nennt jede andere Zeile im
Block ``errMalformedNote``. Gemessen: EINE signierte Note hatte damit eine unbegrenzte Familie
byteverschiedener Formen mit ``ok=True`` — 24 verschiedene sha256-Formen allein aus vier Mustern —,
jede faehig, beliebigen unsignierten Angreifertext mitzufuehren, und jede von der Referenz abgelehnt.
Die Wirkung reichte bis in ``verify_tlog_proof`` und beide CLI-Wege (``verify --trusted-checkpoint``,
``verify-proof``): dort verifizierte die gefaelschte Datei mit Exit 0.

DIE KLASSE, nicht der eine Treiber: "alle Artefakte mit Notiz-Rahmung". Der Fix sitzt deshalb im
gemeinsamen Helfer ``checkpoint._split_signed_note`` und nicht in ``verify_checkpoint`` — das Gate hatte
gemessen, dass ``verify_tlog_proof`` auf denselben gefaelschten Bytes ebenfalls ``ok=True`` lieferte.
Sie ist die Schwester der Invariante in ``tests/test_wire_bytes_strict.py`` ("ein signiertes Artefakt,
EINE akzeptierte Drahtform"), dort fuer die base64-FELDER, hier eine Schicht hoeher: an der RAHMUNG.

DIE EIGENSCHAFT, EINGESCHRAENKT formuliert (und das ist Absicht — eine Zusicherung, die mehr behauptet,
als sie prueft, ist genau der Fehler, den dieser Fix behebt): fuer Eingaben INNERHALB der deklarierten
Grenzen — ``str``-Eingabe, unterstuetzte Signaturtypen (0x01 Log, 0x04 Ed25519-Cosignatur, 0x06
ML-DSA-44), Zeilen- und Zeugenzahl unter ``DEFAULT_BUDGET`` — nimmt eine ``verify_*``-Flaeche dieses
Moduls genau die Bytefolgen an, die auch die kanonische Rahmung annimmt. AUSSERHALB dieser Grenzen
lehnt proofbundle typisiert ab, wo die Referenz noch parst (ueber der Kappe, unbekannter Algorithmus);
das ist absichtlich strenger und wird hier NICHT als Gleichheit behauptet oder geprueft.

DAS ORAKEL, und seine ehrliche Grenze. ``go`` ist auf dieser Maschine NICHT installiert (gemessen mit
``command -v go``), das Go-Differential gegen ``note.Open`` wurde also NICHT gefahren. Das Orakel unten
ist stattdessen aus der Spezifikation neu geschrieben (C2SP ``signed-note.md`` + die Parse-Regeln von
``note.Open``) und teilt KEINE Zeile mit proofbundle: eigener base64-Decoder-Aufruf, eigene
keyID-Rechnung, eigene Ed25519-Pruefung ueber ``cryptography``, eigene Rahmungslogik. Es hat zwei Arme,
weil ein Signatur-Orakel fuer ML-DSA-44 und fuer reine Rahmungsfaelle nichts aussagt: ein
RAHMUNGS-Orakel (algorithmusfrei) und ein SIGNATUR-Orakel (Ed25519).

ANTIPARITAET ist eingebaut, sonst besteht ein Fix, der einfach alles ablehnt, diese Pruefung: die echte
Note, jede Umordnung des Signaturblocks und eine zusaetzliche wohlgeformte Zeile eines UNBEKANNTEN
Schluessels muessen auf BEIDEN Seiten ANGENOMMEN werden. Und die zwanzig echten, ausgelieferten Vektoren
(sum.golang.org, Rekor, MarkovianProtocol, rootcommit) laufen in
``tests/test_checkpoint_external_vectors.py`` und ``tests/test_anchors_*.py`` unveraendert weiter.

ANTITAUTOLOGIE: der Meta-Test pflanzt die VOR-FIX-Rahmung zurueck und verlangt, dass der Korpus sie
faengt. Ein Korpus, der den eingepflanzten Defekt seiner eigenen Klasse nicht sieht, misst nichts.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import re
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from proofbundle import checkpoint as cp
from proofbundle import tlogproof
from proofbundle.budget import DEFAULT_BUDGET
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError, ProofBundleError

EM = "—"

# ======================================================================================
# DAS ORAKEL — Neuimplementierung aus der Spezifikation. Ab hier bis zur naechsten
# Trennlinie wird KEIN proofbundle-Symbol benutzt; das ist der ganze Sinn der Sache.
# ======================================================================================

# Genau note.Opens Menge: ``r < 0x20 && r != '\n'`` (note.go:524, x/mod v0.29.0). 0x7F/DEL gehoert
# NICHT dazu. Meine erste Fassung hatte es drin — DERSELBE Fehler wie in der Implementierung, und
# genau deshalb hat das Spezifikations-Differential ihn nicht gesehen: zwei Fehler in dieselbe
# Richtung heben sich auf. Gefunden hat ihn erst der Lauf gegen echtes Go.
_ORAKEL_STEUERZEICHEN = re.compile(r"[\x00-\x09\x0b-\x1f]")
_ORAKEL_SURROGAT = re.compile(r"[\ud800-\udfff]")


def orakel_rahmung(msg):
    """Die Rahmungsregeln von note.Open, algorithmusfrei. -> (text, sigzeilen) oder (None, Grund).

    1. gueltiges UTF-8, kein ASCII-Steuerzeichen ausser U+000A · 2. Trennung am LETZTEN "\\n\\n", der
    Text ist ``msg[:i+1]`` (der signierte Schluss-Umbruch bleibt drin) · 3. der Block ist nicht leer und
    endet auf "\\n" · 4. jede Zeile beginnt mit EM DASH + Leerzeichen · 5. je Zeile Name (nicht leer,
    ohne '+') + Leerzeichen + nicht-leeres Standard-base64 mit mindestens 5 Nutzbytes.
    """
    if not isinstance(msg, str):
        return None, "kein str"
    if _ORAKEL_SURROGAT.search(msg):
        return None, "errMalformedNote: kein gueltiges UTF-8 (Surrogat)"
    if _ORAKEL_STEUERZEICHEN.search(msg):
        return None, "errMalformedNote: ASCII-Steuerzeichen ausser \\n"
    i = msg.rfind("\n\n")
    if i < 0:
        return None, "errMalformedNote: keine Leerzeile zwischen Text und Signaturen"
    text, block = msg[:i + 1], msg[i + 2:]
    if not block or not block.endswith("\n"):
        return None, "errMalformedNote: Signaturblock leer oder ohne Schluss-Umbruch"
    zeilen = block.split("\n")[:-1]
    if not zeilen:
        return None, "errMalformedNote: keine Signaturzeile"
    for z in zeilen:
        if not z.startswith(EM + " "):
            return None, f"errMalformedNote: Nicht-Signaturzeile {z[:40]!r}"
        rest = z[2:]
        if " " not in rest:
            return None, f"errMalformedNote: kein Leerzeichen nach dem Namen {z[:40]!r}"
        name, b64s = rest.split(" ", 1)
        # isValidName (note.go:238): nicht leer, gueltiges UTF-8, KEIN unicode.IsSpace, kein '+'.
        # Der Schnitt am ASCII-Leerzeichen deckt nur EIN Leerzeichen ab; U+00A0/U+2003/U+3000/U+2028
        # muessen hier fallen. Auch das stand in meiner ersten Fassung nicht drin.
        if not name or "+" in name or not b64s or any(ch.isspace() for ch in name):
            return None, f"errMalformedNote: Name/Nutzlast ungueltig {z[:40]!r}"
        try:
            roh = base64.b64decode(b64s, validate=True)
        except Exception:
            return None, f"errMalformedNote: base64 ungueltig {z[:40]!r}"
        if len(roh) < 5:
            return None, "errMalformedNote: Nutzlast kuerzer als keyID + Signatur"
    return text, zeilen


def _orakel_vkey(vkey):
    """name+hexKeyID+base64(0x01||pub) -> (name, keyID, pubkey) oder None. Eigene Rechnung."""
    try:
        name, kid_hex, keymat_b64 = vkey.split("+", 2)
        keymat = base64.b64decode(keymat_b64, validate=True)
    except Exception:
        return None
    if len(keymat) != 33 or keymat[0] != 0x01:
        return None
    pub = keymat[1:]
    kid = hashlib.sha256(name.encode("utf-8") + b"\n" + b"\x01" + pub).digest()[:4]
    if kid.hex() != kid_hex:
        return None
    return name, kid, pub


def orakel_nimmt_an(msg, vkey):
    """True nur, wenn die Rahmung kanonisch ist UND eine Zeile dieses Schluessels ueber genau diesen
    Text verifiziert. Unbekannte Schluessel werden ignoriert (note.Open tut das auch); eine Zeile MIT
    passender keyID, deren Signatur nicht haelt, zaehlt NIE als Beleg."""
    zerlegt = _orakel_vkey(vkey)
    if zerlegt is None:
        return False
    name, kid, pub = zerlegt
    text, zeilen = orakel_rahmung(msg)
    if text is None:
        return False
    schluessel = Ed25519PublicKey.from_public_bytes(pub)
    for z in zeilen:
        lname, b64s = z[2:].split(" ", 1)
        if lname != name:
            continue
        roh = base64.b64decode(b64s, validate=True)
        if roh[:4] != kid or len(roh) != 4 + 64:
            continue
        try:
            schluessel.verify(roh[4:], text.encode("utf-8"))
            return True
        except InvalidSignature:
            continue
    return False


# ======================================================================================
# Ab hier wieder proofbundle.
# ======================================================================================


def _bau(text, blockzeilen):
    """Notentext (endet auf \\n) + Leerzeile + je Blockzeile ein \\n."""
    return text + "\n" + "".join(z + "\n" for z in blockzeilen)


FUELL_ZEILE = "F" * 63


def korpus(text, block):
    """(Kennung, Bytes) — ENUMERIERT aus den Arten, wie fremde Bytes in eine Note geraten koennen,
    nicht handverlesen: an JEDER Einfuegestelle des Blocks, ueber die ganze Laufweite der
    Leerzeilenlaeufe, ueber ALLE Umordnungen des Blocks. Punktfixtures waeren genau der Fehlermodus,
    den ``test_wire_bytes_strict`` als ``family_property_green_over_a_hand_maintained_population``
    benennt."""
    faelle = [("echt", _bau(text, block))]
    stellen = range(len(block) + 1)
    fake_tripel = ["evil.example/log", "99", base64.b64encode(bytes(32)).decode()]

    for p in stellen:
        faelle.append((f"klartextzeile@{p}", _bau(text, block[:p] + ["INJIZIERT-UNSIGNIERT"] + block[p:])))
        faelle.append((f"zweites-tripel@{p}", _bau(text, block[:p] + fake_tripel + block[p:])))
        for kib in (1, 4, 16):
            fuellung = [FUELL_ZEILE] * (kib * 1024 // 64)
            faelle.append((f"fuellung-{kib}KiB@{p}", _bau(text, block[:p] + fuellung + block[p:])))

    # Leerzeilenlaeufe: r = Anzahl aufeinanderfolgender \n zwischen Text und Block. r=2 ist die echte
    # Form; r>=3 sind die Laeufe, die die Erst-Trennung frueher stumm geschluckt hat.
    blockstr = "".join(z + "\n" for z in block)
    for r in range(2, 25):
        faelle.append((f"leerzeilenlauf-{r}", text[:-1] + "\n" * r + blockstr))
    # dieselben Laeufe INNERHALB des Blocks und an seinem Ende
    for r in range(1, 6):
        faelle.append((f"leerzeilen-im-block-{r}", text + "\n" + "\n" * r + blockstr))
        faelle.append((f"leerzeilen-am-blockende-{r}", _bau(text, block) + "\n" * r))

    # Umordnung: ALLE Permutationen. Der Signaturblock ist eine MENGE, seine Reihenfolge traegt keine
    # Bedeutung — jede Umordnung MUSS angenommen bleiben.
    for perm in itertools.permutations(range(len(block))):
        faelle.append(("umordnung-" + "".join(map(str, perm)), _bau(text, [block[i] for i in perm])))

    # Rahmungskanten
    echt = _bau(text, block)
    gueltige_zusatzzeile = f"{EM} fremd.example {base64.b64encode(bytes(range(68))).decode()}"
    faelle += [
        ("ohne-schluss-umbruch", echt[:-1]),
        ("ohne-trenner", text + blockstr),
        ("leerer-block", text + "\n"),
        ("nur-text", text),
        ("fuehrende-leerzeile", "\n" + echt),
        ("steuerzeichen-im-text", text[:-1] + "\x07\n" + "\n" + blockstr),
        ("steuerzeichen-in-zusatzzeile", _bau(text, block + [gueltige_zusatzzeile + "\x07"])),
        ("surrogat-in-zusatzzeile", _bau(text, block + [gueltige_zusatzzeile + "\ud800"])),
        ("junk-hinter-em-dash", _bau(text, block + [f"{EM} evil BELIEBIGER ANGREIFERTEXT"])),
        ("leerer-name", _bau(text, block + [f"{EM}  {base64.b64encode(bytes(68)).decode()}"])),
        ("plus-im-namen", _bau(text, block + [f"{EM} ev+il {base64.b64encode(bytes(68)).decode()}"])),
        ("nutzlast-zu-kurz", _bau(text, block + [f"{EM} evil QQ=="])),
        ("leere-nutzlast", _bau(text, block + [f"{EM} evil "])),
        # ANTIPARITAET: eine wohlgeformte Zeile eines UNBEKANNTEN Schluessels ist gueltig und wird
        # ignoriert, nicht abgelehnt - sonst waere der Fix "lehne alles ab, was du nicht kennst".
        ("fremde-wohlgeformte-zeile", _bau(text, block + [gueltige_zusatzzeile])),
        ("fremde-zeile-voran", _bau(text, [gueltige_zusatzzeile] + block)),
    ]

    # ZWEI NACHBARN, die eine adversariale Gegenlesung gegen ECHTES note.Open gefunden hat
    # (NOTE-RAHMUNG-ZWEI-NACHBARN-GEGEN-ECHTES-GO-OFFEN-01, 2026-09-05). Beide waren mit lauffaehigem
    # Gegenbeispiel belegt, beide hier nachgefahren, beide jetzt als Korpusfall.
    #
    # (a) UNICODE-LEERZEICHEN IM NAMEN, die gefaehrliche Richtung: der Schnitt am ASCII-Leerzeichen
    #     laesst U+00A0/U+2003/U+3000/U+2028 im Namen durch, die Zeile galt als "unbekannter
    #     Schluessel" und wurde still uebersprungen -> die Note verifizierte mit ok=True, waehrend
    #     note.Open (isValidName mit unicode.IsSpace) die GANZE Note ablehnt. MUSS abgelehnt werden.
    for kenn, zeichen in (("nbsp", "\u00a0"), ("em-space", "\u2003"),
                          ("ideographic-space", "\u3000"), ("line-sep", "\u2028")):
        faelle.append((f"name-mit-{kenn}",
                       _bau(text, block + [f"{EM} ev{zeichen}il {base64.b64encode(bytes(range(68))).decode()}"])))
    # (b) NEGATIVKONTROLLEN, die ANGENOMMEN bleiben muessen - ohne sie waere (a) auch mit einem Fix
    #     erfuellt, der jedes nicht-ASCII im Namen ablehnt, und das waere STRENGER als die Referenz:
    #     U+200B ist KEIN unicode.IsSpace, und 0x7F (DEL) faellt nicht unter note.Opens
    #     ``r < 0x20 && r != '\n'`` - beides nimmt die Referenz an, also nehmen wir es auch an.
    faelle.append(("fremde-zeile-name-zwsp",
                   _bau(text, block + [f"{EM} ev\u200bil {base64.b64encode(bytes(range(68))).decode()}"])))
    faelle.append(("fremde-zeile-name-del-0x7f",
                   _bau(text, block + [f"{EM} ev\x7fil {base64.b64encode(bytes(range(68))).decode()}"])))
    # (c) 0x7F IM NOTENTEXT: von beiden Seiten abgelehnt, aber aus verschiedenen Gruenden - die
    #     Referenz, weil die Signatur den geaenderten Text nicht deckt; wir ebenso. Kein Steuerzeichen-
    #     Riegel mehr, und genau das ist der Punkt.
    faelle.append(("del-0x7f-im-notentext", text[:-1] + "\next\x7fline\n" + "\n" + blockstr))
    return faelle


def _impl_nimmt_an(note, vkey):
    """Annahme der Implementierung: ok=True. Ein typisierter Fehler IST eine Ablehnung."""
    try:
        return cp.verify_checkpoint(note, vkey)["ok"] is True
    except ProofBundleError:
        return False


def _impl_rahmung_ok(note):
    try:
        cp._split_signed_note(note)
        return True
    except ProofBundleError:
        return False


def _vorfix_split(signed_note, what="signed note"):
    """Die Rahmung VOR dem Fix, exakt: Trennung an der ERSTEN Leerzeile, keine Zeilenregel."""
    if not isinstance(signed_note, str):
        raise BundleFormatError("signed note must be a string (non-str is malformed, fail-closed)")
    if "\n\n" not in signed_note:
        raise BundleFormatError("signed note has no empty-line separator between text and signatures")
    t, s = signed_note.split("\n\n", 1)
    return t + "\n", s


class _Aufbau:
    """Echte Note, echtes Bundle, echter tlog-proof — alles ueber die Emitter des Repos."""

    def __init__(self):
        self.log = generate_signer()
        self.witness = generate_signer()
        self.name = "log.example/x"
        self.wname = "w.example"
        self.nutzlast = b'{"suite": "demo", "passed": true}'
        self.bundle = emit_bundle(self.nutzlast, self.log, prior_leaves=[b"e1", b"e2"])
        wurzel = base64.b64decode(self.bundle["merkle"]["root_b64"])
        note = cp.sign_checkpoint(self.name, self.bundle["merkle"]["tree_size"], wurzel,
                                  self.log, self.name)
        self.note = cp.cosign_checkpoint(note, self.witness, self.wname, 1_780_000_000)
        self.vkey = cp.vkey(self.name, self.log.public_key().public_bytes_raw())
        self.wvkey = cp.cosign_vkey(self.wname, self.witness.public_key().public_bytes_raw())
        self.text, self.block_str = self.note[:self.note.rfind("\n\n") + 1], \
            self.note[self.note.rfind("\n\n") + 2:]
        self.block = self.block_str.split("\n")[:-1]
        self.faelle = korpus(self.text, self.block)
        # der Kopf eines echten tlog-proof, damit die Nachbarflaeche mit derselben Note laeuft
        echter_proof = tlogproof.tlog_proof_for_bundle(self.bundle, self.note)
        self.proof_kopf = echter_proof.split("\n\n", 1)[0]


class DerKorpusIstNichtLeerUndNichtEinseitig(unittest.TestCase):
    """Ein Differential ueber einem Korpus, in dem alles gleich ausgeht, misst nichts."""

    def setUp(self):
        self.a = _Aufbau()

    def test_der_korpus_traegt_beide_ausgaenge_in_zahl(self):
        angenommen = [k for k, b in self.a.faelle if orakel_nimmt_an(b, self.a.vkey)]
        abgelehnt = [k for k, b in self.a.faelle if not orakel_nimmt_an(b, self.a.vkey)]
        self.assertGreaterEqual(len(self.a.faelle), 60, "Korpus zu klein")
        self.assertGreaterEqual(len(angenommen), 4, f"zu wenige ANGENOMMENE Faelle: {angenommen}")
        self.assertGreaterEqual(len(abgelehnt), 40, "zu wenige ABGELEHNTE Faelle")
        self.assertIn("echt", angenommen)
        self.assertIn("fremde-wohlgeformte-zeile", angenommen)
        self.assertTrue(any(k.startswith("umordnung-") for k in angenommen))

    def test_jeder_fall_ist_byteverschieden_oder_heisst_echt(self):
        gesehen = {}
        for k, b in self.a.faelle:
            gesehen.setdefault(b, []).append(k)
        # Dubletten sind erlaubt (eine Umordnung kann die echte Form sein), aber der Korpus muss
        # ueberwiegend byteverschieden sein, sonst zaehlt er dieselbe Frage mehrfach.
        self.assertGreater(len(gesehen), len(self.a.faelle) * 0.8)


class DasDifferentialGegenDasSpezifikationsOrakel(unittest.TestCase):
    """Kern: Annahme der Implementierung == Annahme des unabhaengigen Orakels, Fall fuer Fall."""

    def setUp(self):
        self.a = _Aufbau()

    def test_verify_checkpoint_stimmt_mit_dem_signatur_orakel_ueberein(self):
        abweichungen = []
        for k, b in self.a.faelle:
            impl, orakel = _impl_nimmt_an(b, self.a.vkey), orakel_nimmt_an(b, self.a.vkey)
            if impl != orakel:
                abweichungen.append(f"{k}: impl={impl} orakel={orakel}")
        self.assertEqual(abweichungen, [], "\n".join(abweichungen))

    def test_die_rahmung_stimmt_mit_dem_rahmungs_orakel_ueberein(self):
        """Der algorithmusfreie Arm (Auflage A3): er gilt auch dort, wo keine Ed25519-Signatur die
        Frage entscheidet — Leerzeilenlaeufe, Blockkanten, ML-DSA."""
        abweichungen = []
        for k, b in self.a.faelle:
            impl = _impl_rahmung_ok(b)
            orakel = orakel_rahmung(b)[0] is not None
            if impl != orakel:
                abweichungen.append(f"{k}: impl={impl} orakel={orakel}")
        self.assertEqual(abweichungen, [], "\n".join(abweichungen))

    def test_der_notentext_ist_bytegenau_der_signierte(self):
        """Der heikelste Punkt der Rahmung: ``rsplit`` frisst BEIDE Umbrueche, und der erste gehoert
        zur signierten Nachricht. Gemessen statt geglaubt."""
        signiert = cp.checkpoint_note(self.a.name, self.a.bundle["merkle"]["tree_size"],
                                      base64.b64decode(self.a.bundle["merkle"]["root_b64"]))
        text, _ = cp._split_signed_note(self.a.note)
        self.assertEqual(text, signiert)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, self.a.note.rsplit("\n\n", 1)[0] + "\n")
        self.assertNotEqual(text, self.a.note.rsplit("\n\n", 1)[0],
                            "die naive Trennung haette genau ein signiertes Byte verloren")
        # und das Orakel sieht denselben Text
        self.assertEqual(orakel_rahmung(self.a.note)[0], signiert)

    def test_eine_note_hat_genau_eine_angenommene_drahtform(self):
        # Ausgenommen sind die Formen, die eine ZUSAETZLICHE wohlgeformte Zeile eines unbekannten
        # Schluessels tragen (Praefix "fremde-") und die Umordnungen: beide sind nach der Referenz
        # gueltige Formen DESSELBEN signierten Textes und muessen angenommen bleiben.
        formen = {hashlib.sha256(b.encode()).hexdigest()
                  for k, b in self.a.faelle if _impl_nimmt_an(b, self.a.vkey)
                  and not k.startswith("umordnung-") and not k.startswith("fremde-")}
        self.assertEqual(len(formen), 1,
                         f"{len(formen)} byteverschiedene Formen derselben Signatur angenommen")


class DieNachbarflaechenTragenDieselbeRahmung(unittest.TestCase):
    """FIX-THE-CLASS: der Fund war an verify_checkpoint gemessen, der Nachbar verify_tlog_proof lieferte
    auf denselben Bytes ok=True. Beide haengen jetzt am selben Helfer, und das wird hier gemessen."""

    def setUp(self):
        self.a = _Aufbau()

    def test_verify_tlog_proof_stimmt_mit_dem_orakel_ueberein(self):
        abweichungen = []
        for k, b in self.a.faelle:
            proof = self.a.proof_kopf + "\n\n" + b
            r = tlogproof.verify_tlog_proof(proof, self.a.nutzlast, self.a.vkey)
            impl = r["ok"] is True
            orakel = orakel_nimmt_an(b, self.a.vkey)
            if impl != orakel:
                abweichungen.append(f"{k}: verify_tlog_proof={impl} orakel={orakel}")
        self.assertEqual(abweichungen, [], "\n".join(abweichungen))

    def test_verify_witnessed_checkpoint_stimmt_mit_dem_orakel_ueberein(self):
        abweichungen = []
        for k, b in self.a.faelle:
            try:
                impl = cp.verify_witnessed_checkpoint(b, self.a.vkey, [self.a.wvkey],
                                                      threshold=1)["ok"] is True
            except ProofBundleError:
                impl = False
            # Zeugenquorum UND Logsignatur: das Orakel deckt die Logsignatur, die Cosignatur haengt
            # an derselben Rahmung — eine angenommene Rahmung mit gueltiger Logsignatur traegt hier
            # immer auch die unveraenderte Cosignatur.
            if impl != orakel_nimmt_an(b, self.a.vkey):
                abweichungen.append(f"{k}: verify_witnessed={impl}")
        self.assertEqual(abweichungen, [], "\n".join(abweichungen))

    def test_verify_cosignature_lehnt_jede_nicht_kanonische_form_ab(self):
        for k, b in self.a.faelle:
            if orakel_rahmung(b)[0] is not None:
                continue
            with self.assertRaises(BundleFormatError, msg=f"{k} kam durch"):
                cp.verify_cosignature(b, self.a.wvkey)

    def test_die_emit_seite_baut_nichts_was_der_verifizierer_ablehnt(self):
        """``format_tlog_proof``/``tlog_proof_for_bundle`` sind die Emitter derselben Note."""
        for k, b in self.a.faelle:
            if orakel_rahmung(b)[0] is not None:
                continue
            with self.assertRaises(BundleFormatError, msg=f"{k} wurde eingebettet"):
                tlogproof.format_tlog_proof(0, [], b)

    def test_der_rootcommit_zweitverifizierer_faellt_geschlossen_statt_zu_werfen(self):
        """Nachbar ohne eigene Kryptografie: never-raise bleibt, das Verdikt wird malformed."""
        from proofbundle import anchors_rootcommit as rc
        for k, b in self.a.faelle:
            if orakel_rahmung(b)[0] is not None:
                continue
            self.assertIsNone(rc.parse_checkpoint_head(b), f"{k} lieferte einen Kopf")
            self.assertEqual(rc.verify_rootcommit_v1(b)["status"], "malformed_checkpoint")


class EinBekannterSchluesselMitUngueltigerSignaturZaehltNie(unittest.TestCase):
    """Auflage A1: unbekannte Schluessel werden ignoriert, ein BEKANNTER mit kaputter Signatur nie
    als Beleg genommen — auch nicht, wenn er der einzige Traeger seiner keyID ist."""

    def setUp(self):
        self.a = _Aufbau()

    def _kaputte_logzeile(self):
        zeile = next(z for z in self.a.block if z.split(" ")[1] == self.a.name)
        roh = bytearray(base64.b64decode(zeile.split(" ", 2)[2], validate=True))
        roh[-1] ^= 0xFF                                   # keyID bleibt, Signatur bricht
        return f"{EM} {self.a.name} {base64.b64encode(bytes(roh)).decode()}"

    def test_nur_eine_kaputte_signatur_dieses_schluessels_ergibt_kein_ok(self):
        andere = [z for z in self.a.block if z.split(" ")[1] != self.a.name]
        note = _bau(self.a.text, [self._kaputte_logzeile()] + andere)
        r = cp.verify_checkpoint(note, self.a.vkey)
        self.assertIs(r["ok"], False)
        self.assertIs(r["signer_present"], True, "die Zeile trug die keyID — das muss sichtbar sein")
        self.assertFalse(orakel_nimmt_an(note, self.a.vkey))

    def test_eine_kaputte_neben_der_echten_zeile_aendert_nichts(self):
        note = _bau(self.a.text, [self._kaputte_logzeile()] + self.a.block)
        self.assertIs(cp.verify_checkpoint(note, self.a.vkey)["ok"], True)
        self.assertTrue(orakel_nimmt_an(note, self.a.vkey))


class DerMldsaArmDerRahmung(unittest.TestCase):
    """Auflage A3: fuer ML-DSA-44 entscheidet kein Ed25519-Orakel — hier laeuft der algorithmusfreie
    Rahmungsarm ueber denselben Korpus, auf einer Note mit einer 0x06-Cosignatur."""

    def setUp(self):
        try:
            cp._mldsa_module()
        except Exception as exc:                       # noqa: BLE001
            self.skipTest(f"ML-DSA-44 nicht verfuegbar: {exc}")
        from cryptography.hazmat.primitives.asymmetric import mldsa
        self.a = _Aufbau()
        self.w = mldsa.MLDSA44PrivateKey.generate()
        self.note = cp.cosign_checkpoint_mldsa(self.a.note, self.w, "pq.example", 1_780_000_001)
        self.wvkey = cp.cosign_vkey_mldsa("pq.example", self.w.public_key().public_bytes_raw())
        text = self.note[:self.note.rfind("\n\n") + 1]
        block = self.note[self.note.rfind("\n\n") + 2:].split("\n")[:-1]
        self.faelle = korpus(text, block)

    def test_die_echte_mldsa_note_bleibt_gut(self):
        self.assertIsNotNone(orakel_rahmung(self.note)[0])
        self.assertIs(cp.verify_cosignature(self.note, self.wvkey)["ok"], True)

    def test_rahmung_und_orakel_stimmen_auf_der_mldsa_note_ueberein(self):
        abweichungen = [k for k, b in self.faelle
                        if _impl_rahmung_ok(b) != (orakel_rahmung(b)[0] is not None)]
        self.assertEqual(abweichungen, [], f"{abweichungen}")

    def test_keine_nicht_kanonische_mldsa_form_verifiziert(self):
        for k, b in self.faelle:
            if orakel_rahmung(b)[0] is not None:
                continue
            with self.assertRaises(BundleFormatError, msg=f"{k} kam durch"):
                cp.verify_cosignature(b, self.wvkey)


class DieKappeBleibtVorDerArbeit(unittest.TestCase):
    """Die neue Formpruefung dekodiert base64 — sie darf die gelandete Haertung
    L2-BDOS-C2SP-SIGLINES-01 nicht aufweichen. Gemessen wird die Zahl der Dekodierungen VOR der
    Ablehnung, nicht die Zeit."""

    @staticmethod
    def _zaehle_dekodierungen(fn):
        echt = cp.decode_b64_c2sp
        zaehler = {"n": 0}

        def zaehl(*args, **kwargs):
            zaehler["n"] += 1
            return echt(*args, **kwargs)

        with mock.patch.object(cp, "decode_b64_c2sp", zaehl):
            fn()
        return zaehler["n"]

    def test_ueber_der_kappe_wird_keine_einzige_notenzeile_dekodiert(self):
        """Die Grundlinie ist NICHT null, und das ist keine Ausrede, sondern der gemessene Grund: schon
        das Zerlegen des vom AUFRUFER uebergebenen vkey dekodiert einmal (sein eigenes Schluesselmaterial,
        keine angreifer-gelieferte Zeile). Die Aussage ist deshalb 'keine Dekodierung UEBER die Grundlinie
        hinaus' — gemessen gegen genau diese Grundlinie, nicht gegen eine gewuenschte Null."""
        a = _Aufbau()
        grundlinie = self._zaehle_dekodierungen(lambda: cp._parse_vkey(a.vkey))
        self.assertEqual(grundlinie, 1, "die Grundlinie selbst hat sich geaendert — Messung neu ansetzen")
        note = _bau(a.text, [a.block[0]] * (DEFAULT_BUDGET.signatures + 1))

        def lauf():
            with self.assertRaises(BundleFormatError) as cm:
                cp.verify_checkpoint(note, a.vkey)
            self.assertIn("signature lines", str(cm.exception))
            self.assertIn("before any signature", str(cm.exception))

        self.assertEqual(self._zaehle_dekodierungen(lauf), grundlinie,
                         "eine Notenzeile wurde dekodiert, bevor die Kappe fiel")

    def test_meta_ohne_kappe_wuerde_jede_zeile_dekodiert(self):
        """ANTITAUTOLOGIE: mit gehobener Kappe MUSS der Zaehler die Arbeit wieder sehen — sonst misst
        der Test darueber nur, dass irgendetwas frueh abbricht."""
        from proofbundle.budget import VerificationBudget
        a = _Aufbau()
        n = 40
        note = _bau(a.text, [a.block[0]] * n)
        with mock.patch.object(cp, "DEFAULT_BUDGET", VerificationBudget(signatures=10 ** 9)):
            zahl = self._zaehle_dekodierungen(lambda: cp.verify_checkpoint(note, a.vkey))
        self.assertGreaterEqual(zahl, n, f"nur {zahl} Dekodierungen bei {n} Zeilen")


class DieGrenzeZwischenEmitterUndVerifizierer(unittest.TestCase):
    """Zwei Regeln gelten fuer die FERTIGE Note, nicht fuer den Bauplatz — und beide habe ich beim
    ersten Zuschnitt an der falschen Stelle aufgehaengt.

    Die Zeilenkappe (ein Verifikations-Budget) und "mindestens eine Signaturzeile" (eine Aussage ueber
    eine fertige signierte Note) hingen zuerst auch am Emitter. Gefunden hat das beide Male nicht die
    Ueberlegung, sondern die Vollsuite: ``test_kappe_vor_arbeit_signaturzeilen`` konnte seine feindliche
    Note nicht mehr bauen, und ``test_origin_quorum_rule`` cosigniert einen blossen Notenkoerper. Diese
    Klasse haelt die Grenze fest, damit sie nicht beim naechsten Zuschnitt wieder verrutscht."""

    def setUp(self):
        self.a = _Aufbau()
        self.koerper = ("bare.example/log\n7\n"
                        + base64.b64encode(b"\x22" * 32).decode() + "\nextension ok\n")

    def test_der_emitter_darf_die_erste_signaturzeile_anhaengen(self):
        w = generate_signer()
        note = cp.cosign_checkpoint(self.koerper + "\n", w, "w.example", 1_780_000_000)
        wv = cp.cosign_vkey("w.example", w.public_key().public_bytes_raw())
        self.assertIs(cp.verify_cosignature(note, wv)["ok"], True)
        # und das ERGEBNIS ist kanonisch — genau deshalb ist die Ausnahme am Emitter unschaedlich
        self.assertIsNotNone(orakel_rahmung(note)[0])

    def test_der_verifizierer_lehnt_die_note_ohne_signaturzeile_weiterhin_ab(self):
        for flaeche in (lambda n: cp.verify_checkpoint(n, self.a.vkey),
                        lambda n: cp.verify_cosignature(n, self.a.wvkey),
                        lambda n: tlogproof.format_tlog_proof(0, [], n)):
            with self.assertRaises(BundleFormatError):
                flaeche(self.koerper + "\n")
        self.assertIsNone(orakel_rahmung(self.koerper + "\n")[0])

    def test_der_emitter_erbt_die_zeilenkappe_nicht(self):
        viele = _bau(self.a.text, self.a.block * (DEFAULT_BUDGET.signatures // len(self.a.block) + 2))
        self.assertIsInstance(tlogproof.format_tlog_proof(0, [], viele), str)
        with self.assertRaises(BundleFormatError):       # der Verifizierer sehr wohl
            cp.verify_checkpoint(viele, self.a.vkey)

    def test_die_abgeschnittene_letzte_zeile_ist_keine_zweite_drahtform(self):
        echt = _bau(self.a.text, self.a.block)
        self.assertIs(cp.verify_checkpoint(echt, self.a.vkey)["ok"], True)
        with self.assertRaises(BundleFormatError):
            cp.verify_checkpoint(echt[:-1], self.a.vkey)
        self.assertIsNone(orakel_rahmung(echt[:-1])[0])


class AntiTautologieDerEingepflanzteDefekt(unittest.TestCase):
    """Der Korpus MUSS die Vor-Fix-Rahmung fangen. Tut er das nicht, misst er nichts."""

    def test_die_vorfix_rahmung_wird_vom_korpus_gefangen(self):
        a = _Aufbau()
        with mock.patch.object(cp, "_split_signed_note", _vorfix_split):
            abweichungen = [k for k, b in a.faelle
                            if _impl_nimmt_an(b, a.vkey) != orakel_nimmt_an(b, a.vkey)]
        self.assertGreaterEqual(
            len(abweichungen), 20,
            f"der eingepflanzte Vor-Fix-Defekt wurde nur {len(abweichungen)}x gesehen — "
            "dann bindet der Korpus die Eigenschaft nicht")
        self.assertTrue(any(k.startswith("leerzeilenlauf-") for k in abweichungen))
        self.assertTrue(any(k.startswith("klartextzeile@") for k in abweichungen))

    def test_die_vorfix_rahmung_nahm_die_echte_note_weiterhin_an(self):
        """Gegenprobe zum Meta-Test: der Defekt war KEIN Totalausfall, sondern genau die Aufweichung —
        sonst haette der Korpus ihn aus dem falschen Grund gesehen."""
        a = _Aufbau()
        with mock.patch.object(cp, "_split_signed_note", _vorfix_split):
            self.assertTrue(_impl_nimmt_an(a.note, a.vkey))


if __name__ == "__main__":
    unittest.main()
