"""C2SP tlog-checkpoint output — a signed note over the RFC 6962 Merkle root (v0.9).

proofbundle already has an RFC 6962 Merkle root and Ed25519, so it can emit a valid C2SP tlog-checkpoint:
a signed note that makes a receipt witness-network / transparency-log compatible. Pure serialization and
framing, no new crypto. Spec verified 2026-07 against C2SP/C2SP tlog-checkpoint.md + signed-note.md.

Byte-exact rules (the ones that bite):
  - Note text = at least three non-empty lines separated by U+000A: line 1 `origin` (a schemeless log
    identity, no unicode spaces, no '+'), line 2 the tree size as ASCII decimal with no leading zeros
    (empty tree = "0"), line 3 the Merkle root in STANDARD RFC 4648 §4 base64 (with padding) — NOT
    base64url. The note text ends with a final U+000A.
  - The signed note = note text (ending in U+000A) + one empty line + one-or-more signature lines.
  - A signature line is:  U+2014 (EM DASH, not a hyphen) SP keyname SP base64(keyID ‖ signature) U+000A
    where keyID is 4 bytes big-endian and, for Ed25519, signature is 64 raw bytes → 68 bytes total.
  - What is signed: the note text bytes INCLUDING the final U+000A, EXCLUDING the separating empty line.
    Raw bytes — NO DSSE/PAE wrapping.
  - keyID = SHA-256(keyname_bytes ‖ 0x0A ‖ 0x01 ‖ pubkey[32])[:4]   (0x01 = Ed25519 signature type).
  - vkey (to distribute the key) = keyname + "+" + hex8(keyID) + "+" + base64(0x01 ‖ pubkey[32]).
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .budget import DEFAULT_BUDGET
from .errors import BundleFormatError, UnsupportedError
from .signature import verify_ed25519
# NUR der C2SP-Decoder: jedes base64-Feld dieses Moduls ist ein C2SP-Note-Feld (Wurzel,
# Signaturzeile, vkey-Schluesselmaterial), und fuer die gilt die dokumentierte Ausnahme zur
# Ein-Drahtform-Regel. Der strikte `decode_b64` wird hier bewusst NICHT importiert, damit ein
# kuenftiger Aufruf gar nicht erst aufloest — die Gegenlesung vom 2026-09-05 fand genau eine
# Stelle, die er noch trug, und dort war er eine Regression (tests/test_wire_bytes_strict.py::
# TestC2SPFelderNutzenDenC2SPDecoder).
from ._wire_b64 import decode_b64_c2sp

__all__ = ["checkpoint_note", "key_id", "vkey", "sign_checkpoint", "verify_checkpoint",
           "root_bytes_from_b64", "cosign_key_id", "cosign_vkey", "cosign_checkpoint",
           "cosign_key_id_mldsa", "cosign_vkey_mldsa", "cosign_checkpoint_mldsa",
           "verify_cosignature", "verify_witnessed_checkpoint"]

EM_DASH = "—"
# Genau die Menge, die note.Open ablehnt: ``r < 0x20 && r != '\n'`` (note.go:524, x/mod v0.29.0,
# nachgelesen statt erinnert). 0x7F (DEL) gehoert NICHT dazu und wird hier deshalb auch nicht abgelehnt.
#
# WARUM 0x7F NICHT: der erste Zuschnitt hatte es drin und der Docstring behauptete dazu "Zeichen fuer
# Zeichen wie note.Open" — beides zusammen war falsch, und eine adversariale Gegenlesung hat es mit
# einem lauffaehigen Gegenbeispiel gezeigt (Note mit ``— ev\x7fil <b64>``: note.Open ACCEPT, wir
# REJECT). Das Argument "Terminal-Escape-Schutz" traegt fuer 0x7F nicht: der Escape-Einleiter ist ESC
# (0x1B), und der liegt unter 0x20 und faellt auf BEIDEN Seiten. 0x7F ist DEL und leitet nichts ein.
# Die Gegenrichtung waere teuer: eine Note, die ein echtes Log signiert hat und die die Referenz
# annimmt, haetten wir abgelehnt — ein Interoperabilitaetsfehler, den niemand misst, bis er weh tut.
# Der Origin bleibt davon unberuehrt strenger (``_origin_wellformed``: printable ASCII), und in einer
# Signaturzeile ueberlebt ein 0x7F die base64-Pruefung ohnehin nur im NAMEN.
# Einmal kompiliert, damit der Scan ueber eine mehrere MiB grosse Fremddatei in C laeuft.
_CTRL_RE = re.compile(r"[\x00-\x09\x0b-\x1f]")
# Ein einzelnes UTF-16-Surrogat ist der EINZIGE Weg, auf dem ein Python-`str` nicht nach UTF-8
# kodierbar ist. Als Scan statt als `encode`-Versuch: derselbe Befund, ohne eine Kopie der ganzen
# Fremddatei zu allozieren (die Note kann Megabytes gross sein).
_SURROGAT_RE = re.compile(r"[\ud800-\udfff]")
_ED25519_SIG_TYPE = 0x01
_COSIG_V1_SIG_TYPE = 0x04           # C2SP tlog-cosignature, Ed25519 cosignature/v1
_COSIG_MLDSA_SIG_TYPE = 0x06        # C2SP tlog-cosignature, ML-DSA-44 (FIPS 204) — v1.3
_COSIG_V1_PREFIX = "cosignature/v1\n"
_MAX_COSIG_TIMESTAMP = 2**63 - 1    # spec: MUST NOT exceed 2^63 - 1
_MLDSA44_PUB_LEN = 1312             # FIPS 204 ML-DSA-44 public key bytes
_MLDSA44_SIG_LEN = 2420             # FIPS 204 ML-DSA-44 signature bytes
_MLDSA_LABEL = b"subtree/v1\n\x00"  # cosigned_message.label[12] — fixed 12 bytes


def expected_origin_wellformed(expected_origin: "str | None") -> "bool | None":
    """Ist der vom AUFRUFER gepinnte Origin nach derselben Regel wohlgeformt wie der des Logs?

    Befund PB-EXPECTED-ORIGIN-ASCII-INKONSISTENZ-01 (un-Gegenlesung des NFC-Killing-Tests):
    `_origin_wellformed` erzwingt printable-ASCII auf `log_res["origin"]`, aber der gepinnte
    `expected_origin` lief ungeprueft in denselben exakten Vergleich. Das ist KEIN Loch — der
    Vergleich gegen einen bereits validierten Operanden schlaegt fail-closed fehl —, aber er
    schlaegt STILL fehl: wer ein Zero-Width oder ein NBSP in seinen Pin kopiert, sieht `ok=False`
    und sucht den Fehler beim Log statt bei sich.

    WARUM DAS HIER MELDET UND NICHT WIRFT — und das ist die Korrektur an meinem ersten Entwurf:
    der zuerst gebaute `require_*`-Pruefer warf `BundleFormatError`, und die BESTEHENDEN Tests des
    Repos haben ihn widerlegt. `tests/test_verify_proof_expected_origin.py::OriginVergleichIstExakt`
    verlangt fuer jeden Beinahe-Treffer (fuehrendes Leerzeichen, Zeilenumbruch, leerer String)
    ausdruecklich ein VERDIKT: `log_ok=False` bei UNBERUEHRTEM `inclusion_ok` — „der Fehlschlag
    kommt vom Origin, nicht von der Signatur". Ein Wurf bricht die Verifikation ab und nimmt dem
    Aufrufer genau diese Unterscheidung. Der Fund war „still", nicht „falsch"; die Antwort darauf
    ist eine zusaetzliche Auskunft, keine geaenderte Semantik.

    Drei Zustaende: `None` = kein Pin gesetzt (nicht gebunden, dokumentiert) · `True` wohlgeformt ·
    `False` nicht wohlgeformt (der Vergleich kann dann per Konstruktion nicht treffen, weil die
    Log-Seite dieselbe Regel bereits erzwingt).
    """
    if expected_origin is None:
        return None
    return isinstance(expected_origin, str) and _origin_wellformed(expected_origin)


def _root_std_b64(root: bytes) -> str:
    """Standard RFC 4648 §4 base64 (with padding) of the raw Merkle root — NOT base64url."""
    return base64.b64encode(root).decode("ascii")


def _origin_wellformed(origin: str) -> bool:
    """An origin / note identity safe for the EXACT origin-quorum compare: printable ASCII only, no '+'
    (the vkey separator), no leading/trailing space and no double space. A single internal ASCII space
    is allowed so Go sumdb's `go.sum database tree` verifies; a witness NAME carries no space at all
    (enforced), so a spaced origin still cannot equal one.

    Printable-ASCII is the POSITIVE, non-enumerated rule that closes the whole invisible/look-alike
    CLASS at once, instead of chasing one Unicode category per round (Deep-Gate F-1 zero-width → re-gate
    NBSP → re-gate variation-selectors/Default-Ignorable/appended-space). None of those can cloak an
    origin into looking like a witness name it then escapes the exclusion under, because none is
    printable ASCII: a zero-width (Cf), a Default_Ignorable letter (Hangul filler, category Lo), a
    variation selector or combining mark (Mn), a NBSP or other non-plain whitespace (Zs), a control char
    (Cc) — all rejected. Measured against every shipped external vector (Go sumdb, Rekor, rootcommit,
    Colin's fixtures): all pass. Honest scope: this also refuses a non-ASCII (IDN/Unicode) origin, a
    deliberate restriction for the verifier's identity compare; no real tlog origin is non-ASCII."""
    # DEEP-GATE 4.0.0 re-gate iter5 (never-raise, caller-contract): a non-str origin (None/int/list from a
    # caller that built it from an upstream JSON field) reached `.isascii()` and raised a raw AttributeError
    # out of every public constructor/cosign surface that routes identity through this helper. Same
    # isinstance(str) guard the parse helpers already carry — validate the TYPE before the content.
    if not isinstance(origin, str):
        return False
    if not origin or "+" in origin:
        return False
    if not (origin.isascii() and origin.isprintable()):
        return False
    return origin == origin.strip() and "  " not in origin


def _witness_name_wellformed(name: str) -> bool:
    """A witness NAME safe for the exact compare: non-empty printable ASCII, no '+', no space at all
    (a schemeless identity). Stricter than an origin, which allows internal spaces — the emit path
    (cosign_checkpoint / _mldsa) always required this; :func:`_parse_witness_vkey` now enforces it on
    the verify path too, so a name cloaked with any whitespace or invisible character cannot parse."""
    return (isinstance(name, str) and bool(name) and "+" not in name and " " not in name
            and name.isascii() and name.isprintable())


def checkpoint_note(origin: str, tree_size: int, root: bytes) -> str:
    """Build the C2SP checkpoint note text (3 lines + trailing newline). ``root`` is the raw RFC 6962
    Merkle root bytes at ``tree_size``. ``origin`` must be non-empty with no spaces/'+' (a schemeless URL)."""
    if not _origin_wellformed(origin):
        raise BundleFormatError("checkpoint origin must be a printable-ASCII schemeless id without "
                                "edge/double spaces, invisible characters, or '+'")
    if isinstance(tree_size, bool) or not isinstance(tree_size, int) or tree_size < 0:
        raise BundleFormatError("checkpoint tree_size must be a non-negative integer")
    if not isinstance(root, bytes):    # iter5 never-raise: a non-bytes root raised raw TypeError from b64encode
        raise BundleFormatError("checkpoint root must be raw bytes")
    # DER EMITTER DARF NICHTS BAUEN, WAS SEIN EIGENER VERIFIZIERER MALFORMED NENNT (2026-08-18, beim
    # Nachmessen des Befunds PB-CHECKPOINT-CONSTRUCTOR-TYPEERROR-01 gefunden — dessen eigener Kern war
    # laengst geschlossen, DIESER Nachbar nicht). `b""` ist bytes und lief durch, `base64.b64encode(b"")`
    # ist der leere String, und die dritte Notenzeile wurde damit LEER. Gemessen: `sign_checkpoint`
    # signierte diese Note anstandslos, und `verify_checkpoint` wie `_note_text_of` lehnten sie danach
    # als "at least 3 non-empty lines" ab — der Aufrufer haelt eine signierte Note in der Hand, die
    # KEIN Verifizierer akzeptiert, auch keiner ausserhalb dieser Bibliothek.
    # DER REALISTISCHE WEG dorthin ist kein Tippfehler: `root_bytes_from_b64("")` gibt `b""` zurueck
    # (leer ist gueltiges base64), nicht `None` — ein leeres Root-Feld im Bundle wird also stumm zu
    # einem leeren Root und faengt sich nicht am isinstance-Riegel darueber.
    # EHRLICHE GRENZE, absichtlich nicht weiter zugezogen: ein NICHT-leerer Root falscher Laenge
    # (z.B. 5 Bytes) laeuft weiterhin durch, weil er den Rundlauf besteht — das ist ein Aufrufer-Fehler
    # an den EIGENEN Wurzel-Bytes, kein angreifer-gelieferter Wert. Wo das Format eine Laenge wirklich
    # verlangt, steht sie schon (`_mldsa_cosigned_message`: 32 Bytes).
    if not root:
        raise BundleFormatError("checkpoint root must not be empty — an empty root encodes to an "
                                "empty third note line, which no verifier accepts")
    return f"{origin}\n{tree_size}\n{_root_std_b64(root)}\n"


def key_id(keyname: str, pubkey: bytes) -> bytes:
    """C2SP note key ID = first 4 bytes of SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ 32-byte-Ed25519-pubkey)."""
    if not isinstance(pubkey, bytes) or len(pubkey) != 32:
        raise BundleFormatError("Ed25519 public key must be 32 raw bytes")
    # DEEP-GATE re-gate F-8/F-10: the log key name is the third identity slot (with origin and witness
    # name); it is encoded into the keyID, so a surrogate name would raise a raw UnicodeEncodeError
    # out of this public helper, and a zero-width/invisible name would substitute for a real one.
    # Same printable-ASCII rule as origin/witness name — closed at the source that does the encode.
    if not _witness_name_wellformed(keyname):
        raise BundleFormatError("key name must be a printable-ASCII identity without spaces or invisible characters")
    h = hashlib.sha256(keyname.encode("utf-8") + b"\n" + bytes([_ED25519_SIG_TYPE]) + pubkey).digest()
    return h[:4]


def vkey(keyname: str, pubkey: bytes) -> str:
    """C2SP verifier key encoding: name + '+' + hex8(keyID) + '+' + base64(0x01 ‖ pubkey)."""
    kid = key_id(keyname, pubkey)
    kid_hex = f"{int.from_bytes(kid, 'big'):08x}"
    keymat = base64.b64encode(bytes([_ED25519_SIG_TYPE]) + pubkey).decode("ascii")
    return f"{keyname}+{kid_hex}+{keymat}"


def sign_checkpoint(origin: str, tree_size: int, root: bytes, signer, keyname: str) -> str:
    """Produce a signed C2SP checkpoint note. ``signer`` is an Ed25519 private key whose public key must
    correspond to ``keyname``. The signature is over the RAW note-text bytes (including the trailing
    newline), never over base64 and never PAE-wrapped."""
    if not _witness_name_wellformed(keyname):
        raise BundleFormatError("checkpoint keyname must be a printable-ASCII identity "
                                "without spaces, invisible characters, or '+'")
    note = checkpoint_note(origin, tree_size, root)
    pubkey = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = signer.sign(note.encode("utf-8"))
    kid = key_id(keyname, pubkey)
    sig_b64 = base64.b64encode(kid + sig).decode("ascii")
    sig_line = f"{EM_DASH} {keyname} {sig_b64}\n"
    return note + "\n" + sig_line


def _parse_vkey(vkey_str: str, sig_type: int = _ED25519_SIG_TYPE) -> tuple[str, bytes, bytes]:
    # RE-GATE never-raise consistency: a non-str vkey (None/int/list from a caller/config) is a typed
    # BundleFormatError, never a raw AttributeError from `.split` — this parse helper raises BundleFormatError
    # for every other malformed vkey, so a wrong-type vkey joins that contract instead of an untyped crash.
    if not isinstance(vkey_str, str):
        raise BundleFormatError("vkey must be a string (name+hexKeyID+base64KeyMaterial)")
    # The key material is standard base64, which can itself contain '+'. Since the name has no '+' (a
    # schemeless origin) and the hex keyID has none, the FIRST TWO '+' are the separators and everything
    # after is the base64 — so split with maxsplit=2, never a plain split (that would over-split the b64).
    parts = vkey_str.split("+", 2)
    if len(parts) != 3:
        raise BundleFormatError("vkey must have 3 '+'-separated parts (name+hexKeyID+base64KeyMaterial)")
    name, kid_hex, keymat_b64 = parts
    # DEEP-GATE re-gate F-8: the log vkey NAME is encoded into key_id below; a surrogate name would
    # raise UnicodeEncodeError and an invisible one would substitute — same rule as the witness vkey.
    if not _witness_name_wellformed(name):
        raise BundleFormatError("vkey name must be a printable-ASCII identity without spaces or invisible characters")
    try:
        keymat = decode_b64_c2sp(keymat_b64)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("vkey key material is not valid base64") from exc
    if len(keymat) != 33 or keymat[0] != sig_type:
        raise BundleFormatError(
            f"vkey key material must be 0x{sig_type:02x} followed by a 32-byte Ed25519 key")
    pubkey = keymat[1:]
    try:
        kid = bytes.fromhex(kid_hex)
    except ValueError as exc:
        raise BundleFormatError("vkey keyID is not valid hex") from exc
    # EIN VKEY, DER SICH SELBST WIDERSPRICHT, IST MALFORMED — nicht "hat halt nichts signiert".
    # Gefunden in der un-Gegenlesung dieser Scheibe (2026-08-16): deklarierte ID und aus Name +
    # Schluesselmaterial NEU BERECHNETE ID konnten auseinanderfallen, und `verify_checkpoint` lehnte
    # dann still jede Signaturzeile ab. Der Aufrufer sah `ok=False, signer_present=False` und konnte
    # "niemand hat signiert" nicht von "dein Schluessel ist kaputt" unterscheiden — genau die Klasse,
    # die dieses Release an drei anderen Stellen schliesst (nicht messbar liest sich wie gemessenes
    # Nein), hier gefunden von einem Gegenleser in Code, den diese Scheibe nicht angefasst hat.
    # Dies ist der richtige Ort: jede andere Missform des vkey faellt schon hier typisiert durch.
    if kid != key_id(name, pubkey):
        raise BundleFormatError(
            "vkey is self-inconsistent: its declared keyID does not match the ID recomputed from "
            "its own name and key material — this is a malformed key, not a failed verification")
    return name, kid, pubkey


def _split_signed_note(signed_note: str, what: str = "signed note", *,
                       apply_budget_cap: bool = True,
                       require_signature_line: bool = True) -> "tuple[str, str]":
    """DIE EINE kanonische C2SP-Rahmung einer signierten Note -> (note_text, sig_block).

    Fund L1-600-NOTE-FRAMING-01 (deep gate 6.0.0, P1). Drei Stellen dieses Moduls trennten Text und
    Signaturblock an der ERSTEN Leerzeile und ueberSPRANGEN danach still jede Blockzeile, die nicht mit
    EM DASH + Leerzeichen beginnt. Die Referenzimplementierung des Formats
    (golang.org/x/mod/sumdb/note.Open) trennt an der LETZTEN Leerzeile und nennt JEDE andere Zeile im
    Block errMalformedNote. Gemessen am Kopf 917edc69: EINE signierte Note hatte damit eine UNBEGRENZTE
    Familie byteverschiedener Formen, die alle ok=True lieferten (24 sha256-Formen allein aus vier
    Mustern), jede faehig, beliebigen ANGREIFERTEXT mitzufuehren, den das Verdikt nicht deckt —
    eingespeiste Klartextzeile, ein zweites (Ursprung, Groesse, Wurzel)-Tripel, Kilobyte-Fuellmaterial —,
    und jede vom Referenzverifizierer abgelehnt.

    DIE EIGENSCHAFT, die dieser Helfer herstellt — und zwar EINGESCHRAENKT, nicht absolut (Auflage A4:
    eine Zusicherung, die mehr behauptet, als sie prueft, ist genau der Fehler, den dieser Fix behebt):
    fuer Eingaben INNERHALB der deklarierten Grenzen (unterstuetzte Signaturtypen 0x01/0x04/0x06,
    Budgets ``signatures``/``witnesses``/``merkle_path`` aus ``DEFAULT_BUDGET``, ``str``-Eingabe) ist die
    Menge der byteverschiedenen Dateien, die eine ``verify_*``-Oberflaeche dieses Moduls annimmt,
    dieselbe wie die der kanonischen C2SP-Rahmung. AUSSERHALB dieser Grenzen — ueber der Kappe, mit
    einem Algorithmus, den dieser Build nicht kann — lehnt proofbundle typisiert ab, wo die Referenz
    noch parst; das ist absichtlich STRENGER und wird nicht als Gleichheit behauptet. Dieselbe
    Invariante wie ``_wire_b64`` fuer die base64-FELDER ("ein signiertes Artefakt, EINE akzeptierte
    Drahtform") — hier eine Schicht hoeher, an der RAHMUNG.

    Der Vertrag, Zeichen fuer Zeichen wie note.Open:
      1. Gueltiges UTF-8, und ausser dem Zeilenumbruch kein ASCII-Steuerzeichen UNTER 0x20 — genau
         note.Opens Menge (``r < 0x20 && r != '\n'``). 0x7F/DEL gehoert ausdruecklich NICHT dazu.
      2. Trennung am LETZTEN "\n\n", BYTEGENAU: ``rfind`` + Schnitt, NIE ``rsplit``. ``rsplit`` frisst
         BEIDE Umbrueche, und der erste davon gehoert zur SIGNIERTEN Nachricht — der Notentext endet
         per Konstruktion auf genau dem "\n", ueber das der Signierer gerechnet hat.
      3. Der Signaturblock ist nicht leer, endet auf "\n", und traegt MINDESTENS EINE Zeile (eine Note
         ohne Signaturzeile ist malformed, nicht "unsigniert").
      4. JEDE Zeile des Blocks beginnt mit EM DASH + Leerzeichen. Kein stilles Ueberspringen.
      5. Jede Zeile traegt Name + Leerzeichen + nicht-leeres Standard-base64 mit >= 5 Nutzbytes; der
         Name ist nicht leer, traegt kein '+' und KEIN Unicode-Leerzeichen (note.Open: ``isValidName``
         mit ``unicode.IsSpace``, nicht nur das ASCII-Leerzeichen).

    Alles andere ist ``BundleFormatError`` — "malformed", nicht "nicht signiert": ein Aufrufer muss eine
    kaputte Datei von einer echten unsignierten Note unterscheiden koennen.

    ``require_signature_line=False`` NUR fuer die beiden Cosignatur-EMITTER. "Mindestens eine
    Signaturzeile" ist eine Regel fuer die FERTIGE Note; ``cosign_checkpoint`` haengt die erste Zeile
    aber gerade erst an, und der dokumentierte Selbstbezeugungs-Pfad startet mit einem blossen
    Notenkoerper samt Leerzeile. Gefunden hat das nicht ich, sondern die Vollsuite:
    ``tests/test_origin_quorum_rule.py::...::test_a_valid_ascii_extension_line_note_still_verifies``
    baut genau so. Das ERGEBNIS des Emitters ist in beiden Faellen kanonisch — die Regel gehoert also
    an den Verifizierer, nicht an den Bauplatz. Dieselbe Grenze wie bei der Kappe, zweite Instanz.

    BEKANNTE, SPEC-KONFORME ABWEICHUNG bei der Zeilenzahl: note.Open bricht hart bei mehr als 100
    Signaturzeilen ab (note.go:568), ``DEFAULT_BUDGET.signatures`` steht hier auf 512. Die Spezifikation
    ueberlaesst die Zahl ausdruecklich der Implementierung ("An implementation can reject a note with
    too many signatures (for example, more than 100 signatures)", note.go:38-39), beide Werte sind also
    konform — im Bereich 101..512 divergieren die beiden Implementierungen aber, und das steht hier,
    statt still zu bleiben.

    ``apply_budget_cap=False`` NUR auf der EMIT-Seite. Die Zeilenkappe ist ein VERIFIKATIONS-Budget
    gegen fremde Dateien, KEINE Formatregel: C2SP begrenzt die Zahl der Signaturen nicht, und ein
    Betreiber mit mehr Zeugen als ``DEFAULT_BUDGET.signatures`` muss seine eigene Note weiterhin
    verpacken koennen. Beim ersten Zuschnitt hing die Kappe auch am Emitter — gefunden, weil
    ``tests/test_kappe_vor_arbeit_signaturzeilen.py`` seine feindliche Note gar nicht mehr bauen konnte;
    das war kein Testproblem, sondern ein echter Fehlgriff an der Grenze zwischen Format und Budget.

    REIHENFOLGE, und sie ist Teil des Vertrags: (0) und (a) sind Scans in C ueber den Text, ohne eine
    einzige Dekodierung; erst danach faellt die Kappe (b), und erst NACH der Kappe wird ueberhaupt etwas
    dekodiert (c). Damit gilt die Zusage von ``_cap_signature_lines`` ("refused before any signature is
    decoded or verified") strikt FRUEHER als vorher, nicht schwaecher.
    """
    if not isinstance(signed_note, str):
        raise BundleFormatError(f"{what} must be a string (non-str is malformed, fail-closed)")
    # (0) UTF-8 + Steuerzeichen, wie note.Open sie ueber die GANZE Nachricht prueft. Ohne diese Regel
    #     bleibt genau eine Ecke der Klasse offen: eine zusaetzliche, sonst wohlgeformte Signaturzeile
    #     mit einem eingebetteten Steuerzeichen haette die Regeln (2)-(5) bestanden, waere hier
    #     angenommen und von der Referenz als errMalformedNote abgelehnt worden — also wieder zwei
    #     Drahtformen fuer ein Artefakt. Ein Ein-Durchgang-Scan in C, keine Dekodierung.
    if _SURROGAT_RE.search(signed_note):
        raise BundleFormatError(
            f"{what} is not valid UTF-8 (lone UTF-16 surrogate, malformed)")
    if _CTRL_RE.search(signed_note):
        raise BundleFormatError(
            f"{what} carries an ASCII control character other than the line feed — the canonical form "
            "is printable text separated by U+000A (malformed)")
    split = signed_note.rfind("\n\n")
    if split < 0:
        raise BundleFormatError(f"{what} has no empty-line separator between text and signatures")
    note_text, sig_block = signed_note[:split + 1], signed_note[split + 2:]
    if sig_block and not sig_block.endswith("\n"):
        # Eine abgeschnittene letzte Zeile ist eine ZWEITE Drahtform derselben Signatur ("...SIG\n"
        # und "...SIG" wuerden beide dieselbe Signatur tragen) — genau die Klasse, die hier faellt.
        raise BundleFormatError(
            f"{what} has a truncated last signature line — the signature block must end in a newline "
            "(malformed)")
    lines = sig_block.split("\n")[:-1]
    if not lines and require_signature_line:
        # Eigener, benannter Vertragspunkt (Auflage A1) statt Nebenwirkung einer anderen Pruefung.
        raise BundleFormatError(
            f"{what} has no signature line at all — a signed note carries at least one (malformed)")
    # (a) PRAEFIX-DURCHGANG. Reiner Zeichenvergleich je Zeile, keine Dekodierung — er darf deshalb vor
    #     der Kappe stehen.
    for line in lines:
        if not line.startswith(EM_DASH + " "):
            raise BundleFormatError(
                f"{what} carries a non-signature line in its signature block — after the empty-line "
                "separator EVERY line must begin with EM DASH + space. Skipping such a line would let "
                "UNSIGNED attacker-chosen content ride inside a note that verifies (malformed)")
    # (b) KAPPE VOR DER ARBEIT, jetzt an der frühestmoeglichen Stelle: nach (a) ist jede Zeile per
    #     Konstruktion eine Signaturzeile, die Zeilenzahl IST die Signaturzahl, und (c) unten dekodiert.
    #     Ohne diese Reihenfolge haette die neue Formpruefung die gelandete Haertung
    #     L2-BDOS-C2SP-SIGLINES-01 aufgeweicht (74234 base64-Dekodierungen vor der Ablehnung).
    if apply_budget_cap:
        _cap_signature_lines(sig_block, what)
    # (c) FORMDURCHGANG, die restliche Zeilenregel von note.Open: Name (nicht leer, ohne '+', ohne
    #     Leerzeichen per Konstruktion des Schnitts), nicht-leeres Standard-base64, und mindestens die
    #     5 Bytes, unter denen keyID + Signatur nicht passen. OHNE (c) bliebe der naechste Nachbar
    #     derselben Klasse offen: ``EM DASH + Leerzeichen + BELIEBIGER ANGREIFERTEXT`` haette die
    #     Praefixregel bestanden, waere still uebersprungen worden und haette genau die unsignierte
    #     Fracht weitergetragen, gegen die (a) gebaut ist — die Referenz nennt auch das
    #     errMalformedNote. Kryptografie laeuft hier NICHT: geprueft wird die FORM, nicht die Gueltigkeit.
    for line in lines:
        name, sep, payload_b64 = line[len(EM_DASH) + 1:].partition(" ")
        # ``any(ch.isspace())`` ist die Entsprechung zu ``strings.IndexFunc(name, unicode.IsSpace)``
        # (note.go:238). Der Schnitt am ASCII-Leerzeichen allein reicht NICHT: ein Name mit U+00A0,
        # U+2003, U+3000 oder U+2028 traegt kein ASCII-Leerzeichen, kam hier durch, wurde als Zeile
        # eines unbekannten Schluessels still uebersprungen — und die Note verifizierte mit ok=True,
        # waehrend die Referenz die GANZE Note ablehnt. Gemessen mit lauffaehigem Gegenbeispiel;
        # U+200B (ZWSP) ist die Negativkontrolle: kein unicode.IsSpace, beide Seiten nehmen an.
        # Die Mengen fallen dort auseinander, wo Python U+001C..U+001F als space zaehlt und Go nicht —
        # die liegen unter 0x20 und sind oben in (0) auf beiden Seiten schon weg.
        if (not sep or not name or "+" in name or not payload_b64
                or any(ch.isspace() for ch in name)):
            raise BundleFormatError(
                f"{what} has a malformed signature line — the canonical form is EM DASH, space, a "
                "non-empty name without '+' and without any Unicode whitespace, space, and non-empty "
                "standard base64 (malformed)")
        try:
            payload = decode_b64_c2sp(payload_b64)
        except (ValueError, TypeError) as exc:
            raise BundleFormatError(
                f"{what} has a signature line whose payload is not valid standard base64 "
                "(malformed)") from exc
        if len(payload) < 5:
            raise BundleFormatError(
                f"{what} has a signature line whose payload is shorter than the 4-byte key ID plus a "
                "signature (malformed)")
    return note_text, sig_block


def _cap_signature_lines(sig_block: str, what: str) -> None:
    """DIE KAPPE VOR DER ARBEIT, auf der C2SP-Notenfamilie (deep gate 2026-09-05, L2-BDOS-C2SP-SIGLINES-01,
    P2). Das ``signatures``-Budget (Finding 15b) sass auf DSSE und trust_pack; die Signaturzeilen einer
    signierten Note hatten keine Zaehlkappe. Gemessen mit kanonisch geformten Muell-Signaturen (R ein gueltiger
    Punkt, S < L, also der TEURE Pfad, 93 us statt 10 us je Zeile): eine 8-MiB-Note mit 74234 Zeilen fuer die
    keyID des eigenen vkey trieb ~74k Ed25519-Pruefungen, 9,9 s, x63753 gegenueber der echten Note — ueber die
    angreifer-kontrollierte Datei ``verify-proof``, deren Checkpoint woertlich eingebettet ist.

    Gezaehlt werden die Zeilen, die als Signaturzeile beginnen (EM DASH + Leerzeichen), BEVOR eine einzige
    dekodiert oder verifiziert wird; die Zaehlung ist O(n) ueber den Textblock und braucht keine Arbeit, die
    sie begrenzt (Owner-Ausnahme greift nicht). Eine Note ueber der Kappe ist malformed, nicht 'nicht
    signiert' — sie faellt typisiert, damit ein Aufrufer sie von einer unsignierten Note unterscheiden kann.
    Dieselbe Kappe fuer Log-Signaturen (verify_checkpoint) und Cosignaturen (verify_cosignature): beide
    Schleifen tragen dieselbe Form, und zwei Kappen fuer dieselbe Groesse waeren die naechste Drift."""
    # Aufgerufen wird sie seit L1-600-NOTE-FRAMING-01 aus _split_signed_note (Schritt b), also nach dem
    # Praefix-Durchgang und VOR jeder Dekodierung — frueher als zuvor, nicht spaeter.
    n = sig_block.count(EM_DASH + " ")
    if n > DEFAULT_BUDGET.signatures:
        raise BundleFormatError(
            f"{what} carries {n} signature lines (> signatures={DEFAULT_BUDGET.signatures}) "
            "— refused before any signature is decoded or verified (DoS guard, cap before work)")


def verify_checkpoint(signed_note: str, vkey_str: str) -> dict:
    """Verify a signed C2SP checkpoint against a vkey. Returns {ok, origin, tree_size, root}. ``ok`` is
    True iff a signature line whose keyID matches the vkey verifies (Ed25519) over the exact note-text
    bytes. Reconstructs the note text from the parsed bytes — never re-derives it."""
    name, kid_v, pubkey = _parse_vkey(vkey_str)
    # 6-lens DEEP gate L1-02 (never-raise): a non-str signed_note made `"\n\n" not in signed_note` raise a
    # raw TypeError out of the public verify_witnessed_checkpoint/verify_checkpoint surface — mirror the
    # isinstance(str) guard already on witness_vkey (_parse_witness_vkey, RE-GATE never-raise consistency).
    # Die RAHMUNG liegt seit L1-600-NOTE-FRAMING-01 im gemeinsamen Helfer (letzte Leerzeile, jede
    # Blockzeile eine Signaturzeile); der Typboden steht dort mit derselben Meldung.
    note_text, sig_block = _split_signed_note(signed_note)
    lines = note_text.split("\n")
    if len(lines) < 4 or not lines[0] or not lines[1] or not lines[2]:
        raise BundleFormatError("checkpoint note must have at least 3 non-empty lines")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    # DEEP-GATE F-1 + re-gate (2026-08-17): the origin must be a printable-ASCII identity with no
    # edge/double space, so it cannot cloak a witness name it would then escape the origin-quorum
    # exclusion under (via zero-width, Default-Ignorable, variation selector, NBSP or an appended
    # space). Positive rule = the whole class, not one category per round. Go sumdb / Rekor stay valid.
    if not _origin_wellformed(origin):
        raise BundleFormatError("checkpoint origin must be a printable-ASCII identity without "
                                "edge/double spaces, invisible characters, or '+' (malformed)")
    if len(size_s) > 20 or (size_s != "0" and (size_s.startswith("0") or not (size_s.isascii() and size_s.isdigit()))):
        raise BundleFormatError("checkpoint tree size must be ASCII decimal with no leading zeros")
    try:
        root = decode_b64_c2sp(root_b64)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("checkpoint root is not valid standard base64") from exc
    # DEEP-GATE 4.0.0 re-gate (D2/D3): the note-text encode was ABOVE this block, so a lone/unpaired
    # UTF-16 surrogate anywhere in the note (a str survives splitting but is not valid UTF-8) raised a
    # raw UnicodeEncodeError out of verify_witnessed_checkpoint / evaluate_public_transparency — the one
    # verify_checkpoint instance the F-8/F-10 validate-before-encode re-gates missed (verify_tlog_proof
    # already wraps its call; the sibling _note_text_of already validates first). Encode AFTER the string
    # validation, and fail-closed on any residual non-UTF-8 note text (e.g. a surrogate in an extension line).
    # Seit L1-600-NOTE-FRAMING-01 prueft _split_signed_note UTF-8 bereits ueber die GANZE Note, dieser
    # Zweig ist also nicht mehr erreichbar. Er bleibt als zweite Lage stehen, weil er den Vertrag DIESER
    # Funktion beschreibt (kodiere erst nach der Validierung) und nichts kostet.
    try:
        note_bytes = note_text.encode("utf-8")
    except UnicodeEncodeError as exc:                                             # pragma: no cover
        raise BundleFormatError("checkpoint note text is not valid UTF-8 (malformed, fail-closed)") from exc

    ok = False
    # WAR DER SCHLUESSEL UEBERHAUPT DABEI? Diese Unterscheidung entsteht in der Schleife unten und
    # wurde bisher zu einem einzigen `ok=False` verdichtet — mit der Folge, dass ein FALSCHER
    # --log-vkey und eine VERFAELSCHTE Signatur byte-gleiche Verdikte lieferten (gemessen
    # 2026-08-16, `FINDING_json_trennt_die_drei_ursachen_nicht.md`). Ein Signaturvergleich ist ein
    # Zwei-Eingaben-Praedikat und weist bei einem Fehlschlag keiner Seite die Schuld zu; die
    # KEY-ID kann es aber sehr wohl: findet sich keine Signaturzeile mit der ID des uebergebenen
    # Schluessels, hat dieser Schluessel diese Note nicht signiert. Findet sich eine und die
    # Pruefung faellt trotzdem, stimmen die Bytes nicht.
    # EHRLICHE GRENZE, und sie ist keine Schwaeche des Feldes: eine Verfaelschung, die genau die
    # vier keyID-Bytes trifft, ist von einem falschen Schluessel NICHT unterscheidbar — dann traegt
    # die Note keinen Beleg mehr, dass dieser Schluessel je signiert hat. Das ist eine wahre
    # Aussage ueber die Lage, kein Messfehler.
    signer_present = False
    kid_expected = key_id(name, pubkey)
    # Die Kappe lief bereits in _split_signed_note, vor der ersten Dekodierung — hier keine zweite.
    for line in sig_block.split("\n"):
        if not line.startswith(EM_DASH + " "):
            continue
        rest = line[len(EM_DASH) + 1:]
        try:
            lname, payload_b64 = rest.split(" ", 1)
        except ValueError:
            continue
        if lname != name:
            continue
        try:
            payload = decode_b64_c2sp(payload_b64)
        except (ValueError, TypeError):
            continue
        if len(payload) < 4:
            continue
        kid, sig = payload[:4], payload[4:]
        if kid != kid_v or kid != kid_expected:   # keyID must match both the vkey and the recomputed id
            continue
        signer_present = True                     # diese Note traegt eine Zeile FUER diesen Schluessel
        if verify_ed25519(pubkey, sig, note_bytes):
            ok = True
            break
    return {"ok": ok, "origin": origin, "tree_size": int(size_s), "root": root,
            "signer_present": signer_present}


def root_bytes_from_b64(root_b64: str) -> Optional[bytes]:
    """Decode a bundle's standard-base64 Merkle root to raw bytes (for feeding into checkpoint_note)."""
    try:
        return decode_b64_c2sp(root_b64)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# C2SP tlog-cosignature (Ed25519 cosignature/v1) — v1.2.
#
# A cosignature is a witness's statement that it verified the CONSISTENCY of a
# checkpoint: verifying a quorum of cosignatures rules out a split view by the
# log operator, entirely offline. Spec verified 2026-07 against
# C2SP/C2SP tlog-cosignature.md:
#   - witness key ID = SHA-256(name ‖ 0x0A ‖ 0x04 ‖ pubkey[32])[:4]  (0x04 = cosignature/v1;
#     NOTE: intentionally different from the log's 0x01 — a log key can never
#     masquerade as a witness key, the key IDs cannot collide by construction).
#   - signature blob on the note line = keyID[4] ‖ u64-BIG-ENDIAN-timestamp ‖ sig[64].
#   - signed message = "cosignature/v1\n" + "time <ts>\n" + the WHOLE note body
#     (all three-plus lines including the final U+000A, excluding signature lines).
#   - timestamp is a POSIX timestamp, MUST NOT exceed 2^63-1; verifiers MAY
#     reject future timestamps — as a pure-offline tool with no trusted clock,
#     proofbundle exposes the timestamp and leaves freshness policy to the caller.
# ---------------------------------------------------------------------------


def cosign_key_id(witness_name: str, pubkey: bytes) -> bytes:
    """Cosignature/v1 key ID = SHA-256(name ‖ 0x0A ‖ 0x04 ‖ 32-byte-Ed25519-pubkey)[:4]."""
    if not isinstance(pubkey, bytes) or len(pubkey) != 32:
        raise BundleFormatError("Ed25519 public key must be 32 raw bytes")
    # DEEP-GATE re-gate F-8/F-10: the witness name is the third identity slot (with origin and witness
    # name); it is encoded into the keyID, so a surrogate name would raise a raw UnicodeEncodeError
    # out of this public helper, and a zero-width/invisible name would substitute for a real one.
    # Same printable-ASCII rule as origin/witness name — closed at the source that does the encode.
    if not _witness_name_wellformed(witness_name):
        raise BundleFormatError("witness name must be a printable-ASCII identity without spaces or invisible characters")
    h = hashlib.sha256(witness_name.encode("utf-8") + b"\n"
                       + bytes([_COSIG_V1_SIG_TYPE]) + pubkey).digest()
    return h[:4]


def cosign_vkey(witness_name: str, pubkey: bytes) -> str:
    """Witness verifier key: name + '+' + hex8(keyID) + '+' + base64(0x04 ‖ pubkey)."""
    kid = cosign_key_id(witness_name, pubkey)
    kid_hex = f"{int.from_bytes(kid, 'big'):08x}"
    keymat = base64.b64encode(bytes([_COSIG_V1_SIG_TYPE]) + pubkey).decode("ascii")
    return f"{witness_name}+{kid_hex}+{keymat}"


def _note_body_and_sigs(signed_note: str, *,
                        require_signature_line: bool = True) -> "tuple[str, str]":
    """Kanonisch gerahmt UND im Koerper validiert: (note_text, sig_block).

    EIN Aufruf, EINE Rahmung. ``verify_cosignature`` holte sich den Signaturblock frueher mit einer
    ZWEITEN, eigenen Trennung (``signed_note.split("\\n\\n", 1)[1]``) — genau die Doppelung, aus der
    L1-600-NOTE-FRAMING-01 wurde: zwei Schreibweisen derselben Frage driften auseinander.
    """
    # 6-lens DEEP gate L1-01 (never-raise): a non-str signed_note leaked a raw TypeError out of the public
    # verify_cosignature surface — der isinstance(str)-Boden steht jetzt im gemeinsamen Helfer.
    note_text, sig_block = _split_signed_note(signed_note,
                                              require_signature_line=require_signature_line)
    lines = note_text.split("\n")
    if len(lines) < 4 or not lines[0] or not lines[1] or not lines[2]:
        raise BundleFormatError("checkpoint note must have at least 3 non-empty lines")
    # DEEP-GATE F-1 + re-gate: reject a cloaked origin here too, so every consumer of the note body
    # (verify_cosignature, witness_quorum's origin extraction) sees an exact-comparable identity.
    if not _origin_wellformed(lines[0]):
        raise BundleFormatError("checkpoint origin must be a printable-ASCII identity without "
                                "edge/double spaces, invisible characters, or '+' (malformed)")
    # DEEP-GATE 4.0.0 re-gate (D2/D3 CLASS fix): _origin_wellformed only checks lines[0]. The note body
    # ALSO carries size, root and OPTIONAL C2SP extension lines (lines[3:]) that _cosigned_message encodes
    # WHOLE — a lone/unpaired UTF-16 surrogate anywhere in it raised a raw UnicodeEncodeError out of the
    # public verify_cosignature / evaluate_public_transparency / cosign_checkpoint surfaces. verify_checkpoint
    # fixed the ordering for its OWN copy of the text; this shared cosignature-path parser is the neighbour
    # instance the first cut missed. Validate the whole note body is UTF-8-safe here, once, for every consumer.
    try:
        note_text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BundleFormatError("checkpoint note text is not valid UTF-8 (malformed, fail-closed)") from exc
    # DEEP-GATE 4.0.0 re-gate iter4 (D2/D3 CLASS, third neighbour, found by a 4th adversarial pass):
    # _note_text_of guaranteed only origin + UTF-8, NOT that line 1 is a uint64 decimal or line 2 valid
    # base64. cosign_checkpoint_mldsa is the one consumer that does not RE-validate them (verify_checkpoint
    # and verify_cosignature each do their own) — it fed the raw lines into int(size_s).to_bytes(8,"big") and
    # base64.b64decode(validate=True), raising a raw ValueError / binascii.Error / OverflowError (incl. the
    # CVE-2020-10735 integer-string DoS on a 5000-digit size) out of a public witness-signing surface.
    # Validate the note-body fields here, once, for every consumer of the shared parser. The len<=20 test
    # short-circuits before int(size_s), so an over-long digit string never reaches the (bounded) int parse.
    size_s, root_b64 = lines[1], lines[2]
    if len(size_s) > 20 or not (size_s.isascii() and size_s.isdigit()) \
            or (size_s != "0" and size_s.startswith("0")) or int(size_s) >= 2 ** 64:
        raise BundleFormatError("checkpoint tree size must be a uint64 ASCII decimal with no leading zeros")
    try:
        decode_b64_c2sp(root_b64)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("checkpoint root is not valid standard base64") from exc
    return note_text, sig_block


def _note_text_of(signed_note: str, *, require_signature_line: bool = True) -> str:
    """The note body of a signed note: everything before the empty-line separator, newline restored."""
    return _note_body_and_sigs(signed_note, require_signature_line=require_signature_line)[0]


def _cosigned_message(note_text: str, timestamp: int) -> bytes:
    """The Ed25519 cosignature/v1 signed message: header line + time line + whole note body."""
    return (_COSIG_V1_PREFIX + f"time {timestamp}\n" + note_text).encode("utf-8")


def cosign_checkpoint(signed_note: str, witness_signer, witness_name: str, timestamp: int) -> str:
    """Append a witness cosignature line to a signed checkpoint note (Ed25519 cosignature/v1).

    ``witness_signer`` is the witness's Ed25519 private key; ``timestamp`` is the POSIX time of
    observation (explicit — an offline library does not sample wall clocks for signatures).
    Returns the note with the cosignature line appended. Emitting a cosignature here is for
    tests/demos and self-witnessing pipelines; real split-view resistance needs INDEPENDENT
    witnesses, which is a deployment property, not a code property.
    """
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) \
            or not 0 <= timestamp <= _MAX_COSIG_TIMESTAMP:
        raise BundleFormatError("cosignature timestamp must be an integer in [0, 2^63-1]")
    if not _witness_name_wellformed(witness_name):
        raise BundleFormatError("witness name must be a printable-ASCII identity "
                                "without spaces, invisible characters, or '+'")
    # EMIT-Seite: der Notenkoerper darf hier noch ohne Signaturzeile ankommen (Selbstbezeugung), das
    # Ergebnis dieser Funktion ist in jedem Fall kanonisch.
    note_text = _note_text_of(signed_note, require_signature_line=False)
    if not signed_note.endswith("\n"):
        raise BundleFormatError("signed note must end with a newline")
    pubkey = witness_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = witness_signer.sign(_cosigned_message(note_text, timestamp))
    kid = cosign_key_id(witness_name, pubkey)
    blob = kid + timestamp.to_bytes(8, "big") + sig
    return signed_note + f"{EM_DASH} {witness_name} {base64.b64encode(blob).decode('ascii')}\n"


def cosign_key_id_mldsa(witness_name: str, pubkey: bytes) -> bytes:
    """ML-DSA-44 cosignature key ID = SHA-256(name ‖ 0x0A ‖ 0x06 ‖ 1312-byte pubkey)[:4]."""
    if not isinstance(pubkey, bytes) or len(pubkey) != _MLDSA44_PUB_LEN:
        raise BundleFormatError("ML-DSA-44 public key must be 1312 raw bytes")
    # DEEP-GATE re-gate F-8/F-10: the witness name is the third identity slot (with origin and witness
    # name); it is encoded into the keyID, so a surrogate name would raise a raw UnicodeEncodeError
    # out of this public helper, and a zero-width/invisible name would substitute for a real one.
    # Same printable-ASCII rule as origin/witness name — closed at the source that does the encode.
    if not _witness_name_wellformed(witness_name):
        raise BundleFormatError("witness name must be a printable-ASCII identity without spaces or invisible characters")
    h = hashlib.sha256(witness_name.encode("utf-8") + b"\n"
                       + bytes([_COSIG_MLDSA_SIG_TYPE]) + pubkey).digest()
    return h[:4]


def cosign_vkey_mldsa(witness_name: str, pubkey: bytes) -> str:
    """ML-DSA-44 witness verifier key: name + '+' + hex8(keyID) + '+' + base64(0x06 ‖ pubkey)."""
    kid = cosign_key_id_mldsa(witness_name, pubkey)
    kid_hex = f"{int.from_bytes(kid, 'big'):08x}"
    keymat = base64.b64encode(bytes([_COSIG_MLDSA_SIG_TYPE]) + pubkey).decode("ascii")
    return f"{witness_name}+{kid_hex}+{keymat}"


def _mldsa_module():
    """Lazy ML-DSA import — needs `cryptography>=48` on an OpenSSL 3.5+ build (`[pq]` extra).
    Raises UnsupportedError (never ImportError) so a caller who configured an ML-DSA witness on
    a system without the capability gets a clear, fail-closed answer — not a silent False."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: PLC0415
        mldsa.MLDSA44PublicKey  # noqa: B018 — probe the class, backends without PQ lack it
        return mldsa
    except (ImportError, AttributeError) as exc:
        raise UnsupportedError(
            "ML-DSA-44 cosignatures need cryptography>=48 with an OpenSSL 3.5+ backend — "
            "install with: pip install \"proofbundle[pq]\"") from exc


def _opaque8(data: bytes) -> bytes:
    """RFC 8446 §3 opaque<1..2^8-1>: 1-byte length prefix + bytes."""
    if not 1 <= len(data) <= 255:
        raise BundleFormatError("opaque<1..2^8-1> value must be 1..255 bytes")
    return bytes([len(data)]) + data


def _mldsa_cosigned_message(cosigner_name: str, timestamp: int, origin: str,
                            tree_size: int, root: bytes) -> bytes:
    """C2SP cosigned_message struct for an ML-DSA-44 checkpoint cosignature: fixed 12-byte label
    "subtree/v1\\n\\0", cosigner_name, u64 timestamp, log_origin, u64 start (0 for a checkpoint),
    u64 end (= tree size), 32-byte root. Commits to the cosigner NAME (unlike Ed25519) and NOT to
    checkpoint extension lines (per spec)."""
    if len(root) != 32:
        raise BundleFormatError("checkpoint root must be 32 bytes")
    return (_MLDSA_LABEL
            + _opaque8(cosigner_name.encode("utf-8"))
            + timestamp.to_bytes(8, "big")
            + _opaque8(origin.encode("utf-8"))
            + (0).to_bytes(8, "big")            # start = 0: this signs a checkpoint, not a subtree
            + tree_size.to_bytes(8, "big")      # end = tree size
            + root)


def cosign_checkpoint_mldsa(signed_note: str, witness_signer, witness_name: str,
                            timestamp: int) -> str:
    """Append an ML-DSA-44 witness cosignature line (C2SP type 0x06 — the spec's SHOULD for new
    deployments). ``witness_signer`` is a cryptography MLDSA44PrivateKey. Same input rules as
    :func:`cosign_checkpoint`; the signature blob is keyID[4] ‖ u64-BE-timestamp ‖ sig[2420]."""
    _mldsa_module()                              # capability probe, fail-closed
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) \
            or not 0 <= timestamp <= _MAX_COSIG_TIMESTAMP:
        raise BundleFormatError("cosignature timestamp must be an integer in [0, 2^63-1]")
    if not _witness_name_wellformed(witness_name):
        raise BundleFormatError("witness name must be a printable-ASCII identity "
                                "without spaces, invisible characters, or '+'")
    note_text = _note_text_of(signed_note, require_signature_line=False)   # EMIT-Seite, siehe oben
    if not signed_note.endswith("\n"):
        raise BundleFormatError("signed note must end with a newline")
    lines = note_text.split("\n")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    root = decode_b64_c2sp(root_b64)
    pubkey = witness_signer.public_key().public_bytes_raw()
    msg = _mldsa_cosigned_message(witness_name, timestamp, origin, int(size_s), root)
    sig = witness_signer.sign(msg)
    kid = cosign_key_id_mldsa(witness_name, pubkey)
    blob = kid + timestamp.to_bytes(8, "big") + sig
    return signed_note + f"{EM_DASH} {witness_name} {base64.b64encode(blob).decode('ascii')}\n"


def _parse_witness_vkey(vkey_str: str) -> tuple[str, bytes, bytes, int]:
    """Parse a witness vkey, dispatching on the algorithm byte: 0x04 (Ed25519 cosignature/v1,
    32-byte key) or 0x06 (ML-DSA-44, 1312-byte key). Any other byte/length is rejected —
    including 0x01: a LOG key must never be accepted as a witness (domain separation)."""
    # RE-GATE never-raise consistency (mirror _parse_vkey): a non-str witness vkey is a typed
    # BundleFormatError, never a raw AttributeError from `.split` (verify_cosignature routes here).
    if not isinstance(vkey_str, str):
        raise BundleFormatError("vkey must be a string (name+hexKeyID+base64KeyMaterial)")
    parts = vkey_str.split("+", 2)
    if len(parts) != 3:
        raise BundleFormatError("vkey must have 3 '+'-separated parts (name+hexKeyID+base64KeyMaterial)")
    name, kid_hex, keymat_b64 = parts
    # DEEP-GATE re-gate (2026-08-17): a witness NAME must be a printable-ASCII identity with no
    # space (the emit path always required this; enforced on the VERIFY path here too). A name
    # cloaked with whitespace, a zero-width, a variation selector or a Default-Ignorable character
    # would parse and verify, look identical to the origin, yet be byte-different, so the
    # origin-quorum name compare would miss it and the log would vote under a cloaked name.
    if not _witness_name_wellformed(name):
        raise BundleFormatError(
            "witness vkey name must be a printable-ASCII identity without spaces or invisible characters")
    try:
        keymat = decode_b64_c2sp(keymat_b64)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("vkey key material is not valid base64") from exc
    try:
        kid = bytes.fromhex(kid_hex)
    except ValueError as exc:
        raise BundleFormatError("vkey keyID is not valid hex") from exc
    # DERSELBE SELBSTWIDERSPRUCH, ZWEITES MITGLIED. `verify_cosignature` traegt Zeile fuer Zeile
    # dieselbe Form wie `verify_checkpoint` (`kid != kid_v or kid != kid_expected`) und hatte
    # dieselbe Luecke. Im selben Durchgang gefixt statt beim naechsten Mal wiedergefunden — die
    # Neuberechnung haengt hier am Algorithmus, deshalb je Zweig die passende Funktion.
    if len(keymat) == 33 and keymat[0] == _COSIG_V1_SIG_TYPE:
        if kid != cosign_key_id(name, keymat[1:]):
            raise BundleFormatError(
                "witness vkey is self-inconsistent: its declared keyID does not match the ID "
                "recomputed from its own name and key material")
        return name, kid, keymat[1:], _COSIG_V1_SIG_TYPE
    if len(keymat) == _MLDSA44_PUB_LEN + 1 and keymat[0] == _COSIG_MLDSA_SIG_TYPE:
        if kid != cosign_key_id_mldsa(name, keymat[1:]):
            raise BundleFormatError(
                "witness vkey is self-inconsistent: its declared keyID does not match the ID "
                "recomputed from its own name and key material")
        return name, kid, keymat[1:], _COSIG_MLDSA_SIG_TYPE
    raise BundleFormatError(
        "witness vkey must be 0x04+32-byte Ed25519 or 0x06+1312-byte ML-DSA-44 key material")


def verify_cosignature(signed_note: str, witness_vkey: str) -> dict:
    """Verify one witness cosignature on a signed checkpoint note.

    ``witness_vkey`` carries the algorithm in its key material: 0x04 = Ed25519 cosignature/v1,
    0x06 = ML-DSA-44 (v1.3; needs the `[pq]` extra, else UnsupportedError — fail-closed, never a
    silent False). Returns ``{ok, alg, origin, tree_size, root, timestamp}``; ``ok`` is True iff
    a signature line whose name AND key ID match the vkey carries a valid cosignature over this
    checkpoint. Timestamp freshness is caller policy (offline verifier, no trusted clock).
    """
    name, kid_v, pubkey, sig_type = _parse_witness_vkey(witness_vkey)
    note_text, sig_block = _note_body_and_sigs(signed_note)
    lines = note_text.split("\n")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    if len(size_s) > 20 or (size_s != "0" and (size_s.startswith("0") or not (size_s.isascii() and size_s.isdigit()))):
        raise BundleFormatError("checkpoint tree size must be ASCII decimal with no leading zeros")
    try:
        root = decode_b64_c2sp(root_b64)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("checkpoint root is not valid standard base64") from exc

    alg = "ed25519-cosignature/v1" if sig_type == _COSIG_V1_SIG_TYPE else "ml-dsa-44"
    result = {"ok": False, "alg": alg, "origin": origin, "tree_size": int(size_s), "root": root,
              "timestamp": None}
    if sig_type == _COSIG_V1_SIG_TYPE:
        kid_expected = cosign_key_id(name, pubkey)
        blob_len = 4 + 8 + 64
    else:
        kid_expected = cosign_key_id_mldsa(name, pubkey)
        blob_len = 4 + 8 + _MLDSA44_SIG_LEN
        mldsa = _mldsa_module()                  # raise BEFORE scanning lines — fail-closed
        mldsa_pub = mldsa.MLDSA44PublicKey.from_public_bytes(pubkey)

    # KEIN zweiter Schnitt: der Block kommt aus derselben kanonischen Rahmung wie der Notentext oben
    # (L1-600-NOTE-FRAMING-01) — frueher trennte diese Zeile ein zweites Mal, an der ERSTEN Leerzeile.
    # Kappe: siehe _split_signed_note (b) — sie lief dort, vor jeder Dekodierung.
    for line in sig_block.split("\n"):
        if not line.startswith(EM_DASH + " "):
            continue
        rest = line[len(EM_DASH) + 1:]
        try:
            lname, payload_b64 = rest.split(" ", 1)
        except ValueError:
            continue
        if lname != name:
            continue
        try:
            payload = decode_b64_c2sp(payload_b64)
        except (ValueError, TypeError):
            continue
        if len(payload) != blob_len:             # keyID[4] ‖ u64 ts ‖ signature — exact length
            continue
        kid, ts_bytes, sig = payload[:4], payload[4:12], payload[12:]
        if kid != kid_v or kid != kid_expected:
            continue
        timestamp = int.from_bytes(ts_bytes, "big")
        if timestamp > _MAX_COSIG_TIMESTAMP:
            continue
        if sig_type == _COSIG_V1_SIG_TYPE:
            sig_ok = verify_ed25519(pubkey, sig, _cosigned_message(note_text, timestamp))
        else:
            try:
                # build the signed message INSIDE the guard (release-review fix #6): attacker-controlled
                # name/origin/size must not escape as a raw exception from the message construction.
                msg = _mldsa_cosigned_message(name, timestamp, origin, int(size_s), root)
                mldsa_pub.verify(sig, msg)
                sig_ok = True
            except Exception:  # noqa: BLE001 — InvalidSignature and backend errors both mean no
                sig_ok = False
        if sig_ok:
            result["ok"] = True
            result["timestamp"] = timestamp
            break
    return result


def _witness_key_material(vkey: str) -> bytes:
    """The DECODED key material (sig-type byte ‖ pubkey) of a cosignature vkey — the identity to dedup a quorum
    by. NOT the name (a single key can wear many names) and NOT the raw base64 substring (padding can vary while
    the bytes are equal). name+keyID contain no '+'; the base64 keymat is everything after the second '+'.

    DIESELBE FRAGE, DERSELBE DECODER (Gegenlesung 2026-09-05, vor dem Merge von fix/deepgate-600-krypto).
    Das hier ist ein C2SP-vkey-Feld, und `_parse_witness_vkey` liest genau denselben Substring mit
    `decode_b64_c2sp`. Der Sweep dieser Runde stellte neun der zehn Dekodierstellen dieses Moduls auf den
    C2SP-Decoder um und liess diese eine auf dem inzwischen VERSCHAERFTEN `decode_b64` stehen. Damit war die
    Klasse zur Haelfte geschlossen und an dieser Stelle in eine Regression verwandelt: ein gueltig signierter
    ML-DSA-44-Witness traegt 1313 Byte Schluesselmaterial, also genau ein Polsterzeichen und damit eine
    existierende Pad-Bit-Variante — reproduziert, `verify_witnessed_checkpoint` und `witness_quorum` hoben
    darauf eine unabgefangene `binascii.Error`, obwohl `verify_cosignature` dieselbe Zeile mit ok=True
    beurteilte. Zwei Decoder fuer dasselbe Feld sind kein Komfort, sondern eine Divergenz."""
    return decode_b64_c2sp(vkey.split("+", 2)[2])


def _log_key_material_of(log_vkey: str) -> "bytes | None":
    """The raw public-key bytes of a LOG vkey (0x01), for the origin-quorum key-material exclusion
    (DEEP-GATE F-2). Compared against a witness vkey's pubkey bytes WITHOUT the alg-type prefix, so a
    log that reuses its 0x01 signing key as a 0x04 cosignature key is caught despite the differing
    prefix. Defensive: a malformed log vkey yields None (the exclusion then falls back to the name
    test), never a raise — on the real path verify_checkpoint already raised on a malformed log vkey."""
    try:
        _name, _kid, pubkey = _parse_vkey(log_vkey)
        return pubkey
    except (BundleFormatError, ValueError, TypeError):
        # DEEP-GATE re-gate F-7: catch the BASE families, not just BundleFormatError — a lone-surrogate
        # log-vkey name reaches key_id -> name.encode("utf-8") and raises UnicodeEncodeError (a
        # ValueError), which would otherwise escape this "never a raise" helper and, through the new
        # public_transparency call site, become a raw traceback out of a documented fail-closed surface.
        return None


def witness_quorum(signed_note: str, witness_vkeys, threshold: int, *,
                   log_key_material: "bytes | None"):  # DEEP-GATE 4.0.0 D1: REQUIRED keyword (was `= None`)
    """Shared k-of-n witness quorum (release-review fix): counts DISTINCT witness KEY MATERIAL, not names —
    C2SP requires operators to use distinct keys per cosigner, so one physical key under N names is ONE witness.
    Alg-agnostic (Ed25519 0x04 + ML-DSA 0x06). Used by BOTH verify_witnessed_checkpoint AND tlogproof.
    verify_tlog_proof so the hardening can never drift between the two call sites again. Returns
    (witnesses_ok, witnesses_dict); the dict is keyed by name+keyID so a same-name-different-key entry does not
    overwrite. Fail-closed: an unparseable witness vkey raises (verify_cosignature); a non-verifying one is
    False; and a witness whose algorithm this build cannot verify (an ML-DSA vkey without the [pq] extra) also
    counts as non-verifying (False), never a raw UnsupportedError out of the batch (adversarial re-audit round 5).

    ORIGIN-QUORUM RULE — a log never votes in its own quorum. A witness cosignature is EXCLUDED from
    the count (``ok=False``, ``origin_excluded=True``, before any signature math) when EITHER holds:

      * its **key material** equals ``log_key_material`` (the audited log's own signing-key public
        bytes, passed by the caller that knows which log it verifies) — the ROBUST test, algorithm-
        agnostic and independent of the name the line claims; or
      * its **name** equals the note's own origin line — the exact-codepoint name test.

    Why BOTH, and why the name test alone is not enough (Deep-Gate re-gate 2026-08-17, F-1/F-2):
    the Ed25519 cosignature/v1 signed message does NOT commit to the cosigner name (unlike ML-DSA-44,
    which does), so a line CAN be relabelled under any name without the private key — a name-only rule
    is bypassable for Ed25519, and a zero-width character in the origin line defeats the exact name
    compare outright (closed separately by :func:`_origin_wellformed`). Keying the exclusion on the
    LOG's public bytes uses an operand the log/attacker does not get to choose. HONEST LIMITS that
    remain and are documented at the call sites:
      * a log cosigning with a SEPARATE key (not its signing key) under a non-origin alias that a
        relying party wrongly lists as an independent witness — roster provenance, a deployment
        property no local rule can catch;
      * the name compare is EXACT bytes (no normalisation), so BYTE-DIFFERENT FORMS OF THE SAME
        IDENTITY are not caught by the name prong: an ASCII case variant (`LOG.example.com`, DNS is
        case-insensitive), an FQDN trailing dot (`log.example.com.`), or a path-normalisation form
        (`log.example.com//x`). These are the same owner, not a look-alike; the robust defences for
        them are the key-material prong (when the log reuses its signing key) and `expected_origin`
        (the relying-party pin). Exactness is kept deliberately — the opposite (normalising the
        compare) would loosen `expected_origin` acceptance, whose safe direction is the reverse.
    ``log_key_material=None`` (a direct call with no log context) applies only the name test; the
    public surfaces always pass it (and `public_transparency` fails closed if a supplied log_vkey is
    unusable, rather than silently dropping the key-material prong)."""
    keys_ok = set()
    witnesses = {}
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:    # iter5 never-raise (defensive)
        raise BundleFormatError("witness quorum threshold must be a non-negative integer")
    # adversarial re-audit round 4: guard the SHARED SINK, not just one caller — verify_witnessed_checkpoint AND
    # public_transparency.evaluate_public_transparency both funnel witness_vkeys into this loop; a non-iterable
    # (int/bool/object) or a str (per-char iteration) crashed it raw. Fail-closed empty quorum, never a raise.
    if isinstance(witness_vkeys, (str, bytes, bytearray)) or not hasattr(witness_vkeys, "__iter__"):
        return False, {}
    # deep gate 2026-09-05 (L2-BDOS-C2SP-SIGLINES-01, Geschwister): der Roster ist RP-Konfiguration, aber
    # jeder Eintrag treibt einen vollen Scan der Note (verify_cosignature). Dieselbe Budget-Dimension, die
    # trust_pack fuer seine Schluesselmenge traegt (``witnesses``), begrenzt hier die Anzahl der Zeugen,
    # BEVOR der erste Scan laeuft — typisiert, wie ein unparsbarer vkey in derselben Schleife.
    witness_vkeys = list(witness_vkeys)
    if len(witness_vkeys) > DEFAULT_BUDGET.witnesses:
        raise BundleFormatError(
            f"witness roster carries {len(witness_vkeys)} entries (> witnesses={DEFAULT_BUDGET.witnesses}) "
            "— refused before any cosignature is scanned (DoS guard, cap before work)")
    # The origin is parsed LAZILY and defensively: a malformed note must keep its existing contract
    # (an empty roster returns without raising; a non-empty one raises in verify_cosignature below),
    # so a parse failure here downgrades to origin=None instead of introducing a new raise path.
    # origin=None never equals a str vkey name, and on such a note nothing verifies anyway.
    try:
        origin = _note_text_of(signed_note).split("\n", 1)[0]
    except BundleFormatError:
        origin = None
    for wv in witness_vkeys:
        res = None
        if isinstance(wv, str):
            name_hit = origin is not None and wv.split("+", 2)[0] == origin
            if name_hit or log_key_material is not None:
                # Parse to compare key material AND to learn the alg for the report entry. This keeps the
                # documented raise contract: an unparseable vkey raises here (same typed BundleFormatError
                # verify_cosignature would raise one line down), and a 0x01 log key is rejected AS a witness
                # (domain separation) exactly as everywhere else.
                _name, _kid, wv_pk, sig_type = _parse_witness_vkey(wv)
                material_hit = log_key_material is not None and wv_pk == log_key_material
                if name_hit or material_hit:
                    reason = ("its name equals the checked log's own origin" if name_hit
                              else "its key material equals the audited log's own signing key")
                    res = {"ok": False,
                           "alg": "ed25519-cosignature/v1" if sig_type == _COSIG_V1_SIG_TYPE else "ml-dsa-44",
                           "origin": origin, "tree_size": None, "root": None, "timestamp": None,
                           "origin_excluded": True,
                           "detail": f"witness excluded — {reason}; a log never counts toward its own "
                                     "witness quorum (origin-quorum rule, fail-closed)"}
        if res is None:
            try:
                res = verify_cosignature(signed_note, wv)
            except UnsupportedError as exc:
                # adversarial re-audit round 5: a BATCH quorum must not crash because ONE witness in the list is an
                # ML-DSA (0x06) vkey the current build cannot verify (no FIPS-204). verify_cosignature keeps its
                # documented loud raise for a SINGLE explicitly-named witness (a caller config choice, tested), but
                # here — iterating an attacker-influenceable list — an un-verifiable witness counts as non-verifying
                # (fail-closed False), never a raw UnsupportedError out of witness_quorum / verify_witnessed_checkpoint.
                res = {"ok": False, "alg": "ml-dsa-44", "origin": None, "tree_size": None,
                       "root": None, "timestamp": None,
                       "detail": f"witness needs the [pq] extra (FIPS 204) — cannot verify, fail-closed ({exc})"}
        witnesses["+".join(wv.split("+")[:2])] = res
        if res["ok"]:
            keys_ok.add(_witness_key_material(wv))
    return len(keys_ok) >= threshold, witnesses


def verify_witnessed_checkpoint(signed_note: str, log_vkey: str, witness_vkeys, *,
                                threshold: int = 1,
                                expected_origin: "str | None" = None) -> dict:
    """Verify a checkpoint is BOTH log-signed and witnessed by ``threshold`` distinct witnesses.

    The log signature (0x01) is always required — witnesses attest consistency, they do not
    replace the log's own signature. Returns ``{ok, log_ok, witnesses_ok, witnesses, origin,
    expected_origin, tree_size, root}`` where ``witnesses`` maps each vkey's name to its cosignature
    result.
    Fail-closed: an unparseable witness vkey raises; a non-verifying one counts as False; an ML-DSA witness
    this build cannot verify (no [pq] extra) counts as non-verifying, not a raise (adversarial re-audit round 5).
    Origin-quorum rule (see :func:`witness_quorum`): a cosignature made with the LOG's own signing key,
    or one whose name equals the origin line, never counts — this surface passes ``log_key_material`` so
    the robust key-material test applies, not the name test alone.

    ``expected_origin`` (3.8.0) is the origin binding this surface was missing. A checkpoint carries
    the identity of the log that issued it, and a signature proves that SOME log signed — not WHICH
    one. Without the binding a relying party that pins a trusted checkpoint accepts a validly signed
    checkpoint from a DIFFERENT log as an authenticated source for the root and the tree size.
    Measured 2026-08-16 by triggering it: the same root and the same key under two different origins
    produced byte-identical verdicts, and no parameter could separate them. The sibling surface
    ``tlogproof.verify_tlog_proof`` closed this earlier in the same release; this is its neighbour.

    Default ``None`` = origin unconstrained, so every existing call keeps its verdict. The comparison
    is EXACT (codepoint equality, no normalisation, no case folding) — near-miss corpora in
    ``tests/_beinahe_treffer.py`` hold that, because a comparison tested only against a wholly foreign
    value cannot tell an exact one from a loosened one. ``""`` is a REQUEST that always fails, not the
    absence of one: ``is None`` is deliberate where ``not expected_origin`` would silently collapse
    "asked and empty" into "not asked".
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise BundleFormatError("witness threshold must be a positive integer")
    # adversarial re-audit: ``witness_vkeys`` (the relying party's witness roster, a trust-config arg like
    # ``threshold``) was unguarded — a non-iterable (int) crashed ``for wv in witness_vkeys`` in witness_quorum
    # with a raw TypeError out of this public verify_* surface, and a str would silently iterate per-character.
    # Guard it like its sibling config arg: a malformed roster is a typed BundleFormatError, never a raw crash.
    if isinstance(witness_vkeys, (str, bytes, bytearray)) or not hasattr(witness_vkeys, "__iter__"):
        raise BundleFormatError("witness_vkeys must be an iterable of witness vkey strings")
    log_res = verify_checkpoint(signed_note, log_vkey)
    # Exakt wie in tlogproof.verify_tlog_proof, absichtlich Zeichen fuer Zeichen dieselbe Form: die
    # zwei Flaechen tragen DIESELBE Eigenschaft, und zwei verschiedene Schreibweisen davon waeren
    # die naechste Drift. `is None` und nicht `not expected_origin` — ein leerer String ist eine
    # GESTELLTE Frage, die immer fehlschlaegt, keine abwesende.
    log_ok = bool(log_res["ok"]) and (expected_origin is None
                                      or log_res["origin"] == expected_origin)
    # DEEP-GATE F-2: the log's own signing-key public bytes are the operand the log does not choose —
    # pass them so a cosignature made with the log key never counts as a witness, whatever name it wears.
    witnesses_ok, witnesses = witness_quorum(signed_note, witness_vkeys, threshold,
                                             log_key_material=_log_key_material_of(log_vkey))
    return {"ok": log_ok and witnesses_ok, "log_ok": log_ok,
            "witnesses_ok": witnesses_ok, "witnesses": witnesses,
            "origin": log_res["origin"], "expected_origin": expected_origin,
            # Befund PB-EXPECTED-ORIGIN-ASCII-INKONSISTENZ-01: sagt dem Aufrufer, ob SEIN Pin die
            # Regel erfuellt, die die Log-Seite laengst erzwingt. None = kein Pin. Aendert das
            # Verdikt NICHT (der exakte Vergleich bleibt), nimmt ihm nur das Stille.
            "expected_origin_wellformed": expected_origin_wellformed(expected_origin),
            # NACHBAR IM SELBEN DURCHGANG: `verify_checkpoint` liefert `signer_present`, und der
            # tlogproof-Pfad reicht es durch — diese Schwesterflaeche baut ihr Ergebnis selbst und
            # liess es fallen. Ein Aufrufer saehe hier `log_ok=False`, ohne zu wissen, ob der
            # uebergebene Schluessel diese Note ueberhaupt signiert hat. Beim Lesen des eigenen
            # Diffs gefunden, nicht von einem Test — die Klasse "ein Verbraucher gefixt, den
            # Nachbarn in derselben Funktion vergessen" ist genau die, die hier wiederkehrt.
            "signer_present": bool(log_res.get("signer_present")),
            "tree_size": log_res["tree_size"], "root": log_res["root"]}
