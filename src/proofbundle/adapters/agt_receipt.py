"""Offline verification of Agent Governance Toolkit (AGT) MCP governance receipts.

WHAT THIS IS. AGT (github.com/microsoft/agent-governance-toolkit, MIT) emits signed receipts for
MCP tool calls: an Ed25519 signature over a canonical JSON payload, optionally a second signature
from a separate authorizer, and a `parent_receipt_hash` chain link. This module verifies such a
receipt WITHOUT AGT installed and without network access, from the receipt JSON alone.

NO AGT CODE IS COPIED. The format was read from the published tree at commit
``a917ad4ac04aff11a5e9e21f6a26b91642b750cd`` (2026-09-24) and re-derived here; the wire format is
the interface, and an interface can be re-implemented. AGT is MIT, Copyright (c) Microsoft
Corporation. The conformance vectors in ``tests/`` are produced by our own generator, not taken
from AGT.

THE ONE THING A READER MUST KNOW, and it is the reason this module exists in this shape.
AGT's ``canonical_payload`` carries the docstring "RFC 8785 JCS canonical JSON" and is implemented
as ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)``. Those two are NOT the
same serializer, and they diverge on the field every receipt carries. Measured 2026-09-23 on a
receipt produced by AGT's own signer:

    timestamp 1758600000.0   json.dumps -> 1758600000.0     RFC 8785 -> 1758600000
    payload_hash in receipt  f35ba4cf191963b9…  == sha256(json.dumps form)
    sha256(RFC 8785 form)    f7d770b4e6c1fff4…  != the above
    Ed25519 signature        valid against the json.dumps form, REJECTED against RFC 8785

So a verifier that implements the DOCUMENTED format rejects valid receipts. This module therefore
verifies against the form AGT actually signs, and says so, rather than quietly accepting whichever
of the two happens to match. Silently trying both would be the very re-interpretation this house
forbids: it would turn "the receipt is valid" into "one of two readings of the receipt is valid",
and a reader could not tell which.

WHAT HAPPENS THE DAY AGT SWITCHES TO REAL JCS, because an independent review asked and the answer
is not "try both". A receipt carries no canonical-form version, so the form cannot be read off the
document; it has to be a decision the verifier states. The migration is therefore the same one
this house already made for its own wire: name BOTH forms, default to absence meaning the older
one, and never let an unlabelled receipt silently resolve to the newer. Until AGT emits a form
marker there is nothing to switch on, and a second attempt would accept a receipt under a form its
issuer never claimed. The trigger is already wired rather than left to memory:
``test_die_gesignte_form_ist_sortkeys_json_nicht_rfc8785`` goes RED the day the two forms agree,
and that red is the signal to add the second named form.

EXIT CODES follow the house contract used by ``proofbundle verify`` (WP-B2): 0 when the receipt
verifies, 1 on a cryptographic or structural failure, 2 on malformed input, 3 when the crypto is
sound but a supplied relying-party requirement (a trusted authorizer key, an expiry horizon) is not
met. The split matters: a receipt can be perfectly signed and still not satisfy the policy a
relying party brings to it, and those two are different answers.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from typing import Any, Dict, Iterable, Optional, Sequence, cast

from .._membership import is_member
from ..errors import VerificationResult
from ..signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness, verify_ed25519_pinned

__all__ = [
    "AGT_AUTHORIZATION_TYPE",
    "AGT_CANONICAL_FORM",
    "AGTReceiptError",
    "canonical_payload",
    "canonical_authorization_payload",
    "payload_hash",
    "verify_agt_receipt",
    "verify_agt_receipt_chain",
]

#: The type URI AGT binds into the external-authorization payload. Read from the tree, not invented.
AGT_AUTHORIZATION_TYPE = "https://agent-governance.org/receipts/external-authorization/v1"

#: The serializer AGT actually signs with. NAMED, because AGT's own docstring names a different one
#: and the difference is load-bearing (see the module docstring). This identifier is ours; it exists
#: so a verdict can say WHICH canonical form it verified against.
AGT_CANONICAL_FORM = "sortkeys-json-utf8"

#: The payload fields, in the order AGT builds them. Optional ones are present only when set.
_PFLICHTFELDER = ("agent_did", "args_hash", "cedar_decision", "cedar_policy_id",
                  "receipt_id", "timestamp", "tool_name")
_WAHLFELDER = ("parent_receipt_hash", "session_id")

#: The decisions AGT's implementation uses. NOTE for anyone reading the proposal instead of the
#: code: the proposal document says "permit/deny", the implementation says "allow"/"deny". A
#: verifier that accepts "permit" would accept a receipt AGT never emits.
_ENTSCHEIDUNGEN = frozenset({"allow", "deny"})

#: EVERY field that speaks of an external authorization. The detector below reads ALL of them.
#:
#: Codex, review of this branch: the first version looked at only authorizer_id,
#: authorization_signature and authorizer_public_key. All of these sit OUTSIDE the signed payload,
#: so setting exactly those three to null left `assurance_level="externally_authorized"`,
#: `authorization_expires_at` and `authorization_nonce` standing, kept the signature and the
#: payload hash valid, and turned a receipt this verifier had REJECTED (exit 3) into one it
#: ACCEPTED (ok=True, exit 0). Removable evidence must never improve a verdict.
#:
#: THE CLASS is a partial-shape detector over a field set an attacker can choose from: whichever
#: subset the detector does not read is the subset that can be stripped. The fix is not three more
#: names, it is reading the WHOLE set and demanding completeness once any member appears.
_AUTORISIERUNGSFELDER = ("authorizer_id", "authorization_signature", "authorizer_public_key",
                         "authorization_expires_at", "authorization_nonce")

#: The assurance_level value that CLAIMS an external authorization. A receipt claiming it owes a
#: complete and valid one, whatever else was stripped.
_EXTERN_BEHAUPTET = "externally_authorized"


class AGTReceiptError(ValueError):
    """Malformed input: the bytes are not a readable AGT receipt. Exit code 2, never 1.

    Kept apart from a verification failure on purpose. "I cannot read this" and "I read this and
    the signature is wrong" are different answers, and folding them together loses the one a caller
    needs to act on.
    """


#: The getter of a type's `__name__`, taken from `type` itself so that no metaclass can replace it.
_TYPNAME = type.__dict__["__name__"]


def _typname(wert: Any) -> str:
    """The name of `wert`'s type, read so that no method of the caller's runs (lens run 3 at 481a1f26,
    F1). `type(x).__name__` asks the metaclass, and a metaclass can define `__name__` as a property
    that raises. The list reader's own `except` handler made exactly that read, so an exception whose
    type name raised turned a refusal into an escape from both verifiers (`Boom` raised while
    `NamedBoom` was being handled). The getter of `type` returns the name the class was created with,
    and `str.__str__` makes a plain copy of it, so a `str` subclass stored as a name runs nothing
    later either. Every message of this module that names the type of a caller's value reads it here.
    """
    return str.__str__(_TYPNAME.__get__(type(wert)))


def _als_text(wert: Any) -> "str | None":
    """A value as plain text, or None when it is no text, read so that no method of the caller's runs
    (lens run 4 at d461b41a, the sweep of K4-2). By `type()`, not by `isinstance`: `isinstance` asks the
    value for its `__class__` when the type alone does not answer, and a caller's object can define
    that as a property that raises. A `str` subclass keeps its own `__eq__`, `__hash__`, `__bool__` and
    `__getitem__`, and a comparison, a set lookup, a truth test or a slice would run them; the
    signature field of a receipt as such a subclass escaped from both verifiers through `not signatur`.
    `str.__str__` makes a plain copy, so what is compared later is the text and nothing else."""
    return str.__str__(wert) if issubclass(type(wert), str) else None


def _als_zeitpunkt(wert: Any) -> "int | float | None":
    """An instant as its plain number, or None when it is no number (lens run 4 at d461b41a, K4-2).
    `numpy.float64` is a float subclass, so it passed the `isinstance` test, and its own `__le__`
    converts an int to a float: a receipt file whose `authorization_expires_at` is a JSON integer of
    310 digits, judged at `now=np.float64(time.time())`, raised OverflowError out of both verifiers.
    An int or float subclass whose `__le__` raises escaped the same way. `float.__float__` and
    `int.__index__` hand back the plain value without running a method of the caller's type (a bool
    reads as 0 or 1, as it compared before), and Python compares a plain int with a plain float
    exactly, by value, without converting either and without overflow."""
    typ = type(wert)
    if issubclass(typ, float):
        return float.__float__(wert)
    if issubclass(typ, int):
        return int.__index__(wert)
    return None


def _text(receipt: Dict[str, Any], feld: str) -> str:
    wert = receipt.get(feld)
    text = _als_text(wert)
    if text is None:
        raise AGTReceiptError(f"{feld} is {_typname(wert)}, expected a string")
    return text


def _kanonisch(daten: Dict[str, Any], was: str) -> bytes:
    """`sort_keys` JSON with compact separators and raw UTF-8, the one form AGT signs both payloads in.

    WHAT IT CANNOT ENCODE IS UNREADABLE INPUT, raised as `AGTReceiptError` and never as the
    serialiser's own exception (lens run 3 at 481a1f26, the neighbour sweep; the same on main
    20e91c8e). A signed field holding bytes, a set or an object raised TypeError, a value nested 5000
    levels deep RecursionError, a list that contains itself ValueError, and a lone surrogate raised
    UnicodeEncodeError at the UTF-8 step. The last one is plain JSON: `json.loads` turns the escaped
    code point U+D800 in a receipt file into exactly such a string. Each of them left both verifiers
    as a raw exception, while the verify surfaces promise a verdict for any receipt.
    """
    try:
        return json.dumps(daten, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    except Exception as fehler:  # noqa: BLE001 — whatever the serialiser refuses has no signed form
        raise AGTReceiptError(f"the {was} cannot be written as {AGT_CANONICAL_FORM}: encoding it "
                              f"raised {_typname(fehler)}") from fehler


def canonical_payload(receipt: Dict[str, Any]) -> bytes:
    """The bytes AGT signs. `sort_keys` JSON with compact separators and raw UTF-8.

    NOT RFC 8785, although AGT's docstring says so; see the module docstring for the measurement.
    The signature fields are excluded because they cover this payload.
    """
    if not issubclass(type(receipt), dict):    # by the type, so no `__class__` of the caller's runs
        raise AGTReceiptError(f"receipt is {_typname(receipt)}, expected an object")
    fehlend = [f for f in _PFLICHTFELDER if f not in receipt]
    if fehlend:
        raise AGTReceiptError(f"receipt lacks required field(s): {', '.join(sorted(fehlend))}")
    daten: Dict[str, Any] = {f: receipt[f] for f in _PFLICHTFELDER}
    for f in _WAHLFELDER:
        if receipt.get(f) is not None:
            daten[f] = receipt[f]
    return _kanonisch(daten, "receipt payload")


def payload_hash(receipt: Dict[str, Any]) -> str:
    """SHA-256 over :func:`canonical_payload`. This is what `parent_receipt_hash` points at."""
    return hashlib.sha256(canonical_payload(receipt)).hexdigest()


def canonical_authorization_payload(receipt: Dict[str, Any]) -> bytes:
    """The bytes an external authorizer signs. Binds the receipt payload hash and the nonce."""
    fehlend = [f for f in ("authorizer_id", "authorization_expires_at", "authorization_nonce")
               if receipt.get(f) is None]
    if fehlend:
        raise AGTReceiptError(
            f"external authorization metadata is incomplete: {', '.join(sorted(fehlend))}")
    return _autorisierungsnutzlast(receipt, payload_hash(receipt))


def _autorisierungsnutzlast(receipt: Dict[str, Any], nutzlast_hash: str) -> bytes:
    """The authorization payload over a receipt payload hash the caller already has. The verifiers
    pass the hash of the ONE serialisation of the receipt payload they made (lens run 5 at c8c61651,
    F2), so the receipt payload is never serialised a second time, one frame deeper, to bind it here."""
    daten = {
        "authorizer_id": receipt["authorizer_id"],
        "authorization_expires_at": receipt["authorization_expires_at"],
        "authorization_nonce": receipt["authorization_nonce"],
        "receipt_payload_hash": nutzlast_hash,
        "type": AGT_AUTHORIZATION_TYPE,
    }
    return _kanonisch(daten, "authorization payload")


def _ed25519_gueltig(pubkey_hex: str, signatur_hex: str, nutzlast: bytes) -> bool:
    """One Ed25519 check. Returns False on any failure; never raises for bad input.

    A verifier that raises on a malformed key cannot finish a verdict over a list of receipts, and
    an unfinished verdict reads like a clean one.

    THROUGH THE HOUSE PRIMITIVE, not a second path to `cryptography` (deep gate Z195), and for EVERY
    key through the trust-anchor rule (SPEC section 4b). Until 6.2.0 the receipt's own signer key got
    the plain SPEC section 4a check, "as a bundle's key does", and only the authorizer key the rule.
    The comparison did not hold: a bundle's key is trusted through a relying party's pin, which
    carries the rule, while nothing pins an AGT signer key. Measured on 126ed1dc: signer key
    0100..00 (the identity point) with the signature R = identity, S = 0 gave `signature` True and
    `ok` True, a receipt nobody signed. And AGT's authorization binds `receipt_payload_hash`, not
    `signer_public_key`, so the same swap under an authorized receipt kept the authorization valid.
    SPEC section 4b names every key that is not the bundle's own; this one is not.
    """
    try:
        schluessel = bytes.fromhex(pubkey_hex)
        signatur = bytes.fromhex(signatur_hex)
    except (ValueError, TypeError):
        return False
    return verify_ed25519_pinned(schluessel, signatur, nutzlast)


#: One item of a buffer format: the optional byte order and repeat count of the struct syntax (PEP
#: 3118), then one item code, where a complex number (`Zf`, `Zd`, `Zg`) is one code. A format this does
#: not match holds a compound item: a record `T{...}`, a pointer `&...`, a function pointer `X{}`.
_POSTEN = re.compile(r"[@=<>!]?(\d*)(Z[fdg]|\S)")

#: The item codes whose bytes ARE the value they hold: bytes, pad bytes, booleans, integers, floats,
#: complex numbers. Text code units (`u`, `w`), references and pointers (`O`, `P`, `Z`, `z`) hold a
#: value their bytes do not spell, and so does any code outside this set.
_WERTBYTES = frozenset(("x", "c", "b", "B", "?", "h", "H", "i", "I", "l", "L", "q", "Q", "n", "N",
                        "e", "f", "d", "g", "s", "p", "Zf", "Zd", "Zg"))

#: What an entry of each kind holds, for the refusal that names it (see `_vertrauensliste`).
_NICHT_LESBAR = {"zeichen": "text", "texte": "text", "verweise": "references",
                 "verbund": "records, pointers or items of an unknown kind"}

#: The ctypes kinds whose buffer format cannot be trusted to name them, decided by the TYPE of the
#: value (lens run 5 at c8c61651, F1). ctypes is imported only to recognise its objects; no function of
#: it is called. `issubclass(type(x), ...)` reads the type's own method resolution order and runs no
#: code of the caller's. `_CTYPES_ZEIGER` is a pointer, which a walk would follow item after item.
_CTYPES_VERBUND: "tuple[type, ...]" = ()
_CTYPES_ZEIGER: "tuple[type, ...]" = ()
try:
    import ctypes as _ctypes
    from _ctypes import CFuncPtr as _CFuncPtr
except ImportError:  # pragma: no cover — an interpreter built without ctypes holds no ctypes object
    pass
else:
    _CTYPES_VERBUND = (_ctypes.Structure, _ctypes.Union, _ctypes._Pointer, _CFuncPtr)
    _CTYPES_ZEIGER = (_ctypes._Pointer,)


def _groesse_stimmt(form: str, itemsize: int) -> bool:
    """Whether a one-item buffer format describes an item of the size the buffer reports. False only
    when the struct module sizes the format and gets another number: ctypes exports a record it cannot
    describe (a Union, a Structure with `_pack_`, an array of either) with the bare format `B` and the
    record's own item size, 256 bytes for a Union holding 64 wide characters. A code the struct module
    does not size (`u`, `w`, `O`, `Z`, `z`, `g`, a byte-order prefix on `P`) is left to its code."""
    try:
        return struct.calcsize(form) == itemsize
    except struct.error:
        return True


def _puffer(wert: Any) -> "tuple[str, bytes | None, int | None, str | None]":
    """What a value is by the buffer it exports, its bytes where they are the value it holds, the
    number of dimensions of the buffer, and its format (None for both when there is no buffer).

    `kein`      it exports no buffer (a TypeError from `memoryview`).
    `ein`       ONE byte string: bytes in one dimension (the formats `B`, `b`, `c` of bytes,
                bytearray, memoryview, array('B'), mmap, ctypes byte arrays, a numpy uint8 vector) or
                fixed-width byte strings (`s`).
    `binaer`    numbers, or bytes in more than one dimension: its bytes still spell a key.
    `zeichen`   text of single characters (`u`, `w`, numpy's `1w`: array('u'), ctypes wide
                characters, a numpy array of one-character strings): ONE text value, held as code units.
    `texte`     text items of more than one character (numpy's `<n>w`): a collection of texts, or at
                no dimension one text.
    `verweise`  references or pointers (`O`, `P`, `Z`, `z`): a collection of the values they point
                at, or at no dimension one such value.
    `verbund`   a compound or unknown item (a record `T{...}`, a pointer `&...`, a function pointer
                `X{}`, a code outside `_WERTBYTES`). Its bytes are judged as they are, as they were
                before, but they are not known to be the value it holds.

    A RECORD IS A RECORD WHATEVER FORMAT IT EXPORTS (lens run 5 at c8c61651, F1). ctypes exports a
    record it cannot describe with the bare format `B` at no dimension: a `ctypes.Union`, a `Structure`
    with `_pack_` (a big-endian one too), and an array of either, which even exports `B` in one
    dimension. Read by the format alone, the identity point as hex text in a `c_wchar * 65` field of
    such a record was "numbers" (the array: "one byte string"), its 256 bytes named no key, and
    `[real key, record]` gave exit 0 for every receipt and for the chain. So the kind is decided by the
    TYPE as well as by the format: a ctypes Structure, Union, pointer or function pointer is `verbund`
    whatever it exports, and so is any buffer whose one-item format the struct module sizes to another
    number than the item size the buffer reports, which catches an array of such records at any depth
    without reading its element type (`_type_` is a class attribute, and a caller can define the class).
    numpy did not hide a record this way where it was measured (numpy 2.2.6, eighteen dtypes with
    fields, overlay dtypes included): each exports `T{...}`, and an unstructured void exports pad
    bytes, which are its bytes.
    A `P` buffer (`c_void_p`, `memoryview.cast('P')`) holds addresses as numbers, and its bytes are
    handed on (F4 of the same run): walked, the identity point as four pointer-sized numbers named no
    key, so a WHOLE such value is judged by its bytes first, as a buffer of numbers is.

    `ein`, `binaer` and `verbund` hand on their bytes, and the list reader judges a WHOLE value of the
    last kind by them, as it did before: a record of numbers can hold a key's bytes. For `zeichen`,
    `texte`, `verweise` and `verbund` the bytes are code points or addresses, or not known to be the
    value held, and that value could be read only by running code of the caller's (numpy's `item()`,
    ctypes' `.value`) or by following a pointer; `ctypes.c_char_p(12345).value` reads the address
    12345 and ends the process with SIGSEGV. The list reader therefore refuses such an ENTRY (lens run
    4 at d461b41a, K4-1) and walks such a WHOLE value as the collection it is.

    BY THE FORMAT OF THE BUFFER, NOT BY ITS PRESENCE (lens run 3 at 481a1f26, F2). The version before
    read every buffer as one byte string, so `np.array([key])` and the same array with `dtype=object`
    were refused as "one ndarray value, a single key" (exit 2) where main 20e91c8e found the key and
    authorised it (exit 0): numpy exports a text array with the format `64w` and an object array with
    `O`, and neither is a byte string. Before that (lens run 2 at 8cf49247, K2-1-C) only `bytes` and
    `bytearray` were judged and the identity point as a `memoryview` or an `array('B', …)` passed;
    every buffer that holds bytes or numbers is still judged by its bytes. The bytes are taken with
    `memoryview(...).tobytes()`, which runs no method of the caller's. Any exception other than
    TypeError (a released view, a dtype numpy cannot export) is left to the reader of the list, which
    refuses it.
    """
    if type(wert) is bytes:
        return "ein", wert, 1, "B"
    try:
        sicht = memoryview(wert)
    except TypeError:
        return "kein", None, None, None
    with sicht:
        form = str.__str__(sicht.format)
        posten = _POSTEN.fullmatch(form)
        if (posten is None or issubclass(type(wert), _CTYPES_VERBUND)
                or not _groesse_stimmt(form, sicht.itemsize)):
            return "verbund", sicht.tobytes(), sicht.ndim, form
        anzahl, code = posten.group(1), posten.group(2)
        if code in ("O", "P", "Z", "z"):
            return "verweise", (sicht.tobytes() if code == "P" else None), sicht.ndim, form
        if code in ("u", "w"):
            return ("texte" if int(anzahl or "1") > 1 else "zeichen"), None, sicht.ndim, form
        if not is_member(code, _WERTBYTES):
            return "verbund", sicht.tobytes(), sicht.ndim, form
        if code == "s" or (code in ("B", "b", "c") and anzahl in ("", "1") and sicht.ndim == 1):
            return "ein", sicht.tobytes(), sicht.ndim, form
        return "binaer", sicht.tobytes(), sicht.ndim, form


def _schluesselbytes(eintrag) -> "bytes | None":
    """The 32 key bytes an entry names, or None when it names no key. Hex text is decoded; bytes, the
    form the list reader hands on for every entry whose buffer holds bytes or numbers (see `_puffer`),
    are taken as they are (lens run 1 at 053c7800, K2-01: the identity point given as raw bytes was
    never judged). Anything else, a number, a nested list, None, names no key. An entry whose buffer
    holds text, references or records never reaches this point: the list reader refuses it."""
    if isinstance(eintrag, str):
        try:
            roh = bytes.fromhex(eintrag)
        except ValueError:
            return None
    elif isinstance(eintrag, bytes):
        roh = eintrag
    else:
        return None
    return roh if len(roh) == 32 else None


def _schwaeche(eintrag) -> "str | None":
    """Why an entry cannot stand as a trusted Ed25519 key (`low-order`, `non-canonical`), or None.
    An entry that names no 32-byte key is None here: it names no key, verifies nothing and matches
    nothing, and the signature check or the list comparison says so on its own."""
    roh = _schluesselbytes(eintrag)
    if roh is None:
        return None
    grund = ed25519_trust_anchor_weakness(roh)
    return grund if grund in ("low-order", "non-canonical") else None


def _abgewiesen(feld: str, grund: str) -> str:
    """The one sentence every refusal of a key in this module carries, with the shared reason text."""
    return (f"{feld} is a {grund} Ed25519 key, refused as a trusted key before any signature "
            f"arithmetic: {TRUST_ANCHOR_REFUSAL[grund]}")


def _kurz(eintrag) -> str:
    """A short spelling of an entry for a message: hex for raw bytes, the text itself otherwise."""
    if isinstance(eintrag, (bytes, bytearray)):
        return bytes(eintrag).hex()[:16]
    return str(eintrag)[:16]


def _vertrauensliste(schluessel) -> "tuple[tuple | None, str | None]":
    """The relying party's `trusted_authorizer_keys`, materialised ONCE, and its refusal or None.

    AT THE LIST, when a key is AUTHORISED, not only when a receipt happens to name it. A weak key on
    that list authorised nothing before either, because the authorization signature goes through the
    rule; but the list stood as accepted, and the defect showed only on the one receipt that used it.
    The trust policy refuses a weak pin when it is LOADED (`policy._validate_pinned_ed25519_pubkey`),
    and this list is the same kind of object.

    THE SAME ITERABLE AS THE COMPARISON, and that is the fix for lens run 1 at 053c7800 (K2-01). The
    first version walked only list, tuple, set and frozenset, while the comparison below walked any
    iterable: a `deque`, a `UserList`, a `dict` or a `dict.keys()` view carrying the identity point
    next to the real authorizer key gave exit 0 with the weak key never judged. Both now read ONE
    tuple built here, so a one-shot iterator is not consumed by the refusal before the comparison
    sees it, and the two can never again disagree about what the list holds.

    An entry that names no key (text that is no 32-byte hex, bytes of another length, a nested list,
    a number, None) is left standing and matches nothing, as `"x"` has since 3c9c98c3: a list whose
    job is to name keys cannot authorise anything through a non-key. Something that cannot be walked
    at all is no list of keys, and that is a refusal of the list (exit 2), never a TypeError.

    AN ENTRY THAT HOLDS TEXT OR A REFERENCE IN A BUFFER REFUSES THE LIST (lens run 4 at d461b41a,
    K4-1). The identity point as hex text inside `np.array(W)`, `np.array(W, dtype=object)`,
    `ctypes.c_wchar_p(W)`, `ctypes.create_unicode_buffer(W)`, `array('u', W)` or `np.array(list(W))`,
    next to the real key, gave exit 0 for every receipt and for the chain, with the detail "1 of which
    name no key", while the plain str W gave exit 2; so did the raw key as `ctypes.c_char_p(key)`. The
    text was never read as text: a buffer of references or of multi-character text at no dimension was
    taken for a collection and named no key, and a buffer of single characters was handed on as its
    UCS-4 code units, 256 or 260 bytes that name no key either. Such an entry is not read as the text
    it holds, it is refused, naming its position, its type and its buffer format: reading it would run
    code of the caller's or follow a pointer (`c_char_p(12345).value` reads the address 12345 and ends
    the process), and decoding the code units by hand would be a second reading with conventions of
    its own (numpy drops trailing NUL characters from an item, ctypes stops at the first NUL,
    `array('u')` keeps them). The same holds for a record entry (`T{...}`, a numpy structured array or
    a ctypes Structure), whose fields may be text or references and whose format names them in a
    syntax a ctypes field name can make ambiguous. Every entry that exports a buffer is therefore
    either judged by its bytes, where they are the value it holds, or refuses the list; none passes as
    naming no key. A plain container (a nested list, a dict) exports no buffer and still names no key.
    Which entry is a record is decided by its type as well as its format (see `_puffer`, lens run 5 at
    c8c61651, F1: a ctypes Union or packed Structure exports the bare format `B`). The bytes of a
    refused entry are STILL judged where it hands them on: a weak key's 32 bytes inside such a record
    add the key refusal to the record refusal, as they refused the list when the record passed for
    numbers, so no reason a key was refused for before is lost.

    A POINTER IS NOT WALKED (lens run 5, found next to F3). A whole ctypes pointer (`POINTER(c_char)`
    and the like) has no length, and walking it reads one item after another from the address it holds
    and never stops: past the memory it points into, until the process faults. It is refused as a
    pointer before anything is read. A whole ctypes ARRAY of `c_char_p` or `c_wchar_p` is walked, and
    ctypes reads the text each pointer names: that is by design, the caller's own pointers are
    followed, and the real key given as `(c_wchar_p * n)(...)` is authorised that way, as main
    authorises it. Its length bounds the walk; a pointer in it that names no valid address is the
    caller's fault and is not detected.

    ONE KEY IS NOT A LIST (lens run 2 at 8cf49247, K2-1-C). A str, or one byte string (bytes,
    bytearray, a memoryview or array of single bytes, see `_puffer`), is ONE spelling; walked, text
    falls apart into characters and bytes into numbers, none of which names a key. The identity point
    as a bare string gave exit 0 for a receipt without an authorization, and the real key as a bare
    string gave exit 3 for the one that has it. Such a value is refused as a single key, exit 2.

    BUT A BUFFER IS NOT ALWAYS A BYTE STRING (lens run 3 at 481a1f26, F2). Taking every value that
    exports a buffer as one key refused `np.array([key])` and the same array of objects, both of which
    main 20e91c8e read as a list and authorised (exit 0); numpy exports them with the formats `64w`
    and `O`. A buffer of references or of multi-character text is a collection and is walked entry by
    entry, as main walked it. A buffer of numbers or of records (array('I'), a numpy uint32 or float
    array) is walked too, as main walked it, and its bytes are judged FIRST,
    as the one key they spell: walked, the identity point given as `array('I', …)` is eight numbers
    that name no key, and a weak key the version before refused must not pass because it is read a
    second way. `np.array([])`, which is a float array, is an empty list again (exit 3 for an
    authorized receipt, as on main). Fixed-width byte strings (`s`) stay one value: numpy cuts the
    trailing zero bytes off an item it hands out, so the identity point read as an item is one byte
    long and would name no key. A buffer of more than one dimension is refused whole, as 481a1f26
    refused it, and main raised TypeError on it: its entries are arrays, which name no key, so walked,
    a key inside it would never be judged. Measured on a first form of this fix that walked it,
    `np.array([[weak, real]])` gave exit 0 for a receipt without an authorization and exit 3 for the
    authorized one, and so did an object array holding the weak key as a buffer, which numpy expands
    into a row of numbers.

    ANY EXCEPTION WHILE READING THE CALLER'S LIST IS A REFUSAL OF THE LIST, NEVER AN ESCAPE (lens run 2
    at 8cf49247, K2-1-B). The first version caught only TypeError from `tuple(...)`: a generator that
    yields the real key and then raises ValueError, a closed file, a generator raising KeyError, all
    escaped from a verifier that promises never to raise, and did so for a receipt that carries no
    authorization at all. The list is the caller's object, so every call into it happens HERE — the
    buffer probe, `iter`, each `next`, each entry's type and value — and what leaves this function is
    plain `str`, plain `bytes` or None (an entry that names no key). Nothing further down calls into
    a caller's object again: a `str` subclass whose `__eq__` raised escaped from the comparison on
    8cf49247, and an entry whose `__class__` raised escaped from the type test. A list that fails
    part-way is refused whole, never read in part, and the reason names the exception type, read
    through `_typname` so that naming it runs no code of the caller's (lens run 3, F1). Only
    `Exception` is caught. Every BaseException that is not an Exception propagates: KeyboardInterrupt,
    SystemExit, GeneratorExit, asyncio.CancelledError and a caller's own BaseException subclass stop
    or cancel the caller's work, they are not a list that failed to read.
    """
    gelesen: "list[str | bytes | None]" = []
    unlesbar: "dict[int, tuple[str, bytes | None]]" = {}
    try:
        if issubclass(type(schluessel), _CTYPES_ZEIGER):
            return None, (f"trusted_authorizer_keys is a {_typname(schluessel)} pointer, not a "
                          f"collection of keys — a pointer has no length, and walking it would read "
                          f"item after item past the memory it points into")
        art, roh, dimensionen, _ = (("ein", None, 1, None) if isinstance(schluessel, str)
                                    else _puffer(schluessel))
        if art in ("ein", "zeichen"):
            return None, (f"trusted_authorizer_keys is one {_typname(schluessel)} value, a single "
                          f"key, not a collection of keys — pass the key inside a list")
        if dimensionen is not None and dimensionen > 1:
            return None, (f"trusted_authorizer_keys is a {_typname(schluessel)} of {dimensionen} "
                          f"dimensions, not a flat collection of keys — its entries are arrays, "
                          f"which name no key, so a key inside them would never be judged")
        if art in ("binaer", "verbund", "verweise") and roh is not None:
            grund = _schwaeche(roh)
            if grund is not None:
                return None, _abgewiesen(
                    f"trusted_authorizer_keys ({_kurz(roh)}…), whose bytes spell one key,", grund)
        try:
            gang = iter(schluessel)
        except TypeError:
            return None, (f"trusted_authorizer_keys is {_typname(schluessel)}, not a collection of "
                          f"keys — it cannot be read as a relying party's list")
        for eintrag in gang:
            if isinstance(eintrag, str):
                gelesen.append(str.__str__(eintrag))       # plain text, no subclass method runs later
                continue
            art, roh, _, form = _puffer(eintrag)
            if is_member(art, _NICHT_LESBAR):
                unlesbar[len(gelesen)] = (
                    f"trusted_authorizer_keys[{len(gelesen)}] is a {_typname(eintrag)} whose buffer "
                    f"holds {_NICHT_LESBAR[art]} (format {str(form)[:40]!r}), not the bytes of a key: "
                    f"the value it holds cannot be read without running code of the caller's or "
                    f"following a pointer, so a key it carries would never be judged — pass each "
                    f"key as a str", roh)
                gelesen.append(None)
            else:
                gelesen.append(roh if art in ("ein", "binaer") else None)
    except Exception as fehler:  # noqa: BLE001 — never-raise is the promise of this surface
        return None, (f"trusted_authorizer_keys could not be read to the end: after {len(gelesen)} "
                      f"entr{'y' if len(gelesen) == 1 else 'ies'} reading it raised "
                      f"{_typname(fehler)} — a list that cannot be read whole is refused, never "
                      f"read in part")
    eintraege = tuple(gelesen)
    gruende = []
    for i, eintrag in enumerate(eintraege):
        if i in unlesbar:
            ablehnung, verbundbytes = unlesbar[i]
            gruende.append(ablehnung)
            grund = _schwaeche(verbundbytes)
            if grund is not None and verbundbytes is not None:
                gruende.append(_abgewiesen(f"trusted_authorizer_keys[{i}] ({_kurz(verbundbytes)}…), "
                                           f"whose bytes spell one key,", grund))
            continue
        grund = _schwaeche(eintrag)
        if grund is not None:
            gruende.append(_abgewiesen(f"trusted_authorizer_keys[{i}] ({_kurz(eintrag)}…)", grund))
    return eintraege, ("; ".join(gruende) or None)


def _derselbe_schluessel(a_hex: str, b_hex: str) -> bool:
    """Whether two hex spellings name the same key BYTES. Hex is case-insensitive, so `ab…` and `AB…`
    are one key; comparing the strings counted them as two, and `authorizer-key-distinct` passed for a
    receipt whose authorizer was its own signer spelled in capitals (deep gate Z195, the identity-by-
    encoding half of L1-Z195-02). Text that is not hex compares as text."""
    try:
        return bytes.fromhex(a_hex) == bytes.fromhex(b_hex)
    except (ValueError, TypeError):
        return a_hex == b_hex


def _feldkopie(receipt: Any) -> "Dict[str, Any] | None":
    """The receipt's fields as a plain dict with plain `str` names, or None when it is no object.

    READ THROUGH `dict`'S OWN STORAGE, NOT THROUGH THE RECEIPT'S METHODS (lens run 5 at c8c61651, F7).
    A field lookup compares the name with every stored key of the same hash, and a key object whose
    hash equals `hash("agent_did")` and whose `__eq__` raises made both verifiers raise RuntimeError
    from a plain dict (on main 20e91c8e too); a dict subclass whose `get` raises escaped the same way (a
    named limit until now). `dict.items` walks the stored pairs without calling a method of the
    receipt or of a key: a key that is no text names no field and is left out, a `str` subclass key is
    copied to the plain text it holds, and where both spell one name the plain `str` key wins, as a
    lookup by that name found it. Every later read of a field reads this copy."""
    if not issubclass(type(receipt), dict):
        return None
    kopie: "Dict[str, Any]" = {}
    abgeleitet: "list[tuple[str, Any]]" = []
    for name, wert in dict.items(receipt):
        if type(name) is str:
            kopie[name] = wert
        elif issubclass(type(name), str):
            abgeleitet.append((str.__str__(name), wert))
    for name, wert in abgeleitet:
        kopie.setdefault(name, wert)
    return kopie


def _gelesen(receipt: Any) -> "tuple[Dict[str, Any] | None, bytes | None, str]":
    """A receipt read once: its fields (see `_feldkopie`), the canonical payload bytes, and the reason
    when those bytes cannot be made (bytes None). Never raises an `Exception`.

    THE ONE SERIALISATION OF A RECEIPT'S PAYLOAD IN THE VERIFIERS (lens run 5 at c8c61651, F2). The
    single verifier serialised the payload up to three times: guarded for the signature, again through
    `payload_hash` for the self-consistency check, outside every `try`, and a third time inside the
    authorization payload; the chain a fourth time for the link. The second call ran one frame deeper
    than the first, so a plain JSON receipt whose `tool_name` is a list nested just deep enough passed
    the guarded call and raised RecursionError in the unguarded one, `AGTReceiptError` out of both
    verifiers, at every stack depth of the caller (the window moves with it). A value whose own
    `items()` raised on its second call escaped the same way. Now each receipt is serialised once,
    here, and every hash of its payload, the self-consistency check, the authorization binding and the
    chain link, is taken from these bytes. What cannot be serialised is one `readable` verdict."""
    felder: "Dict[str, Any] | None" = None
    try:
        felder = _feldkopie(receipt)
        return felder, canonical_payload(receipt if felder is None else felder), ""
    except AGTReceiptError as fehler:
        return felder, None, str(fehler)
    except Exception as fehler:  # noqa: BLE001 — never-raise is the promise of the verify surfaces
        return felder, None, f"the receipt cannot be read: reading it raised {_typname(fehler)}"


def verify_agt_receipt(
    receipt: Dict[str, Any],
    *,
    trusted_authorizer_keys: Optional[Iterable[Any]] = None,
    require_external_authorization: bool = False,
    now: Optional[float] = None,
) -> VerificationResult:
    """Verify one AGT receipt offline.

    `trusted_authorizer_keys` is the relying party's list; an external authorization is only
    ACCEPTED when its key is on that list AND differs from the receipt signer key. Without the
    list, an externally authorized receipt still verifies cryptographically, and the verdict says
    the authorization was not evaluated. That is not a pass for the authorization.

    WHAT THE AUTHORIZATION CHECKS DO NOT SAY, named because an independent review found the earlier
    check name claiming it. Two distinct keys are two keys, not two organizations: an admin key and
    a service key of the same operator satisfy every check here. AGT's own proposal says the same —
    "different keys alone cannot prove organizational independence" — and the check is therefore
    called `authorizer-key-distinct`, which is what it measures, rather than something that sounds
    like independence. Whether an authorizer is operationally independent is a deployment and
    key-custody property, and no signature can carry it.

    A CALLER WHO READS ONLY `.ok` LOSES THE REASON. `ok` is False for an unreadable receipt, a
    broken signature and an unmet relying-party requirement alike; those are three different
    answers and they are told apart by the check NAMES and by :func:`exit_code`, not by `ok`. The
    same review raised this, and the honest answer is that `ok` is a summary and a summary is not a
    diagnosis.

    `now` is the instant expiry is judged at. Default is the receipt's own `timestamp`, because
    this is the OFFLINE reading: the proposal states that offline verification evaluates expiration
    at the signed receipt timestamp while a live adapter evaluates it at execution time. Passing a
    wall-clock value here gives the live reading; the verdict names which one was used.

    EVERY KEY GOES THROUGH THE TRUST-ANCHOR RULE (SPEC section 4b): the signer key, the authorizer
    key and each key on `trusted_authorizer_keys`. A low-order or non-canonical key is refused before
    any signature arithmetic, and the check says which key and why. A weak key on the relying
    party's list refuses the list before the receipt is read (`trusted-authorizer-keys`, exit 2, the
    malformed-input code, as a weak pin in a trust policy is). The list may be any iterable; it is
    read once, and a list that cannot be read whole, or a single key passed instead of a list, is
    refused the same way (see `_vertrauensliste`).

    WHAT AN ENTRY CAN DO. Every entry that names a 32-byte key is JUDGED by the rule: hex text, and
    anything whose buffer holds bytes or numbers (bytes, bytearray, memoryview, array, a numpy array
    of numbers). An entry whose buffer holds text, references or records (a numpy text, object or
    structured array, `array('u')`, a ctypes wide-character buffer, `c_char_p`, `c_wchar_p`, a ctypes
    Structure, Union or pointer, whatever format it exports) refuses the list, exit 2, because the
    value it holds cannot be read without running the caller's code; a weak key's bytes inside such a
    record are named as well. A nested list exports no buffer and names no key. Only hex TEXT can
    AUTHORISE: the authorizer key is compared with the entries as text, so a key given as raw bytes is
    refused when it is weak and otherwise matches nothing, not even the authorizer's own key (exit 3,
    a named limit in the CHANGELOG). Raw bytes are judged, and never trusted.
    """
    gelesen = None if trusted_authorizer_keys is None else _vertrauensliste(trusted_authorizer_keys)
    return _pruefe_mit_gelesener_liste(
        receipt, gelesen, None, require_external_authorization=require_external_authorization, now=now)


def _pruefe_mit_gelesener_liste(
    receipt: Dict[str, Any],
    gelesen: "tuple[tuple | None, str | None] | None",
    vorgelesen: "tuple[Dict[str, Any] | None, bytes | None, str] | None",
    *,
    require_external_authorization: bool = False,
    now: Optional[float] = None,
) -> VerificationResult:
    """The body of :func:`verify_agt_receipt`, over a list `_vertrauensliste` has ALREADY read (None
    when the caller supplied none). Kept apart so the single call and the chain read the caller's list
    through the same helper exactly once, and every receipt of a chain gets the same reading.
    `vorgelesen` is the receipt as `_gelesen` read it, where the chain has read it already for its
    links; None reads it here, after the list, so a refused list is still refused before the receipt
    is read."""
    ergebnis = VerificationResult()
    vertraut: "tuple | None" = None
    if gelesen is not None:
        vertraut, abgewiesen = gelesen
        if abgewiesen is not None:
            ergebnis.add("trusted-authorizer-keys", False, abgewiesen)
            return ergebnis
    # NEVER-RAISE AT THE VERIFY SURFACE, and the house gate was right to insist. The first version
    # let `canonical_payload` raise through here so that unreadable input could be told apart from
    # a failed check. The type-confusion gate refused it: a verifier that crashes on a broken
    # document does not judge, and a caller who forgets one `except` reads a crash as nothing at
    # all. Both properties are kept instead of traded — the unreadability becomes a NAMED check, and
    # `exit_code` maps that one name to 2 while every other failure maps to 1.
    # A DECISION THAT IS NOT TEXT IS UNREADABLE INPUT TOO, inside the same guard. `_text` raises
    # `AGTReceiptError` for it, and until lens run 3 at 481a1f26 it stood outside this `try`: a
    # `cedar_decision` of 5, None, a list or a dict escaped from both verifiers (on main 20e91c8e too).
    # The payload is serialised ONCE, by `_gelesen`, which never raises; every field below is read
    # from its plain copy, and every hash of the payload is taken from these bytes (lens run 5, F2).
    felder, nutzlast, unlesbar = vorgelesen if vorgelesen is not None else _gelesen(receipt)
    if felder is None or nutzlast is None:
        ergebnis.add("readable", False, unlesbar)
        return ergebnis
    try:
        entscheidung = _text(felder, "cedar_decision")
    except AGTReceiptError as fehler:
        ergebnis.add("readable", False, str(fehler))
        return ergebnis
    eigener_hash = hashlib.sha256(nutzlast).hexdigest()

    # THROUGH `is_member`, NOT THROUGH `in`. `cedar_decision` comes out of the receipt, so it is
    # attacker-controlled, and `_ENTSCHEIDUNGEN` hashes. An unhashable value would raise TypeError
    # at a verify surface that promises never to raise; the house guard measures exactly this shape
    # and it caught this line on 2026-09-23. `is_member` answers False for a value that cannot be
    # an element, which is the correct answer and lets the rejection below fire as written.
    bekannt = is_member(entscheidung, _ENTSCHEIDUNGEN)
    ergebnis.add(
        "decision-vocabulary", bekannt,
        f"cedar_decision={entscheidung!r}" if bekannt else
        f"cedar_decision={entscheidung!r} is not one of {sorted(_ENTSCHEIDUNGEN)} — note that the "
        f"AGT proposal document says permit/deny while the implementation says allow/deny")

    # EVERY VALUE THAT IS COMPARED OR TESTED BELOW IS READ AS ITS PLAIN VALUE FIRST (lens run 4 at
    # d461b41a, K4-2 and its sweep): text through `_als_text`, an instant through `_als_zeitpunkt`. A
    # method of the caller's value, a `__class__` property asked by `isinstance`, a `str` subclass's
    # `__bool__` in a truth test or `__eq__` in a comparison, an int subclass's `__eq__` against the
    # assurance level, a float subclass's `__le__`, escaped from both verifiers before.
    signatur = _als_text(felder.get("signature"))
    pubkey = _als_text(felder.get("signer_public_key"))
    if not signatur or not pubkey:
        ergebnis.add("signature", False, "receipt carries no signature or no signer public key")
        return ergebnis
    schwaeche = _schwaeche(pubkey)
    if schwaeche is not None:
        ergebnis.add("signature", False, _abgewiesen("signer_public_key", schwaeche))
    else:
        ergebnis.add(
            "signature", _ed25519_gueltig(pubkey, signatur, nutzlast),
            f"Ed25519 over the {AGT_CANONICAL_FORM} payload, {len(nutzlast)} bytes")

    # The receipt may carry its own payload_hash. If it does and it disagrees, say so: a receipt
    # whose self-reported hash does not match its own bytes is telling two stories.
    selbst = _als_text(felder.get("payload_hash"))
    if selbst:
        ergebnis.add("payload-hash-self-consistent", selbst == eigener_hash,
                     f"receipt states {selbst[:16]}…")

    behauptet_extern = _als_text(felder.get("assurance_level")) == _EXTERN_BEHAUPTET
    hat_autorisierung = behauptet_extern or any(
        felder.get(f) is not None for f in _AUTORISIERUNGSFELDER)
    if require_external_authorization and not hat_autorisierung:
        ergebnis.add("external-authorization", False,
                     "required by the caller, but the receipt carries none")
        return ergebnis
    if not hat_autorisierung:
        return ergebnis

    # COMPLETENESS IS DEMANDED, not assumed. Once anything speaks of an authorization — a field, or
    # an assurance_level claiming one — every part must be there. Otherwise the subset an attacker
    # leaves standing decides the verdict.
    fehlend = [f for f in _AUTORISIERUNGSFELDER if felder.get(f) is None]
    if fehlend:
        grund = ("assurance_level claims an external authorization" if behauptet_extern
                 else "some authorization fields are present")
        ergebnis.add("external-authorization-complete", False,
                     f"{grund}, but these are missing: {', '.join(sorted(fehlend))} — a receipt "
                     f"whose authorization can be stripped field by field must not verify")
        return ergebnis
    a_sig = _als_text(felder.get("authorization_signature"))
    a_key = _als_text(felder.get("authorizer_public_key"))
    if not a_sig or not a_key:
        ergebnis.add("external-authorization-complete", False,
                     "authorization signature or authorizer key is present but not a string")
        return ergebnis
    # RECORDED IN BOTH DIRECTIONS, and the reason is a test of mine that was wrong. It asserted
    # this check appears on a correctly authorized receipt; it did not, because the check was only
    # added on the failing branch. A property that is only named when it is violated is invisible
    # when it holds, and a reader of a green verdict cannot tell whether it was examined.
    derselbe = _derselbe_schluessel(a_key, pubkey)
    ergebnis.add("authorizer-key-distinct", not derselbe,
                 "authorizer key differs from the receipt signer key" if not derselbe else
                 "authorizer key equals the receipt signer key — a second signature from the same "
                 "key adds no second party at all")
    if derselbe:
        return ergebnis

    # The authorization fields sit outside the receipt payload and go through the same serialiser, so
    # one of them it cannot encode is unreadable input as well, never an escape (lens run 3 at 481a1f26).
    # The receipt payload hash it binds is the one of the single serialisation above (lens run 5, F2).
    try:
        a_nutzlast = _autorisierungsnutzlast(felder, eigener_hash)
    except AGTReceiptError as fehler:
        ergebnis.add("readable", False, str(fehler))
        return ergebnis
    except Exception as fehler:  # noqa: BLE001 — never-raise is the promise of the verify surfaces
        ergebnis.add("readable", False, f"the authorization payload cannot be read: reading it raised "
                                        f"{_typname(fehler)}")
        return ergebnis
    a_schwaeche = _schwaeche(a_key)
    if a_schwaeche is not None:
        ergebnis.add("external-authorization-signature", False,
                     _abgewiesen("authorizer_public_key", a_schwaeche))
    else:
        ergebnis.add("external-authorization-signature",
                     _ed25519_gueltig(a_key, a_sig, a_nutzlast),
                     f"Ed25519 over the authorization payload, type {AGT_AUTHORIZATION_TYPE}")

    frist = _als_zeitpunkt(felder.get("authorization_expires_at"))
    zeitpunkt = _als_zeitpunkt(felder.get("timestamp") if now is None else now)
    quelle = "the receipt timestamp (offline reading)" if now is None else "the supplied instant"
    if frist is not None and zeitpunkt is not None:
        # COMPARED EXACTLY, NOT THROUGH `float()`. Python compares an int with a float by value and
        # never overflows, while `float(10**400)` raised OverflowError out of both verifiers, for a
        # `timestamp` or an `authorization_expires_at` of that size and for such a `now` (lens run 3 at
        # 481a1f26; on main 20e91c8e too). Where `float()` converts both values without rounding, the
        # answer is the same; above 2**53 it rounded, and the exact comparison is the correct one.
        # BOTH ARE PLAIN NUMBERS HERE, and that is the second half (lens run 4 at d461b41a, K4-2): a
        # `numpy.float64` passed the `isinstance` test, and its own `__le__` converted the int with
        # `float()` again, OverflowError for a 310-digit JSON integer as the expiry.
        ergebnis.add("external-authorization-unexpired", zeitpunkt <= frist,
                     f"judged at {quelle}")
    else:
        ergebnis.add("external-authorization-unexpired", False,
                     "expiry or reference instant is not a number")

    if vertraut is None:
        # NOT a pass. The check is recorded as not evaluated so the verdict cannot be read as
        # "the authorizer was trusted".
        ergebnis.add("external-authorization-trusted", False,
                     "no trusted authorizer keys supplied — the authorization was NOT evaluated "
                     "against a relying party's list, and this is not an acceptance")
    else:
        # THE MATERIALISED TUPLE, compared as TEXT, and never through `set(...)`: an unhashable
        # entry raised TypeError there (lens run 1 at 053c7800, a nested list; on main too). Text
        # equality is what `a_key in set(...)` computed for every text entry, so the verdict for a
        # list of hex strings is unchanged, hex case included (a named limit in the CHANGELOG). The
        # tuple holds only plain `str`, plain `bytes` and None, so this comparison runs no method of
        # the caller's (lens run 2 at 8cf49247: a `str` subclass whose `__eq__` raised escaped here).
        treffer = any(isinstance(e, str) and e == a_key for e in vertraut)
        ohne = sum(1 for e in vertraut if _schluesselbytes(e) is None)
        ergebnis.add("external-authorization-trusted", treffer,
                     f"authorizer key {a_key[:16]}… against {len(vertraut)} trusted key(s)"
                     + (f", {ohne} of which name no key" if ohne else ""))
    return ergebnis


def verify_agt_receipt_chain(
    receipts: Sequence[Dict[str, Any]],
    **kwargs: Any,
) -> VerificationResult:
    """Verify a receipt chain: every receipt, plus every `parent_receipt_hash` link.

    An empty sequence is a failure, not a clean chain. A run that examined nothing looks exactly
    like a run that found nothing, and this house has paid for that confusion before.
    """
    ergebnis = VerificationResult()
    # THE SHAPE IS CHECKED BEFORE THE EMPTINESS, and the order is the whole point. `not receipts`
    # is True for `[]` and for `0` and `False` alike, so a truthy non-sequence such as `True` or
    # `-1` slipped past it and died on `enumerate` with a bare TypeError. Measured by the house
    # type-confusion gate on this very module: "TypeError on payload True: 'bool' object is not
    # iterable". A verifier that raises instead of judging is the defect this gate exists to catch.
    if not issubclass(type(receipts), (list, tuple)):  # by the type: no `__class__` of the caller's runs
        ergebnis.add("chain-readable", False,
                     f"receipts is {_typname(receipts)}, expected a list or tuple")
        return ergebnis
    # THE SEQUENCE IS READ ONCE, THROUGH ITS OWN STORAGE (lens run 5 at c8c61651, with F7): a list or
    # tuple subclass whose `__len__`, `__iter__` or `__getitem__` raises escaped from the chain (a named
    # limit until now), and one whose methods answer differently each time gave the receipt checks and
    # the link checks two different chains. `list.__iter__` and `tuple.__iter__` walk the stored items.
    if issubclass(type(receipts), list):
        glieder = tuple(list.__iter__(cast(list, receipts)))
    else:
        glieder = tuple(tuple.__iter__(cast(tuple, receipts)))
    if not glieder:
        ergebnis.add("chain-non-empty", False, "no receipts supplied — nothing was examined")
        return ergebnis

    # ONE READING OF THE RELYING PARTY'S LIST FOR THE WHOLE CHAIN, through the same helper a single
    # call uses, and every receipt gets that one reading: a one-shot iterator read by the first
    # receipt would be empty for the one that carries the authorization. When the reading is a
    # refusal (a weak key, a single key instead of a list, a list that cannot be walked or fails
    # part-way), every receipt reports that same refusal, and the caller's object is NOT read again.
    # Lens run 2 at 8cf49247 (K2-1-A): the chain caught the TypeError of a list that yields a weak key,
    # raises once and then yields the real one, and passed the HALF-READ iterator on; the first
    # receipt then found only the real key, exit 0, where the single call gave exit 2.
    liste = kwargs.pop("trusted_authorizer_keys", None)
    gelesen = None if liste is None else _vertrauensliste(liste)

    # EACH RECEIPT IS READ AND SERIALISED ONCE, and the link check takes the digest of the previous
    # receipt from the same bytes its own signature was checked over (lens run 5 at c8c61651, F2): the
    # link used to serialise the previous receipt a second time, and a receipt that reads differently
    # the second time could be checked as one receipt and linked as another.
    vorgelesen = [_gelesen(r) for r in glieder]
    for i, r in enumerate(glieder):
        teil = _pruefe_mit_gelesener_liste(r, gelesen, vorgelesen[i], **kwargs)
        for c in teil.checks:
            ergebnis.add(f"[{i}] {c.name}", c.ok, c.detail)

    for i in range(1, len(glieder)):
        # Same never-raise rule as above: an unreadable link is a named finding, not a crash that
        # abandons the remaining receipts. A chain verdict that stops halfway is not a verdict.
        _vorher_felder, vorher, unlesbar = vorgelesen[i - 1]
        if vorher is None:
            ergebnis.add(f"[{i}] chain-link", False,
                         f"the previous receipt is not readable, so no link can be checked: {unlesbar}")
            continue
        erwartet = hashlib.sha256(vorher).hexdigest()
        # A CHAIN ELEMENT THAT IS NOT AN OBJECT names no parent, and that is a verdict, never an
        # AttributeError from `.get` (lens run 3 at 481a1f26: `[r1, 5]`, `[r1, None]`, `[r1, "x"]` and
        # `[r1, [1]]` raised, and so does main 20e91c8e). Its own `[i] readable` check already refused
        # it (exit 2); this check says which position and which type broke the link.
        felder = vorgelesen[i][0]
        if felder is None:
            ergebnis.add(f"[{i}] chain-link", False,
                         f"receipts[{i}] is {_typname(glieder[i])}, not an object, so it names no "
                         f"parent_receipt_hash and its link to receipts[{i - 1}] cannot be checked")
            continue
        # THE PLAIN TEXT, compared with the plain digest (lens run 4 at d461b41a, the sweep of K4-2):
        # `gefunden == erwartet` ran the `__eq__` of whatever the field held, and an int subclass
        # whose `__eq__` raises escaped from the chain; one whose `__eq__` answers True passed this
        # check for any parent. A value that is no text names no parent, and the link fails.
        gefunden = felder.get("parent_receipt_hash")
        ergebnis.add(f"[{i}] chain-link", _als_text(gefunden) == erwartet,
                     f"parent_receipt_hash={_kurzwert(gefunden)}… expected {erwartet[:16]}…")
    return ergebnis


def _kurzwert(wert: Any) -> str:
    """A short spelling of a field value for a message: text, None and a bool as they read, anything
    else by its type name. `str()` of a nested value recurses (RecursionError for a parent hash nested 5000
    deep, lens run 3 at 481a1f26) and runs the methods of whatever the value holds."""
    text = _als_text(wert)
    if text is not None:
        return text[:16]
    if wert is None:
        return "None"
    if wert is True or wert is False:
        return "True" if wert is True else "False"
    return f"<{_typname(wert)}>"


#: Strips ONLY a leading chain index such as "[0] ". An independent review read the earlier
#: `split("] ", 1)[-1]` as taking the LAST segment and called it broken for a name containing
#: "] ". Measured, that reading was wrong: with maxsplit=1 the call already returns everything
#: after the FIRST "] ", which is the name. The residual fragility is real though — an
#: UNPREFIXED name containing "] " would still be cut — so the prefix is now matched as a prefix
#: instead of being inferred from a separator that may also occur inside the name.
_KETTENPRAEFIX = re.compile(r"^\[\d+\] ")


def _blanker_name(name: str) -> str:
    return _KETTENPRAEFIX.sub("", name, count=1)


def exit_code(ergebnis: VerificationResult) -> int:
    """Map a verdict onto the house exit-code contract.

    0 verified · 1 cryptographic or structural failure · 2 malformed input · 3 crypto sound but a
    relying-party requirement unmet. Malformed input is the named check `readable` or
    `chain-readable` (unreadable input is not a failed verification, it is a failed reading) or
    `trusted-authorizer-keys` (the relying party's own list names a key the trust-anchor rule
    refuses, the way a weak pin makes a trust policy malformed).
    """
    if ergebnis.ok:
        return 0
    # UNREADABLE FIRST, because it dominates: if the bytes could not be read, nothing else was
    # examined, and reporting a signature failure over input that was never parsed would name the
    # wrong cause. A refused list is the same kind of answer: nothing was judged against it.
    for c in ergebnis.checks:
        if not c.ok and _blanker_name(c.name) in ("readable", "chain-readable",
                                                  "trusted-authorizer-keys"):
            return 2
    # STRUCTURAL FAILURES ARE EXIT 1, and Codex was right to separate them. Exit 3 states "crypto
    # sound but a relying-party requirement unmet", so a receipt that is structurally broken on its
    # own — incomplete authorization, an authorizer equal to the signer — must not borrow that
    # code: no relying party asked for anything. Only `external-authorization-trusted`, which is
    # judged against a list the CALLER supplies, is a relying-party matter.
    krypto = {"signature", "external-authorization-signature", "payload-hash-self-consistent",
              "decision-vocabulary", "chain-link", "chain-non-empty",
              "external-authorization", "external-authorization-complete",
              "authorizer-key-distinct", "external-authorization-unexpired"}
    for c in ergebnis.checks:
        if c.ok:
            continue
        name = _blanker_name(c.name)
        if name in krypto:
            return 1
    return 3
