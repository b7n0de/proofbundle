"""COSE_Sign1 Hash Envelopes that cite a Signed Evaluation Receipt, in both directions (EXPERIMENTAL).

Needs the ``[scitt]`` extra (cbor2): every statement this module writes is read back with it before it is
returned, and the check requires it as the module does. The reader that judges a statement is this
module's own: it reads the bytes as RFC 8949 defines them, keeps the kind of every data item and does not
interpret tags (whether a tag's content is valid for that tag, RFC 8949 section 5.3.2, is not checked; the
data items inside a tag are checked like any other), so a verdict does not depend on which tags a decoder
knows. The receipt format itself
(``signed_eval_receipt``) needs no CBOR, and nothing here runs unless a caller imports this module.
Nothing here opens a network connection.

THE RULE, one statement for one receipt digest (the section "COSE and SCITT" of
draft-gruszka-evaluation-receipt-mappings, as proposed for its next revision):

* payload: the receipt digest, SHA-256 over B, 32 bytes: a COSE Hash Envelope (RFC 9995);
* protected header, exactly these five labels:

  - 1 (alg): written as -19 (Ed25519, RFC 9864) only. Read as -19, or as -8 (EdDSA, RFC 9053) under an
    Ed25519 statement key, the only kind of statement key the check counts; with such a key both values
    select the same signature algorithm, and a statement that changes alg is other protected-header bytes
    and needs a new signature (owner choice B of 2026-10-04: -8 is deprecated by RFC 9864, and statements
    made before that choice may carry it);
  - 4 (kid): the COSE Key Thumbprint (RFC 9679, SHA-256) of the statement key, 32 bytes;
  - 15 (CWT Claims, RFC 9597): exactly 1 (``iss``), an absolute URI (RFC 3986 section 4.3), and 2
    (``sub``), the ``model_id_commit`` of B;
  - 258 (payload hash algorithm): -16 (SHA-256);
  - 259 (preimage content type): the receipt type, as text;

* unprotected header: the empty map;
* tag 18, and the whole COSE_Sign1, the protected header inside it included, in the core deterministic
  encoding of RFC 8949 section 4.2.1, so one statement has one byte string.

FORWARD, ``receipt_to_statement``: the receipt must pass every step of the draft's Section 6 under the key
the caller fixed, or no statement is made.

BACKWARD, ``check_statement``: a statement is accepted only if it reads under the rule, a pair of an
issuer URI and a statement key that the relying party configured has exactly its ``iss`` and a key whose
thumbprint is its kid, its signature meets the four rules of Section 4.4 of the receipts draft under that
key (the Sig_structure in place of PAE), and its payload is the digest of the presented receipt, which
itself passes the draft's Section 6 under the receipt key the relying party fixed; ``sub`` must be that
receipt's model commitment. The received ``iss`` selects among the pairs; it never makes a key trusted for
an issuer. Every other outcome is a status, never a pass, and the check never raises for what it is given
to read. A check that stops at a resource limit (more than 400 nested arrays, maps and tags, or the
receipt's own limit in step 5) returns ``resource_limit``: no status, and not accepted.

WHAT IS LOST. The statement carries the digest and the model commitment of B, nothing else of the receipt:
not the score, threshold, comparator, verdict, suite or timestamp, not the dataset commitment, not the
receipt's signature or key hint. A Receiver that relies on the assertion needs the
receipt itself; the statement only names it. The statement's signature is not the receipt's signature,
even when one key makes both.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from typing import Any, NamedTuple, Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .signature import ed25519_trust_anchor_weakness, plain_bytes, plain_text
from .signed_eval_receipt import (RECEIPT_TYPE, _decode_point, _Fail, _has_order_l, _profile,
                                  verify_signed_eval_receipt)

__all__ = ["ALG_ED25519", "ALG_EDDSA", "ALGS", "WRITE_ALG", "ACCEPTED", "STATUSES", "CoseUnavailable",
           "ReceiptCoseError", "StatementCheck", "cose_key_thumbprint", "receipt_to_statement", "check_statement"]

#: COSE algorithm values. The forward direction writes WRITE_ALG only; the check reads every value of ALGS,
#: and -8 only under an Ed25519 statement key (``_statement_keys`` counts no other kind of key).
ALG_ED25519 = -19   # RFC 9864, fully specified
ALG_EDDSA = -8      # RFC 9053, polymorphic EdDSA, deprecated by RFC 9864: read, never written
ALGS = (ALG_ED25519, ALG_EDDSA)
WRITE_ALG = ALG_ED25519

ACCEPTED = "accepted"
#: The outcome of a check that stopped at a resource limit, in any step: no status of Section 5.2.2 of the
#: mappings draft, and not accepted.
RESOURCE_LIMIT = "resource_limit"
#: Every outcome ``check_statement`` returns; only ``accepted`` is a pass. ``no_lib`` (the [scitt] extra is
#: missing) and ``resource_limit`` are no statuses of Section 5.2.2; the others are.
STATUSES = (ACCEPTED, "no_lib", RESOURCE_LIMIT, "malformed", "outside_profile", "untrusted_key",
            "signature_invalid", "receipt_not_verified", "digest_mismatch", "subject_mismatch")

_ALG, _KID, _CWT, _HASH_ALG, _PREIMAGE_CTY = 1, 4, 15, 258, 259
_ISS, _SUB = 1, 2
_SHA256 = -16
_TAG_SIGN1 = 18
_LABELS = frozenset({_ALG, _KID, _CWT, _HASH_ALG, _PREIMAGE_CTY})
_CLAIMS = frozenset({_ISS, _SUB})
#: An absolute-URI of RFC 3986 section 4.3 (scheme ":" hier-part ["?" query], no fragment), its ABNF
#: written out rule by rule; anything this grammar does not produce is no iss.
_PCT = r"%[0-9A-Fa-f]{2}"
_PCHAR = r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|" + _PCT + ")"
_DEC_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_IPV4 = rf"{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}"
_H16 = r"[0-9A-Fa-f]{1,4}"
_LS32 = rf"(?:{_H16}:{_H16}|{_IPV4})"
_IPV6 = "|".join([
    rf"(?:{_H16}:){{6}}{_LS32}",
    rf"::(?:{_H16}:){{5}}{_LS32}",
    rf"(?:{_H16})?::(?:{_H16}:){{4}}{_LS32}",
    rf"(?:(?:{_H16}:){{0,1}}{_H16})?::(?:{_H16}:){{3}}{_LS32}",
    rf"(?:(?:{_H16}:){{0,2}}{_H16})?::(?:{_H16}:){{2}}{_LS32}",
    rf"(?:(?:{_H16}:){{0,3}}{_H16})?::{_H16}:{_LS32}",
    rf"(?:(?:{_H16}:){{0,4}}{_H16})?::{_LS32}",
    rf"(?:(?:{_H16}:){{0,5}}{_H16})?::{_H16}",
    rf"(?:(?:{_H16}:){{0,6}}{_H16})?::",
])
_IP_LITERAL = rf"\[(?:{_IPV6}|v[0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+)\]"
_REG_NAME = r"(?:[A-Za-z0-9\-._~!$&'()*+,;=]|" + _PCT + ")*"
_AUTHORITY = (r"(?:(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|" + _PCT + rf")*@)?(?:{_IP_LITERAL}|{_IPV4}|{_REG_NAME})"
              r"(?::[0-9]*)?")
_HIER_PART = (rf"(?://{_AUTHORITY}(?:/{_PCHAR}*)*|/(?:{_PCHAR}+(?:/{_PCHAR}*)*)?|{_PCHAR}+(?:/{_PCHAR}*)*|)")
_URI_RE = re.compile(rf"\A[A-Za-z][A-Za-z0-9+.-]*:{_HIER_PART}(?:\?(?:{_PCHAR}|[/?])*)?\Z")
_COMMIT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_MAX_KEYS = 64


class ReceiptCoseError(ValueError):
    """The forward direction refuses: a receipt that does not verify, an argument it cannot write
    honestly, or bytes that did not read back as written."""


class CoseUnavailable(ImportError):
    """The ``[scitt]`` extra is not installed, or its cbor2 lacks the strict options the reader needs."""


class _Refused(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class StatementCheck(NamedTuple):
    """The verdict on one statement. ``status`` is one of ``STATUSES``; ``ok`` only for ``accepted``.
    The header values are filled in as far as the statement could be read; ``receipt_step`` names the
    first failing step of the draft's Section 6 for ``receipt_not_verified``."""
    status: str
    detail: str = ""
    alg: Optional[int] = None
    kid: Optional[bytes] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    payload: Optional[bytes] = None
    receipt_step: Optional[str] = None
    ignored_keys: tuple = ()

    @property
    def ok(self) -> bool:
        return self.status == ACCEPTED


# ---- deterministic CBOR (RFC 8949 section 4.2.1) for the few types a statement holds ---------------------
def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for size, info in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise _Refused("malformed", "an integer beyond 64 bits has no plain CBOR head")


def _enc(value: Any) -> bytes:
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if type(value) is int:
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if type(value) is list:
        return _head(4, len(value)) + b"".join(_enc(v) for v in value)
    if type(value) is dict:
        items = sorted((_enc(k), _enc(v)) for k, v in value.items())
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise _Refused("malformed", f"no deterministic encoding for a {type(value).__name__}")


def _sig_structure(protected_raw: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4 ToBeSigned for a COSE_Sign1, external_aad empty."""
    return _enc(["Signature1", protected_raw, b"", payload])


def cose_key_thumbprint(public_key: bytes) -> bytes:
    """RFC 9679 COSE Key Thumbprint with SHA-256 of a raw Ed25519 public key: SHA-256 over the deterministic
    encoding of the OKP key's required parameters {1 (kty): 1 (OKP), -1 (crv): 6 (Ed25519), -2 (x): key}."""
    raw = plain_bytes(public_key)
    if raw is None or len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return hashlib.sha256(_enc({1: 1, -1: 6, -2: raw})).digest()


# ---- the reader --------------------------------------------------------------------------------------------
def _cbor2() -> Any:
    try:
        import cbor2  # noqa: PLC0415 - the [scitt] extra
    except ImportError:
        raise CoseUnavailable("the [scitt] extra (cbor2) is not installed") from None
    try:
        cbor2.loads(b"\xa0", allow_duplicate_keys=False, allow_indefinite=False)
    except TypeError:
        raise CoseUnavailable("this cbor2 cannot refuse duplicate keys and indefinite lengths; the [scitt] "
                              "extra pins the version the reader was measured with") from None
    return cbor2


def _loads(cbor2: Any, data: bytes) -> Any:
    """cbor2's strict reading, used only to read back what this module wrote."""
    try:
        return cbor2.loads(data, allow_duplicate_keys=False, allow_indefinite=False)
    except Exception as exc:  # noqa: BLE001 - any refusal of the decoder is a refusal to write
        raise ReceiptCoseError(f"cbor2 does not read the written statement ({type(exc).__name__})") from None


#: The deepest nesting of arrays, maps and tags the reader follows: the depth cbor2 6.1.4 enforced when it
#: read statements. Deeper input stops the check at a resource limit; it is not a malformed statement.
_MAX_DEPTH = 400
#: The smallest argument each longer head may carry in the deterministic encoding (RFC 8949 section 4.2.1).
_SHORTEST = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}


class _Limit(Exception):
    """The check stopped at a resource limit: no status of Section 5.2.2."""


class _Tag(NamedTuple):
    """A tag: its number and its content. Step 1 does not check whether the content is valid for that tag
    (RFC 8949 section 5.3.2); the data items inside it are checked like any other data item."""
    number: int
    content: Any


class _Other(NamedTuple):
    """A data item of a kind a statement never holds where it stands: a float, a simple value other than
    false, true and null, or, as a map key, anything but an integer, a text or a byte string. It keeps its
    kind and its value, so it equals only a data item equal to it under the key equivalence of RFC 8949
    section 5.6.1 (the integer 1 and true are two keys, 0.0 and -0.0 are one), and it reaches the rule, which
    refuses it (outside_profile)."""
    kind: str
    value: Any


def _float_is_shortest(info: int, raw: bytes) -> bool:
    """RFC 8949 section 4.2.1: a float in the shortest form that preserves its value (a NaN its payload)."""
    if info == 25:
        return True
    value = struct.unpack(">f" if info == 26 else ">d", raw)[0]
    if value != value:
        bits = int.from_bytes(raw, "big")
        return bits & ((1 << (13 if info == 26 else 29)) - 1) != 0
    for fmt in (">e",) if info == 26 else (">e", ">f"):
        try:
            back = struct.unpack(fmt, struct.pack(fmt, value))[0]
        except (OverflowError, struct.error):
            continue
        if back == value and math.copysign(1.0, back) == math.copysign(1.0, value):
            return False
    return True


def _float_comparable(info: int, raw: bytes) -> tuple:
    """The key equivalence of RFC 8949 section 5.6.1 for a float: numerically equal values are equal (-0.0 is
    equal to 0.0), and NaNs are equal when their significands, zero-extended at the right to 64 bits, are."""
    value = struct.unpack({25: ">e", 26: ">f", 27: ">d"}[info], raw)[0]
    if value == value:
        return ("float", value)
    width = {25: 10, 26: 23, 27: 52}[info]
    return ("float", "NaN", (int.from_bytes(raw, "big") & ((1 << width) - 1)) << (64 - width))


def _argument(data: bytes, i: int, info: int) -> tuple:
    if info < 24:
        return info, i
    size = 1 << (info - 24)
    if i + size > len(data):
        raise _Refused("malformed", "a head ends early")
    n = int.from_bytes(data[i:i + size], "big")
    if n < _SHORTEST[size]:
        raise _Refused("malformed", "a head is not in its shortest form (RFC 8949 section 4.2.1)")
    return n, i + size


def _item(data: bytes, i: int, depth: int) -> tuple:
    """The data item at offset I of DATA as (value, comparable form, offset after it). Refuses (malformed)
    what is not well-formed (RFC 8949 section 3), not in the core deterministic encoding (section 4.2.1) or
    not valid under section 5.3.1: a text string that is not UTF-8, a map with two keys equal under the key
    equivalence of section 5.6.1, by kind and value. Whether a tag's content is valid for that tag (section
    5.3.2) is not checked; the data items inside a tag are checked like any other. Raises _Limit past
    _MAX_DEPTH nested arrays, maps and tags."""
    if i >= len(data):
        raise _Refused("malformed", "a data item ends early")
    major, info = data[i] >> 5, data[i] & 31
    i += 1
    if info >= 28:
        raise _Refused("malformed", "an indefinite length, which the deterministic encoding does not use"
                       if info == 31 and major in (2, 3, 4, 5) else
                       f"additional information {info} is not well-formed for major type {major}")
    if major == 7:
        if info in (25, 26, 27):
            size = 1 << (info - 24)
            raw = data[i:i + size]
            if len(raw) != size:
                raise _Refused("malformed", "a float ends early")
            if not _float_is_shortest(info, raw):
                raise _Refused("malformed", "a float is not in its shortest form (RFC 8949 section 4.2.1)")
            return _Other("float", raw), _float_comparable(info, raw), i + size
        if info == 24:
            if i >= len(data):
                raise _Refused("malformed", "a simple value ends early")
            n, i = data[i], i + 1
            if n < 32:
                raise _Refused("malformed", "a simple value below 32 in two bytes is not well-formed")
        else:
            n = info
        plain = {20: False, 21: True, 22: None}
        return (plain[n] if n in plain else _Other("simple", n)), ("simple", n), i
    n, i = _argument(data, i, info)
    if major in (0, 1):
        value = n if major == 0 else -1 - n
        return value, ("int", value), i
    if major in (2, 3):
        if i + n > len(data):
            raise _Refused("malformed", "a string ends early")
        raw = data[i:i + n]
        if major == 2:
            return raw, ("bytes", raw), i + n
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _Refused("malformed", "a text string is not valid UTF-8 (RFC 8949 section 5.3.1)") from None
        return text, ("text", raw), i + n
    if depth + 1 > _MAX_DEPTH:
        raise _Limit(f"the statement nests more than {_MAX_DEPTH} arrays, maps and tags")
    if major == 6:
        content, comparable, i = _item(data, i, depth + 1)
        return _Tag(n, content), ("tag", n, comparable), i
    if major == 4:
        values, comparables = [], []
        for _ in range(n):
            value, comparable, i = _item(data, i, depth + 1)
            values.append(value)
            comparables.append(comparable)
        return values, ("array", tuple(comparables)), i
    mapping: dict = {}
    pairs: list = []
    seen: set = set()
    previous = None
    for _ in range(n):
        start = i
        key, key_comparable, i = _item(data, i, depth + 1)
        encoded = data[start:i]
        value, comparable, i = _item(data, i, depth + 1)
        if key_comparable in seen:
            raise _Refused("malformed", "a map holds two equal keys (RFC 8949 section 5.3.1)")
        if previous is not None and encoded <= previous:
            raise _Refused("malformed", "the keys of a map are not in bytewise order (RFC 8949 section 4.2.1)")
        seen.add(key_comparable)
        previous = encoded
        if type(key) not in (int, str, bytes):
            key = _Other(key_comparable[0], key_comparable)
        mapping[key] = value
        pairs.append((key_comparable, comparable))
    return mapping, ("map", frozenset(pairs)), i


def _decode(data: bytes, what: str) -> Any:
    value, _comparable, end = _item(data, 0, 0)
    if end != len(data):
        raise _Refused("malformed", f"data follows {what}")
    return value


class _Sign1(NamedTuple):
    tagged: bool
    protected_raw: bytes
    protected: dict
    unprotected: dict
    payload: Optional[bytes]
    signature: bytes


def _read(data: bytes) -> _Sign1:
    """Step 1 of Section 5.2.2. The bytes are one data item, well-formed, valid and in the deterministic
    encoding; the COSE_Sign1 check concerns only the outer tag (none or 18), the array of four and its
    element types; the protected header is decoded as a map, the empty byte string as the empty map. Header
    labels and values are left to the rule (step 2)."""
    _cbor2()   # the module's requirement, the [scitt] extra; the reader itself judges the bytes
    top = _decode(data, "the statement")
    tagged = type(top) is _Tag
    if tagged and top.number != _TAG_SIGN1:
        raise _Refused("malformed", f"tag {top.number}, not 18 (COSE_Sign1)")
    body = top.content if tagged else top
    if type(body) is not list or len(body) != 4:
        raise _Refused("malformed", "not a COSE_Sign1, an array of four")
    protected_raw, unprotected, payload, signature = body
    if type(protected_raw) is not bytes or type(unprotected) is not dict or type(signature) is not bytes \
            or not (payload is None or type(payload) is bytes):
        raise _Refused("malformed", "the four members of a COSE_Sign1 do not have their types")
    protected: Any = {}
    if protected_raw:
        protected = _decode(protected_raw, "the protected header")
        if type(protected) is _Tag:
            raise _Refused("malformed", "the protected header is a tag, not a map")
        if type(protected) is not dict:
            raise _Refused("malformed", "the protected header is not a map")
    return _Sign1(tagged, protected_raw, protected, unprotected, payload, signature)


def _rule_broken(st: _Sign1, algs: tuple) -> Optional[str]:
    """None if the statement follows the rule of the module docstring, else the first rule it breaks."""
    if not st.tagged:
        return "the statement is not tagged 18 (COSE_Sign1)"
    if st.unprotected:
        return "the unprotected header is not empty"
    ph = st.protected
    if any(type(k) is not int for k in ph) or set(ph) != _LABELS:
        return "the protected header does not hold exactly the labels 1, 4, 15, 258 and 259"
    alg = ph[_ALG]
    if type(alg) is not int or alg not in algs:
        return f"alg {alg!r} is not one of {list(algs)}"
    kid = ph[_KID]
    if type(kid) is not bytes or len(kid) != 32:
        return "kid is not a 32-byte COSE Key Thumbprint (RFC 9679, SHA-256)"
    claims = ph[_CWT]
    if type(claims) is not dict or any(type(k) is not int for k in claims) or set(claims) != _CLAIMS:
        return "the CWT Claims (15) are not a map of exactly iss (1) and sub (2)"
    if type(claims[_ISS]) is not str or not _URI_RE.match(claims[_ISS]):
        return "iss is not an absolute URI (RFC 3986 section 4.3)"
    if type(claims[_SUB]) is not str or not _COMMIT_RE.match(claims[_SUB]):
        return "sub is not a model commitment, sha256: followed by 64 lowercase hexadecimal digits"
    if type(ph[_HASH_ALG]) is not int or ph[_HASH_ALG] != _SHA256:
        return f"label 258 is {ph[_HASH_ALG]!r}, not -16 (SHA-256)"
    if type(ph[_PREIMAGE_CTY]) is not str or ph[_PREIMAGE_CTY] != RECEIPT_TYPE:
        return f"label 259 is not the receipt type {RECEIPT_TYPE}"
    if st.payload is None:
        return "the payload is detached"
    if len(st.payload) != 32:
        return f"the payload is {len(st.payload)} bytes, not a 32-byte SHA-256 digest"
    if len(st.signature) != 64:
        return f"the signature is {len(st.signature)} bytes, not an Ed25519 signature"
    return None


def _statement_keys(entries: Any) -> tuple:
    """Relying-party pairs of an issuer URI and a statement key -> ([(issuer, raw key, thumbprint)], [why an
    entry was ignored]). An entry counts only as a pair (a list or tuple of two) of a text, compared exactly
    with ``iss``, and an Ed25519 key of 32 bytes that meets rules 1 and 2 of Section 4.4 of the receipts
    draft: a canonical point encoding (RFC 8032 section 5.1.3 decoding succeeds) of a point of order L. A
    point of small order and a point of mixed order do not count. Anything else is absent trust, and a bare
    key without its issuer is no pair."""
    usable: list = []
    ignored: list = []
    if not isinstance(entries, (list, tuple)):
        return usable, (["statement keys are not a list"] if entries is not None else [])
    for i, entry in enumerate(entries[:_MAX_KEYS]):
        if type(entry) not in (list, tuple) or len(entry) != 2:
            ignored.append(f"entry {i}: not a pair of an issuer URI and a statement key")
            continue
        issuer, raw = plain_text(entry[0]), plain_bytes(entry[1])
        if issuer is None:
            ignored.append(f"entry {i}: the issuer is not a text")
            continue
        if raw is None or len(raw) != 32:
            ignored.append(f"entry {i}: not a 32-byte Ed25519 public key")
            continue
        weakness = ed25519_trust_anchor_weakness(raw)
        if weakness is not None:
            ignored.append(f"entry {i}: {weakness} Ed25519 key, refused as a trust anchor")
            continue
        point = _decode_point(raw)
        if point is None:
            ignored.append(f"entry {i}: the key is no canonical point encoding (rule 1 of Section 4.4)")
            continue
        if not _has_order_l(point):
            ignored.append(f"entry {i}: the key is not a point of order L (rule 2 of Section 4.4)")
            continue
        usable.append((issuer, raw, cose_key_thumbprint(raw)))
    if len(entries) > _MAX_KEYS:
        ignored.append(f"keys beyond {_MAX_KEYS} ignored")
    return usable, ignored


def _profile_holds(key: bytes, signature: bytes, message: bytes) -> bool:
    """The four rules of Section 4.4 of the receipts draft, applied to a statement signature over its
    Sig_structure instead of PAE(type, B): canonical A and R, both of order L, S below L, and the
    cofactorless equation."""
    try:
        _profile(key, signature, message)
    except _Fail:
        return False
    return True


def _algs(algs: Any) -> tuple:
    if not isinstance(algs, (list, tuple)) or not algs or any(type(a) is not int or a not in ALGS for a in algs):
        raise ValueError(f"algs must name one or more of {list(ALGS)}")
    return tuple(algs)


# ---- backward ----------------------------------------------------------------------------------------------
def check_statement(statement: bytes, *, receipt: bytes, receipt_key: bytes,
                    statement_keys: Sequence[tuple[str, bytes]], algs: Sequence[int] = ALGS) -> StatementCheck:
    """Check STATEMENT, a COSE_Sign1 under the rule of the module docstring, against RECEIPT, verified under
    RECEIPT_KEY (32 raw bytes) by the draft's Section 6, with the relying party's STATEMENT_KEYS: pairs of
    an issuer URI and a raw 32-byte Ed25519 public key, configured by the relying party. The statement's
    ``iss`` and kid only select among the pairs; a key counts for the one issuer it is paired with. ALGS
    narrows the accepted alg values; -8 passes only under such an Ed25519 key, because no other kind of
    key is ever counted. Never raises for what it reads; every refusal is a status, and a check that stops
    at a resource limit returns ``resource_limit``, which is none."""
    accepted = _algs(algs)
    seen: dict = {}
    ignored: list = []
    try:
        data = plain_bytes(statement)
        if data is None:
            raise _Refused("malformed", "the statement is not a bytes value")
        st = _read(data)
        ph = st.protected
        raw_claims = ph.get(_CWT)
        claims: dict = raw_claims if type(raw_claims) is dict else {}
        seen = {"alg": ph.get(_ALG) if type(ph.get(_ALG)) is int else None,
                "kid": ph.get(_KID) if type(ph.get(_KID)) is bytes else None,
                "issuer": claims.get(_ISS) if type(claims.get(_ISS)) is str else None,
                "subject": claims.get(_SUB) if type(claims.get(_SUB)) is str else None,
                "payload": st.payload}
        why = _rule_broken(st, accepted)
        if why:
            raise _Refused("outside_profile", why)
        keys, ignored = _statement_keys(statement_keys)
        candidates = [raw for issuer, raw, thumbprint in keys if issuer == ph[_CWT][_ISS] and thumbprint == ph[_KID]]
        if not candidates:
            raise _Refused("untrusted_key", "no relying-party pair has both the statement's iss and a key whose "
                                            "thumbprint is its kid")
        tbs = _sig_structure(st.protected_raw, st.payload or b"")
        if not any(_profile_holds(raw, st.signature, tbs) for raw in candidates):
            raise _Refused("signature_invalid", "the signature fails the rules of Section 4.4 of the receipts "
                                                "draft under the key the pair selects")
        verdict = verify_signed_eval_receipt(receipt, receipt_key)
        if verdict.resource_limit:
            return StatementCheck(RESOURCE_LIMIT, f"step 5 {verdict.reason}",
                                  ignored_keys=tuple(ignored), **seen)
        if not verdict.ok or verdict.payload is None:
            return StatementCheck("receipt_not_verified", f"the presented receipt fails the draft's Section 6: "
                                  f"{verdict.reason}", receipt_step=verdict.step_label,
                                  ignored_keys=tuple(ignored), **seen)
        if hashlib.sha256(verdict.payload).digest() != st.payload:
            raise _Refused("digest_mismatch", "the payload is not SHA-256 over B of the presented receipt")
        if json.loads(verdict.payload)["model_id_commit"] != ph[_CWT][_SUB]:
            raise _Refused("subject_mismatch", "sub is not the model commitment of the presented receipt")
        return StatementCheck(ACCEPTED, "the statement cites the presented receipt under a relying-party key",
                              ignored_keys=tuple(ignored), **seen)
    except _Refused as refusal:
        return StatementCheck(refusal.status, refusal.detail, ignored_keys=tuple(ignored), **seen)
    except _Limit as limit:
        return StatementCheck(RESOURCE_LIMIT, f"stopped at a resource limit: {limit}", ignored_keys=tuple(ignored),
                              **seen)
    except CoseUnavailable as exc:
        return StatementCheck("no_lib", str(exc))
    except (RecursionError, MemoryError) as exc:
        return StatementCheck(RESOURCE_LIMIT, f"stopped at a resource limit ({type(exc).__name__})",
                              ignored_keys=tuple(ignored), **seen)
    except Exception as exc:  # noqa: BLE001 - a check never crashes its caller and never passes by accident
        return StatementCheck("malformed", f"refused (fail-closed): {type(exc).__name__}", **seen)


# ---- forward -----------------------------------------------------------------------------------------------
def receipt_to_statement(receipt: bytes, receipt_key: bytes, signer: Ed25519PrivateKey, *, issuer: str,
                         alg: int = WRITE_ALG) -> bytes:
    """The COSE_Sign1 that cites RECEIPT under the rule of the module docstring, signed by SIGNER.

    RECEIPT must pass every step of the draft's Section 6 under RECEIPT_KEY (32 raw bytes), or no statement
    is made. ISSUER becomes ``iss`` and must be an absolute URI (RFC 3986 section 4.3); ALG can only be
    -19, the one value this direction
    writes: -8 is refused here and accepted only by ``check_statement``. The bytes are
    read back and checked with ``check_statement`` under the pair of ISSUER and the signer's public key
    before they are returned.
    Raises ``ReceiptCoseError`` for anything it cannot write honestly, ``CoseUnavailable`` without the
    ``[scitt]`` extra."""
    if type(alg) is not int or alg != WRITE_ALG:
        raise ReceiptCoseError(f"this direction writes alg {WRITE_ALG} (Ed25519, RFC 9864) only, not {alg!r}; "
                               f"{ALG_EDDSA} (EdDSA, RFC 9053) is read, never written: no statement is made")
    if not isinstance(signer, Ed25519PrivateKey):
        raise ReceiptCoseError("the signer must be an Ed25519 private key")
    if type(issuer) is not str or not _URI_RE.match(issuer):
        raise ReceiptCoseError("issuer must be an absolute URI (RFC 3986 section 4.3)")
    cbor2 = _cbor2()
    verdict = verify_signed_eval_receipt(receipt, receipt_key)
    if verdict.resource_limit:
        raise ReceiptCoseError(f"the receipt check stopped at a resource limit ({verdict.reason}); no statement "
                               "is made")
    if not verdict.ok or verdict.payload is None:
        raise ReceiptCoseError(f"the receipt does not verify (step {verdict.step_label}: {verdict.reason}); "
                               "no statement is made")
    digest = hashlib.sha256(verdict.payload).digest()
    subject = json.loads(verdict.payload)["model_id_commit"]
    public = signer.public_key().public_bytes_raw()
    protected = {_ALG: alg, _KID: cose_key_thumbprint(public), _CWT: {_ISS: issuer, _SUB: subject},
                 _HASH_ALG: _SHA256, _PREIMAGE_CTY: RECEIPT_TYPE}
    protected_raw = _enc(protected)
    signature = signer.sign(_sig_structure(protected_raw, digest))
    data = _head(6, _TAG_SIGN1) + _enc([protected_raw, {}, digest, signature])
    check = check_statement(data, receipt=receipt, receipt_key=receipt_key, statement_keys=[(issuer, public)],
                            algs=(alg,))
    if not check.ok:
        raise ReceiptCoseError(f"the statement did not read back as written: {check.status}, {check.detail}")
    # A second, foreign decoder reads it back too: cbor2 in its strict mode, the [scitt] extra.
    foreign = _loads(cbor2, data)
    if not (isinstance(foreign, cbor2.CBORTag) and foreign.tag == _TAG_SIGN1 and foreign.value[0] == protected_raw
            and _loads(cbor2, protected_raw) == protected):
        raise ReceiptCoseError("the statement did not read back as written with cbor2")
    return data
