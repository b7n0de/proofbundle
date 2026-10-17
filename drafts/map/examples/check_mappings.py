#!/usr/bin/env python3
"""Checks for the examples of draft-gruszka-evaluation-receipt-mappings-03. It does not import the
generator; it re-derives every claim from the bytes in mappings.json:

  D1  the receipt digest is SHA-256 over B, and B is the payload of the receipt bytes;
  M1  the DSSE envelope's payload is B, its payloadType is the receipt type, and its signature verifies
      as a DSSE signature, Ed25519 over PAE(payloadType, payload), under the issuer key, with the
      bytes of the receipt's own signature (no new signature);
  M2  the COSE_Sign1 is tag 18, its unprotected header is empty, the protected header carries alg -19,
      kid = RFC 9679 thumbprint of the issuer key, CWT iss and sub, 258 = -16 and 259 = the receipt
      type, its payload equals the receipt digest, and its signature verifies over Sig_structure;
  C   for each citation case, the match result computed here from the candidate's bytes (read from the
      receipts draft's vectors.json and checked against the SHA-256 in mappings.json) equals the
      expected one. B is obtained by steps 1 to 3 of the receipts draft, written here again; only
      SHA-256 is a defined citation algorithm.
  S   for M2 with P1 and for each status vector, the status computed here by steps 1 to 7 of the checking
      procedure, written here again from the text, under the one configured pair of the examples (the issuer
      URI and the issuer test key), equals the expected status; the candidate is read from the receipts
      draft's vectors.json and checked against the SHA-256 in mappings.json, and step 5 runs the receipts
      draft's own checker.
  X   for each certificate-profile vector, the status computed by the same steps under the one configured
      certificate pair of the examples (the did:x509 issuer of X1 and the test root certificate) equals the
      expected status; the certificates are read with the cryptography library, the chain signature is checked
      as RSASSA-PKCS1-v1_5 with SHA-256 and the statement signature as ECDSA P-256 with SHA-256.
  R   for each of R1 to R14, the state under the declaration of Section 5.1 (Malformed in the terms of CPB Section
      3; Verified, Failed or Unresolved in the terms of CPB Section 8.1) and the result of the matching rule with the
      JSON extraction rule of Section 5.1 equal the expected ones. The reference is read as RFC 8259 JSON with its
      member pairs in order, a repeated name kept and names compared after unescaping; no value is converted. R14
      is the bytes EF BB BF followed by the bytes of R1; the byte order mark is not part of the JSON grammar, so R14
      is Malformed with INDETERMINATE, and a reader that drops it (json.loads on bytes does) would read R1.
  T   for each Transparent Statement, the status under both configured pairs equals the expected one: an
      unprotected header with label 394 alone, holding an array of one or more byte strings, is removed before
      step 2, and the receipts are not read; T2 is X1 with one receipt under 394, byte for byte.
  K   for M2, S1, X1 and T2 (the registered Transparent Statement of X1) with the head byte of key 15 in the
      protected header replaced by 0x2f (-16), nothing reordered and not signed again, the status is malformed at
      step 1: in the deterministic encoding of RFC 8949 Section 4.2.1 the keys are sorted bytewise by their
      encodings, so -16 (0x2f) belongs after 33 (0x18 0x21), 258 and 259 (0x19 0x01 ...).
  G   for X1 with O of its iss changed in one place and the signature kept (steps 2 and 3 come before step 4): a
      leading zero in the last or in the first arc, and a second arc over 39 under a first arc 0 or 1, are
      outside_profile at step 2 (Section 5.2, label 15); O = 1.39.6.1.5.5.7.3.3 and 2.40.6.1.5.5.7.3.3 have the form
      and are untrusted_key at step 3 under the certificate pair.
  H   for M2 with a sixth protected-header pair written as given bytes, the signature kept: step 1 reads a tag as
      its number and content (a bignum, a date and a UUID included), compares keys under RFC 8949 Section 5.6.1
      (1, 1.0 and true are three keys), admits a float in its shortest form and a NaN only as f9 7e00; a key out of
      bytewise order is malformed (Section 5.2.2 step 1).
  L   for M2 with a sixth label -1 holding arrays 60000 deep, maps 30000 deep or tags 30000 deep, step 1 stops at
      MAX_DEPTH (64) with a resource-limit error, which Section 5.2.2 says is no status.
      For M2 with a candidate receipt of arrays 60000 deep, step 5 ends the same way: the receipts draft's checker
      reports RESOURCE_LIMIT, and the error is passed on, not turned into receipt_not_verified.
      The JSON of a candidate and of a typed digest reference has the same limit: a candidate that nests deeper has
      no B, so the C1 citation gives INDETERMINATE (Section 3.3 step 2, "including when processing stops at a
      resource limit") and R1 is Unresolved (Section 5.1); a reference that nests deeper is not read, a resource-limit
      error and no state. P1 with a key member nesting 64 deep in all is read (MATCH, Verified, receipt_not_verified
      at step 5), 65 deep is not; R1 with a member nesting 64 deep in all is read (Malformed, for the member, with
      MATCH), 65 deep is not.
  F   a reference that is not a JSON object (not JSON, an array, a number, a text, null), an object with a member
      name twice and no digest, and {} are Malformed with INDETERMINATE (Section 5.1).
  Z   every input is read up to MAX_INPUT_BYTES (1 MiB) and not above: a candidate receipt over it has no B (C1
      INDETERMINATE, R1 Unresolved), a reference or a statement over it is a resource-limit error, and step 5 passes on
      the receipts draft's checker's RESOURCE_LIMIT. A number is kept as its token, so a number of 5000 digits in a
      candidate or in a reference reads as one of 5 digits does (in a reference a member x, so Malformed with MATCH).
  V   a digest counts only as a text value: R1 with its digest written as a JSON number (64 digits, or 64 characters
      with an exponent), as true or as an array holding the right text, or with digest_alg as an array, is Malformed
      with INDETERMINATE (Section 5.1); C1 with its value as a number, true or an array is INDETERMINATE (Section 3.3
      step 1).
  W   the reverse cases of the review of Section 5.1: R1 with a byte order mark, with a member NaN, or cut short is
      not JSON, Malformed with INDETERMINATE; without type or with type 1, Malformed with MATCH; without digest,
      Malformed with INDETERMINATE; with digest_alg twice, also with the same value, Malformed with INDETERMINATE;
      with type or purpose twice and one digest pair, Malformed with MATCH; with purpose evaluation, the one optional
      member, Unresolved with MATCH, also when it is a lone surrogate escape (RFC 8259, not I-JSON), and with type
      written as "\u0074ype", Verified with MATCH.
Exit 0 when all hold.
"""
import base64
import hashlib
import json
import math
import os
import re
import struct
import sys
from collections.abc import Mapping

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

TYPE = "application/vnd.signed-evidence.eval-receipt+json"
#: The UTF-8 byte order mark, as bytes (Section 5.1, vector R14).
BOM_UTF8 = bytes.fromhex("efbbbf")
RECEIPT_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ser", "examples",
                               "vectors.json")
B64_RE = re.compile(r"\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


class NoB(Exception):
    """B cannot be obtained from the candidate (a step from 1 to 3 of the receipts draft fails, or reading the
    candidate stops at MAX_DEPTH; Section 3.3 step 2 gives INDETERMINATE for both)."""


def _pairs(pairs):
    names = [k for k, _ in pairs]
    if len(names) != len(set(names)):
        raise NoB("duplicate member name")
    return dict(pairs)


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


#: The characters the depth measurement looks at, each matched alone: no state per character of a long string.
_JSON_SPECIAL = re.compile(r'[\\"\[\]{}]')


def json_depth_ok(text: str) -> bool:
    """True if arrays and objects in text nest at most MAX_DEPTH deep: a top-level array or object is depth 1, and
    brackets inside strings do not count. Measured before the text is parsed, as the receipts draft's checker does."""
    depth, in_string, skip = 0, False, -1
    for m in _JSON_SPECIAL.finditer(text):
        i = m.start()
        if i == skip:   # the character after a backslash in a string
            continue
        c = text[i]
        if in_string:
            if c == "\\":
                skip = i + 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif c in "]}":
            depth -= 1
    return True


class Num:
    """A JSON number kept as its token. Not converted to int, whose conversion stops at 4300 digits in Python 3.11
    and would turn a long number into a failure of the reading."""
    __slots__ = ("token",)

    def __init__(self, token: str):
        self.token = token

    def __str__(self):
        return self.token


def b_of(receipt: bytes) -> bytes:
    """Steps 1 to 3 of the receipts draft: strict parse, member sets, schema, canonical base64. A candidate of more
    than MAX_INPUT_BYTES, or that nests deeper than MAX_DEPTH, is not read: processing stops at a resource limit, and B
    is not obtained."""
    if len(receipt) > MAX_INPUT_BYTES:
        raise NoB("processing stops at a resource limit: %d bytes, more than %d" % (len(receipt), MAX_INPUT_BYTES))
    if receipt.startswith(b"\xef\xbb\xbf"):
        raise NoB("byte order mark")
    try:
        text = receipt.decode("utf-8")
        if not json_depth_ok(text):
            raise NoB("processing stops at a resource limit: arrays and objects nested deeper than %d" % MAX_DEPTH)
        obj = json.loads(text, object_pairs_hook=_pairs, parse_int=Num, parse_float=Num)
    except NoB:
        raise
    except (UnicodeDecodeError, ValueError) as e:
        raise NoB("not one JSON text: %s" % e) from None
    for st in _strings(obj):
        for ch in st:
            c = ord(ch)
            if 0xD800 <= c <= 0xDFFF or 0xFDD0 <= c <= 0xFDEF or (c & 0xFFFE) == 0xFFFE:
                raise NoB("surrogate or noncharacter")
    if not isinstance(obj, dict) or set(obj) != {"schema", "payload_b64", "signature"}:
        raise NoB("receipt member set")
    sig = obj["signature"]
    if not isinstance(sig, dict) or set(sig) not in ({"alg", "sig"}, {"alg", "sig", "key"}):
        raise NoB("signature member set")
    if obj["schema"] != TYPE:
        raise NoB("schema")
    pb = obj["payload_b64"]
    if not isinstance(pb, str) or not B64_RE.match(pb):
        raise NoB("payload_b64 not base64 with padding")
    raw = base64.b64decode(pb, validate=True)
    if base64.b64encode(raw).decode("ascii") != pb:
        raise NoB("payload_b64 not canonical")
    return raw


def match(citation, receipt: bytes) -> str:
    value = citation.get("hex")
    if citation.get("alg") != "sha-256" or not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        return "INDETERMINATE"
    try:
        b = b_of(receipt)
    except NoB:
        return "INDETERMINATE"
    return "MATCH" if hashlib.sha256(b).hexdigest() == citation["hex"] else "NO_MATCH"


# RFC 3986 absolute-URI = scheme ":" `hier-part` [ "?" query ], with the four forms of `hier-part` (Section 3) and "["
# "]" only around an IP-literal (Section 3.2.2).
_U, _SD, _PCT = r"A-Za-z0-9\-._~", r"!$&'()*+,;=", r"%[0-9A-Fa-f]{2}"
_PCH = rf"(?:[{_U}{_SD}:@]|{_PCT})"
_HOST = rf"(?:\[[0-9A-Fa-f:.vV{_U}{_SD}]+\]|(?:[{_U}{_SD}]|{_PCT})*)"
_HIER = (rf"(?://(?:(?:[{_U}{_SD}:]|{_PCT})*@)?{_HOST}(?::[0-9]*)?(?:/{_PCH}*)*"
         rf"|/(?:{_PCH}+(?:/{_PCH}*)*)?|{_PCH}+(?:/{_PCH}*)*|)")
ISS_RE = re.compile(rf"\A[A-Za-z][A-Za-z0-9+.\-]*:{_HIER}(?:\?(?:{_PCH}|[/?])*)?\Z")
SUB_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
L_ORDER = 2 ** 252 + 27742317777372353535851937790883648493


def cbor_head(major: int, n: int) -> bytes:
    """The head of a data item with its argument as short as possible (RFC 8949 Section 4.2.1)."""
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << 8 * size:
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("argument over 64 bits")


def cbor_float(x: float) -> bytes:
    """The shortest of half, single and double precision that keeps the value; every NaN as f9 7e00."""
    if math.isnan(x):
        return b"\xf9\x7e\x00"
    for fmt, ib in ((">e", 0xF9), (">f", 0xFA)):
        try:
            b = struct.pack(fmt, x)
        except OverflowError:
            continue
        if struct.unpack(fmt, b)[0] == x:
            return bytes([ib]) + b
    return b"\xfb" + struct.pack(">d", x)


def cbor_encode(v) -> bytes:
    """The deterministic encoding of RFC 8949 Section 4.2.1: arguments as short as possible, definite lengths,
    floating-point values in their shortest form, and the keys of every map, at any depth, sorted bytewise
    lexicographically by their own encodings. cbor2 canonical sorts by length first, so it puts -16 (0x2f)
    before 33 (0x18 0x21) and 258 (0x19 0x01 0x02); this order puts it after them."""
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if v is None:
        return b"\xf6"
    if v is cbor2.undefined:
        return b"\xf7"
    if isinstance(v, int):
        if -(1 << 64) <= v < 1 << 64:
            return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)
        n = v if v >= 0 else -1 - v   # a bignum, tag 2 or 3 (RFC 8949 Section 3.4.3)
        return cbor_encode(cbor2.CBORTag(2 if v >= 0 else 3, n.to_bytes((n.bit_length() + 7) // 8, "big")))
    if isinstance(v, float):
        return cbor_float(v)
    if isinstance(v, bytes):
        return cbor_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return cbor_head(3, len(b)) + b
    # cbor2 5 decodes an array as list and a map as dict, cbor2 6 inside an array as tuple and frozendict
    if isinstance(v, (list, tuple)):
        return cbor_head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, Mapping):
        pairs = sorted((cbor_encode(k), cbor_encode(x)) for k, x in v.items())
        return cbor_head(5, len(pairs)) + b"".join(k + x for k, x in pairs)
    if isinstance(v, cbor2.CBORTag):
        return cbor_head(6, v.tag) + cbor_encode(v.value)
    if isinstance(v, cbor2.CBORSimpleValue):
        return cbor_head(7, v.value)
    raise TypeError("no deterministic encoding here for %s" % type(v).__name__)


class Tag:
    """A tag as the generic data model has it, its number and its content. No tag adds a rule of its own in step 1
    (Section 5.2.2, after RFC 8949 Section 4.2.2), so the content is not read as a date, a bignum or a UUID."""
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class Float:
    """A floating-point value; it equals no integer and no simple value."""
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value


class Simple:
    """A simple value other than null: false (20), true (21), undefined (23) and the unassigned ones. It equals no
    integer, so true and 1 are two map keys."""
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value


class Key:
    """A map key that is not an integer, a text string, a byte string or null, compared under RFC 8949 Section
    5.6.1 (key_rep)."""
    __slots__ = ("rep",)

    def __init__(self, rep):
        self.rep = rep

    def __eq__(self, other):
        return isinstance(other, Key) and self.rep == other.rep

    def __hash__(self):
        return hash(self.rep)


def key_rep(v):
    """v under the key equivalence of RFC 8949 Section 5.6.1: integers, floats, simple values, byte strings, text
    strings, arrays, maps and tags are each their own group, so 1, 1.0 and true are three keys; within the floats
    -0.0 equals 0.0. Step 1 admits one NaN only, f9 7e00, so every NaN here is that one."""
    if isinstance(v, int):
        return ("int", v)
    if isinstance(v, bytes):
        return ("bytes", v)
    if isinstance(v, str):
        return ("text", v)
    if v is None:
        return ("simple", 22)
    if isinstance(v, Simple):
        return ("simple", v.value)
    if isinstance(v, Float):
        return ("float", v.value) if v.value == v.value else ("nan",)
    if isinstance(v, list):
        return ("array", tuple(key_rep(x) for x in v))
    if isinstance(v, dict):
        return ("map", frozenset((k.rep if isinstance(k, Key) else key_rep(k), key_rep(x)) for k, x in v.items()))
    if isinstance(v, Tag):
        return ("tag", v.tag, key_rep(v.value))
    raise TypeError("no key representation for %s" % type(v).__name__)


# Resource limits, all in this one place. A larger or deeper input meets a limit of this Receiver: a resource-limit
# error, which Section 5.2.2 says is no status; for a candidate receipt Section 3.3 step 2 makes it INDETERMINATE.
#: The largest input read, in bytes: a statement, a candidate receipt, a typed digest reference. The largest input of
#: the vectors is 2827 bytes (a certificate-profile statement); the same number in the checkers of the three drafts.
MAX_INPUT_BYTES = 1 << 20
#: The deepest nesting of arrays, maps and tags that step 1 reads (the item itself at depth 0). The same number bounds
#: the JSON of a candidate receipt and of a typed digest reference (json_depth_ok).
MAX_DEPTH = 64


class ResourceLimit(Exception):
    """The Receiver stopped at one of its limits (Section 5.2.2): a resource-limit error, no status, and the
    statement is not accepted."""


class NotDeterministic(Exception):
    """Step 1 fails: the bytes are not one well-formed, valid data item in the deterministic encoding."""


def _fits(x: float, fmt: str) -> bool:
    try:
        return struct.unpack(fmt, struct.pack(fmt, x))[0] == x
    except OverflowError:
        return False


def _decode(b: bytes, i: int, depth: int = 0):
    """The data item at offset i and the offset after it, read from the bytes, not through cbor2. RFC 8949
    Section 4.2.1 with the choices of Section 5.2.2 step 1: arguments as short as possible, definite lengths, floats
    in their shortest form and a NaN only as f9 7e00, the keys of every map in bytewise order of their encodings and
    no two equal under Section 5.6.1, text strings in UTF-8 (Section 5.3.1); a tag is its number and its content.
    An item nested deeper than MAX_DEPTH raises ResourceLimit."""
    if depth > MAX_DEPTH:
        raise ResourceLimit("nesting deeper than %d" % MAX_DEPTH)
    if i >= len(b):
        raise NotDeterministic("ends inside an item")
    mt, ai = b[i] >> 5, b[i] & 0x1F
    if ai < 24:
        arg, j = ai, i + 1
    elif ai < 28:
        n = 1 << (ai - 24)
        if i + 1 + n > len(b):
            raise NotDeterministic("ends inside a head")
        arg, j = int.from_bytes(b[i + 1:i + 1 + n], "big"), i + 1 + n
        if mt != 7 and arg < (24 if n == 1 else 1 << (4 * n)):
            raise NotDeterministic("argument not as short as possible")
    else:
        raise NotDeterministic("indefinite length or reserved additional information")
    if mt == 0:
        return arg, j
    if mt == 1:
        return -1 - arg, j
    if mt in (2, 3):
        if j + arg > len(b):
            raise NotDeterministic("ends inside a string")
        if mt == 2:
            return b[j:j + arg], j + arg
        try:
            return b[j:j + arg].decode("utf-8"), j + arg
        except UnicodeDecodeError:
            raise NotDeterministic("text string not UTF-8") from None
    if mt == 4:
        out = []
        for _ in range(arg):
            x, j = _decode(b, j, depth + 1)
            out.append(x)
        return out, j
    if mt == 5:
        out, seen, last = {}, set(), b""
        for _ in range(arg):
            k, kj = _decode(b, j, depth + 1)
            if b[j:kj] <= last:
                raise NotDeterministic("map keys not in bytewise order of their encodings")
            last, r = b[j:kj], key_rep(k)
            if r in seen:
                raise NotDeterministic("two map keys equal under RFC 8949 Section 5.6.1")
            seen.add(r)
            x, j = _decode(b, kj, depth + 1)
            out[k if isinstance(k, (int, str, bytes)) or k is None else Key(r)] = x
        return out, j
    if mt == 6:
        x, j = _decode(b, j, depth + 1)
        return Tag(arg, x), j
    if ai < 24:
        return (None if arg == 22 else Simple(arg)), j
    if ai == 24:
        if arg < 32:
            raise NotDeterministic("simple value below 32 in two bytes")
        return Simple(arg), j
    x = struct.unpack({25: ">e", 26: ">f", 27: ">d"}[ai], b[i + 1:j])[0]
    if x != x and b[i:j] != b"\xf9\x7e\x00":
        raise NotDeterministic("a NaN other than f9 7e00")
    if ai > 25 and x == x and _fits(x, ">e" if ai == 26 else ">f"):
        raise NotDeterministic("float not in its shortest form")
    return Float(x), j


def deterministic(b: bytes):
    """Step 1 on one byte string: (the item, True) when it is one well-formed, valid data item in the deterministic
    encoding (_decode), else (None, False). ResourceLimit passes through: it is no status; above MAX_INPUT_BYTES it
    comes before anything is read."""
    if len(b) > MAX_INPUT_BYTES:
        raise ResourceLimit("%d bytes, more than %d" % (len(b), MAX_INPUT_BYTES))
    try:
        item, end = _decode(b, 0)
    except NotDeterministic:
        return None, False
    return (item, True) if end == len(b) else (None, False)


KEY_LABELS = {1, 4, 15, 258, 259}
CERT_LABELS = {1, 4, 15, 33, 258, 259}
# O as Section 5.2, label 15 has it: first arc 0, 1 or 2; under 0 or 1 a second arc of at most 39 (X.660 7.6, RFC 9090
# Section 2); under 2 any second arc; one or more further arcs; no leading zeros
DID_RE = re.compile(r"\Adid:x509:0:sha256:([A-Za-z0-9_-]{43})::eku:((?:[01]\.(?:[0-9]|[1-3][0-9])|2\.(?:0|[1-9][0-9]*))"
                    r"(?:\.(?:0|[1-9][0-9]*))*)\Z")
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _cert_pair_counts(iss, kid, chain, pair):
    """Step 3, certificate profile: does this configured pair (did:x509 issuer, trust anchor certificate) count?"""
    p_iss, anchor = pair
    m = DID_RE.match(iss)
    if p_iss != iss or chain[1] != anchor or b64url(hashlib.sha256(anchor).digest()) != m.group(1):
        return False
    try:
        leaf = x509.load_der_x509_certificate(chain[0])
        root = x509.load_der_x509_certificate(chain[1])
        rkey = root.public_key()
        if not isinstance(rkey, rsa.RSAPublicKey) or rkey.key_size < 2048:
            return False
        if leaf.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
            return False
        rkey.verify(leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        if leaf.issuer.public_bytes() != root.subject.public_bytes():
            return False
        eku = leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        if m.group(2) not in [o.dotted_string for o in eku]:
            return False
        lkey = leaf.public_key()
        if not isinstance(lkey, ec.EllipticCurvePublicKey) or lkey.curve.name != "secp256r1":
            return False
        spki = lkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except Exception:  # noqa: BLE001  not a certificate, no EKU, signature invalid
        return False
    return hashlib.sha256(spki).digest() == kid


def check_statement(stmt: bytes, candidate: bytes, receipt_key: bytes, pairs, cert_pairs=()):
    """Steps 1 to 7; returns (status, step) with step None for accepted. The protected-header labels select the
    key profile (1, 4, 15, 258, 259) or the certificate profile (1, 4, 15, 33, 258, 259). Raises ResourceLimit when
    step 1 meets MAX_DEPTH: a resource-limit error, no status."""
    import check_receipts  # noqa: PLC0415  the receipts draft's own checker, for step 5 only
    item, det = deterministic(stmt)
    if item is None or not det:
        return "malformed", 1
    if isinstance(item, Tag):
        if item.tag != 18:
            return "malformed", 1
        arr, tagged = item.value, True
    else:
        arr, tagged = item, False
    # _decode gives an array as list and a map as dict
    if not (isinstance(arr, (list, tuple)) and len(arr) == 4 and isinstance(arr[0], bytes)
            and isinstance(arr[1], Mapping) and isinstance(arr[2], (bytes, type(None))) and isinstance(arr[3], bytes)):
        return "malformed", 1
    prot_b, unprot, payload, sig = arr
    prot, pdet = deterministic(prot_b) if prot_b else ({}, True)
    if not isinstance(prot, Mapping) or not pdet:
        return "malformed", 1
    # A Transparent Statement: label 394 alone, an array of one or more byte strings (COSE Receipts), is removed
    # and the steps go on with the empty unprotected header; the receipts are not read. Anything else that is not
    # the empty map stays and is outside_profile in step 2.
    if (isinstance(unprot, Mapping) and set(unprot) == {394} and isinstance(unprot[394], (list, tuple))
            and len(unprot[394]) >= 1 and all(isinstance(r, bytes) for r in unprot[394])):
        unprot = {}
    cwt = prot.get(15)
    common = (tagged and unprot == {} and isinstance(prot.get(4), bytes) and len(prot[4]) == 32
              and isinstance(cwt, Mapping) and set(cwt) == {1, 2} and isinstance(cwt[1], str)
              and isinstance(cwt[2], str) and SUB_RE.match(cwt[2]) is not None and prot.get(258) == -16
              and prot.get(259) == TYPE and isinstance(payload, bytes) and len(payload) == 32 and len(sig) == 64)
    labels = set(prot)
    if common and labels == KEY_LABELS and prot[1] in (-19, -8) and ISS_RE.match(cwt[1]):
        profile = "key"
    elif (common and labels == CERT_LABELS and prot[1] == -7 and DID_RE.match(cwt[1])
          and isinstance(prot[33], (list, tuple)) and len(prot[33]) == 2
          and all(isinstance(c, bytes) for c in prot[33])):
        profile = "certificate"
    else:
        return "outside_profile", 2
    tbs = cbor_encode(["Signature1", prot_b, b"", payload])
    if profile == "key":
        selected = [k for iss, k in pairs if iss == cwt[1] and len(k) == 32
                    and hashlib.sha256(cbor_encode({1: 1, -1: 6, -2: k})).digest() == prot[4]]
        if not selected:
            return "untrusted_key", 3
        good = False
        for k in selected:
            if int.from_bytes(sig[32:], "little") >= L_ORDER:
                continue
            try:
                Ed25519PublicKey.from_public_bytes(k).verify(sig, tbs)
                good = True
            except Exception:  # noqa: BLE001
                pass
    else:
        chain = list(prot[33])
        if not any(_cert_pair_counts(cwt[1], prot[4], chain, pr) for pr in cert_pairs):
            return "untrusted_key", 3
        r, s_ = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        good = False
        if 1 <= r < P256_N and 1 <= s_ < P256_N:
            try:
                x509.load_der_x509_certificate(chain[0]).public_key().verify(
                    encode_dss_signature(r, s_), tbs, ec.ECDSA(hashes.SHA256()))
                good = True
            except Exception:  # noqa: BLE001
                pass
    if not good:
        return "signature_invalid", 4
    verdict, _step, why = check_receipts.verify(candidate, receipt_key)
    if verdict == "RESOURCE_LIMIT":   # Section 5.2.2: a resource-limit error in any step is no status
        raise ResourceLimit("step 5, the receipt procedure: %s" % why)
    if verdict != "PASS":
        return "receipt_not_verified", 5
    cb = b_of(candidate)
    if payload != hashlib.sha256(cb).digest():
        return "digest_mismatch", 6
    if cwt[2] != json.loads(cb)["model_id_commit"]:
        return "subject_mismatch", 7
    return "accepted", None


def p1_with_key(p1: bytes, total: int) -> bytes:
    """P1 with a key member of nested arrays in its signature object, so that the receipt nests total deep."""
    r = json.loads(p1)
    r["signature"]["key"] = json.loads("[" * (total - 2) + "]" * (total - 2))
    return json.dumps(r, separators=(",", ":")).encode()


def ref_with_member(ref_text: str, total: int) -> str:
    """A reference with one more member of nested arrays, so that it nests total deep."""
    r = json.loads(ref_text)
    r["x"] = json.loads("[" * (total - 1) + "]" * (total - 1))
    return json.dumps(r, separators=(",", ":"))


class _Members(list):
    """The member pairs of one JSON object, in order, with a repeated name kept: Section 5.1 detects repeated names
    before any conversion that could discard them."""


def _not_json(name):
    raise ValueError("%s is not in the JSON grammar" % name)


#: Section 5.1: the required members and the one optional member of the JSON representation, all JSON strings.
REF_REQUIRED, REF_MEMBERS = {"type", "digest_alg", "digest"}, {"type", "purpose", "digest_alg", "digest"}


def reference_state(ref_text: str, receipt: bytes):
    """A typed digest reference in the JSON representation of Section 5.1: (state, matching-rule result). The state is
    Malformed (CPB Section 3) for input outside that form, before anything else; Unresolved, Failed or Verified (CPB
    Section 8.1) only for a well-formed reference. The matching rule takes the one digest_alg and the one digest,
    both strings, by the extraction rule of Section 5.1, whatever the state. A reference that nests deeper than
    MAX_DEPTH is not read: ResourceLimit, a resource-limit error and no state. A candidate that does is one without B
    (Unresolved, INDETERMINATE), as Section 5.1 and Section 3.3 step 2 say. The same holds for MAX_INPUT_BYTES, counted
    in bytes of UTF-8."""
    size = len(ref_text.encode("utf-8", "surrogatepass"))
    if size > MAX_INPUT_BYTES:
        raise ResourceLimit("the reference is %d bytes, more than %d" % (size, MAX_INPUT_BYTES))
    if not json_depth_ok(ref_text):
        raise ResourceLimit("the reference nests arrays and objects deeper than %d" % MAX_DEPTH)
    try:   # RFC 8259: no NaN or Infinity, no byte order mark; a number is kept as its token
        top = json.loads(ref_text, object_pairs_hook=_Members, parse_int=Num, parse_float=Num,
                         parse_constant=_not_json)
    except ValueError:
        top = None
    members = top if isinstance(top, _Members) else _Members()
    # the extraction rule: exactly one digest_alg and exactly one digest, both strings; no occurrence is chosen and
    # no value converted
    algs = [v for k, v in members if k == "digest_alg"]
    digests = [v for k, v in members if k == "digest"]
    unique = len(algs) == 1 and len(digests) == 1 and isinstance(algs[0], str) and isinstance(digests[0], str)
    digest = digests[0] if unique else None
    ok_form = unique and algs[0] == "SHA-256" and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    try:
        b = b_of(receipt)
    except NoB:
        b = None
    if not ok_form or b is None:
        match_ = "INDETERMINATE"
    else:
        match_ = "MATCH" if hashlib.sha256(b).hexdigest() == digest else "NO_MATCH"
    names = [k for k, _ in members]
    if (not isinstance(top, _Members) or len(names) != len(set(names)) or not REF_REQUIRED <= set(names)
            or not set(names) <= REF_MEMBERS or not all(isinstance(v, str) for _, v in members)):
        return "Malformed", match_
    ref = dict(members)
    if ref["type"] != TYPE or "purpose" in ref:
        return "Unresolved", match_
    if not ok_form:
        return "Failed", match_
    if b is None:
        return "Unresolved", match_
    return ("Verified" if match_ == "MATCH" else "Failed"), match_


#: (statement, SHA-256 of the statement with the head byte of key 15 in its protected header replaced by 0x2f)
KEY_ORDER_CASES = [
    ("M2", "9bd318276dcb426a761e45fadeb3a3114e0b3ef539931fe88a5c062116f25bf6"),
    ("S1", "a97822327f64be340787ea32477ef21581ac7de557a4a07f343a44cd4c81c803"),
    ("X1", "af072b12520559c2401c9aaa11a89d17b19570b1ac6f4a50bb6e64b2418aebba"),
    ("T2", "42473a340cc1ad0ac968fce03683acabe84871936ab3578a08c2e098775f07fa"),
]


def key_byte_replaced(stmt: bytes, label: int, new: int) -> bytes:
    """The tagged COSE_Sign1 with the head byte of one protected-header label replaced; nothing is reordered and
    nothing is signed again. The offset is that of the label in the protected header as it stands."""
    prot_b = cbor2.loads(stmt).value[0]
    prot = cbor2.loads(prot_b)
    keys = list(prot)
    start = 2 + len(cbor_head(2, len(prot_b)))   # tag 18 (0xd2) and the array head (0x84) are one byte each
    at = start + len(cbor_head(5, len(prot))) + sum(len(cbor_encode(k)) + len(cbor_encode(prot[k]))
                                                    for k in keys[:keys.index(label)])
    if stmt[start:start + len(prot_b)] != prot_b or stmt[at:at + 1] != cbor_encode(label):
        raise ValueError("label %d not where its encoding puts it" % label)
    return stmt[:at] + bytes([new]) + stmt[at + 1:]


#: (what changes in O of the iss of X1, the new O, the expected status and step)
OID_CASES = [
    ("a leading zero in the last arc", "1.3.6.1.5.5.7.3.03", ("outside_profile", 2)),
    ("a leading zero in the first arc", "01.3.6.1.5.5.7.3.3", ("outside_profile", 2)),
    ("second arc 40 under first arc 1", "1.40.6.1.5.5.7.3.3", ("outside_profile", 2)),
    ("second arc 40 under first arc 0", "0.40.1", ("outside_profile", 2)),
    ("second arc 39 under first arc 1, under the certificate pair", "1.39.6.1.5.5.7.3.3", ("untrusted_key", 3)),
    ("second arc 40 under first arc 2, under the certificate pair", "2.40.6.1.5.5.7.3.3", ("untrusted_key", 3)),
]
#: (what, the value of a sixth protected-header label -1 in M2 at the end): nested past MAX_DEPTH
DEPTH_CASES = [
    ("arrays 60000 deep", bytes([0x81]) * 60000 + b"\x00"),
    ("maps 30000 deep", bytes([0xA1, 0x01]) * 30000 + b"\x00"),
    ("tags 30000 deep", bytes([0xC6]) * 30000 + b"\x00"),
]
#: (the sixth pair in M2, its key and value as bytes, the label it stands before (None: at the end), status and step)
PAIR_CASES = [
    ("key 1.5 (f9 3e00) at the end", "f93e00", "00", None, ("outside_profile", 2)),
    ("key true (f5) at the end, next to 1", "f5", "00", None, ("outside_profile", 2)),
    ("key 1.0 (f9 3c00) at the end, next to 1", "f93c00", "00", None, ("outside_profile", 2)),
    ("key -1 at the end, tag 37 and 16 zero bytes", "20", "d82550" + "00" * 16, None, ("outside_profile", 2)),
    ("key -1 at the end, tag 1 and 0", "20", "c100", None, ("outside_profile", 2)),
    ("key -1 at the end, tag 2 and h'01'", "20", "c24101", None, ("outside_profile", 2)),
    ("key -1 before 258, 0", "20", "00", 258, ("malformed", 1)),
    ("key 16 before 258, tag 0 and '2026-10-11T00:00:00Z'", "10", "c074" + b"2026-10-11T00:00:00Z".hex(), 258,
     ("outside_profile", 2)),
    ("key 16 before 258, 1.5 (f9 3e00)", "10", "f93e00", 258, ("outside_profile", 2)),
    ("key 16 before 258, f9 7e00", "10", "f97e00", 258, ("outside_profile", 2)),
    ("key 16 before 258, f9 7e01", "10", "f97e01", 258, ("malformed", 1)),
    ("key 16 before 258, fb 7ff8000000000001", "10", "fb7ff8000000000001", 258, ("malformed", 1)),
]


def with_pair(stmt: bytes, key: bytes, value: bytes, before) -> bytes:
    """The tagged COSE_Sign1 with one more protected-header pair, key and value as given bytes, put before the pair
    of label `before` or at the end; the other pairs, the unprotected header, payload and signature as they are."""
    item = cbor2.loads(stmt)
    prot = cbor2.loads(item.value[0])
    pairs = [(k, cbor_encode(k) + cbor_encode(x)) for k, x in prot.items()]
    if cbor_head(5, len(pairs)) + b"".join(e for _, e in pairs) != item.value[0]:
        raise ValueError("protected header not as its pairs encode it")
    at = len(pairs) if before is None else [k for k, _ in pairs].index(before)
    enc = [e for _, e in pairs]
    enc.insert(at, key + value)
    prot_b = cbor_head(5, len(enc)) + b"".join(enc)
    return cbor_encode(cbor2.CBORTag(18, [prot_b, item.value[1], item.value[2], item.value[3]]))


def pae(typ, body):
    t = typ.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def check(label, cond):
    print(("OK   " if cond else "FAIL ") + label)
    return bool(cond)


def main():
    d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "mappings.json", encoding="utf-8"))
    pub = base64.b64decode(d["issuer_public_key_b64"])
    vk = Ed25519PublicKey.from_public_bytes(pub)
    receipt = json.loads(bytes.fromhex(d["receipt_hex"]))
    B = base64.b64decode(receipt["payload_b64"])
    ok = True
    ok &= check("D1 B in the summary is the receipt's payload", B.hex() == d["payload_B_hex"])
    ok &= check("D1 receipt digest = SHA-256(B)", hashlib.sha256(B).hexdigest() == d["receipt_digest"]["hex"])

    ok &= check("D1 the summary carries no leaf hash (the receipt has no inclusion proof)", "leaf_hash_hex" not in d)
    ok &= check("D1 SHA-256 of the receipt bytes differs from the receipt digest",
                hashlib.sha256(bytes.fromhex(d["receipt_hex"])).hexdigest() != d["receipt_digest"]["hex"])
    env = json.loads(bytes.fromhex(d["M1_dsse"]["envelope_hex"]))
    eB = base64.b64decode(env["payload"])
    ok &= check("M1 payloadType is the receipt type", env["payloadType"] == TYPE)
    ok &= check("M1 payload is B", eB == B)
    esig = base64.b64decode(env["signatures"][0]["sig"])
    ok &= check("M1 DSSE signature bytes equal the receipt signature",
                esig == base64.b64decode(receipt["signature"]["sig"]))
    try:
        vk.verify(esig, pae(env["payloadType"], eB))
        dsse_ok = True
    except Exception:  # noqa: BLE001
        dsse_ok = False
    ok &= check("M1 DSSE verification: Ed25519 over PAE(payloadType, payload) under the issuer key", dsse_ok)

    tag = cbor2.loads(bytes.fromhex(d["M2_scitt_hash_envelope"]["cose_sign1_hex"]))
    ok &= check("M2 CBOR tag 18 (COSE_Sign1)", isinstance(tag, cbor2.CBORTag) and tag.tag == 18)
    prot_b, unprot, payload, sig = tag.value
    prot = cbor2.loads(prot_b)
    thumb = hashlib.sha256(cbor_encode({1: 1, -1: 6, -2: pub})).digest()
    ok &= check("M2 unprotected header is empty", unprot == {})
    keys_sorted = sorted(prot, key=lambda k: cbor2.dumps(k))
    ok &= check("M2 protected header keys in bytewise order of their encodings (RFC 8949 Section 4.2.1)",
                list(prot) == keys_sorted)
    ok &= check("M2 protected header bytes are the deterministic encoding of the map",
                cbor2.dumps({k: prot[k] for k in keys_sorted}) == prot_b)
    ok &= check("M2 alg -19", prot.get(1) == -19)
    ok &= check("M2 kid = RFC 9679 thumbprint of the issuer key", prot.get(4) == thumb)
    ok &= check("M2 CWT claims iss and sub present", isinstance(prot.get(15), dict) and {1, 2} <= set(prot[15]))
    ok &= check("M2 sub = the receipt's model commitment", prot[15].get(2) == json.loads(B)["model_id_commit"])
    ok &= check("M2 258 = -16 (SHA-256)", prot.get(258) == -16)
    ok &= check("M2 259 = the receipt type", prot.get(259) == TYPE)
    ok &= check("M2 payload = receipt digest", payload == hashlib.sha256(B).digest())
    tbs = cbor_encode(["Signature1", prot_b, b"", payload])
    try:
        vk.verify(sig, tbs)
        cose_ok = True
    except Exception:  # noqa: BLE001
        cose_ok = False
    ok &= check("M2 COSE signature over Sig_structure verifies under the issuer key", cose_ok)
    ok &= check("M2 ToBeSigned in the summary equals the recomputed one",
                tbs.hex() == d["M2_scitt_hash_envelope"]["to_be_signed_hex"])
    rv = json.load(open(RECEIPT_VECTORS, encoding="utf-8"))
    by_id = {v["id"]: v for v in rv["vectors"]}
    for c in d["citation_cases"]:
        cand = bytes.fromhex(by_id[c["candidate"]]["receipt_hex"])
        ok &= check("%s candidate bytes are %s of the receipts draft" % (c["id"], c["candidate"]),
                    hashlib.sha256(cand).hexdigest() == c["candidate_receipt_sha256"])
        h = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}[c["citation"]["alg"]]
        ok &= check("%s cited value is %s over B of P1" % (c["id"], c["citation"]["alg"]),
                    h(B).hexdigest() == c["citation"]["hex"])
        got = match(c["citation"], cand)
        ok &= check("%s match = %s (expected %s)" % (c["id"], got, c["expected_match"]), got == c["expected_match"])
    sys.path.insert(0, os.path.dirname(RECEIPT_VECTORS))
    pairs = [(d["receiver_pairs"][0][0], pub)]
    ok &= check("S the examples configure one pair: the issuer URI of M2 and the issuer test key",
                d["receiver_pairs"] == [[d["M2_scitt_hash_envelope"]["iss"], "issuer test key"]])
    p1 = bytes.fromhex(by_id["P1"]["receipt_hex"])
    got = check_statement(bytes.fromhex(d["M2_scitt_hash_envelope"]["cose_sign1_hex"]), p1, pub, pairs)
    ok &= check("S M2 with P1: %s (expected accepted)" % (got,), got == ("accepted", None))
    seen = {"accepted"}
    for s in d["status_vectors"]:
        stmt = bytes.fromhex(s["statement_hex"])
        cand = bytes.fromhex(by_id[s["candidate"]]["receipt_hex"])
        ok &= check("%s statement bytes match their SHA-256" % s["id"],
                    hashlib.sha256(stmt).hexdigest() == s["statement_sha256"])
        ok &= check("%s candidate bytes are %s of the receipts draft" % (s["id"], s["candidate"]),
                    hashlib.sha256(cand).hexdigest() == s["candidate_receipt_sha256"])
        got = check_statement(stmt, cand, pub, pairs)
        ok &= check("%s status %s at step %s (expected %s at step %s)" % (s["id"], got[0], got[1],
                    s["expected_status"], s["step"]), got == (s["expected_status"], s["step"]))
        seen.add(got[0])
    every = {"accepted", "malformed", "outside_profile", "untrusted_key", "signature_invalid",
             "receipt_not_verified", "digest_mismatch", "subject_mismatch"}
    ok &= check("S every status of the checking procedure has a vector", seen == every)
    s1 = next(s for s in d["status_vectors"] if s["id"] == "S1")
    ok &= check("S S1 carries alg -8 and is accepted",
                cbor2.loads(cbor2.loads(bytes.fromhex(s1["statement_hex"])).value[0])[1] == -8
                and s1["expected_status"] == "accepted")
    cp = d["certificate_profile"]
    root = bytes.fromhex(cp["root_certificate_hex"])
    leaf = bytes.fromhex(cp["leaf_certificate_hex"])
    cert_pairs = [(d["receiver_certificate_pairs"][0][0], root)]
    ok &= check("X the examples configure one certificate pair: the did:x509 issuer of X1 and the test root",
                d["receiver_certificate_pairs"] == [[cp["iss"], "test root certificate"]])
    ok &= check("X the iss of X1 names SHA-256 over the test root certificate, base64url without padding",
                DID_RE.match(cp["iss"]).group(1) == b64url(hashlib.sha256(root).digest()))
    x1 = cbor2.loads(bytes.fromhex(d["certificate_vectors"][0]["statement_hex"]))
    x1p = cbor2.loads(x1.value[0])
    ok &= check("X X1 protected labels are exactly 1, 4, 15, 33, 258, 259 (the labels of the registered form)",
                set(x1p) == CERT_LABELS and x1p[1] == -7 and list(x1p[33]) == [leaf, root])
    ok &= check("X X1 kid = SHA-256 over the DER SubjectPublicKeyInfo of the test leaf",
                x1p[4].hex() == cp["kid_hex"] == hashlib.sha256(bytes.fromhex(cp["leaf_spki_hex"])).hexdigest())
    ok &= check("X X1 payload is the receipt digest", x1.value[2] == hashlib.sha256(B).digest())
    xseen = set()
    for s in d["certificate_vectors"]:
        stmt = bytes.fromhex(s["statement_hex"])
        cand = bytes.fromhex(by_id[s["candidate"]]["receipt_hex"])
        ok &= check("%s statement bytes match their SHA-256" % s["id"],
                    hashlib.sha256(stmt).hexdigest() == s["statement_sha256"])
        got = check_statement(stmt, cand, pub, pairs, cert_pairs)
        ok &= check("%s status %s at step %s (expected %s at step %s)" % (s["id"], got[0], got[1],
                    s["expected_status"], s["step"]), got == (s["expected_status"], s["step"]))
        xseen.add(s["id"])
    ok &= check("X without the certificate pair X1 is untrusted_key at step 3",
                check_statement(bytes.fromhex(d["certificate_vectors"][0]["statement_hex"]), p1, pub, pairs, ())
                == ("untrusted_key", 3))
    ok &= check("X M2 and the status vectors keep their status when the certificate pair is configured too",
                check_statement(bytes.fromhex(d["M2_scitt_hash_envelope"]["cose_sign1_hex"]), p1, pub, pairs,
                                cert_pairs) == ("accepted", None)
                and all(check_statement(bytes.fromhex(s["statement_hex"]),
                                        bytes.fromhex(by_id[s["candidate"]]["receipt_hex"]), pub, pairs, cert_pairs)
                        == (s["expected_status"], s["step"]) for s in d["status_vectors"]))
    for r in d["reference_vectors"]:
        cand = bytes.fromhex(by_id[r["candidate"]]["receipt_hex"])
        ok &= check("%s candidate bytes are %s of the receipts draft" % (r["id"], r["candidate"]),
                    hashlib.sha256(cand).hexdigest() == r["candidate_receipt_sha256"])
        got = reference_state(r["reference_json"], cand)
        ok &= check("%s state %s, matching rule %s (expected %s, %s)" % (r["id"], got[0], got[1], r["expected_state"],
                    r["expected_match"]), got == (r["expected_state"], r["expected_match"]))
    # R14 (A.7): the bytes EF BB BF and then the bytes of R1, not a text that spells them. A reader that drops the
    # byte order mark, as json.loads does for bytes, reads R1 and gives Verified and MATCH; Section 5.1 does not.
    r14 = next((r for r in d["reference_vectors"] if r["id"] == "R14"), None)
    r14_bytes = r14["reference_json"].encode("utf-8") if r14 else b""
    ok &= check("R R14 is the bytes EF BB BF followed by the bytes of R1",
                r14_bytes == BOM_UTF8 + d["reference_vectors"][0]["reference_json"].encode("utf-8"))
    dropped = reference_state(r14_bytes.decode("utf-8-sig"), p1)
    ok &= check("R R14 with the byte order mark dropped by the reader is R1: %s, %s (Section 5.1 does not drop it)"
                % dropped, dropped == ("Verified", "MATCH"))
    t2 = next(t for t in d["transparent_vectors"] if t["id"] == "T2")
    t2v = cbor2.loads(bytes.fromhex(t2["statement_hex"])).value
    x1v = cbor2.loads(bytes.fromhex(d["certificate_vectors"][0]["statement_hex"])).value
    ok &= check("T T2 is X1 with one receipt under unprotected label 394, nothing else changed",
                list(t2v[1]) == [394] and t2v[0] == x1v[0] and t2v[2] == x1v[2] and t2v[3] == x1v[3]
                and list(t2v[1][394]) == [bytes.fromhex(d["receipt_of_t2_hex"])]
                and t2["statement_sha256"] == d["registered_x1"]["transparent_statement_sha256"])
    for s in d["transparent_vectors"]:
        stmt = bytes.fromhex(s["statement_hex"])
        cand = bytes.fromhex(by_id[s["candidate"]]["receipt_hex"])
        ok &= check("%s statement bytes match their SHA-256" % s["id"],
                    hashlib.sha256(stmt).hexdigest() == s["statement_sha256"])
        got = check_statement(stmt, cand, pub, pairs, cert_pairs)
        ok &= check("%s status %s at step %s (expected %s at step %s)" % (s["id"], got[0], got[1],
                    s["expected_status"], s["step"]), got == (s["expected_status"], s["step"]))
    # Reverse cases of the key order: a check that sorts by length first (cbor2 canonical) reads these as
    # deterministic and stops in step 2 with outside_profile.
    stmts = {"M2": d["M2_scitt_hash_envelope"]["cose_sign1_hex"], "S1": s1["statement_hex"],
             "X1": d["certificate_vectors"][0]["statement_hex"], "T2": t2["statement_hex"]}
    for name, want_sha in KEY_ORDER_CASES:
        bad = key_byte_replaced(bytes.fromhex(stmts[name]), 15, 0x2F)
        got = check_statement(bad, p1, pub, pairs, cert_pairs)
        ok &= check("K %s with key 15 of the protected header written as -16 (0x2f), not reordered: %s at step %s "
                    "(expected malformed at step 1)" % (name, got[0], got[1]),
                    got == ("malformed", 1) and hashlib.sha256(bad).hexdigest() == want_sha)
    o_x1 = DID_RE.match(cp["iss"]).group(2)
    for what, o_new, want in OID_CASES:
        bad = cbor_encode(cbor2.CBORTag(18, [cbor_encode({**x1p, 15: {1: cp["iss"][:-len(o_x1)] + o_new,
                                                                      2: x1p[15][2]}}), {}, x1.value[2], x1.value[3]]))
        got = check_statement(bad, p1, pub, pairs, cert_pairs)
        ok &= check("G X1 with O = %s (%s): %s at step %s (expected %s at step %s)" % (o_new, what, got[0], got[1],
                    want[0], want[1]), got == want and o_x1 == cp["eku"])
    m2 = bytes.fromhex(d["M2_scitt_hash_envelope"]["cose_sign1_hex"])
    for what, key_hex, value_hex, before, want in PAIR_CASES:
        bad = with_pair(m2, bytes.fromhex(key_hex), bytes.fromhex(value_hex), before)
        got = check_statement(bad, p1, pub, pairs, cert_pairs)
        ok &= check("H M2 with %s: %s at step %s (expected %s at step %s)" % (what, got[0], got[1], want[0], want[1]),
                    got == want)
    for what, value in DEPTH_CASES:
        bad = with_pair(m2, b"\x20", value, None)
        try:
            got = "%s at step %s" % check_statement(bad, p1, pub, pairs, cert_pairs)
        except ResourceLimit:
            got = "resource-limit error"
        ok &= check("L M2 with key -1 holding %s (%d bytes): %s (expected a resource-limit error, no status)"
                    % (what, len(bad), got), got == "resource-limit error")
    deep_receipt = b"[" * 60000 + b"]" * 60000
    try:
        got = "%s at step %s" % check_statement(m2, deep_receipt, pub, pairs, cert_pairs)
    except ResourceLimit:
        got = "resource-limit error"
    ok &= check("L M2 with a candidate receipt of arrays 60000 deep: %s (expected a resource-limit error in step 5, "
                "no status; the receipts draft's checker reports RESOURCE_LIMIT)" % got, got == "resource-limit error")
    # The matching rule and the typed digest reference under the same limit. A candidate whose reading stops at it has
    # no B (Section 3.3 step 2: INDETERMINATE; Section 5.1: Unresolved); a reference that nests deeper is not read.
    cit, r1 = d["citation_cases"][0]["citation"], d["reference_vectors"][0]["reference_json"]
    for what, cand, want_m, want_r, want_s in (
            ("arrays 60000 deep", ("[" * 60000 + "]" * 60000).encode(), "INDETERMINATE",
             ("Unresolved", "INDETERMINATE"), None),
            ("objects 30000 deep", ('{"a":' * 29999 + "{}" + "}" * 29999).encode(), "INDETERMINATE",
             ("Unresolved", "INDETERMINATE"), None),
            ("P1 with a key member of arrays, %d deep in all" % MAX_DEPTH, p1_with_key(p1, MAX_DEPTH), "MATCH",
             ("Verified", "MATCH"), ("receipt_not_verified", 5)),
            ("P1 with a key member of arrays, %d deep in all" % (MAX_DEPTH + 1), p1_with_key(p1, MAX_DEPTH + 1),
             "INDETERMINATE", ("Unresolved", "INDETERMINATE"), "resource-limit error")):
        got_m, got_r = match(cit, cand), reference_state(r1, cand)
        ok &= check("L C1 citation, candidate %s: match %s, R1 %s (expected %s, %s)" % (what, got_m, got_r, want_m,
                    want_r), got_m == want_m and got_r == want_r)
        if want_s is not None:
            try:
                got_s = check_statement(m2, cand, pub, pairs, cert_pairs)
            except ResourceLimit:
                got_s = "resource-limit error"
            ok &= check("L M2 with the candidate %s: %s (expected %s)" % (what, got_s, want_s), got_s == want_s)
    for what, ref_text, want in (
            ("arrays 60000 deep", "[" * 60000 + "]" * 60000, "resource-limit error"),
            ("objects 30000 deep", '{"a":' * 29999 + "{}" + "}" * 29999, "resource-limit error"),
            ("R1 with a member of arrays, %d deep in all" % MAX_DEPTH, ref_with_member(r1, MAX_DEPTH),
             ("Malformed", "MATCH")),
            ("R1 with a member of arrays, %d deep in all" % (MAX_DEPTH + 1), ref_with_member(r1, MAX_DEPTH + 1),
             "resource-limit error")):
        try:
            got = reference_state(ref_text, p1)
        except ResourceLimit:
            got = "resource-limit error"
        ok &= check("L reference %s with P1: %s (expected %s)" % (what, got, want), got == want)
    for what, ref_text in (("not JSON", "x"), ("a member name twice", '{"type":"%s","type":"%s"}' % (TYPE, TYPE)),
                           ("an array", "[]"), ("a number", "1"), ("a text", '"%s"' % TYPE), ("null", "null"),
                           ("an object without members", "{}")):
        got = reference_state(ref_text, p1)
        ok &= check("F reference that is %s with P1: %s (expected Malformed, INDETERMINATE)" % (what, got),
                    got == ("Malformed", "INDETERMINATE"))
    lim = MAX_INPUT_BYTES

    def padded(b, n):   # b followed by spaces up to n bytes
        return b + b" " * (n - len(b))

    def m2_padded(n):   # M2 with its empty unprotected map replaced by {-1: a byte string}, n bytes in all
        _, j = _decode(m2, 2)   # the offset of the unprotected map, after the protected byte string
        assert m2[j] == 0xA0
        k = n - len(m2) - 1
        while len(m2[:j] + b"\xa1\x20" + cbor_head(2, k) + bytes(k) + m2[j + 1:]) > n:
            k -= 1
        out = m2[:j] + b"\xa1\x20" + cbor_head(2, k) + bytes(k) + m2[j + 1:]
        assert len(out) == n
        return out

    def limited(f):
        try:
            return f()
        except ResourceLimit:
            return "resource-limit error"
    r1 = d["reference_vectors"][0]["reference_json"]
    for what, got, want in (
            ("C1 citation, P1 padded to the limit", match(cit, padded(p1, lim)), "MATCH"),
            ("C1 citation, P1 padded to the limit + 1", match(cit, padded(p1, lim + 1)), "INDETERMINATE"),
            ("R1, P1 padded to the limit", reference_state(r1, padded(p1, lim)), ("Verified", "MATCH")),
            ("R1, P1 padded to the limit + 1", reference_state(r1, padded(p1, lim + 1)),
             ("Unresolved", "INDETERMINATE")),
            ("R1 padded to the limit, P1", limited(lambda: reference_state(r1 + " " * (lim - len(r1)), p1)),
             ("Verified", "MATCH")),
            ("R1 padded to the limit + 1, P1", limited(lambda: reference_state(r1 + " " * (lim + 1 - len(r1)), p1)),
             "resource-limit error"),
            ("M2 of the limit, P1", limited(lambda: check_statement(m2_padded(lim), p1, pub, pairs)),
             ("outside_profile", 2)),
            ("M2 of the limit + 1, P1", limited(lambda: check_statement(m2_padded(lim + 1), p1, pub, pairs)),
             "resource-limit error"),
            ("M2, P1 padded to the limit", limited(lambda: check_statement(m2, padded(p1, lim), pub, pairs)),
             ("accepted", None)),
            ("M2, P1 padded to the limit + 1", limited(lambda: check_statement(m2, padded(p1, lim + 1), pub, pairs)),
             "resource-limit error"),
            ("C1 citation, P1 with its key as a number of 5000 digits",
             match(cit, re.sub(rb'"key":"[^"]*"', b'"key":1' + b"0" * 4999, p1, count=1)), "MATCH"),
            ("R1 with a member of 5000 digits, P1", reference_state(r1[:-1] + ',"x":1' + "0" * 4999 + "}", p1),
             ("Malformed", "MATCH"))):
        ok &= check("Z %s: %s (expected %s)" % (what, got, want), got == want)
    hex1 = json.loads(r1)["digest"]
    assert r1.count('"%s"' % hex1) == 1 and r1.count('"SHA-256"') == 1
    for what, ref_text in (
            ("digest 1 and 63 zeros", r1.replace('"%s"' % hex1, "1" + "0" * 63)),
            ("digest 1, 61 zeros and e0", r1.replace('"%s"' % hex1, "1" + "0" * 61 + "e0")),
            ("digest true", r1.replace('"%s"' % hex1, "true")),
            ("digest an array with the right text", r1.replace('"%s"' % hex1, '["%s"]' % hex1)),
            ("digest_alg an array", r1.replace('"SHA-256"', '["SHA-256"]'))):
        got = reference_state(ref_text, p1)
        ok &= check("V R1 with %s, P1: %s (expected Malformed, INDETERMINATE)" % (what, got),
                    got == ("Malformed", "INDETERMINATE"))
    for what, value in (("1 and 63 zeros", 10 ** 63), ("1e63", 1e63), ("true", True), ("an array", [hex1])):
        got = match(dict(cit, hex=value), p1)
        ok &= check("V C1 with its value %s, P1: %s (expected INDETERMINATE)" % (what, got), got == "INDETERMINATE")
    t_ = '"type":"%s"' % TYPE
    assert r1.count(t_) == 1 and r1.endswith(t_ + "}")
    for what, ref_text, want in (
            ("a byte order mark", "\ufeff" + r1, ("Malformed", "INDETERMINATE")),
            ("a member NaN", r1[:-1] + ',"x":NaN}', ("Malformed", "INDETERMINATE")),
            ("its last byte cut off", r1[:-1], ("Malformed", "INDETERMINATE")),
            ("no type", r1.replace("," + t_, ""), ("Malformed", "MATCH")),
            ("type 1", r1.replace(t_, '"type":1'), ("Malformed", "MATCH")),
            ("no digest", r1.replace('"digest":"%s",' % hex1, ""), ("Malformed", "INDETERMINATE")),
            ("digest_alg twice, the same value", r1.replace('"SHA-256"', '"SHA-256","digest_alg":"SHA-256"'),
             ("Malformed", "INDETERMINATE")),
            ("digest_alg twice, sha-256 first", r1.replace('"digest_alg"', '"digest_alg":"sha-256","digest_alg"'),
             ("Malformed", "INDETERMINATE")),
            ("type twice", r1[:-1] + "," + t_ + "}", ("Malformed", "MATCH")),
            ("purpose twice", r1.replace(t_, '"purpose":"evaluation","purpose":"evaluation",' + t_),
             ("Malformed", "MATCH")),
            ("purpose evaluation, the one optional member", r1.replace(t_, '"purpose":"evaluation",' + t_),
             ("Unresolved", "MATCH")),
            ("purpose a lone surrogate escape", r1.replace(t_, '"purpose":"\\ud800",' + t_), ("Unresolved", "MATCH")),
            ("type written as \"\\u0074ype\"", r1.replace('"type"', '"\\u0074ype"'), ("Verified", "MATCH"))):
        got = reference_state(ref_text, p1)
        ok &= check("W R1 with %s, P1: %s (expected %s)" % (what, got, want), got == want)
    print("all checks hold" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
