"""Signed Evaluation Receipts, the format of draft-gruszka-signed-evaluation-receipts-00 (EXPERIMENTAL).

A receipt is one JSON object ``{"schema", "payload_b64", "signature"}``. B, the RFC 8785 bytes of the
payload, is signed with pure Ed25519 over PAE(type, B), the DSSE pre-authentication encoding with the fixed
type ``application/eval-receipt+json``; the payload schema is ``urn:ietf:params:eval-receipt:v1``. Both
are neutral names whose registration the draft requests from IANA; the vendor-tree type and the vendor
schema URI used before 2026-10-07 are gone, and with them every earlier B and signature. The receipt
carries no inclusion proof (removed from the draft on 2026-10-03): transparency comes from registering a
receipt in an envelope, not from the receipt.

A SECOND FORMAT, NOT A REPLACEMENT. ``proofbundle/eval-claim/v0.1`` (``evalclaim.py``) stays as it is
and stays verifiable. Nothing here runs unless a caller names this format: ``emit-eval --format
eval-receipt-v1`` produces it, and ``show-eval`` reaches it only for a file whose ``schema`` is the
receipt type.

WHAT A RECEIPT PROVES. That the holder of the key the Receiver fixed signed B. A receipt does not show
that it was published or logged, that the score is true, that the run was the only run, or that the named
model was the one evaluated (the draft's Section 6).

THE PROCEDURE IS THE DRAFT'S. ``verify_signed_eval_receipt`` evaluates the eleven steps of the draft's
Section 5 in order and returns the first one that fails, so this verifier and the draft's vectors agree
on the step and not only on the verdict (``tests/test_signed_eval_receipt_conformance.py``). The
signature profile is the draft's Section 4.4, which is stricter than SPEC section 4a: a non-canonical
encoding of the key or of R, and a key or an R that is not a point of order L (a point of small or of
mixed order), are refused before the signature equation is checked. With A and R of order L the
cofactorless and the cofactored equation of RFC 8032 section 5.1.7 accept exactly the same signatures;
each signature is checked on its own, never by a batch.

A RESOURCE LIMIT IS NO VERDICT. A receipt nested deeper than this reader's limits (the interpreter's
recursion limit, unchanged) stops the procedure: the verdict says ``resource_limit``, with no step, and is
neither PASS nor the failure of a step (the draft's Section 5). The verifier still never raises.

The Rust verifier in ``tools/pb_verify_rs`` does not know this format; a receipt of it gets no verdict
there.
"""
from __future__ import annotations

import base64
import decimal
import json
import math
import re
from typing import Any, Mapping, NamedTuple, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._membership import is_member, require_switch
from ._wire_b64 import decode_b64
from .signature import plain_bytes, verify_ed25519_pinned

RECEIPT_TYPE = "application/eval-receipt+json"
PAYLOAD_SCHEMA = "urn:ietf:params:eval-receipt:v1"
COMMIT_ALG = "sha256-salted-v1"
DRAFT = "draft-gruszka-signed-evaluation-receipts-00"

__all__ = ["RECEIPT_TYPE", "PAYLOAD_SCHEMA", "COMMIT_ALG", "DRAFT", "ReceiptVerdict", "pae",
           "payload_bytes", "emit_signed_eval_receipt", "verify_signed_eval_receipt", "names_receipt_type"]

_RECEIPT_MEMBERS = frozenset({"schema", "payload_b64", "signature"})
_SIGNATURE_MEMBER_SETS = (frozenset({"alg", "sig"}), frozenset({"alg", "sig", "key"}))
_PAYLOAD_MEMBERS = frozenset({"schema", "suite", "suite_version", "metric", "comparator", "threshold",
                              "score", "passed", "n", "model_id_commit", "dataset_id_commit", "commit_alg",
                              "timestamp"})
#: The only optional Payload member (the draft's Section 3.2 and 3.5): the digest of a criteria set, with the
#: pattern of the commitments; only its form is checked.
_OPTIONAL_PAYLOAD_MEMBER = "criteria_digest"
_COMPARATORS = (">=", ">", "<=", "<")
# Table 1 of the draft: an optional minus sign, then 0 or a digit 1-9 followed by digits, then
# optionally a full stop and one or more digits. Stricter than eval-claim v0.1, which allows 00.5.
_DECIMAL_RE = re.compile(r"\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_COMMIT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_TIMESTAMP_RE = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z")
_MAX_SAFE = 2 ** 53

# RFC 8032 Section 5.1: the field prime, the group order and the curve constant d.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


class ReceiptVerdict(NamedTuple):
    """The result of the draft's Section 5: ``ok``, and for a FAIL the first failing ``step`` (1 to 11),
    for step 11 the profile ``rule`` (``"profile 3"``, ``"profile 1, key"`` ...), and a ``reason``. When the
    procedure stopped at a resource limit, ``resource_limit`` is True, ``ok`` is False and ``step`` is None:
    no verdict, neither PASS nor FAIL."""
    ok: bool
    step: Optional[int]
    rule: Optional[str]
    reason: str
    payload: Optional[bytes] = None   # B, only when ok
    resource_limit: bool = False

    @property
    def step_label(self) -> str:
        """The step as the draft's vector table writes it: ``all``, ``4`` or ``11 (profile 2, R)``, and
        ``resource limit`` for a procedure that stopped at one."""
        if self.ok:
            return "all"
        if self.resource_limit:
            return "resource limit"
        return f"{self.step} ({self.rule})" if self.rule else str(self.step)


class _Fail(Exception):
    def __init__(self, step: int, reason: str, rule: Optional[str] = None):
        super().__init__(reason)
        self.step, self.reason, self.rule = step, reason, rule


class _Limit(Exception):
    """The procedure stopped at a resource limit: no step failed, and there is no verdict."""


class _Number:
    """A JSON number as its token. B's numbers are judged by their value as RFC 8785 serializes it; the
    receipt object has no number member, so a number there fails the step that checks that member."""
    __slots__ = ("token",)

    def __init__(self, token: str):
        self.token = token

    def value(self) -> float:
        return float(self.token)


# ---- I-JSON (RFC 7493) ----------------------------------------------------------------------------
def _check_text(s: str, what: str, step: int) -> None:
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            raise _Fail(step, f"{what} contains a surrogate code point, which I-JSON forbids")
        if 0xFDD0 <= c <= 0xFDEF or (c & 0xFFFE) == 0xFFFE:
            raise _Fail(step, f"{what} contains a noncharacter, which I-JSON forbids")


def _ijson(raw: bytes, what: str, step: int) -> Any:
    """One I-JSON text: UTF-8 without a byte order mark, no duplicate member names after unescaping
    (RFC 8259 Section 8.3), no surrogate or noncharacter code point, no NaN or Infinity, and nothing
    after the text but insignificant whitespace (RFC 8259 Section 2)."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _Fail(step, f"{what} begins with a byte order mark")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _Fail(step, f"{what} is not UTF-8") from None

    def pairs(items):
        seen: dict = {}
        for name, value in items:
            _check_text(name, what, step)
            if name in seen:
                raise _Fail(step, f"{what} repeats a member name")
            seen[name] = value
        return seen

    def no_constant(name):
        raise _Fail(step, f"{what} contains {name}, which is not JSON")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=_Number, parse_float=_Number,
                           parse_constant=no_constant)
    except _Fail:
        raise
    except (RecursionError, MemoryError) as exc:
        raise _Limit(f"{what} nests deeper than this reader's limit ({type(exc).__name__})") from None
    except ValueError as exc:
        raise _Fail(step, f"{what} is not one JSON text ({type(exc).__name__})") from None

    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            _check_text(v, what, step)
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return value


# ---- RFC 8785 ---------------------------------------------------------------------------------------
def _es_number(x: float) -> str:
    """ECMAScript Number::toString of a finite double (RFC 8785 Section 3.2.2.3)."""
    if math.isnan(x) or math.isinf(x):
        raise ValueError("a number that is not finite has no RFC 8785 form")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + _es_number(-x)
    _sign, digits, exponent = decimal.Decimal(repr(x)).as_tuple()   # repr: the shortest round-trip digits
    if not isinstance(exponent, int):   # 'n', 'N' and 'F' stand for NaN and infinity, refused above
        raise ValueError("a number that is not finite has no RFC 8785 form")
    exp = exponent
    ds = "".join(map(str, digits))
    while len(ds) > 1 and ds.endswith("0"):
        ds, exp = ds[:-1], exp + 1
    k = len(ds)
    n = k + exp                      # the value is 0.ds times 10**n
    if k <= n <= 21:
        return ds + "0" * (n - k)
    if 0 < n <= 21:
        return ds[:n] + "." + ds[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + ds
    e = n - 1
    return ds[0] + ("." + ds[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c < 0x20:
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(c, "\\u%04x" % c))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(v: Any) -> str:
    """RFC 8785 of a parsed value (``_Number`` for numbers) or of a value built here (``int`` below
    2**53). Member names are sorted by their UTF-16 code units (Section 3.2.3)."""
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, _Number):
        return _es_number(v.value())
    if isinstance(v, int):
        if not -_MAX_SAFE < v < _MAX_SAFE:
            raise ValueError("an integer outside the I-JSON range has no exact RFC 8785 form")
        return str(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        names = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v[k]) for k in names) + "}"
    raise TypeError(f"a {type(v).__name__} has no RFC 8785 form here")


# ---- pieces of the procedure ---------------------------------------------------------------------
def pae(typ: str, body: bytes) -> bytes:
    """The DSSE pre-authentication encoding, as the draft's Section 4.1 defines it."""
    t = typ.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" " + str(len(body)).encode("ascii") \
        + b" " + body


def _canonical_b64(value: Any, step: int, what: str, length: Optional[int] = None) -> bytes:
    if not isinstance(value, str):
        raise _Fail(step, f"{what} is not a string")
    try:
        raw = decode_b64(value)
    except (ValueError, TypeError):
        raise _Fail(step, f"{what} is not the canonical base64 encoding of any bytes") from None
    if length is not None and len(raw) != length:
        raise _Fail(step, f"{what} does not decode to {length} bytes")
    return raw


def _valid_timestamp(s: str) -> bool:
    m = _TIMESTAMP_RE.match(s)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(x) for x in m.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return 1 <= month <= 12 and 1 <= day <= days[month - 1] and hour <= 23 and minute <= 59 and second <= 59


def _comparison_holds(score: str, comparator: str, threshold: str) -> bool:
    a, b = decimal.Decimal(score), decimal.Decimal(threshold)
    return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[comparator]


def _digest_members(p: dict) -> tuple:
    """The members with the pattern sha256: followed by 64 lowercase hexadecimal digits: the two commitments, and
    criteria_digest when present."""
    return ("model_id_commit", "dataset_id_commit") + ((_OPTIONAL_PAYLOAD_MEMBER,) if _OPTIONAL_PAYLOAD_MEMBER in p
                                                       else ())


def _payload_violation(p: Any) -> Optional[str]:
    """Step 6: the member set and every row of Table 1, or None."""
    if not isinstance(p, dict):
        return "the payload is not a JSON object"
    if set(p) - {_OPTIONAL_PAYLOAD_MEMBER} != _PAYLOAD_MEMBERS:
        # Only our own names are rendered; the Issuer's extra names are counted, never printed or sorted.
        missing = [name for name in sorted(_PAYLOAD_MEMBERS) if name not in p]
        extra = sum(1 for name in p if not is_member(name, _PAYLOAD_MEMBERS | {_OPTIONAL_PAYLOAD_MEMBER}))
        return f"the payload member set differs from Table 1 (missing {missing}, {extra} extra)"
    if p["schema"] != PAYLOAD_SCHEMA:
        return "the payload schema is not " + PAYLOAD_SCHEMA
    for name in ("suite", "suite_version", "metric"):
        if not isinstance(p[name], str) or p[name] == "":
            return f"{name} is not a non-empty string"
    if not isinstance(p["comparator"], str) or p["comparator"] not in _COMPARATORS:
        return "comparator is not one of >=, >, <=, <"
    for name in ("threshold", "score"):
        if not isinstance(p[name], str) or not _DECIMAL_RE.match(p[name]):
            return f"{name} is not a decimal string"
    if not isinstance(p["passed"], bool):
        return "passed is not true or false"
    n = p["n"]
    if not isinstance(n, _Number) or not (n.value().is_integer() and 1 <= n.value() < _MAX_SAFE):
        return "n is not an integer from 1 to 2^53 - 1"
    for name in _digest_members(p):
        if not isinstance(p[name], str):
            return f"{name} is not a string"
    if p["commit_alg"] != COMMIT_ALG:
        return "commit_alg is not " + COMMIT_ALG
    if not isinstance(p["timestamp"], str) or not _valid_timestamp(p["timestamp"]):
        return "timestamp is not YYYY-MM-DDTHH:MM:SSZ with a valid date and time"
    return None


def _decode_point(enc: bytes) -> Optional[tuple]:
    """RFC 8032 Section 5.1.3 decoding of a 32-byte point; None when it fails: y not below p, no
    square root, or x = 0 with the sign bit set. Point decoding only; the equation of rule 4 is
    checked by the library."""
    v = int.from_bytes(enc, "little")
    y, sign = v & ((1 << 255) - 1), v >> 255
    if y >= _P:
        return None
    u = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if u == 0:
        return None if sign else (0, y)
    x = pow(u, (_P + 3) // 8, _P)
    if (x * x - u) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - u) % _P:
        return None
    return (_P - x if (x & 1) != sign else x, y)


def _has_order_l(point: tuple) -> bool:
    """Rule 2 of the draft's Section 4.4 for a decoded point (x, y): it is not the neutral element and L times
    it is, so it lies in the subgroup of prime order L. A point of small order (8 times it is the neutral
    element) and a point of mixed order (a point of order L plus one of small order) are both refused."""
    x, y = point
    if x == 0 and y == 1:
        return False
    acc, base, n = (0, 1, 1, 0), (x, y, 1, x * y % _P), _L
    while n:
        if n & 1:
            acc = _edwards_add(acc, base)
        base, n = _edwards_add(base, base), n >> 1
    return acc[0] % _P == 0 and (acc[1] - acc[2]) % _P == 0


def _edwards_add(p: tuple, q: tuple) -> tuple:
    """Addition in extended coordinates (RFC 8032 section 5.1.4)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _profile(key: bytes, sig: bytes, message: bytes) -> None:
    """The verification profile of the draft's Section 4.4, rules in order; raises _Fail(11, ...)."""
    a_point, r_point = _decode_point(key), _decode_point(sig[:32])
    if a_point is None:
        raise _Fail(11, "the verification key is not a canonical encoding", "profile 1, key")
    if r_point is None:
        raise _Fail(11, "R is not a canonical encoding", "profile 1, R")
    if not _has_order_l(a_point):
        raise _Fail(11, "the verification key is not a point of order L", "profile 2, key")
    if not _has_order_l(r_point):
        raise _Fail(11, "R is not a point of order L", "profile 2, R")
    if int.from_bytes(sig[32:], "little") >= _L:
        raise _Fail(11, "S is not below L", "profile 3")
    # Rule 4. With A and R canonical and S below L, the library's check (it recomputes S*B' - k*A and
    # compares its encoding with the received R) is the cofactorless equation, because a canonical
    # encoding names exactly one point. With A and R of order L it accepts the same signatures as the
    # cofactored equation. The key is a trust anchor the Receiver fixed, so the call goes through the
    # pinned verify (SPEC 4b); after rules 1 and 2 its refusals can no longer apply, and the verdict is
    # the library's.
    if not verify_ed25519_pinned(key, sig, message):
        raise _Fail(11, "the cofactorless equation does not hold", "profile 4")


def _procedure(receipt: bytes, key: bytes) -> bytes:
    """Steps 1 to 11 of the draft's Section 5; returns B, raises _Fail at the first failing step."""
    r = _ijson(receipt, "the receipt", 1)
    if not isinstance(r, dict) or set(r) != _RECEIPT_MEMBERS:
        raise _Fail(1, "the receipt is not an object with exactly schema, payload_b64, signature")
    if not isinstance(r["signature"], dict) or frozenset(r["signature"]) not in _SIGNATURE_MEMBER_SETS:
        raise _Fail(1, "signature is not an object with exactly alg and sig, or alg, sig and key")
    if r["schema"] != RECEIPT_TYPE:                                                  # step 2
        raise _Fail(2, "schema is not " + RECEIPT_TYPE)
    b = _canonical_b64(r["payload_b64"], 3, "payload_b64")                            # step 3
    payload = _ijson(b, "B", 4)                                                       # step 4
    if not isinstance(payload, dict):
        raise _Fail(4, "B is not a JSON object")
    try:
        own = _jcs(payload).encode("utf-8")
    except (ValueError, TypeError):
        own = None
    except (RecursionError, MemoryError) as exc:
        raise _Limit(f"B nests deeper than its RFC 8785 serialization can follow here ({type(exc).__name__})") \
            from None
    if own != b:                                                                      # step 5
        raise _Fail(5, "B is not the RFC 8785 serialization of its own value")
    violation = _payload_violation(payload)                                           # step 6
    if violation:
        raise _Fail(6, violation)
    for name in _digest_members(payload):                                             # step 7
        if not _COMMIT_RE.match(payload[name]):
            raise _Fail(7, f"{name} is not sha256: followed by 64 lowercase hexadecimal digits")
    if payload["passed"] != _comparison_holds(payload["score"], payload["comparator"],
                                              payload["threshold"]):                  # step 8
        raise _Fail(8, "passed differs from the comparison of score with threshold")
    sig = r["signature"]
    if sig["alg"] != "ed25519":                                                       # step 9
        raise _Fail(9, "signature.alg is not ed25519")
    sig_bytes = _canonical_b64(sig["sig"], 9, "signature.sig", 64)
    if "key" in sig:                                                                  # step 10
        hint = _canonical_b64(sig["key"], 10, "signature.key", 32)
        if hint != key:
            raise _Fail(10, "the key hint is not the verification key")
    _profile(key, sig_bytes, pae(RECEIPT_TYPE, b))                                    # step 11
    return b


# ---- public surface ---------------------------------------------------------------------------------
def verify_signed_eval_receipt(receipt: bytes, key: bytes) -> ReceiptVerdict:
    """Verify receipt BYTES under the verification KEY the Receiver fixed (32 raw bytes), by the draft's
    Section 5. Never raises. Each argument is read once, as the bytes it stores
    (``signature.plain_bytes``): a receipt that is no bytes value fails at step 1, a key that is no
    32-byte value fails rule 1 of the profile (its decoding cannot succeed). A receipt that stops the
    procedure at a resource limit gets a verdict with ``resource_limit`` True and no step: it is neither
    PASS nor FAIL, and a caller that reads only ``ok`` refuses it."""
    raw, pin = plain_bytes(receipt), plain_bytes(key)
    if raw is None:
        return ReceiptVerdict(False, 1, None, "the receipt is not a bytes value")
    if pin is None or len(pin) != 32:
        return ReceiptVerdict(False, 11, "profile 1, key", "the verification key is not 32 bytes")
    try:
        b = _procedure(raw, pin)
    except _Fail as f:
        return ReceiptVerdict(False, f.step, f.rule, f.reason)
    except _Limit as limit:
        return ReceiptVerdict(False, None, None, f"stopped at a resource limit: {limit}", resource_limit=True)
    except (RecursionError, MemoryError) as exc:
        return ReceiptVerdict(False, None, None, f"stopped at a resource limit ({type(exc).__name__})",
                              resource_limit=True)
    return ReceiptVerdict(True, None, None, "every step of Section 5 succeeds", b)


def payload_bytes(payload: Mapping) -> bytes:
    """B for a payload given as a dict of str, bool and int: its RFC 8785 bytes, after the payload has
    passed steps 4 to 8 as a Receiver would apply them. Raises ValueError naming the first violation."""
    if not isinstance(payload, Mapping):
        raise ValueError("the payload must be a JSON object")
    plain = {}
    for name, value in payload.items():
        if type(name) is not str:
            raise ValueError("payload member names must be strings")
        if isinstance(value, bool) or type(value) in (str, int):
            plain[name] = value
        else:
            raise ValueError(f"payload member {name!r} has a type Table 1 does not allow")
    try:
        b = _jcs(plain).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise ValueError(str(exc)) from None
    try:
        parsed = _ijson(b, "B", 4)
        violation = _payload_violation(parsed)
        if violation:
            raise _Fail(6, violation)
        for name in _digest_members(parsed):
            if not _COMMIT_RE.match(parsed[name]):
                raise _Fail(7, f"{name} is not sha256: followed by 64 lowercase hexadecimal digits")
        if parsed["passed"] != _comparison_holds(parsed["score"], parsed["comparator"], parsed["threshold"]):
            raise _Fail(8, "passed differs from the comparison of score with threshold")
    except _Fail as f:
        raise ValueError(f"the payload fails step {f.step}: {f.reason}") from None
    except _Limit as limit:
        raise ValueError(f"the payload stops at a resource limit: {limit}") from None
    return b


def emit_signed_eval_receipt(payload: Mapping, signer: Ed25519PrivateKey, *, key_hint: bool = True) -> bytes:
    """The receipt bytes for PAYLOAD, signed by SIGNER. The receipt object is written in its RFC 8785 form. The bytes are verified under the signer's key before they are
    returned, so this producer never hands out a receipt its own verifier refuses."""
    # The switch first: it changes what is published (the unsigned key hint), so only an exact bool is
    # read, before anything is computed or signed (`_membership.require_switch`).
    require_switch(key_hint, "key_hint")
    if not isinstance(signer, Ed25519PrivateKey):
        raise TypeError("signer must be an Ed25519PrivateKey")
    b = payload_bytes(payload)
    pub = signer.public_key().public_bytes_raw()
    signature = {"alg": "ed25519", "sig": base64.b64encode(signer.sign(pae(RECEIPT_TYPE, b))).decode("ascii")}
    if key_hint:
        signature["key"] = base64.b64encode(pub).decode("ascii")
    receipt = {
        "schema": RECEIPT_TYPE,
        "payload_b64": base64.b64encode(b).decode("ascii"),
        "signature": signature,
    }
    out = _jcs(receipt).encode("utf-8")
    verdict = verify_signed_eval_receipt(out, pub)
    if not verdict.ok:
        raise ValueError(f"the emitted receipt fails its own verification at step {verdict.step_label}: "
                         f"{verdict.reason}")
    return out


def names_receipt_type(raw: bytes) -> bool:
    """True when RAW reads as a JSON object whose schema, after unescaping, is the receipt type. A
    dispatch question only, asked leniently (a byte order mark, bytes that are not UTF-8, trailing data
    and a repeated name do not hide the schema), so that such a file reaches the receipt procedure and
    fails there at the step the draft names, or stops there at a resource limit, instead of being judged
    as another format. A receipt too deep for the JSON decoder is still told apart: its top-level members
    are then read without recursion. It vouches for nothing."""
    if type(raw) is not bytes:
        return False
    text, start = _dispatch_text(raw)
    try:
        obj, _end = json.JSONDecoder().raw_decode(text, start)
    except ValueError:
        return False
    except (RecursionError, MemoryError):
        return _names_receipt_type_by_scan(text, start)
    return isinstance(obj, dict) and obj.get("schema") == RECEIPT_TYPE


def _names_receipt_type_before_cut(raw: bytes) -> bool:
    """``names_receipt_type`` for RAW, the first bytes of a longer file cut at a size limit: the schema is
    looked for among the top-level members before the cut. For the dispatch of a file that is too large
    to read; never raises."""
    if type(raw) is not bytes:
        return False
    return _names_receipt_type_by_scan(*_dispatch_text(raw))


def _dispatch_text(raw: bytes) -> tuple:
    """RAW as the text the dispatch reads (a byte order mark dropped, bytes that are not UTF-8 replaced),
    and the offset after its leading white space."""
    data = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
    text = data.decode("utf-8", errors="replace")
    return text, len(text) - len(text.lstrip(" \t\n\r"))


def _names_receipt_type_by_scan(text: str, start: int) -> bool:
    try:
        return _schema_by_scan(text, start) == RECEIPT_TYPE
    except (ValueError, RecursionError, MemoryError):
        return False


#: The characters a skipped JSON value is walked by: string quotes, brackets and the member separator.
_STRUCTURAL = re.compile(r'["\[\]{},]')


def _string_end(text: str, i: int) -> int:
    """The offset after the JSON string that opens at TEXT[I] (a quote), or -1 when it does not close."""
    j = i + 1
    while True:
        q = text.find('"', j)
        if q < 0:
            return -1
        k = q - 1
        while k > i and text[k] == "\\":
            k -= 1
        if (q - 1 - k) % 2 == 0:
            return q + 1
        j = q + 1


def _schema_by_scan(text: str, start: int) -> Any:
    """The value of the last top-level member named "schema" of the JSON object that opens at START, read
    without recursion: a nested value is skipped by counting brackets outside strings, and only a member
    name or a string value goes through the JSON decoder, which needs no depth for it. None when the text
    is no such object, or breaks off, before such a member with a string value; a later member "schema"
    whose value is no string makes it None again, as the decoder's last value would. For the dispatch only."""
    n = len(text)
    if start >= n or text[start] != "{":
        return None
    found: Any = None
    i = start + 1
    while True:
        while i < n and text[i] in " \t\n\r":
            i += 1
        if i >= n or text[i] != '"':
            return found
        end = _string_end(text, i)
        if end < 0:
            return found
        name = json.loads(text[i:end])
        i = end
        while i < n and text[i] in " \t\n\r":
            i += 1
        if i >= n or text[i] != ":":
            return found
        i += 1
        while i < n and text[i] in " \t\n\r":
            i += 1
        if i < n and text[i] == '"':
            end = _string_end(text, i)
            if end < 0:
                return found
            if name == "schema":
                found = json.loads(text[i:end])
            i = end
        else:
            if name == "schema":
                found = None
            depth = 0
            while True:
                m = _STRUCTURAL.search(text, i)
                if m is None:
                    return found
                i, c = m.start(), m.group()
                if c == '"':
                    end = _string_end(text, i)
                    if end < 0:
                        return found
                    i = end
                elif c in "[{":
                    depth += 1
                    i += 1
                elif depth and c in "]}":
                    depth -= 1
                    i += 1
                elif depth and c == ",":
                    i += 1
                else:
                    break
        while i < n and text[i] in " \t\n\r":
            i += 1
        if i < n and text[i] == ",":
            i += 1
            continue
        return found
