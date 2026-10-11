#!/usr/bin/env python3
"""Verifier for Signed Evaluation Receipts (draft-gruszka-signed-evaluation-receipts-01), second
implementation by the generator's author. It does not import the generator. It verifies the receipt
BYTES with the procedure of the draft, step by step in order, and reports the first failing step; the
Ed25519 profile is pure Python (RFC 8032 Section 5.1 decoding, A and R of order L, S < L, cofactorless
equation). Step 5 uses the full RFC 8785 serialization, including the ECMAScript number form.

For comparison it also asks pyca/cryptography (OpenSSL) for the bare Ed25519 verdict on each vector and
prints it; that column is a measurement, not part of the verdict.

Steps 1 and 4 read arrays and objects nested at most MAX_DEPTH (64) deep; deeper input gives RESOURCE_LIMIT, the
resource-limit error of Section 5, neither PASS nor FAIL. LIMIT_CASES hold that and the limit itself.

Usage: check_receipts.py [vectors.json]  -> exit 0 when every vector and every limit case meets its expected verdict
and step.
"""
import base64
import decimal
import hashlib
import json
import math
import re
import sys

MEDIA_TYPE = "application/vnd.signed-evidence.eval-receipt+json"
TYPE = MEDIA_TYPE
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"
COMMIT_ALG = "sha256-salted-v1"
PAYLOAD_MEMBERS = {"schema", "suite", "suite_version", "metric", "comparator", "threshold", "score",
                   "passed", "n", "model_id_commit", "dataset_id_commit", "commit_alg", "timestamp"}
OPTIONAL_PAYLOAD_MEMBER = "criteria_digest"   # the only optional Payload member
COMMIT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
DECIMAL_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?\Z")
TS_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z")
B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


class Fail(Exception):
    def __init__(self, step, reason):
        super().__init__(reason)
        self.step, self.reason = step, reason


class ResourceLimit(Exception):
    """This Receiver stopped at one of its limits: Section 5 makes that a resource-limit error, neither PASS nor the
    FAIL of a step."""

    def __init__(self, step, reason):
        super().__init__(reason)
        self.step, self.reason = step, reason


#: The deepest nesting of arrays and objects that steps 1 and 4 read; a top-level array or object is depth 1. The
#: depth is measured before the text is parsed, as Section 8 allows ("before and during processing").
MAX_DEPTH = 64
_STRUCTURE = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]', re.S)


def _nesting(text, what, step):
    """Raise ResourceLimit when text nests arrays and objects deeper than MAX_DEPTH (brackets inside strings skipped)."""
    depth = 0
    for m in _STRUCTURE.finditer(text):
        c = m.group()
        if c in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ResourceLimit(step, "%s nests arrays and objects deeper than %d" % (what, MAX_DEPTH))
        elif c in "]}":
            depth -= 1


# ---- Ed25519, RFC 8032 Section 5.1 --------------------------------------------------------------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _dec(b):
    """RFC 8032 Section 5.1.3 decoding; None when it fails (y >= p, x = 0 with sign bit 1, not on curve)."""
    v = int.from_bytes(b, "little")
    y, s = v & ((1 << 255) - 1), v >> 255
    if y >= P:
        return None
    u = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if u == 0:
        if s:
            return None
        x = 0
    else:
        x = pow(u, (P + 3) // 8, P)
        if (x * x - u) % P:
            x = x * SQRT_M1 % P
        if (x * x - u) % P:
            return None
        if (x & 1) != s:
            x = P - x
    return (x, y, 1, x * y % P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    E = 2 * a[2] * b[2] % P
    e, f, g, h = B - A, E - C, E + C, B + A
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(k, pt):
    q = (0, 1, 1, 0)
    while k:
        if k & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        k >>= 1
    return q


def _eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


_ID = (0, 1, 1, 0)
_GY = 4 * pow(5, P - 2, P) % P
_G = _dec(_GY.to_bytes(32, "little"))


def profile_verify(pub: bytes, msg: bytes, sig: bytes):
    """Section 4.4: raises Fail(11, ...) naming the first rule that fails."""
    A, R = _dec(pub), _dec(sig[:32])
    if A is None:
        raise Fail("11 (profile 1, key)", "the verification key is not a canonical encoding")
    if R is None:
        raise Fail("11 (profile 1, R)", "R is not a canonical encoding")
    # rule 2: order L, that is L times the point is the neutral element and the point is not
    if _eq(A, _ID) or not _eq(_mul(L, A), _ID):
        raise Fail("11 (profile 2, key)", "the verification key is not a point of order L")
    if _eq(R, _ID) or not _eq(_mul(L, R), _ID):
        raise Fail("11 (profile 2, R)", "R is not a point of order L")
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        raise Fail("11 (profile 3)", "S is not below L")
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    if not _eq(_mul(S, _G), _add(R, _mul(k, A))):
        raise Fail("11 (profile 4)", "the cofactorless equation does not hold")


def openssl_verdict(pub, msg, sig):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return "n/a"
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return "accept"
    except InvalidSignature:
        return "reject"
    except Exception as exc:  # noqa: BLE001 - a key the library refuses to load
        return "reject (%s)" % type(exc).__name__


# ---- I-JSON parsing (RFC 8259, RFC 7493) -----------------------------------------------------------
class Num:
    """A JSON number with its token as written; value is the IEEE 754 double (RFC 8785 reads numbers so)."""

    def __init__(self, token):
        self.token, self.value = token, float(token)


def _check_string(s, what, step):
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            raise Fail(step, "%s contains a surrogate code point, which I-JSON forbids" % what)
        if 0xFDD0 <= c <= 0xFDEF or (c & 0xFFFE) == 0xFFFE:
            raise Fail(step, "%s contains a noncharacter, which I-JSON forbids" % what)


def ijson(b: bytes, what: str, step):
    """One I-JSON text: UTF-8 without BOM, no duplicate names (after unescaping), no surrogates or
    noncharacters, nothing before or after the text but whitespace, no NaN or Infinity literals. Nesting deeper
    than MAX_DEPTH raises ResourceLimit before the text is parsed."""
    if b.startswith(b"\xef\xbb\xbf"):
        raise Fail(step, "%s begins with a byte order mark" % what)
    try:
        text = b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Fail(step, "%s is not UTF-8" % what)
    _nesting(text, what, step)

    def pairs(items):
        seen = {}
        for k, v in items:
            _check_string(k, what, step)
            if k in seen:
                raise Fail(step, "%s repeats the member name %r" % (what, k))
            seen[k] = v
        return seen

    def bad_constant(name):
        raise Fail(step, "%s contains %s, which is not JSON" % (what, name))

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=Num, parse_float=Num,
                           parse_constant=bad_constant)
    except Fail:
        raise
    except ValueError as exc:
        raise Fail(step, "%s is not one JSON text: %s" % (what, exc))

    def walk(v):
        if isinstance(v, str):
            _check_string(v, what, step)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(value)
    return value


# ---- RFC 8785, in full -----------------------------------------------------------------------------
def _es_number(x: float) -> str:
    """ECMAScript Number::toString for a finite double (RFC 8785 Section 3.2.2.3)."""
    if math.isnan(x) or math.isinf(x):
        raise ValueError("not finite")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + _es_number(-x)
    _sign, dig, e = decimal.Decimal(repr(x)).as_tuple()   # repr gives the shortest round-trip digits
    ds = "".join(map(str, dig))
    while len(ds) > 1 and ds.endswith("0"):
        ds, e = ds[:-1], e + 1
    k = len(ds)
    n = k + e                       # value = 0.ds * 10^n
    if k <= n <= 21:
        return ds + "0" * (n - k)
    if 0 < n <= 21:
        return ds[:n] + "." + ds[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + ds
    exp = n - 1
    return ds[0] + ("." + ds[1:] if k > 1 else "") + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))


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


def jcs(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, Num):
        return _es_number(v.value)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))   # UTF-16 code units (Section 3.2.3)
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


# ---- the other checks ------------------------------------------------------------------------------
def canonical_b64(s, step, what, length=None):
    if not isinstance(s, str):
        raise Fail(step, "%s is not a string" % what)
    if not B64_RE.match(s):
        raise Fail(step, "%s is not base64 with padding" % what)
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode("ascii") != s:
        raise Fail(step, "%s is not the canonical base64 encoding" % what)
    if length is not None and len(raw) != length:
        raise Fail(step, "%s does not decode to %d bytes" % (what, length))
    return raw


def pae(typ: str, body: bytes) -> bytes:
    t = typ.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def _is_int(v, lo, hi):
    return isinstance(v, Num) and v.value.is_integer() and lo <= v.value < hi


def _valid_timestamp(s):
    m = TS_RE.match(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(x) for x in m.groups())
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= mo <= 12 and 1 <= d <= days[mo - 1] and h <= 23 and mi <= 59 and se <= 59


def holds(score, comparator, threshold):
    a, b = decimal.Decimal(score), decimal.Decimal(threshold)
    return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[comparator]


def verify(receipt_bytes: bytes, key: bytes):
    """Return ("PASS", "all", "ok"), ("FAIL", step, reason) or ("RESOURCE_LIMIT", step, reason). key: the
    receiver-fixed 32-byte key."""
    try:
        # 1
        r = ijson(receipt_bytes, "the receipt", "1")
        if not isinstance(r, dict) or set(r) != {"schema", "payload_b64", "signature"}:
            raise Fail("1", "the receipt members are not exactly schema, payload_b64, signature")
        s = r["signature"]
        if not isinstance(s, dict) or set(s) not in ({"alg", "sig"}, {"alg", "sig", "key"}):
            raise Fail("1", "the signature members are not alg and sig, or alg, sig and key")
        # 2
        if r["schema"] != MEDIA_TYPE:
            raise Fail("2", "the receipt schema is not the receipt media type")
        # 3
        B = canonical_b64(r["payload_b64"], "3", "payload_b64")
        # 4
        p = ijson(B, "B", "4")
        if not isinstance(p, dict):
            raise Fail("4", "B is not a JSON object")
        # 5
        try:
            own = jcs(p).encode("utf-8")
        except ValueError:   # a number with no finite double has no RFC 8785 form
            own = None
        if own != B:
            raise Fail("5", "B is not the RFC 8785 serialization of the parsed payload")
        # 6
        if set(p) - {OPTIONAL_PAYLOAD_MEMBER} != PAYLOAD_MEMBERS:
            raise Fail("6", "the payload members are not exactly those of Table 1")
        if p["schema"] != PAYLOAD_SCHEMA:
            raise Fail("6", "the payload schema is not the payload schema URI")
        if p["commit_alg"] != COMMIT_ALG:
            raise Fail("6", "commit_alg is not sha256-salted-v1")
        for f in ("suite", "suite_version", "metric"):
            if not isinstance(p[f], str) or not p[f]:
                raise Fail("6", "%s is not a non-empty string" % f)
        if p["comparator"] not in (">=", ">", "<=", "<"):
            raise Fail("6", "comparator is not one of >=, >, <=, <")
        for f in ("threshold", "score"):
            if not isinstance(p[f], str) or not DECIMAL_RE.match(p[f]):
                raise Fail("6", "%s is not a decimal string" % f)
        if not isinstance(p["passed"], bool):
            raise Fail("6", "passed is not a boolean")
        if not _is_int(p["n"], 1, 2 ** 53):
            raise Fail("6", "n is not an integer from 1 to 2^53 - 1")
        for f in ("model_id_commit", "dataset_id_commit") + ((OPTIONAL_PAYLOAD_MEMBER,) if OPTIONAL_PAYLOAD_MEMBER in p else ()):
            if not isinstance(p[f], str):
                raise Fail("6", "%s is not a string" % f)
        if not isinstance(p["timestamp"], str) or not _valid_timestamp(p["timestamp"]):
            raise Fail("6", "timestamp is not a valid YYYY-MM-DDTHH:MM:SSZ")
        # 7
        for f in ("model_id_commit", "dataset_id_commit") + ((OPTIONAL_PAYLOAD_MEMBER,) if OPTIONAL_PAYLOAD_MEMBER in p else ()):
            if not COMMIT_RE.match(p[f]):
                raise Fail("7", "%s does not have the pattern sha256: followed by 64 lowercase hex digits" % f)
        # 8
        if p["passed"] != holds(p["score"], p["comparator"], p["threshold"]):
            raise Fail("8", "passed does not equal the comparison of score with threshold")
        # 9
        if s["alg"] != "ed25519":
            raise Fail("9", "signature.alg is not ed25519")
        sig = canonical_b64(s["sig"], "9", "signature.sig", 64)
        # 10
        if "key" in s and canonical_b64(s["key"], "10", "signature.key", 32) != key:
            raise Fail("10", "the key hint is not the verification key")
        # 11
        profile_verify(key, pae(TYPE, B), sig)
    except Fail as exc:
        return "FAIL", exc.step, exc.reason
    except ResourceLimit as exc:
        return "RESOURCE_LIMIT", exc.step, exc.reason
    return "PASS", "all", "ok"


def _deep(kind, n):
    """n nested arrays, or n nested objects with the one member name "a"."""
    return "[" * n + "]" * n if kind == "array" else '{"a":' * (n - 1) + "{}" + "}" * (n - 1)


def _receipt_of(b: bytes) -> bytes:
    """A receipt that carries b as B, with a signature of 64 zero bytes (steps 1 to 4 come before the signature)."""
    return ('{"payload_b64":"%s","schema":"%s","signature":{"alg":"ed25519","sig":"%s"}}'
            % (base64.b64encode(b).decode("ascii"), MEDIA_TYPE, base64.b64encode(bytes(64)).decode("ascii"))).encode()


#: (what, receipt bytes, expected verdict, expected step): nesting past MAX_DEPTH and the limit itself
LIMIT_CASES = [
    ("receipt: arrays 60000 deep", _deep("array", 60000).encode(), "RESOURCE_LIMIT", "1"),
    ("receipt: objects 30000 deep", _deep("object", 30000).encode(), "RESOURCE_LIMIT", "1"),
    ("B: arrays 60000 deep", _receipt_of(_deep("array", 60000).encode()), "RESOURCE_LIMIT", "4"),
    ("B: objects 30000 deep", _receipt_of(_deep("object", 30000).encode()), "RESOURCE_LIMIT", "4"),
    ("receipt: arrays MAX_DEPTH deep, read", _deep("array", MAX_DEPTH).encode(), "FAIL", "1"),
    ("receipt: arrays MAX_DEPTH + 1 deep", _deep("array", MAX_DEPTH + 1).encode(), "RESOURCE_LIMIT", "1"),
    ("B: objects MAX_DEPTH deep, read", _receipt_of(_deep("object", MAX_DEPTH).encode()), "FAIL", "6"),
    ("B: objects MAX_DEPTH + 1 deep", _receipt_of(_deep("object", MAX_DEPTH + 1).encode()), "RESOURCE_LIMIT", "4"),
]


def main():
    doc = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json", encoding="utf-8"))
    bad = []
    print("%-4s %-34s %-6s %-6s %-20s %-20s %s" % ("id", "requirement", "expect", "got", "step", "openssl-bare",
                                                    "reason"))
    for v in doc["vectors"]:
        rb = bytes.fromhex(v["receipt_hex"])
        key = base64.b64decode(v["verification_key_b64"])
        got, step, reason = verify(rb, key)
        try:
            j = json.loads(rb.decode("utf-8-sig"))
            ossl = openssl_verdict(key, pae(TYPE, bytes.fromhex(v["payload_hex"])),
                                   base64.b64decode(j["signature"]["sig"]))
        except Exception:  # noqa: BLE001 - the comparison column is best effort
            ossl = "n/a"
        if got != v["expected"] or step != v["step"]:
            bad.append(v["id"])
        print("%-4s %-34s %-6s %-6s %-20s %-20s %s" % (v["id"], v["requirement"], v["expected"], got, step, ossl,
                                                        reason))
    key = base64.b64decode(doc["vectors"][0]["verification_key_b64"])
    for what, rb, expected, exp_step in LIMIT_CASES:
        got, step, reason = verify(rb, key)
        if (got, step) != (expected, exp_step):
            bad.append(what)
        print("%-4s %-34s %-6s %-6s %-20s %-20s %s" % ("L", what[:34], expected[:6], got[:6], step, "n/a", reason))
    if bad:
        print("UNEXPECTED:", bad)
        sys.exit(1)
    print("all %d vectors and %d limit cases meet their expected verdict and step" % (len(doc["vectors"]),
                                                                                     len(LIMIT_CASES)))


if __name__ == "__main__":
    main()
