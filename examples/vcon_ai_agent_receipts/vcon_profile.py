"""Shared helpers of the vCon decision receipt example: strict JSON, RFC 8785, base64, time, a small
deterministic CBOR codec, COSE_Sign1 (RFC 9052) with EdDSA, and the JWS General JSON Serialization
(RFC 7515) with EdDSA (RFC 8037) that the signed form of vCon core uses.

Standard library plus cryptography and rfc8785, which proofbundle depends on anyway.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re

import rfc8785

PT_DECISION = "https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1"
INTOTO = "application/vnd.in-toto+json"
VCON_MEDIA = "application/vcon"
DATE_RX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$")


def strict_json(b: bytes):
    """Parse UTF-8 JSON text; refuse a byte order mark, duplicate member names, NaN and infinities."""
    def pairs(p):
        d = {}
        for k, v in p:
            if k in d:
                raise ValueError("duplicate member " + k)
            d[k] = v
        return d

    def const(c):
        raise ValueError("constant " + c)

    if b.startswith(b"\xef\xbb\xbf"):
        raise ValueError("byte order mark")
    return json.loads(b.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=const)


def jcs(v) -> bytes:
    return rfc8785.dumps(v)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("not unpadded base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(b) != s:
        raise ValueError("base64url not canonical")
    return b


def b64_dec(s: str) -> bytes:
    b = base64.b64decode(s, validate=True)
    if base64.b64encode(b).decode() != s:
        raise ValueError("base64 not canonical")
    return b


def when(s) -> datetime.datetime:
    """An RFC 3339 date-time (the Date type of vCon core) as an aware UTC datetime, at most six fraction digits."""
    m = DATE_RX.match(s) if isinstance(s, str) else None
    if not m:
        raise ValueError("not an RFC 3339 date-time: %r" % (s,))
    y, mo, d, h, mi, se, frac, tz = m.groups()
    if frac is not None and len(frac) > 6:
        raise ValueError("more than six fraction digits: %r" % s)
    t = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), int((frac or "0").ljust(6, "0")),
                          tzinfo=datetime.timezone.utc)
    if tz not in ("Z", "z"):
        sign = 1 if tz[0] == "+" else -1
        t -= sign * datetime.timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))
    return t


def iso(t: datetime.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S") + (".%06d" % t.microsecond if t.microsecond else "") + "Z"


# ---------------------------------------------------------------- CBOR, deterministic (RFC 8949, 4.2.1)
class Tag:
    def __init__(self, tag: int, value):
        self.tag, self.value = tag, value

    def __eq__(self, other):
        return isinstance(other, Tag) and (self.tag, self.value) == (other.tag, other.value)


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("integer too large")


def cbor_encode(v) -> bytes:
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor_encode(k), cbor_encode(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + cbor_encode(v.value)
    raise TypeError("cannot encode %s" % type(v).__name__)


def cbor_decode(b: bytes):
    """Decode one CBOR item and require that it is the whole input and in deterministic encoding."""
    v, i = _dec(b, 0)
    if i != len(b):
        raise ValueError("trailing bytes after the CBOR item")
    if cbor_encode(v) != b:
        raise ValueError("not in deterministic CBOR encoding")
    return v


def _dec(b: bytes, i: int):
    if i >= len(b):
        raise ValueError("truncated CBOR")
    ib = b[i]
    major, ai = ib >> 5, ib & 31
    i += 1
    if major == 7:
        if ai in (20, 21, 22):
            return {20: False, 21: True, 22: None}[ai], i
        raise ValueError("unsupported simple value or float")
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        size = 1 << (ai - 24)
        if i + size > len(b):
            raise ValueError("truncated CBOR")
        n = int.from_bytes(b[i:i + size], "big")
        i += size
    else:
        raise ValueError("indefinite length or reserved value")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(b):
            raise ValueError("truncated CBOR")
        raw = b[i:i + n]
        return (raw if major == 2 else raw.decode("utf-8", errors="strict")), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = _dec(b, i)
            out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = _dec(b, i)
            if isinstance(k, (list, dict, Tag)):
                raise ValueError("unsupported map key")
            if k in out:
                raise ValueError("duplicate map key")
            x, i = _dec(b, i)
            out[k] = x
        return out, i
    x, i = _dec(b, i)
    return Tag(n, x), i


# ---------------------------------------------------------------- COSE_Sign1 (RFC 9052), alg EdDSA (-8)
COSE_ALG, COSE_CTY, COSE_CWT, COSE_X5CHAIN, TRACE_METADATA = 1, 3, 15, 33, 100


def cose_sign1(payload: bytes, signer, protected: dict, unprotected: dict) -> bytes:
    prot = cbor_encode(protected)
    sig = signer.sign(cbor_encode(["Signature1", prot, b"", payload]))
    return cbor_encode(Tag(18, [prot, unprotected, payload, sig]))


def cose_sign1_open(b: bytes):
    """Decode a tagged COSE_Sign1 and return (protected map, protected bytes, unprotected map, payload, signature,
    signature structure bytes); the caller verifies the signature with the key it trusts."""
    t = cbor_decode(b)
    if not isinstance(t, Tag) or t.tag != 18 or not isinstance(t.value, list) or len(t.value) != 4:
        raise ValueError("not a tagged COSE_Sign1")
    prot_b, unprot, payload, sig = t.value
    if not isinstance(prot_b, bytes) or not isinstance(unprot, dict) or not isinstance(sig, bytes):
        raise ValueError("COSE_Sign1 members have the wrong types")
    if not isinstance(payload, bytes):
        raise ValueError("detached payload, this profile needs it attached")
    prot = cbor_decode(prot_b) if prot_b else {}
    if not isinstance(prot, dict):
        raise ValueError("protected header is not a map")
    return prot, prot_b, unprot, payload, sig, cbor_encode(["Signature1", prot_b, b"", payload])


# ---------------------------------------------------------------- JWS General JSON Serialization, EdDSA
def jws_sign(payload: bytes, signer, header: dict) -> dict:
    prot = b64u(jcs({"alg": "EdDSA"}))
    pl = b64u(payload)
    sig = signer.sign((prot + "." + pl).encode("ascii"))
    return {"payload": pl, "signatures": [{"header": header, "protected": prot, "signature": b64u(sig)}]}


def pretty(v) -> bytes:
    return (json.dumps(v, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# ---------------------------------------------------------------- RSA test key from a label, JWS RS256
_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def rsa_from_label(label: str, bits: int = 2048):
    """A deterministic RSA test key: candidates for p and q come from SHA-256 in counter mode over the label,
    Miller-Rabin with 40 bases from the same stream, e = 65537. Anyone can rebuild it; test use only."""
    from math import gcd

    from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPrivateNumbers, RSAPublicNumbers,
                                                               rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp)
    seed = hashlib.sha256(label.encode("ascii")).digest()
    counter = [0]

    def stream(n):
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + counter[0].to_bytes(8, "big")).digest()
            counter[0] += 1
        return out[:n]

    def probable_prime(c):
        if any(c % p == 0 for p in _SMALL_PRIMES):
            return False
        d, r = c - 1, 0
        while d % 2 == 0:
            d, r = d // 2, r + 1
        for _ in range(40):
            a = 2 + int.from_bytes(stream(len(str(c))), "big") % (c - 3)
            x = pow(a, d, c)
            if x in (1, c - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, c)
                if x == c - 1:
                    break
            else:
                return False
        return True

    def prime(nbits):
        while True:
            c = int.from_bytes(stream(nbits // 8), "big") | (3 << (nbits - 2)) | 1
            if probable_prime(c):
                return c

    e = 65537
    while True:
        p, q = prime(bits // 2), prime(bits // 2)
        if p != q and gcd(e, p - 1) == 1 and gcd(e, q - 1) == 1:
            break
    p, q = max(p, q), min(p, q)
    d = pow(e, -1, (p - 1) * (q - 1))
    return RSAPrivateNumbers(p, q, d, rsa_crt_dmp1(d, p), rsa_crt_dmq1(d, q), rsa_crt_iqmp(p, q),
                             RSAPublicNumbers(e, p * q)).private_key()


def jws_sign_rs256(payload: bytes, key, header: dict) -> dict:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    prot = b64u(jcs({"alg": "RS256"}))
    pl = b64u(payload)
    sig = key.sign((prot + "." + pl).encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return {"payload": pl, "signatures": [{"header": header, "protected": prot, "signature": b64u(sig)}]}
