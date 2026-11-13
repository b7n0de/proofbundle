#!/usr/bin/env python3
"""An independent reading of Section 6 of draft-gruszka-scitt-statement-identification-03.

Written from the draft text only (SHA-256 9176957a...). The author's check_cases.py and tools/build_cases.py
were not read. Python standard library only: own CBOR reader, own Ed25519 arithmetic (RFC 8032).

Axes: ref_usable, match (MATCH / NO_MATCH / INDETERMINATE), is_scitt, sig_valid (True / False / None).

Choices that are this reader's own (the draft leaves them to the cases):
  - a reference alg names a hash function when it is one of the eight hash algorithms of the COSE Algorithms
    registry with a fixed output length (-14, -15, -16, -17, -18, -43, -44, -45);
  - the reference is checked for the same CBOR well-formedness and validity as the candidate;
  - CBOR nested deeper than 200 or input longer than 1 MiB stops the run (an error, not a result);
  - an external_aad given as null is "not supplied": where ToBeSigned is needed, match is INDETERMINATE and
    sig_valid None (Section 7: a missing input must not silently become an empty one).
"""
import hashlib, math, struct

MAX_DEPTH, MAX_LEN = 200, 1 << 20


class NotWellFormed(Exception):
    pass


class Tag:
    def __init__(self, n, v):
        self.n, self.v = n, v


class Simple:
    def __init__(self, n):
        self.n = n


UNDEF = Simple(23)


class Map:
    def __init__(self, pairs):
        self.pairs = pairs


def _head(b, i):
    if i >= len(b):
        raise NotWellFormed("truncated head")
    ib = b[i]; mt, ai = ib >> 5, ib & 31; i += 1
    if ai < 24:
        return mt, ai, ai, i
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if i + n > len(b):
            raise NotWellFormed("truncated argument")
        return mt, ai, int.from_bytes(b[i:i + n], "big"), i + n
    if ai == 31:
        return mt, ai, None, i
    raise NotWellFormed("reserved additional information %d" % ai)


def _item(b, i, depth):
    if depth > MAX_DEPTH:
        raise RuntimeError("nesting deeper than %d" % MAX_DEPTH)
    mt, ai, arg, i = _head(b, i)
    if mt == 0:
        if arg is None: raise NotWellFormed("indefinite integer")
        return arg, i
    if mt == 1:
        if arg is None: raise NotWellFormed("indefinite integer")
        return -1 - arg, i
    if mt in (2, 3):
        if arg is None:
            parts = []
            while True:
                if i >= len(b): raise NotWellFormed("missing break")
                if b[i] == 0xFF:
                    i += 1; break
                cmt, cai, carg, j = _head(b, i)
                if cmt != mt or carg is None: raise NotWellFormed("bad chunk")
                if j + carg > len(b): raise NotWellFormed("truncated chunk")
                parts.append(b[j:j + carg]); i = j + carg
            raw = b"".join(parts)
        else:
            if i + arg > len(b): raise NotWellFormed("truncated string")
            raw = b[i:i + arg]; i += arg
        if mt == 2:
            return bytes(raw), i
        try:
            return raw.decode("utf-8", "strict"), i     # strict: rejects surrogates and overlongs
        except UnicodeDecodeError:
            raise NotWellFormed("text string is not valid UTF-8")   # validity (RFC 8949 5.3.1)
    if mt == 4:
        out = []
        if arg is None:
            while True:
                if i >= len(b): raise NotWellFormed("missing break")
                if b[i] == 0xFF:
                    i += 1; break
                v, i = _item(b, i, depth + 1); out.append(v)
        else:
            for _ in range(arg):
                v, i = _item(b, i, depth + 1); out.append(v)
        return out, i
    if mt == 5:
        pairs = []
        if arg is None:
            while True:
                if i >= len(b): raise NotWellFormed("missing break")
                if b[i] == 0xFF:
                    i += 1; break
                k, i = _item(b, i, depth + 1)
                if i < len(b) and b[i] == 0xFF: raise NotWellFormed("map with odd items")
                v, i = _item(b, i, depth + 1); pairs.append((k, v))
        else:
            for _ in range(arg):
                k, i = _item(b, i, depth + 1); v, i = _item(b, i, depth + 1); pairs.append((k, v))
        seen = set()
        for k, _ in pairs:
            e = _equiv(k)
            if e in seen: raise NotWellFormed("duplicate map key")       # validity (RFC 8949 5.6.1)
            seen.add(e)
        return Map(pairs), i
    if mt == 6:
        if arg is None: raise NotWellFormed("indefinite tag")
        v, i = _item(b, i, depth + 1)
        return Tag(arg, v), i
    # mt == 7
    if ai == 31: raise NotWellFormed("break outside an indefinite item")
    if ai < 24:
        return {20: False, 21: True, 22: None, 23: UNDEF}.get(ai) if ai >= 20 else Simple(ai), i
    if ai == 24:
        if arg < 32: raise NotWellFormed("two-byte simple value below 32")
        return Simple(arg), i
    if ai == 25:
        return struct.unpack(">e", arg.to_bytes(2, "big"))[0], i
    if ai == 26:
        return struct.unpack(">f", arg.to_bytes(4, "big"))[0], i
    return struct.unpack(">d", arg.to_bytes(8, "big"))[0], i


def _equiv(x):
    """A hashable form under which two map keys are equal exactly when RFC 8949 5.6.1 calls them equal."""
    if x is True or x is False:
        return ("bool", x)
    if x is None:
        return ("null",)
    if isinstance(x, int):
        return ("int", x)
    if isinstance(x, float):
        return ("float", "nan") if math.isnan(x) else ("float", x + 0.0)   # 0.0 and -0.0 one key
    if isinstance(x, bytes):
        return ("bytes", x)
    if isinstance(x, str):
        return ("text", x)
    if isinstance(x, list):
        return ("array", tuple(_equiv(v) for v in x))
    if isinstance(x, Map):
        return ("map", frozenset((_equiv(k), _equiv(v)) for k, v in x.pairs))
    if isinstance(x, Tag):
        return ("tag", x.n, _equiv(x.v))
    if isinstance(x, Simple):
        return ("simple", x.n)
    raise TypeError(type(x))


def decode_one(b):
    """One well-formed and valid data item with nothing after it."""
    if len(b) > MAX_LEN:
        raise RuntimeError("input longer than 1 MiB")
    v, i = _item(b, 0, 0)
    if i != len(b):
        raise NotWellFormed("bytes after the data item")
    return v


# ---- references --------------------------------------------------------------------------------------------
HASHES = {  # COSE Algorithms registry, hash functions with a fixed output length
    -14: ("sha1", 20), -15: ("sha256/64", 8), -16: ("sha256", 32), -17: ("sha512_256", 32),
    -18: ("shake128", 32), -43: ("sha384", 48), -44: ("sha512", 64), -45: ("shake256", 64),
}


def digest(alg, data):
    name, n = HASHES[alg]
    if name == "sha256/64":
        return hashlib.sha256(data).digest()[:8]
    if name.startswith("shake"):
        return hashlib.new(name, data).digest(n)
    return hashlib.new(name, data).digest()


def reference_usable(ref_bytes, scheme_alg, scheme_name):
    try:
        r = decode_one(ref_bytes)
    except NotWellFormed:
        return None
    if not (isinstance(r, list) and len(r) == 3):
        return None
    alg, scheme, dg = r
    if not (isinstance(alg, int) and not isinstance(alg, bool) and alg in HASHES):
        return None
    if not isinstance(scheme, str) or not isinstance(dg, bytes) or len(dg) != HASHES[alg][1]:
        return None
    if alg != scheme_alg or scheme != scheme_name:
        return None
    return alg, dg


# ---- candidates --------------------------------------------------------------------------------------------
def read_candidate(c):
    """(tagged, protected, payload, signature) or None when the candidate is not a statement."""
    try:
        v = decode_one(c)
    except NotWellFormed:
        return None
    tagged = False
    if isinstance(v, Tag):
        if v.n != 18:
            return None
        tagged, v = True, v.v
    if not (isinstance(v, list) and len(v) == 4):
        return None
    prot, unprot, payload, sig = v
    if not isinstance(prot, bytes) or not isinstance(unprot, Map) or not isinstance(sig, bytes):
        return None
    if not (payload is None or isinstance(payload, bytes)):
        return None
    if prot:
        try:
            if not isinstance(decode_one(prot), Map):
                return None
        except NotWellFormed:
            return None
    return tagged, prot, payload, sig


def _bstr(b):
    n = len(b)
    if n < 24: h = bytes([0x40 | n])
    elif n < 256: h = bytes([0x58, n])
    elif n < 65536: h = b"\x59" + n.to_bytes(2, "big")
    else: h = b"\x5a" + n.to_bytes(4, "big")
    return h + b


def to_be_signed(prot, aad, payload):
    return b"\x84" + b"\x6aSignature1" + _bstr(prot) + _bstr(aad) + _bstr(payload)


# ---- Ed25519 (RFC 8032) ------------------------------------------------------------------------------------
P = 2 ** 255 - 19
Lq = 2 ** 252 + 27742317777372353535851937790883648493
Dc = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
NEUTRAL = (0, 1, 1, 0)


def _add(p, q):
    X1, Y1, Z1, T1 = p; X2, Y2, Z2, T2 = q
    A = (Y1 - X1) * (Y2 - X2) % P; B = (Y1 + X1) * (Y2 + X2) % P
    C = T1 * 2 * Dc * T2 % P; D = Z1 * 2 * Z2 % P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(n, p):
    q = NEUTRAL
    while n > 0:
        if n & 1: q = _add(q, p)
        p = _add(p, p); n >>= 1
    return q


def _eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _decode_point(s):
    """RFC 8032 Section 5.1.3; None when decoding fails."""
    if len(s) != 32: return None
    y = int.from_bytes(s, "little"); x0 = y >> 255; y &= (1 << 255) - 1
    if y >= P: return None
    u = (y * y - 1) % P; v = (Dc * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if v * x * x % P == u: pass
    elif v * x * x % P == (-u) % P: x = x * SQRT_M1 % P
    else: return None
    if x == 0 and x0 == 1: return None
    if x % 2 != x0: x = P - x
    return (x, y, 1, x * y % P)


def _encode_point(p):
    zi = pow(p[2], P - 2, P); x = p[0] * zi % P; y = p[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BY = 4 * pow(5, P - 2, P) % P
BASE = _decode_point(_BY.to_bytes(32, "little"))


def public_from_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8; a |= 1 << 254
    return _encode_point(_mul(a, BASE))


def sig_rules(A_bytes, sig, msg, rules="all"):
    """rules: 'all' (Section 6), 'no-rule-2' (cofactorless), 'no-rule-2-cofactored'."""
    Rb, Sb = sig[:32], sig[32:]
    A = _decode_point(A_bytes); R = _decode_point(Rb)
    if A is None or R is None:                                  # rule 1
        return False
    if rules == "all":                                          # rule 2
        for X in (A, R):
            if _eq(X, NEUTRAL) or not _eq(_mul(Lq, X), NEUTRAL):
                return False
    S = int.from_bytes(Sb, "little")
    if S >= Lq:                                                 # rule 3
        return False
    k = int.from_bytes(hashlib.sha512(Rb + A_bytes + msg).digest(), "little") % Lq
    lhs = _mul(S, BASE); rhs = _add(R, _mul(k, A))
    if rules == "no-rule-2-cofactored":
        return _eq(_mul(8, lhs), _mul(8, rhs))
    return _eq(lhs, rhs)                                        # rule 4, cofactorless


# ---- the four axes -----------------------------------------------------------------------------------------
NOT_SUPPLIED = object()


def axes(candidate, reference, scheme_alg, scheme_name, external_aad, detached_payload, key, rules="all"):
    """external_aad / detached_payload: bytes, or NOT_SUPPLIED."""
    ref = reference_usable(reference, scheme_alg, scheme_name)
    ref_usable = ref is not None
    c = read_candidate(candidate)
    if c is None:
        return {"ref_usable": ref_usable, "match": "NO_MATCH" if ref_usable else "INDETERMINATE",
                "is_scitt": False, "sig_valid": None}
    tagged, prot, payload, sig = c
    if payload is None:
        payload = None if detached_payload is NOT_SUPPLIED else detached_payload
    tbs = None
    if payload is not None and external_aad is not NOT_SUPPLIED:
        tbs = to_be_signed(prot, external_aad, payload)
    if not ref_usable or tbs is None:
        match = "INDETERMINATE"
    else:
        match = "MATCH" if digest(ref[0], tbs) == ref[1] else "NO_MATCH"
    if len(sig) != 64:
        sv = False
    elif tbs is None:
        sv = None
    else:
        sv = sig_rules(key, sig, tbs, rules)
    return {"ref_usable": ref_usable, "match": match, "is_scitt": tagged, "sig_valid": sv}
