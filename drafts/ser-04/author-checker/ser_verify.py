"""Verifier for Signed Evaluation Receipts, written from
draft-gruszka-signed-evaluation-receipts-04 alone.

verify(receipt_bytes, vk32) -> ("PASS", None) or ("FAIL", step_string)
step_string is "1".."10" or "11 (profile R)" / "11 (profile R, key|R)".
ResourceLimit is raised (never PASS, never a step FAIL) on resource limits.
InputError is raised, before any step runs, when the verification-key input
is not exactly 32 octets (Section 5 of the revised -04 text, lines 529-531).

Everything here is implemented directly (UTF-8 check, JSON parser, RFC 8785
serializer, base64, Ed25519 arithmetic); hashlib supplies SHA-256/SHA-512.
"""
import hashlib

TYPE = "application/vnd.signed-evidence.eval-receipt+json"
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"
COMMIT_ALG = "sha256-salted-v1"

MAX_DEPTH = 512          # resource limit on nesting (Section 8)
MAX_INPUT = 16 * 1024 * 1024


class ResourceLimit(Exception):
    pass


class InputError(Exception):
    """Section 5: a verification-key input that is not exactly 32 octets is
    an input error; the steps are not run; neither PASS nor a step FAIL."""
    pass


class JSONReject(Exception):
    pass


# ---------------------------------------------------------------- values
# Tagged representation, so that booleans are never confused with numbers.
class JNum:
    __slots__ = ("lexeme", "value")

    def __init__(self, lexeme):
        self.lexeme = lexeme
        # Section 5 step 4: read as IEEE 754 double, round to nearest even,
        # overflow to infinity.  Python float() on a grammar-checked decimal
        # literal is correctly rounded and yields inf on overflow.
        self.value = float(lexeme)


class JBool:
    __slots__ = ("value",)

    def __init__(self, v):
        self.value = v


class JNull:
    __slots__ = ()


JNULL = JNull()
JTRUE = JBool(True)
JFALSE = JBool(False)


# ---------------------------------------------------------------- UTF-8
def utf8_decode_strict(b):
    """RFC 3629 UTF-8 decoding, implemented by hand. Rejects overlongs,
    encoded surrogates, code points above U+10FFFF, truncated sequences."""
    out = []
    i, n = 0, len(b)
    while i < n:
        c = b[i]
        if c < 0x80:
            out.append(chr(c)); i += 1; continue
        if 0xC2 <= c <= 0xDF:
            need, cp, lo = 1, c & 0x1F, 0x80
        elif 0xE0 <= c <= 0xEF:
            need, cp, lo = 2, c & 0x0F, 0x800
        elif 0xF0 <= c <= 0xF4:
            need, cp, lo = 3, c & 0x07, 0x10000
        else:
            raise JSONReject("invalid UTF-8 lead byte 0x%02x at %d" % (c, i))
        if i + need >= n:
            raise JSONReject("truncated UTF-8 sequence at %d" % i)
        for j in range(1, need + 1):
            cc = b[i + j]
            if cc & 0xC0 != 0x80:
                raise JSONReject("invalid UTF-8 continuation at %d" % (i + j))
            cp = (cp << 6) | (cc & 0x3F)
        if cp < lo:
            raise JSONReject("overlong UTF-8 at %d" % i)
        if 0xD800 <= cp <= 0xDFFF:
            raise JSONReject("UTF-8 encoded surrogate at %d" % i)
        if cp > 0x10FFFF:
            raise JSONReject("code point above U+10FFFF at %d" % i)
        out.append(chr(cp))
        i += need + 1
    return "".join(out)


def is_noncharacter(cp):
    return (0xFDD0 <= cp <= 0xFDEF) or (cp & 0xFFFE) == 0xFFFE


# ---------------------------------------------------------------- JSON parser
WS = " \t\n\r"


class Parser:
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.n = len(text)

    def ws(self):
        s, i, n = self.s, self.i, self.n
        while i < n and s[i] in WS:
            i += 1
        self.i = i

    def fail(self, msg):
        raise JSONReject("%s at char %d" % (msg, self.i))

    def value(self, depth):
        if depth > MAX_DEPTH:
            raise ResourceLimit("nesting depth above %d" % MAX_DEPTH)
        self.ws()
        if self.i >= self.n:
            self.fail("unexpected end")
        c = self.s[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        if c == "-" or "0" <= c <= "9":
            return self.number()
        for lit, val in (("true", JTRUE), ("false", JFALSE), ("null", JNULL)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        self.fail("unexpected character %r" % c)

    def obj(self, depth):
        self.i += 1
        members = []          # list of (name, value), in order
        seen = set()
        self.ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return dict_from(members)
        while True:
            self.ws()
            if self.i >= self.n or self.s[self.i] != '"':
                self.fail("expected member name")
            name = self.string()
            if name in seen:   # compared after unescaping (RFC 8259 8.3)
                self.fail("duplicate member name %r" % name)
            seen.add(name)
            self.ws()
            if self.i >= self.n or self.s[self.i] != ":":
                self.fail("expected ':'")
            self.i += 1
            v = self.value(depth + 1)
            members.append((name, v))
            self.ws()
            if self.i >= self.n:
                self.fail("unterminated object")
            c = self.s[self.i]
            if c == ",":
                self.i += 1
                continue
            if c == "}":
                self.i += 1
                return dict_from(members)
            self.fail("expected ',' or '}'")

    def arr(self, depth):
        self.i += 1
        items = []
        self.ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return items
        while True:
            items.append(self.value(depth + 1))
            self.ws()
            if self.i >= self.n:
                self.fail("unterminated array")
            c = self.s[self.i]
            if c == ",":
                self.i += 1
                continue
            if c == "]":
                self.i += 1
                return items
            self.fail("expected ',' or ']'")

    def hex4(self):
        h = self.s[self.i:self.i + 4]
        if len(h) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in h):
            self.fail("bad \\u escape")
        self.i += 4
        return int(h, 16)

    def string(self):
        self.i += 1
        out = []
        s, n = self.s, self.n
        while True:
            if self.i >= n:
                self.fail("unterminated string")
            c = s[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\":
                self.i += 1
                if self.i >= n:
                    self.fail("unterminated escape")
                e = s[self.i]
                self.i += 1
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b",
                          "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    out.append(simple[e])
                    continue
                if e != "u":
                    self.fail("bad escape \\%s" % e)
                cp = self.hex4()
                if 0xD800 <= cp <= 0xDBFF:
                    # needs a following \uDC00-\uDFFF
                    if s.startswith("\\u", self.i):
                        save = self.i
                        self.i += 2
                        lo = self.hex4()
                        if 0xDC00 <= lo <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                        else:
                            self.i = save
                            self.fail("lone high surrogate")
                    else:
                        self.fail("lone high surrogate")
                elif 0xDC00 <= cp <= 0xDFFF:
                    self.fail("lone low surrogate")
                if is_noncharacter(cp):
                    self.fail("noncharacter U+%04X" % cp)
                out.append(chr(cp))
                continue
            o = ord(c)
            if o < 0x20:
                self.fail("unescaped control character")
            if is_noncharacter(o):
                self.fail("noncharacter U+%04X" % o)
            # literal surrogates cannot occur: input came from strict UTF-8
            out.append(c)
            self.i += 1

    def number(self):
        s, n, st = self.s, self.n, self.i
        i = st
        if s[i] == "-":
            i += 1
        if i >= n:
            self.i = i; self.fail("bad number")
        if s[i] == "0":
            i += 1
        elif "1" <= s[i] <= "9":
            i += 1
            while i < n and "0" <= s[i] <= "9":
                i += 1
        else:
            self.i = i; self.fail("bad number")
        if i < n and s[i] == ".":
            i += 1
            j = i
            while i < n and "0" <= s[i] <= "9":
                i += 1
            if i == j:
                self.i = i; self.fail("bad fraction")
        if i < n and s[i] in "eE":
            i += 1
            if i < n and s[i] in "+-":
                i += 1
            j = i
            while i < n and "0" <= s[i] <= "9":
                i += 1
            if i == j:
                self.i = i; self.fail("bad exponent")
        self.i = i
        return JNum(s[st:i])


def dict_from(members):
    d = {}
    for k, v in members:
        d[k] = v
    return d


def parse_ijson(b):
    """Section 3.1 / step 1 / step 4 rules.  Returns the parsed value."""
    if len(b) > MAX_INPUT:
        raise ResourceLimit("input above %d bytes" % MAX_INPUT)
    if b[:3] == b"\xef\xbb\xbf":
        raise JSONReject("byte order mark")
    text = utf8_decode_strict(b)
    p = Parser(text)
    v = p.value(0)
    p.ws()
    if p.i != p.n:
        p.fail("data after the JSON text")
    return v


# ---------------------------------------------------------------- RFC 8785
class NoSerialization(Exception):
    pass


def es_number_to_string(x):
    """ECMAScript Number::toString for a finite double (RFC 8785 3.2.2.3)."""
    if x != x or x in (float("inf"), float("-inf")):
        raise NoSerialization("NaN/Infinity has no RFC 8785 serialization")
    if x == 0:
        return "0"            # also -0
    if x < 0:
        return "-" + es_number_to_string(-x)
    # shortest round-trip digits s (k digits) and n with value s*10^(n-k).
    # repr() gives the shortest round-tripping decimal, nearest to x.
    r = repr(x)
    mant, _, exp = r.partition("e")
    e10 = int(exp) if exp else 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    alld = ip + fp
    digits = alld.lstrip("0")
    lead_zeros = len(alld) - len(digits)
    # value = 0.d1d2... * 10^n  (ECMAScript: s * 10^(n-k), k = len(s))
    n = len(ip) + e10 - lead_zeros
    digits = digits.rstrip("0")
    k = len(digits)
    if k == 0:
        return "0"
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    sign = "+" if e >= 0 else "-"
    if k == 1:
        return digits + "e" + sign + str(abs(e))
    return digits[0] + "." + digits[1:] + "e" + sign + str(abs(e))


def jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            m = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
            out.append(m.get(o, "\\u%04x" % o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v):
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, str):
        return jcs_string(v)
    if isinstance(v, JNum):
        return es_number_to_string(v.value)
    if isinstance(v, JBool):
        return "true" if v.value else "false"
    if v is JNULL:
        return "null"
    raise TypeError(type(v))


def jcs_bytes(v):
    return jcs(v).encode("utf-8")


# ---------------------------------------------------------------- base64
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64IDX = {c: i for i, c in enumerate(B64)}


def b64encode(b):
    out = []
    for i in range(0, len(b) - len(b) % 3, 3):
        x = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]
        out.append(B64[x >> 18] + B64[(x >> 12) & 63] + B64[(x >> 6) & 63] + B64[x & 63])
    r = len(b) % 3
    if r == 1:
        x = b[-1] << 16
        out.append(B64[x >> 18] + B64[(x >> 12) & 63] + "==")
    elif r == 2:
        x = (b[-2] << 16) | (b[-1] << 8)
        out.append(B64[x >> 18] + B64[(x >> 12) & 63] + B64[(x >> 6) & 63] + "=")
    return "".join(out)


def b64decode_canonical(s):
    """RFC 4648 Section 4 with padding; returns bytes or None when s is not
    a string of the base64 alphabet with padding or not canonical (3.5)."""
    if not isinstance(s, str) or len(s) % 4 != 0:
        return None
    pad = 0
    if s.endswith("=="):
        pad = 2
    elif s.endswith("="):
        pad = 1
    body = s[:len(s) - pad]
    if any(c not in B64IDX for c in body):
        return None
    out = bytearray()
    for i in range(0, len(s), 4):
        q = s[i:i + 4]
        vals = [B64IDX[c] if c != "=" else 0 for c in q]
        x = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
        out += bytes([(x >> 16) & 255, (x >> 8) & 255, x & 255])
    if pad:
        del out[-pad:]
    out = bytes(out)
    if b64encode(out) != s:       # canonical: re-encoding gives the same string
        return None
    return out


# ---------------------------------------------------------------- Ed25519
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRTM1 = pow(2, (P - 1) // 4, P)


def inv(x):
    return pow(x, P - 2, P)


def recover_x(y, sign):
    """RFC 8032 5.1.3 steps 2-4; returns x or None."""
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == u:
        pass
    elif vx2 == (-u) % P:
        x = (x * SQRTM1) % P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if x % 2 != sign:
        x = P - x
    return x


def point_decode(b):
    """RFC 8032 5.1.3 decoding of a 32-byte string; extended coords or None."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def point_add(p1, p2):
    # RFC 8032 5.1.4
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = ((Y1 - X1) * (Y2 - X2)) % P
    B = ((Y1 + X1) * (Y2 + X2)) % P
    C = (T1 * 2 * D * T2) % P
    Dd = (Z1 * 2 * Z2) % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return ((E * F) % P, (G * H) % P, (F * G) % P, (E * H) % P)


NEUTRAL = (0, 1, 1, 0)


def scalar_mul(k, pt):
    q = NEUTRAL
    while k > 0:
        if k & 1:
            q = point_add(q, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return q


def point_equal(p1, p2):
    X1, Y1, Z1, _ = p1
    X2, Y2, Z2, _ = p2
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0


def is_neutral(pt):
    return point_equal(pt, NEUTRAL)


def point_encode(pt):
    X, Y, Z, _ = pt
    zi = inv(Z)
    x, y = (X * zi) % P, (Y * zi) % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


GY = (4 * inv(5)) % P
BASE = (recover_x(GY, 0), GY, 1, (recover_x(GY, 0) * GY) % P)


def public_from_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return point_encode(scalar_mul(a, BASE)), a, h[32:]


def sign_pure(seed, msg):
    """RFC 8032 5.1.6, used only to self-test the arithmetic."""
    pub, a, prefix = public_from_seed(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    Rb = point_encode(scalar_mul(r, BASE))
    k = int.from_bytes(hashlib.sha512(Rb + pub + msg).digest(), "little") % L
    S = (r + k * a) % L
    return Rb + S.to_bytes(32, "little")


def has_order_L(pt):
    return (not is_neutral(pt)) and is_neutral(scalar_mul(L, pt))


def profile_verify(Ab, sig, msg):
    """Section 4.4.  Returns None if valid, else the profile tag string."""
    Rb, Sb = sig[:32], sig[32:]
    # rule 1, key before R
    A = point_decode(Ab)
    if A is None:
        return "profile 1, key"
    R = point_decode(Rb)
    if R is None:
        return "profile 1, R"
    # rule 2, key before R
    if not has_order_L(A):
        return "profile 2, key"
    if not has_order_L(R):
        return "profile 2, R"
    # rule 3
    S = int.from_bytes(Sb, "little")
    if S >= L:
        return "profile 3"
    # rule 4 (cofactorless), R and A exactly as received
    k = int.from_bytes(hashlib.sha512(Rb + Ab + msg).digest(), "little") % L
    if not point_equal(scalar_mul(S, BASE), point_add(R, scalar_mul(k, A))):
        return "profile 4"
    return None


def pae(type_str, body):
    t = type_str.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


# ---------------------------------------------------------------- Payload rules
DIG = "0123456789"
HEXL = "0123456789abcdef"


def is_decimal_string(s):
    if not isinstance(s, str):
        return False
    i, n = 0, len(s)
    if i < n and s[i] == "-":
        i += 1
    if i >= n:
        return False
    if s[i] == "0":
        i += 1
    elif s[i] in "123456789":
        i += 1
        while i < n and s[i] in DIG:
            i += 1
    else:
        return False
    if i < n and s[i] == ".":
        i += 1
        j = i
        while i < n and s[i] in DIG:
            i += 1
        if i == j:
            return False
    return i == n


def decimal_value(s):
    """exact value of a decimal string as (numerator, denominator 10^f)."""
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    ip, _, fp = s.partition(".")
    num = int(ip + fp) if (ip + fp) else 0
    if neg:
        num = -num
    return num, 10 ** len(fp)


def decimal_cmp(a, b):
    na, da = decimal_value(a)
    nb, db = decimal_value(b)
    x, y = na * db, nb * da
    return (x > y) - (x < y)


def is_leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def is_timestamp(s):
    if not isinstance(s, str) or len(s) != 20:
        return False
    tmpl = "DDDD-DD-DDTDD:DD:DDZ"
    for c, t in zip(s, tmpl):
        if t == "D":
            if c not in DIG:
                return False
        elif c != t:
            return False
    Y, M, Dd = int(s[0:4]), int(s[5:7]), int(s[8:10])
    hh, mm, ss = int(s[11:13]), int(s[14:16]), int(s[17:19])
    if not 1 <= M <= 12:
        return False
    mdays = [31, 29 if is_leap(Y) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][M - 1]
    if not 1 <= Dd <= mdays:
        return False
    return hh <= 23 and mm <= 59 and ss <= 59


def is_sha256_pattern(s):
    return (isinstance(s, str) and len(s) == 71 and s.startswith("sha256:")
            and all(c in HEXL for c in s[7:]))


def nonempty_string(s):
    return isinstance(s, str) and len(s) >= 1


REQUIRED = ["schema", "suite", "suite_version", "metric", "comparator", "threshold",
            "score", "passed", "n", "model_id_commit", "dataset_id_commit",
            "commit_alg", "timestamp"]
OPTIONAL = ["criteria_digest"]


def step6_ok(p):
    keys = set(p.keys())
    if not set(REQUIRED) <= keys:
        return False
    if not keys <= set(REQUIRED) | set(OPTIONAL):
        return False
    if p["schema"] != PAYLOAD_SCHEMA:          # str compare; non-str never equal
        return False
    if not isinstance(p["schema"], str):
        return False
    for m in ("suite", "suite_version", "metric"):
        if not nonempty_string(p[m]):
            return False
    if not (isinstance(p["comparator"], str) and p["comparator"] in (">=", ">", "<=", "<")):
        return False
    if not is_decimal_string(p["threshold"]) or not is_decimal_string(p["score"]):
        return False
    if not isinstance(p["passed"], JBool):
        return False
    n = p["n"]
    if not isinstance(n, JNum):
        return False
    x = n.value
    if x != x or x in (float("inf"), float("-inf")) or x != int(x):
        return False
    if not (1 <= int(x) <= 2 ** 53 - 1):
        return False
    for m in ("model_id_commit", "dataset_id_commit"):
        if not isinstance(p[m], str):
            return False
    if not (isinstance(p["commit_alg"], str) and p["commit_alg"] == COMMIT_ALG):
        return False
    if not is_timestamp(p["timestamp"]):
        return False
    if "criteria_digest" in p and not isinstance(p["criteria_digest"], str):
        return False
    return True


# ---------------------------------------------------------------- Section 5
def verify(receipt, vk, trace=None):
    """Returns ("PASS", None) or ("FAIL", step).
    Raises InputError (key not 32 octets; checked before step 1, so the
    receipt is not read at all) or ResourceLimit."""
    def T(msg):
        if trace is not None:
            trace.append(msg)

    if not isinstance(vk, (bytes, bytearray)) or len(vk) != 32:
        n = len(vk) if isinstance(vk, (bytes, bytearray)) else "non-octet"
        raise InputError("verification-key input is %s octets, not exactly 32" % n)
    vk = bytes(vk)
    # step 1
    try:
        r = parse_ijson(receipt)
    except JSONReject as e:
        T("step1: %s" % e)
        return "FAIL", "1"
    if not isinstance(r, dict) or set(r.keys()) != {"schema", "payload_b64", "signature"}:
        T("step1: top-level member set")
        return "FAIL", "1"
    sigobj = r["signature"]
    if not isinstance(sigobj, dict) or set(sigobj.keys()) not in ({"alg", "sig"}, {"alg", "sig", "key"}):
        T("step1: signature member set")
        return "FAIL", "1"
    # step 2
    if not (isinstance(r["schema"], str) and r["schema"] == TYPE):
        T("step2: schema %r" % (r["schema"] if isinstance(r["schema"], str) else type(r["schema"]).__name__))
        return "FAIL", "2"
    # step 3
    B = b64decode_canonical(r["payload_b64"])
    if B is None:
        T("step3: payload_b64 not canonical base64")
        return "FAIL", "3"
    # step 4
    try:
        payload = parse_ijson(B)
    except JSONReject as e:
        T("step4: %s" % e)
        return "FAIL", "4"
    if not isinstance(payload, dict):
        T("step4: not an object")
        return "FAIL", "4"
    # step 5
    try:
        ser = jcs_bytes(payload)
    except NoSerialization as e:
        T("step5: %s" % e)
        return "FAIL", "5"
    if ser != B:
        T("step5: B is not its own RFC 8785 serialization")
        return "FAIL", "5"
    # step 6
    if not step6_ok(payload):
        T("step6: member set or Table 1 row")
        return "FAIL", "6"
    # step 7
    for m in ("model_id_commit", "dataset_id_commit"):
        if not is_sha256_pattern(payload[m]):
            T("step7: %s" % m)
            return "FAIL", "7"
    if "criteria_digest" in payload and not is_sha256_pattern(payload["criteria_digest"]):
        T("step7: criteria_digest")
        return "FAIL", "7"
    # step 8
    c = decimal_cmp(payload["score"], payload["threshold"])
    comp = payload["comparator"]
    holds = {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0}[comp]
    if payload["passed"].value != holds:
        T("step8: passed=%s, comparison=%s" % (payload["passed"].value, holds))
        return "FAIL", "8"
    # step 9
    if not (isinstance(sigobj["alg"], str) and sigobj["alg"] == "ed25519"):
        T("step9: alg")
        return "FAIL", "9"
    sig = b64decode_canonical(sigobj["sig"])
    if sig is None or len(sig) != 64:
        T("step9: sig (%s)" % ("not canonical base64" if sig is None else "%d bytes" % len(sig)))
        return "FAIL", "9"
    # step 10
    if "key" in sigobj:
        kb = b64decode_canonical(sigobj["key"])
        if kb is None or kb != vk:
            T("step10: key hint is not the canonical base64 of the verification key")
            return "FAIL", "10"
    # step 11
    tag = profile_verify(vk, sig, pae(TYPE, B))
    if tag is not None:
        T("step11: %s" % tag)
        return "FAIL", "11 (%s)" % tag
    return "PASS", None
