"""Edwards25519 arithmetic and the four-rule verification profile.

Built from RFC 8032 Section 5.1 (curve constants, point decoding 5.1.3,
key derivation 5.1.5, cofactored equation 5.1.7) and from the profile text
of SER Section 4.4 and ID Section 6, which state the same four rules.
Only SHA-512 comes from a library (hashlib).
"""
import hashlib

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
SQRT_M1 = pow(2, (p - 1) // 4, p)

# Base point B' (RFC 8032 Section 5.1)
_By = (4 * pow(5, p - 2, p)) % p
_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
B = (_Bx, _By, 1, (_Bx * _By) % p)
NEUTRAL = (0, 1, 1, 0)


def add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % p
    b = (y1 + x1) * (y2 + x2) % p
    c = 2 * t1 * t2 * d % p
    dd = 2 * z1 * z2 % p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def mul(n, P):
    Q = NEUTRAL
    while n > 0:
        if n & 1:
            Q = add(Q, P)
        P = add(P, P)
        n >>= 1
    return Q


def neg(P):
    x, y, z, t = P
    return ((-x) % p, y, z, (-t) % p)


def equal(P, Q):
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    return (x1 * z2 - x2 * z1) % p == 0 and (y1 * z2 - y2 * z1) % p == 0


def is_neutral(P):
    return equal(P, NEUTRAL)


def encode(P):
    x, y, z, _ = P
    zi = pow(z, p - 2, p)
    x, y = x * zi % p, y * zi % p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _recover_x(y, sign):
    """x from y and the sign bit; None when no point exists or x = 0 with sign 1."""
    u = (y * y - 1) % p
    v = (d * y * y + 1) % p
    x = (u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p)) % p
    vx2 = v * x * x % p
    if vx2 == u:
        pass
    elif vx2 == (-u) % p:
        x = x * SQRT_M1 % p
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = p - x
    return x


def decode(s):
    """RFC 8032 Section 5.1.3. Returns the point, or None when decoding fails.

    Rejects y >= p and x = 0 with the sign bit set, as the rules require.
    """
    if len(s) != 32:
        return None
    n = int.from_bytes(s, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= p:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def decode_lenient(s):
    """Diagnostics only: a decoder that reduces y modulo p (not the profile)."""
    n = int.from_bytes(s, "little")
    sign = n >> 255
    y = (n & ((1 << 255) - 1)) % p
    x = _recover_x(y, sign)
    if x is None:
        u = (y * y - 1) % p
        if u == 0:
            return (0, y, 1, 0)
        return None
    return (x, y, 1, x * y % p)


def has_order_L(P):
    return (not is_neutral(P)) and is_neutral(mul(L, P))


def order_class(P):
    """'small', 'mixed' or 'L' for diagnostics."""
    if is_neutral(mul(8, P)):
        return "small"
    if is_neutral(mul(L, P)):
        return "L"
    return "mixed"


def public_from_seed(seed):
    """RFC 8032 Section 5.1.5."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encode(mul(a, B)), a, h[32:]


def sign(seed, msg):
    """RFC 8032 Section 5.1.6, used only to make counter-probe inputs."""
    A, a, prefix = public_from_seed(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    R = encode(mul(r, B))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % L
    S = (r + k * a) % L
    return R + S.to_bytes(32, "little")


def verify_profile(A_bytes, sig, msg):
    """The four rules, in order, key before R within rules 1 and 2.

    Returns (True, None, None) or (False, rule_number, 'key'|'R'|None).
    """
    if len(A_bytes) != 32 or len(sig) != 64:
        return (False, 0, "length")
    R_bytes, S_bytes = sig[:32], sig[32:]
    A = decode(A_bytes)
    if A is None:
        return (False, 1, "key")
    R = decode(R_bytes)
    if R is None:
        return (False, 1, "R")
    if not has_order_L(A):
        return (False, 2, "key")
    if not has_order_L(R):
        return (False, 2, "R")
    S = int.from_bytes(S_bytes, "little")
    if S >= L:
        return (False, 3, None)
    k = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + msg).digest(), "little") % L
    if not equal(mul(S, B), add(R, mul(k, A))):
        return (False, 4, None)
    return (True, None, None)


def equations(A_bytes, sig, msg):
    """Diagnostics: cofactorless and cofactored equation without rules 1 to 3."""
    A = decode(A_bytes)
    R = decode(sig[:32])
    if A is None or R is None:
        return None
    S = int.from_bytes(sig[32:], "little")
    k = int.from_bytes(hashlib.sha512(sig[:32] + A_bytes + msg).digest(), "little") % L
    lhs = mul(S, B)
    rhs = add(R, mul(k, A))
    cofactorless = equal(lhs, rhs)
    cofactored = equal(mul(8, lhs), mul(8, rhs))
    return {"cofactorless": cofactorless, "cofactored": cofactored}
