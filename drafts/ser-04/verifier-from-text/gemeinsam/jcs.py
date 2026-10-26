"""RFC 8785 serialization of a parsed JSON value (ijson.Obj, list, str, Num, bool, None).

Numbers are serialized from their IEEE 754 double as ECMAScript
Number::toString does (RFC 8785 Section 3.2.2.3).
"""
import math

from .ijson import Num, Obj


class NotSerializable(Exception):
    pass


def es_number(x):
    if math.isnan(x) or math.isinf(x):
        raise NotSerializable("number without finite double: %r" % x)
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    x = abs(x)
    r = repr(x)  # shortest round-trip digits, nearest when several
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    # decimal point position: value = 0.d1d2... * 10^n
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) - lead_zeros + exp
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        if k == 1:
            s = digits + "e" + es
        else:
            s = digits[0] + "." + digits[1:] + "e" + es
    return sign + s


def _str(s):
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


def _utf16_key(s):
    return s.encode("utf-16-be")


def serialize_text(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, Num):
        return es_number(v.double)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, list):
        return "[" + ",".join(serialize_text(x) for x in v) + "]"
    if isinstance(v, Obj):
        ms = sorted(v.members, key=lambda m: _utf16_key(m[0]))
        return "{" + ",".join(_str(n) + ":" + serialize_text(x) for n, x in ms) + "}"
    raise NotSerializable(type(v))


def serialize(v):
    return serialize_text(v).encode("utf-8")


def from_python(v):
    """Build ijson values from plain Python (dict order irrelevant; ints/str numbers)."""
    if isinstance(v, dict):
        return Obj([(k, from_python(x)) for k, x in v.items()])
    if isinstance(v, list):
        return [from_python(x) for x in v]
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int):
        return Num(str(v))
    raise TypeError(type(v))
