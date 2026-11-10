#!/usr/bin/env python3
"""Check the cases of draft-gruszka-scitt-statement-identification-03 against the rules of its Section 6.

Usage:
    python3 check_cases.py [--cases DIR]

For every file cases/<id>.json, in sorted order, the script checks each byte string against its sha256 and length,
computes the four axes of Section 6 (ref_usable, match, is_scitt, sig_valid) from the inputs alone, and compares them
with the expected axes of the case. A case may name variants, each a stated change of one input together with the
axes Appendix A gives for it; they are computed and compared the same way. The script prints one line per case and
per variant and exits with 0 only if every one matches. It uses the Python standard library only.

What it implements, all from Section 6 and Section 5.1 of the draft:
- A reference is one CBOR data item, the array [alg, scheme, digest] with exactly three elements. It is well-formed
  when alg is an integer that names a hash function of the COSE Algorithms registry (the hash functions of RFC 9054
  with a fixed output length), scheme is a text string and digest is a byte string of that output length; it is
  compatible when alg and scheme equal those of the named scheme. ref_usable is both.
- A candidate is a COSE_Sign1, bare or with tag 18: an array of exactly four elements, the protected header a byte
  string that is empty or encodes one map, the unprotected header a map, the payload a byte string or nil, the
  signature a byte string. It and its protected header must each be one CBOR data item, well-formed and valid
  under RFC 8949 Section 5.3.1 (valid UTF-8, no two map keys equal under Section 5.6.1). The deterministic encoding
  is not required, and the content of a tag is not checked for that tag. is_scitt is this read check with tag 18.
- ToBeSigned is the deterministic encoding of ["Signature1", body_protected, external_aad, payload], where
  body_protected is the protected header byte string as received and a nil payload is replaced by the supplied
  detached payload. match compares the digest of ToBeSigned under the scheme's hash function with the reference.
  An external_aad or a detached payload that is needed and not supplied (null) gives no ToBeSigned: match is
  INDETERMINATE and sig_valid None, never a success (Section 4.1, A1, and Section 7).
- sig_valid applies the four rules of Section 6 to the stated Ed25519 key: canonical A and R, A and R of order L,
  S below L, and the cofactorless equation S*B = R + k*A.

Limits of this script, not of the draft: it implements the ToBeSigned scheme of Section 5.1 only, so a case that
names another scheme is an error, not a result; CBOR nested deeper than 200 levels and inputs over 1 MiB are not read
and end the run with an error, not with a verdict.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import struct
import sys

DRAFT = "draft-gruszka-scitt-statement-identification-03"
SCHEME_NAME = "ToBeSigned"
MAX_DEPTH = 200
MAX_BYTES = 1 << 20

#: COSE hash algorithms of RFC 9054 and their output length in bytes (IANA COSE Algorithms registry).
HASHES = {
    -14: ("sha1", 20),
    -15: ("sha256/64", 8),
    -16: ("sha256", 32),
    -17: ("sha512/256", 32),
    -18: ("shake128", 32),
    -43: ("sha384", 48),
    -44: ("sha512", 64),
    -45: ("shake256", 64),
}


def digest(alg, data):
    name, size = HASHES[alg]
    if name == "sha256/64":
        return hashlib.sha256(data).digest()[:8]
    if name == "sha512/256":
        return hashlib.new("sha512_256", data).digest()
    if name == "shake128":
        return hashlib.shake_128(data).digest(size)
    if name == "shake256":
        return hashlib.shake_256(data).digest(size)
    return hashlib.new(name, data).digest()


# ----------------------------------------------------------------------------------------------------------------
# CBOR, RFC 8949: well-formedness (Section 3, Appendix F) and validity (Section 5.3.1) of one data item


class NotWellFormed(Exception):
    """The bytes are not one well-formed and valid CBOR data item."""


class BeyondLimits(Exception):
    """The input is beyond the limits of this script; no verdict is given."""


class Item:
    """A decoded data item: kind, value, and the span [start, end) of its encoding."""

    __slots__ = ("kind", "value", "start", "end", "tag")

    def __init__(self, kind, value, start, end, tag=None):
        self.kind, self.value, self.start, self.end, self.tag = kind, value, start, end, tag


def _head(buf, pos):
    if pos >= len(buf):
        raise NotWellFormed("data ends inside an item")
    ib = buf[pos]
    major, ai = ib >> 5, ib & 0x1F
    pos += 1
    if ai < 24:
        return major, ai, ai, pos
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if pos + n > len(buf):
            raise NotWellFormed("data ends inside a head")
        return major, ai, int.from_bytes(buf[pos:pos + n], "big"), pos + n
    if ai == 31:
        return major, ai, None, pos
    raise NotWellFormed("reserved additional information %d" % ai)


def _float_key(width, bits):
    """The map-key equivalence of a float (RFC 8949 Section 5.6.1)."""
    if width == 2:
        exp_all, sig_bits, sig = (bits >> 10) & 0x1F == 0x1F, 10, bits & 0x3FF
        value = struct.unpack(">e", bits.to_bytes(2, "big"))[0]
    elif width == 4:
        exp_all, sig_bits, sig = (bits >> 23) & 0xFF == 0xFF, 23, bits & 0x7FFFFF
        value = struct.unpack(">f", bits.to_bytes(4, "big"))[0]
    else:
        exp_all, sig_bits, sig = (bits >> 52) & 0x7FF == 0x7FF, 52, bits & ((1 << 52) - 1)
        value = struct.unpack(">d", bits.to_bytes(8, "big"))[0]
    if exp_all and sig:
        return ("nan", sig << (64 - sig_bits))
    return ("float", value + 0.0)


def _key(item):
    """A hashable value under which two equivalent map keys are equal (RFC 8949 Section 5.6.1)."""
    k = item.kind
    if k in ("int", "bytes", "simple"):
        return (k, item.value)
    if k == "text":
        return ("text", item.value.encode("utf-8"))
    if k == "float":
        return item.value[2]
    if k == "array":
        return ("array", tuple(_key(x) for x in item.value))
    if k == "map":
        return ("map", frozenset((_key(a), _key(b)) for a, b in item.value))
    return ("tag", item.tag, _key(item.value))


def _string(buf, pos, major, ai, arg, start):
    if ai == 31:
        chunks = []
        while True:
            if pos >= len(buf):
                raise NotWellFormed("data ends inside an indefinite-length string")
            if buf[pos] == 0xFF:
                pos += 1
                break
            m, cai, n, pos = _head(buf, pos)
            if m != major or cai == 31:
                raise NotWellFormed("a chunk of an indefinite-length string is not a definite string of its type")
            if pos + n > len(buf):
                raise NotWellFormed("data ends inside a chunk")
            chunks.append(bytes(buf[pos:pos + n]))
            pos += n
    else:
        if pos + arg > len(buf):
            raise NotWellFormed("data ends inside a string")
        chunks = [bytes(buf[pos:pos + arg])]
        pos += arg
    if major == 2:
        return Item("bytes", b"".join(chunks), start, pos)
    try:
        text = "".join(c.decode("utf-8") for c in chunks)
    except UnicodeDecodeError:
        raise NotWellFormed("a text string is not valid UTF-8") from None
    return Item("text", text, start, pos)


def decode(buf, pos=0, depth=0):
    """One data item at pos: (Item, end). Raises NotWellFormed or BeyondLimits."""
    if depth > MAX_DEPTH:
        raise BeyondLimits("nested deeper than %d levels" % MAX_DEPTH)
    start = pos
    major, ai, arg, pos = _head(buf, pos)
    if major == 0:
        if ai == 31:
            raise NotWellFormed("indefinite length for an integer")
        return Item("int", arg, start, pos), pos
    if major == 1:
        if ai == 31:
            raise NotWellFormed("indefinite length for an integer")
        return Item("int", -1 - arg, start, pos), pos
    if major in (2, 3):
        item = _string(buf, pos, major, ai, arg, start)
        return item, item.end
    if major in (4, 5):
        out, seen = [], set()
        count = None if ai == 31 else arg * (2 if major == 5 else 1)
        i = 0
        while count is None or i < count:
            if count is None:
                if pos >= len(buf):
                    raise NotWellFormed("data ends inside an indefinite-length container")
                if buf[pos] == 0xFF:
                    pos += 1
                    break
            x, pos = decode(buf, pos, depth + 1)
            out.append(x)
            i += 1
        if major == 4:
            return Item("array", out, start, pos), pos
        if len(out) % 2:
            raise NotWellFormed("a map ends after a key")
        pairs = list(zip(out[0::2], out[1::2]))
        for k, _v in pairs:
            kk = _key(k)
            if kk in seen:
                raise NotWellFormed("a map holds two equal keys")
            seen.add(kk)
        return Item("map", pairs, start, pos), pos
    if major == 6:
        if ai == 31:
            raise NotWellFormed("indefinite length for a tag")
        content, pos = decode(buf, pos, depth + 1)
        return Item("tagged", content, start, pos, tag=arg), pos
    # major 7
    if ai < 24:
        return Item("simple", ai, start, pos), pos
    if ai == 24:
        if arg < 32:
            raise NotWellFormed("a simple value below 32 in two bytes")
        return Item("simple", arg, start, pos), pos
    if ai in (25, 26, 27):
        width = 1 << (ai - 24)
        return Item("float", (width, arg, _float_key(width, arg)), start, pos), pos
    raise NotWellFormed("a break outside an indefinite-length container")


def decode_one(buf):
    """Exactly one data item and nothing after it."""
    if len(buf) > MAX_BYTES:
        raise BeyondLimits("input longer than %d bytes" % MAX_BYTES)
    item, end = decode(buf, 0)
    if end != len(buf):
        raise NotWellFormed("bytes after the data item")
    return item


def _bstr(b):
    n = len(b)
    if n < 24:
        head = bytes([0x40 | n])
    elif n < 0x100:
        head = bytes([0x58, n])
    elif n < 0x10000:
        head = b"\x59" + n.to_bytes(2, "big")
    elif n < 0x100000000:
        head = b"\x5a" + n.to_bytes(4, "big")
    else:
        head = b"\x5b" + n.to_bytes(8, "big")
    return head + b


def to_be_signed(body_protected, external_aad, payload):
    """["Signature1", body_protected, external_aad, payload] in the deterministic encoding (RFC 9052 Sections 4.4, 9)."""
    return b"\x84\x6aSignature1" + _bstr(body_protected) + _bstr(external_aad) + _bstr(payload)


# ----------------------------------------------------------------------------------------------------------------
# Ed25519, RFC 8032 Section 5.1, with the four rules of Section 6 of the draft

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
NEUTRAL = (0, 1, 1, 0)


def _add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(n, pt):
    q = NEUTRAL
    while n > 0:
        if n & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        n >>= 1
    return q


def _equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _decode_point(s):
    """RFC 8032 Section 5.1.3; None when decoding fails, so the encoding is not canonical."""
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if (v * x * x - u) % P != 0:
        if (v * x * x + u) % P != 0:
            return None
        x = x * SQRT_M1 % P
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _encode_point(pt):
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, P - 2, P) % P
BASE = _decode_point(_GY.to_bytes(32, "little"))


def public_key_from_seed(seed):
    """RFC 8032 Section 5.1.5."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encode_point(_mul(a, BASE))


def ed25519_rules(public_key, signature, message, rules="section6"):
    """sig_valid for a 64-byte signature. rules: "section6" applies the four rules of Section 6; "no-rule-2" and
    "no-rule-2-cofactored" leave rule 2 out and apply the cofactorless or the cofactored equation (case C11)."""
    a_pt, r_pt = _decode_point(public_key), _decode_point(signature[:32])
    if a_pt is None or r_pt is None:
        return False
    if rules == "section6":
        for pt in (a_pt, r_pt):
            if not _equal(_mul(L, pt), NEUTRAL) or _equal(pt, NEUTRAL):
                return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    left, right = _mul(s, BASE), _add(r_pt, _mul(k, a_pt))
    if rules == "no-rule-2-cofactored":
        return _equal(_mul(8, left), _mul(8, right))
    return _equal(left, right)


# ----------------------------------------------------------------------------------------------------------------
# The axes of Section 6


def reference_usable(ref_bytes, scheme):
    try:
        ref = decode_one(ref_bytes)
    except NotWellFormed:
        return False
    if ref.kind != "array" or len(ref.value) != 3:
        return False
    alg, name, dig = ref.value
    if alg.kind != "int" or alg.value not in HASHES or name.kind != "text" or dig.kind != "bytes":
        return False
    if len(dig.value) != HASHES[alg.value][1]:
        return False
    return alg.value == scheme["alg"] and name.value == scheme["name"]


def read_candidate(cand_bytes):
    """(tagged with 18, body_protected, payload or None, signature), or None when the candidate is not a statement."""
    try:
        top = decode_one(cand_bytes)
    except NotWellFormed:
        return None
    tagged = top.kind == "tagged"
    if tagged:
        if top.tag != 18:
            return None
        top = top.value
    if top.kind != "array" or len(top.value) != 4:
        return None
    prot, unprot, payload, sig = top.value
    if prot.kind != "bytes" or unprot.kind != "map" or sig.kind != "bytes":
        return None
    if not (payload.kind == "bytes" or (payload.kind == "simple" and payload.value == 22)):
        return None
    if prot.value:
        try:
            if decode_one(prot.value).kind != "map":
                return None
        except NotWellFormed:
            return None
    return tagged, prot.value, payload.value if payload.kind == "bytes" else None, sig.value


def axes(inputs, rules="section6"):
    ref_bytes, cand_bytes = inputs["reference"], inputs["candidate"]
    scheme, aad, detached = inputs["scheme"], inputs["external_aad"], inputs["detached_payload"]
    usable = reference_usable(ref_bytes, scheme)
    read = read_candidate(cand_bytes)
    if read is None:
        return {"ref_usable": usable, "match": "NO_MATCH" if usable else "INDETERMINATE",
                "is_scitt": False, "sig_valid": None}
    tagged, body_protected, payload, sig = read
    if payload is None:
        payload = detached
    tbs = None if payload is None or aad is None else to_be_signed(body_protected, aad, payload)
    if not usable or tbs is None:
        match = "INDETERMINATE"
    else:
        ref = decode_one(ref_bytes)
        match = "MATCH" if digest(ref.value[0].value, tbs) == ref.value[2].value else "NO_MATCH"
    if len(sig) != 64:
        sig_valid = False
    elif tbs is None:
        sig_valid = None
    else:
        sig_valid = ed25519_rules(inputs["public_key"], sig, tbs, rules)
    return {"ref_usable": usable, "match": match, "is_scitt": tagged, "sig_valid": sig_valid}


# ----------------------------------------------------------------------------------------------------------------
# Case files


class CaseError(Exception):
    """A case file that this script cannot use."""


def _no_duplicates(pairs):
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError("a member is named twice")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(name + " is not JSON")


def _bytes(obj, what):
    """A byte string given as {"base64", "sha256", "length"}, checked against both; None stays None."""
    if obj is None:
        return None
    if not isinstance(obj, dict) or set(obj) != {"base64", "sha256", "length"}:
        raise CaseError(what + ": not an object with base64, sha256 and length")
    try:
        data = base64.b64decode(obj["base64"], validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise CaseError(what + ": base64 does not decode") from None
    if len(data) != obj["length"] or hashlib.sha256(data).hexdigest() != obj["sha256"]:
        raise CaseError(what + ": the bytes differ from their sha256 or length")
    return data


def case_inputs(raw, what):
    if not isinstance(raw, dict):
        raise CaseError(what + ": inputs is not an object")
    scheme = raw.get("scheme")
    if (not isinstance(scheme, dict) or set(scheme) != {"alg", "name"} or type(scheme["alg"]) is not int
            or type(scheme["name"]) is not str):
        raise CaseError(what + ": scheme is not {alg, name}")
    if scheme["name"] != SCHEME_NAME or scheme["alg"] not in HASHES:
        raise CaseError(what + ": this checker implements the ToBeSigned scheme of Section 5.1 with a hash function of "
                        "RFC 9054 only, not %r with alg %r" % (scheme["name"], scheme["alg"]))
    key = raw.get("stated_key")
    if not isinstance(key, dict) or set(key) != {"name", "public_key"}:
        raise CaseError(what + ": stated_key is not {name, public_key}")
    out = {"scheme": scheme, "public_key": _bytes(key["public_key"], what + " stated_key")}
    for name in ("candidate", "reference"):
        out[name] = _bytes(raw.get(name), what + " " + name)
        if out[name] is None:
            raise CaseError(what + ": " + name + " is missing")
    for name in ("external_aad", "detached_payload"):
        if name not in raw:
            raise CaseError(what + ": " + name + " is missing (null when not supplied)")
        out[name] = _bytes(raw[name], what + " " + name)
    if len(out["public_key"]) != 32:
        raise CaseError(what + ": the stated key is not 32 bytes")
    return out


AXES = ("ref_usable", "match", "is_scitt", "sig_valid")
RULES = ("section6", "no-rule-2", "no-rule-2-cofactored")


def _show(d):
    return ", ".join("%s=%s" % (a, d[a]) for a in AXES if a in d)


def check_file(path):
    """Rows (label, expected, computed, ok) for the case and each of its variants."""
    with open(path, encoding="utf-8") as fh:
        case = json.load(fh, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    cid = case.get("id") if isinstance(case, dict) else None
    if not isinstance(cid, str) or case.get("draft") != DRAFT:
        raise CaseError(os.path.basename(path) + ": no id, or not a case of " + DRAFT)
    base = case_inputs(case.get("inputs"), cid)
    rows = []
    jobs = [(cid, base, "section6", case.get("expected"))]
    for v in case.get("variants") or []:
        label = "%s / %s" % (cid, v.get("name"))
        inputs = dict(base)
        for name, value in (v.get("change") or {}).items():
            if name not in ("external_aad", "detached_payload"):
                raise CaseError(label + ": a variant may change external_aad or detached_payload only")
            inputs[name] = _bytes(value, label + " " + name)
        rules = v.get("rules", "section6")
        if rules not in RULES:
            raise CaseError(label + ": rules is not one of " + ", ".join(RULES))
        jobs.append((label, inputs, rules, v.get("expected")))
    for label, inputs, rules, exp in jobs:
        if not isinstance(exp, dict) or not exp or not set(exp) <= set(AXES):
            raise CaseError(label + ": expected names no axis or another member")
        got = axes(inputs, rules)
        ok = all(got[a] == exp[a] for a in exp)
        rows.append((label, _show(exp), _show({a: got[a] for a in exp}), ok))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cases", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases"))
    a = ap.parse_args()
    try:
        files = sorted(f for f in os.listdir(a.cases) if f.endswith(".json"))
    except OSError as e:
        print("cannot read %s: %s" % (a.cases, e.strerror))
        return 2
    if not files:
        print("no cases found in " + a.cases)
        return 2
    rows = []
    for f in sorted(files, key=lambda n: (len(n), n)):
        try:
            rows.extend(check_file(os.path.join(a.cases, f)))
        except (CaseError, ValueError, OSError, BeyondLimits, RecursionError) as e:
            rows.append((f, "", "(" + str(e) + ")", False))
    for label, exp, got, ok in rows:
        print("%-36s %s" % (label, "ok" if ok else "MISMATCH"))
        print("    expected  " + exp)
        print("    computed  " + got)
    bad = [r[0] for r in rows if not r[3]]
    print("%d of %d checks match (%d case files)" % (len(rows) - len(bad), len(rows), len(files)))
    if bad:
        print("mismatch: " + ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
