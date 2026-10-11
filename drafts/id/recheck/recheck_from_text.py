"""Recompute Appendix A of draft-gruszka-scitt-statement-identification-00 from the .txt alone.

Reads only the rendered text: statement bytes, case bytes, seeds, digests and expected axes.
No generator, no cases.json, no source package is used.

Round 2 of the review (2026-10-07): sig_valid follows the four rules that Section 6 now states
(canonical A and R per RFC 8032 Section 5.1.3, both of order L, S below L, the cofactorless
equation over ToBeSigned). They are implemented here with affine Edwards
arithmetic written from RFC 8032 Section 5.1, independent of the generator; A is derived from the
seed as in RFC 8032 Section 5.1.5 and compared with the general library. The library verdict is
printed beside the rule for every case. A case may state the result of the cofactored equation;
it is recomputed.

Differential round (2026-10-07), as revised the same evening: Section 6 reads a candidate as one
well-formed CBOR data item, valid under RFC 8949 Section 5.3.1 (duplicate keys judged by the key
equivalence of Section 5.6.1), that is a COSE_Sign1, without checking whether a tag's content is valid for
that tag (the data items inside a tag are checked); anything else is not a statement:
NO_MATCH under a usable reference, INDETERMINATE under an unusable one, is_scitt False, sig_valid None. The paragraph is found in the text, and two probes
are built from the bytes of Appendix A: statement 01 with one byte of iss replaced by 0xff, and the C5
candidate with one byte of its unprotected text replaced by 0xff. The second keeps the protected header
and the payload, so a reader without the validity check would report MATCH.

Round 3 of the review (2026-10-07): Section 6 says that the read check covers only the outer tag, the array
shape, the element types and basic CBOR validity, that header labels are not validated, and that is_scitt
reports this structural check with tag 18; and that sig_valid is False for a signature that is not 64 bytes
before an absent payload leaves it None. Both sentences are found in the text. Two probes are built from
the bytes of Appendix A: C1 with its empty unprotected header (a0 at offset 127) replaced by {true: 0}
(a1 f5 00), which keeps every axis of C1; and C8 with its signature head 58 40 changed to 58 3f and its last
byte removed, which gives match INDETERMINATE and sig_valid False.

Closing round (2026-10-07): Section 6 reads a COSE_Sign1 as an array of exactly four elements, says that
the content of a tag inside the COSE_Sign1 is not checked for that tag, names the base point B' (as in
S*B' = R + k*A and 8*S*B' = 8*R + 8*k*A), and says that a candidate that is not a statement has is_scitt
False and sig_valid None under any reference, with match NO_MATCH under a usable reference and
INDETERMINATE under an unusable one. The sentences are found in the text and the replaced ones are gone.
The reader below checks the structure as the paragraph states it. Probes from the bytes of Appendix A:
statement 01 with one byte of iss replaced by 0xff, under the scheme SHA-512 (-44) and under the reference's
own scheme; arrays of two, three and five elements; the four elements of statement 01 without the tag.
"""
import hashlib
import re
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

raw = open(sys.argv[1], encoding="utf-8").read().split("\n")
lines = [
    ln for ln in raw
    if "\f" not in ln
    and not re.match(r"^Gruszka\s+Expires .*\[Page \d+\]$", ln)
    and not re.match(r"^Internet-Draft\s{2,}Identifying SCITT Signed Statements\s{2,}\w+ \d{4}$", ln)
]
start = next(i for i, ln in enumerate(lines) if ln.startswith("Appendix A.  "))
end = next(i for i, ln in enumerate(lines) if i > start and ln.startswith("Acknowledgments"))
app = lines[start:end]
text = "\n".join(app)


def hexblock(seg):
    return bytes.fromhex("".join(m.group(1) for ln in seg for m in [re.match(r"^   ([0-9a-f]+)$", ln)] if m))


def section(title_re, stop_re):
    i = next(k for k, ln in enumerate(app) if re.match(title_re, ln))
    j = next((k for k, ln in enumerate(app) if k > i and re.match(stop_re, ln)), len(app))
    return app[i:j]


# base statements
stm = {}
a1 = section(r"^A\.1\.  ", r"^A\.2\.  ")
idx = [k for k, ln in enumerate(a1) if re.match(r"^   Statement 0[123] \(", ln)]
for n, k in enumerate(idx):
    seg = a1[k: idx[n + 1] if n + 1 < len(idx) else len(a1)]
    head = " ".join(s.strip() for s in seg[:4])
    name = re.match(r"Statement (0[123])", head).group(1)
    size = int(re.search(r"(\d+) bytes", head).group(1))
    digest = re.search(r"SHA-256\s+([0-9a-f]{64})", head).group(1)
    b = hexblock(seg)
    stm[name] = b
    print(f"statement {name}: {len(b)} bytes (stated {size}), sha256 {'OK' if hashlib.sha256(b).hexdigest()==digest else 'DIFF'}")
    assert len(b) == size and hashlib.sha256(b).hexdigest() == digest

ref_stated = re.search(r"Reference digest \(SHA-256 over ToBeSigned of 01\):\s+([0-9a-f]{64})", text).group(1)

# keys
a2 = "\n".join(section(r"^A\.2\.  ", r"^A\.3\.  "))
keys = {}
for who, seed, kid in re.findall(r"(issuer|auditor):\s+\*  Ed25519 seed \(hex, 32 bytes\):\s+([0-9a-f]{64})\s+\*  kid \(hex, SHA-256 of the SubjectPublicKeyInfo\):\s+([0-9a-f]{64})", a2):
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    spki = sk.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ok = hashlib.sha256(spki).hexdigest() == kid
    print(f"key {who}: kid = SHA-256(SPKI) {'OK' if ok else 'DIFF'}")
    assert ok
    keys[bytes.fromhex(kid)] = sk.public_key()


def decode(b):
    obj = cbor2.loads(b)
    tagged = isinstance(obj, cbor2.CBORTag)
    arr = obj.value if tagged else obj
    is_scitt = tagged and obj.tag == 18 and b[0] == 0xD2
    return arr, is_scitt


def tbs(arr, aad=b""):
    return cbor2.dumps(["Signature1", arr[0], aad, arr[2]])


# ---- Section 6: the sig_valid rule, read from the text ------------------------------------------
def _norm(seg):
    return re.sub(r"\s+", " ", " ".join(seg))


s6_i = next(i for i, ln in enumerate(lines) if re.match(r"^6\.  Conformance and Illustrative Test Cases", ln))
s6_j = next(i for i, ln in enumerate(lines) if i > s6_i and re.match(r"^7\.  ", ln))
s6 = _norm(lines[s6_i:s6_j])
RULE_PHRASES = [
    "A and R are canonical encodings: decoding each as in [RFC8032] Section 5.1.3 succeeds.",
    "A and R have order L: L*A and L*R are the neutral element, and A and R are not the neutral element.",
    "S is below L.",
    "With k = SHA-512(R || A || ToBeSigned) read as a little-endian integer and reduced modulo L, the "
    "cofactorless equation S*B' = R + k*A holds.",
    "Because A and R have order L, the cofactorless equation of rule 4 and the cofactored equation "
    "8*S*B' = 8*R + 8*k*A of [RFC8032] Section 5.1.7 accept exactly the same signatures.",
    "B' is the base point and L the order of B' ([RFC8032] Section 5.1)",
    "derived from its seed in Appendix A.2 as in [RFC8032] Section 5.1.5",
    "After the candidate passes the read checks above, a signature that is not 64 bytes gives sig_valid False. "
    "Otherwise, if the payload is absent and not supplied, there is no ToBeSigned and sig_valid is None, not "
    "evaluated (C8). Otherwise, evaluate the four rules above.",
]
missing = [ph for ph in RULE_PHRASES if ph not in s6]
print("Section 6 sig_valid rule phrases found: %d of %d%s" % (len(RULE_PHRASES) - len(missing), len(RULE_PHRASES),
      "" if not missing else "; missing: " + " | ".join(missing)))
assert not missing
gone6 = [ph for ph in ("B is the base point", "S*B = R", "8*S*B = 8*R") if ph in s6]
print("Section 6 names the base point B only as B': %s" % (not gone6))
assert not gone6
norm_refs = _norm(lines[next(i for i, ln in enumerate(lines) if re.match(r"^\d+\.1\.  Normative References", ln)):
                       next(i for i, ln in enumerate(lines) if re.match(r"^\d+\.2\.  Informative References", ln))])
print("RFC 8032 among the normative references: %s" % ("[RFC8032]" in norm_refs))
assert "[RFC8032]" in norm_refs

FP = 2 ** 255 - 19
FD = -121665 * pow(121666, FP - 2, FP) % FP
FL = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, FP - 2, FP)


def pt_decode(b):
    """RFC 8032 Section 5.1.3, affine; None when decoding fails."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    x0, y = n >> 255, n & ((1 << 255) - 1)
    if y >= FP:
        return None
    u, v = (y * y - 1) % FP, (FD * y * y + 1) % FP
    x = u * pow(v, 3, FP) * pow(u * pow(v, 7, FP), (FP - 5) // 8, FP) % FP
    if v * x * x % FP == u:
        pass
    elif v * x * x % FP == (-u) % FP:
        x = x * pow(2, (FP - 1) // 4, FP) % FP
    else:
        return None
    if x == 0 and x0 == 1:
        return None
    if x % 2 != x0:
        x = FP - x
    return (x, y)


def pt_add(p, q):
    (x1, y1), (x2, y2) = p, q
    t = FD * x1 * x2 * y1 * y2 % FP
    return ((x1 * y2 + y1 * x2) * _inv(1 + t) % FP, (y1 * y2 + x1 * x2) * _inv(1 - t) % FP)


def pt_mul(n, p):
    acc, base = (0, 1), p
    while n > 0:
        if n & 1:
            acc = pt_add(acc, base)
        base, n = pt_add(base, base), n >> 1
    return acc


def pt_enc(p):
    return (p[1] | ((p[0] & 1) << 255)).to_bytes(32, "little")


G = pt_decode((4 * _inv(5) % FP).to_bytes(32, "little"))
IDENT = (0, 1)


def rule_sig_valid(a_enc, sig, msg, cofactored=False, rule2=True):
    if not isinstance(sig, bytes) or len(sig) != 64:
        return False
    A, R = pt_decode(a_enc), pt_decode(sig[:32])
    if A is None or R is None:                                   # rule 1
        return False
    if rule2 and not all(P_ != IDENT and pt_mul(FL, P_) == IDENT for P_ in (A, R)):   # rule 2: order L
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= FL:                                                  # rule 3
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + a_enc + msg).digest(), "little") % FL
    lhs, rhs = pt_mul(s, G), pt_add(R, pt_mul(k, A))             # rule 4
    if cofactored:
        lhs, rhs = pt_mul(8, lhs), pt_mul(8, rhs)
    return lhs == rhs


def a_from_seed(seed):
    """RFC 8032 Section 5.1.5."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a = (a & ((1 << 254) - 8)) | (1 << 254)
    return pt_enc(pt_mul(a, G))


A_OF = {}
for who, seed, kid in re.findall(r"(issuer|auditor):\s+\*  Ed25519 seed \(hex, 32 bytes\):\s+([0-9a-f]{64})\s+"
                                 r"\*  kid \(hex, SHA-256 of the SubjectPublicKeyInfo\):\s+([0-9a-f]{64})", a2):
    enc = a_from_seed(bytes.fromhex(seed))
    lib_raw = keys[bytes.fromhex(kid)].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"key {who}: A from the seed (RFC 8032 Section 5.1.5) equals the library public key: {enc == lib_raw}")
    assert enc == lib_raw
    A_OF[bytes.fromhex(kid)] = enc


def lib_ok(arr, aad=b""):
    if arr[2] is None:
        return None
    pk = keys.get(cbor2.loads(arr[0]).get(4))
    if pk is None:
        return False
    try:
        pk.verify(arr[3], tbs(arr, aad))
        return True
    except Exception:
        return False


def sig_ok(arr, aad=b"", cofactored=False, rule2=True):
    """sig_valid in the order of Section 6: a signature that is not 64 bytes gives False; otherwise an absent
    payload leaves no ToBeSigned and None; otherwise the four rules."""
    if not isinstance(arr[3], bytes) or len(arr[3]) != 64:
        return False
    if arr[2] is None:
        return None
    a_enc = A_OF.get(cbor2.loads(arr[0]).get(4))
    if a_enc is None:
        return False
    return rule_sig_valid(a_enc, arr[3], tbs(arr, aad), cofactored, rule2)


# reference carried by 02 and 03, and the 01 ToBeSigned
a01, _ = decode(stm["01"])
d01 = hashlib.sha256(tbs(a01)).hexdigest()
for n in ("02", "03"):
    arr, sc = decode(stm[n])
    refs = cbor2.loads(arr[0]).get(-70001)
    print(f"statement {n}: refs {[(r[0], r[1], r[2].hex()[:16]) for r in refs]}, is_scitt {sc}, sig_valid {sig_ok(arr)}")
    assert refs == [[-16, "ToBeSigned", bytes.fromhex(ref_stated)]] and sc and sig_ok(arr)
print(f"01 ToBeSigned sha256 == reference digest: {d01 == ref_stated}; 01 sig_valid {sig_ok(a01)}")
assert d01 == ref_stated

# cases
a3 = section(r"^A\.3\.  ", r"^ZZZ")
cidx = [k for k, ln in enumerate(a3) if re.match(r"^A\.3\.\d+\.  C\d+ ", ln)]
fails = 0
for n, k in enumerate(cidx):
    seg = a3[k: cidx[n + 1] if n + 1 < len(cidx) else len(a3)]
    st = "\n".join(seg)
    cname = re.match(r"^A\.3\.\d+\.  (C\d+)", seg[0]).group(1)
    joined = re.sub(r"\s+", " ", st)
    cand_sha = re.search(r"candidate SHA-256 \(whole COSE_Sign1\): ([0-9a-f]{64}) \((\d+) bytes\)", joined)
    meas = re.search(r"measured: ref_usable = (\w+), match = (\w+), is_scitt = (\w+), sig_valid = (\w+)", joined)
    aad_m = re.search(r"external_aad \(hex, \d+ bytes\): ([0-9a-f]+)", joined)
    b = hexblock(seg)
    bytes_ok = hashlib.sha256(b).hexdigest() == cand_sha.group(1) and len(b) == int(cand_sha.group(2))
    arr, is_scitt = decode(b)
    # scheme: SHA-256 over ToBeSigned, empty external_aad unless the case supplies one; a case may name
    # another hash. Review round 2026-10-07 (R4): the number the text gives must be the COSE value of the
    # named hash (RFC 9054 Table 2 and RFC 9053: SHA-256 -16, SHA-384 -43, SHA-512 -44).
    COSE_HASH = {"SHA-256": -16, "SHA-384": -43, "SHA-512": -44}
    named = re.search(r"names (SHA-\d+) \((-\d+)\)", joined)
    scheme_alg = int(named.group(2)) if named else -16
    if named and COSE_HASH.get(named.group(1)) != scheme_alg:
        print(f"{cname}: the text names {named.group(1)} as {scheme_alg}, its COSE value is {COSE_HASH.get(named.group(1))}")
        fails += 1
    ref_alg = -16
    ref_usable = scheme_alg == ref_alg
    aad = bytes.fromhex(aad_m.group(1)) if aad_m else b""
    if not ref_usable or arr[2] is None:
        match = "INDETERMINATE"
    else:
        match = "MATCH" if hashlib.sha256(tbs(arr, aad)).hexdigest() == ref_stated else "NO_MATCH"
    sv = sig_ok(arr, aad)
    got = (str(ref_usable), match, str(is_scitt), str(sv))
    exp = meas.groups()
    extra = ""
    if aad_m:
        m2 = re.search(r"fixed empty external_aad rule: match = (\w+), sig_valid = (\w+)", joined)
        g2 = ("MATCH" if hashlib.sha256(tbs(arr)).hexdigest() == ref_stated else "NO_MATCH", str(sig_ok(arr)))
        extra = f" | empty-aad rule stated {m2.groups()} computed {g2} {'OK' if g2 == m2.groups() else 'DIFF'}"
        fails += g2 != m2.groups()
    m3 = re.search(r"with rule 2 left out: the cofactorless equation gives sig_valid = (\w+), the cofactored "
                   r"equation gives sig_valid = (\w+)", joined)
    if m3:
        g3 = (str(sig_ok(arr, aad, rule2=False)), str(sig_ok(arr, aad, cofactored=True, rule2=False)))
        extra += f" | without rule 2 stated {m3.groups()} computed {g3} {'OK' if g3 == m3.groups() else 'DIFF'}"
        fails += g3 != m3.groups()
    extra += f" | library {lib_ok(arr, aad)}"
    ok = bytes_ok and got == exp
    fails += not ok
    print(f"{cname}: bytes {'OK' if bytes_ok else 'DIFF'} ({len(b)} B), stated {exp} computed {got} {'OK' if got == exp else 'DIFF'}{extra}")
print("cases:", len(cidx), "deviations:", fails)

# the reading of a candidate (Section 6)
body = re.sub(r"\s+", " ", "\n".join(lines))
reading = ("A candidate is read as a COSE_Sign1 ([RFC9052] Section 4.2), bare or with tag 18: an array of exactly "
           "four elements: the protected header, a byte string that is empty or encodes one map; the unprotected header, a map; the "
           "payload, a byte string or nil; and the signature, a byte string. For these illustrative axes, this read "
           "check covers only the outer tag, the array shape, the stated element types and the basic CBOR validity "
           "rules below. It does not validate header labels or header parameter semantics. The is_scitt axis "
           "reports this structural check with tag 18, not complete conformance to the SCITT envelope profile. "
           "The candidate and its protected header "
           "are each one CBOR data item that is well-formed and valid under [RFC8949] Section 5.3.1: every text "
           "string is valid UTF-8, and no map holds two keys that are equal under the key equivalence of [RFC8949] "
           "Section 5.6.1, so that the integer 1 and true are two keys and 0.0 and -0.0 are one. Whether the "
           "content of a tag inside the COSE_Sign1 is valid for that tag ([RFC8949] Section 5.3.2) is not checked; the data items inside "
           "a tag are checked like any other data item. The deterministic encoding is not required. A candidate "
           "that breaks any "
           "of this, for example with a text string that is not valid UTF-8 in either header, is not a statement: "
           "its is_scitt is False and its sig_valid is None, not evaluated; its match is NO_MATCH under a usable "
           "reference and INDETERMINATE under an unusable one.")
old_k7 = "under an unusable reference its match is INDETERMINATE."
print(f"the replaced sentence on the unusable reference is gone: {old_k7 not in body}")
fails += old_k7 in body
batch = ("accept exactly the same signatures. This document defines individual verification only. A randomized "
         "batch result MUST NOT substitute for checking all four rules for each signature.")
old_batch = "randomized batch verification reaches the same verdict"
print(f"batch sentence of Section 6 found: {batch in body}; the old batch sentence gone: {old_batch not in body}")
fails += batch not in body or old_batch in body
found = reading in body
print(f"reading paragraph of Section 6 found: {found}")
fails += not found


def read_strict(b):
    """None if the candidate is not a statement by Section 6, else the array. This reader: cbor2 refuses
    invalid UTF-8; the structure is checked as the reading paragraph states it: bare or tag 18, an array of
    exactly four elements, a protected header that is empty or encodes one map, an unprotected map, a payload
    that is a byte string or nil, a signature that is a byte string."""
    try:
        obj = cbor2.loads(b)
        if isinstance(obj, cbor2.CBORTag):
            if obj.tag != 18:
                return None
            obj = obj.value
        if not isinstance(obj, list) or len(obj) != 4:
            return None
        prot, unprot, payload, sig = obj
        if not isinstance(prot, bytes) or not isinstance(unprot, dict) or not isinstance(sig, bytes) \
                or not (payload is None or isinstance(payload, bytes)):
            return None
        if prot and not isinstance(cbor2.loads(prot), dict):
            return None
        return obj
    except Exception:  # noqa: BLE001
        return None


def flip(b, needle, at):
    i = b.index(needle) + at
    return b[:i] + b"\xff" + b[i + 1:]


c5_seg = a3[cidx[4]: cidx[5]]
c5_bytes = hexblock(c5_seg)
probes = {"statement 01, byte 8 of iss": flip(stm["01"], b"https://issuer.example", 8),
          "C5, byte 5 of its unprotected text": flip(c5_bytes, b"added after signing", 5)}
for what, b in probes.items():
    arr = read_strict(b)
    lenient = "MATCH" if what.startswith("C5") and hashlib.sha256(tbs(a01)).hexdigest() == ref_stated \
        and b.count(a01[0]) == 1 and b.count(a01[2]) == 1 else "NO_MATCH"
    got = "NO_MATCH" if arr is None else "read"
    print(f"probe {what}: Section 6 gives {got}, is_scitt False, sig_valid None (not evaluated); a reader "
          f"without the validity check: {lenient}")
    fails += got != "NO_MATCH"
print("deviations after the reading probes:", fails)

# Round 3: two probes from the bytes of Appendix A
old_c8 = "A case whose payload is absent and not supplied has no ToBeSigned"
print(f"the replaced C8 sentence is gone: {old_c8 not in body}")
fails += old_c8 in body
c1_bytes, c8_bytes = hexblock(a3[cidx[0]: cidx[1]]), hexblock(a3[cidx[7]: cidx[8]])
r31 = c1_bytes[:127] + b"\xa1\xf5\x00" + c1_bytes[128:]
r32 = c8_bytes[:-66] + b"\x58\x3f" + c8_bytes[-64:-1]
for what, b, size, digest, expect in (
        ("R3-1, C1 with an unprotected header {true: 0}", r31, 332,
         "96d1dd55ddfdeee7b8fe65e00bdba7418c190002787d96b11dbc5a138db9f17b", ("True", "MATCH", "True", "True")),
        ("R3-2, C8 with a signature of 63 bytes", r32, 194,
         "7013cfce60b5fc5b707c6d4d66672e17a72d66cdb1dcccf1699736717720b929", ("True", "INDETERMINATE", "True", "False"))):
    arr, is_scitt = decode(b)
    match = "INDETERMINATE" if arr[2] is None else \
        ("MATCH" if hashlib.sha256(tbs(arr)).hexdigest() == ref_stated else "NO_MATCH")
    got = ("True", match, str(is_scitt), str(sig_ok(arr)))
    same = (len(b), hashlib.sha256(b).hexdigest()) == (size, digest)
    print(f"probe {what}: {len(b)} B, sha256 as stated by the review: {same}; axes {got} "
          f"{'OK' if got == expect else 'DIFF, expected ' + str(expect)}")
    fails += got != expect or not same
print("deviations after the round 3 probes:", fails)

# Closing round: the candidate that is not a statement, under either reference (K7), and the four elements (K5)
k7 = probes["statement 01, byte 8 of iss"]
same = (len(k7), hashlib.sha256(k7).hexdigest()) == (330, "50b21e6a18c0d6b59f0f4a236a8782ebeaec0a000ec3054a580adecc7bd2c99a")


def axes_of_no_statement(scheme_alg):
    """Section 6 as it now reads: is_scitt False and sig_valid None, match by the reference only."""
    ref_usable = scheme_alg == -16
    return (str(ref_usable), "NO_MATCH" if ref_usable else "INDETERMINATE", "False", "None")


for scheme_alg, expect in ((-44, ("False", "INDETERMINATE", "False", "None")), (-16, ("True", "NO_MATCH", "False", "None"))):
    got = axes_of_no_statement(scheme_alg) if read_strict(k7) is None else ("read",)
    print(f"probe statement 01 with byte 8 of iss 0xff, scheme {scheme_alg}: {len(k7)} B, sha256 as stated: {same}; "
          f"axes {got} {'OK' if got == expect else 'DIFF, expected ' + str(expect)}")
    fails += got != expect or not same
a01_raw, _ = decode(stm["01"])
els = [cbor2.dumps(x) for x in a01_raw]
assert stm["01"] == b"\xd2\x84" + b"".join(els)
for what, b, readable in (("[1, 2]", b"\xd2\x82\x01\x02", False), ("three elements", b"\xd2\x83" + b"".join(els[:3]), False),
                          ("five elements", b"\xd2\x85" + b"".join(els) + b"\x00", False),
                          ("the four elements of 01, bare", b"\x84" + b"".join(els), True)):
    got = read_strict(b) is not None
    print(f"probe {what}: read as a COSE_Sign1: {got} {'OK' if got == readable else 'DIFF'}")
    fails += got != readable
print("deviations after the closing-round probes:", fails)
sys.exit(1 if fails else 0)
