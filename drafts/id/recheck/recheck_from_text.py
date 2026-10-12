"""Recompute Appendix A of draft-gruszka-scitt-statement-identification-02 from the .txt alone.

Reads only the rendered text: statement bytes, case bytes, seeds, digests and expected axes.
No generator, no cases.json, no source package is used.

Revision -02 (owner choice A of 2026-10-12): the text is now draft-gruszka-scitt-statement-identification-02; its
cases are those of the -01, byte for byte. A2 writes "may" in lowercase, Section 11 gives the measurement of the
package on proofbundle main and the result of a further checker written from the text, the Open Items are gone,
Open Question 2 stays in Section 10, and an unnumbered appendix of changes follows the Provenance. The round
"revision -02" at the end holds it. After the review of the -01 (blocks D to F), Section 11 gives the package nine
cases directly and C10 mirrored, never twelve; the round reads that sentence. Since card SER-ID-02-SEIT-00-01 the
round holds every point of the appendix of changes, since -01 (with blocks D, E and F) and since -00, in order, and
counts them.

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

Review point 9 of 2026-10-08 (revision -01): case C12 keeps tag 18 and changes the outer encoding. Its sentence in
Section 6 and the names C5 and C12 in A4 are found in the text; C12 is rebuilt from the bytes of statement 01 as
the sentence states (the array head 84 written as 98 04) and compared with the bytes of Appendix A; the head is
read byte by byte, ToBeSigned is compared with that of 01, and the preferred re-encoding gives statement 01 again.

Depth limit (2026-10-12, no change to the text): Section 7 asks an implementation to bound the nesting it processes,
and Section 6 names no number. Every CBOR read of this script, the candidate and its protected header on their own,
first walks the heads and stops at MAX_DEPTH (64, the item itself at depth 0) with ResourceLimit, a resource-limit
error with no value on any axis; before, a candidate of 60000 nested arrays crashed decode with RecursionError, and
read_strict turned the RecursionError into "not a statement" (NO_MATCH), also for statement 01 with such an item in
its unprotected header, whose ToBeSigned is that of 01. The depth round at the end holds the limit.

Size limit (owner choice A of 2026-10-12, no change to the text): read_item and loads read at most MAX_INPUT_BYTES
(1 MiB) and stop above it with ResourceLimit, before anything is read; before, statement 01 with a byte string of
64 MiB in its unprotected header was a statement with match MATCH. The depth round holds the limit itself.

Tools round (owner choice A of 2026-10-12, points 5 to 7, no change to the text): read_strict no longer reads with
cbor2. Measured on generated inputs (report of 2026-10-12), cbor2 5.4.6 and 6.1.5 read past the end of the first
data item, which Section 6 refuses, and apply the meaning of a tag, which Section 6 does not check (cbor2 5.4.6
refuses such a tag with six kinds of exception, 6.1.5 with CBORDecodeError); cbor2 6 also gives the content of a
tag as tuple and its maps as cbor2.frozendict, so the old check for list and dict made every tagged statement "not a
statement". read_item reads the bytes itself as Section 6 states it, and read_strict
answers "not a statement" for NotRead and a wrong form alone; any other exception passes. ref_usable is the form of
A.1, an array of the integer -16, the text "ToBeSigned" and 32 bytes, read from statement 02 and checked here, not
assumed. Values that cbor2 still gives (the protected headers, the references) are compared by kind (Mapping,
Sequence), not by Python type. The tools round at the end holds all of it.
"""
import hashlib
import re
import struct
import sys
from collections.abc import Mapping, Sequence

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

#: The deepest data item read (the item itself at depth 0, an item inside an array, map, tag or indefinite-length
#: string one deeper than its container); the limit of the checkers of the two companion drafts.
MAX_DEPTH = 64
#: The largest candidate, and protected header, read, in bytes; Section 7 asks to bound the input size. The largest
#: candidate of Appendix A is 450 bytes; the same number in the checkers of the three drafts. Both limits are here.
MAX_INPUT_BYTES = 1 << 20


class ResourceLimit(Exception):
    """A read stopped at MAX_DEPTH: a resource-limit error, no value on any axis."""


def depth_ok(b):
    """False if a data item of b lies deeper than MAX_DEPTH. Only the heads are walked, in the order of the bytes; the
    walk stops without a verdict where the first data item ends or a head is not well-formed, and cbor2 decides."""
    stack, i = [], 0   # per open container: items still to come, or -1 for an indefinite length
    while i < len(b):
        if stack and stack[-1] == -1 and b[i] == 0xFF:
            stack.pop()
            i += 1
        else:
            if len(stack) > MAX_DEPTH:
                return False
            major, ai = b[i] >> 5, b[i] & 31
            i += 1
            if ai >= 28 and not (ai == 31 and major in (2, 3, 4, 5)):
                return True
            if ai == 31:
                n = -1
            elif ai < 24:
                n = ai
            else:
                if i + (1 << (ai - 24)) > len(b):
                    return True
                n = int.from_bytes(b[i:i + (1 << (ai - 24))], "big")
                i += 1 << (ai - 24)
            if stack and stack[-1] > 0:
                stack[-1] -= 1
            if major in (2, 3) and n >= 0:
                i += n
            elif major in (2, 3, 4):
                stack.append(n)
            elif major == 5:
                stack.append(n if n < 0 else 2 * n)
            elif major == 6:
                stack.append(1)
        while stack and stack[-1] == 0:
            stack.pop()
        if not stack:
            return True
    return True


def loads(b):
    """cbor2.loads after the size check and the depth walk."""
    if len(b) > MAX_INPUT_BYTES:
        raise ResourceLimit("%d bytes, more than %d" % (len(b), MAX_INPUT_BYTES))
    if not depth_ok(b):
        raise ResourceLimit("a data item deeper than %d" % MAX_DEPTH)
    return cbor2.loads(b)


class NotRead(ValueError):
    """The bytes are not one well-formed CBOR data item that is valid under RFC 8949 Section 5.3.1 (Section 6)."""


def read_item(b):
    """The data item of b as a comparable value, read as Section 6 states it: exactly one well-formed data item
    (RFC 8949 Section 3), valid under Section 5.3.1 (text strings in UTF-8, each chunk on its own; no two map keys
    equivalent under Section 5.6.1, so the integer 1 and true are two keys and 0.0 and -0.0 are one), a tag as its
    number and content, the content not checked for its tag. NotRead otherwise; ResourceLimit, before anything is
    read, above MAX_INPUT_BYTES or past MAX_DEPTH."""
    if len(b) > MAX_INPUT_BYTES:
        raise ResourceLimit("%d bytes, more than %d" % (len(b), MAX_INPUT_BYTES))
    if not depth_ok(b):
        raise ResourceLimit("a data item deeper than %d" % MAX_DEPTH)
    value, end = _rd(b, 0)
    if end != len(b):
        raise NotRead("data after the data item")
    return value


def _arg(b, i, ai):
    if ai < 24:
        return ai, i
    if ai > 27:
        raise NotRead("additional information %d" % ai)
    size = 1 << (ai - 24)
    if i + size > len(b):
        raise NotRead("the head ends early")
    return int.from_bytes(b[i:i + size], "big"), i + size


def _container(major, items):
    if major == 4:
        return ("array", tuple(items))
    keys = items[0::2]
    if len(set(keys)) != len(keys):
        raise NotRead("two map keys equivalent under RFC 8949 Section 5.6.1")
    return ("map", frozenset(zip(keys, items[1::2])))


def _rd(b, i):
    if i >= len(b):
        raise NotRead("the item ends early")
    major, ai = b[i] >> 5, b[i] & 31
    i += 1
    if ai == 31:
        if major not in (2, 3, 4, 5):
            raise NotRead("an indefinite length or a break where an item begins")
        items = []
        while True:
            if i >= len(b):
                raise NotRead("an indefinite length without its break")
            if b[i] == 0xFF:
                i += 1
                break
            if major in (2, 3) and (b[i] >> 5 != major or b[i] & 31 == 31):
                raise NotRead("a chunk that is not a definite string of the same type")
            v, i = _rd(b, i)
            items.append(v)
        if major in (2, 3):
            return ("bytes" if major == 2 else "text", b"".join(v[1] for v in items)), i
        if major == 5 and len(items) % 2:
            raise NotRead("an indefinite-length map that ends after a key")
        return _container(major, items), i
    n, i = _arg(b, i, ai)
    if major in (0, 1):
        return ("int", n if major == 0 else -1 - n), i
    if major in (2, 3):
        if i + n > len(b):
            raise NotRead("the string ends early")
        raw = b[i:i + n]
        if major == 3:
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                raise NotRead("a text string that is not UTF-8") from None
        return ("bytes" if major == 2 else "text", raw), i + n
    if major in (4, 5):
        items = []
        for _ in range(n if major == 4 else 2 * n):
            v, i = _rd(b, i)
            items.append(v)
        return _container(major, items), i
    if major == 6:
        v, i = _rd(b, i)
        return ("tag", n, v), i
    if ai == 24 and n < 32:
        raise NotRead("a two-byte simple value below 32")
    if ai in (25, 26, 27):
        raw = b[i - (1 << (ai - 24)):i]
        x = struct.unpack({25: ">e", 26: ">f", 27: ">d"}[ai], raw)[0]
        if x != x:   # NaNs are equivalent when their significands, zero-extended at the right to 64 bits, are equal
            width = {25: 10, 26: 23, 27: 52}[ai]
            return ("nan", (int.from_bytes(raw, "big") & ((1 << width) - 1)) << (64 - width)), i
        return ("float", x), i
    return ("simple", n), i


def is_array(v):
    """A CBOR array as cbor2 gives it: list, or tuple inside a tag in cbor2 6; not a text or byte string."""
    return isinstance(v, Sequence) and not isinstance(v, (str, bytes, bytearray))


def plain(v):
    """v with every array as list and every map as dict, whatever container types cbor2 gives."""
    if is_array(v):
        return [plain(x) for x in v]
    if isinstance(v, Mapping):
        return {k: plain(x) for k, x in v.items()}
    return v


def usable(ref, scheme_alg):
    """ref_usable of Section 6 for the form of A.1: an array of three, the integer -16 (not true or false, not a
    float), the text "ToBeSigned" and a digest of exactly 32 bytes; compatible with the scheme when it names -16."""
    return (is_array(ref) and len(ref) == 3 and type(ref[0]) is int and ref[0] == -16 and type(ref[1]) is str
            and ref[1] == "ToBeSigned" and type(ref[2]) is bytes and len(ref[2]) == 32 and scheme_alg == -16)


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
    obj = loads(b)
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
    pk = keys.get(loads(arr[0]).get(4))
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
    a_enc = A_OF.get(loads(arr[0]).get(4))
    if a_enc is None:
        return False
    return rule_sig_valid(a_enc, arr[3], tbs(arr, aad), cofactored, rule2)


# reference carried by 02 and 03, and the 01 ToBeSigned
a01, _ = decode(stm["01"])
d01 = hashlib.sha256(tbs(a01)).hexdigest()
for n in ("02", "03"):
    arr, sc = decode(stm[n])
    refs = loads(arr[0]).get(-70001)
    print(f"statement {n}: refs {[(r[0], r[1], r[2].hex()[:16]) for r in refs]}, is_scitt {sc}, sig_valid {sig_ok(arr)}")
    assert plain(refs) == [[-16, "ToBeSigned", bytes.fromhex(ref_stated)]] and sc and sig_ok(arr)
    assert usable(refs[0], -16)
ref02 = plain(loads(decode(stm["02"])[0][0]).get(-70001)[0])   # the reference of A.1, as statement 02 carries it
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
    ref_usable = usable(ref02, scheme_alg)
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
    """None if the candidate is not a statement by Section 6, else its four elements as read_item gives them. The
    candidate and its protected header are each read by read_item; the structure is checked as the reading paragraph
    states it: bare or tag 18, an array of exactly four elements, a protected header that is empty or encodes one
    map, an unprotected map, a payload that is a byte string or nil, a signature that is a byte string. Only NotRead
    and a wrong form mean "not a statement"; ResourceLimit and any other exception pass."""
    try:
        top = read_item(b)
        if top[0] == "tag":
            if top[1] != 18:
                return None
            top = top[2]
        if top[0] != "array" or len(top[1]) != 4:
            return None
        prot, unprot, payload, sig = top[1]
        if prot[0] != "bytes" or unprot[0] != "map" or sig[0] != "bytes" \
                or not (payload[0] == "bytes" or payload == ("simple", 22)):
            return None
        if prot[1] and read_item(prot[1])[0] != "map":
            return None
        return top[1]
    except NotRead:
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
    ref_usable = usable(ref02, scheme_alg)
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

# Review point 9 of 2026-10-08: C12 is rebuilt from statement 01 and the sentence of Section 6
c12_text = ("Case C12 keeps tag 18 and every element of statement 01 and writes the head of the four-element array "
            "with a one-byte length argument (98 04 in place of 84), which is well-formed but not the preferred "
            "encoding: as in C5, the ToBeSigned reference matches and the signature verifies while the "
            "whole-object digest changes.")
a4_text = "(an added unprotected parameter, C5; a changed outer encoding, C12)"
print(f"C12 sentence of Section 6 found: {c12_text in body}; A4 names C5 and C12: {a4_text in body}")
fails += c12_text not in body or a4_text not in body
c12_seg = next(a3[k: cidx[n + 1] if n + 1 < len(cidx) else len(a3)] for n, k in enumerate(cidx)
               if re.match(r"^A\.3\.\d+\.  C12 ", a3[k]))
c12_stated = hexblock(c12_seg)
c12_built = stm["01"][:1] + b"\x98\x04" + stm["01"][2:] if stm["01"][:2] == b"\xd2\x84" else b""
head = (c12_built[0], c12_built[1] >> 5, c12_built[1] & 31, c12_built[2]) if c12_built else ()
a12, sc12 = decode(c12_built) if c12_built else (None, False)
same_tbs = a12 is not None and tbs(a12) == tbs(a01)
renc = cbor2.dumps(cbor2.CBORTag(18, a12)) == stm["01"] if a12 is not None else False
print(f"C12 built from statement 01 equals the bytes of Appendix A: {c12_built == c12_stated}; tag byte d2 kept, "
      f"array head major {head[1] if head else '-'} with additional information {head[2] if head else '-'} and "
      f"argument {head[3] if head else '-'}; ToBeSigned equal to that of 01: {same_tbs}; whole-object SHA-256 "
      f"differs: {hashlib.sha256(c12_built).digest() != hashlib.sha256(stm['01']).digest()}; re-encoded in "
      f"preferred form it is statement 01 again: {renc}")
fails += not (c12_built == c12_stated and head == (0xD2, 4, 24, 4) and sc12 and same_tbs and renc
              and hashlib.sha256(c12_built).digest() != hashlib.sha256(stm["01"]).digest())
print("deviations after the C12 round:", fails)

# Depth limit (2026-10-12): the candidate and its protected header, each read on its own, stop at MAX_DEPTH
a01_at = 2 + len(cbor2.dumps(a01[0]))   # the offset of the empty unprotected map of statement 01
assert stm["01"][:2] == b"\xd2\x84" and stm["01"][a01_at] == 0xA0
rest01 = stm["01"][a01_at + 1:]


def deep(kind, n):
    return {"a": b"\x81", "m": b"\xa1\x01", "t": b"\xc6"}[kind] * n + b"\x00"


def unprot01(inner):
    return stm["01"][:a01_at] + b"\xa1\x20" + inner + rest01


def prot01(inner):
    return b"\xd2\x84" + cbor2.dumps(b"\xa1\x20" + inner) + b"\xa0" + rest01


def padded01(n):
    """Statement 01 with its unprotected header {-1: a byte string}, n bytes in all (the size limit)."""
    k = n - len(stm["01"])
    while len(unprot01(cbor2.dumps(bytes(k)))) > n:
        k -= 1
    out = unprot01(cbor2.dumps(bytes(k)))
    assert len(out) == n
    return out


def axes_or_limit(b):
    try:
        if read_strict(b) is None:
            return axes_of_no_statement(-16)
        arr, is_scitt = decode(b)
        match = "INDETERMINATE" if arr[2] is None else \
            ("MATCH" if hashlib.sha256(tbs(arr)).hexdigest() == ref_stated else "NO_MATCH")
        return ("True", match, str(is_scitt), str(sig_ok(arr)))
    except ResourceLimit:
        return "resource-limit error"


rl = "resource-limit error"
for what, b, expect in (
        ("the candidate: arrays 60000 deep", deep("a", 60000), rl),
        ("the candidate: maps 30000 deep", deep("m", 30000), rl),
        ("the candidate: tags 30000 deep", deep("t", 30000), rl),
        ("01, unprotected {-1: arrays 60000 deep}", unprot01(deep("a", 60000)), rl),
        ("01, unprotected {-1: maps 30000 deep}", unprot01(deep("m", 30000)), rl),
        ("01, unprotected {-1: tags 30000 deep}", unprot01(deep("t", 30000)), rl),
        ("the candidate: arrays, deepest item at %d" % MAX_DEPTH, deep("a", MAX_DEPTH),
         ("True", "NO_MATCH", "False", "None")),
        ("the candidate: arrays, deepest item at %d" % (MAX_DEPTH + 1), deep("a", MAX_DEPTH + 1), rl),
        ("01, unprotected, deepest item at %d" % MAX_DEPTH, unprot01(deep("a", MAX_DEPTH - 3)),
         ("True", "MATCH", "True", "True")),
        ("01, unprotected, deepest item at %d" % (MAX_DEPTH + 1), unprot01(deep("a", MAX_DEPTH - 2)), rl),
        ("01, protected header, deepest item at %d" % MAX_DEPTH, prot01(deep("a", MAX_DEPTH - 1)),
         ("True", "NO_MATCH", "True", "False")),
        ("01, protected header, deepest item at %d" % (MAX_DEPTH + 1), prot01(deep("a", MAX_DEPTH)), rl),
        ("01, unprotected {-1: a byte string}, %d bytes in all" % MAX_INPUT_BYTES, padded01(MAX_INPUT_BYTES),
         ("True", "MATCH", "True", "True")),
        ("01, unprotected {-1: a byte string}, %d bytes in all" % (MAX_INPUT_BYTES + 1), padded01(MAX_INPUT_BYTES + 1),
         rl)):
    got = axes_or_limit(b)
    print(f"depth probe {what}: {got} {'OK' if got == expect else 'DIFF, expected ' + str(expect)}")
    fails += got != expect
print("deviations after the depth round:", fails)

# Tools round (2026-10-12): the reader of Section 6, the form of the reference of A.1, and what "not a statement" is
for n in ("01", "02", "03"):
    got = read_strict(stm[n]) is not None
    print(f"tools probe: statement {n} is read as a statement: {got} {'OK' if got else 'DIFF'}")
    fails += not got
d32 = bytes.fromhex(ref_stated)
a01_lenient = decode(stm["01"])[0]   # the match column reads statement 01 with cbor2, as the cases above do
for what, ref, expect in (
        ("the reference of statement 02", ref02, True),
        ("the same as a tuple, as cbor2 6 gives an array inside a tag", tuple(ref02), True),
        ("covers COSE_Sign1", [-16, "COSE_Sign1", d32], False),
        ("covers COSE_Sign1 with the digest of the whole statement 01",
         [-16, "COSE_Sign1", hashlib.sha256(stm["01"]).digest()], False),
        ("covers tobesigned", [-16, "tobesigned", d32], False),
        ("a digest of 0 bytes", [-16, "ToBeSigned", b""], False),
        ("a digest of 31 bytes", [-16, "ToBeSigned", d32[:31]], False),
        ("a digest of 33 bytes", [-16, "ToBeSigned", d32 + b"\x00"], False),
        ("the digest as text", [-16, "ToBeSigned", ref_stated], False),
        ("the algorithm -16.0", [-16.0, "ToBeSigned", d32], False),
        ("the algorithm true", [True, "ToBeSigned", d32], False),
        ("the algorithm -44", [-44, "ToBeSigned", d32], False),
        ("the algorithm as text", ["-16", "ToBeSigned", d32], False),
        ("two elements", [-16, "ToBeSigned"], False),
        ("four elements", [-16, "ToBeSigned", d32, b""], False),
        ("not an array", d32, False)):
    got = usable(ref, -16)
    match = ("MATCH" if hashlib.sha256(tbs(a01_lenient)).hexdigest() == ref_stated else "NO_MATCH") \
        if got else "INDETERMINATE"
    print(f"tools probe: reference with {what}: ref_usable {got}, match on statement 01 {match} "
          f"{'OK' if got == expect else 'DIFF, expected ' + str(expect)}")
    fails += got != expect
for what, b, expect in (
        ("statement 01 and one byte 00 after it", stm["01"] + b"\x00", False),
        ("statement 01, unprotected {-1: tag 37 around one byte}", unprot01(b"\xd8\x25\x41\x00"), True),
        ("statement 01, unprotected {-1: tag 1 around a text}", unprot01(b"\xc1\x61\x78"), True),
        ("statement 01, unprotected {-1: tag 4 around [1, 2]}", unprot01(b"\xc4\x82\x01\x02"), True),
        ("statement 01, unprotected {1: 0, true: 0}", stm["01"][:a01_at] + b"\xa2\x01\x00\xf5\x00" + rest01, True),
        ("statement 01, unprotected {0.0: 0, -0.0: 0}",
         stm["01"][:a01_at] + b"\xa2\xf9\x00\x00\x00\xf9\x80\x00\x00" + rest01, False)):
    try:
        cb = "reads" if cbor2.loads(b) is not None else "reads"
    except Exception as e:  # noqa: BLE001 - only the cbor2 column, for comparison
        cb = "refuses (%s)" % type(e).__name__
    got = read_strict(b) is not None
    print(f"tools probe: {what}: a statement by Section 6: {got} (cbor2 {cb}) "
          f"{'OK' if got == expect else 'DIFF, expected ' + str(expect)}")
    fails += got != expect
_read_item = read_item
for injected in (RuntimeError("injected"), ValueError("injected"), KeyError("injected")):
    def read_item(b, _e=injected):   # noqa: F811 - an exception that is not a reading error, injected for this probe
        raise _e
    try:
        got = "not a statement" if read_strict(stm["01"]) is None else "read"
    except type(injected):
        got = "passes"
    read_item = _read_item
    print(f"tools probe: an injected {type(injected).__name__} in the reader {got} "
          f"{'OK' if got == 'passes' else 'DIFF, expected passes'}")
    fails += got != "passes"
print("deviations after the tools round:", fails)

# Revision -02 (2026-10-12): the name, A2, Section 11, no Open Items, Open Question 2, the appendix of changes
flat02 = re.sub(r"\s+", " ", re.sub(r"(?<=\S-)\n\s*(?=\S)", "", "\n".join(lines)))
s02 = ["Recomputing a target digest may still require the target's payload bytes;",
       "On 2026-10-12, the checker of that package as merged into the main branch of proofbundle, at commit "
       "3611eb73fca16cf68ef47af00fd5193f733bc552, was applied to the twelve cases of Section 6 with the bytes of "
       "Appendix A: its own reading, ToBeSigned, signature and digest functions gave all four axes of the table for "
       "nine cases directly and for C10 with the scheme and the reference algorithm exchanged, because the package "
       "takes no scheme as input; it has no external_aad input and gives for C7 the result under the fixed empty external_aad rule that "
       "the case also records, and it refuses C8, whose payload is nil, as malformed.",
       "A further checker, written from the published text of this document alone, reproduced the four axes of 11 "
       "of the 12 cases directly and those of C10 in that mirrored form, as it also takes no scheme as input, and "
       "showed no deviation over 30237 generated inputs (measured on 2026-10-12).",
       "2. Registration derivation. That open question stands:"]
i_ch02 = next((i for i, ln in enumerate(lines) if ln.rstrip() == "Changes (to be removed before publication)"), None)
i_pv02 = next((i for i, ln in enumerate(lines) if ln.rstrip() == "Provenance"), None)
i_aa02 = next((i for i, ln in enumerate(lines) if ln.rstrip() == "Author's Address"), None)
ch02 = (re.sub(r"\s+", " ", re.sub(r"(?<=\S-)\n\s*(?=\S)", "", "\n".join(lines[i_ch02:i_aa02])))
        if None not in (i_ch02, i_aa02) else "")
s02c = {"01": ['In requirement A2, "may" is no longer written in capitals; recomputing a target digest is not a '
               "permission in the sense of BCP 14.",
               "Requirement A5 says that the illustrative cases in Section 6 do not test leaf hashing or Receipts.",
               "Section 11 adds the measurement of the package on the main branch of proofbundle against the cases of "
               "Section 6, and the result of a further checker written from the text.",
               "Section 11 adds a local check of inclusion receipts from three instances of the ledger and cites pull "
               "request 31 of the CCF Receipt profile [CCF-DATA-HASH].",
               "The Open Items section is removed. The references were checked against the published documents on "
               "2026-10-12; Open Question 2 stays in Section 10.",
               "This appendix is added."],
        "00": ["Case C12 (requirement A4) is added: statement 01 with the head of its array written with a one-byte "
               "length argument, so that the ToBeSigned reference matches and the signature verifies while the "
               "whole-object digest changes. Its bytes are in Appendix A.",
               "Section 11 adds a second local measurement, on 2026-10-11, with two implementations, the ledger and an "
               "archived emulator. Section 4.4 refers to it and to cases C5 and C12, and states that the emulator's "
               "receipts are not COSE Receipts, so the measurement is not a test of two Transparency Services."]}
h01 = ch02.find("Since draft-gruszka-scitt-statement-identification-01")
h00 = ch02.find("Since draft-gruszka-scitt-statement-identification-00")
got02 = {"01": [b.strip() for b in ch02[h01:h00 if h00 > h01 else None].split(" * ")[1:]] if h01 > -1 else [],
         "00": [b.strip() for b in ch02[h00:].split(" * ")[1:]] if -1 < h01 < h00 else []}
ok02 = (any(ln.strip() == "draft-gruszka-scitt-statement-identification-02" for ln in lines)
        and all(x in flat02 for x in s02) and "MAY still require" not in flat02 and len(cidx) == 12
        and not any(ln.strip().startswith("Open Items") for ln in lines)
        and None not in (i_ch02, i_pv02, i_aa02) and i_pv02 < i_ch02 < i_aa02
        and got02 == s02c)
print("revision -02: name -02, A2 'may' in lowercase, Section 11 and Open Question 2, no Open Items, the appendix of "
      "changes after the Provenance with %d points since -01 and %d since -00: %s; cases %d; missing: %s; differing "
      "points: %s" % (
          len(got02["01"]), len(got02["00"]), "OK" if ok02 else "DIFF", len(cidx),
          ", ".join(x[:40] for x in s02 if x not in flat02) or "none",
          ", ".join("%s %d" % (k, i + 1) for k in s02c for i in range(max(len(s02c[k]), len(got02[k])))
                    if s02c[k][i:i + 1] != got02[k][i:i + 1]) or "none"))
fails += not ok02
print("deviations after the revision -02 round:", fails)
sys.exit(1 if fails else 0)
