#!/usr/bin/python3
"""Independent check of the examples of draft-gruszka-evaluation-receipt-mappings-01
("Draft 2"), written only from the texts of Draft 2 and of
draft-gruszka-signed-evaluation-receipts-01 ("Draft 1").

Round 22 (card DRAFTS-01-INHALT-02, owner choice 3 of 2026-10-11): Open Items ask, besides alg -9, whether the
certificate profile admits an intermediate certificate or a root other than RSA, with the measured reason; R22-OI finds
the item and the measurement in Section 12 that it cites.

Round 21 (card DRAFTS-01-INHALT-01, lab-chain findings): Section 5.2.2 step 2 removes unprotected label 394 when
it is the only label and holds an array of one or more byte strings (the receipts of a Transparent Statement), and
does not read the receipts. Appendix A.9 gives R, the receipt in the Transparent Statement that a local Transparency
Service returned for X1, and T1 to T5 as their parts; R21-* rebuild them from M2, X1 and R, compare the SHA-256 the
text lists and compute each status with status20, which now applies that rule. R21-TEXT finds the sentences of the
lab-chain findings in Sections 5.2.2, 9 and 12 and the limit on where B came from in the copied non-claims list.

Round 20 (card DRAFTS-01-INHALT-01, owner choices of 2026-10-11): Section 5.2 has two profiles. The key profile is
unchanged; the certificate profile has exactly the protected labels 1, 4, 15, 33, 258 and 259, alg -7, an iss of the
form did:x509:0:sha256:F::eku:O and an x5chain of a P-256 leaf and an RSA trust anchor; 5.2.2 selects the profile by
the label set and checks each exactly. Appendix A.8 gives X1 in full and X2 to X6 as a change of X1 with their own
signature; R20-* read the certificates, F and O, rebuild X2 to X6 from X1 and the change the text names, and compute
every status with status20, which adds to status19 a DER reader, RSASSA-PKCS1-v1_5 with SHA-256 and ECDSA P-256 with
SHA-256, all written here (from memory of X.690, RFC 8017 and FIPS 186), each held to the library in a SELF check.
Section 5.1 takes proposals P1 and P2 of the CPB comparison; Appendix A.7 gives R1 to R6, whose state and matching
result R20-R* compute. Two defects of this script were found and fixed in this round: the absolute-URI grammar knew
only the "//" authority form of hier-part (a did:x509 identifier was wrongly no absolute URI), and match_rule took the
union of the carriers' names for SHA-256, so a typed digest reference with sha-256 gave MATCH where the text gives
INDETERMINATE (R3; check R20-CARRIER). Neither changed the result of an earlier vector.

Round 19 (card DRAFTS-01-VORARBEIT-01, preparation of the -01): Draft 2 has a new Appendix A.6, Status
Vectors: S1 to S8, each a Signed Statement with a candidate receipt of Draft 1, and a table that with M2 names
one statement for each status of Section 5.2.2. R19-* read the table, the foreign test key and every hex block
from the text and compute each status with this script's own implementation of steps 1 to 7 of Section 5.2.2:
step 1 with cbor2 to decode and this script's deterministic encoder to compare, step 2 from the five parameters
of 5.2.1 and the absolute-URI grammar of S522-ISS, step 3 with the key rule of S522-3 and the RFC 9679
thumbprint, step 4 with the Draft 1 Section 4.4 profile of this script, steps 5 to 7 with
statement_steps_5_to_7. R19-A8 holds S1 to the statement of R17-A8 (the third review's counterexample). The
file names read are the -01 names.

Every byte string is extracted from the hex blocks of the two texts.  Draft 1
Section 5 (verification procedure, including the Ed25519 profile of Section 4.4
and RFC 8785 serialization) is implemented here from Draft 1's text; RFC 8032
point decoding, RFC 8785 number/string rules, RFC 8949 Section 4.2.1 and RFC
9679 are written from memory, because those documents are not in this folder.

Round 18 (owner choice of 2026-10-08, card RECEIPT-COSE-ALGS-01): the code's fixture no longer has the
statement for a Receiver that reads -19 only (B10), since no Receiver may refuse -8 under an Ed25519 key, so
Section 12 counts 49 statements; no other text changed. COUNT finds 49 and no longer 50.

Round 17 (owner choice A of 2026-10-08, card 02): every Receiver accepts -19 and -8. 5.2.1 says that a Receiver
MUST accept both values, 5.2.2 step 2 no longer has the sentence on a Receiver that does not accept -8, and
5.2.4 says that every Receiver accepts -8 so that one statement gives one status. R17-ALG finds the three
texts and the old ones gone. R17-A8 builds M2 with alg -8 and a new signature under the Draft 1 issuer seed
(the counterexample of the third review, SHA-256 4ffcd0d2...): the protected header differs from M2 in one
byte, the signature verifies under the issuer key with the library and with the own profile, and the alg
value is one that 5.2.1 now admits for every Receiver. [VSA] points at SLSA v1.2 (R17-VSA), the ABAK
paragraph says that the correspondences are not a conformance claim (R17-ABAK), and the Open Item on
re-checking SLSA is gone while the in-toto sentence stays (R17-OI). R16-OPEN no longer holds the old 5.2.4
sentence, which this round replaces.

Round 16 (owner choices of 2026-10-08, before submission): Draft 1's vector P11 is N61 (only its identifier
changed), so A.1 is read at "used only by vector N61". Draft 2 drops the open item on accepting -8 and keeps
the rule of 5.2.1 and 5.2.4; Section 12 says that the signature of M2 is checked from the text alone, with
the Sig_structure built by hand and a general Ed25519 implementation, without a COSE library (checks M2-17
and M2-18). R16-OPEN finds the item gone and the rule unchanged; R16-M2 finds the sentence and holds it to
this run: M2-17 and M2-18 hold, and no COSE library is loaded in this process. R16-REFS holds every Draft 1
vector Draft 2 names to Draft 1's text: it exists there, a P vector expects PASS and an N vector FAIL.

Round 15 (owner choices of 2026-10-08, Restpunkte): Draft 1 10.1 is titled "Media Type Registration
Template" and still holds the template and the sentence that the type identifies B, so T2 expects that
title for '[RECEIPTS] Section 10.1'; no other check changed. cbor2 6 returns the content of a tag immutable,
an array as tuple and a map as cbor2.frozendict (no dict), where cbor2 5.4.6 returns list and dict. Every
place that reads decoded CBOR now takes an array as list or tuple and a map as any mapping: the encoder
cenc, M2-2 (the four-element array of the COSE_Sign1) and M2-10 (the CWT Claims map). The run prints the
cbor2 and cryptography versions it ran with.

Round 14 (owner choices of 2026-10-08): the type is application/vnd.signed-evidence.eval-receipt+json and
the payload schema https://signed-evidence.org/eval-receipt/v1; every example is regenerated under them. Draft 1
has no Section 10.2 any more and its 10.1 is an informational template. Checks R14-* find the new type in
the artwork, the VSA and the CPB declaration, no old name, the 10.1 sentence Draft 2 relies on, and the
measurement date of the foreign verifiers.

Round 13 (owner answers of 2026-10-07): the set of statements counts 50 with B50, the float 1.5 as a sixth key
in single precision. Check S522-1F computes, from the text's deterministic encoding (RFC 8949 Section 4.2.1)
and an IEEE 754 conversion written here, that 1.5 fits half precision, so fa 3fc00000 is not the shortest form
and the status is malformed; COUNT finds 50.

Round 12 (supplement of 2026-10-07): Section 5.2.2 step 1 names the key equivalence of RFC 8949 Section
5.6.1 (1 and true are two keys, 0.0 and -0.0 are one) and says that step 1 does not check whether a tag's
content is valid for that tag (Section 5.3.2) while the data items inside a tag are checked like any other;
the set of statements counts 49. Check S522-1B finds the new sentences; S522-1E computes the equivalence on
the encodings of 0.0, -0.0, 1 and true; S522-1T computes a tag 1 around a text of the one byte ff (well-formed,
its inner text no UTF-8, so malformed); S522-ISS computes iss https://issuer.example/e[val against the
absolute-URI grammar of RFC 3986 (written here from the RFC's ABNF, Sections 3 and 3.2.2): "[" stands only in an
IP-literal, so the iss is no absolute URI and the statement is outside_profile; COUNT finds 49.

Round 11 (adversarial review, owner choices of 2026-10-07): Section 5.2.2 step 1 limits validity to RFC
8949 Section 5.3.1, names duplicate keys as data items (Section 5.6, 1 and true are two keys), does not check
a tag's content and draws the line to step 2; the general resource-limit sentence replaces the one for step
5; Section 6 step 1 is the procedure in three outcomes; DSSE is dated 28 May 2024. Checks S522-1B, S522-RL
(revised), S6-1 and REF-DSSE find the sentences; S522-1V keeps its computation with the new wording.

Round 10: Draft 2 Section 5.2.2 step 1 says that a data item that is well-formed but not valid (RFC 8949
Section 5.3), such as a text string that is not valid UTF-8, is malformed. Check S522-1V finds the sentence
and computes it on M2 with one byte of iss replaced by 0xff: the byte stands inside the content of the iss
text string, so every head and length is unchanged and the item stays well-formed, the content is no UTF-8,
and a decoder that checks validity refuses the protected header.

Round 9: Draft 1 Section 4.4 rule 2 requires A and R of order L (L*P is the neutral element and P is not);
Draft 1 vector P11 becomes a FAIL at step 11 (profile 2, key) and N59 (R of mixed order) is new. Draft 2
Section 5.2.2 step 3 counts a statement key only if it is a canonical encoding of a point of order L. Check
S522-3 finds the sentence and recomputes it on the mixed-order test key, the issuer key and the neutral
element.

Round 8: Draft 2 Section 3.3 step 2 and Section 5.2.2 step 5 take up the third outcome of Draft 1
Section 5, a resource-limit error; Sections 4.1 and 8 say what a DSSE signature check shows. Checks
S522-RL, S33-RL and S41-DSSE find the sentences and compute them with a Receiver's limits (an input-size
limit, a budget of scalar multiplications) and a body that is not JSON; R8-OLD checks the old sentences
are gone.

Round 7: Draft 2 Section 3.3 step 1 adds a sentence: the rule is narrower than the in-toto DigestSet
guidance (any acceptable field matches); a set without sha256 gives INDETERMINATE, one whose sha256 entry
passes step 1 but differs from SHA-256 over B gives NO_MATCH whatever its other entries are. Check
S33-NARROW finds the sentence and computes each of its cases with the rule of steps 1 to 3, together with
the two cases the sentence leaves to steps 1 and 2 (a malformed sha256 entry, a candidate without B).

Round 6: Draft 1 Appendix A.1 adds a mixed-order test key for its new vector P11; it is read from the
text (the line after "... and the public key (base64, 32 bytes):"), and P11 joins the calibration.
Draft 2 changes no example byte; its new rules for checking a statement (pairs of issuer and key,
the rules of Draft 1 Section 4.4 for the statement signature) have no example in Draft 2 itself.

Round 4: Draft 1 has no inclusion member any more (receipt object exactly
schema, payload_b64, signature; eleven steps in Section 5; the optional Payload
member criteria_digest of Section 3.5).  Draft 2 cites P1, P4 and P6 as three
receipts with the same B (cases C1 to C3), has eight cases, no leaf hash, a typed
digest reference (5.1), a PRML section (6) and an Abak section (7).

Check categories:
  D2    a claim made by Draft 2 about its examples (the document under test)
  D1CAL calibration of this script's Draft 1 Section 6 implementation against
        Draft 1's own vectors (not a claim of Draft 2)
  SELF  self-test of this script's primitives
  DEMO  a value constructed by this script to test a Draft 2 statement that
        no given vector covers (not bytes from either draft)
"""
import base64
import hashlib
import json as _json
import os
import re
import struct as _struct
import sys
from collections.abc import Mapping
from decimal import Decimal
from decimal import Decimal as _D
from importlib.metadata import version

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
D2_PATH = os.path.join(HERE, "..", "draft", "draft-gruszka-evaluation-receipt-mappings-01.txt")
D1_PATH = os.path.join(HERE, "..", "..", "ser", "draft", "draft-gruszka-signed-evaluation-receipts-01.txt")

RESULTS = []  # (category, id, ok, title)


def check(cat, cid, ok, title, *measured):
    ok = bool(ok)
    RESULTS.append((cat, cid, ok, title))
    print("[%s] %s %s: %s" % ("HOLDS" if ok else "FAILS", cat, cid, title))
    for m in measured:
        print("      " + str(m))


def info(*lines):
    for line in lines:
        print("      " + str(line))


def sha256(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------------------
# Text handling
# ---------------------------------------------------------------------------
FOOTER = re.compile(r"^Gruszka\s+Expires .*\[Page \d+\]\s*$")
HEADER = re.compile(r"^Internet-Draft\s+.*\s+October 2026\s*$")
HEXLINE = re.compile(r"^\s*[0-9a-f]+\s*$")


def load_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().replace("\f", "")
    out = []
    for line in raw.split("\n"):
        if FOOTER.match(line) or HEADER.match(line):
            continue
        out.append(line.rstrip())
    return out


def find_line(lines, pattern, start=0, end=None):
    rx = re.compile(pattern)
    end = len(lines) if end is None else end
    for i in range(start, end):
        if rx.search(lines[i]):
            return i
    raise LookupError("pattern not found: %r" % pattern)


def hex_block(lines, label_idx):
    """Hex block after the label at label_idx (label may wrap; the block
    starts after the first line at or after label_idx that ends with ':')."""
    i = label_idx
    while not lines[i].rstrip().endswith(":"):
        i += 1
    i += 1
    parts = []
    n = len(lines)
    while i < n:
        s = lines[i].strip()
        if s == "":
            j = i
            while j < n and lines[j].strip() == "":
                j += 1
            if parts and j < n and HEXLINE.match(lines[j]):
                i = j
                continue
            if not parts:
                i = j
                continue
            break
        if HEXLINE.match(lines[i]):
            parts.append(s)
            i += 1
        else:
            break
    if not parts:
        raise LookupError("no hex block after line %d" % label_idx)
    return bytes.fromhex("".join(parts))


def next_text(lines, label_idx):
    i = label_idx + 1
    while lines[i].strip() == "":
        i += 1
    return lines[i].strip(), i


def norm_ws(s):
    s = re.sub(r"\s+", " ", s).strip()
    return re.sub(r"- (?=\w)", "-", s)


# ---------------------------------------------------------------------------
# Ed25519 arithmetic (RFC 8032, written from memory) and the Draft 1
# Section 4.4 verification profile
# ---------------------------------------------------------------------------
P = 2 ** 255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
L = 2 ** 252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (P - 1) // 4, P)
NEUTRAL = (0, 1, 1, 0)


def decode_point(b):
    """RFC 8032 Section 5.1.3 decoding; None on failure."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    x0 = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == u % P:
        pass
    elif vx2 == (-u) % P:
        x = (x * SQRT_M1) % P
    else:
        return None
    if x == 0 and x0 == 1:
        return None
    if x % 2 != x0:
        x = P - x
    return (x, y, 1, (x * y) % P)


def padd(p1, p2):
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = T1 * 2 * D * T2 % P
    DD = Z1 * 2 * Z2 % P
    E, F, G, H = B - A, DD - C, DD + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def smul(k, pt):
    q = NEUTRAL
    while k > 0:
        if k & 1:
            q = padd(q, pt)
        pt = padd(pt, pt)
        k >>= 1
    return q


def is_neutral(pt):
    X, Y, Z, _ = pt
    return X % P == 0 and (Y - Z) % P == 0


def peq(p1, p2):
    X1, Y1, Z1, _ = p1
    X2, Y2, Z2, _ = p2
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0


def encode_point(pt):
    X, Y, Z, _ = pt
    zi = pow(Z, P - 2, P)
    x, y = X * zi % P, Y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


BASE = decode_point(((4 * pow(5, P - 2, P)) % P).to_bytes(32, "little"))


def pubkey_from_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encode_point(smul(a, BASE))


def profile_verify(key, sig, msg):
    """Draft 1 Section 4.4.  Returns None if valid, else the failing rule."""
    R_b, S = sig[:32], int.from_bytes(sig[32:], "little")
    A = decode_point(key)
    if A is None:
        return "profile 1, key"
    R = decode_point(R_b)
    if R is None:
        return "profile 1, R"
    # rule 2 (round 9): order L, L*P is the neutral element and P is not
    if is_neutral(A) or not is_neutral(smul(L, A)):
        return "profile 2, key"
    if is_neutral(R) or not is_neutral(smul(L, R)):
        return "profile 2, R"
    if S >= L:
        return "profile 3"
    k = int.from_bytes(hashlib.sha512(R_b + key + msg).digest(), "little") % L
    if not peq(smul(S, BASE), padd(R, smul(k, A))):
        return "profile 4"
    return None


def lib_verify(key, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# I-JSON parser (Draft 1 Section 3.1 / step 1 / step 4 rules)
# ---------------------------------------------------------------------------
class JErr(Exception):
    pass


class JObj:
    def __init__(self, pairs):
        self.pairs = pairs
        self.d = dict(pairs)


class JNum:
    def __init__(self, token):
        self.token = token
        self.value = float(token)  # IEEE 754, nearest-even, overflow -> inf


NUM_RX = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def bad_cp(cp):
    return (0xD800 <= cp <= 0xDFFF) or (0xFDD0 <= cp <= 0xFDEF) or ((cp & 0xFFFE) == 0xFFFE)


class Parser:
    def __init__(self, s):
        self.s, self.i = s, 0

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t\n\r":
            self.i += 1

    def peek(self):
        if self.i >= len(self.s):
            raise JErr("unexpected end")
        return self.s[self.i]

    def value(self):
        c = self.peek()
        if c == "{":
            return self.obj()
        if c == "[":
            return self.arr()
        if c == '"':
            return self.string()
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        m = NUM_RX.match(self.s, self.i)
        if m and m.end() > self.i:
            self.i = m.end()
            return JNum(m.group(0))
        raise JErr("unexpected character %r at %d" % (c, self.i))

    def obj(self):
        self.i += 1
        pairs, seen = [], set()
        self.ws()
        if self.peek() == "}":
            self.i += 1
            return JObj(pairs)
        while True:
            self.ws()
            if self.peek() != '"':
                raise JErr("member name expected")
            k = self.string()
            if k in seen:
                raise JErr("duplicate member name %r" % k)
            seen.add(k)
            self.ws()
            if self.peek() != ":":
                raise JErr("colon expected")
            self.i += 1
            self.ws()
            v = self.value()
            pairs.append((k, v))
            self.ws()
            c = self.peek()
            self.i += 1
            if c == "}":
                return JObj(pairs)
            if c != ",":
                raise JErr("comma expected")

    def arr(self):
        self.i += 1
        out = []
        self.ws()
        if self.peek() == "]":
            self.i += 1
            return out
        while True:
            self.ws()
            out.append(self.value())
            self.ws()
            c = self.peek()
            self.i += 1
            if c == "]":
                return out
            if c != ",":
                raise JErr("comma expected in array")

    def hex4(self):
        h = self.s[self.i:self.i + 4]
        if not re.fullmatch(r"[0-9A-Fa-f]{4}", h):
            raise JErr("bad \\u escape")
        self.i += 4
        return int(h, 16)

    def string(self):
        self.i += 1
        out = []
        while True:
            c = self.peek()
            self.i += 1
            if c == '"':
                break
            if c == "\\":
                e = self.peek()
                self.i += 1
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
                          "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    out.append(simple[e])
                elif e == "u":
                    cp = self.hex4()
                    if 0xD800 <= cp <= 0xDBFF and self.s.startswith("\\u", self.i):
                        save = self.i
                        self.i += 2
                        lo = self.hex4()
                        if 0xDC00 <= lo <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                        else:
                            self.i = save
                    out.append(chr(cp))
                else:
                    raise JErr("bad escape")
            elif ord(c) < 0x20:
                raise JErr("control character in string")
            else:
                out.append(c)
        s = "".join(out)
        for ch in s:
            if bad_cp(ord(ch)):
                raise JErr("surrogate or noncharacter U+%04X in string" % ord(ch))
        return s


def parse_ijson(b):
    if b.startswith(b"\xef\xbb\xbf"):
        raise JErr("byte order mark")
    try:
        s = b.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        raise JErr("not UTF-8: %s" % e)
    p = Parser(s)
    p.ws()
    v = p.value()
    p.ws()
    if p.i != len(s):
        raise JErr("data after the end of the JSON text")
    return v


# ---------------------------------------------------------------------------
# RFC 8785 serialization (written from memory of RFC 8785 / ECMAScript)
# ---------------------------------------------------------------------------
def es_number(x):
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("no finite double")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + es_number(-x)
    t = Decimal(repr(x)).as_tuple()
    digits = list(t.digits)
    exp = t.exponent
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    ds = "".join(map(str, digits))
    k = len(ds)
    n = k + exp
    if k <= n <= 21:
        return ds + "0" * (n - k)
    if 0 < n <= 21:
        return ds[:n] + "." + ds[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + ds
    e = n - 1
    sign = "+" if e >= 0 else "-"
    if k == 1:
        return ds + "e" + sign + str(abs(e))
    return ds[0] + "." + ds[1:] + "e" + sign + str(abs(e))


def jcs_str(s):
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


def jcs(v):
    if isinstance(v, JObj):
        items = sorted(v.pairs, key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(jcs_str(k) + ":" + jcs(x) for k, x in items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, str):
        return jcs_str(v)
    if isinstance(v, JNum):
        return es_number(v.value)
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    raise TypeError(type(v))


# ---------------------------------------------------------------------------
# Draft 1 Section 6
# ---------------------------------------------------------------------------
TYPE = "application/vnd.signed-evidence.eval-receipt+json"
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"
COMMIT_ALG = "sha256-salted-v1"
PAYLOAD_MEMBERS = {"schema", "suite", "suite_version", "metric", "comparator",
                   "threshold", "score", "passed", "n", "model_id_commit",
                   "dataset_id_commit", "commit_alg", "timestamp"}
DEC_RX = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
TS_RX = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
COMMIT_RX = re.compile(r"sha256:[0-9a-f]{64}")
HEX64_RX = re.compile(r"[0-9a-f]{64}")
INT_TOKEN_RX = re.compile(r"0|[1-9][0-9]*")


def pae(t, body):
    tb = t.encode("utf-8")
    return b"DSSEv1 " + str(len(tb)).encode() + b" " + tb + b" " + str(len(body)).encode() + b" " + body


def canon_b64(s):
    if not isinstance(s, str):
        return None
    if len(s) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", s):
        return None
    try:
        b = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if base64.b64encode(b).decode("ascii") != s:
        return None
    return b


def ts_ok(s):
    if not isinstance(s, str):
        return False
    m = TS_RX.fullmatch(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(g) for g in m.groups())
    if not 1 <= mo <= 12:
        return False
    leap = (y % 4 == 0) and (y % 100 != 0 or y % 400 == 0)
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return 1 <= d <= dim and h <= 23 and mi <= 59 and se <= 59


def nonempty(v):
    return isinstance(v, str) and len(v) >= 1


def steps_1_to_3(rb):
    """Returns (B, None) or (None, (step, reason)).  Also returns parsed receipt."""
    try:
        rec = parse_ijson(rb)
    except JErr as e:
        return None, (1, str(e)), None
    if not isinstance(rec, JObj) or set(rec.d) != {"schema", "payload_b64", "signature"} \
            or len(rec.pairs) != 3:
        return None, (1, "top-level member set"), None
    sig = rec.d["signature"]
    if not isinstance(sig, JObj) or set(sig.d) not in ({"alg", "sig"}, {"alg", "sig", "key"}):
        return None, (1, "signature member set"), None
    if not (isinstance(rec.d["schema"], str) and rec.d["schema"] == TYPE):
        return None, (2, "schema is not the type"), rec
    B = canon_b64(rec.d["payload_b64"])
    if B is None:
        return None, (3, "payload_b64 not canonical base64"), rec
    return B, None, rec


def verify_receipt(rb, vkey):
    """Draft 1 Section 5.  Returns (verdict, step, detail, B)."""
    B, fail, rec = steps_1_to_3(rb)
    if fail:
        return ("FAIL", fail[0], fail[1], None)
    # step 4
    try:
        pl = parse_ijson(B)
    except JErr as e:
        return ("FAIL", 4, str(e), B)
    if not isinstance(pl, JObj):
        return ("FAIL", 4, "B is not an object", B)
    # step 5
    try:
        ser = jcs(pl).encode("utf-8")
    except ValueError as e:
        return ("FAIL", 5, str(e), B)
    if ser != B:
        return ("FAIL", 5, "B is not its own RFC 8785 serialization", B)
    # step 6
    m = pl.d
    if set(m) - {"criteria_digest"} != PAYLOAD_MEMBERS:    # 3.2: the only optional member
        return ("FAIL", 6, "payload member set", B)
    digests = ["model_id_commit", "dataset_id_commit"] + (["criteria_digest"] if "criteria_digest" in m else [])
    n = m["n"]
    ok6 = (m["schema"] == PAYLOAD_SCHEMA if isinstance(m["schema"], str) else False) \
        and all(nonempty(m[x]) for x in ("suite", "suite_version", "metric")) \
        and isinstance(m["comparator"], str) and m["comparator"] in (">=", ">", "<=", "<") \
        and all(isinstance(m[x], str) and DEC_RX.fullmatch(m[x]) for x in ("threshold", "score")) \
        and (m["passed"] is True or m["passed"] is False) \
        and isinstance(n, JNum) and n.value == int(n.value) and 1 <= n.value <= 2 ** 53 - 1 \
        and all(isinstance(m[x], str) for x in digests) \
        and isinstance(m["commit_alg"], str) and m["commit_alg"] == COMMIT_ALG \
        and ts_ok(m["timestamp"])
    if not ok6:
        return ("FAIL", 6, "a member violates its row", B)
    # step 7
    if not all(COMMIT_RX.fullmatch(m[x]) for x in digests):
        return ("FAIL", 7, "commitment or criteria_digest pattern", B)
    # step 8
    s, t, c = Decimal(m["score"]), Decimal(m["threshold"]), m["comparator"]
    cmp = {">=": s >= t, ">": s > t, "<=": s <= t, "<": s < t}[c]
    if m["passed"] is not cmp:
        return ("FAIL", 8, "passed disagrees with comparison", B)
    # step 9
    sig = rec.d["signature"].d
    sigb = canon_b64(sig["sig"])
    if not (isinstance(sig["alg"], str) and sig["alg"] == "ed25519") or sigb is None or len(sigb) != 64:
        return ("FAIL", 9, "signature alg/sig", B)
    # step 10
    if "key" in sig:
        if not (isinstance(sig["key"], str) and sig["key"] == base64.b64encode(vkey).decode()):
            return ("FAIL", 10, "key hint is not the verification key", B)
    # step 11
    r = profile_verify(vkey, sigb, pae(TYPE, B))
    if r is not None:
        return ("FAIL", 11, r, B)
    return ("PASS", None, None, B)


# ---------------------------------------------------------------------------
# Draft 2 Section 3.3 matching rule
# ---------------------------------------------------------------------------
# Round 2: Draft 2 Section 3.3 step 1 now names the identifiers: "sha256" in an
# in-toto digest set, -16 in COSE header parameter 258, "sha-256" in the
# examples.  Matched exactly as written (the text does not say case-insensitive).
SHA256_IDS = {"sha256", -16, "sha-256", "SHA-256"}   # round 4: "SHA-256" in a typed digest reference (5.1)


def match_rule(alg, value, rb):
    """value: 64 lowercase hex digits (text form) or 32 bytes (byte form)."""
    if isinstance(value, bytes):
        ok_form = len(value) == 32
        vhex = value.hex()
    else:
        ok_form = isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        vhex = value
    if alg not in SHA256_IDS or isinstance(alg, bool) or not ok_form:
        return "INDETERMINATE", "rule step 1 (algorithm or value form)"
    B, fail, _ = steps_1_to_3(rb)
    if fail:
        return "INDETERMINATE", "rule step 2 (Draft 1 step %d fails: %s)" % fail
    return ("MATCH" if sha256(B).hex() == vhex else "NO_MATCH"), "rule step 3"


#: Round 20: "each name counts only in its own carrier" (3.3 step 1). match_rule above takes the union of the
#: names, which is right for the cases of A.3 (all in the examples' carrier) but too wide for one carrier alone.
CARRIER_NAME = {"digest set": "sha256", "cose": -16, "examples": "sha-256", "typed reference": "SHA-256"}


def match_rule_in(carrier, alg, value, rb):
    if isinstance(alg, bool) or alg != CARRIER_NAME[carrier]:
        return "INDETERMINATE", "rule step 1 (not the name of SHA-256 in this carrier)"
    return match_rule(alg, value, rb)


def match_digest_set(ds, rb):
    """Draft 2 3.3 step 1: a digest set with several entries is matched on its sha256 entry alone."""
    if "sha256" not in ds:
        return "INDETERMINATE", "rule step 1 (no sha256 entry)"
    return match_rule("sha256", ds["sha256"], rb)


# ---------------------------------------------------------------------------
# Deterministic CBOR encoder (RFC 8949 Section 4.2.1 as remembered)
# ---------------------------------------------------------------------------
def chead(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 2 ** (8 * size):
            return bytes([(major << 5) | ai]) + n.to_bytes(size, "big")
    raise ValueError


def cenc(v):
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return chead(0, v) if v >= 0 else chead(1, -1 - v)
    if isinstance(v, bytes):
        return chead(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return chead(3, len(b)) + b
    # An array and a map by their kind: cbor2 6 returns the content of a tag as tuple and cbor2.frozendict.
    if isinstance(v, (list, tuple)):
        return chead(4, len(v)) + b"".join(cenc(x) for x in v)
    if isinstance(v, Mapping):
        items = sorted((cenc(k), cenc(x)) for k, x in v.items())
        return chead(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, cbor2.CBORTag):
        return chead(6, v.tag) + cenc(v.value)
    raise TypeError(type(v))


# ===========================================================================
# Extraction
# ===========================================================================
d1 = load_lines(D1_PATH)
d2 = load_lines(D2_PATH)

# --- Draft 1 constants ---
i = find_line(d1, r"^A\.1\.\s+Constants and Test Material")
iseed = find_line(d1, r"Issuer test key, Ed25519 seed", i)
seed_hex, k1 = next_text(d1, iseed + 1)
pk_b64, _ = next_text(d1, k1)
ISSUER_SEED = bytes.fromhex(seed_hex)
ISSUER_PK = base64.b64decode(pk_b64)
i2 = find_line(d1, r"Second test key", i)
seed2_hex, k2 = next_text(d1, i2 + 1)
pk2_b64, _ = next_text(d1, k2)
SECOND_SEED = bytes.fromhex(seed2_hex)
SECOND_PK = base64.b64decode(pk2_b64)
imx = find_line(d1, r"Mixed-order test key, used only by vector N61", i)
# round 9: the sentence now wraps before "32 bytes):"; take the first line after it that ends so
imx = find_line(d1, r"32 bytes\):\s*$", imx)
t8_hex, kx = next_text(d1, imx)
mx_b64, _ = next_text(d1, kx)
MIXED_PK = base64.b64decode(mx_b64)
im = find_line(d1, r"The model commitment: salt", i)
m_salt, a = next_text(d1, im)
m_id, a = next_text(d1, a)
m_commit, _ = next_text(d1, a)
icrit = find_line(d1, r"The example criteria set of vectors P10 and N57", i)
CRITERIA_BYTES = hex_block(d1, icrit)
_j = icrit
while not d1[_j].strip().startswith("sha256:"):
    _j += 1
CRITERIA_DIGEST_TEXT = d1[_j].strip()
D1_TYPE, _ = next_text(d1, find_line(d1, r"Receipt schema, also the type", i))

# --- Draft 1 vectors ---
HEAD_RX = re.compile(r"^A\.2\.(\d+)\.\s+(\S+) \((.+?); expected (PASS|FAIL), step (.+)\)$")
starts = [j for j, line in enumerate(d1) if re.match(r"^A\.2\.\d+\.\s", line)]
end_vectors = find_line(d1, r"^Open Items")
VEC = {}
for n_, s0 in enumerate(starts):
    s1 = starts[n_ + 1] if n_ + 1 < len(starts) else end_vectors
    head = d1[s0]
    j = s0
    while head.count("(") != head.count(")"):
        j += 1
        head += " " + d1[j].strip()
    m = HEAD_RX.match(head)
    assert m, head
    vid, expected, stepdesc = m.group(2), m.group(4), m.group(5)
    if expected == "PASS":
        exp = ("PASS", None, None)
    else:
        mm = re.match(r"(\d+)(?: \((.+)\))?$", stepdesc)
        exp = ("FAIL", int(mm.group(1)), mm.group(2))
    chunk = d1[s0:s1]
    kidx = find_line(chunk, r"verification key:")
    ktext = chunk[kidx].split("verification key:")[1].strip()
    q = kidx + 1
    while chunk[q].strip():
        ktext += " " + chunk[q].strip()
        q += 1
    if "issuer test key" in ktext:
        vkey = ISSUER_PK
    elif "mixed-order test key" in ktext:
        vkey = MIXED_PK
    elif "non-canonical encoding y = p + 1 (EE, 30 bytes FF, 7F)" in ktext:
        vkey = bytes([0xEE]) + b"\xff" * 30 + bytes([0x7F])
    elif "canonical encoding (01 followed by 31 zero bytes)" in ktext:
        vkey = b"\x01" + b"\x00" * 31
    else:
        raise ValueError(ktext)
    # Round 2: Draft 1 labels either "payload bytes B: ..." or
    # "payload bytes carried (not B: the procedure stops at step N before it obtains B): ..."
    bidx = find_line(chunk, r"payload bytes (B:|carried)")
    btxt = " ".join(x.strip() for x in chunk[bidx:bidx + 4])
    mb = re.search(r"payload bytes (?:B|carried \(not B: the procedure stops at step \d+ before it obtains B\)): "
                   r"(\d+) bytes, SHA-256 ([0-9a-f]{64})", btxt)
    mcar = re.search(r"payload bytes carried \(not B: the procedure stops at step (\d+) before it obtains B\)", btxt)
    b_label = "carried" if mcar else ("none" if re.search(r"payload bytes B: none", btxt) else "B")
    carried_step = int(mcar.group(1)) if mcar else None
    ridx = find_line(chunk, r"receipt bytes:")
    rtxt = " ".join(x.strip() for x in chunk[ridx:ridx + 3])
    mr = re.search(r"receipt bytes: (\d+) bytes, SHA-256 ([0-9a-f]{64})", rtxt)
    try:
        Bv = hex_block(chunk, find_line(chunk, r"^\s+(B|Payload bytes carried) \(hex\):"))
        hex_label = "carried" if any(re.match(r"^\s+Payload bytes carried \(hex\):", x) for x in chunk) else "B"
    except LookupError:
        Bv = None
        hex_label = None
    Rv = hex_block(chunk, find_line(chunk, r"^\s+Receipt \(hex\):"))
    # field "B" holds the payload hex block, whether Draft 1 labels it B or "carried"
    VEC[vid] = dict(exp=exp, vkey=vkey, ktext=ktext, B=Bv, R=Rv,
                    B_len=int(mb.group(1)) if mb else None, B_sha=mb.group(2) if mb else None,
                    R_len=int(mr.group(1)), R_sha=mr.group(2),
                    b_label=b_label, carried_step=carried_step, hex_label=hex_label)

# --- Draft 1 section titles and Section 7 text ---
D1_TITLES = {}
for line in d1:
    mt = re.match(r"^(\d+(?:\.\d+)?)\.\s+(\S.*)$", line)
    if mt:
        D1_TITLES[mt.group(1)] = mt.group(2).strip()

# --- Draft 2 ---
a1 = find_line(d2, r"^A\.1\.\s+Constants")
a2 = find_line(d2, r"^A\.2\.\s+Digests of Vector P1")
a3 = find_line(d2, r"^A\.3\.\s+Citation Cases")
a4 = find_line(d2, r"^A\.4\.\s+M1")
a5 = find_line(d2, r"^A\.5\.\s+M2")
aend = find_line(d2, r"^Open Items")
D2_TYPE, _ = next_text(d2, find_line(d2, r"^\s+Type:", a1))
kpl = find_line(d2, r"Issuer test key, public key \(base64 and hex\)", a1)
D2_PK_B64, q = next_text(d2, kpl)
D2_PK_HEX, _ = next_text(d2, q)
D2_ISS, _ = next_text(d2, find_line(d2, r"Issuer URI of the Signed Statement", a1))

lbl = find_line(d2, r"B, (\d+) bytes \(hex\):", a2)
D2_B_LEN = int(re.search(r"B, (\d+) bytes", d2[lbl]).group(1))
D2_B = hex_block(d2, lbl)
D2_DIGEST = hex_block(d2, find_line(d2, r"Receipt digest, SHA-256 over B:", a2))
D2_RSHA = hex_block(d2, find_line(d2, r"SHA-256 over the receipt bytes of P1", a2))
D2_SHA512 = hex_block(d2, find_line(d2, r"sha-512, this value over the same B:", a3))
D2_CASE_SHA = {}
for line in d2[a3:a4]:
    mc = re.match(r"^\s+(C\d)\s+([0-9a-f]{64})$", line)
    if mc:
        D2_CASE_SHA[mc.group(1)] = mc.group(2)
lp = find_line(d2, r"PAE\(type, B\), (\d+) bytes \(hex\):", a4)
D2_PAE_LEN = int(re.search(r"(\d+) bytes", d2[lp]).group(1))
D2_PAE = hex_block(d2, lp)
le = find_line(d2, r"Envelope, (\d+) bytes \(hex\):", a4)
D2_ENV_LEN = int(re.search(r"(\d+) bytes", d2[le]).group(1))
D2_ENV = hex_block(d2, le)
D2_ENV_SHA = hex_block(d2, find_line(d2, r"SHA-256 over the envelope bytes", a4))
D2_KID = hex_block(d2, find_line(d2, r"kid, the COSE Key Thumbprint", a5))
D2_SUB, _ = next_text(d2, find_line(d2, r"sub, the model commitment of B:", a5))
lph = find_line(d2, r"Protected header, (\d+) bytes \(hex\):", a5)
D2_PH_LEN = int(re.search(r"(\d+) bytes", d2[lph]).group(1))
D2_PH = hex_block(d2, lph)
lss = find_line(d2, r"Sig_structure \(ToBeSigned\), (\d+) bytes", a5)
D2_SS_LEN = int(re.search(r"(\d+) bytes", d2[lss]).group(1))
D2_SS = hex_block(d2, lss)
D2_M2SIG = hex_block(d2, find_line(d2, r"Signature, Ed25519 over the Sig_structure", a5))
lcs = find_line(d2, r"COSE_Sign1, (\d+) bytes \(hex\):", a5)
D2_CS_LEN = int(re.search(r"(\d+) bytes", d2[lcs]).group(1))
D2_CS = hex_block(d2, lcs)
D2_CS_SHA = hex_block(d2, find_line(d2, r"SHA-256 over the COSE_Sign1 bytes:", a5))

# --- Draft 2 Table 1 ---
t_start = find_line(d2, r"^\s+\| Case \| Candidate")
t_end = find_line(d2, r"Table 1: Citation cases")
rows, cur = [], None
for line in d2[t_start:t_end]:
    s = line.strip()
    if s.startswith("+") or not s:
        if s.startswith("+") and cur is not None:
            rows.append(cur)
            cur = None
        continue
    cells = [c for c in s.split("|")[1:-1]]
    if cur is None:
        cur = [""] * len(cells)
    for k, c in enumerate(cells):
        cur[k] += " " + c.strip()
if cur is not None:
    rows.append(cur)
TABLE1 = {}
for r in rows:
    r = [norm_ws(x) for x in r]
    if re.fullmatch(r"C\d", r[0]):
        TABLE1[r[0]] = dict(candidate=r[1], result=r[2], verification=r[3], shows=r[4])


def parse_verif(s):
    if s == "PASS":
        return ("PASS", None, None)
    mv = re.fullmatch(r"FAIL, step (\d+)(?: \((.+)\))?", s)
    return ("FAIL", int(mv.group(1)), mv.group(2))


# ===========================================================================
# Checks
# ===========================================================================
print("Independent check of draft-gruszka-evaluation-receipt-mappings-01 from its text")
print("Python %s, cbor2 %s, cryptography %s" % (sys.version.split()[0], version("cbor2"), version("cryptography")))
print("Draft 1 vectors extracted: %d" % len(VEC))
print()

print("=== SELF: primitives of this script ===")
check("SELF", "S1", pubkey_from_seed(ISSUER_SEED) == ISSUER_PK,
      "own Ed25519 key derivation from Draft 1 issuer seed gives Draft 1 issuer public key",
      "derived " + pubkey_from_seed(ISSUER_SEED).hex(), "given   " + ISSUER_PK.hex())
lib_pk = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
check("SELF", "S2", lib_pk == ISSUER_PK, "pyca/cryptography derivation from the same seed agrees")
check("SELF", "S3", pubkey_from_seed(SECOND_SEED) == SECOND_PK,
      "own derivation of Draft 1 second test key agrees with its given public key")
es_cases = {1800.0: "1800", 0.1: "0.1", 1e21: "1e+21", 1e-7: "1e-7", 123e-20: "1.23e-18",
            9007199254740992.0: "9007199254740992", 0.000001: "0.000001", -0.0: "0"}
check("SELF", "S4", all(es_number(k) == v for k, v in es_cases.items()),
      "own ECMAScript number serialization on 8 known inputs")
nk = bytes([0xEE]) + b"\xff" * 30 + bytes([0x7F])
check("SELF", "S5", int.from_bytes(nk, "little") & ((1 << 255) - 1) == P + 1,
      "Draft 1 text 'EE, 30 bytes FF, 7F' is y = p + 1 (sign bit 0)")
print()

print("=== D1CAL: own Draft 1 Section 5 implementation against all Draft 1 vectors ===")
cal_bad = []
for vid, v in VEC.items():
    got = verify_receipt(v["R"], v["vkey"])
    gotv = (got[0], got[1], got[2] if got[1] == 11 else None)
    expv = (v["exp"][0], v["exp"][1], v["exp"][2] if v["exp"][1] == 11 else None)
    lens_ok = len(v["R"]) == v["R_len"] and sha256(v["R"]).hex() == v["R_sha"]
    if v["B"] is not None:
        lens_ok = lens_ok and len(v["B"]) == v["B_len"] and sha256(v["B"]).hex() == v["B_sha"]
    if gotv != expv or not lens_ok:
        cal_bad.append((vid, expv, gotv, got, lens_ok))
check("D1CAL", "K1", not cal_bad,
      "verdict and first failing step (and profile rule at step 11) equal Draft 1's expected value "
      "for every vector; stated lengths and SHA-256 of B and of receipt bytes equal the hex blocks",
      "vectors run: %d, disagreements: %d" % (len(VEC), len(cal_bad)),
      *["%s expected %s got %s (%s) lengths/hashes ok=%s" % (a, b, c, d, e) for a, b, c, d, e in cal_bad])
pass_ids = [k for k, v in VEC.items() if v["exp"][0] == "PASS"]
check("D1CAL", "K2", all(set(parse_ijson(VEC[k]["R"]).d) == {"schema", "payload_b64", "signature"} for k in pass_ids),
      "every Draft 1 vector that verifies has exactly the receipt members schema, payload_b64, signature (3.1)",
      "PASS vectors: " + ", ".join(pass_ids))
p10 = parse_ijson(VEC["P10"]["B"]).d if "P10" in VEC else {}
check("D1CAL", "K3", p10.get("criteria_digest") == CRITERIA_DIGEST_TEXT == "sha256:" + sha256(CRITERIA_BYTES).hex(),
      "P10's criteria_digest is sha256: followed by SHA-256 over the example criteria set bytes of Draft 1 A.1",
      "criteria bytes %d, digest %s" % (len(CRITERIA_BYTES), CRITERIA_DIGEST_TEXT))
print()

print("=== D2 A.1 constants ===")
check("D2", "A1-1", D2_TYPE == TYPE == D1_TYPE, "type string equals Draft 1's type", D2_TYPE)
check("D2", "A1-2", base64.b64decode(D2_PK_B64) == bytes.fromhex(D2_PK_HEX) == ISSUER_PK,
      "issuer public key: Draft 2 base64 == Draft 2 hex == Draft 1 issuer key (derived from Draft 1 seed, S1)",
      D2_PK_HEX)
print()

print("=== D2 A.2 digests of vector P1 ===")
check("D2", "A2-1", D2_B == VEC["P1"]["B"], "B of Draft 2 A.2 is byte-equal to B of Draft 1 P1")
check("D2", "A2-2", len(D2_B) == D2_B_LEN, "B is %d bytes as stated" % D2_B_LEN, "measured %d" % len(D2_B))
digest = sha256(D2_B)
check("D2", "A2-3", digest == D2_DIGEST, "receipt digest = SHA-256(B)", digest.hex())
check("D2", "A2-4", not any("Leaf hash" in x for x in d2[a2:a3]), "A.2 lists no leaf hash (Draft 1 has no inclusion proof)")
rsha = sha256(VEC["P1"]["R"])
check("D2", "A2-5", rsha == D2_RSHA, "SHA-256 over P1 receipt bytes as stated", rsha.hex())
check("D2", "A2-6", len({digest, rsha}) == 2, "receipt digest and receipt-bytes SHA-256 are two different values")
check("D2", "A2-7", digest.hex() == VEC["P1"]["B_sha"] and rsha.hex() == VEC["P1"]["R_sha"],
      "Draft 2 A.2 values agree with the SHA-256 values Draft 1 states for P1")
print()

print("=== D2 Section 3.2 / 3.4 statements about P1, P4, P6 ===")
three = ["P1", "P4", "P6"]
vr = {x: verify_receipt(VEC[x]["R"], ISSUER_PK) for x in three}
check("D2", "S32-1", len({VEC[x]["R"] for x in three}) == 3 and all(vr[x][0] == "PASS" for x in three)
      and all(vr[x][3] == D2_B for x in three),
      "P1, P4, P6 are three different receipt byte strings, all verify (own Section 5), all carry the same B",
      *["%s: %d bytes, sha256 %s, verdict %s" % (x, len(VEC[x]["R"]), sha256(VEC[x]["R"]).hex(), vr[x][0]) for x in three])
check("D2", "S32-2", len({sha256(VEC[x]["R"]) for x in three}) == 3,
      "a digest over receipt bytes gives the one B three names (three distinct SHA-256 values)")
check("D2", "S34-A3", all(match_rule("sha-256", D2_DIGEST.hex(), VEC[x]["R"])[0] == "MATCH" for x in ("P4", "P6")),
      "A3: C2 (P4) and C3 (P6) carry receipt bytes other than P1's and still MATCH")
p6 = vr["P6"]
check("D2", "S34-A1", p6[0] == "PASS" and p6[3] == D2_B and set(parse_ijson(VEC["P6"]["R"]).d["signature"].d) == {"alg", "sig"},
      "A1 'identity preserved under ... its key hint': P6 (C3) has no key hint, carries the same B and verifies")
print()

print("=== D2 A.3 citation cases and Table 1 ===")
check("D2", "A3-1", hashlib.sha512(D2_B).digest() == D2_SHA512 and len(D2_SHA512) == 64,
      "C8 value is SHA-512 over the same B", hashlib.sha512(D2_B).hexdigest())
check("D2", "A3-2", sorted(TABLE1) == ["C%d" % k for k in range(1, 9)] and sorted(D2_CASE_SHA) == sorted(TABLE1),
      "Table 1 and the A.3 hash list both have exactly cases C1 to C8",
      "Table 1 parsed: " + ", ".join("%s=%s" % (c, TABLE1[c]["candidate"]) for c in sorted(TABLE1)))
for c in sorted(TABLE1):
    row = TABLE1[c]
    cand = row["candidate"]
    v = VEC.get(cand)
    if v is None:
        check("D2", c + "-0", False, "candidate %s found in Draft 1" % cand)
        continue
    rb = v["R"]
    h = sha256(rb).hex()
    check("D2", c + "-a", h == D2_CASE_SHA[c],
          "SHA-256 over candidate %s receipt bytes equals the value Draft 2 A.3 lists" % cand, h)
    alg, val = ("sha-512", D2_SHA512.hex()) if c == "C8" else ("sha-256", D2_DIGEST.hex())
    res, why = match_rule(alg, val, rb)
    check("D2", c + "-b", res == row["result"],
          "matching rule (Section 3.3) on candidate %s with citation %s gives Table 1 result %s" % (cand, alg, row["result"]),
          "computed %s via %s" % (res, why))
    vv = verify_receipt(rb, ISSUER_PK)
    got = (vv[0], vv[1], vv[2] if vv[1] == 11 else None)
    expv = parse_verif(row["verification"])
    check("D2", c + "-c", got == expv,
          "full Draft 1 Section 5 on %s under the issuer key gives Table 1 column '%s'" % (cand, row["verification"]),
          "computed %s step %s %s" % (vv[0], vv[1], vv[2] or ""))
# specific statements in Table 1 'What it shows'
p4raw = VEC["P4"]["R"]
p1raw = VEC["P1"]["R"]
check("D2", "C2-d", p4raw == p1raw.replace(b'"schema":"application/', b'"schema":"application\\/', 1),
      "C2: P4 differs from P1 only by one JSON escape \\/ in schema (one escaped character)",
      "P1 %d bytes, P4 %d bytes" % (len(p1raw), len(p4raw)))
p6sig = parse_ijson(VEC["P6"]["R"]).d["signature"].d
p1sigobj = parse_ijson(p1raw).d["signature"].d
check("D2", "C3-d", set(p6sig) == {"alg", "sig"} and "key" in p1sigobj and p6sig["sig"] == p1sigobj["sig"],
      "C3: P6 differs from P1 by the missing key hint; the signature value is P1's")
check("D2", "C4-d", VEC["P2"]["B"] != D2_B and parse_ijson(VEC["P2"]["B"]).d["passed"] is False,
      "C4: P2 carries another B (passed false)", "SHA-256(B of P2) " + sha256(VEC["P2"]["B"]).hex())
n7 = parse_ijson(VEC["N7"]["R"]).d["signature"].d["sig"]
p1sig = parse_ijson(p1raw).d["signature"].d["sig"]
check("D2", "C5-d", VEC["N7"]["B"] == D2_B and n7 != p1sig,
      "C5: N7 has the same B and another signature value than P1")
check("D2", "S33-C5", verify_receipt(VEC["N7"]["R"], ISSUER_PK)[1] == 11,
      "Section 3.3: 'Case C5 is a candidate that matches and fails that procedure at step 11'")
print()

print("=== D2 A.4 M1, DSSE envelope ===")
check("D2", "M1-1", len(D2_ENV) == D2_ENV_LEN, "envelope is %d bytes as stated" % D2_ENV_LEN, "measured %d" % len(D2_ENV))
env = parse_ijson(D2_ENV)
check("D2", "M1-2", isinstance(env, JObj) and [k for k, _ in env.pairs] == ["payload", "payloadType", "signatures"],
      "envelope is a JSON object with exactly payload, payloadType, signatures, in name order",
      "member order " + str([k for k, _ in env.pairs]))
check("D2", "M1-3", jcs(env).encode() == D2_ENV,
      "envelope is serialized without insignificant whitespace and with sorted members (equals its RFC 8785 form)")
check("D2", "M1-4", env.d["payloadType"] == TYPE, "payloadType is exactly the type")
env_payload = canon_b64(env.d["payload"])
check("D2", "M1-5", env_payload == D2_B and env.d["payload"] == parse_ijson(p1raw).d["payload_b64"],
      "payload decodes (canonical base64) to B, and is the same string as P1's payload_b64")
sigs = env.d["signatures"]
check("D2", "M1-6", isinstance(sigs, list) and len(sigs) == 1 and isinstance(sigs[0], JObj)
      and [k for k, _ in sigs[0].pairs] == ["sig"],
      "signatures has one element with only the member sig (no keyid)")
m1sig = canon_b64(sigs[0].d["sig"])
check("D2", "M1-7", sigs[0].d["sig"] == p1sig and m1sig == canon_b64(p1sig),
      "signatures[0].sig is byte-equal to P1's signature.sig (as string and as decoded 64 bytes)",
      m1sig.hex())
my_pae = pae(env.d["payloadType"], env_payload)
check("D2", "M1-8", my_pae == D2_PAE and len(D2_PAE) == D2_PAE_LEN,
      "PAE(type, B) per Draft 1 Section 4.1 equals the %d bytes given" % D2_PAE_LEN, "measured %d bytes" % len(my_pae))
check("D2", "M1-9", lib_verify(ISSUER_PK, m1sig, my_pae) and profile_verify(ISSUER_PK, m1sig, my_pae) is None,
      "M1 signature verifies as Ed25519 over PAE(payloadType, payload) under the issuer key "
      "(pyca/cryptography and own Section 4.4 profile)")
check("D2", "M1-10", Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).sign(pae(TYPE, D2_B)) == m1sig,
      "re-signing PAE(type, B) with the Draft 1 issuer seed reproduces the M1/P1 signature (Ed25519 is deterministic)")
env_sha = sha256(D2_ENV)
check("D2", "M1-11", env_sha == D2_ENV_SHA, "SHA-256 over envelope bytes as stated", env_sha.hex())
check("D2", "S9-DC", len({digest, rsha, env_sha}) == 3,
      "Section 9 'digest confusion': receipt digest, receipt-bytes SHA-256, envelope SHA-256 are three different values")
others = ["application/json", "application/vnd.in-toto+json", TYPE + " ", TYPE[:-len("+json")]]
check("D2", "S41-T", not any(lib_verify(ISSUER_PK, m1sig, pae(t, D2_B)) for t in others),
      "Section 4.1 'under any other type it fails': fails for a sample of 4 other payloadType strings "
      "(a sample, not a proof of 'any')", *others)
print()

print("=== D2 A.5 M2, COSE_Sign1 ===")
check("D2", "M2-1", len(D2_CS) == D2_CS_LEN and len(D2_PH) == D2_PH_LEN and len(D2_SS) == D2_SS_LEN,
      "stated lengths: COSE_Sign1 %d, protected header %d, Sig_structure %d" % (D2_CS_LEN, D2_PH_LEN, D2_SS_LEN),
      "measured %d, %d, %d" % (len(D2_CS), len(D2_PH), len(D2_SS)))
cs = cbor2.loads(D2_CS)
check("D2", "M2-2", isinstance(cs, cbor2.CBORTag) and cs.tag == 18 and isinstance(cs.value, (list, tuple)) and len(cs.value) == 4,
      "COSE_Sign1 is CBOR tag 18 over a 4-element array")
ph_b, uh, payload, sig2 = cs.value
check("D2", "M2-3", ph_b == D2_PH, "protected header bstr equals the protected header hex given")
check("D2", "M2-4", uh == {}, "unprotected header is the empty map")
check("D2", "M2-5", payload == D2_DIGEST and len(payload) == 32, "payload is the 32-byte receipt digest")
check("D2", "M2-6", sig2 == D2_M2SIG and len(sig2) == 64, "signature equals the Signature hex given (64 bytes)")
ph = cbor2.loads(ph_b)
check("D2", "M2-7", list(ph.keys()) == [1, 4, 15, 258, 259], "protected header keys in this order: 1, 4, 15, 258, 259",
      "decoded key order " + str(list(ph.keys())))
check("D2", "M2-8", ph.get(1) == -19, "alg (1) = -19")
check("D2", "M2-9", ph.get(4) == D2_KID and isinstance(ph.get(4), bytes) and len(ph[4]) == 32, "kid (4) is the 32-byte value given")
cwt = ph.get(15)
check("D2", "M2-10", isinstance(cwt, Mapping) and list(cwt.keys()) == [1, 2] and cwt[1] == D2_ISS == "https://issuer.example/eval"
      and cwt[2] == D2_SUB, "CWT Claims (15) is a map with exactly 1 (iss) = A.1 URI and 2 (sub) = sub text given",
      "iss %r" % cwt.get(1), "sub %r" % cwt.get(2))
p1payload = parse_ijson(D2_B).d
check("D2", "M2-11", D2_SUB == p1payload["model_id_commit"] == m_commit,
      "sub equals B's model_id_commit and Draft 1's model commitment",
      "salt||id check: " + str(("sha256:" + hashlib.sha256(bytes.fromhex(m_salt) + m_id.encode()).hexdigest()) == m_commit))
check("D2", "M2-12", ph.get(258) == -16, "258 (payload hash algorithm) = -16")
check("D2", "M2-13", ph.get(259) == TYPE and isinstance(ph.get(259), str), "259 (preimage content type) = the type, as text")
check("D2", "M2-14", cenc(ph) == ph_b,
      "protected header is the deterministic encoding (own RFC 8949 4.2.1 encoder: shortest heads, bytewise-sorted keys) of its content")
check("D2", "M2-15", cenc(cs) == D2_CS, "whole COSE_Sign1 re-encodes deterministically to the same %d bytes" % len(D2_CS))
cose_key = {1: 1, -1: 6, -2: ISSUER_PK}
thumb = sha256(cenc(cose_key))
check("D2", "M2-16", thumb == D2_KID,
      "kid = SHA-256 over deterministic CBOR of COSE_Key {1(kty):1(OKP), -1(crv):6(Ed25519), -2(x):pk} "
      "(RFC 9679 as remembered)", "COSE_Key " + cenc(cose_key).hex(), "thumbprint " + thumb.hex())
my_ss = cenc(["Signature1", ph_b, b"", payload])
check("D2", "M2-17", my_ss == D2_SS, "Sig_structure ['Signature1', protected, h'', payload] equals the 242 bytes given")
check("D2", "M2-18", lib_verify(ISSUER_PK, sig2, D2_SS) and profile_verify(ISSUER_PK, sig2, D2_SS) is None,
      "M2 signature verifies (Ed25519 over Sig_structure) under the issuer key, library and own profile")
check("D2", "M2-19", sig2 != m1sig, "M2 signature is not the receipt's signature")
check("D2", "M2-20", Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).sign(D2_SS) == sig2,
      "re-signing the Sig_structure with the issuer seed reproduces the M2 signature")
cs_sha = sha256(D2_CS)
check("D2", "M2-21", cs_sha == D2_CS_SHA, "SHA-256 over COSE_Sign1 bytes as stated", cs_sha.hex())
check("D2", "S71-C", not lib_verify(ISSUER_PK, m1sig, D2_SS) and not lib_verify(ISSUER_PK, sig2, my_pae),
      "Section 9: receipt signature is not a valid signature over the Sig_structure, and vice versa")
print()

print("=== D2 textual claims checkable against Draft 1 text ===")
d2s = norm_ws(" ".join(d2[find_line(d2, r"^8\.\s+What Is Not Proven"):find_line(d2, r"^9\.\s+Security Considerations")]))
d1s = norm_ws(" ".join(d1[find_line(d1, r"^6\.\s+What a Receipt Does Not Prove"):find_line(d1, r"^7\.\s+Related Work")]))
_end = re.search(r"Each (citing )?envelope adds", d2s).start()  # round 3: "Each envelope adds"
# Round 6: both lists open with "Verification establishes"; Draft 2 says its one cross-reference is
# written as a reference to Section 5 of [RECEIPTS], which Draft 1 writes as its own "Section 5".
q2 = d2s[d2s.index("Verification establishes that the receipt passes"):_end].strip()
q1 = d1s[d1s.index("Verification establishes that the receipt passes"):].strip()
check("D2", "T1", q2.count("Section 5 of [RECEIPTS]") == 1 and q1 == q2.replace("Section 5 of [RECEIPTS]", "Section 5"),
      "Section 8: the list of Draft 1 Section 6 is repeated word for word, its one cross-reference written "
      "as Section 5 of [RECEIPTS]",
      "Draft 1 %d chars, Draft 2 %d chars (whitespace-normalized)" % (len(q1), len(q2)))
d2flat = norm_ws(" ".join(d2))
refs = re.findall(r"\[RECEIPTS\] Section (\d+(?:\.\d+)?)", d2flat) + re.findall(r"Section (\d+(?:\.\d+)?) of \[RECEIPTS\]", d2flat)
expected_titles = {"3.1": "The Receipt Object", "3.4": "The Bytes B", "3.5": "The Criteria Digest",
                   "4.1": "Pre-Authentication Encoding", "4.2": "The Type", "9": "Privacy Considerations",
                   "4.4": "Verification Profile", "5": "Verification Procedure",
                   "6": "What a Receipt Does Not Prove", "10.1": "Media Type Registration Template"}
bad_refs = [r for r in refs if D1_TITLES.get(r) != expected_titles.get(r)]
check("D2", "T2", not bad_refs and refs,
      "every '[RECEIPTS] Section N' reference names a Draft 1 section with the topic the sentence uses it for",
      "references: " + ", ".join(sorted(set(refs), key=lambda x: [int(y) for y in x.split('.')])),
      *["%s -> %s" % (r, D1_TITLES.get(r)) for r in sorted(set(refs), key=lambda x: [int(y) for y in x.split('.')])])
print()

print("=== DEMO: statements no given vector covers ===")
# same B signed by Draft 1's second test key
sig_b = Ed25519PrivateKey.from_private_bytes(SECOND_SEED).sign(pae(TYPE, D2_B))
rec = parse_ijson(p1raw)
def build(sig_b64, key_b64):
    s = {"alg": "ed25519", "sig": sig_b64}
    if key_b64 is not None:
        s["key"] = key_b64
    import json
    obj = {"payload_b64": rec.d["payload_b64"], "schema": TYPE, "signature": s}
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
x_hint = build(base64.b64encode(sig_b).decode(), base64.b64encode(SECOND_PK).decode())
x_nohint = build(base64.b64encode(sig_b).decode(), None)
r_iss_h = verify_receipt(x_hint, ISSUER_PK)
r_iss_n = verify_receipt(x_nohint, ISSUER_PK)
r_sec = verify_receipt(x_hint, SECOND_PK)
check("DEMO", "X1", match_rule("sha-256", D2_DIGEST.hex(), x_hint)[0] == "MATCH" and r_sec[0] == "PASS"
      and r_iss_h[0] == "FAIL" and r_iss_n[0] == "FAIL",
      "Section 9 'Signer not bound': P1's B signed by Draft 1's second test key MATCHes the citation, "
      "verifies under the second key, fails under the issuer key",
      "under issuer key with own key hint: FAIL step %s (%s)" % (r_iss_h[1], r_iss_h[2]),
      "under issuer key without key hint: FAIL step %s (%s)" % (r_iss_n[1], r_iss_n[2]))
n13_payload = parse_ijson(VEC["N13"]["R"]).d["payload_b64"]
lenient = base64.b64decode(n13_payload, validate=True)
check("DEMO", "X2", sha256(lenient) == D2_DIGEST and canon_b64(n13_payload) is None,
      "N13 (C6): a standard library base64 decoder (Python, validate=True) decodes payload_b64 to the 449 bytes "
      "whose SHA-256 is the receipt digest; only the canonical-encoding rule of Draft 1 step 3 rejects it",
      "N13 payload_b64 tail %r" % n13_payload[-6:], "P1 payload_b64 tail %r" % parse_ijson(p1raw).d["payload_b64"][-6:])
n14_s = VEC["N14"]["R"].decode()
n14_lax = _json.loads(n14_s)
n14_lax_digest = sha256(base64.b64decode(n14_lax["payload_b64"]))
check("DEMO", "X3", n14_s.count('"sig"') == 2 and n14_lax_digest == D2_DIGEST,
      "N14 (C7): the signature object has two 'sig' members; Python json.loads (last value wins) "
      "accepts it and SHA-256 over its decoded payload_b64 equals the receipt digest",
      "json.loads keeps sig=" + n14_lax["signature"]["sig"][:16] + "...",
      "lax digest " + n14_lax_digest.hex())
ws_variant = p1raw.replace(b'{"payload_b64":', b'{ "payload_b64" :\n', 1).replace(b'","schema":', b'" , "schema" : ', 1)
r_ws = verify_receipt(ws_variant, ISSUER_PK)
check("DEMO", "X4", ws_variant != p1raw and match_rule("sha-256", D2_DIGEST.hex(), ws_variant)[0] == "MATCH"
      and r_ws[0] == "PASS",
      "Section 3.4 A1 'identity preserved under ... whitespace': P1 with insignificant whitespace added "
      "MATCHes and verifies (no vector of either draft covers receipt whitespace)",
      "variant %d bytes, sha256 %s" % (len(ws_variant), sha256(ws_variant).hex()))
print()

print("=== SELF: negative controls (the checks above can fail) ===")
bad_sig = bytearray(m1sig)
bad_sig[10] ^= 1
check("SELF", "N1", not lib_verify(ISSUER_PK, bytes(bad_sig), my_pae)
      and profile_verify(ISSUER_PK, bytes(bad_sig), my_pae) is not None,
      "M1 signature with one bit flipped fails under library and own profile")
bad_hint = p1raw.replace(base64.b64encode(ISSUER_PK), base64.b64encode(SECOND_PK))
check("SELF", "N2", bad_hint != p1raw and verify_receipt(bad_hint, ISSUER_PK)[:2] == ("FAIL", 10),
      "P1 with the key hint replaced by Draft 1's second test key fails at step 10")
bad_dig = bytearray(D2_DIGEST)
bad_dig[0] ^= 1
check("SELF", "N3", match_rule("sha-256", bytes(bad_dig).hex(), p1raw)[0] == "NO_MATCH",
      "matching rule with one bit of the cited digest flipped gives NO_MATCH")
nondet = b"\xa5" + b"".join(cenc(k) + cenc(ph[k]) for k in (1, 4, 15, 259, 258))
check("SELF", "N4", cenc(cbor2.loads(nondet)) != nondet and len(nondet) == len(ph_b),
      "a protected header with 259 before 258 is detected as non-deterministic by the encoder check")
check("SELF", "N5", match_rule("SHA-256", D2_DIGEST.hex().upper(), p1raw)[0] == "INDETERMINATE",
      "uppercase hex citation value is INDETERMINATE under rule step 1 (64 lowercase digits)")
print()

print("=== D2 Table 2 coverage of receipt parts (Section 4: 'for each part of a receipt') ===")
t2s = find_line(d2, r"^\s+\| Receipt part")
t2e = find_line(d2, r"Table 2: Receipt parts in three envelopes")
t2rows, cur = [], None
for line in d2[t2s + 1:t2e]:
    s = line.strip()
    if s.startswith("+") or not s:
        if s.startswith("+") and cur is not None:
            t2rows.append(cur)
            cur = None
        continue
    first = s.split("|")[1].strip()
    cur = (cur or "") + " " + first
if cur is not None:
    t2rows.append(cur)
t2names = set()
for r in t2rows:
    for nm in r.split(","):
        if nm.strip():
            t2names.add(nm.strip())
# Draft 1 Table 1 (payload members), first column
p1s = find_line(d1, r"^\s+\| Member\s+\| Type")
p1e = find_line(d1, r"^\s+Table 1$", p1s)
d1_payload = set()
for line in d1[p1s + 1:p1e]:
    s = line.strip()
    if s.startswith("|"):
        nm = s.split("|")[1].strip()
        if re.fullmatch(r"[a-z_]+", nm):
            d1_payload.add(nm)
receipt_parts = {"schema->type", "payload_b64->B", "signature.alg", "signature.sig", "signature.key"}
# Round 2: Table 2 names the Payload member schema "payload schema"
if "payload schema" in t2names:
    t2names.add("schema")
covered = set()
for part in receipt_parts:
    alias = part.split("->")[-1]
    if alias in t2names:
        covered.add(part)
missing_receipt = sorted(receipt_parts - covered)
missing_payload = sorted(d1_payload - t2names)
check("D2", "T2-COV", not missing_receipt and not missing_payload,
      "Table 2 has a row for every member of the receipt object (Draft 1 3.1) and of the Payload (Draft 1 3.2)",
      "Table 2 part names (plus alias 'schema' added by this script for the row 'payload schema'): "
      + ", ".join(sorted(t2names)),
      "Draft 1 payload members: " + ", ".join(sorted(d1_payload)),
      "receipt parts without a row: " + (", ".join(missing_receipt) or "none"),
      "payload members without a row: " + (", ".join(missing_payload) or "none"))
print()

print("=== XREF: Draft 1 payload labels against Draft 2's 'B is not obtained' (C6, C7) ===")
lab_bad, n_carried, n_b, n_none = [], 0, 0, 0
for vid, v in VEC.items():
    Bx, fail, _ = steps_1_to_3(v["R"])
    if fail:
        if v["b_label"] == "carried":
            n_carried += 1
            if v["carried_step"] != fail[0] or v["hex_label"] != "carried":
                lab_bad.append("%s: label says stop at step %s (hex label %s), own procedure stops at step %d"
                               % (vid, v["carried_step"], v["hex_label"], fail[0]))
        elif v["b_label"] == "none":
            n_none += 1
            if v["B"] is not None:
                lab_bad.append("%s: label 'B: none' but a payload hex block is given" % vid)
        else:
            lab_bad.append("%s: fails step %d but is labelled 'payload bytes B'" % (vid, fail[0]))
    else:
        n_b += 1
        if v["b_label"] != "B" or v["hex_label"] != "B" or v["B"] != Bx:
            lab_bad.append("%s: steps 1-3 obtain B but label is %s/%s or bytes differ" % (vid, v["b_label"], v["hex_label"]))
check("XREF", "L1", not lab_bad,
      "Draft 1 labels payload bytes 'B' exactly where steps 1 to 3 obtain B (and the bytes are that B); "
      "elsewhere 'carried (not B ...)' with the step at which own procedure stops, or 'B: none'",
      "labelled B: %d, labelled carried: %d, labelled 'B: none': %d, disagreements: %d" % (n_b, n_carried, n_none, len(lab_bad)),
      *lab_bad)
print()

print("=== INFO: matching rule with the P1 citation over every Draft 1 vector (sibling classes) ===")
cls_ind_sameB, cls_match_fail, cls_other = [], [], []
for vid, v in VEC.items():
    res, why = match_rule("sha-256", D2_DIGEST.hex(), v["R"])
    ver = verify_receipt(v["R"], v["vkey"])
    tag = "%s:%s/%s%s" % (vid, res, ver[0], "" if ver[1] is None else " step %d" % ver[1])
    if res == "INDETERMINATE" and v["B"] == D2_B:
        cls_ind_sameB.append(tag)
    elif res == "MATCH" and ver[0] == "FAIL":
        cls_match_fail.append(tag)
    else:
        cls_other.append(tag)
info("INDETERMINATE although the payload bytes carried equal P1's B (siblings of C6/C7): %d" % len(cls_ind_sameB),
     "  " + ", ".join(cls_ind_sameB),
     "MATCH but full procedure FAILS under the vector's key (siblings of C5): %d" % len(cls_match_fail),
     "  " + ", ".join(cls_match_fail),
     "other: %d" % len(cls_other), "  " + ", ".join(cls_other))
fp = hashlib.sha256("".join("%s:%s;" % (k, sha256(v["R"]).hex()) for k, v in VEC.items()).encode()).hexdigest()
info("fingerprint over (vector id, SHA-256 of receipt bytes) of all %d Draft 1 vectors: %s" % (len(VEC), fp))
print()

print("=== D2 round-2 revisions checkable against bytes ===")
n7sig = canon_b64(n7)
mt = re.search(r"made over PAE with the type (\S+), fails under the fixed type", d2flat)
t_named = mt.group(1) if mt else None
d1_names_it = bool(t_named) and t_named in norm_ws(" ".join(d1))
check("D2", "C5-e", t_named is not None and t_named != TYPE and lib_verify(ISSUER_PK, n7sig, pae(t_named, D2_B))
      and profile_verify(ISSUER_PK, n7sig, pae(t_named, D2_B)) is None
      and verify_receipt(VEC["N7"]["R"], ISSUER_PK)[2] == "profile 4",
      "Section 4.1: N7's signature is valid over PAE(T', B) for the type T' Draft 2 names, and fails under the fixed type",
      "T' named in Draft 2 = %r" % t_named, "T' also stated in Draft 1 text: %s" % d1_names_it)
check("D2", "S2-T", parse_ijson(p1raw).d["schema"] == TYPE and lib_verify(ISSUER_PK, m1sig, pae(TYPE, D2_B)),
      "Section 2: in Draft 1 the type is both receipt.schema (P1) and the type under which B is signed")
# Section 3.3 step 1 identifiers
cite_m2 = (ph[258], payload)
r_m2_p1 = match_rule(cite_m2[0], cite_m2[1], p1raw)[0]
r_m2_p2 = match_rule(cite_m2[0], cite_m2[1], VEC["P2"]["R"])[0]
check("D2", "S33-COSE", r_m2_p1 == "MATCH" and r_m2_p2 == "NO_MATCH",
      "citation read from M2 (alg = header 258 = -16, value = 32-byte payload) MATCHes P1 and is NO_MATCH for P2",
      "P1 %s, P2 %s" % (r_m2_p1, r_m2_p2))
iv = find_line(d2, r'^\s+\{"digest": \{"sha256": "<receipt digest')
vsa_txt = d2[iv].strip() + " " + d2[iv + 1].strip()
vsa = _json.loads(vsa_txt.replace("<receipt digest, 64 hex digits>", D2_DIGEST.hex()))
r_vsa = match_digest_set(vsa["digest"], p1raw)[0]
r_multi = match_digest_set({"sha512": D2_SHA512.hex(), "sha256": D2_DIGEST.hex()}, p1raw)[0]
r_512 = match_digest_set({"sha512": D2_SHA512.hex()}, p1raw)[0]
r_bad_other = match_digest_set({"sha512": "00" * 64, "sha256": D2_DIGEST.hex()}, p1raw)[0]
check("D2", "S33-VSA", r_vsa == "MATCH" and vsa["mediaType"] == TYPE and r_multi == "MATCH" and r_512 == "INDETERMINATE",
      "Section 4.3 descriptor (placeholder filled with the receipt digest) MATCHes P1; a two-entry digest set "
      "matches on sha256; a set with only sha512 is INDETERMINATE",
      "4.3 text: " + vsa_txt, "two entries: %s, sha512 only: %s" % (r_multi, r_512),
      "two entries with a wrong sha512 value (ignored by the rule): %s" % r_bad_other)
# Round 7: the sentence on the in-toto matching guidance (Section 3.3 step 1)
d2flat7 = norm_ws(" ".join(d2))
narrow = ("This is narrower than the matching guidance of [INTOTO-DIGESTSET], under which two digest sets match "
          "if any acceptable field matches: here a digest set without a sha256 entry gives INDETERMINATE, and one "
          "whose sha256 entry passes step 1 but differs from SHA-256 over B gives NO_MATCH, whatever its other "
          "entries are.")
p2_digest = sha256(steps_1_to_3(VEC["P2"]["R"])[0]).hex()
n_no256 = match_digest_set({"sha512": D2_SHA512.hex()}, p1raw)[0]
n_wrong256 = match_digest_set({"sha256": p2_digest, "sha512": D2_SHA512.hex()}, p1raw)[0]
n_upper256 = match_digest_set({"sha256": D2_DIGEST.hex().upper(), "sha512": D2_SHA512.hex()}, p1raw)[0]
n_noB = match_digest_set({"sha256": p2_digest, "sha512": D2_SHA512.hex()}, VEC["N13"]["R"])[0]
any_rule = any(v == {"sha256": D2_DIGEST.hex(), "sha512": D2_SHA512.hex()}[k]
               for k, v in {"sha256": p2_digest, "sha512": D2_SHA512.hex()}.items())
check("D2", "S33-NARROW", narrow in d2flat7 and n_no256 == "INDETERMINATE" and n_wrong256 == "NO_MATCH"
      and n_upper256 == "INDETERMINATE" and n_noB == "INDETERMINATE" and any_rule,
      "Section 3.3 step 1: the sentence stands in the text; without sha256 INDETERMINATE; a well-formed sha256 "
      "that differs from SHA-256 over B gives NO_MATCH although sha512 matches (the in-toto any-field guidance "
      "would match); a malformed sha256 or a candidate without B stays INDETERMINATE (steps 1 and 2)",
      "sentence found: %s" % (narrow in d2flat7),
      "sha512 only: %s; sha256 = P2's digest, sha512 = P1's: %s; sha256 uppercase: %s; same set against N13: %s"
      % (n_no256, n_wrong256, n_upper256, n_noB),
      "in-toto any-field reading of the second set against P1's digest set: %s" % ("match" if any_rule else "no match"))
# Section 3.1 revised
check("D2", "S31", sha256(lenient) == D2_DIGEST and n14_lax_digest == D2_DIGEST
      and match_rule("sha-256", D2_DIGEST.hex(), VEC["N13"]["R"])[0] == "INDETERMINATE"
      and match_rule("sha-256", D2_DIGEST.hex(), VEC["N14"]["R"])[0] == "INDETERMINATE",
      "Section 3.1: for C6 and C7 a lenient decoder/parser produces the 449 bytes, and the rule still gives INDETERMINATE")
# Section 4.1 path from the envelope to receipt bytes
def assemble(env_obj):
    Bd = base64.b64decode(env_obj["payload"])           # "B (the decoded payload)"
    sd = base64.b64decode(env_obj["signatures"][0]["sig"])
    obj = {"schema": env_obj["payloadType"], "payload_b64": base64.b64encode(Bd).decode(),
           "signature": {"alg": "ed25519", "sig": base64.b64encode(sd).decode()}}
    return _json.dumps(obj, separators=(",", ":")).encode()
m1_json = _json.loads(D2_ENV)
asm = assemble(m1_json)
r_asm = verify_receipt(asm, ISSUER_PK)
check("D2", "S41-PATH", r_asm[0] == "PASS" and match_rule("sha-256", D2_DIGEST.hex(), asm)[0] == "MATCH",
      "Section 4.1: B and sig taken from M1, written as canonical base64 into a receipt object, verify "
      "(own Section 5) and MATCH", "assembled %d bytes" % len(asm))
m1_nc = dict(m1_json)
m1_nc["payload"] = m1_json["payload"][:-2] + "1="
assert m1_nc["payload"] != m1_json["payload"] and base64.b64decode(m1_nc["payload"]) == D2_B
asm_nc = assemble(m1_nc)
copy_nc = asm_nc.replace(m1_json["payload"].encode(), m1_nc["payload"].encode())
r_nc, r_copy = verify_receipt(asm_nc, ISSUER_PK), verify_receipt(copy_nc, ISSUER_PK)
check("DEMO", "X5", lib_verify(ISSUER_PK, m1sig, pae(m1_nc["payloadType"], base64.b64decode(m1_nc["payload"])))
      and r_nc[0] == "PASS" and r_copy[:2] == ("FAIL", 3),
      "M1 with non-canonical payload padding ('...1='): a DSSE-style check passes; the Section 4.1 path "
      "(re-encode canonically) gives PASS; copying the string instead would give FAIL at step 3",
      "re-encoded: %s; copied: %s step %s" % (r_nc[0], r_copy[0], r_copy[1]))
c_same = "sha256:" + hashlib.sha256(bytes.fromhex(m_salt) + m_id.encode()).hexdigest()
c_other = "sha256:" + hashlib.sha256(bytes.fromhex(m_salt) + b"acme/model-y@2026-09").hexdigest()
check("DEMO", "X6", c_same == D2_SUB and c_other != D2_SUB,
      "Section 10 'links every receipt and statement that reuse the same salt': with Draft 1's model salt, "
      "the same identifier reproduces sub, another identifier (constructed) gives another value; "
      "equal sub values need the same salt and the same identifier",
      "same salt, other identifier: " + c_other)
print()

print("=== D2 round 4: typed digest reference (5.1) and PRML rule (6) ===")
check("D2", "R4-TDR", match_rule("SHA-256", D2_DIGEST.hex(), p1raw)[0] == "MATCH"
      and match_rule("SHA-256", D2_DIGEST.hex(), VEC["N13"]["R"])[0] == "INDETERMINATE",
      "5.1: a reference with digest_alg 'SHA-256' and the receipt digest as 64 lowercase hex digits MATCHes P1; "
      "for N13 (no B) it is INDETERMINATE, which 5.1 maps to Unresolved")
check("DEMO", "X7", _D("0.8") == _D("0.800") and _D("0.80000000000000001") != _D("0.8")
      and float("0.80000000000000001") == float("0.8"),
      "6 step 4: 0.8 and 0.800 are the same decimal number; 0.80000000000000001 is not, although it is the same "
      "IEEE 754 double as 0.8 (the rule is stricter than double equality)")
crit_text = norm_ws(" ".join(d2[find_line(d2, r"^6\.\s+Criteria Sets in PRML"):find_line(d2, r"^7\.\s+Relation to")]))
check("D2", "R4-PRML", "BOUND" in crit_text and "UNBOUND" in crit_text and "AGREE" in crit_text and "DIFFER" in crit_text
      and "== has no counterpart" in crit_text,
      "6: the rule names BOUND/UNBOUND and AGREE/DIFFER, and the PRML table (Table 4) says == has no counterpart")
print()

# Round 8: Draft 2 Section 5.2.2 step 5 and Section 3.3 step 2 name the third outcome of Draft 1
# Section 5 (a resource-limit error, neither PASS nor FAIL); Sections 4.1 and 8 say what a DSSE
# signature check shows and what a receipt verdict additionally requires.
print("=== D2 round 8: resource-limit outcome (3.3 step 2, 5.2.2) and DSSE (4.1, 8) ===")
d2flat8 = norm_ws(" ".join(d2))


class ResourceLimit(Exception):
    pass


_smul_plain = smul
_LIMIT = {"bytes": None, "curve": None}


def _smul_counted(k, pt):
    if _LIMIT["curve"] is not None:
        if _LIMIT["curve"] <= 0:
            raise ResourceLimit("curve-operation budget reached")
        _LIMIT["curve"] -= 1
    return _smul_plain(k, pt)


def run_limited(fn, rb, *args, max_bytes=None, max_curve=None):
    """Runs fn(rb, *args) with a Receiver's documented limits: an input-size limit checked before
    step 1 and a budget of scalar multiplications (Draft 1 Section 8 allows both)."""
    global smul
    _LIMIT["bytes"], _LIMIT["curve"] = max_bytes, max_curve
    smul = _smul_counted
    try:
        if max_bytes is not None and len(rb) > max_bytes:
            raise ResourceLimit("input-size limit %d < %d" % (max_bytes, len(rb)))
        return fn(rb, *args)
    finally:
        smul = _smul_plain
        _LIMIT["bytes"], _LIMIT["curve"] = None, None


def match_rule_r8(alg, value, rb, **lim):
    """Section 3.3 as revised: step 2 gives INDETERMINATE also when steps 1 to 3 stop at a limit."""
    try:
        return run_limited(lambda r: match_rule(alg, value, r), rb, **lim)
    except ResourceLimit as e:
        return "INDETERMINATE", "rule step 2 (resource limit: %s)" % e


def statement_steps_5_to_7(payload_, sub_, rb, rkey, **lim):
    """Section 5.2.2 steps 5 to 7 as revised; steps 1 to 4 for M2 are the checks M2-1 to M2-18 above.
    Returns a status, or the string 'resource-limit error' for the propagated error (no status)."""
    try:
        r = run_limited(verify_receipt, rb, rkey, **lim)
    except ResourceLimit:
        return "resource-limit error"
    if r[0] != "PASS":
        return "receipt_not_verified"
    if sha256(r[3]) != payload_:
        return "digest_mismatch"
    if parse_ijson(r[3]).d["model_id_commit"] != sub_:
        return "subject_mismatch"
    return "accepted"


s5 = ("Run the verification procedure of [RECEIPTS] Section 5 under the Receiver's receipt key. Continue to "
      "step 6 only if it returns PASS. If it returns FAIL, the status is receipt_not_verified. If it stops with a "
      "resource-limit error, propagate that error and stop without accepting the statement.")
s5_intro = ("A Receiver that stops because it reached a resource limit, in any step, reports a resource-limit "
            "error; that is no status, and the statement is not accepted.")
s33 = ("If steps 1 through 3 of [RECEIPTS] Section 5 do not all complete successfully, including when processing "
       "stops at a resource limit, B is not obtained and the result is INDETERMINATE.")
s41 = ("A successful DSSE signature check alone is not a receipt verdict. DSSE also requires a supported payloadType "
       "and parsing the authenticated payload according to that type. To obtain a receipt verdict, a Receiver decodes "
       "the payload and the selected signature once, uses those same bytes to construct the receipt object with "
       "canonical base64 as required by [RECEIPTS] Section 3.1, and runs [RECEIPTS] Section 5 under its "
       "independently selected receipt verification key.")
s8 = ("A successful DSSE signature check authenticates PAE(type, B) under the selected key. A receipt verdict "
      "additionally requires the verification profile and all checks of [RECEIPTS] Section 5. The unauthenticated "
      "keyid is only a key-selection hint.")
d1flat8 = norm_ws(" ".join(d1))
d1_rl = "reports a resource-limit error; that is neither PASS nor the FAIL of one of the steps below" in d1flat8

# the probe: P1 with signature octet 32 XOR 01, re-encoded canonically; M2 unchanged
rec_p1 = parse_ijson(p1raw)
sig_p1 = canon_b64(rec_p1.d["signature"].d["sig"])
sig_x = sig_p1[:32] + bytes([sig_p1[32] ^ 1]) + sig_p1[33:]
p1x = p1raw.replace(base64.b64encode(sig_p1), base64.b64encode(sig_x))
assert p1x != p1raw and len(p1x) == len(p1raw) and steps_1_to_3(p1x)[0] == D2_B
r_p1x = verify_receipt(p1x, ISSUER_PK)
st_x_free = statement_steps_5_to_7(payload, D2_SUB, p1x, ISSUER_PK)
st_x_zero = statement_steps_5_to_7(payload, D2_SUB, p1x, ISSUER_PK, max_curve=0)
st_p1_free = statement_steps_5_to_7(payload, D2_SUB, p1raw, ISSUER_PK)
st_p1_zero = statement_steps_5_to_7(payload, D2_SUB, p1raw, ISSUER_PK, max_curve=0)
# the adapter the old wording invited: refuse only on FAIL, treat everything else as passing
try:
    _a = run_limited(verify_receipt, p1x, ISSUER_PK, max_curve=0)
    adapter_old = "receipt_not_verified" if _a[0] == "FAIL" else "accepted"
except ResourceLimit:
    adapter_old = "accepted"
check("D2", "S522-RL", s5 in d2flat8 and s5_intro in d2flat8 and d1_rl
      and r_p1x[:2] == ("FAIL", 11) and r_p1x[2] == "profile 4"
      and st_x_free == "receipt_not_verified" and st_x_zero == "resource-limit error"
      and st_p1_free == "accepted" and st_p1_zero == "resource-limit error",
      "Section 5.2.2 step 5 and the sentence after the introduction stand in the text, and Draft 1 Section 5 names "
      "the resource-limit error as neither PASS nor FAIL; M2 with P1 whose signature octet 32 is XORed with 01: "
      "without a limit receipt_not_verified (Draft 1 step 11, rule 4); with a budget of zero scalar "
      "multiplications the error is propagated and no status is given; unchanged P1: accepted, and under the "
      "same budget the error, never accepted",
      "sentences found: step 5 %s, introduction %s, Draft 1 %s" % (s5 in d2flat8, s5_intro in d2flat8, d1_rl),
      "modified P1 (%d bytes): Draft 1 Section 5 %s at step %s (%s)" % (len(p1x), r_p1x[0], r_p1x[1], r_p1x[2]),
      "statuses: modified P1 %s / budget 0: %s; P1 %s / budget 0: %s" % (st_x_free, st_x_zero, st_p1_free, st_p1_zero),
      "an adapter that refuses only on FAIL would give %s under budget 0" % adapter_old)
m_free = match_rule_r8("sha-256", D2_DIGEST.hex(), p1raw)[0]
m_834 = match_rule_r8("sha-256", D2_DIGEST.hex(), p1raw, max_bytes=len(p1raw) - 1)
m_835 = match_rule_r8("sha-256", D2_DIGEST.hex(), p1raw, max_bytes=len(p1raw))[0]
m_curve0 = match_rule_r8("sha-256", D2_DIGEST.hex(), p1raw, max_curve=0)[0]
check("D2", "S33-RL", s33 in d2flat8 and m_free == "MATCH" and m_834[0] == "INDETERMINATE" and m_835 == "MATCH"
      and m_curve0 == "MATCH",
      "Section 3.3 step 2 stands in the text; P1 under an input-size limit one octet below its length gives "
      "INDETERMINATE (B not obtained), at its length MATCH; a curve-operation budget of zero does not touch "
      "steps 1 to 3, so the match stays MATCH and is not a receipt verdict",
      "sentence found: %s; P1 %d octets" % (s33 in d2flat8, len(p1raw)),
      "no limit %s; limit %d: %s (%s); limit %d: %s; curve budget 0: %s"
      % (m_free, len(p1raw) - 1, m_834[0], m_834[1], len(p1raw), m_835, m_curve0))
# 4.1 and 8: what a DSSE signature check shows, and the further DSSE and receipt checks
body_nj = b"not json"
sig_nj = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).sign(pae(TYPE, body_nj))
try:
    parse_ijson(body_nj)
    nj_parses = True
except JErr:
    nj_parses = False


def dsse_full(ptype, body, sig, key):
    """DSSE as Draft 2 Section 4.1 now states it: signature over PAE, a supported type, the body parsed by it."""
    return lib_verify(key, sig, pae(ptype, body)) and ptype == TYPE and _parses(body)


def _parses(body):
    try:
        parse_ijson(body)
        return True
    except JErr:
        return False


nj_env = {"payloadType": TYPE, "payload": base64.b64encode(body_nj).decode(),
          "signatures": [{"sig": base64.b64encode(sig_nj).decode()}]}
r_nj = verify_receipt(assemble(nj_env), ISSUER_PK)
check("D2", "S41-DSSE", s41 in d2flat8 and s8 in d2flat8
      and lib_verify(ISSUER_PK, sig_nj, pae(TYPE, body_nj)) and not nj_parses
      and not dsse_full(TYPE, body_nj, sig_nj, ISSUER_PK) and dsse_full(TYPE, D2_B, m1sig, ISSUER_PK)
      and r_nj[:2] == ("FAIL", 4) and r_asm[0] == "PASS",
      "Sections 4.1 and 8 stand in the text; the 8 octets 'not json' signed over PAE with the type and Draft 1's "
      "test seed: the signature check passes, parsing as JSON fails, so a DSSE verifier that parses by type "
      "rejects it, and the Section 4.1 path gives FAIL at Draft 1 step 4; M1 passes both and gives PASS",
      "sentences found: 4.1 %s, 8 %s" % (s41 in d2flat8, s8 in d2flat8),
      "'not json': signature %s, parses %s, DSSE with parsing %s, Section 5 %s at step %s"
      % (lib_verify(ISSUER_PK, sig_nj, pae(TYPE, body_nj)), nj_parses, dsse_full(TYPE, body_nj, sig_nj, ISSUER_PK),
         r_nj[0], r_nj[1]))
# Round 9: Draft 2 Section 5.2.2 step 3, a statement key counts only if it is of order L
s3 = ("A configured pair counts only if its statement key is 32 octets and its point A meets rules 1 and 2 of "
      "[RECEIPTS] Section 4.4: A is a canonical encoding of a point of order L. A point of small order or of mixed "
      "order does not count.")


def key_counts(raw):
    A_ = decode_point(raw) if len(raw) == 32 else None
    return A_ is not None and not is_neutral(A_) and is_neutral(smul(L, A_))


check("D2", "S522-3", s3 in d2flat8 and key_counts(ISSUER_PK) and not key_counts(MIXED_PK)
      and not key_counts((1).to_bytes(32, "little")) and "A point of mixed order counts" not in d2flat8,
      "Section 5.2.2 step 3: the sentence stands in the text and the old one is gone; the issuer test key counts, "
      "the mixed-order test key of Draft 1 A.1 and the neutral element do not",
      "sentence found: %s; issuer %s, mixed-order %s, neutral %s" % (s3 in d2flat8, key_counts(ISSUER_PK),
                                                                     key_counts(MIXED_PK),
                                                                     key_counts((1).to_bytes(32, "little"))))
# Round 10: Draft 2 Section 5.2.2 step 1, a data item that is well-formed but not valid is malformed
s1v = ("A data item that is well-formed but not valid under [RFC8949] Section 5.3.1, such as a text string that "
       "is not valid UTF-8 or a map with duplicate keys, is malformed;")
iss_b = D2_ISS.encode("utf-8")
iss_at = ph_b.find(chead(3, len(iss_b)) + iss_b)
iss_content = iss_at + len(chead(3, len(iss_b)))
bad_at = iss_content + 8
ph_bad = ph_b[:bad_at] + b"\xff" + ph_b[bad_at + 1:]
try:
    ph_bad[iss_content:iss_content + len(iss_b)].decode("utf-8")
    bad_is_utf8 = True
except UnicodeDecodeError:
    bad_is_utf8 = False
try:
    cbor2.loads(ph_bad)
    refused = "no"
except Exception as exc_:  # noqa: BLE001
    refused = type(exc_).__name__
check("D2", "S522-1V", s1v in d2flat8 and ph_b.count(chead(3, len(iss_b)) + iss_b) == 1
      and iss_content <= bad_at < iss_content + len(iss_b) and len(ph_bad) == len(ph_b)
      and not bad_is_utf8 and refused != "no",
      "Section 5.2.2 step 1: the sentence stands in the text; M2's protected header with byte 8 of the iss content "
      "replaced by 0xff keeps every head and length (well-formed), its iss is no UTF-8 (not valid), and a decoder "
      "that checks validity refuses it, so the status is malformed",
      "sentence found: %s; iss content at offset %d of %d, replaced byte at %d; still UTF-8: %s; cbor2 refuses: %s"
      % (s1v in d2flat8, iss_content, len(ph_b), bad_at, bad_is_utf8, refused))
# Round 11: Section 5.2.2 step 1 and its line to step 2, Section 6 step 1, the DSSE date
s1b = ["two keys are duplicates only when they are equal under the key equivalence of [RFC8949] Section 5.6.1, so "
       "the integer 1 and true are two keys and 0.0 and -0.0 are one. Step 1 does not check whether the content of a "
       "tag inside the COSE_Sign1 is valid for that tag ([RFC8949] Section 5.3.2); the data items inside a tag are "
       "checked like any other data item.",
       "For step 1, the COSE_Sign1 check concerns only the outer tag, the four-element array and its element types: "
       "a wrapping in a CBOR tag other than 18 is not a COSE_Sign1 and is malformed, and an otherwise valid "
       "COSE_Sign1 without a tag goes on to step 2 and is outside_profile there.",
       "The protected-header byte string is decoded as a CBOR map, with the empty byte string treated as an empty "
       "map ([RFC9052] Section 3), which fails in step 2. CBOR validity and deterministic encoding are checked "
       "before step 2. Header label types are checked only in step 2; a header label that is not a label of either "
       "profile gives outside_profile if step 1 succeeds."]
gone_1 = ["A data item that is well-formed but not valid ([RFC8949] Section 5.3)",
          "A resource-limit error in step 5 is not a failing step",
          "only when they are the same data item",
          "Step 1 does not check the content of a tag inside the COSE_Sign1."]
check("D2", "S522-1B", all(s in d2flat8 for s in s1b) and not any(g in d2flat8 for g in gone_1),
      "Section 5.2.2 step 1: validity under RFC 8949 5.3.1, duplicate keys as data items, no tag content check, the "
      "line to step 2; the sentences of round 10 and the step-5-only limit sentence are gone",
      "found %d of %d; old left %d" % (sum(s in d2flat8 for s in s1b), len(s1b), sum(g in d2flat8 for g in gone_1)))
s6_1 = ("Run the procedure of [RECEIPTS] Section 5 under the Receiver's receipt key. Continue only if it returns PASS. "
        "If it returns FAIL, do not perform the comparison. If it stops with a resource-limit error, propagate that "
        "error and stop without reporting binding or agreement results.")
check("D2", "S6-1", s6_1 in d2flat8 and "otherwise there is nothing to compare" not in d2flat8,
      "Section 6 step 1 names the three outcomes of the receipt procedure; the old step is gone")
check("D2", "REF-DSSE", re.search(r"\[DSSE\][^\[]*28 May 2024", d2flat8) is not None and "10 May 2024" not in d2flat8,
      "the DSSE reference is dated 28 May 2024, the date of tag v1.0.2")
# Round 12: key equivalence (RFC 8949 Section 5.6.1), the data items inside a tag, B49's iss, the count
def _half(b):
    """An IEEE 754 half-precision float from its two bytes (RFC 8949 Appendix D), without a library."""
    h = int.from_bytes(b, "big")
    sign, exp, man = h >> 15, (h >> 10) & 0x1F, h & 0x3FF
    if exp == 0:
        val = man * 2.0 ** -24
    elif exp == 31:
        val = float("inf") if man == 0 else float("nan")
    else:
        val = (man + 1024) * 2.0 ** (exp - 25)
    return -val if sign else val
zero, minus_zero = bytes.fromhex("f90000"), bytes.fromhex("f98000")
eq_zero = _half(zero[1:]) == _half(minus_zero[1:]) and zero != minus_zero
one_int, one_true = bytes.fromhex("01"), bytes.fromhex("f5")   # major type 0 against major type 7, simple 21
distinct_1_true = (one_int[0] >> 5, one_true[0] >> 5) == (0, 7)
check("D2", "S522-1E", eq_zero and distinct_1_true and "0.0 and -0.0 are one" in d2flat8,
      "Section 5.2.2 step 1 with RFC 8949 Section 5.6.1: the half floats f9 0000 and f9 8000 differ in bytes and are "
      "numerically equal, so as keys of one map they are duplicates and the map is malformed; 01 (major type 0) and "
      "f5 (major type 7) are of different kinds, so 1 and true are two keys",
      "0.0 == -0.0: %s; kinds of 1 and true: %s" % (eq_zero, (one_int[0] >> 5, one_true[0] >> 5)))
tagged = bytes.fromhex("c161ff")   # tag 1 (c1), a text of length 1 (61), the byte ff
well_formed = tagged[0] >> 5 == 6 and tagged[0] & 31 == 1 and tagged[1] >> 5 == 3 and tagged[1] & 31 == len(tagged) - 2
try:
    tagged[2:].decode("utf-8")
    inner_valid = True
except UnicodeDecodeError:
    inner_valid = False
check("D2", "S522-1T", well_formed and not inner_valid
      and "the data items inside a tag are checked like any other data item" in d2flat8,
      "Section 5.2.2 step 1: c1 61 ff is well-formed (tag 1 around a text of one byte) and the text inside the tag is "
      "no UTF-8; the text checks the data items inside a tag like any other, so a sixth key -1 with this value is "
      "malformed, whether or not a decoder knows tag 1",
      "well-formed: %s; inner text UTF-8: %s" % (well_formed, inner_valid))
# RFC 3986 Section 3 (absolute-URI = scheme ":" hier-part [ "?" query ]), 3.2 (authority), 3.2.2 (host, with
# "[" and "]" only around an IP-literal), 3.3 (path-abempty = *( "/" segment ), path-absolute, path-rootless =
# segment-nz *( "/" segment ), path-empty; segment = *pchar, segment-nz = 1*pchar), 2.1 to 2.3. Round 20: the
# hier-part has all four forms; before, only "//" authority path-abempty was written here, so an absolute URI such
# as a did:x509 identifier (path-rootless) was wrongly no absolute URI.
_unres, _sub = r"A-Za-z0-9\-._~", r"!$&'()*+,;="
_pct = r"%[0-9A-Fa-f]{2}"
_pchar = rf"(?:[{_unres}{_sub}:@]|{_pct})"
_host = rf"(?:\[[0-9A-Fa-f:.vV{_unres}{_sub}]+\]|(?:[{_unres}{_sub}]|{_pct})*)"
_hier = (rf"(?://(?:(?:[{_unres}{_sub}:]|{_pct})*@)?{_host}(?::[0-9]*)?(?:/{_pchar}*)*"
         rf"|/(?:{_pchar}+(?:/{_pchar}*)*)?|{_pchar}+(?:/{_pchar}*)*|)")
_abs_uri = re.compile(rf"\A[A-Za-z][A-Za-z0-9+.\-]*:{_hier}(?:\?(?:{_pchar}|[/?])*)?\Z")
b49_iss, m2_iss = "https://issuer.example/e[val", "https://issuer.example/eval"
check("D2", "S522-ISS", _abs_uri.match(b49_iss) is None and _abs_uri.match(m2_iss) is not None
      and "an absolute URI ([RFC3986] Section 4.3)" in d2flat8,
      "Section 5.2.2 step 2 with the iss rule of Section 5.2: https://issuer.example/e[val has \"[\" in its path, which "
      "RFC 3986 admits only around an IP-literal (Section 3.2.2), so it is no absolute URI and vector B49 is "
      "outside_profile even where a pair names that iss; the iss of M2 is one",
      "B49 iss absolute URI: %s; M2 iss absolute URI: %s" % (_abs_uri.match(b49_iss) is not None,
                                                            _abs_uri.match(m2_iss) is not None))
# Round 13: B50, a float key that is not in its shortest form
_f32 = bytes.fromhex("fa3fc00000")
_value = _struct.unpack(">f", _f32[1:])[0]
_as_half = _struct.unpack(">e", _struct.pack(">e", _value))[0]
check("D2", "S522-1F", _value == 1.5 and _as_half == _value and _struct.pack(">e", _value) == bytes.fromhex("3e00")
      and "in the deterministic encoding, the status is malformed" in d2flat8 and "Section 4.2.1" in d2flat8,
      "Section 5.2.2 step 1 with RFC 8949 Section 4.2.1: fa 3fc00000 is 1.5 in single precision; 1.5 has the "
      "half-precision form f9 3e00, so the single-precision form is not the shortest and the key of vector B50 "
      "makes the protected header not deterministic: malformed, before step 2 asks the kind of the key",
      "value %r; half precision %s keeps it: %s" % (_value, _struct.pack(">e", _value).hex(), _as_half == _value))
check("D2", "COUNT", "for a set of 49 statements and 6 receipts" in d2flat8 and "50 statements" not in d2flat8,
      "Section 12 counts the statements of the code's fixture: 49, without B10, since every Receiver accepts -8")
old_frags = ["If the candidate receipt fails the verification procedure",
             "fails for the candidate, B is not obtained",
             "A DSSE verification is not a receipt verification",
             "A DSSE verification of M1 shows"]
left = [f for f in old_frags if f in d2flat8]
check("D2", "R8-OLD", not left, "the four replaced sentences are no longer in the text",
      "left: " + (", ".join(left) if left else "none"))
print()

# Round 14: the type under signed-evidence.org
d2flat14 = norm_ws(" ".join(d2))
d1flat14 = norm_ws(" ".join(d1))
check("D2", "R14-T", any(line.strip() == TYPE for line in d2)
      and '"mediaType": "%s"}' % TYPE in d2flat14
      and "type is %s, the type, which identifies B;" % TYPE in d2flat14,
      "the type stands on a line of its own, in the VSA mediaType and in the CPB declaration, unbroken")
check("D2", "R14-OLD", "application/eval-receipt+json" not in d2flat14 and "urn:ietf:params" not in d2flat14
      and "[RECEIPTS] Section 10.2" not in d2flat14,
      "neither name used before 2026-10-08 and no reference to a Section 10.2 of Draft 1 stands in Draft 2")
check("D2", "R14-101", "This media type identifies the canonical payload bytes B" in d1flat14
      and "The type identifies B ([RECEIPTS] Section 10.1)." in d2flat14
      and "This document has no IANA actions." in d1flat14,
      "Draft 2's 'The type identifies B (Section 10.1)' rests on the sentence that stays in Draft 1 10.1, "
      "which is informational now")
check("D2", "R14-DATE", "Measured on 2026-10-08" in d2flat14 and "Measured on 2026-10-07" not in d2flat14,
      "Section 12: the foreign verifiers were measured again on the regenerated statements")
print()

# Round 16: the open item on -8, the M2 sentence of Section 12, Draft 2's references to Draft 1 vectors
d2flat16 = norm_ws(" ".join(d2))
rule524 = ("A Receiver may meet statements with -8, for example ones made before a producer moved to -19, and may "
           "accept them; it does so only under an Ed25519 statement key, because -8 names EdDSA for any curve and "
           "only the Ed25519 key fixes which signature algorithm it is.")
check("D2", "R16-OPEN", "keeps accepting -8" not in d2flat16
      and "A party that makes a statement therefore writes -19 only." in d2flat16,
      "Open Items no longer ask whether a Receiver keeps accepting -8; 5.2.4 still says a party writes -19 only "
      "(round 17 replaces the rest of the paragraph, see R17-ALG)")
s16 = ("The signature of M2 (alg -19) is checked from the text alone, without a COSE library: a script written from "
       "the texts of this document and of [RECEIPTS] builds the Sig_structure by hand and verifies the signature "
       "over it with a general Ed25519 implementation (its checks M2-17 and M2-18).")
held16 = {cid: ok for cat, cid, ok, _ in RESULTS if cat == "D2" and cid in ("M2-17", "M2-18")}
cose_libs = sorted(m for m in sys.modules if m.split(".")[0] in ("pycose", "cose", "cwt", "go_cose"))
check("D2", "R16-M2", s16 in d2flat16 and held16 == {"M2-17": True, "M2-18": True} and not cose_libs,
      "Section 12: the M2 sentence stands, and this run bears it out: M2-17 and M2-18 hold, no COSE library loaded",
      "M2-17/M2-18 %s; COSE modules loaded: %s" % (held16, cose_libs or "none"))
named = sorted(set(re.findall(r"\b([PN][0-9]{1,2})\b", d2flat16)), key=lambda x: (x[0] != "P", int(x[1:])))
bad = [x for x in named if x not in VEC or (x[0] == "P") != (VEC[x]["exp"][0] == "PASS")]
check("D2", "R16-REFS", named and not bad and "P11" not in named,
      "every Draft 1 vector Draft 2 names exists in Draft 1, a P vector expects PASS and an N vector FAIL",
      "named: " + ", ".join(named), "not matching: " + (", ".join(bad) if bad else "none"))
print()

# Round 17: one alg rule for every Receiver, the counterexample M2 with -8, VSA at v1.2, ABAK, Open Items
a521 = ("1 (alg): -19, Ed25519 as fully specified in [RFC9864], or -8, EdDSA [RFC9053]. A party that makes a "
        "statement MUST write -19. A Receiver MUST accept both values and applies every other check of Section "
        "5.2.2 to either; under the Ed25519 statement keys that step 3 selects, both values select the same "
        "signature algorithm. Changing alg changes the protected header bytes and requires a new signature "
        "(Section 5.2.4);")
a524 = ("In the key profile, value -19 is the fully specified Ed25519 identifier of [RFC9864], which sets the "
        "polymorphic EdDSA "
        "identifier -8 of [RFC9053] to Deprecated. A party that makes a statement therefore writes -19 only. Every "
        "Receiver accepts -8 as well, for statements made before a producer moved to -19 and for general COSE "
        "verifiers that implement -8 but not -19 (Section 12), so that one statement gives one status. -8 names "
        "EdDSA for any curve; step 3 of Section 5.2.2 counts only Ed25519 statement keys, so a statement with -8 "
        "under any other key is untrusted_key.")
old17 = ["A Receiver MAY also accept -8", "for a Receiver that does not accept it", "and may accept them",
         "A Receiver may meet statements with -8"]
check("D2", "R17-ALG", a521 in d2flat16 and a524 in d2flat16 and not any(o in d2flat16 for o in old17)
      and "the labels select neither profile, a parameter does not have the type and value that the selected profile "
          "gives" in d2flat16,
      "5.2.1, 5.2.2 step 2 and 5.2.4 give one alg rule: every Receiver accepts -19 and -8; any other alg value is "
      "still outside_profile under step 2",
      "old sentences left: " + (", ".join(o for o in old17 if o in d2flat16) or "none"))
_ph17 = dict(cbor2.loads(ph_b))
_ph17[1] = -8
_ph17_b = cenc(_ph17)
_ss17 = cenc(["Signature1", _ph17_b, b"", payload])
_sig17 = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).sign(_ss17)
_cs17 = cenc(cbor2.CBORTag(18, [_ph17_b, {}, payload, _sig17]))
_diff17 = sum(a != b for a, b in zip(_ph17_b, ph_b)) if len(_ph17_b) == len(ph_b) else None
check("D2", "R17-A8", sha256(_cs17).hex() == "4ffcd0d2a970d9dfa17cc9ffed00d7ff84b368177390bb170ee270bc1a336bda"
      and _diff17 == 1 and lib_verify(ISSUER_PK, _sig17, _ss17) and profile_verify(ISSUER_PK, _sig17, _ss17) is None
      and "or -8, EdDSA [RFC9053]" in d2flat16,
      "M2 with alg -8, signed anew with the issuer seed, has the SHA-256 the third review gave, differs from M2 in "
      "one protected-header byte, verifies under the issuer key, and its alg is admitted for every Receiver",
      "sha256 %s, %d bytes, header bytes changed %s" % (sha256(_cs17).hex(), len(_cs17), _diff17))
check("D2", "R17-VSA", "<https://slsa.dev/spec/v1.2/verification_summary>" in d2flat16
      and "slsa.dev/spec/v1.1" not in d2flat16,
      "[VSA] points at SLSA v1.2 and no longer at v1.1")
check("D2", "R17-ABAK", "This document addresses parts of these requirements for the conversions it describes; the "
      "correspondences below are not a conformance claim." in d2flat16 and "This document meets some of them" not in d2flat16,
      "the ABAK paragraph says the correspondences are not a conformance claim")
check("D2", "R17-OI", "References. The in-toto references are pinned to release v1.2.0 of the in-toto Attestation "
      "Framework." in d2flat16 and "The SLSA reference is to be re-checked" not in d2flat16,
      "Open Items: the in-toto sentence stays, the SLSA re-check sentence is gone")
print()

# ---------------------------------------------------------------------------
print("=== D2 round 19: Appendix A.6 status vectors, one statement per status of 5.2.2 ===")
a6 = find_line(d2, r"^A\.6\.\s+Status Vectors")
a6_end = find_line(d2, r"^Open Items", a6)
d2flat19 = norm_ws(" ".join(d2))
t19s = find_line(d2, r"^\s+\| Vector \| Candidate", a6)
t19e = find_line(d2, r"Table \d+: Status vectors", a6)
TAB19 = {}
for line in d2[t19s:t19e]:
    s_ = line.strip()
    if s_.startswith("|") and not s_.startswith("| Vector"):
        c_ = [x.strip() for x in s_.split("|")[1:-1]]
        TAB19[c_[0]] = (c_[1], c_[2], None if c_[3] == "(none)" else int(c_[3]))
fk = find_line(d2, r"and hex\):\s*$", find_line(d2, r"foreign test key whose seed", a6))
FK_B64, q19 = next_text(d2, fk)
FK_HEX, _ = next_text(d2, q19)
lab19 = re.search(r'seed is SHA-256 over the UTF-8 bytes of "([^"]+)"',
                  norm_ws(" ".join(d2[a6:fk + 1])).replace('" ', '"'))
FK_LABEL = lab19.group(1) if lab19 else None
SV19, SVSHA19 = {}, {}
for sid in [k for k in TAB19 if k != "M2"]:
    lsv = find_line(d2, r"^\s+%s, (\d+) bytes \(hex\):" % sid, a6, a6_end)
    SV19[sid] = (int(re.search(r"(\d+) bytes", d2[lsv]).group(1)), hex_block(d2, lsv))
for line in d2[a6:a6_end]:
    mm19 = re.match(r"^\s+(S\d)\s+([0-9a-f]{64})$", line)
    if mm19:
        SVSHA19[mm19.group(1)] = mm19.group(2)
STATUSES = ["malformed", "outside_profile", "untrusted_key", "signature_invalid", "receipt_not_verified",
            "digest_mismatch", "subject_mismatch"]
s522_txt = norm_ws(" ".join(d2[find_line(d2, r"^5\.2\.2\.\s+Checking a Statement"):
                               find_line(d2, r"^5\.2\.3\.\s+What Crosses")]))
in_text = [st for st in STATUSES if ("the status is " + st) in s522_txt] + (
    ["accepted"] if "the status is accepted" in s522_txt else [])


def thumb19(k):
    return sha256(cenc({1: 1, -1: 6, -2: k}))


def status19(stmt, rb, rkey, pairs):
    """Section 5.2.2 steps 1 to 7 as written; returns (status, first failing step or None)."""
    try:
        item = cbor2.loads(stmt)
        det = cenc(item) == stmt
    except Exception:  # noqa: BLE001  not one well-formed, valid data item
        return ("malformed", 1)
    if not det:
        return ("malformed", 1)
    tagged = isinstance(item, cbor2.CBORTag)
    if tagged and item.tag != 18:
        return ("malformed", 1)
    arr = item.value if tagged else item
    if not (isinstance(arr, (list, tuple)) and len(arr) == 4 and isinstance(arr[0], bytes)
            and isinstance(arr[1], Mapping) and isinstance(arr[2], (bytes, type(None))) and isinstance(arr[3], bytes)):
        return ("malformed", 1)
    ph_, uh_, pl_, sg_ = arr
    try:
        prot_ = cbor2.loads(ph_) if ph_ else {}
        pdet = (not ph_) or cenc(prot_) == ph_
    except Exception:  # noqa: BLE001
        return ("malformed", 1)
    if not isinstance(prot_, Mapping) or not pdet:
        return ("malformed", 1)
    cwt_ = prot_.get(15)
    if (not tagged or len(uh_) != 0 or set(prot_) != {1, 4, 15, 258, 259} or prot_[1] not in (-19, -8)
            or not (isinstance(prot_[4], bytes) and len(prot_[4]) == 32) or not isinstance(cwt_, Mapping)
            or set(cwt_) != {1, 2} or not isinstance(cwt_[1], str) or _abs_uri.match(cwt_[1]) is None
            or not isinstance(cwt_[2], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", cwt_[2]) is None
            or prot_[258] != -16 or prot_[259] != D2_TYPE or not isinstance(pl_, bytes) or len(pl_) != 32
            or len(sg_) != 64):
        return ("outside_profile", 2)
    sel = [k for iss_, k in pairs if iss_ == cwt_[1] and key_counts(k) and thumb19(k) == prot_[4]]
    if not sel:
        return ("untrusted_key", 3)
    ss_ = cenc(["Signature1", ph_, b"", pl_])
    if not any(profile_verify(k, sg_, ss_) is None for k in sel):
        return ("signature_invalid", 4)
    st_ = statement_steps_5_to_7(pl_, cwt_[2], rb, rkey)
    return (st_, None if st_ == "accepted" else {"receipt_not_verified": 5, "digest_mismatch": 6,
                                                 "subject_mismatch": 7}[st_])


pairs19 = [(D2_ISS, ISSUER_PK)]
check("D2", "R19-TAB", set(TAB19) == {"M2"} | {"S%d" % n for n in range(1, 9)}
      and {v[1] for v in TAB19.values()} == set(in_text) | {"accepted"} and len(in_text) == 8,
      "Table 'Status vectors' names M2 and S1 to S8, and their statuses are exactly the eight statuses Section 5.2.2 "
      "names in its text",
      "rows %s; statuses named by 5.2.2: %s" % (sorted(TAB19), in_text))
check("D2", "R19-SHA", set(SV19) == set(SVSHA19) and all(
      len(b_) == n_ and sha256(b_).hex() == SVSHA19[k_] for k_, (n_, b_) in SV19.items()),
      "each status vector's hex block has the byte count of its label and the SHA-256 listed for it",
      ", ".join("%s %d" % (k_, len(b_)) for k_, (_n, b_) in sorted(SV19.items())))
fk_pub = base64.b64decode(FK_B64)
check("D2", "R19-FKEY", FK_LABEL is not None and fk_pub.hex() == FK_HEX
      and pubkey_from_seed(sha256(FK_LABEL.encode("utf-8"))) == fk_pub,
      "the foreign test key: base64 equals hex, and this script's own Ed25519 derivation from SHA-256 over the label "
      "in the text gives that public key", "label %r" % FK_LABEL)
got_m2 = status19(D2_CS, VEC[TAB19["M2"][0]]["R"], ISSUER_PK, pairs19)
check("D2", "R19-M2", got_m2 == ("accepted", None) and TAB19["M2"] == ("P1", "accepted", None),
      "M2 with P1: status computed from the text %s, table says %s" % (got_m2, TAB19["M2"][1:]))
for k_ in sorted(SV19):
    cand_, st_exp, step_exp = TAB19[k_]
    got = status19(SV19[k_][1], VEC[cand_]["R"], ISSUER_PK, pairs19)
    check("D2", "R19-" + k_, got == (st_exp, step_exp),
          "%s with %s: status computed from the text (%s, step %s), table says (%s, step %s)"
          % (k_, cand_, got[0], got[1], st_exp, step_exp))
s1_ph = cbor2.loads(cbor2.loads(SV19["S1"][1]).value[0])
check("D2", "R19-A8", sha256(SV19["S1"][1]).hex() == sha256(_cs17).hex() and s1_ph[1] == -8,
      "S1 is byte for byte the statement R17-A8 builds (M2 with alg -8, signed again with the issuer seed), the "
      "third review's counterexample", "S1 sha256 %s" % sha256(SV19["S1"][1]).hex())
s19_txt = ["Vector M2 with vector P1 of [RECEIPTS] is accepted, and Appendix A.6 gives a statement for each other "
           "status.",
           "Vector S1 (Appendix A.6) is M2 with alg -8, signed again under the same key; it is accepted.",
           "the status of M2, of every status vector and of every certificate-profile vector, with its own "
           "implementation of the steps of Section 5.2.2 in both profiles;",
           "M2 and the status vectors of Appendix A.6 are, byte for byte, statements of that set, made independently "
           "by the generator of Appendix A."]
check("D2", "R19-TEXT", all(x in d2flat19 for x in s19_txt),
      "Sections 5.2.2, 5.2.4 and 12 point at the status vectors",
      "found %d of %d" % (sum(x in d2flat19 for x in s19_txt), len(s19_txt)))
# negative control: a status vector with one signature bit changed is no longer what the table says
_s5x = bytearray(SV19["S8"][1])
_s5x[-1] ^= 1
check("SELF", "N19", status19(bytes(_s5x), VEC["P1"]["R"], ISSUER_PK, pairs19) == ("signature_invalid", 4)
      and status19(SV19["S8"][1], VEC["P1"]["R"], ISSUER_PK, []) == ("untrusted_key", 3),
      "negative control: S8 with its last signature bit flipped is signature_invalid at step 4, and S8 under no "
      "configured pair is untrusted_key at step 3")
print()

# ---------------------------------------------------------------------------
print("=== D2 round 20: the certificate profile (5.2, 5.2.2, A.8) and typed digest references (5.1, A.7) ===")
d2flat20 = norm_ws(" ".join(d2))


# DER (X.690) as remembered: tag, length, contents; only what a certificate needs here.
class DerErr(Exception):
    pass


def der_tlv(b, i):
    """(tag, contents start, contents end, end) of the TLV at offset i; definite lengths only."""
    if i + 2 > len(b):
        raise DerErr("short")
    tag = b[i]
    if tag & 0x1F == 0x1F:
        raise DerErr("high tag number")
    n = b[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or j + k > len(b) or b[j] == 0:
            raise DerErr("length form")
        n = int.from_bytes(b[j:j + k], "big")
        if n < 128:
            raise DerErr("length not minimal")
        j += k
    if j + n > len(b):
        raise DerErr("overrun")
    return tag, j, j + n, j + n


def der_children(b, start, end):
    out, i = [], start
    while i < end:
        t, cs, ce, i = der_tlv(b, i)
        out.append((t, cs, ce))
    if i != end:
        raise DerErr("children overrun")
    return out


def der_oid(content):
    first, rest, val = content[0], [], 0
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    for c in content[1:]:
        val = (val << 7) | (c & 0x7F)
        if not c & 0x80:
            rest.append(val)
            val = 0
    return ".".join(str(a) for a in arcs + rest)


def der_uint(content):
    if not content or (content[0] & 0x80):
        raise DerErr("negative or empty INTEGER")
    return int.from_bytes(content, "big")


def parse_cert(c):
    """The parts of an X.509 certificate (RFC 5280 Section 4.1) that step 3 of the certificate profile reads."""
    t, cs, ce, end = der_tlv(c, 0)
    if t != 0x30 or end != len(c):
        raise DerErr("not one SEQUENCE")
    top = der_children(c, cs, ce)
    if len(top) != 3 or top[0][0] != 0x30 or top[1][0] != 0x30 or top[2][0] != 0x03:
        raise DerErr("Certificate shape")
    tbs_raw = c[top[0][1] - (2 if top[0][2] - top[0][1] < 128 else (2 + len((top[0][2] - top[0][1]).to_bytes(4, 'big').lstrip(b'\0')))):top[0][2]]
    sig_alg = der_children(c, top[1][1], top[1][2])
    sig_oid = der_oid(c[sig_alg[0][1]:sig_alg[0][2]])
    bits = c[top[2][1]:top[2][2]]
    if bits[0] != 0:
        raise DerErr("unused bits")
    tbs = der_children(c, top[0][1], top[0][2])
    k = 1 if tbs[0][0] == 0xA0 else 0
    issuer = c[tbs[k + 2][1] - _hdr_len(tbs[k + 2]):tbs[k + 2][2]]
    subject = c[tbs[k + 4][1] - _hdr_len(tbs[k + 4]):tbs[k + 4][2]]
    spki_t = tbs[k + 5]
    spki = c[spki_t[1] - _hdr_len(spki_t):spki_t[2]]
    spki_parts = der_children(c, spki_t[1], spki_t[2])
    alg = der_children(c, spki_parts[0][1], spki_parts[0][2])
    key_oid = der_oid(c[alg[0][1]:alg[0][2]])
    key_param = der_oid(c[alg[1][1]:alg[1][2]]) if len(alg) > 1 and alg[1][0] == 0x06 else None
    key_bits = c[spki_parts[1][1]:spki_parts[1][2]]
    if key_bits[0] != 0:
        raise DerErr("key unused bits")
    ekus = None
    for t_, s_, e_ in tbs[k + 6:]:
        if t_ != 0xA3:
            continue
        (seq_t, seq_s, seq_e), = der_children(c, s_, e_)
        for _t, xs, xe in der_children(c, seq_s, seq_e):
            parts = der_children(c, xs, xe)
            if der_oid(c[parts[0][1]:parts[0][2]]) == "2.5.29.37":
                octets = parts[-1]
                (_ot, os_, oe_), = der_children(c, octets[1], octets[2])
                ekus = [der_oid(c[a:b]) for _x, a, b in der_children(c, os_, oe_)]
    return {"tbs": tbs_raw, "sig_oid": sig_oid, "sig": bits[1:], "issuer": issuer, "subject": subject,
            "spki": spki, "key_oid": key_oid, "key_param": key_param, "key": key_bits[1:], "eku": ekus}


def _hdr_len(t):
    n = t[2] - t[1]
    return 2 if n < 128 else 2 + len(n.to_bytes(4, "big").lstrip(b"\0"))


def rsa_key(raw):
    (_t, cs, ce), = [der_tlv(raw, 0)[:3]]
    n_t, e_t = der_children(raw, cs, ce)
    return der_uint(raw[n_t[1]:n_t[2]]), der_uint(raw[e_t[1]:e_t[2]])


DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_pkcs1v15_sha256_ok(n, e, msg, sig):
    """RFC 8017 Section 8.2.2 with EMSA-PKCS1-v1_5 (Section 9.2) and SHA-256, as remembered."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = DIGESTINFO_SHA256 + hashlib.sha256(msg).digest()
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


# P-256 (SEC 2 / FIPS 186), constants as remembered; affine arithmetic.
EC_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
EC_A = EC_P - 3
EC_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
EC_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
EC_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def ec_on(pt):
    x, y = pt
    return (y * y - (x * x * x + EC_A * x + EC_B)) % EC_P == 0


def ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % EC_P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + EC_A) * pow(2 * p1[1], -1, EC_P) % EC_P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, EC_P) % EC_P
    x = (lam * lam - p1[0] - p2[0]) % EC_P
    return (x, (lam * (p1[0] - x) - p1[1]) % EC_P)


def ec_mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = ec_add(acc, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return acc


def es256_ok(point, msg, sig):
    """ECDSA verification with SHA-256 (FIPS 186), r and s from the two halves of the signature (RFC 9053 2.1)."""
    if len(sig) != 64 or point is None or not ec_on(point):
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < EC_N and 1 <= s < EC_N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, EC_N)
    pt = ec_add(ec_mul(e * w % EC_N, EC_G), ec_mul(r * w % EC_N, point))
    return pt is not None and pt[0] % EC_N == r


def es256_lib(point, msg, sig):
    from cryptography.hazmat.primitives.asymmetric import ec as _ec  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes as _h  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature as _enc  # noqa: PLC0415
    try:
        k = _ec.EllipticCurvePublicNumbers(point[0], point[1], _ec.SECP256R1()).public_key()
        k.verify(_enc(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, _ec.ECDSA(_h.SHA256()))
        return True
    except Exception:  # noqa: BLE001
        return False


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


DID_RX = re.compile(r"\Adid:x509:0:sha256:([A-Za-z0-9_-]{43})::eku:([0-2](?:\.(?:0|[1-9][0-9]*))+)\Z")


def cert_pair_counts(iss_, kid_, chain, pair):
    """Section 5.2.2 step 3, certificate profile, as written."""
    p_iss, anchor = pair
    m = DID_RX.match(iss_)
    if p_iss != iss_ or chain[1] != anchor or b64url_nopad(sha256(anchor)) != m.group(1):
        return False
    try:
        leaf, root = parse_cert(chain[0]), parse_cert(chain[1])
        if root["key_oid"] != "1.2.840.113549.1.1.1":
            return False
        n_, e_ = rsa_key(root["key"])
        if n_.bit_length() < 2048 or leaf["sig_oid"] != "1.2.840.113549.1.1.11":
            return False
        if not rsa_pkcs1v15_sha256_ok(n_, e_, leaf["tbs"], leaf["sig"]):
            return False
        if leaf["issuer"] != root["subject"] or leaf["eku"] is None or m.group(2) not in leaf["eku"]:
            return False
        if leaf["key_oid"] != "1.2.840.10045.2.1" or leaf["key_param"] != "1.2.840.10045.3.1.7":
            return False
    except (DerErr, IndexError, ValueError):
        return False
    return sha256(leaf["spki"]) == kid_


def leaf_point(cert):
    k = parse_cert(cert)["key"]
    if len(k) != 65 or k[0] != 4:
        return None
    return int.from_bytes(k[1:33], "big"), int.from_bytes(k[33:], "big")


def status20(stmt, rb, rkey, pairs, cert_pairs):
    """Section 5.2.2 steps 1 to 7 with both profiles, as written in round 20."""
    try:
        item = cbor2.loads(stmt)
        det = cenc(item) == stmt
    except Exception:  # noqa: BLE001
        return ("malformed", 1)
    if not det:
        return ("malformed", 1)
    tagged = isinstance(item, cbor2.CBORTag)
    if tagged and item.tag != 18:
        return ("malformed", 1)
    arr = item.value if tagged else item
    if not (isinstance(arr, (list, tuple)) and len(arr) == 4 and isinstance(arr[0], bytes)
            and isinstance(arr[1], Mapping) and isinstance(arr[2], (bytes, type(None))) and isinstance(arr[3], bytes)):
        return ("malformed", 1)
    ph_, uh_, pl_, sg_ = arr
    try:
        prot_ = cbor2.loads(ph_) if ph_ else {}
        pdet = (not ph_) or cenc(prot_) == ph_
    except Exception:  # noqa: BLE001
        return ("malformed", 1)
    if not isinstance(prot_, Mapping) or not pdet:
        return ("malformed", 1)
    # round 21, 5.2.2 step 2: label 394 alone, an array of one or more byte strings, is removed; not read
    if (set(uh_) == {394} and isinstance(uh_[394], (list, tuple)) and len(uh_[394]) >= 1
            and all(isinstance(r_, bytes) for r_ in uh_[394])):
        uh_ = {}
    cwt_ = prot_.get(15)
    shared = (tagged and len(uh_) == 0 and isinstance(prot_.get(4), bytes) and len(prot_[4]) == 32
              and isinstance(cwt_, Mapping) and set(cwt_) == {1, 2} and isinstance(cwt_[1], str)
              and isinstance(cwt_[2], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", cwt_[2]) is not None
              and prot_.get(258) == -16 and prot_.get(259) == D2_TYPE and isinstance(pl_, bytes) and len(pl_) == 32
              and len(sg_) == 64)
    labels = set(prot_)
    if shared and labels == {1, 4, 15, 258, 259} and prot_[1] in (-19, -8) and _abs_uri.match(cwt_[1]):
        prof = "key"
    elif (shared and labels == {1, 4, 15, 33, 258, 259} and prot_[1] == -7 and DID_RX.match(cwt_[1])
          and isinstance(prot_[33], (list, tuple)) and len(prot_[33]) == 2 and all(isinstance(c, bytes) for c in prot_[33])):
        prof = "certificate"
    else:
        return ("outside_profile", 2)
    ss_ = cenc(["Signature1", ph_, b"", pl_])
    if prof == "key":
        sel = [k for iss_, k in pairs if iss_ == cwt_[1] and key_counts(k) and thumb19(k) == prot_[4]]
        if not sel:
            return ("untrusted_key", 3)
        good = any(profile_verify(k, sg_, ss_) is None for k in sel)
    else:
        chain = list(prot_[33])
        if not any(cert_pair_counts(cwt_[1], prot_[4], chain, pr) for pr in cert_pairs):
            return ("untrusted_key", 3)
        good = es256_ok(leaf_point(chain[0]), ss_, sg_)
    if not good:
        return ("signature_invalid", 4)
    st_ = statement_steps_5_to_7(pl_, cwt_[2], rb, rkey)
    return (st_, None if st_ == "accepted" else {"receipt_not_verified": 5, "digest_mismatch": 6,
                                                 "subject_mismatch": 7}[st_])


# self-tests of the primitives written above
check("SELF", "R20-EC", ec_on(EC_G) and ec_mul(EC_N, EC_G) is None and ec_mul(EC_N - 1, EC_G) == (EC_G[0], EC_P - EC_G[1]),
      "P-256 as written: G is on the curve, n*G is the point at infinity and (n-1)*G is -G")
check("SELF", "R20-OID", der_oid(bytes.fromhex("2a864886f70d01010b")) == "1.2.840.113549.1.1.11"
      and der_oid(bytes.fromhex("2b06010505070303")) == "1.3.6.1.5.5.7.3.3",
      "the OID reader gives sha256WithRSAEncryption and code signing for their DER contents")

# Appendix A.8 read from the text
a8 = find_line(d2, r"^A\.8\.\s+Certificate-Profile Vectors")
a8_end = find_line(d2, r"^Open Items", a8)
lf = find_line(d2, r"^\s+F [A-Za-z0-9_-]{43}$", a8, a8_end)
F20 = d2[lf].split()[1]
O20 = d2[lf + 1].split()[1]
ISS20 = "did:x509:0:sha256:%s::eku:%s" % (F20, O20)
ll = find_line(d2, r"Test leaf certificate, \d+ bytes \(hex\):", a8, a8_end)
LEAF20 = hex_block(d2, ll)
lr = find_line(d2, r"Test root certificate, the trust anchor", a8, a8_end)
ROOT20 = hex_block(d2, lr)
lsh = find_line(d2, r"SHA-256 over the test leaf and over the test root certificate:", a8, a8_end)
SH20 = [next_text(d2, lsh)[0]]
SH20.append(next_text(d2, next_text(d2, lsh)[1])[0])
KID20 = hex_block(d2, find_line(d2, r"kid of X1, SHA-256 over the SubjectPublicKeyInfo", a8, a8_end))
lx1 = find_line(d2, r"^\s+X1, \d+ bytes \(hex\):", a8, a8_end)
X1 = hex_block(d2, lx1)
SIG20 = {}
for xid in ("X2", "X3", "X4", "X5", "X6"):
    lxs = find_line(d2, r"^\s+%s: .*" % xid, a8, a8_end)
    SIG20[xid] = hex_block(d2, lxs)
TAB20 = {}
t20s = find_line(d2, r"^\s+\| Vector \| Bytes", a8, a8_end)
t20e = find_line(d2, r"Table \d+: Certificate-profile vectors", a8, a8_end)
t20b = find_line(d2, r"^\s+\+=", t20s + 1, t20e)   # the rule under the (wrapped) heading
for line in d2[t20b:t20e]:
    s_ = line.strip()
    if s_.startswith("|"):
        c_ = [x.strip() for x in s_.split("|")[1:-1]]
        TAB20[c_[0]] = (int(c_[1]), c_[2], c_[3], None if c_[4] == "(none)" else int(c_[4]))
XSHA20 = {}
for line in d2[t20e:a8_end]:
    mm20 = re.match(r"^\s+(X\d)\s+([0-9a-f]{64})$", line)
    if mm20:
        XSHA20[mm20.group(1)] = mm20.group(2)
x1t = cbor2.loads(X1)
x1p = dict(cbor2.loads(x1t.value[0]))
leaf20, root20 = parse_cert(LEAF20), parse_cert(ROOT20)
check("D2", "R20-CERTS", sha256(LEAF20).hex() == SH20[0] and sha256(ROOT20).hex() == SH20[1]
      and b64url_nopad(sha256(ROOT20)) == F20 and sha256(leaf20["spki"]) == KID20
      and list(x1p.get(33, [])) == [LEAF20, ROOT20],
      "A.8: the two certificates match their SHA-256, F is SHA-256 over the test root in base64url without padding, "
      "kid is SHA-256 over the SubjectPublicKeyInfo of the test leaf (read with this script's DER reader), and "
      "x5chain of X1 is the leaf and the root", "F %s, O %s" % (F20, O20))
check("D2", "R20-X1FORM", list(x1p) == [1, 4, 15, 33, 258, 259] and x1p[1] == -7 and x1p[4] == KID20
      and dict(x1p[15]) == {1: ISS20, 2: x1p[15][2]} and x1p[15][2] == D2_SUB and x1p[258] == -16
      and x1p[259] == D2_TYPE and len(x1t.value[1]) == 0 and x1t.value[2] == D2_DIGEST and len(X1) == TAB20["X1"][0],
      "X1 has exactly the six parameters of the certificate profile in the order the text lists, iss F and O as "
      "given, sub of M2, the receipt digest as payload and the length of the table")


def build_x(prot_map, sig_):
    return cenc(cbor2.CBORTag(18, [cenc(prot_map), {}, D2_DIGEST, sig_]))


_iss_leaf = "did:x509:0:sha256:%s::eku:%s" % (b64url_nopad(sha256(LEAF20)), O20)
X20 = {"X1": X1,
       "X2": build_x({**x1p, 1: -9}, SIG20["X2"]),
       "X3": build_x({k: v for k, v in x1p.items() if k != 33}, SIG20["X3"]),
       "X4": build_x({**x1p, 15: {1: _iss_leaf, 2: x1p[15][2]}}, SIG20["X4"]),
       "X5": build_x({**x1p, 16: "application/cose"}, SIG20["X5"]),
       "X6": build_x(x1p, SIG20["X6"])}
x_desc = ["X2: X1 with 1 (alg) -9 in place of -7.", "X3: X1 without parameter 33 (x5chain).",
          "X4: X1 with iss in the form of Section 5.2, whose F is SHA-256 over the test leaf certificate.",
          "X5: X1 with one more parameter, 16 (typ), the text string \"application/cose\".",
          "X6: X1's protected header unchanged."]
check("D2", "R20-REBUILD", all(x in d2flat20 for x in x_desc) and set(XSHA20) == set(X20)
      and all(sha256(X20[k]).hex() == XSHA20[k] and len(X20[k]) == TAB20[k][0] for k in X20),
      "X2 to X6 rebuilt from X1 with the change the text names and the signature it gives: each has the SHA-256 and "
      "the length the text lists", ", ".join("%s %d" % (k, len(v)) for k, v in sorted(X20.items())))
pairs20 = [(D2_ISS, ISSUER_PK)]
cpairs20 = [(ISS20, ROOT20)]
in_text20 = "configured certificate pair is the did:x509 identifier below with the test root certificate" in d2flat20
for k_ in sorted(X20):
    _n, cand_, st_exp, step_exp = TAB20[k_]
    got = status20(X20[k_], VEC[cand_]["R"], ISSUER_PK, pairs20, cpairs20)
    check("D2", "R20-" + k_, got == (st_exp, step_exp) and in_text20,
          "%s with %s under the certificate pair of A.8: status computed from the text (%s, step %s), table says (%s, "
          "step %s)" % (k_, cand_, got[0], got[1], st_exp, step_exp))
x1_ss = cenc(["Signature1", x1t.value[0], b"", D2_DIGEST])
lp = leaf_point(LEAF20)
check("SELF", "R20-ECLIB", es256_ok(lp, x1_ss, x1t.value[3]) and es256_lib(lp, x1_ss, x1t.value[3])
      and not es256_ok(lp, cenc(["Signature1", cbor2.loads(X20["X6"]).value[0], b"", D2_DIGEST]), SIG20["X6"])
      and not es256_lib(lp, cenc(["Signature1", cbor2.loads(X20["X6"]).value[0], b"", D2_DIGEST]), SIG20["X6"]),
      "this script's ECDSA P-256 and the library agree: X1's signature verifies under the leaf key, X6's does not")
_rn, _re_ = rsa_key(root20["key"])
check("SELF", "R20-RSA", rsa_pkcs1v15_sha256_ok(_rn, _re_, leaf20["tbs"], leaf20["sig"])
      and not rsa_pkcs1v15_sha256_ok(_rn, _re_, leaf20["tbs"][:-1] + bytes([leaf20["tbs"][-1] ^ 1]), leaf20["sig"])
      and _rn.bit_length() == 3072 and root20["sig_oid"] == "1.2.840.113549.1.1.11"
      and rsa_pkcs1v15_sha256_ok(_rn, _re_, root20["tbs"], root20["sig"]),
      "RSASSA-PKCS1-v1_5 with SHA-256 as written: the leaf's signature verifies under the 3072-bit root key, fails "
      "with one bit of the TBSCertificate changed, and the root's self-signature verifies")
# controls that the steps of the certificate profile, not only the vectors, are computed
_root_bad = bytearray(ROOT20)
_root_bad[-1] ^= 1
check("SELF", "N20", status20(X1, VEC["P1"]["R"], ISSUER_PK, pairs20, []) == ("untrusted_key", 3)
      and status20(X1, VEC["P1"]["R"], ISSUER_PK, pairs20, [(ISS20, bytes(_root_bad))]) == ("untrusted_key", 3)
      and status20(X1, VEC["N7"]["R"], ISSUER_PK, pairs20, cpairs20) == ("receipt_not_verified", 5)
      and status20(D2_CS, VEC["P1"]["R"], ISSUER_PK, pairs20, cpairs20) == ("accepted", None)
      and all(status20(b_, VEC[TAB19[k_][0]]["R"], ISSUER_PK, pairs20, cpairs20) == TAB19[k_][1:]
              for k_, (_n2, b_) in SV19.items()),
      "negative controls: X1 under no certificate pair, or under a pair whose anchor has one bit changed, is "
      "untrusted_key at step 3; X1 with N7 is receipt_not_verified; M2 and S1 to S8 keep their status with the "
      "certificate pair configured too")
check("DEMO", "R20-URI", _abs_uri.match(ISS20) is not None and _abs_uri.match("https://issuer.example/e[val") is None
      and _abs_uri.match("did:") is not None and _abs_uri.match("did:x509:0#frag") is None,
      "RFC 3986 absolute-URI with all forms of hier-part: the did:x509 identifier of X1 (path-rootless) is one, "
      "https://issuer.example/e[val is not, an empty path is one, a fragment is not")
s20_txt = ["The labels of the protected header select the profile: exactly 1, 4, 15, 258 and 259 select the key "
           "profile, and exactly 1, 4, 15, 33, 258 and 259 the certificate profile.",
           "This step is not certification path validation ([RFC5280] Section 6) and does not resolve iss as a DID",
           "[RFC9864] also sets -7 to Deprecated and registers -9 (ESP256) for ECDSA with SHA-256 on P-256.",
           "The steps of Section 5.2.2, applied on 2026-10-11 to the registered statement under the certificate pair "
           "of its test root, give accepted",
           "054f1f6e364580c42fad862747903f2a6ee19976", "[RFC9360]", "[RFC5280]", "[RFC8017]", "[RFC6979]"]
check("D2", "R20-TEXT", all(x in d2flat20 for x in s20_txt),
      "5.2.2 names the two label sets, says that step 3 is not path validation, 5.2.4 says that RFC 9864 deprecates "
      "-7, Section 12 gives the registration measurement, and the new references stand",
      "missing: " + (", ".join(x[:40] for x in s20_txt if x not in d2flat20) or "none"))

# Appendix A.7, typed digest references, and Section 5.1
a7 = find_line(d2, r"^A\.7\.\s+Typed Digest References")
t7s = find_line(d2, r"^\s+\| Vector \| Change to", a7, a8)
t7e = find_line(d2, r"Table \d+: Typed digest references", a7, a8)
t7b = find_line(d2, r"^\s+\+=", t7s + 1, t7e)   # the rule under the (wrapped) heading
TAB7, _row = {}, None
for line in d2[t7b:t7e]:
    s_ = line.strip()
    if s_.startswith("|"):
        c_ = [x.strip() for x in s_.split("|")[1:-1]]
        if c_[0]:
            _row = c_[0]
            TAB7[_row] = c_
        else:
            TAB7[_row] = [(a + " " + b).strip() for a, b in zip(TAB7[_row], c_)]
_p2b = steps_1_to_3(VEC["P2"]["R"])[0]
REF1 = {"type": D2_TYPE, "digest_alg": "SHA-256", "digest": D2_DIGEST.hex()}
CHANGES7 = {"(none)": {}, "purpose evaluation added": {"purpose": "evaluation"},
            "digest_alg sha-256": {"digest_alg": "sha-256"}, "digest in uppercase": {"digest": D2_DIGEST.hex().upper()},
            "digest names B of P2": {"digest": sha256(_p2b).hex()}}


def ref_state(ref, rb):
    """Section 5.1 with CPB Section 8.1 as Section 5.1 cites it: (state, matching rule)."""
    mr = match_rule_in("typed reference", ref.get("digest_alg"), ref.get("digest"), rb)[0]
    B_, fail_, _ = steps_1_to_3(rb)
    if ref.get("type") != D2_TYPE or "purpose" in ref:
        return "Unresolved", mr
    if ref.get("digest_alg") != "SHA-256" or re.fullmatch(r"[0-9a-f]{64}", str(ref.get("digest"))) is None:
        return "Failed", mr
    if fail_:
        return "Unresolved", mr
    return ("Verified" if sha256(B_).hex() == ref["digest"] else "Failed"), mr


s51 = ["the context has no purpose label, so a reference that carries purpose is Unresolved ([CPB] Section 8.1);",
       "a digest_alg other than SHA-256, a digest that is not a text value of 64 lowercase hexadecimal digits, and a "
       "digest that differs from SHA-256 over B are Failed ([CPB] Section 8.1); the matching rule of Section 3.3 gives "
       "INDETERMINATE for the first two and NO_MATCH for the third, because it also reads citations outside a typed "
       "digest reference."]
check("SELF", "R20-CARRIER", match_rule("sha-256", D2_DIGEST.hex(), VEC["P1"]["R"])[0] == "MATCH"
      and match_rule_in("typed reference", "sha-256", D2_DIGEST.hex(), VEC["P1"]["R"])[0] == "INDETERMINATE"
      and match_rule_in("typed reference", "SHA-256", D2_DIGEST.hex(), VEC["P1"]["R"])[0] == "MATCH"
      and "each name counts only in its own carrier" in d2flat20,
      "3.3 step 1 per carrier: sha-256 matches in the examples' carrier and gives INDETERMINATE in a typed digest "
      "reference, where only SHA-256 names the algorithm; the union of the names (match_rule) is too wide there")
check("D2", "R20-51", all(x in d2flat20 for x in s51) and set(TAB7) == {"R%d" % i for i in range(1, 7)},
      "5.1 holds the two sentences of the CPB comparison (P1 and P2), and A.7 lists R1 to R6",
      "found %d of %d; rows %s" % (sum(x in d2flat20 for x in s51), len(s51), sorted(TAB7)))
for rid in sorted(TAB7):
    _v, change, cand_, state_exp, match_exp = TAB7[rid]
    ref = {**REF1, **CHANGES7[change.replace("`", "")]}
    got = ref_state(ref, VEC[cand_]["R"])
    check("D2", "R20-" + rid, got == (state_exp, match_exp),
          "%s (%s) with %s: state and matching rule computed from the text %s, table says %s"
          % (rid, change, cand_, got, (state_exp, match_exp)))
print()


# ---------------------------------------------------------------------------
print("=== D2 round 21: Transparent Statements (5.2.2 step 2, A.9) and the lab-chain sentences ===")
d2flat21 = norm_ws(" ".join(d2))
a9 = find_line(d2, r"^A\.9\.\s+Transparent Statements")
a9_end = find_line(d2, r"^Open Items", a9)
R21 = hex_block(d2, find_line(d2, r"^\s+R, \d+ bytes \(hex\):", a9, a9_end))
# Revision -01, build of 2026-10-11: the array is written [ R ] with spaces, so that idnits does not read [R] as a
# citation; the CBOR diagnostic notation allows the spaces.
FORM21 = {"T1": "T1: the protected header, payload and signature of M2; unprotected header {394: [ R ]}.",
          "T2": "T2: the protected header, payload and signature of X1; unprotected header {394: [ R ]}.",
          "T3": "T3: as T2; unprotected header {4: the kid of X1, 394: [ R ]}.",
          "T4": "T4: as T2; unprotected header {394: R}, the byte string not in an array.",
          "T5": "T5: as T2; unprotected header {394: []}."}
_m2v, _x1v = cbor2.loads(D2_CS).value, cbor2.loads(X20["X1"]).value


def ts21(v, unprotected):
    return cenc(cbor2.CBORTag(18, [v[0], unprotected, v[2], v[3]]))


T21 = {"T1": ts21(_m2v, {394: [R21]}), "T2": ts21(_x1v, {394: [R21]}),
       "T3": ts21(_x1v, {4: KID20, 394: [R21]}), "T4": ts21(_x1v, {394: R21}), "T5": ts21(_x1v, {394: []})}
t21s = find_line(d2, r"^\s+\| Vector \| Bytes", a9, a9_end)
t21e = find_line(d2, r"Table \d+: Transparent Statements", a9, a9_end)
t21b = find_line(d2, r"^\s+\+=", t21s + 1, t21e)
TAB21 = {}
for line in d2[t21b:t21e]:
    s_ = line.strip()
    if s_.startswith("|"):
        c_ = [x.strip() for x in s_.split("|")[1:-1]]
        TAB21[c_[0]] = (int(c_[1]), c_[2], c_[3], None if c_[4] == "(none)" else int(c_[4]))
TSHA21 = {}
for line in d2[t21e:a9_end]:
    mm21 = re.match(r"^\s+(T\d)\s+([0-9a-f]{64})$", line)
    if mm21:
        TSHA21[mm21.group(1)] = mm21.group(2)
check("D2", "R21-REBUILD", all(f in d2flat21 for f in FORM21.values()) and set(TSHA21) == set(T21) == set(TAB21)
      and all(sha256(T21[k]).hex() == TSHA21[k] and len(T21[k]) == TAB21[k][0] for k in T21),
      "T1 to T5 rebuilt from M2, X1 and R as A.9 names them: each has the SHA-256 and the length the text lists",
      ", ".join("%s %d" % (k, len(v)) for k, v in sorted(T21.items())))
for k_ in sorted(T21):
    _n, cand_, st_exp, step_exp = TAB21[k_]
    got = status20(T21[k_], VEC[cand_]["R"], ISSUER_PK, pairs20, cpairs20)
    check("D2", "R21-" + k_, got == (st_exp, step_exp),
          "%s with %s under both configured pairs: status computed from the text (%s, step %s), table says (%s, step "
          "%s)" % (k_, cand_, got[0], got[1], st_exp, step_exp))
_rcpt = cbor2.loads(R21)
check("DEMO", "R21-NOREAD", isinstance(_rcpt, cbor2.CBORTag) and _rcpt.tag == 18
      and status20(ts21(_x1v, {394: [b"\x00"]}), VEC["P1"]["R"], ISSUER_PK, pairs20, cpairs20) == ("accepted", None)
      and status20(ts21(_x1v, {394: [R21, R21]}), VEC["P1"]["R"], ISSUER_PK, pairs20, cpairs20) == ("accepted", None)
      and status20(ts21(_x1v, {395: [R21]}), VEC["P1"]["R"], ISSUER_PK, pairs20, cpairs20) == ("outside_profile", 2),
      "the steps do not read the receipts: X1 with a one-byte string or with R twice under 394 is accepted, X1 with R "
      "under 395 is outside_profile; R itself is a tagged COSE_Sign1, which the steps never open")
s21_txt = [
    "If the unprotected header holds label 394 and no other label, and the value of 394 is an array of one or more "
    "byte strings, the Receiver removes label 394",
    "These steps do not read the receipts.",
    "Receipts not read. Step 2 of Section 5.2.2 removes the receipts of a Transparent Statement without reading them;",
    "It fixes the key, not the issuer name in the receipt: two instances of a Transparency Service can carry the same "
    "issuer name and differ only in their keys (Section 12).",
    "Digest not checked at registration.", "Only the Receiver recomputes the receipt digest",
    "as cannot-evaluate (exit status 3), not as untrusted (exit status 1); this document maps no verdict of another "
    "tool to a status of Section 5.2.2.",
    "did not anchor a chain whose leaf certificate was signed with ECDSA (exit status 3) and verified the chain with "
    "an RSA root.",
    "Vector T2 is the Transparent Statement that a local instance of the same service returned on 2026-10-11 for X1",
    "A receipt does not show where B came from."]
check("D2", "R21-TEXT", all(x in d2flat21 for x in s21_txt),
      "5.2.2 step 2 has the rule for Transparent Statements, Section 9 the paragraphs on receipts and on the digest at "
      "registration, Section 12 the lab-chain measurements, and the copied non-claims list the limit on where B came "
      "from", "missing: " + (", ".join(x[:40] for x in s21_txt if x not in d2flat21) or "none"))
print()

print("=== D2 round 22: Open Items, the question on intermediate certificates and other roots ===")
oi22_i = find_line(d2, r"^Open Items")
oi22 = norm_ws(" ".join(d2[oi22_i:find_line(d2, r"^Author's Address", oi22_i)]))
s12_i = find_line(d2, r"^12\.  Implementation Status")
s12_22 = norm_ws(" ".join(d2[s12_i:find_line(d2, r"^13\.  ", s12_i)]))
oi22_txt = ("Whether the certificate profile admits an intermediate certificate or an anchor key other than RSA. It "
            "requires exactly two certificates and an RSA root because that is the form measured to work: the offline "
            "verifier named in Section 12 did not anchor a chain whose leaf certificate was signed with ECDSA, and "
            "verified the chain with an RSA root.")
oi22_alg = "Whether the certificate profile also admits alg -9 (ESP256) of [RFC9864] (Section 5.2.4)."
s12_22_txt = ("did not anchor a chain whose leaf certificate was signed with ECDSA (exit status 3) and verified the "
              "chain with an RSA root.")
check("D2", "R22-OI", oi22_txt in oi22 and oi22_alg in oi22 and s12_22_txt in s12_22
      and "verified the Transparent Statement it returned offline" in s12_22,
      "Open Items keep the question on alg -9 and ask about intermediate certificates and other roots with the "
      "measured reason; Section 12, which that item cites, holds the measurement and names the offline verifier",
      "item found: %s; alg -9 item: %s; Section 12 sentence: %s" % (oi22_txt in oi22, oi22_alg in oi22,
                                                                   s12_22_txt in s12_22))
print()

# ---------------------------------------------------------------------------
tot = len(RESULTS)
held = sum(1 for r in RESULTS if r[2])
failed = [r for r in RESULTS if not r[2]]
by = {}
for cat, cid, ok, _ in RESULTS:
    by.setdefault(cat, [0, 0])
    by[cat][0 if ok else 1] += 1
print("SUMMARY: %d of %d checks hold; failing: %s" % (
    held, tot, ", ".join("%s %s" % (c, i_) for c, i_, _, _ in failed) if failed else "none"))
print("By category: " + "; ".join("%s %d hold / %d fail" % (k, v[0], v[1]) for k, v in by.items()))
sys.exit(0 if not failed else 1)
