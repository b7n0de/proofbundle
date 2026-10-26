#!/usr/bin/env python3
"""A fresh challenge set for a second implementation of draft-gruszka-signed-evaluation-receipts-04, and the
comparison of its answers. Ported from the set for -02 (card FOXTROT-CLOUD-SER-PRUEFMENGE-01; owner choice of
2026-10-13, 18:2x Berlin, A and A) to the text and the vector file in the parent folder.

The 66 vectors of Appendix A and their expected results are public, so a submission that reports 66 of 66 proves
nothing: the answers can be built in or claimed. Each submission therefore answers a challenge set that was never
published. It comes from a seed of 32 bytes that never enters the repository, an entry count (200 by default) and the
name of the submission; every set has test keys and salts of its own. The entries mix all eleven steps of the
verification procedure and the four rules of the verification profile, about a third of them valid, with edge cases
of the RFC 8785 number serialization, keys of small and of mixed order and single byte faults in valid receipts. No
entry equals a vector of Appendix A byte for byte. The same seed, count and name give byte-identical files.

The expected answer of each entry comes from two verifiers of this draft, both written by us from the -04 text:
the checker of the session that writes the draft and its vectors (author-checker/ser_verify.py) and the one written
from the text alone in a separate session (verifier-from-text/ser04/pruefer_ser.py). An entry on which they do not give
the same verdict and the same first failing step (with the same profile rule) is left out of the set and kept as a
finding on the text. The comparison only reads a submission's answers; it never runs foreign code.

Interface, as the prompt for the second implementation states it (items 7 and 8):
  challenge.jsonl  one line per entry: {"id": "c001", "receipt_b64": "...", "key_b64": "..."}, unique string ids, the
                   receipt bytes and the 32-byte verification key, each canonical base64 with padding
  answers.jsonl    one line per entry, in input order, exactly {"id", "verdict", "step", "detail"}: PASS with step
                   and detail null; FAIL with step 1 to 11, detail null at steps 1 to 10 and one of SECHS at step 11;
                   ERROR with step null and detail "resource-limit" or "execution-error"
  results.jsonl    the same form for Appendix A, with the vector ids as id

Calls (Python 3, standard library only):
  pruefmenge_erzeugen <kennung> [--anzahl N]          writes seed.hex, challenge.jsonl, expected.jsonl into
                                                       $SER_PRUEFMENGE_ORDNER/<kennung> (default ~/ser_pruefmengen)
                                                       and prints the name and the SHA-256 of challenge.jsonl
  pruefmenge_vergleichen <kennung> <answers.jsonl> --summe <sha256>
                                                       checks name and sum from the reply, then compares; exit 0
                                                       when the envelope of the answer is complete, whatever the
                                                       classes of the entries; 1 for an execution error of the
                                                       envelope or a name or sum that do not match; 2 for a call
                                                       that cannot run
Seed and expected.jsonl stay in that folder; only challenge.jsonl goes out. Keys and salts are test material only.
"""
from __future__ import annotations

import argparse
import base64
import decimal
import hashlib
import json
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
SER = HERE.parent
sys.path.insert(0, str(SER / "author-checker"))
sys.path.insert(0, str(SER / "verifier-from-text"))

import ser_verify as autor_pruefer  # noqa: E402  the checker of the session that writes the draft
from ser04 import pruefer_ser as text_pruefer  # noqa: E402  the verifier written from the text alone

#: The derivation of a set's random stream; it changes only when the same seed should give other challenge bytes.
VERSION = "ser-pruefmenge-3"
#: The tool as erzeugung.json names it; -4 writes detail with the key or R (owner choice O2) and the later fault of
#: entries with two faults, with challenge bytes unchanged from -3; -5 takes its expected answers from the verifiers of
#: -04 and Appendix A from the -04 vector file, with the generator and the derivation unchanged.
WERKZEUG = "ser-pruefmenge-5"
VECTORS = SER / "test-vectors.json"
TEXT = SER / "draft-gruszka-signed-evaluation-receipts-04.txt"
STANDARD_ANZAHL = 200
ORDNER_VARIABLE = "SER_PRUEFMENGE_ORDNER"
STANDARD_ORDNER = pathlib.Path.home() / "ser_pruefmengen"
KENNUNG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
ANHANG_A = "anhang-a"

MEDIA_TYPE = "application/vnd.signed-evidence.eval-receipt+json"
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"
COMMIT_ALG = "sha256-salted-v1"


# ---- a deterministic random source from the seed -------------------------------------------------------------------
class Zufall:
    """SHA-256 in counter mode over a key; the same key gives the same stream on every platform and version."""

    def __init__(self, key: bytes):
        self._key, self._counter, self._buf = key, 0, b""

    def bytes(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def below(self, n: int) -> int:
        """Uniform in 0 .. n-1, by rejection."""
        if n <= 1:
            return 0
        size = (n - 1).bit_length()
        while True:
            v = int.from_bytes(self.bytes((size + 7) // 8), "big") & ((1 << size) - 1)
            if v < n:
                return v

    def choice(self, seq):
        return seq[self.below(len(seq))]

    def chance(self, num: int, den: int) -> bool:
        return self.below(den) < num

    def shuffle(self, items: list) -> None:
        for i in range(len(items) - 1, 0, -1):
            j = self.below(i + 1)
            items[i], items[j] = items[j], items[i]

    def child(self, label: str) -> "Zufall":
        return Zufall(hashlib.sha256(self._key + b"\x00child\x00" + label.encode("utf-8")).digest())


# ---- Ed25519, RFC 8032 Section 5.1, pure Python, only to make test material -----------------------------------------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
NEUTRAL = (0, 1, 1, 0)


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, pt):
    q = NEUTRAL
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _compress(pt) -> bytes:
    zi = pow(pt[2], P - 2, P)
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point(enc: bytes):
    v = int.from_bytes(enc, "little")
    y = v & ((1 << 255) - 1)
    x = _recover_x(y, v >> 255)
    if x is None:
        raise ValueError("not a canonical point encoding")
    return (x, y, 1, x * y % P)


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def _order8_point():
    """The first point of order exactly 8 reached from y = 2, 3, ... (as the vector generator finds it)."""
    y = 2
    while True:
        x = _recover_x(y, 0)
        if x is not None:
            t8 = _mul(L, (x, y, 1, x * y % P))
            if _compress(_mul(4, t8)) != _compress(NEUTRAL):
                return t8
        y += 1


T8 = _order8_point()
#: The eight points of small order with their orders: k*T8 for k = 0 .. 7.
SMALL = [(_mul(k, T8), (1, 8, 4, 8, 2, 8, 4, 8)[k]) for k in range(8)]


class Schluessel:
    """A test key from a 32-byte RFC 8032 seed."""

    def __init__(self, seed: bytes):
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        self.seed, self.a, self.prefix = seed, a, h[32:]
        self.public = _compress(_mul(a, BASE))

    def sign(self, msg: bytes) -> bytes:
        r = int.from_bytes(hashlib.sha512(self.prefix + msg).digest(), "little") % L
        R = _compress(_mul(r, BASE))
        k = int.from_bytes(hashlib.sha512(R + self.public + msg).digest(), "little") % L
        return R + ((r + k * self.a) % L).to_bytes(32, "little")


def _k(R: bytes, A: bytes, msg: bytes) -> int:
    return int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % L


def pae(typ: str, body: bytes) -> bytes:
    t = typ.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _noncanonical_encodings() -> list:
    """The 40 encodings rule 1 rejects that a decoder reducing y modulo p would try: y from p to p + 18 with either
    sign bit, and x = 0 with the sign bit set (the neutral element and the point of order 2)."""
    out = []
    for j in range(19):
        for sign in (0, 1):
            out.append((P + j | (sign << 255)).to_bytes(32, "little"))
    out.append((1 | (1 << 255)).to_bytes(32, "little"))
    out.append((P - 1 | (1 << 255)).to_bytes(32, "little"))
    return out


NONCANONICAL = _noncanonical_encodings()


# ---- RFC 8785 for the Payload of a valid receipt ---------------------------------------------------------------------
_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c < 0x20:
            out.append(_SHORT.get(c, "\\u%04x" % c))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs_value(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        assert float(v) == v and abs(v) < 10 ** 21   # a double holds it, and its ECMAScript form is its digits
        return str(v)
    if isinstance(v, str):
        return jcs_string(v)
    raise TypeError(type(v))


def jcs_payload(payload: dict) -> bytes:
    """The RFC 8785 bytes of a Payload whose member names are ASCII and whose numbers are integers a double holds."""
    names = sorted(payload, key=lambda n: n.encode("utf-16-be"))
    return ("{" + ",".join(jcs_string(n) + ":" + jcs_value(payload[n]) for n in names) + "}").encode("utf-8")


# ---- one set's material --------------------------------------------------------------------------------------------
WORDS = ["acme", "nordwind", "lumen", "safety", "bench", "harm", "truth", "qa", "reason", "code", "math", "vision",
         "suite", "eval", "kraxo", "delta", "omega", "sigma", "pilot", "core"]
METRICS = ["accuracy", "pass@1", "f1", "exact_match", "refusal_rate", "toxicity", "bleu", "win_rate", "auc", "mae"]
# Characters that RFC 8785 writes raw, escapes short or escapes as \\u00xx; no surrogate, no noncharacter.
SPECIAL_CHARS = ["é", "ü", "中", "\U0001F600", " ", "\u007f", "\n", "\t", "\u0001", "\u001f",
                 '"', "\\", "/", " ", "İ", "א"]


class Satz:
    """The material of one challenge set: its keys, salts, identifiers and criteria bytes."""

    def __init__(self, rng: Zufall):
        self.rng = rng
        self.issuer = Schluessel(rng.bytes(32))
        self.other = Schluessel(rng.bytes(32))
        torsion, self.mixed_order = rng.choice([s for s in SMALL if s[1] > 1])
        self.mixed_public = _compress(_add(_mul(self.issuer.a, BASE), torsion))
        self.mixed_torsion = torsion
        self.salt_model, self.salt_dataset = rng.bytes(16), rng.bytes(16)
        self.model_id = "%s/model-%s@%s" % (rng.choice(WORDS), rng.bytes(3).hex(), rng.choice(["v1", "2026-10", "rc2"]))
        self.dataset_id = "%s/data-%s@%s" % (rng.choice(WORDS), rng.bytes(3).hex(), rng.choice(["v3", "2026-09", "x"]))
        self.criteria = ('{"metric":"%s","threshold":"0.%03d","nonce":"%s"}\n'
                         % (rng.choice(METRICS), rng.below(1000), rng.bytes(8).hex())).encode()

    @staticmethod
    def commit(identifier: str, salt: bytes) -> str:
        return "sha256:" + hashlib.sha256(salt + identifier.encode("utf-8")).hexdigest()


def _decimal(rng: Zufall) -> str:
    form = rng.below(9)
    if form == 0:
        return "0." + "%03d" % rng.below(1000)
    if form == 1:
        return str(rng.below(100))
    if form == 2:
        return "-" + str(1 + rng.below(50)) + "." + str(rng.below(10))
    if form == 3:
        return "0." + "".join(str(rng.below(10)) for _ in range(1 + rng.below(30)))
    if form == 4:
        return rng.choice(["0", "-0", "0.0", "-0.000", "1.000", "100"])
    if form == 5:
        return str(rng.below(10 ** 25)) + "." + str(rng.below(10 ** 5))
    if form == 6:
        return "0.30000000000000001" if rng.chance(1, 2) else "0.3"
    if form == 7:
        return "-" + str(rng.below(10 ** 6))
    return "%d.%d" % (rng.below(10), rng.below(10 ** 8))


def _holds(score: str, comparator: str, threshold: str) -> bool:
    a, b = decimal.Decimal(score), decimal.Decimal(threshold)
    return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[comparator]


def _timestamp(rng: Zufall) -> str:
    form = rng.below(6)
    if form == 0:
        return "0000-02-29T%02d:%02d:%02dZ" % (rng.below(24), rng.below(60), rng.below(60))
    if form == 1:
        year = rng.choice([2000, 2024, 2028, 1600, 2400])
        return "%04d-02-29T23:59:59Z" % year
    year, month = rng.below(10000), 1 + rng.below(12)
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    day = days if form == 2 else 1 + rng.below(days)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (year, month, day, rng.below(24), rng.below(60), rng.below(60))


def _text(rng: Zufall, base: str) -> str:
    """A non-empty string, sometimes with characters RFC 8785 writes raw or escapes."""
    if rng.chance(1, 4):
        cut = rng.below(len(base) + 1)
        return base[:cut] + rng.choice(SPECIAL_CHARS) + base[cut:]
    return base


def payload(satz: Satz, rng: Zufall, criteria: bool | None = None) -> dict:
    """A valid Payload with values of its own."""
    comparator = rng.choice([">=", ">", "<=", "<"])
    threshold, score = _decimal(rng), _decimal(rng)
    if rng.chance(1, 6):
        score = threshold   # equality, where > and < decide
    n = rng.choice([1, 2 ** 53 - 1, 1 + rng.below(5000), 1 + rng.below(2 ** 53 - 1), 1800])
    p = {
        "schema": PAYLOAD_SCHEMA,
        "suite": _text(rng, "%s-%s-suite" % (rng.choice(WORDS), rng.choice(WORDS))),
        "suite_version": _text(rng, "%d.%d.%d" % (rng.below(5), rng.below(20), rng.below(50))),
        "metric": _text(rng, rng.choice(METRICS)),
        "comparator": comparator,
        "threshold": threshold,
        "score": score,
        "passed": _holds(score, comparator, threshold),
        "n": n,
        "model_id_commit": satz.commit(satz.model_id, satz.salt_model),
        "dataset_id_commit": satz.commit(satz.dataset_id, satz.salt_dataset),
        "commit_alg": COMMIT_ALG,
        "timestamp": _timestamp(rng),
    }
    if criteria if criteria is not None else rng.chance(1, 2):
        p["criteria_digest"] = "sha256:" + hashlib.sha256(satz.criteria).hexdigest()
    return p


# ---- the receipt object, written with free member order, whitespace and escapes --------------------------------------
_WS = ["", "", "", " ", "\n", "\t", "\r\n", "  "]


def _escape_some(s: str, rng: Zufall) -> str:
    """The JSON text of an ASCII string, with some characters written as an escape: \\/ or \\uXXXX in either case."""
    out = ['"']
    for ch in s:
        if ch == '"' or ch == "\\":
            out.append("\\" + ch)
        elif rng.chance(1, 12):
            out.append(("\\u%04x" if rng.chance(1, 2) else "\\u%04X") % ord(ch))
        elif ch == "/" and rng.chance(1, 3):
            out.append("\\/")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _plain(s: str) -> str:
    return json.dumps(s)


def write_object(members: list, rng: Zufall | None) -> str:
    """members: [(name, value text)]; with rng, a random member order, whitespace and escapes in the names."""
    if rng is not None:
        members = list(members)
        rng.shuffle(members)

    def ws() -> str:
        return rng.choice(_WS) if rng is not None else ""

    parts = []
    for name, value in members:
        key = _escape_some(name, rng) if rng is not None and rng.chance(1, 6) else _plain(name)
        parts.append(ws() + key + ws() + ":" + ws() + value + ws())
    return "{" + ",".join(parts) + "}"


def receipt(B: bytes, sig: bytes, hint: bytes | None, rng: Zufall | None = None, *, schema_text: str | None = None,
            payload_text: str | None = None, alg_text: str | None = None, sig_text: str | None = None,
            hint_text: str | None = None, extra_signature: list | None = None, extra_receipt: list | None = None,
            outer: tuple = ("", "")) -> bytes:
    """The receipt bytes; each *_text replaces the JSON text of that member's value."""
    def text(value: str) -> str:
        return _escape_some(value, rng) if rng is not None and rng.chance(1, 5) else _plain(value)

    sig_members = [("alg", alg_text if alg_text is not None else text("ed25519")),
                   ("sig", sig_text if sig_text is not None else text(b64(sig)))]
    if hint is not None or hint_text is not None:
        sig_members.append(("key", hint_text if hint_text is not None else text(b64(hint))))
    sig_members += extra_signature or []
    members = [("schema", schema_text if schema_text is not None else text(MEDIA_TYPE)),
               ("payload_b64", payload_text if payload_text is not None else text(b64(B))),
               ("signature", write_object(sig_members, rng))]
    members += extra_receipt or []
    return (outer[0] + write_object(members, rng) + outer[1]).encode("utf-8")


# ---- the kinds of entries ---------------------------------------------------------------------------------------------
class Werkstatt:
    """Builds entries for one set: each method returns (receipt bytes, verification key, intended label), where the
    label is that of the verifiers ("all" for PASS, "6", "11 (profile 2, key)") or None for a byte fault."""

    def __init__(self, satz: Satz, rng: Zufall):
        self.s, self.rng = satz, rng

    # helpers
    def B(self, p: dict | None = None) -> bytes:
        return jcs_payload(p if p is not None else payload(self.s, self.rng))

    def signed(self, B: bytes, *, hint="issuer", **kw) -> bytes:
        sig = self.s.issuer.sign(pae(MEDIA_TYPE, B))
        return receipt(B, sig, self._hint(hint), self.rng, **kw)

    def _hint(self, hint):
        if hint == "issuer":
            return self.s.issuer.public if self.rng.chance(3, 4) else None
        return hint

    def raw_B(self, text: bytes) -> bytes:
        """A receipt whose B is the given bytes, signed with the issuer key."""
        return self.signed(text)

    def with_member(self, name, value_text) -> bytes:
        """B: a valid Payload's RFC 8785 bytes with the JSON text of one member replaced (name kept)."""
        p = payload(self.s, self.rng)
        p[name] = "\x00placeholder\x00"
        raw = jcs_payload(p).decode("utf-8")
        return raw.replace(jcs_string("\x00placeholder\x00"), value_text, 1).encode("utf-8")

    def resigned(self, B: bytes) -> bytes:
        return self.signed(B)

    # valid
    def gueltig(self):
        rng = self.rng
        outer = (rng.choice(["", "", "", " ", "\n", "\t", "\r\n"]), rng.choice(["", "", "", "\n", " ", "\r\n\t"]))
        return self.signed(self.B(), outer=outer), self.s.issuer.public, "all"

    # step 1
    def s1_bom(self):
        return b"\xef\xbb\xbf" + self.signed(self.B()), self.s.issuer.public, "1"

    def s1_utf8(self):
        bad = self.rng.choice([b"\xff", b"\xc0\x80", b"\x80", b"\xe2\x82", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"])
        return self._alg_bytes(bad), self.s.issuer.public, "1"

    def _alg_bytes(self, inserted: bytes) -> bytes:
        rb = self.signed(self.B(), alg_text='"ed25519@"')
        return rb.replace(b'ed25519@', b'ed25519' + inserted, 1)

    def s1_surrogate(self):
        esc = self.rng.choice(["\\ud800", "\\udfff", "\\uDBFF"])
        return self.signed(self.B(), alg_text='"ed25519%s"' % esc), self.s.issuer.public, "1"

    def s1_noncharacter(self):
        if self.rng.chance(1, 2):
            esc = self.rng.choice(["\\uffff", "\\ufffe", "\\ufdd0", "\\uFDEF", "\\ud83f\\udffe"])
            return self.signed(self.B(), alg_text='"ed25519%s"' % esc), self.s.issuer.public, "1"
        raw = self.rng.choice(["￿".encode(), "﷕".encode(), "\U0002FFFF".encode()])
        return self._alg_bytes(raw), self.s.issuer.public, "1"

    def s1_duplicate(self):
        rng = self.rng
        B = self.B()
        sig = self.s.issuer.sign(pae(MEDIA_TYPE, B))
        form = rng.below(3)
        if form == 0:
            extra = [("schema", _plain(MEDIA_TYPE))]
            return receipt(B, sig, self.s.issuer.public, rng, extra_receipt=extra), self.s.issuer.public, "1"
        if form == 1:
            extra = [("sig", _plain(b64(bytes(64))))]
            return receipt(B, sig, None, rng, extra_signature=extra), self.s.issuer.public, "1"
        rb = receipt(B, sig, self.s.issuer.public, None)
        return rb.replace(b'{"schema":', b'{"sch\\u0065ma":"x","schema":', 1), self.s.issuer.public, "1"

    def s1_trailing(self):
        tail = self.rng.choice([b" x", b"{}", b'\n{"a":1}', b"\x00", b"]", b" 0", b"\n\x0b"])
        return self.signed(self.B()) + tail, self.s.issuer.public, "1"

    def s1_members(self):
        rng, B = self.rng, self.B()
        sig = self.s.issuer.sign(pae(MEDIA_TYPE, B))
        form = rng.below(6)
        pub = self.s.issuer.public
        if form == 0:
            return receipt(B, sig, pub, rng, extra_receipt=[("comment", '"x"')]), pub, "1"
        if form == 1:
            return receipt(B, sig, pub, rng, extra_signature=[("kid", '"x"')]), pub, "1"
        if form == 2:
            rb = receipt(B, sig, pub, None)
            return rb.replace(b'"schema":"%s",' % MEDIA_TYPE.encode(), b"", 1), pub, "1"
        if form == 3:
            return receipt(B, sig, pub, None).replace(b'"signature":{', b'"signature":[{', 1)[:-1] + b"]}", pub, "1"
        if form == 4:
            return ("[" + receipt(B, sig, pub, None).decode() + "]").encode(), pub, "1"
        rb = receipt(B, sig, None, None)
        return rb.replace(b'"alg":"ed25519",', b"", 1), pub, "1"

    def s1_syntax(self):
        rb = self.signed(self.B())
        form = self.rng.below(5)
        if form == 0:
            return rb[:-1 - self.rng.below(min(20, len(rb) - 2))], self.s.issuer.public, "1"
        if form == 1:
            return rb[:-1] + b",}", self.s.issuer.public, "1"
        if form == 2:
            # a member name in single quotes, in a receipt written without escapes so that the name "alg" is there
            B = self.B()
            plain = receipt(B, self.s.issuer.sign(pae(MEDIA_TYPE, B)), self.s.issuer.public, None)
            return plain.replace(b'"alg"', b"'alg'", 1), self.s.issuer.public, "1"
        if form == 3:
            return self._alg_bytes(b"\n"), self.s.issuer.public, "1"
        return rb[:-1] + b',"n":NaN}', self.s.issuer.public, "1"

    # step 2
    def s2_schema(self):
        value = self.rng.choice([
            '"application/vnd.signed-evidence.eval-receipt+cbor"', '"Application/vnd.signed-evidence.eval-receipt+json"',
            '"application/vnd.signed-evidence.eval-receipt+json "', '"%s"' % PAYLOAD_SCHEMA, '""', "null", "1",
            "1e400", "[]", '{"a":"b"}', "true", '"application\\/vnd.signed-evidence.eval-receipt+JSON"'])
        return self.signed(self.B(), schema_text=value), self.s.issuer.public, "2"

    # step 3
    def s3_payload_b64(self):
        B = self.B()
        good = b64(B)
        form = self.rng.below(7)
        if form == 0:
            pos = self.rng.below(len(good.rstrip("=")))
            bad = good[:pos] + self.rng.choice(["!", "-", "_", " ", "*"]) + good[pos + 1:]
        elif form == 1:
            bad = good.rstrip("=") if good.endswith("=") else good + "=="
        elif form == 2:
            bad = good + "===="
        elif form == 3:
            bad = _noncanonical_b64(B, good)
            if bad is None:
                bad = good + "A"
        elif form == 4:
            return self.signed(B, payload_text=self.rng.choice(["null", "1", "[]", "true"])), self.s.issuer.public, "3"
        elif form == 5:
            bad = good[:4] + "\n" + good[4:]
        else:
            bad = good + "A"
        return self.signed(B, payload_text=json.dumps(bad)), self.s.issuer.public, "3"

    # step 4
    def s4_payload_json(self):
        base = self.B()
        form = self.rng.below(10)
        if form == 0:
            raw = b"\xef\xbb\xbf" + base
        elif form == 1:
            raw = base.replace(b'"schema":"', b'"schema":"\xff', 1)
        elif form == 2:
            raw = base.replace(b'"schema":"', b'"schema":"\\udc00', 1)
        elif form == 3:
            raw = base.replace(b'"schema":"', b'"schema":"\xef\xbf\xbe', 1)
        elif form == 4:
            raw = base[:-1] + b',"passed":true}'
        elif form == 5:
            raw = base[:-1] + b',"p\\u0061ssed":false}'
        elif form == 6:
            raw = base + self.rng.choice([b"x", b"{}", b"\x00", b" 1"])
        elif form == 7:
            raw = self.rng.choice([b"[]", b'"a"', b"1800", b"null", b"[" + base + b"]"])
        elif form == 8:
            raw = self.rng.choice([b"", b"{", base[:-1], b'{"n":NaN}', b"{'a':1}", base.replace(b'"n":', b'"n":0', 1)])
        else:
            raw = base.replace(b'"schema":"', b'"schema":"\\ufdd0', 1)
        return self.signed(raw), self.s.issuer.public, "4"

    # step 5: B is not its own RFC 8785 serialization
    def s5_jcs(self):
        p = payload(self.s, self.rng)
        base = jcs_payload(p)
        n = jcs_value(p["n"]).encode()
        form = self.rng.below(12)
        if form == 0:
            raw = json.dumps(p, indent=self.rng.choice([None, 1]), ensure_ascii=False,
                             separators=(", ", ": ")).encode()
        elif form == 1:
            raw = json.dumps(dict(reversed(list(sorted(p.items())))), separators=(",", ":"), ensure_ascii=False).encode()
        elif form == 2:
            raw = base.replace(b'"n":' + n, b'"n":' + n + self.rng.choice([b".0", b".00", b"e0", b"E0", b"e+0"]), 1)
        elif form == 3:
            raw = base.replace(b'"n":' + n, b'"n":' + self.rng.choice([b"1e400", b"-1e400", b"1E999"]), 1)
        elif form == 4:
            raw = base.replace(b'"n":' + n, b'"n":' + self.rng.choice(
                [b"9007199254740993", b"-0", b"1e21", b"1.8e3", b"18E2", b"0.1e1", b"123456789012345678901",
                 b"1E+21", b"1e-07", b"0.0000001", b"1800.000000000000000001"]), 1)
        elif form == 5:
            raw = base.replace(b'"schema":"https:', b'"schema":"https:\\/', 1).replace(b"https:\\//", b"https:\\/", 1)
        elif form == 6:
            raw = base.replace(b'"comparator":"', b'"comparator":"\\u00%02x' % ord(p["comparator"][0]), 1)
            raw = raw.replace(b"\\u00%02x" % ord(p["comparator"][0]) + p["comparator"][0].encode(),
                              b"\\u00%02x" % ord(p["comparator"][0]), 1)
        elif form == 7:
            raw = base + self.rng.choice([b"\n", b" ", b"\r\n", b"\t"])
        elif form == 8:
            raw = self.rng.choice([b" ", b"\n"]) + base
        else:
            # the suite ends in a character RFC 8785 writes raw, escapes short or escapes in lower case; B writes it
            # otherwise
            end, own, other = [("é", "é", "\\u00e9"), ("\n", "\\n", self.rng.choice(["\\u000a", "\\u000A"])),
                               ("\u001f", "\\u001f", "\\u001F")][form - 9]
            p["suite"] = p["suite"] + end
            token = '"suite":' + jcs_string(p["suite"])
            assert token.endswith(own + '"')
            raw = jcs_payload(p).replace(token.encode(), (token[:-len(own) - 1] + other + '"').encode(), 1)
        return self.signed(raw), self.s.issuer.public, "5"

    def s5_numbers_that_pass(self):
        """A number written as its own RFC 8785 form, in a member that wants something else: step 5 admits it, step
        6 rejects it."""
        member, token = self.rng.choice([
            ("n", "1e+21"), ("n", "1e-7"), ("n", "0.000001"), ("n", "100000000000000000000"), ("n", "4.5"),
            ("n", "-1"), ("n", "5e-324"), ("n", "1.7976931348623157e+308"), ("n", "9007199254740992"),
            ("n", "123456789012345680000"), ("n", "0"), ("score", "0.834"), ("threshold", "1e+21"),
            ("score", "-0.5"), ("n", "2e-7"), ("n", "1.5")])
        return self.signed(self.with_member(member, token)), self.s.issuer.public, "6"

    # step 6
    def s6_member(self):
        rng = self.rng
        p = payload(self.s, rng)
        form = rng.below(5)
        if form == 0:
            p.pop(rng.choice(sorted(set(p) - {"criteria_digest"})))
        elif form == 1:
            p[rng.choice(["extra", "issuer", "Schema", "criteria"])] = "x"
        elif form == 2:
            p["schema"] = rng.choice(["https://signed-evidence.org/eval-receipt/v2", PAYLOAD_SCHEMA + "/",
                                      "http://signed-evidence.org/eval-receipt/v1", MEDIA_TYPE])
        elif form == 3:
            p["commit_alg"] = rng.choice(["sha256-salted-v2", "sha256", "SHA256-SALTED-V1", ""])
        else:
            p[rng.choice(["suite", "suite_version", "metric"])] = ""
        return self.signed(self.B(p)), self.s.issuer.public, "6"

    def s6_types(self):
        name, text = self.rng.choice([
            ("n", '"1800"'), ("n", "true"), ("n", "null"), ("passed", '"true"'), ("passed", "null"), ("passed", "1"),
            ("score", "null"), ("threshold", "[]"), ("suite", "1"), ("metric", '{"a":"b"}'), ("comparator", "null"),
            ("model_id_commit", "1"), ("dataset_id_commit", "null"), ("timestamp", "1700000000"),
            ("criteria_digest", "null"), ("criteria_digest", "1"), ("criteria_digest", "[]")])
        return self.signed(self.with_member(name, text)), self.s.issuer.public, "6"

    def s6_values(self):
        rng = self.rng
        p = payload(self.s, rng)
        form = rng.below(5)
        if form == 0:
            p["comparator"] = rng.choice(["=>", "==", "≥", " >=", ">= ", "=", "!=", "lt"])
        elif form == 1:
            p[rng.choice(["score", "threshold"])] = rng.choice(
                ["01", "+1", "1.", ".5", "1e3", "1E3", "0x1", "١٢", "1,5", "", "-", "--1", " 1", "1 ",
                 "0.8٣", "１", "-.5", "00.5", "1.2.3", "NaN", "Infinity"])
        elif form == 2:
            p["n"] = rng.choice([0, 2 ** 53, -1, -(2 ** 52)])
        elif form == 3:
            p["timestamp"] = rng.choice([
                "2026-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-13-01T00:00:00Z",
                "2026-00-10T00:00:00Z", "2026-01-00T00:00:00Z", "2026-01-32T00:00:00Z", "2026-01-01T24:00:00Z",
                "2026-01-01T23:60:00Z", "2026-01-01T23:59:60Z", "2026-01-01t00:00:00Z", "2026-01-01T00:00:00z",
                "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00.5Z", "2026-01-01 00:00:00Z", "26-01-01T00:00:00Z",
                "2026-1-01T00:00:00Z", "+2026-01-01T00:00:00Z", "2026-01-01T00:00:00", "٢026-01-01T00:00:00Z",
                "0000-02-30T00:00:00Z", "2100-02-29T00:00:00Z"])
        else:
            p["n"] = 2 ** 53 + rng.below(2 ** 40) * 2   # even, so a double holds it, but not below 2^53
        return self.signed(self.B(p)), self.s.issuer.public, "6"

    # step 7
    def s7_pattern(self):
        rng = self.rng
        p = payload(self.s, rng, criteria=rng.chance(1, 2))
        members = ["model_id_commit", "dataset_id_commit"] + (["criteria_digest"] if "criteria_digest" in p else [])
        name = rng.choice(members)
        digits = p[name][7:]
        p[name] = rng.choice([
            "sha256:" + digits.upper(), "sha256:" + digits[:63], "sha256:" + digits + "0", digits,
            "sha512:" + digits, "SHA256:" + digits, "sha256: " + digits[1:], "sha256:" + digits[:-1] + "g",
            "sha256:" + digits + "\n", "", self.s.model_id])
        return self.signed(self.B(p)), self.s.issuer.public, "7"

    # step 8
    def s8_passed(self):
        rng = self.rng
        p = payload(self.s, rng)
        form = rng.below(4)
        if form == 1:
            p.update(comparator=">", threshold="0.3", score="0.30000000000000001")
            p["passed"] = _holds(p["score"], p["comparator"], p["threshold"])
        elif form == 2:
            p.update(comparator=rng.choice([">", "<"]), threshold="0.8", score=rng.choice(["0.80", "0.800", "0.8"]))
            p["passed"] = _holds(p["score"], p["comparator"], p["threshold"])
        elif form == 3:
            p.update(comparator=rng.choice([">=", "<="]), threshold="-0", score="0")
            p["passed"] = _holds(p["score"], p["comparator"], p["threshold"])
        p["passed"] = not p["passed"]
        return self.signed(self.B(p)), self.s.issuer.public, "8"

    # step 9
    def s9_signature(self):
        rng = self.rng
        B = self.B()
        sig = self.s.issuer.sign(pae(MEDIA_TYPE, B))
        form = rng.below(6)
        if form == 0:
            return self.signed(B, alg_text=json.dumps(rng.choice(["Ed25519", "ed448", "EdDSA", "", " ed25519",
                                                                  "ed25519 ", "ED25519"]))), self.s.issuer.public, "9"
        if form == 1:
            return self.signed(B, alg_text=rng.choice(["null", "1", "[]", "true"])), self.s.issuer.public, "9"
        if form == 2:
            bad = _noncanonical_b64(sig, b64(sig))
            return receipt(B, sig, None, rng, sig_text=json.dumps(bad)), self.s.issuer.public, "9"
        if form == 3:
            other = rng.choice([sig[:63], sig + b"\x00", sig[:32], b""])
            return receipt(B, sig, None, rng, sig_text=json.dumps(b64(other))), self.s.issuer.public, "9"
        if form == 4:
            good = b64(sig)
            pos = rng.below(len(good) - 2)
            return receipt(B, sig, None, rng, sig_text=json.dumps(good[:pos] + rng.choice(["!", "-", "_"]) +
                                                                  good[pos + 1:])), self.s.issuer.public, "9"
        return receipt(B, sig, None, rng, sig_text=rng.choice(["null", "1", "[]"])), self.s.issuer.public, "9"

    # step 10
    def s10_hint(self):
        rng = self.rng
        B = self.B()
        sig = self.s.issuer.sign(pae(MEDIA_TYPE, B))
        form = rng.below(5)
        pub = self.s.issuer.public
        if form == 0:
            return receipt(B, sig, rng.choice([self.s.other.public, self.s.mixed_public]), rng), pub, "10"
        if form == 1:
            return receipt(B, sig, None, rng, hint_text=json.dumps(_noncanonical_b64(pub, b64(pub)))), pub, "10"
        if form == 2:
            return receipt(B, sig, None, rng, hint_text=json.dumps(b64(rng.choice([pub[:31], pub + b"\x00"])))), pub, "10"
        if form == 3:
            return receipt(B, sig, None, rng, hint_text=rng.choice(["null", "1", "[]", '""'])), pub, "10"
        return receipt(B, sig, None, rng, hint_text=json.dumps(b64(pub)[:-1])), pub, "10"

    # step 11, the profile
    def _hint_for(self, key: bytes):
        return key if self.rng.chance(1, 2) else None

    def p1_key(self):
        key = self.rng.choice(NONCANONICAL + [self._off_curve()])
        B = self.B()
        rr = 1 + self.rng.below(L - 1)
        sig = _compress(_mul(rr, BASE)) + rr.to_bytes(32, "little")
        return receipt(B, sig, self._hint_for(key), self.rng), key, "11 (profile 1, key)"

    def _off_curve(self) -> bytes:
        while True:
            y = self.rng.below(P)
            if _recover_x(y, 0) is None:
                return (y | (self.rng.below(2) << 255)).to_bytes(32, "little")

    def p1_R(self):
        B = self.B()
        msg = pae(MEDIA_TYPE, B)
        R = self.rng.choice(NONCANONICAL + [self._off_curve()])
        S = (_k(R, self.s.issuer.public, msg) * self.s.issuer.a) % L
        return receipt(B, R + S.to_bytes(32, "little"), self._hint("issuer"), self.rng), self.s.issuer.public, \
            "11 (profile 1, R)"

    def p2_key_small(self):
        point, _order = self.rng.choice(SMALL)
        key = _compress(point)
        B = self.B()
        rr = 1 + self.rng.below(L - 1)
        sig = _compress(_mul(rr, BASE)) + rr.to_bytes(32, "little")
        return receipt(B, sig, self._hint_for(key), self.rng), key, "11 (profile 2, key)"

    def p2_key_mixed(self):
        """The set's mixed-order key with a signature that meets the cofactorless equation (k a multiple of the
        torsion order), or any signature."""
        B = self.B()
        msg = pae(MEDIA_TYPE, B)
        key = self.s.mixed_public
        while True:
            r = 1 + self.rng.below(L - 1)
            R = _compress(_mul(r, BASE))
            k = _k(R, key, msg)
            if k % self.s.mixed_order == 0 or self.rng.chance(1, 4):
                break
        sig = R + ((r + k * self.s.issuer.a) % L).to_bytes(32, "little")
        return receipt(B, sig, self._hint_for(key), self.rng), key, "11 (profile 2, key)"

    def p2_R(self):
        B = self.B()
        msg = pae(MEDIA_TYPE, B)
        pub, a = self.s.issuer.public, self.s.issuer.a
        point, _order = self.rng.choice(SMALL)
        if self.rng.chance(1, 2):
            R = _compress(point)
            S = _k(R, pub, msg) * a % L
        else:
            r = 1 + self.rng.below(L - 1)
            R = _compress(_add(_mul(r, BASE), point if _order > 1 else SMALL[1][0]))
            S = (r + _k(R, pub, msg) * a) % L
        return receipt(B, R + S.to_bytes(32, "little"), self._hint("issuer"), self.rng), pub, "11 (profile 2, R)"

    def p3_S(self):
        B = self.B()
        sig = self.s.issuer.sign(pae(MEDIA_TYPE, B))
        S = int.from_bytes(sig[32:], "little")
        S2 = self.rng.choice([S + L, L, 2 ** 256 - 1, S + 2 * L if S + 2 * L < 2 ** 256 else S + L, 2 ** 255 + S])
        return receipt(B, sig[:32] + S2.to_bytes(32, "little"), self._hint("issuer"), self.rng), \
            self.s.issuer.public, "11 (profile 3)"

    def p4_equation(self):
        rng = self.rng
        B = self.B()
        form = rng.below(5)
        pub = self.s.issuer.public
        if form == 0:
            sig = self.s.issuer.sign(pae(rng.choice(["application/vnd.example.other+json", MEDIA_TYPE + " ",
                                                     "application/vnd.signed-evidence.eval-receipt+cbor"]), B))
        elif form == 1:
            sig = self.s.other.sign(pae(MEDIA_TYPE, B))
            return receipt(B, sig, None, rng), pub, "11 (profile 4)"
        elif form == 2:
            sig = self.s.issuer.sign(pae(MEDIA_TYPE, self.B()))
        elif form == 3:
            sig = self.s.issuer.sign(B)
        else:
            r = 1 + rng.below(L - 1)
            sig = _compress(_mul(r, BASE)) + rng.below(L).to_bytes(32, "little")
        return receipt(B, sig, self._hint("issuer"), rng), pub, "11 (profile 4)"

    # two faults in one entry: the earlier step decides (Section 5), within step 11 the earlier rule, and within rules
    # 1 and 2 the key before R (Section 4)
    def mehrfach(self, form: int | None = None):
        """An entry with two faults. self.zweiter is the label of the later fault: the answer of an implementation
        that checks in another order. form fixes the form for tests; the random stream is the same either way."""
        rb, key, first, self.zweiter = self._mehrfach(form)
        return rb, key, first

    def _mehrfach(self, form):
        rng, s = self.rng, self.s
        pub = s.issuer.public
        B = self.B()
        msg = pae(MEDIA_TYPE, B)
        small_key, small_R = _compress(rng.choice(SMALL)[0]), _compress(rng.choice(SMALL)[0])
        bad_key, bad_R = rng.choice(NONCANONICAL), rng.choice(NONCANONICAL)
        good_R = _compress(_mul(1 + rng.below(L - 1), BASE))
        low_S, big_S = rng.below(L).to_bytes(32, "little"), (L + rng.below(2 ** 256 - L)).to_bytes(32, "little")
        drawn = rng.below(14)
        form = drawn if form is None else form
        if form == 0:   # rule 2 for the key, rule 1 for R
            return (receipt(B, bad_R + low_S, self._hint_for(small_key), rng), small_key,
                    "11 (profile 1, R)", "11 (profile 2, key)")
        if form == 1:   # rule 1 for the key and for R
            return (receipt(B, bad_R + low_S, self._hint_for(bad_key), rng), bad_key,
                    "11 (profile 1, key)", "11 (profile 1, R)")
        if form == 2:   # rule 2 for the key and for R
            return (receipt(B, small_R + low_S, self._hint_for(small_key), rng), small_key,
                    "11 (profile 2, key)", "11 (profile 2, R)")
        if form == 3:   # rule 2 for R, rule 3
            return (receipt(B, small_R + big_S, self._hint("issuer"), rng), pub,
                    "11 (profile 2, R)", "11 (profile 3)")
        if form == 4:   # rule 3, rule 4
            return (receipt(B, good_R + big_S, self._hint("issuer"), rng), pub,
                    "11 (profile 3)", "11 (profile 4)")
        if form == 5:   # the mixed-order key (rule 2), rule 3
            key = s.mixed_public
            return (receipt(B, good_R + big_S, self._hint_for(key), rng), key,
                    "11 (profile 2, key)", "11 (profile 3)")
        if form == 6:   # step 2, step 9
            return (self.signed(B, schema_text=json.dumps(rng.choice(["application/json", MEDIA_TYPE.upper()])),
                                alg_text=json.dumps(rng.choice(["Ed25519", "EdDSA"]))), pub, "2", "9")
        if form == 7:   # step 3, step 10
            return (receipt(B, s.issuer.sign(msg), s.other.public, rng, payload_text=json.dumps(b64(B) + "A")),
                    pub, "3", "10")
        if form == 8:   # step 7, step 8
            p = payload(s, rng)
            p["model_id_commit"] = p["model_id_commit"].upper()
            p["passed"] = not p["passed"]
            return self.signed(self.B(p)), pub, "7", "8"
        if form == 9:   # step 8, step 11 (rule 4: signed with the other key)
            p = payload(s, rng)
            p["passed"] = not p["passed"]
            Bp = self.B(p)
            return receipt(Bp, s.other.sign(pae(MEDIA_TYPE, Bp)), None, rng), pub, "8", "11 (profile 4)"
        if form == 10:  # step 10, step 11: the other key's hint and signature, verified with the issuer key
            return receipt(B, s.other.sign(msg), s.other.public, rng), pub, "10", "11 (profile 4)"
        if form == 11:  # step 5, step 6: a member too many, and B not in its RFC 8785 form
            p = payload(s, rng)
            p["extra"] = "x"
            return self.signed(json.dumps(p, separators=(", ", ": "), ensure_ascii=False).encode()), pub, "5", "6"
        if form == 12:  # step 9, step 10
            sig = s.issuer.sign(msg)
            return receipt(B, sig, s.other.public, rng, sig_text=json.dumps(b64(sig[:63]))), pub, "9", "10"
        # step 1, step 2
        return self.signed(B, schema_text='"x"') + b" x", pub, "1", "2"

    # a single byte fault in a valid receipt; the verifiers alone say what it is
    def bytefehler(self):
        rb, key, _label = self.gueltig()
        rb = bytearray(rb)
        pos = self.rng.below(len(rb))
        if self.rng.chance(1, 2):
            rb[pos] ^= 1 << self.rng.below(8)
        else:
            new = self.rng.below(255)
            rb[pos] = new if new < rb[pos] else new + 1
        return bytes(rb), key, None


def _noncanonical_b64(raw: bytes, good: str):
    """The canonical base64 of raw with a padding bit set, which decodes to the same bytes; None without padding."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    stem = good.rstrip("=")
    if stem == good:
        return None
    last = len(stem) - 1
    value = alphabet.index(good[last])
    bumped = good[:last] + alphabet[value | 1] + good[last + 1:]   # a padding bit, always zero in the canonical form
    assert base64.b64decode(bumped) == raw and bumped != good
    return bumped


#: (kind, share of the invalid entries); each kind is one method of Werkstatt.
UNGUELTIG = ["s1_bom", "s1_utf8", "s1_surrogate", "s1_noncharacter", "s1_duplicate", "s1_trailing", "s1_members",
             "s1_syntax", "s2_schema", "s3_payload_b64", "s4_payload_json", "s5_jcs", "s5_jcs", "s5_jcs",
             "s5_numbers_that_pass", "s5_numbers_that_pass", "s6_member", "s6_types", "s6_values", "s7_pattern",
             "s8_passed", "s9_signature", "s10_hint", "p1_key", "p1_R", "p2_key_small", "p2_key_mixed", "p2_R",
             "p3_S", "p4_equation", "mehrfach", "mehrfach", "mehrfach"]
#: One kind per step and per profile rule, placed first so that every set of at least this many invalid entries holds
#: each.
PFLICHT = ["s1_members", "s2_schema", "s3_payload_b64", "s4_payload_json", "s5_jcs", "s6_types", "s7_pattern",
           "s8_passed", "s9_signature", "s10_hint", "p1_key", "p1_R", "p2_key_small", "p2_R", "p3_S", "p4_equation",
           "mehrfach", "mehrfach"]


# ---- the verifiers' answers ---------------------------------------------------------------------------------------
#: What a verifier answers when it raises instead of giving a verdict. The author checker is kept byte for byte, and on
#: Python's default limits it can raise RecursionError on deep nesting or ValueError when a long decimal string
#: meets the integer-conversion limit (Codex on pull request 425). Such an entry gets this label, so the two verifiers
#: disagree on it and it is left out as a finding; the generator does not stop.
KEIN_URTEIL = "NO_VERDICT"


def _label_autor(rb: bytes, key: bytes) -> tuple:
    try:
        verdict, step = autor_pruefer.verify(rb, key)
    except autor_pruefer.ResourceLimit:
        return "RESOURCE_LIMIT", "RESOURCE_LIMIT"
    except (RecursionError, ValueError) as exc:
        return KEIN_URTEIL, type(exc).__name__
    return verdict, "all" if verdict == "PASS" else step


def _label_text(rb: bytes, key: bytes) -> tuple:
    try:
        result = text_pruefer.verify(rb, key)
    except (RecursionError, ValueError) as exc:
        return KEIN_URTEIL, type(exc).__name__
    return result["result"], text_pruefer.step_label(result)


PRUEFER = {"autor": _label_autor, "text": _label_text}


#: The answer contract of prompt item 7 (Nachtrag 2): the six details of step 11 and the two details of ERROR.
SECHS = ("profile 1, key", "profile 1, R", "profile 2, key", "profile 2, R", "profile 3", "profile 4")
ERROR_DETAILS = ("resource-limit", "execution-error")
FELDER = ("id", "verdict", "step", "detail")

#: Nachtrag 2, point 3: each label of our verifiers ("all", "6", "11 (profile 2, key)") and the answer
#: (verdict, step, detail) it stands for, as an explicit table; a label that is not in it is no answer.
ABBILDUNG = {"all": ("PASS", None, None)}
ABBILDUNG.update({str(k): ("FAIL", k, None) for k in range(1, 11)})
ABBILDUNG.update({"11 (%s)" % d: ("FAIL", 11, d) for d in SECHS})
#: What a verifier that stops at its own resource limit answers, whatever step it stopped in.
GRENZE = ("ERROR", None, "resource-limit")


def antwort(entry_id: str, verdict: str, label: str) -> dict:
    """The answer of the contract for a verifier's verdict and label, through ABBILDUNG."""
    if verdict == "RESOURCE_LIMIT":
        form = GRENZE
    else:
        form = ABBILDUNG.get(label)
        if form is None or form[0] != verdict:
            raise ValueError("the label %r with the verdict %r is not in the mapping table" % (label, verdict))
    return {"id": entry_id, "verdict": form[0], "step": form[1], "detail": form[2]}


def _jsonl(rows: list) -> bytes:
    return "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows).encode("ascii")


# ---- the set ------------------------------------------------------------------------------------------------------
class Pruefmenge:
    def __init__(self, challenge: bytes, expected: bytes, befunde: list, bauarten: list, meta: dict,
                 schluessel_aussteller: bytes):
        self.challenge, self.expected, self.befunde = challenge, expected, befunde
        self.bauarten, self.meta, self.schluessel_aussteller = bauarten, meta, schluessel_aussteller


_WERT = re.compile(r"[0-9a-f]{64}|[A-Za-z0-9+/]{43}=")


def _zweiter_wert(lines: list, anchor: str) -> str:
    """The second value line (64 hex digits or 44 characters of base64) after the line that holds anchor."""
    start = next(i for i, line in enumerate(lines) if anchor in line)
    values = [s for s in (line.strip() for line in lines[start + 1:start + 41]) if _WERT.fullmatch(s)]
    return values[1]


def schluessel_anhang_a() -> dict:
    """The verification keys the vectors name in their first item: the issuer and the mixed-order test key as Appendix
    A.1 gives them in base64, and the two encodings of the neutral element as the item spells them out."""
    lines = TEXT.read_text(encoding="utf-8").splitlines()
    return {
        "the issuer test key": base64.b64decode(_zweiter_wert(lines, "Issuer test key, Ed25519 seed")),
        "the neutral element, canonical encoding (01 followed by 31 zero bytes)": bytes([1]) + bytes(31),
        "the neutral element, non-canonical encoding y = p + 1 (EE, 30 bytes FF, 7F)":
            bytes([0xEE]) + b"\xff" * 30 + bytes([0x7F]),
        "the mixed-order test key": base64.b64decode(_zweiter_wert(lines, "Mixed-order test key, used only by vector N61")),
    }


def anhang_a() -> list:
    """The vectors of Appendix A as (id, receipt bytes, verification key, expected verdict, expected label)."""
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    keys = schluessel_anhang_a()
    out = []
    for v in doc["vectors"]:
        name = v["items"][0][len("verification key: "):]
        receipt = bytes.fromhex(next(b["hex"] for b in v["bytes"] if b["label"] == "Receipt"))
        out.append((v["id"], receipt, keys[name], v["expected"], v["step"]))
    return out


def _annex_receipts() -> set:
    return {receipt for _id, receipt, _key, _verdict, _label in anhang_a()}


def erzeugen(seed: bytes, anzahl: int = STANDARD_ANZAHL, kennung: str = "einsendung") -> Pruefmenge:
    """The challenge set of (seed, anzahl, kennung): challenge.jsonl, expected.jsonl, the findings (entries the two
    verifiers disagree on, left out), the kind of each entry and a summary. Deterministic."""
    if len(seed) != 32:
        raise ValueError("the seed has 32 bytes")
    if anzahl < 1:
        raise ValueError("at least one entry")
    if not KENNUNG.match(kennung):
        raise ValueError("the name of the submission is 1 to 64 characters of A-Z a-z 0-9 . _ -, starting with a "
                         "letter or digit")
    master = hashlib.sha256(b"%s\x00" % VERSION.encode() + seed + kennung.encode("utf-8") + b"\x00"
                            + str(anzahl).encode()).digest()
    rng = Zufall(master)
    satz = Satz(rng.child("satz"))
    werk = Werkstatt(satz, rng.child("werkstatt"))
    valid = round(anzahl / 3)
    faults = round(anzahl * 0.12) if anzahl >= 20 else 0
    invalid = anzahl - valid - faults
    plan = ["gueltig"] * valid + ["bytefehler"] * faults
    kinds = list(PFLICHT)
    pool = list(UNGUELTIG)
    order = rng.child("plan")
    while len(kinds) < invalid:
        order.shuffle(pool)
        kinds += pool
    plan += kinds[:invalid]
    annex, seen = _annex_receipts(), set()
    entries, befunde, abweichungen_bau, grenze = [], [], 0, 0
    for slot, kind in enumerate(plan):
        for attempt in range(50):
            rb, key, intended = getattr(werk, kind)()
            zweiter = werk.zweiter if kind == "mehrfach" else None
            if rb in annex or (rb, key) in seen:
                continue
            a, t = _label_autor(rb, key), _label_text(rb, key)
            if a != t or a[0] == KEIN_URTEIL:
                befunde.append({"bauart": kind, "receipt_b64": b64(rb), "key_b64": b64(key),
                                "autor": "%s %s" % a, "text": "%s %s" % t})
                continue
            if a[0] == "RESOURCE_LIMIT":
                grenze += 1
                continue
            if intended is not None and a[1] != intended:
                abweichungen_bau += 1
            seen.add((rb, key))
            entries.append((kind, intended, zweiter, rb, key, a))
            break
        else:
            raise RuntimeError("no entry of kind %s after 50 attempts (slot %d)" % (kind, slot))
    rng.child("mischen").shuffle(entries)
    width = max(3, len(str(anzahl)))
    challenge, expected, bauarten = [], [], []
    for i, (kind, intended, zweiter, rb, key, label) in enumerate(entries, 1):
        entry_id = "c%0*d" % (width, i)
        challenge.append({"id": entry_id, "receipt_b64": b64(rb), "key_b64": b64(key)})
        expected.append(antwort(entry_id, *label))
        bauarten.append({"id": entry_id, "bauart": kind, "beabsichtigt": intended, "pruefer": label[1],
                         "zweiter_fehler": zweiter})
    counts: dict = {}
    for e in expected:
        name = "PASS" if e["verdict"] == "PASS" else ("11 %s" % e["detail"] if e["step"] == 11 else str(e["step"]))
        counts[name] = counts.get(name, 0) + 1
    challenge_b, expected_b = _jsonl(challenge), _jsonl(expected)
    probleme = pruefe_challenge(challenge_b)
    if probleme:
        raise RuntimeError("the set breaks its own envelope: %s" % "; ".join(probleme[:5]))
    meta = {"werkzeug": WERKZEUG, "ableitung": VERSION, "kennung": kennung, "anzahl": anzahl,
            "seed_sha256": hashlib.sha256(seed).hexdigest(),
            "challenge_sha256": hashlib.sha256(challenge_b).hexdigest(),
            "expected_sha256": hashlib.sha256(expected_b).hexdigest(),
            "je_erwartung": dict(sorted(counts.items(), key=lambda kv: _order_key(kv[0]))),
            "ausgelassen_uneinig": len(befunde), "ausgelassen_grenze": grenze,
            "bau_anders_als_beabsichtigt": abweichungen_bau,
            "schluessel_aussteller_b64": b64(satz.issuer.public)}
    return Pruefmenge(challenge_b, expected_b, befunde, bauarten, meta, satz.issuer.public)


def _b64_kanonisch(value):
    """The bytes of canonical base64 with padding, or None."""
    if not isinstance(value, str) or not value.isascii():
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        return None
    return raw if base64.b64encode(raw).decode("ascii") == value else None


def pruefe_challenge(challenge: bytes) -> list:
    """Nachtrag 2, point 5: what breaks the envelope of a challenge set, or []. UTF-8 without a byte order mark, one
    object per line ending in LF with exactly id, receipt_b64 and key_b64, unique non-empty string ids, canonical
    base64 with padding, and keys that decode to exactly 32 bytes."""
    out = []
    if challenge.startswith(b"\xef\xbb\xbf"):
        out.append("BOM am Anfang")
    if not challenge.endswith(b"\n"):
        out.append("die letzte Zeile endet nicht mit LF")
    try:
        text = challenge.decode("utf-8")
    except UnicodeDecodeError:
        return out + ["kein UTF-8"]
    seen: set = set()
    for n, line in enumerate(text[:-1].split("\n") if text.endswith("\n") else text.split("\n"), 1):
        try:
            row = json.loads(line, object_pairs_hook=_eindeutig, parse_constant=_keine_konstante)
        except (ValueError, RecursionError):
            out.append("Zeile %d: kein JSON-Objekt" % n)
            continue
        if not isinstance(row, dict) or set(row) != {"id", "receipt_b64", "key_b64"}:
            out.append("Zeile %d: nicht genau die Felder id, receipt_b64, key_b64" % n)
            continue
        if not isinstance(row["id"], str) or not row["id"]:
            out.append("Zeile %d: id ist keine nicht leere Zeichenkette" % n)
        elif row["id"] in seen:
            out.append("Zeile %d: die id %s steht doppelt" % (n, row["id"]))
        else:
            seen.add(row["id"])
        for name in ("receipt_b64", "key_b64"):
            raw = _b64_kanonisch(row[name])
            if raw is None:
                out.append("Zeile %d: %s ist kein kanonisches Base64 mit Padding" % (n, name))
            elif name == "key_b64" and len(raw) != 32:
                out.append("Zeile %d: key_b64 dekodiert zu %d Bytes statt 32" % (n, len(raw)))
    if not out and not seen:
        out.append("keine Einträge")
    return out


def _order_key(name: str):
    if name == "PASS":
        return (0, 0)
    head = name.split()
    return (int(head[0]), head[1] if len(head) > 1 else "")


def antworten_von(name: str, challenge: bytes) -> bytes:
    """answers.jsonl of one of our verifiers ("autor" or "text") for a challenge set."""
    label = PRUEFER[name]
    rows = []
    for line in challenge.decode("utf-8").splitlines():
        c = json.loads(line)
        rows.append(antwort(c["id"], *label(base64.b64decode(c["receipt_b64"]), base64.b64decode(c["key_b64"]))))
    return _jsonl(rows)


def erwartung_anhang_a() -> bytes:
    """The expected answers of Appendix A, in the answer form with the vector ids."""
    return _jsonl([antwort(i, verdict, label) for i, _receipt, _key, verdict, label in anhang_a()])


def ergebnisse_anhang_a(name: str) -> bytes:
    """results.jsonl of one of our verifiers for Appendix A."""
    label = PRUEFER[name]
    return _jsonl([antwort(i, *label(receipt, key)) for i, receipt, key, _verdict, _label in anhang_a()])


def gemischte_antworten(challenge: bytes, expected: bytes, seed: bytes) -> bytes:
    """A mixed answer file for the contract tests: per entry the expected answer, PASS or a FAIL at a random step,
    each about a third."""
    rng = Zufall(hashlib.sha256(b"gemischt\x00" + seed).digest())
    rows = []
    for e in (json.loads(line) for line in expected.decode("ascii").splitlines()):
        pick = rng.below(3)
        if pick == 0:
            rows.append(e)
        elif pick == 1:
            rows.append({"id": e["id"], "verdict": "PASS", "step": None, "detail": None})
        else:
            step = 1 + rng.below(11)
            rows.append({"id": e["id"], "verdict": "FAIL", "step": step,
                         "detail": "profile %d" % (1 + rng.below(4)) if step == 11 else None})
    return _jsonl(rows)


# ---- the comparison -------------------------------------------------------------------------------------------------
#: The classes of an expected entry; their counts add up to the number of entries.
KLASSEN = ("voll gleich", "Formabweichung", "inhaltliche Abweichung", "ERROR resource-limit",
           "ERROR execution-error", "Formfehler", "fehlt")


class Vergleich:
    def __init__(self):
        self.gesamt = self.uebereinstimmung = self.formabweichung = self.urteil_gleich = 0
        self.profilregel_gleich = self.profil_gesamt = 0
        self.nicht_beantwortet = {d: 0 for d in ERROR_DETAILS}
        self.klassen = {k: 0 for k in KLASSEN}
        self.je_schritt: dict = {}
        self.abweichungen: list = []        # answers in the contract that differ in content
        self.formabweichungen: list = []    # answers equal to the expected one only after NORMALISIERUNG
        self.formfehler: list = []          # answers outside the contract: no SER result
        # the envelope of the answer: execution errors of the submission, never a SER result
        self.fehlend: list = []
        self.doppelt: list = []
        self.fremd: list = []
        self.umgestellt: list = []
        self.kaputt: list = []
        self.leere_zeilen: list = []
        self.bom = False
        self.zeilenzahl = 0

    @property
    def huelle(self) -> list:
        """The execution errors of the answer file, each with its reason; [] for a complete run."""
        out = []
        if self.bom:
            out.append("BOM am Anfang der Datei")
        if self.leere_zeilen:
            out.append("leere Zeile: Zeile %s" % ", ".join(map(str, self.leere_zeilen[:GEZEIGT])))
        if self.zeilenzahl != self.gesamt:
            out.append("Zeilenzahl %d statt %d" % (self.zeilenzahl, self.gesamt))
        for name, items in (("fehlende ids", self.fehlend), ("doppelte ids", self.doppelt),
                            ("fremde ids", self.fremd), ("umgestellte ids", self.umgestellt),
                            ("kaputte Zeilen", self.kaputt)):
            if items:
                out.append("%s: %d" % (name, len(items)))
        return out

    @property
    def vollstaendig(self) -> bool:
        return not self.huelle


_PROFILREGEL = re.compile(r"profile ([1-4])(?:, (?:key|R))?\Z")


def _profilregel(detail):
    """The number of the profile rule one of the six details names, or None."""
    m = _PROFILREGEL.match(detail) if isinstance(detail, str) else None
    return int(m.group(1)) if m else None


def _name(e: dict) -> str:
    if e["verdict"] == "PASS":
        return "PASS"
    if e["verdict"] == "ERROR":
        return "ERROR"
    return "Schritt 11, %s" % e["detail"] if e["step"] == 11 else "Schritt %d" % e["step"]


def vertragsform(row) -> str | None:
    """Nachtrag 2, point 1: why an answer is outside the contract of prompt item 7, or None. Exactly the fields id,
    verdict, step and detail; PASS with step and detail null; FAIL with an integer step from 1 to 11, detail null at
    steps 1 to 10 and one of SECHS at step 11; ERROR with step null and one of ERROR_DETAILS."""
    if not isinstance(row, dict):
        return "kein JSON-Objekt"
    if set(row) != set(FELDER):
        fehlt = [k for k in FELDER if k not in row]
        return ("es fehlt %s" % ", ".join(fehlt)) if fehlt else "weitere Felder neben id, verdict, step, detail"
    if not isinstance(row["id"], str):
        return "id ist keine Zeichenkette"
    verdict, step, detail = row["verdict"], row["step"], row["detail"]
    if verdict == "PASS":
        if step is not None or detail is not None:
            return "PASS mit step oder detail ungleich null"
    elif verdict == "FAIL":
        if isinstance(step, bool) or not isinstance(step, int) or not 1 <= step <= 11:
            return "FAIL ohne step als ganze Zahl von 1 bis 11"
        if step == 11 and not (isinstance(detail, str) and detail in SECHS):
            return "Schritt 11 ohne einen der sechs Werte in detail"
        if step != 11 and detail is not None:
            return "detail ungleich null an Schritt 1 bis 10"
    elif verdict == "ERROR":
        if step is not None:
            return "ERROR mit step ungleich null"
        if not (isinstance(detail, str) and detail in ERROR_DETAILS):
            return "ERROR ohne resource-limit oder execution-error in detail"
    else:
        return "verdict ist nicht PASS, FAIL oder ERROR"
    return None


#: Nachtrag 2, point 2: the fixed normalisation, as (field, rule, example before, example after). An answer outside
#: the contract that equals the expected one after these rules is a form deviation, a number of its own, never
#: agreement and never a deviation in content. Nothing else is changed; normalisiert() does exactly this, and a test
#: holds each example against it.
NORMALISIERUNG = (
    ("verdict", "Leerzeichen und Tab am Anfang und Ende entfernt", " FAIL\t", "FAIL"),
    ("verdict", "ASCII-Kleinbuchstaben werden groß", "fail", "FAIL"),
    ("detail", "Leerzeichen und Tab am Anfang und Ende entfernt", " profile 2, key ", "profile 2, key"),
    ("detail", "eine Folge von Leerzeichen und Tab wird ein Leerzeichen", "profile  2,\tkey", "profile 2, key"),
    ("detail", "ASCII-Großbuchstaben werden klein, nur ein r am Ende wird R", "PROFILE 1, R", "profile 1, R"),
    ("detail", "ein fehlendes Komma oder Leerraum um das Komma vor key oder R wird Komma und ein Leerzeichen",
     "profile 2 ,key", "profile 2, key"),
    ("detail", "ohne Komma vor key oder R", "Profile 1 r", "profile 1, R"),
    ("verdict", "ein Wert mit einem Zeichen außerhalb ASCII wird nicht normalisiert", "FA\u0130L", None),
    ("detail", "ein Wert mit einem Zeichen außerhalb ASCII wird nicht normalisiert", "profile 2, \u212aey", None),
)
_LEERRAUM = re.compile(r"[ \t]+")
_KOMMA = re.compile(r"(profile [1-4]) ?,? ?(key|r)\Z")


def normalisiert(row):
    """The answer after NORMALISIERUNG, or None where the table does not apply: not an object with exactly the four
    fields, or a verdict or detail with a character outside ASCII. step and id are never changed."""
    if not isinstance(row, dict) or set(row) != set(FELDER):
        return None
    out = dict(row)
    if isinstance(row["verdict"], str):
        if not row["verdict"].isascii():
            return None
        out["verdict"] = row["verdict"].strip(" \t").upper()
    if isinstance(row["detail"], str):
        if not row["detail"].isascii():
            return None
        d = _LEERRAUM.sub(" ", row["detail"].strip(" \t")).lower()
        out["detail"] = _KOMMA.sub(lambda m: m.group(1) + ", " + ("R" if m.group(2) == "r" else "key"), d)
    return out


#: Owner choice O1 of 2026-10-13: the comparison reads at most 10 MB (10 000 000 bytes) of an answer file.
MAX_ANTWORT_BYTES = 10 * 1000 * 1000


class AntwortZuGross(Exception):
    """The answer file holds more than MAX_ANTWORT_BYTES; it is not compared."""


def lies_begrenzt(fh, grenze: int = MAX_ANTWORT_BYTES) -> bytes:
    """All bytes of a binary stream if there are at most grenze; AntwortZuGross as soon as one more is there. Reads at
    most grenze + 1 bytes, so a stream without end is not read past the limit."""
    parts, total = [], 0
    while total <= grenze:
        chunk = fh.read(grenze + 1 - total)
        if not chunk:
            break
        parts.append(chunk)
        total += len(chunk)
    if total > grenze:
        raise AntwortZuGross(grenze)
    return b"".join(parts)


class _DoppelterName(ValueError):
    pass


class _KeinJson(ValueError):
    pass


def _keine_konstante(name: str):
    """parse_constant: NaN, Infinity and -Infinity, which Python's json reads by default, are no JSON (RFC 8259,
    section 6). A line that holds one is not one JSON text (Codex on pull request 425)."""
    raise _KeinJson(name)


def _eindeutig(pairs: list) -> dict:
    """object_pairs_hook: a member name twice in one object makes the line ambiguous."""
    out: dict = {}
    for name, value in pairs:
        if name in out:
            raise _DoppelterName()
        out[name] = value
    return out


def _zeile(chunk: bytes):
    """The answer of one line, or the reason it is a broken line. Each line is read on its own and strictly: UTF-8,
    one JSON text, no member name twice, nesting only as deep as the parser goes without running out of stack."""
    try:
        line = chunk.decode("utf-8")
    except UnicodeDecodeError:
        return None, "kein UTF-8"
    try:
        return json.loads(line, object_pairs_hook=_eindeutig, parse_constant=_keine_konstante), None
    except _DoppelterName:
        return None, "ein Name steht doppelt"
    except _KeinJson:
        return None, "kein JSON (NaN oder Infinity)"
    except RecursionError:
        return None, "zu tief verschachtelt"
    except ValueError:
        return None, "kein JSON"


def vergleichen(answers: bytes, expected: bytes) -> Vergleich:
    """Compare answers.jsonl with expected.jsonl (Nachtrag 2). Each expected entry falls in one class of KLASSEN;
    the envelope of the answer file (vollstaendig, huelle) is judged apart, and a run with an envelope error is
    evaluated only as far as its lines go: no missing answer is filled in. Answers above MAX_ANTWORT_BYTES raise
    AntwortZuGross."""
    if len(answers) > MAX_ANTWORT_BYTES:
        raise AntwortZuGross(MAX_ANTWORT_BYTES)
    erwartet = [json.loads(line) for line in expected.decode("utf-8").splitlines() if line.strip()]
    position = {e["id"]: i for i, e in enumerate(erwartet)}
    v = Vergleich()
    v.gesamt = len(erwartet)
    got: dict = {}
    fremd: set = set()
    doppelt: set = set()
    if answers.startswith(b"\xef\xbb\xbf"):
        v.bom = True
        answers = answers[3:]
    lines = answers.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()                       # the LF that ends the last line
    v.zeilenzahl = len(lines)
    weiteste = -1
    for number, chunk in enumerate(lines, 1):
        if not chunk.strip():
            v.leere_zeilen.append(number)
            continue
        row, why = _zeile(chunk)
        if why is None and not (isinstance(row, dict) and isinstance(row.get("id"), str)):
            why = "keine Zeile mit einer id als Zeichenkette"
        if why is not None:
            v.kaputt.append((number, why))
            continue
        entry_id = row["id"]
        if entry_id not in position:
            if entry_id not in fremd:
                fremd.add(entry_id)
                v.fremd.append(entry_id)
            continue
        if entry_id in got:
            if entry_id not in doppelt:
                doppelt.add(entry_id)
                v.doppelt.append(entry_id)
            continue
        if position[entry_id] < weiteste:
            v.umgestellt.append(entry_id)
        weiteste = max(weiteste, position[entry_id])
        got[entry_id] = row
    for e in erwartet:
        name = _name(e)
        hit, total = v.je_schritt.get(name, (0, 0))
        a = got.get(e["id"])
        if e["step"] == 11:
            v.profil_gesamt += 1
        if a is None:
            v.fehlend.append(e["id"])
            v.klassen["fehlt"] += 1
            v.je_schritt[name] = (hit, total + 1)
            continue
        v.urteil_gleich += a.get("verdict") == e["verdict"]
        grund = vertragsform(a)
        wirksam = a if grund is None else None
        same = False
        if grund is None and a["verdict"] == "ERROR":
            v.nicht_beantwortet[a["detail"]] += 1
            v.klassen["ERROR " + a["detail"]] += 1
        elif grund is None:
            same = (a["verdict"], a["step"], a["detail"]) == (e["verdict"], e["step"], e["detail"])
            if same:
                v.uebereinstimmung += 1
                v.klassen["voll gleich"] += 1
            else:
                v.klassen["inhaltliche Abweichung"] += 1
                v.abweichungen.append({"id": e["id"], "erwartet": {k: e[k] for k in FELDER[1:]},
                                       "antwort": {k: a[k] for k in FELDER[1:]}})
        else:
            n = normalisiert(a)
            if n is not None and vertragsform(n) is None and all(n[k] == e[k] for k in FELDER[1:]):
                wirksam = n
                v.formabweichung += 1
                v.klassen["Formabweichung"] += 1
                v.formabweichungen.append({"id": e["id"], "antwort": a})
            else:
                v.klassen["Formfehler"] += 1
                v.formfehler.append({"id": e["id"], "grund": grund, "antwort": a})
        if (e["step"] == 11 and wirksam is not None and wirksam["verdict"] == "FAIL" and wirksam["step"] == 11
                and _profilregel(wirksam["detail"]) == _profilregel(e["detail"])):
            v.profilregel_gleich += 1
        v.je_schritt[name] = (hit + same, total + 1)
    assert sum(v.klassen.values()) == v.gesamt
    return v


#: How many ids or lines of one kind the text report names; --json names all.
GEZEIGT = 20


def _fremd(text: str) -> str:
    """A string from the answer file as the report shows it: JSON-escaped to ASCII, so that no control character,
    escape sequence or bidirectional mark reaches the terminal, and at most 60 characters of it."""
    shown = json.dumps(text[:60], ensure_ascii=True).replace("\x7f", "\\u007f")
    return shown + ("..." if len(text) > 60 else "")


def _kurz(a: dict) -> str:
    """An answer in the contract (ours or a submission's), short."""
    return "%s %s %s" % (a["verdict"], "-" if a["step"] is None else a["step"], a["detail"] or "-")


def _fremd_json(value) -> str:
    """Any value from the answer file as the report shows it: JSON, escaped to ASCII, at most 160 characters."""
    try:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True)
    except (TypeError, ValueError, RecursionError):
        text = "<nicht darstellbar>"
    text = text.replace("\x7f", "\\u007f")
    return text[:160] + ("..." if len(text) > 160 else "")


def _liste(items: list) -> str:
    if not items:
        return "keine"
    more = len(items) - GEZEIGT
    return "; ".join(items[:GEZEIGT]) + ("; und %d weitere (alle mit --json)" % more if more > 0 else "")


def _prozent(teil: int, ganz: int) -> str:
    return "%.1f %%" % (100.0 * teil / ganz if ganz else 0.0)


def bericht(v: Vergleich, kennung: str) -> str:
    out = ["Prüfmenge %s: %d Einträge" % (kennung, v.gesamt),
           "Volle Übereinstimmung (alle vier Felder gleich): %d von %d (%s)"
           % (v.uebereinstimmung, v.gesamt, _prozent(v.uebereinstimmung, v.gesamt)),
           "Formabweichung (gleich erst nach der Normalisierungstabelle): %d" % v.formabweichung,
           "Inhaltliche Abweichung: %d" % len(v.abweichungen),
           "Nicht beantwortet, ERROR resource-limit: %d" % v.nicht_beantwortet["resource-limit"],
           "Nicht beantwortet, ERROR execution-error: %d" % v.nicht_beantwortet["execution-error"],
           "Formfehler (kein SER-Ergebnis): %d" % len(v.formfehler),
           "Fehlt (keine Zeile): %d" % len(v.fehlend),
           "Summe der Klassen: %d" % sum(v.klassen.values()),
           "Nur das Urteil gleich: %d von %d" % (v.urteil_gleich, v.gesamt),
           "Profilregel gleich, key oder R nicht gewertet: %d von %d mit Erwartung Schritt 11"
           % (v.profilregel_gleich, v.profil_gesamt), "Je erwarteter Antwort, voll gleich:"]
    for name in sorted(v.je_schritt, key=_name_key):
        hit, total = v.je_schritt[name]
        out.append("  %-24s %d von %d" % (name, hit, total))
    out.append("Inhaltliche Abweichungen: %d" % len(v.abweichungen))
    for a in v.abweichungen:
        out.append("  %s: erwartet %s, Antwort %s" % (a["id"], _kurz(a["erwartet"]), _fremd_json(a["antwort"])))
    out.append("Formabweichungen: %d" % len(v.formabweichungen))
    for a in v.formabweichungen:
        out.append("  %s: Antwort %s" % (a["id"], _fremd_json(a["antwort"])))
    out.append("Formfehler: %d" % len(v.formfehler))
    for a in v.formfehler:
        out.append("  %s: %s; Antwort %s" % (a["id"], a["grund"], _fremd_json(a["antwort"])))
    out.append("Hülle der Antwort (Fehler der Ausführung, kein SER-Ergebnis): %s"
               % ("in Ordnung" if v.vollstaendig else "; ".join(v.huelle)))
    out.append("fehlende ids (%d): %s" % (len(v.fehlend), _liste(v.fehlend)))
    out.append("doppelte ids (%d): %s" % (len(v.doppelt), _liste(v.doppelt)))
    out.append("fremde ids (%d): %s" % (len(v.fremd), _liste([_fremd(i) for i in v.fremd[:GEZEIGT]] +
                                                             v.fremd[GEZEIGT:])))
    out.append("umgestellte ids (%d): %s" % (len(v.umgestellt), _liste(v.umgestellt)))
    out.append("kaputte Zeilen (%d): %s" % (len(v.kaputt), _liste(["Zeile %d, %s" % k for k in v.kaputt])))
    if not v.vollstaendig:
        out.append("Unvollständiger Lauf: gewertet sind nur die vorhandenen Zeilen, keine fehlende Antwort ergänzt")
    out.append("Antwort vollständig und lesbar: %s" % ("ja" if v.vollstaendig else "nein"))
    return "\n".join(out) + "\n"


def _name_key(name: str):
    if name == "PASS":
        return (0, 0, "")
    if name == "ERROR":
        return (99, 0, "")
    parts = name.replace(",", "").split()
    return (int(parts[1]), 0, " ".join(parts[2:]))


# ---- the two calls --------------------------------------------------------------------------------------------------
def _ordner(arg: str | None) -> pathlib.Path:
    return pathlib.Path(arg or os.environ.get(ORDNER_VARIABLE) or STANDARD_ORDNER).expanduser()


def _write_private(path: pathlib.Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(str(path), 0o600)


def main_erzeugen(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="pruefmenge_erzeugen", description="Erzeugt eine frische Prüfmenge für eine "
                                 "Einsendung zu draft-gruszka-signed-evaluation-receipts-04.")
    ap.add_argument("kennung", help="Kennung der Einsendung, zugleich Name ihres Ordners")
    ap.add_argument("--anzahl", type=int, default=STANDARD_ANZAHL, help="Zahl der Einträge (Vorgabe 200)")
    ap.add_argument("--ordner", help="Grundordner (Vorgabe $%s oder ~/ser_pruefmengen)" % ORDNER_VARIABLE)
    ap.add_argument("--seed-hex", help="nur für Tests: fester Seed aus 64 Hexziffern statt eines zufälligen")
    args = ap.parse_args(argv)
    if not KENNUNG.match(args.kennung):
        print("Die Kennung besteht aus 1 bis 64 Zeichen A-Z a-z 0-9 . _ - und beginnt mit einem Buchstaben oder "
              "einer Ziffer.", file=sys.stderr)
        return 2
    if args.kennung == ANHANG_A:
        print("%s steht in pruefmenge_vergleichen für Anhang A und ist keine Kennung einer Einsendung." % ANHANG_A,
              file=sys.stderr)
        return 2
    folder = _ordner(args.ordner) / args.kennung
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    seed_file = folder / "seed.hex"
    if seed_file.exists():
        seed = bytes.fromhex(seed_file.read_text(encoding="ascii").strip())
        if args.seed_hex and bytes.fromhex(args.seed_hex) != seed:
            print("seed.hex liegt schon vor und ist ein anderer Seed; nichts geschrieben.", file=sys.stderr)
            return 2
    else:
        seed = bytes.fromhex(args.seed_hex) if args.seed_hex else os.urandom(32)
        _write_private(seed_file, (seed.hex() + "\n").encode("ascii"))
    if len(seed) != 32:
        print("Der Seed hat 32 Bytes.", file=sys.stderr)
        return 2
    made = erzeugen(seed, args.anzahl, args.kennung)
    challenge_file = folder / "challenge.jsonl"
    if challenge_file.exists() and challenge_file.read_bytes() != made.challenge:
        print("challenge.jsonl liegt schon vor und ist eine andere Prüfmenge (andere Anzahl?); nichts geschrieben.",
              file=sys.stderr)
        return 2
    _write_private(challenge_file, made.challenge)
    _write_private(folder / "expected.jsonl", made.expected)
    _write_private(folder / "befunde.jsonl", _jsonl(made.befunde))
    _write_private(folder / "bauarten.jsonl", _jsonl(made.bauarten))
    _write_private(folder / "erzeugung.json", (json.dumps(made.meta, indent=2, ensure_ascii=False) + "\n").encode())
    print("Prüfmenge %s: %d Einträge, %d ausgelassen, weil die beiden Prüfer uneinig waren"
          % (args.kennung, args.anzahl, len(made.befunde)))
    print("Kennung: %s" % args.kennung)
    print("SHA-256 von challenge.jsonl: %s" % made.meta["challenge_sha256"])
    print("Nach außen geht nur: %s, mit Kennung und SHA-256; die Rückmeldung nennt beide wieder" % challenge_file)
    print("Bleiben hier: %s und %s" % (seed_file, folder / "expected.jsonl"))
    return 0


def main_vergleichen(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="pruefmenge_vergleichen", description="Vergleicht answers.jsonl einer "
                                 "Einsendung mit expected.jsonl ihrer Prüfmenge; führt keinen fremden Code aus.")
    ap.add_argument("kennung", help="Kennung der Einsendung, oder anhang-a für results.jsonl zu Anhang A")
    ap.add_argument("antworten", help="answers.jsonl, für anhang-a results.jsonl")
    ap.add_argument("--ordner", help="Grundordner (Vorgabe $%s oder ~/ser_pruefmengen)" % ORDNER_VARIABLE)
    ap.add_argument("--json", help="schreibt die Auswertung zusätzlich als JSON in diese Datei")
    ap.add_argument("--summe", help="SHA-256 von challenge.jsonl, wie die Rückmeldung der Einsendung sie nennt "
                    "(Pflicht für eine Prüfmenge)")
    args = ap.parse_args(argv)
    if args.kennung == ANHANG_A:
        expected = erwartung_anhang_a()
        if args.summe:
            print("Hinweis: für anhang-a gibt es keine Prüfmenge; die Summe wird nicht geprüft.", file=sys.stderr)
    else:
        if not KENNUNG.match(args.kennung):
            print("Die Kennung ist kein Ordnername.", file=sys.stderr)
            return 2
        folder = _ordner(args.ordner) / args.kennung
        path = folder / "expected.jsonl"
        if not path.exists():
            print("Keine Prüfmenge %s: %s fehlt." % (args.kennung, path), file=sys.stderr)
            return 2
        if not args.summe:
            print("Die Summe aus der Rückmeldung fehlt: --summe <SHA-256 von challenge.jsonl>.", file=sys.stderr)
            return 2
        try:
            meta = json.loads((folder / "erzeugung.json").read_text(encoding="utf-8"))
            eigene = hashlib.sha256((folder / "challenge.jsonl").read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            print("Die Prüfmenge %s ist hier nicht lesbar: %s" % (args.kennung, exc), file=sys.stderr)
            return 2
        if eigene != meta.get("challenge_sha256"):
            print("challenge.jsonl in %s passt nicht zu erzeugung.json; die Prüfmenge am Mac ist verändert."
                  % folder, file=sys.stderr)
            return 2
        huelle = []
        if meta.get("kennung") != args.kennung:
            huelle.append("Kennung passt nicht: der Ordner %s hält die Prüfmenge %s"
                          % (args.kennung, _fremd(str(meta.get("kennung")))))
        if args.summe.lower() != eigene:
            huelle.append("Summe passt nicht: die Rückmeldung nennt %s, die Prüfmenge %s hat %s"
                          % (_fremd(args.summe), args.kennung, eigene))
        if huelle:
            sys.stdout.write("Prüfmenge %s: Antwort nicht verglichen\n" % args.kennung
                             + "".join("Hülle: %s\n" % h for h in huelle)
                             + "Antwort vollständig und lesbar: nein\n")
            return 1
        expected = path.read_bytes()
    try:
        with open(args.antworten, "rb", buffering=0) as fh:   # unbuffered: no read ahead past the limit
            answers = lies_begrenzt(fh)
    except AntwortZuGross:
        print("Die Antwortdatei ist größer als %d Bytes (10 MB); sie wird nicht weiter gelesen und nicht verglichen."
              % MAX_ANTWORT_BYTES, file=sys.stderr)
        return 2
    except OSError as exc:
        print("Die Antwortdatei ist nicht lesbar: %s" % exc, file=sys.stderr)
        return 2
    v = vergleichen(answers, expected)
    sys.stdout.write(bericht(v, args.kennung))
    if args.json:
        summary = {"kennung": args.kennung, "summe": args.summe, "gesamt": v.gesamt, "klassen": v.klassen,
                   "uebereinstimmung": v.uebereinstimmung, "formabweichung": v.formabweichung,
                   "nicht_beantwortet": v.nicht_beantwortet, "urteil_gleich": v.urteil_gleich,
                   "profilregel_gleich": v.profilregel_gleich, "profil_gesamt": v.profil_gesamt,
                   "je_erwartung": {k: list(x) for k, x in v.je_schritt.items()},
                   "abweichungen": v.abweichungen, "formabweichungen": v.formabweichungen,
                   "formfehler": v.formfehler, "huelle": v.huelle, "fehlend": v.fehlend, "doppelt": v.doppelt,
                   "fremd": v.fremd, "umgestellt": v.umgestellt, "kaputt": [list(k) for k in v.kaputt],
                   "leere_zeilen": v.leere_zeilen, "bom": v.bom, "zeilenzahl": v.zeilenzahl,
                   "vollstaendig": v.vollstaendig, "antworten_sha256": hashlib.sha256(answers).hexdigest()}
        pathlib.Path(args.json).write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    return 0 if v.vollstaendig else 1


if __name__ == "__main__":
    sys.exit(main_vergleichen(sys.argv[1:]) if len(sys.argv) > 1 and sys.argv[1] == "vergleichen"
             else main_erzeugen(sys.argv[1:]))
