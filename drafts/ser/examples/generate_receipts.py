#!/usr/bin/env python3
"""Test vectors for draft-gruszka-signed-evaluation-receipts-01 (Signed Evaluation Receipts).

A Signed Evaluation Receipt is one JSON object

    {"schema", "payload_b64", "signature"}

where

  * payload_b64 is the canonical base64 (RFC 4648 Section 4, with padding) of B, and B is the
    RFC 8785 (JCS) byte string of the payload object: one assertion, whether a threshold held,
    with suite, metric, comparator, threshold, score and result, plus salted model and dataset
    commitments (sha256-salted-v1);
  * signature.sig is Ed25519 (RFC 8032, pure, no context) over PAE(TYPE, B), where PAE is the
    DSSE pre-authentication encoding and TYPE is the fixed media type.

The receipt carries no inclusion proof: transparency comes from registering
the receipt in an envelope, not from the receipt. B is unchanged by that removal, so every signature is too.

Every vector carries the exact receipt bytes, so a verifier works from bytes, not from a parsed
object. Deterministic: fixed test keys, salts and timestamps; two runs are byte-identical. The keys
and salts are pure test material and MUST NOT be used for any real receipt. Standard library plus
cryptography (used only to derive the test keys and to sign).
"""
import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---- fixed format constants (owner choice B, Nachtrag 17f point 6) ------------------------------
# The media type is the one identifier that enters every signature (the PAE type, also the DSSE
# payloadType). The version lives in the payload schema URI. Both stand under signed-evidence.org, a
# project domain chosen on 2026-10-08; the type is a vendor-tree media type name and no IANA action of the draft.
MEDIA_TYPE = "application/vnd.signed-evidence.eval-receipt+json"
RECEIPT_SCHEMA = MEDIA_TYPE
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"
COMMIT_ALG = "sha256-salted-v1"
TYPE = MEDIA_TYPE

# ---- Ed25519 arithmetic (RFC 8032 Section 5.1), used only to build the profile vectors -----------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
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


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _compress(pt):
    zi = pow(pt[2], P - 2, P)
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY_ENCODING = (1).to_bytes(32, "little")   # the neutral element (0, 1), a point of order 1
# A non-canonical encoding of the same point: y = p + 1 (>= p), sign bit 0. A decoder that reduces y modulo p
# reads the neutral element; RFC 8032 Section 5.1.3 decoding rejects it.
NONCANON_IDENTITY_ENCODING = (P + 1).to_bytes(32, "little")


def _order8_point():
    """The first point of order exactly 8 reached from y = 2, 3, ...: L times a decoded point lands in the
    small-order subgroup; it is kept when 4 times it is not the neutral element. Deterministic."""
    y = 2
    while True:
        x = _recover_x(y, 0)
        if x is not None:
            t8 = _mul(L, (x, y, 1, x * y % P))
            if _compress(_mul(4, t8)) != IDENTITY_ENCODING:
                assert _compress(_mul(8, t8)) == IDENTITY_ENCODING
                return t8
        y += 1


def _point(enc: bytes):
    """The extended point of a canonical 32-byte encoding."""
    v = int.from_bytes(enc, "little")
    y = v & ((1 << 255) - 1)
    x = _recover_x(y, v >> 255)
    assert x is not None
    return (x, y, 1, x * y % P)


def _secret_scalar(seed: bytes) -> int:
    """RFC 8032 Section 5.1.5: the clamped scalar a of the private key."""
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


# ---- RFC 8785 (JCS) for the subset used here -----------------------------------------------------
def jcs(obj) -> bytes:
    """Canonical bytes. Member names are ASCII and every number is an integer below 2**53, so RFC 8785
    reduces to sorted member names, no insignificant whitespace and the shortest string escapes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---- DSSE pre-authentication encoding -------------------------------------------------------------
def pae(typ: str, body: bytes) -> bytes:
    t = typ.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t
            + b" " + str(len(body)).encode("ascii") + b" " + body)


# ---- salted commitments (sha256-salted-v1) --------------------------------------------------------
def test_salt(label: str) -> bytes:
    """16-byte test salt from a fixed label (a real issuer takes 16 bytes from a CSPRNG and keeps them)."""
    return hashlib.sha256(("draft-gruszka-signed-evaluation-receipts salt " + label).encode()).digest()[:16]


def salted_commit(identifier: str, salt: bytes) -> str:
    assert len(salt) == 16
    return "sha256:" + hashlib.sha256(salt + identifier.encode("utf-8")).hexdigest()


# ---- fixed test material --------------------------------------------------------------------------
def test_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(("draft-gruszka-signed-evaluation-receipts test key " + label).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


ISSUER = test_key("issuer")
OTHER = test_key("other")
ISSUER_PUB = ISSUER.public_key().public_bytes_raw()
OTHER_PUB = OTHER.public_key().public_bytes_raw()
ORDER8_POINT = _order8_point()
ORDER8_ENCODING = _compress(ORDER8_POINT)
# The mixed-order test key: the issuer's public point plus the point of order 8. A PURE TEST KEY with no seed.
MIXED_PUB = _compress(_add(_mul(_secret_scalar(ISSUER.private_bytes_raw()), BASE), ORDER8_POINT))
assert _recover_x(int.from_bytes(MIXED_PUB, "little") & ((1 << 255) - 1), MIXED_PUB[31] >> 7) is not None
SALT_MODEL = test_salt("model")
SALT_DATASET = test_salt("dataset")
MODEL_ID = "acme/model-x@2026-09"
DATASET_ID = "acme/suite-data@v3"
TS = "2026-10-02T00:00:00Z"
# An example criteria set, as its publisher fixed its bytes. The format defines no criteria format; these bytes
# are only test material for the optional criteria_digest member.
CRITERIA_BYTES = b'{"comparator":">=","metric":"accuracy","suite":"acme-safety-suite","threshold":"0.800"}\n'
CRITERIA_DIGEST = "sha256:" + hashlib.sha256(CRITERIA_BYTES).hexdigest()

def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def base_payload(passed=True):
    """The one assertion. The payload names no trust instance: no issuer URI, no certificate, no
    key-fetch address. Model and dataset appear only as salted commitments."""
    return {
        "schema": PAYLOAD_SCHEMA,
        "suite": "acme-safety-suite",
        "suite_version": "1.2.0",
        "metric": "accuracy",
        "comparator": ">=",
        "threshold": "0.800",
        "score": "0.834" if passed else "0.762",
        "passed": passed,
        "n": 1800,
        "model_id_commit": salted_commit(MODEL_ID, SALT_MODEL),
        "dataset_id_commit": salted_commit(DATASET_ID, SALT_DATASET),
        "commit_alg": COMMIT_ALG,
        "timestamp": TS,
    }


def receipt_object(payload_bytes, *, sig, key_hint=ISSUER_PUB, payload_b64=None):
    signature = {"alg": "ed25519", "sig": b64(sig)}
    if key_hint is not None:
        signature["key"] = b64(key_hint)
    return {
        "schema": RECEIPT_SCHEMA,
        "payload_b64": payload_b64 if payload_b64 is not None else b64(payload_bytes),
        "signature": signature,
    }


def signed(payload_bytes, *, key=ISSUER, sig_type=TYPE, **kw):
    return receipt_object(payload_bytes, sig=key.sign(pae(sig_type, payload_bytes)), **kw)


VECTORS = []


def add(vid, requirement, expected, reason, receipt, *, step, receipt_bytes=None, key=ISSUER_PUB, note=None,
        payload=None):
    """step: the first failing step of the verification procedure under in-order evaluation ("all" for PASS)."""
    rb = receipt_bytes if receipt_bytes is not None else jcs(receipt)
    if payload is None:
        payload = base64.b64decode(receipt["payload_b64"])
    rec = {"id": vid, "requirement": requirement, "expected": expected, "step": step, "reason": reason,
           "verification_key_b64": b64(key),
           "payload_hex": payload.hex(), "payload_sha256": hashlib.sha256(payload).hexdigest(),
           "receipt_hex": rb.hex(), "receipt_sha256": hashlib.sha256(rb).hexdigest()}
    if note:
        rec["note"] = note
    VECTORS.append(rec)


def build():
    b_pass = jcs(base_payload(True))
    b_fail = jcs(base_payload(False))

    # ---- positive vectors ------------------------------------------------------------------------
    add("P1", "pass", "PASS", "A well-formed receipt: the signature over PAE(TYPE, B) verifies under the "
        "verification key, the commitments have the fixed pattern, and passed = true agrees with "
        "score >= threshold.", signed(b_pass), step="all")
    add("P2", "recorded-failure", "PASS", "A recorded failure (score below the threshold, passed = false) "
        "verifies exactly like a recorded success.", signed(b_fail), step="all")

    # ---- negative vectors, one or more per FAIL case of the verification procedure ---------------
    dup = (b'{"commit_alg":"sha256-salted-v1","passed":true,"passed":false,"schema":"'
           + PAYLOAD_SCHEMA.encode() + b'"}')
    add("N1", "no-duplicate-names", "FAIL", "The payload repeats the member name \"passed\" (RFC 7493 "
        "Section 2.3, RFC 8785 Section 3.1).", signed(dup), note="the signature over these bytes is valid", step="4")

    r = signed(b_pass)
    r["schema"] = "application/vnd.example.other+json"
    add("N2", "receipt-schema", "FAIL", "The receipt schema is not the receipt media type.", r, step="2")

    trailing = b_pass + b"\n# trailing"
    add("N3", "no-trailing-data", "FAIL", "The payload bytes carry data after the end of the JSON text "
        "(RFC 8259 Section 2).", signed(trailing), note="the signature over these bytes is valid", step="4")

    p = base_payload(True)
    p["model_id_commit"] = MODEL_ID
    add("N4", "commitment-pattern", "FAIL", "model_id_commit is the cleartext identifier, not \"sha256:\" "
        "followed by 64 lowercase hexadecimal digits.", signed(jcs(p)), step="7")

    noncanon = json.dumps(base_payload(True), indent=1).encode("utf-8")
    add("N5", "jcs-form", "FAIL", "The payload bytes are a valid JSON text of the same object but not its "
        "own RFC 8785 form (insignificant whitespace, member order).", signed(noncanon),
        note="the signature over these bytes is valid; re-serializing the parsed payload gives other bytes", step="5")

    sig = ISSUER.sign(pae(TYPE, b_pass))
    s_plus_l = sig[:32] + (int.from_bytes(sig[32:], "little") + L).to_bytes(32, "little")
    add("N6", "s-less-than-L", "FAIL", "The signature scalar S is not reduced (S >= L, RFC 8032 Section "
        "5.1.7); S was replaced by S + L, which a verifier without the range check accepts.",
        receipt_object(b_pass, sig=s_plus_l), step="11 (profile 3)")

    add("N7", "pae-type", "FAIL", "The signature was made over PAE with a different type string; under the "
        "fixed type it does not verify.", signed(b_pass, sig_type="application/vnd.example.other+json"), step="11 (profile 4)")

    add("N9", "key-hint", "FAIL", "The key hint in the receipt is not the verification key the receiver "
        "fixed.", signed(b_pass, key_hint=OTHER_PUB), step="10")

    p = base_payload(True)
    p["schema"] = "https://signed-evidence.org/eval-receipt/v0"
    add("N10", "payload-schema", "FAIL", "The payload schema is not the payload schema URI.", signed(jcs(p)), step="6")

    p = base_payload(True)
    p["score"] = "0.762"
    add("N11", "result-consistency", "FAIL", "passed = true, but the score 0.762 does not satisfy >= 0.800.",
        signed(jcs(p)), step="8")

    # small-order verification key: with A the neutral element, [S]B = R + [k]A holds for R = [S]B and
    # any message, so a verifier without the small-order check accepts a signature nobody made.
    s_scalar = int.from_bytes(hashlib.sha256(b"draft-gruszka-signed-evaluation-receipts small-order").digest(),
                              "little") % L
    forged = _compress(_mul(s_scalar, BASE)) + s_scalar.to_bytes(32, "little")
    add("N12", "small-order-key", "FAIL", "The verification key is the neutral element (a point of small "
        "order). The signature R || S with R = S*B' satisfies the cofactorless equation for any message "
        "under that key; the profile rejects small-order keys.",
        receipt_object(b_pass, sig=forged, key_hint=IDENTITY_ENCODING), key=IDENTITY_ENCODING,
        note="the receiver fixed this key; the vector shows why the profile refuses it", step="11 (profile 2, key)")

    # non-canonical base64: the last character carries non-zero padding bits; it decodes to the same B
    good = b64(b_pass)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    pad = len(good) - len(good.rstrip("="))
    if pad == 0:
        raise SystemExit("payload length gives no padding bits; adjust the test payload")
    last = len(good.rstrip("=")) - 1
    bumped = good[:last] + alphabet[alphabet.index(good[last]) + 1] + good[last + 1:]
    assert base64.b64decode(bumped) == b_pass and bumped != good
    add("N13", "canonical-base64", "FAIL", "payload_b64 decodes to the same B but is not its canonical base64 "
        "encoding (non-zero padding bits, RFC 4648 Section 3.5).", signed(b_pass, payload_b64=bumped), step="3")

    r = signed(b_pass)
    rb = jcs(r)
    second_sig = '"sig":"' + b64(bytes(64)) + '"'
    dup_outer = rb.replace(b'"sig":"', (second_sig + ',"sig":"').encode(), 1)
    assert dup_outer != rb
    add("N14", "receipt-duplicate-names", "FAIL", "The signature object repeats the member name \"sig\"; a "
        "parser that keeps the last value and one that keeps the first disagree.", r, receipt_bytes=dup_outer, step="1")

    r = signed(b_pass)
    r["signature"]["alg"] = "ed448"
    add("N15", "signature-alg", "FAIL", "signature.alg is not \"ed25519\"; the signature itself is a valid "
        "Ed25519 signature.", r, step="9")

    # ---- vectors added after the independent review (Nachtrag 17f rework) --------------------------
    # P4: string values of the receipt are compared after unescaping; "\/" is "/".
    r = signed(b_pass)
    rb = jcs(r).replace(b'"schema":"' + MEDIA_TYPE.encode() + b'"',
                        b'"schema":"' + MEDIA_TYPE.replace("/", "\\/").encode() + b'"', 1)
    assert rb != jcs(r)
    add("P4", "escaped-receipt-string", "PASS", "The receipt writes the schema with the JSON escape \\/ for "
        "each solidus; compared after unescaping it is the receipt media type. The receipt object is not "
        "canonicalized.", r, receipt_bytes=rb, step="all")

    a = _secret_scalar(ISSUER.private_bytes_raw())
    assert _compress(_mul(a, BASE)) == ISSUER_PUB
    msg = pae(TYPE, b_pass)

    # N16: R is the neutral element and S = k*a mod L; the cofactorless equation holds (S*B' = k*A = R + k*A),
    # rules 1, 3 and 4 hold, only rule 2 for R fails. The key holder can make it.
    k = int.from_bytes(hashlib.sha512(IDENTITY_ENCODING + ISSUER_PUB + msg).digest(), "little") % L
    add("N16", "small-order-R", "FAIL", "R is the neutral element (01 followed by 31 zero bytes) and S = k*a "
        "mod L with the issuer's secret scalar a. The cofactorless equation holds, R is canonical and S is "
        "below L; only the small-order rule for R rejects it.",
        receipt_object(b_pass, sig=IDENTITY_ENCODING + (k * a % L).to_bytes(32, "little")),
        step="11 (profile 2, R)")

    # N17: R is a non-canonical encoding of the neutral element (y = p + 1); S = k*a mod L over these bytes.
    k = int.from_bytes(hashlib.sha512(NONCANON_IDENTITY_ENCODING + ISSUER_PUB + msg).digest(), "little") % L
    add("N17", "noncanonical-R", "FAIL", "R is the non-canonical encoding y = p + 1 of the neutral element and "
        "S = k*a mod L over these R bytes. A decoder that reduces y modulo p accepts the signature; RFC 8032 "
        "Section 5.1.3 decoding rejects R (the small-order rule would reject it too).",
        receipt_object(b_pass, sig=NONCANON_IDENTITY_ENCODING + (k * a % L).to_bytes(32, "little")),
        step="11 (profile 1, R)")

    # N18: the fixed key is a non-canonical encoding of the neutral element; R = r*B', S = r satisfies the
    # cofactorless equation for any message under a decoder that reduces y modulo p.
    rr = int.from_bytes(hashlib.sha256(b"draft-gruszka-signed-evaluation-receipts noncanonical key").digest(),
                        "little") % L
    add("N18", "noncanonical-key", "FAIL", "The verification key is the non-canonical encoding y = p + 1 of the "
        "neutral element. With R = r*B' and S = r the cofactorless equation holds for any message under a "
        "decoder that reduces y modulo p; RFC 8032 Section 5.1.3 decoding rejects the key.",
        receipt_object(b_pass, sig=_compress(_mul(rr, BASE)) + rr.to_bytes(32, "little"),
                       key_hint=NONCANON_IDENTITY_ENCODING),
        key=NONCANON_IDENTITY_ENCODING, step="11 (profile 1, key)",
        note="the receiver fixed this key; the vector shows why the profile refuses it")

    r = signed(b_pass)
    add("N19", "receipt-trailing-data", "FAIL", "Data follows the end of the receipt's JSON text (RFC 8259 "
        "Section 2).", r, receipt_bytes=jcs(r) + b" x", step="1")

    r = signed(b_pass)
    r["comment"] = "x"
    add("N20", "receipt-member-set", "FAIL", "The receipt object has a member other than schema, payload_b64 "
        "and signature.", r, step="1")

    r = signed(b_pass)
    r["signature"]["kid"] = "x"
    add("N21", "signature-member-set", "FAIL", "The signature object has a member other than alg, sig and the "
        "optional key.", r, step="1")

    r = signed(b_pass)
    rb = jcs(r)
    dup_esc = rb.replace(b'"sig":"', b'"s\\u0069g":"' + b64(bytes(64)).encode() + b'","sig":"', 1)
    assert dup_esc != rb
    add("N22", "receipt-duplicate-after-unescaping", "FAIL", "The signature object has the member names "
        "\"s\\u0069g\" and \"sig\", which are the same name after unescaping.", r, receipt_bytes=dup_esc,
        step="1")

    r = signed(b_pass)
    add("N23", "receipt-bom", "FAIL", "The receipt bytes begin with a UTF-8 byte order mark, which is not part "
        "of a JSON text.", r, receipt_bytes=b"\xef\xbb\xbf" + jcs(r), step="1")

    r = signed(b_pass)
    r["payload_b64"] = "!" + r["payload_b64"][1:]
    add("N24", "payload-not-base64", "FAIL", "payload_b64 contains a character outside the base64 alphabet.",
        r, step="3", payload=b"")

    r = signed(b_pass)
    r["signature"]["sig"] = b64(base64.b64decode(r["signature"]["sig"])[:63])
    add("N25", "signature-length", "FAIL", "signature.sig decodes to 63 bytes, not 64.", r, step="9")

    r = signed(b_pass)
    good = r["signature"]["sig"]
    last = len(good.rstrip("=")) - 1
    bumped = good[:last] + alphabet[alphabet.index(good[last]) + 1] + good[last + 1:]
    assert base64.b64decode(bumped) == base64.b64decode(good) and bumped != good
    r["signature"]["sig"] = bumped
    add("N26", "signature-canonical-base64", "FAIL", "signature.sig decodes to the valid signature but is not "
        "its canonical base64 encoding (non-zero padding bits).", r, step="9")

    def payload_vector(vid, requirement, reason, change, step):
        p = base_payload(True)
        change(p)
        add(vid, requirement, "FAIL", reason, signed(jcs(p)), step=step)

    payload_vector("N30", "commit-alg", "commit_alg is not sha256-salted-v1.",
                   lambda p: p.update(commit_alg="sha256-salted-v2"), "6")
    payload_vector("N31", "payload-member-missing", "The payload lacks the member n.",
                   lambda p: p.pop("n"), "6")
    payload_vector("N32", "payload-member-extra", "The payload has a member not in Table 1.",
                   lambda p: p.update(extra="x"), "6")
    payload_vector("N33", "payload-member-type", "n is a string, not an integer.",
                   lambda p: p.update(n="1800"), "6")
    payload_vector("N34", "decimal-grammar", "score is .834, which is not a decimal string (no leading digit).",
                   lambda p: p.update(score=".834"), "6")
    payload_vector("N35", "n-at-least-1", "n is 0.", lambda p: p.update(n=0), "6")
    payload_vector("N36", "timestamp-calendar", "timestamp names 30 February.",
                   lambda p: p.update(timestamp="2026-02-30T00:00:00Z"), "6")
    payload_vector("N37", "timestamp-leap-second", "timestamp has second 60, which this format does not admit.",
                   lambda p: p.update(timestamp="2026-12-31T23:59:60Z"), "6")
    payload_vector("N38", "comparator-set", "comparator is => , not one of >=, >, <=, <.",
                   lambda p: p.update(comparator="=>"), "6")
    payload_vector("N39", "non-empty-string", "suite is the empty string.", lambda p: p.update(suite=""), "6")

    def raw_payload_vector(vid, requirement, reason, raw, step):
        add(vid, requirement, "FAIL", reason, signed(raw), step=step, note="the signature over these bytes is valid")

    raw_payload_vector("N40", "payload-utf8", "B contains the byte 0xFF, which is not UTF-8.",
                       b_pass.replace(b'"acme-safety-suite"', b'"acme-\xff-suite"', 1), "4")
    raw_payload_vector("N41", "payload-lone-surrogate", "B contains the escape \\ud800, a lone surrogate, which "
                       "I-JSON forbids (RFC 7493 Section 2.1).",
                       b_pass.replace(b'"acme-safety-suite"', b'"acme-\\ud800-suite"', 1), "4")
    raw_payload_vector("N42", "payload-noncharacter", "B contains U+FFFF, a noncharacter, which I-JSON forbids "
                       "(RFC 7493 Section 2.1).",
                       b_pass.replace(b'"acme-safety-suite"', b'"acme-\xef\xbf\xbf-suite"', 1), "4")
    raw_payload_vector("N43", "payload-bom", "B begins with a UTF-8 byte order mark.", b"\xef\xbb\xbf" + b_pass, "4")

    # ---- closing the gaps the independent verifier measured (each a rule no earlier vector exercised) --
    add("P6", "no-key-hint", "PASS", "The signature object has exactly alg and sig, without a key hint; step 10 "
        "has nothing to compare.", signed(b_pass, key_hint=None), step="all")

    def variant(**members):
        q = base_payload(True)
        q.update(members)
        return jcs(q)

    add("P7", "comparator-le", "PASS", "comparator <= with score 0.762 below threshold 0.800 and passed = true; "
        "read as >= the comparison would not hold.",
        signed(variant(comparator="<=", score="0.762")), step="all")
    add("P8", "exact-decimal", "PASS", "comparator > with score 0.30000000000000001 and threshold 0.3: as exact "
        "decimals the score is greater; as binary floating-point numbers the two are equal.",
        signed(variant(comparator=">", threshold="0.3", score="0.30000000000000001")), step="all")
    add("N48", "comparator-gt", "FAIL", "comparator > with score equal to threshold (0.800) and passed = true; "
        "read as >= the comparison would hold.", signed(variant(comparator=">", score="0.800")), step="8")
    add("N49", "comparator-lt", "FAIL", "comparator < with score 0.834 below threshold 0.900 and passed = false; "
        "the comparison holds, so passed must be true.",
        signed(variant(comparator="<", threshold="0.900", passed=False)), step="8")
    add("N50", "n-below-2-53", "FAIL", "n = 9007199254740992 (2^53). B is its own RFC 8785 form, since 2^53 is a "
        "double, but n is not below 2^53.", signed(variant(n=2 ** 53)), step="6")

    # The character goes into signature.alg, not into schema, so that a reader that tells formats
    # apart by schema still sees the receipt type; step 1 fails before step 9 would look at alg.
    p1_bytes = jcs(signed(b_pass))
    alg_member = b'"alg":"ed25519"'
    assert p1_bytes.count(alg_member) == 1

    def receipt_bytes_vector(vid, requirement, reason, inserted):
        rb = p1_bytes.replace(alg_member, alg_member[:-1] + inserted + b'"', 1)
        add(vid, requirement, "FAIL", reason, None, receipt_bytes=rb, payload=b_pass, step="1")

    receipt_bytes_vector("N44", "receipt-utf8", "The receipt contains the byte 0xFF, which is not UTF-8.", b"\xff")
    receipt_bytes_vector("N45", "receipt-lone-surrogate", "A string of the receipt contains the escape \\ud800, a "
                         "lone surrogate, which I-JSON forbids.", b"\\ud800")
    receipt_bytes_vector("N46", "receipt-noncharacter", "A string of the receipt contains U+FFFF, a "
                         "noncharacter, which I-JSON forbids.", b"\xef\xbf\xbf")

    # ---- round 2 of the independent verifier: rules the text states that no vector pinned yet --------
    add("P9", "year-0000", "PASS", "The timestamp is 0000-02-29T00:00:00Z: under the leap-year rule of RFC 3339 "
        "Appendix C the year 0000 exists and is a leap year.",
        signed(variant(timestamp="0000-02-29T00:00:00Z")), step="all")
    add("N51", "ascii-digits", "FAIL", "The score is 0. followed by the Arabic-Indic digits U+0668 U+0663 U+0664; "
        "a digit is an ASCII digit, so the score is not a decimal string.",
        signed(variant(score="0.\u0668\u0663\u0664")), step="6")
    add("N52", "number-without-double", "FAIL", "B writes n as 1e400, a number with no finite double; it has no "
        "RFC 8785 serialization, so B is not its own.",
        signed(b_pass.replace(b'"n":1800', b'"n":1e400', 1)), note="the signature over these bytes is valid",
        step="5")
    add("N53", "key-before-R-rule-1", "FAIL", "The verification key and R are both the non-canonical encoding "
        "y = p + 1 and S = 0; rule 1 fails for both and is reported for the key, which is checked first.",
        receipt_object(b_pass, sig=NONCANON_IDENTITY_ENCODING + bytes(32), key_hint=NONCANON_IDENTITY_ENCODING),
        key=NONCANON_IDENTITY_ENCODING, step="11 (profile 1, key)",
        note="the receiver fixed this key; the vector shows the order of the profile's checks")
    add("N54", "key-before-R-rule-2", "FAIL", "The verification key and R are both the neutral element and S = 0; "
        "rule 2 fails for both and is reported for the key, which is checked first.",
        receipt_object(b_pass, sig=IDENTITY_ENCODING + bytes(32), key_hint=IDENTITY_ENCODING),
        key=IDENTITY_ENCODING, step="11 (profile 2, key)",
        note="the receiver fixed this key; the vector shows the order of the profile's checks")
    schema_member = b'"schema":"' + RECEIPT_SCHEMA.encode() + b'"'
    assert p1_bytes.count(schema_member) == 1
    add("N55", "receipt-number-at-step-2", "FAIL", "The receipt writes schema as the number 1e400. Step 1 does not "
        "judge numbers, so the receipt fails at step 2, where schema is not the type.", None,
        receipt_bytes=p1_bytes.replace(schema_member, b'"schema":1e400', 1), payload=b_pass, step="2")
    add("N56", "number-serialization", "FAIL", "B writes n as 1800.0. Its RFC 8785 serialization is 1800, so B is "
        "not its own serialization, although the value is the n of P1 written another way.",
        signed(b_pass.replace(b'"n":1800', b'"n":1800.0', 1)), note="the signature over these bytes is valid",
        step="5")

    # ---- the optional criteria_digest member (the only optional Payload member) ----------------------------
    add("P10", "criteria-digest", "PASS", "The Payload carries the optional member criteria_digest: sha256: "
        "followed by the 64 lowercase hexadecimal digits of SHA-256 over the bytes of the example criteria set. "
        "A Receiver checks only its pattern.", signed(variant(criteria_digest=CRITERIA_DIGEST)), step="all")
    add("N57", "criteria-digest-pattern", "FAIL", "criteria_digest has uppercase hexadecimal digits, so it is not "
        "sha256: followed by 64 lowercase hexadecimal digits.",
        signed(variant(criteria_digest="sha256:" + CRITERIA_DIGEST[7:].upper())), step="7")
    add("N58", "criteria-digest-type", "FAIL", "criteria_digest is null, not a string.",
        signed(variant(criteria_digest=None)), step="6")

    # ---- a verification key of mixed order: rule 2 requires order L (owner choice of 2026-10-07) ---------------
    # MIXED_PUB = A + T8 with A the issuer's public point and T8 a point of order 8. It passes rule 1 and fails
    # rule 2. A signature under it that meets the cofactorless equation exists for whoever knows the discrete
    # logarithm a of its prime-order part A: with R = r*B' and k = SHA-512(R || MIXED_PUB || PAE) mod L divisible
    # by 8, k*T8 is the neutral element, so S = r + k*a satisfies S*B' = R + k*MIXED_PUB. r is drawn
    # deterministically. Only rule 2 for the key refuses it.
    a = _secret_scalar(ISSUER.private_bytes_raw())
    msg = pae(TYPE, b_pass)
    i = 0
    while True:
        r = int.from_bytes(hashlib.sha512(b"draft-gruszka-signed-evaluation-receipts mixed-order nonce "
                                          + str(i).encode()).digest(), "little") % L
        r_enc = _compress(_mul(r, BASE))
        k = int.from_bytes(hashlib.sha512(r_enc + MIXED_PUB + msg).digest(), "little") % L
        if k % 8 == 0:
            break
        i += 1
    sig_mixed = r_enc + ((r + k * a) % L).to_bytes(32, "little")
    add("N61", "mixed-order-key", "FAIL", "The verification key is the mixed-order test key: the issuer's public "
        "point plus a point of order 8. It is a canonical encoding and not a point of small order, but it is not "
        "of order L, so rule 2 rejects it. The signature satisfies the cofactorless equation under that key; a "
        "Receiver without rule 2 would accept it.",
        receipt_object(b_pass, sig=sig_mixed, key_hint=MIXED_PUB), key=MIXED_PUB, step="11 (profile 2, key)",
        note="the key is a pure test key with no RFC 8032 seed; R is of order L and S is below L")

    # ---- an R of mixed order under the issuer key: rule 2 is checked for R as well --------------------------------
    # R = r*B' + T8 and S = r + k*a mod L. The cofactored equation 8*S*B' = 8*R + 8*k*A holds; the cofactorless one
    # cannot, because k*A has order L or 1 and so cannot cancel T8. Rule 2 rejects R before rule 4 is reached.
    r = int.from_bytes(hashlib.sha512(b"draft-gruszka-signed-evaluation-receipts mixed-order R nonce").digest(),
                       "little") % L
    r_mixed = _compress(_add(_mul(r, BASE), ORDER8_POINT))
    k = int.from_bytes(hashlib.sha512(r_mixed + ISSUER_PUB + msg).digest(), "little") % L
    s_mixed = (r + k * a) % L
    lhs, rhs = _mul(s_mixed, BASE), _add(_point(r_mixed), _mul(k, _point(ISSUER_PUB)))
    assert _compress(_mul(8, lhs)) == _compress(_mul(8, rhs)) and _compress(lhs) != _compress(rhs)
    add("N59", "mixed-order-R", "FAIL", "R is the point r*B' plus the point of order 8, a canonical encoding of a "
        "point of mixed order, and S = r + k*a mod L with the issuer's secret scalar a. The cofactored equation "
        "8*S*B' = 8*R + 8*k*A holds and the cofactorless equation does not; rule 2 rejects R before rule 4 is "
        "reached.", receipt_object(b_pass, sig=r_mixed + s_mixed.to_bytes(32, "little")), step="11 (profile 2, R)")

    # ---- insignificant whitespace before or after the JSON text: admitted at step 1 and step 4 ------------------
    # The receipt is not canonicalized, so a line feed around it changes nothing; B is, so step 5 rejects one.
    add("P12", "receipt-trailing-whitespace", "PASS", "The receipt bytes of P1 followed by one line feed (0a), "
        "insignificant whitespace after the end of the JSON text (RFC 8259 Section 2), which step 1 admits.",
        None, receipt_bytes=p1_bytes + b"\n", payload=b_pass, step="all")
    add("N60", "payload-trailing-whitespace", "FAIL", "B is that of P1 followed by one line feed (0a), signed "
        "anew. Step 4 admits the line feed under the rules of step 1; step 5 rejects B, because its RFC 8785 "
        "serialization has no insignificant whitespace.", signed(b_pass + b"\n"),
        note="the signature over these bytes is valid", step="5")
    add("P13", "receipt-leading-whitespace", "PASS", "One line feed (0a) followed by the receipt bytes of P1, "
        "insignificant whitespace before the JSON text (RFC 8259 Section 2), which step 1 admits.",
        None, receipt_bytes=b"\n" + p1_bytes, payload=b_pass, step="all")


def main():
    build()
    doc = {
        "draft": "draft-gruszka-signed-evaluation-receipts-01",
        "format": {
            "media_type": MEDIA_TYPE,
            "receipt_schema": RECEIPT_SCHEMA,
            "payload_schema": PAYLOAD_SCHEMA,
            "commit_alg": COMMIT_ALG,
            "pae_type": TYPE,
            "signature_alg": "Ed25519 (RFC 8032), pure, no context",
            "signing_input": "PAE(TYPE, B) with B = RFC 8785 (JCS) payload bytes",
        },
        "test_keys": {
            "issuer": {"ed25519_seed_hex": ISSUER.private_bytes_raw().hex(), "public_raw_b64": b64(ISSUER_PUB)},
            "other": {"ed25519_seed_hex": OTHER.private_bytes_raw().hex(), "public_raw_b64": b64(OTHER_PUB)},
            "mixed_order": {"public_raw_b64": b64(MIXED_PUB), "order8_point_hex": ORDER8_ENCODING.hex(),
                            "construction": "the issuer test key's public point plus the point of order 8; "
                                            "no RFC 8032 seed; the discrete logarithm of its prime-order part "
                                            "is the issuer test key's secret scalar"},
        },
        "test_salts": {
            "model": {"salt_hex": SALT_MODEL.hex(), "identifier": MODEL_ID,
                      "commit": salted_commit(MODEL_ID, SALT_MODEL)},
            "dataset": {"salt_hex": SALT_DATASET.hex(), "identifier": DATASET_ID,
                        "commit": salted_commit(DATASET_ID, SALT_DATASET)},
        },
        "test_criteria": {"bytes_hex": CRITERIA_BYTES.hex(), "criteria_digest": CRITERIA_DIGEST},
        "test_material_notice": "PURE TEST KEYS AND SALTS. They MUST NOT be used for any real receipt.",
        "vectors": VECTORS,
    }
    out = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote %s  (%d vectors)" % (out, len(VECTORS)), file=sys.stderr)


if __name__ == "__main__":
    main()
