"""Generate tests/fixtures/receipt_cose/vectors.json: the vectors of the receipt <-> COSE_Sign1 translator.

Forward vectors run ``proofbundle.receipt_cose.receipt_to_statement`` on receipts of the Draft 1 fixture
(tests/fixtures/signed_eval_receipt/draft1_vectors.json). Backward vectors are statements built here,
byte by byte, with an encoder of this script's own, so that a negative vector differs from a valid one in
the one property it names and is signed where its point is not the signature. Every value is
deterministic; two runs write the same bytes.

Keys: the receipt key and the relying party's statement key are the issuer test key of Draft 1 (its seed
is in the Draft 1 fixture), as in vector M2 of draft-gruszka-evaluation-receipt-mappings-00. The relying
party configures each statement key as a pair with the issuer URI it trusts the key for; a vector names
its pairs as [issuer URI, key name]. The foreign key's seed is SHA-256 over FOREIGN_SEED_LABEL, and the
P-256 key's private scalar is SHA-256 over P256_SEED_LABEL read as a big-endian integer. The mixed-order
key is the key of Draft 1 vector P11, the issuer's public point plus a point of order 8; ``off_curve`` is
the first y from 2 on that names no curve point. PURE TEST KEYS. They MUST NOT be used for anything real.

Alg (owner choice B, 2026-10-04): the forward direction writes -19 only, so F2 (-8) is a refusal; the
statement with -8 that the check still reads (B2) is built here, byte for byte the statement the forward
direction wrote for -8 before that choice.

Run from the repository root: ``python tools/receipt_cose_vectors/generate.py`` (needs the [scitt] extra).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from proofbundle import receipt_cose as rc  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402
from proofbundle.signed_eval_receipt import RECEIPT_TYPE  # noqa: E402

DRAFT1 = REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json"
OUT = REPO / "tests" / "fixtures" / "receipt_cose" / "vectors.json"
ISSUER = "https://issuer.example/eval"
OTHER_ISSUER = "https://other-issuer.example/eval"
FOREIGN_SEED_LABEL = "receipt-cose foreign statement key, PURE TEST KEY"
P256_SEED_LABEL = "receipt-cose P-256 statement key, PURE TEST KEY"
#: The Draft 1 PURE TEST seed of the issuer key, written out; main() holds it equal to the fixture's seed.
DRAFT_TEST_SEED = b'#eR\x04\x10t\x8d\xe8w\x8bTD\x10\xb1W\x92\xfc\xf1t\xe0\xfb\xa4\x80j\x8c\x1a\xfb\xdb\xb0\x94k\x07'


# ---- Ed25519 arithmetic (RFC 8032 section 5.1), only to build the profile vectors B38, B39, B41 and B42 ------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (1).to_bytes(32, "little")   # the neutral element (0, 1), a point of order 1


def recover_x(y: int, sign: int):
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


def add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(k: int, pt):
    q = (0, 1, 1, 0)
    while k:
        if k & 1:
            q = add(q, pt)
        pt = add(pt, pt)
        k >>= 1
    return q


def compress(pt) -> bytes:
    zi = pow(pt[2], P - 2, P)
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, P - 2, P) % P
BASE = (recover_x(_GY, 0), _GY, 1, recover_x(_GY, 0) * _GY % P)


def order8_point():
    """The point of order 8 of Draft 1's mixed-order key: the first one reached from y = 2, 3, ... as L times
    a decoded point, kept when 4 times it is not the neutral element."""
    y = 2
    while True:
        x = recover_x(y, 0)
        if x is not None:
            t8 = mul(L, (x, y, 1, x * y % P))
            if compress(mul(4, t8)) != IDENTITY:
                return t8
        y += 1


def secret_scalar(seed: bytes) -> int:
    """RFC 8032 section 5.1.5: the clamped scalar a of the private key."""
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little")
    return (a & ((1 << 254) - 8)) | (1 << 254)


def challenge(r_enc: bytes, a_enc: bytes, message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r_enc + a_enc + message).digest(), "little") % L


# ---- an encoder of this script's own, able to write what the rule forbids ----------------------------------
def head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for size, info in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError(n)


def enc(v) -> bytes:
    if type(v) is int:
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if type(v) is bytes:
        return head(2, len(v)) + v
    if type(v) is str:
        return head(3, len(v.encode())) + v.encode()
    if v is None:
        return b"\xf6"
    if type(v) is list:
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if type(v) is dict:
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def map_in_order(pairs) -> bytes:
    """A map with its pairs in the order given, even a repeated key: the encodings the rule refuses."""
    return head(5, len(pairs)) + b"".join(enc(k) + enc(v) for k, v in pairs)


def tbs(protected_raw: bytes, payload: bytes) -> bytes:
    return enc(["Signature1", protected_raw, b"", payload])


def sign1(protected_raw: bytes, payload, signature: bytes, *, unprotected=None, tag: int | None = 18) -> bytes:
    body = enc([protected_raw, unprotected or {}, payload, signature])
    return (head(6, tag) if tag is not None else b"") + body


def main() -> None:
    doc = json.loads(DRAFT1.read_text(encoding="utf-8"))
    payloads = {n: (p["text"].encode() if "text" in p else decode_b64(p["b64"])) for n, p in doc["payloads"].items()}

    def receipt(vid: str) -> bytes:
        v = next(x for x in doc["vectors"] if x["id"] == vid)
        raw = v["receipt_text"].encode() if "receipt_text" in v else decode_b64(v["receipt_b64"])
        for name, b in payloads.items():
            raw = raw.replace(b"@" + name.encode() + b"@", base64.b64encode(b))
        assert hashlib.sha256(raw).hexdigest() == v["receipt_sha256"], vid
        return raw

    assert DRAFT_TEST_SEED.hex() == doc["issuer_seed_hex"]
    issuer_key = Ed25519PrivateKey.from_private_bytes(DRAFT_TEST_SEED)
    foreign_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(FOREIGN_SEED_LABEL.encode()).digest())
    issuer_pub = issuer_key.public_key().public_bytes_raw()
    foreign_pub = foreign_key.public_key().public_bytes_raw()
    keys = {"issuer": issuer_pub, "foreign": foreign_pub}

    # ---- forward ---------------------------------------------------------------------------------------
    forward = []

    def fwd(vid, rid, alg, receipt_key, what):
        try:
            data = rc.receipt_to_statement(receipt(rid), keys[receipt_key], issuer_key, issuer=ISSUER, alg=alg)
            forward.append({"id": vid, "receipt": rid, "receipt_key": receipt_key, "alg": alg, "expect": "statement",
                            "statement_hex": data.hex(), "statement_sha256": hashlib.sha256(data).hexdigest(),
                            "what": what})
            return data
        except rc.ReceiptCoseError as exc:
            forward.append({"id": vid, "receipt": rid, "receipt_key": receipt_key, "alg": alg, "expect": "refused",
                            "detail": str(exc), "what": what})
            return None

    f1 = fwd("F1", "P1", -19, "issuer", "P1 with alg -19: byte for byte vector M2 of the mappings draft")
    f2 = fwd("F2", "P1", -8, "issuer", "P1 with alg -8: this direction writes -19 only, no statement")
    fwd("F3", "P4", -19, "issuer", "P4, other receipt bytes of the same B: the statement of F1 again")
    fwd("F4", "N7", -19, "issuer", "N7 fails step 11 of the receipt procedure: no statement")
    fwd("F5", "P1", -19, "foreign", "P1 under a key the receipt was not made with: fails step 10, no statement")
    f6 = fwd("F6", "P2", -19, "issuer", "P2, another B: the statement B4 presents with P1")
    assert f1 and f2 is None and f6 and forward[2]["statement_hex"] == f1.hex()

    # ---- backward --------------------------------------------------------------------------------------
    p1_raw = decode_b64(json.loads(receipt("P1"))["payload_b64"])
    p1_b = json.loads(p1_raw)
    digest = hashlib.sha256(p1_raw).digest()
    kid_issuer, kid_foreign = rc.cose_key_thumbprint(issuer_pub), rc.cose_key_thumbprint(foreign_pub)

    def protected(**change):
        p = {1: -19, 4: kid_issuer, 15: {1: ISSUER, 2: p1_b["model_id_commit"]}, 258: -16, 259: RECEIPT_TYPE}
        for label, value in change.items():
            label = int(label[1:])
            if value is _DROP:
                p.pop(label)
            else:
                p[label] = value
        return p

    def signed(prot, *, key=issuer_key, payload=digest, protected_raw=None, **kw):
        raw = enc(prot) if protected_raw is None else protected_raw
        return sign1(raw, payload, key.sign(tbs(raw, payload if payload is not None else b"")), **kw)

    backward = []
    s8 = signed(protected(k1=-8))   # alg -8, read and never written: B2, B10 and B36
    p256_pub = ec.derive_private_key(int.from_bytes(hashlib.sha256(P256_SEED_LABEL.encode()).digest(), "big"),
                                     ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def bwd(vid, statement, rid, status, what, statement_keys=((ISSUER, "issuer"),), algs=None):
        item = {"id": vid, "statement_hex": statement.hex(), "receipt": rid,
                "statement_keys": [[iss, key] for iss, key in statement_keys], "expect_status": status, "what": what}
        if algs is not None:
            item["algs"] = list(algs)
        backward.append(item)

    bwd("B1", f1, "P1", "accepted", "F1 (alg -19) with the receipt it was made from")
    bwd("B2", s8, "P1", "accepted", "alg -8 under the Ed25519 issuer key, with the receipt it cites: read")
    bwd("B3", f1, "P4", "accepted", "F1 with P4, other receipt bytes (an escaped character), the same B")
    bwd("B4", f6, "P1", "digest_mismatch", "a statement on another digest (P2's B), validly signed, with P1")
    bwd("B5", signed(protected(k4=kid_foreign), key=foreign_key), "P1", "untrusted_key",
        "a valid signature under a foreign key whose kid it names: no relying-party key has that kid")
    bwd("B6", signed(protected(), key=foreign_key), "P1", "signature_invalid",
        "the relying-party key's kid, signed by a foreign key")
    bwd("B7", f1, "N7", "receipt_not_verified", "F1 with N7, a receipt that fails step 11")
    bwd("B8", signed(protected(k15={1: ISSUER, 2: p1_b["dataset_id_commit"]})), "P1", "subject_mismatch",
        "sub names a commitment of the right form that is not the receipt's model commitment")
    bwd("B9", signed(protected(k1=-7)), "P1", "outside_profile", "alg -7 (ES256)")
    bwd("B10", s8, "P1", "outside_profile", "alg -8 where the relying party accepts -19 only", algs=(-19,))
    bwd("B11", signed(protected(), unprotected={4: kid_issuer}), "P1", "outside_profile",
        "the unprotected header is not empty")
    bwd("B12", signed(protected(), tag=None), "P1", "outside_profile", "the COSE_Sign1 is not tagged 18")
    bwd("B13", signed(protected(k260="https://receipts.example/p1")), "P1", "outside_profile",
        "a sixth protected label, 260 (payload location)")
    bwd("B14", signed(protected(k4=kid_issuer[:16])), "P1", "outside_profile", "kid of 16 bytes")
    bwd("B15", signed(protected(k15={1: ISSUER, 2: p1_b["model_id_commit"], 6: 1790000000})), "P1",
        "outside_profile", "the CWT Claims carry a third claim, 6 (iat)")
    bwd("B16", signed(protected(k15={1: "issuer example", 2: p1_b["model_id_commit"]})), "P1",
        "outside_profile", "iss is not a URI")
    bwd("B17", signed(protected(k15={1: ISSUER, 2: "model-x"})), "P1", "outside_profile",
        "sub is not a commitment")
    bwd("B18", signed(protected(k258=-43)), "P1", "outside_profile", "label 258 is -43 (SHA-384)")
    bwd("B19", signed(protected(k259="application/json")), "P1", "outside_profile",
        "label 259 is application/json, not the receipt type")
    bwd("B20", signed(protected(), payload=None), "P1", "outside_profile", "the payload is detached")
    bwd("B21", signed(protected(), payload=digest[:31]), "P1", "outside_profile", "a payload of 31 bytes")
    assert f1[-66:-64] == head(2, 64)
    bwd("B22", f1[:-66] + head(2, 63) + f1[-63:], "P1", "outside_profile", "a signature of 63 bytes")
    bwd("B23", signed(protected(k1=_DROP)), "P1", "outside_profile", "no alg (label 1)")
    p = protected()
    reordered = map_in_order([(259, p[259]), (1, p[1]), (4, p[4]), (15, p[15]), (258, p[258])])
    bwd("B24", signed(None, protected_raw=reordered), "P1", "malformed",
        "the protected header's labels out of deterministic order, signed over those bytes")
    duplicate = map_in_order([(1, -19), (1, -19), (4, p[4]), (15, p[15]), (258, p[258]), (259, p[259])])
    bwd("B25", signed(None, protected_raw=duplicate), "P1", "malformed",
        "label 1 twice in the protected header, signed over those bytes")
    bwd("B26", f1 + b"\x00", "P1", "malformed", "a byte after the COSE_Sign1")
    bwd("B27", head(6, 98) + f1[1:], "P1", "malformed", "tag 98 (COSE_Sign) instead of 18")
    bwd("B28", f1[:1] + b"\x9f" + f1[2:] + b"\xff", "P1", "malformed", "the outer array in indefinite length")
    bwd("B29", head(6, 18) + head(4, 3) + enc(enc(p)) + enc({}) + enc(digest), "P1", "malformed",
        "an array of three: protected, unprotected and payload, no signature")
    as_text = head(6, 18) + enc([enc(p).decode("latin-1"), {}, digest, b"\x00" * 64])
    bwd("B30", as_text, "P1", "malformed", "the protected header as a text string")
    bwd("B31", signed(None, protected_raw=enc([1, -19])), "P1", "malformed",
        "the protected header is an array, not a map")
    bwd("B32", signed(None, protected_raw=head(6, 24) + enc(enc(p))), "P1", "malformed",
        "the protected header is a tag (24), not a map")
    bwd("B33", signed(None, protected_raw=enc(p) + b"\x00"), "P1", "malformed",
        "a byte after the protected header's map")
    bwd("B34", signed(None, protected_raw=b""), "P1", "outside_profile", "an empty protected header")
    low_order = bytes(32)   # the encoding of a small-order point; a signature can verify under it without a secret
    bwd("B35", signed(protected(k4=rc.cose_key_thumbprint(low_order)), key=foreign_key), "P1", "untrusted_key",
        "the kid of a small-order key that the relying party lists: refused as a trust anchor",
        statement_keys=((ISSUER, "low_order"),))
    bwd("B36", s8, "P1", "untrusted_key",
        "alg -8 where the relying party's only statement key is a P-256 key: -8 is read only under an Ed25519 key",
        statement_keys=((ISSUER, "p256"),))

    # ---- added 2026-10-07: the pair of issuer and key, and the rules of Section 4.4 -------------------------
    other = signed(protected(k15={1: OTHER_ISSUER, 2: p1_b["model_id_commit"]}))
    assert hashlib.sha256(other).hexdigest() == "1e205e47f7f0e71ae16a0c35b55728369561d0984a83253f3f3b38b1f791ad28"
    bwd("B37", other, "P1", "untrusted_key",
        "B1 with iss https://other-issuer.example/eval, signed with the issuer test seed: the relying party "
        "trusts that key for https://issuer.example/eval only, and the received iss does not make it trusted "
        "for another issuer")
    a_issuer = secret_scalar(DRAFT_TEST_SEED)
    raw38 = enc(protected())
    k38 = challenge(IDENTITY, issuer_pub, tbs(raw38, digest))
    sig38 = IDENTITY + (k38 * a_issuer % L).to_bytes(32, "little")
    bwd("B38", sign1(raw38, digest, sig38), "P1", "signature_invalid",
        "a signature whose R is the neutral element, a point of small order, made with the issuer test seed: "
        "the cofactorless equation holds, rule 2 of Section 4.4 of the receipts draft refuses it")
    y = 2
    while recover_x(y, 0) is not None:
        y += 1
    off_curve = y.to_bytes(32, "little")
    bwd("B39", signed(protected(k4=rc.cose_key_thumbprint(off_curve)), key=foreign_key), "P1", "untrusted_key",
        "the kid of a 32-byte entry whose y names no curve point: no canonical encoding (rule 1 of Section 4.4), "
        "so the entry is no trusted key", statement_keys=((ISSUER, "off_curve"),))
    fragment = ISSUER + "#frag"
    bwd("B40", signed(protected(k15={1: fragment, 2: p1_b["model_id_commit"]})), "P1", "outside_profile",
        "iss carries a fragment, so it is no absolute URI (RFC 3986 section 4.3), even where a pair names "
        "that string", statement_keys=((fragment, "issuer"),))
    mixed = compress(add(mul(a_issuer, BASE), order8_point()))
    p11 = next(x for x in doc["vectors"] if x["id"] == "P11")
    assert decode_b64(p11["key_b64"]) == mixed
    raw41 = enc(protected(k4=rc.cose_key_thumbprint(mixed)))
    i = 0
    while True:
        r = int.from_bytes(hashlib.sha512(f"receipt-cose mixed-order nonce {i}".encode()).digest(), "little") % L
        r_enc = compress(mul(r, BASE))
        k41 = challenge(r_enc, mixed, tbs(raw41, digest))
        if k41 % 8 == 0:
            break
        i += 1
    sig41 = r_enc + ((r + k41 * a_issuer) % L).to_bytes(32, "little")
    bwd("B41", sign1(raw41, digest, sig41), "P1", "untrusted_key",
        "a statement under the mixed-order key of Draft 1 vector P11 (the issuer's point plus a point of order "
        "8), with a signature that meets the cofactorless equation: the key is not of order L, so rule 2 of "
        "Section 4.4 refuses it as a statement key and no pair counts", statement_keys=((ISSUER, "mixed_order"),))
    # ---- added 2026-10-07, rule 2 is order L: an R of mixed order under the issuer key -----------------------
    raw42 = enc(protected())
    r = int.from_bytes(hashlib.sha512(b"receipt-cose mixed-order R nonce").digest(), "little") % L
    r_point = add(mul(r, BASE), order8_point())
    r_enc = compress(r_point)
    k42 = challenge(r_enc, issuer_pub, tbs(raw42, digest))
    s42 = (r + k42 * a_issuer) % L
    lhs, rhs = mul(s42, BASE), add(r_point, mul(k42, mul(a_issuer, BASE)))
    assert compress(mul(8, lhs)) == compress(mul(8, rhs)) and compress(lhs) != compress(rhs)
    bwd("B42", sign1(raw42, digest, r_enc + s42.to_bytes(32, "little")), "P1", "signature_invalid",
        "a signature whose R has mixed order (r times the base point plus the point of order 8), made with the "
        "issuer test seed: the cofactored equation holds and the cofactorless one does not; rule 2 of Section "
        "4.4 of the receipts draft refuses R before the equation")
    # ---- added 2026-10-07 after a differential run against a second checker built from the draft's text ------
    iss_raw = ISSUER.encode()
    bad_iss = iss_raw[:8] + b"\xff" + iss_raw[9:]
    assert f1.count(iss_raw) == 1
    bwd("B43", f1.replace(iss_raw, bad_iss, 1), "P1", "malformed",
        "B1 with one byte of iss replaced by 0xff, which is no UTF-8: a well-formed but not valid data item "
        "(RFC 8949 section 5.3.1), signature unchanged")
    b1_pairs = [(enc(k), enc(v)) for k, v in protected().items()]
    raw44 = head(5, 6) + b"".join(k + v for k, v in sorted(b1_pairs + [(b"\xa0", enc(0))]))
    bwd("B44", signed(None, protected_raw=raw44), "P1", "outside_profile",
        "B1 with an empty map as a sixth key of the protected header, in the deterministic encoding, signed over "
        "those bytes: a valid item whose header does not hold exactly the five labels")
    raw45 = head(5, 6) + b"".join(k + v for k, v in sorted(b1_pairs + [(enc(-1), enc(0))],
                                                          key=lambda kv: (len(kv[0]), kv[0])))
    assert raw45 != head(5, 6) + b"".join(k + v for k, v in sorted(b1_pairs + [(enc(-1), enc(0))]))
    bwd("B45", signed(None, protected_raw=raw45), "P1", "malformed",
        "B1 with a sixth key -1, its keys ordered length first (RFC 7049 section 3.9) instead of bytewise "
        "(RFC 8949 section 4.2.1), signed over those bytes: not the deterministic encoding")
    # B46 to B48 (2026-10-07): a sixth entry whose key or value is of a kind a statement never holds there,
    # in the deterministic encoding and signed over those bytes. Step 1 checks well-formedness, validity
    # under RFC 8949 section 5.3.1 and the deterministic encoding, also of the data items inside a tag, but
    # not whether a tag's content is valid for that tag (section 5.3.2); step 2 refuses.
    for vid, key, value, what in (
            ("B46", b"\xf9\x3e\x00", enc(0), "the float 1.5 (half precision) as a sixth key"),
            ("B47", b"\xf5", enc(0), "true as a sixth key, beside the integer label 1: two keys (RFC 8949 "
                                     "section 5.6)"),
            ("B48", enc(-1), b"\xc1\x61x", "a sixth key -1 whose value is tag 1 around the text \"x\", content "
                                           "tag 1 does not admit; step 1 does not check whether a tag's "
                                           "content is valid for that tag")):
        raw = head(5, 6) + b"".join(k + v for k, v in sorted(b1_pairs + [(key, value)]))
        bwd(vid, signed(None, protected_raw=raw), "P1", "outside_profile",
            f"B1 with {what}, in the deterministic encoding, signed over those bytes: a valid item whose header "
            "does not hold exactly the five labels")
    # B49 (2026-10-07): "[" in the path of iss. RFC 3986 admits "[" and "]" only around an IP-literal in the
    # host (sections 2.2 and 3.2.2), so the text is no absolute URI; a pair names exactly that text, so a
    # Receiver whose URI check let it through would accept the statement.
    bracket = "https://issuer.example/e[val"
    bwd("B49", signed(protected(k15={1: bracket, 2: p1_b["model_id_commit"]})), "P1", "outside_profile",
        f"B1 with iss {bracket}, signed over those bytes: \"[\" stands only in an IP-literal (RFC 3986 "
        "sections 2.2 and 3.2.2), so iss is no absolute URI (section 4.3), even where a pair names that string",
        statement_keys=((bracket, "issuer"),))
    # B50 (2026-10-07): the float 1.5 as a sixth key in single precision (fa 3fc00000), bytewise ordered and
    # signed over those bytes. 1.5 fits half precision (f9 3e00), so this is not the shortest form RFC 8949
    # section 4.2.1 requires: step 1, malformed, before the kind of the key is ever asked.
    raw50 = head(5, 6) + b"".join(k + v for k, v in sorted(b1_pairs + [(b"\xfa\x3f\xc0\x00\x00", enc(0))]))
    bwd("B50", signed(None, protected_raw=raw50), "P1", "malformed",
        "B1 with the float 1.5 as a sixth key in single precision (fa 3fc00000), signed over those bytes: the "
        "value fits half precision, so the float is not in its shortest form (RFC 8949 section 4.2.1)")
    keys_out = {"issuer": issuer_pub.hex(), "foreign": foreign_pub.hex(), "low_order": low_order.hex(),
                "p256": p256_pub.hex(), "off_curve": off_curve.hex(), "mixed_order": mixed.hex()}

    out = {
        "notice": "PURE TEST KEYS. They MUST NOT be used for anything real.",
        "generator": "tools/receipt_cose_vectors/generate.py",
        "receipts": "tests/fixtures/signed_eval_receipt/draft1_vectors.json, by vector id",
        "receipt_key": "issuer",
        "issuer": ISSUER,
        "statement_keys": "pairs of [the issuer URI the relying party trusts the key for, the key's name in keys_hex]",
        "foreign_seed": f"SHA-256 over the UTF-8 bytes of {FOREIGN_SEED_LABEL!r}",
        "p256_seed": f"private scalar: SHA-256 over the UTF-8 bytes of {P256_SEED_LABEL!r}, big-endian",
        "keys_hex": keys_out,
        "forward": forward,
        "backward": backward,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"{OUT.relative_to(REPO)}: {len(forward)} forward, {len(backward)} backward, "
          f"sha256 {hashlib.sha256(OUT.read_bytes()).hexdigest()}")


class _Drop:
    pass


_DROP = _Drop()

if __name__ == "__main__":
    main()
