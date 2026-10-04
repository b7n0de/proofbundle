"""Generate tests/fixtures/receipt_cose/vectors.json: the vectors of the receipt <-> COSE_Sign1 translator.

Forward vectors run ``proofbundle.receipt_cose.receipt_to_statement`` on receipts of the Draft 1 fixture
(tests/fixtures/signed_eval_receipt/draft1_vectors.json). Backward vectors are statements built here,
byte by byte, with an encoder of this script's own, so that a negative vector differs from a valid one in
the one property it names and is signed where its point is not the signature. Every value is
deterministic; two runs write the same bytes.

Keys: the receipt key and the relying party's statement key are the issuer test key of Draft 1 (its seed
is in the Draft 1 fixture), as in vector M2 of draft-gruszka-evaluation-receipt-mappings-00. The foreign
key's seed is SHA-256 over FOREIGN_SEED_LABEL. PURE TEST KEYS. They MUST NOT be used for anything real.

Run from the repository root: ``python tools/receipt_cose_vectors/generate.py`` (needs the [scitt] extra).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from proofbundle import receipt_cose as rc  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402
from proofbundle.signed_eval_receipt import RECEIPT_TYPE  # noqa: E402

DRAFT1 = REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json"
OUT = REPO / "tests" / "fixtures" / "receipt_cose" / "vectors.json"
ISSUER = "https://issuer.example/eval"
FOREIGN_SEED_LABEL = "receipt-cose foreign statement key, PURE TEST KEY"
#: The Draft 1 PURE TEST seed of the issuer key, written out; main() holds it equal to the fixture's seed.
DRAFT_TEST_SEED = b'#eR\x04\x10t\x8d\xe8w\x8bTD\x10\xb1W\x92\xfc\xf1t\xe0\xfb\xa4\x80j\x8c\x1a\xfb\xdb\xb0\x94k\x07'


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
    f2 = fwd("F2", "P1", -8, "issuer", "P1 with alg -8: the same rule, only label 1 differs")
    fwd("F3", "P4", -19, "issuer", "P4, other receipt bytes of the same B: the statement of F1 again")
    fwd("F4", "N7", -19, "issuer", "N7 fails step 11 of the receipt procedure: no statement")
    fwd("F5", "P1", -19, "foreign", "P1 under a key the receipt was not made with: fails step 10, no statement")
    f6 = fwd("F6", "P2", -19, "issuer", "P2, another B: the statement B4 presents with P1")
    assert f1 and f2 and f6 and forward[2]["statement_hex"] == f1.hex()

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

    def bwd(vid, statement, rid, status, what, statement_keys=("issuer",), algs=None):
        item = {"id": vid, "statement_hex": statement.hex(), "receipt": rid, "statement_keys": list(statement_keys),
                "expect_status": status, "what": what}
        if algs is not None:
            item["algs"] = list(algs)
        backward.append(item)

    bwd("B1", f1, "P1", "accepted", "F1 (alg -19) with the receipt it was made from")
    bwd("B2", f2, "P1", "accepted", "F2 (alg -8) with the receipt it was made from")
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
    bwd("B10", f2, "P1", "outside_profile", "alg -8 where the relying party accepts -19 only", algs=(-19,))
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
        statement_keys=("low_order",))
    keys_out = {"issuer": issuer_pub.hex(), "foreign": foreign_pub.hex(), "low_order": low_order.hex()}

    out = {
        "notice": "PURE TEST KEYS. They MUST NOT be used for anything real.",
        "generator": "tools/receipt_cose_vectors/generate.py",
        "receipts": "tests/fixtures/signed_eval_receipt/draft1_vectors.json, by vector id",
        "receipt_key": "issuer",
        "issuer": ISSUER,
        "foreign_seed": f"SHA-256 over the UTF-8 bytes of {FOREIGN_SEED_LABEL!r}",
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
