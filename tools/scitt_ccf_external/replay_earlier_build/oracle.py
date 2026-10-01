#!/usr/bin/env python3
"""An independent oracle for the replay on an earlier CCF build: C(n) from the request bytes alone.

It owes nothing to the library under test. It imports nothing from proofbundle; it reads CBOR with its own
code from the standard library, and only the receipt's ECDSA signature is checked with `cryptography`.

    python3 oracle.py --request request.hex [--receipt receipt.hex --returned statement.hex --keyset scitt-keys.hex]
                      [--outcome registered|refused] [--stage STAGE] [--error TEXT]

From the request it takes only three contents: the protected header bstr, the payload bstr and the signature
bstr. It rebuilds

    C(n) = tag 18 ( [ protected, {}, payload, signature ] )

with each bstr in preferred (shortest) framing and an empty unprotected map, and hashes it with SHA-256. With a
receipt it reads the data-hash from the leaf of every inclusion proof (label 396, key -1), recomputes the Merkle
root, and verifies the receipt's signature under the service key set given (a COSE_KeySet, the key selected by
the receipt's kid). With a returned statement it removes label 394 from the unprotected map and compares the
result, re-emitted in the same framing, with C(n). It prints one JSON object.

A refused row has no receipt, so there is no commitment result: the receipt fields stay null, never false. The
oracle gives no verdict about any statement or receipt shape beyond these comparisons.

Each request.hex, receipt.hex, statement.hex and scitt-keys.hex holds lowercase hex, one line.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

RECEIPTS, VDP, INCLUSION = 394, 396, -1
ALG, KID = 1, 4


class NotCbor(ValueError):
    """The bytes are not CBOR this oracle reads (definite lengths only, no floats)."""


class NotCoseSign1(ValueError):
    """The bytes are not a tagged COSE_Sign1 with a definite four-element array."""


class Tag:
    def __init__(self, tag: int, value):
        self.tag, self.value = tag, value

    def __eq__(self, other):
        return isinstance(other, Tag) and (self.tag, self.value) == (other.tag, other.value)


# --------------------------------------------------------------------------------------------- CBOR, read
def _head(b: bytes, i: int) -> tuple[int, int, int]:
    """(major type, argument, next index). Any argument width is read; indefinite lengths are refused."""
    if i >= len(b):
        raise NotCbor("truncated")
    mt, ai = b[i] >> 5, b[i] & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
    if width is None:
        raise NotCbor(f"additional information {ai} (indefinite length or reserved) at byte {i - 1}")
    if i + width > len(b):
        raise NotCbor("truncated argument")
    return mt, int.from_bytes(b[i:i + width], "big"), i + width


def decode(b: bytes, i: int = 0, depth: int = 0):
    """(value, next index) for one data item."""
    if depth > 64:
        raise NotCbor("nested too deeply")
    mt, arg, i = _head(b, i)
    if mt == 0:
        return arg, i
    if mt == 1:
        return -1 - arg, i
    if mt in (2, 3):
        if i + arg > len(b):
            raise NotCbor("truncated string")
        raw = b[i:i + arg]
        return (raw if mt == 2 else raw.decode("utf-8")), i + arg
    if mt == 4:
        out = []
        for _ in range(arg):
            v, i = decode(b, i, depth + 1)
            out.append(v)
        return out, i
    if mt == 5:
        m = {}
        for _ in range(arg):
            k, i = decode(b, i, depth + 1)
            if not isinstance(k, (int, str, bytes)):
                raise NotCbor("a map key that is not an integer or a string")
            v, i = decode(b, i, depth + 1)
            m[k] = v
        return m, i
    if mt == 6:
        v, i = decode(b, i, depth + 1)
        return Tag(arg, v), i
    simple = {20: False, 21: True, 22: None}
    if arg in simple:
        return simple[arg], i
    raise NotCbor(f"simple value or float {arg} is not read here")


def loads(b: bytes):
    v, i = decode(b)
    if i != len(b):
        raise NotCbor(f"{len(b) - i} bytes after the data item")
    return v


# -------------------------------------------------------------------------------------------- CBOR, write
def _ehead(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([mt << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([mt << 5 | ai]) + n.to_bytes(width, "big")
    raise NotCbor("argument too large")


def encode(o) -> bytes:
    """Preferred serialization; maps keep the order they were read in."""
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if o is None:
        return b"\xf6"
    if isinstance(o, int):
        return _ehead(0, o) if o >= 0 else _ehead(1, -1 - o)
    if isinstance(o, bytes):
        return _ehead(2, len(o)) + o
    if isinstance(o, str):
        raw = o.encode("utf-8")
        return _ehead(3, len(raw)) + raw
    if isinstance(o, list):
        return _ehead(4, len(o)) + b"".join(encode(x) for x in o)
    if isinstance(o, dict):
        return _ehead(5, len(o)) + b"".join(encode(k) + encode(v) for k, v in o.items())
    if isinstance(o, Tag):
        return _ehead(6, o.tag) + encode(o.value)
    raise NotCbor(f"cannot encode {type(o).__name__}")


# ------------------------------------------------------------------------------------------------ COSE_Sign1
def sign1_parts(raw: bytes) -> dict:
    """The four elements of a tagged COSE_Sign1: protected and signature as bstr contents, the unprotected map
    as read, and the payload as a bstr content (None when detached)."""
    try:
        v = loads(raw)
    except NotCbor as exc:
        raise NotCoseSign1(f"not readable: {exc}") from None
    if not isinstance(v, Tag) or v.tag != 18:
        raise NotCoseSign1("not tagged 18")
    a = v.value
    if not isinstance(a, list) or len(a) != 4:
        raise NotCoseSign1("tag 18 does not hold a four-element array")
    prot, unprot, payload, sig = a
    if not isinstance(prot, bytes) or not isinstance(unprot, dict) or not isinstance(sig, bytes) \
            or not (payload is None or isinstance(payload, bytes)):
        raise NotCoseSign1("the elements are not [bstr, map, bstr or nil, bstr]")
    return {"protected": prot, "unprotected": unprot, "payload": payload, "signature": sig}


def rebuild(raw: bytes) -> bytes:
    """C(n): tag 18, the request's protected, payload and signature contents in preferred framing, {}."""
    p = sign1_parts(raw)
    if p["payload"] is None:
        raise NotCoseSign1("detached payload: C(n) needs the payload content")
    return b"\xd2\x84" + encode(p["protected"]) + b"\xa0" + encode(p["payload"]) + encode(p["signature"])


# ---------------------------------------------------------------------------------------------- the receipt
def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _keys(raw: bytes) -> dict:
    """kid -> public key, EC2 keys of a COSE_KeySet."""
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    curves = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}
    out = {}
    for k in loads(raw):
        if isinstance(k, dict) and k.get(1) == 2 and k.get(-1) in curves:
            out[k.get(2)] = ec.EllipticCurvePublicNumbers(int.from_bytes(k[-2], "big"), int.from_bytes(k[-3], "big"),
                                                          curves[k[-1]]).public_key()
    return out


def _verify(alg: int, key, tbs: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: PLC0415

    hashes_by_alg = {-7: (hashes.SHA256, 32, "secp256r1"), -35: (hashes.SHA384, 48, "secp384r1"),
                     -36: (hashes.SHA512, 66, "secp521r1")}
    if alg not in hashes_by_alg:
        raise NotCoseSign1(f"receipt algorithm {alg} is not read here")
    h, n, curve = hashes_by_alg[alg]
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != curve or len(sig) != 2 * n:
        return False
    der = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
    try:
        key.verify(der, tbs, ec.ECDSA(h()))
    except InvalidSignature:
        return False
    return True


def read_receipt(raw: bytes) -> dict:
    """The data-hash, the Merkle root and what the signature needs, from a receipt."""
    p = sign1_parts(raw)
    ph = loads(p["protected"])
    proofs = (p["unprotected"].get(VDP) or {}).get(INCLUSION) if isinstance(p["unprotected"].get(VDP), dict) else None
    if not isinstance(ph, dict) or not isinstance(proofs, list) or not proofs:
        raise NotCoseSign1("no inclusion proof under 396 / -1")
    hashes_seen, roots = set(), set()
    for pr in proofs:
        d = loads(pr)
        itx, evidence, dh = d[1]
        h = _sha(itx + _sha(evidence.encode("utf-8")) + dh)
        for left, sibling in d[2]:
            h = _sha(sibling + h) if left else _sha(h + sibling)
        hashes_seen.add(dh)
        roots.add(h)
    if len(hashes_seen) != 1 or len(roots) != 1:
        raise NotCoseSign1("the inclusion proofs disagree")
    ccf = ph.get("ccf.v1") if isinstance(ph.get("ccf.v1"), dict) else {}
    return {"data_hash": hashes_seen.pop(), "root": roots.pop(), "protected": p["protected"], "alg": ph.get(ALG),
            "kid": ph.get(KID), "signature": p["signature"], "txid": ccf.get("txid")}


# ------------------------------------------------------------------------------------------------ the check
def check(request: bytes, receipt: bytes | None = None, returned: bytes | None = None, keyset: bytes | None = None,
          outcome: str | None = None, stage: str | None = None, error: str | None = None) -> dict:
    c = rebuild(request)
    rep = {"request_sha256": hashlib.sha256(request).hexdigest(), "rebuilt_sha256": hashlib.sha256(c).hexdigest(),
           "rebuilt_length": len(c), "registration_outcome": outcome, "refusal_stage": stage, "raw_error": error,
           "receipt_data_hash": None, "data_hash_match": None, "merkle_root": None, "receipt_txid": None,
           "receipt_kid": None, "receipt_signature_valid": None, "receipt_signature_note": None,
           "returned_statement_sha256": None, "returned_unprotected_labels": None,
           "rebuilt_equals_returned_minus_394": None}
    if receipt is not None:
        r = read_receipt(receipt)
        rep.update(receipt_data_hash=r["data_hash"].hex(), data_hash_match=r["data_hash"] == _sha(c),
                   merkle_root=r["root"].hex(), receipt_txid=r["txid"],
                   receipt_kid=r["kid"].decode("ascii", "replace") if isinstance(r["kid"], bytes) else r["kid"])
        if keyset is None:
            rep["receipt_signature_note"] = "not evaluated: no service key set given"
        else:
            key = _keys(keyset).get(r["kid"])
            if key is None:
                rep["receipt_signature_note"] = "not evaluated: the receipt's kid is not in the key set given"
            else:
                tbs = encode(["Signature1", r["protected"], b"", r["root"]])
                rep["receipt_signature_valid"] = _verify(r["alg"], key, tbs, r["signature"])
                rep["receipt_signature_note"] = "verified over the recomputed root, key selected by kid"
    if returned is not None:
        rep["returned_statement_sha256"] = hashlib.sha256(returned).hexdigest()
        p = sign1_parts(returned)
        rep["returned_unprotected_labels"] = sorted(p["unprotected"], key=str)
        rest = {k: v for k, v in p["unprotected"].items() if k != RECEIPTS}
        if p["payload"] is None:
            rep["rebuilt_equals_returned_minus_394"] = False
        else:
            minus = b"\xd2\x84" + encode(p["protected"]) + encode(rest) + encode(p["payload"]) + encode(p["signature"])
            rep["rebuilt_equals_returned_minus_394"] = minus == c
    return rep


def _hex(path: str | None) -> bytes | None:
    return None if path is None else bytes.fromhex(Path(path).read_text(encoding="ascii").strip())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--request", required=True)
    ap.add_argument("--receipt")
    ap.add_argument("--returned")
    ap.add_argument("--keyset")
    ap.add_argument("--outcome", choices=("registered", "refused", "timeout", "unfinished"))
    ap.add_argument("--stage")
    ap.add_argument("--error")
    a = ap.parse_args(argv)
    try:
        rep = check(_hex(a.request), _hex(a.receipt), _hex(a.returned), _hex(a.keyset), a.outcome, a.stage, a.error)
    except (NotCbor, NotCoseSign1) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    print(json.dumps(rep, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
