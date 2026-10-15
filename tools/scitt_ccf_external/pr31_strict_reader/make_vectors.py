#!/usr/bin/env python3
"""The vectors of pull request 31 that the 24 probes do not carry, written to ``vectors/``.

The probes in ``probes/`` (taken unchanged from a separate generator) repeat a duplicate key with the SAME value, so a reader
that keeps the first value and one that keeps the last one agree there. These vectors make them disagree:

* ``dup_leaf_*`` and ``dup_path_*``: one inclusion proof whose map carries key 1 (leaf) or key 2 (path) twice with
  two DIFFERENT values. The receipt is signed over the root of exactly one of the two readings, named in the vector:
  ``first`` means a first-wins reader verifies it and a last-wins reader does not, ``last`` the other way round. A
  strict reader refuses both. ``dup_twin`` is the same receipt with one leaf and one path, signed, as the control.
* ``vdp_*`` (commit f6d4eb04): a valid inclusion proof next to an empty consistency-proof array, a duplicate key in
  the vdp map, and an unknown vdp key, each with a valid twin.
* ``empty_map_*``: one statement whose unprotected header is not empty, and three receipts whose data
  hash is the SHA-256 of the statement with that header replaced by ``a0``, by ``b8 00`` or by ``bf ff``. A reader
  that writes the empty map as ``a0`` verifies the first and refuses the other two with a data-hash mismatch.

The key is the fixed TEST key of ``probes/sonden.py`` (a constant, no secret). Signatures are deterministic ECDSA
(RFC 6979), so running this again writes the same bytes. Standard library and ``cryptography`` only; no cbor2, and
the duplicate keys are written byte by byte because no encoder writes them.

Usage: make_vectors.py [OUTPUT DIRECTORY]   (default: vectors/ next to this file)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

HERE = Path(__file__).resolve().parent
#: The constant of probes/sonden.py, line 7: a TEST key, published on purpose.
SK = ec.derive_private_key(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678,
                           ec.SECP384R1())
KID = b"sonde-kid-1"


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | ai]) + n.to_bytes(width, "big")
    raise ValueError(n)


def uint(n: int) -> bytes:
    return head(0, n) if n >= 0 else head(1, -1 - n)


def bs(b: bytes) -> bytes:
    return head(2, len(b)) + b


def ts(s: bytes) -> bytes:
    return head(3, len(s)) + s


def arr(items: list) -> bytes:
    return head(4, len(items)) + b"".join(items)


def cmap(pairs: list) -> bytes:
    """A map written pair by pair, so a key can occur twice."""
    return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


ITS, DH, S1, S2, S3 = H(b"its"), H(b"statement"), H(b"s1"), H(b"s2"), H(b"s3")
EV = b"ce:2.5:" + b"a" * 64
EV_OTHER = b"ce:2.5:" + b"b" * 64


def leaf(ev: bytes = EV, dh: bytes = DH) -> bytes:
    return arr([bs(ITS), ts(ev), bs(dh)])


def path(els: list) -> bytes:
    return arr([arr([b"\xf5" if left else b"\xf4", bs(x)]) for left, x in els])


PATH_A = [(True, S1), (False, S2)]
PATH_B = [(False, S3), (True, S1)]


def root(ev: bytes = EV, els: list = PATH_A, dh: bytes = DH) -> bytes:
    h = H(ITS + H(ev) + dh)
    for left, x in els:
        h = H(x + h) if left else H(h + x)
    return h


def protected() -> bytes:
    return cmap([(uint(1), uint(-35)), (uint(4), bs(KID)), (uint(395), uint(2))])


def receipt(vdp_pairs: list, signed_root: bytes) -> bytes:
    prot = protected()
    text = b"Signature1"
    tbs = arr([ts(text), bs(prot), bs(b""), bs(signed_root)])
    r, s = utils.decode_dss_signature(SK.sign(tbs, ec.ECDSA(hashes.SHA384(), deterministic_signing=True)))
    signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    unprotected = cmap([(uint(396), cmap(vdp_pairs))])
    return b"\xd2" + arr([bs(prot), unprotected, b"\xf6", bs(signature)])


def proof(pairs: list) -> bytes:
    return cmap(pairs)


def inclusion(*proofs: bytes) -> tuple:
    return (uint(-1), arr([bs(p) for p in proofs]))


def keyset() -> bytes:
    pn = SK.public_key().public_numbers()
    return arr([cmap([(uint(1), uint(2)), (uint(2), bs(KID)), (uint(-1), uint(2)),
                      (uint(-2), bs(pn.x.to_bytes(48, "big"))), (uint(-3), bs(pn.y.to_bytes(48, "big")))])])


def statement() -> bytes:
    """A tagged COSE_Sign1 whose unprotected header is NOT empty; its own signature is not checked here."""
    prot = cmap([(uint(1), uint(-7))])
    unprotected = cmap([(uint(99), ts(b"carried after signing"))])
    return b"\xd2" + arr([bs(prot), unprotected, bs(b"payload"), bs(b"\x00" * 64)])


def preimage(stmt: bytes, empty_map: bytes) -> bytes:
    """The statement with its unprotected header (written by statement() as a1 18 63 ...) replaced by empty_map."""
    prot = cmap([(uint(1), uint(-7))])
    unprotected = cmap([(uint(99), ts(b"carried after signing"))])
    start = 2 + len(bs(prot))
    assert stmt[start:start + len(unprotected)] == unprotected
    return stmt[:start] + empty_map + stmt[start + len(unprotected):]


def vectors() -> dict:
    good = proof([(uint(1), leaf()), (uint(2), path(PATH_A))])
    v = {}
    # Duplicate leaf: values EV and EV_OTHER; the root of the reading named in "signed_for" is signed.
    for order, first, second in (("first", EV, EV_OTHER), ("last", EV_OTHER, EV)):
        p = proof([(uint(1), leaf(first)), (uint(2), path(PATH_A)), (uint(1), leaf(second))])
        v[f"dup_leaf_{order}"] = (receipt([inclusion(p)], root(EV)), DH, None, {
            "signed_for": order, "strict": "FAIL", "first_wins": "PASS" if order == "first" else "FAIL",
            "last_wins": "PASS" if order == "last" else "FAIL"})
    for order, first, second in (("first", PATH_A, PATH_B), ("last", PATH_B, PATH_A)):
        p = proof([(uint(1), leaf()), (uint(2), path(first)), (uint(2), path(second))])
        v[f"dup_path_{order}"] = (receipt([inclusion(p)], root(EV, PATH_A)), DH, None, {
            "signed_for": order, "strict": "FAIL", "first_wins": "PASS" if order == "first" else "FAIL",
            "last_wins": "PASS" if order == "last" else "FAIL"})
    v["dup_twin"] = (receipt([inclusion(good)], root()), DH, None, {"strict": "PASS"})
    # The vdp map (f6d4eb04), each with its twin.
    v["vdp_empty_consistency"] = (receipt([inclusion(good), (uint(-2), arr([]))], root()), DH, None,
                                  {"strict": "FAIL", "twin": "vdp_twin"})
    v["vdp_duplicate_key"] = (receipt([inclusion(good), inclusion(good)], root()), DH, None,
                              {"strict": "FAIL", "twin": "vdp_twin"})
    v["vdp_unknown_key"] = (receipt([inclusion(good), (uint(-3), arr([bs(good)]))], root()), DH, None,
                            {"strict": "FAIL", "twin": "vdp_twin"})
    v["vdp_twin"] = (receipt([inclusion(good)], root()), DH, None, {"strict": "PASS"})
    # The empty map in the data-hash preimage, written as a0, b8 00 and bf ff.
    stmt = statement()
    for name, em in (("a0", b"\xa0"), ("b8_00", b"\xb8\x00"), ("bf_ff", b"\xbf\xff")):
        dh = H(preimage(stmt, em))
        p = proof([(uint(1), leaf(dh=dh)), (uint(2), path(PATH_A))])
        v[f"empty_map_{name}"] = (receipt([inclusion(p)], root(dh=dh)), dh, stmt, {
            "strict": "PASS" if name == "a0" else "FAIL", "preimage_empty_map_hex": em.hex()})
    return v


def main(argv: list) -> int:
    out = Path(argv[1]) if len(argv) > 1 else HERE / "vectors"
    out.mkdir(parents=True, exist_ok=True)
    (out / "keys.cbor").write_bytes(keyset())
    (out / "statement.cose").write_bytes(statement())
    index = {}
    for name, (rec, dh, stmt, expect) in sorted(vectors().items()):
        (out / f"{name}.cose").write_bytes(rec)
        index[name] = {"receipt_sha256": hashlib.sha256(rec).hexdigest(), "data_hash_hex": dh.hex(),
                       "statement": "statement.cose" if stmt is not None else None, **expect}
    (out / "vectors.json").write_text(json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(len(index), "vectors in", out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
