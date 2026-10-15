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
* ``label_*``: a key that equals an integer label in Python but is another data item (``1.0``, ``true``, ``-1.0``,
  ``396.0``) in the proof map, the vdp map, the unprotected header or the protected header. Only the unprotected
  part changes for the first five, so the signature stays valid without the key; a reader that looks labels up as
  Python values reads them as the integers. A label is ``int / tstr`` (RFC 9052 Section 1.4).
* ``evidence_*``, ``its_33``, ``form_*``: one requirement each that no probe exercises, with its control: a code point
  spread between two chunks of the evidence (RFC 8949 Section 3.2.3), 1024 and 1026 bytes of evidence in 512 and 513
  two-byte characters, evidence of one byte, an ``internal-transaction-hash`` of 33 bytes, evidence as a byte string,
  receipts whose tag, array, headers, vdp map, proof or leaf have another form, and a protected header longer than 255
  bytes.
* ``roots_differ_signed_for_the_second``: two inclusion proofs with different roots, signed for the second one, so a
  reader that keeps the last root it computed verifies the signature.
* ``signature_padded``: the signature of ``vdp_twin`` with a zero byte in front of r and of s (RFC 9053 Section 2.1
  fixes the length of each).
* ``curve_p256_es256``, ``curve_p521_es512``: valid receipts under two more fixed TEST keys, in ``keys_p256_p521.cbor``.

Every vector carries ``strict_line``, the whole line this reader must print, derived from the text of pull request 31
and RFC 9052, not from a run of the reader.

The key is the fixed TEST key of the separate probe generator, which is not in this tree (a constant, no secret). Signatures are deterministic ECDSA
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
#: The constant of the separate probe generator (its file sonden.py, line 7): a TEST key, published on purpose.
SK = ec.derive_private_key(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678,
                           ec.SECP384R1())
KID = b"sonde-kid-1"
#: Two more TEST keys, constants published on purpose, for the other two curves of the reader.
SK_P256 = ec.derive_private_key(0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a, ec.SECP256R1())
SK_P521 = ec.derive_private_key(0x5215215215215215215215215215215215215215215215215215215215215215, ec.SECP521R1())
KID_P256, KID_P521 = b"test-kid-p256", b"test-kid-p521"


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


def leaf(ev: bytes = EV, dh: bytes = DH, its: bytes = ITS, ev_item: bytes | None = None) -> bytes:
    return arr([bs(its), ts(ev) if ev_item is None else ev_item, bs(dh)])


def path(els: list) -> bytes:
    return arr([arr([b"\xf5" if left else b"\xf4", bs(x)]) for left, x in els])


PATH_A = [(True, S1), (False, S2)]
PATH_B = [(False, S3), (True, S1)]


def root(ev: bytes = EV, els: list = PATH_A, dh: bytes = DH, its: bytes = ITS) -> bytes:
    h = H(its + H(ev) + dh)
    for left, x in els:
        h = H(x + h) if left else H(h + x)
    return h


def protected(alg_label: bytes = b"\x01", alg: bytes = b"\x38\x22", vds: bytes = b"\x02", kid: bytes = KID,
              extra: list = ()) -> bytes:
    """alg -35 (written 38 22) under label 1, the kid under 4, VDS 2 under 395, and any extra pairs."""
    return cmap([(alg_label, alg), (uint(4), bs(kid)), (uint(395), vds), *extra])


#: The key, the hash and the byte length of r and of s for each curve (RFC 9053 Section 2.1).
SIGNERS = {"p384": (SK, hashes.SHA384, 48), "p256": (SK_P256, hashes.SHA256, 32), "p521": (SK_P521, hashes.SHA512, 66)}


def sign(prot: bytes, signed_root: bytes, curve: str = "p384") -> bytes:
    sk, hash_alg, n = SIGNERS[curve]
    tbs = arr([ts(b"Signature1"), bs(prot), bs(b""), bs(signed_root)])
    r, s = utils.decode_dss_signature(sk.sign(tbs, ec.ECDSA(hash_alg(), deterministic_signing=True)))
    return r.to_bytes(n, "big") + s.to_bytes(n, "big")


def receipt(vdp_pairs: list, signed_root: bytes, *, prot: bytes | None = None, vdp_label: bytes = b"\x19\x01\x8c",
            tag: bytes = b"\xd2", unprotected: bytes | None = None, extra: list = (), curve: str = "p384",
            pad_signature: bool = False) -> bytes:
    prot = protected() if prot is None else prot
    signature = sign(prot, signed_root, curve)
    if pad_signature:
        n = len(signature) // 2
        signature = b"\x00" + signature[:n] + b"\x00" + signature[n:]
    if unprotected is None:
        unprotected = cmap([(vdp_label, cmap(vdp_pairs))])
    return tag + arr([bs(prot), unprotected, b"\xf6", bs(signature), *extra])


def proof(pairs: list) -> bytes:
    return cmap(pairs)


def inclusion(*proofs: bytes) -> tuple:
    return (uint(-1), arr([bs(p) for p in proofs]))


def _cose_key(sk, kid: bytes, crv: int, n: int) -> bytes:
    pn = sk.public_key().public_numbers()
    return cmap([(uint(1), uint(2)), (uint(2), bs(kid)), (uint(-1), uint(crv)),
                 (uint(-2), bs(pn.x.to_bytes(n, "big"))), (uint(-3), bs(pn.y.to_bytes(n, "big")))])


def keyset() -> bytes:
    return arr([_cose_key(SK, KID, 2, 48)])


def keyset_p256_p521() -> bytes:
    return arr([_cose_key(SK_P256, KID_P256, 1, 32), _cose_key(SK_P521, KID_P521, 3, 66)])


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


#: Data items that equal an integer label in Python and are other CBOR data items.
F16_1, F16_2, F16_M1, F16_396, TRUE = b"\xf9\x3c\x00", b"\xf9\x40\x00", b"\xf9\xbc\x00", b"\xf9\x5e\x30", b"\xf5"
#: A two-byte character: 512 of them are 1024 bytes, the most evidence may hold, and 513 are 1026.
U_UMLAUT = "\u00fc".encode("utf-8")


def vectors() -> dict:
    good = proof([(uint(1), leaf()), (uint(2), path(PATH_A))])
    pass_line = "PASS " + root().hex()
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
    for name, line in (("dup_leaf_first", "FAIL cbor_proof: duplicate map key 1"),
                       ("dup_leaf_last", "FAIL cbor_proof: duplicate map key 1"),
                       ("dup_path_first", "FAIL cbor_proof: duplicate map key 2"),
                       ("dup_path_last", "FAIL cbor_proof: duplicate map key 2"), ("dup_twin", pass_line)):
        v[name][3]["strict_line"] = line
    # The vdp map (f6d4eb04), each with its twin.
    v["vdp_empty_consistency"] = (receipt([inclusion(good), (uint(-2), arr([]))], root()), DH, None,
                                  {"strict": "FAIL", "twin": "vdp_twin"})
    v["vdp_duplicate_key"] = (receipt([inclusion(good), inclusion(good)], root()), DH, None,
                              {"strict": "FAIL", "twin": "vdp_twin"})
    v["vdp_unknown_key"] = (receipt([inclusion(good), (uint(-3), arr([bs(good)]))], root()), DH, None,
                            {"strict": "FAIL", "twin": "vdp_twin"})
    v["vdp_twin"] = (receipt([inclusion(good)], root()), DH, None, {"strict": "PASS"})
    for name, line in (("vdp_empty_consistency", "FAIL vdp_empty"),
                       ("vdp_duplicate_key", "FAIL cbor_receipt: duplicate map key -1"),
                       ("vdp_unknown_key", "FAIL vdp_key"), ("vdp_twin", pass_line)):
        v[name][3]["strict_line"] = line
    # Labels that are not the integer (RFC 9052 Section 1.4: label = int / tstr). The first five change only the
    # unprotected part, so the signature over the root stays valid.
    for name, pairs, line in (
            ("label_leaf_float_1_0", [(F16_1, leaf()), (uint(2), path(PATH_A))], "FAIL proof_keys"),
            ("label_leaf_true", [(TRUE, leaf()), (uint(2), path(PATH_A))], "FAIL proof_keys"),
            ("label_path_float_2_0", [(uint(1), leaf()), (F16_2, path(PATH_A))], "FAIL proof_keys")):
        v[name] = (receipt([inclusion(proof(pairs))], root()), DH, None,
                   {"strict": "FAIL", "strict_line": line, "twin": "vdp_twin"})
    v["label_vdp_float_minus_1_0"] = (receipt([(F16_M1, arr([bs(good)]))], root()), DH, None,
                                      {"strict": "FAIL", "strict_line": "FAIL vdp_key", "twin": "vdp_twin"})
    v["label_unprotected_float_396_0"] = (receipt([inclusion(good)], root(), vdp_label=F16_396), DH, None,
                                          {"strict": "FAIL", "strict_line": "FAIL unprotected_label", "twin": "vdp_twin"})
    v["label_protected_alg_true"] = (receipt([inclusion(good)], root(), prot=protected(alg_label=TRUE)), DH, None,
                                     {"strict": "FAIL", "strict_line": "FAIL protected_label", "twin": "vdp_twin"})
    v["label_protected_vds_float"] = (receipt([inclusion(good)], root(), prot=protected(vds=F16_2)), DH, None,
                                      {"strict": "FAIL", "strict_line": "FAIL vds", "twin": "vdp_twin"})
    v["label_protected_alg_value_float"] = (
        receipt([inclusion(good)], root(), prot=protected(alg=b"\xfb\xc0\x41\x80\x00\x00\x00\x00\x00")), DH, None,
        {"strict": "FAIL", "strict_line": "FAIL alg", "twin": "vdp_twin"})
    # Evidence: a code point spread between two chunks, and the byte length against the character length.
    ev_u = b"ce:2.5:" + U_UMLAUT * 4
    for name, cut, line in (("evidence_chunks_split_inside_a_code_point", 8,
                             "FAIL cbor_proof: a chunk of an indefinite text string is not valid UTF-8 on its own"),
                            ("evidence_chunks_split_at_code_points", 9, "PASS " + root(ev_u).hex())):
        item = b"\x7f" + ts(ev_u[:cut]) + ts(ev_u[cut:]) + b"\xff"
        p = proof([(uint(1), leaf(ev_u, ev_item=item)), (uint(2), path(PATH_A))])
        v[name] = (receipt([inclusion(p)], root(ev_u)), DH, None, {"strict": line.split()[0], "strict_line": line})
    for n, line in ((512, None), (513, "FAIL evidence_len")):
        ev = U_UMLAUT * n
        p = proof([(uint(1), leaf(ev)), (uint(2), path(PATH_A))])
        line = line or "PASS " + root(ev).hex()
        v[f"evidence_{n}_two_byte_characters"] = (receipt([inclusion(p)], root(ev)), DH, None,
                                                  {"strict": line.split()[0], "strict_line": line})
    p = proof([(uint(1), arr([bs(ITS), bs(EV), bs(DH)])), (uint(2), path(PATH_A))])
    v["evidence_as_byte_string"] = (receipt([inclusion(p)], root()), DH, None,
                                    {"strict": "FAIL", "strict_line": "FAIL evidence"})
    its33 = ITS + b"\x00"
    p = proof([(uint(1), leaf(its=its33)), (uint(2), path(PATH_A))])
    v["its_33"] = (receipt([inclusion(p)], root(its=its33)), DH, None, {"strict": "FAIL", "strict_line": "FAIL leaf_hash"})
    # Two proofs whose roots differ, signed for the second one; a padded signature; a short evidence.
    p_a = proof([(uint(1), leaf()), (uint(2), path(PATH_A))])
    p_b = proof([(uint(1), leaf()), (uint(2), path(PATH_B))])
    v["roots_differ_signed_for_the_second"] = (receipt([inclusion(p_a, p_b)], root(EV, PATH_B)), DH, None,
                                               {"strict": "FAIL", "strict_line": "FAIL roots"})
    v["signature_padded"] = (receipt([inclusion(good)], root(), pad_signature=True), DH, None,
                             {"strict": "FAIL", "strict_line": "FAIL signature", "twin": "vdp_twin"})
    p = proof([(uint(1), leaf(b"e")), (uint(2), path(PATH_A))])
    v["evidence_1_byte"] = (receipt([inclusion(p)], root(b"e")), DH, None,
                            {"strict": "PASS", "strict_line": "PASS " + root(b"e").hex()})
    # The other two curves of the reader, each under its own TEST key in keys_p256_p521.cbor.
    for name, curve, alg, kid in (("curve_p256_es256", "p256", uint(-7), KID_P256),
                                  ("curve_p521_es512", "p521", uint(-36), KID_P521)):
        rec = receipt([inclusion(good)], root(), prot=protected(alg=alg, kid=kid), curve=curve)
        v[name] = (rec, DH, None, {"strict": "PASS", "strict_line": pass_line, "keys": "keys_p256_p521.cbor"})
    # A protected header longer than 255 bytes, so its byte string head takes two bytes of length.
    big = protected(extra=[(uint(99), bs(b"x" * 300))])
    v["form_protected_header_over_255_bytes"] = (receipt([inclusion(good)], root(), prot=big), DH, None,
                                                 {"strict": "PASS", "strict_line": pass_line})
    # Forms of the receipt, the headers, the vdp map, the proof and the leaf.
    for name, rec, line in (
            ("form_leaf_of_two", receipt([inclusion(proof([(uint(1), arr([bs(ITS), ts(EV)])),
                                                          (uint(2), path(PATH_A))]))], root()), "FAIL leaf"),
            ("form_leaf_of_four", receipt([inclusion(proof([(uint(1), arr([bs(ITS), ts(EV), bs(DH), bs(DH)])),
                                                           (uint(2), path(PATH_A))]))], root()), "FAIL leaf"),
            ("form_leaf_a_map", receipt([inclusion(proof([(uint(1), cmap([(uint(1), bs(ITS))])),
                                                         (uint(2), path(PATH_A))]))], root()), "FAIL leaf"),
            ("form_vdp_missing", receipt([], root(), unprotected=cmap([(uint(99), bs(b"x"))])), "FAIL vdp"),
            ("form_tag_17", receipt([inclusion(good)], root(), tag=b"\xd1"), "FAIL tag"),
            ("form_five_elements", receipt([inclusion(good)], root(), extra=[b"\xf6"]), "FAIL struct"),
            ("form_unprotected_not_a_map", receipt([], root(), unprotected=bs(b"\xa0")), "FAIL struct"),
            ("form_protected_not_a_map", receipt([inclusion(good)], root(), prot=arr([uint(1)])), "FAIL protected"),
            ("form_vdp_without_inclusion", receipt([(uint(-2), arr([bs(b"\xa0")]))], root()), "FAIL vdp"),
            ("form_proof_not_a_map", receipt([inclusion(arr([leaf(), path(PATH_A)]))], root()), "FAIL vdp_map")):
        v[name] = (rec, DH, None, {"strict": "FAIL", "strict_line": line, "twin": "vdp_twin"})
    # The empty map in the data-hash preimage, written as a0, b8 00 and bf ff.
    stmt = statement()
    for name, em in (("a0", b"\xa0"), ("b8_00", b"\xb8\x00"), ("bf_ff", b"\xbf\xff")):
        dh = H(preimage(stmt, em))
        p = proof([(uint(1), leaf(dh=dh)), (uint(2), path(PATH_A))])
        v[f"empty_map_{name}"] = (receipt([inclusion(p)], root(dh=dh)), dh, stmt, {
            "strict": "PASS" if name == "a0" else "FAIL", "preimage_empty_map_hex": em.hex(),
            "strict_line": "PASS " + root(dh=dh).hex() if name == "a0" else "FAIL digest_mismatch"})
    return v


def main(argv: list) -> int:
    out = Path(argv[1]) if len(argv) > 1 else HERE / "vectors"
    out.mkdir(parents=True, exist_ok=True)
    (out / "keys.cbor").write_bytes(keyset())
    (out / "keys_p256_p521.cbor").write_bytes(keyset_p256_p521())
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
