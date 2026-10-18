#!/usr/bin/env python3
"""Steps 3 and 4 of the checking procedure of draft-gruszka-evaluation-receipt-mappings-03, key profile, against
statement keys and signatures the backend would take (draft_body.md, Section 5.2, steps 3 and 4).

Step 3: a configured pair counts only if its statement key is 32 octets and its point A meets rules 1 and 2 of the
receipts draft's Section 4.4, a canonical encoding of a point of order L; a point of small order or of mixed order
does not count, and with no pair that counts the status is untrusted_key, before any signature is read. Step 4: the
signature meets the four rules of that Section 4.4, R as well as S, with the Sig_structure in place of PAE(type, B).

The keys here are made at run time: the eight points of small order, in every encoding that decodes to one of them,
and a fresh key from os.urandom, alone and with a point of order 8 added. No key is stored in this file.

Run: python3 -m unittest test_check_mappings   (in this folder)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SER = HERE.parent.parent / "ser" / "examples"
sys.path[:0] = [str(HERE), str(SER)]

try:   # the checker reads CBOR with cbor2 and certificates with cryptography; without them it does not run
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import check_mappings as cm
    import check_receipts as cr
except ImportError as exc:   # a clean skip of the module, never an error at collection
    raise unittest.SkipTest(f"{exc.name} is not installed") from None

P, L = cr.P, cr.L
#: A point of order 8 in its canonical encoding; the eight points of small order are its multiples.
ORDER_8 = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
ZERO_S = bytes(32)


def affine(pt):
    zi = pow(pt[2], P - 2, P)
    return pt[0] * zi % P, pt[1] * zi % P


def encode(pt) -> bytes:
    x, y = affine(pt)
    return (y | (x & 1) << 255).to_bytes(32, "little")


def small_order_points():
    t = cr._dec(ORDER_8)
    return [cr._mul(i, t) for i in range(8)]


def small_order_encodings():
    """(canonical, non-canonical): the canonical encodings of the eight points, and every other 32-byte string that
    decodes to one of them when y is read modulo p and the sign bit of x = 0 is ignored: y + p where that is below
    2^255, and the sign bit set where x is 0."""
    canonical, other = [], []
    for pt in small_order_points():
        x, y = affine(pt)
        canonical.append(encode(pt))
        for yy in (y, y + P):
            if yy >= 1 << 255:
                continue
            for sign in ((0, 1) if x == 0 else (x & 1,)):
                e = (yy | sign << 255).to_bytes(32, "little")
                if e != canonical[-1]:
                    other.append(e)
    return canonical, other


class Examples:
    def __init__(self):
        self.d = json.loads((HERE / "mappings.json").read_text(encoding="utf-8"))
        vectors = json.loads((SER / "vectors.json").read_text(encoding="utf-8"))["vectors"]
        self.p1 = bytes.fromhex(next(v for v in vectors if v["id"] == "P1")["receipt_hex"])
        self.receipt_key = base64.b64decode(self.d["issuer_public_key_b64"])
        self.iss = self.d["receiver_pairs"][0][0]
        self.m2 = bytes.fromhex(self.d["M2_scitt_hash_envelope"]["cose_sign1_hex"])
        tag = cbor2.loads(self.m2)
        self.prot_b, self.payload, self.sig = tag.value[0], tag.value[2], tag.value[3]

    def statement(self, key: bytes, sign) -> bytes:
        """M2 with kid set to the thumbprint of `key` and the signature `sign(Sig_structure)`; nothing else changes."""
        prot = dict(cbor2.loads(self.prot_b))
        prot[4] = hashlib.sha256(cm.cbor_encode({1: 1, -1: 6, -2: key})).digest()
        prot_b = cm.cbor_encode(prot)
        tbs = cm.cbor_encode(["Signature1", prot_b, b"", self.payload])
        return cm.cbor_encode(cbor2.CBORTag(18, [prot_b, {}, self.payload, sign(tbs)]))

    def status(self, stmt: bytes, key: bytes):
        return cm.check_statement(stmt, self.p1, self.receipt_key, [(self.iss, key)])


class FreshKey:
    """A key made from os.urandom at run time, with its scalar a, so that signatures can be made by hand."""

    def __init__(self):
        self.seed = os.urandom(32)
        h = hashlib.sha512(self.seed).digest()
        self.a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
        self.point = cr._mul(self.a, cr._G)
        self.public = encode(self.point)

    def sign_by_hand(self, public: bytes, msg: bytes, r_bytes: bytes | None = None, r: int | None = None) -> bytes:
        """S = r + k*a with k over R || public || msg; R is [r]B, or the given bytes R with r = 0."""
        if r_bytes is None:
            r_bytes = encode(cr._mul(r, cr._G))
        else:
            r = 0
        k = int.from_bytes(hashlib.sha512(r_bytes + public + msg).digest(), "little") % L
        return r_bytes + ((r + k * self.a) % L).to_bytes(32, "little")


EX = Examples()
CANONICAL, NON_CANONICAL = small_order_encodings()
IDENTITY = encode(cr._ID)


class TheMaterialIsWhatItSays(unittest.TestCase):
    def test_eight_points_of_small_order_and_six_other_encodings(self):
        self.assertEqual(len(set(CANONICAL)), 8)
        self.assertEqual(len(set(NON_CANONICAL)), 6)
        for e in CANONICAL:
            pt = cr._dec(e)
            self.assertIsNotNone(pt, e.hex())
            self.assertTrue(cr._eq(cr._mul(8, pt), cr._ID), e.hex())
        for e in NON_CANONICAL:
            self.assertIsNone(cr._dec(e), e.hex())

    def test_the_rebuilt_m2_is_m2(self):
        tag = cbor2.loads(EX.m2)
        rebuilt = cm.cbor_encode(cbor2.CBORTag(18, [EX.prot_b, {}, EX.payload, EX.sig]))
        self.assertEqual(rebuilt, EX.m2)
        self.assertEqual(cbor2.loads(EX.prot_b)[4], hashlib.sha256(cm.cbor_encode(
            {1: 1, -1: 6, -2: EX.receipt_key})).digest())
        self.assertEqual(tag.tag, 18)

    def test_the_fresh_key_is_the_backends(self):
        key = FreshKey()
        self.assertEqual(key.public, Ed25519PrivateKey.from_private_bytes(key.seed).public_key().public_bytes_raw())


class AKeyOfSmallOrMixedOrderIsUntrusted(unittest.TestCase):
    def test_every_small_order_key_with_r_the_neutral_element_and_s_zero(self):
        for key in CANONICAL + NON_CANONICAL:
            stmt = EX.statement(key, lambda tbs: IDENTITY + ZERO_S)
            self.assertEqual(EX.status(stmt, key), ("untrusted_key", 3), key.hex())

    def test_every_small_order_key_with_each_small_order_r(self):
        for key in CANONICAL + NON_CANONICAL:
            for r in CANONICAL:
                stmt = EX.statement(key, lambda tbs, r=r: r + ZERO_S)
                self.assertEqual(EX.status(stmt, key), ("untrusted_key", 3), (key.hex(), r.hex()))

    def test_the_key_is_refused_before_the_signature_is_read(self):
        not_a_signature = b"\xff" * 64     # S is not below L: step 4 would refuse it, step 3 comes first
        for key in CANONICAL:
            stmt = EX.statement(key, lambda tbs: not_a_signature)
            self.assertEqual(EX.status(stmt, key), ("untrusted_key", 3), key.hex())

    def test_a_key_of_mixed_order_with_a_signature_the_cofactorless_equation_takes(self):
        key = FreshKey()
        mixed = encode(cr._add(key.point, cr._dec(ORDER_8)))

        def sign(tbs):
            # k must be a multiple of 8, so that k times the point of order 8 is the neutral element
            while True:
                r = int.from_bytes(os.urandom(64), "little") % L
                r_bytes = encode(cr._mul(r, cr._G))
                k = int.from_bytes(hashlib.sha512(r_bytes + mixed + tbs).digest(), "little") % L
                if k % 8 == 0:
                    return key.sign_by_hand(mixed, tbs, r=r)

        stmt = EX.statement(mixed, sign)
        self.assertEqual(EX.status(stmt, mixed), ("untrusted_key", 3))


class TheSignatureMeetsTheFourRules(unittest.TestCase):
    def test_a_fresh_key_with_its_own_signature_is_accepted(self):
        key = FreshKey()
        signer = Ed25519PrivateKey.from_private_bytes(key.seed)
        stmt = EX.statement(key.public, signer.sign)
        self.assertEqual(EX.status(stmt, key.public), ("accepted", None))

    def test_a_fresh_key_with_a_signature_made_by_hand_is_accepted(self):
        key = FreshKey()
        stmt = EX.statement(key.public, lambda tbs: key.sign_by_hand(key.public, tbs,
                                                                     r=int.from_bytes(os.urandom(64), "little") % L))
        self.assertEqual(EX.status(stmt, key.public), ("accepted", None))

    def test_a_fresh_key_with_a_forged_signature(self):
        key = FreshKey()
        for forged in (IDENTITY + ZERO_S, bytes(64), os.urandom(32) + ZERO_S):
            stmt = EX.statement(key.public, lambda tbs, f=forged: f)
            self.assertEqual(EX.status(stmt, key.public), ("signature_invalid", 4), forged.hex())

    def test_r_the_neutral_element_with_the_cofactorless_equation_holding(self):
        # S = k*a makes S*B = k*A = R + k*A with R the neutral element: rule 2 refuses R, the backend does not
        key = FreshKey()
        stmt = EX.statement(key.public, lambda tbs: key.sign_by_hand(key.public, tbs, r_bytes=IDENTITY))
        self.assertEqual(EX.status(stmt, key.public), ("signature_invalid", 4))

    def test_r_in_another_encoding_of_the_neutral_element(self):
        # y read modulo p is 1 and x is 0: the neutral element, written as y + p or with the sign bit set
        key = FreshKey()
        others = [e for e in NON_CANONICAL if (int.from_bytes(e, "little") & ((1 << 255) - 1)) % P == 1]
        self.assertEqual(len(others), 3)
        for r_bytes in others:
            stmt = EX.statement(key.public, lambda tbs, rb=r_bytes: key.sign_by_hand(key.public, tbs, r_bytes=rb))
            self.assertEqual(EX.status(stmt, key.public), ("signature_invalid", 4), r_bytes.hex())


class TheExamplesKeepTheirStatus(unittest.TestCase):
    def test_the_configured_issuer_test_key_counts(self):
        self.assertTrue(cm.key_counts(EX.receipt_key))

    def test_the_checker_passes_on_its_examples(self):
        run = subprocess.run([sys.executable, str(HERE / "check_mappings.py"), str(HERE / "mappings.json")],
                             cwd=HERE, capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stdout[-2000:] + run.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
