"""Official published test vectors from the specs proofbundle implements (external conformance).

Complements the vendored corpora (RFC 6962 in test_rfc6962_external_vectors.py, ed25519-speccheck in
test_ed25519_semantics.py, the sd-jwt-python reference in test_sdjwt_reference.py) with the canonical
spec-document vectors that are small enough to inline verbatim with their source.
"""
from __future__ import annotations

import unittest

from proofbundle.dsse import pae
from proofbundle.signature import verify_ed25519


class TestDsseOfficialPae(unittest.TestCase):
    def test_official_pae_vector(self):
        # secure-systems-lab/dsse protocol.md — the one published PAE example.
        # PAE("http://example.com/HelloWorld", "hello world")
        self.assertEqual(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")


class TestEd25519Rfc8032Section71(unittest.TestCase):
    """RFC 8032 §7.1 Ed25519 test vectors (canonical positive KATs). public key / message / signature."""

    _VECTORS = [
        # (public_key_hex, message_hex, signature_hex)
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39"
         "701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f36"
         "13d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f7"
         "60984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_positive_vectors_verify(self):
        for i, (pk, msg, sig) in enumerate(self._VECTORS):
            self.assertTrue(
                verify_ed25519(bytes.fromhex(pk), bytes.fromhex(sig), bytes.fromhex(msg)),
                msg=f"RFC 8032 §7.1 vector #{i + 1} did not verify")

    def test_wrong_message_is_rejected(self):
        pk, _msg, sig = self._VECTORS[1]
        self.assertFalse(verify_ed25519(bytes.fromhex(pk), bytes.fromhex(sig), b"\x73"))  # 0x73 != 0x72

    def test_tampered_signature_is_rejected(self):
        pk, msg, sig = self._VECTORS[2]
        raw = bytearray(bytes.fromhex(sig))
        raw[0] ^= 0xFF
        self.assertFalse(verify_ed25519(bytes.fromhex(pk), bytes(raw), bytes.fromhex(msg)))


if __name__ == "__main__":
    unittest.main()
