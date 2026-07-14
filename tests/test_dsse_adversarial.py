"""Adversarial vectors for dsse.verify_envelope + pae — multi-signature arrays, PAE framing injection,
base64-alphabet confusion, payloadType pinning. DSSE is the signature envelope for the in-toto export,
so its verify correctness is a trust root.
"""
from __future__ import annotations

import base64
import unittest

from proofbundle.dsse import pae, sign_envelope, verify_envelope


def _signer():
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(encoding=s.Encoding.Raw, format=s.PublicFormat.Raw)
    return sk, pub


BODY = b'{"_type":"https://in-toto.io/Statement/v1","subject":[]}'
PTYPE = "application/vnd.in-toto+json"


class TestDsseMultiSignature(unittest.TestCase):
    def test_single_valid_signature_verifies(self):
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        self.assertTrue(verify_envelope(env, pub, payload_type=PTYPE))

    def test_valid_among_forged_verifies(self):
        # a signatures array [forged, valid] and [valid, forged] must both verify (OR semantics)
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        good = env["signatures"][0]
        forged = {"sig": base64.b64encode(b"\x00" * 64).decode("ascii")}
        env["signatures"] = [forged, good]
        self.assertTrue(verify_envelope(env, pub, payload_type=PTYPE))
        env["signatures"] = [good, forged]
        self.assertTrue(verify_envelope(env, pub, payload_type=PTYPE))

    def test_forged_only_array_is_rejected(self):
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        env["signatures"] = [
            {"sig": base64.b64encode(b"\x00" * 64).decode("ascii")},
            {"sig": base64.b64encode(b"\x11" * 64).decode("ascii")},
        ]
        self.assertFalse(verify_envelope(env, pub, payload_type=PTYPE))

    def test_signature_from_other_key_is_rejected(self):
        sk, _pub = _signer()
        _sk2, pub2 = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        self.assertFalse(verify_envelope(env, pub2, payload_type=PTYPE))

    def test_non_dict_signature_entries_are_skipped_not_crash(self):
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        env["signatures"] = ["not-a-dict", {"nosig": 1}, env["signatures"][0]]
        self.assertTrue(verify_envelope(env, pub, payload_type=PTYPE))


class TestPaeFraming(unittest.TestCase):
    def test_length_prefix_prevents_type_body_collision(self):
        # the classic DSSE trap: without length prefixes, ("ab","cd") and ("a","bcd") could collide. The
        # PAE length fields must keep them distinct.
        self.assertNotEqual(pae("ab", b"cd"), pae("a", b"bcd"))
        self.assertNotEqual(pae("", b"xy"), pae("x", b"y"))

    def test_tampered_payload_breaks_verification(self):
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        env["payload"] = base64.b64encode(BODY + b"x").decode("ascii")  # one byte appended
        self.assertFalse(verify_envelope(env, pub, payload_type=PTYPE))

    def test_wrong_payload_type_pin_is_rejected(self):
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        self.assertFalse(verify_envelope(env, pub, payload_type="application/other"))

    def test_payload_type_is_part_of_the_signed_bytes(self):
        # changing the envelope's payloadType (without re-signing) must break verification even if the
        # caller does not pin, because PAE binds the type into the signed message
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        env["payloadType"] = "application/attacker-chosen"
        self.assertFalse(verify_envelope(env, pub))


class TestBase64Alphabet(unittest.TestCase):
    def test_urlsafe_signature_alphabet_accepted(self):
        # DSSE verifiers MUST accept standard OR url-safe base64 for the signature
        sk, pub = _signer()
        env = sign_envelope(BODY, sk, payload_type=PTYPE)
        raw = base64.b64decode(env["signatures"][0]["sig"])
        env["signatures"][0]["sig"] = base64.urlsafe_b64encode(raw).decode("ascii")
        self.assertTrue(verify_envelope(env, pub, payload_type=PTYPE))


if __name__ == "__main__":
    unittest.main()
