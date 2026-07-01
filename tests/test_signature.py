import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.signature import verify_ed25519


def raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class TestSignature(unittest.TestCase):
    def test_valid(self):
        key = Ed25519PrivateKey.generate()
        msg = b"attestation payload"
        self.assertTrue(verify_ed25519(raw_pub(key), key.sign(msg), msg))

    def test_tampered_message(self):
        key = Ed25519PrivateKey.generate()
        sig = key.sign(b"hello")
        self.assertFalse(verify_ed25519(raw_pub(key), sig, b"hell0"))

    def test_wrong_key(self):
        key = Ed25519PrivateKey.generate()
        other = Ed25519PrivateKey.generate()
        msg = b"x"
        self.assertFalse(verify_ed25519(raw_pub(other), key.sign(msg), msg))

    def test_malformed_inputs(self):
        self.assertFalse(verify_ed25519(b"too-short", b"\x00" * 64, b"m"))
        self.assertFalse(verify_ed25519(b"\x00" * 32, b"short-sig", b"m"))


if __name__ == "__main__":
    unittest.main()
