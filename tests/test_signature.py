import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.signature import verify_ecdsa_p256, verify_ed25519


def raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _p256_raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _p256_raw_sig(key, message: bytes) -> bytes:
    """Convert a DER ECDSA signature to the fixed-width 64-byte R||S JWS wire format (RFC 7518 §3.4)."""
    der_sig = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


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


class TestVerifyEcdsaP256(unittest.TestCase):
    """Finding 20 / issue #27 (PB-2026-07-15): ECDSA P-256 (ES256) issuer-signature interop."""

    def test_valid(self):
        key = ec.generate_private_key(ec.SECP256R1())
        msg = b"attestation payload"
        self.assertTrue(verify_ecdsa_p256(_p256_raw_pub(key), _p256_raw_sig(key, msg), msg))

    def test_tampered_message(self):
        key = ec.generate_private_key(ec.SECP256R1())
        sig = _p256_raw_sig(key, b"hello")
        self.assertFalse(verify_ecdsa_p256(_p256_raw_pub(key), sig, b"hell0"))

    def test_wrong_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        other = ec.generate_private_key(ec.SECP256R1())
        msg = b"x"
        self.assertFalse(verify_ecdsa_p256(_p256_raw_pub(other), _p256_raw_sig(key, msg), msg))

    def test_tampered_signature_bytes(self):
        # a bit-flip in R or S (still 64 bytes, still parses as two ints) must not verify — proves
        # the DER round-trip conversion does not silently widen what "valid" means.
        key = ec.generate_private_key(ec.SECP256R1())
        msg = b"x"
        sig = bytearray(_p256_raw_sig(key, msg))
        sig[-1] ^= 0xFF
        self.assertFalse(verify_ecdsa_p256(_p256_raw_pub(key), bytes(sig), msg))

    def test_malformed_inputs(self):
        key = ec.generate_private_key(ec.SECP256R1())
        pub, sig = _p256_raw_pub(key), _p256_raw_sig(key, b"m")
        self.assertFalse(verify_ecdsa_p256(b"too-short", sig, b"m"))
        self.assertFalse(verify_ecdsa_p256(pub, b"short-sig", b"m"))
        self.assertFalse(verify_ecdsa_p256(None, sig, b"m"))
        self.assertFalse(verify_ecdsa_p256(pub, None, b"m"))

    def test_ed25519_key_length_confusion_fails_closed(self):
        # a 32-byte Ed25519-shaped key must not be silently accepted by the P-256 verifier just
        # because SOME byte lengths happen to overlap elsewhere — the algorithms never cross-verify.
        self.assertFalse(verify_ecdsa_p256(b"\x00" * 32, b"\x00" * 64, b"m"))

    def test_compressed_point_rejected(self):
        # only the SEC1 UNCOMPRESSED point (0x04 prefix, 65 bytes) is the documented "raw" format;
        # a compressed point (0x02/0x03 prefix, 33 bytes) must fail closed, not be silently expanded.
        key = ec.generate_private_key(ec.SECP256R1())
        compressed = key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        self.assertEqual(len(compressed), 33)
        self.assertFalse(verify_ecdsa_p256(compressed, _p256_raw_sig(key, b"m"), b"m"))

    def test_point_not_on_curve_does_not_crash(self):
        # a 65-byte, 0x04-prefixed blob whose (X, Y) is not actually a point on P-256 must fail
        # closed (from_encoded_point rejects it), never raise out of the "always a boolean" contract.
        bogus = b"\x04" + b"\xff" * 64
        self.assertFalse(verify_ecdsa_p256(bogus, b"\x00" * 64, b"m"))


if __name__ == "__main__":
    unittest.main()
