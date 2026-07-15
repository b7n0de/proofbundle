import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from make_example import build_bundle  # noqa: E402

from proofbundle import emit_bundle, generate_signer, verify_bundle  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402


def _es256_compact(payload: dict, key) -> str:
    """A hand-built, zero-disclosure ES256-signed compact SD-JWT (issuer part only, trailing '~' =
    no key binding). Mirrors sdjwt.py's own signing_input construction (header_b64 + '.' + payload_b64,
    RFC 7518 §3.4 fixed-width R||S)."""
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: PLC0415

    def _b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    header = {"alg": "ES256", "typ": "dc+sd-jwt"}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    der_sig = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input + "." + _b64url(raw_sig) + "~"


def _flip_last_byte_b64(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


class TestBundle(unittest.TestCase):
    def test_valid_bundle_passes_all_checks(self):
        result = verify_bundle(build_bundle())
        self.assertTrue(result.ok, msg=result.as_dict())
        names = {c.name for c in result.checks}
        self.assertEqual(
            names,
            {
                "ed25519-signature",
                "merkle-inclusion",
                "sd-jwt-disclosures",
                "sd-jwt-issuer-signature",
            },
        )

    def test_tampered_payload_fails(self):
        bundle = build_bundle()
        bundle["payload_b64"] = _flip_last_byte_b64(bundle["payload_b64"])
        self.assertFalse(verify_bundle(bundle).ok)

    def test_tampered_signature_fails(self):
        bundle = build_bundle()
        bundle["signature"]["sig_b64"] = _flip_last_byte_b64(bundle["signature"]["sig_b64"])
        result = verify_bundle(bundle)
        self.assertFalse(result.ok)

    def test_tampered_merkle_root_fails(self):
        bundle = build_bundle()
        bundle["merkle"]["root_b64"] = _flip_last_byte_b64(bundle["merkle"]["root_b64"])
        self.assertFalse(verify_bundle(bundle).ok)

    def test_unknown_schema_raises(self):
        bundle = build_bundle()
        bundle["schema"] = "proofbundle/v9"
        with self.assertRaises(ProofBundleError):
            verify_bundle(bundle)

    def test_without_sd_jwt_still_passes(self):
        bundle = build_bundle()
        del bundle["sd_jwt_vc"]
        result = verify_bundle(bundle)
        self.assertTrue(result.ok)
        names = {c.name for c in result.checks}
        self.assertEqual(names, {"ed25519-signature", "merkle-inclusion"})

    def test_es256_sd_jwt_issuer_identity_uses_alg_aware_prefix(self):
        # Finding 20 / issue #27 (PB-2026-07-15): the sd-jwt-issuer-identity fingerprint prefix must
        # match the algorithm that actually verified — "ed25519:" hardcoded regardless of alg was a
        # latent false-reject the moment ES256 issuer-signature support landed.
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415

        sd_key = ec.generate_private_key(ec.SECP256R1())
        sd_pub = sd_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        disclosed_issuer = "es256:" + base64.b64encode(sd_pub).decode("ascii")
        compact = _es256_compact({"issuer": disclosed_issuer, "vct": "https://example.test/vct"}, sd_key)

        bundle = emit_bundle(b'{"x":1}', generate_signer(), sd_jwt_vc={
            "compact": compact,
            "issuer_public_key_b64": base64.b64encode(sd_pub).decode("ascii"),
        })
        result = verify_bundle(bundle)
        by_name = {c.name: c.ok for c in result.checks}
        self.assertTrue(by_name.get("sd-jwt-issuer-signature"))
        self.assertIn("sd-jwt-issuer-identity", by_name)
        self.assertTrue(by_name["sd-jwt-issuer-identity"],
                        "an ES256-signed sd_jwt_vc whose disclosed issuer uses the alg-correct "
                        "'es256:' fingerprint prefix must match, not always mismatch")

    def test_es256_sd_jwt_issuer_identity_wrong_prefix_still_fails(self):
        # bidirectional: an ES256-verified signature disclosing the EdDSA-shaped "ed25519:" prefix
        # (wrong for this alg) must still be caught as a mismatch — the alg-awareness fix must not
        # have widened the check into always-True.
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415

        sd_key = ec.generate_private_key(ec.SECP256R1())
        sd_pub = sd_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        wrong_prefix_issuer = "ed25519:" + base64.b64encode(sd_pub).decode("ascii")
        compact = _es256_compact({"issuer": wrong_prefix_issuer, "vct": "https://example.test/vct"}, sd_key)

        bundle = emit_bundle(b'{"x":1}', generate_signer(), sd_jwt_vc={
            "compact": compact,
            "issuer_public_key_b64": base64.b64encode(sd_pub).decode("ascii"),
        })
        result = verify_bundle(bundle)
        by_name = {c.name: c.ok for c in result.checks}
        self.assertTrue(by_name.get("sd-jwt-issuer-signature"))
        self.assertFalse(by_name["sd-jwt-issuer-identity"])


if __name__ == "__main__":
    unittest.main()
