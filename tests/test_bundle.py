import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from make_example import build_bundle  # noqa: E402

from proofbundle import verify_bundle  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
