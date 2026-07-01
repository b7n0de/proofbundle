import os
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.emit import load_signer, save_signer


class TestEmit(unittest.TestCase):
    def test_emit_then_verify_ok(self):
        signer = generate_signer()
        bundle = emit_bundle(b"hello evidence", signer)
        result = verify_bundle(bundle)
        self.assertTrue(result.ok, msg=result.as_dict())
        self.assertEqual(
            {c.name for c in result.checks},
            {"ed25519-signature", "merkle-inclusion"},
        )

    def test_emit_with_prior_leaves(self):
        signer = generate_signer()
        bundle = emit_bundle(
            b"the newest entry",
            signer,
            prior_leaves=[b"older-0", b"older-1", b"older-2"],
        )
        self.assertEqual(bundle["merkle"]["tree_size"], 4)
        self.assertEqual(bundle["merkle"]["leaf_index"], 3)
        self.assertTrue(verify_bundle(bundle).ok)

    def test_tamper_after_emit_fails(self):
        signer = generate_signer()
        bundle = emit_bundle(b"immutable", signer)
        bundle["payload_b64"] = "AAAA"  # replace payload, signature no longer matches
        self.assertFalse(verify_bundle(bundle).ok)

    def test_key_save_and_load_roundtrip(self):
        signer = generate_signer()
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        try:
            save_signer(signer, handle.name)
            reloaded = load_signer(handle.name)
            b1 = emit_bundle(b"same payload", signer)
            b2 = emit_bundle(b"same payload", reloaded)
            # Same key produces the same signature and public key over same bytes.
            self.assertEqual(b1["signature"], b2["signature"])
            self.assertTrue(verify_bundle(b2).ok)
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
