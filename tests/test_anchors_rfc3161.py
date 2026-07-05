"""RFC 3161 TSA anchor — offline verify against a REAL captured FreeTSA token, and the frozen-chain
rotation test (Paket 1 test 8). Skipped when the [anchors] extra (rfc3161-client) is not installed, so
the base test job stays green; a dedicated CI job installs the extra and exercises it."""
import base64
import json
import pathlib
import unittest

try:
    import rfc3161_client  # noqa: F401
    _HAS_TSA = True
except ImportError:
    _HAS_TSA = False

from proofbundle import anchors

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "anchors" / "freetsa_receipt_anchor.json"


def _load_fixture():
    anchor = json.loads(FIXTURE.read_text())
    root = base64.b64decode(anchor["canonicalRoot"])
    return anchor, {"receipt": root}


@unittest.skipUnless(_HAS_TSA, "needs proofbundle[anchors] (rfc3161-client)")
class TestRfc3161Anchor(unittest.TestCase):
    def test_real_token_verifies_against_frozen_chain(self):
        anchor, roots = _load_fixture()
        res = anchors.verify_anchors([anchor], target_roots=roots)
        self.assertEqual(res["status"], "PASS", res)
        self.assertTrue(res["results"][0]["ok"])

    def test_require_anchor_rfc3161_passes(self):
        anchor, roots = _load_fixture()
        self.assertEqual(anchors.verify_anchors([anchor], target_roots=roots, require="rfc3161-tsa")["status"],
                         "PASS")

    def test_root_mismatch_fails(self):
        # a different receipt root → the anchor's canonicalRoot no longer matches → FAIL (fail-closed).
        anchor, _ = _load_fixture()
        res = anchors.verify_anchors([anchor], target_roots={"receipt": b"\x00" * 32})
        self.assertEqual(res["status"], "FAIL")

    def test_frozen_chain_rotation(self):
        # Paket 1 test 8: the token verifies against the FROZEN chain but NOT against a rotated (different)
        # chain. Simulate rotation by swapping the frozen root cert for a freshly generated self-signed
        # cert (the TSA's hypothetical NEW cert) — the old token must fail against it, and still succeed
        # against the frozen original.
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, roots = _load_fixture()
        proof = base64.b64decode(anchor["proof"])
        canonical_root = base64.b64decode(anchor["canonicalRoot"])

        # frozen (original) chain → verifies
        good = verify_rfc3161(proof, canonical_root, frozen=anchor["frozen"])
        self.assertTrue(good["ok"], good["detail"])

        # rotated chain: replace the root with an unrelated self-signed cert → must FAIL
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rotated-freetsa-root")])
        rotated = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime(2026, 1, 1))
                   .not_valid_after(datetime.datetime(2030, 1, 1)).sign(key, hashes.SHA256()))
        rotated_frozen = dict(anchor["frozen"])
        rotated_frozen["rootCertsDerB64"] = [base64.b64encode(rotated.public_bytes(Encoding.DER)).decode()]
        bad = verify_rfc3161(proof, canonical_root, frozen=rotated_frozen)
        self.assertFalse(bad["ok"], "old token must NOT verify against a rotated chain")

    def test_missing_frozen_root_fails_closed(self):
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        proof = base64.b64decode(anchor["proof"])
        root = base64.b64decode(anchor["canonicalRoot"])
        res = verify_rfc3161(proof, root, frozen={})   # no frozen chain
        self.assertFalse(res["ok"])
        self.assertIn("rootCertsDerB64", res["detail"])


if __name__ == "__main__":
    unittest.main()
