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

    def test_create_anchor_freezes_chain_and_self_verifies(self):
        # create_rfc3161_anchor does the network POST, freezes the supplied chain, and refuses to return
        # an anchor whose fresh token does not verify. Mock the TSA response with the captured token
        # (same canonical root) so this stays offline and deterministic.
        import contextlib
        import io
        import unittest.mock

        from proofbundle.anchors_rfc3161 import create_rfc3161_anchor
        anchor, roots = _load_fixture()
        token = base64.b64decode(anchor["proof"])
        canonical_root = base64.b64decode(anchor["canonicalRoot"])
        root_der = base64.b64decode(anchor["frozen"]["rootCertsDerB64"][0])
        tsa_der = base64.b64decode(anchor["frozen"]["tsaCertDerB64"])

        fake_resp = contextlib.closing(io.BytesIO(token))
        fake_resp.read = io.BytesIO(token).read   # urlopen(...).read()
        with unittest.mock.patch("urllib.request.urlopen", return_value=fake_resp):
            built = create_rfc3161_anchor(canonical_root, "receipt", tsa_url="https://freetsa.org/tsr",
                                          root_certs_der=[root_der], tsa_cert_der=tsa_der,
                                          anchored_at="2026-07-05T00:00:00Z")
        self.assertEqual(built["type"], "rfc3161-tsa")
        self.assertEqual(built["target"], "receipt")
        # the built anchor must verify through the generic layer
        self.assertEqual(anchors.verify_anchors([built], target_roots=roots)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
