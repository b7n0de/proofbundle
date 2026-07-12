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


def _rp(anchor) -> dict:
    """WP-A1: the relying party supplies the TSA root out of band. In these tests the RP independently
    trusts the same FreeTSA root the fixture froze, so it passes it as rp_trust.trusted_tsa_roots."""
    return {"trusted_tsa_roots": list((anchor.get("frozen") or {}).get("rootCertsDerB64") or [])}


@unittest.skipUnless(_HAS_TSA, "needs proofbundle[anchors] (rfc3161-client)")
class TestRfc3161Anchor(unittest.TestCase):
    def test_real_token_verifies_against_relying_party_root(self):   # WP-A1 re-pin
        anchor, roots = _load_fixture()
        res = anchors.verify_anchors([anchor], target_roots=roots, rp_trust=_rp(anchor))
        self.assertEqual(res["status"], "PASS", res)
        self.assertTrue(res["results"][0]["ok"])
        self.assertTrue(res["results"][0]["rp_trusted"])
        # WP-A1 security property: the SAME token WITHOUT a relying-party root does NOT verify
        no_rp = anchors.verify_anchors([anchor], target_roots=roots)
        self.assertNotEqual(no_rp["status"], "PASS")
        self.assertFalse(no_rp["results"][0]["ok"])
        self.assertTrue(no_rp["results"][0]["needs_rp_trust"])

    def test_require_anchor_rfc3161_passes(self):   # WP-A1 re-pin: needs RP root
        anchor, roots = _load_fixture()
        self.assertEqual(anchors.verify_anchors([anchor], target_roots=roots, require="rfc3161-tsa",
                                                rp_trust=_rp(anchor))["status"], "PASS")
        # without the relying-party root, --require-anchor is UNMET (→ exit 3 at the CLI)
        unmet = anchors.verify_anchors([anchor], target_roots=roots, require="rfc3161-tsa")
        self.assertFalse(unmet["require_met"])

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

        # relying party trusts the original FreeTSA root → verifies (WP-A1)
        good = verify_rfc3161(proof, canonical_root, frozen=anchor["frozen"], rp_trust=_rp(anchor))
        self.assertTrue(good["ok"], good["detail"])

        # rotated: the relying party now trusts a DIFFERENT root (an unrelated self-signed cert) → must FAIL
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
        rotated_rp = {"trusted_tsa_roots": [base64.b64encode(rotated.public_bytes(Encoding.DER)).decode()]}
        bad = verify_rfc3161(proof, canonical_root, frozen=anchor["frozen"], rp_trust=rotated_rp)
        self.assertFalse(bad["ok"], "old token must NOT verify against a rotated relying-party root")

    def test_missing_relying_party_root_fails_closed(self):   # WP-A1 re-pin
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        proof = base64.b64decode(anchor["proof"])
        root = base64.b64decode(anchor["canonicalRoot"])
        res = verify_rfc3161(proof, root, frozen=anchor["frozen"])   # frozen present but NO rp_trust
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "needs_rp_trust")
        self.assertTrue(res["frozenEvidence"])          # frozen root reported…
        self.assertIn("relying-party", res["detail"])   # …but never trusted

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
        # the built anchor must verify through the generic layer when the relying party supplies the root
        self.assertEqual(anchors.verify_anchors([built], target_roots=roots, rp_trust=_rp(built))["status"],
                         "PASS")


@unittest.skipUnless(_HAS_TSA, "needs proofbundle[anchors] (rfc3161-client)")
class TestRfc3161PolicyOid(unittest.TestCase):
    """WP4 — anchors_rfc3161 delegates policy-OID handling to the rfc3161-client lib, but proofbundle
    now lets a relying party OPT IN to pinning it via the anchor's frozen.policyOid. These pin the
    documented behaviour: absent → any policy accepted; present → fail-closed on mismatch/malformed."""

    def _fixture_policy_oid(self) -> str:
        import rfc3161_client as tsp
        anchor, _ = _load_fixture()
        return tsp.decode_timestamp_response(base64.b64decode(anchor["proof"])).tst_info.policy.dotted_string

    def test_absent_policy_oid_accepts_any_policy(self):
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        frozen = dict(anchor["frozen"])
        frozen.pop("policyOid", None)   # no pin
        res = verify_rfc3161(base64.b64decode(anchor["proof"]),
                             base64.b64decode(anchor["canonicalRoot"]), frozen=frozen, rp_trust=_rp(anchor))
        self.assertTrue(res["ok"], res["detail"])

    def test_matching_policy_oid_passes(self):
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        frozen = dict(anchor["frozen"])
        frozen["policyOid"] = self._fixture_policy_oid()   # the token's real TSA policy OID
        res = verify_rfc3161(base64.b64decode(anchor["proof"]),
                             base64.b64decode(anchor["canonicalRoot"]), frozen=frozen, rp_trust=_rp(anchor))
        self.assertTrue(res["ok"], res["detail"])

    def test_mismatched_policy_oid_fails_closed(self):   # WP-A1: supply rp roots so the OID pin actually runs
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        frozen = dict(anchor["frozen"])
        real = self._fixture_policy_oid()
        frozen["policyOid"] = real + ".999"   # a policy OID the token does NOT carry
        res = verify_rfc3161(base64.b64decode(anchor["proof"]),
                             base64.b64decode(anchor["canonicalRoot"]), frozen=frozen, rp_trust=_rp(anchor))
        self.assertFalse(res["ok"], "a pinned policy OID that does not match the token must FAIL closed")
        self.assertEqual(res["status"], "chain_fail")   # reached the pin (not short-circuited at needs_rp_trust)

    def test_malformed_policy_oid_fails_closed(self):   # WP-A1: supply rp roots so the OID parse actually runs
        # a non-OID string must not crash and must not pass — x509.ObjectIdentifier raises, caught as FAIL.
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        frozen = dict(anchor["frozen"])
        frozen["policyOid"] = "not-an-oid"
        res = verify_rfc3161(base64.b64decode(anchor["proof"]),
                             base64.b64decode(anchor["canonicalRoot"]), frozen=frozen, rp_trust=_rp(anchor))
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "chain_fail")

    def test_mismatched_policy_oid_through_generic_layer(self):   # WP-A1: supply rp roots
        anchor, roots = _load_fixture()
        bad = dict(anchor)
        bad["frozen"] = dict(anchor["frozen"], policyOid=self._fixture_policy_oid() + ".999")
        self.assertEqual(anchors.verify_anchors([bad], target_roots=roots, rp_trust=_rp(anchor))["status"],
                         "FAIL")


@unittest.skipUnless(_HAS_TSA, "needs proofbundle[anchors] (rfc3161-client)")
class TestRfc3161CertExpiration(unittest.TestCase):
    """WP4 — cert expiration handling. The rfc3161-client lib validates the chain at the token's OWN
    gen_time (not the current wall clock): that is why a frozen token stays re-verifiable after the TSA
    cert has expired/rotated, AND why a chain that was not valid at gen_time fails closed."""

    def test_certs_are_valid_at_the_tokens_gen_time(self):
        # Document WHY the fixture verifies: its frozen root cert's validity window CONTAINS gen_time.
        import rfc3161_client as tsp
        from cryptography import x509
        anchor, _ = _load_fixture()
        ti = tsp.decode_timestamp_response(base64.b64decode(anchor["proof"])).tst_info
        root = x509.load_der_x509_certificate(base64.b64decode(anchor["frozen"]["rootCertsDerB64"][0]))
        self.assertLessEqual(root.not_valid_before_utc, ti.gen_time)
        self.assertGreaterEqual(root.not_valid_after_utc, ti.gen_time)

    def test_verdict_is_independent_of_the_callers_clock(self):
        # The `now` argument must not change the verdict — verification is anchored to the token's
        # gen_time, so an expired-TODAY TSA cert stays offline re-verifiable (the frozen-chain contract).
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        proof = base64.b64decode(anchor["proof"])
        root = base64.b64decode(anchor["canonicalRoot"])
        far_future = 4_102_444_800   # 2100-01-01, long after any TSA cert would have expired
        rp = _rp(anchor)
        self.assertTrue(verify_rfc3161(proof, root, frozen=anchor["frozen"], now=None, rp_trust=rp)["ok"])
        self.assertTrue(verify_rfc3161(proof, root, frozen=anchor["frozen"], now=far_future, rp_trust=rp)["ok"])
        self.assertTrue(verify_rfc3161(proof, root, frozen=anchor["frozen"], now=0, rp_trust=rp)["ok"])

    def test_frozen_root_expired_before_gen_time_fails_closed(self):
        # A frozen root whose validity window ENDS before the token's gen_time cannot anchor the token
        # → fail-closed (the layer never silently passes an out-of-validity trust anchor). Simulated with
        # a self-signed cert valid only in 2000–2001, well before the fixture's 2026 gen_time.
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID

        from proofbundle.anchors_rfc3161 import verify_rfc3161
        anchor, _ = _load_fixture()
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired-freetsa-root")])
        expired = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime(2000, 1, 1))
                   .not_valid_after(datetime.datetime(2001, 1, 1)).sign(key, hashes.SHA256()))
        # WP-A1: the expired root is now the RELYING-PARTY root (that is where trust lives) — the RP trusting
        # an expired-at-gen_time root must still fail closed at the chain build, not short-circuit earlier.
        expired_b64 = base64.b64encode(expired.public_bytes(Encoding.DER)).decode()
        res = verify_rfc3161(base64.b64decode(anchor["proof"]),
                             base64.b64decode(anchor["canonicalRoot"]), frozen=anchor["frozen"],
                             rp_trust={"trusted_tsa_roots": [expired_b64]})
        self.assertFalse(res["ok"], "an expired-at-gen-time relying-party root must fail closed")
        self.assertEqual(res["status"], "chain_fail")


if __name__ == "__main__":
    unittest.main()
