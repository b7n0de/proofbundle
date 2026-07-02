"""Token Status List snapshot (draft-ietf-oauth-status-list) — green + red matrix (v1.3)."""
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.statuslist import (issue_status_list_token, status_claim,
                                    verify_status_snapshot)

URI = "https://issuer.example/statuslists/1"
IAT = 1_780_000_000


def _raw(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class TestStatusList(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = _raw(self.signer)
        # spec example shape: 1-bit statuses; index 1 and 4 revoked
        self.token = issue_status_list_token([0, 1, 0, 0, 1, 0], uri=URI,
                                             signer=self.signer, iat=IAT)

    def test_green_valid_and_invalid(self):
        ok = verify_status_snapshot(self.token, expected_uri=URI, index=0, issuer_pubkey=self.pub)
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["status_label"], "VALID")
        rev = verify_status_snapshot(self.token, expected_uri=URI, index=4, issuer_pubkey=self.pub)
        self.assertTrue(rev["ok"])
        self.assertEqual(rev["status_label"], "INVALID")

    def test_green_2bit_suspended(self):
        token = issue_status_list_token([0, 2, 1, 3], uri=URI, signer=self.signer, iat=IAT, bits=2)
        res = verify_status_snapshot(token, expected_uri=URI, index=1, issuer_pubkey=self.pub)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status_label"], "SUSPENDED")

    def test_freshness_reported_not_assumed(self):
        token = issue_status_list_token([0], uri=URI, signer=self.signer, iat=IAT, ttl=3600)
        res = verify_status_snapshot(token, expected_uri=URI, index=0, issuer_pubkey=self.pub)
        self.assertIsNone(res["fresh"])                          # no clock supplied → no judgement
        fresh = verify_status_snapshot(token, expected_uri=URI, index=0, issuer_pubkey=self.pub,
                                       now=IAT + 60)
        self.assertTrue(fresh["fresh"])
        stale = verify_status_snapshot(token, expected_uri=URI, index=0, issuer_pubkey=self.pub,
                                       now=IAT + 7200)
        self.assertTrue(stale["ok"])                             # crypto still fine
        self.assertFalse(stale["fresh"])                         # but not fresh — caller decides

    def test_expiry(self):
        token = issue_status_list_token([0], uri=URI, signer=self.signer, iat=IAT, exp=IAT + 100)
        self.assertFalse(verify_status_snapshot(token, expected_uri=URI, index=0,
                                                issuer_pubkey=self.pub, now=IAT + 101)["fresh"])

    def test_red_wrong_issuer_key(self):
        stranger = generate_signer()
        res = verify_status_snapshot(self.token, expected_uri=URI, index=0,
                                     issuer_pubkey=_raw(stranger))
        self.assertFalse(res["ok"])
        self.assertIn("signature", res["detail"])

    def test_red_uri_mismatch(self):
        res = verify_status_snapshot(self.token, expected_uri="https://other.example/list",
                                     index=0, issuer_pubkey=self.pub)
        self.assertFalse(res["ok"])
        self.assertIn("sub", res["detail"])

    def test_red_wrong_typ(self):
        import base64
        import json
        h, p, s = self.token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
        header["typ"] = "jwt"
        h2 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        sig2 = base64.urlsafe_b64encode(
            self.signer.sign(f"{h2}.{p}".encode("ascii"))).rstrip(b"=").decode()
        res = verify_status_snapshot(f"{h2}.{p}.{sig2}", expected_uri=URI, index=0,
                                     issuer_pubkey=self.pub)
        self.assertFalse(res["ok"])
        self.assertIn("typ", res["detail"])

    def test_red_index_out_of_range(self):
        res = verify_status_snapshot(self.token, expected_uri=URI, index=999,
                                     issuer_pubkey=self.pub)
        self.assertFalse(res["ok"])

    def test_red_status_flip_needs_resign(self):
        # Flipping a bit in lst breaks the signature — a snapshot is tamper-evident.
        import base64
        import json
        h, p, s = self.token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        import zlib
        arr = bytearray(zlib.decompress(base64.urlsafe_b64decode(
            payload["status_list"]["lst"] + "==")))
        arr[0] ^= 0b00000001                                     # revoke index 0
        payload["status_list"]["lst"] = base64.urlsafe_b64encode(
            zlib.compress(bytes(arr), 9)).rstrip(b"=").decode()
        p2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        res = verify_status_snapshot(f"{h}.{p2}.{s}", expected_uri=URI, index=0,
                                     issuer_pubkey=self.pub)
        self.assertFalse(res["ok"])

    def test_red_issue_guards(self):
        with self.assertRaises(BundleFormatError):
            issue_status_list_token([0], uri=URI, signer=self.signer, iat=IAT, bits=3)
        with self.assertRaises(BundleFormatError):
            issue_status_list_token([2], uri=URI, signer=self.signer, iat=IAT, bits=1)
        with self.assertRaises(BundleFormatError):
            status_claim("", 0)
        with self.assertRaises(BundleFormatError):
            status_claim(URI, -1)

    def test_sdjwt_carries_status_and_vct(self):
        import base64
        import json
        from proofbundle.sdjwt_issue import DEFAULT_VCT, SD_JWT_TYP, issue_sd_jwt
        issuer = generate_signer()
        claim = {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "s",
                 "issuer": "ed25519:" + base64.b64encode(_raw(issuer)).decode()}
        compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==",
                               status=status_claim(URI, 4))
        jwt = compact.split("~", 1)[0]
        h, p, _ = jwt.split(".")
        header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        self.assertEqual(header["typ"], SD_JWT_TYP)              # dc+sd-jwt marker
        self.assertEqual(payload["vct"], DEFAULT_VCT)
        self.assertEqual(payload["status"]["status_list"], {"idx": 4, "uri": URI})
        # end-to-end: the pointed-at snapshot says INVALID for this receipt
        res = verify_status_snapshot(self.token,
                                     expected_uri=payload["status"]["status_list"]["uri"],
                                     index=payload["status"]["status_list"]["idx"],
                                     issuer_pubkey=self.pub)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status_label"], "INVALID")


if __name__ == "__main__":
    unittest.main()


class TestFreshnessAndStrictTypes(unittest.TestCase):
    """v1.6 external review: unbounded snapshots are not 'fresh forever', and exp/ttl must be typed."""

    def setUp(self):
        self.signer = generate_signer()
        self.pub = _raw(self.signer)

    def test_no_exp_no_ttl_fresh_is_none(self):
        token = issue_status_list_token([0], uri=URI, signer=self.signer, iat=IAT)  # no exp/ttl
        res = verify_status_snapshot(token, expected_uri=URI, index=0, issuer_pubkey=self.pub,
                                     now=IAT + 10**9)
        self.assertTrue(res["ok"])
        self.assertIsNone(res["fresh"], "unbounded token cannot be judged fresh — must be None")

    def test_ttl_bounded_is_judged(self):
        token = issue_status_list_token([0], uri=URI, signer=self.signer, iat=IAT, ttl=3600)
        self.assertTrue(verify_status_snapshot(token, expected_uri=URI, index=0,
                                               issuer_pubkey=self.pub, now=IAT + 60)["fresh"])
        self.assertFalse(verify_status_snapshot(token, expected_uri=URI, index=0,
                                                issuer_pubkey=self.pub, now=IAT + 7200)["fresh"])

    def test_string_exp_rejected(self):
        import base64
        import json
        # forge a token whose exp is a string that "looks like" an expiry
        h = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA", "typ": "statuslist+jwt"}).encode()).rstrip(b"=").decode()
        import zlib
        payload = {"sub": URI, "iat": IAT, "exp": "9999999999",
                   "status_list": {"bits": 1, "lst": base64.urlsafe_b64encode(zlib.compress(bytes(1), 9)).rstrip(b"=").decode()}}
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(self.signer.sign(f"{h}.{p}".encode("ascii"))).rstrip(b"=").decode()
        res = verify_status_snapshot(f"{h}.{p}.{sig}", expected_uri=URI, index=0, issuer_pubkey=self.pub)
        self.assertFalse(res["ok"])
        self.assertIn("exp", res["detail"])


class TestSelfIssuedSeparation(unittest.TestCase):
    """v1.9.1 (#8/#12): a status list signed by the receipt key has no independent revocation
    assurance — verify_status_snapshot reports self_issued so the relying party can refuse it."""

    def setUp(self):
        self.status_signer = generate_signer()
        self.status_pub = _raw(self.status_signer)
        self.token = issue_status_list_token([0, 1], uri=URI, signer=self.status_signer, iat=IAT)

    def test_self_issued_none_when_not_asked(self):
        res = verify_status_snapshot(self.token, expected_uri=URI, index=0,
                                     issuer_pubkey=self.status_pub)
        self.assertTrue(res["ok"])
        self.assertIsNone(res["self_issued"])          # not requested → not judged

    def test_self_issued_true_when_same_key(self):
        res = verify_status_snapshot(self.token, expected_uri=URI, index=0,
                                     issuer_pubkey=self.status_pub,
                                     receipt_issuer_pubkey=self.status_pub)
        self.assertTrue(res["ok"])                      # still valid crypto
        self.assertTrue(res["self_issued"])             # but flagged as self-issued

    def test_self_issued_false_when_distinct_key(self):
        receipt_pub = _raw(generate_signer())           # an independent receipt issuer
        res = verify_status_snapshot(self.token, expected_uri=URI, index=1,
                                     issuer_pubkey=self.status_pub,
                                     receipt_issuer_pubkey=receipt_pub)
        self.assertTrue(res["ok"])
        self.assertFalse(res["self_issued"])            # distinct anchor → not self-issued
        self.assertEqual(res["status_label"], "INVALID")
