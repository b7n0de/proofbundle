"""TEE-attestation bridge (v2.0 preview) — binding, verify roundtrip, adversarial red matrix.

Also pins the experimental gating: importing proofbundle.experimental warns, and enclave is NOT
on the top-level package surface.
"""
import base64
import json
import unittest
import warnings

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.experimental.enclave import (EAT_TYP, enclave_binding_for,
                                              issue_enclave_attestation,
                                              verify_enclave_attestation)

PROFILE = "https://b7n0de.com/proofbundle/eat-profile/tdx-gpu/v1"


def _raw(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s.encode("ascii") + b"=" * (-len(s) % 4))


def _setup():
    """A receipt + a Verifier who attests the enclave that produced it, bound to the receipt."""
    issuer = generate_signer()
    bundle = emit_bundle(b'{"suite": "safety", "passed": true}', issuer)
    binding = enclave_binding_for(bundle)
    verifier = generate_signer()
    eat = issue_enclave_attestation(binding, verifier, profile=PROFILE, tier="affirming",
                                    ueid="tdx:0x1234", iat=1_780_000_000, exp=1_780_003_600)
    return bundle, binding, verifier, eat


class TestBinding(unittest.TestCase):
    def test_binding_is_stable_and_receipt_specific(self):
        b1 = emit_bundle(b"payload-A", generate_signer())
        b2 = emit_bundle(b"payload-B", generate_signer())
        self.assertEqual(enclave_binding_for(b1), enclave_binding_for(b1))    # deterministic
        self.assertNotEqual(enclave_binding_for(b1), enclave_binding_for(b2)) # bytes-specific
        # fits the RFC 9711 JSON eat_nonce window (8..88 chars): sha256 b64url = 43 chars
        self.assertEqual(len(enclave_binding_for(b1)), 43)

    def test_binding_rejects_non_bundle(self):
        with self.assertRaises(BundleFormatError):
            enclave_binding_for({"no": "payload"})
        with self.assertRaises(BundleFormatError):
            enclave_binding_for({"payload_b64": "!!not-base64!!"})


class TestVerifyRoundtrip(unittest.TestCase):
    def test_green(self):
        bundle, binding, verifier, eat = _setup()
        res = verify_enclave_attestation(eat, verifier_pubkey=_raw(verifier),
                                         expected_binding=binding, expected_profile=PROFILE)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["tier"], "affirming")
        self.assertEqual(res["profile"], PROFILE)
        self.assertEqual(res["ueid"], "tdx:0x1234")
        self.assertTrue(res["nonce_ok"])

    def test_freshness_reported_not_assumed(self):
        bundle, binding, verifier, eat = _setup()
        r = verify_enclave_attestation(eat, verifier_pubkey=_raw(verifier), expected_binding=binding)
        self.assertIsNone(r["fresh"])                                   # no clock → no judgement
        self.assertTrue(verify_enclave_attestation(eat, verifier_pubkey=_raw(verifier),
                        expected_binding=binding, now=1_780_000_060)["fresh"])
        self.assertFalse(verify_enclave_attestation(eat, verifier_pubkey=_raw(verifier),
                         expected_binding=binding, now=1_780_010_000)["fresh"])  # past exp

    def test_unbounded_fresh_is_none(self):
        bundle, binding, verifier, eat = _setup()
        v = generate_signer()
        eat2 = issue_enclave_attestation(binding, v, profile=PROFILE, tier="affirming")  # no exp
        r = verify_enclave_attestation(eat2, verifier_pubkey=_raw(v), expected_binding=binding,
                                       now=10**12)
        self.assertTrue(r["ok"])
        self.assertIsNone(r["fresh"])                                   # unbounded → cannot judge


class TestAdversarial(unittest.TestCase):
    def test_red_wrong_verifier_key(self):
        bundle, binding, verifier, eat = _setup()
        res = verify_enclave_attestation(eat, verifier_pubkey=_raw(generate_signer()),
                                         expected_binding=binding)
        self.assertFalse(res["ok"])
        self.assertIn("signature", res["detail"])

    def test_red_binding_mismatch_other_receipt(self):
        # An attestation for a DIFFERENT receipt must not verify against this one — the core guard.
        bundle, binding, verifier, eat = _setup()
        other = emit_bundle(b'{"forged": true}', generate_signer())
        res = verify_enclave_attestation(eat, verifier_pubkey=_raw(verifier),
                                         expected_binding=enclave_binding_for(other))
        self.assertFalse(res["ok"])
        self.assertIn("does not bind", res["detail"])

    def test_red_wrong_typ(self):
        bundle, binding, verifier, eat = _setup()
        h, p, s = eat.split(".")
        header = json.loads(_b64url_decode(h))
        header["typ"] = "jwt"
        h2 = _b64url(json.dumps(header).encode())
        sig2 = _b64url(verifier.sign(f"{h2}.{p}".encode("ascii")))
        res = verify_enclave_attestation(f"{h2}.{p}.{sig2}", verifier_pubkey=_raw(verifier),
                                         expected_binding=binding)
        self.assertFalse(res["ok"])
        self.assertIn(EAT_TYP, res["detail"])

    def test_red_alg_none(self):
        bundle, binding, verifier, eat = _setup()
        h, p, s = eat.split(".")
        h2 = _b64url(json.dumps({"alg": "none", "typ": EAT_TYP}).encode())
        res = verify_enclave_attestation(f"{h2}.{p}.{s}", verifier_pubkey=_raw(verifier),
                                         expected_binding=binding)
        self.assertFalse(res["ok"])

    def test_red_profile_mismatch(self):
        bundle, binding, verifier, eat = _setup()
        res = verify_enclave_attestation(eat, verifier_pubkey=_raw(verifier),
                                         expected_binding=binding,
                                         expected_profile="https://evil.example/profile")
        self.assertFalse(res["ok"])
        self.assertIn("profile", res["detail"])

    def test_red_claim_tamper_breaks_signature(self):
        # Flip the tier in the payload without re-signing → signature fails.
        bundle, binding, verifier, eat = _setup()
        h, p, s = eat.split(".")
        claims = json.loads(_b64url_decode(p))
        claims["tier"] = "contraindicated->affirming"
        p2 = _b64url(json.dumps(claims).encode())
        res = verify_enclave_attestation(f"{h}.{p2}.{s}", verifier_pubkey=_raw(verifier),
                                         expected_binding=binding)
        self.assertFalse(res["ok"])

    def test_red_garbage(self):
        for bad in ("", "not.a.jws", "a.b", "x.y.z"):
            res = verify_enclave_attestation(bad, verifier_pubkey=b"\x00" * 32, expected_binding="x")
            self.assertFalse(res["ok"])

    def test_red_string_exp_rejected(self):
        bundle, binding, verifier, eat = _setup()
        v = generate_signer()
        h = _b64url(json.dumps({"alg": "EdDSA", "typ": EAT_TYP}).encode())
        claims = {"eat_nonce": binding, "eat_profile": PROFILE, "tier": "affirming", "exp": "9999"}
        p = _b64url(json.dumps(claims).encode())
        sig = _b64url(v.sign(f"{h}.{p}".encode("ascii")))
        res = verify_enclave_attestation(f"{h}.{p}.{sig}", verifier_pubkey=_raw(v),
                                         expected_binding=binding, now=1)
        self.assertFalse(res["ok"])
        self.assertIn("exp", res["detail"])


class TestExperimentalGating(unittest.TestCase):
    def test_not_on_top_level_surface(self):
        import proofbundle
        self.assertNotIn("enclave", getattr(proofbundle, "__all__", []))
        self.assertFalse(hasattr(proofbundle, "verify_enclave_attestation"))

    def test_import_warns(self):
        import importlib
        import proofbundle.experimental as exp
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            importlib.reload(exp)
        self.assertTrue(any(issubclass(x.category, exp.ExperimentalWarning) for x in w))

    def test_cli_verify_enclave(self):
        import contextlib
        import io
        import os
        import tempfile
        from proofbundle.cli import main
        bundle, binding, verifier, eat = _setup()
        d = tempfile.mkdtemp()
        rp = os.path.join(d, "receipt.json")
        json.dump(bundle, open(rp, "w"))
        ep = os.path.join(d, "att.eat")
        open(ep, "w").write(eat)
        vkey = base64.b64encode(_raw(verifier)).decode()
        with contextlib.redirect_stdout(io.StringIO()), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            rc = main(["verify-enclave", ep, "--receipt", rp, "--verifier-key", vkey,
                       "--profile", PROFILE, "--json"])
        self.assertEqual(rc, 0)
        # wrong receipt → fail
        other = os.path.join(d, "other.json")
        json.dump(emit_bundle(b"other", generate_signer()), open(other, "w"))
        with contextlib.redirect_stdout(io.StringIO()), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            rc2 = main(["verify-enclave", ep, "--receipt", other, "--verifier-key", vkey])
        self.assertEqual(rc2, 1)


if __name__ == "__main__":
    unittest.main()
