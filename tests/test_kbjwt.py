"""Key Binding JWT (RFC 9901 §4.3) — green roundtrip + adversarial red matrix (v1.2)."""
import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.errors import BundleFormatError
from proofbundle.kbjwt import holder_key_from_cnf, split_key_binding, verify_key_binding
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

IAT = 1_780_000_000
CLAIM = {"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "demo-suite",
         "issuer": "ed25519:placeholder"}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _issue_presented(holder=None, *, exact_score="0.92", aud="verifier.example", nonce="n-1"):
    """Issue an SD-JWT (issuer == holder-binding optional) and present it with a KB-JWT."""
    issuer = generate_signer()
    holder = holder or generate_signer()
    claim = dict(CLAIM)
    claim["issuer"] = "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")
    compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score=exact_score,
                           holder_public_key=_raw_pub(holder))
    presented = present_with_key_binding(compact, holder, aud=aud, nonce=nonce, iat=IAT)
    return presented, issuer, holder


class TestSplit(unittest.TestCase):
    def test_no_kb_when_trailing_tilde(self):
        sd, kb = split_key_binding("a.b.c~disc~")
        self.assertEqual(sd, "a.b.c~disc~")
        self.assertIsNone(kb)

    def test_kb_split(self):
        sd, kb = split_key_binding("a.b.c~disc~h.p.s")
        self.assertEqual(sd, "a.b.c~disc~")
        self.assertEqual(kb, "h.p.s")

    def test_non_jws_tail_is_not_kb(self):
        sd, kb = split_key_binding("a.b.c~disc~nodots")
        self.assertIsNone(kb)


class TestKbRoundtrip(unittest.TestCase):
    def test_green_roundtrip(self):
        presented, _, _ = _issue_presented()
        res = verify_key_binding(presented)
        self.assertTrue(res["present"])
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["aud"], "verifier.example")
        self.assertEqual(res["nonce"], "n-1")
        self.assertEqual(res["iat"], IAT)

    def test_aud_nonce_policy(self):
        presented, _, _ = _issue_presented()
        self.assertTrue(verify_key_binding(presented, expected_aud="verifier.example",
                                           expected_nonce="n-1")["ok"])
        self.assertFalse(verify_key_binding(presented, expected_aud="other.example")["ok"])
        self.assertFalse(verify_key_binding(presented, expected_nonce="n-2")["ok"])

    def test_absent_kb_is_reported_absent(self):
        issuer = generate_signer()
        claim = dict(CLAIM)
        claim["issuer"] = "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")
        compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score="0.5")
        res = verify_key_binding(compact)
        self.assertFalse(res["present"])
        self.assertFalse(res["ok"])

    def test_cnf_extraction(self):
        presented, _, holder = _issue_presented()
        issuer_jwt = presented.split("~", 1)[0]
        payload = json.loads(_b64url_decode(issuer_jwt.split(".")[1]))
        self.assertEqual(holder_key_from_cnf(payload), _raw_pub(holder))


class TestKbAdversarial(unittest.TestCase):
    """Red matrix: every mutated presentation MUST fail. Each case is an independent
    (orthogonal) fault dimension: binding, header, payload, signature, key source."""

    def test_red_disclosure_dropped_after_signing(self):
        # sd_hash binds the presented set: dropping a disclosure post-KB must fail.
        presented, _, _ = _issue_presented()
        sd, kb = split_key_binding(presented)
        parts = sd.split("~")
        self.assertGreaterEqual(len(parts), 3, "need at least one disclosure")
        tampered = "~".join([parts[0]] + parts[2:]) + kb
        self.assertFalse(verify_key_binding(tampered)["ok"])

    def test_red_disclosure_swapped(self):
        presented, _, _ = _issue_presented(exact_score="0.92")
        other, _, _ = _issue_presented(exact_score="0.11")
        sd_a, kb_a = split_key_binding(presented)
        sd_b, _ = split_key_binding(other)
        # graft A's KB-JWT onto B's disclosures
        self.assertFalse(verify_key_binding(sd_b + kb_a)["ok"])

    def test_red_wrong_typ(self):
        presented, _, holder = _issue_presented()
        sd, kb = split_key_binding(presented)
        h, p, _ = kb.split(".")
        header = json.loads(_b64url_decode(h))
        header["typ"] = "jwt"
        h2 = _b64url(json.dumps(header).encode())
        sig2 = _b64url(holder.sign(f"{h2}.{p}".encode("ascii")))
        res = verify_key_binding(sd + f"{h2}.{p}.{sig2}")
        self.assertFalse(res["ok"])
        self.assertIn("kb+jwt", res["detail"])

    def test_red_alg_none(self):
        presented, _, _ = _issue_presented()
        sd, kb = split_key_binding(presented)
        _, p, s = kb.split(".")
        h2 = _b64url(json.dumps({"alg": "none", "typ": "kb+jwt"}).encode())
        self.assertFalse(verify_key_binding(sd + f"{h2}.{p}.{s}")["ok"])

    def _mutate_payload(self, presented, holder, drop=None):
        sd, kb = split_key_binding(presented)
        h, p, _ = kb.split(".")
        payload = json.loads(_b64url_decode(p))
        del payload[drop]
        p2 = _b64url(json.dumps(payload).encode())
        sig2 = _b64url(holder.sign(f"{h}.{p2}".encode("ascii")))
        return sd + f"{h}.{p2}.{sig2}"

    def test_red_required_claims(self):
        for claim in ("iat", "aud", "nonce", "sd_hash"):
            presented, _, holder = _issue_presented()
            mutated = self._mutate_payload(presented, holder, drop=claim)
            res = verify_key_binding(mutated)
            self.assertFalse(res["ok"], f"missing {claim} must fail")

    def test_red_wrong_holder_key_signature(self):
        # KB signed by an attacker key, cnf points to the real holder → fail.
        presented, _, _ = _issue_presented()
        sd, kb = split_key_binding(presented)
        h, p, _ = kb.split(".")
        attacker = generate_signer()
        sig2 = _b64url(attacker.sign(f"{h}.{p}".encode("ascii")))
        res = verify_key_binding(sd + f"{h}.{p}.{sig2}")
        self.assertFalse(res["ok"])
        self.assertIn("signature invalid", res["detail"])

    def test_red_no_key_available_fails_closed(self):
        # No cnf in issuer payload and no supplied key → fail, never skip.
        issuer, holder = generate_signer(), generate_signer()
        claim = dict(CLAIM)
        claim["issuer"] = "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")
        compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score="0.9")
        presented = present_with_key_binding(compact, holder, aud="a", nonce="n", iat=IAT)
        res = verify_key_binding(presented)
        self.assertTrue(res["present"])
        self.assertFalse(res["ok"])
        self.assertIn("no holder key", res["detail"])
        # but verifiable with the explicitly supplied holder key
        self.assertTrue(verify_key_binding(presented, _raw_pub(holder))["ok"])

    def test_red_sd_hash_recomputed_not_trusted(self):
        # A KB-JWT whose sd_hash is a hash of something else entirely must fail.
        presented, _, holder = _issue_presented()
        sd, kb = split_key_binding(presented)
        h, p, _ = kb.split(".")
        payload = json.loads(_b64url_decode(p))
        payload["sd_hash"] = _b64url(hashlib.sha256(b"unrelated").digest())
        p2 = _b64url(json.dumps(payload).encode())
        sig2 = _b64url(holder.sign(f"{h}.{p2}".encode("ascii")))
        res = verify_key_binding(sd + f"{h}.{p2}.{sig2}")
        self.assertFalse(res["ok"])
        self.assertIn("sd_hash", res["detail"])


class TestBundleIntegration(unittest.TestCase):
    def _bundle_with(self, compact, issuer):
        return emit_bundle(b'{"x":1}', issuer,
                           sd_jwt_vc={"compact": compact,
                                      "issuer_public_key_b64":
                                          base64.b64encode(_raw_pub(issuer)).decode("ascii")})

    def test_bundle_kb_check_green(self):
        presented, issuer, _ = _issue_presented()
        result = verify_bundle(self._bundle_with(presented, issuer))
        names = [c.name for c in result.checks]
        self.assertIn("sd-jwt-key-binding", names)
        self.assertTrue(result.ok, result.as_dict())

    def test_bundle_kb_check_red_fail_closed(self):
        # Tampered KB (attacker-signed) makes the WHOLE bundle fail — no silent ignore.
        presented, issuer, _ = _issue_presented()
        sd, kb = split_key_binding(presented)
        h, p, _ = kb.split(".")
        attacker = generate_signer()
        bad = sd + f"{h}.{p}." + _b64url(attacker.sign(f"{h}.{p}".encode("ascii")))
        result = verify_bundle(self._bundle_with(bad, issuer))
        kb_checks = [c for c in result.checks if c.name == "sd-jwt-key-binding"]
        self.assertEqual(len(kb_checks), 1)
        self.assertFalse(kb_checks[0].ok)
        self.assertFalse(result.ok)

    def test_bundle_without_kb_unchanged(self):
        # v0.9 bundles (no KB-JWT) get NO extra check — backwards compatible.
        issuer = generate_signer()
        claim = dict(CLAIM)
        claim["issuer"] = "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")
        compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score="0.9")
        result = verify_bundle(self._bundle_with(compact, issuer))
        names = [c.name for c in result.checks]
        self.assertNotIn("sd-jwt-key-binding", names)
        self.assertTrue(result.ok, result.as_dict())

    def test_bundle_cnf_bound_stripped_kb_fails(self):
        # CRITICAL (release review): a credential ISSUED WITH a cnf holder key REQUIRES proof-of-possession.
        # Stripping the KB-JWT to the RFC-9901-legal no-key-binding form must FAIL (bearer-replay bypass).
        presented, issuer, _ = _issue_presented()
        stripped = presented.rsplit("~", 1)[0] + "~"
        result = verify_bundle(self._bundle_with(stripped, issuer))
        kb_checks = [c for c in result.checks if c.name == "sd-jwt-key-binding"]
        self.assertEqual(len(kb_checks), 1, "cnf-bound credential without KB must add a failing check")
        self.assertFalse(kb_checks[0].ok)
        self.assertFalse(result.ok)

    def test_bundle_verify_enforces_aud_nonce(self):
        # HIGH (audit): RFC 9901 §7.3 replay/audience binding must be reachable through the public verify_bundle.
        presented, issuer, _ = _issue_presented(aud="verifier.example", nonce="n-1")
        b = self._bundle_with(presented, issuer)
        self.assertTrue(verify_bundle(b, expected_aud="verifier.example", expected_nonce="n-1").ok)
        wrong = verify_bundle(b, expected_aud="attacker.example", expected_nonce="n-1")
        self.assertFalse(wrong.ok)
        stale = verify_bundle(b, expected_aud="verifier.example", expected_nonce="old-nonce")
        self.assertFalse(stale.ok)

    def test_bundle_nonstring_compact_is_format_error(self):
        # HIGH (audit): a non-string sd_jwt_vc.compact must be a BundleFormatError, never a raw AttributeError.
        b = emit_bundle(b'{"x":1}', generate_signer())
        b["sd_jwt_vc"] = {"compact": 12345}
        with self.assertRaises(BundleFormatError):
            verify_bundle(b)

    def test_bundle_kb_skipped_when_issuer_unverified(self):
        # HIGH (release review): the holder-binding check is meaningful only with a VERIFIED issuer signature.
        # With issuer_public_key_b64 OMITTED, the cnf key is unauthenticated (a forged SD-JWT could declare it),
        # so NO sd-jwt-key-binding verdict is emitted — it must not read as a valid holder binding.
        presented, _issuer, _ = _issue_presented()
        b = emit_bundle(b'{"x":1}', generate_signer(), sd_jwt_vc={"compact": presented})  # no issuer key
        names = [c.name for c in verify_bundle(b).checks]
        self.assertNotIn("sd-jwt-key-binding", names)
        self.assertNotIn("sd-jwt-issuer-signature", names)


class TestPresentGuards(unittest.TestCase):
    def test_present_rejects_double_binding(self):
        presented, _, holder = _issue_presented()
        with self.assertRaises(ValueError):
            present_with_key_binding(presented, holder, aud="a", nonce="n", iat=IAT)

    def test_present_rejects_bad_iat(self):
        issuer, holder = generate_signer(), generate_signer()
        claim = dict(CLAIM)
        claim["issuer"] = "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")
        compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score="0.9")
        with self.assertRaises(ValueError):
            present_with_key_binding(compact, holder, aud="a", nonce="n", iat=True)

    def test_issue_rejects_short_holder_key(self):
        issuer = generate_signer()
        claim = dict(CLAIM)
        claim["issuer"] = "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")
        with self.assertRaises(ValueError):
            issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", holder_public_key=b"short")


if __name__ == "__main__":
    unittest.main()
