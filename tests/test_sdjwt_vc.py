"""3.2.0 O7 SD-JWT VC minimal profile — typ/vct allowlist, offline metadata integrity, holder binding.

SSRF-safe by construction (no network I/O). unittest-style.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.emit import generate_signer
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.sdjwt_vc import (
    SD_JWT_VC_TYP,
    SdjwtVcError,
    check_vc_profile,
    validate_vc_policy,
    verify_sdjwt_vc,
)

_VCT = "https://b7n0de.com/vct/eval-credential/v1"
_AUD, _NONCE, _IAT = "verifier.example", "n-1", 1_700_000_000


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _raw_pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _hand_jwt(typ: str, payload: dict) -> str:
    """A hand-built compact SD-JWT (issuer part only) with a chosen header typ + payload — for profile-only
    checks that do not need a real signature (check_vc_profile does not verify the issuer signature; it checks
    typ/vct/metadata — the issuer signature is a separate concern verified elsewhere)."""
    header = {"alg": "EdDSA", "typ": typ}
    return _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode()) + "." + _b64url(b"sig") + "~"


def _claim(issuer) -> dict:
    return {"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "demo-suite",
            "issuer": "ed25519:" + base64.b64encode(_raw_pub(issuer)).decode("ascii")}


def _real_bound_vc(vct: str = _VCT):
    issuer = generate_signer()
    holder = generate_signer()
    compact = issue_sd_jwt(_claim(issuer), issuer, root_b64="cm9vdA==", exact_score="0.9",
                           holder_public_key=_raw_pub(holder), vct=vct)
    presented = present_with_key_binding(compact, holder, aud=_AUD, nonce=_NONCE, iat=_IAT)
    return presented, holder, issuer


class TestPolicyValidate(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_vc_policy({"vctAllowlist": [_VCT]}), [])

    def test_allowlist_required(self):
        self.assertTrue(validate_vc_policy({}))

    def test_unknown_key(self):
        self.assertTrue(validate_vc_policy({"vctAllowlist": [_VCT], "nope": 1}))

    def test_bad_policy_raises(self):
        with self.assertRaises(SdjwtVcError):
            check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {"vct": _VCT}), {})


class TestProfile(unittest.TestCase):
    def test_typ_and_vct_ok(self):
        r = check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {"vct": _VCT}), {"vctAllowlist": [_VCT]})
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["typ_ok"] and r["vct_ok"])

    def test_wrong_typ_fails(self):
        r = check_vc_profile(_hand_jwt("kb+jwt", {"vct": _VCT}), {"vctAllowlist": [_VCT]})
        self.assertFalse(r["typ_ok"])
        self.assertFalse(r["ok"])

    def test_vct_not_on_allowlist_fails(self):
        r = check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {"vct": "https://evil/vct"}), {"vctAllowlist": [_VCT]})
        self.assertFalse(r["vct_ok"])
        self.assertFalse(r["ok"])

    def test_missing_vct_fails(self):
        r = check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {}), {"vctAllowlist": [_VCT]})
        self.assertFalse(r["vct_ok"])
        self.assertFalse(r["ok"])

    def test_alg_none_issuer_header_fails(self):
        r = check_vc_profile(_hand_jwt2_alg_none(), {"vctAllowlist": [_VCT]})
        self.assertFalse(r["ok"])
        self.assertTrue(any("alg" in e for e in r["errors"]))

    def test_metadata_integrity_missing_offline_entry_fails_closed(self):
        # requireTypeMetadataIntegrity but no offline cache → FAIL, never a fetch (SSRF-safe).
        r = check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {"vct": _VCT}),
                             {"vctAllowlist": [_VCT], "requireTypeMetadataIntegrity": True})
        self.assertFalse(r["metadata_integrity_ok"])
        self.assertFalse(r["ok"])

    def test_metadata_integrity_match_from_offline_cache(self):
        meta = b'{"vct":"eval","claims":[]}'
        integ = "sha256-" + base64.b64encode(hashlib.sha256(meta).digest()).decode()
        cache = {_VCT: {"bytes_b64": base64.b64encode(meta).decode(), "integrity": integ}}
        r = check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {"vct": _VCT}),
                             {"vctAllowlist": [_VCT], "requireTypeMetadataIntegrity": True},
                             offline_metadata=cache)
        self.assertTrue(r["metadata_integrity_ok"])
        self.assertTrue(r["ok"], r)

    def test_metadata_integrity_mismatch_fails(self):
        cache = {_VCT: {"bytes_b64": base64.b64encode(b"real").decode(), "integrity": "sha256-" + base64.b64encode(hashlib.sha256(b"tampered").digest()).decode()}}
        r = check_vc_profile(_hand_jwt(SD_JWT_VC_TYP, {"vct": _VCT}),
                             {"vctAllowlist": [_VCT], "requireTypeMetadataIntegrity": True},
                             offline_metadata=cache)
        self.assertFalse(r["metadata_integrity_ok"])
        self.assertFalse(r["ok"])


class TestVerifyEndToEnd(unittest.TestCase):
    def test_bound_vc_verifies(self):
        presented, _, issuer = _real_bound_vc(_VCT)
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT], "requireKeyBinding": True},
                            issuer_pubkey=_raw_pub(issuer), expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["profile"]["ok"])
        self.assertTrue(r["issuer"]["sig_ok"])
        self.assertTrue(r["binding"]["ok"])

    def test_unbound_presentation_under_profile_fails(self):
        # a VC issued but presented WITHOUT key binding → requireKeyBinding default True → FAIL (issuer sig ok).
        issuer = generate_signer()
        compact = issue_sd_jwt(_claim(issuer), issuer, root_b64="cm9vdA==", exact_score="0.9", vct=_VCT)
        r = verify_sdjwt_vc(compact, {"vctAllowlist": [_VCT]}, issuer_pubkey=_raw_pub(issuer))
        self.assertFalse(r["ok"])

    def test_wrong_vct_end_to_end_fails(self):
        presented, _, issuer = _real_bound_vc("https://other/vct")
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT]}, issuer_pubkey=_raw_pub(issuer),
                            expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertFalse(r["ok"])
        self.assertFalse(r["profile"]["vct_ok"])


class TestIssuerSignatureAuthenticity(unittest.TestCase):
    """#3 (release-review): verify_sdjwt_vc must cryptographically authenticate the ISSUER, not just parse it."""

    def test_issuer_signature_green(self):
        presented, _, issuer = _real_bound_vc(_VCT)
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT]}, issuer_pubkey=_raw_pub(issuer),
                            expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertTrue(r["issuer"]["sig_checked"])
        self.assertTrue(r["issuer"]["sig_ok"])
        self.assertTrue(r["ok"], r)

    def test_wrong_issuer_key_rejected(self):
        # the credential was signed by the real issuer; verifying against a DIFFERENT (attacker) anchor fails —
        # this is what makes a self-issued/garbage-signed credential (the PoC) return ok=False.
        presented, _, _real_issuer = _real_bound_vc(_VCT)
        attacker = generate_signer()
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT]}, issuer_pubkey=_raw_pub(attacker),
                            expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertTrue(r["issuer"]["sig_checked"])
        self.assertFalse(r["issuer"]["sig_ok"])
        self.assertFalse(r["ok"])

    def test_missing_issuer_pubkey_fails_closed(self):
        # the old broken behavior: no issuer key supplied → the credential is NOT authenticated → ok=False.
        presented, _, _issuer = _real_bound_vc(_VCT)
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT]},
                            expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertFalse(r["issuer"]["sig_checked"])
        self.assertFalse(r["ok"])

    def test_explicit_opt_out_is_honest(self):
        # a caller may explicitly opt out (requireIssuerSignature=False) — then issuer is not evaluated and the
        # result reflects only profile+binding. Documented, explicit, not the default.
        presented, _, issuer = _real_bound_vc(_VCT)
        r = verify_sdjwt_vc(presented, {"vctAllowlist": [_VCT], "requireIssuerSignature": False},
                            expected_aud=_AUD, expected_nonce=_NONCE)
        self.assertIsNone(r["issuer"])
        self.assertTrue(r["ok"], r)


def _hand_jwt2_alg_none() -> str:
    header = {"alg": "none", "typ": SD_JWT_VC_TYP}
    return _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps({"vct": _VCT}).encode()) + "." + _b64url(b"") + "~"


if __name__ == "__main__":
    unittest.main()
