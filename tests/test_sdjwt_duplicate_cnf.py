"""F12 (2026-07-12) — duplicate-`cnf` parser-differential guard for the SD-JWT / KB-JWT payloads.

Regression for the release-audit finding: every verify path parses with loads_strict EXCEPT the
SD-JWT/KB-JWT payload, which used plain json.loads (last-wins). An issuer-signed SD-JWT whose payload
carries TWO `cnf` claims — the legitimate holder first, an attacker key second — is a single valid
Ed25519 signature over the raw bytes (the signature covers exact wire bytes, duplication does not break
it); last-wins silently binds the ATTACKER's key. A first-wins / duplicate-rejecting verifier reading
the SAME bytes disagrees — the classic cross-verifier consensus break. The fix rejects duplicate keys
fail-closed at the structure gate (verify_sd_jwt) and in kbjwt directly.
"""
import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.kbjwt import verify_key_binding
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

IAT = 1_780_000_000


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _jwk(key: Ed25519PrivateKey) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(_raw_pub(key))}


def _issuer_jwt_with_duplicate_cnf(issuer, legit, attacker) -> str:
    """Hand-craft an issuer-signed SD-JWT (no disclosures) whose payload JSON has a DUPLICATE `cnf`:
    the legit holder first, the attacker second. json.dumps cannot emit duplicates, so we build the
    raw bytes by string concatenation, then sign them with the real issuer key (issuer-complicit /
    rotation-buggy tool scenario — the only producer of such a payload)."""
    payload = (
        '{"iss":"issuer.example","_sd_alg":"sha-256",'
        '"cnf":{"jwk":' + json.dumps(_jwk(legit)) + '},'
        '"cnf":{"jwk":' + json.dumps(_jwk(attacker)) + '}}'
    ).encode("utf-8")
    header = b'{"alg":"EdDSA","typ":"application/sd-jwt"}'
    h_b64, p_b64 = _b64url(header), _b64url(payload)
    sig = issuer.sign(f"{h_b64}.{p_b64}".encode("ascii"))
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def _present_with_kb(compact_sd_part: str, kb_signer: Ed25519PrivateKey,
                     *, aud="verifier.example", nonce="n-1") -> str:
    """Attach a KB-JWT (signed by kb_signer — the attacker) to a compact SD-JWT ending in '~'."""
    sd_hash = _b64url(hashlib.sha256(compact_sd_part.encode("ascii")).digest())
    kb_h = _b64url(b'{"typ":"kb+jwt","alg":"EdDSA"}')
    kb_p = _b64url(json.dumps({"iat": IAT, "aud": aud, "nonce": nonce, "sd_hash": sd_hash}).encode("utf-8"))
    kb_sig = kb_signer.sign(f"{kb_h}.{kb_p}".encode("ascii"))
    return compact_sd_part + f"{kb_h}.{kb_p}.{_b64url(kb_sig)}"


class TestDuplicateCnfRejected(unittest.TestCase):
    def test_verify_sd_jwt_rejects_duplicate_key_at_structure_gate(self):
        """The primary chokepoint: a duplicate key in the issuer payload → structure_ok False."""
        issuer, legit, attacker = generate_signer(), generate_signer(), generate_signer()
        issuer_jwt = _issuer_jwt_with_duplicate_cnf(issuer, legit, attacker)
        res = verify_sd_jwt(issuer_jwt + "~", issuer_pubkey=_raw_pub(issuer))
        self.assertFalse(res["structure_ok"], "duplicate key must fail the SD-JWT structure gate")
        self.assertIn("duplicate", res["detail"].lower())

    def test_verify_key_binding_rejects_duplicate_cnf(self):
        """The demonstrated PoC path: verify_key_binding must NOT bind the attacker's last-wins cnf key."""
        issuer, legit, attacker = generate_signer(), generate_signer(), generate_signer()
        issuer_jwt = _issuer_jwt_with_duplicate_cnf(issuer, legit, attacker)
        sd_part = issuer_jwt + "~"
        presented = _present_with_kb(sd_part, attacker)   # KB-JWT signed by the attacker's (last-wins) key
        res = verify_key_binding(presented)
        self.assertFalse(res["ok"], "a duplicated cnf must be rejected fail-closed, not bind the attacker key")
        self.assertIn("duplicate", res["detail"].lower())

    def test_legit_single_cnf_presentation_still_verifies(self):
        """Bidirectional: no over-rejection — an ordinary single-cnf presentation still passes."""
        issuer, holder = generate_signer(), generate_signer()
        claim = {"schema": "proofbundle/eval-claim/v0.1", "passed": True,
                 "threshold": 0.9, "comparator": ">=", "suite": "s", "issuer": "ed25519:x"}
        compact = issue_sd_jwt(claim, issuer, root_b64="cm9vdA==", exact_score="0.92",
                               holder_public_key=_raw_pub(holder))
        presented = present_with_key_binding(compact, holder, aud="verifier.example", nonce="n-1", iat=IAT)
        res = verify_key_binding(presented, expected_aud="verifier.example", expected_nonce="n-1")
        self.assertTrue(res["ok"], res["detail"])


if __name__ == "__main__":
    unittest.main()
