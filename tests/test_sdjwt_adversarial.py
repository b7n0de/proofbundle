"""Adversarial vectors for sdjwt.verify_sd_jwt — the highest-ranked coverage gap (algorithm confusion +
disclosure-digest binding). Built by MUTATING the committed reference SD-JWT, so every vector starts from
a genuinely-valid credential and changes exactly one thing.

Headline properties:
  * algorithm confusion: with an issuer key supplied, a non-EdDSA `alg` (`none`, `HS256`) must NOT yield
    sig_ok — and structure_ok being True must never be mistaken for a verified signature;
  * disclosure tamper: mutating any presented disclosure breaks structure_ok (its digest is no longer
    committed);
  * an appended disclosure whose digest is not committed breaks structure_ok.
"""
from __future__ import annotations

import base64
import json
import unittest
from base64 import b64decode
from pathlib import Path

from proofbundle.sdjwt import verify_sd_jwt

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sdjwt_reference_eddsa.json"


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


@unittest.skipIf(not FIXTURE.exists(), "sd-jwt reference fixture not present")
class TestSdJwtAdversarial(unittest.TestCase):
    def setUp(self):
        f = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.compact = f["compact"]
        self.pubkey = b64decode(f["issuer_public_key_b64"])
        self.jwt, _, self.rest = self.compact.partition("~")
        self.header_b64, self.payload_b64, self.sig_b64 = self.jwt.split(".")

    def _with_alg(self, alg) -> str:
        header = json.loads(_b64url_decode(self.header_b64))
        if alg is None:
            header.pop("alg", None)
        else:
            header["alg"] = alg
        jwt = f"{_b64url(header)}.{self.payload_b64}.{self.sig_b64}"
        return f"{jwt}~{self.rest}" if self.rest else jwt

    def test_baseline_reference_verifies(self):
        res = verify_sd_jwt(self.compact, self.pubkey)
        self.assertTrue(res["structure_ok"])
        self.assertTrue(res["sig_ok"])

    def test_alg_none_never_yields_sig_ok(self):
        # the classic algorithm-confusion vector: structure may still parse, but a 'none' alg must NEVER
        # produce a verified signature, and the caller must not read structure_ok as verification.
        res = verify_sd_jwt(self._with_alg("none"), self.pubkey)
        self.assertFalse(res["sig_ok"])
        self.assertNotEqual(res["alg"], "EdDSA")

    def test_alg_hs256_not_accepted(self):
        res = verify_sd_jwt(self._with_alg("HS256"), self.pubkey)
        self.assertFalse(res["sig_ok"])

    def test_alg_absent_not_accepted(self):
        res = verify_sd_jwt(self._with_alg(None), self.pubkey)
        self.assertFalse(res["sig_ok"])

    def test_structure_ok_is_not_sufficient_for_signature(self):
        # explicit anti-confusion: a verify where structure_ok is True but the signature is NOT verified
        res = verify_sd_jwt(self._with_alg("none"), self.pubkey)
        # a relying party must gate on sig_ok, not structure_ok
        self.assertTrue(res["sig_checked"])
        self.assertFalse(res["sig_ok"])

    def test_tampered_disclosure_breaks_structure(self):
        # flip a character inside the first presented disclosure → its digest is no longer committed
        if not self.rest:
            self.skipTest("reference SD-JWT has no disclosures")
        parts = self.compact.split("~")
        # find the first non-empty disclosure part (index >= 1)
        for i in range(1, len(parts)):
            if parts[i] and parts[i].count(".") == 0:
                original = parts[i]
                parts[i] = ("A" if original[0] != "A" else "B") + original[1:]
                break
        tampered = "~".join(parts)
        res = verify_sd_jwt(tampered, self.pubkey)
        self.assertFalse(res["structure_ok"])

    def test_uncommitted_disclosure_breaks_structure(self):
        # append a well-formed disclosure whose digest is NOT committed in the payload
        forged = base64.urlsafe_b64encode(
            json.dumps(["c2FsdA", "injected", "value"], separators=(",", ":")).encode()
        ).rstrip(b"=").decode("ascii")
        parts = self.compact.split("~")
        # insert before a trailing empty element if present, else append
        if parts and parts[-1] == "":
            parts.insert(-1, forged)
        else:
            parts.append(forged)
        res = verify_sd_jwt("~".join(parts), self.pubkey)
        self.assertFalse(res["structure_ok"])


    def test_duplicate_key_in_disclosure_rejected(self):
        # F12 parser-differential: a disclosure whose JSON value carries a DUPLICATE key must be rejected
        # (loads_strict), not last-wins-parsed. A recently-shipped security fix that had no test.
        forged = base64.urlsafe_b64encode(b'["c2FsdA", "claim", {"k": 1, "k": 2}]').rstrip(b"=").decode()
        parts = self.compact.split("~")
        parts.insert(1, forged)
        res = verify_sd_jwt("~".join(parts), self.pubkey)
        self.assertFalse(res["structure_ok"])
        self.assertIn("duplicate", res["detail"].lower())

    def test_sd_alg_downgrade_rejected(self):
        # an issuer payload _sd_alg of a weak/unknown hash (md5) must be rejected — a downgrade would let an
        # attacker-chosen weak hash bind the disclosures.
        payload = json.loads(_b64url_decode(self.payload_b64))
        payload["_sd_alg"] = "md5"
        p2 = _b64url(payload)
        jwt = f"{self.header_b64}.{p2}.{self.sig_b64}"
        compact = f"{jwt}~{self.rest}" if self.rest else jwt
        res = verify_sd_jwt(compact, self.pubkey)
        self.assertFalse(res["structure_ok"])
        self.assertIn("_sd_alg", res["detail"])


if __name__ == "__main__":
    unittest.main()
