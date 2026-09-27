"""Lens run (Claude family) on fix/every-constant-lookup-on-a-foreign-key-is-classified at e5b39b81.

Every case below was RED at e5b39b81228bc24b5ed837547721fbdf4b24a7d9 and at main 31816e08 when it was
written (python -m pytest on this file, Python 3.11.15), and is the reproduction of one row of
REVIEW_lens_claude_234_e5b39b81228b.md. No production code changes. Oracles: the Token Status List
draft's form for `bits` ("JSON Integer", one of 1, 2, 4, 8) and the house rule the same function holds
for `iat`, `exp` and `ttl` (M2, M3); the function's own documented contract (M1, M3, M4).
"""
from __future__ import annotations

import base64
import json
import unittest
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import evalclaim as ec
from proofbundle import statuslist
from proofbundle.emit import emit_bundle
from proofbundle.errors import ProofBundleError

_SK = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
_PK = _SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_URI = "https://status.example/1"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _token(bits) -> str:
    """A correctly signed Status List Token whose `status_list.bits` is `bits`, over a 1-bit list."""
    payload = {"sub": _URI, "iat": 1000,
               "status_list": {"bits": bits, "lst": _b64u(zlib.compress(bytes([0b0101]), 9))}}
    kopf = _b64u(json.dumps({"alg": "EdDSA", "typ": statuslist.TYP}).encode())
    rumpf = _b64u(json.dumps(payload).encode())
    return f"{kopf}.{rumpf}.{_b64u(_SK.sign(f'{kopf}.{rumpf}'.encode()))}"


def _verify(bits) -> dict:
    return statuslist.verify_status_snapshot(_token(bits), expected_uri=_URI, index=0, issuer_pubkey=_PK)


class M1TheRelyingPartysListIsReadWithoutRaising(unittest.TestCase):
    """PROPERTY: verify_agt_receipt answers with a result or a typed refusal. `a_key in
    set(trusted_authorizer_keys)` hashes every element of the relying party's list, and an unhashable
    one raises a raw TypeError. The membership guard names this site as safe "behind an
    isinstance(x, str)"; that holds for `a_key`, not for the list. P2: fail-closed, wrong error;
    the caller's configuration, not the receipt."""

    def test_m1_unhashable_entry_in_trusted_authorizer_keys(self) -> None:
        from proofbundle.adapters.agt_receipt import verify_agt_receipt  # noqa: PLC0415
        pfad = Path(__file__).resolve().parent / "vektoren" / "agt_receipts" / "03_extern_autorisiert.json"
        receipt = json.loads(pfad.read_text(encoding="utf-8"))
        self.assertTrue(verify_agt_receipt(
            receipt, trusted_authorizer_keys=[receipt["authorizer_public_key"]]).ok)
        for eintrag in ([], {}, ["a"]):
            with self.subTest(entry=eintrag):
                try:
                    ergebnis = verify_agt_receipt(
                        receipt, trusted_authorizer_keys=[eintrag, receipt["authorizer_public_key"]])
                except ProofBundleError:
                    continue
                self.assertIsNotNone(ergebnis)


class M2ABooleanIsNoBitWidth(unittest.TestCase):
    """PROPERTY: `bits` is one of the integers 1, 2, 4, 8. `bits not in (1, 2, 4, 8)` classifies
    `true` as known, because True == 1 and hash(True) == hash(1): a signed token with `"bits": true`
    verifies ok=True and is read as a 1-bit list, and issue_status_list_token(bits=True) signs one.
    The same function refuses a bool for `iat`, `exp` and `ttl`. P1: the bound admits a value of
    another JSON type."""

    def test_m2_verify_bits_true(self) -> None:
        self.assertTrue(_verify(1)["ok"])
        self.assertFalse(_verify(True)["ok"])

    def test_m2_issue_bits_true(self) -> None:
        with self.assertRaises(ProofBundleError):
            statuslist.issue_status_list_token([1, 0], uri=_URI, signer=_SK, iat=1, bits=True)


class M3AFloatBitWidthIsARefusalNotACrash(unittest.TestCase):
    """PROPERTY: verify_status_snapshot returns its result dict for every token (its docstring and
    the comments at its guards: 'never crashes'). `"bits": 2.0` passes `bits not in (1, 2, 4, 8)`
    (2.0 == 2), then `8 // bits` is a float and `bit_array[byte_i]` raises a raw TypeError. P1."""

    def test_m3_verify_bits_float(self) -> None:
        for bits in (1.0, 2.0, 4.0, 8.0):
            with self.subTest(bits=bits):
                try:
                    ergebnis = _verify(bits)
                except TypeError as exc:
                    self.fail(f"raw TypeError out of verify_status_snapshot: {exc}")
                self.assertFalse(ergebnis["ok"])


class M4ARefusalNeedsADeclaration(unittest.TestCase):
    """PROPERTY (classify_eval_claim's own rule for the envelope identifier): only a present,
    non-empty string that is not ours declares a foreign format; an absent value or one that is no
    usable identifier stays `invalid`. At the payload, `claim.get("schema") != EVAL_CLAIM_SCHEMA`
    classifies all of them as an unknown schema. P1: fail-closed, wrong outcome class. The same case
    is L11 of the D4 lens run; it is this branch's class."""

    def test_m4_payload_schema_without_a_declaration(self) -> None:
        claim, _ = ec.build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
            score="0.5", n=100, model_id="m", dataset_id="d", issuer="x",
            timestamp="2026-07-09T10:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        signed = ec.decode_eval_claim(ec.emit_eval_receipt(claim, _SK))
        for label, value in (("absent", None), ("null", "null"), ("empty", ""), ("int", 1),
                             ("list", [ec.EVAL_CLAIM_SCHEMA])):
            with self.subTest(schema=label):
                payload = dict(signed)
                if value is None:
                    del payload["schema"]
                else:
                    payload["schema"] = None if value == "null" else value
                bundle = emit_bundle(ec.canonicalize(payload), _SK)
                self.assertEqual(ec.classify_eval_claim(bundle)[0], ec.CLAIM_INVALID)


if __name__ == "__main__":
    unittest.main()
