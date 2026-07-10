"""WP7 tamper/fuzz matrix for Decision Receipts (systematic, deterministic, fail-closed lock-in).

Where test_decision_verify.py checks a handful of hand-picked tamper cases, this sweeps them:
every signature byte, a spread of payload bytes, every required field deleted, every top-level field
type-confused, ten malformed-envelope classes, and a batch of wrong keys. The properties asserted are
the integrity contract itself: any single tamper of a signed receipt breaks crypto_ok, no wrong key ever
accepts, and no malformed input escapes as an untyped exception (only the typed ProofBundleError family or
a fail-closed result). Sweeps are bounded so CI stays fast; unittest-style to match `python -m unittest`."""
from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from proofbundle.decision import (
    ProofBundleError,
    _ALLOWED_TOP,
    _REQUIRED_ALWAYS,
    _REQUIRED_STRICT,
    emit_decision_receipt,
    validate_decision_predicate,
    verify_decision_receipt,
)
from proofbundle.emit import generate_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


class TestDecisionFuzz(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.env = emit_decision_receipt(_pred("deny"), self.signer, strict=True)

    def test_signature_bitflip_sweep_all_break_crypto(self):
        """Flip every single bit-carrying byte of the Ed25519 signature; each must fail crypto (no forgery)."""
        raw = base64.b64decode(self.env["signatures"][0]["sig"])
        self.assertEqual(len(raw), 64, "Ed25519 signature is 64 bytes")
        for i in range(len(raw)):
            mut = bytearray(raw)
            mut[i] ^= 0x01
            env = copy.deepcopy(self.env)
            env["signatures"][0]["sig"] = base64.b64encode(bytes(mut)).decode()
            self.assertIs(verify_decision_receipt(env, self.pub)["crypto_ok"], False, f"sig byte {i}")

    def test_payload_byte_mutation_never_accepts(self):
        """Mutate a spread of payload bytes; the payload is the signed material, so each must fail closed
        (crypto_ok False, or a typed BundleFormatError when the mutation also breaks JSON/UTF-8)."""
        raw = bytearray(base64.b64decode(self.env["payload"]))
        step = max(1, len(raw) // 40)
        for i in range(0, len(raw), step):
            mut = bytearray(raw)
            mut[i] ^= 0x20
            env = copy.deepcopy(self.env)
            env["payload"] = base64.b64encode(bytes(mut)).decode()
            try:
                self.assertIsNot(verify_decision_receipt(env, self.pub)["crypto_ok"], True, f"payload byte {i}")
            except ProofBundleError:
                pass  # mutation broke the JSON structure -> typed fail-closed, acceptable

    def test_wrong_key_never_accepts(self):
        """A batch of independent keys must all reject the receipt (no probabilistic false accept)."""
        for n in range(16):
            other = generate_signer().public_key().public_bytes_raw()
            self.assertIs(verify_decision_receipt(self.env, other)["crypto_ok"], False, f"key {n}")

    def test_required_field_deletion_fail_closed(self):
        """Deleting any always/strict-required predicate field must be rejected by the strict validator."""
        pred = _pred("deny")
        for field in sorted(set(_REQUIRED_ALWAYS) | set(_REQUIRED_STRICT)):
            self.assertIn(field, pred, f"the deny example should carry required field {field!r}")
            broken = copy.deepcopy(pred)
            del broken[field]
            self.assertTrue(validate_decision_predicate(broken, strict=True),
                            f"deleting required {field!r} must be rejected")

    def test_type_confusion_sweep_no_crash(self):
        """Replacing any top-level field with a wrong-typed value must never crash the validator; it returns
        a list of errors (fail-closed), never an exception."""
        for field in sorted(_ALLOWED_TOP):
            for bad in (None, 123, [], "", {"x": 1}, True):
                broken = _pred("deny")
                broken[field] = bad
                try:
                    errs = validate_decision_predicate(broken, strict=True)
                except Exception as exc:  # noqa: BLE001 - the point is to prove nothing leaks
                    self.fail(f"validate crashed on {field}={bad!r}: {type(exc).__name__}: {exc}")
                self.assertIsInstance(errs, list)

    def test_malformed_envelopes_fail_closed(self):
        """Ten malformed-envelope classes must each fail closed: a typed ProofBundleError or a result whose
        crypto_ok is not True. No untyped exception (KeyError, binascii.Error, ...) may escape verify."""
        env = self.env
        cases = {
            "empty_dict": {},
            "no_payload": {"payloadType": "x", "signatures": [{"sig": "AA"}]},
            "no_signatures": {"payload": env["payload"], "payloadType": env["payloadType"]},
            "sig_not_b64": {**copy.deepcopy(env), "signatures": [{"sig": "!!!notb64!!!"}]},
            "payload_not_b64": {**copy.deepcopy(env), "payload": "!!!notb64!!!"},
            "payload_not_json": {**copy.deepcopy(env), "payload": base64.b64encode(b"\xff\x00 raw").decode()},
            "signatures_empty": {**copy.deepcopy(env), "signatures": []},
            "sig_entry_empty": {**copy.deepcopy(env), "signatures": [{}]},
            "payload_int": {**copy.deepcopy(env), "payload": 123},
            "signatures_none": {**copy.deepcopy(env), "signatures": None},
        }
        for name, garbage in cases.items():
            try:
                result = verify_decision_receipt(garbage, self.pub)
            except ProofBundleError:
                continue  # typed fail-closed
            except Exception as exc:  # noqa: BLE001 - a leaked untyped exception is the failure we hunt
                self.fail(f"{name}: leaked untyped {type(exc).__name__}: {exc}")
            self.assertIsNot(result.get("crypto_ok"), True, f"{name} must not verify")


if __name__ == "__main__":
    unittest.main()
