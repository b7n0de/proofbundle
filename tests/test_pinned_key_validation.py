"""Review-hardening: a PINNED trusted Ed25519 key must not be a low-order point.

The core verifier deliberately accepts small-/mixed-order public keys (SPEC §4a, "Taming the Many
EdDSAs"). A trust policy that PINS such a key as a trusted issuer / decision-maker would then accept a
fixed (pub, sig) pair as a valid signature for a large fraction of arbitrary messages with NO private
key — forgery of a trusted identity without a secret. `load_policy` must reject a low-order pinned key.
The low-order encodings here are the exact ed25519-speccheck small-order vectors this repo ships.
"""
import base64
import unittest

from proofbundle.policy import PolicyError, load_policy

# ed25519-speccheck small-order public keys (order 8 and order 2) — also in tests/fixtures/ed25519_speccheck_cases.json
_LOW_ORDER_B64 = [
    base64.b64encode(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")).decode(),
    base64.b64encode(bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).decode(),
]
# a genuine full-order key from an honest keygen — must be ACCEPTED (NOT a speccheck vector: those
# include mixed-/small-order points; fix-review caught that case 2 is "mixed-order A", not full-order)
from proofbundle.emit import generate_signer  # noqa: E402
_FULL_ORDER_B64 = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode()


class TestPinnedKeyValidation(unittest.TestCase):
    def test_low_order_allowed_issuer_rejected(self):
        for k in _LOW_ORDER_B64:
            with self.assertRaises(PolicyError):
                load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                             "allowed_issuers": [{"public_key_b64": k}]})

    def test_low_order_trusted_decision_maker_rejected(self):
        for k in _LOW_ORDER_B64:
            with self.assertRaises(PolicyError):
                load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "x",
                             "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": k}]}})

    def test_full_order_key_accepted(self):
        load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                     "allowed_issuers": [{"public_key_b64": _FULL_ORDER_B64}]})

    def test_non_base64_and_wrong_length_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                         "allowed_issuers": [{"public_key_b64": "!!!not-base64!!!"}]})
        short = base64.b64encode(b"\x01" * 16).decode()
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                         "allowed_issuers": [{"public_key_b64": short}]})

    def test_sign_variant_and_non_canonical_encodings_rejected(self):
        # Fix-review re-break: a hand-kept byte-string blocklist missed these three low-order/identity
        # encodings (sign-bit and non-canonical-y variants); the y-value check must catch all of them.
        for h in ("0100000000000000000000000000000000000000000000000000000000000080",  # identity, sign=1
                  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y=p+1 (non-canonical)
                  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"):  # y=p (non-canonical)
            k = base64.b64encode(bytes.fromhex(h)).decode()
            with self.assertRaises(PolicyError):
                load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
                             "allowed_issuers": [{"public_key_b64": k}]})

    def test_evaluate_layer_refuses_low_order_key_even_without_load_policy(self):
        # Fix-review Finding 2 (defense-in-depth): a policy dict that skipped load_policy must still not
        # grant trust to a low-order pinned decision-maker key.
        from proofbundle.policy import evaluate_decision_policy
        low = base64.b64encode(bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")).decode()
        raw_policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "x",
                      "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": low}]}}
        stmt = {"predicateType": "x", "predicate": {"decisionMaker": {"id": "dm"}}}
        pe = evaluate_decision_policy(stmt, {}, raw_policy, signer_public_key_b64=low)
        self.assertFalse(pe["signer_trusted"])


if __name__ == "__main__":
    unittest.main()
