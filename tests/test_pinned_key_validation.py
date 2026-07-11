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
# a genuine full-order key (speccheck case 2's pub) — must be ACCEPTED
_FULL_ORDER_B64 = base64.b64encode(
    bytes.fromhex("f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43")).decode()


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


if __name__ == "__main__":
    unittest.main()
