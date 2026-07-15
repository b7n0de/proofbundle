"""Finding 16 — the `outcomeReceivers` Trust Pack role (mirrors `outcomeExecutors`), additive.

Minimal, direct coverage of `trust_pack.py` itself (the bulk of the wiring is exercised through
`outcome.py`'s `receiver_trusted_by_role` in tests/test_outcome_receiver_corroboration.py — this file
proves the role is accepted end-to-end by the real hand-rolled validator + threshold sign/verify path, not
just constructed as a bare dict literal)."""
from __future__ import annotations

import unittest

from proofbundle.emit import generate_signer
from proofbundle.trust_pack import (
    _ROLE_NAMES,
    sign_trust_pack,
    validate_trust_pack_predicate,
    verify_trust_pack,
)


def _b64_pub(signer) -> str:
    import base64
    return base64.b64encode(signer.public_key().public_bytes_raw()).decode("ascii")


class TestOutcomeReceiversRoleAccepted(unittest.TestCase):
    def test_role_name_is_declared(self):
        self.assertIn("outcomeReceivers", _ROLE_NAMES)

    def test_pack_with_outcome_receivers_role_validates(self):
        root = generate_signer()
        receiver = generate_signer()
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-recv", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                     "outcomeReceivers": {"keyIds": ["recv-0"], "threshold": 1}},
            "keys": {"root-0": {"publicKey": _b64_pub(root)}, "recv-0": {"publicKey": _b64_pub(receiver)}},
            "nonClaims": ["names which keys hold which role, not that the holders are honest"],
        }
        self.assertEqual(validate_trust_pack_predicate(pred), [])

    def test_unknown_role_name_still_rejected(self):
        # the addition of outcomeReceivers must not have accidentally widened the allowlist beyond the
        # declared _ROLE_NAMES tuple.
        root = generate_signer()
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-bad", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                     "outcomeSpectators": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": {"root-0": {"publicKey": _b64_pub(root)}},
            "nonClaims": ["x"],
        }
        errs = validate_trust_pack_predicate(pred)
        self.assertTrue(any("outcomeSpectators" in e for e in errs), errs)

    def test_signed_pack_with_outcome_receivers_role_verifies(self):
        root = generate_signer()
        receiver = generate_signer()
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-recv-2", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                     "outcomeReceivers": {"keyIds": ["recv-0"], "threshold": 1}},
            "keys": {"root-0": {"publicKey": _b64_pub(root)}, "recv-0": {"publicKey": _b64_pub(receiver)}},
            "nonClaims": ["names which keys hold which role, not that the holders are honest"],
        }
        env = sign_trust_pack(pred, {"root-0": root})
        r = verify_trust_pack(env)
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["root_threshold_met"])


if __name__ == "__main__":
    unittest.main()
