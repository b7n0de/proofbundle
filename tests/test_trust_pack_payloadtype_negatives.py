"""WP-F / §9 criterion 5 — trust-pack payloadType/predicateType confusion negative vectors.

The audit-candidate obligation O7 (payloadType binding) is exercised here as the machine-checkable
NEGATIVE surface the acceptance criterion names: a Trust Pack verifier must REJECT (never accept, never
raw-crash) an envelope whose payloadType field or whose in-toto predicateType has been confused with a
different type. Both directions are asserted: a genuine pack still verifies (no over-firing), and every
confusion variant is a typed rejection (ok is False) without a raw traceback.
"""
from __future__ import annotations

import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proofbundle import dsse  # noqa: E402
from proofbundle.emit import generate_signer  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402
from proofbundle.trust_pack import (  # noqa: E402
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    TRUST_PACK_PREDICATE_TYPE,
    sign_trust_pack,
    verify_trust_pack,
)


def _pack_envelope():
    r1, r2, r3 = generate_signer(), generate_signer(), generate_signer()
    pub = {kid: base64.b64encode(sk.public_key().public_bytes_raw()).decode()
           for kid, sk in (("r1", r1), ("r2", r2), ("r3", r3))}
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    predicate = {
        "schemaVersion": "0.1.0", "trustPackId": "tp-payloadtype-neg", "version": 1,
        "expires": expires, "prevVersionDigest": None,
        "roles": {"root": {"keyIds": ["r1", "r2", "r3"], "threshold": 2}},
        "keys": {kid: {"publicKey": pk} for kid, pk in pub.items()},
        "nonClaims": ["does not assert the key holders are honest, only that a threshold signed"],
    }
    return sign_trust_pack(predicate, {"r1": r1, "r2": r2}), predicate, {"r1": r1, "r2": r2, "r3": r3}


class TestTrustPackPayloadTypeNegatives(unittest.TestCase):
    def test_genuine_pack_verifies_no_overfire(self):
        env, _pred, _keys = _pack_envelope()
        r = verify_trust_pack(env)
        self.assertTrue(r["ok"], r["errors"])
        self.assertTrue(r["predicate_type_ok"])
        self.assertTrue(r["root_threshold_met"])

    def test_confused_envelope_payloadtype_is_rejected(self):
        # The signed bytes are untouched; only the envelope's payloadType FIELD is mislabelled. A
        # downstream consumer trusting that field must not be fed an accepted verdict.
        env, _pred, _keys = _pack_envelope()
        env2 = dict(env)
        env2["payloadType"] = "application/vnd.attacker+json"
        r = verify_trust_pack(env2)
        self.assertFalse(r["ok"])
        self.assertFalse(r["predicate_type_ok"])
        self.assertTrue(any("payloadType" in e for e in r["errors"]))

    def test_nonstring_payloadtype_is_typed_reject_not_crash(self):
        env, _pred, _keys = _pack_envelope()
        for bad in (None, 123, [], {}, True):
            env2 = dict(env)
            env2["payloadType"] = bad
            try:
                r = verify_trust_pack(env2)
            except ProofBundleError:
                continue  # a typed rejection is also acceptable defended behaviour
            self.assertFalse(r["ok"], f"payloadType={bad!r} must not be accepted")

    def test_wrong_predicate_type_is_rejected(self):
        # A validly-SIGNED in-toto statement of a DIFFERENT predicateType presented to the trust-pack
        # verifier: the classic type-confusion. predicateType binding must reject it.
        r1 = generate_signer()
        body = json.dumps({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://proofbundle.dev/decision-receipt/v0.1",  # NOT trust-pack
            "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
            "predicate": {"schemaVersion": "0.1.0"},
        }).encode()
        env = dsse.sign_envelope(body, r1, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid="r1")
        r = verify_trust_pack(env)
        self.assertFalse(r["ok"])
        self.assertFalse(r["predicate_type_ok"])
        self.assertNotEqual(TRUST_PACK_PREDICATE_TYPE,
                            "https://proofbundle.dev/decision-receipt/v0.1")


if __name__ == "__main__":
    unittest.main()
