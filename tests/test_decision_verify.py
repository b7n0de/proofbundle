"""WP3 tests: DSSE emit/verify of Decision Receipts (crypto core, fail-closed).

Roundtrip, tamper detection, wrong-key, predicateType confusion attack, audience/nonce replay, and the
RFC-8785 hash-binding rule. unittest-style to match the repo's `python -m unittest discover`."""
from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from proofbundle import dsse
from proofbundle.decision import (
    DECISION_RECEIPT_PREDICATE_TYPE,
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    _rfc8785_bytes,
    build_decision_statement,
    emit_decision_receipt,
    verify_decision_receipt,
)
from proofbundle.emit import generate_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _repayload(env: dict, statement: dict) -> dict:
    env = copy.deepcopy(env)
    env["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    return env


class TestDecisionVerify(unittest.TestCase):
    def test_roundtrip_all_checks_green(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True,
                                    expected_audience=p["validity"]["audience"][0],
                                    expected_nonce=p["validity"]["nonce"])
        self.assertTrue(r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"])
        self.assertTrue(r["evidence_bound"] and r["audience_ok"] and r["nonce_ok"])
        self.assertEqual(r["errors"], [])

    def test_tamper_breaks_crypto(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        body = json.loads(base64.b64decode(env["payload"]))
        body["predicate"]["decision"]["verdict"] = "ALLOW"
        self.assertIs(verify_decision_receipt(_repayload(env, body), pub)["crypto_ok"], False)

    def test_wrong_key_fails(self):
        s, _ = _keys()
        env = emit_decision_receipt(_pred("deny"), s)
        _, other_pub = _keys()
        self.assertIs(verify_decision_receipt(env, other_pub)["crypto_ok"], False)

    def test_predicate_type_confusion_rejected(self):
        p = _pred("deny")
        s, pub = _keys()
        stmt = build_decision_statement(p)
        stmt["predicateType"] = "https://b7n0de.com/proofbundle/predicates/eval-result/v0.1"
        env = dsse.sign_envelope(_rfc8785_bytes(stmt), s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_decision_receipt(env, pub)
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["predicate_type_ok"], False)
        self.assertIs(r["structure_ok"], False)
        self.assertTrue(any("confusion attack" in e for e in r["errors"]))

    def test_audience_and_nonce_replay(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        self.assertIs(verify_decision_receipt(env, pub, expected_audience="https://evil.example/x")["audience_ok"], False)
        self.assertIs(verify_decision_receipt(env, pub, expected_nonce="deadbeef")["nonce_ok"], False)

    def test_hash_binding_non_canonical_payload_rejected(self):
        p = _pred("deny")
        s, pub = _keys()
        stmt = build_decision_statement(p)
        non_canonical = json.dumps(stmt, indent=2).encode()
        env = dsse.sign_envelope(non_canonical, s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_decision_receipt(env, pub)
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["structure_ok"], False)
        self.assertTrue(any("RFC-8785 canonical" in e for e in r["errors"]))

    def test_emit_rejects_invalid_predicate(self):
        p = _pred("deny")
        del p["decision"]
        s, _ = _keys()
        with self.assertRaises(Exception):
            emit_decision_receipt(p, s, strict=True)

    def test_emitted_statement_shape(self):
        p = _pred("deny")
        stmt = build_decision_statement(p)
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], DECISION_RECEIPT_PREDICATE_TYPE)
        self.assertEqual(stmt["subject"][0]["name"], f"decision:{p['decisionId']}")
        self.assertEqual(len(stmt["subject"][0]["digest"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
