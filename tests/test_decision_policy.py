"""WP5 tests: trust policy v0.2 decision_receipt section + evaluate_decision_policy (fail-closed).

Backward compat (v0.1 policy valid under the v0.2 parser), the additive section rules, signer<->trusted-key
binding, predicateType confusion at the policy layer, and the exit-3 contract end to end.
unittest-style to match the repo's `python -m unittest discover`."""
from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from proofbundle.decision import build_decision_statement, emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.policy import PolicyError, evaluate_decision_policy, load_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _keys():
    s = generate_signer()
    return s, base64.b64encode(s.public_key().public_bytes_raw()).decode()


def _policy_trusting(pub_b64: str, **overrides) -> dict:
    section = {
        "accepted_predicate_types": ["https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1"],
        "trusted_decision_makers": [{"id": "https://example.org/decision-platform/proofbundle-gate/v1", "public_key_b64": pub_b64}],
        "allowed_decision_types": ["preActionAuthorization", "humanEscalation"],
        "allowed_verdicts": ["ALLOW", "DENY", "ESCALATE"],
        "required_evidence_relations": ["evalResult"],
        "require_policy_digest": True,
    }
    section.update(overrides)
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t", "decision_receipt": section}


class TestDecisionPolicyLoad(unittest.TestCase):
    def test_v01_policy_valid_under_v02_parser(self):
        v01 = load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x"})
        self.assertEqual(v01["schema"], "proofbundle/trust-policy/v0.1")

    def test_v02_decision_section_loads(self):
        p = load_policy(_policy_trusting("AAAA"))
        self.assertIs(p["decision_receipt"]["require_policy_digest"], True)

    def test_decision_section_under_v01_schema_rejected(self):
        bad = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
               "decision_receipt": {"require_policy_digest": True}}
        with self.assertRaises(PolicyError):
            load_policy(bad)

    def test_unknown_decision_field_rejected(self):
        bad = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "x", "decision_receipt": {"surprise": 1}}
        with self.assertRaises(PolicyError):
            load_policy(bad)


class TestEvaluateDecisionPolicy(unittest.TestCase):
    def test_trusted_signer_policy_ok(self):
        _, pub = _keys()
        stmt = build_decision_statement(_pred("deny"))
        r = evaluate_decision_policy(stmt, {}, load_policy(_policy_trusting(pub)), signer_public_key_b64=pub)
        self.assertTrue(r["signer_trusted"] and r["policy_ok"] and r["errors"] == [])

    def test_untrusted_signer_fails(self):
        _, pub = _keys()
        _, other = _keys()
        stmt = build_decision_statement(_pred("deny"))
        r = evaluate_decision_policy(stmt, {}, load_policy(_policy_trusting(other)), signer_public_key_b64=pub)
        self.assertIs(r["signer_trusted"], False)
        self.assertIs(r["policy_ok"], False)

    def test_predicate_type_confusion_fails_policy(self):
        _, pub = _keys()
        stmt = build_decision_statement(_pred("deny"))
        stmt["predicateType"] = "https://b7n0de.com/proofbundle/predicates/eval-result/v0.1"
        r = evaluate_decision_policy(stmt, {}, load_policy(_policy_trusting(pub)), signer_public_key_b64=pub)
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("accepted_predicate_types" in e for e in r["errors"]))

    def test_verdict_not_allowed_fails(self):
        _, pub = _keys()
        p = _policy_trusting(pub, allowed_verdicts=["ALLOW"])
        r = evaluate_decision_policy(build_decision_statement(_pred("deny")), {}, load_policy(p), signer_public_key_b64=pub)
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("verdict" in e for e in r["errors"]))

    def test_missing_required_evidence_relation_fails(self):
        _, pub = _keys()
        pred = _pred("deny")
        pred["evidenceRefs"] = []
        r = evaluate_decision_policy(build_decision_statement(pred), {}, load_policy(_policy_trusting(pub)), signer_public_key_b64=pub)
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("evidence relations" in e for e in r["errors"]))

    def test_no_decision_section_is_not_evaluated(self):
        r = evaluate_decision_policy(build_decision_statement(_pred("deny")), {},
                                     {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x"},
                                     signer_public_key_b64="AAAA")
        self.assertIsNone(r["policy_ok"])


class TestVerifyWithPolicy(unittest.TestCase):
    def test_verify_with_policy_ok(self):
        s, pub = _keys()
        env = emit_decision_receipt(_pred("deny"), s, strict=True)
        r = verify_decision_receipt(env, s.public_key().public_bytes_raw(), strict=True,
                                    policy=load_policy(_policy_trusting(pub)))
        self.assertTrue(r["crypto_ok"] and r["structure_ok"] and r["policy_ok"] and r["signer_trusted"])

    def test_verify_with_policy_violation(self):
        s, _ = _keys()
        env = emit_decision_receipt(_pred("deny"), s, strict=True)
        _, other = _keys()
        r = verify_decision_receipt(env, s.public_key().public_bytes_raw(),
                                    policy=load_policy(_policy_trusting(other)))
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["policy_ok"], False)


if __name__ == "__main__":
    unittest.main()
