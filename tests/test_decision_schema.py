"""Bidirectional tests for the decision-receipt/v0.1 predicate validator (fail-closed).

Positive: the 4 golden examples validate clean in strict mode. Negative: unknown fields, bad enums, missing
required fields, non-RFC3339-Z timestamps, malformed digests and generic `timestamp` are all rejected.
unittest-style to match the repo's `python -m unittest discover`."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from proofbundle.decision import (
    DECISION_RECEIPT_PREDICATE_TYPE,
    action_outcome_proven,
    validate_decision_predicate,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def _deny() -> dict:
    return _load("decision_receipt_deny.json")


class TestDecisionSchema(unittest.TestCase):
    def test_golden_examples_validate_strict(self):
        for name in ("allow", "deny", "escalate"):
            self.assertEqual(validate_decision_predicate(_load(f"decision_receipt_{name}.json"), strict=True), [], name)

    def test_wrapped_statement_predicate_validates(self):
        stmt = _load("decision_receipt_with_eval_ref.intoto.json")
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], DECISION_RECEIPT_PREDICATE_TYPE)
        self.assertEqual(validate_decision_predicate(stmt["predicate"], strict=True), [])

    def test_unknown_top_level_field_rejected(self):
        p = _deny()
        p["surpriseField"] = 1
        self.assertTrue(any("unknown top-level field" in e for e in validate_decision_predicate(p)))

    def test_generic_timestamp_forbidden(self):
        p = _deny()
        p["timestamp"] = "2026-07-09T10:00:00Z"
        self.assertTrue(any("timestamp" in e and "forbidden" in e for e in validate_decision_predicate(p)))

    def test_bad_verdict_rejected(self):
        p = _deny()
        p["decision"]["verdict"] = "MAYBE"
        self.assertTrue(any("verdict must be one of" in e for e in validate_decision_predicate(p)))

    def test_empty_reason_codes_rejected(self):
        p = _deny()
        p["decision"]["reasonCodes"] = []
        self.assertTrue(any("reasonCodes" in e for e in validate_decision_predicate(p)))

    def test_bad_decision_type_rejected(self):
        p = _deny()
        p["decisionType"] = "guessing"
        self.assertTrue(any("decisionType must be one of" in e for e in validate_decision_predicate(p)))

    def test_non_rfc3339z_time_rejected(self):
        p = _deny()
        p["decidedAt"] = "2026-07-09 10:00:00"
        self.assertTrue(any("decidedAt must be RFC3339" in e for e in validate_decision_predicate(p)))

    def test_missing_required_field_rejected(self):
        p = _deny()
        del p["policyBoundary"]
        self.assertTrue(any("missing required field 'policyBoundary'" in e for e in validate_decision_predicate(p)))

    def test_malformed_digest_rejected_in_strict(self):
        p = _deny()
        p["policyBoundary"]["policyDigest"]["sha256"] = "tooshort"
        self.assertTrue(any("policyDigest" in e for e in validate_decision_predicate(p, strict=True)))

    def test_strict_requires_notchecked_privacy(self):
        p = _deny()
        del p["notChecked"]
        del p["privacy"]
        errs = validate_decision_predicate(p, strict=True)
        self.assertTrue(any("notChecked" in e for e in errs) and any("privacy" in e for e in errs))
        self.assertFalse(any("notChecked" in e for e in validate_decision_predicate(p, strict=False)))

    def test_field_order_independent(self):
        p = _deny()
        reordered = dict(reversed(list(p.items())))
        self.assertEqual(validate_decision_predicate(reordered, strict=True), [])

    def test_action_outcome_proven(self):
        self.assertIs(action_outcome_proven(_load("decision_receipt_allow.json")), True)
        self.assertIsNone(action_outcome_proven(_deny()))
        p = copy.deepcopy(_load("decision_receipt_allow.json"))
        p["actionOutcome"]["outcomeRef"] = None
        self.assertIs(action_outcome_proven(p), False)


if __name__ == "__main__":
    unittest.main()
