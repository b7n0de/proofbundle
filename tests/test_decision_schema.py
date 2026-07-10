"""Bidirectional tests for the decision-receipt/v0.1 predicate validator (fail-closed).

Positive: the 4 golden examples validate clean in strict mode. Negative: unknown fields, bad enums, missing
required fields, non-RFC3339-Z timestamps, malformed digests and generic `timestamp` are all rejected."""
from __future__ import annotations

import copy
import json
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


# ── Positive ────────────────────────────────────────────────────────────────
def test_golden_examples_validate_strict():
    for name in ("allow", "deny", "escalate"):
        errs = validate_decision_predicate(_load(f"decision_receipt_{name}.json"), strict=True)
        assert errs == [], (name, errs)


def test_wrapped_statement_predicate_validates():
    stmt = _load("decision_receipt_with_eval_ref.intoto.json")
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == DECISION_RECEIPT_PREDICATE_TYPE
    assert validate_decision_predicate(stmt["predicate"], strict=True) == []


# ── Negative (fail-closed) ──────────────────────────────────────────────────
def test_unknown_top_level_field_rejected():
    p = _deny()
    p["surpriseField"] = 1
    assert any("unknown top-level field" in e for e in validate_decision_predicate(p))


def test_generic_timestamp_forbidden():
    p = _deny()
    p["timestamp"] = "2026-07-09T10:00:00Z"
    assert any("timestamp" in e and "forbidden" in e for e in validate_decision_predicate(p))


def test_bad_verdict_rejected():
    p = _deny()
    p["decision"]["verdict"] = "MAYBE"
    assert any("verdict must be one of" in e for e in validate_decision_predicate(p))


def test_empty_reason_codes_rejected():
    p = _deny()
    p["decision"]["reasonCodes"] = []
    assert any("reasonCodes" in e for e in validate_decision_predicate(p))


def test_bad_decision_type_rejected():
    p = _deny()
    p["decisionType"] = "guessing"
    assert any("decisionType must be one of" in e for e in validate_decision_predicate(p))


def test_non_rfc3339z_time_rejected():
    p = _deny()
    p["decidedAt"] = "2026-07-09 10:00:00"
    assert any("decidedAt must be RFC3339" in e for e in validate_decision_predicate(p))


def test_missing_required_field_rejected():
    p = _deny()
    del p["policyBoundary"]
    assert any("missing required field 'policyBoundary'" in e for e in validate_decision_predicate(p))


def test_malformed_digest_rejected_in_strict():
    p = _deny()
    p["policyBoundary"]["policyDigest"]["sha256"] = "tooshort"
    assert any("policyDigest" in e for e in validate_decision_predicate(p, strict=True))


def test_strict_requires_notchecked_privacy():
    p = _deny()
    del p["notChecked"]
    del p["privacy"]
    errs = validate_decision_predicate(p, strict=True)
    assert any("notChecked" in e for e in errs) and any("privacy" in e for e in errs)
    # but non-strict tolerates their absence
    assert not any("notChecked" in e for e in validate_decision_predicate(p, strict=False))


def test_field_order_independent():
    p = _deny()
    reordered = dict(reversed(list(p.items())))
    assert validate_decision_predicate(reordered, strict=True) == []


# ── action_outcome_proven honesty limit ─────────────────────────────────────
def test_action_outcome_proven():
    assert action_outcome_proven(_load("decision_receipt_allow.json")) is True   # executed + signed outcomeRef
    assert action_outcome_proven(_deny()) is None                                 # status blocked -> N/A
    p = copy.deepcopy(_load("decision_receipt_allow.json"))
    p["actionOutcome"]["outcomeRef"] = None
    assert action_outcome_proven(p) is False                                      # executed self-asserted
