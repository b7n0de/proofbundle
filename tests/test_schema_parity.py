"""Schema parity (Finding 04 regression guard).

For every decision/outcome golden example, the CLI `init` templates, AND every Finding-04 negative vector
(the 11 reproduced schema-vs-hand-validator gaps: decisionId int/empty, empty parametersRef `{}`, scalar
actionOutcome/validity, unknown nested fields in decision/policyBoundary/proposedAction/decisionMaker/
evidenceRefs, plus the outcome-side traceContext/validity nested closure), the hand-rolled fail-closed
validator (`validate_decision_predicate` / `validate_outcome_predicate` — the ENFORCED contract) and the
docs-only JSON Schema (`schemas/*.schema.json`) must AGREE: both accept, or both reject. A divergence here
means the schema and the enforced validator drifted apart — exactly the class of bug Finding 04 fixed.

unittest-style to match the repo's `python -m unittest discover`.
"""
from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None

from proofbundle import cli
from proofbundle.decision import validate_decision_predicate
from proofbundle.outcome import validate_outcome_predicate

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
DECISION_SCHEMA = json.loads((ROOT / "schemas" / "decision-receipt-v0.1.schema.json").read_text(encoding="utf-8"))
OUTCOME_SCHEMA = json.loads((ROOT / "schemas" / "action-outcome-v0.1.schema.json").read_text(encoding="utf-8"))


def _load_example(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def _deny() -> dict:
    return _load_example("decision_receipt_deny.json")


def _outcome_pred(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0",
        "outcomeId": "outcome-0001",
        "decisionRef": {"sha256": "a" * 64},
        "executor": {"id": "executor:runner-7"},
        "requestedActionDigest": {"sha256": "c" * 64},
        "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z",
        "effectDigest": {"sha256": "c" * 64},
    }
    p.update(over)
    return p


def _jsonschema_valid(instance: dict, schema: dict) -> bool:
    try:
        jsonschema.validate(instance=instance, schema=schema)
        return True
    except jsonschema.ValidationError:
        return False


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestDecisionSchemaParity(unittest.TestCase):
    def _assert_both_agree(self, predicate: dict, *, expect_valid: bool, msg: str = "") -> None:
        hand_errs = validate_decision_predicate(predicate, strict=True)
        hand_valid = not hand_errs
        schema_valid = _jsonschema_valid(predicate, DECISION_SCHEMA)
        self.assertEqual(hand_valid, expect_valid, f"{msg}: hand-validator valid={hand_valid} errs={hand_errs}")
        self.assertEqual(schema_valid, expect_valid, f"{msg}: jsonschema valid={schema_valid}")
        self.assertEqual(hand_valid, schema_valid, f"{msg}: DIVERGENCE hand={hand_valid} schema={schema_valid}")

    # ── positive: golden examples + wrapped statement + init template ──
    def test_golden_examples_agree(self):
        for name in ("allow", "deny", "escalate"):
            self._assert_both_agree(_load_example(f"decision_receipt_{name}.json"), expect_valid=True, msg=name)

    def test_wrapped_statement_predicate_agrees(self):
        stmt = _load_example("decision_receipt_with_eval_ref.intoto.json")
        self._assert_both_agree(stmt["predicate"], expect_valid=True, msg="with_eval_ref")

    def test_decision_init_template_agrees(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "d.json"
            cli._cmd_decision_init(argparse.Namespace(out=str(path)))
            tpl = json.loads(path.read_text(encoding="utf-8"))
        self._assert_both_agree(tpl, expect_valid=True, msg="decision init template")
        # REGRESSION-PFLICHT: the init template must stay strict-clean.
        self.assertEqual(validate_decision_predicate(tpl, strict=True), [])

    def test_decision_maker_version_extension_container_stays_open_both(self):
        # decisionMaker.version is a DELIBERATE open extensions container (Finding 04 explicitly leaves it
        # undeclared) — an arbitrary key inside it must still validate on both sides, or the fix over-closed.
        p = _deny()
        p["decisionMaker"]["version"] = {"proofbundle": "2.1.0", "anything": "goes"}
        self._assert_both_agree(p, expect_valid=True, msg="decisionMaker.version open container")

    # ── negative: the 11 reproduced Finding-04 gaps, both validators must now reject ──
    def test_decision_id_int_rejected_both(self):
        p = _deny()
        p["decisionId"] = 12345
        self._assert_both_agree(p, expect_valid=False, msg="decisionId int")

    def test_decision_id_empty_rejected_both(self):
        p = _deny()
        p["decisionId"] = ""
        self._assert_both_agree(p, expect_valid=False, msg="decisionId empty")

    def test_empty_parameters_ref_rejected_both(self):
        p = _deny()
        del p["proposedAction"]["parametersDigest"]
        p["proposedAction"]["parametersRef"] = {}
        self._assert_both_agree(p, expect_valid=False, msg="empty parametersRef {}")

    def test_scalar_action_outcome_rejected_both(self):
        p = _deny()
        p["actionOutcome"] = "executed"
        self._assert_both_agree(p, expect_valid=False, msg="scalar actionOutcome")

    def test_scalar_validity_rejected_both(self):
        p = _deny()
        p["validity"] = "not-an-object"
        self._assert_both_agree(p, expect_valid=False, msg="scalar validity")

    def test_unknown_nested_field_in_decision_rejected_both(self):
        p = _deny()
        p["decision"]["sneaky"] = 1
        self._assert_both_agree(p, expect_valid=False, msg="decision.sneaky")

    def test_unknown_nested_field_in_policy_boundary_rejected_both(self):
        p = _deny()
        p["policyBoundary"]["sneaky"] = 1
        self._assert_both_agree(p, expect_valid=False, msg="policyBoundary.sneaky")

    def test_unknown_nested_field_in_proposed_action_rejected_both(self):
        p = _deny()
        p["proposedAction"]["sneaky"] = 1
        self._assert_both_agree(p, expect_valid=False, msg="proposedAction.sneaky")

    def test_unknown_nested_field_in_decision_maker_rejected_both(self):
        p = _deny()
        p["decisionMaker"]["sneaky"] = 1
        self._assert_both_agree(p, expect_valid=False, msg="decisionMaker.sneaky")

    def test_unknown_nested_field_in_evidence_refs_rejected_both(self):
        p = _deny()
        p["evidenceRefs"][0]["sneaky"] = 1
        self._assert_both_agree(p, expect_valid=False, msg="evidenceRefs[].sneaky")


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestOutcomeSchemaParity(unittest.TestCase):
    def _assert_both_agree(self, predicate: dict, *, expect_valid: bool, msg: str = "") -> None:
        hand_errs = validate_outcome_predicate(predicate, strict=True)
        hand_valid = not hand_errs
        schema_valid = _jsonschema_valid(predicate, OUTCOME_SCHEMA)
        self.assertEqual(hand_valid, expect_valid, f"{msg}: hand-validator valid={hand_valid} errs={hand_errs}")
        self.assertEqual(schema_valid, expect_valid, f"{msg}: jsonschema valid={schema_valid}")
        self.assertEqual(hand_valid, schema_valid, f"{msg}: DIVERGENCE hand={hand_valid} schema={schema_valid}")

    def test_valid_predicate_agrees(self):
        self._assert_both_agree(_outcome_pred(), expect_valid=True, msg="valid outcome")

    def test_outcome_init_template_agrees(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "o.json"
            cli._cmd_outcome_init(argparse.Namespace(out=str(path)))
            tpl = json.loads(path.read_text(encoding="utf-8"))
        self._assert_both_agree(tpl, expect_valid=True, msg="outcome init template")
        self.assertEqual(validate_outcome_predicate(tpl, strict=True), [])

    def test_unknown_nested_field_in_trace_context_rejected_both(self):
        p = _outcome_pred(traceContext={"traceparent": "x", "sneaky": 1})
        self._assert_both_agree(p, expect_valid=False, msg="traceContext.sneaky")

    def test_unknown_nested_field_in_validity_rejected_both(self):
        p = _outcome_pred(validity={"audience": ["a"], "nonce": "n", "sneaky": 1})
        self._assert_both_agree(p, expect_valid=False, msg="validity.sneaky")

    def test_scalar_validity_rejected_both(self):
        p = _outcome_pred(validity="n-1")
        self._assert_both_agree(p, expect_valid=False, msg="scalar validity")


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestRelationshipsSchemaParity(unittest.TestCase):
    """6-lens audit L4: the additive relationships field (relation/v0.1) must agree between the
    hand validator and the JSON-Schema mirror on BOTH predicates — the divergence class Finding 04
    was created to prevent, extended to the new field."""

    _GOOD = {"digestAlgorithm": "jcs-sha256-v1", "digest": "b" * 64}
    _EDGE = {"relation": "supersedes", "targetReceiptDigest": _GOOD}

    def _chk_decision(self, relationships):
        p = _load_example("decision_receipt_deny.json")
        p["relationships"] = relationships
        hand = not validate_decision_predicate(p, strict=True)
        schema = _jsonschema_valid(p, DECISION_SCHEMA)
        return hand, schema

    def _chk_outcome(self, relationships):
        p = _outcome_pred()
        p["relationships"] = relationships
        hand = not validate_outcome_predicate(p, strict=True)
        schema = _jsonschema_valid(p, OUTCOME_SCHEMA)
        return hand, schema

    def _both(self, relationships, expect_valid, msg):
        for label, fn in (("decision", self._chk_decision), ("outcome", self._chk_outcome)):
            hand, schema = fn(relationships)
            self.assertEqual(hand, expect_valid, f"{msg}/{label}: hand={hand}")
            self.assertEqual(schema, expect_valid, f"{msg}/{label}: schema={schema}")
            self.assertEqual(hand, schema, f"{msg}/{label}: DIVERGENCE hand={hand} schema={schema}")

    def test_valid_edge_agrees(self):
        self._both([self._EDGE], expect_valid=True, msg="valid edge")

    def test_full_edge_agrees(self):
        e = dict(self._EDGE, targetSubjectDigest=self._GOOD, reason="x",
                 reasonCode="correction", declaredAt="2026-07-16T00:00:00Z")
        self._both([e], expect_valid=True, msg="full edge")

    def test_unknown_relation_rejected_by_both(self):
        self._both([{"relation": "replaces", "targetReceiptDigest": self._GOOD}],
                   expect_valid=False, msg="unknown relation")

    def test_missing_digest_algorithm_rejected_by_both(self):
        self._both([{"relation": "supersedes", "targetReceiptDigest": {"digest": "b" * 64}}],
                   expect_valid=False, msg="missing digestAlgorithm")

    def test_non_hex_digest_rejected_by_both(self):
        self._both([{"relation": "supersedes",
                     "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "ZZ"}}],
                   expect_valid=False, msg="non-hex digest")

    def test_unknown_edge_field_rejected_by_both(self):
        self._both([dict(self._EDGE, sneaky=1)], expect_valid=False, msg="unknown edge field")

    def test_empty_array_rejected_by_both(self):
        self._both([], expect_valid=False, msg="empty relationships")

    def test_bad_reason_code_rejected_by_both(self):
        self._both([dict(self._EDGE, reasonCode="because")], expect_valid=False, msg="bad reasonCode")
