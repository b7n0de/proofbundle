"""3.2.0 O6 Subject Binding + Nested Schema Closure — classify DERIVED vs EXTERNAL_ATTESTED, fail-closed
require, and nested-object closure. unittest-style."""
from __future__ import annotations

import unittest

from proofbundle.outcome import build_outcome_statement
from proofbundle.subject_binding import (
    SubjectBindingError,
    classify_subject,
    derive_subject_digest,
    nested_closure_violations,
    require_derived_subject,
)

_DIG = "c" * 64


def _outcome_pred(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0",
        "outcomeId": "o-1",
        "decisionRef": {"sha256": "a" * 64},
        "executor": {"id": "executor://runner-7"},
        "requestedActionDigest": {"sha256": _DIG},
        "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z",
        "effectDigest": {"sha256": _DIG},
    }
    p.update(over)
    return p


class TestSubjectBinding(unittest.TestCase):
    def test_derived_default_is_classified_derived(self):
        stmt = build_outcome_statement(_outcome_pred())   # default subject = derived
        c = classify_subject(stmt)
        self.assertEqual(c["mode"], "DERIVED")
        self.assertTrue(c["matches"])
        self.assertEqual(c["declared_sha256"], derive_subject_digest(stmt["predicate"]))

    def test_override_is_external_attested(self):
        stmt = build_outcome_statement(_outcome_pred(), subject_sha256="f" * 64)
        c = classify_subject(stmt)
        self.assertEqual(c["mode"], "EXTERNAL_ATTESTED")
        self.assertFalse(c["matches"])

    def test_require_derived_passes_on_derived(self):
        stmt = build_outcome_statement(_outcome_pred())
        require_derived_subject(stmt)   # no raise

    def test_require_derived_raises_on_external(self):
        stmt = build_outcome_statement(_outcome_pred(), subject_sha256="f" * 64)
        with self.assertRaises(SubjectBindingError):
            require_derived_subject(stmt)

    def test_tampered_predicate_breaks_derived_match(self):
        # a subject built for predicate A no longer matches after the predicate mutates (a re-derive catches it)
        stmt = build_outcome_statement(_outcome_pred())
        stmt["predicate"]["outcomeId"] = "MUTATED"
        c = classify_subject(stmt)
        self.assertEqual(c["mode"], "EXTERNAL_ATTESTED")
        self.assertFalse(c["matches"])

    def test_malformed_statement_fail_closed(self):
        self.assertFalse(classify_subject({"predicate": _outcome_pred()})["matches"])  # no subject
        self.assertFalse(classify_subject({"subject": [{"digest": {"sha256": _DIG}}]})["matches"])  # no predicate


class TestNestedClosure(unittest.TestCase):
    def test_clean_nested_object_passes(self):
        obj = {"a": 1, "decision": {"verdict": "ALLOW", "reasonCodes": ["x"]}}
        allowed = {"": ("a", "decision"), "decision": ("verdict", "reasonCodes")}
        self.assertEqual(nested_closure_violations(obj, allowed), [])

    def test_undeclared_nested_key_is_violation(self):
        obj = {"decision": {"verdict": "ALLOW", "reasonCodes": ["x"], "sneaky": 1}}
        allowed = {"": ("decision",), "decision": ("verdict", "reasonCodes")}
        v = nested_closure_violations(obj, allowed)
        self.assertTrue(any("sneaky" in e for e in v), v)

    def test_array_items_are_walked(self):
        obj = {"evidenceRefs": [{"relation": "x", "digest": {"sha256": _DIG}, "bad": 1}]}
        allowed = {"": ("evidenceRefs",), "evidenceRefs[]": ("relation", "digest")}
        v = nested_closure_violations(obj, allowed)
        self.assertTrue(any("bad" in e for e in v), v)

    def test_undeclared_path_is_not_walked(self):
        # a path not in the allowed_map is not asserted (composes with top-level additionalProperties)
        obj = {"decision": {"anything": 1}}
        self.assertEqual(nested_closure_violations(obj, {"": ("decision",)}), [])


if __name__ == "__main__":
    unittest.main()
