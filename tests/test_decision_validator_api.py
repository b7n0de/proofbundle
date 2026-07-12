"""WP-W6 — the validator-API footgun that caused a public 'VALID' overclaim.

`validate_decision_predicate` RETURNS a list of findings (empty == valid); it does not
raise. A caller that wraps it in try/except sees no exception and wrongly reports the
predicate as valid — exactly the mistake behind the 2026-07-11 #7 thread post that
claimed a cross-implementation fixture "passes the enforced v0.1 validator as-is" when
it actually reported 12 findings. These tests pin the failure mode and the raising
wrapper that gives callers a real exception when they want one.
"""
import json
import pathlib
import unittest

from proofbundle.decision import (
    DecisionReceiptError,
    require_valid_decision_predicate,
    validate_decision_predicate,
)

# The thread-prose shape (as the external audit-anchor fixture was built): fields taken
# from the #7 discussion, not from the schema. Reports many findings against v0.1.
_THREAD_PROSE_PREDICATE = {
    "action": "deploy",
    "verdict": "allow",
    "policy": {"id": "release-gate/prod", "digest": {"sha256": "8c561dd1f0c5eb47c9353a60d573dccda3ee30b1a820ccb08660466a36450be9"}},
    "evidenceRefs": [{"predicateType": "https://b7n0de.com/attestation/eval-result/v0.1",
                      "digest": {"sha256": "323adb188f840e90331c920b32a73f348acc5caea8d40f9a84ea384d46c258d4"}}],
    "inputsSnapshot": {"digest": {"sha256": "bb8601c1fc3cf1dc3e829652df409b1bdd9e866e18f25bf7750c9f8702096edc"}},
    "flipConditions": ["accuracy on holdout-2026-06 below 0.90"],
    "decidedAt": "2026-07-10T00:00:00Z",
}

_EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "examples" / "decision_receipt_with_eval_ref.intoto.json"


class TestValidatorReturnsNotRaises(unittest.TestCase):
    def test_invalid_predicate_returns_findings_without_raising(self):
        # The core footgun: validation of an INVALID predicate must NOT raise — it
        # returns findings. (If it ever raised here, a try/except idiom would at least
        # fail closed; it does not, which is why the wrapper below exists.)
        errors = validate_decision_predicate(_THREAD_PROSE_PREDICATE)
        self.assertTrue(errors, "thread-prose predicate must report findings")
        self.assertIn("unknown top-level field(s)", errors[0])

    def test_try_except_idiom_would_wrongly_pass(self):
        # Documents WHY require_valid_decision_predicate exists: the naive idiom passes.
        wrongly_valid = True
        try:
            validate_decision_predicate(_THREAD_PROSE_PREDICATE)
        except Exception:
            wrongly_valid = False
        self.assertTrue(wrongly_valid,
                        "validate_* never raises — a try/except check silently passes invalid input")

    def test_empty_list_means_valid(self):
        example = json.loads(_EXAMPLE.read_text())
        self.assertEqual(validate_decision_predicate(example["predicate"]), [],
                         "the in-repo example predicate must validate clean (empty list == valid)")


class TestRaisingWrapper(unittest.TestCase):
    def test_wrapper_raises_on_invalid(self):
        with self.assertRaises(DecisionReceiptError) as ctx:
            require_valid_decision_predicate(_THREAD_PROSE_PREDICATE)
        self.assertIn("finding", str(ctx.exception))

    def test_wrapper_returns_none_on_valid(self):
        example = json.loads(_EXAMPLE.read_text())
        self.assertIsNone(require_valid_decision_predicate(example["predicate"]))

    def test_wrapper_message_carries_the_count(self):
        n = len(validate_decision_predicate(_THREAD_PROSE_PREDICATE))
        try:
            require_valid_decision_predicate(_THREAD_PROSE_PREDICATE)
        except DecisionReceiptError as e:
            self.assertIn(f"{n} finding", str(e))
        else:
            self.fail("expected DecisionReceiptError")


if __name__ == "__main__":
    unittest.main()
