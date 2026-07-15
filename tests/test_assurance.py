"""assurance.EvidenceLevel — Finding 03 (2026-07 verify-layer hardening).

Unit tests of the pure classification helpers, plus integration tests proving decision.py/outcome.py wire
the ladder additively (the old boolean *_proven / evidence_bound fields are unchanged)."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from proofbundle.assurance import (
    EFFECT_OBSERVED_NOT_IMPLEMENTED,
    EvidenceLevel,
    classify_digest_evidence,
    evidence_ladder_best,
    evidence_ladder_summary,
)
from proofbundle.emit import generate_signer

_DIGEST = {"sha256": "a" * 64}


class TestClassifyDigestEvidence(unittest.TestCase):
    def test_not_applicable_is_none_level(self):
        r = classify_digest_evidence(_DIGEST, applicable=False)
        self.assertIsNone(r["level"])
        self.assertIsNone(r["level_name"])

    def test_missing_digest_is_claimed(self):
        for bad in (None, {}, {"sha256": "not-hex"}, "abc", 5):
            r = classify_digest_evidence(bad)
            self.assertEqual(r["level"], EvidenceLevel.CLAIMED, bad)

    def test_digest_presence_never_sets_proven_level_above_reference(self):
        # THE core Finding 03 assertion: a syntactically valid but content-unchecked digest reaches
        # REFERENCE_WELL_FORMED and NO FURTHER — never CONTENT_RESOLVED or above, without an
        # evidence_resolver actually confirming the content.
        r = classify_digest_evidence(_DIGEST)
        self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertLess(r["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_evidence_resolver_true_reaches_content_resolved(self):
        r = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)
        self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_evidence_resolver_false_stays_at_reference_well_formed(self):
        r = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: False)
        self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)

    def test_evidence_resolver_exception_fails_closed(self):
        def _boom(_d):
            raise RuntimeError("resolver blew up")
        r = classify_digest_evidence(_DIGEST, evidence_resolver=_boom)
        self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED,
                         "a raising resolver must never be silently promoted to CONTENT_RESOLVED")

    def test_evidence_resolver_never_called_when_digest_malformed(self):
        calls = []
        classify_digest_evidence(None, evidence_resolver=lambda d: calls.append(d) or True)
        self.assertEqual(calls, [])

    def test_ordering_is_monotone(self):
        levels = list(EvidenceLevel)
        self.assertEqual(levels, sorted(levels))
        self.assertLess(EvidenceLevel.CLAIMED, EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertLess(EvidenceLevel.REFERENCE_WELL_FORMED, EvidenceLevel.CONTENT_RESOLVED)
        self.assertLess(EvidenceLevel.CONTENT_RESOLVED, EvidenceLevel.EFFECT_OBSERVED)


class TestEvidenceLadderSummary(unittest.TestCase):
    def test_and_semantics_weakest_link_wins(self):
        strong = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)
        weak = classify_digest_evidence(_DIGEST)  # no resolver -> REFERENCE_WELL_FORMED
        s = evidence_ladder_summary(strong, weak)
        self.assertEqual(s["level"], EvidenceLevel.REFERENCE_WELL_FORMED)

    def test_and_semantics_all_empty_or_not_applicable_is_none(self):
        na = classify_digest_evidence(_DIGEST, applicable=False)
        s = evidence_ladder_summary(na, na)
        self.assertIsNone(s["level"])
        self.assertEqual(evidence_ladder_summary()["level"], None)

    def test_or_semantics_strongest_wins(self):
        strong = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)
        weak = classify_digest_evidence(_DIGEST)
        s = evidence_ladder_best(strong, weak)
        self.assertEqual(s["level"], EvidenceLevel.CONTENT_RESOLVED)


class TestEffectObservedMarker(unittest.TestCase):
    def test_effect_observed_marker_is_a_visible_string_not_silence(self):
        self.assertIn("EFFECT_OBSERVED", EFFECT_OBSERVED_NOT_IMPLEMENTED)
        self.assertIn("Finding 16", EFFECT_OBSERVED_NOT_IMPLEMENTED)
        # EFFECT_OBSERVED is a real enum member (orderable), just structurally unreachable via this module.
        self.assertEqual(EvidenceLevel.EFFECT_OBSERVED.name, "EFFECT_OBSERVED")


EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


class TestDecisionWiresEvidenceLevels(unittest.TestCase):
    def _pred(self, name: str = "deny") -> dict:
        return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))

    def test_evidence_levels_present_and_additive(self):
        from proofbundle.decision import action_outcome_proven, emit_decision_receipt, verify_decision_receipt
        p = self._pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True)
        self.assertIn("evidence_levels", r)
        self.assertIn("actionOutcome.outcomeRef", r["evidence_levels"])
        self.assertIn("evidenceRefs", r["evidence_levels"])
        # old boolean field unchanged (mirrors the predicate's own actionOutcome, if any)
        self.assertEqual(r["action_outcome_proven"], action_outcome_proven(p))

    def test_evidence_resolver_wired_through_to_evidence_refs(self):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        p = copy.deepcopy(self._pred("deny"))
        p["evidenceRefs"] = [{"relation": "evalResult", "digest": {"sha256": "b" * 64}}]
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        # without a resolver: REFERENCE_WELL_FORMED
        r = verify_decision_receipt(env, pub, strict=True)
        self.assertEqual(r["evidence_levels"]["evidenceRefs"]["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertTrue(r["evidence_bound"])   # old boolean field: unaffected, still True
        # with a resolver that confirms every ref: CONTENT_RESOLVED
        r2 = verify_decision_receipt(env, pub, strict=True, evidence_resolver=lambda d: True)
        self.assertEqual(r2["evidence_levels"]["evidenceRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertTrue(r2["evidence_bound"])  # old boolean field still unaffected

    def test_empty_evidence_refs_evidence_level_is_none(self):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        p = copy.deepcopy(self._pred("deny"))
        p["evidenceRefs"] = []
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        r = verify_decision_receipt(env, pub)
        self.assertIsNone(r["evidence_levels"]["evidenceRefs"])
        self.assertIsNone(r["evidence_bound"])   # mirrors the old vacuous-None convention


class TestOutcomeWiresEvidenceLevels(unittest.TestCase):
    def _pred(self, **over) -> dict:
        p = {
            "schemaVersion": "0.1.0", "outcomeId": "o-1", "decisionRef": {"sha256": "a" * 64},
            "executor": {"id": "executor:1", "keyId": "kid-1"},
            "requestedActionDigest": {"sha256": "b" * 64},
            "status": "executed", "performedAt": "2026-07-15T10:00:00Z",
            "effectDigest": {"sha256": "c" * 64},
        }
        p.update(over)
        return p

    def test_evidence_levels_present_and_additive(self):
        from proofbundle.outcome import emit_outcome_receipt, outcome_execution_proven, verify_outcome_receipt
        p = self._pred()
        s, pub = _keys()
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, strict=True)
        self.assertIn("evidence_levels", r)
        self.assertIn("effect", r["evidence_levels"])
        self.assertEqual(r["execution_proven"], outcome_execution_proven(p))  # old field unchanged
        self.assertEqual(r["evidence_levels"]["effect"]["level"], EvidenceLevel.REFERENCE_WELL_FORMED)

    def test_evidence_resolver_reaches_content_resolved(self):
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
        p = self._pred()
        s, pub = _keys()
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, strict=True, evidence_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["effect"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertTrue(r["execution_proven"])  # old field still unaffected by the resolver

    def test_not_executed_status_evidence_level_is_none(self):
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
        p = self._pred(status="refused")
        del p["effectDigest"]
        s, pub = _keys()
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub)
        self.assertIsNone(r["evidence_levels"]["effect"]["level"])
        self.assertIsNone(r["execution_proven"])


if __name__ == "__main__":
    unittest.main()
