"""3.6.1 — legacy digest-presence booleans are deprecated in favour of the EvidenceLevel ladder
(PB-2026-0717-08).

v3.6.0 carries the additive evidence_levels ladder (CLAIMED / REFERENCE_WELL_FORMED / CONTENT_RESOLVED)
AND the older, stronger-named booleans action_outcome_proven / evidence_bound (decision) and
execution_proven / receiver_bound (outcome), which read True on a MERE well-formed digest — an
overstatement (attacker-choosable content, not a content proof). The fix keeps the legacy fields for
backward compat (the 3.x format is frozen) but DEPRECATES them: the ladder is the sole normative
assurance semantic, and a proven/bound True that is not backed by a CONTENT_RESOLVED ladder level emits
a deprecation warning. Digest presence never reaches the "proven-content" ladder rung without a resolver.
"""
import json
import pathlib
import unittest

from proofbundle.assurance import EvidenceLevel
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BASE_PRED = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))


def _pub(signer):
    return signer.public_key().public_bytes_raw()


def _decision_with_executed_outcome():
    pred = json.loads(json.dumps(BASE_PRED))
    pred["actionOutcome"] = {"status": "executed", "outcomeRef": {"digest": {"sha256": "a" * 64}}}
    return pred


def _outcome_executed():
    return {
        "schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
        "executor": {"id": "ex"}, "requestedActionDigest": {"sha256": "1" * 64},
        "effectDigest": {"sha256": "2" * 64}, "status": "executed",
        "performedAt": "2026-07-17T00:00:00Z", "policyPurpose": "outcome",
    }


class DigestPresenceNeverProvesContent(unittest.TestCase):
    def test_digest_presence_never_sets_proven_decision(self):
        # an executed outcome with a well-formed outcomeRef but NO evidence_resolver: the legacy field is
        # still True (compat), but the normative ladder stays at REFERENCE_WELL_FORMED — never CONTENT_RESOLVED.
        signer = generate_signer()
        env = emit_decision_receipt(_decision_with_executed_outcome(), signer, strict=True)
        r = verify_decision_receipt(env, _pub(signer))  # no evidence_resolver
        self.assertIs(r["action_outcome_proven"], True)   # legacy field unchanged (compat)
        # the normative ladder never reaches CONTENT_RESOLVED on mere digest presence (no resolver).
        level = r["evidence_levels"]["actionOutcome.outcomeRef"]["level"]
        self.assertLess(int(level), int(EvidenceLevel.CONTENT_RESOLVED))

    def test_digest_presence_never_sets_proven_outcome(self):
        signer = generate_signer()
        env = emit_outcome_receipt(_outcome_executed(), signer, strict=True)
        r = verify_outcome_receipt(env, _pub(signer))
        self.assertIs(r["execution_proven"], True)
        level = r["evidence_levels"]["effect"]["level"]
        self.assertEqual(level, EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertLess(int(level), int(EvidenceLevel.CONTENT_RESOLVED))


class LegacyBoundFieldsAreDeprecated(unittest.TestCase):
    def _warn_blob(self, r):
        return " ".join(r["warnings"])

    def test_legacy_bound_fields_are_deprecated_decision(self):
        signer = generate_signer()
        env = emit_decision_receipt(_decision_with_executed_outcome(), signer, strict=True)
        r = verify_decision_receipt(env, _pub(signer))
        blob = self._warn_blob(r)
        self.assertIn("DEPRECATED", blob)
        self.assertIn("action_outcome_proven", blob)

    def test_legacy_bound_fields_are_deprecated_outcome(self):
        signer = generate_signer()
        env = emit_outcome_receipt(_outcome_executed(), signer, strict=True)
        r = verify_outcome_receipt(env, _pub(signer))
        blob = self._warn_blob(r)
        self.assertIn("DEPRECATED", blob)
        self.assertIn("execution_proven", blob)

    def test_human_summary_matches_evidence_ladder_decision(self):
        # the deprecation summary must point at the ladder (evidence_levels / REFERENCE_WELL_FORMED),
        # so a human reading it is redirected from the overstating legacy name to the honest ladder.
        signer = generate_signer()
        env = emit_decision_receipt(_decision_with_executed_outcome(), signer, strict=True)
        r = verify_decision_receipt(env, _pub(signer))
        blob = self._warn_blob(r)
        self.assertIn("evidence_levels", blob)
        self.assertIn("REFERENCE_WELL_FORMED", blob)

    def test_no_deprecation_warning_when_content_resolved(self):
        # bidirectional: when an evidence_resolver CONFIRMS the referenced bytes, the ladder reaches
        # CONTENT_RESOLVED — the legacy bound field is then NOT an overstatement, so no deprecation
        # warning fires. This proves the warning is a real over-claim signal, not blanket noise.
        signer = generate_signer()
        env = emit_decision_receipt(BASE_PRED, signer, strict=True)  # deny example: evidenceRefs bound
        r = verify_decision_receipt(env, _pub(signer), evidence_resolver=lambda _digest: True)
        self.assertNotIn("DEPRECATED", " ".join(r["warnings"]))


if __name__ == "__main__":
    unittest.main()
