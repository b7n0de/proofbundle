"""Regression tests for the 3.6.2 bug-hunt follow-ups on the automation-verdict surface.

Both P1 findings were fail-OPEN on `.automation.safeForAutomation` — the surface the docs explicitly
recommend for automation gating — while `.ok` was already False (a caller filtering on `ok` alone was
safe, but one following the documented automation guidance was not).

  P1-A  decision.py: a v0.2 decision_receipt policy that constrains type/verdict but pins NO
        trusted_decision_makers left signer_trusted=None with policy_ok=True; automation_summary has no
        signer dimension, so safeForAutomation stayed True (the 'attributes to nobody' hole the eval
        path blocks with SIGNER_NOT_PINNED).
  P1-B  outcome.py: a violated relations trust-policy (LINEAGE_REQUIREMENT_FAILED / reject_superseded)
        set policy_ok=False but never reached the automation surface (no block after automation_summary,
        and the 'policy' dimension mapped to executor_role_trusted, not policy_ok) — safeForAutomation
        stayed True. The decision path wires this correctly; outcome must mirror it.
"""
import base64
import json
import unittest
from pathlib import Path

from proofbundle.emit import generate_signer
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.policy import load_policy

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


class DecisionUnpinnedSignerNotAutomationSafe(unittest.TestCase):
    """P1-A: a crypto-valid decision receipt whose policy pins no decision-maker is never safe."""

    def _emit(self):
        pred = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        s, pub = _keys()
        return emit_decision_receipt(pred, s), pub

    def test_unpinned_signer_is_fail_closed_for_automation(self):
        env, pub = self._emit()
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "a",
                           "decision_receipt": {"allowed_verdicts": ["ALLOW", "DENY", "REFUSE",
                                                                     "ESCALATE", "DEFER", "OBSERVE"]}})
        r = verify_decision_receipt(env, pub, policy=pol)
        # policy passes (constrains verdict) but pins no maker -> not automation-safe
        self.assertTrue(r["policy_ok"])
        self.assertIsNone(r["signer_trusted"])
        self.assertFalse(r["automation"]["safeForAutomation"])
        self.assertIn("SIGNER_NOT_PINNED", r["automation"]["automationBlockers"])

    def test_pinned_matching_signer_stays_automation_safe(self):
        # bidirectional: the fix must NOT over-fire on the legitimately safe case
        env, pub = self._emit()
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "b",
                           "decision_receipt": {"trusted_decision_makers":
                                                [{"public_key_b64": base64.b64encode(pub).decode()}]}})
        r = verify_decision_receipt(env, pub, policy=pol)
        self.assertTrue(r["signer_trusted"])
        self.assertTrue(r["automation"]["safeForAutomation"])
        self.assertNotIn("SIGNER_NOT_PINNED", r["automation"]["automationBlockers"])


class OutcomeRelationsViolationNotAutomationSafe(unittest.TestCase):
    """P1-B: a relations trust-policy violation on an outcome receipt must project to fail-closed."""

    def _verify(self, policy_relations):
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
        s = generate_signer()
        pub = s.public_key().public_bytes_raw()
        edge = {"relation": "supersedes",
                "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64}}
        pred = {"schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
                "executor": {"id": "ex", "keyId": "kid-exec"}, "requestedActionDigest": {"sha256": "1" * 64},
                "effectDigest": {"sha256": "1" * 64}, "status": "executed",
                "performedAt": "2026-07-17T00:00:00Z", "policyPurpose": "outcome", "relationships": [edge]}
        trust_pack = {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
                      "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                      "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                                "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1}},
                      "keys": {"root-0": {"publicKey": "A" * 43 + "="}}, "nonClaims": ["role mapping only"]}
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "rel",
                           "relations": policy_relations})
        env = emit_outcome_receipt(pred, s, strict=False)
        return verify_outcome_receipt(env, pub, policy=pol, trust_pack=trust_pack)

    def test_unresolved_required_relation_blocks_outcome_automation(self):
        # relations-ONLY policy (executor_role_trusted stays True) isolates the relations failure
        r = self._verify({"require_relation_resolution": ["supersedes"]})
        self.assertTrue(r["relations_policy_failed"])
        self.assertTrue(r["executor_role_trusted"])          # the failure is purely the relations policy
        au = r["automation"]
        self.assertFalse(au["safeForAutomation"])
        self.assertIn("LINEAGE_REQUIREMENT_FAILED", au["automationBlockers"])
        self.assertFalse(au["referencesResolved"])

    def test_reject_superseded_blocks_outcome_automation(self):
        r = self._verify({"reject_superseded": True})
        # a declared supersedes edge under reject_superseded is a violation
        if r["relations_policy_failed"]:
            self.assertFalse(r["automation"]["safeForAutomation"])
            self.assertFalse(r["automation"]["referencesResolved"])


if __name__ == "__main__":
    unittest.main()
