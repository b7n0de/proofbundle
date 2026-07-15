"""automation_verdict.automation_summary — Finding 01 (2026-07 verify-layer hardening).

Unit tests of the pure `automation_summary` function itself, plus integration tests proving every one of
the five receipt-chain verify_* functions (decision/outcome/trust_pack/verification_summary/run_ledger)
now emits `result["automation"]` WITHOUT changing the pre-existing `result["ok"]` aggregate."""
from __future__ import annotations

import base64
import unittest

from proofbundle.automation_verdict import automation_summary
from proofbundle.emit import generate_signer


class TestAutomationSummaryUnit(unittest.TestCase):
    def test_all_true_no_policy_dimension_is_safe(self):
        s = automation_summary({"crypto_ok": True, "structure_ok": True},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": None, "references": []})
        self.assertTrue(s["safeForAutomation"])
        self.assertEqual(s["automationBlockers"], [])
        self.assertIsNone(s["policyAuthorized"])
        self.assertIsNone(s["referencesResolved"])

    def test_policy_none_is_not_safe_never_merely_not_false(self):
        # THE core Finding 01 assertion: policy_ok=None ("not evaluated") must NOT be treated as safe, even
        # though `None is not False` is True (the existing `ok` aggregates use exactly that permissive test).
        s = automation_summary({"crypto_ok": True, "structure_ok": True, "policy_ok": None},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": "policy_ok", "references": []})
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_NOT_EVALUATED", s["automationBlockers"])
        self.assertFalse(s["policyAuthorized"])

    def test_policy_false_is_policy_failed_not_not_evaluated(self):
        s = automation_summary({"crypto_ok": True, "structure_ok": True, "policy_ok": False},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": "policy_ok", "references": []})
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("POLICY_FAILED", s["automationBlockers"])
        self.assertNotIn("POLICY_NOT_EVALUATED", s["automationBlockers"])

    def test_policy_true_is_authorized_and_safe(self):
        s = automation_summary({"crypto_ok": True, "structure_ok": True, "policy_ok": True},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": "policy_ok", "references": []})
        self.assertTrue(s["safeForAutomation"])
        self.assertTrue(s["policyAuthorized"])
        self.assertEqual(s["automationBlockers"], [])

    def test_crypto_false_blocks(self):
        s = automation_summary({"crypto_ok": False, "structure_ok": True},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": None, "references": []})
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("CRYPTO_NOT_OK", s["automationBlockers"])

    def test_structure_none_blocks_same_as_false(self):
        # crypto/structure use a strict `is True` bar too — None (never computed) is not safe either.
        s = automation_summary({"crypto_ok": True, "structure_ok": None},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": None, "references": []})
        self.assertFalse(s["safeForAutomation"])
        self.assertIn("STRUCTURE_NOT_OK", s["automationBlockers"])

    def test_reference_false_blocks_reference_none_does_not(self):
        base = {"crypto_ok": True, "structure_ok": True}
        checks = {"crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
                  "references": ["audience_ok", "nonce_ok"]}
        safe = automation_summary({**base, "audience_ok": None, "nonce_ok": None}, required_checks=checks)
        self.assertTrue(safe["safeForAutomation"])
        self.assertTrue(safe["referencesResolved"])
        unsafe = automation_summary({**base, "audience_ok": False, "nonce_ok": None}, required_checks=checks)
        self.assertFalse(unsafe["safeForAutomation"])
        self.assertFalse(unsafe["referencesResolved"])
        self.assertIn("REFERENCES_NOT_RESOLVED", unsafe["automationBlockers"])

    def test_every_reason_enumerated_simultaneously(self):
        s = automation_summary(
            {"crypto_ok": False, "structure_ok": False, "policy_ok": False, "x": False},
            required_checks={"crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
                             "references": ["x"]})
        for b in ("CRYPTO_NOT_OK", "STRUCTURE_NOT_OK", "POLICY_FAILED", "REFERENCES_NOT_RESOLVED"):
            self.assertIn(b, s["automationBlockers"])

    def test_pure_never_mutates_input(self):
        result = {"crypto_ok": True, "structure_ok": True, "policy_ok": True}
        before = dict(result)
        automation_summary(result, required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                     "policy": "policy_ok", "references": []})
        self.assertEqual(result, before)


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


class TestAllReceiptTypesEmitAutomation(unittest.TestCase):
    """`all_receipt_types_emit_automation` (prompt-mandated test name): every one of the five
    receipt-chain verify_* functions emits `result["automation"]` with the 6 canonical fields, and the
    pre-existing `result["ok"]` is UNCHANGED by its presence."""

    def test_decision_emits_automation(self):
        import json
        from pathlib import Path

        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        pred = json.loads((Path(__file__).resolve().parent.parent / "examples" /
                           "decision_receipt_deny.json").read_text())
        s, pub = _keys()
        env = emit_decision_receipt(pred, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True)
        self._assert_automation_shape(r)
        self.assertTrue(r["ok"])
        # decision_ok_without_policy_never_safe_for_automation (prompt-mandated test name)
        self.assertFalse(r["automation"]["safeForAutomation"])
        self.assertIn("POLICY_NOT_EVALUATED", r["automation"]["automationBlockers"])

    def test_outcome_emits_automation(self):
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
        s, pub = _keys()
        pred = {
            "schemaVersion": "0.1.0", "outcomeId": "o-1", "decisionRef": {"sha256": "a" * 64},
            "executor": {"id": "executor:1"}, "requestedActionDigest": {"sha256": "b" * 64},
            "status": "refused", "performedAt": "2026-07-15T10:00:00Z",
        }
        env = emit_outcome_receipt(pred, s)
        r = verify_outcome_receipt(env, pub)
        self._assert_automation_shape(r)
        self.assertTrue(r["ok"])
        self.assertFalse(r["automation"]["safeForAutomation"])  # no trust_pack supplied

    def test_trust_pack_emits_automation(self):
        from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack
        sk = generate_signer()
        keys = {"root-0": {"publicKey": base64.b64encode(sk.public_key().public_bytes_raw()).decode()}}
        pred = {
            "schemaVersion": "0.1.0", "trustPackId": "tp-x", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1}},
            "keys": keys, "nonClaims": ["x"],
        }
        env = sign_trust_pack(pred, {"root-0": sk})
        r = verify_trust_pack(env, strict=True)
        self._assert_automation_shape(r)
        self.assertTrue(r["ok"])
        # trust_pack has NO policy dimension at all -> policyAuthorized None, never blocks
        self.assertIsNone(r["automation"]["policyAuthorized"])
        self.assertTrue(r["automation"]["safeForAutomation"])

    def test_verification_summary_emits_automation(self):
        from proofbundle.verification_summary import emit_verification_summary, verify_verification_summary
        s, pub = _keys()
        pred = {
            "schemaVersion": "0.1.0", "summaryId": "sum-1", "producedAt": "2026-07-15T10:00:00Z",
            "levels": [{"kind": "eval", "status": "NOT_EVALUATED", "evidenceClass": "authorship_integrity"}],
            "nonClaims": ["x"],
        }
        env = emit_verification_summary(pred, s)
        r = verify_verification_summary(env, pub, strict=True)
        self._assert_automation_shape(r)
        self.assertTrue(r["ok"])
        self.assertTrue(r["automation"]["safeForAutomation"])

    def test_run_ledger_emits_automation(self):
        from proofbundle.run_ledger import emit_run_ledger, link_runs, verify_run_ledger
        s, pub = _keys()
        pred = {
            "schemaVersion": "0.1.0", "studyId": "study-x", "runBudget": 2,
            "runs": link_runs(["1" * 64], ["completed"]),
            "nonClaims": ["x", "y"],
        }
        env = emit_run_ledger(pred, s)
        r = verify_run_ledger(env, pub, strict=True)
        self._assert_automation_shape(r)
        self.assertTrue(r["ok"])
        self.assertTrue(r["automation"]["safeForAutomation"])

    def test_trust_pack_malformed_early_return_still_emits_automation(self):
        # the early "malformed predicate" return path in verify_trust_pack must ALSO carry automation
        # (never a code path where result["automation"] is silently absent). sign_trust_pack would itself
        # reject this predicate (fail-closed at emit) — build the envelope by hand to reach the verify-side
        # early return.
        import json as _json

        from proofbundle import dsse
        from proofbundle.trust_pack import INTOTO_STATEMENT_PAYLOAD_TYPE, verify_trust_pack
        sk = generate_signer()
        pred = {"schemaVersion": "not-semver"}   # deliberately malformed/incomplete
        stmt = {"_type": "https://in-toto.io/Statement/v1",
               "subject": [{"name": "trust-pack:bad", "digest": {"sha256": "a" * 64}}],
               "predicateType": "https://b7n0de.com/proofbundle/predicates/trust-pack/v0.1",
               "predicate": pred}
        body = _json.dumps(stmt).encode()
        msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
        env = {"payload": base64.b64encode(body).decode("ascii"),
               "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": "k", "sig": base64.b64encode(sk.sign(msg)).decode("ascii")}]}
        r = verify_trust_pack(env)
        self.assertFalse(r["ok"])
        self._assert_automation_shape(r)
        self.assertFalse(r["automation"]["safeForAutomation"])

    def _assert_automation_shape(self, result: dict) -> None:
        self.assertIn("automation", result)
        a = result["automation"]
        for key in ("cryptoValid", "structureValid", "policyAuthorized", "referencesResolved",
                   "safeForAutomation", "automationBlockers"):
            self.assertIn(key, a, f"missing {key} in {a}")
        self.assertIsInstance(a["safeForAutomation"], bool)
        self.assertIsInstance(a["automationBlockers"], list)


if __name__ == "__main__":
    unittest.main()
