"""3.2.0 O1 Action Outcome Receipt — regressions FIRST (methodology §2: red test, then fix).

Covers the seven prompt-mandated negative vectors plus the positive round-trip and the No-Overclaim honesty
limit. unittest-style to match the repo's `python -m unittest discover`.

Vectors (prompt §O1 "Regressionen zuerst"):
  wrong_decision_ref_fails
  wrong_executor_fails                              (role separation)
  missing_execution_time_fails
  replay_outcome_against_other_decision_fails
  executor_equals_decisionmaker_fails_or_warns
  claimed_executed_without_evidence_not_strong
  outcome_wrong_policy_purpose_fails
"""
from __future__ import annotations

import base64
import copy
import json
import unittest

from proofbundle import dsse
from proofbundle.emit import generate_signer
from proofbundle.outcome import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    OutcomeReceiptError,
    _rfc8785_bytes,
    build_outcome_statement,
    emit_outcome_receipt,
    outcome_execution_proven,
    validate_outcome_predicate,
    verify_outcome_receipt,
)

_DEC_ROOT = "a" * 64        # a plausible decision content root (sha256 hex)
_OTHER_ROOT = "b" * 64
_DIG = "c" * 64


def _pred(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0",
        "outcomeId": "outcome-0001",
        "decisionRef": {"sha256": _DEC_ROOT},
        "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
        "requestedActionDigest": {"sha256": _DIG},
        "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z",
        "effectDigest": {"sha256": _DIG},
    }
    p.update(over)
    return p


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _repayload(env: dict, statement: dict) -> dict:
    env = copy.deepcopy(env)
    env["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    return env


class TestOutcomeValidate(unittest.TestCase):
    def test_valid_predicate_has_no_errors(self):
        self.assertEqual(validate_outcome_predicate(_pred()), [])

    def test_missing_execution_time_fails(self):
        p = _pred()
        del p["performedAt"]
        errs = validate_outcome_predicate(p)
        self.assertTrue(any("performedAt" in e for e in errs), errs)

    def test_unknown_field_fails_closed(self):
        errs = validate_outcome_predicate(_pred(surprise=1))
        self.assertTrue(any("additionalProperties" in e for e in errs), errs)

    def test_bad_status_enum_fails(self):
        errs = validate_outcome_predicate(_pred(status="done"))
        self.assertTrue(any("status" in e for e in errs), errs)

    def test_outcome_wrong_policy_purpose_fails(self):
        errs = validate_outcome_predicate(_pred(policyPurpose="decision"))
        self.assertTrue(any("policyPurpose" in e for e in errs), errs)

    def test_correct_policy_purpose_ok(self):
        self.assertEqual(validate_outcome_predicate(_pred(policyPurpose="outcome")), [])

    def test_malformed_decision_ref_fails(self):
        errs = validate_outcome_predicate(_pred(decisionRef={"sha256": "short"}))
        self.assertTrue(any("decisionRef" in e for e in errs), errs)

    def test_claimed_executed_without_evidence_not_strong(self):
        # executed WITH an effect digest → proven True
        self.assertTrue(outcome_execution_proven(_pred()))
        # executed WITHOUT any effect/actual digest → False (self-asserted, the honesty limit)
        p = _pred()
        del p["effectDigest"]
        self.assertFalse(outcome_execution_proven(p))
        # non-executed status → not applicable (None)
        self.assertIsNone(outcome_execution_proven(_pred(status="refused")))

    def test_emit_rejects_invalid_predicate(self):
        s, _ = _keys()
        with self.assertRaises(OutcomeReceiptError):
            emit_outcome_receipt(_pred(status="nope"), s)


class TestOutcomeVerify(unittest.TestCase):
    def test_roundtrip_all_checks_green(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, pub, strict=True,
                                   expected_decision_ref=_DEC_ROOT,
                                   decision_maker_id="decider:policy-gate")
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"])
        self.assertTrue(r["decision_bound"])
        self.assertTrue(r["role_separation_ok"])
        self.assertTrue(r["execution_proven"])

    def test_tamper_breaks_crypto(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        statement = build_outcome_statement(_pred(outcomeId="TAMPERED"))
        forged = _repayload(env, statement)
        r = verify_outcome_receipt(forged, pub)
        self.assertFalse(r["ok"])
        self.assertFalse(r["crypto_ok"])
        self.assertTrue(r["errors"])

    def test_wrong_key_fails(self):
        s, _ = _keys()
        _, other_pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, other_pub)
        self.assertFalse(r["ok"])
        self.assertFalse(r["crypto_ok"])

    def test_predicate_type_confusion_fails(self):
        s, pub = _keys()
        stmt = build_outcome_statement(_pred())
        stmt["predicateType"] = "https://in-toto.io/attestation/vulns"
        env = dsse.sign_envelope(_rfc8785_bytes(stmt), s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_outcome_receipt(env, pub)
        self.assertFalse(r["predicate_type_ok"])
        self.assertFalse(r["ok"])

    def test_wrong_decision_ref_fails(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, pub, expected_decision_ref=_OTHER_ROOT)
        self.assertFalse(r["decision_bound"])
        self.assertFalse(r["ok"])

    def test_replay_outcome_against_other_decision_fails(self):
        # An outcome bound to decision A, replayed where decision B is expected → decision_bound False.
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(decisionRef={"sha256": _DEC_ROOT}), s)
        r = verify_outcome_receipt(env, pub, expected_decision_ref=_OTHER_ROOT)
        self.assertFalse(r["decision_bound"])
        self.assertFalse(r["ok"])
        self.assertTrue(any("replay" in e.lower() for e in r["errors"]), r["errors"])

    def test_wrong_executor_role_separation_fails(self):
        # executor equals the decision maker → role_separation_ok False (fail-closed).
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(executor={"id": "decider:policy-gate"}), s)
        r = verify_outcome_receipt(env, pub, decision_maker_id="decider:policy-gate")
        self.assertFalse(r["role_separation_ok"])
        self.assertFalse(r["ok"])

    def test_executor_differs_role_separation_ok(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(executor={"id": "executor:runner-7"}), s)
        r = verify_outcome_receipt(env, pub, decision_maker_id="decider:policy-gate")
        self.assertTrue(r["role_separation_ok"])

    def test_claimed_executed_without_evidence_warns_not_hard_fail(self):
        # self-asserted executed (no effect digest) → execution_proven False + warning, but crypto/structure
        # green and no other failing check → aggregate ok stays True (an honest limit, not tampering).
        s, pub = _keys()
        p = _pred()
        del p["effectDigest"]
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, strict=True, expected_decision_ref=_DEC_ROOT,
                                   decision_maker_id="decider:policy-gate")
        self.assertFalse(r["execution_proven"])
        self.assertTrue(any("self-asserted" in w for w in r["warnings"]), r["warnings"])
        self.assertTrue(r["ok"], r)

    def test_audience_and_nonce_binding_fail_closed(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(validity={"audience": ["rp.example"], "nonce": "n-1"}), s)
        # correct audience+nonce → ok
        r = verify_outcome_receipt(env, pub, expected_audience="rp.example", expected_nonce="n-1")
        self.assertTrue(r["audience_ok"] and r["nonce_ok"])
        # wrong audience → fail-closed
        r2 = verify_outcome_receipt(env, pub, expected_audience="other.rp")
        self.assertFalse(r2["audience_ok"])
        self.assertFalse(r2["ok"])
        # requested audience but receipt has none → fail-closed (not silent None-pass)
        env_no = emit_outcome_receipt(_pred(), s)
        r3 = verify_outcome_receipt(env_no, pub, expected_audience="rp.example")
        self.assertFalse(r3["audience_ok"])
        self.assertFalse(r3["ok"])

    def test_nonce_mismatch_is_fail_closed(self):
        # replay protection (the untested sibling of the audience-mismatch case): a receipt bound to nonce
        # n-1, verified with expected_nonce n-2, must fail closed — and requesting a nonce the receipt lacks
        # must not silently pass.
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(validity={"audience": ["rp.example"], "nonce": "n-1"}), s)
        r = verify_outcome_receipt(env, pub, expected_nonce="n-2")
        self.assertFalse(r["nonce_ok"])
        self.assertFalse(r["ok"])
        env_no = emit_outcome_receipt(_pred(), s)
        r2 = verify_outcome_receipt(env_no, pub, expected_nonce="n-1")
        self.assertFalse(r2["nonce_ok"])
        self.assertFalse(r2["ok"])


class TestOutcomeSubjectBinding(unittest.TestCase):
    """#4 (release-review): a subject that does not commit to the predicate (subject-rehang) must not be
    silent — it is always warned, and require_derived_subject makes it a hard fail-closed error."""

    def test_derived_subject_default_green(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)  # subject derived from the predicate
        r = verify_outcome_receipt(env, pub, strict=True, expected_decision_ref=_DEC_ROOT)
        self.assertEqual(r["subject_binding"]["mode"], "DERIVED")
        self.assertTrue(r["subject_binding"]["matches"])
        self.assertFalse(any("subject-rehang" in w for w in r["warnings"]))
        self.assertTrue(r["ok"], r)

    def test_external_attested_subject_is_warned_not_silent(self):
        # the PoC: a validly-signed outcome whose subject points elsewhere. It must no longer verify with ZERO
        # signal — the classification + a warning are always present (ok still True by default, override is a
        # documented self-attest feature).
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s, subject_sha256="d" * 64)
        r = verify_outcome_receipt(env, pub, strict=True, expected_decision_ref=_DEC_ROOT)
        self.assertEqual(r["subject_binding"]["mode"], "EXTERNAL_ATTESTED")
        self.assertFalse(r["subject_binding"]["matches"])
        self.assertTrue(any("subject-rehang" in w for w in r["warnings"]), r["warnings"])

    def test_require_derived_subject_rejects_rehang(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s, subject_sha256="d" * 64)
        r = verify_outcome_receipt(env, pub, strict=True, expected_decision_ref=_DEC_ROOT,
                                   require_derived_subject=True)
        self.assertFalse(r["subject_derived_ok"])
        self.assertFalse(r["ok"])

    def test_require_derived_subject_green(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, pub, strict=True, expected_decision_ref=_DEC_ROOT,
                                   require_derived_subject=True)
        self.assertTrue(r["subject_derived_ok"])
        self.assertTrue(r["ok"], r)

    def test_require_derived_subject_fail_closed_when_classify_raises(self):
        # #4 hardening: if classify_subject raises, require_derived_subject must fail-closed EXPLICITLY, not
        # pass the gate on a coincidence elsewhere. (Patch classify to raise and assert the hard fail.)
        import unittest.mock as mock

        from proofbundle import subject_binding
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        with mock.patch.object(subject_binding, "classify_subject", side_effect=RuntimeError("boom")):
            r = verify_outcome_receipt(env, pub, strict=True, expected_decision_ref=_DEC_ROOT,
                                       require_derived_subject=True)
        self.assertFalse(r["subject_derived_ok"])
        self.assertFalse(r["ok"])


class TestOutcomeExecutorRoleTrust(unittest.TestCase):
    """Finding 01 (2026-07 verify-layer hardening): trust_pack.py declared an `outcomeExecutors` role but
    no verify_* path ever consumed it (docs/predicates/action-outcome.md §7, "open, not yet built"). This
    tests `executor_trusted_by_role` / the new `trust_pack` param, additively."""

    @staticmethod
    def _trust_pack(*, member_key_id="kid-exec", revoked=None):
        return {
            "schemaVersion": "0.1.0", "trustPackId": "tp-1", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                     "outcomeExecutors": {"keyIds": [member_key_id], "threshold": 1}},
            "keys": {"root-0": {"publicKey": "A" * 43 + "="}},
            "nonClaims": ["names which keys hold which role, not that the holders are honest"],
            **({"revoked": revoked} if revoked else {}),
        }

    def test_no_trust_pack_supplied_stays_none(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, pub)
        self.assertIsNone(r["executor_role_trusted"])
        self.assertTrue(r["ok"], r)   # unaffected: fully backward compatible

    def test_member_key_id_is_trusted(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)   # _pred()'s executor.keyId == "kid-exec"
        r = verify_outcome_receipt(env, pub, trust_pack=self._trust_pack(member_key_id="kid-exec"))
        self.assertTrue(r["executor_role_trusted"], r)
        self.assertTrue(r["ok"], r)

    def test_non_member_key_id_fails_closed(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, pub, trust_pack=self._trust_pack(member_key_id="someone-else"))
        self.assertFalse(r["executor_role_trusted"])
        self.assertFalse(r["ok"])
        self.assertTrue(any("outcomeExecutors" in e for e in r["errors"]), r["errors"])

    def test_revoked_member_fails_closed(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(
            env, pub, trust_pack=self._trust_pack(member_key_id="kid-exec", revoked=["kid-exec"]))
        self.assertFalse(r["executor_role_trusted"])
        self.assertFalse(r["ok"])

    def test_missing_role_fails_closed(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        pack = self._trust_pack()
        del pack["roles"]["outcomeExecutors"]
        r = verify_outcome_receipt(env, pub, trust_pack=pack)
        self.assertFalse(r["executor_role_trusted"])
        self.assertFalse(r["ok"])

    def test_executor_without_keyid_fails_closed(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(executor={"id": "executor:runner-7"}), s)   # no keyId
        r = verify_outcome_receipt(env, pub, trust_pack=self._trust_pack())
        self.assertFalse(r["executor_role_trusted"])
        self.assertFalse(r["ok"])

    def test_malformed_trust_pack_never_crashes(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        for bad_pack in ({}, {"roles": "not-a-dict"}, {"roles": {"outcomeExecutors": "not-a-dict"}},
                         {"roles": {"outcomeExecutors": {"keyIds": "not-a-list"}}}):
            r = verify_outcome_receipt(env, pub, trust_pack=bad_pack)   # must not raise
            self.assertFalse(r["executor_role_trusted"], bad_pack)

    def test_executor_trusted_by_role_direct(self):
        from proofbundle.outcome import executor_trusted_by_role
        pack = self._trust_pack(member_key_id="kid-1")
        self.assertTrue(executor_trusted_by_role({"id": "x", "keyId": "kid-1"}, pack))
        self.assertFalse(executor_trusted_by_role({"id": "x", "keyId": "kid-2"}, pack))
        self.assertFalse(executor_trusted_by_role({"id": "x"}, pack))          # no keyId
        self.assertFalse(executor_trusted_by_role(None, pack))                 # malformed executor
        self.assertFalse(executor_trusted_by_role({"id": "x", "keyId": "kid-1"}, None))  # malformed pack


if __name__ == "__main__":
    unittest.main()
