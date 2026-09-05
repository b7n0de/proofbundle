"""A role from a Trust Pack applies to the key that SIGNED, never to a keyId label the signer wrote.

Deep gate run 3 on 049b3195 (2026-09-05), finding L1-600-02 (P2, fail-open). `verify_outcome_receipt`
answered `executor_role_trusted=True` and `safeForAutomation=True` for an outcome signed by a FRESH
attacker key whose predicate merely CLAIMED `executor.keyId = root-0` — the pack held root-0's real key
material right next to the role, and nobody compared it with the key the envelope had just verified
under. The decision path never had this defect (`evaluate_decision_policy` pins trusted makers against
`signer_public_key_b64`), which is the positive control below.

THE CLASS (neighbour of `signatur_beglaubigt_das_lesen_nicht_die_behauptung`): a signed field taken as
proof of a relation the verifier never checked. The invariant closed here: whenever a pack names key
material for a keyId, a role verdict about that keyId is bound to that material — for the executor
against the verifying key, for a receiver against the signer key the attestation resolver reports.
"""
from __future__ import annotations

import base64
import unittest

from proofbundle.assurance import EvidenceLevel, classify_receiver_corroboration
from proofbundle.emit import generate_signer
from proofbundle.outcome import (
    emit_outcome_receipt,
    executor_trusted_by_role,
    pack_key_binds_signer,
    verify_outcome_receipt,
)

_DIG = "d" * 64


def _pub(signer) -> bytes:
    return signer.public_key().public_bytes_raw()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _pack(keys: dict, *, executors=("root-0",), receivers=("root-1",), revoked=None) -> dict:
    return {
        "schemaVersion": "0.1.0", "trustPackId": "tp-bind", "version": 1,
        "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
        "roles": {"root": {"keyIds": list(keys), "threshold": 1},
                  "outcomeExecutors": {"keyIds": list(executors), "threshold": 1},
                  "outcomeReceivers": {"keyIds": list(receivers), "threshold": 1}},
        "keys": {kid: {"publicKey": _b64(pk)} for kid, pk in keys.items()},
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
        **({"revoked": revoked} if revoked else {}),
    }


def _outcome(executor_key_id="root-0", **extra) -> dict:
    return {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
            "executor": {"id": "executor:x", "keyId": executor_key_id},
            "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
            "performedAt": "2026-09-05T10:00:00Z", "effectDigest": {"sha256": "c" * 64}, **extra}


class TestExecutorKeyIdIsBoundToTheSigner(unittest.TestCase):
    def setUp(self):
        self.root0, self.root1, self.attacker = generate_signer(), generate_signer(), generate_signer()
        self.pack = _pack({"root-0": _pub(self.root0), "root-1": _pub(self.root1)})

    def test_control_the_real_role_key_is_trusted_and_bound(self):
        env = emit_outcome_receipt(_outcome(), self.root0)
        r = verify_outcome_receipt(env, _pub(self.root0), trust_pack=self.pack)
        self.assertTrue(r["ok"], r["errors"])
        self.assertTrue(r["executor_role_trusted"])
        self.assertTrue(r["executor_key_bound"])
        self.assertTrue(r["automation"]["safeForAutomation"])

    def test_the_confirmed_finding_a_claimed_keyid_signed_by_another_key_is_not_trusted(self):
        """The exact measured shape: fresh attacker key, predicate claims root-0, verified under the
        attacker's own key (the key the envelope's keyid hint / a per-receipt key file invites)."""
        spoof = emit_outcome_receipt(_outcome(), self.attacker)
        r = verify_outcome_receipt(spoof, _pub(self.attacker), trust_pack=self.pack)
        self.assertTrue(r["crypto_ok"], "the envelope IS validly signed — by the wrong key for the label")
        self.assertFalse(r["executor_role_trusted"])
        self.assertIs(r["executor_key_bound"], False)
        self.assertFalse(r["ok"])
        self.assertFalse(r["automation"]["safeForAutomation"])
        self.assertIn("KEY_ID_NOT_BOUND_TO_SIGNER", r["automation"]["automationBlockers"])
        self.assertTrue(any("KEY_ID_NOT_BOUND_TO_SIGNER" in e for e in r["errors"]), r["errors"])

    def test_a_keyid_without_key_material_in_the_pack_cannot_be_bound(self):
        pack = _pack({"root-0": _pub(self.root0)}, executors=("ghost",))
        env = emit_outcome_receipt(_outcome(executor_key_id="ghost"), self.root0)
        r = verify_outcome_receipt(env, _pub(self.root0), trust_pack=pack)
        self.assertFalse(r["executor_role_trusted"])
        self.assertFalse(r["ok"])

    def test_an_mldsa_only_key_never_binds_an_ed25519_envelope(self):
        pack = self.pack
        pack["keys"]["root-0"]["alg"] = "mldsa65"
        env = emit_outcome_receipt(_outcome(), self.root0)
        r = verify_outcome_receipt(env, _pub(self.root0), trust_pack=pack)
        self.assertFalse(r["executor_role_trusted"])

    def test_membership_only_check_still_answers_the_label_question(self):
        # the label-only helper keeps its documented contract (no public_key -> membership only) ...
        self.assertTrue(executor_trusted_by_role({"id": "x", "keyId": "root-0"}, self.pack))
        # ... and binds as soon as the signing key is supplied
        self.assertTrue(executor_trusted_by_role({"id": "x", "keyId": "root-0"}, self.pack,
                                                 public_key=_pub(self.root0)))
        self.assertFalse(executor_trusted_by_role({"id": "x", "keyId": "root-0"}, self.pack,
                                                  public_key=_pub(self.attacker)))

    def test_pack_key_binds_signer_never_raises_on_malformed_input(self):
        for kid, pack, key in ((None, self.pack, _pub(self.root0)), ("root-0", None, _pub(self.root0)),
                               ("root-0", self.pack, None), ("root-0", self.pack, b"short"),
                               ("root-0", {"keys": {"root-0": {"publicKey": 5}}}, _pub(self.root0)),
                               ("root-0", {"keys": {"root-0": {"publicKey": "!!!"}}}, _pub(self.root0))):
            self.assertFalse(pack_key_binds_signer(kid, pack, key))

    def test_meta_the_pre_fix_shape_is_caught_by_the_finding_test(self):
        """PLANT-AND-MUST-CATCH: the pre-fix verifier asked only the label question. The label question
        answers True for the spoof — which is exactly what the finding test above refuses. If the
        membership helper stopped saying True here, the plant would be ineffective and the finding
        test would prove nothing about the binding."""
        spoof_pred = _outcome()
        self.assertTrue(executor_trusted_by_role(spoof_pred["executor"], self.pack),
                        "the plant is ineffective: even the label check refuses the spoof")
        self.assertFalse(executor_trusted_by_role(spoof_pred["executor"], self.pack,
                                                  public_key=_pub(self.attacker)))

    def test_positive_control_the_decision_path_pins_the_signer_key(self):
        """The neighbour that did NOT have the defect: decision.evaluate_decision_policy pins trusted makers
        against the signer's public key, so a claimed decisionMaker signed by another key is not trusted."""
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        from proofbundle.policy import load_policy
        import json
        from pathlib import Path
        maker, other = generate_signer(), generate_signer()
        pred = json.loads((Path(__file__).resolve().parent.parent / "examples" / "decision_receipt_deny.json")
                          .read_text(encoding="utf-8"))
        maker_id = pred["decisionMaker"]["id"]
        pol = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "pin",
                           "decision_receipt": {"trusted_decision_makers": [
                               {"id": maker_id, "public_key_b64": _b64(_pub(maker))}]}})
        env = emit_decision_receipt(pred, other, strict=True)   # claims the maker, signed by `other`
        r = verify_decision_receipt(env, _pub(other), policy=pol)
        self.assertIsNot(r.get("policy_ok"), True)
        self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True)


class TestReceiverKeyIdIsBoundWhenThePackNamesTheKey(unittest.TestCase):
    def setUp(self):
        self.exec_, self.recv, self.attacker = generate_signer(), generate_signer(), generate_signer()
        self.pack = _pack({"root-0": _pub(self.exec_), "root-1": _pub(self.recv)})
        self.env = emit_outcome_receipt(_outcome(receiverRefs=[
            {"relation": "acknowledges", "digest": {"sha256": _DIG}, "receiverKeyId": "root-1"}]), self.exec_)

    def _verify(self, resolver):
        return verify_outcome_receipt(self.env, _pub(self.exec_), trust_pack=self.pack,
                                      evidence_resolver=lambda d: True,
                                      receiver_attestation_resolver=resolver)

    def test_resolver_returning_the_packs_key_binds_the_label_and_promotes(self):
        r = self._verify(lambda d: _pub(self.recv))
        self.assertTrue(r["receiver_role_trusted"])
        self.assertIs(r["receiver_key_bound"], True)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)

    def test_resolver_returning_another_key_is_the_finding_on_the_receiver_side(self):
        r = self._verify(lambda d: _pub(self.attacker))
        self.assertFalse(r["receiver_role_trusted"])
        self.assertIs(r["receiver_key_bound"], False)
        self.assertLess(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertTrue(any("KEY_ID_NOT_BOUND_TO_SIGNER" in e for e in r["errors"]), r["errors"])
        self.assertTrue(r["ok"], "receiverRefs is advisory and never gates ok — unchanged")

    def test_a_bare_true_cannot_bind_a_label_the_pack_names(self):
        r = self._verify(lambda d: True)
        self.assertTrue(r["receiver_role_trusted"])      # membership by label, as before ...
        self.assertIsNone(r["receiver_key_bound"])       # ... but explicitly unbound ...
        self.assertLess(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertTrue(any("LABEL only" in w for w in r["warnings"]), r["warnings"])

    def test_without_a_pack_the_bool_resolver_contract_is_unchanged(self):
        r = verify_outcome_receipt(self.env, _pub(self.exec_), evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertIsNone(r["receiver_role_trusted"])

    def test_classifier_direct_expected_key_must_match_and_a_short_key_never_attests(self):
        base = dict(digest_obj={"sha256": _DIG}, evidence_resolver=lambda d: True,
                    executor_key_id="root-0", receiver_key_id="root-1", expected_receiver_public_key=_pub(self.recv))
        good = classify_receiver_corroboration(independent_attestation_resolver=lambda d: _pub(self.recv), **base)
        self.assertEqual(good["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        wrong = classify_receiver_corroboration(independent_attestation_resolver=lambda d: _pub(self.attacker), **base)
        self.assertEqual(wrong["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertIn("KEY_ID_NOT_BOUND_TO_SIGNER", wrong["detail"])
        short = classify_receiver_corroboration(independent_attestation_resolver=lambda d: b"nope", **base)
        self.assertEqual(short["level"], EvidenceLevel.CONTENT_RESOLVED)


if __name__ == "__main__":
    unittest.main()
