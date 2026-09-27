"""A caller's resolver promotes a verdict only when it answers the exact ``True``.

The evidence ladder and the renewal anchor take a callable from the caller and used to promote on the
truthiness of its answer: ``bool(evidence_resolver(...))`` in ``classify_digest_evidence``,
``bool(res)`` in ``classify_receiver_corroboration``, and ``bool(verify_anchor(newest))`` in
``verify_sequence``. A resolver that answers ``1``, ``"true"``, ``"false"``, a non-empty list or an
object whose ``__bool__`` says True therefore reached CONTENT_RESOLVED, INDEPENDENTLY_ATTESTED or an
anchored newest ArchiveTimeStamp, although it never said True. The contract of all three is a bool.

Every surface is asked with the same values, directly and through the public verify functions that
pass the resolver on (``verify_decision_receipt``, ``verify_outcome_receipt``). Each such answer must
leave the level where it was, the detail must say why, and the answer's own ``__bool__`` must never run.
The controls show that the exact True still promotes, the exact False still does not, a raising
resolver still does not, and 32 bytes of key material still attest as before.

A fourth surface has the same shape: ``anchors.register_anchor_type`` is a public extension point, so a
registered anchor verifier is caller code, and ``verify_anchor`` read its result with
``bool(res.get("ok"))``, ``bool(res.get("warn"))`` and ``bool(res.get(flag))`` for the three provenance
flags, outside the try, so a result that is not a dict raised a raw AttributeError. It is asked the same
values, directly, through ``verify_anchors(require=...)`` and through
``verify_decision_receipt(anchors=...)``.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from proofbundle import anchors, dsse
from proofbundle.assurance import EvidenceLevel, classify_digest_evidence, classify_receiver_corroboration
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.renewal import build_initial_sequence, verify_sequence

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
_DIGEST = {"sha256": "a" * 64}
_DATA = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]
#: The words every refusal detail carries.
_WHY = "only the exact True"


class _Truthy:
    """An answer whose truthiness is True and which records every time something asks for it."""

    def __init__(self):
        self.asked = 0

    def __bool__(self):
        self.asked += 1
        return True


def _answers():
    """The answers that are not True, fresh for every use (the object counts its own calls)."""
    return [("int 1", 1), ("str 'true'", "true"), ("str 'false'", "false"),
            ("object with __bool__", _Truthy()), ("non-empty list", [0]), ("float 1.0", 1.0)]


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _outcome(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "e" * 64},
        "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
        "requestedActionDigest": {"sha256": "b" * 64}, "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
    }
    p.update(over)
    return p


def _check(result, name):
    return next((c for c in result.checks if c.name == name), None)


class TestTheDigestLadderPromotesOnlyOnTrue(unittest.TestCase):
    def test_an_answer_that_is_not_true_stays_well_formed_and_says_why(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d, a=answer: a)
                self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
                self.assertIn(_WHY, r["detail"])
                if isinstance(answer, _Truthy):
                    self.assertEqual(answer.asked, 0, "the answer's own __bool__ ran")

    def test_control_true_promotes_false_and_raise_do_not(self):
        self.assertEqual(classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)["level"],
                         EvidenceLevel.CONTENT_RESOLVED)
        r = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: False)
        self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertNotIn(_WHY, r["detail"])

        def _boom(_d):
            raise RuntimeError("resolver failed")
        self.assertEqual(classify_digest_evidence(_DIGEST, evidence_resolver=_boom)["level"],
                         EvidenceLevel.REFERENCE_WELL_FORMED)


class TestTheReceiverLadderAttestsOnlyOnTrue(unittest.TestCase):
    _base = dict(executor_key_id="kid-exec", receiver_key_id="kid-recv")

    def test_an_attestation_answer_that_is_not_true_keeps_the_base_level_and_says_why(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = classify_receiver_corroboration(
                    _DIGEST, evidence_resolver=lambda d: True,
                    independent_attestation_resolver=lambda d, a=answer: a, **self._base)
                self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                self.assertIn(_WHY, r["detail"])
                if isinstance(answer, _Truthy):
                    self.assertEqual(answer.asked, 0, "the answer's own __bool__ ran")

    def test_an_evidence_answer_that_is_not_true_opens_no_step_above_it(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = classify_receiver_corroboration(
                    _DIGEST, evidence_resolver=lambda d, a=answer: a,
                    independent_attestation_resolver=lambda d: True, **self._base)
                self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
                self.assertIn(_WHY, r["detail"])

    def test_control_true_and_key_material_attest_false_and_raise_do_not(self):
        top = EvidenceLevel.INDEPENDENTLY_ATTESTED
        self.assertEqual(classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: True,
            **self._base)["level"], top)
        self.assertEqual(classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: b"k" * 32,
            **self._base)["level"], top)
        r = classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: False,
            **self._base)
        self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertNotIn(_WHY, r["detail"])

        def _boom(_d):
            raise RuntimeError("resolver failed")
        self.assertEqual(classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=_boom,
            **self._base)["level"], EvidenceLevel.CONTENT_RESOLVED)


class TestTheRenewalAnchorHoldsOnlyOnTrue(unittest.TestCase):
    def setUp(self):
        self.seq = build_initial_sequence(_DATA, hash_alg="sha256", time=1000)

    def test_an_anchor_answer_that_is_not_true_is_not_anchored_and_says_why(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = verify_sequence(self.seq, _DATA, anchor_verifier=lambda a, x=answer: x)
                c = _check(r, "renewal:last_anchor")
                self.assertIsNotNone(c, [x.name for x in r.checks])
                self.assertIs(c.ok, False)
                self.assertIs(r.ok, False)
                self.assertIn(_WHY, c.detail)
                if isinstance(answer, _Truthy):
                    self.assertEqual(answer.asked, 0, "the answer's own __bool__ ran")

    def test_control_true_anchors_false_does_not(self):
        r = verify_sequence(self.seq, _DATA, anchor_verifier=lambda a: True)
        self.assertIs(_check(r, "renewal:last_anchor").ok, True)
        self.assertIs(r.ok, True)
        r = verify_sequence(self.seq, _DATA, anchor_verifier=lambda a: False)
        c = _check(r, "renewal:last_anchor")
        self.assertIs(c.ok, False)
        self.assertNotIn(_WHY, c.detail)


class TestThePublicVerifiersPassTheRuleOn(unittest.TestCase):
    """The resolvers reach the ladder only through these two functions; the CLI sets none."""

    def _decision(self):
        p = copy.deepcopy(json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8")))
        p["evidenceRefs"] = [{"relation": "evalResult", "digest": {"sha256": "b" * 64}}]
        s, pub = _keys()
        return emit_decision_receipt(p, s, strict=True), pub

    def test_decision_evidence_refs(self):
        env, pub = self._decision()
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = verify_decision_receipt(env, pub, strict=True, evidence_resolver=lambda d, a=answer: a)
                self.assertEqual(r["evidence_levels"]["evidenceRefs"]["level"],
                                 EvidenceLevel.REFERENCE_WELL_FORMED)
        r = verify_decision_receipt(env, pub, strict=True, evidence_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["evidenceRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_outcome_effect_and_receiver(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome(receiverRefs=[
            {"relation": "receiverAck", "digest": {"sha256": "d" * 64}, "receiverKeyId": "kid-recv"}]), s)
        for label, answer in _answers():
            with self.subTest(answer=label, resolver="evidence"):
                r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d, a=answer: a)
                self.assertEqual(r["evidence_levels"]["effect"]["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
            with self.subTest(answer=label, resolver="receiver attestation"):
                r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                           receiver_attestation_resolver=lambda d, a=answer: a)
                self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["effect"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)


class _LyingDict(dict):
    """A result that is a dict subclass whose own ``get`` answers True for every key."""

    def get(self, key, default=None):
        return True


class TestARegisteredAnchorVerifierCountsOnlyOnTrue(unittest.TestCase):
    """``register_anchor_type`` hands ``verify_anchor`` caller code; its answer counts only as the exact True."""

    _TYPE = "test-only-the-exact-true/v1"
    _FLAGS = ("rp_trusted", "needs_rp_trust", "frozenEvidence")

    def setUp(self):
        self.answer = None
        anchors.register_anchor_type(self._TYPE, lambda proof, root, *, frozen, now: self.answer)

    def tearDown(self):
        anchors._VERIFIERS.pop(self._TYPE, None)

    def _anchor(self, root: bytes, target: str = "statement") -> dict:
        return {"type": self._TYPE, "target": target, "canonicalRoot": base64.b64encode(root).decode("ascii"),
                "proof": base64.b64encode(b"proof").decode("ascii")}

    def _one(self, answer):
        self.answer = answer
        root = hashlib.sha256(b"statement").digest()
        return anchors.verify_anchor(self._anchor(root), target_roots={"statement": root})

    def _required(self, answer, *, allow_pending: bool):
        self.answer = answer
        root = hashlib.sha256(b"statement").digest()
        return anchors.verify_anchors([self._anchor(root)], target_roots={"statement": root}, require="any",
                                      allow_pending=allow_pending)

    def test_an_ok_that_is_not_true_is_not_verified_and_says_why(self):
        for label, value in _answers():
            with self.subTest(answer=label):
                out = self._one({"ok": value, "detail": "from the verifier"})
                self.assertIs(out["ok"], False)
                self.assertIs(out["warn"], False)
                self.assertEqual(out["status"], "fail")
                self.assertIn(_WHY, out["detail"])
                self.assertIs(self._required({"ok": value}, allow_pending=False)["require_met"], False)
                if isinstance(value, _Truthy):
                    self.assertEqual(value.asked, 0, "the answer's own __bool__ ran")

    def test_a_warn_that_is_not_true_does_not_turn_a_fail_into_pending(self):
        for label, value in _answers():
            with self.subTest(answer=label):
                out = self._one({"ok": False, "warn": value})
                self.assertIs(out["warn"], False)
                self.assertIn(_WHY, out["detail"])
                res = self._required({"ok": False, "warn": value}, allow_pending=True)
                self.assertIs(res["require_met"], False)
                self.assertEqual(res["status"], "FAIL")
                if isinstance(value, _Truthy):
                    self.assertEqual(value.asked, 0, "the answer's own __bool__ ran")

    def test_a_provenance_flag_that_is_not_true_is_false(self):
        for flag in self._FLAGS:
            for label, value in _answers():
                with self.subTest(flag=flag, answer=label):
                    out = self._one({"ok": False, flag: value})
                    self.assertIs(out[flag], False)
                    self.assertIn(_WHY, out["detail"])
                    if isinstance(value, _Truthy):
                        self.assertEqual(value.asked, 0, "the answer's own __bool__ ran")

    def test_a_result_that_is_not_a_dict_fails_closed_and_does_not_raise(self):
        for label, value in (("bool True", True), ("None", None), ("list of pairs", [("ok", True)]),
                             ("str 'ok'", "ok"), ("int 1", 1), ("dict subclass with its own get",
                                                                 _LyingDict(ok=False))):
            with self.subTest(result=label):
                out = self._one(value)
                self.assertIs(out["ok"], False)
                self.assertIs(out["warn"], False)
                self.assertEqual(out["status"], "fail")
                self.assertIn("no result object", out["detail"])
                self.assertIs(self._required(value, allow_pending=True)["require_met"], False)

    def test_control_exact_bools_behave_as_before(self):
        out = self._one({"ok": True, "detail": "verified"})
        self.assertIs(out["ok"], True)
        self.assertEqual(out["status"], "pass")
        self.assertEqual(out["detail"], "verified")
        self.assertIs(self._required({"ok": True}, allow_pending=False)["require_met"], True)
        out = self._one({"ok": False, "detail": "bad proof"})
        self.assertIs(out["ok"], False)
        self.assertEqual(out["detail"], "bad proof")
        self.assertNotIn(_WHY, out["detail"])
        out = self._one({"ok": False, "warn": True, "status": "pending"})
        self.assertIs(out["warn"], True)
        self.assertEqual(out["status"], "pending")
        self.assertIs(self._required({"ok": False, "warn": True}, allow_pending=True)["require_met"], True)
        self.assertIs(self._required({"ok": False, "warn": True}, allow_pending=False)["require_met"], False)
        out = self._one({"ok": True, "rp_trusted": True, "needs_rp_trust": False, "frozenEvidence": False})
        self.assertEqual((out["rp_trusted"], out["needs_rp_trust"], out["frozenEvidence"]), (True, False, False))
        self.assertNotIn(_WHY, out["detail"])

    def test_control_a_raising_verifier_is_a_failed_anchor(self):
        def _boom(proof, root, *, frozen, now):
            raise RuntimeError("verifier failed")
        anchors.register_anchor_type(self._TYPE, _boom)
        root = hashlib.sha256(b"statement").digest()
        out = anchors.verify_anchor(self._anchor(root), target_roots={"statement": root})
        self.assertIs(out["ok"], False)
        self.assertIs(out["warn"], False)
        self.assertEqual(out["status"], "fail")

    def _decision(self):
        p = copy.deepcopy(json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8")))
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        return env, pub, anchors.statement_content_root(dsse.load_payload(env))

    def test_decision_receipt_anchors_ok_only_on_true(self):
        env, pub, root = self._decision()
        for label, value in _answers():
            with self.subTest(answer=label, field="ok"):
                self.answer = {"ok": value}
                r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
                self.assertIs(r["anchors_ok"], False)
                self.assertIs(r["ok"], False)
        for label, value in (("bool True", True), ("None", None), ("dict subclass with its own get",
                                                                   _LyingDict(ok=False))):
            with self.subTest(result=label):
                self.answer = value
                r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
                self.assertIs(r["anchors_ok"], False)
                self.assertIs(r["ok"], False)
        self.answer = {"ok": True}
        r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
        self.assertIs(r["anchors_ok"], True)
        self.assertIs(r["ok"], True, "the refusals above must come from the anchor, not from elsewhere")
        self.answer = {"ok": False}
        r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
        self.assertIs(r["anchors_ok"], False)


if __name__ == "__main__":
    unittest.main()
