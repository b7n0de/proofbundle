"""Finding 16 (self-fixable part) — outcome receiver/observer corroboration, additive.

An Action Outcome's `execution_proven` is by default a claim the EXECUTOR signs about itself. This closes
the SELF-FIXABLE half: an optional, digest-bound `receiverRefs[]` (mirrors decision.py's `evidenceRefs[]`),
an `assurance.classify_receiver_corroboration` wiring that can reach `EvidenceLevel.INDEPENDENTLY_ATTESTED`,
an `outcomeReceivers` Trust Pack role, and `detect_outcome_sequence_gaps` for opted-in gap detection.

The INHERENT half (proofbundle cannot itself make a receiving system SIGN an acknowledgement) is NOT built
here and is not claimed to be — see the "honest limit" tests below, which prove the guard against faking a
stronger claim without genuine content resolution.

unittest-style to match the repo's `python -m unittest discover`.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None

from proofbundle import dsse
from proofbundle.assurance import EvidenceLevel
from proofbundle.emit import generate_signer
from proofbundle.outcome import (
    build_outcome_statement,
    detect_outcome_sequence_gaps,
    emit_outcome_receipt,
    receiver_trusted_by_role,
    resolve_receiver_ref,
    validate_outcome_predicate,
    verify_outcome_receipt,
)

ROOT = Path(__file__).resolve().parent.parent
OUTCOME_SCHEMA = json.loads((ROOT / "schemas" / "action-outcome-v0.1.schema.json").read_text(encoding="utf-8"))

_DEC_ROOT = "a" * 64
_DIG = "c" * 64
_RECV_DIG = "d" * 64


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


def _jsonschema_valid(instance: dict) -> bool:
    try:
        jsonschema.validate(instance=instance, schema=OUTCOME_SCHEMA)
        return True
    except jsonschema.ValidationError:
        return False


def _trust_pack(*, receiver_key_id="kid-recv", revoked=None):
    # Also trusts _pred()'s default executor keyId ("kid-exec") as an outcomeExecutors member, so passing
    # this pack to verify_outcome_receipt does not ALSO trip the (pre-existing, Finding 01) executor_role_
    # trusted hard-gate — these tests isolate the receiver-role concern, not the executor-role one.
    return {
        "schemaVersion": "0.1.0", "trustPackId": "tp-1", "version": 1,
        "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
        "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                 "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1},
                 "outcomeReceivers": {"keyIds": [receiver_key_id], "threshold": 1}},
        "keys": {"root-0": {"publicKey": "A" * 43 + "="}},
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
        **({"revoked": revoked} if revoked else {}),
    }


class TestReceiverRefsValidation(unittest.TestCase):
    def test_absent_receiver_refs_is_valid(self):
        self.assertEqual(validate_outcome_predicate(_pred()), [])

    def test_valid_receiver_ref(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG},
                                 "receiverId": "receiver:svc-1", "receiverKeyId": "kid-recv"}])
        self.assertEqual(validate_outcome_predicate(p), [])

    def test_receiver_ref_missing_relation_fails(self):
        p = _pred(receiverRefs=[{"digest": {"sha256": _RECV_DIG}}])
        errs = validate_outcome_predicate(p)
        self.assertTrue(any("receiverRefs" in e for e in errs), errs)

    def test_receiver_ref_bad_digest_fails(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": "short"}}])
        errs = validate_outcome_predicate(p)
        self.assertTrue(any("receiverRefs" in e for e in errs), errs)

    def test_receiver_ref_bad_receiver_id_type_fails(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG},
                                 "receiverId": 5}])
        errs = validate_outcome_predicate(p)
        self.assertTrue(any("receiverId" in e for e in errs), errs)

    def test_receiver_refs_not_a_list_fails(self):
        p = _pred(receiverRefs="nope")
        errs = validate_outcome_predicate(p)
        self.assertTrue(any("receiverRefs must be a list" in e for e in errs), errs)

    def test_unknown_nested_field_in_receiver_ref_rejected(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}, "sneaky": 1}])
        errs = validate_outcome_predicate(p)
        self.assertTrue(any("receiverRefs" in e and "undeclared" in e for e in errs), errs)

    def test_empty_receiver_refs_list_is_valid(self):
        self.assertEqual(validate_outcome_predicate(_pred(receiverRefs=[])), [])


class TestSequenceValidation(unittest.TestCase):
    def test_valid_sequence(self):
        self.assertEqual(validate_outcome_predicate(_pred(sequence={"runId": "run-1", "seq": 0})), [])

    def test_sequence_not_an_object_fails(self):
        errs = validate_outcome_predicate(_pred(sequence="n-1"))
        self.assertTrue(any("sequence must be an object" in e for e in errs), errs)

    def test_sequence_missing_run_id_fails(self):
        errs = validate_outcome_predicate(_pred(sequence={"seq": 1}))
        self.assertTrue(any("runId" in e for e in errs), errs)

    def test_sequence_negative_seq_fails(self):
        errs = validate_outcome_predicate(_pred(sequence={"runId": "run-1", "seq": -1}))
        self.assertTrue(any("seq" in e for e in errs), errs)

    def test_sequence_bool_seq_fails(self):
        # a bool IS an int in Python — this pins that the hand validator does NOT accept it as an integer.
        errs = validate_outcome_predicate(_pred(sequence={"runId": "run-1", "seq": True}))
        self.assertTrue(any("seq" in e for e in errs), errs)

    def test_unknown_nested_field_in_sequence_rejected(self):
        errs = validate_outcome_predicate(_pred(sequence={"runId": "run-1", "seq": 0, "sneaky": 1}))
        self.assertTrue(any("sequence" in e and "undeclared" in e for e in errs), errs)


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestSchemaParity(unittest.TestCase):
    """Finding 04 discipline extended to Finding 16's new fields: the hand-rolled validator and the
    docs-only JSON Schema must agree, both accept or both reject."""

    def _agree(self, predicate: dict, *, expect_valid: bool, msg: str = ""):
        hand_valid = not validate_outcome_predicate(predicate, strict=True)
        schema_valid = _jsonschema_valid(predicate)
        self.assertEqual(hand_valid, expect_valid, f"{msg}: hand={hand_valid}")
        self.assertEqual(schema_valid, expect_valid, f"{msg}: schema={schema_valid}")
        self.assertEqual(hand_valid, schema_valid, f"{msg}: DIVERGENCE hand={hand_valid} schema={schema_valid}")

    def test_valid_receiver_refs_and_sequence_agree(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}],
                  sequence={"runId": "run-1", "seq": 3})
        self._agree(p, expect_valid=True, msg="valid receiverRefs+sequence")

    def test_receiver_ref_unknown_field_rejected_both(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}, "sneaky": 1}])
        self._agree(p, expect_valid=False, msg="receiverRefs[].sneaky")

    def test_sequence_missing_seq_rejected_both(self):
        p = _pred(sequence={"runId": "run-1"})
        self._agree(p, expect_valid=False, msg="sequence missing seq")

    def test_receiver_ref_missing_digest_rejected_both(self):
        p = _pred(receiverRefs=[{"relation": "receiverAck"}])
        self._agree(p, expect_valid=False, msg="receiverRefs[] missing digest")


class TestReceiverTrustedByRole(unittest.TestCase):
    def test_member_key_id_is_trusted(self):
        self.assertTrue(receiver_trusted_by_role("kid-recv", _trust_pack(receiver_key_id="kid-recv")))

    def test_non_member_fails_closed(self):
        self.assertFalse(receiver_trusted_by_role("kid-other", _trust_pack(receiver_key_id="kid-recv")))

    def test_revoked_member_fails_closed(self):
        pack = _trust_pack(receiver_key_id="kid-recv", revoked=["kid-recv"])
        self.assertFalse(receiver_trusted_by_role("kid-recv", pack))

    def test_missing_role_fails_closed(self):
        pack = _trust_pack()
        del pack["roles"]["outcomeReceivers"]
        self.assertFalse(receiver_trusted_by_role("kid-recv", pack))

    def test_malformed_input_never_crashes(self):
        self.assertFalse(receiver_trusted_by_role(None, _trust_pack()))
        self.assertFalse(receiver_trusted_by_role("kid-recv", None))
        self.assertFalse(receiver_trusted_by_role("kid-recv", {}))
        self.assertFalse(receiver_trusted_by_role("", _trust_pack()))


class TestResolveReceiverRef(unittest.TestCase):
    def setUp(self):
        self.receiver_pred = _pred(outcomeId="receiver-statement", executor={"id": "receiver:svc-1"})
        self.env = emit_outcome_receipt(self.receiver_pred, generate_signer())
        self.payload = dsse.load_payload(self.env)
        self.content_root_hex = hashlib.sha256(self.payload).hexdigest()

    def _ref(self, digest_hex, artifact_hex=None):
        ref = {"relation": "receiverAck", "digest": {"sha256": digest_hex}}
        if artifact_hex is not None:
            ref["artifactDigest"] = {"sha256": artifact_hex}
        return ref

    def test_resign_receiver_statement_keeps_content_root(self):
        env2 = emit_outcome_receipt(self.receiver_pred, generate_signer())
        payload2 = dsse.load_payload(env2)
        self.assertEqual(payload2, self.payload)
        res = resolve_receiver_ref(self._ref(self.content_root_hex), receiver_payload=payload2)
        self.assertIs(res["content_root_ok"], True)

    def test_changed_receiver_content_breaks_content_root(self):
        import copy
        mutated = copy.deepcopy(self.receiver_pred)
        mutated["outcomeId"] = "different-outcome-id"
        payload_mut = dsse.load_payload(emit_outcome_receipt(mutated, generate_signer()))
        res = resolve_receiver_ref(self._ref(self.content_root_hex), receiver_payload=payload_mut)
        self.assertIs(res["content_root_ok"], False)

    def test_subject_only_change_breaks_content_root(self):
        from proofbundle.outcome import _rfc8785_bytes
        payload_alt = _rfc8785_bytes(build_outcome_statement(self.receiver_pred, subject_name="outcome:tampered"))
        res = resolve_receiver_ref(self._ref(self.content_root_hex), receiver_payload=payload_alt)
        self.assertIs(res["content_root_ok"], False)

    def test_artifact_digest_pins_exact_blob(self):
        blob = b"the stored receiver ack bytes"
        ref = self._ref(self.content_root_hex, artifact_hex=hashlib.sha256(blob).hexdigest())
        self.assertIs(resolve_receiver_ref(ref, artifact_bytes=blob)["artifact_ok"], True)
        self.assertIs(resolve_receiver_ref(ref, artifact_bytes=b"different blob")["artifact_ok"], False)


class TestVerifyOutcomeWithReceiverRefs(unittest.TestCase):
    def test_no_receiver_refs_stays_none_and_ok_unaffected(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_pred(), s)
        r = verify_outcome_receipt(env, pub)
        self.assertIsNone(r["receiver_bound"])
        self.assertIsNone(r["receiver_role_trusted"])
        self.assertIsNone(r["evidence_levels"]["receiverRefs"])
        self.assertTrue(r["ok"], r)

    def test_receiver_ref_without_resolver_reaches_reference_well_formed(self):
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub)
        self.assertTrue(r["receiver_bound"])
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertTrue(r["ok"], r)

    def test_receiver_ref_with_evidence_resolver_reaches_content_resolved(self):
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_receiver_ref_with_attestation_resolver_reaches_independently_attested(self):
        # A receiver DISTINCT from the executor (receiverKeyId "kid-recv" != executor "kid-exec") that a
        # resolver confirms is validly signed reaches INDEPENDENTLY_ATTESTED.
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG},
                                 "receiverKeyId": "kid-recv"}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"],
                         EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertTrue(r["ok"], r)

    def test_receiver_ref_that_is_the_executor_is_not_independent(self):
        # STRUCTURAL independence (crypto-review, 2026-07-15): a receiver whose receiverKeyId EQUALS the
        # executor's keyId is self-corroboration — the executor signing its own outcome and pointing a
        # receiverRefs entry at a second statement it also controls. Even a resolver that says "validly
        # signed" (lambda d: True) must NOT let this reach INDEPENDENTLY_ATTESTED. This is exactly the
        # No-Overclaim hole Finding 16 was meant to close.
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG},
                                 "receiverKeyId": "kid-exec"}])  # == executor keyId
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_receiver_ref_without_key_id_cannot_be_shown_independent(self):
        # Fail-closed: a receiverRefs entry with NO receiverKeyId cannot be shown DISTINCT from the executor,
        # so it is not promoted to INDEPENDENTLY_ATTESTED even with a permissive resolver (an absent key id
        # would otherwise be the trivial evasion of the self-corroboration guard above).
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_attestation_resolver_alone_without_content_resolved_does_not_fake_it(self):
        # THE adversarial/bidirectional guard: an attestation resolver returning True WITHOUT the digest
        # first reaching CONTENT_RESOLVED must NOT be silently promoted to INDEPENDENTLY_ATTESTED — that
        # would let a caller fake the strongest claim on an attacker-choosable, never-resolved digest.
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, receiver_attestation_resolver=lambda d: True)  # no evidence_resolver
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.REFERENCE_WELL_FORMED)

    def test_raising_attestation_resolver_fails_closed(self):
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}])
        env = emit_outcome_receipt(p, s)

        def _boom(_d):
            raise RuntimeError("boom")

        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=_boom)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_receiver_role_trusted_true_when_member(self):
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG},
                                 "receiverKeyId": "kid-recv"}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, trust_pack=_trust_pack(receiver_key_id="kid-recv"))
        self.assertTrue(r["receiver_role_trusted"])
        self.assertTrue(r["ok"], r)

    def test_receiver_role_trusted_false_but_ok_unaffected(self):
        # THE key design decision under test: receiverRefs is OPTIONAL supplementary evidence, so an
        # untrusted-labeled receiver must NOT break the outcome's own core verdict (unlike executor_role_trusted).
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG},
                                 "receiverKeyId": "kid-unknown"}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub, trust_pack=_trust_pack(receiver_key_id="kid-recv"))
        self.assertFalse(r["receiver_role_trusted"])
        self.assertTrue(r["ok"], r)   # deliberately NOT gated — see docstring

    def test_receiver_role_trusted_none_without_trust_pack(self):
        s, pub = _keys()
        p = _pred(receiverRefs=[{"relation": "receiverAck", "digest": {"sha256": _RECV_DIG}}])
        env = emit_outcome_receipt(p, s)
        r = verify_outcome_receipt(env, pub)
        self.assertIsNone(r["receiver_role_trusted"])


class TestDetectOutcomeSequenceGaps(unittest.TestCase):
    def _p(self, seq, executor_id="executor:1", run_id="run-1"):
        return _pred(executor={"id": executor_id}, sequence={"runId": run_id, "seq": seq})

    def test_no_gaps_reports_complete(self):
        preds = [self._p(0), self._p(1), self._p(2)]
        out = detect_outcome_sequence_gaps(preds)
        key = ("executor:1", "run-1")
        self.assertIn(key, out)
        self.assertEqual(out[key]["seqs"], [0, 1, 2])
        self.assertEqual(out[key]["gaps"], [])
        self.assertTrue(out[key]["complete"])

    def test_suppressed_middle_receipt_detected_as_gap(self):
        # the exact scenario Finding 16 targets: seq 1 (e.g. a "failed" outcome) was never emitted.
        preds = [self._p(0), self._p(2), self._p(3)]
        out = detect_outcome_sequence_gaps(preds)
        key = ("executor:1", "run-1")
        self.assertEqual(out[key]["gaps"], [1])
        self.assertFalse(out[key]["complete"])

    def test_groups_by_executor_and_run_id_separately(self):
        preds = [self._p(0, executor_id="e1", run_id="r1"), self._p(5, executor_id="e2", run_id="r1"),
                 self._p(0, executor_id="e1", run_id="r2")]
        out = detect_outcome_sequence_gaps(preds)
        self.assertEqual(set(out.keys()), {("e1", "r1"), ("e2", "r1"), ("e1", "r2")})

    def test_predicate_without_sequence_is_skipped_not_crashed(self):
        preds = [self._p(0), _pred(executor={"id": "executor:1"})]   # second has no `sequence` at all
        out = detect_outcome_sequence_gaps(preds)
        key = ("executor:1", "run-1")
        self.assertEqual(out[key]["seqs"], [0])   # the sequence-less predicate is invisible (honest limit)

    def test_malformed_predicates_never_crash(self):
        out = detect_outcome_sequence_gaps([None, "not-a-dict", 5, {}, {"executor": "bad"},
                                            {"executor": {"id": "e"}, "sequence": "bad"}])
        self.assertEqual(out, {})

    def test_duplicate_seq_deduplicated(self):
        preds = [self._p(0), self._p(0), self._p(1)]
        out = detect_outcome_sequence_gaps(preds)
        self.assertEqual(out[("executor:1", "run-1")]["seqs"], [0, 1])


if __name__ == "__main__":
    unittest.main()
