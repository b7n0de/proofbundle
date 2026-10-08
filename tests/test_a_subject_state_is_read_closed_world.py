"""A subject_digest_state outside the four words of the resolver is malformed, never present.

SOURCE. The deep gate of the 6.2.0 release preparation at d97de8e5 (pull request 311), lens L4, RT-01
(PB-2026-0717-01). `relation._target_subject_pin_error` failed only the exact lowercase words
"ambiguous", "absent" and "malformed", and read every other explicit state as "present". An attached
target labelled "AMBIGUOUS", "multiple" or ["ambiguous"], with subject_digest set to its first subject,
bound a declared targetSubjectDigest to subject[0]: lineage VERIFIED and ok True at the decision, outcome
and relation statement verifiers, where "ambiguous" gives FAIL. The Rust verifier derives the state from
the target's payload itself (`target_subject_pin_error` in tools/pb_verify_rs/src/main.rs) and reads none
from a caller, so no label it never writes can reach it.

THE CLASS. A field with a closed vocabulary was read open-world, so an unknown value took the permissive
branch. The rule now sends every explicit value but the four words to the refusal; a missing state is
still inferred from the digest, as before.
"""
from __future__ import annotations

import base64
import unittest

from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement
from proofbundle.relation import (
    CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS,
    CODE_RELATION_TARGET_SUBJECT_MALFORMED,
    CODE_RELATION_TARGET_SUBJECT_MISMATCH,
    CODE_RELATION_TARGET_SUBJECT_MISSING,
    LINEAGE_FAIL,
    LINEAGE_VERIFIED,
    verify_relationship_edges,
)

_ZIEL = "a" * 64
_PIN = "c" * 64
_ANDERS = "d" * 64

class _SagtPresent(str):
    """A str subclass that answers "present" to every comparison, whatever it stores."""

    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


#: Values of subject_digest_state that no resolver of this package writes. Each is read as malformed.
#: The last group are look-alikes of "present" and two modes of `subject_binding.SUBJECT_MODES`; the
#: jury measured the third mode, "AMBIGUOUS" in upper case, as enough on its own.
_FREMDE_ZUSTAENDE = ("AMBIGUOUS", "Ambiguous", "multiple", "ambiguous ", " present", "PRESENT",
                     "ABSENT", "missing", "MALFORMED", "unknown", "", ["ambiguous"], ["present"],
                     {"present": True}, 0, 1, True, False, 1.0,
                     "present\u200b", "\uff50resent",
                     "DERIVED", "EXTERNAL_ATTESTED")


def _kante(declared: str | None = _PIN) -> dict:
    e = {"relation": "supersedes",
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": _ZIEL}}
    if declared is not None:
        e["targetSubjectDigest"] = {"digestAlgorithm": "jcs-sha256-v1", "digest": declared}
    return e


def _ziel(state, subject_digest: str | None = _PIN) -> dict:
    return {"verified": True, "relationships": None, "verified_under": "k",
            "subject_digest": subject_digest, "subject_digest_state": state}


def _motor(state, subject_digest: str | None = _PIN) -> dict:
    return verify_relationship_edges([_kante()], {_ZIEL: _ziel(state, subject_digest)}, subject_hex="f" * 64)


class TheEngineReadsTheStateClosedWorld(unittest.TestCase):

    def test_a_state_no_resolver_writes_is_malformed(self) -> None:
        for state in _FREMDE_ZUSTAENDE:
            with self.subTest(state=repr(state)):
                r = _motor(state)
                self.assertEqual(r["lineage"], LINEAGE_FAIL, "an unknown state was read as present")
                self.assertIn(CODE_RELATION_TARGET_SUBJECT_MALFORMED, " ".join(r["errors"]))

    def test_control_the_four_words_keep_their_verdicts(self) -> None:
        self.assertEqual(_motor("present")["lineage"], LINEAGE_VERIFIED)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MISMATCH, " ".join(_motor("present", _ANDERS)["errors"]))
        for state, code in (("ambiguous", CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS),
                            ("absent", CODE_RELATION_TARGET_SUBJECT_MISSING),
                            ("malformed", CODE_RELATION_TARGET_SUBJECT_MALFORMED)):
            with self.subTest(state=state):
                r = _motor(state)
                self.assertEqual(r["lineage"], LINEAGE_FAIL)
                self.assertIn(code, " ".join(r["errors"]))

    def test_control_a_missing_state_is_still_inferred(self) -> None:
        ziel = _ziel(None)
        del ziel["subject_digest_state"]
        r = verify_relationship_edges([_kante()], {_ZIEL: ziel}, subject_hex="f" * 64)
        self.assertEqual(r["lineage"], LINEAGE_VERIFIED)
        ziel["subject_digest"] = None
        r = verify_relationship_edges([_kante()], {_ZIEL: ziel}, subject_hex="f" * 64)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MISSING, " ".join(r["errors"]))

    def test_control_an_edge_without_a_pin_ignores_the_state(self) -> None:
        for state in ("AMBIGUOUS", ["x"], True):
            with self.subTest(state=repr(state)):
                r = verify_relationship_edges([_kante(declared=None)], {_ZIEL: _ziel(state)}, subject_hex="f" * 64)
                self.assertEqual(r["lineage"], LINEAGE_VERIFIED)


_WEITER = "b" * 64


def _ueber_einen_hop(state) -> dict:
    """The receipt's own edge carries no pin; the attached target's edge pins its own target."""
    zwischen = {"verified": True, "verified_under": "k", "subject_digest": None,
                "subject_digest_state": "absent",
                "relationships": [{"relation": "supersedes",
                                   "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": _WEITER},
                                   "targetSubjectDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": _PIN}}]}
    return verify_relationship_edges([_kante(declared=None)], {_ZIEL: zwischen, _WEITER: _ziel(state)},
                                     subject_hex="f" * 64)


class TheSameRuleHoldsAtEveryHop(unittest.TestCase):
    """The hop path (relation.py, the pin check inside the ancestor walk) is a member of its own."""

    def test_a_state_no_resolver_writes_fails_one_hop_out(self) -> None:
        for state in _FREMDE_ZUSTAENDE:
            with self.subTest(state=repr(state)):
                r = _ueber_einen_hop(state)
                self.assertEqual(r["lineage"], LINEAGE_FAIL, "an unknown state was read as present at a hop")
                self.assertIn(CODE_RELATION_TARGET_SUBJECT_MALFORMED, " ".join(r["errors"]))

    def test_control_present_verifies_and_ambiguous_fails_at_the_hop(self) -> None:
        self.assertEqual(_ueber_einen_hop("present")["lineage"], LINEAGE_VERIFIED)
        r = _ueber_einen_hop("ambiguous")
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS, " ".join(r["errors"]))


def _schluessel() -> tuple:
    signer = generate_signer()
    pub = signer.public_key().public_bytes_raw()
    return signer, pub, base64.b64encode(pub).decode("ascii")


def _mit_schluessel(state, key_b64: str) -> dict:
    ziel = _ziel(state)
    ziel["verified_under"] = key_b64
    return ziel


class TheOutcomeAndRelationStatementVerifiersDoNotBindSubjectZero(unittest.TestCase):
    """The other two receipt verifiers that take `related=`, with the same state corpus."""

    def _pruefe(self, lauf) -> None:
        self.assertEqual((lauf("present").get("lineage") or {}).get("lineage"), LINEAGE_VERIFIED)   # control
        self.assertEqual((lauf("ambiguous").get("lineage") or {}).get("lineage"), LINEAGE_FAIL)   # control
        for state in _FREMDE_ZUSTAENDE:
            with self.subTest(state=repr(state)):
                r = lauf(state)
                self.assertEqual((r.get("lineage") or {}).get("lineage"), LINEAGE_FAIL)
                self.assertIs(r["ok"], False)

    def test_outcome_verifier(self) -> None:
        signer, pub, key_b64 = _schluessel()
        pred = {"schemaVersion": "0.1.0", "outcomeId": "o1", "decisionRef": {"sha256": "e" * 64},
                "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "1" * 64},
                "status": "executed", "performedAt": "2026-09-29T00:00:00Z", "effectDigest": {"sha256": "2" * 64},
                "relationships": [_kante()]}
        umschlag = emit_outcome_receipt(pred, signer)
        self._pruefe(lambda state: verify_outcome_receipt(umschlag, pub,
                                                          related={_ZIEL: _mit_schluessel(state, key_b64)}))

    def test_relation_statement_verifier(self) -> None:
        signer, pub, key_b64 = _schluessel()
        kante = _kante()
        kante.update({"relation": "retracts", "reasonCode": "withdrawal", "reason": "x",
                      "declaredAt": "2026-09-29T00:00:00Z"})
        pred = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:closed-world", "relationships": [kante]}
        umschlag = emit_relation_statement(pred, signer)
        self._pruefe(lambda state: verify_relation_statement(umschlag, pub,
                                                             related={_ZIEL: _mit_schluessel(state, key_b64)}))


class AStrSubclassIsReadByWhatItStores(unittest.TestCase):
    """Each argument is read once, by what it stores (pull request 312), so a str subclass is its stored text.

    A subclass that answers "present" to every comparison but stores "ambiguous" is the ambiguous state
    and fails. One that stores "present" is present, whatever it answers. Neither reaches the verdict
    through its own comparison.
    """

    def test_a_subclass_storing_ambiguous_fails_at_the_edge_and_at_the_hop(self) -> None:
        for lauf in (_motor, _ueber_einen_hop):
            with self.subTest(pfad=lauf.__name__):
                r = lauf(_SagtPresent("ambiguous"))
                self.assertEqual(r["lineage"], LINEAGE_FAIL)
                self.assertIn(CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS, " ".join(r["errors"]))

    def test_control_a_subclass_storing_present_is_present(self) -> None:
        for lauf in (_motor, _ueber_einen_hop):
            with self.subTest(pfad=lauf.__name__):
                self.assertEqual(lauf(_SagtPresent("present"))["lineage"], LINEAGE_VERIFIED)


class TheDecisionVerifierDoesNotBindSubjectZero(unittest.TestCase):

    def test_an_unknown_state_gives_no_verified_lineage(self) -> None:
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        pred = {
            "schemaVersion": "0.1.0", "decisionId": "urn:uuid:closed-world", "decisionType": "preActionAuthorization",
            "decidedAt": "2026-09-29T00:00:00Z", "decisionMaker": {"id": "dm"}, "agent": {"id": "a"},
            "principal": {"id": "p"},
            "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
            "inputSnapshot": [],
            "policyBoundary": {"policyEngine": "opa", "policyId": "p", "policyDigest": {"sha256": "0" * 64},
                               "decisionPath": "data.allow"},
            "evidenceRefs": [], "decision": {"verdict": "ALLOW", "reasonCodes": ["OK"]},
            "relationships": [_kante()],
        }
        umschlag = emit_decision_receipt(pred, signer, strict=False)
        key_b64 = base64.b64encode(pub).decode("ascii")

        def lauf(state):
            ziel = _ziel(state)
            ziel["verified_under"] = key_b64
            return verify_decision_receipt(umschlag, pub, related={_ZIEL: ziel})

        kontrolle = lauf("present")
        self.assertEqual((kontrolle.get("lineage") or {}).get("lineage"), LINEAGE_VERIFIED)   # control
        self.assertEqual((lauf("ambiguous").get("lineage") or {}).get("lineage"), LINEAGE_FAIL)   # control
        for state in ("AMBIGUOUS", "multiple", ["ambiguous"], True):
            with self.subTest(state=repr(state)):
                r = lauf(state)
                self.assertEqual((r.get("lineage") or {}).get("lineage"), LINEAGE_FAIL)
                self.assertIs(r["ok"], False)


if __name__ == "__main__":
    unittest.main()
