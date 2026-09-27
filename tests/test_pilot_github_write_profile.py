"""The pilot profile github-write/1 over decision-receipt/v0.1 and action-outcome/v0.1.

tools/pilot/github_write_profile.py fills and reads the two shipped predicates for the first pilot: the
outbound gate's verdict as a decision receipt, what an observer reads from the GitHub API as an outcome
bound to it. PROPERTY: a valid signature with the wrong issuer, a wrong subject, an expired approval or a
missing effect never reads as accepted; unknown and missing never become accepted; a receipt without the
profile's version signal is not read under it. The vectors hold positive and negative bytes for each rule;
they are regenerated here and must equal the committed file byte for byte.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_TOOL = REPO / "tools/pilot/github_write_profile.py"
_VECTORS = REPO / "tools/pilot/vectors.json"
_RFC8785 = importlib.util.find_spec("rfc8785") is not None


def _load():
    spec = importlib.util.spec_from_file_location("_github_write_profile", _TOOL)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


@unittest.skipUnless(_RFC8785, "the profile emits RFC 8785 canonical statements (the [eval] extra)")
class TheVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.g = _load()
        self.daten = json.loads(_VECTORS.read_text(encoding="utf-8"))

    def test_the_committed_vectors_are_what_the_generator_writes(self) -> None:
        neu = json.dumps(self.g.build_vectors(), indent=1, ensure_ascii=False) + "\n"
        self.assertEqual(neu, _VECTORS.read_text(encoding="utf-8"))

    def test_every_vector_reads_as_its_expected_answer(self) -> None:
        ergebnisse = self.g.check_vectors(self.daten)
        self.assertEqual(len(ergebnisse), 21)
        for name, erwartet, bekommen, gruende in ergebnisse:
            with self.subTest(case=name):
                self.assertEqual(bekommen, erwartet, gruende)

    def test_exactly_one_vector_is_accepted(self) -> None:
        angenommen = [f["case"] for f in self.daten["cases"] if f["expected"] == self.g.ACCEPTED]
        self.assertEqual(angenommen, ["approved and arrived as approved"])

    def test_the_named_classes_never_read_as_accepted(self) -> None:
        klassen = ("wrong issuer", "wrong subject", "expired approval", "missing effect")
        ergebnisse = {n: b for n, _, b, _ in self.g.check_vectors(self.daten)}
        for klasse in klassen:
            faelle = [n for n in ergebnisse if n.startswith(klasse)]
            with self.subTest(kind=klasse):
                self.assertTrue(faelle)
                for n in faelle:
                    self.assertNotEqual(ergebnisse[n], self.g.ACCEPTED, n)

    def test_unknown_and_missing_are_never_accepted(self) -> None:
        for name, erwartet, bekommen, _ in self.g.check_vectors(self.daten):
            if erwartet == self.g.UNKNOWN:
                with self.subTest(case=name):
                    self.assertEqual(bekommen, self.g.UNKNOWN)


@unittest.skipUnless(_RFC8785, "the profile emits RFC 8785 canonical statements (the [eval] extra)")
class TheOldFormatIsNotReinterpreted(unittest.TestCase):
    def setUp(self) -> None:
        self.g = _load()
        self.daten = json.loads(_VECTORS.read_text(encoding="utf-8"))

    def _reconcile(self, decision, outcome=None, scope=None) -> dict:
        d = self.daten
        return self.g.reconcile(decision, outcome, scope, gate_key=bytes.fromhex(d["gate_public_key"]),
                                gate_id=d["gate_id"], observer_key=bytes.fromhex(d["observer_public_key"]),
                                observer_id=d["observer_id"])

    def test_the_repositorys_own_decision_example_is_not_read_under_the_profile(self) -> None:
        beispiel = json.loads((REPO / "examples/decision_receipt_allow.json").read_text(encoding="utf-8"))
        umschlag = self.g.sign_decision(beispiel, self.g.test_key("gate"))
        antwort = self._reconcile(umschlag)
        self.assertEqual(antwort["verdict"], self.g.UNKNOWN)
        self.assertFalse(antwort["checks"]["version_signal"])

    def test_malformed_input_is_unknown_and_never_raises(self) -> None:
        kaputt = {"payload": base64.b64encode(b'{"predicate": {}}').decode(), "payloadType": "x", "signatures": []}
        for eingabe in (kaputt, {"payload": "!!"}, {}):
            with self.subTest(decision=str(eingabe)[:40]):
                self.assertEqual(self._reconcile(eingabe)["verdict"], self.g.UNKNOWN)


class TheProposalsNeedANewVersion(unittest.TestCase):
    """The profile adds no field. Each field it proposes is refused by the shipped v0.1 validators, which is
    why a proposal needs a new predicate version and cannot be slipped into v0.1."""

    @unittest.skipUnless(_RFC8785, "the profile emits RFC 8785 canonical statements (the [eval] extra)")
    def test_each_proposed_field_is_refused_by_v0_1(self) -> None:
        from proofbundle.decision import validate_decision_predicate
        from proofbundle.outcome import validate_outcome_predicate
        g = _load()
        d = g.decision_predicate(action_id="a", attempt=1, decided_at="2026-09-27T00:40:00Z",
                                 expires_at="2026-09-27T00:45:00Z", surface="github.conversationComment", target="t",
                                 approved=b"x", verdict="ALLOW", reasons=["r"], gate_id="g", agent_id="a",
                                 principal_id="p", policy_digest="0" * 64, nonce="n", audience="o")
        o = g.outcome_predicate(outcome_id="o", decision_root="0" * 64, executor_id="e", approved=b"x",
                                performed_at="2026-09-27T00:40:09Z", recorded_at="2026-09-27T00:41:00Z", stored=b"x",
                                scope=g.scope_descriptor("s", "t", "i"), nonce="n", audience="o")
        self.assertEqual(validate_decision_predicate(d, strict=True), [])
        self.assertEqual(validate_outcome_predicate(o, strict=True), [])
        self.assertTrue(validate_decision_predicate(dict(d, attempt=1), strict=True))
        self.assertTrue(validate_decision_predicate(
            dict(d, proposedAction=dict(d["proposedAction"], surface="x")), strict=True))
        self.assertTrue(validate_outcome_predicate(dict(o, observer={"id": "x"}), strict=True))
        self.assertTrue(validate_outcome_predicate(dict(o, outcomeScope={"surface": "s"}), strict=True))
        self.assertTrue(validate_outcome_predicate(dict(o, status="notObserved"), strict=True))


if __name__ == "__main__":
    unittest.main()
