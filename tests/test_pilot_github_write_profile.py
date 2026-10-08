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
        self.assertEqual(len(ergebnisse), 40)
        for name, erwartet, bekommen, gruende in ergebnisse:
            with self.subTest(case=name):
                self.assertEqual(bekommen, erwartet, gruende)

    def test_the_accepted_vectors_are_the_ones_named(self) -> None:
        """The positive case, its twin a fraction of a second after the approval (Codex thread 4121766408), the
        time with ten fraction digits (4217993700), the inclusive boundary at both ends (4217993712), and the
        expiry with six fraction digits, the most its verifier reads (4218663063)."""
        angenommen = [f["case"] for f in self.daten["cases"] if f["expected"] == self.g.ACCEPTED]
        self.assertEqual(angenommen, ["approved and arrived as approved",
                                      "approved and arrived a fraction of a second after the approval",
                                      "approved and arrived, the time with ten fraction digits",
                                      "approved and arrived at the second the approval was made and expires",
                                      "approved and arrived, GitHub reporting the gate's id as the author",
                                      "approved and arrived, the expiry with six fraction digits"])

    def test_the_profile_promises_no_more_than_the_verifier_it_reuses_reads(self) -> None:
        """Codex thread 4218663063: the profile read any number of fraction digits, and the decision's verifier reads
        expiresAt with at most six, so a seven-digit expiry the profile called in window did not verify. The vector
        holds the boundary, with the verifier's reason, beside its six-digit control."""
        ergebnisse = {n: (b, g) for n, _, b, g in self.g.check_vectors(self.daten)}
        verdict, gruende = ergebnisse["approved and arrived, the expiry with seven fraction digits"]
        self.assertEqual(verdict, self.g.NOT_ACCEPTED)
        self.assertIn("expiresAt", " ".join(gruende))
        self.assertEqual(ergebnisse["approved and arrived, the expiry with six fraction digits"][0], self.g.ACCEPTED)

    def test_the_strict_fields_are_constraints_the_profile_states(self) -> None:
        """Codex thread 4219676762: the decision is verified in strict mode, which requires notChecked,
        decisionChangeConditions and privacy, and the profile called them recorded, not read. The profile states
        them as constraints, and a decision without one of them, signed by the gate, is not accepted."""
        g = self.g
        gate, observer = g.test_key("gate"), g.test_key("observer")
        args = dict(action_id="action-0001", attempt=1, decided_at="2026-09-27T00:40:00Z",
                    expires_at="2026-09-27T00:45:00Z", surface="github.conversationComment", target=g._TARGET,
                    approved=g._TEXT, verdict="ALLOW", reasons=["rules.satisfied"], gate_id=g.GATE_ID,
                    agent_id="agent:session-a", principal_id="operator",
                    policy_digest=g.sha256_hex(b"outbound gate rules, revision 1"), nonce="action-0001#1",
                    audience=g.OBSERVER_ID)
        scope = g.scope_descriptor("github.conversationComment", g._TARGET, "issuecomment-5851339484")

        def lies(praedikat):
            # signed outside strict mode: the generator's sign_decision refuses such a decision before signing
            dec = g.emit_decision_receipt(praedikat, gate, strict=False)
            out = g.sign_outcome(g.outcome_predicate(
                outcome_id="observation-0001", decision_root=g.content_root(dec), executor_id="github:b7n0de",
                approved=g._TEXT, performed_at="2026-09-27T00:40:09Z", recorded_at="2026-09-27T00:41:00Z",
                stored=g._TEXT, scope=scope, nonce="action-0001#1", audience=g.OBSERVER_ID), observer)
            return g.reconcile(dec, out, scope, gate_key=g._pub(gate), gate_id=g.GATE_ID,
                               observer_key=g._pub(observer), observer_id=g.OBSERVER_ID)
        self.assertEqual(lies(g.decision_predicate(**args))["verdict"], g.ACCEPTED, "control: the full decision")
        profil = " ".join((REPO / "docs/pilot/pilot_profile.md").read_text(encoding="utf-8").split())
        zeile = profil[profil.index("| strict mode |"):]
        zeile = zeile[:zeile.index(" | ", zeile.index("| none |") + 3)]
        for feld in ("notChecked", "decisionChangeConditions", "privacy"):
            with self.subTest(field=feld):
                praedikat = g.decision_predicate(**args)
                del praedikat[feld]
                antwort = lies(praedikat)
                self.assertEqual(antwort["verdict"], g.NOT_ACCEPTED)
                self.assertIn(f"missing required field '{feld}'", " ".join(antwort["reasons"]))
                self.assertIn(f"`{feld}`", zeile)
        self.assertIn("Strict mode requires `notChecked`, `decisionChangeConditions` and `privacy` to be present",
                      profil)

    def test_an_outcome_whose_subject_is_not_derived_is_not_accepted(self) -> None:
        """Codex thread 4220243730: the outcome is verified with require_derived_subject, and the profile stated the
        derivation only for the decision. It states it for both, and an observer-signed outcome with the right
        decisionRef and a subject not derived from its predicate is not accepted."""
        g = self.g
        d0 = next(f for f in self.daten["cases"] if f["case"] == "approved and arrived as approved")
        gate, observer = g.test_key("gate"), g.test_key("observer")
        self.assertEqual(g._pub(gate).hex(), self.daten["gate_public_key"], "control: the generator's gate key")
        praedikat = g._statement(d0["outcome"])["predicate"]
        for subjekt, erwartet in ((None, g.ACCEPTED), ("0" * 64, g.NOT_ACCEPTED)):
            out = g.emit_outcome_receipt(praedikat, observer, subject_sha256=subjekt)
            antwort = g.reconcile(d0["decision"], out, d0["observed_scope"], gate_key=g._pub(gate), gate_id=g.GATE_ID,
                                  observer_key=g._pub(observer), observer_id=g.OBSERVER_ID)
            with self.subTest(subject=subjekt):
                self.assertEqual(antwort["verdict"], erwartet, antwort["reasons"])

    def test_a_status_other_than_executed_is_not_accepted(self) -> None:
        """Codex thread 4217993684: failed, refused and partial, signed by the observer, read as unknown."""
        ergebnisse = {n: b for n, _, b, _ in self.g.check_vectors(self.daten)}
        faelle = [n for n in ergebnisse if n.startswith("the observer signed status")]
        self.assertEqual(len(faelle), 3)
        for n in faelle:
            with self.subTest(case=n):
                self.assertEqual(ergebnisse[n], self.g.NOT_ACCEPTED)

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
class EveryArgumentOfTheReusedVerifiersIsAProfileRule(unittest.TestCase):
    """Codex threads 4219676762 and 4220243730: an argument the profile passes to a reused verifier, beyond its
    default, narrows what verifies, and twice the profile did not say so. Every keyword of both calls is mapped to the
    words the profile states it with, in the column of its receipt; a keyword added later fails here until the profile
    names it."""

    _GESAGT = {
        "verify_decision_receipt": {"strict": "verified in strict mode", "expected_audience": "`validity.audience`",
                                    "expected_nonce": "`validity.nonce`",
                                    "require_derived_subject": "`require_derived_subject`",
                                    "now": "one second before its `decidedAt`"},
        "verify_outcome_receipt": {"strict": "verified in strict mode", "expected_decision_ref": "`decisionRef.sha256`",
                                   "expected_audience": "`validity.audience`", "expected_nonce": "`validity.nonce`",
                                   "require_derived_subject": "`require_derived_subject`"},
    }

    def test_each_keyword_of_both_calls_is_stated_in_its_column(self) -> None:
        import ast
        baum = ast.parse(_TOOL.read_text(encoding="utf-8"))
        aufrufe = {}
        for knoten in ast.walk(baum):
            if isinstance(knoten, ast.Call) and getattr(knoten.func, "id", None) in self._GESAGT:
                aufrufe.setdefault(knoten.func.id, []).append(sorted(k.arg for k in knoten.keywords))
        self.assertEqual(sorted(aufrufe), sorted(self._GESAGT), "control: both calls are found")
        zeilen = [z for z in (REPO / "docs/pilot/pilot_profile.md").read_text(encoding="utf-8").splitlines()
                  if z.startswith("| ") and not z.startswith("| aspect")]
        spalte = {"verify_decision_receipt": 2, "verify_outcome_receipt": 3}
        for name, liste in aufrufe.items():
            # A call with no keyword narrows nothing (the crypto-only check of thread 4220771559); every keyword of
            # every call is mapped, and the mapped ones are all passed somewhere.
            for schluessel in liste:
                with self.subTest(call=name):
                    self.assertLessEqual(set(schluessel), set(self._GESAGT[name]))
            self.assertEqual(set().union(*map(set, liste)), set(self._GESAGT[name]))
            text = " ".join(z.split("|")[spalte[name]] for z in zeilen if z.count("|") >= 5)
            alles = " ".join(zeilen)
            for schluessel, worte in self._GESAGT[name].items():
                with self.subTest(call=name, keyword=schluessel):
                    self.assertIn(worte, alles if schluessel == "now" else text)


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

    def test_a_deeply_nested_payload_is_an_answer_and_never_raises(self) -> None:
        """Codex thread 4121766439: JSON of 10,000 nested arrays raised RecursionError out of `_statement`. Signed by
        the gate key it reaches the reader and is unknown; unsigned it is not accepted, since the pinned key is checked
        first (thread 4220771559)."""
        from proofbundle import dsse
        roh = b"[" * 10000 + b"]" * 10000
        signiert = dsse.sign_envelope(roh, self.g.test_key("gate"), payload_type="application/vnd.in-toto+json")
        antwort = self._reconcile(signiert)
        self.assertEqual(antwort["verdict"], self.g.UNKNOWN)
        self.assertIn("RecursionError", antwort["reasons"][0])
        antwort = self._reconcile({"payload": base64.b64encode(roh).decode(), "payloadType": "x", "signatures": []})
        self.assertEqual(antwort["verdict"], self.g.NOT_ACCEPTED)
        self.assertIn("not signed by the pinned gate key", antwort["reasons"][0])

    def test_instants_are_compared_as_numbers(self) -> None:
        """Codex thread 4121766408: '.' sorts before 'Z', so the strings ordered 00:45:00.9Z before 00:45:00Z."""
        i = self.g.instant
        self.assertLess(i("2026-09-27T00:45:00Z"), i("2026-09-27T00:45:00.9Z"))
        self.assertLess(i("2026-09-27T00:45:00.09Z"), i("2026-09-27T00:45:00.1Z"))
        self.assertEqual(i("2026-09-27T00:45:00.50Z"), i("2026-09-27T00:45:00.5Z"))
        self.assertEqual(i("2026-09-27T00:45:00.000Z"), i("2026-09-27T00:45:00Z"))
        # Codex thread 4217993700: any number of fraction digits, as action-outcome/v0.1 takes them
        self.assertLess(i("2026-09-27T00:45:00Z"), i("2026-09-27T00:45:00.0000000001Z"))
        self.assertLess(i("2026-09-27T00:45:00.1Z"), i("2026-09-27T00:45:00.10001Z"))
        lang = "2026-09-27T00:45:00." + "1" * 5000
        self.assertLess(i(lang + "Z"), i(lang + "2Z"))
        for falsch in ("2026-09-27T00:45:00", "2026-13-01T00:00:00Z", "2026-09-27T00:45:00+00:00",
                       "\u0662\u0660\u0662\u0666-09-27T00:45:00Z", None, 5):
            with self.subTest(value=repr(falsch)):
                self.assertIsNone(i(falsch))

    def test_an_observed_scope_of_another_type_is_an_answer_and_never_raises(self) -> None:
        """Codex thread 4219220651: the digest of the observed scope was taken before its shape was checked, and the
        canonicalizer's refusal of a value that is no JSON escaped reconcile. The shape comes first now, and any
        exception of a reader is an answer at the boundary."""
        fall = next(f for f in self.daten["cases"] if f["case"] == "approved and arrived as approved")

        class Text(str):
            pass
        for wert in (object(), Text("issuecomment-1"), 5, None, float("nan")):
            scope = dict(fall["observed_scope"], objectId=wert)
            with self.subTest(objectId=repr(wert)[:30]):
                antwort = self._reconcile(fall["decision"], fall["outcome"], scope)
                self.assertEqual(antwort["verdict"], self.g.NOT_ACCEPTED, antwort["reasons"])
                self.assertIn("objectId", antwort["reasons"][0])

    def test_any_exception_of_a_reader_is_an_answer(self) -> None:
        fall = next(f for f in self.daten["cases"] if f["case"] == "approved and arrived as approved")

        class Fremd(Exception):
            pass

        def wirft(*args, **kwargs):
            raise Fremd("a reader's own refusal")
        alt = self.g._reconcile
        self.g._reconcile = wirft
        try:
            antwort = self._reconcile(fall["decision"], fall["outcome"], fall["observed_scope"])
        finally:
            self.g._reconcile = alt
        self.assertEqual(antwort["verdict"], self.g.UNKNOWN)
        self.assertIn("Fremd", antwort["reasons"][0])

    def test_malformed_input_is_an_answer_and_never_raises(self) -> None:
        """Input with nothing to check is unknown; a predicate the gate key did not sign is not accepted, since the
        pinned key is checked first (Codex thread 4220771559), and the same predicate signed by it is unknown."""
        from proofbundle import dsse
        roh = b'{"predicate": {}}'
        kaputt = {"payload": base64.b64encode(roh).decode(), "payloadType": "x", "signatures": []}
        signiert = dsse.sign_envelope(roh, self.g.test_key("gate"), payload_type="application/vnd.in-toto+json")
        for eingabe, erwartet in ((signiert, self.g.UNKNOWN), ({"payload": "!!"}, self.g.UNKNOWN), ({}, self.g.UNKNOWN),
                                  (kaputt, self.g.NOT_ACCEPTED)):
            with self.subTest(decision=str(eingabe)[:40]):
                self.assertEqual(self._reconcile(eingabe)["verdict"], erwartet)


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
