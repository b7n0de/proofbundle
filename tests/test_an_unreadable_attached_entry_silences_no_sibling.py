"""One unreadable attached entry silences no readable sibling (Codex review of PR 300, thread 4121924153, P1).

THE FINDING, measured before the fix at 2b389cc8, whose source is that of 3c5755c0 (the pushed head of
PR 300): `verify_relationship_edges` read the whole `related` map through one `_pruefkopie` call and,
when that refused the map, went on with an EMPTY map. One entry that is no JSON value
(`{"irrelevant": object()}`) therefore discarded every attached target beside it:

- a verified attachment that retracts the subject no longer set `supersededByAttached`, so
  `reject_superseded` raised no violation (the relation-statement surface then reported `policy_ok` True);
- a direct edge to an attached target that does not verify fell from FAIL to DECLARED_UNRESOLVED, so
  `lineage_ok` went from False to None and a decision receipt's `ok` from False to True;
- a direct edge to a verified target fell from VERIFIED to DECLARED_UNRESOLVED, so `reject_retracted`
  stopped blocking a verified relation statement.

THE CLASS: a container that feeds a verdict is read as a whole, and one entry that cannot be read discards
all of them. The rule held here: each attached entry is read on its own; an entry that cannot be read is
named (the `successor_warning` invariant, "an unreadable statement about this receipt is never silence")
and never promotes anything. The neighbour on the same verdict path, `evaluate_relations_policy`, read a
relations section that holds one unreadable value as ABSENT, so every rule of it was dropped (measured:
`verify_outcome_receipt` reported `policy_ok` True over an attached retraction); it is refused now,
fail-closed, as `evaluate_policy` and `evaluate_decision_policy` refuse such a policy.
"""
from __future__ import annotations

import base64
import json
import pathlib
import unittest

from proofbundle import anchors, dsse
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.relation import (
    CODE_LINEAGE_REQUIREMENT_FAILED,
    CODE_RELATION_MALFORMED_SUCCESSOR,
    LINEAGE_DECLARED_UNRESOLVED,
    LINEAGE_FAIL,
    LINEAGE_VERIFIED,
    evaluate_relations_policy,
    successor_warning,
    verify_relationship_edges,
)
from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BASE = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))

SUBJ = "a" * 64
NEIGHBOUR = "b" * 64
TARGET = "c" * 64


def _edge(target_hex: str, relation: str = "supersedes") -> dict:
    return {"relation": relation,
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}


class _NotAJsonValue:
    """A value no JSON document can hold."""


def _unreadable_siblings() -> dict:
    """label -> (key, value): entries of `related` that cannot be read as a JSON member, one per way."""
    return {
        "an object": ("irrelevant", _NotAJsonValue()),
        "a set": ("irrelevant", {1, 2}),
        "bytes": ("irrelevant", b"x"),
        "a target holding an object": ("d" * 64, {"verified": True, "extra": _NotAJsonValue()}),
        "a subclass of int": ("irrelevant", type("_Zahl", (int,), {})(5)),
        "a key that is not a string": (5, {"verified": True}),
    }


def _with(related: dict, key, value, *, first: bool) -> dict:
    """`related` with the entry (key, value) put before or after its own entries."""
    return {key: value, **related} if first else {**related, key: value}


RETRACTION = {"verified": True, "relationships": [_edge(SUBJ, "retracts")]}


class TheFindingAsMeasured(unittest.TestCase):
    """The reproduction of the thread: the same input with and without one unreadable sibling."""

    def test_a_readable_retraction_beside_an_unreadable_sibling_still_sets_superseded_by_attached(self):
        for label, (key, value) in _unreadable_siblings().items():
            for first in (True, False):
                with self.subTest(sibling=label, sibling_first=first):
                    related = _with({NEIGHBOUR: RETRACTION}, key, value, first=first)
                    lineage = verify_relationship_edges(None, related, subject_hex=SUBJ)
                    self.assertIn("retracted_by_attached", lineage["supersededByAttached"] or "")
                    self.assertIn("retracted_by_attached", successor_warning(None, related, subject_hex=SUBJ) or "")

    def test_reject_superseded_raises_its_violation_beside_an_unreadable_sibling(self):
        for label, (key, value) in _unreadable_siblings().items():
            with self.subTest(sibling=label):
                lineage = verify_relationship_edges(None, _with({NEIGHBOUR: RETRACTION}, key, value, first=False),
                                                    subject_hex=SUBJ)
                codes = [v["code"] for v in evaluate_relations_policy({"reject_superseded": True}, lineage,
                                                                      successor_key_b64=None)]
                self.assertEqual(codes, [CODE_LINEAGE_REQUIREMENT_FAILED])

    def test_control_without_the_sibling(self):
        lineage = verify_relationship_edges(None, {NEIGHBOUR: RETRACTION}, subject_hex=SUBJ)
        self.assertIn("retracted_by_attached", lineage["supersededByAttached"])


class ADirectEdgeResolvesBesideAnUnreadableSibling(unittest.TestCase):
    """The second path the finding names: direct-edge resolution read the same cleared map."""

    def test_an_attached_target_that_does_not_verify_stays_a_fail(self):
        for label, (key, value) in _unreadable_siblings().items():
            with self.subTest(sibling=label):
                res = verify_relationship_edges([_edge(TARGET)], _with({TARGET: {"verified": False}}, key, value,
                                                                       first=True), subject_hex=SUBJ)
                self.assertEqual(res["lineage"], LINEAGE_FAIL)
                self.assertTrue(any("target_verification_failed" in e for e in res["errors"]), res["errors"])

    def test_a_verified_attached_target_stays_verified(self):
        for label, (key, value) in _unreadable_siblings().items():
            with self.subTest(sibling=label):
                res = verify_relationship_edges([_edge(TARGET)], _with({TARGET: {"verified": True}}, key, value,
                                                                       first=True), subject_hex=SUBJ)
                self.assertEqual(res["lineage"], LINEAGE_VERIFIED, res["errors"])

    def test_an_ancestor_that_does_not_verify_stays_a_fail_at_the_second_hop(self):
        related = {TARGET: {"verified": True, "relationships": [_edge(NEIGHBOUR)]},
                   NEIGHBOUR: {"verified": False}, "irrelevant": _NotAJsonValue()}
        res = verify_relationship_edges([_edge(TARGET)], related, subject_hex=SUBJ)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("ancestor_verification_failed" in e for e in res["errors"]), res["errors"])

    def test_a_decision_receipt_whose_target_does_not_verify_is_not_ok(self):
        sk = generate_signer()
        env = emit_decision_receipt({**BASE, "decisionId": "d-succ", "relationships": [_edge(TARGET)]}, sk,
                                    strict=True)
        r = verify_decision_receipt(env, sk.public_key().public_bytes_raw(),
                                    related={TARGET: {"verified": False}, "irrelevant": _NotAJsonValue()})
        self.assertTrue(r["crypto_ok"])
        self.assertEqual(r["lineage"]["lineage"], LINEAGE_FAIL)
        self.assertIs(r["lineage_ok"], False)
        self.assertIs(r["ok"], False)


class TheRelationStatementSurface(unittest.TestCase):
    """The surface that reads `supersededByAttached` only from `verify_relationship_edges`, and whose
    `reject_retracted` gate reads the direct edge's resolution."""

    def setUp(self):
        self.sk = generate_signer()
        self.pub = self.sk.public_key().public_bytes_raw()
        target = emit_decision_receipt({**BASE, "decisionId": "d-target"}, self.sk, strict=True)
        self.root = anchors.statement_content_root(dsse.load_payload(target)).hex()
        self.env = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
                                            "relationships": [_edge(self.root, "retracts")]}, self.sk)
        self.statement_hex = anchors.statement_content_root(dsse.load_payload(self.env)).hex()
        self.key = base64.b64encode(self.pub).decode()

    def _attached(self, relationships=None) -> dict:
        return {"verified": True, "relationships": relationships, "verified_under": self.key,
                "subject_digest": None}

    def test_reject_retracted_blocks_beside_an_unreadable_sibling(self):
        for label, (key, value) in _unreadable_siblings().items():
            with self.subTest(sibling=label):
                related = _with({self.root: self._attached()}, key, value, first=True)
                r = verify_relation_statement(self.env, self.pub, related=related,
                                              policy={"relations": {"reject_retracted": True}})
                self.assertEqual(r["lineage"]["lineage"], LINEAGE_VERIFIED)
                self.assertIs(r["policy_ok"], False)
                self.assertIn(CODE_LINEAGE_REQUIREMENT_FAILED, r["relations_policy_codes"] or [])

    def test_reject_superseded_blocks_an_attached_successor_beside_an_unreadable_sibling(self):
        related = {self.root: self._attached([_edge(self.statement_hex, "supersedes")]),
                   "irrelevant": _NotAJsonValue()}
        r = verify_relation_statement(self.env, self.pub, related=related,
                                      policy={"relations": {"reject_superseded": True}})
        self.assertIn("superseded_by_attached", r["lineage"]["supersededByAttached"] or "")
        self.assertIs(r["policy_ok"], False)


class AnUnreadableEntryIsNamedAndPromotesNothing(unittest.TestCase):
    """The unreadable entry itself: named where it can hide a statement, never a reason to pass."""

    def test_alone_it_is_named_with_the_stable_code(self):
        for label, (key, value) in _unreadable_siblings().items():
            with self.subTest(entry=label):
                related = {key: value}
                for warning in (successor_warning(None, related, subject_hex=SUBJ),
                                verify_relationship_edges(None, related, subject_hex=SUBJ)["supersededByAttached"]):
                    self.assertIn("relation:malformed_successor", warning or "")
                    self.assertIn(CODE_RELATION_MALFORMED_SUCCESSOR, warning or "")

    def test_under_reject_superseded_it_is_a_violation(self):
        lineage = verify_relationship_edges(None, {"irrelevant": _NotAJsonValue()}, subject_hex=SUBJ)
        codes = [v["code"] for v in evaluate_relations_policy({"reject_superseded": True}, lineage,
                                                              successor_key_b64=None)]
        self.assertEqual(codes, [CODE_LINEAGE_REQUIREMENT_FAILED])

    def test_an_edge_that_names_it_fails_as_present_and_malformed(self):
        for label, value in (("an object", _NotAJsonValue()),
                             ("a target holding an object", {"verified": True, "extra": _NotAJsonValue()})):
            with self.subTest(entry=label):
                res = verify_relationship_edges([_edge(TARGET)], {TARGET: value}, subject_hex=SUBJ)
                self.assertEqual(res["lineage"], LINEAGE_FAIL)
                self.assertTrue(any("attached_target_malformed" in e for e in res["errors"]), res["errors"])

    def test_two_keys_with_the_same_characters_are_no_target_an_edge_can_resolve(self):
        class _Text(str):
            """Holds the same characters as another key; its own hash differs, so a dict stores both."""

            def __hash__(self):
                return 7

        related = {TARGET: {"verified": True}, _Text(TARGET): {"verified": True}}
        self.assertEqual(len(dict.keys(related)), 2, "precondition: the map stores two keys")
        # Since deep gate run 6 at fda55f98 (L4-620v6-T15-LIVE-RELATED-01) such a map does not reach the body:
        # its keys meet as one in the copy of the reading at the call, which refuses the call before the body
        # runs (`canonical._StandUnkopierbar`); until then it stayed the caller's object, read at body time. The
        # rule of the body for a map it is handed is still held by calling the engine on the reading's output.
        from proofbundle.canonical import _StandUnkopierbar  # noqa: PLC0415
        with self.assertRaises(_StandUnkopierbar):
            verify_relationship_edges([_edge(TARGET)], related, subject_hex=SUBJ)
        from proofbundle.relation import _kanten_urteil, _related_lesen  # noqa: PLC0415
        res = _kanten_urteil([_edge(TARGET)], _related_lesen(related), subject_hex=SUBJ)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("attached_target_malformed" in e for e in res["errors"]), res["errors"])

    def test_the_named_entry_does_not_depend_on_the_order_of_the_map(self):
        one, two = ("e" * 64, _NotAJsonValue()), ("f" * 64, {1, 2})
        forward = successor_warning(None, dict([one, two]), subject_hex=SUBJ)
        backward = successor_warning(None, dict([two, one]), subject_hex=SUBJ)
        self.assertEqual(forward, backward)

    def test_adding_an_unreadable_entry_never_makes_a_verdict_more_permissive(self):
        """Monotonicity over a small corpus: with one unreadable entry added, a FAIL stays a FAIL, a
        superseded receipt stays superseded, and a violation is never lost."""
        corpus = {
            "verified target": {TARGET: {"verified": True}},
            "unverified target": {TARGET: {"verified": False}},
            "retraction": {NEIGHBOUR: RETRACTION},
            "malformed successor": {NEIGHBOUR: {"verified": True, "relationships": [42]}},
            "payload malformed": {NEIGHBOUR: {"verified": False, "payload_malformed": "dup key"}},
            "empty": {},
        }
        rank = {LINEAGE_VERIFIED: 0, LINEAGE_DECLARED_UNRESOLVED: 1, LINEAGE_FAIL: 2}
        section = {"reject_superseded": True, "require_relation_resolution": ["supersedes"]}
        for label, related in corpus.items():
            for extra_label, (key, value) in _unreadable_siblings().items():
                with self.subTest(related=label, added=extra_label):
                    before = verify_relationship_edges([_edge(TARGET)], related, subject_hex=SUBJ)
                    after = verify_relationship_edges([_edge(TARGET)], _with(related, key, value, first=True),
                                                      subject_hex=SUBJ)
                    self.assertGreaterEqual(rank[after["lineage"]], rank[before["lineage"]])
                    if before["supersededByAttached"] is not None:
                        self.assertIsNotNone(after["supersededByAttached"])
                    v_before = evaluate_relations_policy(section, before, successor_key_b64=None)
                    v_after = evaluate_relations_policy(section, after, successor_key_b64=None)
                    self.assertGreaterEqual(len(v_after), len(v_before))


class ControlsThatStayAsTheyWere(unittest.TestCase):
    """What an unreadable entry is not: a readable entry keeps its old reading."""

    def test_a_readable_value_that_is_no_target_still_has_no_voice(self):
        for value in (5, "x", [1], None):
            with self.subTest(value=value):
                self.assertIsNone(successor_warning(None, {NEIGHBOUR: value}, subject_hex=SUBJ))

    def test_an_unverified_readable_neighbour_still_has_no_voice(self):
        self.assertIsNone(successor_warning(
            None, {NEIGHBOUR: {"verified": False, "relationships": [_edge(SUBJ, "retracts")]}}, subject_hex=SUBJ))

    def test_a_related_container_that_is_no_dict_is_refused(self):
        """Changed by the deep gate at 7409b123 (L4-620b-01): such a container held nothing here, and a Mapping
        that is no dict holding a verified retraction then hid it from reject_superseded. It is refused now:
        lineage FAIL, and a named warning that reject_superseded turns into its violation."""
        for bad in ([1, 2], "string", 5, {1, 2}, (1,), True, _NotAJsonValue()):
            with self.subTest(related=type(bad).__name__):
                self.assertIn("relation:related_malformed", successor_warning(None, bad, subject_hex=SUBJ) or "")
                res = verify_relationship_edges([_edge(TARGET)], bad, subject_hex=SUBJ)
                self.assertEqual(res["lineage"], LINEAGE_FAIL)
                self.assertIn("relation:related_malformed", res["supersededByAttached"] or "")
        self.assertEqual(verify_relationship_edges([_edge(TARGET)], None, subject_hex=SUBJ)["lineage"],
                         LINEAGE_DECLARED_UNRESOLVED)   # control: absent stays absent

    def test_no_method_of_the_callers_map_or_entry_runs(self):
        calls: list = []

        class _Recording(dict):
            def items(self):
                calls.append("items")
                return dict.items(self)

            def get(self, key, default=None):
                calls.append("get")
                return dict.get(self, key, default)

            def __iter__(self):
                calls.append("__iter__")
                return dict.__iter__(self)

            def __getitem__(self, key):
                calls.append("__getitem__")
                return dict.__getitem__(self, key)

        related = _Recording({NEIGHBOUR: _Recording(RETRACTION), "irrelevant": _NotAJsonValue()})
        lineage = verify_relationship_edges([_edge(TARGET)], related, subject_hex=SUBJ)
        warning = successor_warning(None, related, subject_hex=SUBJ)
        self.assertEqual(calls, [])
        self.assertIn("retracted_by_attached", lineage["supersededByAttached"])
        self.assertEqual(warning, lineage["supersededByAttached"])


class _SaysItIsEmpty(dict):
    """A map that stores entries and answers its own `__len__` and `__bool__` with empty."""

    def __len__(self):
        return 0

    def __bool__(self):
        return False


class _MustNotBeAsked(dict):
    """A map whose own `__len__` and `__bool__` must never run."""

    def __len__(self):
        raise AssertionError("the caller's __len__ ran")

    def __bool__(self):
        raise AssertionError("the caller's __bool__ ran")


class AMapThatSaysItIsEmptyHidesNothing(unittest.TestCase):
    """The decision and outcome verifiers asked the caller's map whether it held targets through its own
    `__bool__` (`if "relationships" in predicate or related`). Measured 2026-09-28 on main 86671552 and on
    D4 before this change: a `dict` subclass whose `__len__` is 0, holding a verified retraction of the
    subject, skipped the lineage block, `reject_superseded` never saw the retraction, and both verifiers
    answered `ok` True; the plain dict with the same entry answers `ok` False."""

    def setUp(self):
        self.sk = generate_signer()
        self.pub = self.sk.public_key().public_bytes_raw()

    @staticmethod
    def _retraction_of(root: str) -> dict:
        return {"verified": True, "relationships": [_edge(root, "retracts")]}

    def _emit_decision(self):
        env = emit_decision_receipt({**BASE, "decisionId": "d-says-empty"}, self.sk, strict=True)
        return env, anchors.statement_content_root(dsse.load_payload(env)).hex()

    def _emit_outcome(self):
        pred = {"schemaVersion": "0.1.0", "outcomeId": "o-says-empty", "decisionRef": {"sha256": "d" * 64},
                "executor": {"id": "ex"}, "requestedActionDigest": {"sha256": "e" * 64}, "status": "executed",
                "performedAt": "2026-09-28T00:00:00Z"}
        env = emit_outcome_receipt(pred, self.sk, strict=True)
        return env, anchors.statement_content_root(dsse.load_payload(env)).hex()

    def test_a_decision_retracted_by_an_attached_receipt_is_not_ok(self):
        env, root = self._emit_decision()
        for label, kind in (("plain dict", dict), ("says it is empty", _SaysItIsEmpty)):
            with self.subTest(related=label):
                r = verify_decision_receipt(env, self.pub, related=kind({NEIGHBOUR: self._retraction_of(root)}),
                                            policy={"relations": {"reject_superseded": True}})
                self.assertIn("retracted_by_attached", r["lineage"]["supersededByAttached"] or "")
                self.assertIs(r["policy_ok"], False)
                self.assertIs(r["ok"], False)

    def test_an_outcome_retracted_by_an_attached_receipt_is_not_ok(self):
        env, root = self._emit_outcome()
        for label, kind in (("plain dict", dict), ("says it is empty", _SaysItIsEmpty)):
            with self.subTest(related=label):
                r = verify_outcome_receipt(env, self.pub, related=kind({NEIGHBOUR: self._retraction_of(root)}),
                                           policy={"relations": {"reject_superseded": True}})
                self.assertIs(r["policy_ok"], False)
                self.assertIs(r["ok"], False)

    def test_the_callers_len_and_bool_never_run(self):
        env, root = self._emit_decision()
        r = verify_decision_receipt(env, self.pub, related=_MustNotBeAsked({NEIGHBOUR: self._retraction_of(root)}),
                                    policy={"relations": {"reject_superseded": True}})
        self.assertIs(r["ok"], False)
        env2, root2 = self._emit_outcome()
        r2 = verify_outcome_receipt(env2, self.pub, related=_MustNotBeAsked({NEIGHBOUR: self._retraction_of(root2)}),
                                    policy={"relations": {"reject_superseded": True}})
        self.assertIs(r2["ok"], False)

    def test_the_reader_counts_what_the_map_stores(self):
        from proofbundle.relation import _carries_attached_entries
        self.assertFalse(_carries_attached_entries({}))
        self.assertTrue(_carries_attached_entries({NEIGHBOUR: {}}))
        self.assertTrue(_carries_attached_entries(_SaysItIsEmpty({NEIGHBOUR: {}})))
        self.assertFalse(_carries_attached_entries(_SaysItIsEmpty()))
        self.assertTrue(_carries_attached_entries(_MustNotBeAsked({NEIGHBOUR: {}})))
        self.assertFalse(_carries_attached_entries(None))
        # A value that is neither None nor a dict counts as carrying, so the verifiers run the lineage step,
        # which refuses it (deep gate at 7409b123, L4-620b-01); it used to count as holding nothing.
        for no_map in ([1], "x", 5, (NEIGHBOUR,), []):
            with self.subTest(related=type(no_map).__name__):
                self.assertTrue(_carries_attached_entries(no_map))

    def test_control_an_empty_plain_map_still_adds_no_lineage(self):
        env, _root = self._emit_decision()
        self.assertIsNone(verify_decision_receipt(env, self.pub, related={})["lineage"])
        self.assertIsNotNone(verify_decision_receipt(env, self.pub, related={NEIGHBOUR: {"verified": False}})["lineage"])


class TheRelationsSectionIsNotReadAsAbsent(unittest.TestCase):
    """The neighbour on the same verdict path: `evaluate_relations_policy` read a relations section that
    holds one value that is no JSON value as absent, which dropped every rule it sets."""

    LINEAGE = {"edges": [], "supersededByAttached": "retracted_by_attached: attached receipt X"}

    def _codes(self, section):
        return [v["code"] for v in evaluate_relations_policy(section, self.LINEAGE, successor_key_b64=None)]

    def test_a_section_holding_an_unreadable_value_is_refused(self):
        for label, section in (
                ("an unknown key holding an object", {"reject_superseded": True, "x": _NotAJsonValue()}),
                ("a nested object", {"reject_superseded": True,
                                     "require_relation_target": {"supersedes": [_NotAJsonValue()]}}),
                ("a flag that is an object", {"reject_superseded": _NotAJsonValue()})):
            with self.subTest(section=label):
                violations = evaluate_relations_policy(section, self.LINEAGE, successor_key_b64=None)
                self.assertEqual([v["code"] for v in violations], [CODE_LINEAGE_REQUIREMENT_FAILED])
                self.assertIn("rejected before evaluation (fail-closed)", violations[0]["message"])

    def test_a_flag_that_is_no_bool_is_refused_with_the_loaders_message(self):
        violations = evaluate_relations_policy({"reject_superseded": _NotAJsonValue()}, self.LINEAGE,
                                               successor_key_b64=None)
        self.assertIn("relations.reject_superseded must be a boolean (true/false)", violations[0]["message"])

    def test_the_outcome_surface_does_not_report_policy_ok(self):
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        pred = {"schemaVersion": "0.1.0", "outcomeId": "o-unreadable-section", "decisionRef": {"sha256": "d" * 64},
                "executor": {"id": "ex"}, "requestedActionDigest": {"sha256": "e" * 64}, "status": "executed",
                "performedAt": "2026-09-28T00:00:00Z"}
        env = emit_outcome_receipt(pred, sk, strict=True)
        root = anchors.statement_content_root(dsse.load_payload(env)).hex()
        related = {NEIGHBOUR: {"verified": True, "relationships": [_edge(root, "retracts")]}}
        r = verify_outcome_receipt(env, pub, related=related,
                                   policy={"relations": {"reject_superseded": True, "x": _NotAJsonValue()}})
        self.assertIs(r["policy_ok"], False)
        self.assertIn(CODE_LINEAGE_REQUIREMENT_FAILED, r["relations_policy_codes"] or [])

    def test_a_section_that_is_no_dict_is_refused_and_none_is_absent(self):
        """Changed by the deep gate at 7409b123 (the sweep of L4-620b-01): a present section that is no dict read
        as absent here, and the outcome and relation statement verifiers then judged an attached retraction
        with no rule. None stays "no relations section"."""
        self.assertEqual(self._codes(None), [])
        for section in (5, "x", [1], _NotAJsonValue()):
            with self.subTest(section=type(section).__name__):
                self.assertEqual(self._codes(section), [CODE_LINEAGE_REQUIREMENT_FAILED])

    def test_control_a_readable_section_is_judged_as_before(self):
        self.assertEqual(self._codes({"reject_superseded": True}), [CODE_LINEAGE_REQUIREMENT_FAILED])
        self.assertEqual(self._codes({"reject_superseded": False}), [])


if __name__ == "__main__":
    unittest.main()
