"""relation/v0.1 lineage profile — fail-closed validation + chain verification.

Covers: structural validation (every field mutated singly — no false accept), the four
lineage states, self-reference/attached cycles vs. legitimate diamond DAGs, depth cap,
target-verification-failed (present-and-wrong beats absent), successor warning, and the
lattice-honesty guarantee that DECLARED_UNRESOLVED/NOT_EVALUATED never read as VERIFIED.
"""
import unittest

from proofbundle.relation import (
    LINEAGE_DECLARED_UNRESOLVED,
    LINEAGE_FAIL,
    LINEAGE_NOT_EVALUATED,
    LINEAGE_VERIFIED,
    MAX_CHAIN_DEPTH,
    MAX_EDGES_PER_RECEIPT,
    RELATIONS,
    RelationProfileError,
    require_valid_relationships,
    successor_warning,
    validate_relationships,
    verify_relationship_edges,
)

H_A = "a" * 64
H_B = "b" * 64
H_C = "c" * 64
H_D = "d" * 64


def edge(target_hex, relation="supersedes", **extra):
    e = {"relation": relation,
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}
    e.update(extra)
    return e


class TestValidateRelationships(unittest.TestCase):
    def test_valid_minimal_edge(self):
        self.assertEqual(validate_relationships([edge(H_B)]), [])

    def test_valid_full_edge(self):
        e = edge(H_B, relation="corrects",
                 targetSubjectDigest={"digestAlgorithm": "jcs-sha256-v1", "digest": H_C},
                 reason="fixed a scoring bug", reasonCode="correction",
                 declaredAt="2026-07-16T00:00:00Z")
        self.assertEqual(validate_relationships([e]), [])

    def test_every_relation_in_vocabulary_is_valid(self):
        for rel in RELATIONS:
            self.assertEqual(validate_relationships([edge(H_B, relation=rel)]), [], rel)

    def test_not_a_list(self):
        self.assertTrue(validate_relationships({"relation": "supersedes"}))
        self.assertTrue(validate_relationships("supersedes"))
        self.assertTrue(validate_relationships(None))

    def test_empty_array_rejected(self):
        self.assertTrue(validate_relationships([]))

    def test_edge_cap(self):
        edges = [edge(H_B) for _ in range(MAX_EDGES_PER_RECEIPT + 1)]
        self.assertTrue(any("hard cap" in e for e in validate_relationships(edges)))

    def test_unknown_edge_field_fail_closed(self):
        e = edge(H_B)
        e["sneaky"] = 1
        self.assertTrue(any("unknown field" in x for x in validate_relationships([e])))

    def test_unknown_relation_fail_closed(self):
        errs = validate_relationships([edge(H_B, relation="replaces")])
        self.assertTrue(any("closed vocabulary" in x for x in errs))

    def test_missing_required_fields(self):
        self.assertTrue(validate_relationships([{"relation": "supersedes"}]))
        self.assertTrue(validate_relationships(
            [{"targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": H_B}}]))

    def test_digest_algorithm_never_defaulted(self):
        e = {"relation": "supersedes", "targetReceiptDigest": {"digest": H_B}}
        errs = validate_relationships([e])
        self.assertTrue(any("digestAlgorithm is required" in x for x in errs))

    def test_unregistered_digest_algorithm(self):
        e = {"relation": "supersedes",
             "targetReceiptDigest": {"digestAlgorithm": "sha256", "digest": H_B}}
        self.assertTrue(validate_relationships([e]))

    def test_malformed_digest_hex(self):
        for bad in ("A" * 64, "a" * 63, "a" * 65, "zz", 7, None):
            e = {"relation": "supersedes",
                 "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": bad}}
            self.assertTrue(validate_relationships([e]), repr(bad))

    def test_digest_object_unknown_field(self):
        e = {"relation": "supersedes",
             "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": H_B, "x": 1}}
        self.assertTrue(validate_relationships([e]))

    def test_bad_reason_code(self):
        self.assertTrue(validate_relationships([edge(H_B, reasonCode="because")]))

    def test_bad_declared_at(self):
        for bad in ("2026-07-16", "2026-07-16T00:00:00+02:00", "gestern", 5):
            self.assertTrue(validate_relationships([edge(H_B, declaredAt=bad)]), repr(bad))

    def test_reason_must_be_string(self):
        self.assertTrue(validate_relationships([edge(H_B, reason=42)]))

    def test_require_valid_raises(self):
        with self.assertRaises(RelationProfileError):
            require_valid_relationships([{"relation": "nope"}])
        require_valid_relationships([edge(H_B)])  # must not raise


class TestVerifyRelationshipEdges(unittest.TestCase):
    def test_absent_profile_not_evaluated(self):
        res = verify_relationship_edges(None)
        self.assertEqual(res["lineage"], LINEAGE_NOT_EVALUATED)
        self.assertEqual(res["edges"], [])

    def test_declared_unresolved_is_not_an_error_and_not_a_pass(self):
        res = verify_relationship_edges([edge(H_B)], related={})
        self.assertEqual(res["lineage"], LINEAGE_DECLARED_UNRESOLVED)
        self.assertEqual(res["errors"], [])
        self.assertNotEqual(res["lineage"], LINEAGE_VERIFIED)

    def test_verified_when_target_attached_and_verified(self):
        res = verify_relationship_edges([edge(H_B)], related={H_B: {"verified": True}},
                                        subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_VERIFIED)

    def test_attached_but_unverified_target_is_hard_fail(self):
        res = verify_relationship_edges([edge(H_B)], related={H_B: {"verified": False}})
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("target_verification_failed" in e for e in res["errors"]))

    def test_verified_flag_must_be_exactly_true(self):
        for sneaky in (1, "true", "True", [1]):
            res = verify_relationship_edges([edge(H_B)], related={H_B: {"verified": sneaky}})
            self.assertEqual(res["lineage"], LINEAGE_FAIL, repr(sneaky))

    def test_malformed_block_is_fail(self):
        res = verify_relationship_edges([{"relation": "nope"}])
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(res["errors"])

    def test_fail_dominates_verified_and_unresolved(self):
        res = verify_relationship_edges(
            [edge(H_B), edge(H_C), edge(H_D)],
            related={H_B: {"verified": True}, H_D: {"verified": False}}, subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)

    def test_unresolved_dominates_verified(self):
        res = verify_relationship_edges(
            [edge(H_B), edge(H_C)], related={H_B: {"verified": True}}, subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_DECLARED_UNRESOLVED)

    def test_self_reference_is_cycle_fail(self):
        res = verify_relationship_edges([edge(H_A)], related={}, subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("cycle" in e for e in res["errors"]))

    def test_two_node_cycle_via_subject(self):
        # A -> B attached; B declares an edge back to A (the receipt under verification).
        res = verify_relationship_edges(
            [edge(H_B)],
            related={H_B: {"verified": True, "relationships": [edge(H_A)]}},
            subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("cycle" in e for e in res["errors"]))

    def test_attached_three_node_cycle(self):
        res = verify_relationship_edges(
            [edge(H_B)],
            related={
                H_B: {"verified": True, "relationships": [edge(H_C)]},
                H_C: {"verified": True, "relationships": [edge(H_B)]},
            },
            subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("cycle" in e for e in res["errors"]))

    def test_diamond_dag_is_legitimate_not_a_cycle(self):
        # A -> B, A -> C, B -> D, C -> D: same ancestor via two paths is lineage, no cycle.
        res = verify_relationship_edges(
            [edge(H_B), edge(H_C)],
            related={
                H_B: {"verified": True, "relationships": [edge(H_D, relation="derivedFrom")]},
                H_C: {"verified": True, "relationships": [edge(H_D, relation="derivedFrom")]},
                H_D: {"verified": True},
            },
            subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_VERIFIED)
        self.assertEqual(res["errors"], [])

    def test_depth_exceeded_stable_code(self):
        # Straight attached chain longer than the cap.
        hexes = [format(i, "064x") for i in range(1, MAX_CHAIN_DEPTH + 3)]
        related = {}
        for i, h in enumerate(hexes[:-1]):
            related[h] = {"verified": True, "relationships": [edge(hexes[i + 1])]}
        related[hexes[-1]] = {"verified": True}
        res = verify_relationship_edges([edge(hexes[0])], related=related, subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("depth_exceeded" in e for e in res["errors"]))

    def test_malformed_ancestor_block_fails(self):
        res = verify_relationship_edges(
            [edge(H_B)],
            related={H_B: {"verified": True, "relationships": [{"relation": "nope"}]}},
            subject_hex=H_A)
        self.assertEqual(res["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("malformed_ancestor" in e for e in res["errors"]))

    def test_never_raises_on_garbage(self):
        for garbage in (42, "x", {"a": 1}, [None], [[]], [{"relation": None}]):
            res = verify_relationship_edges(garbage)
            self.assertEqual(res["lineage"], LINEAGE_FAIL, repr(garbage))

    def test_attached_target_malformed_entry(self):
        res = verify_relationship_edges([edge(H_B)], related={H_B: "not-a-dict"})
        self.assertEqual(res["lineage"], LINEAGE_FAIL)


class TestSuccessorWarning(unittest.TestCase):
    def test_superseded_by_attached_fires(self):
        warn = successor_warning(None, related={
            H_B: {"verified": True, "relationships": [edge(H_A, relation="supersedes")]},
        }, subject_hex=H_A)
        self.assertIsNotNone(warn)
        self.assertIn("supersedes", warn)

    def test_no_warning_for_non_successor_relations(self):
        warn = successor_warning(None, related={
            H_B: {"verified": True, "relationships": [edge(H_A, relation="derivedFrom")]},
        }, subject_hex=H_A)
        self.assertIsNone(warn)

    def test_unverified_attacker_receipt_cannot_mark_superseded(self):
        warn = successor_warning(None, related={
            H_B: {"verified": False, "relationships": [edge(H_A, relation="supersedes")]},
        }, subject_hex=H_A)
        self.assertIsNone(warn)

    def test_no_subject_no_warning(self):
        self.assertIsNone(successor_warning(None, related={}, subject_hex=None))


if __name__ == "__main__":
    unittest.main()
