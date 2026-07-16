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


class TestPredicateWiring(unittest.TestCase):
    """The relationships block rides INSIDE the signed predicates (decision/outcome) —
    valid edges pass predicate validation, malformed ones fail it (fail-closed)."""

    def _minimal_decision(self):
        # Mirrors the repo's golden example shape (validate-only fields).
        return {
            "schemaVersion": "0.1.0", "decisionId": "d-1",
            "decisionType": "preActionAuthorization", "decidedAt": "2026-07-16T00:00:00Z",
            "decisionMaker": {"id": "dm-1"}, "agent": {"id": "agent-1"},
            "principal": {"id": "p-1"},
            "proposedAction": {"actionType": "http.request", "parametersDigest": {"sha256": H_C}},
            "inputSnapshot": [],
            "policyBoundary": {"policyEngine": "opa", "policyId": "pol-1", "decisionPath": "allow/main"},
            "evidenceRefs": [], "decision": {"verdict": "ALLOW", "reasonCodes": ["OK"]},
        }

    def _minimal_outcome(self):
        return {
            "schemaVersion": "0.1.0", "outcomeId": "o-1",
            "decisionRef": {"sha256": H_B}, "executor": {"id": "ex-1"},
            "requestedActionDigest": {"sha256": H_C},
            "status": "executed", "performedAt": "2026-07-16T00:00:00Z",
        }

    def test_decision_predicate_accepts_valid_relationships(self):
        from proofbundle.decision import validate_decision_predicate
        pred = self._minimal_decision()
        pred["relationships"] = [edge(H_B, relation="corrects")]
        self.assertEqual(validate_decision_predicate(pred), [])

    def test_decision_predicate_rejects_malformed_relationships(self):
        from proofbundle.decision import validate_decision_predicate
        pred = self._minimal_decision()
        pred["relationships"] = [{"relation": "replaces"}]
        errs = validate_decision_predicate(pred)
        self.assertTrue(any("relationships" in e for e in errs))

    def test_outcome_predicate_accepts_valid_relationships(self):
        from proofbundle.outcome import validate_outcome_predicate
        pred = self._minimal_outcome()
        pred["relationships"] = [edge(H_D, relation="supersedes")]
        self.assertEqual(validate_outcome_predicate(pred), [])

    def test_outcome_predicate_rejects_malformed_relationships(self):
        from proofbundle.outcome import validate_outcome_predicate
        pred = self._minimal_outcome()
        pred["relationships"] = [edge(H_D, relation="supersedes", sneaky=1)]
        errs = validate_outcome_predicate(pred)
        self.assertTrue(any("relationships" in e for e in errs))

    def test_absent_relationships_changes_nothing(self):
        from proofbundle.decision import validate_decision_predicate
        from proofbundle.outcome import validate_outcome_predicate
        self.assertEqual(validate_decision_predicate(self._minimal_decision()), [])
        self.assertEqual(validate_outcome_predicate(self._minimal_outcome()), [])


class TestVerifyLevelLineage(unittest.TestCase):
    """End-to-end over REAL DSSE-signed decision receipts: lineage is additive, computed only
    over authenticated bytes, and NEVER flips the crypto verdict (lattice monotonicity)."""

    def _signed_decision(self, relationships=None):
        import json
        from pathlib import Path
        from proofbundle.decision import emit_decision_receipt
        from proofbundle.emit import generate_signer
        examples = Path(__file__).resolve().parent.parent / "examples"
        pred = json.loads((examples / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        if relationships is not None:
            pred["relationships"] = relationships
        signer = generate_signer()
        env = emit_decision_receipt(pred, signer, strict=True)
        return env, signer.public_key().public_bytes_raw()

    def test_no_relationships_lineage_stays_none(self):
        from proofbundle.decision import verify_decision_receipt
        env, pub = self._signed_decision()
        r = verify_decision_receipt(env, pub)
        self.assertTrue(r["crypto_ok"])
        self.assertIsNone(r["lineage"])

    def test_declared_unresolved_over_signed_bytes(self):
        from proofbundle.decision import verify_decision_receipt
        env, pub = self._signed_decision([edge(H_B, relation="corrects")])
        r = verify_decision_receipt(env, pub)
        self.assertTrue(r["crypto_ok"])
        self.assertEqual(r["lineage"]["lineage"], LINEAGE_DECLARED_UNRESOLVED)
        self.assertEqual(r["errors"], [])

    def test_verified_with_attached_target(self):
        from proofbundle.decision import verify_decision_receipt
        env, pub = self._signed_decision([edge(H_B, relation="supersedes")])
        r = verify_decision_receipt(env, pub, related={H_B: {"verified": True}})
        self.assertTrue(r["crypto_ok"])
        self.assertEqual(r["lineage"]["lineage"], LINEAGE_VERIFIED)

    def test_lineage_fail_never_flips_crypto(self):
        # The MONOTONICITY guarantee: an attached-but-unverified target FAILs lineage and
        # surfaces in errors[], but cryptoValid stays True — lineage never upgrades OR
        # downgrades the crypto verdict.
        from proofbundle.decision import verify_decision_receipt
        env, pub = self._signed_decision([edge(H_B, relation="supersedes")])
        r = verify_decision_receipt(env, pub, related={H_B: {"verified": False}})
        self.assertTrue(r["crypto_ok"])
        self.assertEqual(r["lineage"]["lineage"], LINEAGE_FAIL)
        self.assertTrue(any("target_verification_failed" in e for e in r["errors"]))

    def test_forged_envelope_never_computes_lineage(self):
        # Trust-derived fields stay None on unauthenticated bytes — including lineage.
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.emit import generate_signer
        env, _ = self._signed_decision([edge(H_B)])
        wrong_pub = generate_signer().public_key().public_bytes_raw()
        r = verify_decision_receipt(env, wrong_pub, related={H_B: {"verified": True}})
        self.assertFalse(r["crypto_ok"])
        self.assertIsNone(r["lineage"])


class TestCLIWithRelated(unittest.TestCase):
    """CLI e2e: decision verify --with-related resolves lineage offline; the JSON report
    carries the lineage field (no silent field drop)."""

    def _write_signed(self, tmpdir, name, pred_patch=None, signer=None):
        import json
        from pathlib import Path
        from proofbundle.decision import emit_decision_receipt
        from proofbundle.emit import generate_signer
        examples = Path(__file__).resolve().parent.parent / "examples"
        pred = json.loads((examples / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        if pred_patch:
            pred.update(pred_patch)
        signer = signer or generate_signer()
        env = emit_decision_receipt(pred, signer, strict=True)
        p = tmpdir / name
        p.write_text(json.dumps(env), encoding="utf-8")
        return p, env, signer

    def _content_root_hex(self, env):
        from proofbundle import anchors, dsse
        return anchors.statement_content_root(dsse.load_payload(env)).hex()

    def test_cli_with_related_verified_lineage_in_json(self):
        import base64
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path
        from proofbundle import cli
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # Vorgänger B (gleicher Signer, same-key-Vertrag), dann Nachfolger A mit Kante auf B.
            b_path, b_env, signer = self._write_signed(tmp, "b.json")
            b_root = self._content_root_hex(b_env)
            a_path, a_env, _ = self._write_signed(
                tmp, "a.json",
                pred_patch={"relationships": [edge(b_root, relation="supersedes")],
                            "decisionId": "d-successor"},
                signer=signer)
            pub = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(["decision", "verify", str(a_path), "--pub", pub,
                               "--with-related", str(b_path), "--json"])
            report = json.loads(buf.getvalue())
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertEqual(report["lineage"]["lineage"], LINEAGE_VERIFIED)

    def test_cli_unreadable_related_is_usage_error(self):
        import base64
        import tempfile
        from pathlib import Path
        from proofbundle import cli
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            a_path, _, signer = self._write_signed(tmp, "a.json")
            pub = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
            rc = cli.main(["decision", "verify", str(a_path), "--pub", pub,
                           "--with-related", str(tmp / "missing.json")])
            self.assertEqual(rc, 2)


class TestRelationsPolicyGate(unittest.TestCase):
    """Trust-policy relations section (v0.2): require_relation_resolution + reject_superseded
    are enforced on the decision verify path — a violation fails policy_ok and raises the
    dedicated LINEAGE_REQUIREMENT_FAILED automation blocker; crypto stays untouched."""

    def _policy(self, **relations):
        return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "rel-test",
                "relations": relations}

    def _signed(self, relationships=None):
        import json
        from pathlib import Path
        from proofbundle.decision import emit_decision_receipt
        from proofbundle.emit import generate_signer
        examples = Path(__file__).resolve().parent.parent / "examples"
        pred = json.loads((examples / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        if relationships is not None:
            pred["relationships"] = relationships
        signer = generate_signer()
        return emit_decision_receipt(pred, signer, strict=True), signer

    def test_unresolved_required_relation_fails_policy_with_named_blocker(self):
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.policy import load_policy
        env, signer = self._signed([edge(H_B, relation="retracts")])
        pol = load_policy(self._policy(require_relation_resolution=["retracts"]))
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), policy=pol)
        self.assertTrue(r["crypto_ok"])                      # crypto NIE beruehrt
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("LINEAGE_REQUIREMENT_FAILED" in e for e in r["errors"]))
        self.assertIn("LINEAGE_REQUIREMENT_FAILED", r["automation"]["automationBlockers"])
        self.assertFalse(r["automation"]["safeForAutomation"])

    def test_resolved_required_relation_is_silent(self):
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.policy import load_policy
        env, signer = self._signed([edge(H_B, relation="retracts")])
        pol = load_policy(self._policy(require_relation_resolution=["retracts"]))
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), policy=pol,
                                    related={H_B: {"verified": True}})
        self.assertTrue(r["crypto_ok"])
        self.assertFalse(any("LINEAGE_REQUIREMENT_FAILED" in e for e in r["errors"]))
        self.assertNotIn("LINEAGE_REQUIREMENT_FAILED",
                         (r["automation"] or {}).get("automationBlockers", []))

    def test_absent_named_relation_is_no_violation(self):
        # require_relation_resolution ist konditional auf PRAESENZ der Kante.
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.policy import load_policy
        env, signer = self._signed(None)
        pol = load_policy(self._policy(require_relation_resolution=["retracts"]))
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), policy=pol)
        self.assertFalse(any("LINEAGE_REQUIREMENT_FAILED" in e for e in r["errors"]))

    def test_reject_superseded_blocks(self):
        from proofbundle import anchors, dsse
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.policy import load_policy
        env, signer = self._signed(None)
        subject_hex = anchors.statement_content_root(dsse.load_payload(env)).hex()
        pol = load_policy(self._policy(reject_superseded=True))
        related = {H_C: {"verified": True,
                         "relationships": [edge(subject_hex, relation="supersedes")]}}
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), policy=pol,
                                    related=related)
        self.assertTrue(r["crypto_ok"])
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("reject_superseded" in e for e in r["errors"]))
        self.assertIn("LINEAGE_REQUIREMENT_FAILED", r["automation"]["automationBlockers"])

    def test_superseded_without_policy_is_only_a_warning(self):
        from proofbundle import anchors, dsse
        from proofbundle.decision import verify_decision_receipt
        env, signer = self._signed(None)
        subject_hex = anchors.statement_content_root(dsse.load_payload(env)).hex()
        related = {H_C: {"verified": True,
                         "relationships": [edge(subject_hex, relation="supersedes")]}}
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw(), related=related)
        self.assertTrue(any("superseded_by_attached" in w for w in r["warnings"]))
        self.assertIsNot(r["policy_ok"], False)

    def test_explain_lists_relations_pins(self):
        from proofbundle.policy import explain_policy, load_policy
        pol = load_policy(self._policy(require_relation_resolution=["retracts", "supersedes"],
                                       reject_superseded=True))
        lines = " | ".join(explain_policy(pol))
        self.assertIn("retracts", lines)
        self.assertIn("superseded", lines)
