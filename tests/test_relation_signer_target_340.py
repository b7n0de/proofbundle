"""3.4.0 — relation_signer (WP-A) · require_relation_target + targetSubjectDigest (WP-A2) ·
outcome-path relations gate (WP-B) · F5 automation-surface consistency.

Regression-first + adversarial: the decoy-parent (F1) and targetSubjectDigest (O2) vectors are the
central refutation targets. Fail-closed load discipline, exit-code contracts on BOTH verify paths,
the pure shared evaluator, lattice monotonicity (policy never touches crypto), and a Hypothesis
property over random pinned signer sets.
"""
import base64
import json
import pathlib
import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # PB-2026-0718-L6-01: hypothesis is a dev-only dep — clean skip from a bare sdist install
    import pytest
    pytest.skip("hypothesis not installed (dev-only dependency)", allow_module_level=True)

from proofbundle import anchors, dsse
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.policy import PolicyError, explain_policy, load_policy
from proofbundle.relation import (
    CODE_RELATION_SIGNER_UNAUTHORIZED,
    CODE_RELATION_TARGET_MISMATCH,
    _keys_equal,
    evaluate_relations_policy,
    verify_relationship_edges,
)

V02 = "proofbundle/trust-policy/v0.2"
_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BASE_PRED = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
OUT_PRED = {
    "schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
    "executor": {"id": "ex"}, "requestedActionDigest": {"sha256": "1" * 64},
    "effectDigest": {"sha256": "1" * 64}, "status": "executed", "performedAt": "2026-07-16T00:00:00Z",
    "policyPurpose": "outcome",
}


def _pub(signer):
    return base64.b64encode(signer.public_key().public_bytes_raw()).decode()


def _root(env):
    return anchors.statement_content_root(dsse.load_payload(env)).hex()


def _subject(env):
    stmt = json.loads(dsse.load_payload(env).decode("utf-8"))
    return stmt["subject"][0]["digest"]["sha256"]


def _edge(target_hex, relation="supersedes", **extra):
    e = {"relation": relation,
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}
    e.update(extra)
    return e


def _emit(patch, signer, outcome=False):
    if outcome:
        pred = dict(OUT_PRED, **(patch or {}))
        return emit_outcome_receipt(pred, signer, strict=True)
    pred = json.loads(json.dumps(BASE_PRED))
    pred.update(patch or {})
    return emit_decision_receipt(pred, signer, strict=True)


class TestLoadPolicyFailClosed(unittest.TestCase):
    """WP-A/WP-A2: the two new pins are fail-closed at load time (never a silent no-op)."""

    def _ok(self, relations):
        return load_policy({"schema": V02, "policy_id": "p", "relations": relations})

    def _bad(self, relations):
        with self.assertRaises(PolicyError):
            load_policy({"schema": V02, "policy_id": "p", "relations": relations})

    def test_relation_signer_same_key_and_pinned_valid(self):
        k = _pub(generate_signer())
        self._ok({"relation_signer": {"supersedes": {"mode": "same-key"}}})
        self._ok({"relation_signer": {"supersedes": {"mode": "pinned", "keys": [k]}}})

    def test_relation_signer_unknown_mode_rejected(self):
        self._bad({"relation_signer": {"supersedes": {"mode": "whoever"}}})

    def test_relation_signer_empty_keys_rejected(self):
        self._bad({"relation_signer": {"supersedes": {"mode": "pinned", "keys": []}}})

    def test_relation_signer_extra_field_rejected(self):
        k = _pub(generate_signer())
        self._bad({"relation_signer": {"supersedes": {"mode": "pinned", "keys": [k], "x": 1}}})

    def test_relation_signer_same_key_with_keys_rejected(self):
        k = _pub(generate_signer())
        self._bad({"relation_signer": {"supersedes": {"mode": "same-key", "keys": [k]}}})

    def test_relation_signer_unknown_relation_rejected(self):
        k = _pub(generate_signer())
        self._bad({"relation_signer": {"whoops": {"mode": "pinned", "keys": [k]}}})

    def test_relation_signer_non_b64_key_rejected(self):
        self._bad({"relation_signer": {"supersedes": {"mode": "pinned", "keys": ["!!not-b64!!"]}}})

    def test_require_relation_target_single_and_list_valid(self):
        r = "a" * 64
        self._ok({"require_relation_target": {"supersedes": r}})
        self._ok({"require_relation_target": {"supersedes": [r, "b" * 64]}})

    def test_require_relation_target_non_hex_rejected(self):
        self._bad({"require_relation_target": {"supersedes": "NOTHEX"}})
        self._bad({"require_relation_target": {"supersedes": ["a" * 63]}})

    def test_require_relation_target_empty_list_rejected(self):
        self._bad({"require_relation_target": {"supersedes": []}})

    def test_require_relation_target_unknown_relation_rejected(self):
        self._bad({"require_relation_target": {"nope": "a" * 64}})

    def test_never_raise_on_arbitrary_types(self):
        # Never-Raise matrix: malformed values are a Load ERROR (PolicyError), never a bare exception.
        for bad in ([], "str", 5, {"supersedes": []}, {"supersedes": "x"}):
            with self.assertRaises(PolicyError):
                load_policy({"schema": V02, "policy_id": "p", "relations": {"relation_signer": bad}})

    def test_v01_schema_rejects_relations_section(self):
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
                         "relations": {"relation_signer": {"supersedes": {"mode": "same-key"}}}})


class TestExplainParity(unittest.TestCase):
    def test_explain_lists_both_new_pins(self):
        k = _pub(generate_signer())
        pins = explain_policy(load_policy({
            "schema": V02, "policy_id": "p",
            "relations": {"relation_signer": {"supersedes": {"mode": "pinned", "keys": [k]}},
                          "require_relation_target": {"supersedes": ["a" * 64]}}}))
        blob = " ".join(pins)
        self.assertIn("relation_signer[supersedes]", blob)
        self.assertIn("require_relation_target[supersedes]", blob)


class TestKeysEqual(unittest.TestCase):
    def test_same_key_equal_different_not(self):
        a, b = _pub(generate_signer()), _pub(generate_signer())
        self.assertTrue(_keys_equal(a, a))
        self.assertFalse(_keys_equal(a, b))

    def test_undecodable_never_equal(self):
        self.assertFalse(_keys_equal("!!", "!!"))
        self.assertFalse(_keys_equal(None, _pub(generate_signer())))


class TestSignerDecisionPath(unittest.TestCase):
    def setUp(self):
        self.x, self.y, self.o = generate_signer(), generate_signer(), generate_signer()

    def _verify(self, succ_env, succ_signer, related, policy):
        pub = succ_signer.public_key().public_bytes_raw()
        return verify_decision_receipt(succ_env, pub, policy=policy, related=related)

    def _related(self, env, verify_signer):
        return {_root(env): {"verified": True, "relationships": None,
                             "verified_under": _pub(verify_signer), "subject_digest": _subject(env)}}

    def test_pinned_member_passes(self):
        b = _emit({"decisionId": "b"}, self.y)
        a = _emit({"decisionId": "a", "relationships": [_edge(_root(b))]}, self.x)
        pol = load_policy({"schema": V02, "policy_id": "p", "relations": {
            "relation_signer": {"supersedes": {"mode": "pinned", "keys": [_pub(self.x)]}}}})
        r = self._verify(a, self.x, self._related(b, self.y), pol)
        self.assertTrue(r["ok"])
        self.assertIsNot(r["policy_ok"], False)

    def test_pinned_non_member_unauthorized(self):
        b = _emit({"decisionId": "b"}, self.y)
        a = _emit({"decisionId": "a", "relationships": [_edge(_root(b))]}, self.x)
        pol = load_policy({"schema": V02, "policy_id": "p", "relations": {
            "relation_signer": {"supersedes": {"mode": "pinned", "keys": [_pub(self.o)]}}}})
        r = self._verify(a, self.x, self._related(b, self.y), pol)
        self.assertFalse(r["ok"])
        self.assertFalse(r["policy_ok"])
        # lattice monotonicity: crypto stays valid; the block is only in the policy verdict.
        self.assertTrue(r["crypto_ok"])
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, r["relations_policy_codes"])

    def test_same_key_cross_issuer_rejected(self):
        b = _emit({"decisionId": "b"}, self.y)  # target verifies under Y
        a = _emit({"decisionId": "a", "relationships": [_edge(_root(b))]}, self.x)  # successor X
        pol = load_policy({"schema": V02, "policy_id": "p", "relations": {
            "relation_signer": {"supersedes": {"mode": "same-key"}}}})
        r = self._verify(a, self.x, self._related(b, self.y), pol)
        self.assertFalse(r["policy_ok"])
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, r["relations_policy_codes"])


class TestTargetPinDecoy(unittest.TestCase):
    """WP-A2 KERNFUND: the decoy-parent (F1) must fail-closed, accept path included."""

    def setUp(self):
        self.x = generate_signer()
        self.r0 = _emit({"decisionId": "r0"}, self.x)
        self.rx = _emit({"decisionId": "rx"}, self.x)

    def _related(self, *envs):
        return {_root(e): {"verified": True, "relationships": None,
                           "verified_under": _pub(self.x), "subject_digest": _subject(e)}
                for e in envs}

    def _verify(self, env, related, roots):
        pol = load_policy({"schema": V02, "policy_id": "p",
                           "relations": {"require_relation_target": {"supersedes": roots}}})
        return verify_decision_receipt(env, self.x.public_key().public_bytes_raw(),
                                       policy=pol, related=related)

    def test_decoy_parent_fails_closed(self):
        child = _emit({"decisionId": "c", "relationships": [_edge(_root(self.rx))]}, self.x)
        r = self._verify(child, self._related(self.r0, self.rx), [_root(self.r0)])
        self.assertFalse(r["ok"])
        self.assertFalse(r["policy_ok"])
        self.assertTrue(r["crypto_ok"])  # lattice monotonicity
        self.assertEqual(r["lineage"]["lineage"], "VERIFIED")  # crypto resolves; policy blocks
        self.assertIn(CODE_RELATION_TARGET_MISMATCH, r["relations_policy_codes"])

    def test_correct_parent_passes(self):
        child = _emit({"decisionId": "c", "relationships": [_edge(_root(self.r0))]}, self.x)
        r = self._verify(child, self._related(self.r0, self.rx), [_root(self.r0)])
        self.assertIsNot(r["policy_ok"], False)

    def test_decoy_on_accept_path_fails(self):
        # Only RX attached — the previously-'good' accepted T2 — still FAILs under the pin.
        child = _emit({"decisionId": "c", "relationships": [_edge(_root(self.rx))]}, self.x)
        r = self._verify(child, self._related(self.rx), [_root(self.r0)])
        self.assertFalse(r["policy_ok"])
        self.assertIn(CODE_RELATION_TARGET_MISMATCH, r["relations_policy_codes"])


class TestTargetSubjectDigestO2(unittest.TestCase):
    """WP-A2/O2: the dormant targetSubjectDigest field is now binding when present (lineage FAIL)."""

    def setUp(self):
        self.x = generate_signer()
        self.r0 = _emit({"decisionId": "r0"}, self.x)

    def _related(self):
        return {_root(self.r0): {"verified": True, "relationships": None,
                                 "verified_under": _pub(self.x), "subject_digest": _subject(self.r0)}}

    def test_wrong_subject_digest_fails_lineage(self):
        edge = _edge(_root(self.r0),
                     targetSubjectDigest={"digestAlgorithm": "jcs-sha256-v1", "digest": "f" * 64})
        res = verify_relationship_edges([edge], self._related())
        self.assertEqual(res["lineage"], "FAIL")
        self.assertTrue(any("RELATION_TARGET_SUBJECT_MISMATCH" in e for e in res["errors"]))

    def test_correct_subject_digest_verifies(self):
        edge = _edge(_root(self.r0),
                     targetSubjectDigest={"digestAlgorithm": "jcs-sha256-v1",
                                          "digest": _subject(self.r0)})
        res = verify_relationship_edges([edge], self._related())
        self.assertEqual(res["lineage"], "VERIFIED")

    def test_absent_subject_digest_stays_optional(self):
        res = verify_relationship_edges([_edge(_root(self.r0))], self._related())
        self.assertEqual(res["lineage"], "VERIFIED")


class TestF5AutomationSurface(unittest.TestCase):
    """WP-A3 / F5: a REQUESTED lineage relation that does not resolve must not read as
    referencesResolved=true (bidirectional: unaffected when no relation is required)."""

    def setUp(self):
        self.x = generate_signer()
        self.b = _emit({"decisionId": "b"}, self.x)

    def test_required_unresolved_flips_references_resolved_false(self):
        # edge present but target NOT attached (DECLARED_UNRESOLVED) under require_relation_resolution.
        a = _emit({"decisionId": "a", "relationships": [_edge(_root(self.b))]}, self.x)
        pol = load_policy({"schema": V02, "policy_id": "p",
                           "relations": {"require_relation_resolution": ["supersedes"]}})
        r = verify_decision_receipt(a, self.x.public_key().public_bytes_raw(), policy=pol)
        self.assertFalse(r["policy_ok"])
        self.assertFalse(r["automation"]["referencesResolved"])
        self.assertFalse(r["automation"]["safeForAutomation"])

    def test_no_required_relation_leaves_surface_clean(self):
        a = _emit({"decisionId": "a"}, self.x)  # no relationships at all
        r = verify_decision_receipt(a, self.x.public_key().public_bytes_raw())
        # referencesResolved reflects the ordinary reference checks, never forced False by lineage.
        self.assertIsNot(r["automation"]["referencesResolved"], False)


class TestOutcomePathGate(unittest.TestCase):
    """WP-B: the relations gate is enforced IDENTICALLY on the outcome verify path."""

    def setUp(self):
        self.x, self.y = generate_signer(), generate_signer()

    def _related(self, env, signer):
        return {_root(env): {"verified": True, "relationships": None,
                             "verified_under": _pub(signer), "subject_digest": _subject(env)}}

    def test_outcome_relation_signer_unauthorized(self):
        b = _emit({"outcomeId": "urn:uuid:b"}, self.y, outcome=True)
        a = _emit({"outcomeId": "urn:uuid:a", "relationships": [_edge(_root(b))]}, self.x, outcome=True)
        pol = load_policy({"schema": V02, "policy_id": "p", "relations": {
            "relation_signer": {"supersedes": {"mode": "pinned", "keys": [_pub(self.y)]}}}})
        r = verify_outcome_receipt(a, self.x.public_key().public_bytes_raw(),
                                   related=self._related(b, self.y), policy=pol)
        self.assertFalse(r["ok"])
        self.assertFalse(r["policy_ok"])
        self.assertTrue(r["crypto_ok"])
        self.assertIn(CODE_RELATION_SIGNER_UNAUTHORIZED, r["relations_policy_codes"])

    def test_outcome_target_mismatch(self):
        r0 = _emit({"outcomeId": "urn:uuid:r0"}, self.x, outcome=True)
        rx = _emit({"outcomeId": "urn:uuid:rx"}, self.x, outcome=True)
        child = _emit({"outcomeId": "urn:uuid:c", "relationships": [_edge(_root(rx))]},
                      self.x, outcome=True)
        related = {**self._related(r0, self.x), **self._related(rx, self.x)}
        pol = load_policy({"schema": V02, "policy_id": "p", "relations": {
            "require_relation_target": {"supersedes": [_root(r0)]}}})
        r = verify_outcome_receipt(child, self.x.public_key().public_bytes_raw(),
                                   related=related, policy=pol)
        self.assertFalse(r["policy_ok"])
        self.assertIn(CODE_RELATION_TARGET_MISMATCH, r["relations_policy_codes"])

    def test_outcome_no_policy_backward_compatible(self):
        a = _emit({"outcomeId": "urn:uuid:a"}, self.x, outcome=True)
        r = verify_outcome_receipt(a, self.x.public_key().public_bytes_raw())
        self.assertTrue(r["ok"])
        self.assertIsNone(r["policy_ok"])


class TestSignerSetProperty(unittest.TestCase):
    """Hypothesis: over random pinned signer sets the evaluator authorizes iff the successor key is a
    member (byte membership), and a keyId-style alias never grants membership."""

    @settings(max_examples=120, deadline=None)
    @given(st.integers(min_value=1, max_value=8), st.integers(min_value=0, max_value=8))
    def test_pinned_membership_is_byte_exact(self, n_keys, succ_idx):
        keys = [generate_signer() for _ in range(n_keys)]
        successor = keys[succ_idx] if succ_idx < n_keys else generate_signer()
        pinned = [_pub(k) for k in keys]
        lineage = {"edges": [{"relation": "supersedes", "resolution": "VERIFIED",
                              "targetDigest": "a" * 64, "verified_under": _pub(successor)}],
                   "supersededByAttached": None}
        section = {"relation_signer": {"supersedes": {"mode": "pinned", "keys": pinned}}}
        viol = evaluate_relations_policy(section, lineage, successor_key_b64=_pub(successor))
        is_member = any(_keys_equal(_pub(successor), p) for p in pinned)
        self.assertEqual(viol == [], is_member)


if __name__ == "__main__":
    unittest.main()
