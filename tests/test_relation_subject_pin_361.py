"""3.6.1 — targetSubjectDigest pin fail-closed (PB-2026-0717-01).

Regression + adversarial for the P0 subject-pin fail-open: before 3.6.1 a DECLARED
``targetSubjectDigest`` against an absent / null / malformed / ambiguous actual target subject
fell through to ``VERIFIED`` (False Accept). The fix makes the pin fail-closed with a stable,
Python/Rust-identical wire code in every state except present-and-equal, and propagates to the
decision AND outcome automation gates (``safeForAutomation=false``) because both paths call the
same :func:`verify_relationship_edges`. The pre-existing present-but-wrong (``MISMATCH``) rejection
and the absent-declared-pin (optional field) accept path are unchanged (no wire-break).

Acceptance criterion (verbatim, PB-FIX-361-AUDIT-VOLL Befund A): *A declared targetSubjectDigest
must fail with a stable error code whenever the resolved target subject digest is absent, ambiguous,
malformed, or unequal. Python and Rust must pass the same negative vectors.*
"""
import base64
import json
import pathlib
import tempfile
import unittest

from proofbundle import anchors, dsse
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.policy import load_policy
from proofbundle.relation import (
    CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS,
    CODE_RELATION_TARGET_SUBJECT_MALFORMED,
    CODE_RELATION_TARGET_SUBJECT_MISMATCH,
    CODE_RELATION_TARGET_SUBJECT_MISSING,
    LINEAGE_FAIL,
    LINEAGE_VERIFIED,
    validate_relationships,
    verify_relationship_edges,
)

V02 = "proofbundle/trust-policy/v0.2"
_INTOTO = "application/vnd.in-toto+json"
_HEX_A = "a" * 64
_HEX_B = "b" * 64


def _pub_bytes(signer):
    return signer.public_key().public_bytes_raw()


def _pub_b64(signer):
    return base64.b64encode(_pub_bytes(signer)).decode()


def _edge(target_hex, declared_subject=None, relation="supersedes"):
    e = {"relation": relation,
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}
    if declared_subject is not None:
        e["targetSubjectDigest"] = {"digestAlgorithm": "jcs-sha256-v1", "digest": declared_subject}
    return e


def _target(*, verified=True, subject_digest=None, subject_digest_state=None, key_b64="k"):
    """A resolved-target entry mimicking the CLI loader output. When ``subject_digest_state`` is
    omitted the verifier infers it fail-closed from ``subject_digest`` (exercises the robust path)."""
    t = {"verified": verified, "relationships": None, "verified_under": key_b64,
         "subject_digest": subject_digest}
    if subject_digest_state is not None:
        t["subject_digest_state"] = subject_digest_state
    return t


def _emit_subjectless_target(signer):
    """A valid DSSE statement with an EMPTY in-toto subject array (the P0 vector)."""
    stmt = {"_type": "https://in-toto.io/Statement/v1", "subject": [],
            "predicateType": "https://example.invalid/subjectless/v1",
            "predicate": {"note": "valid DSSE target with no subject"}}
    body = json.dumps(stmt, separators=(",", ":"), sort_keys=True).encode("utf-8")
    env = dsse.sign_envelope(body, signer, payload_type=_INTOTO)
    return env, anchors.statement_content_root(body).hex()


def _load_related_target(env, signer, related_pub_b64):
    from proofbundle.cli import _load_related
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "target.json"
        p.write_text(json.dumps(env), encoding="utf-8")
        return _load_related([str(p)], _pub_bytes(signer), [related_pub_b64])


class DirectVerifierSubjectPin(unittest.TestCase):
    """Unit-level over verify_relationship_edges: every negative state fails closed."""

    def _run(self, declared_subject, target):
        return verify_relationship_edges([_edge(_HEX_A, declared_subject=declared_subject)],
                                         {_HEX_A: target}, subject_hex="f" * 64)

    def test_relation_target_subject_digest_missing_fails_closed(self):
        r = self._run(_HEX_B, _target(subject_digest=None, subject_digest_state="absent"))
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MISSING, " ".join(r["errors"]))

    def test_relation_target_subject_digest_null_fails_closed(self):
        r = self._run(_HEX_B, _target(subject_digest=None))  # no state annotation -> inferred absent
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MISSING, " ".join(r["errors"]))

    def test_target_multiple_subjects_is_ambiguous_fails_closed(self):
        r = self._run(_HEX_B, _target(subject_digest=None, subject_digest_state="ambiguous"))
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS, " ".join(r["errors"]))

    def test_target_subject_digest_malformed_hex_fails_closed(self):
        r = self._run(_HEX_B, _target(subject_digest="XYZ", subject_digest_state=None))
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MALFORMED, " ".join(r["errors"]))

    def test_target_subject_digest_malformed_state_fails_closed(self):
        r = self._run(_HEX_B, _target(subject_digest=None, subject_digest_state="malformed"))
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MALFORMED, " ".join(r["errors"]))

    def test_present_but_unequal_stays_mismatch(self):
        r = self._run(_HEX_B, _target(subject_digest=_HEX_A, subject_digest_state="present"))
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MISMATCH, " ".join(r["errors"]))

    def test_present_and_equal_verifies(self):
        r = self._run(_HEX_A, _target(subject_digest=_HEX_A, subject_digest_state="present"))
        self.assertEqual(r["lineage"], LINEAGE_VERIFIED)

    def test_absent_declared_pin_is_optional_no_wire_break(self):
        r = verify_relationship_edges([_edge(_HEX_A, declared_subject=None)],
                                      {_HEX_A: _target(subject_digest=None, subject_digest_state="absent")},
                                      subject_hex="f" * 64)
        self.assertEqual(r["lineage"], LINEAGE_VERIFIED)

    def test_target_subject_digest_algorithm_must_match_declared(self):
        # a declared targetSubjectDigest with a non-registered digestAlgorithm is structurally
        # rejected (never defaulted) — the algorithm is bound, not free-form.
        bad = {"relation": "supersedes",
               "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": _HEX_A},
               "targetSubjectDigest": {"digestAlgorithm": "sha256", "digest": _HEX_B}}
        errs = validate_relationships([bad])
        self.assertTrue(any("digestAlgorithm" in e for e in errs), errs)


class MetamorphicMonotonicity(unittest.TestCase):
    """Weakening the actual subject evidence must never flip FAIL->PASS (SMRL monotonicity)."""

    def test_weakening_present_to_absent_never_upgrades(self):
        edges = [_edge(_HEX_A, declared_subject=_HEX_B)]
        strong = verify_relationship_edges(
            edges, {_HEX_A: _target(subject_digest=_HEX_B, subject_digest_state="present")},
            subject_hex="f" * 64)
        weak = verify_relationship_edges(
            edges, {_HEX_A: _target(subject_digest=None, subject_digest_state="absent")},
            subject_hex="f" * 64)
        self.assertEqual(strong["lineage"], LINEAGE_VERIFIED)
        self.assertEqual(weak["lineage"], LINEAGE_FAIL)

    def test_adding_pin_never_upgrades(self):
        no_pin = verify_relationship_edges(
            [_edge(_HEX_A, declared_subject=None)],
            {_HEX_A: _target(subject_digest=None, subject_digest_state="absent")}, subject_hex="f" * 64)
        with_pin = verify_relationship_edges(
            [_edge(_HEX_A, declared_subject=_HEX_B)],
            {_HEX_A: _target(subject_digest=None, subject_digest_state="absent")}, subject_hex="f" * 64)
        self.assertEqual(no_pin["lineage"], LINEAGE_VERIFIED)
        self.assertEqual(with_pin["lineage"], LINEAGE_FAIL)


class CliLoaderSubjectless(unittest.TestCase):
    """End-to-end through the CLI loader: a valid subjectless DSSE cannot satisfy a subject pin."""

    def test_cli_subjectless_dsse_cannot_satisfy_target_subject_pin(self):
        signer = generate_signer()
        env, root_hex = _emit_subjectless_target(signer)
        related, errs = _load_related_target(env, signer, _pub_b64(signer))
        self.assertEqual(errs, [])
        # the loader classifies the subjectless target as absent, not a silently-picked subject.
        self.assertIsNone(related[root_hex]["subject_digest"])
        self.assertEqual(related[root_hex]["subject_digest_state"], "absent")
        r = verify_relationship_edges([_edge(root_hex, declared_subject=_HEX_B)], related,
                                      subject_hex="f" * 64)
        self.assertEqual(r["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_SUBJECT_MISSING, " ".join(r["errors"]))


def _automation_policy(successor, target_root):
    return load_policy({
        "schema": V02, "policy_id": "audit/subject-pin-automation",
        "decision_receipt": {
            "accepted_predicate_types": ["https://b7n0de.org/proofbundle/decision/v0.1"],
            "trusted_decision_makers": [{"id": "dm", "public_key_b64": _pub_b64(successor)}],
            "allowed_decision_types": ["preActionAuthorization"],
            "allowed_verdicts": ["ALLOW"], "require_policy_digest": True,
        },
        "relations": {
            "relation_signer": {"supersedes": {"mode": "pinned", "keys": [_pub_b64(successor)]}},
            "require_relation_target": {"supersedes": target_root},
            "require_relation_resolution": ["supersedes"],
        },
    })


class AutomationGateProjection(unittest.TestCase):
    """A subject-pin failure must project into safeForAutomation=false on BOTH gates (fail-closed)."""

    def setUp(self):
        self.successor = generate_signer()
        self.target_signer = generate_signer()
        env, self.target_root = _emit_subjectless_target(self.target_signer)
        self.related, errs = _load_related_target(env, self.successor, _pub_b64(self.target_signer))
        self.assertEqual(errs, [])
        self.policy = _automation_policy(self.successor, self.target_root)
        self.edge = _edge(self.target_root, declared_subject=_HEX_B)

    def test_decision_subject_pin_failure_blocks_automation(self):
        pred = {
            "schemaVersion": "0.1.0", "decisionId": "urn:uuid:d", "decisionType": "preActionAuthorization",
            "decidedAt": "2026-07-17T00:00:00Z", "decisionMaker": {"id": "dm"}, "agent": {"id": "a"},
            "principal": {"id": "p"},
            "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
            "inputSnapshot": [],
            "policyBoundary": {"policyEngine": "opa", "policyId": "p", "policyDigest": {"sha256": "0" * 64},
                               "decisionPath": "data.allow"},
            "evidenceRefs": [], "decision": {"verdict": "ALLOW", "reasonCodes": ["OK"]},
            "relationships": [self.edge],
        }
        env = emit_decision_receipt(pred, self.successor, strict=False)
        r = verify_decision_receipt(env, _pub_bytes(self.successor), policy=self.policy, related=self.related)
        self.assertNotEqual((r.get("lineage") or {}).get("lineage"), LINEAGE_VERIFIED)
        self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True)

    def test_outcome_subject_pin_failure_blocks_automation(self):
        trust_pack = {
            "schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1, "expires": "2099-01-01T00:00:00Z",
            "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root-0"], "threshold": 1},
                      "outcomeExecutors": {"keyIds": ["kid-exec"], "threshold": 1}},
            "keys": {"root-0": {"publicKey": "A" * 43 + "="}}, "nonClaims": ["role mapping only"],
        }
        pred = {
            "schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
            "executor": {"id": "ex", "keyId": "kid-exec"}, "requestedActionDigest": {"sha256": "1" * 64},
            "effectDigest": {"sha256": "1" * 64}, "status": "executed",
            "performedAt": "2026-07-17T00:00:00Z", "policyPurpose": "outcome", "relationships": [self.edge],
        }
        env = emit_outcome_receipt(pred, self.successor, strict=False)
        r = verify_outcome_receipt(env, _pub_bytes(self.successor), policy=self.policy,
                                   related=self.related, trust_pack=trust_pack)
        self.assertNotEqual((r.get("lineage") or {}).get("lineage"), LINEAGE_VERIFIED)
        self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True)


class RustParity(unittest.TestCase):
    """Python/Rust must pass the same negative vectors (PB-FIX-361-AUDIT-VOLL Befund A).

    The Rust relation verifier carries the SAME permissive branch (static finding) and is NOT yet
    fixed in this increment — so parity cannot yet PASS. This is recorded as an honest NOT-RUN
    (skip), never a fake PASS: the Rust-side fix + `cargo test` is a declared open item."""

    def test_python_rust_missing_target_subject_parity(self):
        self.skipTest("BLOCKED-rust-fix-open: the Rust verifier subject-pin fix is a separate open "
                      "item (PB-2026-0717-01 Rust half); parity is NOT-RUN, not a PASS.")


if __name__ == "__main__":
    unittest.main()
