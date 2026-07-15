"""WP3 tests: DSSE emit/verify of Decision Receipts (crypto core, fail-closed).

Roundtrip, tamper detection, wrong-key, predicateType confusion attack, audience/nonce replay, and the
RFC-8785 hash-binding rule. unittest-style to match the repo's `python -m unittest discover`."""
from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from proofbundle import dsse
from proofbundle.decision import (
    DECISION_RECEIPT_PREDICATE_TYPE,
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    _rfc8785_bytes,
    build_decision_statement,
    emit_decision_receipt,
    verify_decision_receipt,
)
from proofbundle.emit import generate_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _repayload(env: dict, statement: dict) -> dict:
    env = copy.deepcopy(env)
    env["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    return env


class TestDecisionVerify(unittest.TestCase):
    def test_roundtrip_all_checks_green(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True,
                                    expected_audience=p["validity"]["audience"][0],
                                    expected_nonce=p["validity"]["nonce"])
        self.assertTrue(r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"])
        self.assertTrue(r["evidence_bound"] and r["audience_ok"] and r["nonce_ok"])
        self.assertEqual(r["errors"], [])

    def test_tamper_breaks_crypto(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        body = json.loads(base64.b64decode(env["payload"]))
        body["predicate"]["decision"]["verdict"] = "ALLOW"
        self.assertIs(verify_decision_receipt(_repayload(env, body), pub)["crypto_ok"], False)

    def test_forged_envelope_leaves_trust_fields_none_and_aggregate_false(self):
        # 6-lens review (fail-open lens): a forged/unsigned envelope must not report audience_ok/nonce_ok
        # true, must record a crypto error, and the aggregate `ok` must be False — a consumer keying off an
        # individual *_ok field over unauthenticated bytes was the finding.
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        forged = copy.deepcopy(env)
        forged["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
        r = verify_decision_receipt(forged, pub,
                                    expected_audience=p["validity"]["audience"][0],
                                    expected_nonce=p["validity"]["nonce"])
        self.assertFalse(r["crypto_ok"])
        self.assertFalse(r["ok"])                       # aggregate verdict is false
        self.assertIsNone(r["audience_ok"])             # not computed over unauthenticated bytes
        self.assertIsNone(r["nonce_ok"])
        self.assertIsNone(r["evidence_bound"])
        self.assertTrue(r["errors"])                    # never an empty errors[] on a forged envelope

    def test_valid_receipt_aggregate_ok_true(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True,
                                    expected_audience=p["validity"]["audience"][0],
                                    expected_nonce=p["validity"]["nonce"])
        self.assertTrue(r["ok"])

    def test_empty_evidence_refs_is_none_not_vacuous_true(self):
        # evidence_bound must be None (nothing to bind), never a vacuous all([]) True.
        p = _pred("deny")
        p = copy.deepcopy(p)
        p["evidenceRefs"] = []
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        r = verify_decision_receipt(env, pub)
        self.assertIsNone(r["evidence_bound"])

    def test_attributes_to_nobody_not_suppressed_by_allowed_issuers(self):
        # Fix-review (H3 false negative): allowed_issuers / require_expected_signer are EVAL-bundle
        # concepts that the decision path never reads, so an orthogonal allowed_issuers block must NOT
        # suppress the "attributes to nobody" warning for a decision receipt with no
        # trusted_decision_makers.
        from proofbundle.policy import load_policy
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        full = "Ts6DJw7AT4alPGqp9JVzh83VvXoMcRXVU0Lb7R2qB08="  # a real full-order key (irrelevant to decisions)
        policy = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "x",
                              "allowed_issuers": [{"issuer": "X", "public_key_b64": full}],
                              "decision_receipt": {"allowed_verdicts": ["ALLOW", "DENY", "REFUSE",
                                                                        "ESCALATE", "DEFER", "OBSERVE"]}})
        r = verify_decision_receipt(env, pub, policy=policy)
        self.assertTrue(any("attributes to nobody" in w for w in r["warnings"]))

    def test_pinned_decision_maker_no_false_positive_warning(self):
        import base64 as _b64
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        from proofbundle.policy import load_policy
        policy = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "y",
                              "decision_receipt": {"trusted_decision_makers":
                                                   [{"public_key_b64": _b64.b64encode(pub).decode()}]}})
        r = verify_decision_receipt(env, pub, policy=policy)
        self.assertFalse(any("attributes to nobody" in w for w in r["warnings"]))
        self.assertTrue(r["signer_trusted"])

    def test_wrong_key_fails(self):
        s, _ = _keys()
        env = emit_decision_receipt(_pred("deny"), s)
        _, other_pub = _keys()
        self.assertIs(verify_decision_receipt(env, other_pub)["crypto_ok"], False)

    def test_predicate_type_confusion_rejected(self):
        p = _pred("deny")
        s, pub = _keys()
        stmt = build_decision_statement(p)
        stmt["predicateType"] = "https://b7n0de.com/proofbundle/predicates/eval-result/v0.1"
        env = dsse.sign_envelope(_rfc8785_bytes(stmt), s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_decision_receipt(env, pub)
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["predicate_type_ok"], False)
        self.assertIs(r["structure_ok"], False)
        self.assertTrue(any("confusion attack" in e for e in r["errors"]))

    def test_audience_and_nonce_replay(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        self.assertIs(verify_decision_receipt(env, pub, expected_audience="https://evil.example/x")["audience_ok"], False)
        self.assertIs(verify_decision_receipt(env, pub, expected_nonce="deadbeef")["nonce_ok"], False)

    def test_hash_binding_non_canonical_payload_rejected(self):
        p = _pred("deny")
        s, pub = _keys()
        stmt = build_decision_statement(p)
        non_canonical = json.dumps(stmt, indent=2).encode()
        env = dsse.sign_envelope(non_canonical, s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_decision_receipt(env, pub)
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["structure_ok"], False)
        self.assertTrue(any("RFC-8785 canonical" in e for e in r["errors"]))

    def test_emit_rejects_invalid_predicate(self):
        p = _pred("deny")
        del p["decision"]
        s, _ = _keys()
        with self.assertRaises(Exception):
            emit_decision_receipt(p, s, strict=True)

    def test_emitted_statement_shape(self):
        p = _pred("deny")
        stmt = build_decision_statement(p)
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], DECISION_RECEIPT_PREDICATE_TYPE)
        self.assertEqual(stmt["subject"][0]["name"], f"decision:{p['decisionId']}")
        self.assertEqual(len(stmt["subject"][0]["digest"]["sha256"]), 64)


class TestDecisionSubjectBinding(unittest.TestCase):
    """Finding 05: `build_decision_statement`'s documented `subject_sha256` override is self-attested and NOT
    cross-checked at build time. Before this fix `verify_decision_receipt` never called subject_binding at
    all (no `subject_binding` field in the result, no way to opt into a hard fail-closed check). Mirrors
    outcome.py's `TestOutcomeSubjectBinding` — the two verify paths must offer the same guarantee."""

    def test_default_subject_is_derived(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)  # subject derived from the predicate (no override)
        r = verify_decision_receipt(env, pub, strict=True)
        self.assertEqual(r["subject_binding"]["mode"], "DERIVED")
        self.assertTrue(r["subject_binding"]["matches"])
        self.assertFalse(any("subject-rehang" in w for w in r["warnings"]))
        self.assertTrue(r["ok"], r)

    def test_subject_mode_field_present(self):
        # The field must be populated (not left None) on BOTH a DERIVED and an EXTERNAL_ATTESTED subject —
        # never zero signal.
        p = _pred("deny")
        s, pub = _keys()
        derived_env = emit_decision_receipt(p, s)
        rehung_env = emit_decision_receipt(p, s, subject_sha256="d" * 64)
        self.assertIsNotNone(verify_decision_receipt(derived_env, pub)["subject_binding"])
        self.assertIsNotNone(verify_decision_receipt(rehung_env, pub)["subject_binding"])

    def test_external_attested_subject_is_warned_not_silent(self):
        # The PoC: a validly-signed decision whose subject points elsewhere. It must no longer verify with
        # ZERO signal — the classification + a warning are always present (ok still True by default, the
        # override is a documented self-attest feature).
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s, subject_sha256="d" * 64)
        r = verify_decision_receipt(env, pub, strict=True)
        self.assertEqual(r["subject_binding"]["mode"], "EXTERNAL_ATTESTED")
        self.assertFalse(r["subject_binding"]["matches"])
        self.assertTrue(any("subject-rehang" in w for w in r["warnings"]), r["warnings"])
        self.assertTrue(r["ok"], r)   # default: warn, not a hard fail

    def test_decision_subject_rehang_fails_with_require_derived_subject(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s, subject_sha256="d" * 64)
        r = verify_decision_receipt(env, pub, strict=True, require_derived_subject=True)
        self.assertFalse(r["subject_derived_ok"])
        self.assertFalse(r["ok"])
        self.assertTrue(any("require_derived_subject" in e for e in r["errors"]), r["errors"])

    def test_require_derived_subject_green_on_derived(self):
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        r = verify_decision_receipt(env, pub, strict=True, require_derived_subject=True)
        self.assertTrue(r["subject_derived_ok"])
        self.assertTrue(r["ok"], r)

    def test_require_derived_subject_fail_closed_when_classify_raises(self):
        import unittest.mock as mock

        from proofbundle import subject_binding
        p = _pred("deny")
        s, pub = _keys()
        env = emit_decision_receipt(p, s)
        with mock.patch.object(subject_binding, "classify_subject", side_effect=RuntimeError("boom")):
            r = verify_decision_receipt(env, pub, strict=True, require_derived_subject=True)
        self.assertFalse(r["subject_derived_ok"])
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
