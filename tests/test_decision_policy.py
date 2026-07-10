"""WP5 tests: trust policy v0.2 decision_receipt section + evaluate_decision_policy (fail-closed).

Backward compat (v0.1 policy valid under the v0.2 parser), the additive section rules, signer<->trusted-key
binding, predicateType confusion at the policy layer, and the exit-3 contract end to end."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from proofbundle.decision import build_decision_statement, emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.policy import PolicyError, evaluate_decision_policy, load_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pred(name: str = "deny") -> dict:
    return json.loads((EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _keys():
    s = generate_signer()
    return s, base64.b64encode(s.public_key().public_bytes_raw()).decode()


def _policy_trusting(pub_b64: str, **overrides) -> dict:
    section = {
        "accepted_predicate_types": ["https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1"],
        "trusted_decision_makers": [{"id": "https://example.org/decision-platform/proofbundle-gate/v1", "public_key_b64": pub_b64}],
        "allowed_decision_types": ["preActionAuthorization", "humanEscalation"],
        "allowed_verdicts": ["ALLOW", "DENY", "ESCALATE"],
        "required_evidence_relations": ["evalResult"],
        "require_policy_digest": True,
    }
    section.update(overrides)
    return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t", "decision_receipt": section}


# ── load_policy: additive v0.2 ──────────────────────────────────────────────
def test_v01_policy_valid_under_v02_parser():
    v01 = load_policy(json.loads((EXAMPLES / "trust_policy_strict.json").read_text())
                      if (EXAMPLES / "trust_policy_strict.json").exists()
                      else {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x"})
    assert v01["schema"] == "proofbundle/trust-policy/v0.1"


def test_v02_decision_section_loads():
    p = load_policy(_policy_trusting("AAAA"))
    assert p["decision_receipt"]["require_policy_digest"] is True


def test_decision_section_under_v01_schema_rejected():
    bad = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x",
           "decision_receipt": {"require_policy_digest": True}}
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_unknown_decision_field_rejected():
    bad = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "x", "decision_receipt": {"surprise": 1}}
    with pytest.raises(PolicyError):
        load_policy(bad)


# ── evaluate_decision_policy ────────────────────────────────────────────────
def test_trusted_signer_policy_ok():
    s, pub = _keys()
    stmt = build_decision_statement(_pred("deny"))
    r = evaluate_decision_policy(stmt, {}, load_policy(_policy_trusting(pub)), signer_public_key_b64=pub)
    assert r["signer_trusted"] is True and r["policy_ok"] is True and r["errors"] == []


def test_untrusted_signer_fails():
    _, pub = _keys()
    _, other = _keys()
    stmt = build_decision_statement(_pred("deny"))
    r = evaluate_decision_policy(stmt, {}, load_policy(_policy_trusting(other)), signer_public_key_b64=pub)
    assert r["signer_trusted"] is False and r["policy_ok"] is False


def test_predicate_type_confusion_fails_policy():
    _, pub = _keys()
    stmt = build_decision_statement(_pred("deny"))
    stmt["predicateType"] = "https://b7n0de.com/proofbundle/predicates/eval-result/v0.1"
    r = evaluate_decision_policy(stmt, {}, load_policy(_policy_trusting(pub)), signer_public_key_b64=pub)
    assert r["policy_ok"] is False and any("accepted_predicate_types" in e for e in r["errors"])


def test_verdict_not_allowed_fails():
    _, pub = _keys()
    p = _policy_trusting(pub, allowed_verdicts=["ALLOW"])   # deny example has verdict DENY
    r = evaluate_decision_policy(build_decision_statement(_pred("deny")), {}, load_policy(p), signer_public_key_b64=pub)
    assert r["policy_ok"] is False and any("verdict" in e for e in r["errors"])


def test_missing_required_evidence_relation_fails():
    _, pub = _keys()
    pred = _pred("deny")
    pred["evidenceRefs"] = []   # required 'evalResult' now missing
    r = evaluate_decision_policy(build_decision_statement(pred), {}, load_policy(_policy_trusting(pub)), signer_public_key_b64=pub)
    assert r["policy_ok"] is False and any("evidence relations" in e for e in r["errors"])


def test_no_decision_section_is_not_evaluated():
    r = evaluate_decision_policy(build_decision_statement(_pred("deny")), {},
                                 {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "x"},
                                 signer_public_key_b64="AAAA")
    assert r["policy_ok"] is None


# ── end-to-end verify + exit 3 ──────────────────────────────────────────────
def test_verify_with_policy_ok():
    s, pub = _keys()
    env = emit_decision_receipt(_pred("deny"), s, strict=True)
    r = verify_decision_receipt(env, s.public_key().public_bytes_raw(), strict=True,
                                policy=load_policy(_policy_trusting(pub)))
    assert r["crypto_ok"] and r["structure_ok"] and r["policy_ok"] is True and r["signer_trusted"] is True


def test_verify_with_policy_violation():
    s, pub = _keys()
    env = emit_decision_receipt(_pred("deny"), s, strict=True)
    _, other = _keys()  # a policy that trusts a DIFFERENT signer
    r = verify_decision_receipt(env, s.public_key().public_bytes_raw(),
                                policy=load_policy(_policy_trusting(other)))
    assert r["crypto_ok"] is True and r["policy_ok"] is False  # crypto OK, policy fail -> exit 3 at the CLI
