"""WP3 tests: DSSE emit/verify of Decision Receipts (crypto core, fail-closed).

Roundtrip, tamper detection, wrong-key, predicateType confusion attack, audience/nonce replay, and the
RFC-8785 hash-binding rule (verify never re-serializes; received bytes must be canonical)."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from proofbundle.decision import (
    DECISION_RECEIPT_PREDICATE_TYPE,
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


def test_roundtrip_all_checks_green():
    p = _pred("deny")
    s, pub = _keys()
    env = emit_decision_receipt(p, s, strict=True)
    r = verify_decision_receipt(env, pub, strict=True,
                                expected_audience=p["validity"]["audience"][0],
                                expected_nonce=p["validity"]["nonce"])
    assert r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
    assert r["evidence_bound"] and r["audience_ok"] and r["nonce_ok"]
    assert r["errors"] == []


def test_tamper_breaks_crypto():
    p = _pred("deny")
    s, pub = _keys()
    env = emit_decision_receipt(p, s)
    body = json.loads(base64.b64decode(env["payload"]))
    body["predicate"]["decision"]["verdict"] = "ALLOW"
    assert verify_decision_receipt(_repayload(env, body), pub)["crypto_ok"] is False


def test_wrong_key_fails():
    s, _ = _keys()
    env = emit_decision_receipt(_pred("deny"), s)
    _, other_pub = _keys()
    assert verify_decision_receipt(env, other_pub)["crypto_ok"] is False


def test_predicate_type_confusion_rejected():
    # a receipt whose predicateType claims eval-result (or anything not decision-receipt) fails structure
    p = _pred("deny")
    s, pub = _keys()
    stmt = build_decision_statement(p)
    stmt["predicateType"] = "https://b7n0de.com/proofbundle/predicates/eval-result/v0.1"
    from proofbundle import dsse
    from proofbundle.decision import INTOTO_STATEMENT_PAYLOAD_TYPE, _rfc8785_bytes
    env = dsse.sign_envelope(_rfc8785_bytes(stmt), s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = verify_decision_receipt(env, pub)
    assert r["crypto_ok"] is True            # correctly signed …
    assert r["predicate_type_ok"] is False   # … but not a decision receipt
    assert r["structure_ok"] is False
    assert any("confusion attack" in e for e in r["errors"])


def test_audience_and_nonce_replay():
    p = _pred("deny")
    s, pub = _keys()
    env = emit_decision_receipt(p, s)
    assert verify_decision_receipt(env, pub, expected_audience="https://evil.example/x")["audience_ok"] is False
    assert verify_decision_receipt(env, pub, expected_nonce="deadbeef")["nonce_ok"] is False


def test_hash_binding_non_canonical_payload_rejected():
    # re-emit with a deliberately non-RFC-8785 payload (extra whitespace); verify must flag it fail-closed
    p = _pred("deny")
    s, pub = _keys()
    stmt = build_decision_statement(p)
    from proofbundle import dsse
    from proofbundle.decision import INTOTO_STATEMENT_PAYLOAD_TYPE
    non_canonical = json.dumps(stmt, indent=2).encode()  # pretty-printed = not RFC-8785
    env = dsse.sign_envelope(non_canonical, s, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = verify_decision_receipt(env, pub)
    assert r["crypto_ok"] is True
    assert r["structure_ok"] is False
    assert any("RFC-8785 canonical" in e for e in r["errors"])


def test_emit_rejects_invalid_predicate():
    p = _pred("deny")
    del p["decision"]
    s, _ = _keys()
    with pytest.raises(Exception):
        emit_decision_receipt(p, s, strict=True)


def test_emitted_statement_shape():
    p = _pred("deny")
    stmt = build_decision_statement(p)
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == DECISION_RECEIPT_PREDICATE_TYPE
    assert stmt["subject"][0]["name"] == f"decision:{p['decisionId']}"
    assert len(stmt["subject"][0]["digest"]["sha256"]) == 64
