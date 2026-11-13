"""An attached `--with-related` receipt counts as verified only when its predicate passes the structure check of
its own type, as its standalone verifier applies it.

Deep gate 6.6.0 at d8881edc, iteration 1, finding Z4: `_load_related` checked the signature, the strict reading and
the shape of the predicate, so a correctly signed decision receipt without its required `decision` member was
loaded as verified. With no edge naming it, `decision verify --with-related` ended with exit 0 and `ok` true, while
the same bytes alone give `structure_ok` false and exit 2.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import cli, dsse
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.outcome import emit_outcome_receipt

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
_PUB = _KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_PUB64 = base64.b64encode(_PUB).decode("ascii")
_INTOTO = "application/vnd.in-toto+json"


def _decision(decision_id: str) -> dict:
    return {"schemaVersion": "0.1.0", "decisionId": decision_id, "decisionType": "preActionAuthorization",
            "decidedAt": "2026-01-01T00:00:00Z", "decisionMaker": {"id": "urn:test:maker"},
            "agent": {"id": "urn:test:agent"}, "principal": {"id": "urn:test:principal"},
            "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
            "inputSnapshot": [], "policyBoundary": {"policyEngine": "test", "policyId": "urn:test:policy",
                                                     "decisionPath": "allow"},
            "evidenceRefs": [], "decision": {"verdict": "DENY", "reasonCodes": ["test"]}}


def _resign_without(envelope: dict, member: str) -> dict:
    """The same statement without one predicate member, with its subject recomputed and signed again."""
    statement = json.loads(dsse.load_payload(envelope))
    del statement["predicate"][member]
    statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(rfc8785.dumps(statement["predicate"])).hexdigest()
    return dsse.sign_envelope(rfc8785.dumps(statement), _KEY, payload_type=_INTOTO)


def _invoke(argv: list[str]) -> tuple[int, dict]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, json.loads(out.getvalue())


def _verify_parent_with(tmp_path, target: dict) -> tuple[int, dict]:
    parent = tmp_path / "parent.json"
    parent.write_text(json.dumps(emit_decision_receipt(_decision("urn:test:parent"), _KEY, strict=False)),
                      encoding="utf-8")
    attached = tmp_path / "target.json"
    attached.write_text(json.dumps(target), encoding="utf-8")
    return _invoke(["decision", "verify", str(parent), "--pub", _PUB64, "--json",
                    "--with-related", str(attached), "--related-pub", _PUB64])


def test_a_valid_attachment_without_an_edge_leaves_the_parent_verified(tmp_path):
    code, report = _verify_parent_with(tmp_path, emit_decision_receipt(_decision("urn:test:other"), _KEY,
                                                                        strict=False))
    assert code == 0 and report["ok"] is True


def test_a_decision_attachment_without_its_decision_member_fails_the_parent(tmp_path):
    bad = _resign_without(emit_decision_receipt(_decision("urn:test:other"), _KEY, strict=False), "decision")
    alone = verify_decision_receipt(bad, _PUB)
    assert alone["crypto_ok"] is True and alone["structure_ok"] is False and alone["ok"] is False
    code, report = _verify_parent_with(tmp_path, bad)
    automation = report.get("automation") or {}
    assert (code, report.get("lineage_ok"), report.get("ok"), automation.get("referencesResolved"),
            automation.get("safeForAutomation")) == (2, False, False, False, False)


def test_an_outcome_attachment_without_its_executor_fails_the_parent(tmp_path):
    outcome = {"schemaVersion": "0.1.0", "outcomeId": "urn:test:outcome", "decisionRef": {"sha256": "0" * 64},
               "executor": {"id": "urn:test:executor"}, "requestedActionDigest": {"sha256": "0" * 64},
               "status": "refused", "performedAt": "2026-01-01T00:00:00Z"}
    bad = _resign_without(emit_outcome_receipt(outcome, _KEY), "executor")
    code, report = _verify_parent_with(tmp_path, bad)
    assert code == 2 and report.get("lineage_ok") is False and report.get("ok") is False


@pytest.mark.parametrize("predicate_type", ["https://example.org/other/v1"])
def test_a_foreign_predicate_type_is_not_judged_here(tmp_path, predicate_type):
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
                 "predicateType": predicate_type, "predicate": {"anything": True}}
    target = dsse.sign_envelope(rfc8785.dumps(statement), _KEY, payload_type=_INTOTO)
    code, report = _verify_parent_with(tmp_path, target)
    assert code == 0 and report["ok"] is True


# ---- the neighbours (Codex, round 1 of the review of this fix): the same rule on the two other commands ----

_OTHER_KEY = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
_OUTCOME = {"schemaVersion": "0.1.0", "outcomeId": "urn:test:o", "decisionRef": {"sha256": "e" * 64},
            "executor": {"id": "urn:test:executor"}, "requestedActionDigest": {"sha256": "b" * 64},
            "status": "refused", "performedAt": "2026-01-01T00:00:00Z"}
_RELATION = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:parent",
             "relationships": [{"relation": "retracts",
                                "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64},
                                "reasonCode": "withdrawal", "reason": "x", "declaredAt": "2026-01-01T00:00:00Z"}]}


def _parent(tmp_path, command: str):
    from proofbundle.relation_statement import emit_relation_statement
    env = {"decision": lambda: emit_decision_receipt(_decision("urn:test:parent"), _KEY, strict=False),
           "outcome": lambda: emit_outcome_receipt(_OUTCOME, _KEY),
           "relation-statement": lambda: emit_relation_statement(_RELATION, _KEY)}[command]()
    path = tmp_path / f"{command}.json"
    path.write_text(json.dumps(env), encoding="utf-8")
    return path


def _verify_with(tmp_path, command: str, target: dict | None) -> tuple[int, dict]:
    argv = [command, "verify", str(_parent(tmp_path, command)), "--pub", _PUB64, "--json"]
    if target is not None:
        attached = tmp_path / "target.json"
        attached.write_text(json.dumps(target), encoding="utf-8")
        argv += ["--with-related", str(attached), "--related-pub", _PUB64]
    return _invoke(argv)


_COMMANDS = ["decision", "outcome", "relation-statement"]


@pytest.mark.parametrize("command", _COMMANDS)
def test_the_parent_alone_verifies(tmp_path, command):
    code, report = _verify_with(tmp_path, command, None)
    assert code == 0 and report["ok"] is True


@pytest.mark.parametrize("command", _COMMANDS)
def test_an_invalid_decision_attachment_no_edge_names_fails_every_parent(tmp_path, command):
    bad = _resign_without(emit_decision_receipt(_decision("urn:test:other"), _KEY, strict=False), "decision")
    code, report = _verify_with(tmp_path, command, bad)
    assert code == 2 and report.get("lineage_ok") is False and report.get("ok") is False


@pytest.mark.parametrize("command", _COMMANDS)
def test_an_attachment_signed_under_another_key_fails_every_parent(tmp_path, command):
    foreign = emit_decision_receipt(_decision("urn:test:other"), _OTHER_KEY, strict=False)
    code, report = _verify_with(tmp_path, command, foreign)
    assert code == 2 and report.get("lineage_ok") is False and report.get("ok") is False


def _with_null_relationships() -> dict:
    statement = json.loads(dsse.load_payload(emit_decision_receipt(_decision("urn:test:other"), _KEY, strict=False)))
    statement["predicate"]["relationships"] = None
    statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(rfc8785.dumps(statement["predicate"])).hexdigest()
    return dsse.sign_envelope(rfc8785.dumps(statement), _KEY, payload_type=_INTOTO)


@pytest.mark.parametrize("command", _COMMANDS)
def test_an_attachment_with_null_relationships_is_judged_as_one_without_them(tmp_path, command):
    """docs/predicates/relation.md: on an attachment, `relationships: null` declares nothing."""
    code, report = _verify_with(tmp_path, command, _with_null_relationships())
    assert code == 0 and report["ok"] is True


@pytest.mark.parametrize("command", _COMMANDS)
def test_an_attachment_without_a_predicate_is_judged_as_before(tmp_path, command):
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
                 "predicateType": "https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1"}
    target = dsse.sign_envelope(rfc8785.dumps(statement), _KEY, payload_type=_INTOTO)
    code, report = _verify_with(tmp_path, command, target)
    assert code == 0 and report["ok"] is True


# ---- the relationships member of an attachment (the circle at 07f9ef3a, conformance case
# relation-malformed-relationships-successor): the relation profile judges it, with its own codes ----

def _resign_with(envelope: dict, member: str, value) -> dict:
    statement = json.loads(dsse.load_payload(envelope))
    statement["predicate"][member] = value
    statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(rfc8785.dumps(statement["predicate"])).hexdigest()
    return dsse.sign_envelope(rfc8785.dumps(statement), _KEY, payload_type=_INTOTO)


def _loaded(tmp_path, envelope: dict) -> dict:
    path = tmp_path / "attached.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    related, errors = cli._load_related([str(path)], _PUB)
    assert errors == []
    (entry,) = related.values()
    return entry


@pytest.mark.parametrize("value", [42, "x", {"a": 1}])
def test_unreadable_relationships_of_a_decision_attachment_are_left_to_the_relation_profile(tmp_path, value):
    """docs/predicates/relation.md gives an unreadable block on an attached neighbour its own code,
    RELATION_MALFORMED_SUCCESSOR; the structure check of the attachment does not take it over."""
    entry = _loaded(tmp_path, _resign_with(emit_decision_receipt(_decision("urn:test:other"), _KEY, strict=False),
                                           "relationships", value))
    assert entry["verified"] is True and entry["payload_malformed"] is None


def test_unreadable_relationships_of_a_relation_statement_attachment_fail_its_structure(tmp_path):
    """For a relation-statement, `relationships` is the required content of its type, so its structure check keeps it."""
    from proofbundle.relation_statement import emit_relation_statement
    entry = _loaded(tmp_path, _resign_with(emit_relation_statement(_RELATION, _KEY), "relationships", 42))
    assert entry["verified"] is False and entry["payload_malformed"]
