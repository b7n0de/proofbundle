"""`relation-statement verify` gives the lineage verdict of `verify_relationship_edges` over the same inputs.

Deep gate 6.6.0 at d8881edc, iteration 1, finding Z4, review round 2 of its fix: `verify_relation_statement` now judges
its edge with `relation._kanten_urteil` over one reading of the attached targets (`relation._related_lesen`), so that
the rule of B22 reads the same reading, where it called the public `verify_relationship_edges` before. The public
function is that same computation, but the review asked for a measurement over resolved and unresolved edges,
unverified targets, subject pins, malformed and cyclic ancestors and the depth limit, with the edge verdict compared
apart from the aggregate refusal of B22.

Each case pins the verdict it must reach, so the set cannot pass by covering only one kind of edge, and runs once
with a retraction and once with a successor relation, each without a policy and with a policy that carries a
`relations` section. The two keys the verifier stamps onto the lineage when such a section is judged under a passing
signature (`_stamp_lineage_origin`) are the only difference allowed, and they must be there exactly then. The
comparison holds at d8881edc as well, where the command still called the public function.
"""
from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import anchors, dsse
from proofbundle.relation import MAX_CHAIN_DEPTH, verify_relationship_edges
from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
_PUB = _KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_PUB64 = base64.b64encode(_PUB).decode("ascii")
#: What `verify_relation_statement` adds to a lineage it judged under a passing signature, and nothing else.
_STAMP = {"verified_successor_key_b64", "verified_origin"}

A, B, C = "a" * 64, "b" * 64, "c" * 64
SUBJECT_OF_TARGET = "d" * 64


def _digest(hex64: str) -> dict:
    return {"digestAlgorithm": "jcs-sha256-v1", "digest": hex64}


#: The relation of the statement's edge and a reason code for it: a retraction, and a successor relation, under
#: which the verifier stamps the lineage it judged.
RELATIONS = {"retracts": "withdrawal", "supersedes": "correction"}


def _edge(target: str, *, pin: str | None = None, relation: str = "retracts") -> dict:
    edge = {"relation": relation, "targetReceiptDigest": _digest(target), "reasonCode": RELATIONS[relation],
            "reason": "x", "declaredAt": "2026-01-01T00:00:00Z"}
    if pin is not None:
        edge["targetSubjectDigest"] = _digest(pin)
    return edge


def _ancestor_edge(target: str) -> dict:
    return {"relation": "derivedFrom", "targetReceiptDigest": _digest(target)}


def _target(*, verified=True, relationships=None, payload_malformed=None, subject=SUBJECT_OF_TARGET,
            state="present") -> dict:
    return {"verified": verified, "relationships": relationships, "payload_malformed": payload_malformed,
            "subject_digest": subject, "subject_digest_state": state, "verified_under": _PUB64}


def _chain(length: int) -> dict:
    """`length` attached targets, each deriving from the next; the edge of the statement names the first."""
    names = [f"{i:064x}" for i in range(1, length + 1)]
    out = {}
    for i, name in enumerate(names):
        nxt = names[i + 1] if i + 1 < len(names) else None
        out[name] = _target(relationships=[_ancestor_edge(nxt)] if nxt else None)
    return out


# (name, target the edge names, declared subject pin, related as a function of the statement's own content root,
#  the aggregate lineage the case must reach)
CASES = [
    ("nothing attached", A, None, lambda s: None, "DECLARED_UNRESOLVED"),
    ("an empty map", A, None, lambda s: {}, "DECLARED_UNRESOLVED"),
    ("another target attached", A, None, lambda s: {B: _target()}, "DECLARED_UNRESOLVED"),
    ("a verified target", A, None, lambda s: {A: _target()}, "VERIFIED"),
    ("an unverified target", A, None, lambda s: {A: _target(verified=False)}, "FAIL"),
    ("a target whose payload is malformed", A, None, lambda s: {A: _target(payload_malformed="not a statement")},
     "FAIL"),
    ("a target that is no object", A, None, lambda s: {A: "x"}, "FAIL"),
    ("an equal subject pin", A, SUBJECT_OF_TARGET, lambda s: {A: _target()}, "VERIFIED"),
    ("an unequal subject pin", A, C, lambda s: {A: _target()}, "FAIL"),
    ("a pin on an absent subject", A, SUBJECT_OF_TARGET, lambda s: {A: _target(subject=None, state="absent")},
     "FAIL"),
    ("a pin on an ambiguous subject", A, SUBJECT_OF_TARGET, lambda s: {A: _target(state="ambiguous")}, "FAIL"),
    ("a pin on a malformed subject", A, SUBJECT_OF_TARGET, lambda s: {A: _target(subject="zz", state="malformed")},
     "FAIL"),
    ("a cycle among the ancestors", A, None,
     lambda s: {A: _target(relationships=[_ancestor_edge(B)]), B: _target(relationships=[_ancestor_edge(A)])},
     "FAIL"),
    ("an ancestor that names the statement itself", A, None,
     lambda s: {A: _target(relationships=[_ancestor_edge(s)])}, "FAIL"),
    ("a malformed ancestor block", A, None,
     lambda s: {A: _target(relationships=[{"relation": "bogus", "targetReceiptDigest": _digest(B)}])}, "FAIL"),
    ("an unverified ancestor", A, None,
     lambda s: {A: _target(relationships=[_ancestor_edge(B)]), B: _target(verified=False)}, "FAIL"),
    ("a chain at the depth limit", f"{1:064x}", None, lambda s: _chain(MAX_CHAIN_DEPTH), "VERIFIED"),
    ("a chain past the depth limit", f"{1:064x}", None, lambda s: _chain(MAX_CHAIN_DEPTH + 1), "FAIL"),
    ("an attached retraction of the statement", A, None,
     lambda s: {A: _target(), B: _target(relationships=[_edge(s)])}, "VERIFIED"),
    ("an unreadable sibling entry", A, None, lambda s: {A: _target(), B: object()}, "VERIFIED"),
    ("a key that is no string", A, None, lambda s: {A: _target(), 5: _target()}, "VERIFIED"),
    ("related that is no map", A, None, lambda s: [(A, _target())], "FAIL"),
]


def _statement(edge: dict) -> tuple[dict, list, str]:
    predicate = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:parent", "relationships": [edge]}
    envelope = emit_relation_statement(predicate, _KEY)
    subject = anchors.statement_content_root(dsse.load_payload(envelope)).hex()
    return envelope, predicate["relationships"], subject


@pytest.mark.parametrize("policy", [None, {"relations": {}}], ids=["no policy", "relations policy"])
@pytest.mark.parametrize("relation", sorted(RELATIONS))
@pytest.mark.parametrize("name,target,pin,related_for,expected", CASES, ids=[c[0] for c in CASES])
def test_the_command_judges_the_edge_as_the_public_function_does(name, target, pin, related_for, expected, relation,
                                                                 policy):
    envelope, relationships, subject = _statement(_edge(target, pin=pin, relation=relation))
    related = related_for(subject)
    public = verify_relationship_edges(copy.deepcopy(relationships), _copy(related), subject_hex=subject)
    assert public["lineage"] == expected, (name, public)
    result = verify_relation_statement(envelope, _PUB, related=_copy(related), policy=copy.deepcopy(policy))
    assert result["crypto_ok"] is True
    lineage = result["lineage"]
    assert set(public) <= set(lineage), sorted(set(public) - set(lineage))
    assert set(lineage) - set(public) == (_STAMP if policy else set()), sorted(set(lineage) ^ set(public))
    assert {k: v for k, v in lineage.items() if k not in _STAMP} == public


def _copy(related):
    """A deep copy where it can be one; an entry that is no JSON value (`object()`) is handed on as it is."""
    if isinstance(related, dict):
        return {k: (v if type(v) is object else copy.deepcopy(v)) for k, v in related.items()}
    return copy.deepcopy(related)


def test_an_unattached_unverified_target_leaves_the_edge_verdict_and_fails_only_the_lineage_check():
    """B22 sits beside the edge verdict and never changes it: the edge still resolves VERIFIED, and only
    `lineage_ok` and `ok` turn."""
    envelope, relationships, subject = _statement(_edge(A))
    related = {A: _target(), B: _target(verified=False)}
    public = verify_relationship_edges(copy.deepcopy(relationships), copy.deepcopy(related), subject_hex=subject)
    result = verify_relation_statement(envelope, _PUB, related=copy.deepcopy(related))
    assert public["lineage"] == "VERIFIED" and [e["resolution"] for e in public["edges"]] == ["VERIFIED"]
    assert {k: v for k, v in result["lineage"].items() if k not in _STAMP} == public
    assert result["lineage_ok"] is False and result["ok"] is False
    assert any("relation:target_verification_failed" in e for e in result["errors"])
