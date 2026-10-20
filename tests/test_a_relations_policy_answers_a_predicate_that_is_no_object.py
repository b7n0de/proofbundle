"""A verifier with a relations policy answers a signed statement whose predicate is no object.

The second reading of 4be8f120 (F2): `verify_decision_receipt` and `verify_outcome_receipt` bound `_sw`, the
one reading of `supersededByAttached`, inside the block that reads an object predicate, and read it again in the
relations gate, which runs on any signature that verifies. A correctly signed statement whose predicate is
`5`, `1.5`, `true`, null, a string or a list, checked under a policy with a `relations` section, raised
`UnboundLocalError` out of the two verifiers: 14 of the 42 cases below on 4be8f120 and on main 570dd164. Both
verifiers bind it before that block now and answer each case.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import decision, dsse, outcome

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()
VERIFIERS = {
    "decision": (decision.verify_decision_receipt, decision.DECISION_RECEIPT_PREDICATE_TYPE),
    "outcome": (outcome.verify_outcome_receipt, outcome.ACTION_OUTCOME_PREDICATE_TYPE),
}
PREDICATES = [5, 1.5, True, None, "x", [1], []]
POLICIES = [{"relations": {}}, None, {}]


def _signed(predicate_type, predicate):
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
                 "predicateType": predicate_type, "predicate": predicate}
    body = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    return dsse.sign_envelope(body, SK, payload_type="application/vnd.in-toto+json")


@pytest.mark.parametrize("policy", POLICIES, ids=json.dumps)
@pytest.mark.parametrize("predicate", PREDICATES, ids=repr)
@pytest.mark.parametrize("name", sorted(VERIFIERS))
def test_the_verifier_answers_instead_of_raising(name, predicate, policy):
    verify, predicate_type = VERIFIERS[name]
    kwargs = {} if policy is None else {"policy": policy}
    result = verify(_signed(predicate_type, predicate), PK, **kwargs)
    assert result["crypto_ok"] is True, result
    assert result["ok"] is False, result
