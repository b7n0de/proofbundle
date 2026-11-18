"""An anchored executor key attests only the executor ids its Trust Pack names for it.

docs/predicates/action-outcome.md section 7 listed the independent attestation of `executor.id` via a trust-pack role
binding as closed, while the check bound only `executor.keyId` to the signing key: a Trust Pack named no identifier per
key. Measured at main e1fec863: one key in outcomeExecutors, anchored by the genesis digest, signed two outcomes that
differ only in `executor.id`, and both verified with `executor_role_trusted` True and `ok` True.
draft-gruszka-audit-decision-receipts-05 section 3.4 step 5 asks that the trust policy permit the outcome-signing key to
attest the identifier the outcome names.

A key entry of a Trust Pack may now carry `executorIds`, the identifiers that key attests. When it does, an outcome whose
`executor.id` is not among them is not trusted (`executor_id_bound` False). A key entry without `executorIds` binds no
identifier: `executor_id_bound` is None and the result says so in a warning. Whether such a pack should fail closed is
the owner's choice and not made here.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from proofbundle.budget import DEFAULT_BUDGET
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt
from proofbundle.trust_pack import sign_trust_pack, validate_trust_pack_predicate, verify_trust_pack
from test_security_fix_620_trustpack_n45_anchor import _content_root, _genesis_pack, _outcome_pred

_EXPECTED = "executor:runner-7"
_FOREIGN = "executor:someone-else"


def _pack_and_signer(executor_ids=None):
    sk = generate_signer()
    pub = sk.public_key().public_bytes_raw()
    pack, root_sks = _genesis_pack(pub)
    if executor_ids is not None:
        pack["keys"]["kid-exec"]["executorIds"] = list(executor_ids)
    return pack, root_sks, sk, pub


def _verify(pack, sk, pub, executor_id):
    p = _outcome_pred()
    p["executor"] = {"id": executor_id, "keyId": "kid-exec"}
    return verify_outcome_receipt(emit_outcome_receipt(copy.deepcopy(p), sk), pub, trust_pack=pack,
                                  trust_pack_expected_genesis_digest=_content_root(pack))


def test_control_a_key_is_trusted_for_the_executor_id_its_pack_names():
    pack, _, sk, pub = _pack_and_signer([_EXPECTED])
    r = _verify(pack, sk, pub, _EXPECTED)
    assert r["executor_role_trusted"] is True and r["ok"] is True, r


def test_the_result_says_the_executor_id_is_bound():
    pack, _, sk, pub = _pack_and_signer([_EXPECTED])
    assert _verify(pack, sk, pub, _EXPECTED).get("executor_id_bound") is True


def test_a_key_does_not_attest_an_executor_id_its_pack_does_not_name():
    pack, _, sk, pub = _pack_and_signer([_EXPECTED])
    r = _verify(pack, sk, pub, _FOREIGN)
    assert r["executor_key_bound"] is True, "precondition: the key itself is the pack's key for kid-exec"
    assert r["executor_role_trusted"] is False and r["ok"] is False, r
    assert r["automation"]["safeForAutomation"] is False, r["automation"]
    assert r.get("executor_id_bound") is False, r
    assert "EXECUTOR_ID_NOT_ATTESTED" in r["automation"]["automationBlockers"], r["automation"]
    assert any("EXECUTOR_ID_NOT_ATTESTED" in e for e in r["errors"]), r["errors"]


def test_one_key_attests_each_of_several_executor_ids():
    pack, _, sk, pub = _pack_and_signer([_EXPECTED, "executor:runner-8"])
    for executor_id in (_EXPECTED, "executor:runner-8"):
        assert _verify(pack, sk, pub, executor_id)["executor_role_trusted"] is True, executor_id
    assert _verify(pack, sk, pub, _FOREIGN)["executor_role_trusted"] is False


def test_a_key_without_executor_ids_binds_no_executor_id_and_says_so():
    pack, _, sk, pub = _pack_and_signer(None)
    r = _verify(pack, sk, pub, _FOREIGN)
    assert any("EXECUTOR_ID_NOT_BOUND" in w for w in r["warnings"]), r["warnings"]
    assert r.get("executor_id_bound") is None, r
    # The owner's option A: such a pack keeps the verdict it had. A check that asked for `executor_id_bound is
    # True` would refuse every pack without executorIds, and the two asserts above would still pass.
    assert r["executor_role_trusted"] is True and r["ok"] is True, r


@pytest.mark.parametrize("executor_ids", [_EXPECTED + "-and-more", [7, _EXPECTED], ["", _EXPECTED],
                                         {_EXPECTED: True}],
                         ids=["a-string-holding-the-id", "a-list-with-a-number-and-the-id",
                              "a-list-with-an-empty-id-and-the-id", "an-object"])
def test_a_pack_handed_in_with_malformed_executor_ids_trusts_no_executor_id(executor_ids):
    # verify_outcome_receipt does not validate a pack it is handed; a string here would answer `in` as a
    # substring test and an object by its keys. The two lists hold the expected id itself, so only the check of
    # every element refuses them, not the membership test.
    pack, _, sk, pub = _pack_and_signer(None)
    pack["keys"]["kid-exec"]["executorIds"] = executor_ids
    r = _verify(pack, sk, pub, _EXPECTED)
    assert r["executor_role_trusted"] is False and r["ok"] is False, r
    assert r.get("executor_id_bound") is False, r


@pytest.mark.parametrize("executor_ids", [[], [""], [7], [_EXPECTED, _EXPECTED], _EXPECTED, None],
                         ids=["empty", "empty-id", "not-a-string", "twice", "a-string", "null"])
def test_the_pack_validator_refuses_malformed_executor_ids(executor_ids):
    pack, _, _, _ = _pack_and_signer(None)
    pack["keys"]["kid-exec"]["executorIds"] = executor_ids
    errors = validate_trust_pack_predicate(pack)
    assert any("executorIds must be" in e for e in errors), errors


def test_a_pack_with_executor_ids_is_signed_validates_and_verifies():
    pack, root_sks, _, _ = _pack_and_signer([_EXPECTED])
    assert validate_trust_pack_predicate(pack) == []
    envelope = sign_trust_pack(pack, root_sks)
    r = verify_trust_pack(envelope)
    assert r["ok"] is True and r["structure_ok"] is True, r


def _with_extra_keys(pack, n):
    """The pack with real Ed25519 keys added until keys holds n entries, and their ids."""
    extra = []
    while len(pack["keys"]) < n:
        kid = "kid-extra-%d" % len(pack["keys"])
        pack["keys"][kid] = {"publicKey": base64.b64encode(generate_signer().public_key().public_bytes_raw())
                             .decode("ascii")}
        extra.append(kid)
    return extra


_BOUND = DEFAULT_BUDGET.witnesses


@pytest.mark.parametrize("count", [_BOUND, _BOUND + 1], ids=["at-the-bound", "one-past-the-bound"])
def test_executor_ids_are_held_at_the_published_bound(count):
    pack, _, _, _ = _pack_and_signer(["executor:%d" % i for i in range(count)])
    errors = validate_trust_pack_predicate(pack)
    assert (errors == []) is (count <= _BOUND), errors


@pytest.mark.parametrize("count", [_BOUND, _BOUND + 1], ids=["at-the-bound", "one-past-the-bound"])
def test_the_keys_map_is_held_at_the_published_bound(count):
    # A neighbour of executorIds under the same bound: the keys map.
    pack, _, _, _ = _pack_and_signer(None)
    _with_extra_keys(pack, count)
    assert len(pack["keys"]) == count
    errors = validate_trust_pack_predicate(pack)
    assert (errors == []) is (count <= _BOUND), errors
    assert any(("keys has %d entries" % count) in e for e in errors) is (count > _BOUND), errors


@pytest.mark.parametrize("count", [_BOUND, _BOUND + 1], ids=["at-the-bound", "one-past-the-bound"])
def test_a_role_s_key_ids_are_held_at_the_published_bound(count):
    # The other neighbour: a role's keyIds. At the bound every key id is a distinct key of the pack; one past it,
    # the ids repeat the pack's three keys, so the keys map stays below its own bound.
    pack, _, _, _ = _pack_and_signer(None)
    if count <= _BOUND:
        _with_extra_keys(pack, count)
        kids = list(pack["keys"])
    else:
        kids = [list(pack["keys"])[i % 3] for i in range(count)]
    pack["roles"]["outcomeExecutors"]["keyIds"] = kids
    assert len(kids) == count
    errors = validate_trust_pack_predicate(pack)
    assert (errors == []) is (count <= _BOUND), errors
    assert any(("keyIds has %d entries" % count) in e for e in errors) is (count > _BOUND), errors


def test_the_schema_states_the_bounds_the_validator_holds():
    """Codex reading of 9 November 2026: the validator refused 257 executorIds while the schema accepted them.
    The schema now states each bound of the validator on keys, a role's keyIds and executorIds."""
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "trust-pack-v0.1.schema.json")
                        .read_text(encoding="utf-8"))
    keys = schema["properties"]["keys"]
    assert (keys["minProperties"], keys["maxProperties"]) == (1, _BOUND)
    assert schema["$defs"]["role"]["properties"]["keyIds"]["maxItems"] == _BOUND
    executor_ids = keys["additionalProperties"]["properties"]["executorIds"]
    assert (executor_ids["minItems"], executor_ids["maxItems"]) == (1, _BOUND)


def test_control_an_outcome_without_a_trust_pack_reports_no_executor_id_binding():
    sk = generate_signer()
    p = _outcome_pred()
    r = verify_outcome_receipt(emit_outcome_receipt(p, sk), sk.public_key().public_bytes_raw())
    assert r["ok"] is True and r.get("executor_id_bound") is None, r
