"""E1 of the class search for 6.3.1 at f6ea5cc3: a test-result statement names at least one case, lists or not.

`validate_test_result_statement` required a named case, and derived the result from the case lists, only when
at least one of ``passedTests``, ``warnedTests`` and ``failedTests`` was present. Three empty lists were refused
("a statement over zero cases cannot be PASSED, WARNED or FAILED"); with all three removed from a valid PASSED
statement the validator returned no error, the signing helper signed it, the DSSE signature verified under the
external test key, and `join_test_result` reported all four equalities and ``ok``: evidence of no case at all,
joined as a passing run. The in-toto predicate makes each list optional, so an absent list is now read as an
empty one, and the rule and the derivation run whether the lists are there or not.

The inputs are the report's: the two-case corpus ``a, b`` measured into a vector set, the build of
`_valid_block`, both cases full and passed, version 6.1.0, the test key from the seed ``bytes(range(32))``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import dsse
from proofbundle import verifier_block as VB

LISTS = ("passedTests", "warnedTests", "failedTests")
BUILD = {"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 77}


def _corpus(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps({"schema": "proofbundle.conformance.manifest.v1",
                                                    "cases": ["a", "b"]}))
    for case in ("a", "b"):
        (root / case).mkdir(exist_ok=True)
        (root / case / "case.json").write_text(json.dumps({"caseId": case}))
    return VB.measure_vector_set(root)


def _statement(vector_set: dict, results=(("a", True, "full"), ("b", True, "full"))) -> dict:
    return VB.build_test_result_statement(
        build=BUILD, vector_set=vector_set, version="6.1.0",
        results=[{"caseId": c, "ok": ok, "scope": scope} for c, ok, scope in results])


def _block_citing(statement: dict, vector_set: dict) -> dict:
    """A block that cites ``statement`` by its result and canonical digest, built without `test_result_ref`,
    which refuses an invalid statement: the join has to judge the statement on its own."""
    ref = {"predicateType": VB.TEST_RESULT_PREDICATE_TYPE, "result": statement["predicate"]["result"],
           "statementDigest": {"sha256": VB.statement_digest(statement)}}
    return VB.build_verifier_block(build=BUILD, version="6.1.0", vector_set=vector_set, test_result=ref)


def _without(statement: dict, *names: str) -> dict:
    for name in names:
        statement["predicate"].pop(name)
    return statement


@pytest.fixture
def vector_set(tmp_path):
    return _corpus(tmp_path / "corpus")


def test_without_any_list_the_validator_refuses(vector_set):
    errs = VB.validate_test_result_statement(_without(_statement(vector_set), *LISTS))
    assert any("names no case" in e for e in errs), errs


def test_without_any_list_no_result_word_is_accepted(vector_set):
    s = _without(_statement(vector_set), *LISTS)
    for result in ("PASSED", "WARNED", "FAILED"):
        s["predicate"]["result"] = result
        assert any("names no case" in e for e in VB.validate_test_result_statement(s)), result


def test_without_any_list_the_reference_and_the_signing_helper_refuse(vector_set):
    s = _without(_statement(vector_set), *LISTS)
    with pytest.raises(VB.VerifierBlockError, match="names no case"):
        VB.test_result_ref(s)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with pytest.raises(VB.VerifierBlockError, match="names no case"):
        VB.sign_test_result_statement(s, key)


def test_without_any_list_the_join_is_not_ok(vector_set):
    s = _without(_statement(vector_set), *LISTS)
    j = VB.join_test_result(_block_citing(s, vector_set), s)
    assert j["ok"] is False
    assert any("names no case" in e for e in j["errors"]), j


@pytest.mark.parametrize("missing", LISTS)
def test_a_single_missing_list_is_read_as_an_empty_one(vector_set, missing):
    """Two named passed cases: without ``passedTests`` nothing is named, without one of the two empty lists the
    statement is the same as before. A mixed run derives FAILED: without ``failedTests`` the lists that remain
    derive WARNED and contradict the result, without one of the other two it stays a FAILED run."""
    passed_run = _without(_statement(vector_set), missing)
    errs = VB.validate_test_result_statement(passed_run)
    if missing == "passedTests":
        assert any("names no case" in e for e in errs), errs
    else:
        assert errs == []
    mixed = _without(_statement(vector_set, (("a", True, "full"), ("b", True, "partial"), ("c", False, "full"))),
                     missing)
    errs = VB.validate_test_result_statement(mixed)
    if missing == "failedTests":
        assert any("contradicts its own case lists" in e and "'WARNED'" in e for e in errs), errs
    else:
        assert errs == []


def test_three_empty_lists_are_refused_as_before(vector_set):
    s = _statement(vector_set)
    for name in LISTS:
        s["predicate"][name] = []
    assert any("names no case" in e for e in VB.validate_test_result_statement(s))


def test_the_complete_statement_validates_signs_and_joins(vector_set):
    s = _statement(vector_set)
    assert VB.validate_test_result_statement(s) == []
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    envelope = VB.sign_test_result_statement(s, key)
    assert dsse.verify_envelope(envelope, key.public_key().public_bytes_raw(),
                                payload_type=VB.INTOTO_STATEMENT_PAYLOAD_TYPE)
    block = VB.build_verifier_block(build=BUILD, version="6.1.0", vector_set=vector_set,
                                    test_result=VB.test_result_ref(s))
    assert VB.join_test_result(block, s)["ok"] is True


def test_a_foreign_vector_set_digest_still_fails_the_join(vector_set):
    s = _statement(vector_set)
    foreign = {**vector_set, "digest": {"sha256": "8" * 64}}
    block = VB.build_verifier_block(build=BUILD, version="6.1.0", vector_set=foreign,
                                    test_result=VB.test_result_ref(s))
    assert VB.join_test_result(block, s)["ok"] is False


# ── the lens on ca844d0c: a nameless entry, a falsy value in place of a list, and the export's neighbour ──

NAMELESS = ("", " ", "\t\n", "\u200b", "\u00a0")


@pytest.mark.parametrize("name", NAMELESS, ids=("empty", "space", "tab-newline", "zero-width-space", "no-break-space"))
@pytest.mark.parametrize("where", LISTS)
def test_an_entry_that_names_nothing_is_no_named_case(vector_set, where, name):
    """P2 of the lens: ``passedTests: [""]`` (or a space, a tab, a zero-width or a no-break space) and no other
    list counted as a named case, and the statement was signed and joined as a run over nothing."""
    s = _without(_statement(vector_set), *LISTS)
    s["predicate"][where] = [name]
    s["predicate"]["result"] = {"passedTests": "PASSED", "warnedTests": "WARNED", "failedTests": "FAILED"}[where]
    errs = VB.validate_test_result_statement(s)
    assert any(f"predicate.{where} holds an entry that names no case" in e for e in errs), errs
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with pytest.raises(VB.VerifierBlockError, match="names no case"):
        VB.sign_test_result_statement(s, key)
    assert VB.join_test_result(_block_citing(s, vector_set), s)["ok"] is False


def test_a_named_entry_beside_a_nameless_one_is_still_refused(vector_set):
    s = _statement(vector_set)
    s["predicate"]["passedTests"] = ["a", " "]
    assert any("holds an entry that names no case" in e for e in VB.validate_test_result_statement(s))


@pytest.mark.parametrize("case_id", NAMELESS[1:])
def test_the_producer_refuses_a_case_id_that_names_nothing(vector_set, case_id):
    with pytest.raises(VB.VerifierBlockError, match="without a caseId"):
        _statement(vector_set, (("a", True, "full"), (case_id, True, "full")))


@pytest.mark.parametrize("value", (None, False, 0, "", {}), ids=("null", "false", "zero", "empty-text", "empty-object"))
@pytest.mark.parametrize("where", ("warnedTests", "failedTests"))
def test_a_falsy_value_in_place_of_a_list_is_not_an_empty_list(vector_set, where, value):
    """P3 of the lens: a mutant that reads a falsy value that is no list as an empty list survived every test.
    An absent list is an empty one; a present ``null`` or ``0`` is a list of the wrong type."""
    s = _statement(vector_set)
    s["predicate"][where] = value
    assert f"predicate.{where} must be a list of strings" in VB.validate_test_result_statement(s)


def _export_parts():
    import base64
    from proofbundle import intoto
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate", comparator=">=", threshold="0.80",
        score="0.92", n=500, model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-01T12:00:00Z",
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    envelope = intoto.export_intoto_dsse(claim, signer)
    statement = json.loads(base64.b64decode(envelope["payload"]))

    def verify(changed: dict) -> dict:
        body = intoto._serialize_statement(changed, changed.get("contentRootAlg", intoto.CONTENT_ROOT_ALG))
        env = dsse.sign_envelope(body, signer, payload_type=intoto.TEST_RESULT_PAYLOAD_TYPE)
        return intoto.verify_intoto_dsse(env, signer.public_key().public_bytes_raw())

    return statement, verify


def test_the_export_without_its_case_lists_or_its_result_does_not_verify():
    """P2 of the lens, the neighbour `intoto._verdict_agreement`: with the case lists, or the lists and
    ``result``, removed from an export and signed again, `verify_intoto_dsse` said ok=True, while three empty
    lists failed. The unchanged export is the control."""
    import copy
    statement, verify = _export_parts()
    assert verify(copy.deepcopy(statement))["ok"] is True
    no_lists = copy.deepcopy(statement)
    for name in LISTS:
        no_lists["predicate"].pop(name, None)
    assert verify(no_lists)["ok"] is False
    no_result = copy.deepcopy(no_lists)
    no_result["predicate"].pop("result")
    assert verify(no_result)["ok"] is False
    only_result_gone = copy.deepcopy(statement)
    only_result_gone["predicate"].pop("result")
    assert verify(only_result_gone)["ok"] is False


def test_without_a_suite_the_export_writes_no_list_and_none_is_asked_for():
    """The export writes a case list only when the claim has a suite, so a verdict of ours without a suite
    and without lists is one the export produces; the rule asks for the list only when it knows the suite."""
    from proofbundle import intoto
    assert intoto._verdict_agreement({"result": "PASSED"}, [(True, None)]) == []
    grund = intoto._verdict_agreement({"result": "PASSED"}, [(True, "safety-refusal")])
    assert grund and grund[0][0] == "passedTests", grund
