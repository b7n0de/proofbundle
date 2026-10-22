"""E1 of CODEX-KLASSENSUCHE-631-01 (class E, at f6ea5cc3): absent case lists are not stronger than empty ones.

Measured at f6ea5cc3: from a valid two-case PASSED test-result statement only ``passedTests``, ``warnedTests`` and
``failedTests`` were removed. ``validate_test_result_statement`` returned ``[]``, the signing helper signed it, the
DSSE signature verified with the external test key, ``predicate.result`` stayed ``PASSED`` and ``join_test_result``
reported all four equalities and ``ok=True``. Three present empty lists are refused ("a statement over zero cases
cannot be PASSED, WARNED or FAILED"). The rule that a statement names at least one case, and the derivation of the
result from the lists, now hold whether a list is present or not. Controls: the complete statement joins; three empty
lists and a foreign corpus digest still fail; a statement that carries only the lists it needs stays valid.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import verifier_block as VB

BUILD = {"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 77}
VECTORS = {"name": "proofbundle.conformance.manifest.v1", "digest": {"sha256": "2" * 64}, "cases": 2}
LISTS = ("passedTests", "warnedTests", "failedTests")
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))              # the repository's test seed
ZERO = "names no case in any of its lists"


def _statement(results=(("a", True, "full"), ("b", True, "full"))) -> dict:
    return VB.build_test_result_statement(
        build=BUILD, vector_set=VECTORS, version="6.1.0",
        results=[{"caseId": c, "ok": ok, "scope": scope} for c, ok, scope in results])


def _block_for(statement: dict) -> dict:
    return VB.build_verifier_block(build=BUILD, vector_set=VECTORS, version="6.1.0",
                                   test_result=VB.test_result_ref(statement))


def _without(statement: dict, *fields) -> dict:
    for field in fields:
        statement["predicate"].pop(field)
    return statement


def test_a_statement_without_any_case_list_is_no_test_result():
    s = _without(_statement(), *LISTS)
    assert s["predicate"]["result"] == "PASSED"
    assert any(ZERO in e for e in VB.validate_test_result_statement(s))
    with pytest.raises(VB.VerifierBlockError, match=ZERO):
        VB.sign_test_result_statement(s, KEY)
    with pytest.raises(VB.VerifierBlockError, match=ZERO):
        VB.test_result_ref(s)


def test_the_join_refuses_it_beside_a_block_that_cites_it():
    complete = _statement()
    block = _block_for(complete)
    stripped = _without(_statement(), *LISTS)
    block["testResult"]["statementDigest"] = {"sha256": VB.statement_digest(stripped)}   # cite the stripped bytes
    r = VB.join_test_result(block, stripped)
    assert r["ok"] is False and any(ZERO in e for e in r["errors"]), r


@pytest.mark.parametrize("result", ["PASSED", "WARNED", "FAILED"])
def test_no_headline_stands_without_a_named_case(result):
    s = _without(_statement(), *LISTS)
    s["predicate"]["result"] = result
    assert any(ZERO in e for e in VB.validate_test_result_statement(s))


@pytest.mark.parametrize("kept", LISTS)
def test_one_list_present_and_empty_the_others_absent_is_no_test_result(kept):
    s = _without(_statement(), *(k for k in LISTS if k != kept))
    s["predicate"][kept] = []
    assert any(ZERO in e for e in VB.validate_test_result_statement(s))


def test_a_headline_the_present_lists_do_not_derive_is_refused_with_the_others_absent():
    s = _without(_statement(), "passedTests", "warnedTests")
    s["predicate"]["failedTests"] = ["a"]
    errs = VB.validate_test_result_statement(s)
    assert any("contradicts its own case lists" in e for e in errs), errs


# --- controls -----------------------------------------------------------------------------------------------------

def test_control_the_complete_statement_joins():
    s = _statement()
    assert VB.validate_test_result_statement(s) == []
    assert VB.join_test_result(_block_for(s), s)["ok"] is True


def test_control_three_empty_lists_are_still_refused():
    s = _statement()
    for field in LISTS:
        s["predicate"][field] = []
    assert any(ZERO in e for e in VB.validate_test_result_statement(s))


def test_control_a_foreign_corpus_digest_does_not_join():
    s = _statement()
    block = _block_for(s)
    block["vectorSet"]["digest"] = {"sha256": "3" * 64}
    assert VB.join_test_result(block, s)["ok"] is False


def test_control_only_the_list_that_names_the_cases_is_enough():
    s = _without(_statement(), "warnedTests", "failedTests")
    assert s["predicate"]["passedTests"] == ["a", "b"]
    assert VB.validate_test_result_statement(s) == []
    assert VB.join_test_result(_block_for(s), s)["ok"] is True
