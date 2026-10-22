"""F1 of CODEX-KLASSENSUCHE-631-01 (class F, at f6ea5cc3) and its matrix630 sibling: the differential cell C8.2
computes the agreement itself and holds the report's flags against it.

Measured at f6ea5cc3 on the unchanged C8.2 admission path, with the isolated fixture `welt` and `_rumpf`/`_signiere`
of `tests/test_freigabe_evidenz_provenienz_l5_g7_02.py` (a real local git tree, anchor committed first, candidate
second; candidate, tree, dist, anchor, version, role, freshness and signature checks all run; only `m.REPO` and
`m.VERSION_UNDER_TEST` are set to the test tree and 9.9.9). The signed report has one row of the form
`tools/pb_verify_rs/crosscheck.py:798-803`: expected and python VERIFIED/VERIFIED, python_exit 0; rust
CRYPTO_FAIL/FAIL, rust_exit 1; agree_python_rust, rust_reproduces_expectation and all_agree true. The cell answered
PASS, "Python==Rust on every row". The sibling (delta, matrix630 at 479e01ee): `compare(py_label, rust_label)`
checks only the axes the Python side fills. Controls: the consistent row with Rust exit 0 passes; the contradicting
row with its flags set to false fails; the same report under a foreign test key fails.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from test_freigabe_evidenz_provenienz_l5_g7_02 import (  # noqa: F401
    VERSION, _braucht_krypto, _matrix_modul, _rumpf, _signiere, welt)

REPO = Path(__file__).resolve().parents[1]
REL = "audit_artifacts/360/rust_differential_matrix.json"
VERIFIED = {"exitClass": "VERIFIED", "lineage": "VERIFIED", "policyVerdict": None}


def _row(**change) -> dict:
    row = {"caseId": "r", "kind": "outcome_relation", "expected": dict(VERIFIED), "python": dict(VERIFIED),
           "rust": dict(VERIFIED), "python_exit": 0, "rust_exit": 0, "agree_python_rust": True,
           "rust_reproduces_expectation": True}
    row.update(change)
    return row


def _report(*rows, all_agree=True) -> dict:
    return {"schema": "proofbundle.rust_relation_differential_matrix.v1", "total_relation_vectors": len(rows),
            "all_agree": all_agree, "rows": list(rows)}


def _cell(world, report: dict, key=None):
    target = world["repo"] / REL
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(_signiere(_rumpf(world, report), key or world["key"])), encoding="utf-8")
    m = _matrix_modul()
    m.REPO = world["repo"]
    m.VERSION_UNDER_TEST = VERSION
    verdict, reason = m.c8_2_differential_agrees()
    return verdict, reason, m


RUST_FAILS = {"rust": {"exitClass": "CRYPTO_FAIL", "lineage": "FAIL", "policyVerdict": None}, "rust_exit": 1}


@_braucht_krypto
def test_a_row_whose_labels_disagree_fails_whatever_its_flags_say(welt):  # noqa: F811
    verdict, reason, m = _cell(welt, _report(_row(**RUST_FAILS)))
    assert verdict == m.FAIL and "contradict their own labels" in reason, reason


@_braucht_krypto
def test_an_axis_only_rust_fills_is_compared_too(welt):  # noqa: F811
    rust = dict(VERIFIED, policyVerdict="DENY")
    verdict, reason, m = _cell(welt, _report(_row(rust=rust)))
    assert verdict == m.FAIL and "contradict their own labels" in reason, reason


@_braucht_krypto
@pytest.mark.parametrize("change", [
    {"expected": None}, {"python": {"exitClass": "VERIFIED"}}, {"rust_exit": "0"}, {"agree_python_rust": 1},
    {"python": {"exitClass": "PASSED", "lineage": "VERIFIED", "policyVerdict": None}},
], ids=["no expected label", "a label short of axes", "an exit code as text", "a flag as a number",
        "a word outside the vocabulary"])
def test_an_incomplete_row_is_no_evidence(welt, change):  # noqa: F811
    row = _row()
    row.update(change)
    verdict, reason, m = _cell(welt, _report(row))
    assert verdict == m.FAIL and "without the three labels" in reason, reason


@_braucht_krypto
def test_an_exit_code_that_is_not_its_label_s_class_fails(welt):  # noqa: F811
    verdict, reason, m = _cell(welt, _report(_row(python_exit=1)))
    assert verdict == m.FAIL and "contradict their own labels" in reason, reason


@_braucht_krypto
def test_all_agree_that_is_not_the_rows_conjunction_fails(welt):  # noqa: F811
    verdict, reason, m = _cell(welt, _report(_row(), all_agree=False))
    assert verdict == m.FAIL and "contradicts itself" in reason, reason


# --- controls -----------------------------------------------------------------------------------------------------

@_braucht_krypto
def test_control_the_consistent_row_passes(welt):  # noqa: F811
    verdict, reason, m = _cell(welt, _report(_row()))
    assert verdict == m.PASS and "Python==Rust on every row" in reason, reason


@_braucht_krypto
def test_control_the_contradiction_with_honest_flags_fails(welt):  # noqa: F811
    row = _row(**RUST_FAILS, agree_python_rust=False, rust_reproduces_expectation=False)
    verdict, reason, m = _cell(welt, _report(row, all_agree=False))
    assert verdict == m.FAIL and "disagree on 1" in reason, reason


@_braucht_krypto
def test_control_a_foreign_test_key_fails(welt):  # noqa: F811
    verdict, _reason, m = _cell(welt, _report(_row()), key=welt["foreign"])
    assert verdict == m.FAIL


def test_control_the_committed_report_holds_complete_agreeing_rows():
    rows = json.loads((REPO / REL).read_text(encoding="utf-8"))["rows"]
    assert len(rows) == 45
    assert _matrix_modul()._differential_rows(copy.deepcopy(rows)) == ([], [], [])


def test_agree_compares_every_axis_either_side_fills_and_compare_only_the_pinned_ones():
    sys.path.insert(0, str(REPO / "conformance"))
    from common_vocabulary import agree, compare
    python, rust = dict(VERIFIED), dict(VERIFIED, policyVerdict="DENY")
    assert compare(python, rust)[0] is True, "compare stays the expectation-against-observation check"
    assert agree(python, rust)[0] is False and agree(rust, python)[0] is False
    assert agree(dict(VERIFIED, lineage=None), dict(VERIFIED, lineage="NOT_EVALUATED"))[0] is True
