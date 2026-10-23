"""CV1 (6.3.1): conformance/common_vocabulary.compare compares every axis that either side fills.

Until 6.3.1 only the axes the first side filled were compared. That is right for a case's expectation against a run,
where an axis the case does not pin is no part of its claim, and wrong between two observations: the Python<->Rust
differential (tools/pb_verify_rs/crosscheck.py) passes the Python label first, so an axis only the Rust side filled
was never compared and a disagreement on it passed. The cases below compare observed labels, built by
label_from_verify from verifier reports, in both directions; an expectation keeps its unpinned axes out, in either
position, and two labels that are no observations keep the rule of an expectation.

RED at 22aa954e: every case in which only the second side fills an axis, the symmetry over all label pairs, and an
expectation passed as the second side. The controls are green there and after.
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "conformance") not in sys.path:
    sys.path.insert(0, str(REPO / "conformance"))

import common_vocabulary as cv  # noqa: E402

REPORTS = {
    "lineage only": {"lineage": "FAIL"},
    "nested lineage only": {"lineage": {"lineage": "DECLARED_UNRESOLVED"}},
    "policy verdict only": {"policyVerdict": "DENY"},
    "predicate verdict only": {"predicate": {"decision": {"verdict": "REFUSE"}}},
}


@pytest.mark.parametrize("name", sorted(REPORTS))
def test_CV1_an_axis_only_the_other_side_fills_is_compared(name):
    python_side = cv.label_from_verify(0, {})
    other_side = cv.label_from_verify(0, REPORTS[name])
    ok, diffs = cv.compare(python_side, other_side)
    assert not ok and len(diffs) == 1, (name, diffs)


@pytest.mark.parametrize("name", sorted(REPORTS))
def test_CV1_control_an_axis_only_the_first_side_fills_is_compared(name):
    ok, diffs = cv.compare(cv.label_from_verify(0, REPORTS[name]), cv.label_from_verify(0, {}))
    assert not ok and len(diffs) == 1, (name, diffs)


def test_CV1_two_observed_labels_compare_the_same_in_both_directions():
    lineages = [None, "VERIFIED", "FAIL", "NOT_EVALUATED", "DECLARED_UNRESOLVED"]
    verdicts = [None, "ALLOW", "DENY"]
    labels = [cv.label_from_verify(rc, {"lineage": lin, "policyVerdict": ver})
              for rc in (0, 3) for lin in lineages for ver in verdicts]
    for a, b in itertools.product(labels, repeat=2):
        assert cv.compare(a, b)[0] == cv.compare(b, a)[0], (a, b)
        assert cv.compare(a, b)[0] == all(cv._axis_equal(a[x], b[x]) for x in cv.AXES), (a, b)


def test_CV1_control_an_absent_lineage_and_NOT_EVALUATED_are_one_fact_on_both_sides():
    a, b = cv.label_from_verify(0, {}), cv.label_from_verify(0, {"lineage": "NOT_EVALUATED"})
    assert cv.compare(a, b)[0] and cv.compare(b, a)[0]


def test_CV1_an_expectation_leaves_its_unpinned_axes_out_in_either_position():
    want = cv.expected_label({"exitCode": 0})
    got = cv.label_from_verify(0, {"lineage": "FAIL", "policyVerdict": "DENY"})
    assert cv.compare(want, got) == (True, [])
    assert cv.compare(got, want) == (True, [])
    assert isinstance(want, dict) and want["lineage"] is None


def test_CV1_control_an_expectation_still_fails_a_pinned_axis_the_run_does_not_fill():
    want = cv.expected_label({"exitCode": 0, "lineage": "VERIFIED"})
    ok, diffs = cv.compare(want, cv.label_from_verify(0, {}))
    assert not ok and any("lineage" in d for d in diffs), diffs


def test_CV1_control_two_plain_labels_keep_the_rule_of_an_expectation():
    """A label that is no ObservedLabel is read as an expectation, as before: only the axes the first side pins count
    (the rule the conformance runner and the expectation check of the Rust differential rely on)."""
    plain = {"exitClass": "VERIFIED", "lineage": None, "policyVerdict": None}
    assert cv.compare(plain, dict(plain, policyVerdict="DENY")) == (True, [])
    assert cv.compare(dict(plain, policyVerdict="DENY"), plain)[0] is False


def test_CV1_label_from_verify_says_it_is_an_observation():
    label = cv.label_from_verify(0, {"lineage": "FAIL"})
    assert isinstance(label, cv.ObservedLabel) and label == {"exitClass": cv.exit_class(0), "lineage": "FAIL",
                                                               "policyVerdict": None}
    assert not isinstance(cv.expected_label({"exitCode": 0}), cv.ObservedLabel)
