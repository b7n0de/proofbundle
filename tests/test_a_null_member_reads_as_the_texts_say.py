"""Three sentences on `null` hold the reference to what they say (pull request 437, threads 4420117777 and 4420117784).

conformance/README.md said that an `absence_assertions` which is present and not an array of objects fires R6, and the
field table of docs/AGENT_REVIEW_PREDICATE.md said that `times.declaredAt` is an RFC 3339 time. The reference reads
`absence_assertions: null` as an absent member, and it accepts `declaredAt: null` as long as the member is present. The
texts now say so, and a third sentence names where the two layers part: in an agent-review coverage, a CAP-1 member whose
value is `null` still counts as carried, so the CAP-1 rules judge the coverage.

Each case below falls if the code reads `null` another way than the sentence beside it, and each has a control that
must keep its old verdict.
"""
from pathlib import Path

import pytest

from proofbundle import agent_review, cap1

ROOT = Path(__file__).resolve().parents[1]
CONFORMANT = {"profile": "cap/1", "subject": {"ref": "x"},
              "strata": [{"id": "s1", "basis": {"kind": "declared"}, "eligible": 1, "examined": 1, "unexamined": [],
                          "supports": ["c"]}],
              "integrity": {"complete": True}}


def _rules(**members) -> set[str]:
    return {f["rule"] for f in cap1.check_cap1_document(dict(CONFORMANT, **members))}


def test_the_control_document_is_conformant():
    assert _rules() == set()


def test_absence_assertions_null_reads_as_absent():
    assert _rules(absence_assertions=None) == set()


@pytest.mark.parametrize("value", ["x", 1, {}, True, [1], [{"stratum": "zz"}]],
                         ids=["string", "integer", "object", "boolean", "array-of-non-object", "unknown-stratum"])
def test_control_any_other_non_conformant_value_fires_r6_alone(value):
    assert _rules(absence_assertions=value) == {"R6-absence-is-scoped"}


def test_declared_at_null_is_accepted_while_the_member_is_present():
    assert agent_review._validate_times({"declaredAt": None}) == []


def test_control_an_absent_declared_at_and_a_non_time_are_refused():
    assert agent_review._validate_times({}) == ["missing 'declaredAt'"]
    assert agent_review._validate_times({"declaredAt": "yesterday"})


def test_a_null_cap1_member_counts_as_carried_in_an_agent_review_coverage():
    legacy = {"status": "PARTIAL", "knownGaps": ["g"]}
    fields = agent_review._COVERAGE_FIELDS_V02
    assert agent_review._validate_coverage(legacy, zusatz=fields) == []
    for member in sorted(fields):
        errs = agent_review._validate_coverage(dict(legacy, **{member: None}), zusatz=fields)
        assert any("CAP-1 R0-shape" in str(e) for e in errs), member


def test_the_texts_name_the_null_cases():
    readme = (ROOT / "conformance" / "README.md").read_text(encoding="utf-8")
    predicate = (ROOT / "docs" / "AGENT_REVIEW_PREDICATE.md").read_text(encoding="utf-8")
    assert " ".join(readme.split()).count("while `null` reads as an absent member, fires no rule") == 1
    assert "| `times` | `declaredAt` | yes | an RFC 3339 time or null; the member must be present |" in predicate
    assert " ".join(predicate.split()).count("a member whose value is `null` counts as carried") == 1
