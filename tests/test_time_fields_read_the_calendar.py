"""Every `rfc3339z` time field is a real calendar instant, not only the FORM of one.

WHERE THIS COMES FROM. Measured 2026-11-03 on proofbundle 6.4.0 (triage DELTA-TRIAGE-B1-B3-VOR-650-01, vector
class G20 of draft-gruszka-audit-decision-receipts-06): `decision verify --strict` exited 0 on a receipt whose
decidedAt was `2026-13-15T09:05:00Z` or `2026-10-32T09:05:00Z`, while docs/predicates/decision-receipt.md section 5
states "Time fields are RFC3339 with a trailing Z" under its fail-closed rules, and the same value in
validity.expiresAt failed closed. `_schema_shapes.RFC3339_Z` was the schema pattern alone; seven modules read it
and agent_review carried a private copy. Owner choice A on card OA-7eda3d6d7b: fix the class before v6.5.0.

THE RULE is the one `intoto._is_rfc3339` already applies: month 01 to 12, a day that exists in that month and
year, hour to 23, minute to 59, second to 60 (RFC 3339 5.6 and 5.7 allow a leap second).
"""
import copy
import json
import re
from pathlib import Path

import pytest

from proofbundle import _schema_shapes as shapes
from proofbundle import decision

REPO = Path(__file__).resolve().parents[1]

REFUSED = [
    "2026-13-15T09:05:00Z",   # month 13
    "2026-00-10T00:00:00Z",   # month 00
    "2026-10-32T09:05:00Z",   # day 32
    "2026-01-00T00:00:00Z",   # day 00
    "2026-02-29T00:00:00Z",   # 29 February in a common year
    "2100-02-29T00:00:00Z",   # 2100 is not a leap year
    "2026-02-30T00:00:00Z",   # 30 February
    "2026-04-31T00:00:00Z",   # 31 April
    "2026-10-15T24:00:00Z",   # hour 24
    "2026-10-15T09:60:00Z",   # minute 60
    "2026-10-15T09:05:61Z",   # second 61
    "2026-13-15T09:05:00.5Z",  # month 13 with a fraction
]
ACCEPTED = [
    "2026-10-15T09:05:00Z",
    "2024-02-29T00:00:00Z",   # leap year
    "2000-02-29T00:00:00Z",   # divisible by 400
    "2026-12-31T23:59:60Z",   # leap second, as RFC 3339 5.7 allows
    "2026-10-15T09:05:00.123456Z",
]


@pytest.mark.parametrize("value", REFUSED)
def test_the_shared_time_check_refuses_an_instant_that_does_not_exist(value):
    assert shapes.RFC3339_Z.match(value) is None, value


@pytest.mark.parametrize("value", ACCEPTED)
def test_the_shared_time_check_accepts_real_instants(value):
    assert shapes.RFC3339_Z.match(value) is not None, value


def test_the_form_still_refuses_what_it_refused():
    for value in ("2026-10-15T09:05:00+00:00", "2026-10-15T09:05:00Z\n", "２０２６-10-15T09:05:00Z", 20261015, None):
        assert shapes.RFC3339_Z.match(value) is None, value


def test_the_pinned_form_line_stays_the_mutation_target():
    """scripts/mutation_check.py mutates this exact line; the calendar check wraps it and must not replace it."""
    text = (REPO / "src" / "proofbundle" / "_schema_shapes.py").read_text(encoding="utf-8")
    assert 'RFC3339_Z = re.compile(r"\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z\\Z")' in text


def _allow():
    return json.loads((REPO / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))


def test_control_the_decision_example_is_valid_in_strict_mode():
    assert decision.validate_decision_predicate(_allow(), strict=True) == []


@pytest.mark.parametrize("field", ["decidedAt", "recordedAt"])
@pytest.mark.parametrize("value", ["2026-13-15T09:05:00Z", "2026-10-32T09:05:00Z", "2026-02-30T09:05:00Z"])
def test_a_decision_receipt_with_an_impossible_time_is_refused_in_strict_mode(field, value):
    pred = copy.deepcopy(_allow())
    pred[field] = value
    errors = decision.validate_decision_predicate(pred, strict=True)
    assert any(field in str(e) for e in errors), errors


MODULES = {"decision": "_RFC3339_Z", "outcome": "_RFC3339_Z", "relation": "_RFC3339_Z", "run_ledger": "_RFC3339_Z",
           "subject_binding": "_RFC3339_Z_TYPE", "trust_pack": "_RFC3339_Z", "verification_summary": "_RFC3339_Z",
           "agent_review": "_RFC3339_Z"}


@pytest.mark.parametrize("name", sorted(MODULES))
def test_every_module_that_checks_a_time_reads_the_one_calendar_check(name):
    mod = __import__("proofbundle." + name, fromlist=["x"])
    check = getattr(mod, MODULES[name])
    assert check is shapes.RFC3339_Z, f"{name}.{MODULES[name]} is not _schema_shapes.RFC3339_Z"
    assert check.match("2026-13-15T09:05:00Z") is None


def test_no_module_keeps_a_private_copy_of_the_time_form():
    """The class guard: a module that compiles the rfc3339z form itself would miss the calendar check again."""
    form = re.compile(r're\.compile\(r"\\A\[0-9\]\{4\}-\[0-9\]\{2\}-\[0-9\]\{2\}T')
    copies = []
    for p in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
        if p.name == "_schema_shapes.py":
            continue
        if form.search(p.read_text(encoding="utf-8")):
            copies.append(str(p.relative_to(REPO)))
    assert copies == [], copies
