"""A version-scoped gate must fail closed when its scope no longer matches what ships.

FOUND BY THE PRE-TAG DEEP GATE, 2026-08-25, finding L6-01 (P3). Three lenses converged
independently on the same drift, and two of them confirmed the shipped false-green.

WHAT WAS OBSERVED. `scripts/audit_candidate_matrix.py` pinned `VERSION_UNDER_TEST = "3.6.0"`,
evaluated `release_evidence_slots["3.6.0"]` and `pre_tag_audit_gate.evaluate(version="3.6.0")`,
and reported `audit_candidate_ready=True` with exit 0 — while the shipping package was `5.0.0`,
two majors ahead. A release-readiness gate attested readiness from evidence about a different
release, and it is wired into CI. Nothing in the pipeline could notice, because nothing compared
the two numbers.

WHY THE FIX IS NOT A BUMP. Editing the literal to `5.0.0` would turn this instance green and
recreate the class at the next version bump — stale again, silently again. The gate's own
remediation says it in one line: *"do NOT just edit the literal, that recreates the class at the
next release."* What was missing is the BINDING.

THE PROPERTY, executable: every release-readiness gate G that evaluates version-scoped evidence
must bind its pinned version to the shipping identity. On mismatch, G reports not-ready with an
explicit reason and a nonzero exit — never a green row about another release.

THE ANTI-PARITY HALF, and it is the half that makes the test worth having: a guard that always
says FAIL proves nothing and would pass a naive test of the property above. With the pin EQUAL to
the shipping version, the binding must NOT withhold readiness. Both directions are checked here.

HONEST BOUNDARY: this measures the BINDING, not the evidence. A bound pin says the matrix speaks
about the shipping version — it says nothing about whether that version's evidence is any good.
That is what the 33 checks are for.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def matrix():
    for sub in ("src", "scripts"):
        p = str(REPO / sub)
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location(
        "_acm_pin", str(REPO / "scripts" / "audit_candidate_matrix.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_acm_pin"] = m
    spec.loader.exec_module(m)
    return m


def _shipping() -> str:
    import proofbundle
    return proofbundle.__version__


class TestTheBindingItself:
    def test_a_pin_that_matches_is_bound(self, matrix):
        r = matrix.version_pin_binding(_shipping())
        assert r["state"] == "bound", r
        assert r["shipping"] == _shipping()

    def test_a_pin_that_differs_is_drift(self, matrix):
        r = matrix.version_pin_binding("0.0.1-not-the-shipping-version")
        assert r["state"] == "drift", r
        # The reason must NAME both numbers — a drift report that hides them cannot be acted on.
        assert "0.0.1-not-the-shipping-version" in r["detail"]
        assert _shipping() in r["detail"]

    def test_an_unreadable_package_is_not_a_pass(self, matrix, monkeypatch):
        """THREE STATES: unmeasurable is explicitly not bound. A gate that reads 'could not check'
        as 'checked and fine' is the exact failure mode this whole file exists for."""
        monkeypatch.setitem(sys.modules, "proofbundle", None)
        r = matrix.version_pin_binding("3.6.0")
        assert r["state"] == "not_determinable", r
        assert r["state"] != "bound"


class TestTheBindingGatesTheVerdict:
    def test_drift_withholds_readiness(self, matrix, monkeypatch):
        """The live repository IS the drift case (matrix pinned 3.6.0, package 5.0.0). The
        verdict must be withheld and the exit code nonzero — the observed defect was the opposite."""
        result = matrix.evaluate()
        assert result["version_pin"]["state"] == "drift", (
            "expected the live repo to exhibit the drift this test is about; "
            f"got {result['version_pin']}")
        assert result["audit_candidate_ready"] is False
        assert result["fully_verified_here"] is False

    def test_the_reason_travels_with_the_result(self, matrix):
        """A withheld verdict without a reason is indistinguishable from a broken check."""
        result = matrix.evaluate()
        assert "version_pin" in result
        assert result["version_pin"]["detail"]

    def test_the_human_output_leads_with_the_drift(self, matrix):
        """A reader who stops after the first line must not walk away with a readiness
        impression that a later line would have withdrawn."""
        text = matrix._fmt(matrix.evaluate())
        first = text.splitlines()[0]
        assert "DRIFT" in first.upper(), f"first line does not lead with the drift: {first!r}"


class TestNotAConstantFail:
    """ANTI-PARITY. A guard that always fails would satisfy every test above and be worthless."""

    def test_a_bound_pin_does_not_withhold_readiness(self, matrix, monkeypatch):
        """With the pin equal to the shipping version, the BINDING must not be the thing that
        lowers the verdict. Whether the 33 checks then pass is a different question — this test
        isolates the guard by comparing the verdict to the same run without the guard's effect."""
        monkeypatch.setattr(matrix, "VERSION_UNDER_TEST", _shipping())
        result = matrix.evaluate()
        assert result["version_pin"]["state"] == "bound", result["version_pin"]
        rows = result["checks"]
        ohne_riegel = (result["counts"][matrix.FAIL] == 0
                       and all(r["verdict"] in matrix._NON_FAIL for r in rows))
        assert result["audit_candidate_ready"] == ohne_riegel, (
            "with a BOUND pin the guard changed the verdict -- it is behaving like a constant "
            "FAIL instead of a binding check")

    def test_the_guard_is_reached_at_all(self, matrix):
        """A guard nobody calls is not a guard. `evaluate()` must consult it, not just define it."""
        quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
        nach_evaluate = quelle.split("def evaluate(", 1)[-1]
        assert "version_pin_binding(" in nach_evaluate, (
            "evaluate() does not call version_pin_binding -- the binding would be decoration")
