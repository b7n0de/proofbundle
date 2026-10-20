#!/usr/bin/env python3
"""Fundament F1 — the ONE common verifier vocabulary + the ONE comparator.

Front-Loading (GO_OWNER_PB_ROADMAP_FRONTLOAD_20260716, §2): the conformance runner
(``run_conformance.py``), the cross-format comparator (``cross_format.py``) and the
Python<->Rust differential (``tools/pb_verify_rs/crosscheck.py``) are three views of the
SAME question — "does verifying THIS input land on THIS verdict?". Before this module each
view re-derived its own ad-hoc labels (an exit code here, a ``lineage`` string there),
which is exactly how the 3.4.0 F3-comparator could have re-introduced a second vocabulary.

This module is the single source of truth for that vocabulary and the single ``verifier
JSON -> common label`` mapping. Everything downstream (3.4.0 target-pin comparator, 3.5.0
relation-statement parity, 3.6.0 audit-candidate matrix) EXTENDS this map, never forks it.

Pure stdlib, no import of the package internals except the lineage state names (so the
label vocabulary tracks the real implementation, never a hand-copied duplicate that drifts).

The vocabulary has three orthogonal axes; a case may pin any subset (fail-closed: an
unpinned axis is simply not compared, but a pinned axis that mismatches is a FAIL):

  * ``exitClass``    — the CLI verify exit-code contract, named:
                       0 VERIFIED · 1 CRYPTO_FAIL · 2 MALFORMED · 3 POLICY_UNMET
  * ``lineage``      — relation/v0.1 lineage state:
                       VERIFIED · DECLARED_UNRESOLVED · FAIL · NOT_EVALUATED
  * ``policyVerdict``— the decision predicate verdict, when present:
                       ALLOW · DENY · REFUSE · ESCALATE · DEFER · OBSERVE
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Track the REAL implementation constants so the vocabulary can never silently drift from
# the code it describes. The src path is added defensively; conformance/crosscheck already
# put it on sys.path, but this module must be importable standalone (tests, tooling).
_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from proofbundle.relation import (  # noqa: E402
    LINEAGE_DECLARED_UNRESOLVED,
    LINEAGE_FAIL,
    LINEAGE_NOT_EVALUATED,
    LINEAGE_VERIFIED,
)

# --- axis 1: the CLI verify exit-code contract, named (see proofbundle.cli._verify_exit_code) ---
EXIT_VERIFIED = "VERIFIED"
EXIT_CRYPTO_FAIL = "CRYPTO_FAIL"
EXIT_MALFORMED = "MALFORMED"
EXIT_POLICY_UNMET = "POLICY_UNMET"
EXIT_CLASS: dict[int, str] = {
    0: EXIT_VERIFIED,
    1: EXIT_CRYPTO_FAIL,
    2: EXIT_MALFORMED,
    3: EXIT_POLICY_UNMET,
}
EXIT_CLASSES = frozenset(EXIT_CLASS.values())

# --- axis 2: relation/v0.1 lineage states (re-exported from the implementation) ---
LINEAGE_STATES = frozenset({
    LINEAGE_VERIFIED, LINEAGE_DECLARED_UNRESOLVED, LINEAGE_FAIL, LINEAGE_NOT_EVALUATED,
})

# --- axis 3: decision predicate verdicts (mirrors proofbundle.policy._VERDICTS) ---
POLICY_VERDICTS = frozenset({"ALLOW", "DENY", "REFUSE", "ESCALATE", "DEFER", "OBSERVE"})

#: DIE ARTEN VON KORPUS-FAELLEN — EINE Quelle, zwei Leser.
#:
#: DER GEMESSENE ANLASS (01.09.2026, gefunden beim Bau des reproduzierbaren Reviewerpakets):
#: `cross_format._structural_validate` ist der Notpfad OHNE `jsonschema` und trug eine EIGENE,
#: fest eingetragene Liste mit VIER Arten. Der Laeufer unterstuetzt ACHT. Im Entwicklungs-venv ist
#: `jsonschema` installiert, der Notpfad laeuft dort NIE — und genau deshalb konnte die Liste
#: veralten, ohne dass es je auffiel. In einem frischen venv mit nur dem Wheel (also exakt der
#: Umgebung, die N09/P1.3 der Gegenlese verlangt) lief er, und ALLE 14 agent-review-Faelle fielen
#: mit `unknown kind 'agent_review_predicate'` aus der Korpus-Integritaet.
#:
#: Zwei Listen ueber dieselbe Groesse sind zwei Wahrheiten, die auseinanderlaufen — und die
#: zweite ist die, die niemand mitpflegt, weil sie im Alltag nicht ausgefuehrt wird.
CASE_KINDS = frozenset({
    "decision_crossimpl", "native_bundle", "decision_relation", "outcome_relation",
    "relation_statement", "provenance_version_status", "envelope_profile_rule",
    "agent_review_predicate",
    "cap1_document",
    "content_root_vector",
})

AXES = ("exitClass", "lineage", "policyVerdict")


def exit_class(exit_code: int) -> str:
    """Name the CLI verify exit code. An out-of-contract code is returned as ``EXIT:<n>``
    rather than silently coerced — an unexpected exit is itself a finding, never a pass."""
    return EXIT_CLASS.get(exit_code, f"EXIT:{exit_code}")


def _normalize_lineage(value: Any) -> Any:
    """The verifier reports lineage either as a bare state string, as ``null`` (not evaluated),
    or nested as ``{"lineage": <state>, ...}`` (the ``decision verify --json`` report). Collapse
    all three to a bare state string (or None). NOT_EVALUATED and a reported ``null`` are the
    SAME observable fact, so a case may pin either — they are treated as equal by ``compare``."""
    if isinstance(value, dict):
        value = value.get("lineage")
    return value


class ObservedLabel(dict):
    """A label that states what a run OBSERVED, as ``label_from_verify`` builds it. Its ``None`` means "the report does
    not carry this axis", while the ``None`` of an expectation (``expected_label``) means "this axis is not pinned".
    ``compare`` reads the difference from the type (6.3.1, CV1); every other reader sees a plain dict over the same three
    axes."""


def label_from_verify(exit_code: int, report: dict | None) -> dict[str, Any]:
    """The ONE mapping ``(verify exit code, verify --json report) -> common label``.

    Called by all three differential layers so a scenario can never be labelled one way by
    the conformance runner and another way by the cross-format or Rust differential. Returns
    a dict over the three axes, an ``ObservedLabel``; an axis the report does not carry is ``None``
    (absent), never fabricated."""
    report = report or {}
    lineage = _normalize_lineage(report.get("lineage"))
    # The decision predicate verdict, when the report surfaces it (decision receipts).
    verdict = None
    pred = report.get("predicate")
    if isinstance(pred, dict):
        dec = pred.get("decision")
        if isinstance(dec, dict) and isinstance(dec.get("verdict"), str):
            verdict = dec["verdict"]
    if verdict is None and isinstance(report.get("policyVerdict"), str):
        verdict = report["policyVerdict"]
    return ObservedLabel({
        "exitClass": exit_class(exit_code),
        "lineage": lineage,
        "policyVerdict": verdict,
    })


def expected_label(expected: dict) -> dict[str, Any]:
    """Project a case's ``expected`` block onto the same three-axis label, so a case's
    declaration and a run's observation are compared in ONE vocabulary. Only axes the case
    actually pins are populated; the rest are ``None`` (not compared)."""
    label: dict[str, Any] = {"exitClass": None, "lineage": None, "policyVerdict": None}
    if "exitCode" in expected and isinstance(expected["exitCode"], int):
        label["exitClass"] = exit_class(expected["exitCode"])
    elif "exitClass" in expected:
        label["exitClass"] = expected["exitClass"]
    if "lineage" in expected:
        label["lineage"] = _normalize_lineage(expected["lineage"])
    if "policyVerdict" in expected:
        label["policyVerdict"] = expected["policyVerdict"]
    return label


def _axis_equal(want: Any, got: Any) -> bool:
    # NOT_EVALUATED and a reported null lineage are the same observable fact.
    if want in (None, LINEAGE_NOT_EVALUATED) and got in (None, LINEAGE_NOT_EVALUATED):
        return True
    return want == got


def compare(want: dict, got: dict) -> tuple[bool, list[str]]:
    """Compare two labels axis by axis. Returns ``(ok, [human-readable diffs])``.

    Between two observations (two ``ObservedLabel``) every axis either side fills is checked. Otherwise one side is
    an expectation, and only the axes it pins (non-None) are checked, fail-closed on those and silent on the others:
    the first side's, as before, or the second side's where the first side is the observation. A label that is no
    ``ObservedLabel`` is read as an expectation, as before.

    6.3.1, CV1. Until 6.3.1 only the axes the FIRST side filled were checked, also between two observations: the
    Python<->Rust differential (tools/pb_verify_rs/crosscheck.py) passes two labels of ``label_from_verify``, the Python
    one first, so an axis only the Rust side filled (a lineage, a policy verdict) was never compared, and a
    disagreement on it passed. An expectation passed second was held to the first side's axes, so an axis it does
    not pin failed."""
    diffs: list[str] = []
    both_observed = isinstance(want, ObservedLabel) and isinstance(got, ObservedLabel)
    for axis in AXES:
        want_v, got_v = want.get(axis), got.get(axis)
        if both_observed:
            pinned = True                      # two observations: every axis either side fills
        elif isinstance(want, ObservedLabel):
            pinned = got_v is not None         # the expectation is the second side
        else:
            pinned = want_v is not None        # the expectation is the first side, as before
        if pinned and not _axis_equal(want_v, got_v):
            diffs.append(f"{axis}: expected {want_v!r} but got {got_v!r}")
    return (not diffs, diffs)


def agree(left: dict, right: dict) -> tuple[bool, list[str]]:
    """Whether two OBSERVED labels agree: every axis is compared, whichever side fills it.

    ``compare`` checks only the axes its first argument pins, which is right for a declared expectation held
    against an observation and wrong between two observations (matrix630, finding of delta at 479e01ee, the
    sibling of CODEX-KLASSENSUCHE-631-01 F1): a Python label with ``policyVerdict`` None was never compared
    with the Rust one, whatever Rust reported. NOT_EVALUATED and None stay one observable fact."""
    diffs: list[str] = []
    for axis in AXES:
        left_v, right_v = left.get(axis), right.get(axis)
        if not _axis_equal(left_v, right_v):
            diffs.append(f"{axis}: {left_v!r} on one side, {right_v!r} on the other")
    return (not diffs, diffs)


__all__ = [
    "EXIT_CLASS", "EXIT_CLASSES", "EXIT_VERIFIED", "EXIT_CRYPTO_FAIL", "EXIT_MALFORMED",
    "EXIT_POLICY_UNMET", "LINEAGE_STATES", "POLICY_VERDICTS", "AXES",
    "exit_class", "label_from_verify", "expected_label", "compare", "agree",
]
