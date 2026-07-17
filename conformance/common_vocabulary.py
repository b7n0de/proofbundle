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


def label_from_verify(exit_code: int, report: dict | None) -> dict[str, Any]:
    """The ONE mapping ``(verify exit code, verify --json report) -> common label``.

    Called by all three differential layers so a scenario can never be labelled one way by
    the conformance runner and another way by the cross-format or Rust differential. Returns
    a dict over the three axes; an axis the report does not carry is ``None`` (absent), never
    fabricated."""
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
    return {
        "exitClass": exit_class(exit_code),
        "lineage": lineage,
        "policyVerdict": verdict,
    }


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
    """Compare two labels axis by axis. Only axes the EXPECTED side pins (non-None) are
    checked (fail-closed on the pinned axes; silent on unpinned ones). Returns
    ``(ok, [human-readable diffs])``."""
    diffs: list[str] = []
    for axis in AXES:
        want_v = want.get(axis)
        if want_v is None:
            continue
        got_v = got.get(axis)
        if not _axis_equal(want_v, got_v):
            diffs.append(f"{axis}: expected {want_v!r} but got {got_v!r}")
    return (not diffs, diffs)


__all__ = [
    "EXIT_CLASS", "EXIT_CLASSES", "EXIT_VERIFIED", "EXIT_CRYPTO_FAIL", "EXIT_MALFORMED",
    "EXIT_POLICY_UNMET", "LINEAGE_STATES", "POLICY_VERDICTS", "AXES",
    "exit_class", "label_from_verify", "expected_label", "compare",
]
