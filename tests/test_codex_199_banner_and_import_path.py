"""Finding nodes for the two Codex findings from PR 199, each with a reproduction and a property.

FINDING A, r3999288387, scripts/mutation_check.py. The pattern `^!+ .* !+$` asks for ONE exclamation
mark on each side, not five. It therefore matches the ordinary diagnostic line of a FAILED test,
which pytest copies from the captured stdout into its failure report. With rc=1 and a valid report
with one failure the run counted as NOT MEASURABLE and the mandatory gate aborted, although pytest
finished normally. A measured red became an abort.

FINDING B, r3999288389, scripts/test_manifest_gate.py. The text path required `unittest` DIRECTLY
after `import` and did not see `import os, unittest`; the AST path saw it. The two derivations
disagreed, and the equality check refused a valid test module.

WHY BOTH HERE AND NOT ON THE PR BRANCH. Measured: both places stood unchanged on main. The house
answers of 2026-09-13 named the merge conflict of the PR branch as the reason to defer the fix, and
the conflict has no bearing on this repair, because the defects sit in the base.

FIXED EXPECTATION. The reproduction nodes measure against FROZEN samples, not against freshly
produced output. What they claim stands as an expectation in the case, not as the result of a run.

HONEST LIMIT, finding B: what is measured is the agreement of the two derivations over a named set
of import forms. Whether a third form exists that both read equally wrong is not decided by this
guard; two readers with the same failure geometry would be one.
"""
from __future__ import annotations

import ast
import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _load(rel: str, name: str):
    p = REPO / rel
    if not p.is_file():
        pytest.skip(f"NOT MEASURABLE: {rel} is not in the tree")
    s = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


# ── FINDING A ──────────────────────────────────────────────────────────────────────────────

#: Frozen samples. Each carries its expectation WITH it, so that the case does not measure what it
#: produces.
SAMPLES_A = (
    ("ordinary diagnostic line of a failure", "! ordinary diagnostic !", True),
    ("three exclamation marks, harmless text", "!!! attention !!!", True),
    ("real abort banner", "!!!!!! Interrupted: 1 error !!!!!!", True),
    ("ordinary assertion error", "E   assert 1 == 2", False),
    ("table row with exclamation marks", "| ! | a | ! |", False),
)


def test_A_node1_the_pattern_matches_an_ordinary_failure_line():
    """[COUNTS] REPRODUCTION: the form of the finding, against frozen samples."""
    m = _load("scripts/mutation_check.py", "_mc_a1")
    for name, line, expected in SAMPLES_A:
        assert bool(m._ABBRUCH_BANNER.search(line)) is expected, name
    assert m._ABBRUCH_BANNER.search("! ordinary diagnostic !"), (
        "the reproduction no longer matches, so this node measures a different subject than the "
        "one Codex reported")


#: The REAL form of a pytest failure report: the test's output stands in a section that pytest
#: EXPLICITLY labels as such. Exactly that tells it apart from a runner banner.
REPORT_WITH_CAPTURED_OUTPUT = (
    "=================================== FAILURES ===================================\n"
    "_________________________________ test_etwas __________________________________\n"
    "\n"
    "    def test_etwas():\n"
    ">       assert 1 == 2\n"
    "E       assert 1 == 2\n"
    "\n"
    "test_probe.py:3: AssertionError\n"
    "----------------------------- Captured stdout call -----------------------------\n"
    "! ordinary diagnostic !\n"
    "=========================== short test summary info ============================\n"
    "FAILED test_probe.py::test_etwas\n"
    "1 failed in 0.10s\n"
)

#: A REAL abort by `pytest.exit`, on the top level and with rc=1. Measured case from
#: tests/test_mutationstor_sammler_sieht_die_freigabeflaeche.py: the summary looks clean, and the
#: test that should have killed the mutant never ran.
REAL_ABORT_WITH_RC1 = (
    "! _pytest.outcomes.Exit: aborted because the mutant made the environment unusable !\n"
    "1 failed, 1 passed in 0.14s\n"
)


def _report(tmp_path, failures=1):
    p = tmp_path / "junit.xml"
    p.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
        f'tests="1" failures="{failures}" errors="0"><testcase name="t"><failure/></testcase>'
        "</testsuite></testsuites>\n", encoding="utf-8")
    return p


def test_A_node2_captured_output_does_NOT_make_the_run_unmeasurable(tmp_path):
    """[COUNTS] PROPERTY: what the TEST prints is not a banner of the RUNNER."""
    m = _load("scripts/mutation_check.py", "_mc_a2")
    assert m._rote_aus_lauf(_report(tmp_path), REPORT_WITH_CAPTURED_OUTPUT, rc=1) == 1, (
        "a line from the captured stdout of a test must not make the run unmeasurable")


def test_A_ANTI_a_real_abort_stays_unmeasurable_ALSO_with_rc1(tmp_path):
    """[COUNTS] Anti-parity, and it is the reason against the first remedy of the report.

    The report proposed to apply the form check only when there is no return code. This measured
    case shows why that would be wrong: `pytest.exit` writes its banner AND returns rc=1.
    """
    m = _load("scripts/mutation_check.py", "_mc_a3")
    assert m._rote_aus_lauf(_report(tmp_path), REAL_ABORT_WITH_RC1, rc=1) is None


def test_A_ANTI_return_code_two_stays_unmeasurable(tmp_path):
    """[COUNTS] Anti-parity: rc=2 means aborted, and the fix changes nothing about that."""
    m = _load("scripts/mutation_check.py", "_mc_a4")
    assert m._rote_aus_lauf(tmp_path / "missing.xml", "anything\n", rc=2) is None


def test_A_the_surface_itself_is_cut_correctly():
    """[COUNTS] The cut takes out the captured block and only that."""
    m = _load("scripts/mutation_check.py", "_mc_a5")
    without = m._ohne_aufgefangene_ausgabe(REPORT_WITH_CAPTURED_OUTPUT)
    assert "! ordinary diagnostic !" not in without, "the captured block stayed in"
    assert "short test summary info" in without, "the cut took out too much"
    assert "1 failed in 0.10s" in without, "the summary line must not disappear"
    assert m._ohne_aufgefangene_ausgabe(REAL_ABORT_WITH_RC1) == REAL_ABORT_WITH_RC1, (
        "a text without a captured block must stay unchanged")


def test_A_the_misleading_comment_is_gone():
    """[COUNTS] The text claimed a border of five exclamation marks that the form does not have.

    The literal below quotes the removed comment of scripts/mutation_check.py verbatim.
    """
    q = (REPO / "scripts" / "mutation_check.py").read_text(encoding="utf-8")
    assert "Die fuenf Ausrufezeichen halten die Grenze" not in q, (
        "the comment still describes a property the pattern does not carry")


# ── FINDING B ──────────────────────────────────────────────────────────────────────────────

#: Frozen sources with their expectation: does the module import `unittest`?
SAMPLES_B = (
    ("import os, unittest", "import os, unittest\n\nclass T(unittest.TestCase):\n    pass\n", True),
    ("import unittest", "import unittest\n\nclass T(unittest.TestCase):\n    pass\n", True),
    ("import unittest.mock", "import unittest.mock\n", True),
    ("from unittest import mock", "from unittest import mock\n", True),
    ("import pytest", "import pytest\n\ndef test_x():\n    assert True\n", False),
    ("import my_unittest_helper", "import my_unittest_helper\n", False),
    ("import os, unittest_extras", "import os, unittest_extras\n", False),
)

_TEXT_PATH = re.compile(r"^\s*(?:import\s+[^\n]*\bunittest\b|from\s+unittest\b)", re.MULTILINE)


def _ast_path(source: str) -> bool:
    for n in ast.walk(ast.parse(source)):
        if isinstance(n, ast.Import) and any(a.name.split(".")[0] == "unittest" for a in n.names):
            return True
        if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] == "unittest":
            return True
    return False


def test_B_node1_the_old_pattern_does_NOT_see_the_multiple_import():
    """[COUNTS] REPRODUCTION: the pattern from before the fix, frozen in the case."""
    old = re.compile(r"^\s*(?:import\s+unittest|from\s+unittest\b)", re.MULTILINE)
    source = "import os, unittest\n\nclass T(unittest.TestCase):\n    pass\n"
    assert not old.search(source), "the old pattern saw the multiple import after all"
    assert _ast_path(source), "the syntax tree must see it, otherwise there is no difference"


def test_B_node2_both_derivations_AGREE_over_all_forms():
    """[COUNTS] PROPERTY: text and syntax tree measure the same property."""
    disagree = [(n, bool(_TEXT_PATH.search(q)), _ast_path(q))
                for n, q, _ in SAMPLES_B if bool(_TEXT_PATH.search(q)) != _ast_path(q)]
    assert not disagree, f"text and syntax tree contradict each other: {disagree}"


def test_B_node2_both_meet_the_frozen_expectation():
    """[COUNTS] Agreement alone is not enough, both could be equally wrong."""
    wrong = [(n, bool(_TEXT_PATH.search(q)), _ast_path(q), expected)
             for n, q, expected in SAMPLES_B
             if bool(_TEXT_PATH.search(q)) != expected or _ast_path(q) != expected]
    assert not wrong, f"wrong against the frozen expectation: {wrong}"


def test_B_the_tool_in_the_tree_carries_the_same_path():
    """[COUNTS] The guard does not measure its own copy but the shipped place."""
    m = _load("scripts/test_manifest_gate.py", "_tmg")
    source = (REPO / "scripts" / "test_manifest_gate.py").read_text(encoding="utf-8")
    assert "import\\s+[^\\n]*\\bunittest\\b" in source, (
        "the text path in the tool does not read every name of the statement")
    assert hasattr(m, "pytest_only_modules") and hasattr(m, "pytest_only_modules_ast")
