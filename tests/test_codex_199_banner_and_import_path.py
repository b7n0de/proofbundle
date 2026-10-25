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
import time

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


def _report_with_captured(lines: str) -> str:
    """A failure report in pytest's real shape, its separators 80 wide, with `lines` captured."""
    return (
        "=================================== FAILURES ===================================\n"
        "_________________________________ test_etwas __________________________________\n"
        "\n"
        "test_probe.py:3: AssertionError\n"
        "----------------------------- Captured stdout call -----------------------------\n"
        f"{lines}"
        "=========================== short test summary info ============================\n"
        "FAILED test_probe.py::test_etwas\n"
        "1 failed in 0.10s\n"
    )


@pytest.mark.parametrize("separator", ["---", "===", "___", "--- a heading of the test ---"])
def test_A_a_separator_the_test_prints_stays_inside_the_capture(tmp_path, separator):
    """[COUNTS] Codex on pull request 371, round one, P2. The capture closed on ANY line that began
    with three of `-`, `=` or `_`, so a test printing `---` and then `! ordinary diagnostic !` put the
    second line back on the top level, and the run counted as NOT MEASURABLE. pytest draws every
    separator whose title fits to the same full width of the run, the width of the `Captured` line
    that opened the block; a shorter line is the test's own text. A title longer than the run makes
    its separator wider (`TerminalWriter.sep`, counter-reading of pull request 371, F6)."""
    m = _load("scripts/mutation_check.py", "_mc_a6")
    report = _report_with_captured(f"{separator}\n! ordinary diagnostic !\n")
    assert "! ordinary diagnostic !" not in m._ohne_aufgefangene_ausgabe(report), separator
    assert m._rote_aus_lauf(_report(tmp_path), report, rc=1) == 1, separator


def test_A_the_next_section_of_pytest_still_closes_the_capture():
    """[COUNTS] Counter-direction: a cut that never closed would hide the summary and the next
    failure, and a real banner after the block would go unseen."""
    m = _load("scripts/mutation_check.py", "_mc_a7")
    report = _report_with_captured("printed\n")
    without = m._ohne_aufgefangene_ausgabe(report)
    assert "printed" not in without
    assert "short test summary info" in without and "1 failed in 0.10s" in without
    after = report + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
    assert m._ABBRUCH_BANNER.search(m._ohne_aufgefangene_ausgabe(after)), (
        "a banner after the captured block must stay visible")


#: A real abort banner as `pytest.exit` writes it, placed after the short summary as pytest does.
_EXIT_BANNER = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!! _pytest.outcomes.Exit: stop !!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"


def _with_banner(report: str) -> str:
    return report.replace("1 failed in 0.10s\n", _EXIT_BANNER + "1 failed in 0.10s\n")


@pytest.mark.parametrize("header", ["-- Captured x --", "--- Captured stdout call ---"])
def test_A_a_header_the_test_prints_does_not_reset_the_width(tmp_path, header):
    """[COUNTS] Counter-reading of pull request 371, F1 (P2): a `Captured` line the test printed itself
    set the width of the block to its own, no separator of the run closed the block again, and the
    real abort banner after it was cut away as the test's output."""
    m = _load("scripts/mutation_check.py", "_mc_a8")
    report = _report_with_captured(f"{header}\n! ordinary diagnostic !\n")
    assert m._rote_aus_lauf(_report(tmp_path), _with_banner(report), rc=1) is None, (
        f"{header!r} printed by the test hid the abort banner after the block")
    # The counter-direction: without the banner the printed lines stay inside, the run is a measured red.
    assert "! ordinary diagnostic !" not in m._ohne_aufgefangene_ausgabe(report), header
    assert m._rote_aus_lauf(_report(tmp_path), report, rc=1) == 1, header


def test_A_a_header_wider_than_the_run_still_closes_at_the_runs_width(tmp_path):
    """[COUNTS] Counter-reading of pull request 371, F1 (P2), the other form: a section whose title is
    longer than the run's width gets one fill character on each side (`TerminalWriter.sep`), so its
    header is wider than every separator after it, and the block it opened never closed."""
    m = _load("scripts/mutation_check.py", "_mc_a9")
    title = "Captured " + "k" * 80 + " call"
    report = _report_with_captured("printed\n").replace(
        "----------------------------- Captured stdout call -----------------------------\n",
        f"- {title} -\n")
    assert len(f"- {title} -") > 80, "the header must be wider than the run, or this case checks nothing"
    assert m._rote_aus_lauf(_report(tmp_path), _with_banner(report), rc=1) is None, (
        "a wide section header hid the abort banner after its block")
    without = m._ohne_aufgefangene_ausgabe(report)
    assert "printed" not in without and "1 failed in 0.10s" in without


def test_A_an_internalerror_line_the_test_prints_stays_a_measured_red(tmp_path):
    """[COUNTS] Counter-reading of pull request 371, F2 (P2): `^INTERNALERROR` was still searched in
    the whole text, so a captured line that began with it made a measured red NOT MEASURABLE."""
    m = _load("scripts/mutation_check.py", "_mc_a10")
    report = _report_with_captured("INTERNALERROR> printed by the test\n")
    assert m._rote_aus_lauf(_report(tmp_path), report, rc=1) == 1


def test_A_ANTI_a_real_internalerror_stays_unmeasurable(tmp_path):
    """[COUNTS] Anti-parity of the case above: pytest's own INTERNALERROR stands on the top level and
    still makes the run not measurable, also when no return code is passed."""
    m = _load("scripts/mutation_check.py", "_mc_a11")
    text = "INTERNALERROR> Traceback (most recent call last):\nINTERNALERROR> RuntimeError: x\n1 failed in 0.10s\n"
    assert m._rote_aus_lauf(_report(tmp_path), text) is None


# ── FOLLOW-UP of the counter-reading of pull request 371: F3, F9 and probe J ─────────────────


@pytest.mark.parametrize("fill", ["-", "=", "_"])
def test_A_F3_an_untitled_line_of_the_runs_width_stays_inside_the_capture(tmp_path, fill):
    """[COUNTS] Counter-reading of pull request 371, F3 (P3, named as a limit until now): a test that
    printed a line of 80 `-`, `=` or `_` closed the block, because the line had the run's width, and a
    `! ordinary diagnostic !` printed after it stood on the top level again. Every separator pytest
    writes after a captured block carries a title (`TerminalWriter.sep(fill, title)`); a line without
    one is the test's own text."""
    m = _load("scripts/mutation_check.py", "_mc_f3")
    report = _report_with_captured(f"{fill * 80}\n! ordinary diagnostic !\n")
    assert "! ordinary diagnostic !" not in m._ohne_aufgefangene_ausgabe(report), fill
    assert m._rote_aus_lauf(_report(tmp_path), report, rc=1) == 1, fill


def test_A_F3_LIMIT_a_titled_line_of_the_runs_width_still_closes_the_capture():
    """[COUNTS] The limit that stays, named in `_ohne_aufgefangene_ausgabe`: a line the test prints in
    the shape of a titled separator AND in the run's width cannot be told apart from pytest's own. The
    case pins that limit, so that a change of it is seen."""
    m = _load("scripts/mutation_check.py", "_mc_f3l")
    line = "=" * 29 + " printed by the tests " + "=" * 29
    assert len(line) == 80, "the line must have the run's width, or this case pins nothing"
    report = _report_with_captured(f"{line}\n! ordinary diagnostic !\n")
    assert "! ordinary diagnostic !" in m._ohne_aufgefangene_ausgabe(report)


def test_A_F9_a_long_run_of_dashes_after_Captured_is_read_in_linear_time():
    r"""[COUNTS] Counter-reading of pull request 371, F9 (P3): in `^-+ Captured [^\n]*-+\s*$` the parts
    `[^\n]*` and `-+` shared every dash of a line `- Captured ` + dashes + one other character, and the
    failing match took quadratic time (measured at the head 4b4e83a0 under CPython 3.12.3: 0.57 s for
    8000 dashes, 2.59 s for 16000). The lines below cost each pattern of the reader one pass."""
    m = _load("scripts/mutation_check.py", "_mc_f9")
    n = 30000
    text = ("- Captured " + "-" * n + "x\n"
            "= x" + " =" * n + "y\n"
            "----------------------------- Captured stdout call -----------------------------\n"
            "- x" + " -" * n + "y\n"
            "_ x" + " _" * n + "y\n")
    t0 = time.perf_counter()
    m._ohne_aufgefangene_ausgabe(text)
    assert time.perf_counter() - t0 < 1.0, "a line of dashes is read in more than linear time"


def test_A_J_a_captured_abort_line_stays_a_measured_red_without_a_junit_file(tmp_path):
    """[COUNTS] Counter-reading of pull request 371, P3 under F2 (probe J): without a JUnit file the
    verdict falls back to `_rote_aus_text`, and that one still searched `^!+ Interrupted` and
    `^INTERNALERROR` in the whole text, so `! Interrupted by the test !` printed by a failing test made
    a measured red NOT MEASURABLE. It reads the top level now, as `_rote_aus_lauf` does."""
    m = _load("scripts/mutation_check.py", "_mc_j")
    for printed in ("! Interrupted by the test !", "INTERNALERROR> printed by the test"):
        report = _report_with_captured(f"{printed}\n")
        assert m._rote_aus_text(report) == 1, printed
        assert m._rote_aus_lauf(tmp_path / "missing.xml", report, rc=1) == 1, printed


def test_A_J_ANTI_a_real_interrupt_without_a_junit_file_stays_unmeasurable(tmp_path):
    """[COUNTS] Anti-parity of the case above: pytest's own banner stands on the top level."""
    m = _load("scripts/mutation_check.py", "_mc_j2")
    text = ("=========================== short test summary info ============================\n"
            "ERROR tests/test_x.py\n"
            "!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!\n"
            "1 error in 0.10s\n")
    assert m._rote_aus_text(text) is None
    assert m._rote_aus_lauf(tmp_path / "missing.xml", text, rc=1) is None


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
    # Codex on pull request 371, round one, P2: the text path read the REST OF THE LINE.
    ("a comment after the import", "import os  # unittest is intentionally not used\n", False),
    ("an alias named unittest", "import os as unittest\n", False),
    ("a backslash continuation", "import os, \\\n    unittest\n", True),
    # Neighbours of the same class: names that are not imports, and imports that are not one line.
    ("a docstring that shows an import", '"""\nimport unittest\n"""\n', False),
    ("a parenthesised from-import", "from unittest import (\n    mock,\n)\n", True),
    ("an import inside a function", "def f():\n    import unittest\n", True),
    ("a second import right after the first", "import os\nimport unittest\n", True),
    ("an import after a semicolon", "import os; import unittest\n", True),
    ("an import on the line of a compound statement", "if True: import unittest\n", True),
    # Counter-reading of pull request 371, F4: Python reads a name after NFKC, and so does the tree.
    ("a module name in full-width letters", "import \uff55nittest\n", True),
    ("a from-import in full-width letters", "from \uff55nittest import mock\n", True),
)


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


def _both_readers(tmp_path) -> dict[str, tuple[bool, bool]]:
    """{sample: (text reader says it imports unittest, syntax tree says so)}, measured on the TOOL.

    The first version of these nodes held a copy of the text pattern, so a change of the shipped
    reader was never measured here; the readers of scripts/test_manifest_gate.py are asked now, on
    real files, the way the gate asks them."""
    m = _load("scripts/test_manifest_gate.py", "_tmg_b")
    d = tmp_path / "tests"
    d.mkdir()
    names = {}
    for i, (name, source, _) in enumerate(SAMPLES_B):
        (d / f"test_sample_{i:02d}.py").write_text(source, encoding="utf-8")
        names[f"test_sample_{i:02d}.py"] = name
    text_only = set(m.pytest_only_modules(d))
    tree_only = set(m.pytest_only_modules_ast(d))
    return {name: (f not in text_only, f not in tree_only) for f, name in names.items()}


def test_B_node2_both_derivations_AGREE_over_all_forms(tmp_path):
    """[COUNTS] PROPERTY: text and syntax tree measure the same property."""
    disagree = {n: v for n, v in _both_readers(tmp_path).items() if v[0] != v[1]}
    assert not disagree, f"text and syntax tree contradict each other: {disagree}"


def test_B_node2_both_meet_the_frozen_expectation(tmp_path):
    """[COUNTS] Agreement alone is not enough, both could be equally wrong."""
    expected = {n: e for n, _, e in SAMPLES_B}
    wrong = {n: (v, expected[n]) for n, v in _both_readers(tmp_path).items() if v != (expected[n],) * 2}
    assert not wrong, f"wrong against the frozen expectation: {wrong}"


def test_B_the_two_readers_of_the_tool_are_two():
    """[COUNTS] Two derivations with one failure geometry would be one (owner order 2026-09-07):
    the text reader reads tokens, the second reader the syntax tree, and neither calls the other."""
    m = _load("scripts/test_manifest_gate.py", "_tmg")
    assert hasattr(m, "pytest_only_modules") and hasattr(m, "pytest_only_modules_ast")
    import inspect
    text_reader = inspect.getsource(m._importiert_unittest_lexikalisch)
    assert "tokenize" in text_reader and "ast." not in text_reader


def test_B_F5_a_source_with_a_NUL_byte_is_read_on_both_paths_without_a_crash(tmp_path):
    """[COUNTS] Counter-reading of pull request 371, F5 (P3): `tokenize` of CPython 3.12 raises
    `SystemError` for a NUL byte after an indented line (measured here on 3.12.3 and 3.12.13, in the
    report on 3.12.15). The token reader did not catch it, and the gate stopped with a traceback.
    3.11 tokenizes the same source, 3.13 and 3.14 refuse it. No Python compiles a source with a NUL
    byte, so it counts as importing on every version now, and both paths leave it out."""
    m = _load("scripts/test_manifest_gate.py", "_tmg_f5")
    source = "def test_x():\n    assert True\n\x00"
    assert m._importiert_unittest_lexikalisch(source) is True
    d = tmp_path / "tests"
    d.mkdir()
    (d / "test_nul.py").write_text(source, encoding="utf-8")
    assert m.pytest_only_modules(d) == m.pytest_only_modules_ast(d) == []


def test_B_F5_a_source_that_is_not_utf8_is_left_out_on_both_paths(tmp_path):
    """[COUNTS] A neighbour of F5 in the same class, found while measuring F5 under Python 3.10: a test
    source that is not UTF-8 stopped both readers with `UnicodeDecodeError`, on every version from 3.10 to
    3.14 and on main as well. It cannot be parsed, so both paths leave it out, as they leave out a NUL byte."""
    m = _load("scripts/test_manifest_gate.py", "_tmg_f5_utf8")
    d = tmp_path / "tests"
    d.mkdir()
    (d / "test_latin1.py").write_bytes(b"def test_x():\n    assert True\n# \xff\n")
    assert m.pytest_only_modules(d) == m.pytest_only_modules_ast(d) == []


def test_B_F5_a_chain_the_parser_cannot_nest_stops_no_reader(tmp_path):
    """[COUNTS] The third form of the class: from Python 3.11 on `ast.parse` answers a chain of 100000
    additions with `RecursionError`, which the syntax tree did not catch. Python 3.10 parses the chain, so
    what the tree reads depends on the interpreter; that it reads without a traceback does not. The token
    reader reads the chain on every version, and a file only one reader keeps is the difference that
    `evaluate()` reports."""
    m = _load("scripts/test_manifest_gate.py", "_tmg_f5_chain")
    source = "x = " + "1+" * 100000 + "1\n"
    try:
        ast.parse(source)
        expected = ["test_chain.py"]
    except RecursionError:
        expected = []
    d = tmp_path / "tests"
    d.mkdir()
    (d / "test_chain.py").write_text(source, encoding="utf-8")
    assert m.pytest_only_modules_ast(d) == expected
    assert m.pytest_only_modules(d) == ["test_chain.py"]
