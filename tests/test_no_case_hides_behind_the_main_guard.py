"""No test may be defined after its file's ``__main__`` guard, because such a file reports OK.

MEASURED 2026-09-19 on this checkout, and this is the false-green shape the repository already
names in its own registers: a headline result that does not say what did not run.

    tests/test_rust_parity_gate.py under pytest            22 tests collected
    the same file run directly                             20 tests ran, and it printed OK

Two cases vanished behind a green word. Across the tree the sweep found seventeen files of that
shape, holding 117 cases in total, the largest three being the relation profile (31), the release
scope title gate (15) and the typed-code contract (11). Every one of those files printed OK when
run directly, over a set that was quietly smaller than the file.

WHY IT HAPPENS. ``unittest.main()`` runs at the point it is reached, so anything defined below it
is not yet in the module namespace. pytest imports the whole module first and therefore sees
everything, which is exactly why the gap is invisible in normal use: the normative runner is
pytest, the reduced run only appears when someone executes the file directly to check one thing.
That is the moment a person trusts a green word most.

THE HONEST LIMIT, and it is not small. This contract fixes the ORDER, not the mixture. A file that
holds bare module-level ``def test_*`` functions alongside TestCase classes will still under-report
when executed directly, because ``unittest.main()`` never sees plain functions at all. Measured on
the release scope title gate: pytest collects 36, a direct run reports 21, and the 15 missing ones
are bare functions. There is no ordering that repairs that; the normative runner is pytest, and a
direct run of a mixed file is not a measurement of the file.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent
GUARD = re.compile(r'^if __name__ == ["\']__main__["\']:', re.M)


def _cases_after_guard(text: str) -> list[str]:
    """Names of tests defined after the FIRST ``__main__`` guard of a module."""
    match = GUARD.search(text)
    if not match:
        return []
    guard_line = text[:match.start()].count("\n") + 1
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[str] = []
    for node in tree.body:
        if getattr(node, "lineno", 0) <= guard_line:
            continue
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            out.append(node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            out.extend(f"{node.name}.{b.name}" for b in node.body
                       if isinstance(b, ast.FunctionDef) and b.name.startswith("test_"))
    return out


def test_NO_FILE_DEFINES_A_CASE_AFTER_ITS_MAIN_GUARD():  # noqa: N802
    """The contract. It was red on seventeen files when it was written, and they were moved."""
    schuldig = {}
    for path in sorted(TESTS.rglob("test_*.py")):
        namen = _cases_after_guard(path.read_text(encoding="utf-8", errors="replace"))
        if namen:
            schuldig[path.name] = namen
    assert not schuldig, (
        "these files define tests after their __main__ guard, so a direct run of them reports OK "
        f"over a smaller set than the file holds: { {k: len(v) for k, v in schuldig.items()} }")


def test_META_the_detector_finds_a_planted_case(tmp_path: Path):  # noqa: N802
    """A contract that can never go red is not a contract.

    The detector is handed a file of exactly the shape it exists to catch. Without this, an error
    in the parsing above would present itself as a clean tree.
    """
    planted = (
        "import unittest\n\n\n"
        "class TestEarly(unittest.TestCase):\n"
        "    def test_a(self):\n        pass\n\n\n"
        'if __name__ == "__main__":\n'
        "    unittest.main()\n\n\n"
        "class TestHidden(unittest.TestCase):\n"
        "    def test_b(self):\n        pass\n"
    )
    assert _cases_after_guard(planted) == ["TestHidden.test_b"]


def test_META_a_well_ordered_file_is_not_flagged():
    """The other direction: the same content with the guard last must come back empty."""
    fine = (
        "import unittest\n\n\n"
        "class TestEarly(unittest.TestCase):\n"
        "    def test_a(self):\n        pass\n\n\n"
        "class TestAlsoEarly(unittest.TestCase):\n"
        "    def test_b(self):\n        pass\n\n\n"
        'if __name__ == "__main__":\n'
        "    unittest.main()\n"
    )
    assert _cases_after_guard(fine) == []


def test_a_file_without_a_guard_is_not_flagged():
    """Most files here are plain pytest modules with no guard at all; they must stay quiet."""
    assert _cases_after_guard("def test_a():\n    pass\n") == []
