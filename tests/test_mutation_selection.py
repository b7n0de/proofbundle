"""The mutation gate judges each mutant by a selection of test files, and a baseline-red test never
kills (owner decisions C, Z230 and Z231, 2026-09-26).

WHY. Measured on main in run 36253567619: the full suite took 1226-1661 s for a baseline and
1174-1610 s per mutant under a 60-minute job limit, and no mutant was judged. A mutant now runs the
test files that reach the mutated file (`mutation_check._auswahl`), and its baseline runs over the
same files.

THE PROPERTIES, each pinned below:
1. The selection holds every test file that imports the mutated module directly or transitively
   ("in doubt one file more, never one less").
2. A selection can only lose kills, never add one: a mutant is killed only by a test that is red
   under it and not red in the baseline over the same selection, and such a test is red over the
   whole suite too (tests taken as independent). The old rule, `red > baseline` over counts, does
   not have this property on a selection, and a case shows it.
3. A test that is red in the baseline never counts as a killer. Under the old rule a baseline-red
   test that also failed its teardown under the mutant raised the count by one and the mutant read
   as KILLED; the end-to-end case below is red against the old gate.
4. A baseline-red test that is not on the allowlist with the class it failed with stops the baseline.
5. The failure class comes from pytest's own JUnit report, and the restoration after the mutants is
   checked byte by byte.
"""
from __future__ import annotations

import importlib.util
import itertools
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "mutation_check.py"


def _load(path: Path = SCRIPT):
    spec = importlib.util.spec_from_file_location("mutation_check_selection_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(base: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return base


_MINI = {
    "src/pkg/__init__.py": '''
        _LAZY = {"helper": ".c"}
        def __getattr__(name):
            import importlib
            return getattr(importlib.import_module(_LAZY[name], __name__), name)
    ''',
    "src/pkg/a.py": "def f(x):\n    return x is not None\n",
    "src/pkg/b.py": "from .a import f\ndef g(x):\n    return f(x)\n",
    "src/pkg/c.py": "from . import a\ndef helper():\n    return a.f(1)\n",
    "src/pkg/d.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from .a import f\n",
    "src/pkg/__main__.py": "from .b import g\nprint(g(1))\n",
    "tests/test_direct.py": "from pkg.a import f\ndef test_x():\n    assert f(1)\n",
    "tests/test_transitive.py": "from pkg.b import g\ndef test_x():\n    assert g(1)\n",
    "tests/test_lazy.py": "import pkg\ndef test_x():\n    assert pkg.helper()\n",
    "tests/test_type_only.py": "import pkg.d\ndef test_x():\n    assert True\n",
    "tests/test_unrelated.py": "def test_x():\n    assert True\n",
    "tests/test_runs_module.py": '''
        import subprocess, sys
        def test_x():
            subprocess.run([sys.executable, "-m", "pkg"], check=False)
    ''',
    "tests/test_reads_every_source.py": '''
        from pathlib import Path
        def test_x():
            assert list(Path("src").rglob("*.py"))
    ''',
    "tests/test_loads_by_path.py": '''
        import importlib.util
        from pathlib import Path
        def test_x():
            spec = importlib.util.spec_from_file_location("x", Path("src") / "pkg" / "a.py")
            assert spec
    ''',
}


class TheSelectionHoldsEveryImporter(unittest.TestCase):
    """Property 1, on a planted tree where every way of reaching a module is present once."""

    def test_the_selection_of_a_module_on_a_planted_tree(self):
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-") as d:
            tree = _tree(Path(d), _MINI)
            got = set(mc._auswahl(tree, "src/pkg/a.py"))
        self.assertEqual(got, {
            "tests/test_direct.py",            # imports it
            "tests/test_transitive.py",        # imports pkg.b, which imports it
            "tests/test_lazy.py",              # pkg.helper -> .c (the lazy table) -> a
            "tests/test_runs_module.py",       # -m pkg -> pkg.__main__ -> b -> a
            "tests/test_reads_every_source.py",  # a glob over *.py can read any module
            "tests/test_loads_by_path.py",     # names the file
        })

    def test_what_does_not_reach_a_module_is_not_selected(self):
        """The other direction, so the case above is not met by a selection of everything: a test
        that imports nothing of the package, and one that reaches the module only in a block a type
        checker reads and Python never runs, are left out."""
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-") as d:
            tree = _tree(Path(d), _MINI)
            got = set(mc._auswahl(tree, "src/pkg/a.py"))
        self.assertNotIn("tests/test_unrelated.py", got)
        self.assertNotIn("tests/test_type_only.py", got)

    def test_every_direct_importer_in_this_tree_is_selected(self):
        """Property 1 on the real tree, for every file an operator mutates: each test file that
        imports the operator's module by an import statement is in its selection."""
        import ast
        mc = _load()
        excluded = {f"tests/{n}.py" for n in mc._AUSSCHLUSS_JE_MUTANTE}
        imports: dict[str, set[str]] = {}
        for t in sorted((ROOT / "tests").rglob("test_*.py")):
            for k in ast.walk(ast.parse(t.read_text(encoding="utf-8", errors="replace"))):
                names = ([a.name for a in k.names] if isinstance(k, ast.Import) else
                         [f"{k.module}.{a.name}" for a in k.names] + [k.module or ""]
                         if isinstance(k, ast.ImportFrom) and not k.level else [])
                imports.setdefault(str(t.relative_to(ROOT)), set()).update(names)
        for rel in sorted({m[0] for m in mc.MUTATIONS if m[0].startswith("src/") and m[0].endswith(".py")}):
            modul = ".".join(Path(rel).with_suffix("").parts[1:]).removesuffix(".__init__")
            direct = {t for t, names in imports.items() if modul in names}
            with self.subTest(module=modul):
                missing = sorted(direct - set(mc._auswahl(ROOT, rel)) - excluded)
                self.assertEqual(missing, [], f"test files import {modul} and are not in its selection")

    def test_the_gates_own_controls_exist(self):
        mc = _load()
        for rel in mc._TOR_KONTROLLEN:
            with self.subTest(control=rel):
                self.assertTrue((ROOT / rel).is_file(), f"{rel} is named as a control and does not exist")


class ASelectionOnlyLosesKills(unittest.TestCase):
    """Property 2 and 3 on every small case, not on a chosen one."""

    TESTS = ("a", "b", "c", "d")

    def _subsets(self):
        return [set(c) for r in range(len(self.TESTS) + 1) for c in itertools.combinations(self.TESTS, r)]

    def test_a_kill_over_a_selection_is_a_kill_over_the_whole_suite(self):
        mc = _load()
        teilmengen = self._subsets()
        for basis, mutant, auswahl in itertools.product(teilmengen, teilmengen, teilmengen):
            b = {t: "call:AssertionError" for t in basis & auswahl}
            m = {t: "call:AssertionError" for t in mutant & auswahl}
            if mc._getoetet(b, m):
                full = mc._getoetet({t: "x" for t in basis}, {t: "x" for t in mutant})
                self.assertTrue(full, (basis, mutant, auswahl))

    def test_a_test_red_in_the_baseline_never_kills(self):
        mc = _load()
        teilmengen = self._subsets()
        for basis, mutant in itertools.product(teilmengen, teilmengen):
            toeter = mc._getoetet({t: "x" for t in basis}, {t: "x" for t in mutant})
            self.assertFalse(set(toeter) & basis, (basis, mutant, toeter))

    def test_the_old_count_rule_kills_on_a_selection_what_the_whole_suite_does_not(self):
        """Why the rule changed, as a case: `red > baseline` over counts. The baseline has one red
        test a, the mutant turns a green and b red. Over the whole suite the count stays 1, SURVIVED;
        over the selection {b} it is 0 against 1, KILLED."""
        def old(basis, mutant):
            return len(mutant) > len(basis)
        basis, mutant, auswahl = {"a"}, {"b"}, {"b"}
        self.assertFalse(old(basis, mutant))
        self.assertTrue(old(basis & auswahl, mutant & auswahl))


class TheGateEndToEnd(unittest.TestCase):
    """Property 3 through `_run_operators` itself, and property 4 and the restoration."""

    def _mini(self, d: str, core: bytes = b"def check(x):\n    if x is None:\n        return False\n    return True\n"):
        tree = _tree(Path(d), {"tests/test_core.py": "from mini.core import check\n\n\ndef test_it():\n    assert check(1)\n"})
        (tree / "src" / "mini").mkdir(parents=True)
        (tree / "src" / "mini" / "__init__.py").write_text("", encoding="utf-8")
        (tree / "src" / "mini" / "core.py").write_bytes(core)
        return tree

    def _run(self, mc, tree: Path, red_for, expect_killed: bool) -> int:
        """Run the real `_run_operators` over one operator, with the suite replaced by `red_for`,
        which gets the mutated file's text and returns {test id: class}. Works against a gate that
        passes `auswahl`/`aus` and against one that does not (the gate before Z230)."""
        def fake_red_count(work, *a, **k):
            rote = red_for((work / "src" / "mini" / "core.py").read_text(encoding="utf-8"))
            if isinstance(k.get("aus"), list):
                k["aus"].append(rote)
            return sum(len(v.split("+")) for v in rote.values())   # failures + errors, as JUnit counts
        mc.MUTATIONS = [("src/mini/core.py", "if x is None:", "if False:", "mini: check disabled", expect_killed)]
        mc._red_count = fake_red_count
        if hasattr(mc, "_GRAPH_JE_BAUM"):
            mc._GRAPH_JE_BAUM.clear()
        return mc._run_operators(tree)

    def test_a_baseline_red_test_that_also_fails_its_teardown_does_not_kill(self):
        """Red against the gate before Z230, where it counted: baseline 1 record, mutant 2 records
        (the same test, now also failing its teardown), `2 > 1`, KILLED, and for an operator documented
        as equivalent that is a gap."""
        mc = _load()

        def red_for(text):
            if "if False:" in text:
                return {"tests.test_core::test_it": "call:AssertionError+teardown:RuntimeError"}
            return {"tests.test_core::test_it": "call:AssertionError"}
        with tempfile.TemporaryDirectory(prefix="mutsel-") as d:
            tree = self._mini(d)
            (tree / "scripts").mkdir()
            (tree / "scripts" / "mutation_baseline_allowlist.json").write_text(
                '{"eintraege": [{"test": "tests.test_core::test_it", "fehlerklasse": "call:AssertionError", '
                '"art": "environment", "grund": "planted for this case"}]}', encoding="utf-8")
            self.assertEqual(self._run(mc, tree, red_for, expect_killed=False), 0)

    def test_a_new_red_test_still_kills(self):
        """The control: a test green in the baseline and red under the mutant kills."""
        mc = _load()

        def red_for(text):
            return {"tests.test_core::test_it": "call:AssertionError"} if "if False:" in text else {}
        with tempfile.TemporaryDirectory(prefix="mutsel-") as d:
            self.assertEqual(self._run(mc, self._mini(d), red_for, expect_killed=True), 0)

    def test_a_baseline_red_test_not_on_the_allowlist_stops_the_baseline(self):
        mc = _load()
        for allowlist in (None, '{"eintraege": [{"test": "tests.test_core::test_it", '
                                '"fehlerklasse": "call:PermissionError", "art": "environment", "grund": "x"}]}'):
            with self.subTest(allowlist=allowlist), tempfile.TemporaryDirectory(prefix="mutsel-") as d:
                tree = self._mini(d)
                if allowlist:
                    (tree / "scripts").mkdir()
                    (tree / "scripts" / "mutation_baseline_allowlist.json").write_text(allowlist, encoding="utf-8")
                with self.assertRaises(SystemExit) as stop:
                    self._run(mc, tree, lambda text: {"tests.test_core::test_it": "call:AssertionError"}, True)
                self.assertIn("allowlist", str(stop.exception.code))

    def test_the_mutated_file_is_restored_byte_for_byte(self):
        """A file with CRLF line ends: reading it as text and writing the text back gave LF, and the
        gate before Z230 checked the restoration only by the red count of a last full run."""
        mc = _load()
        core = b"def check(x):\r\n    if x is None:\r\n        return False\r\n    return True\r\n"
        with tempfile.TemporaryDirectory(prefix="mutsel-") as d:
            tree = self._mini(d, core)
            self._run(mc, tree, lambda text: {"tests.test_core::test_it": "call:AssertionError"}
                      if "if False:" in text else {}, True)
            self.assertEqual((tree / "src" / "mini" / "core.py").read_bytes(), core)


class TheAllowlistSaysWhyForEveryEntry(unittest.TestCase):
    """Owner decision C, Z231: each entry names the test, the class it fails with and a reason that
    lies in the environment; a real defect never goes on the list."""

    def test_every_entry_is_an_environment_failure_with_a_named_class(self):
        import json
        mc = _load()
        data = json.loads((ROOT / mc.ERLAUBNIS_DATEI).read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "proofbundle.mutation_baseline_allowlist.v1")
        erlaubt = set(data["allowed_kinds"])
        self.assertEqual(erlaubt, {"root", "network", "time-limit-under-load"})
        for e in data["eintraege"]:
            with self.subTest(test=e.get("test")):
                self.assertTrue(e.get("test"))
                self.assertIn(e.get("art"), erlaubt)
                self.assertTrue((e.get("grund") or "").strip())
                # an unnamed class would accept any failure of that test
                self.assertRegex(e.get("fehlerklasse", ""), r"^(call|setup|teardown|collection|error):[\w.]+")
                self.assertNotIn("unknown", e["fehlerklasse"])
        self.assertEqual(mc.lade_erlaubnisliste(ROOT), {e["test"]: e["fehlerklasse"] for e in data["eintraege"]})


class TheClassComesFromPytestsOwnReport(unittest.TestCase):
    """Property 5, with a real pytest run over a planted suite."""

    def test_identifiers_and_classes_of_a_real_run(self):
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-junit-") as d:
            tree = _tree(Path(d), {
                "tests/test_p.py": '''
                    import pytest
                    class TestK:
                        def test_a(self):
                            assert 1 == 2
                    @pytest.fixture
                    def f():
                        yield
                        raise RuntimeError("teardown")
                    def test_b(f):
                        assert False
                    def test_c():
                        raise PermissionError("root needed")
                    def test_d():
                        assert True
                    class OwnError(Exception):
                        pass
                    def test_e():
                        raise OwnError("an exception whose module name starts lower case")
                ''',
                "tests/test_q.py": "import a_module_that_is_not_there\n",
            })
            report = tree / "r.xml"
            subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            "-p", "no:randomly", "--continue-on-collection-errors", "tests",
                            f"--junitxml={report}"], cwd=tree, capture_output=True, text=True, timeout=120)
            rote = mc._rote_kennungen(report)
        self.assertEqual(rote, {
            "tests.test_p.TestK::test_a": "call:AssertionError",
            "tests.test_p::test_b": "call:AssertionError+teardown:RuntimeError",
            "tests.test_p::test_c": "call:PermissionError",
            "tests.test_q": "collection:ModuleNotFoundError",
            "tests.test_p::test_e": rote.get("tests.test_p::test_e", ""),
        })
        # A dotted name whose module part starts lower case is still a name: the first form read
        # `pre_tag_receipt_lib.BaumNichtLesbar` as `unknown` (eleven of the 38 baseline-red tests).
        self.assertRegex(rote["tests.test_p::test_e"], r"^call:[\w.]*OwnError$")


if __name__ == "__main__":
    unittest.main()
