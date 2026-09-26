"""The mutation gate judges each mutant by a selection of test files, and only a test that passed in
the baseline and fails again when it runs by itself kills (owner decisions C, Z230 and Z231,
2026-09-26, and Z230 round 2).

WHY. Measured on main in run 36253567619: the full suite took 1226-1661 s for a baseline and
1174-1610 s per mutant under a 60-minute job limit; the three shards that got a baseline judged one
mutant each before they were cancelled, and no other operator was judged. A mutant now runs the test
files that reach the mutated file (`mutation_check._auswahl`), and its baseline runs over the same
files.

THE PROPERTIES, each pinned below:
1. The selection holds every test file that reaches the mutated module directly or through other
   files ("in doubt one file more, never one less"): by an import, by Python code in a string, by
   `-m` or `runpy` wherever the literal stands, by a file name that several files carry, through a
   module anywhere in the tree, through a script that is not Python, and through a `conftest.py`
   above it. A file that is not Python (MANIFEST.in) is reached through every file that names it.
2. A selection can only lose kills, never add one: a mutant is killed only by a test that passed in
   the baseline over the same selection and is red under the mutant, and such a test is red over
   the whole suite too (tests taken as independent).
3. A test that did not pass in the baseline never kills: red there, skipped there (a test the
   baseline never ran read as a killer until round 2), xfailed, xpassed, or absent.
4. A killer counts only when it holds: red again under the mutant and green on the restored tree
   when it runs by itself. A test that flips (a timing test under load) is unstable and is named.
5. A baseline-red test that is not on the allowlist with the class it failed with stops the
   baseline; the class comes from the JUnit message first, and the restoration after the mutants is
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
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path
from unittest import mock

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


#: One test file per way of reaching `src/pkg/a.py` that the selection missed at 2502e6c7 (measured
#: by a lens with a planted tree), and the negative cases that must stay out.
_FORMEN = {
    "src/pkg/__init__.py": "",
    "src/pkg/a.py": "def f(x):\n    return x is not None\n",
    "src/pkg/__main__.py": "from .a import f\nprint(f(1))\n",
    "src/pkg/c.py": 'NAME = "runner"\n',          # a library string that names a module outside it
    "tools/one/helper.py": "from pkg.a import f\n",
    "tools/other/a.py": "Y = 2\n",                 # carries the file name of src/pkg/a.py as well
    "conformance/runner.py": "from pkg.a import f\n",
    "scripts/run.sh": "#!/bin/sh\n# a script that is not Python\npython3 -m pkg\n",
    "tests/test_dash_c.py": '''
        import subprocess, sys
        def test_x():
            subprocess.run([sys.executable, "-c", "import pkg.a; assert pkg.a.f(1)"], check=True)
    ''',
    "tests/test_dash_c_bound_before.py": '''
        import subprocess, sys
        CODE = "import pkg.a\\nassert pkg.a.f(1)\\n"
        def test_x():
            subprocess.run([sys.executable, "-c", CODE], check=True)
    ''',
    "tests/test_dash_c_that_does_not_parse.py": '''
        import subprocess, sys
        def test_x():
            subprocess.run([sys.executable, "-c",
                            "import sys; sys.path.insert(0, %r); from pkg.a import f; f(1)" % "src"])
    ''',
    "tests/test_m_in_a_list_bound_before.py": '''
        import subprocess, sys
        CMD = [sys.executable, "-m", "pkg"]
        def test_x():
            subprocess.run(CMD, check=True)
    ''',
    "tests/test_m_in_a_shell_line.py": '''
        import subprocess
        def test_x():
            subprocess.run("python3 -m pkg", shell=True, check=True)
    ''',
    "tests/test_run_module.py": '''
        import runpy
        def test_x():
            runpy.run_module("pkg", run_name="__main__")
    ''',
    "tests/test_run_path_of_a_directory.py": '''
        import runpy
        def test_x():
            runpy.run_path("src/pkg", run_name="__main__")
    ''',
    "tests/test_a_name_two_files_carry.py": '''
        import importlib.util, os
        def test_x():
            s = importlib.util.spec_from_file_location("x", os.path.join(os.environ["BASE"], "a.py"))
            m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    ''',
    "tests/test_outside_the_old_graph.py": '''
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parents[1] / "conformance"))
        import runner
        def test_x():
            assert runner.f(1)
    ''',
    "tests/test_runs_a_script.py": '''
        import subprocess
        def test_x():
            subprocess.run(["sh", "scripts/run.sh"], check=True)
    ''',
    "tests/test_pytest_argv_bound_before.py": '''
        import subprocess, sys
        ARGS = [sys.executable, "-m", "pytest", "-q", "tests/test_direct.py"]
        def test_x():
            subprocess.run(ARGS, check=True)
    ''',
    "tests/test_direct.py": "from pkg.a import f\ndef test_x():\n    assert f(1)\n",
    # stay out
    "tests/test_unrelated.py": "def test_x():\n    assert True\n",
    "tests/test_git_message.py": '''
        import subprocess
        def commit(message):
            subprocess.run(["git", "commit", "-m", message])
        def test_x():
            assert commit
    ''',
    "tests/test_runs_itself.py": '''
        import pytest
        def test_x():
            assert True
        if __name__ == "__main__":
            raise SystemExit(pytest.main([__file__, "-q"]))
    ''',
    "tests/test_library_string.py": "import pkg.c\ndef test_x():\n    assert pkg.c.NAME\n",
}


class TheSelectionHoldsEveryImporter(unittest.TestCase):
    """Property 1, on planted trees where every way of reaching a module is present once."""

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

    def test_every_form_of_reaching_a_module(self):
        """Each form a lens measured as missed at 2502e6c7, one test file each; all of them are red
        against that gate. And the negative cases: a git commit message after `-m`, a test that runs
        pytest on itself only when it is run as a script, and a library module whose string names a
        module outside the library (nothing under src/ puts a directory on sys.path)."""
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-formen-") as d:
            tree = _tree(Path(d), _FORMEN)
            got = set(mc._auswahl(tree, "src/pkg/a.py"))
        for rel, why in {
            "tests/test_direct.py": "imports it (the control)",
            "tests/test_dash_c.py": "`python -c` with an import statement",
            "tests/test_dash_c_bound_before.py": "the `-c` code is a name bound before the call",
            "tests/test_dash_c_that_does_not_parse.py": "the `-c` code is formatted and does not parse",
            "tests/test_m_in_a_list_bound_before.py": "`-m pkg` in a list bound outside the call",
            "tests/test_m_in_a_shell_line.py": "`-m pkg` in a command line held in one string",
            "tests/test_run_module.py": "`runpy.run_module('pkg')` runs pkg.__main__",
            "tests/test_run_path_of_a_directory.py": "`runpy.run_path('src/pkg')` runs its __main__.py",
            "tests/test_a_name_two_files_carry.py": "a bare file name that two files carry names both",
            "tests/test_outside_the_old_graph.py": "a module under conformance/, on sys.path",
            "tests/test_runs_a_script.py": "a shell script that runs `python3 -m pkg`",
            "tests/test_pytest_argv_bound_before.py": "a pytest command bound outside the call",
        }.items():
            with self.subTest(form=why):
                self.assertIn(rel, got)
        for rel in ("tests/test_unrelated.py", "tests/test_git_message.py", "tests/test_runs_itself.py",
                    "tests/test_library_string.py"):
            with self.subTest(stays_out=rel):
                self.assertNotIn(rel, got)

    def test_a_file_that_is_not_python_is_reached_through_the_files_that_name_it(self):
        """MANIFEST.in, read by a helper that a test imports: at 2502e6c7 the selection held only
        the files that name it, not the files that reach those, and here it was empty."""
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-manifest-") as d:
            tree = _tree(Path(d), {
                "MANIFEST.in": "include x\n",
                "scripts/manifest_lib.py": "def lines():\n    return open('MANIFEST.in').read().splitlines()\n",
                "tests/test_manifest_via_script.py": "import manifest_lib\ndef test_x():\n    assert manifest_lib.lines()\n",
                "tests/test_unrelated.py": "def test_x():\n    assert True\n",
            })
            got = set(mc._auswahl(tree, "MANIFEST.in"))
        self.assertIn("tests/test_manifest_via_script.py", got)
        self.assertNotIn("tests/test_unrelated.py", got)

    def test_a_conftest_below_tests_selects_the_tests_below_it(self):
        """A `conftest.py` loads for every test under its directory; at 2502e6c7 only
        tests/conftest.py counted."""
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-conftest-") as d:
            tree = _tree(Path(d), {
                "src/pkg/__init__.py": "",
                "src/pkg/a.py": "def f(x):\n    return x\n",
                "tests/sub/conftest.py": "import pkg.a\n",
                "tests/sub/test_below.py": "def test_x():\n    assert True\n",
                "tests/test_beside.py": "def test_x():\n    assert True\n",
            })
            got = set(mc._auswahl(tree, "src/pkg/a.py"))
        self.assertIn("tests/sub/test_below.py", got)
        self.assertNotIn("tests/test_beside.py", got)

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

    def test_the_hops_a_lens_measured_in_this_tree_are_selected(self):
        """Property 1 on the real tree, for the chains a lens measured as broken at 2502e6c7: a hop
        through conformance/ or examples/, or Python code after `-c`. The first case is the killer
        it measured: with "strict-json: duplicate-key reject disabled" applied,
        test_cap1_conformance_runner.py::test_ein_dokument_mit_doppeltem_namen_ist_kein_pass fails,
        and the file was absent from the selection of `_strict_json.py`.

        Each test must be in the module's selection, AND reach it by a chain of edges that passes
        through no `conftest.py` and no file that reaches everything, so the case keeps measuring the
        chain when a wider rule would select the file anyway."""
        mc = _load()
        faelle = [
            ("tests/test_cap1_conformance_runner.py", "_strict_json"),
            ("tests/test_cap1_conformance_runner.py", "budget"),
            ("tests/test_cap1_conformance_runner.py", "relation"),
            ("tests/test_cap1_conformance_runner.py", "anchors_ots"),
            ("tests/test_cross_format_singleton_361.py", "relation"),
            ("tests/test_cross_format_singleton_361.py", "budget"),
            ("tests/test_agent_review_conformance_runner.py", "relation"),
            ("tests/test_agent_review_conformance_runner.py", "anchors_ots"),
            ("tests/test_rekor_interop.py", "budget"),
            ("tests/test_rust_policy_reader_judges_the_relations_section.py", "cli"),
        ]
        mc._auswahl(ROOT, "src/proofbundle/cli.py")          # builds the graph once, as the gate does
        graph = mc._GRAPH_JE_BAUM[str(ROOT)]
        kanten, ueberall = graph[0], graph[1]

        def kette(start: str, ziel: str) -> list[str] | None:
            vorher: dict[str, str | None] = {start: None}
            offen = deque([start])
            while offen:
                x = offen.popleft()
                if x == ziel:
                    weg = []
                    while x is not None:
                        weg.append(x)
                        x = vorher[x]
                    return weg[::-1]
                for y in sorted(kanten.get(x, ())):
                    if y not in vorher and y not in ueberall and Path(y).name != "conftest.py":
                        vorher[y] = x
                        offen.append(y)
            return None

        for test, modul in faelle:
            rel = f"src/proofbundle/{modul}.py"
            with self.subTest(test=test, module=modul):
                self.assertIn(test, mc._auswahl(ROOT, rel))
                self.assertNotIn(test, ueberall, "the case would not measure a chain")
                self.assertIsNotNone(kette(test, rel), f"no chain of edges from {test} to {rel}")

    def test_the_gates_own_controls_exist(self):
        mc = _load()
        for rel in mc._TOR_KONTROLLEN:
            with self.subTest(control=rel):
                self.assertTrue((ROOT / rel).is_file(), f"{rel} is named as a control and does not exist")


class ASelectionOnlyLosesKills(unittest.TestCase):
    """Properties 2 and 3 on every small case, not on a chosen one."""

    TESTS = ("a", "b", "c", "d")
    AUSGANG = ("passed", "red", "skipped")

    def _subsets(self):
        return [set(c) for r in range(len(self.TESTS) + 1) for c in itertools.combinations(self.TESTS, r)]

    def test_a_kill_over_a_selection_is_a_kill_over_the_whole_suite(self):
        mc = _load()
        teilmengen = self._subsets()
        for ausgang in itertools.product(self.AUSGANG, repeat=len(self.TESTS)):
            bestanden = {t for t, a in zip(self.TESTS, ausgang) if a == "passed"}
            for mutant, auswahl in itertools.product(teilmengen, teilmengen):
                m = {t: "call:AssertionError" for t in mutant & auswahl}
                if mc._getoetet(bestanden & auswahl, m):
                    full = mc._getoetet(bestanden, {t: "x" for t in mutant})
                    self.assertTrue(full, (ausgang, mutant, auswahl))

    def test_a_test_that_did_not_pass_in_the_baseline_never_kills(self):
        """Red, skipped or absent there: none of them is a killer (at 2502e6c7 a skipped one was)."""
        mc = _load()
        teilmengen = self._subsets()
        for ausgang in itertools.product(self.AUSGANG + ("absent",), repeat=len(self.TESTS)):
            bestanden = {t for t, a in zip(self.TESTS, ausgang) if a == "passed"}
            for mutant in teilmengen:
                toeter = mc._getoetet(bestanden, {t: "x" for t in mutant})
                self.assertTrue(set(toeter) <= bestanden, (ausgang, mutant, toeter))

    def test_a_module_that_fails_to_collect_under_the_mutant_kills(self):
        """A collection error has a record without `::`; it kills when a test of that module passed
        in the baseline, and not when none did."""
        mc = _load()
        self.assertEqual(mc._getoetet({"tests.test_q::test_x", "tests.test_q.TestK::test_y"},
                                      {"tests.test_q": "collection:ImportError"}), ["tests.test_q"])
        self.assertEqual(mc._getoetet({"tests.test_other::test_x"},
                                      {"tests.test_q": "collection:ImportError"}), [])

    def test_the_old_count_rule_kills_on_a_selection_what_the_whole_suite_does_not(self):
        """Why the rule changed, as a case: `red > baseline` over counts. The baseline has one red
        test a, the mutant turns a green and b red. Over the whole suite the count stays 1, SURVIVED;
        over the selection {b} it is 0 against 1, KILLED."""
        def old(basis, mutant):
            return len(mutant) > len(basis)
        basis, mutant, auswahl = {"a"}, {"b"}, {"b"}
        self.assertFalse(old(basis, mutant))
        self.assertTrue(old(basis & auswahl, mutant & auswahl))


class AKillerMustHold(unittest.TestCase):
    """Property 4 as a function: which killers hold after they ran again by themselves."""

    def test_red_again_under_the_mutant_and_green_on_the_restored_tree(self):
        mc = _load()
        k = "tests.test_t::test_x"
        self.assertEqual(mc._bestaetigt([k], {k: "call:AssertionError"}, {}, {k}), ([k], []))
        self.assertEqual(mc._bestaetigt([k], {}, {}, {k}), ([], [k]))                        # flipped under the mutant
        self.assertEqual(mc._bestaetigt([k], {k: "x"}, {k: "x"}, set()), ([], [k]))          # red on the restored tree
        self.assertEqual(mc._bestaetigt([k], None, None, None), ([], [k]))                   # no verdict
        modul = "tests.test_q"
        self.assertEqual(mc._bestaetigt([modul], {modul: "collection:ImportError"}, {},
                                        {"tests.test_q::test_x"}), ([modul], []))

    def test_node_ids_and_report_identifiers_are_one_mapping(self):
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-ids-") as d:
            tree = _tree(Path(d), {"tests/test_p.py": "", "tests/sub/test_s.py": ""})
            for knoten in ("tests/test_p.py::test_a", "tests/test_p.py::TestK::test_b",
                           "tests/test_p.py::test_c[x-1]", "tests/sub/test_s.py::test_d", "tests/test_p.py"):
                with self.subTest(knoten=knoten):
                    self.assertEqual(mc._knoten_der_kennung(tree, mc._kennung_des_knotens(knoten)), knoten)
            self.assertIsNone(mc._knoten_der_kennung(tree, "tests.test_gone::test_x"))


class TheGateEndToEnd(unittest.TestCase):
    """Properties 3, 4 and 5 through `_run_operators` itself."""

    def _mini(self, d: str, core: bytes = b"def check(x):\n    if x is None:\n        return False\n    return True\n"):
        tree = _tree(Path(d), {"tests/test_core.py": "from mini.core import check\n\n\ndef test_it():\n    assert check(1)\n"})
        (tree / "src" / "mini").mkdir(parents=True)
        (tree / "src" / "mini" / "__init__.py").write_text("", encoding="utf-8")
        (tree / "src" / "mini" / "core.py").write_bytes(core)
        return tree

    def _run(self, mc, tree: Path, red_for, expect_killed: bool) -> int:
        """Run the real `_run_operators` over one operator, with the suite replaced by `red_for`,
        which gets the mutated file's text and returns {test id: class}. Works against a gate that
        passes `auswahl`/`aus`/`gruen` and against one that does not (the gate before Z230)."""
        def fake_red_count(work, *a, **k):
            rote = red_for((work / "src" / "mini" / "core.py").read_text(encoding="utf-8"))
            if isinstance(k.get("aus"), list):
                k["aus"].append(rote)
            if isinstance(k.get("gruen"), list):
                k["gruen"].append({"tests.test_core::test_it"} - set(rote))
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
        """The control: a test green in the baseline and red under the mutant kills, and it holds
        when it runs again (red under the mutant, green on the restored file)."""
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


def _echter_lauf(files: dict[str, str], operator: tuple) -> tuple[int, str]:
    """`_run_operators` with real pytest over a planted tree and one operator; (gaps, its output)."""
    import contextlib
    import io
    mc = _load()
    with tempfile.TemporaryDirectory(prefix="mutsel-echt-") as d:
        tree = _tree(Path(d), files)
        mc.MUTATIONS = [operator]
        ausgabe = io.StringIO()
        with contextlib.redirect_stdout(ausgabe):
            gaps = mc._run_operators(tree)
    return gaps, ausgabe.getvalue()


_OPTIONAL = {
    "src/mini/__init__.py": "",
    "src/mini/core.py": '''
        FAST_PATH = False          # an optional path, off in this build


        def check(x):
            if x is None:
                return False
            return True


        def fast_check(x):
            return x is not None or x == 0     # a defect in the optional path, there before the mutant
    ''',
}


class OnlyAPassedTestKillsWithRealPytest(unittest.TestCase):
    """Properties 3 and 4 with real pytest runs over planted trees, through `_run_operators`."""

    #: An operator documented as equivalent for `check`: it only switches the optional path on.
    GLEICHWERTIG = ("src/mini/core.py", "FAST_PATH = False", "FAST_PATH = True",
                    "mini: optional path switched on (EQUIVALENT for check)", False)

    def test_a_test_skipped_in_the_baseline_does_not_kill(self):
        """The lens's case (Z-2): the test is skipped while the optional path is off, runs and fails
        under the mutant, and the failure is in `fast_check`, not in anything the mutant changed. At
        2502e6c7 it read as KILLED, a gap for an operator documented as equivalent."""
        gaps, out = _echter_lauf({**_OPTIONAL, "tests/test_core.py": '''
            import pytest
            from mini import core


            def test_check():
                assert core.check(1) and not core.check(None)


            @pytest.mark.skipif(not core.FAST_PATH, reason="fast path off in this build")
            def test_fast_path_rejects_zero():
                assert core.fast_check(0) is False
        '''}, self.GLEICHWERTIG)
        self.assertEqual(gaps, 0, out)
        self.assertIn("SURVIVED", out)

    def test_a_killer_that_flips_when_it_runs_again_does_not_count(self):
        """Owner addendum: a timing test green in the baseline and red under a mutant only because
        the machine got loaded read as a kill. Planted with a run counter: red from the second run on
        (the load stays: red again under the mutant, red on the restored tree), and red on exactly
        the second run (the load passes: green again under the mutant). Both read as KILLED at
        2502e6c7; both are unstable now and named, and the operator survives as documented."""
        for name, bedingung in (("red from the second run on", "n < 2"), ("red on the second run only", "n != 2")):
            with self.subTest(case=name):
                gaps, out = _echter_lauf({**_OPTIONAL, "tests/test_timing.py": f'''
                    from pathlib import Path
                    from mini import core

                    ZAEHLER = Path(__file__).with_name("runs.txt")


                    def test_under_load():
                        n = int(ZAEHLER.read_text()) + 1 if ZAEHLER.exists() else 1
                        ZAEHLER.write_text(str(n))
                        assert core.check(1)
                        assert {bedingung}, "the machine got loaded after the baseline"
                '''}, self.GLEICHWERTIG)
                self.assertEqual(gaps, 0, out)
                self.assertIn("unstable, not counted (1): tests.test_timing::test_under_load", out)

    def test_a_real_kill_holds(self):
        """The control: a test that fails because of the mutant is red again under it and green on
        the restored tree, and the mutant is KILLED."""
        gaps, out = _echter_lauf({**_OPTIONAL, "tests/test_core.py": '''
            from mini import core


            def test_none_is_refused():
                assert core.check(None) is False
        '''}, ("src/mini/core.py", "if x is None:", "if False:", "mini: None check disabled", True))
        self.assertEqual(gaps, 0, out)
        self.assertIn("confirmed=1", out)
        self.assertIn("killed by tests.test_core::test_none_is_refused", out)


class TheSuiteRunIsPinned(unittest.TestCase):
    def test_the_hash_seed_is_the_same_in_every_suite_run(self):
        """Baseline and mutant runs compare test ids; a parametrised id built from a set changes with
        the hash seed from one process to the next unless the seed is pinned."""
        mc = _load()
        gesehen = {}

        def fake_run(argv, **kw):
            gesehen.update(kw.get("env") or {})
            return subprocess.CompletedProcess(argv, 0, "", "")
        with tempfile.TemporaryDirectory(prefix="mutsel-env-") as d, \
                mock.patch.object(mc.subprocess, "run", fake_run):
            mc._lauf_der_suite(Path(d), None, ("tests",))
        self.assertEqual(gesehen.get("PYTHONHASHSEED"), "0")


class TheReportNamesThePassedTests(unittest.TestCase):
    def test_passed_means_ran_and_passed(self):
        """A real run through the gate's own suite call: only a test that ran and passed is passed;
        a failed, errored, skipped, xfailed or xpassed test is not (pytest writes an xpassed test
        into the report like a passing one; the short summary names it)."""
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-bestanden-") as d:
            tree = _tree(Path(d), {"tests/test_p.py": '''
                import pytest

                def test_pass():
                    assert True

                def test_fail():
                    assert False

                @pytest.fixture
                def kaputt():
                    raise RuntimeError("setup")

                def test_error(kaputt):
                    pass

                def test_skip():
                    pytest.skip("not here")

                @pytest.mark.xfail(reason="known")
                def test_xfail():
                    assert False

                @pytest.mark.xfail(reason="known")
                def test_xpass():
                    assert True

                @pytest.mark.xfail(reason="known", strict=True)
                def test_xpass_strict():
                    assert True

                @pytest.mark.parametrize("v", [1])
                def test_param(v):
                    assert v
            '''})
            bericht = tree / "r.xml"
            proc = mc._lauf_der_suite(tree, bericht, ("tests",))
            bestanden = mc._bestandene_kennungen(bericht, proc.stdout)
        self.assertEqual(bestanden, {"tests.test_p::test_pass", "tests.test_p::test_param[1]"})


def _fall(tag: str, message: str, text: str = ""):
    k = ET.Element(tag, message=message)
    k.text = text
    return k


class TheClassComesFromPytestsOwnReport(unittest.TestCase):
    """Property 5, from the message first and from the traceback only when the message names none."""

    def test_the_message_decides_before_the_traceback(self):
        """The lens's case (Z-3): a RuntimeError whose message carries an `assert` line read as
        AssertionError at 2502e6c7, and so did a KeyError raised while handling a failed assert, and
        a failed assert in a teardown read as `teardown:assert`."""
        mc = _load()
        for knoten, klasse in (
            (_fall("failure", "RuntimeError: the child failed:\nassert digest == expected",
                   "E       RuntimeError: the child failed:\nE       assert digest == expected\n"), "call:RuntimeError"),
            (_fall("failure", "KeyError: 'k'",
                   "E       assert None == 1\n\nDuring handling of the above exception, another exception "
                   "occurred:\n\nE           KeyError: 'k'\n"), "call:KeyError"),
            (_fall("error", 'failed on teardown with "assert 1 == 2"', "E       assert 1 == 2\n"),
             "teardown:AssertionError"),
            (_fall("failure", "assert 1 == 2", "E       assert 1 == 2\n"), "call:AssertionError"),
            (_fall("failure", "AssertionError: the tool is missing\nassert False"), "call:AssertionError"),
            (_fall("error", "collection failure", "E   ModuleNotFoundError: No module named 'x'\n"),
             "collection:ModuleNotFoundError"),
        ):
            with self.subTest(message=knoten.get("message")):
                self.assertEqual(mc._fehlerklasse(knoten), klasse)

    def test_an_allowlist_entry_does_not_accept_another_failure(self):
        """End to end with real pytest: an entry for `call:AssertionError` must not accept a
        RuntimeError whose message carries an `assert` line (at 2502e6c7 the baseline accepted it)."""
        mc = _load()
        with tempfile.TemporaryDirectory(prefix="mutsel-klasse-") as d:
            tree = _tree(Path(d), {
                "tests/test_env.py": '''
                    def test_child_reports():
                        raise RuntimeError("the child failed:\\nassert digest == expected")
                ''',
                "scripts/mutation_baseline_allowlist.json": '''
                    {"eintraege": [{"test": "tests.test_env::test_child_reports",
                      "fehlerklasse": "call:AssertionError", "art": "network", "grund": "planted"}]}
                ''',
            })
            with self.assertRaises(SystemExit) as stop:
                mc._basislinie(tree, ("tests/test_env.py",), mc.lade_erlaubnisliste(tree))
        self.assertIn("allowlist", str(stop.exception.code))

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

    def test_the_list_ships_with_the_script_that_reads_it(self):
        """MANIFEST.in decides the list the way it decides scripts/mutation_check.py: in. Undecided
        at 2502e6c7, the list was missing from the sdist, and this contract failed there with
        FileNotFoundError (CI, PR 285, job hermetic-cleanroom)."""
        mc = _load()
        manifest = [z.strip() for z in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()]
        self.assertIn("include scripts/mutation_check.py", manifest)
        self.assertIn(f"include {mc.ERLAUBNIS_DATEI}", manifest)


if __name__ == "__main__":
    unittest.main()
