"""The crypto-floor job runs the suite in five parts, and the five parts together are the suite, test for test.

Owner choice of 2026-10-28: crypto-floor gets faster, rather than keeping a raised time limit. Before
the split the job ran one serial `python -m unittest discover -s tests`: 43m40s at main 4e333f8e
(run 40887037072), the suite step `Ran 5378 tests in 2529.946s`, `OK (skipped=229)`.

THE SPLIT KEEPS THE RUNNER AND THE LOADER. Each part runs the same command with its own `-k`
selection. `-k` is unittest's own filter: the loader keeps a test method when one of the patterns
matches `module.Class.method` (`TestLoader.getTestCaseNames`), and every module is loaded as before.
A split by file name was not enough: five tests of one file each run the whole audit matrix, 1389 of
the 2530 s in the log of that run.

What can go wrong is the partition. A test that no part selects runs nowhere, and the job stays
green over a smaller suite. A test that two parts select runs twice. A part that is skipped or may
fail without failing the job drops its tests in silence. This contract loads the whole suite the way
`unittest discover -s tests` does, in a process of its own, checks that every test it finds is
selected by exactly one part, and checks that every part runs and counts.

A SECOND THING `-k` TOUCHES. `unittest.main` sets the patterns on the shared
`unittest.defaultTestLoader`. Code that loads tests through that object while the suite runs would
be filtered too and could quietly run fewer cases than it asserts on. Nothing in tests/, scripts/,
src/, conformance/ or formal/ uses it today; a case below keeps it that way. It counts the object
under any local name: imported under an alias, or fetched with `getattr` or a subscript by its name
(reading of pull request 436, line 3, P2 on Z4 and Z5).

A STAND-IN RUNS IN EVERY PART. A module that raises `unittest.SkipTest` while it is imported becomes
a stand-in test the loader builds directly, so no `-k` filters it out: a skip counted once in the
serial run is counted once per part. The real suite must load no such stand-in (the same reading,
P2 on Z6 and Z1); a case below builds one and shows that it is found.
"""
from __future__ import annotations

import ast
import fnmatch
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover - the [dev] extra carries PyYAML
    yaml = None

REPO = pathlib.Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"

#: The suite step of every part. The selection reaches the shell through the environment, and
#: `set -f` keeps the shell from expanding the patterns against the files of the checkout.
SUITE = "set -f; python -m unittest discover -s tests $SELECTION"

#: Loads the suite exactly as `python -m unittest discover -s tests` does from the current directory
#: and prints every test id.
_LOAD = r"""
import json, os, sys, unittest
sys.path[0] = os.getcwd()
def flat(s):
    for t in s:
        if isinstance(t, unittest.TestSuite):
            yield from flat(t)
        else:
            yield t
print(json.dumps([t.id() for t in flat(unittest.TestLoader().discover("tests", "test*.py", None))]))
"""

#: The prefix of the stand-in tests the loader makes for a module it cannot import or must skip
#: (`unittest.loader._FailedTest`, `unittest.loader.ModuleSkipped`). The loader builds them directly,
#: not through `getTestCaseNames`, so no `-k` filters them out: such a stand-in runs in EVERY part, and
#: a failed import turns every part red. They are outside the partition, and a case below pins that.
STAND_IN = "unittest.loader."
#: The stand-in of a module that skipped itself at import. A failed import is loud in every part; a
#: skipped one is silent, and it multiplies the skip count by the number of parts.
MODULE_SKIPPED = "unittest.loader.ModuleSkipped."


def as_unittest_pattern(pattern: str) -> str:
    """What `-k` makes of a pattern: one without `*` is a substring (unittest.main._convert_select_pattern)."""
    return pattern if "*" in pattern else f"*{pattern}*"


def read_selection(selection: str) -> tuple[list[str], list[str]]:
    """(patterns, findings) of one part's selection: `-k <pattern>` pairs and nothing else."""
    words = selection.split()
    patterns, findings = [], []
    if len(words) % 2 or not words:
        findings.append(f"the selection {selection!r} is not a list of `-k <pattern>` pairs")
        return patterns, findings
    for flag, value in zip(words[::2], words[1::2]):
        if flag != "-k":
            findings.append(f"the selection {selection!r} carries {flag!r} where `-k` belongs")
        else:
            patterns.append(value)
    return patterns, findings


def partition_findings(ids: list[str], parts: dict[str, list[str]]) -> list[str]:
    """Where the parts are not a partition of the loaded ids. Pure, so a built counter-example can make
    it fail. A test id is `module.Class.method`, the very name `-k` is matched against."""
    findings = []
    if not parts:
        findings.append("no part at all")
    for tid in ids:
        hits = sorted(name for name, patterns in parts.items()
                      if any(fnmatch.fnmatchcase(tid, as_unittest_pattern(p)) for p in patterns))
        if not hits:
            findings.append(f"{tid}: no part runs it")
        elif len(hits) > 1:
            findings.append(f"{tid}: {len(hits)} parts run it {hits}")
    return findings


def stand_in_findings(ids: list[str]) -> list[str]:
    """The stand-ins of modules that skipped themselves at import: each would run in every part."""
    return [f"{tid}: a module skipped at import, so every part runs and counts this stand-in"
            for tid in ids if tid.startswith(MODULE_SKIPPED)]


def job_findings(job: dict) -> list[str]:
    """Where the job shape lets a part drop out or stop counting. Pure, like the one above."""
    findings = []
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    numbers = [str(p) for p in matrix.get("part") or []]
    selections = {str(e.get("part")): str(e.get("selection") or "") for e in matrix.get("include") or []}
    if (job.get("strategy") or {}).get("fail-fast") is not False:
        findings.append("fail-fast is not false: one red part would cancel the others")
    if sorted(numbers) != sorted(selections) or len(set(numbers)) != len(numbers):
        findings.append(f"the parts {numbers} and the selections {sorted(selections)} do not match one to one")
    if "exclude" in matrix:
        findings.append("the matrix carries an exclude, which can drop a part")
    if job.get("name") != f"crypto-floor (${{{{ matrix.part }}}} of {len(numbers)})":
        findings.append(f"the job name {job.get('name')!r} does not count the {len(numbers)} parts")
    for key in ("if", "continue-on-error"):
        if key in job:
            findings.append(f"the job carries `{key}`, so a part may not run or may fail without failing it")
    suite = [s for s in job.get("steps") or [] if "unittest discover" in str(s.get("run", ""))]
    if len(suite) != 1:
        return findings + [f"expected one suite step, found {len(suite)}"]
    step = suite[0]
    if str(step.get("run", "")).strip() != SUITE:
        findings.append(f"the suite step runs {step.get('run')!r}, not {SUITE!r}")
    if (step.get("env") or {}).get("SELECTION") != "${{ matrix.selection }}":
        findings.append("the suite step does not take SELECTION from the matrix")
    for key in ("if", "continue-on-error"):
        if key in step:
            findings.append(f"the suite step carries `{key}`")
    for part, selection in sorted(selections.items()):
        findings += [f"part {part}: {f}" for f in read_selection(selection)[1]]
    return findings


def parts_of(job: dict) -> dict[str, list[str]]:
    """The `-k` patterns of each part, by part number."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    return {str(e.get("part")): read_selection(str(e.get("selection") or ""))[0]
            for e in matrix.get("include") or []}


def load_ids(root: pathlib.Path) -> list[str]:
    """Every test id `unittest discover -s tests` finds under `root`, loaded in a process of its own."""
    r = subprocess.run([sys.executable, "-c", _LOAD], cwd=root, capture_output=True, text=True,
                       timeout=600, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if r.returncode != 0:
        raise AssertionError(f"loading the suite failed: {r.stderr[-2000:]}")
    return json.loads(r.stdout.strip().splitlines()[-1])


_LOADER = "defaultTestLoader"


def _origins(tree: ast.AST) -> tuple[set[str], set[str], set[str]]:
    """(names bound to unittest or one of its modules, names bound by an import from elsewhere, names bound in the module
    by an assignment, a definition or an argument). The first reading of PR 440 (Z6) found that a name alone said nothing
    about where a value comes from."""
    ours: set[str] = set()
    theirs: set[str] = set()
    local: set[str] = set()
    for k in ast.walk(tree):
        if isinstance(k, ast.Import):
            for a in k.names:
                bound = a.asname or a.name.split(".", 1)[0]
                (ours if a.name == "unittest" or a.name.startswith("unittest.") else theirs).add(bound)
        elif isinstance(k, ast.ImportFrom):
            from_unittest = k.module == "unittest" or str(k.module or "").startswith("unittest.")
            for a in k.names:
                (ours if from_unittest and a.name != _LOADER else theirs if not from_unittest else set()).add(
                    a.asname or a.name)
        elif isinstance(k, ast.Name) and isinstance(k.ctx, ast.Store):
            local.add(k.id)
        elif isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local.add(k.name)
        elif isinstance(k, ast.arg):
            local.add(k.arg)
    return ours, theirs, local


def _may_be_unittest(v: ast.AST, ours: set[str], theirs: set[str], local: set[str]) -> bool:
    """Can this value be unittest or one of its modules? A name bound to unittest can, a name bound only by an import
    from elsewhere cannot, and every value whose origin is not read here can (the strict direction). The origins are
    read for the whole module, not per scope, so a name the module also binds otherwise (a parameter, an assignment)
    can too: a foreign import of `m` hid the parameter `m` of another function (reading of the follow-up to 441, line
    3, P2). For the same reason a name bound to unittest anywhere counts, also where another binding is in reach."""
    if isinstance(v, ast.Name):
        return v.id in ours or v.id not in theirs or v.id in local
    return True


def _names_the_loader(k: ast.AST, ours: set[str], theirs: set[str], local: set[str]) -> bool:
    """Whether one node reaches the shared loader of unittest: as an attribute of a value that may be unittest, as the
    name imported from unittest, as an import of it under any alias, or fetched by its name with `getattr` or from the
    namespace of a module. A name of the same spelling from elsewhere or bound in the module, and a key of a plain
    mapping, are not the shared loader."""
    if isinstance(k, ast.Attribute):
        return k.attr == _LOADER and _may_be_unittest(k.value, ours, theirs, local)
    if isinstance(k, ast.Name):
        return k.id == _LOADER and isinstance(k.ctx, ast.Load) and k.id not in theirs and k.id not in local
    if isinstance(k, ast.ImportFrom):
        return ((k.module == "unittest" or str(k.module or "").startswith("unittest."))
                and any(a.name == _LOADER for a in k.names))
    if isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id == "getattr":
        return (len(k.args) > 1 and isinstance(k.args[1], ast.Constant) and k.args[1].value == _LOADER
                and _may_be_unittest(k.args[0], ours, theirs, local))
    if isinstance(k, ast.Subscript) and isinstance(k.slice, ast.Constant) and k.slice.value == _LOADER:
        v = k.value
        if isinstance(v, ast.Name):
            return False                     # a plain mapping; the namespace of a module is vars(m) or m.__dict__
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "vars" and v.args:
            return _may_be_unittest(v.args[0], ours, theirs, local)
        if isinstance(v, ast.Attribute) and v.attr == "__dict__":
            return _may_be_unittest(v.value, ours, theirs, local)
        return True
    return False


def shared_loader_lines(source: str) -> list[int]:
    """Lines that reach `defaultTestLoader` of unittest in code, outside an `if __name__ == "__main__":` block."""
    tree = ast.parse(source)
    ours, theirs, local = _origins(tree)
    exempt: set[int] = set()
    for k in ast.walk(tree):
        if (isinstance(k, ast.If) and isinstance(k.test, ast.Compare)
                and isinstance(k.test.left, ast.Name) and k.test.left.id == "__name__"):
            exempt |= {n.lineno for n in ast.walk(k) if hasattr(n, "lineno")}
    return sorted({k.lineno for k in ast.walk(tree)
                   if _names_the_loader(k, ours, theirs, local) and k.lineno not in exempt})


def _floor_job() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["crypto-floor"]


@unittest.skipIf(yaml is None, "PyYAML is missing, so the workflow cannot be read")
class TheFloorJobRunsTheWholeSuiteInParts(unittest.TestCase):

    def test_every_part_runs_the_same_command_and_counts(self):
        self.assertEqual(job_findings(_floor_job()), [])

    def test_the_pattern_rule_is_the_one_unittest_applies(self):
        # The module, not the attribute: `unittest.main` is the TestProgram class on the package.
        import importlib  # noqa: PLC0415
        unittest_main = importlib.import_module("unittest.main")
        for pattern in ("test_a_*", "test_audit_candidate_360.TestAuditCandidateMatrix.test_x"):
            self.assertEqual(as_unittest_pattern(pattern), unittest_main._convert_select_pattern(pattern))

    def test_every_test_of_the_suite_runs_in_exactly_one_part(self):
        ids = load_ids(REPO)
        # A sweep over an empty set is green and says nothing. The floor is far below the 5378 of
        # 2026-10-29 on purpose: it catches a blind load, not a smaller suite.
        self.assertGreater(len(ids), 1000, f"only {len(ids)} tests loaded, the load is blind")
        self.assertEqual(stand_in_findings(ids), [])
        selectable = [i for i in ids if not i.startswith(STAND_IN)]
        self.assertEqual(partition_findings(selectable, parts_of(_floor_job())), [])


class TheCommentClaimsNoMoreThanTheContractCarries(unittest.TestCase):
    """Reading of pull request 436, line 3, P2 on Z7: the contract holds test IDs and the job shape,
    not the same execution. The parts run in separate processes, and the comment of the job says so."""

    def test_the_comment_says_the_parts_run_in_separate_processes(self):
        text = CI.read_text(encoding="utf-8")
        start = text.index("\n  crypto-floor:\n")
        block = text[start:text.index("\n    name: crypto-floor", start)]
        flat = " ".join(line.strip().lstrip("#").strip() for line in block.splitlines())
        self.assertNotIn("every test stay as they were", flat)
        self.assertIn("The parts run in separate processes", flat)


class NoCodeLoadsTestsThroughTheSharedLoader(unittest.TestCase):

    def test_no_module_names_the_shared_loader(self):
        hits = []
        for folder in ("tests", "scripts", "src", "conformance", "formal"):
            for p in sorted((REPO / folder).rglob("*.py")):
                try:
                    lines = shared_loader_lines(p.read_text(encoding="utf-8", errors="replace"))
                except SyntaxError:
                    continue
                hits += [f"{p.relative_to(REPO)}:{n}" for n in lines]
        self.assertEqual(hits, [], "`-k` in crypto-floor filters every load through the shared loader")


class ThePartitionCheckCatchesWhatItIsFor(unittest.TestCase):
    """Each finding above must be able to fail on a built counter-example."""

    IDS = ["test_alpha.A.test_x", "test_beta.B.test_y", "test_9.C.test_z"]

    def _job(self, **changes) -> dict:
        job = {"name": "crypto-floor (${{ matrix.part }} of 2)",
               "strategy": {"fail-fast": False,
                            "matrix": {"part": [1, 2],
                                       "include": [{"part": 1, "selection": "-k test_[0-9a]*"},
                                                   {"part": 2, "selection": "-k test_[!0-9a]*"}]}},
               "steps": [{"env": {"SELECTION": "${{ matrix.selection }}"}, "run": SUITE}]}
        job.update(changes)
        return job

    def test_a_test_no_part_selects_is_found(self):
        self.assertEqual(partition_findings(self.IDS, {"1": ["test_[a-z]*"]}), ["test_9.C.test_z: no part runs it"])

    def test_a_test_two_parts_select_is_found(self):
        self.assertEqual(partition_findings(self.IDS, {"1": ["test_[0-9a]*"], "2": ["test_[a-z]*"]}),
                         ["test_alpha.A.test_x: 2 parts run it ['1', '2']"])

    def test_a_pattern_without_a_star_is_a_substring(self):
        self.assertEqual(partition_findings(["test_m.C.test_one", "test_m.C.test_one_more"],
                                            {"1": ["test_m.C.test_one"], "2": ["test_m.C.test_one_more"]}),
                         ["test_m.C.test_one_more: 2 parts run it ['1', '2']"])

    def test_no_part_at_all_is_found(self):
        self.assertEqual(partition_findings([], {}), ["no part at all"])

    def test_a_partition_is_not_reported(self):
        self.assertEqual(partition_findings(self.IDS, parts_of(self._job())), [])

    def test_a_selection_that_is_not_k_pairs_is_found(self):
        self.assertEqual(read_selection("-k test_a* -k test_b*"), (["test_a*", "test_b*"], []))
        self.assertEqual(read_selection("-k test_a* test_b*")[1],
                         ["the selection '-k test_a* test_b*' is not a list of `-k <pattern>` pairs"])
        self.assertEqual(read_selection("-k test_a* -p test_b*")[1],
                         ["the selection '-k test_a* -p test_b*' carries '-p' where `-k` belongs"])
        self.assertEqual(read_selection("")[1], ["the selection '' is not a list of `-k <pattern>` pairs"])

    def test_a_sound_job_shape_is_not_reported(self):
        self.assertEqual(job_findings(self._job()), [])

    def test_a_job_shape_that_drops_or_hides_a_part_is_found(self):
        strategy = self._job()["strategy"]
        cases = {
            "fail-fast": dict(strategy={**strategy, "fail-fast": True}),
            "exclude": dict(strategy={**strategy, "matrix": {**strategy["matrix"], "exclude": [{"part": 2}]}}),
            "one to one": dict(strategy={**strategy, "matrix": {**strategy["matrix"], "part": [1, 2, 3]}}),
            "does not count": dict(name="crypto-floor (${{ matrix.part }} of 5)"),
            "`if`": {"if": "github.event_name == 'push'"},
            "`continue-on-error`": {"continue-on-error": True},
            "not 'set": dict(steps=[{"env": {"SELECTION": "${{ matrix.selection }}"},
                                     "run": "python -m unittest discover -s tests"}]),
            "SELECTION": dict(steps=[{"run": SUITE}]),
            "suite step carries": dict(steps=[{"env": {"SELECTION": "${{ matrix.selection }}"}, "run": SUITE,
                                               "continue-on-error": True}]),
        }
        for words, change in cases.items():
            with self.subTest(words):
                found = job_findings(self._job(**change))
                self.assertTrue(any(words in f for f in found), found)

    def test_a_module_that_fails_to_load_shows_up_as_a_stand_in(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "tests").mkdir()
            (root / "tests" / "test_fine.py").write_text(
                "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n",
                encoding="utf-8")
            (root / "tests" / "test_broken.py").write_text("import a_module_that_does_not_exist\n",
                                                           encoding="utf-8")
            ids = load_ids(root)
            # The stand-in of the broken module runs although `-k` selects only test_fine: a failed
            # import is loud in every part, which is why the partition leaves stand-ins out.
            r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-k", "test_fine.*"],
                               cwd=root, capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertIn("test_fine.T.test_x", ids)
        self.assertEqual([i for i in ids if i.startswith(STAND_IN)], ["unittest.loader._FailedTest.test_broken"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Ran 2 tests", r.stderr)
        self.assertIn("FAILED (errors=1)", r.stderr)

    def test_a_module_skipped_at_import_is_a_stand_in_every_part_would_run(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "tests").mkdir()
            (root / "tests" / "test_fine.py").write_text(
                "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n",
                encoding="utf-8")
            (root / "tests" / "test_skipped.py").write_text(
                "import unittest\n\nraise unittest.SkipTest('optional dependency is unavailable')\n",
                encoding="utf-8")
            ids = load_ids(root)
            # A pattern that matches nothing still runs the stand-in: it bypasses -k.
            r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-k", "does_not_match"],
                               cwd=root, capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual([i for i in ids if i.startswith(STAND_IN)],
                         ["unittest.loader.ModuleSkipped.test_skipped"])
        self.assertEqual(len(stand_in_findings(ids)), 1, stand_in_findings(ids))
        self.assertEqual(stand_in_findings(["test_fine.T.test_x", "unittest.loader._FailedTest.test_broken"]), [])
        self.assertIn("Ran 1 test", r.stderr)
        self.assertIn("skipped=1", r.stderr)

    def test_the_shared_loader_is_found_under_an_alias_and_by_its_name(self):
        self.assertEqual(shared_loader_lines("from unittest import defaultTestLoader as loader\n"
                                             "s = loader.discover('t')\n"), [1])
        self.assertEqual(shared_loader_lines("import unittest\n"
                                             "s = getattr(unittest, 'defaultTestLoader').discover('t')\n"), [2])
        self.assertEqual(shared_loader_lines("import unittest\n"
                                             "s = vars(unittest)['defaultTestLoader'].discover('t')\n"), [2])
        # The control: a loader of its own is not the shared one, and a name in a string is not a use.
        self.assertEqual(shared_loader_lines("import unittest\nloader = unittest.TestLoader()\n"
                                             "x = 'defaultTestLoader'\n"), [])

    def test_the_shared_loader_is_found_in_code_and_not_in_a_main_block(self):
        self.assertEqual(shared_loader_lines("import unittest\nx = unittest.defaultTestLoader\n"), [2])
        self.assertEqual(shared_loader_lines("from unittest import defaultTestLoader\n"
                                             "s = defaultTestLoader.discover('t')\n"), [1, 2])
        self.assertEqual(shared_loader_lines("import unittest\nif __name__ == '__main__':\n"
                                             "    unittest.defaultTestLoader.discover('t')\n"), [])
        self.assertEqual(shared_loader_lines("# unittest.defaultTestLoader in a comment\n"), [])

    def test_a_name_from_elsewhere_or_a_mapping_key_is_not_the_shared_loader(self):
        """The first reading of PR 440 (Z6): the finder went by the name, so an import of the same name from another
        module and a key of a plain mapping were reported (the strict direction, a false alarm)."""
        for source in ("from mylib import defaultTestLoader\ns = defaultTestLoader.discover('t')\n",
                       "cfg = {'defaultTestLoader': 1}\nx = cfg['defaultTestLoader']\n",
                       "import mylib\nx = mylib.defaultTestLoader\n",
                       "import mylib\nx = getattr(mylib, 'defaultTestLoader')\n",
                       "defaultTestLoader = object()\nx = defaultTestLoader\n"):
            with self.subTest(source):
                self.assertEqual(shared_loader_lines(source), [])

    def test_the_shared_loader_is_still_found_by_its_origin_under_any_name(self):
        """The other direction: the loader of unittest under an alias, through a submodule, or from a value whose
        origin the finder cannot read, stays a finding."""
        for source, lines in (("import unittest as u\nx = u.defaultTestLoader\n", [2]),
                              ("from unittest import loader\nx = loader.defaultTestLoader\n", [2]),
                              ("import unittest.loader as L\nx = L.defaultTestLoader\n", [2]),
                              ("from unittest.loader import defaultTestLoader as dl\n", [1]),
                              ("import importlib\nx = importlib.import_module('unittest').defaultTestLoader\n", [2]),
                              ("def f(m):\n    return m.defaultTestLoader\n", [2]),
                              ("import unittest\nx = unittest.__dict__['defaultTestLoader']\n", [2]),
                              ("import sys\nx = sys.modules['unittest'].defaultTestLoader\n", [2])):
            with self.subTest(source):
                self.assertEqual(shared_loader_lines(source), lines)

    def test_a_foreign_import_does_not_hide_another_binding_of_the_same_name(self):
        """Reading of the follow-up to 441, line 3 (P2): the origins are read for the whole module, so a name imported
        from elsewhere hid a parameter or an assignment of the same name, and the loader of unittest handed in through
        it went unseen, the strict direction lost."""
        for source, lines in (("import mylib as m\n\ndef unrelated():\n    return m.value\n\ndef load(m):\n"
                               "    return m.defaultTestLoader\n", [7]),
                              ("import mylib as m\nm = __import__('unittest')\nx = m.defaultTestLoader\n", [3]),
                              ("import mylib as m\ndef load(m):\n    return getattr(m, 'defaultTestLoader')\n", [3])):
            with self.subTest(source):
                self.assertEqual(shared_loader_lines(source), lines)


if __name__ == "__main__":
    unittest.main()
