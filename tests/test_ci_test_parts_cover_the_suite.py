"""The legs of the CI job `test` run in parts, and the parts of one leg together are the suite, test for test.

Owner order of 2026-10-30 (accelerator first): the legs of `test` were the long path of every landing.
Measured through the GitHub API, the suite step alone took 42 to 99 min at 1e050a1d (run 41004981271)
and 37 to 82 min at f407cfea (run 40996293556); test (3.14) set the end of both runs. Each leg now
runs its suite in parts, the same way crypto-floor does since pull request 436.

THE SPLIT KEEPS THE RUNNER AND THE COLLECTION. Every part runs the same pytest call with the part
plugin `scripts/ci_test_part.py`: pytest collects the whole suite as `python -m pytest` does, and the
plugin then keeps the items of the part and deselects the rest. The assignment is by unit: a test
file, or one of the few heavy tests the measured weights beside the plugin list on their own.

What can go wrong is the partition and its wiring. An item no part keeps runs nowhere, and the leg
stays green over a smaller suite. An item two parts keep runs twice. A part that is skipped, may fail
without failing the job, or is missing from the matrix drops its items in silence. A malformed part
value could run everything or nothing. This contract therefore

  1. reads the job: the parts are 1 to K, nothing is included or excluded, no part may fail or be
     skipped silently, the suite step is exactly the declared call with `<part>/K` from the matrix,
     and the checks that are not the suite run once per version, in part 1;
  2. collects the whole suite once, the way the CI call does without the part, and checks that the
     plugin's assignment puts every collected item in exactly one part and leaves no part empty;
  3. runs the plugin for real on a small suite: each part keeps exactly the items assigned to it, the
     parts together are the suite, xdist workers agree, and a malformed value is refused.

The parts run in separate jobs, so module and class fixtures and state global to a process apply per
part. This contract holds the files and the job shape, not one shared process.
"""
from __future__ import annotations

import importlib.util
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
PLUGIN = REPO / "scripts" / "ci_test_part.py"

#: The suite step of every part. CI_PART reaches the call through the environment.
SUITE = "python -m pytest -q --numprocesses=auto --dist=worksteal -p scripts.ci_test_part --ci-part=$CI_PART"
#: The step that builds the Rust verifier the suite requires; every part needs it.
BUILD = "cd tools/pb_verify_rs && cargo build --release"
#: The step that fills uv's cache with the plugin's pinned verifier; every part runs plugin tests offline from it.
#: Named by its step name: its command names the plugin's server, a test file naming the plugin is a plugin test
#: (tests/_plugin_env.py), and tests/test_plugin_ci_uv_cache.py holds that command word for word.
FILL = "Fill uv's cache with the plugin's pinned verifier (the suite reads it offline)"
#: The condition of a check that runs once per version.
PART_ONE = "matrix.part == 1"
#: The share of collected files the weights must know; below it the table is stale, not wrong.
KNOWN_SHARE = 0.8


def _plugin():
    spec = importlib.util.spec_from_file_location("ci_test_part_under_contract", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def job_findings(job: dict) -> list[str]:
    """Where the job shape lets a part drop out, run twice or stop counting. Pure."""
    findings = []
    strategy = job.get("strategy") or {}
    matrix = strategy.get("matrix") or {}
    parts = matrix.get("part")
    k = None
    if strategy.get("fail-fast") is not False:
        findings.append("fail-fast is not false: one red part would cancel the others")
    if not isinstance(parts, list) or len(parts) < 2 or parts != list(range(1, len(parts) + 1)):
        findings.append(f"the parts {parts!r} are not the numbers 1 to K with K of at least 2")
    else:
        k = len(parts)
    if "python-version" not in matrix:
        findings.append("the matrix has no python-version key")
    for key in ("include", "exclude"):
        if key in matrix:
            findings.append(f"the matrix carries `{key}`, which can add or drop a part")
    for key in ("if", "continue-on-error"):
        if key in job:
            findings.append(f"the job carries `{key}`, so a part may not run or may fail without failing it")
    steps = job.get("steps") or []
    suite = [s for s in steps if "-m pytest" in str(s.get("run", ""))]
    if len(suite) != 1:
        return findings + [f"expected one suite step, found {len(suite)}"]
    step = suite[0]
    if str(step.get("run", "")).strip() != SUITE:
        findings.append(f"the suite step runs {step.get('run')!r}, not {SUITE!r}")
    if k is not None and (step.get("env") or {}).get("CI_PART") != f"${{{{ matrix.part }}}}/{k}":
        findings.append(f"the suite step does not take CI_PART as `<part>/{k}` from the matrix")
    for s in steps:
        run = str(s.get("run", ""))
        name = s.get("name") or s.get("uses") or run
        if "continue-on-error" in s:
            findings.append(f"the step {name!r} carries `continue-on-error`")
        every_part = ("uses" in s or s is step or run.strip() == BUILD or s.get("name") == FILL
                      or "pip install" in run)
        if every_part:
            if "if" in s:
                findings.append(f"the step {name!r} carries `if`, and every part needs it")
        elif s.get("if") != PART_ONE:
            findings.append(f"the step {name!r} runs under {s.get('if')!r}, not once per version in part 1")
    return findings


def collected_ids(root: pathlib.Path) -> list[str]:
    """The node id of every item `python -m pytest --collect-only` collects under `root`."""
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:randomly",
                        "-p", "no:cacheprovider"], cwd=root, capture_output=True, text=True, timeout=900,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root / "src")))
    if r.returncode != 0:
        raise AssertionError(f"collecting the suite failed with {r.returncode}: {r.stdout[-2000:]}{r.stderr[-1000:]}")
    return sorted({line for line in r.stdout.splitlines()
                   if "::" in line and not line[:1].isspace() and line.split("::", 1)[0].endswith(".py")})


def _test_job() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["test"]


@unittest.skipIf(yaml is None, "PyYAML is missing, so the workflow cannot be read")
class TheTestJobRunsTheWholeSuiteInParts(unittest.TestCase):

    def test_every_part_runs_the_same_call_and_counts(self):
        self.assertEqual(job_findings(_test_job()), [])

    def test_every_collected_item_runs_in_exactly_one_part(self):
        plugin = _plugin()
        ids = collected_ids(REPO)
        # A sweep over an empty set is green and says nothing; far below the suite on purpose.
        self.assertGreater(len(ids), 2000, f"only {len(ids)} items collected, the collection is blind")
        k = len(_test_job()["strategy"]["matrix"]["part"])
        files, tests, offset = plugin.load_weights()
        units = {i: plugin.unit_of(i, tests) for i in ids}
        where = plugin.assign(units.values(), k, files, tests, offset)
        parts_of_item = {i: where[u] for i, u in units.items()}
        self.assertEqual(sorted(parts_of_item), ids)
        self.assertTrue(set(parts_of_item.values()) <= set(range(1, k + 1)))
        self.assertEqual(sorted(set(parts_of_item.values())), list(range(1, k + 1)), "a part keeps no item")
        # The weights steer only the balance; when they no longer know the suite, they are measured again.
        collected_files = {plugin.file_of(i) for i in ids}
        known = len(collected_files & set(files)) / len(collected_files)
        self.assertGreaterEqual(known, KNOWN_SHARE, f"the weights know {known:.0%} of the collected files; "
                                                    "measure them again (scripts/ci_test_part_weights.json)")
        listed = len(set(tests) & set(ids)) / max(len(tests), 1)
        self.assertGreaterEqual(listed, KNOWN_SHARE, f"only {listed:.0%} of the heavy tests the weights list "
                                                     "are still collected; measure them again")


def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ThePluginKeepsExactlyItsFiles(unittest.TestCase):
    """The plugin, run for real by pytest on a small suite of its own."""

    #: One parametrized case is a unit of its own, as the heavy tests of the real suite are.
    WEIGHTS = {"seconds": {"tests/test_a.py": 5, "tests/test_b.py": 4, "tests/test_c.py": 3},
               "tests": {"tests/test_e.py::test_e[2]": 6}, "part_one_offset_seconds": 1}

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)
        _write(self.root / "scripts" / "ci_test_part.py", PLUGIN.read_text(encoding="utf-8"))
        _write(self.root / "scripts" / "ci_test_part_weights.json", json.dumps(self.WEIGHTS))
        _write(self.root / "pytest.ini", "[pytest]\n")
        _write(self.root / "tests" / "test_a.py", "def test_one():\n    pass\n\n\ndef test_two():\n    pass\n")
        _write(self.root / "tests" / "test_b.py",
               "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n\n"
               "    def test_y(self):\n        pass\n")
        _write(self.root / "tests" / "test_c.py", "def test_c():\n    pass\n")
        _write(self.root / "tests" / "test_d.py", "def test_d():\n    pass\n")
        _write(self.root / "tests" / "test_e.py",
               "import pytest\n\n\n@pytest.mark.parametrize('n', [1, 2, 3])\ndef test_e(n):\n    pass\n")

    def tearDown(self):
        self._dir.cleanup()

    def _pytest(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *args], cwd=self.root,
                              capture_output=True, text=True, timeout=300,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))

    def _ids(self, *args: str) -> set[str]:
        r = self._pytest("--collect-only", "-q", *args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return {line for line in r.stdout.splitlines() if "::" in line and not line[:1].isspace()}

    def _where(self, ids, parts: int) -> dict[str, int]:
        """The part of every item, as the plugin's pure assignment gives it for these weights."""
        plugin = _plugin()
        files = {k: float(v) for k, v in self.WEIGHTS["seconds"].items()}
        tests = {k: float(v) for k, v in self.WEIGHTS["tests"].items()}
        units = {i: plugin.unit_of(i, tests) for i in ids}
        where = plugin.assign(units.values(), parts, files, tests, 1.0)
        return {i: where[u] for i, u in units.items()}

    def test_the_parts_are_the_suite_and_each_keeps_its_assigned_items(self):
        whole = self._ids()
        self.assertEqual(len(whole), 9)
        for parts in (2, 3):
            with self.subTest(parts=parts):
                where = self._where(whole, parts)
                kept = {p: self._ids("-p", "scripts.ci_test_part", f"--ci-part={p}/{parts}")
                        for p in range(1, parts + 1)}
                self.assertEqual(set().union(*kept.values()), whole)
                self.assertEqual(sum(len(k) for k in kept.values()), len(whole), "an item ran in two parts")
                for p in kept:
                    self.assertEqual(kept[p], {i for i, q in where.items() if q == p})
        # The listed case left its file: its siblings are kept by another part than it.
        where = self._where(whole, 2)
        self.assertNotEqual(where["tests/test_e.py::test_e[2]"], where["tests/test_e.py::test_e[1]"])

    def test_without_a_part_the_plugin_changes_nothing(self):
        self.assertEqual(self._ids("-p", "scripts.ci_test_part"), self._ids())

    def test_a_malformed_part_is_refused(self):
        for bad in ("0/2", "3/2", "1/0", "a/2", "2", "", "${{ matrix.part }}/2", "1/2/3", " 1/2", "01/2"):
            with self.subTest(bad=bad):
                r = self._pytest("--collect-only", "-q", "-p", "scripts.ci_test_part", f"--ci-part={bad}")
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("--ci-part", r.stdout + r.stderr)

    def test_missing_weights_are_refused(self):
        (self.root / "scripts" / "ci_test_part_weights.json").unlink()
        r = self._pytest("--collect-only", "-q", "-p", "scripts.ci_test_part", "--ci-part=1/2")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("weights", r.stdout + r.stderr)

    def test_a_part_that_keeps_nothing_fails(self):
        for name in ("test_b.py", "test_c.py", "test_d.py", "test_e.py"):
            (self.root / "tests" / name).unlink()
        where = self._where({"tests/test_a.py::test_one", "tests/test_a.py::test_two"}, 2)
        empty = ({1, 2} - set(where.values())).pop()
        r = self._pytest("-q", "-p", "scripts.ci_test_part", f"--ci-part={empty}/2")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        r = self._pytest("-q", "-p", "scripts.ci_test_part", f"--ci-part={3 - empty}/2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    @unittest.skipIf(importlib.util.find_spec("xdist") is None,
                     "pytest-xdist is not installed here; the job `test` installs it and runs this case")
    def test_xdist_workers_keep_the_same_part(self):
        one = self._ids("-p", "scripts.ci_test_part", "--ci-part=1/2")
        r = self._pytest("-q", "-rA", "--numprocesses=2", "--dist=worksteal", "-p", "scripts.ci_test_part",
                         "--ci-part=1/2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        passed = {line.split(" ", 1)[1].strip() for line in r.stdout.splitlines() if line.startswith("PASSED ")}
        self.assertEqual(passed, one)


class TheJobCheckCatchesWhatItIsFor(unittest.TestCase):
    """Each finding of job_findings must be able to fail on a built counter-example."""

    def _job(self, **changes) -> dict:
        job = {"strategy": {"fail-fast": False,
                            "matrix": {"python-version": "${{ fromJSON('[\"3.12\"]') }}", "part": [1, 2]}},
               "steps": [{"uses": "actions/checkout@x"},
                         {"name": "Install", "run": "python -m pip install -e .[dev]"},
                         {"name": "Lint", "if": PART_ONE, "run": "ruff check ."},
                         {"name": "Build", "run": BUILD},
                         {"name": "Test", "env": {"CI_PART": "${{ matrix.part }}/2"}, "run": SUITE},
                         {"name": "Gate", "if": PART_ONE, "run": "python scripts/test_manifest_gate.py"},
                         {"name": FILL, "env": {"UV_OFFLINE": "false"}, "run": "uv run --script server.py"}]}
        job.update(changes)
        return job

    def _with_step(self, index: int, **changes) -> dict:
        job = self._job()
        job["steps"] = [dict(s, **changes) if i == index else s for i, s in enumerate(job["steps"])]
        return job

    def _with_matrix(self, **changes) -> dict:
        job = self._job()
        job["strategy"] = dict(job["strategy"], matrix=dict(job["strategy"]["matrix"], **changes))
        return job

    def test_a_sound_job_is_not_reported(self):
        self.assertEqual(job_findings(self._job()), [])

    def test_a_job_that_drops_hides_or_doubles_a_part_is_found(self):
        lint_everywhere = self._job()
        del lint_everywhere["steps"][2]["if"]
        cases = {
            "fail-fast": self._job(strategy={**self._job()["strategy"], "fail-fast": True}),
            "1 to K": self._with_matrix(part=[1, 3]),
            "at least 2": self._with_matrix(part=[1]),
            "no python-version": self._job(strategy={"fail-fast": False, "matrix": {"part": [1, 2]}}),
            "`exclude`": self._with_matrix(exclude=[{"part": 2}]),
            "`include`": self._with_matrix(include=[{"part": 3}]),
            "job carries `if`": self._job(**{"if": "github.event_name == 'push'"}),
            "job carries `continue-on-error`": self._job(**{"continue-on-error": True}),
            "not 'python": self._with_step(4, run="python -m pytest -q --numprocesses=auto --dist=worksteal"),
            "CI_PART": self._with_step(4, env={"CI_PART": "${{ matrix.part }}/3"}),
            "every part needs it": self._with_step(3, **{"if": PART_ONE}),
            f"the step {FILL!r} carries `if`": self._with_step(6, **{"if": PART_ONE}),
            "not once per version": lint_everywhere,
            "carries `continue-on-error`": self._with_step(5, **{"continue-on-error": True}),
            "one suite step": self._job(steps=[]),
        }
        for words, job in cases.items():
            with self.subTest(words):
                found = job_findings(job)
                self.assertTrue(any(words in f for f in found), found)

    def test_the_assignment_is_a_partition_whatever_the_weights_say(self):
        plugin = _plugin()
        ids = [f"tests/test_{n}.py::test_{m}" for n in range(40) for m in range(3)]
        heavy = {"tests/test_0.py::test_1": 900.0, "tests/test_7.py::test_0": 800.0, "tests/test_gone.py::x": 5.0}
        for k in (2, 3, 6, 7):
            for files in ({}, {"tests/test_0.py": 1000.0}, {f"tests/test_{n}.py": float(n) for n in range(40)}):
                for tests in ({}, heavy):
                    with self.subTest(k=k, files=len(files), tests=len(tests)):
                        units = [plugin.unit_of(i, tests) for i in ids]
                        where = plugin.assign(list(reversed(units)), k, files, tests, 5.0)
                        self.assertEqual(sorted(where), sorted(set(units)))
                        self.assertTrue(set(where.values()) <= set(range(1, k + 1)))
                        self.assertEqual(where, plugin.assign(units, k, files, tests, 5.0),
                                         "the order of the collected items must not change the assignment")
        self.assertEqual(plugin.unit_of("tests/test_0.py::test_1", heavy), "tests/test_0.py::test_1")
        self.assertEqual(plugin.unit_of("tests/test_0.py::test_2", heavy), "tests/test_0.py")


@unittest.skipIf(yaml is None, "PyYAML is missing, so the workflow cannot be read")
class TheTimeLimitFollowsTheMeasuredParts(unittest.TestCase):
    """The comment above the limit said it comes down once three runs on main have measured a part. Three have: the
    longest part took 15.1 minutes on main and 20.9 in a PR run (owner decision of 2026-10-30, 45 minutes). The lower
    bound, the measured part plus its reserve, is held in ONE table, GEMESSENE_MAXIMA_MIN in
    tests/test_der_ci_schnitt_haelt.py; this test holds the upper one, so a hung part stops within the hour."""

    def test_the_limit_of_a_part_is_at_most_45_minutes(self):
        self.assertLessEqual(_test_job()["timeout-minutes"], 45)


@unittest.skipIf(yaml is None, "PyYAML is missing, so the workflow cannot be read")
class TheNoteSaysWhatTheWeightsHold(unittest.TestCase):
    """The rereading of the weights of PR 440 (Z6): the note said "no file is heavier than a part". Measured on
    30.10.2026 at 647ed0a2: two files weigh more than a mean part in all (the heaviest 3055 s against 1389 s over seven
    parts), and no unit does, because the heavy tests of a file are units of their own."""

    def test_no_unit_is_heavier_than_a_mean_part_and_the_note_says_unit(self):
        plugin = _plugin()
        data = json.loads(plugin.WEIGHTS.read_text(encoding="utf-8"))
        files, tests, offset = plugin.load_weights()
        parts = len(_test_job()["strategy"]["matrix"]["part"])
        mean_part = (sum(files.values()) + sum(tests.values()) + offset) / parts
        heaviest = max([*files.values(), *tests.values()])
        self.assertLessEqual(heaviest, mean_part, "a unit is heavier than a mean part; split it in the weights")
        self.assertIn("no unit is heavier than a part", data["note"])
        self.assertNotIn("no file is heavier than a part", data["note"])


class TheWeightsRejectWhatIsNoDuration(unittest.TestCase):
    """The first reading of PR 440 (Z7): `load_weights` checked only `v < 0`. JSON reads `1e309` as infinity and `NaN`
    as not a number, and both passed; an infinite weight pins every unit after it to one part."""

    CASES = {
        "infinite file": '{"seconds": {"tests/test_a.py": 1e309}, "tests": {}, "part_one_offset_seconds": 0}',
        "nan test": '{"seconds": {"tests/test_a.py": 1}, "tests": {"tests/test_a.py::t": NaN}, '
                    '"part_one_offset_seconds": 0}',
        "infinite offset": '{"seconds": {"tests/test_a.py": 1}, "tests": {}, "part_one_offset_seconds": 1e309}',
    }

    def test_infinity_and_nan_are_a_usage_error(self):
        import pytest
        plugin = _plugin()
        with tempfile.TemporaryDirectory() as t:
            for name, text in self.CASES.items():
                with self.subTest(name):
                    p = pathlib.Path(t) / "weights.json"
                    p.write_text(text, encoding="utf-8")
                    with self.assertRaises(pytest.UsageError):
                        plugin.load_weights(p)

    def test_finite_weights_still_load(self):
        plugin = _plugin()
        with tempfile.TemporaryDirectory() as t:
            p = pathlib.Path(t) / "weights.json"
            p.write_text('{"seconds": {"tests/test_a.py": 1.5}, "tests": {"tests/test_a.py::t": 0}, '
                         '"part_one_offset_seconds": 2}', encoding="utf-8")
            self.assertEqual(plugin.load_weights(p), ({"tests/test_a.py": 1.5}, {"tests/test_a.py::t": 0.0}, 2.0))


if __name__ == "__main__":
    unittest.main()
