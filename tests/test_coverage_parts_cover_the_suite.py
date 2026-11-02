"""The CI job `coverage` measures the whole suite in parts, and its verdict needs the data of every part.

Owner choice of 2026-11-02 (order DELTA-COVERAGE-IN-TEILEN-01): `coverage` ran the whole suite on one runner and
set the end of every run, 101.7 min at main c8b5b285 (run 41466807258) and 92.1 min at pull request 454 (run
41444424659). The suite now runs in the matrix job `coverage-part`, split by the plugin and the measured weights
of `test` (scripts/ci_test_part.py), and the job `coverage` checks and combines the data of the parts
(scripts/ci_coverage_combine.py) before it holds the floor of 83.

What can go wrong is what goes wrong with any split, plus the step that joins it. An item no part keeps is
measured nowhere and the total looks like the whole suite's; an item two parts keep counts its lines once anyway,
so a doubled part hides; a part that is skipped, may fail without failing, or uploads nothing drops its share in
silence; and a closing job that combines whatever arrived reports a floor over fewer parts than ran. This
contract therefore

  1. reads both jobs: the parts are 1 to K, nothing is included or excluded, no part may fail or be skipped
     silently, every part runs the declared call with `<part>/K`, requires the Rust verifier and sysmon, and
     uploads its data under its own name; the closing job needs the parts, runs on their failure, downloads
     their data merged into the one directory the closing script reads, checks K parts and holds the floor;
  2. collects the whole suite once and checks that the plugin's assignment puts every collected item in exactly
     one of the K parts and leaves no part empty. That the collection hook keeps exactly the assigned items is
     held by tests/test_ci_test_parts_cover_the_suite.py (ThePluginKeepsExactlyItsFiles), which runs the plugin
     for real; every part runs that same plugin through the call SUITE below;
  3. runs the closing script as a program on real coverage data: K sound parts combine, and every way to lose
     a part is refused before the floor, zero parts included.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover - the [dev] extra carries PyYAML
    yaml = None

try:
    import coverage
except ImportError:  # pragma: no cover - the coverage job installs it; the cases that need it say so
    coverage = None

REPO = pathlib.Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"
PLUGIN = REPO / "scripts" / "ci_test_part.py"
COMBINE = REPO / "scripts" / "ci_coverage_combine.py"
PARTS_JOB, CLOSING_JOB = "coverage-part", "coverage"

#: The suite step of every part. CI_PART reaches the call through the environment.
SUITE = ("python -m pytest -q --numprocesses=auto --dist=worksteal -p scripts.ci_test_part --ci-part=$CI_PART "
         "--cov=src/proofbundle --cov-report=")
BUILD = "cd tools/pb_verify_rs && cargo build --release"
PINNED = "${{ github.workspace }}/tools/pb_verify_rs/target/release/pb_verify_rs"
UPLOAD = "actions/upload-artifact@"
DOWNLOAD = "actions/download-artifact@"
FLOOR = "python -m coverage report -m --fail-under=83"
#: The directory the closing job downloads the parts into and the closing script reads.
DATA_DIR = "coverage-data"


def _ci_jobs() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]


def _plugin():
    spec = importlib.util.spec_from_file_location("ci_test_part_under_coverage_contract", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def part_findings(job: dict) -> list[str]:
    """Where the parts job lets a part drop out, run twice, measure without the verifier or lose its data. Pure."""
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
    for key in ("include", "exclude"):
        if key in matrix:
            findings.append(f"the matrix carries `{key}`, which can add or drop a part")
    for key in ("if", "continue-on-error", "needs"):
        if key in job:
            findings.append(f"the job carries `{key}`, so a part may not run or may fail without failing it")
    env = job.get("env") or {}
    if str(env.get("PROOFBUNDLE_REQUIRE_PB_VERIFY_RS")) != "1" or env.get("PROOFBUNDLE_PB_VERIFY_RS") != PINNED:
        findings.append("a part does not require and pin the Rust verifier")
    if env.get("COVERAGE_CORE") != "sysmon":
        findings.append(f"a part measures with COVERAGE_CORE={env.get('COVERAGE_CORE')!r}, not sysmon")
    if k is not None and f"of {k})" not in str(job.get("name") or ""):
        findings.append(f"the name {job.get('name')!r} does not say `of {k}`")
    steps = job.get("steps") or []
    suite = [s for s in steps if "-m pytest" in str(s.get("run", ""))]
    if len(suite) != 1:
        return findings + [f"expected one suite step, found {len(suite)}"]
    if str(suite[0].get("run", "")).strip() != SUITE:
        findings.append(f"the suite step runs {suite[0].get('run')!r}, not {SUITE!r}")
    if k is not None and (suite[0].get("env") or {}).get("CI_PART") != f"${{{{ matrix.part }}}}/{k}":
        findings.append(f"the suite step does not take CI_PART as `<part>/{k}` from the matrix")
    runs = [str(s.get("run", "")).strip() for s in steps]
    if BUILD not in runs or runs.index(BUILD) > steps.index(suite[0]):
        findings.append("the Rust verifier is not built before the suite")
    keep = [s for s in steps if ".coverage.part-${{ matrix.part }}" in str(s.get("run", ""))]
    if len(keep) != 1 or "test -s .coverage" not in str(keep[0].get("run", "")):
        findings.append("no step keeps the part's data under `.coverage.part-<part>` after checking it is not empty")
    up = [s for s in steps if str(s.get("uses", "")).startswith(UPLOAD)]
    w = (up[0].get("with") or {}) if len(up) == 1 else {}
    if (len(up) != 1 or w.get("name") != "coverage-part-${{ matrix.part }}" or w.get("include-hidden-files") is not True
            or w.get("if-no-files-found") != "error" or ".coverage.part-${{ matrix.part }}" not in str(w.get("path"))):
        findings.append("the part does not upload its data as coverage-part-<part>, hidden file included, "
                        "and failing when there is none")
    for s in steps:
        name = s.get("name") or s.get("uses") or s.get("run")
        for key in ("if", "continue-on-error"):
            if key in s:
                findings.append(f"the step {name!r} carries `{key}`, and every part needs every step")
    return findings


def closing_findings(job: dict, k: "int | None") -> list[str]:
    """Where the closing job could report a floor over fewer parts than ran. Pure."""
    findings = []
    if job.get("needs") not in (["coverage-part"], "coverage-part"):
        findings.append(f"the job needs {job.get('needs')!r}, not the parts")
    if " ".join(str(job.get("if") or "").split()) != "${{ !cancelled() }}":
        findings.append(f"the job runs under {job.get('if')!r}: without `!cancelled()` a failed part skips it, "
                        "and a skipped job is not red")
    if job.get("name", CLOSING_JOB) != CLOSING_JOB:
        findings.append(f"the job reports as {job.get('name')!r}, not as `coverage`")
    for key in ("strategy", "continue-on-error"):
        if key in job:
            findings.append(f"the job carries `{key}`")
    steps = job.get("steps") or []
    down = [s for s in steps if str(s.get("uses", "")).startswith(DOWNLOAD)]
    w = (down[0].get("with") or {}) if len(down) == 1 else {}
    if len(down) != 1 or w.get("pattern") != "coverage-part-*":
        findings.append("the job does not download the data of the parts by the pattern coverage-part-*")
    if w.get("merge-multiple") is not True or w.get("path") != DATA_DIR:
        findings.append(f"the closing job must merge all matching artifacts directly into {DATA_DIR}")
    close = [s for s in steps if "ci_coverage_combine.py" in str(s.get("run", ""))]
    if len(close) != 1:
        return findings + [f"expected one closing step, found {len(close)}"]
    run = str(close[0].get("run", ""))
    lines = [x.strip() for x in run.strip().splitlines()]
    expected = (f"python scripts/ci_coverage_combine.py --data-dir {DATA_DIR} --parts {k} "
                '--result "$PARTS_RESULT"')
    if k is None or not lines or lines[0] != expected:
        findings.append(f"the closing step does not run {expected!r} first")
    if FLOOR not in lines or lines.index(FLOOR) == 0:
        findings.append(f"the floor {FLOOR!r} does not follow the check")
    if (close[0].get("env") or {}).get("PARTS_RESULT") != "${{ needs.coverage-part.result }}":
        findings.append("PARTS_RESULT is not the result of the matrix coverage-part")
    for s in steps:
        if "continue-on-error" in s or "if" in s:
            findings.append(f"the step {s.get('name') or s.get('uses')!r} carries `if` or `continue-on-error`")
    return findings


@unittest.skipIf(yaml is None, "PyYAML is missing, so the workflow cannot be read")
class TheCoverageJobsAreShapedSoNoPartIsLost(unittest.TestCase):

    def test_the_parts_and_the_closing_job_as_they_stand(self):
        jobs = _ci_jobs()
        self.assertEqual(part_findings(jobs[PARTS_JOB]), [])
        k = len(jobs[PARTS_JOB]["strategy"]["matrix"]["part"])
        self.assertEqual(closing_findings(jobs[CLOSING_JOB], k), [])

    def test_the_jobs_that_wait_for_coverage_wait_for_the_closing_job(self):
        """`mutation` and `all-checks-passed` keep `needs: [test, coverage]`; `coverage` is the closing job, so
        their verdict comes after every part (scripts/landung_waits_for_ci.py waits for the same names)."""
        jobs = _ci_jobs()
        for name in ("mutation", "all-checks-passed"):
            with self.subTest(name):
                self.assertEqual(jobs[name]["needs"], ["test", "coverage"])
        self.assertEqual(jobs[CLOSING_JOB]["needs"], [PARTS_JOB])

    def test_every_collected_item_is_measured_in_exactly_one_part(self):
        plugin = _plugin()
        ids = _collected_ids(REPO)
        self.assertGreater(len(ids), 2000, f"only {len(ids)} items collected, the collection is blind")
        k = len(_ci_jobs()[PARTS_JOB]["strategy"]["matrix"]["part"])
        files, tests, offset = plugin.load_weights()
        units = {i: plugin.unit_of(i, tests) for i in ids}
        where = plugin.assign(units.values(), k, files, tests, offset)
        part_of = {i: where[u] for i, u in units.items()}
        self.assertEqual(sorted(part_of), ids)
        self.assertEqual(sorted(set(part_of.values())), list(range(1, k + 1)), "a part keeps no item")


def _collected_ids(root: pathlib.Path) -> list[str]:
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:randomly",
                        "-p", "no:cacheprovider"], cwd=root, capture_output=True, text=True, timeout=900,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root / "src")))
    if r.returncode != 0:
        raise AssertionError(f"collecting the suite failed with {r.returncode}: {r.stdout[-2000:]}{r.stderr[-1000:]}")
    return sorted({line for line in r.stdout.splitlines()
                   if "::" in line and not line[:1].isspace() and line.split("::", 1)[0].endswith(".py")})


class TheShapeChecksCatchWhatTheyAreFor(unittest.TestCase):
    """Each finding of part_findings and closing_findings must fail on a built counter-example."""

    def _part(self) -> dict:
        return {"name": "coverage part (${{ matrix.part }} of 2)",
                "env": {"PROOFBUNDLE_REQUIRE_PB_VERIFY_RS": "1", "PROOFBUNDLE_PB_VERIFY_RS": PINNED,
                        "COVERAGE_CORE": "sysmon"},
                "strategy": {"fail-fast": False, "matrix": {"part": [1, 2]}},
                "steps": [{"uses": "actions/checkout@x"},
                          {"name": "Install", "run": "python -m pip install -e .[dev]"},
                          {"name": "Build", "run": BUILD},
                          {"name": "Suite", "env": {"CI_PART": "${{ matrix.part }}/2"}, "run": SUITE},
                          {"name": "Keep", "run": "test -s .coverage\ncp .coverage x/.coverage.part-${{ matrix.part }}"},
                          {"name": "Up", "uses": UPLOAD + "x",
                           "with": {"name": "coverage-part-${{ matrix.part }}", "include-hidden-files": True,
                                    "if-no-files-found": "error", "path": "x/.coverage.part-${{ matrix.part }}"}}]}

    def _closing(self) -> dict:
        return {"needs": ["coverage-part"], "if": "${{ !cancelled() }}",
                "steps": [{"uses": "actions/checkout@x"},
                          {"name": "Down", "uses": DOWNLOAD + "x",
                           "with": {"pattern": "coverage-part-*", "merge-multiple": True, "path": DATA_DIR}},
                          {"name": "Close", "env": {"PARTS_RESULT": "${{ needs.coverage-part.result }}"},
                           "run": "python scripts/ci_coverage_combine.py --data-dir coverage-data --parts 2 "
                                  '--result "$PARTS_RESULT"\n' + FLOOR + "\n"}]}

    def _step(self, job: dict, index: int, **changes) -> dict:
        job = json.loads(json.dumps(job))
        job["steps"][index].update(changes)
        return job

    def test_sound_jobs_are_not_reported(self):
        self.assertEqual(part_findings(self._part()), [])
        self.assertEqual(closing_findings(self._closing(), 2), [])

    def test_a_part_job_that_drops_hides_or_doubles_a_part_is_found(self):
        def changed(**top):
            job = self._part()
            job.update(top)
            return job

        def matrix(**m):
            job = self._part()
            job["strategy"]["matrix"].update(m)
            return job
        no_core = self._part()
        no_core["env"]["COVERAGE_CORE"] = "ctrace"
        no_rust = self._part()
        del no_rust["env"]["PROOFBUNDLE_REQUIRE_PB_VERIFY_RS"]
        late_build = self._part()
        late_build["steps"][2], late_build["steps"][3] = late_build["steps"][3], late_build["steps"][2]
        cases = {
            "fail-fast": changed(strategy={"fail-fast": True, "matrix": {"part": [1, 2]}}),
            "1 to K": matrix(part=[1, 3]),
            "at least 2": matrix(part=[1]),
            "`include`": matrix(include=[{"part": 3}]),
            "`exclude`": matrix(exclude=[{"part": 2}]),
            "carries `if`, so": changed(**{"if": "github.event_name == 'push'"}),
            "carries `continue-on-error`, so": changed(**{"continue-on-error": True}),
            "carries `needs`": changed(needs=["test"]),
            "Rust verifier": no_rust,
            "COVERAGE_CORE": no_core,
            "does not say `of 2`": changed(name="coverage part (${{ matrix.part }})"),
            "not 'python": self._step(self._part(), 3, run="python -m pytest -q --cov=src/proofbundle"),
            "CI_PART": self._step(self._part(), 3, env={"CI_PART": "${{ matrix.part }}/3"}),
            "built before the suite": late_build,
            "keeps the part's data": self._step(self._part(), 4, run="cp .coverage x/.coverage.part-${{ matrix.part }}"),
            "does not upload": self._step(self._part(), 5, **{"with": {"name": "coverage-part-${{ matrix.part }}",
                                                                     "if-no-files-found": "error",
                                                                     "path": "x/.coverage.part-${{ matrix.part }}"}}),
            "every part needs every step": self._step(self._part(), 5, **{"if": "always()"}),
            "one suite step": changed(steps=[]),
        }
        for words, job in cases.items():
            with self.subTest(words):
                found = part_findings(job)
                self.assertTrue(any(words in f for f in found), found)

    def test_a_closing_job_that_could_judge_fewer_parts_is_found(self):
        def changed(**top):
            job = self._closing()
            job.update(top)
            return job
        close = self._closing()["steps"][2]
        cases = {
            "not the parts": changed(needs=["test"]),
            "without `!cancelled()`": changed(**{"if": "success()"}),
            "not as `coverage`": changed(name="coverage total"),
            "carries `strategy`": changed(strategy={"matrix": {"x": [1]}}),
            "pattern coverage-part-*": self._step(self._closing(), 1, **{"with": {"pattern": "coverage-*"}}),
            "merge all matching artifacts": self._step(self._closing(), 1, **{"with": {
                "pattern": "coverage-part-*", "merge-multiple": False, "path": DATA_DIR}}),
            "directly into coverage-data": self._step(self._closing(), 1, **{"with": {
                "pattern": "coverage-part-*", "merge-multiple": True, "path": "data"}}),
            "--parts 2": self._step(self._closing(), 2, run=close["run"].replace("--parts 2", "--parts 1")),
            "does not follow": self._step(self._closing(), 2, run=close["run"].replace(FLOOR, "true")),
            "PARTS_RESULT": self._step(self._closing(), 2, env={"PARTS_RESULT": "success"}),
            "`if` or `continue-on-error`": self._step(self._closing(), 2, **{"continue-on-error": True}),
            "one closing step": changed(steps=[]),
        }
        for words, job in cases.items():
            with self.subTest(words):
                found = closing_findings(job, 2)
                self.assertTrue(any(words in f for f in found), found)


@unittest.skipIf(coverage is None, "coverage is not installed here; the job coverage installs it and runs this case")
class TheClosingScriptRefusesEveryLostPart(unittest.TestCase):
    """scripts/ci_coverage_combine.py as a program, on data files written by coverage itself."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)
        self.data = self.root / "coverage-data"
        self.data.mkdir()
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.py").write_text("def a():\n    return 1\n\n\ndef b():\n    return 2\n", encoding="utf-8")
        (self.root / "drive.py").write_text("import sys\nsys.path.insert(0, 'pkg')\nimport a\ngetattr(a, sys.argv[1])()\n",
                                            encoding="utf-8")

    def tearDown(self):
        self._dir.cleanup()

    def _part(self, n: int, call: str) -> pathlib.Path:
        """The data of one part: coverage measures pkg/a.py while `call` runs."""
        out = self.data / f".coverage.part-{n}"
        r = subprocess.run([sys.executable, "-m", "coverage", "run", f"--data-file={out}", "--include=pkg/*",
                            "drive.py", call], cwd=self.root, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return out

    def _run(self, parts: int = 2, result: str = "success") -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(COMBINE), "--data-dir", str(self.data), "--parts", str(parts),
                               "--result", result], cwd=self.root, capture_output=True, text=True, timeout=120)

    def test_sound_parts_combine_into_the_union_of_their_lines(self):
        self._part(1, "a")
        self._part(2, "b")
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("combined the data of 2 of 2 parts", r.stdout)
        data = coverage.CoverageData(basename=str(self.root / ".coverage"))
        data.read()
        lines = data.lines(str(self.root / "pkg" / "a.py"))
        self.assertTrue({2, 5} <= set(lines), lines)
        self.assertTrue((self.data / ".coverage.part-1").exists(), "--keep leaves the parts for a second look")

    def test_a_missing_part_is_refused(self):
        self._part(1, "a")
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-2 is missing", r.stdout)
        self.assertFalse((self.root / ".coverage").exists(), "nothing is combined over a partial suite")

    def test_no_part_at_all_is_never_green(self):
        for parts in (0, -1):
            with self.subTest(parts=parts):
                r = self._run(parts=parts)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn("zero parts are never a combined coverage", r.stdout)
        r = self._run(parts=1)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-1 is missing", r.stdout)

    def test_a_matrix_that_did_not_succeed_is_refused_even_with_all_data(self):
        self._part(1, "a")
        self._part(2, "b")
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result):
                r = self._run(result=result)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("not 'success'", r.stdout)

    def test_an_empty_or_foreign_or_unmeasured_file_is_refused(self):
        self._part(1, "a")
        (self.data / ".coverage.part-2").write_bytes(b"")
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-2 is empty", r.stdout)
        (self.data / ".coverage.part-2").write_text("not a database", encoding="utf-8")
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-2 is not readable coverage data", r.stdout)
        # Real coverage data with its schema and version, whose measured files are taken out.
        leer = self._part(2, "b")
        con = sqlite3.connect(leer)
        con.execute("DELETE FROM line_bits")
        con.execute("DELETE FROM file")
        con.commit()
        con.close()
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-2 measured no file", r.stdout)

    def test_a_file_no_part_writes_is_refused(self):
        self._part(1, "a")
        self._part(2, "b")
        (self.data / ".coverage.part-3").write_bytes((self.data / ".coverage.part-2").read_bytes())
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-3 is no part's data file", r.stdout)

    def test_data_of_another_coverage_version_is_refused(self):
        self._part(1, "a")
        p = self._part(2, "b")
        con = sqlite3.connect(p)
        con.execute("UPDATE meta SET value = '0.0.1' WHERE key = 'version'")
        con.commit()
        con.close()
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("written by coverage 0.0.1", r.stdout)


if __name__ == "__main__":
    unittest.main()
