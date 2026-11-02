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
     their data merged into the one directory the closing script reads, checks K parts and holds the floor.
     Every run block the contract holds (suite, build, keep, closing) is compared line for line, no run step
     carries a `shell` or a `working-directory`, so a held line cannot sit in a branch that never runs, no step
     sets the Rust verifier or coverage core settings again, and the matrix has the part axis only;
  2. collects the whole suite once and checks that the plugin's assignment puts every collected item in exactly
     one of the K parts and leaves no part empty. That the collection hook keeps exactly the assigned items is
     held by tests/test_ci_test_parts_cover_the_suite.py (ThePluginKeepsExactlyItsFiles), which runs the plugin
     for real; every part runs that same plugin through the call SUITE below;
  3. runs the closing script as a program on real coverage data: K sound parts combine, and every way to lose
     a part is refused before the floor, zero parts and data of files outside the measured source included.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
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
#: The directory the suite measures (`--cov` of SUITE); every measured file of every part must lie in it.
SOURCE = "src/proofbundle"
#: The step that keeps a part's data, line for line, and where it puts the file the part uploads.
KEEP = ("set -euo pipefail", "test -s .coverage", 'mkdir -p "$RUNNER_TEMP/coverage-data"',
        'cp .coverage "$RUNNER_TEMP/coverage-data/.coverage.part-${{ matrix.part }}"')
KEPT = "${{ runner.temp }}/coverage-data/.coverage.part-${{ matrix.part }}"
#: The settings every part must measure under; the job sets them, and no step may set them again.
HELD_ENV = frozenset({"PROOFBUNDLE_REQUIRE_PB_VERIFY_RS", "PROOFBUNDLE_PB_VERIFY_RS", "COVERAGE_CORE"})
#: What a run step may carry besides `if` and `continue-on-error` (found on their own): a `shell` or a
#: `working-directory` changes what its lines do.
RUN_STEP_KEYS = frozenset({"name", "env", "run"})


#: An action pinned to a commit, the form tests/test_pr_form_gate_in_ci.py holds for its own workflow.
PINNED_USES = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
#: The actions a coverage job may run besides the ones it is held to (upload, download).
SETUP_ACTIONS = ("actions/checkout", "actions/setup-python")


def _unknown_steps(steps: list, held: list) -> list[str]:
    """Every step that is none of the held steps, an installed package list or a pinned checkout or setup-python.
    A step before the suite can change its environment for the steps after it through GITHUB_ENV or GITHUB_PATH,
    whatever the declared env says, so a step of an unknown kind is a finding, an action as well as a run step;
    the one install step may not write there. Each known kind appears once. Pure."""
    found, seen = [], set()
    for s in steps:
        if any(s is h for h in held):
            continue
        uses, run = str(s.get("uses", "")), str(s.get("run", "")).strip()
        if uses:
            kind = uses.split("@", 1)[0]
            if kind not in SETUP_ACTIONS:
                found.append(f"the step {s.get('name') or uses!r} runs {uses!r}, none of the known actions: a step "
                             "must not narrow the following suite through GITHUB_ENV")
                continue
            if not PINNED_USES.match(uses):
                found.append(f"the step {s.get('name') or uses!r} uses {uses!r}, not pinned to a commit")
        elif (run.startswith("python -m pip install ") and "\n" not in run
              and not any(w in run for w in ("GITHUB_ENV", "GITHUB_PATH", ">", ";", "&", "|", "$("))):
            kind = "install"
        else:
            found.append(f"the step {s.get('name') or run!r} is none of the known steps: a run step must not "
                         "narrow the following suite through GITHUB_ENV")
            continue
        if kind in seen:
            found.append(f"a second {kind} step ({s.get('name') or uses or run!r}): each known step runs once")
        seen.add(kind)
    for h in held:
        uses = str(h.get("uses", ""))
        if uses and not PINNED_USES.match(uses):
            found.append(f"the step {h.get('name') or uses!r} uses {uses!r}, not pinned to a commit")
    return found


def _lines(step: dict) -> list[str]:
    return [x.strip() for x in str(step.get("run", "")).strip().splitlines()]


def _run_step_keys(steps: list) -> list[str]:
    found = []
    for s in steps:
        if "run" in s:
            for key in sorted(set(s) - RUN_STEP_KEYS - {"if", "continue-on-error"}):
                found.append(f"the step {s.get('name') or s.get('run')!r} carries `{key}`, which changes what "
                             "its lines do")
    return found


def _ci_workflow() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


def _ci_jobs() -> dict:
    return _ci_workflow()["jobs"]


def _combine():
    spec = importlib.util.spec_from_file_location("ci_coverage_combine_under_contract", COMBINE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workflow_findings(workflow: dict) -> list[str]:
    """Where the whole workflow changes how the coverage steps run: run defaults change the shell or directory of
    every run step, and an env key of pytest or coverage changes what a part collects or measures. Pure."""
    found = []
    for key in sorted((workflow.get("defaults") or {}).get("run") or {}):
        found.append(f"the workflow sets defaults.run.{key}, which changes what every run step does")
    for key in sorted(workflow.get("env") or {}):
        if key in HELD_ENV or key.startswith(("PYTEST", "COVERAGE")):
            found.append(f"the workflow env sets {key}, which changes what the parts collect or measure")
    return found


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
    for key in sorted(set(matrix) - {"part", "include", "exclude"}):
        findings.append(f"the matrix carries the axis `{key}`: the parts matrix must contain only the part axis, "
                        "additional axes repeat parts")
    for key in ("if", "continue-on-error", "needs"):
        if key in job:
            findings.append(f"the job carries `{key}`, so a part may not run or may fail without failing it")
    env = job.get("env") or {}
    if str(env.get("PROOFBUNDLE_REQUIRE_PB_VERIFY_RS")) != "1" or env.get("PROOFBUNDLE_PB_VERIFY_RS") != PINNED:
        findings.append("a part does not require and pin the Rust verifier")
    if env.get("COVERAGE_CORE") != "sysmon":
        findings.append(f"a part measures with COVERAGE_CORE={env.get('COVERAGE_CORE')!r}, not sysmon")
    for key in sorted(set(env) - HELD_ENV):
        findings.append(f"the job env sets {key}: a part runs under exactly the held settings, and another key "
                        "can narrow the collection (PYTEST_ADDOPTS) or move the data")
    if "defaults" in job:
        findings.append("the job carries `defaults`, which changes the shell or directory of every run step")
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
    for s in steps:
        for key in sorted(set(s.get("env") or {}) - ({"CI_PART"} if s is suite[0] else set())):
            findings.append(f"the step {s.get('name') or s.get('run') or s.get('uses')!r} sets {key}: a step "
                            "overrides the required Rust verifier or coverage core settings of the job, or adds "
                            "to them")
    runs = [str(s.get("run", "")).strip() for s in steps]
    if BUILD not in runs or runs.index(BUILD) > steps.index(suite[0]):
        findings.append("the Rust verifier is not built before the suite")
    keep = [s for s in steps if ".coverage.part-${{ matrix.part }}" in str(s.get("run", ""))]
    if len(keep) != 1 or _lines(keep[0]) != list(KEEP):
        findings.append("no step keeps the part's data under `.coverage.part-<part>` after checking it is not empty, "
                        "line for line")
    up = [s for s in steps if str(s.get("uses", "")).startswith(UPLOAD)]
    w = (up[0].get("with") or {}) if len(up) == 1 else {}
    if (len(up) != 1 or w.get("name") != "coverage-part-${{ matrix.part }}" or w.get("include-hidden-files") is not True
            or w.get("if-no-files-found") != "error" or w.get("path") != KEPT):
        findings.append("the part does not upload the file it kept as coverage-part-<part>, hidden file included, "
                        "and failing when there is none")
    if len(keep) == 1 and len(up) == 1 and not steps.index(suite[0]) < steps.index(keep[0]) < steps.index(up[0]):
        findings.append("the part does not run the suite, keep its data and upload it, in that order")
    held = [suite[0]] + [s for s in steps if str(s.get("run", "")).strip() == BUILD][:1] + keep[:1] + up[:1]
    findings += _unknown_steps(steps, held)
    for s in steps:
        name = s.get("name") or s.get("uses") or s.get("run")
        for key in ("if", "continue-on-error"):
            if key in s:
                findings.append(f"the step {name!r} carries `{key}`, and every part needs every step")
    return findings + _run_step_keys(steps)


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
    if "defaults" in job:
        findings.append("the job carries `defaults`, which changes the shell or directory of every run step")
    for key in sorted(job.get("env") or {}):
        findings.append(f"the closing job env sets {key}, which the check and the floor do not need")
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
    if len(down) == 1 and not steps.index(down[0]) < steps.index(close[0]):
        findings.append("the closing job does not download the data before the closing step")
    findings += _unknown_steps(steps, close[:1] + down[:1])
    run = str(close[0].get("run", ""))
    lines = [x.strip() for x in run.strip().splitlines()]
    expected = (f"python scripts/ci_coverage_combine.py --data-dir {DATA_DIR} --parts {k} "
                f'--result "$PARTS_RESULT" --source {SOURCE}')
    if k is None or not lines or lines[0] != expected:
        findings.append(f"the closing step does not run {expected!r} first")
    if lines[1:] != [FLOOR]:
        findings.append(f"the floor {FLOOR!r} does not follow the check as the one other line")
    if (close[0].get("env") or {}).get("PARTS_RESULT") != "${{ needs.coverage-part.result }}":
        findings.append("PARTS_RESULT is not the result of the matrix coverage-part")
    for s in steps:
        for key in sorted(set(s.get("env") or {}) - ({"PARTS_RESULT"} if s is close[0] else set())):
            findings.append(f"the step {s.get('name') or s.get('uses') or s.get('run')!r} sets {key}, which the "
                            "check and the floor do not need")
    for s in steps:
        if "continue-on-error" in s or "if" in s:
            findings.append(f"the step {s.get('name') or s.get('uses')!r} carries `if` or `continue-on-error`")
    return findings + _run_step_keys(steps)


@unittest.skipIf(yaml is None, "PyYAML is missing, so the workflow cannot be read")
class TheCoverageJobsAreShapedSoNoPartIsLost(unittest.TestCase):

    def test_the_parts_and_the_closing_job_as_they_stand(self):
        jobs = _ci_jobs()
        self.assertEqual(part_findings(jobs[PARTS_JOB]), [])
        k = len(jobs[PARTS_JOB]["strategy"]["matrix"]["part"])
        self.assertEqual(closing_findings(jobs[CLOSING_JOB], k), [])
        self.assertEqual(workflow_findings(_ci_workflow()), [])

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


#: A commit id of the right form for the built jobs; none of them is run.
PIN = "0123456789abcdef" * 2 + "01234567"


class TheShapeChecksCatchWhatTheyAreFor(unittest.TestCase):
    """Each finding of part_findings and closing_findings must fail on a built counter-example."""

    def _part(self) -> dict:
        return {"name": "coverage part (${{ matrix.part }} of 2)",
                "env": {"PROOFBUNDLE_REQUIRE_PB_VERIFY_RS": "1", "PROOFBUNDLE_PB_VERIFY_RS": PINNED,
                        "COVERAGE_CORE": "sysmon"},
                "strategy": {"fail-fast": False, "matrix": {"part": [1, 2]}},
                "steps": [{"uses": "actions/checkout@" + PIN},
                          {"name": "Install", "run": "python -m pip install -e .[dev]"},
                          {"name": "Build", "run": BUILD},
                          {"name": "Suite", "env": {"CI_PART": "${{ matrix.part }}/2"}, "run": SUITE},
                          {"name": "Keep", "run": "\n".join(KEEP) + "\n"},
                          {"name": "Up", "uses": UPLOAD + PIN,
                           "with": {"name": "coverage-part-${{ matrix.part }}", "include-hidden-files": True,
                                    "if-no-files-found": "error", "path": KEPT}}]}

    def _closing(self) -> dict:
        return {"needs": ["coverage-part"], "if": "${{ !cancelled() }}",
                "steps": [{"uses": "actions/checkout@" + PIN},
                          {"name": "Down", "uses": DOWNLOAD + PIN,
                           "with": {"pattern": "coverage-part-*", "merge-multiple": True, "path": DATA_DIR}},
                          {"name": "Close", "env": {"PARTS_RESULT": "${{ needs.coverage-part.result }}"},
                           "run": "python scripts/ci_coverage_combine.py --data-dir coverage-data --parts 2 "
                                  f'--result "$PARTS_RESULT" --source {SOURCE}\n' + FLOOR + "\n"}]}

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
            "line for line": self._step(self._part(), 4, run="if false; then\n" + "\n".join(KEEP) + "\nfi\n"),
            "in that order": changed(steps=[self._part()["steps"][i] for i in (0, 1, 2, 3, 5, 4)]),
            "run step must not narrow": changed(steps=self._part()["steps"][:3] + [{"name": "Narrow", "run": "echo 'PYTEST_ADDOPTS=--ignore=tests/x.py' >> \"$GITHUB_ENV\""}]
                                               + self._part()["steps"][3:]),
            "none of the known actions": changed(steps=self._part()["steps"][:3]
                                                 + [{"uses": "someone/sets-env@" + PIN}] + self._part()["steps"][3:]),
            "checkout@v7', not pinned": self._step(self._part(), 0, uses="actions/checkout@v7"),
            "upload-artifact@v7', not pinned": self._step(self._part(), 5, uses="actions/upload-artifact@v7"),
            "a second install step": changed(steps=self._part()["steps"][:2] + [self._part()["steps"][1]]
                                             + self._part()["steps"][2:]),
            "none of the known steps": self._step(self._part(), 1, run="python -m pip install x >> \"$GITHUB_ENV\""),
            "can narrow the collection": changed(env={**self._part()["env"], "PYTEST_ADDOPTS": "--ignore=tests/x.py"}),
            "carries `defaults`": changed(defaults={"run": {"shell": "bash {0}"}}),
            "additional axes repeat parts": matrix(replica=[1, 2]),
            "overrides the required Rust verifier": self._step(self._part(), 3, env={
                "CI_PART": "${{ matrix.part }}/2", "PROOFBUNDLE_REQUIRE_PB_VERIFY_RS": "0",
                "PROOFBUNDLE_PB_VERIFY_RS": "/missing/pb_verify_rs", "COVERAGE_CORE": "ctrace"}),
            "sets COVERAGE_CORE": self._step(self._part(), 2, env={"COVERAGE_CORE": "ctrace"}),
            "changes what its lines do": self._step(self._part(), 4, shell="bash {0}"),
            "upload the file it kept": self._step(self._part(), 5, **{"with": {
                "name": "coverage-part-${{ matrix.part }}", "include-hidden-files": True, "if-no-files-found": "error",
                "path": "${{ runner.temp }}/other/.coverage.part-${{ matrix.part }}"}}),
            "one suite step": changed(steps=[]),
        }
        for words, job in cases.items():
            with self.subTest(words):
                found = part_findings(job)
                self.assertTrue(any(words in f for f in found), found)

    def test_a_workflow_that_changes_how_every_step_runs_is_found(self):
        """Codex pre-run at 6f2b21b1: the shell and the env of a step come from three levels, and the contract
        held the step only. The workflow level is held here, the job and the step level in the two checks."""
        self.assertEqual(workflow_findings({"jobs": {}}), [])
        self.assertEqual(workflow_findings({"env": {"FOO": "1"}}), [], "control: an unrelated key is no finding")
        for words, workflow in {"defaults.run.shell": {"defaults": {"run": {"shell": "bash {0}"}}},
                                "env sets PYTEST_ADDOPTS": {"env": {"PYTEST_ADDOPTS": "-k x"}},
                                "env sets COVERAGE_FILE": {"env": {"COVERAGE_FILE": "x"}},
                                "env sets COVERAGE_CORE": {"env": {"COVERAGE_CORE": "ctrace"}}}.items():
            with self.subTest(words):
                found = workflow_findings(workflow)
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
            "as the one other line": self._step(self._closing(), 2,
                                                run=close["run"].replace(FLOOR, "if false; then\n" + FLOOR + "\nfi")),
            "--source src/proofbundle": self._step(self._closing(), 2,
                                                   run=close["run"].replace(f" --source {SOURCE}", "")),
            "changes what its lines do": self._step(self._closing(), 2, shell="bash {0}"),
            "before the closing step": changed(steps=[self._closing()["steps"][i] for i in (0, 2, 1)]),
            "run step must not narrow": changed(steps=self._closing()["steps"][:2] + [{"name": "Move", "run": "echo COVERAGE_FILE=elsewhere >> \"$GITHUB_ENV\""}]
                                               + self._closing()["steps"][2:]),
            "download-artifact@v8', not pinned": self._step(self._closing(), 1, uses="actions/download-artifact@v8"),
            "carries `defaults`": changed(defaults={"run": {"shell": "bash {0}"}}),
            "closing job env sets COVERAGE_FILE": changed(env={"COVERAGE_FILE": "elsewhere"}),
            "sets COVERAGE_FILE, which": self._step(self._closing(), 2, env={
                "PARTS_RESULT": "${{ needs.coverage-part.result }}", "COVERAGE_FILE": "elsewhere"}),
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

    def _run(self, parts: int = 2, result: str = "success", source: str = "pkg") -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(COMBINE), "--data-dir", str(self.data), "--parts", str(parts),
                               "--result", result, "--source", source], cwd=self.root, capture_output=True, text=True,
                              timeout=120)

    def _foreign(self, n: int, include: str) -> pathlib.Path:
        """The data of one part that measured `other/b.py`, a file outside the source pkg (and pkg/a.py when
        `include` names it too): real coverage data, the right name, the running version."""
        (self.root / "other").mkdir(exist_ok=True)
        (self.root / "other" / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")
        (self.root / "drive_other.py").write_text(
            "import sys\nsys.path[:0] = ['pkg', 'other']\nimport a, b\na.a()\nb.b()\n", encoding="utf-8")
        out = self.data / f".coverage.part-{n}"
        r = subprocess.run([sys.executable, "-m", "coverage", "run", f"--data-file={out}", f"--include={include}",
                            "drive_other.py"], cwd=self.root, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return out

    def test_sound_parts_combine_into_the_union_of_their_lines(self):
        self._part(1, "a")
        self._part(2, "b")
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("combined the data of 2 of 2 parts", r.stdout)
        data = coverage.CoverageData(basename=str(self.root / ".coverage"))
        data.read()
        lines = data.lines(str(self.root / "pkg" / "a.py"))
        # Exactly the union: part 1 runs lines 1, 2 and 5 (the import and a()), part 2 lines 1, 5 and 6 (b()), so
        # line 6 is there only if the data of part 2 was combined.
        self.assertEqual(set(lines), {1, 2, 5, 6})
        self.assertIn("every executed line of every part kept", r.stdout)
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

    def test_data_of_files_outside_the_source_is_refused(self):
        """Codex pre-run at 06c2cb6b: seven sound data files that measured only a foreign file combined, and the
        floor judged 100 % over it. The old check passed this; a part that measured a file outside the source is
        refused now, alone and next to files of the source, and nothing is combined."""
        for include in ("other/*", "pkg/*,other/*"):
            with self.subTest(include=include):
                self._part(1, "a")
                self._foreign(2, include)
                r = self._run()
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn(".coverage.part-2 measured 1 file(s) outside pkg", r.stdout)
                self.assertIn("b.py", r.stdout)
                self.assertFalse((self.root / ".coverage").exists(), "nothing is combined over foreign data")
        self._part(2, "b")
        self.assertEqual(self._run().returncode, 0, "control: the same parts inside the source combine")

    def test_a_part_that_only_names_a_file_is_refused(self):
        """Codex pre-run at c385f320: a part whose data names a source file but holds no executed line (coverage
        records such a name through touch_file) passed as measured, and the other parts carried the floor. The old
        check let it through; it is refused now, and nothing is combined."""
        self._part(1, "a")
        data = coverage.CoverageData(basename=str(self.data / ".coverage.part-2"))
        data.add_lines({})
        data.touch_file(str(self.root / "pkg" / "a.py"))
        data.write()
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".coverage.part-2 names 1 file(s) but holds no executed line", r.stdout)
        self.assertFalse((self.root / ".coverage").exists(), "nothing is combined over a part that measured nothing")

    def test_lines_that_the_combine_drops_are_refused_after_it(self):
        """Codex pre-run at 69423447: a part file whose lines point at no context passes every check before the
        combine, and `coverage combine` then drops those lines, so the floor judged fewer lines than the parts
        measured. After the combine the data the report reads must hold every executed line of every part."""
        self._part(1, "a")
        p = self._part(2, "b")
        con = sqlite3.connect(p)
        con.execute("UPDATE line_bits SET context_id = 999999")
        con.commit()
        con.close()
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("the combined data does not preserve every accepted input measurement", r.stdout)
        self.assertIn("lines [6]", r.stdout)

    def test_two_names_of_one_file_give_the_lines_of_both(self):
        """Codex pre-run at 6f2b21b1: the lines were keyed by the resolved path, and of two names of one file the
        lines of one were kept. Pure, without coverage data."""
        class Data:
            def measured_files(self):
                return {"pkg/a.py", "pkg/./a.py"}

            def lines(self, name):
                return [1] if "/./" not in name else [2]
        self.assertEqual(_combine()._executed(Data()), {os.path.realpath("pkg/a.py"): {1, 2}})

    def test_lines_of_either_name_of_one_file_that_the_combine_drops_are_refused(self):
        """The end-to-end control of the case above: one part names pkg/a.py twice, the combine drops the lines of
        one name (it keeps both names apart), and the script refuses, each name in turn. This case is no catch of
        the old code: which name the old keyed dict kept depended on the iteration order of a set of strings, so
        on the hash seed of the child process. The pure case above falls on the old code every time."""
        plain = str(self.root / "pkg" / "a.py")
        dotted = str(self.root / "pkg") + "/./a.py"
        for n, damaged in enumerate((plain, dotted)):
            with self.subTest(damaged=damaged):
                d = self.root / f"data-{n}"
                d.mkdir()
                data = coverage.CoverageData(basename=str(d / ".coverage.part-1"))
                data.add_lines({plain: {2}, dotted: {6}})
                data.write()
                con = sqlite3.connect(d / ".coverage.part-1")
                con.execute("UPDATE line_bits SET context_id = 999999 WHERE file_id = (SELECT id FROM file "
                            "WHERE path = ?)", (damaged,))
                con.commit()
                con.close()
                r = subprocess.run([sys.executable, str(COMBINE), "--data-dir", str(d), "--parts", "1", "--result",
                                    "success", "--source", "pkg"], cwd=self.root, capture_output=True, text=True,
                                   timeout=120)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("does not preserve every accepted input measurement", r.stdout)

    def test_a_source_that_is_no_directory_is_a_usage_error(self):
        self._part(1, "a")
        self._part(2, "b")
        r = self._run(source="no_such_dir")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("--source no_such_dir is no directory", r.stdout)

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
