"""Review round 8 of 2026-10-10, R8-1: the check process reads git in the work tree the gate attests.

Measured by the reviewer at 1fc58527: a clean repository P/repo, P absolute, with value.txt holding BAD at the top, a
versioned repo/value.txt holding GOOD, and a test under tests/ that reads `git rev-parse --show-toplevel` and demands
value.txt == GOOD there. Started from P with GIT_DIR="$P/repo/.git" and GIT_WORK_TREE=repo, run-evidence attested the
tree of P/repo, while the pytest it started with cwd=P/repo and the host's raw environment took the relative value a
second time and read P/repo/repo/value.txt: green_run, exit 0, bound to the digest of P/repo. With GIT_WORK_TREE
absolute the same test read P/repo/value.txt and failed (no_evidence, run_failed, exit 1). Measured with git 2.43.0 and
2.51.1.

Property: the check process and the tree check refer the git environment to the same work tree. The gate already
holds the values git resolved in the call's directory (_pins, R7-1); the check process now gets exactly those values,
and none of the other settings of the gate's own reads (_read_env). Red against 1fc58527.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_gate_n2c_push_done as n2c

GATE = n2c.GATE
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git
_write = n2c._write

#: The test the check process runs: it asks git for the work tree and demands the value the attested tree does not
#: hold. A green run means the test read another tree than the one the statement names.
_TOPLEVEL_TEST = """import pathlib, subprocess
def test_value_at_the_work_tree_git_names():
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    assert (pathlib.Path(top.stdout.strip()) / "value.txt").read_text() == "GOOD\\n"
"""
#: The same through the object store: the committed value.txt of the repository git opens.
_HEAD_TEST = """import subprocess
def test_value_in_the_repository_git_opens():
    out = subprocess.run(["git", "show", "HEAD:value.txt"], capture_output=True, text=True, check=True)
    assert out.stdout == "GOOD\\n"
"""
#: The settings of the gate's own reads that must not reach the check process.
_READ_ONLY_NAMES = ("GIT_NO_REPLACE_OBJECTS", "GIT_GRAFT_FILE", "GIT_NO_LAZY_FETCH", "GIT_LITERAL_PATHSPECS")
_ENV_TEST = """import os
def test_only_the_pins_reach_the_check_process():
    for name in %r:
        assert name not in os.environ, name
    assert os.environ.get("LC_ALL") == "en_US.UTF-8"
    assert os.environ.get("GIT_TRACE_SETUP") == "/dev/null"
""" % (_READ_ONLY_NAMES,)


def _repo(path: pathlib.Path, test: str, top_value: str = "BAD\n") -> pathlib.Path:
    """value.txt at the top, repo/value.txt with GOOD one level down, one test under tests/; committed, clean."""
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    _write(path / "value.txt", top_value)
    _write(path / "repo" / "value.txt", "GOOD\n")
    _write(path / "tests" / "test_value.py", test)
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "fixture")
    return path


def _run_evidence(directory: pathlib.Path, out: pathlib.Path, cwd: pathlib.Path, **extra: str) -> tuple[int, dict]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PROOFBUNDLE_", "PYTEST_"))}
    env.update(PYTHONDONTWRITEBYTECODE="1", **extra)
    argv = [sys.executable, "-I", str(GATE), "run-evidence", "--repo", str(directory), "--out", str(out), "--",
            sys.executable, "-m", "pytest", "-q", "-s", "tests/"]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=cwd, timeout=300, check=False)
    return proc.returncode, json.loads(proc.stdout)


def _verdict(report: dict) -> tuple[str, str]:
    return report["outcome"], report["reason_id"]


def test_git_started_in_p_and_in_the_work_tree_reads_two_trees(tmp_path):
    """Non-vacuous: the relative value names P/repo started in P and P/repo/repo started in P/repo, where the test
    runs; the value the test demands lies only in the second."""
    repo = _repo(tmp_path / "repo", _TOPLEVEL_TEST)
    env = dict(os.environ, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE="repo")
    top = lambda cwd: subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True,  # noqa: E731
                                     text=True, env=env, timeout=60, check=True).stdout.strip()
    assert top(tmp_path) == str(repo)
    assert top(repo) == str(repo / "repo")
    assert (repo / "value.txt").read_text() == "BAD\n" and (repo / "repo" / "value.txt").read_text() == "GOOD\n"


def test_a_relative_work_tree_gives_the_check_process_the_tree_the_statement_names(tmp_path):
    """The review's case: the run reads the attested P/repo and fails, as it does with the absolute value."""
    repo = _repo(tmp_path / "repo", _TOPLEVEL_TEST)
    out = tmp_path / "statement.json"
    code, report = _run_evidence(tmp_path, out, tmp_path, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE="repo")
    assert (code, _verdict(report)) == (1, ("no_evidence", "run_failed")), report
    assert not out.exists()


def test_control_an_absolute_work_tree_fails_the_same_run(tmp_path):
    repo = _repo(tmp_path / "repo", _TOPLEVEL_TEST)
    code, report = _run_evidence(tmp_path, tmp_path / "statement.json", tmp_path, GIT_DIR=str(repo / ".git"),
                                 GIT_WORK_TREE=str(repo))
    assert (code, _verdict(report)) == (1, ("no_evidence", "run_failed")), report


def test_control_a_value_the_attested_tree_holds_stays_green(tmp_path):
    """The fix changes the tree the test reads, not whether a run can be green: with GOOD at the top of P/repo the
    relative run is green and names that tree."""
    repo = _repo(tmp_path / "repo", _TOPLEVEL_TEST, top_value="GOOD\n")
    out = tmp_path / "statement.json"
    code, report = _run_evidence(tmp_path, out, tmp_path, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE="repo")
    assert (code, _verdict(report)) == (0, ("evidence", "green_run")), report
    statement = json.loads(out.read_text(encoding="utf-8"))
    assert statement["run"]["commit"] == _git(repo, "rev-parse", "HEAD").stdout.strip()


def _nested(tmp_path: pathlib.Path) -> pathlib.Path:
    """An outer repository P whose committed value.txt is GOOD, and inside it the attested repository P/repo whose
    committed value.txt is BAD, with a subdirectory sub; P/repo is ignored in P."""
    outer = tmp_path
    _git(outer, "init", "-q", "-b", "main")
    _write(outer / "value.txt", "GOOD\n")
    _write(outer / ".gitignore", "/repo/\n/statement.json\n")
    _git(outer, "add", "-A")
    _git(outer, "commit", "-q", "-m", "outer")
    repo = _repo(outer / "repo", _HEAD_TEST)
    (repo / "sub").mkdir()
    return repo


def test_git_takes_a_relative_git_dir_against_the_directory_it_starts_in(tmp_path):
    """Non-vacuous: GIT_DIR=../.git with GIT_WORK_TREE=.. opens P/repo/.git started in P/repo/sub and P/.git started
    in P/repo, where the check process runs; only the second holds GOOD."""
    repo = _nested(tmp_path)
    env = dict(os.environ, GIT_DIR="../.git", GIT_WORK_TREE="..")
    show = lambda cwd: subprocess.run(["git", "show", "HEAD:value.txt"], cwd=cwd, capture_output=True,  # noqa: E731
                                      text=True, env=env, timeout=60, check=True).stdout
    assert show(repo / "sub") == "BAD\n"
    assert show(repo) == "GOOD\n"


def test_a_relative_git_dir_gives_the_check_process_the_repository_the_statement_names(tmp_path):
    """The sibling of the class: a relative GIT_DIR (with its work tree) named in a subdirectory. The gate pinned
    P/repo/.git for its own reads; the check process had opened the outer repository and passed."""
    repo = _nested(tmp_path)
    out = tmp_path / "statement.json"
    code, report = _run_evidence(repo / "sub", out, repo / "sub", GIT_DIR="../.git", GIT_WORK_TREE="..")
    assert (code, _verdict(report)) == (1, ("no_evidence", "run_failed")), report
    assert not out.exists()


@pytest.mark.parametrize("relative", [True, False])
def test_only_the_pins_reach_the_check_process_not_the_settings_of_the_gates_reads(tmp_path, relative):
    """The repair gives the check process the resolved values only: the gate's own read settings (replace refs off,
    grafts emptied, no lazy fetch, literal pathspecs, LC_ALL=C, no trace) stay out of the test's environment, which
    keeps the host's values."""
    repo = _repo(tmp_path / "repo", _ENV_TEST)
    out = tmp_path / "statement.json"
    work_tree = "repo" if relative else str(repo)
    code, report = _run_evidence(tmp_path, out, tmp_path, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE=work_tree,
                                 LC_ALL="en_US.UTF-8", GIT_TRACE_SETUP="/dev/null")
    assert (code, _verdict(report)) == (0, ("evidence", "green_run")), report
