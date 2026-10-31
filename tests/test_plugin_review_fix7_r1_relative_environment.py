"""Review round 7 of 2026-10-10, R7-1: a relative environment keeps the directory it was given in.

Measured by the reviewer at 0c88746f: a valid signed done fixture in P/repo (order src/*, a clean receipted change), an
empty directory P/repo/repo and an untracked P/repo/outside.txt. With GIT_DIR=P/repo/.git (absolute) and
GIT_WORK_TREE=repo (relative) git started in P addresses the work tree P/repo, which holds outside.txt. The gate named
the work tree in P, then ran every further read with `-C P/repo`, where git took the same relative value against
P/repo and listed the empty P/repo/repo: both Stop paths said done and `done-check --repo P` exited 0 with pass/done.
With GIT_WORK_TREE absolute the Stop hook blocked and the CLI exited 1 (stale_receipt, outside_paths).

Property: the attested work tree contains every unignored file of the work tree git addresses in the call's context.
The gate reads every input from the same source and in the same meaning as git; where it cannot, the verdict stays NOT
MEASURED. git resolves GIT_DIR and GIT_WORK_TREE once, against the directory it starts in, and the other path-valued
names against the directory it works in after that (measured with git 2.43.0 and 2.51.1). The gate now pins what git
resolved in the call's directory as absolute values for every later read, and leaves a value whose meaning it cannot
pin NOT MEASURED. Red against 0c88746f. Both hosts.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

import test_plugin_done_check as dc
import test_plugin_gate_n2c_push_done as n2c
import test_plugin_review_fix_f6_early_open as f6
from _gate_answer import Silent, long_text

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment


def _fixture(tmp_path: pathlib.Path, keys, outside: bool = True) -> pathlib.Path:
    """P/repo with the order src/* at A, the work at B, a receipt for B; an empty P/repo/repo and, optionally, an
    untracked P/repo/outside.txt written after the receipt."""
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(repo, "A: the order")
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "B: the work")
    dc._run(repo, keys.signer, UNIT)
    (repo / "repo").mkdir()
    if outside:
        dc._write(repo / "outside.txt", "x\n")
    return repo


def _done_check(env: dict, directory: pathlib.Path, cwd: pathlib.Path | None = None) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, "-I", str(dc.GATE), "done-check", "--repo", str(directory)],
                          capture_output=True, text=True, env=env, cwd=cwd, timeout=180, check=False)
    return proc.returncode, json.loads(proc.stdout)


def _relative(env: dict, repo: pathlib.Path, **extra: str) -> dict:
    return dict(env, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE="repo", **extra)


def _open_reasons(report: dict) -> set:
    return {p["status"] for p in report.get("open", [])} | {report["reason_id"]}


def test_git_started_in_p_addresses_the_work_tree_that_holds_the_untracked_file(env, tmp_path, keys):
    """Non-vacuous: started in P, git names P/repo and lists outside.txt; started in P/repo, the same value names the
    empty P/repo/repo, which is the directory the gate read at 0c88746f."""
    repo = _fixture(tmp_path, keys)
    rel = _relative(env, repo)
    run = lambda cwd, *args: subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,  # noqa: E731
                                            env=rel, timeout=60, check=False).stdout
    assert run(tmp_path, "rev-parse", "--show-toplevel").strip() == str(repo)
    assert "outside.txt" in run(tmp_path, "ls-files", "--others", "--exclude-standard").split("\n")
    assert run(repo, "rev-parse", "--show-toplevel").strip() == str(repo / "repo")
    assert run(repo, "ls-files", "--others", "--exclude-standard") == ""


def test_the_done_check_reads_the_work_tree_git_addresses_from_the_named_directory(env, tmp_path, keys):
    repo = _fixture(tmp_path, keys)
    code, report = _done_check(_relative(env, repo), tmp_path)
    assert code == 1 and report["verdict"] == "deny", report
    assert {"stale_receipt", "outside_paths"} & _open_reasons(report), report


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_stop_hook_reads_the_work_tree_git_addresses_from_the_session_directory(env, tmp_path, keys, host):
    repo = _fixture(tmp_path, keys)
    answer = f6.stop(_relative(env, repo), tmp_path, host)
    assert answer is not None and answer.get("decision") == "block", answer


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_the_absolute_value_gives_the_same_verdict(env, tmp_path, keys, host):
    repo = _fixture(tmp_path, keys)
    absolute = dict(env, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE=str(repo))
    code_abs, report_abs = _done_check(absolute, tmp_path)
    code_rel, report_rel = _done_check(_relative(env, repo), tmp_path)
    assert code_abs == 1 and (code_rel, report_rel["reason_id"]) == (code_abs, report_abs["reason_id"]), \
        (report_abs, report_rel)
    answer = f6.stop(absolute, tmp_path, host)
    assert answer is not None and answer.get("decision") == "block", answer


def test_control_without_the_untracked_file_the_relative_environment_passes(env, tmp_path, keys):
    """The pinned values change no verdict where the relative value already named the right tree: without
    outside.txt the work is the receipted change inside src/*, from P and from the work tree itself."""
    repo = _fixture(tmp_path, keys, outside=False)
    code, report = _done_check(_relative(env, repo), tmp_path)
    assert (code, report["verdict"], report["reason_id"]) == (0, "pass", "done"), report
    inside = dict(env, GIT_DIR=".git", GIT_WORK_TREE=".")
    code, report = _done_check(inside, repo)
    assert (code, report["verdict"], report["reason_id"]) == (0, "pass", "done"), report


def test_a_relative_git_dir_is_taken_against_the_named_directory(env, tmp_path, keys):
    """The sibling: GIT_DIR=repo/.git and GIT_WORK_TREE=repo, both relative, from P."""
    _fixture(tmp_path, keys)
    rel = dict(env, GIT_DIR="repo/.git", GIT_WORK_TREE="repo")
    code, report = _done_check(rel, tmp_path)
    assert code == 1 and {"stale_receipt", "outside_paths"} & _open_reasons(report), report


def test_a_work_tree_without_git_dir_keeps_the_repository_git_found_from_the_named_directory(env, tmp_path, keys):
    """The sibling of discovery: GIT_WORK_TREE set, GIT_DIR not. git started in O/P finds the outer repository O and
    takes P/repo as its work tree; a read started in P/repo finds P/repo/.git instead, another repository. The gate
    judges the repository git found in the call's directory: here O, which declares nothing, so nothing passes as
    done for P/repo's declaration."""
    outer = tmp_path / "outer"
    outer.mkdir()
    dc._git(outer, "init", "-q", "-b", "main")
    dc._write(outer / "o.txt", "o\n")
    dc._commit(outer, "outer")
    repo = _fixture(outer, keys, outside=False)
    wt = dict(env, GIT_WORK_TREE=str(repo))
    found = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], cwd=outer, env=wt, capture_output=True,
                           text=True, timeout=60).stdout.strip()
    assert found == str(outer / ".git")   # non-vacuous: git in O uses O's repository
    code, report = _done_check(wt, outer)
    assert not (code == 0 and report["reason_id"] == "done"), report
    code, report = _done_check(dict(env), repo)   # control: P/repo itself passes
    assert (code, report["reason_id"]) == (0, "done"), report


PHASED = ["GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
          "GIT_SHALLOW_FILE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "HOME", "XDG_CONFIG_HOME"]


def test_git_started_outside_the_work_tree_reads_a_relative_index_file_in_two_places(env, tmp_path, keys):
    """Non-vacuous: from P, outside the work tree P/repo, with GIT_INDEX_FILE=idx, `ls-files --others` reads P/idx and
    `status` reads P/repo/idx (measured with git 2.43.0 and 2.51.1); no one file is the index git reads there."""
    repo = _fixture(tmp_path, keys, outside=False)
    base = dict(env, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE=str(repo))
    for where, name in ((tmp_path, "test_ok.py"), (repo, "src/module.py")):
        idx = dict(base, GIT_INDEX_FILE=str(where / "idx"))
        subprocess.run(["git", "read-tree", "--empty"], env=idx, cwd=repo, check=True, timeout=60)
        subprocess.run(["git", "add", name], env=idx, cwd=repo, check=True, timeout=60)
    rel = dict(base, GIT_INDEX_FILE="idx")
    run = lambda *args: subprocess.run(["git", *args], cwd=tmp_path, env=rel, capture_output=True,  # noqa: E731
                                       text=True, timeout=60, check=False).stdout.split("\n")
    assert "src/module.py" in run("ls-files", "--others", "--exclude-standard")   # P/idx holds test_ok.py only
    assert "D  test_ok.py" in run("status", "--porcelain", "--untracked-files=no")   # P/repo/idx: src/module.py only


@pytest.mark.parametrize("name", PHASED)
def test_a_relative_value_git_reads_in_two_places_outside_the_work_tree_is_not_measured(env, tmp_path, keys, name):
    """From P, outside the work tree, git reads these names against P in one command and against the work tree in
    another: a relative value is NOT MEASURED, never done, and the answer names it. The object and common directory
    are copies under P, so git started in P accepts the repository."""
    repo = _fixture(tmp_path, keys, outside=False)
    if name in ("GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"):
        shutil.copytree(repo / ".git" / ("objects" if name == "GIT_OBJECT_DIRECTORY" else ""), tmp_path / "somewhere")
    code, report = _done_check(_relative(env, repo, **{name: "somewhere"}), tmp_path)
    assert code != 0 and report["verdict"] == "deny", report
    assert name in report["message"], report
    answer = f6.stop(_relative(env, repo, **{name: "somewhere"}), tmp_path)
    assert answer is not None and answer.get("decision") == "block" and name in answer["reason"], answer


def _pins_where_config_fails(tmp_path, monkeypatch) -> tuple[dict | None, str]:
    """_pins from P for the work tree P/repo, with a git that says P lies outside the work tree and fails every config
    read, as git 2.56 does once it loads a relative GIT_ALTERNATE_OBJECT_DIRECTORIES as it starts (its release notes:
    "eagerly loading alternate object directories upon initialization")."""
    top = tmp_path / "repo"
    top.mkdir()

    def git(repo, *args, deadline):
        if args == ("rev-parse", "--is-inside-work-tree"):
            return subprocess.CompletedProcess(args, 0, b"false\n", b"")
        if args[:1] == ("config",):
            return subprocess.CompletedProcess(args, 128, b"", b"error: unable to normalize alternate object path\n")
        raise AssertionError(args)

    monkeypatch.setattr(gate, "_git", git)
    return gate._pins(str(tmp_path), str(top), time.monotonic() + 60)


def test_a_key_git_cannot_read_does_not_hide_a_relative_name_already_found(tmp_path, monkeypatch):
    """Measured in CI at b21eaaf9 with git 2.56.0: the done check answered "git could not read core.excludesFile" for a
    relative GIT_ALTERNATE_OBJECT_DIRECTORIES, still a deny, but without the name. The name the gate found before it
    read the keys is the answer: NOT MEASURED, naming it. Red at b21eaaf9."""
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "somewhere")
    pins, why = _pins_where_config_fails(tmp_path, monkeypatch)
    assert pins is None and "GIT_ALTERNATE_OBJECT_DIRECTORIES" in why and "NOT MEASURED" in why, why


def test_control_a_key_git_cannot_read_without_a_relative_name_stays_a_read_failure(tmp_path, monkeypatch):
    pins, why = _pins_where_config_fails(tmp_path, monkeypatch)
    assert pins is None and why.startswith("git could not read core.excludesFile"), why


def test_a_relative_exclude_file_outside_the_work_tree_is_not_measured(env, tmp_path, keys):
    """The configuration sibling: core.excludesFile=ex (here from the host's GIT_CONFIG_COUNT) from P. `ls-files` read
    P/ex and `check-ignore` P/repo/ex (measured with git 2.43.0 and 2.51.1)."""
    repo = _fixture(tmp_path, keys)
    (tmp_path / "ex").write_text("outside.txt\n", encoding="utf-8")
    rel = _relative(env, repo, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.excludesFile", GIT_CONFIG_VALUE_0="ex")
    code, report = _done_check(rel, tmp_path)
    assert code != 0 and report["verdict"] == "deny" and "core.excludesFile" in report["message"], report


def test_control_an_absolute_exclude_file_outside_the_work_tree_is_read(env, tmp_path, keys):
    """The same file named absolute: one meaning, outside.txt is ignored, the receipted change passes."""
    repo = _fixture(tmp_path, keys)
    (tmp_path / "ex").write_text("outside.txt\n", encoding="utf-8")
    rel = _relative(env, repo, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.excludesFile",
                    GIT_CONFIG_VALUE_0=str(tmp_path / "ex"))
    code, report = _done_check(rel, tmp_path)
    assert (code, report["reason_id"]) == (0, "done"), report


@pytest.mark.parametrize("name", ["HOME", "GIT_CONFIG_GLOBAL", "GIT_INDEX_FILE"])
def test_control_the_same_relative_value_from_inside_the_work_tree_passes(env, tmp_path, keys, name):
    """Started at or below the top of the work tree, git changes into the top before it reads these names, as the
    gate's reads do: one meaning, the receipted change passes, from the top and from src/."""
    repo = _fixture(tmp_path, keys, outside=False)
    (repo / "somewhere").mkdir()
    value = "somewhere" if name == "HOME" else "somewhere/file"
    for directory in (repo, repo / "src"):
        code, report = _done_check(dict(env, **{name: value}), directory)
        assert (code, report["reason_id"]) == (0, "done"), (directory, report)


def test_relative_git_dir_and_work_tree_from_a_subdirectory_are_taken_against_it(env, tmp_path, keys):
    """GIT_DIR=../.git and GIT_WORK_TREE=.. from P/repo/src: git takes both against src/, the gate pins what it
    named, and the untracked outside.txt blocks as with absolute values."""
    repo = _fixture(tmp_path, keys)
    code, report = _done_check(dict(env, GIT_DIR="../.git", GIT_WORK_TREE=".."), repo / "src")
    assert code == 1 and {"stale_receipt", "outside_paths"} & _open_reasons(report), report


def _push(env: dict, cwd: pathlib.Path) -> tuple[dict, dict]:
    """Level 1 for `git push origin main` started in cwd, with the log entry it wrote."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": "git push origin main"}})
    proc = subprocess.run([sys.executable, "-I", str(dc.GATE)], input=event, capture_output=True, text=True, env=env,
                          timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    log = pathlib.Path(env["PLUGIN_DATA"]) / gate.LOG_NAME
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    return (json.loads(proc.stdout) if proc.stdout.strip() else Silent(entry)), entry   # D53: a pass prints nothing


@pytest.mark.parametrize("git_dir", ["relative", "absolute"])
def test_level_1_reads_the_push_in_the_repository_git_names_from_the_call_directory(env, tmp_path, git_dir):
    """The push path takes its repository from the same reader: from P, GIT_DIR=r/.git (or absolute) and
    GIT_WORK_TREE=r name P/r, and a valid receipt for the pushed commit passes the done check (since R9-1 the
    destination check leaves the push NOT MEASURED). At 0c88746f the reads after the first took GIT_DIR=r/.git against
    P/r, found no repository and denied the push without a verdict."""
    logs = str(tmp_path / "logs")
    push_env = dict(env, CLAUDE_PLUGIN_DATA=logs, PLUGIN_DATA=logs)
    r = n2c.Repo(tmp_path)
    r.make("valid")
    rel = dict(push_env, GIT_DIR="r/.git" if git_dir == "relative" else str(r.path / ".git"), GIT_WORK_TREE="r")
    answer, entry = _push(rel, tmp_path)
    n2c.assert_destination_not_measured(answer, entry)
    head = n2c._rev(r.path, "HEAD")[:12]
    assert f"the sent source commit(s) {head} showed no failure" in long_text(answer), answer
    assert n2c._level2(push_env, r.path).returncode == 0

