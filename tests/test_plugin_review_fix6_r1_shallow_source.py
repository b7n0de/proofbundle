"""Review round 6 of 2026-10-10, R6-1: the history walk and the check of where it is cut use the view git uses.

Measured by the reviewer at b513ff5a: commit A declares an order with paths src/* and one check, B changes outside.txt,
C changes src/module.py, a valid receipt for C, .git/shallow present and empty, and a second file outside the work tree
holding only B's id. Without a variable the done check fails with outside_paths. With GIT_SHALLOW_FILE on the second file
git cuts the history at B, `rev-list` stops there and B reads as a root, while the gate read the cut points from
`--git-path shallow`, the empty file: B passed as the commit that declared the order, the done check exited 0 and the Stop
hook said done. git itself said shallow true.

Property: the history walk and the check of its cut points use the same view as git; where the history is cut before
the order, the order's base stays NOT MEASURED. The gate reads no shallow file now: a commit whose parents git does not
show, while the commit object names one, is a cut, whatever told git so. Red against b513ff5a. Both hosts.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment


def _rev(repo: pathlib.Path, rev: str) -> str:
    return dc._git(repo, "rev-parse", rev)


def _history(tmp_path: pathlib.Path, keys, outside: bool = True) -> tuple[pathlib.Path, dict]:
    """P (base files), A (the order, paths src/*), B (outside.txt, optional), C (src/module.py), a receipt for C, an
    empty .git/shallow."""
    repo = f6._repo(tmp_path)
    commits = {"P": _rev(repo, "HEAD")}
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(repo, "A: the order")
    commits["A"] = _rev(repo, "HEAD")
    if outside:
        dc._write(repo / "outside.txt", "x\n")
        dc._commit(repo, "B: a file outside the order's paths")
        commits["B"] = _rev(repo, "HEAD")
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "C: the work")
    commits["C"] = _rev(repo, "HEAD")
    dc._run(repo, keys.signer, UNIT)
    (repo / ".git" / "shallow").write_bytes(b"")
    return repo, commits


def _cut_at(tmp_path: pathlib.Path, commit: str, name: str = "cut") -> pathlib.Path:
    path = tmp_path / name
    path.write_bytes(commit.encode("ascii") + b"\n")
    return path


def _done_check(env: dict, repo: pathlib.Path) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, "-I", str(dc.GATE), "done-check", "--repo", str(repo)], capture_output=True,
                          text=True, env=env, timeout=180, check=False)
    return proc.returncode, json.loads(proc.stdout)


def test_git_cuts_the_history_where_the_variable_says(env, tmp_path, keys):
    """Non-vacuous: with the variable git says shallow, shows B without its parent and names the empty file as the
    shallow file; the commit object of B still names A."""
    repo, commits = _history(tmp_path, keys)
    cut = _cut_at(tmp_path, commits["B"])
    with_var = dict(env, GIT_SHALLOW_FILE=str(cut))
    run = lambda *args: subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,  # noqa: E731
                                       env=with_var, timeout=60, check=False).stdout.strip()
    assert run("rev-parse", "--is-shallow-repository") == "true"
    assert run("rev-list", "--parents", "-n", "1", commits["B"]) == commits["B"]
    assert pathlib.Path(run("rev-parse", "--path-format=absolute", "--git-path", "shallow")).read_bytes() == b""
    assert f"parent {commits['A']}" in run("cat-file", "commit", commits["B"])
    without = subprocess.run(["git", "-C", str(repo), "rev-list", "--parents", "-n", "1", commits["B"]],
                             capture_output=True, text=True, env=env, timeout=60).stdout.split()
    assert without == [commits["B"], commits["A"]]   # without the variable git shows B's parent


def test_the_done_check_does_not_pass_on_a_history_cut_by_another_shallow_file(env, tmp_path, keys):
    repo, commits = _history(tmp_path, keys)
    code, report = _done_check(dict(env, GIT_SHALLOW_FILE=str(_cut_at(tmp_path, commits["B"]))), repo)
    assert code != 0 and report["verdict"] == "deny", report
    assert report["reason_id"] == "order_base_not_measured", report
    assert commits["B"][:12] in report["message"], report


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_stop_hook_blocks_on_a_history_cut_by_another_shallow_file(env, tmp_path, keys, host):
    repo, commits = _history(tmp_path, keys)
    answer = f6.stop(dict(env, GIT_SHALLOW_FILE=str(_cut_at(tmp_path, commits["B"]))), repo, host)
    assert answer is not None and answer.get("decision") == "block", answer
    assert "shallow" in answer["reason"] and commits["B"][:12] in answer["reason"], answer


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_without_the_variable_the_work_outside_the_paths_blocks(env, tmp_path, keys, host):
    repo, _commits = _history(tmp_path, keys)
    code, report = _done_check(env, repo)
    assert (code, report["reason_id"]) == (1, "outside_paths"), report
    answer = f6.stop(env, repo, host)
    assert answer is not None and answer.get("decision") == "block" and "outside paths" in answer["reason"], answer


@pytest.mark.parametrize("value", ["empty_file", ""])
def test_control_a_variable_that_cuts_nothing_reads_the_full_history(env, tmp_path, keys, value):
    """An empty shallow file, or an empty value (git reads it as not shallow), leaves git's history whole: the gate
    finds A as the base, as without the variable."""
    repo, _commits = _history(tmp_path, keys)
    target = ""
    if value == "empty_file":
        target = str(tmp_path / "empty")
        pathlib.Path(target).write_bytes(b"")
    code, report = _done_check(dict(env, GIT_SHALLOW_FILE=target), repo)
    assert (code, report["reason_id"]) == (1, "outside_paths"), report


def test_control_a_cut_below_the_commit_that_declared_the_order_still_lets_the_check_pass(env, tmp_path, keys):
    """The cut at P, the parent of A: git still shows A's parent, the order's base is A, the work is inside src/*."""
    repo, commits = _history(tmp_path, keys, outside=False)
    code, report = _done_check(dict(env, GIT_SHALLOW_FILE=str(_cut_at(tmp_path, commits["P"]))), repo)
    assert (code, report["verdict"], report["reason_id"]) == (0, "pass", "done"), report
