"""D107, follow-up note 33, point 5: a file of the hook folder counts as a hook only by a name git runs and when executable.

The order: only a file with exactly the name of a hook git runs, and with the right to execute, counts as a hook. Red
with `pre-push.vor-ruff-<date>`, green after, a counter case with a real `pre-push`. Found on account A (1518Z): a backup
`pre-push.vor-ruff-20260919` in the hook folder let fetch, `worktree add` and push ask despite https; git never runs it.

Measured with git 2.43.0 (truth_hook_names_n33.sh: commit and fetch, a hook that writes a marker): git ran pre-commit,
post-commit and reference-transaction by their name when executable and through a symbolic link to an executable file;
not when not executable, and never under a name with a suffix (.vor-ruff-20260919, .local, .bak). B36-3 had settled the
names for the read forms (D78); D107 settles them for every count of _hook_problem: the state check of `git add` and
`git commit -m` (D3), `git worktree add` (D40), the fetch profile (D45) and merge-tree (D91).

RED at 63b88d07: the fetch and the commit with a backup, a file that is not executable or a folder of a hook name. The
counter cases (a real hook, a link whatever it points to, a name in another letter case) ask at both.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for key in [k for k in os.environ if k.lower().endswith("_proxy")]:
        monkeypatch.delenv(key)
    r = d71._repo(tmp_path)
    d71._git(r, "update-ref", "refs/remotes/origin/main", "main")
    for sample in (r / ".git" / "hooks").glob("*.sample"):
        sample.unlink()
    (r / "n.txt").write_text("n\n")
    return r


def _hook(repo, name, body="#!/bin/sh\nexit 0\n", mode=0o755):
    path = repo / ".git" / "hooks" / name
    path.write_text(body)
    path.chmod(mode)
    return path


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _decide(repo, form):
    return gate.decide(form.replace("{R}", str(repo)), str(repo), time.monotonic() + 60, "claude")


FETCH = "git -C {R} fetch origin"
COMMIT = "git -C {R} add n.txt"


@pytest.mark.parametrize("name", ["pre-push.vor-ruff-20260919", "reference-transaction.vor-ruff-20260919",
                                  "reference-transaction.local", "pre-auto-gc.bak", "reference-transaction~"])
def test_D107_a_file_git_never_runs_by_its_name_leaves_the_fetch_free(repo, name):
    _hook(repo, name)
    out = _decide(repo, FETCH)
    assert out is not None and out.decision == "pass" and "free_after_fetch_profile" in _ids(out), (name, _ids(out))


def test_D107_a_hook_that_is_not_executable_leaves_the_fetch_free(repo):
    _hook(repo, "reference-transaction", mode=0o644)
    out = _decide(repo, FETCH)
    assert out is not None and out.decision == "pass", _ids(out)


@pytest.mark.parametrize("name", ["pre-commit.local", "post-index-change.vor-ruff-20260919", "commit-msg.bak"])
def test_D107_a_file_git_never_runs_leaves_git_add_free(repo, name):
    _hook(repo, name)
    out = _decide(repo, COMMIT)
    assert out is not None and out.decision == "pass", (name, _ids(out))


def test_D107_counter_an_executable_hook_the_fetch_runs_keeps_the_ask(repo):
    _hook(repo, "reference-transaction")
    out = _decide(repo, FETCH)
    assert out is not None and out.decision == "ask" and "remote_read_not_modeled" in _ids(out), _ids(out)


def test_D107_counter_a_link_to_an_executable_file_is_a_hook(repo, tmp_path):
    target = tmp_path / "hook-target"
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)
    os.symlink(target, repo / ".git" / "hooks" / "reference-transaction")
    out = _decide(repo, FETCH)
    assert out is not None and out.decision == "ask", _ids(out)


@pytest.mark.parametrize("how", ["link to a file without the right to execute", "dangling link", "letter case"])
def test_D107_counter_a_link_counts_whatever_it_points_to_and_the_case_frees_no_name(repo, tmp_path, how):
    target = tmp_path / "hook-target"
    if how == "link to a file without the right to execute":
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o644)
    if how == "letter case":
        _hook(repo, "Reference-Transaction")
    else:
        os.symlink(target, repo / ".git" / "hooks" / "reference-transaction")
    out = _decide(repo, FETCH)
    assert out is not None and out.decision == "ask", (how, _ids(out))
    assert _decide(repo, COMMIT).decision == "ask", how


def test_D107_a_folder_of_a_hook_name_is_no_hook(repo):
    (repo / ".git" / "hooks" / "pre-commit").mkdir()
    out = _decide(repo, COMMIT)
    assert out is not None and out.decision == "pass", _ids(out)


def test_D107_counter_a_real_pre_commit_keeps_git_add_from_being_free(repo):
    _hook(repo, "pre-commit")
    out = _decide(repo, COMMIT)
    assert out is not None and out.decision == "ask", _ids(out)


def test_D107_counter_the_fallbook_case_with_a_real_pre_push_the_fetch_does_not_run(repo):
    _hook(repo, "pre-push")
    out = _decide(repo, FETCH)
    assert out is not None and out.decision == "pass", "a fetch never runs pre-push (measured in D45)"


def test_D107_the_hook_names_are_the_documented_ones():
    assert "pre-push" in gate._GIT_HOOK_NAMES and "pre-push.vor-ruff-20260919" not in gate._GIT_HOOK_NAMES
    assert gate._HOOKS_NOT_RUN_BY_FETCH < gate._GIT_HOOK_NAMES
