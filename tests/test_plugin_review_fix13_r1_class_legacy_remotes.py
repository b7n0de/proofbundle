"""Review round 13 of 2026-10-13, the class of R13-1: a remote that `git remote` does not list, taken from git's older
remote files.

Measured here at 0ece16ad with git 2.43.0, in the class search of R13-1 (every place that concludes the whole stock from
an output of git): a repository that declares nothing; a branch other whose history holds a declared commit and whose tip
does not; a file .git/remotes/legacy with `URL: <path of the remote>` and `Push: refs/heads/other:refs/heads/other`.
`git remote` listed origin only. Level 1 for `git push legacy` was inactive/nothing_declared_locally and named the history
of HEAD as the commits the push may send; the push run apart sent other, and the remote then held the declared commit.

Property (owner choice 1, conditions a and c; contract D5): where git takes the remote from .git/remotes/<name> or
.git/branches/<name> (a name without `/` whose URL the configuration does not give), the refs and URLs of that file decide
the push, which the gate does not read; a push with no refspec is not resolved, and the exception does not apply to any
push to that remote. Red against 0ece16ad.
"""
from __future__ import annotations

import subprocess

import test_plugin_owner_choice1_undeclared_push as w1
import test_plugin_owner_choice1_ask_names_the_record_20261013 as a1
import test_plugin_review_fix12_r1_present_refs as p1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

UNDETERMINED = "the commits the push sends are not all determined"
OLDER_FILES = "git takes the remote legacy from its older remote files (.git/remotes/ or .git/branches/)"


def _other_with_a_declared_past(work, a):
    """refs/heads/other: the declared commit on top of A, then A's tree again on top of it; returns (declared, tip)."""
    declared = a1._declared_on_top(work, a)
    tree = w1._git(work, "rev-parse", f"{a}^{{tree}}").stdout.strip()
    tip = w1._git(work, "commit-tree", tree, "-p", declared, "-m", "clean again").stdout.strip()
    w1._git(work, "update-ref", "refs/heads/other", tip)
    return declared, tip


def _remotes_file(work, name, text):
    folder = work / ".git" / "remotes"
    folder.mkdir(exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


def test_the_measured_case_a_push_line_in_a_remotes_file(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    declared, tip = _other_with_a_declared_past(work, a)
    _remotes_file(work, "legacy", f"URL: {remote}\nPush: refs/heads/other:refs/heads/other\n")
    assert w1._git(work, "remote").stdout.split() == ["origin"]
    answer, entry, text = w1._l1(env, work, "git push legacy")
    w1._assert_exception_refused(answer, entry, text, UNDETERMINED)
    # non-vacuous: the push run apart sends other, and the remote then holds the declared commit
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", "legacy"], capture_output=True,
                          text=True, check=False)
    assert push.returncode == 0 and p1._remote_rev(remote, "refs/heads/other") == tip, push.stderr
    assert p1._remote_rev(remote, "refs/heads/main") == a
    assert subprocess.run(["git", "--git-dir", str(remote), "cat-file", "-e", declared], check=False).returncode == 0


def test_a_push_with_a_refspec_to_a_remote_of_a_remotes_file(env, tmp_path):
    """Two URL lines: git pushes to both, and the records, if any, come from the first."""
    work, remote, _a = w1._undeclared(tmp_path)
    second = tmp_path / "second.git"
    subprocess.run(["git", "init", "-q", "--bare", str(second)], check=True)
    _remotes_file(work, "legacy", f"URL: {remote}\nURL: {second}\n")
    answer, entry, text = w1._l1(env, work, "git push legacy main")
    w1._assert_exception_refused(answer, entry, text, OLDER_FILES)
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", "legacy", "main"], capture_output=True,
                          text=True, check=False)
    assert push.returncode == 0 and p1._remote_rev(second, "refs/heads/main") != "", push.stderr


def test_a_branches_file_pushes_head_to_the_branch_it_names(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "branches").mkdir(exist_ok=True)
    (work / ".git" / "branches" / "legacy").write_text(f"{remote}#other\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work, "git push legacy")
    w1._assert_exception_refused(answer, entry, text, UNDETERMINED)
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", "legacy"], capture_output=True,
                          text=True, check=False)
    head = w1.n2c._rev(work, "HEAD")
    assert push.returncode == 0 and p1._remote_rev(remote, "refs/heads/other") == head, push.stderr
    assert p1._remote_rev(remote, "refs/heads/main") == a


def test_control_a_configured_url_takes_precedence_over_a_remotes_file(env, tmp_path):
    work, remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "add", "legacy", str(remote))
    _remotes_file(work, "legacy", f"URL: {tmp_path / 'nowhere.git'}\nPush: refs/heads/other:refs/heads/other\n")
    w1._assert_inactive(*w1._l1(env, work, "git push legacy main"))
