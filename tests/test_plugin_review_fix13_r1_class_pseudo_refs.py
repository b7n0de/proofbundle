"""Review round 13 of 2026-10-13, the class of R13-1: records git's ref listing does not show at all.

Measured here at 2baf120e with git 2.43.0, in the class search of R13-1 (every place that concludes the whole stock from
an output of git): a repository that declares nothing; the remote's tag release held a declared commit; `git fetch
<path of the remote> refs/tags/release`, a fetch that stores no ref, left that commit only in FETCH_HEAD. Level 1 for
`git push origin :refs/tags/release` was inactive/nothing_declared_locally, and the push run apart deleted the remote tag.
`git for-each-ref` lists no FETCH_HEAD, no ORIG_HEAD and no HEAD of another worktree, so the count of refs read in the
answer left them out.

Property (condition d of owner choice 1, strict as the owner chose it): FETCH_HEAD with each of its lines, the other
root refs of the git directory (ORIG_HEAD, MERGE_HEAD and their kin) and the HEAD and own refs of every other worktree
are present records too, named as git names them (FETCH_HEAD, a later line of it with its number, ORIG_HEAD,
worktrees/<name>/HEAD, main-worktree/refs/bisect/<name>); a declaration at one of them leaves the exception unapplied,
and the ask names it. Red against 2d40ffea.
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


def test_a_declaration_only_in_fetch_head_is_read(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "push", "-q", "--no-verify", "origin", f"+{declared}:refs/tags/release")
    w1._git(work, "fetch", "-q", "--no-tags", str(remote), "refs/tags/release")
    assert (work / ".git" / "FETCH_HEAD").read_text(encoding="utf-8").startswith(declared)
    assert declared not in w1._git(work, "for-each-ref", "--format=%(objectname)").stdout
    answer, entry, text = w1._l1(env, work, "git push origin :refs/tags/release")
    p1._refused_at(answer, entry, text, "FETCH_HEAD", declared, ("house_tag_out",))   # a tag goes out: H2 of D73
    # non-vacuous: the push run apart deletes the remote tag that holds the declaration, exit 0
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", "origin", ":refs/tags/release"],
                          capture_output=True, text=True, check=False)
    assert push.returncode == 0 and p1._remote_rev(remote, "refs/tags/release") == "", push.stderr


def test_a_later_line_of_fetch_head_is_read(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "push", "-q", "--no-verify", "origin", f"+{declared}:refs/tags/release")
    w1._git(work, "fetch", "-q", "--no-tags", str(remote), "refs/heads/main", "refs/tags/release")
    lines = (work / ".git" / "FETCH_HEAD").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and lines[1].startswith(declared), lines
    answer, entry, text = w1._l1(env, work, "git push origin :refs/tags/release")
    p1._refused_at(answer, entry, text, "FETCH_HEAD (line 2)", declared, ("house_tag_out",))   # H2 of D73


def test_orig_head_is_read(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "update-ref", "ORIG_HEAD", declared)
    answer, entry, text = w1._l1(env, work)
    p1._refused_at(answer, entry, text, "ORIG_HEAD", declared)


def test_the_head_of_another_worktree_is_read(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "worktree", "add", "-q", "--detach", str(tmp_path / "other"), declared)
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


def test_control_fetch_head_of_clean_commits_keeps_the_exception(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    assert (work / ".git" / "FETCH_HEAD").is_file()
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(tmp_path / "other"))
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


def test_a_per_worktree_ref_of_the_main_worktree_is_read_from_a_linked_one(env, tmp_path):
    """From a linked worktree the main worktree's HEAD and its per-worktree refs are another worktree's records."""
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "update-ref", "refs/bisect/bad", declared)
    linked = tmp_path / "linked"
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(linked))
    answer, entry, text = w1._l1(env, linked, "git push origin side")
    # Narrow contract of 2026-10-13, 17:0x: a linked worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a linked worktree", str(linked))
