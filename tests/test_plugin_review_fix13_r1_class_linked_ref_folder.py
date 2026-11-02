"""Review round 13 of 2026-10-13, the class of R13-1: a folder under refs/ that is a symbolic link.

Measured here at 456af3de with git 2.43.0, in the class search of R13-1: git follows a folder under refs/ that is a
symbolic link (`git for-each-ref` listed refs/linked/real from it) and leaves out a symbolic ref there whose target does
not exist, with exit 0 and no warning, as in R13-1; the ref store's listing of the gate (_stored_ref_names) did not follow
the link, so that ref was in neither list, and Level 1 for `git push origin main` was inactive/nothing_declared_locally.
The same for a folder of another worktree's own refs.

Property (contract D5, condition d, as R13-1): where the gate cannot tell every present ref, the exception does not apply.
A folder of the refs, in the common directory or of another worktree, that is a symbolic link leaves it unapplied. Red
against 456af3de.
"""
from __future__ import annotations

import os
import subprocess

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

LINKED = "a folder of the repository's refs is a symbolic link, which git follows and the gate does not"


def _linked_folder(tmp_path, at, oid):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real").write_text(f"{oid}\n", encoding="utf-8")
    (outside / "dangling").write_text("ref: refs/heads/missing\n", encoding="utf-8")
    os.symlink(outside, at)


def test_a_linked_folder_under_refs_with_a_symbolic_ref_without_a_target(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    _linked_folder(tmp_path, work / ".git" / "refs" / "linked", a)
    listing = subprocess.run(["git", "-C", str(work), "for-each-ref", "--format=%(refname)"], capture_output=True,
                             text=True, check=False)
    assert (listing.returncode, listing.stderr) == (0, ""), listing
    assert "refs/linked/real" in listing.stdout.split() and "refs/linked/dangling" not in listing.stdout, listing
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, LINKED)


def test_a_linked_folder_of_another_worktrees_own_refs(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "worktree", "add", "-q", "--detach", str(tmp_path / "other"), a)
    own = work / ".git" / "worktrees" / "other" / "refs"
    own.mkdir(exist_ok=True)       # git 2.51.1 writes it on `git worktree add`, git 2.43.0 does not (R14-2)
    _linked_folder(tmp_path, own / "bisect", a)
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")
