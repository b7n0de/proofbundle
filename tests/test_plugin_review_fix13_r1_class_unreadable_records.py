"""Review round 13 of 2026-10-13, the class of R13-1: a record beside git's ref listing that the gate cannot read whole.

Found by the mutation probe of FIX-13 at 0322b28b with git 2.43.0: three mutants of _refs_beside_the_listing survived the
catch cases of the class, one accepting a symbolic entry whose target git does not list, one accepting an empty root ref,
one passing over a line that names no object. Each case below is a repository that declares nothing, with one such
record; the property is that of R13-1 (contract D5, condition d: a broken or unresolvable record is no empty state), so
the exception does not apply and the ask names the record. Red against 2d40ffea, where none of these records was read.
An empty FETCH_HEAD, which a fetch that brings nothing writes, holds no record and keeps the exception.
"""
from __future__ import annotations

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

NOT_RESOLVED = "is present, but git does not resolve it"


def test_a_root_ref_that_is_a_symbolic_ref_without_a_target(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD").write_text("ref: refs/heads/missing\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref ORIG_HEAD {NOT_RESOLVED}")


def test_another_worktree_on_a_branch_that_does_not_exist_yet(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "worktree", "add", "-q", "--orphan", "-b", "fresh", str(tmp_path / "fresh"))
    assert (work / ".git" / "worktrees" / "fresh" / "HEAD").read_text(encoding="utf-8") == "ref: refs/heads/fresh\n"
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref worktrees/fresh/HEAD {NOT_RESOLVED}")


def test_an_empty_root_ref(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD").write_bytes(b"")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, "the local ref ORIG_HEAD names nothing the gate can read")


def test_a_root_ref_with_a_line_that_names_no_object(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD").write_text("garbage\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, "the local ref ORIG_HEAD holds a line the gate cannot read")


def test_control_an_empty_fetch_head_keeps_the_exception(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "FETCH_HEAD").write_bytes(b"")
    w1._assert_inactive(*w1._l1(env, work))
