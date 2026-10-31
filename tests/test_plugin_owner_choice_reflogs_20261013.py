"""Owner choice of 2026-10-13, 14:0x Berlin, on the reviewer's recommendation of review round 14: where the records of
condition d end (DECISIONS.md D5).

The current refs/stash is a present ref and is read. Older stash entries and reflogs in general are no condition of the
exception and are not read: a reflog can be missing, expire or be deleted, and it proves no complete history. A state
chosen as the source of a push, an older stash entry as well, goes through the normal resolution of sources, so its whole
history is read. A leftover lock file or a name git skips under refs/ leaves the exception unapplied and is named; the gate
cleans up nothing. Measured at ae654d59 with git 2.43.0: as these tests say; the boundary was inactive in review fix 13 too.
"""
from __future__ import annotations

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate


def _stashed_declaration_below_the_top(work):
    """stash@{1} holds a declaration, stash@{0} and the working tree do not; returns the commit of stash@{1}."""
    (work / ".proofbundle").mkdir()
    (work / gate.DECLARATION).write_text(w1.EMPTY_LIST, encoding="utf-8")
    w1._git(work, "add", ".proofbundle")
    w1._git(work, "stash", "push", "-q")
    (work / "a.txt").write_text("changed\n", encoding="utf-8")
    w1._git(work, "stash", "push", "-q")
    assert not (work / ".proofbundle").exists()
    return w1.n2c._rev(work, "stash@{1}")


def test_an_older_stash_entry_is_not_read(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    _stashed_declaration_below_the_top(work)
    w1._assert_inactive(*w1._l1(env, work))


def test_the_current_stash_is_a_present_ref(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".proofbundle").mkdir()
    (work / gate.DECLARATION).write_text(w1.EMPTY_LIST, encoding="utf-8")
    w1._git(work, "add", ".proofbundle")
    w1._git(work, "stash", "push", "-q")
    stash = w1.n2c._rev(work, "refs/stash")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/stash holds something at {gate.DECLARATION} "
                                                      f"or in place of its folder at {stash[:12]}")


@pytest.mark.parametrize("spelling", ["object", "'stash@{1}'"])
def test_an_older_stash_entry_chosen_as_the_source_is_resolved_as_a_source(env, tmp_path, spelling):
    work, _remote, _a = w1._undeclared(tmp_path)
    older = _stashed_declaration_below_the_top(work)
    source = older if spelling == "object" else spelling
    answer, entry, text = w1._l1(env, work, f"git push origin {source}:refs/heads/from-stash")
    w1._assert_exception_refused(answer, entry, text, f"something stands at {gate.DECLARATION} or in place of its "
                                                      f"folder at {older[:12]}, a commit the push may send")


@pytest.mark.parametrize("name", ["refs/heads/main.lock", "refs/heads/.hidden"])
def test_a_leftover_lock_file_or_a_name_git_skips_is_named(env, tmp_path, name):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / name).write_text(f"{a}\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref {name} is present, but git does not resolve it")
    assert (work / ".git" / name).read_text(encoding="utf-8") == f"{a}\n"     # nothing cleaned up
