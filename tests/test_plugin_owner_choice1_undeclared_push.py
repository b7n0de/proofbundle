"""Owner choice 1 A of 2026-10-11 (D5 C of 2026-09-30): a repository without a declaration stays outside Level 1.

This is local inactivity, never a pass and never a check presumed at Level 2. The host's normal approval decides (the
answer carries no permission decision), the push's destination stays NOT MEASURED, and the answer begins with NOT
MEASURED and says that the gate checks nothing here. Four conditions, each part of the choice:
a. the repository, the work tree, the git environment and every source are determined; no unresolved source is
   replaced by HEAD; added ref updates, wrappers and submodule pushes are not exempted; the hook-bypass deny stays;
b. the absence is established at HEAD, in the actual working tree and at every commit the push may send: an empty,
   broken or done-only declaration, a folder or a link is no absence;
c. those commits are the whole history of every source, with no tracking ref subtracted; shallow, unreadable or too
   long a history is asked. The review's case, measured with git 2.43.0 and 2.51.1: A without a declaration, B with,
   C without; HEAD and the tracking ref at C, the remote reset to A. The range against the tracking ref is empty,
   while git sends C and B;
d. every local record of a ref the push may write is read with its commit, all recorded candidates where the choice is
   unclear; a declaration there blocks the exception, an unreadable record is no empty state, a missing record says
   nothing about the remote.
Where the exception does not apply in a repository whose HEAD declares nothing, the answer says why. Red against
a7207266, where every such push was asked as NOT MEASURED at the destination and the answer named no exception.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
gate = n2c.gate

HEAD_TEXT = "NOT MEASURED: the gate checks nothing here."
EXCEPTION = "The gate's exception for a repository without a declaration (owner choice 1 A of 2026-10-11"
EMPTY_LIST = json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": []})


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return n2c._git(repo, *args)


def _commit(repo: pathlib.Path, name: str, content: str = "x\n") -> str:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", name)
    return n2c._rev(repo, "HEAD")


def _undeclared(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str]:
    """A repository that never declared anything: A on the remote and in origin/main, a new commit C on main."""
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    a = _commit(work, "a.txt")
    _git(work, "remote", "add", "origin", str(remote))
    _git(work, "push", "-q", "--no-verify", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    _commit(work, "c.txt")
    return work, remote, a


def _l1(env: dict, work: pathlib.Path, command: str = "git push origin main") -> tuple[dict, dict, str]:
    answer, entry = n2c._level1(env, work, command=command)
    return answer, entry, answer["systemMessage"]


def _assert_inactive(answer: dict, entry: dict, text: str) -> None:
    assert "permissionDecision" not in answer["hookSpecificOutput"], answer
    assert (entry["verdict"], entry["reason_ids"]) == ("inactive", ["nothing_declared_locally"]), entry
    assert text.startswith(HEAD_TEXT), text
    assert "The gate is not active in this repository, because nothing is declared." in text, text
    assert "This is local inactivity (owner choice 1 A" in text and "not a check and not a pass" in text, text
    assert "the host's normal approval decides" in text, text
    assert "remain NOT MEASURED" in text, text


def _assert_exception_refused(answer: dict, entry: dict, text: str, why: str) -> None:
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert entry["verdict"] == "ask" and entry["reason_ids"] == ["push_not_measured"], entry
    assert EXCEPTION in text and why in text, text


# --- the exception -----------------------------------------------------------------------------------------------

def test_a_push_from_an_undeclared_repository_is_locally_inactive(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry, text = _l1(env, work)
    _assert_inactive(answer, entry, text)
    assert "refs/remotes/origin/main at " in text, text


def test_a_push_to_a_new_branch_without_any_record_is_locally_inactive(env, tmp_path):
    """d: a missing record says nothing about the remote, and blocks nothing."""
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry, text = _l1(env, work, "git push origin main:fresh")
    _assert_inactive(answer, entry, text)
    assert "no local record of its destination was found, which says nothing about the remote" in text, text


def test_a_pure_deletion_with_a_clean_record_is_locally_inactive(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "push", "-q", "--no-verify", "origin", "main:old")
    _git(work, "fetch", "-q", "origin")
    answer, entry, text = _l1(env, work, "git push origin :old")
    _assert_inactive(answer, entry, text)


def test_the_codex_answer_is_unchanged(env, tmp_path):
    """Under Codex the hook cannot bind the push to its directory (R5-2), so condition a never holds there."""
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry = n2c._level1(env, work, host="codex")
    assert entry["reason_ids"] == ["codex_context_unbound"], entry


# --- a: determined sources, no added updates, no wrapper, no recursion ---------------------------------------------

def test_a_an_ambiguous_source_is_not_exempted(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "tag", "main")
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, "the commits the push sends are not all determined")


@pytest.mark.parametrize("key, value", [("push.followTags", "true"), ("remote.origin.push", "refs/heads/main"),
                                        ("remote.origin.mirror", "true")])
def test_a_configured_added_updates_are_not_exempted(env, tmp_path, key, value):
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "config", key, value)
    answer, entry, text = _l1(env, work, "git push origin main:main")
    _assert_exception_refused(answer, entry, text, "the configuration adds ref updates the command does not name")


def test_a_a_configured_submodule_push_is_not_exempted(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "config", "push.recurseSubmodules", "on-demand")
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, "push.recurseSubmodules=on-demand")


@pytest.mark.parametrize("command", ["git push --recurse-submodules=on-demand origin main",
                                     "git push --follow-tags origin main", "git push --all origin"])
def test_a_an_option_that_adds_updates_or_recursion_is_not_exempted(env, tmp_path, command):
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry, text = _l1(env, work, command)
    _assert_exception_refused(answer, entry, text, "the commits the push sends are not all determined")


def test_a_a_detached_head_bare_push_is_not_replaced_by_head(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "checkout", "-q", "--detach")
    answer, entry, text = _l1(env, work, "git push origin")
    _assert_exception_refused(answer, entry, text, "the commits the push sends are not all determined")


def test_a_a_gh_call_is_not_exempted(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry, text = _l1(env, work, "gh pr create --fill")
    _assert_exception_refused(answer, entry, text, "a gh call sends through steps of its own")


@pytest.mark.parametrize("command", ["env git push origin main", "sh -c 'git push origin main'"])
def test_a_a_wrapper_is_not_exempted(env, tmp_path, command):
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry, _text = _l1(env, work, command)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert entry["verdict"] == "ask" and "nothing_declared_locally" not in entry["reason_ids"], entry


def test_a_the_hook_bypass_deny_stays(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    answer, entry, _text = _l1(env, work, "git push --no-verify origin main")
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    assert entry["reason_ids"] == ["hooks_disabled"], entry


# --- b: absence at HEAD, in the working tree and at every commit the push may send ---------------------------------

@pytest.mark.parametrize("content", ["", "{", EMPTY_LIST])
def test_b_a_declaration_only_in_the_working_tree_blocks_the_exception(env, tmp_path, content):
    work, _remote, _a = _undeclared(tmp_path)
    (work / ".proofbundle").mkdir()
    (work / gate.DECLARATION).write_text(content, encoding="utf-8")
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, "the working tree holds something at")


@pytest.mark.parametrize("shape", ["folder-at-declaration", "link-for-folder", "dangling-link-for-folder",
                                   "file-for-folder"])
def test_b_a_folder_or_a_link_in_the_working_tree_is_no_absence(env, tmp_path, shape):
    work, _remote, _a = _undeclared(tmp_path)
    if shape == "folder-at-declaration":
        (work / gate.DECLARATION).mkdir(parents=True)
    elif shape == "link-for-folder":
        (tmp_path / "elsewhere").mkdir()
        os.symlink(tmp_path / "elsewhere", work / ".proofbundle")
    elif shape == "dangling-link-for-folder":
        os.symlink(tmp_path / "nowhere", work / ".proofbundle")
    else:
        (work / ".proofbundle").write_text("x", encoding="utf-8")
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, "the working tree holds something at")


def test_b_a_declaration_at_a_sent_tip_blocks_the_exception(env, tmp_path):
    """An empty evidence list at the tip of the pushed branch: no deny at the source, and still no absence there."""
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "checkout", "-q", "-b", "feature")
    tip = _commit(work, gate.DECLARATION, EMPTY_LIST)
    _git(work, "checkout", "-q", "main")
    answer, entry, text = _l1(env, work, "git push origin feature")
    _assert_exception_refused(answer, entry, text, f"in place of its folder at {tip[:12]}, a commit the push may send")


def test_b_a_link_in_place_of_the_folder_at_a_sent_commit_is_no_absence(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    os.symlink("elsewhere", work / ".proofbundle")
    linked = _commit(work, "b.txt")
    (work / ".proofbundle").unlink()
    _commit(work, "d.txt")
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, f"in place of its folder at {linked[:12]}")


def test_b_a_declaration_at_head_keeps_the_gate_active_and_names_no_exception(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    _git(work, "checkout", "-q", "-b", "clean")
    _git(work, "checkout", "-q", "main")
    _commit(work, gate.DECLARATION, EMPTY_LIST)
    answer, entry, text = _l1(env, work, "git push origin clean")
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert EXCEPTION not in text, text


# --- c: the whole history of every source, read whole --------------------------------------------------------------

def _history_case(tmp_path: pathlib.Path, declare_b: bool) -> tuple[pathlib.Path, pathlib.Path, str, str, str]:
    """The review's case: A without a declaration, B with one (or without), C without; C pushed and fetched, so HEAD
    and the tracking ref are at C; then the remote is reset to A."""
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    _git(work, "remote", "add", "origin", str(remote))
    a = _commit(work, "a.txt")
    b = _commit(work, gate.DECLARATION, EMPTY_LIST) if declare_b else _commit(work, "b.txt")
    if declare_b:
        _git(work, "rm", "-q", "-r", ".proofbundle")
        _git(work, "commit", "-q", "-m", "C")
        c = n2c._rev(work, "HEAD")
    else:
        c = _commit(work, "c.txt")
    _git(work, "push", "-q", "--no-verify", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    subprocess.run(["git", "--git-dir", str(remote), "update-ref", "refs/heads/main", a], check=True)
    return work, remote, a, b, c


def test_c_the_reviewers_history_case_is_not_exempted(env, tmp_path):
    work, _remote, a, b, c = _history_case(tmp_path, declare_b=True)
    # non-vacuous: against the tracking ref the range is empty, while git sends C and B to the remote at A
    assert _git(work, "rev-list", "HEAD", "--not", "refs/remotes/origin/main").stdout.split() == []
    assert _git(work, "rev-list", c, "--not", a).stdout.split() == [c, b]
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, f"in place of its folder at {b[:12]}, a commit the push may send")


def test_c_control_the_same_history_without_a_declaration_is_locally_inactive(env, tmp_path):
    work, _remote, _a, _b, _c = _history_case(tmp_path, declare_b=False)
    answer, entry, text = _l1(env, work)
    _assert_inactive(answer, entry, text)
    assert "at the 3 commit(s) the push may send" in text, text


def test_c_a_long_removed_declaration_in_the_source_history_still_blocks(env, tmp_path):
    """The price in the other direction (D5, D20): a declaration removed long ago keeps blocking the exception."""
    work, _remote, _a = _undeclared(tmp_path)
    old = _commit(work, gate.DECLARATION, EMPTY_LIST)
    _git(work, "rm", "-q", "-r", ".proofbundle")
    _git(work, "commit", "-q", "-m", "removed")
    for n in range(5):
        _commit(work, f"later{n}.txt")
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, f"at {old[:12]}, a commit the push may send")


def test_c_a_shallow_repository_is_not_exempted(env, tmp_path):
    work, remote, _a = _undeclared(tmp_path)
    _git(work, "push", "-q", "--no-verify", "origin", "main")
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{remote}", str(shallow)], check=True)
    _commit(shallow, "s.txt")
    answer, entry, text = _l1(env, shallow)
    _assert_exception_refused(answer, entry, text, "the repository is shallow")


def test_c_a_history_git_does_not_give_whole_is_not_exempted(env, tmp_path):
    work, _remote, _a = _undeclared(tmp_path)
    middle = _commit(work, "m.txt")
    _commit(work, "n.txt")
    tree = n2c._rev(work, f"{middle}^{{tree}}")
    (work / ".git" / "objects" / tree[:2] / tree[2:]).unlink()   # loose objects only: nothing was packed
    answer, entry, text = _l1(env, work)
    _assert_exception_refused(answer, entry, text, f"git does not give the whole tree of {middle[:12]}")


def test_c_too_long_a_history_is_not_exempted(tmp_path, monkeypatch):
    work, _remote, _a = _undeclared(tmp_path)
    monkeypatch.setattr(gate, "MAX_HISTORY_COMMITS", 1)
    verdict = gate.evaluate_push(str(work), ["origin", "main"], time.monotonic() + 60)
    assert verdict.decision == "ask", verdict.detail
    assert "holds more than 1 commits, more than the gate reads" in verdict.detail, verdict.detail


# --- d: the local records of every ref the push may write -----------------------------------------------------------

def _record_with_declaration(work: pathlib.Path, remote: pathlib.Path, branch: str) -> str:
    """A commit with a declaration that only the remote and its local record hold, at `branch` of the remote."""
    other = work.parent / "other"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)], check=True)
    _git(other, "checkout", "-q", "--orphan", "declared")
    _git(other, "rm", "-q", "-r", "--cached", ".")
    for path in other.iterdir():
        if path.name != ".git":
            path.unlink()
    declared = _commit(other, gate.DECLARATION, EMPTY_LIST)
    _git(other, "push", "-q", "--no-verify", "origin", f"declared:{branch}")
    _git(work, "fetch", "-q", "--no-tags", "origin")
    return declared


def test_d_a_record_of_the_destination_with_a_declaration_blocks_the_exception(env, tmp_path):
    work, remote, _a = _undeclared(tmp_path)
    declared = _record_with_declaration(work, remote, "release")
    answer, entry, text = _l1(env, work, "git push origin main:release")
    _assert_exception_refused(answer, entry, text,
                              f"the local ref refs/remotes/origin/release holds something at "
                              f"{gate.DECLARATION} or in place of its folder at {declared[:12]}")


def test_d_a_recorded_candidate_with_a_declaration_blocks_the_exception(env, tmp_path):
    """The choice is unclear: git push may also write refs/remotes/refs/heads/main for `refs/heads/main`, and this
    repository records that candidate under refs/recorded/ (the fixture of R10-3)."""
    work, remote, _a = _undeclared(tmp_path)
    declared = _record_with_declaration(work, remote, "staging")
    subprocess.run(["git", "--git-dir", str(remote), "update-ref", "refs/remotes/refs/heads/main", declared], check=True)
    _git(work, "config", "--add", "remote.origin.fetch", "+refs/remotes/*:refs/recorded/origin/remotes/*")
    _git(work, "fetch", "-q", "--no-tags", "origin")
    answer, entry, text = _l1(env, work, "git push origin HEAD:refs/heads/main")
    _assert_exception_refused(answer, entry, text,
                              "the local ref refs/recorded/origin/remotes/refs/heads/main holds something at")


@pytest.mark.parametrize("content", ["1" * 40 + "\n", "garbage\n"], ids=["dangling", "broken"])
def test_d_an_unreadable_record_is_no_empty_state(env, tmp_path, content):
    work, _remote, _a = _undeclared(tmp_path)
    (work / ".git" / "refs" / "remotes" / "origin").mkdir(parents=True, exist_ok=True)
    (work / ".git" / "refs" / "remotes" / "origin" / "release").write_text(content, encoding="utf-8")
    answer, entry, text = _l1(env, work, "git push origin main:release")
    _assert_exception_refused(answer, entry, text, "the local ref refs/remotes/origin/release, which may record the "
                                                   "ref this push writes")


def test_d_a_deletion_whose_record_holds_a_declaration_is_not_exempted(env, tmp_path):
    work, remote, _a = _undeclared(tmp_path)
    _record_with_declaration(work, remote, "old")
    answer, entry, text = _l1(env, work, "git push origin :old")
    _assert_exception_refused(answer, entry, text, "the local ref refs/remotes/origin/old holds something at")


# --- the price, named in D5 and D20 ----------------------------------------------------------------------------------

def _section(text: str, start: str, end: str) -> str:
    return " ".join(text[text.index(start):text.index(end)].split())


def test_d5_and_d20_name_the_price_of_owner_choice_1():
    decisions = (pathlib.Path(gate.__file__).resolve().parents[1] / "DECISIONS.md").read_text(encoding="utf-8")
    for start, end in (("## D5. ", "## D6. "), ("## D20. ", "## D21. ")):
        section = _section(decisions, start, end)
        assert ("a declaration that only the remote holds, standing neither in the checked source history nor in a "
                "local record, and its removal can go unnoticed at Level 1, above all with a push that only deletes a "
                "ref") in section, start
        assert "a declaration removed long ago from the source history still blocks the exception" in section, start
