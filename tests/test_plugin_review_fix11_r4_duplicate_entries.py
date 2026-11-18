"""Review round 11 of 2026-10-12, R11-4: a tree with two entries of one name is never a whole reading of absence.

Measured by the reviewer at 3bbbf66f: history A without a declaration, B whose raw root tree holds two entries named
.proofbundle, b"40000 .proofbundle\\x00" + the declared subtree + b"40000 .proofbundle\\x00" + the empty tree, written
with `git hash-object --literally -t tree -w --stdin`; B and C (again the clean tree of A) with `git commit-tree`, main at
C; Level 1 for `git push origin main`. `git ls-tree -r B` showed .proofbundle/evidence.json, `git fsck --full` reported
duplicateEntries, the hook claimed absence at all three commits and was inactive, and the real push to a bare repository
with the default configuration exited 0. With only the first entry the push was asked and B named.

Property (conditions b and c of owner choice 1): a malformed or ambiguous tree is never a whole reading of absence.
Duplicate names are found before the entries become a map, and neither the first nor the last entry counts as read; the
same function reads HEAD and the local records of the destination. Red against 0fc7b487.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

EMPTY_TREE_INPUT = b""


def _raw(work: pathlib.Path, kind: str, data: bytes) -> str:
    return subprocess.run(["git", "-C", str(work), "hash-object", "--literally", "-t", kind, "-w", "--stdin"],
                          input=data, capture_output=True, check=True).stdout.decode().strip()


def _commit_tree(work: pathlib.Path, tree: str, parent: str, message: str) -> str:
    return w1._git(work, "commit-tree", tree, "-p", parent, "-m", message).stdout.strip()


def _duplicate_tree(work: pathlib.Path, order: str) -> str:
    """A root tree with two entries named .proofbundle: the declared subtree and the empty tree, in `order`."""
    blob = _raw(work, "blob", w1.EMPTY_LIST.encode())
    declared = _raw(work, "tree", b"100644 evidence.json\x00" + bytes.fromhex(blob))
    empty = _raw(work, "tree", EMPTY_TREE_INPUT)
    entries = [bytes.fromhex(declared), bytes.fromhex(empty)]
    if order == "empty first":
        entries.reverse()
    return _raw(work, "tree", b"".join(b"40000 .proofbundle\x00" + oid for oid in entries))


def _history(tmp_path: pathlib.Path, order: str) -> tuple[pathlib.Path, pathlib.Path, str, str, str]:
    """A on the remote and in origin/main, B with the duplicate root tree, C with the tree of A; main at C."""
    work, remote, a = w1._undeclared(tmp_path)
    b = _commit_tree(work, _duplicate_tree(work, order), a, "B")
    c = _commit_tree(work, w1.n2c._rev(work, f"{a}^{{tree}}"), b, "C")
    w1._git(work, "reset", "-q", "--hard", c)
    return work, remote, a, b, c


@pytest.mark.parametrize("order", ["declared first", "empty first"])
def test_the_reviewers_case_a_duplicate_entry_in_the_sent_history_is_not_exempted(env, tmp_path, order):
    work, _remote, _a, b, _c = _history(tmp_path, order)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"git does not give the whole tree of {b[:12]}")


def test_git_lists_the_declaration_and_pushes_the_malformed_tree(env, tmp_path):
    """Non-vacuous: ls-tree shows the declaration in B, fsck names the duplicate, and the push to a bare repository with
    the default configuration exits 0."""
    work, _remote, _a, b, _c = _history(tmp_path, "declared first")
    assert ".proofbundle/evidence.json" in w1._git(work, "ls-tree", "-r", "--name-only", b).stdout.split("\n")
    fsck = subprocess.run(["git", "-C", str(work), "fsck", "--full"], capture_output=True, text=True, check=False)
    assert "duplicateEntries" in fsck.stdout + fsck.stderr, fsck.stdout + fsck.stderr
    target = tmp_path / "target.git"
    subprocess.run(["git", "init", "-q", "--bare", str(target)], check=True)
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", str(target), "main"],
                          capture_output=True, text=True, check=False)
    assert push.returncode == 0, push.stderr


def test_a_duplicate_entry_at_head_is_no_absence(env, tmp_path):
    work, _remote, _a, b, _c = _history(tmp_path, "declared first")
    w1._git(work, "update-ref", "refs/heads/main", b)
    answer, entry, text = w1._l1(env, work)
    assert entry["verdict"] != "inactive", (entry, text)
    assert answer["hookSpecificOutput"].get("permissionDecision") in ("ask", "deny"), answer


def test_a_duplicate_entry_at_a_local_record_of_the_destination_is_no_empty_state(env, tmp_path):
    work, _remote, _a, b, _c = _history(tmp_path, "declared first")
    w1._git(work, "reset", "-q", "--hard", "refs/remotes/origin/main")
    w1._git(work, "update-ref", "refs/remotes/origin/release", b)
    answer, entry, text = w1._l1(env, work, "git push origin main:release")
    w1._assert_exception_refused(answer, entry, text, f"git does not give the whole tree of {b[:12]}")


def test_control_only_the_declared_entry_is_asked_and_names_b(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    blob = _raw(work, "blob", w1.EMPTY_LIST.encode())
    declared = _raw(work, "tree", b"100644 evidence.json\x00" + bytes.fromhex(blob))
    b = _commit_tree(work, _raw(work, "tree", b"40000 .proofbundle\x00" + bytes.fromhex(declared)), a, "B")
    c = _commit_tree(work, w1.n2c._rev(work, f"{a}^{{tree}}"), b, "C")
    w1._git(work, "reset", "-q", "--hard", c)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"in place of its folder at {b[:12]}, a commit the push may send")
