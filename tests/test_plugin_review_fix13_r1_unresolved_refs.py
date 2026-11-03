"""Review round 13 of 2026-10-13, R13-1: a present ref git does not resolve is no record the exception may pass over.

Measured by the reviewer at 2baf120e with git 2.51.1 and 2.43.0: a clean work repository with two commits and no
declaration, a bare remote origin, the remote and its fetch record at the first commit, local main at the second; in the
work repository `git symbolic-ref refs/remotes/origin/main refs/heads/missing` (refs/heads/missing does not exist); the real
Level 1 hook for `git push origin main`. The record exists with the content `ref: refs/heads/missing`, `git for-each-ref`
ends with exit 0 and an empty stderr and leaves it out, the hook logged inactive/nothing_declared_locally with no
permissionDecision, and the text claimed refs read. The same for refs/recorded/x.

Measured here at 2baf120e with git 2.43.0: `git show-ref` and `GIT_REF_PARANOIA=1 git for-each-ref` leave such a ref out
too; only `git fsck` names it; `git pack-refs --all` leaves it loose.

Property (contract D5, condition d: a broken or unresolvable record is no empty state): where the gate cannot tell every
present ref from git's listing, the exception does not apply. Every ref the ref store holds, loose files and packed-refs
alike, is matched against git's listing; one git does not list or calls broken is named in the ask; a ref store in another
format than files (reftable), which the gate cannot read whole, leaves the exception unapplied. Red against 2baf120e.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

NOT_RESOLVED = "is present, but git does not resolve it"
NAMED = re.compile(r"the local ref (\S+) is present, but git does not resolve it")


def _refused_on_the_damaged_chain(answer, entry, text, work: pathlib.Path, damaged: str) -> None:
    """The ask names a record that is present, that git does not resolve and whose chain of symbolic refs runs through
    the damaged ref. Which one of them is named is not fixed: under git 2.51.1 a fetch also writes
    refs/remotes/origin/HEAD, a symbolic ref to refs/remotes/origin/main (review round 14 of 2026-10-13, R14-2)."""
    named = NAMED.search(text)
    assert named is not None, text
    record = named.group(1)
    w1._assert_exception_refused(answer, entry, text, f"the local ref {record} {NOT_RESOLVED}")
    resolved = subprocess.run(["git", "-C", str(work), "rev-parse", "--verify", "--quiet", record],
                              capture_output=True, text=True, check=False)
    assert resolved.returncode != 0 and resolved.stdout == "", resolved
    chain = [record]
    while chain[-1] != damaged and len(chain) <= 5:
        step = subprocess.run(["git", "-C", str(work), "symbolic-ref", "--quiet", "--no-recurse", chain[-1]],
                              capture_output=True, text=True, check=False)
        assert step.returncode == 0, (chain, step)      # present, and a symbolic ref
        chain.append(step.stdout.strip())
    assert chain[-1] == damaged, chain


def _dangling(work: pathlib.Path, ref: str) -> None:
    w1._git(work, "symbolic-ref", ref, "refs/heads/missing")
    path = work / ".git" / ref
    assert path.read_text(encoding="utf-8") == "ref: refs/heads/missing\n"
    listing = subprocess.run(["git", "-C", str(work), "for-each-ref"], capture_output=True, text=True, check=False)
    assert (listing.returncode, listing.stderr) == (0, "") and ref not in listing.stdout, listing


@pytest.mark.parametrize("ref", ["refs/remotes/origin/main", "refs/recorded/x"])
def test_the_reviewers_case_a_symbolic_ref_without_a_target_leaves_the_exception_unapplied(env, tmp_path, ref):
    work, _remote, _a = w1._undeclared(tmp_path)
    _dangling(work, ref)
    answer, entry, text = w1._l1(env, work)
    _refused_on_the_damaged_chain(answer, entry, text, work, ref)


def test_with_packed_refs_the_symbolic_ref_without_a_target_is_still_found(env, tmp_path):
    """The repository keeps its other refs in packed-refs; git keeps a symbolic ref loose."""
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "pack-refs", "--all")
    assert (work / ".git" / "packed-refs").is_file()
    _dangling(work, "refs/remotes/origin/main")
    answer, entry, text = w1._l1(env, work)
    _refused_on_the_damaged_chain(answer, entry, text, work, "refs/remotes/origin/main")


def test_a_symbolic_ref_whose_target_is_another_symbolic_ref_without_a_target(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    _dangling(work, "refs/recorded/inner")
    w1._git(work, "symbolic-ref", "refs/recorded/outer", "refs/recorded/inner")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/recorded/inner {NOT_RESOLVED}")


def test_control_packed_refs_and_a_resolving_symbolic_ref_keep_the_exception(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    w1._git(work, "pack-refs", "--all")
    w1._git(work, "tag", "loose-after-pack")
    w1._assert_inactive(*w1._l1(env, work))


def test_control_a_ref_store_in_another_format_is_refused(env, tmp_path):
    """git 2.43.0 cannot open a repository that names refStorage reftable, so the push is refused before the gate lists
    a ref; the branch of the gate for a reftable store is not measured with a real one here."""
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "config", "core.repositoryformatversion", "1")
    w1._git(work, "config", "extensions.refStorage", "reftable")
    answer, entry, text = w1._l1(env, work)
    assert entry["verdict"] != "inactive", (entry, text)


def test_control_a_push_from_a_linked_worktree_keeps_the_exception(env, tmp_path):
    """The refs of a linked worktree's own folder and the common folder's main-worktree refs are told apart."""
    work, _remote, _a = w1._undeclared(tmp_path)
    linked = tmp_path / "linked"
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(linked))
    w1._git(work, "update-ref", "refs/bisect/main-worktree", "HEAD")
    answer, entry, text = w1._l1(env, linked, "git push origin side")
    # Narrow contract of 2026-10-13, 17:0x: a linked worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a linked worktree", str(linked))
