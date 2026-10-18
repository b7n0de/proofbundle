"""Review round 12 of 2026-10-13, R12-1: condition d reads the refs that are present, not only those today's
configuration names.

Measured by the reviewer at 7588fe4a with git 2.51.1 and 2.43.0: a source whose HEAD and history declare nothing, a bare
remote origin with the fetch rule +refs/heads/*:refs/remotes/origin/*; another commit with .proofbundle/evidence.json set
for a while on the remote's main and on refs/tags/release; `git fetch origin` followed the tag on its own, so the local
refs/tags/release names the declared commit; the remote's main went back to the clean commit and was fetched again. No
fetch rule for tags. Level 1 for `git push origin :refs/tags/release` answered inactive/nothing_declared_locally with no
permission decision and said no local record of the destination was found; the push run apart deleted the remote tag,
exit 0. With +refs/tags/*:refs/tags/* added as a fetch rule the same call was asked and named refs/tags/release.

The class, measured here at 69730798 with git 2.43.0: records that today's configuration does not name, but that are
present: a tag git followed, refs/remotes/<name>/ of a remote whose configuration is gone, the refs an earlier fetch rule
wrote, a branch a one-time `git fetch origin main:<branch>` wrote. Each held a declaration and the push was inactive.

Property (condition d of owner choice 1): every present local ref is read, since a fetch without a lasting rule and
earlier rules leave records anywhere, and which present ref recorded the destination is not determinable here. A
declaration at any of them, a ref that names no object the gate reads, or a broken ref leaves the exception unapplied, and
the ask names the ref without claiming it is a record of the destination. Red against 69730798.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1
import test_plugin_owner_choice1_ask_names_the_record_20261013 as a1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate


def _remote_rev(remote: pathlib.Path, ref: str) -> str:
    return subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "--verify", "--quiet", ref],
                          capture_output=True, text=True, check=False).stdout.strip()


def _declared_on_remote(work: pathlib.Path, remote: pathlib.Path, a: str) -> str:
    """The declared commit D on top of A, on the remote's main for a while; returns D."""
    declared = a1._declared_on_top(work, a)
    w1._git(work, "push", "-q", "--no-verify", "origin", f"+{declared}:refs/heads/main")
    return declared


def _back_to_clean(work: pathlib.Path, remote: pathlib.Path, a: str) -> None:
    subprocess.run(["git", "--git-dir", str(remote), "update-ref", "refs/heads/main", a], check=True)
    w1._git(work, "fetch", "-q", "origin")
    assert w1.n2c._rev(work, "refs/remotes/origin/main") == a


def _reviewers_case(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str, str]:
    work, remote, a = w1._undeclared(tmp_path)
    assert w1._git(work, "config", "--get-all", "remote.origin.fetch").stdout.split() == ["+refs/heads/*:refs/remotes/origin/*"]
    declared = _declared_on_remote(work, remote, a)
    subprocess.run(["git", "--git-dir", str(remote), "update-ref", "refs/tags/release", declared], check=True)
    w1._git(work, "fetch", "-q", "origin")
    assert w1.n2c._rev(work, "refs/tags/release") == declared, "git followed the tag"
    _back_to_clean(work, remote, a)
    return work, remote, a, declared


def _refused_at(answer: dict, entry: dict, text: str, ref: str, declared: str, house: tuple = ()) -> None:
    w1._assert_exception_refused(answer, entry, text, f"the local ref {ref} holds something at {gate.DECLARATION} or in "
                                                      f"place of its folder at {declared[:12]}; {a1.NOT_ESTABLISHED}",
                                 house)


def test_the_reviewers_case_a_tag_git_followed_is_read(env, tmp_path):
    work, remote, _a, declared = _reviewers_case(tmp_path)
    answer, entry, text = w1._l1(env, work, "git push origin :refs/tags/release")
    _refused_at(answer, entry, text, "refs/tags/release", declared, ("house_tag_out",))   # a tag goes out: H2 of D73
    assert "no local record of its destination was found" not in text, text
    # non-vacuous: the push run apart deletes the remote tag, exit 0
    push = subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", "origin", ":refs/tags/release"],
                          capture_output=True, text=True, check=False)
    assert push.returncode == 0 and _remote_rev(remote, "refs/tags/release") == "", push.stderr


def test_the_reviewers_control_with_a_tag_rule_is_asked(env, tmp_path):
    work, _remote, _a, declared = _reviewers_case(tmp_path)
    w1._git(work, "config", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*")
    answer, entry, text = w1._l1(env, work, "git push origin :refs/tags/release")
    _refused_at(answer, entry, text, "refs/tags/release", declared, ("house_tag_out",))   # a tag goes out: H2 of D73


def _gone(tmp_path: pathlib.Path, remote_head: bool) -> tuple[pathlib.Path, str]:
    """A remote fetched once and its configuration removed, its records left. Whether a fetch also writes the symbolic
    refs/remotes/gone/HEAD depends on the git version (2.51.1 does, 2.43.0 does not; review round 17 of 2026-10-13,
    R17-2), so each case sets it itself: present as a symbolic ref, or absent."""
    work, remote, a = w1._undeclared(tmp_path)
    declared = _declared_on_remote(work, remote, a)
    w1._git(work, "remote", "add", "gone", str(remote))
    w1._git(work, "fetch", "-q", "--no-tags", "gone")
    present = subprocess.run(["git", "-C", str(work), "symbolic-ref", "-q", "refs/remotes/gone/HEAD"],
                             capture_output=True, text=True, check=False).returncode == 0
    if remote_head and not present:
        w1._git(work, "symbolic-ref", "refs/remotes/gone/HEAD", "refs/remotes/gone/main")
    if not remote_head and present:
        w1._git(work, "symbolic-ref", "--delete", "refs/remotes/gone/HEAD")
    w1._git(work, "config", "--remove-section", "remote.gone")     # the configuration goes, the refs stay
    _back_to_clean(work, remote, a)
    return work, declared


def test_the_records_of_a_remote_whose_configuration_is_gone_are_read(env, tmp_path):
    """Only the direct record stays: it is read, and its declaration is named with its object."""
    work, declared = _gone(tmp_path, remote_head=False)
    record = "refs/remotes/gone/main"
    assert w1.n2c._rev(work, record) == declared
    assert subprocess.run(["git", "-C", str(work), "rev-parse", "--verify", "--quiet", "refs/remotes/gone/HEAD"],
                          capture_output=True, check=False).returncode == 1
    answer, entry, text = w1._l1(env, work)
    _refused_at(answer, entry, text, record, declared)


def test_the_symbolic_head_of_a_remote_whose_configuration_is_gone_is_outside_the_contract(env, tmp_path):
    """The symbolic refs/remotes/gone/HEAD stays as well: a symbolic ref of a remote git no longer lists lies outside
    the narrow contract, and the ask names it (the production contract is not loosened)."""
    work, declared = _gone(tmp_path, remote_head=True)
    assert w1.n2c._rev(work, "refs/remotes/gone/HEAD") == declared
    w1._assert_outside(*w1._l1(env, work), "a symbolic ref other than HEAD and refs/remotes/<remote>/HEAD",
                       "refs/remotes/gone/HEAD")


def test_the_refs_an_earlier_fetch_rule_wrote_are_read(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    declared = _declared_on_remote(work, remote, a)
    w1._git(work, "fetch", "-q", "--no-tags", "origin", "+refs/heads/*:refs/recorded/origin/*")
    _back_to_clean(work, remote, a)
    answer, entry, text = w1._l1(env, work)
    _refused_at(answer, entry, text, "refs/recorded/origin/main", declared)


def test_a_branch_a_one_time_fetch_wrote_is_read(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    declared = _declared_on_remote(work, remote, a)
    w1._git(work, "fetch", "-q", "--no-tags", "origin", "main:refs/heads/copy")
    _back_to_clean(work, remote, a)
    answer, entry, text = w1._l1(env, work)
    _refused_at(answer, entry, text, "refs/heads/copy", declared)


@pytest.mark.parametrize("target", ["tree", "nested tag"])
def test_a_tag_of_a_declared_tree_or_of_a_tag_is_read(env, tmp_path, target):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    if target == "tree":
        w1._git(work, "tag", "-a", "-m", "t", "treetag", f"{declared}^{{tree}}")
        ref, at = "refs/tags/treetag", w1.n2c._rev(work, f"{declared}^{{tree}}")
    else:
        w1._git(work, "tag", "-a", "-m", "inner", "inner", declared)
        w1._git(work, "tag", "-a", "-m", "outer", "outer", "inner")
        w1._git(work, "tag", "-d", "inner")
        ref, at = "refs/tags/outer", declared
    answer, entry, text = w1._l1(env, work)
    _refused_at(answer, entry, text, ref, at)


def test_a_broken_ref_anywhere_leaves_the_exception_unapplied(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    broken = work / ".git" / "refs" / "recorded" / "x"
    broken.parent.mkdir(parents=True)
    broken.write_text("garbage\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    # The normal form of the ref store (review round 16 of 2026-10-13) names the file before git calls it broken.
    w1._assert_exception_refused(answer, entry, text, "the ref store is not in the form the gate reads (a file not of "
                                                      "the form <object>LF or ref: <name>LF): refs/recorded/x")


def test_control_present_refs_without_a_declaration_keep_the_exception(env, tmp_path):
    work, remote, a = w1._undeclared(tmp_path)
    w1._git(work, "tag", "-a", "-m", "v", "v1", a)
    w1._git(work, "branch", "side", a)
    w1._git(work, "fetch", "-q", "--no-tags", "origin", "+refs/heads/*:refs/recorded/origin/*")
    answer, entry, text = w1._l1(env, work)
    w1._assert_inactive(answer, entry, text)
    count = len(w1._git(work, "for-each-ref", "--format=%(refname)").stdout.split())
    # since the class of R13-1 the lines of FETCH_HEAD count as well
    count += len((work / ".git" / "FETCH_HEAD").read_text(encoding="utf-8").splitlines())
    assert f"at any of the {count} local refs of this repository" in text, text
