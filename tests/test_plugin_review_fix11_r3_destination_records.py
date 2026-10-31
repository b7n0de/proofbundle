"""Review round 11 of 2026-10-12, R11-3: owner choice 1 reads every local record of the destination the push writes.

Measured by the reviewer at 3bbbf66f: the source, its whole history and refs/remotes/origin/main declare nothing; a
second local remote `other` whose main holds .proofbundle/evidence.json, fetched as refs/remotes/other/main;
remote.origin.pushurl names the URL of other; Level 1 for `git push origin +main:refs/heads/main` answered
inactive/nothing_declared_locally with no permission decision and named only origin's clean record, while the push over
origin replaced other's main. `git push other +main:refs/heads/main` was asked. The sibling: GIT_NAMESPACE=team, a
declaration in refs/namespaces/team/refs/heads/main on the remote, recorded with
+refs/namespaces/team/refs/heads/*:refs/recorded/team/*; the hook passed over refs/recorded/team/main and was inactive.

Property: condition d needs every relevant local record of the destination. Where the endpoint or the namespace the push
goes to is not modelled (a pushurl, a further URL, a URL rewrite, GIT_NAMESPACE), the exception does not apply; the
records of every remote whose URL is the destination's are read. No statement on the unknown state of the remote is
added. Red against 2322f123.
"""
from __future__ import annotations

import pathlib
import subprocess

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate


def _declared_commit(remote: pathlib.Path, ref: str, scratch: pathlib.Path) -> str:
    """Write a commit that holds a declaration to `ref` of the bare `remote`, through a clone of its own."""
    clone = scratch / f"declare-{remote.name}-{ref.replace('/', '-')}"
    subprocess.run(["git", "init", "-q", "-b", "declared", str(clone)], check=True)
    declared = w1._commit(clone, gate.DECLARATION, w1.EMPTY_LIST)
    w1._git(clone, "push", "-q", "--no-verify", str(remote), f"+declared:{ref}")
    return declared


def test_the_reviewers_case_a_pushurl_to_a_remote_whose_record_declares_is_not_exempted(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    other = tmp_path / "other.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(other)], check=True)
    declared = _declared_commit(other, "refs/heads/main", tmp_path)
    w1._git(work, "remote", "add", "other", str(other))
    w1._git(work, "fetch", "-q", "--no-tags", "other")
    w1._git(work, "config", "remote.origin.pushurl", str(other))
    answer, entry, text = w1._l1(env, work, "git push origin +main:refs/heads/main")
    w1._assert_exception_refused(answer, entry, text, "goes to another endpoint than the one its local records come from")
    # non-vacuous: the push over origin replaces other's main, whose record held the declaration
    w1._git(work, "push", "-q", "--no-verify", "origin", "+main:refs/heads/main")
    head = subprocess.run(["git", "--git-dir", str(other), "rev-parse", "refs/heads/main"], capture_output=True,
                          text=True, check=True).stdout.strip()
    assert head == w1.n2c._rev(work, "HEAD") != declared


def test_control_the_push_to_other_itself_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    other = tmp_path / "other.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(other)], check=True)
    declared = _declared_commit(other, "refs/heads/main", tmp_path)
    w1._git(work, "remote", "add", "other", str(other))
    w1._git(work, "fetch", "-q", "--no-tags", "other")
    answer, entry, text = w1._l1(env, work, "git push other +main:refs/heads/main")
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/remotes/other/main "
                                                      f"holds something at {gate.DECLARATION} or in place of its folder "
                                                      f"at {declared[:12]}")


def test_a_second_remote_with_the_same_url_has_its_records_read(env, tmp_path):
    """mirror and origin name the same repository; mirror recorded its main while it held a declaration, origin
    after the remote went back. Both are local records of the destination of `git push origin main`."""
    work, remote, a = w1._undeclared(tmp_path)
    declared = _declared_commit(remote, "refs/heads/main", tmp_path)
    w1._git(work, "remote", "add", "mirror", str(remote))
    w1._git(work, "fetch", "-q", "--no-tags", "mirror")
    subprocess.run(["git", "--git-dir", str(remote), "update-ref", "refs/heads/main", a], check=True)
    w1._git(work, "fetch", "-q", "--no-tags", "origin")
    assert w1.n2c._rev(work, "refs/remotes/origin/main") == a
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/remotes/mirror/main "
                                                      f"holds something at {gate.DECLARATION} or in place of its "
                                                      f"folder at {declared[:12]}")


def test_a_push_under_a_namespace_is_not_exempted(env, tmp_path):
    work, remote, _a = w1._undeclared(tmp_path)
    _declared_commit(remote, "refs/namespaces/team/refs/heads/main", tmp_path)
    w1._git(work, "config", "--add", "remote.origin.fetch", "+refs/namespaces/team/refs/heads/*:refs/recorded/team/*")
    w1._git(work, "fetch", "-q", "--no-tags", "origin")
    answer, entry, text = w1._l1(dict(env, GIT_NAMESPACE="team"), work)
    w1._assert_exception_refused(answer, entry, text, "GIT_NAMESPACE=team")
    # non-vacuous: under the namespace git writes refs/namespaces/team/refs/heads/main on the local remote
    subprocess.run(["git", "-C", str(work), "push", "-q", "--no-verify", "origin", "+main"], check=True,
                   env={**env, "GIT_NAMESPACE": "team"}, capture_output=True)
    ns = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "refs/namespaces/team/refs/heads/main"],
                        capture_output=True, text=True, check=True).stdout.strip()
    assert ns == w1.n2c._rev(work, "HEAD")


def test_control_without_pushurl_namespace_or_second_remote_the_exception_holds(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._assert_inactive(*w1._l1(env, work))
