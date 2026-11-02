"""Review round 11 of 2026-10-12, the class of R11-3: owner choice 1 reads the records of every remote that may name the
destination, not only of those that spell its URL alike.

Measured here at 98dba10a with git 2.43.0, in the class search of R11-3: origin names the bare repository `remote.git`,
a second remote `mirror` names it as `remote`, without the suffix, which git completes to `remote.git` (a push over
mirror wrote main there, exit 0); mirror recorded main while it held a declaration, origin after the remote went back.
Level 1 for `git push origin main` was inactive and named only origin's clean record. The same with no local path:
origin and mirror spelling one network repository as https and scp form, as ssh URL, with and without .git, or through a
host alias, mirror's record written as a fetch leaves it. _same_endpoint had compared the URLs as written, or as local
paths resolved without git's own completion; git does not say which remotes name the endpoint a push goes to.

Property (condition d of owner choice 1): a local record that may be of the destination is read. Every configured
remote's records of the ref the push writes are read, as already for a push to a URL or a path; a declaration in one
of them, or a record that cannot be read, leaves the exception unapplied. Red against 98dba10a.
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


def _raw(work: pathlib.Path, kind: str, data: bytes) -> str:
    return subprocess.run(["git", "-C", str(work), "hash-object", "-t", kind, "-w", "--stdin"], input=data,
                          capture_output=True, check=True).stdout.decode().strip()


def _declared_on_top(work: pathlib.Path, parent: str) -> str:
    """A commit on `parent` whose tree holds only a declaration with an empty evidence list."""
    folder = _raw(work, "tree", b"100644 evidence.json\x00" + bytes.fromhex(_raw(work, "blob", w1.EMPTY_LIST.encode())))
    root = _raw(work, "tree", b"40000 .proofbundle\x00" + bytes.fromhex(folder))
    return w1._git(work, "commit-tree", root, "-p", parent, "-m", "declared on the remote").stdout.strip()


def _mirror_without_suffix(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str, str]:
    """origin at <tmp>/remote.git, mirror at <tmp>/remote; mirror recorded main while the remote held a declaration,
    origin after the remote went back to A."""
    work, remote, a = w1._undeclared(tmp_path)
    declared = _declared_on_top(work, a)
    w1._git(work, "push", "-q", "--no-verify", "origin", f"+{declared}:refs/heads/main")
    w1._git(work, "remote", "add", "mirror", str(remote)[:-len(".git")])
    w1._git(work, "fetch", "-q", "--no-tags", "mirror")
    w1._git(work, "push", "-q", "--no-verify", "origin", f"+{a}:refs/heads/main")
    w1._git(work, "fetch", "-q", "--no-tags", "origin")
    assert w1.n2c._rev(work, "refs/remotes/mirror/main") == declared
    assert w1.n2c._rev(work, "refs/remotes/origin/main") == a
    return work, remote, a, declared


def test_git_pushes_over_a_path_without_its_suffix_into_the_repository(env, tmp_path):
    """Non-vacuous: mirror's URL names the same repository; a push over mirror writes main of remote.git."""
    work, remote, _a, _declared = _mirror_without_suffix(tmp_path)
    assert not pathlib.Path(str(remote)[:-len(".git")]).exists()
    w1._git(work, "push", "-q", "--no-verify", "mirror", "+main:refs/heads/main")
    head = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "refs/heads/main"], capture_output=True,
                          text=True, check=True).stdout.strip()
    assert head == w1.n2c._rev(work, "HEAD")


def test_the_record_of_a_remote_naming_the_repository_without_its_suffix_is_read(env, tmp_path):
    work, _remote, _a, declared = _mirror_without_suffix(tmp_path)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/remotes/mirror/main "
                                                      f"holds something at {gate.DECLARATION} or in place of its "
                                                      f"folder at {declared[:12]}")


SPELLINGS = {"https and scp form": ("https://example.invalid/o/r.git", "git@example.invalid:o/r.git"),
             "https and ssh URL": ("https://example.invalid/o/r.git", "ssh://git@example.invalid/o/r.git"),
             "with and without .git": ("https://example.invalid/o/r.git", "https://example.invalid/o/r"),
             "a host alias": ("git@example.invalid:o/r.git", "git@alias-for-example:o/r.git")}


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_the_record_of_a_remote_spelling_a_network_url_otherwise_is_read(env, tmp_path, spelling):
    """No network: mirror's record is written with update-ref, as a fetch would have left it; the gate reads no
    remote at Level 1, so the URLs are not contacted."""
    work, _remote, a = w1._undeclared(tmp_path)
    origin_url, mirror_url = SPELLINGS[spelling]
    w1._git(work, "remote", "set-url", "origin", origin_url)
    w1._git(work, "remote", "add", "mirror", mirror_url)
    declared = _declared_on_top(work, a)
    w1._git(work, "update-ref", "refs/remotes/mirror/main", declared)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/remotes/mirror/main "
                                                      f"holds something at {gate.DECLARATION} or in place of its "
                                                      f"folder at {declared[:12]}")


def test_a_second_remote_whose_record_declares_nothing_is_read_and_the_exception_holds(env, tmp_path):
    work, remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "add", "mirror", str(remote)[:-len(".git")])
    w1._git(work, "fetch", "-q", "--no-tags", "mirror")
    answer, entry, text = w1._l1(env, work)
    w1._assert_inactive(answer, entry, text)
    assert "refs/remotes/mirror/main at " in text and "refs/remotes/origin/main at " in text, text
