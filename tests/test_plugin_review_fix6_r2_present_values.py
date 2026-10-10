"""Review round 6 of 2026-10-10, R6-2: a present empty value is not an absent one; the gate sets no other target than git.

Measured by the reviewer at b513ff5a: with `branch.main.pushRemote` set to the empty string, a bare `git push` passed
Level 1 with done while `git push --dry-run` exited 128 ("no path specified"); the same for `remote.pushDefault` and
`branch.main.remote`. The gate read the three keys through one reader that returned None for an absent key and for an
empty value alike, and an or-chain then fell through to the next key and to origin. `push.default` set to the empty
string stayed ask, because git stops every command at that value.

The class, measured with git 2.43.0 (builtin/push.c setup_default_push_refspecs and get_upstream_ref, remote.c
pushremote_for_branch): git takes the first of pushRemote, remote.pushDefault and branch.<name>.remote that is present,
whatever its value, and only where none is present the one configured remote or else origin. A push without refspec
then stops where the upstream does not fit: push.default simple to the branch's own remote with no upstream, an
upstream of another name or two upstreams; push.default upstream to another remote than the branch's, or with no
branch remote. Each of these fallbacks passed Level 1 before; the gate now sets the target git sets or none at all.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

EMPTY_KEYS = ("branch.main.pushRemote", "remote.pushDefault", "branch.main.remote")


def _repo(tmp_path, **config) -> n2c.Repo:
    """main tracks origin/main (upstream set by `push -u`), one commit of work with a valid receipt."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    for key, value in config.items():
        _git(r.path, "config", key.replace("__", "."), value)
    return r


def _dry_run(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "push", "--dry-run", "--no-verify", *args], capture_output=True,
                          text=True, timeout=60, check=False)


def _verdict(env, repo, command: str) -> tuple[str, list]:
    _answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"]


def _other_remote(tmp_path, repo) -> None:
    """A second remote `other` that holds main and has its tracking ref, so the gate could judge a push to it."""
    subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "other.git")], check=True, timeout=60)
    _git(repo, "remote", "add", "other", str(tmp_path / "other.git"))
    n2c.record_remote_refs(repo, "other")
    _git(repo, "push", "-q", "other", "origin/main:refs/heads/main")
    _git(repo, "fetch", "-q", "other")


@pytest.mark.parametrize("key", EMPTY_KEYS)
def test_git_reads_the_empty_value_and_pushes_nowhere(tmp_path, key):
    """Non-vacuous: git takes the empty value as the push remote (exit 128), it does not fall back; with an explicit
    remote the same value plays no part and the push goes through. Measured by the exit and by the remote's main, which
    a real bare push leaves where it was: git 2.43.0 says "no path specified", 2.51.1 "No configured push destination"
    (review round 7 of 2026-10-10, R7-6)."""
    r = _repo(tmp_path, **{key.replace(".", "__"): ""})
    bare = _dry_run(r.path)
    assert bare.returncode == 128, bare.stderr
    before = _git(r.path, "ls-remote", "origin", "refs/heads/main").stdout
    pushed = subprocess.run(["git", "-C", str(r.path), "push", "--no-verify"], capture_output=True, text=True,
                            timeout=60, check=False)
    assert pushed.returncode == 128, pushed.stderr
    assert _git(r.path, "ls-remote", "origin", "refs/heads/main").stdout == before   # nothing was pushed
    assert before.split()[0] != _git(r.path, "rev-parse", "HEAD").stdout.strip()   # there was something to push
    assert _dry_run(r.path, "origin", "main").returncode == 0


@pytest.mark.parametrize("command", ["git push", "gh pr create --fill"])
@pytest.mark.parametrize("key", EMPTY_KEYS)
def test_a_bare_push_with_an_empty_remote_value_is_not_measured(env, tmp_path, key, command):
    r = _repo(tmp_path, **{key.replace(".", "__"): ""})
    assert _verdict(env, r.path, command) == ("ask", ["push_not_measured"])


@pytest.mark.parametrize("key", EMPTY_KEYS)
def test_control_an_explicit_remote_is_judged_as_git_pushes_it(env, tmp_path, key):
    r = _repo(tmp_path, **{key.replace(".", "__"): ""})
    assert _verdict(env, r.path, "git push origin main") == ("pass", ["done"])


def test_control_without_a_value_the_bare_push_passes(env, tmp_path):
    r = _repo(tmp_path)
    assert _dry_run(r.path).returncode == 0
    assert _verdict(env, r.path, "git push") == ("pass", ["done"])


def test_control_an_empty_push_default_stops_git_and_the_gate(env, tmp_path):
    r = _repo(tmp_path, push__default="")
    assert _dry_run(r.path).returncode == 128
    assert _verdict(env, r.path, "git push")[0] != "pass"


def test_control_push_default_is_read_with_its_case(env, tmp_path):
    """git reads push.default case-sensitively and stops every command at `Simple`; the gate does not pass it."""
    r = _repo(tmp_path, push__default="Simple")
    dry = _dry_run(r.path)
    assert dry.returncode == 128 and "malformed value for push.default" in dry.stderr, dry.stderr
    assert _verdict(env, r.path, "git push")[0] != "pass"


# --- the fallbacks git does not make (siblings of R6-2) ------------------------------------------------------------

def _not_pass_where_git_stops(env, r, command: str = "git push", *, git_args: tuple = (), message: str) -> None:
    dry = _dry_run(r.path, *git_args)
    assert dry.returncode == 128 and message in dry.stderr, dry.stderr
    assert _verdict(env, r.path, command) == ("ask", ["push_not_measured"])


def test_simple_to_the_branch_remote_without_an_upstream(env, tmp_path):
    r = _repo(tmp_path)
    _git(r.path, "config", "--unset", "branch.main.merge")
    _not_pass_where_git_stops(env, r, message="has no upstream branch")


def test_control_simple_without_an_upstream_but_auto_setup_remote(env, tmp_path):
    """push.autoSetupRemote makes git push the branch under its own name and set the upstream: the gate judges that."""
    r = _repo(tmp_path, push__autoSetupRemote="true")
    _git(r.path, "config", "--unset", "branch.main.merge")
    assert _dry_run(r.path).returncode == 0
    assert _verdict(env, r.path, "git push") == ("pass", ["done"])


@pytest.mark.parametrize("merge", ["refs/heads/other", "main"])
def test_simple_to_the_branch_remote_with_an_upstream_of_another_name(env, tmp_path, merge):
    """git compares the upstream as written with refs/heads/main: another branch, and the short name, both stop it."""
    r = _repo(tmp_path, branch__main__merge=merge)
    _not_pass_where_git_stops(env, r, message="The upstream branch of your current branch does not match")


@pytest.mark.parametrize("default", ["simple", "upstream"])
def test_two_upstreams(env, tmp_path, default):
    r = _repo(tmp_path, push__default=default)
    _git(r.path, "config", "--add", "branch.main.merge", "refs/heads/main")
    _not_pass_where_git_stops(env, r, message="has multiple upstream branches")


@pytest.mark.parametrize("default", ["simple", "upstream"])
def test_a_branch_remote_absent_while_the_upstream_branch_is_set(env, tmp_path, default):
    """With no branch.main.remote git has no upstream, whatever branch.main.merge says; the gate pushed to origin."""
    r = _repo(tmp_path, push__default=default)
    _git(r.path, "config", "--unset", "branch.main.remote")
    _not_pass_where_git_stops(env, r, message="has no upstream branch")


def test_upstream_to_another_remote_than_the_branch_remote(env, tmp_path):
    r = _repo(tmp_path, push__default="upstream", branch__main__pushRemote="other")
    _other_remote(tmp_path, r.path)
    _not_pass_where_git_stops(env, r, message="which is not the upstream of")


def test_control_simple_to_another_remote_pushes_the_branch_under_its_name(env, tmp_path):
    """A triangular push with push.default simple: git pushes main to other's main, no upstream needed."""
    r = _repo(tmp_path, branch__main__pushRemote="other", branch__main__merge="refs/heads/zzz")
    _other_remote(tmp_path, r.path)
    dry = _dry_run(r.path)
    assert dry.returncode == 0 and "main -> main" in dry.stderr, dry.stderr
    assert _verdict(env, r.path, "git push") == ("pass", ["done"])


def test_the_one_configured_remote_is_the_default_as_in_git(env, tmp_path):
    """Neither key present and exactly one remote, not named origin: git pushes to it, the gate judges that push
    (before, the gate looked for origin only and left the push NOT MEASURED)."""
    r = _repo(tmp_path, push__default="current")
    _git(r.path, "remote", "rename", "origin", "upstream")
    _git(r.path, "config", "--unset", "branch.main.remote")
    dry = _dry_run(r.path)
    assert dry.returncode == 0 and "remote.git" in dry.stderr, dry.stderr
    assert _verdict(env, r.path, "git push") == ("pass", ["done"])


def test_the_sources_of_an_unresolved_push_come_from_the_remote_git_pushes_to(env, tmp_path):
    """The source check of an unresolved bare push (_push_sources) chose origin where git takes the one remote: with a
    push list configured on that remote git sends `side`, not HEAD, and the gate named HEAD as the commit sent."""
    r = n2c.Repo(tmp_path)  # no receipt: a check of HEAD would deny
    _git(r.path, "remote", "rename", "origin", "upstream")
    _git(r.path, "config", "--unset", "branch.main.remote")
    _git(r.path, "checkout", "-q", "-b", "side", "upstream/main")
    n2c._write(r.path / "side.txt", "side\n")
    n2c._commit(r.path, "a commit only on side")
    _git(r.path, "checkout", "-q", "main")
    _git(r.path, "config", "remote.upstream.push", "refs/heads/side:refs/heads/main")
    dry = _dry_run(r.path)
    assert dry.returncode == 0 and "side -> main" in dry.stderr, dry.stderr
    answer, entry = n2c._level1(env, r.path, command="git push")
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    reason = answer["hookSpecificOutput"]["permissionDecisionReason"]
    assert "cannot tell which commits the push sends" in reason, reason
