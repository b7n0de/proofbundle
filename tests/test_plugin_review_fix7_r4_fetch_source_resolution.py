"""Review round 7 of 2026-10-10, R7-4: a fetch source is the ref git resolves it to, not its spelling.

Measured by the reviewer at 0c88746f: remote.second.fetch `+other:refs/remotes/origin/main` and `^other`. git resolves
the source other to the remote's refs/heads/other, and `^other`, compared with that name, excludes nothing: `git fetch
second` writes other's state into refs/remotes/origin/main. The gate compared the spelling other with the spelling of
the negative refspec, read the rule as excluded and passed `git push origin main` with done. Under 2.51.1 the source
refs/heads/other can also match refs/heads/refs/heads/other.

Property: the gate reads every input in the same meaning as git; where it cannot, NOT MEASURED. git resolves a plain
fetch source against the refs the remote advertises (remote.c get_remote_ref, the best of refname_match's rules;
measured with git 2.43.0 and 2.51.1): `other` and `heads/other` name refs/heads/other, and refs/heads/gone names
refs/heads/refs/heads/gone where the branch gone is missing, under both versions. That remote ref is not evidenced in
this repository, so a plain source that writes the tracking ref, or any plain source of the pushing remote, leaves the
comparison NOT MEASURED. A pattern source matches full names only and stays read. The remainder FIX-06 named
(refname_match) is a verdict now. Red against 91190324.
"""
from __future__ import annotations

import json
import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git
TRACKING = "refs/remotes/origin/main"


def _rev(repo, ref: str) -> str | None:
    out = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", ref], capture_output=True,
                         text=True, timeout=60, check=False)
    return out.stdout.strip() or None


def _repo(tmp_path) -> n2c.Repo:
    """main tracks origin/main, one commit of work with a valid receipt; a second remote `second` holds a branch other
    at a commit of its own."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "second.git")], check=True, timeout=60)
    _git(r.path, "remote", "add", "second", str(tmp_path / "second.git"))
    _git(r.path, "commit", "-q", "--allow-empty", "-m", "only on second's other")
    _git(r.path, "push", "-q", "--no-verify", "second", "HEAD:refs/heads/other")
    _git(r.path, "reset", "-q", "--hard", "HEAD~1")
    return r


def _second_rules(repo, *specs: str) -> None:
    _git(repo, "config", "--unset-all", "remote.second.fetch")
    for spec in specs:
        _git(repo, "config", "--add", "remote.second.fetch", spec)


def _verdict(env, repo, command: str = "git push origin main") -> tuple[str, list, bool]:
    """The verdict, its reasons, and whether the resolution reached the destination check (R9-1)."""
    answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"], n2c.reached_destination(json.dumps(answer, ensure_ascii=False))


#: NOT MEASURED at the fetch rules, before the destination check.
NOT_MEASURED = ("ask", ["push_not_measured"], False)

WRITERS = {   # rules of `second` that make `git fetch second` write other's state into refs/remotes/origin/main
    "reviewer": ("+other:refs/remotes/origin/main", "^other"),
    "short_source": ("+heads/other:refs/remotes/origin/main", "^heads/other"),
    "full_source_short_exclusion": ("+refs/heads/other:refs/remotes/origin/main", "^other"),
}


@pytest.mark.parametrize("case", WRITERS)
def test_git_writes_the_tracking_ref_from_the_resolved_source(tmp_path, case):
    """Non-vacuous: the negative refspec spelled like the source excludes nothing; the fetch of second writes other's
    commit into refs/remotes/origin/main."""
    r = _repo(tmp_path)
    _second_rules(r.path, *WRITERS[case])
    other = subprocess.run(["git", "-C", str(r.path), "ls-remote", "second", "refs/heads/other"], capture_output=True,
                           text=True, timeout=60, check=True).stdout.split()[0]
    assert _rev(r.path, TRACKING) != other
    fetched = subprocess.run(["git", "-C", str(r.path), "fetch", "second"], capture_output=True, text=True, timeout=60)
    assert fetched.returncode == 0, fetched.stderr
    assert _rev(r.path, TRACKING) == other


@pytest.mark.parametrize("case", WRITERS)
def test_a_rule_whose_source_git_resolves_onto_the_tracking_ref_is_not_measured(env, tmp_path, case):
    r = _repo(tmp_path)
    _second_rules(r.path, *WRITERS[case])
    assert _verdict(env, r.path) == NOT_MEASURED


def _gone(tmp_path) -> n2c.Repo:
    """origin holds no branch main but refs/heads/refs/heads/main, at the declaring commit; the single-branch rule
    `+refs/heads/main:refs/remotes/origin/main` fetches that ref into the tracking ref."""
    r = _repo(tmp_path)
    remote = str(tmp_path / "remote.git")
    declared = _rev(r.path, "refs/remotes/origin/main")
    subprocess.run(["git", "--git-dir", remote, "update-ref", "refs/heads/refs/heads/main", declared], check=True,
                   timeout=60)
    subprocess.run(["git", "--git-dir", remote, "update-ref", "-d", "refs/heads/main"], check=True, timeout=60)
    _git(r.path, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main")
    _git(r.path, "update-ref", "-d", TRACKING)
    return r


def test_git_fetches_another_ref_into_the_tracking_ref_where_the_branch_is_missing(tmp_path):
    """Non-vacuous, under 2.43.0 as under 2.51.1: the full source refs/heads/main fetched the remote's
    refs/heads/refs/heads/main, and `git push origin main` updates that ref on the remote, not a branch main: git
    resolves the destination against the remote's refs as it resolved the fetch source."""
    r = _gone(tmp_path)
    fetched = subprocess.run(["git", "-C", str(r.path), "fetch", "origin"], capture_output=True, text=True,
                             timeout=60)
    assert fetched.returncode == 0 and "refs/heads/main" in fetched.stderr, fetched.stderr
    assert _rev(r.path, TRACKING) is not None
    push = subprocess.run(["git", "-C", str(r.path), "push", "--dry-run", "--porcelain", "--no-verify", "origin",
                           "main"], capture_output=True, text=True, timeout=60)
    assert "\trefs/heads/main:refs/heads/refs/heads/main\t" in push.stdout, push.stdout


def test_a_tracking_ref_a_plain_source_wrote_is_not_the_target_state(env, tmp_path):
    """The gate had taken that ref for the known state of the branch main and passed; git names another ref."""
    r = _gone(tmp_path)
    subprocess.run(["git", "-C", str(r.path), "fetch", "-q", "origin"], check=True, timeout=60)
    assert _verdict(env, r.path) == NOT_MEASURED


def test_a_single_branch_rule_is_not_measured(env, tmp_path):
    """The cost of the class, stated: `git clone --single-branch` writes `+refs/heads/main:refs/remotes/origin/main`.
    Which remote ref that plain source names is not evidenced here, so a push to that remote is NOT MEASURED, where
    the gate had passed it (owner question in the report)."""
    r = _repo(tmp_path)
    _git(r.path, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main")
    assert _verdict(env, r.path) == NOT_MEASURED


def test_a_plain_source_of_another_remote_onto_its_own_refs_keeps_the_pass(env, tmp_path):
    """Control: another remote's plain source that writes its own tracking ref changes nothing for origin/main (since
    R9-1 the destination check leaves the push NOT MEASURED, as it does without the rule)."""
    r = _repo(tmp_path)
    _second_rules(r.path, "+other:refs/remotes/second/other")
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path))
    assert n2c._level2(env, r.path).returncode == 0


def test_control_a_pattern_of_another_remote_onto_its_own_refs_keeps_the_pass(env, tmp_path):
    r = _repo(tmp_path)
    _second_rules(r.path, "+refs/heads/*:refs/remotes/second/*")
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path))   # since R9-1 NOT MEASURED at the destination
    assert n2c._level2(env, r.path).returncode == 0


def test_control_a_pattern_of_another_remote_onto_origin_stays_not_measured(env, tmp_path):
    """A pattern source matches full names only and is read as before (R6-3): second's refs/heads/* writes
    refs/remotes/origin/main from second's main, another remote's state, whatever `^other` says."""
    r = _repo(tmp_path)
    _second_rules(r.path, "+refs/heads/*:refs/remotes/origin/*", "^other")
    assert _verdict(env, r.path) == NOT_MEASURED


@pytest.mark.parametrize("spec", ["+main:refs/remotes/origin/elsewhere", "+refs/heads/main:refs/remotes/origin/elsewhere"])
def test_a_plain_source_of_the_pushing_remote_onto_another_ref_is_not_measured(env, tmp_path, spec):
    """Mutation M74b: a plain source of the pushing remote also maps the target branch to another ref when git resolves
    it to that branch, which the spelling does not tell (main and refs/heads/main both fetch main into elsewhere); the
    gate had passed the short spelling and left the full one NOT MEASURED."""
    r = _repo(tmp_path)
    _git(r.path, "config", "--add", "remote.origin.fetch", spec)
    fetched = subprocess.run(["git", "-C", str(r.path), "fetch", "origin"], capture_output=True, text=True, timeout=60)
    assert fetched.returncode == 0, fetched.stderr
    assert _rev(r.path, "refs/remotes/origin/elsewhere") == _rev(r.path, TRACKING)   # non-vacuous: main fetched there too
    assert _verdict(env, r.path) == NOT_MEASURED
