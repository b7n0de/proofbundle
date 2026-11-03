"""Review round 6 of 2026-10-10, R6-3: a tracking ref counts as mapped only where the fetch rules in effect map the target
branch onto it; an exclusion cancels the mapping.

Measured by the reviewer at b513ff5a: `git config --add remote.origin.fetch '^refs/heads/main'` and `git push origin main`
passed Level 1 with done. Counter-check: with refs/remotes/origin/main deleted, `git fetch` exited 0 and the ref did not
come back. The gate skipped every fetch refspec without a colon, a negative one included.

The class, measured with git 2.43.0 (refspec.c parse_refspec, remote.c match_name_with_pattern and
apply_negative_refspecs): a negative refspec excludes the remote refs it names, exactly or by a pattern whose one `*`
may stand anywhere (`^refs/heads/ma*`, `^*main`); a `*` in the middle of a side maps as well as a trailing one; a short
name or an empty source (the remote's HEAD) writes the tracking ref too; and another remote's fetch rules can write it.
git refuses the fetch for each collision ("Cannot fetch both ..."), so the tracking ref stays as it was. The gate read
none of these; now each leaves the comparison NOT MEASURED, and an excluded source no longer counts as a collision,
as git does not fetch it.
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
DEFAULT = "+refs/heads/*:refs/remotes/origin/*"


def _repo(tmp_path, *fetch: str, branches=("other", "oiher")) -> n2c.Repo:
    """main tracks origin/main, one commit of work with a valid receipt; the remote also holds `branches`, each at a
    commit of its own, and the fetch rules of origin are DEFAULT followed by `fetch`."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    subprocess.run(["git", "--git-dir", str(tmp_path / "remote.git"), "symbolic-ref", "HEAD", "refs/heads/main"],
                   check=True, timeout=60)   # the remote's HEAD names main, as on a hosted remote
    for name in branches:
        _git(r.path, "commit", "-q", "--allow-empty", "-m", f"only on {name}")
        _git(r.path, "push", "-q", "origin", f"HEAD:refs/heads/{name}")
        _git(r.path, "reset", "-q", "--hard", "HEAD~1")
    _git(r.path, "fetch", "-q", "origin")
    for spec in fetch:
        _git(r.path, "config", "--add", "remote.origin.fetch", spec)
    return r


def _fetch(repo, remote: str = "origin") -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "fetch", remote], capture_output=True, text=True, timeout=60,
                          check=False)


def _tracking(repo) -> str | None:
    out = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", TRACKING], capture_output=True,
                         text=True, timeout=60, check=False)
    return out.stdout.strip() or None


def _remote_main(repo) -> str:
    return subprocess.run(["git", "-C", str(repo), "ls-remote", "origin", "refs/heads/main"], capture_output=True,
                          text=True, timeout=60, check=True).stdout.split()[0]


def _verdict(env, repo, command: str = "git push origin main") -> tuple[str, list, bool]:
    """The verdict, its reasons, and whether the resolution reached the destination check (R9-1)."""
    answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"], n2c.reached_destination(json.dumps(answer, ensure_ascii=False))


def _judged(env, repo, command: str = "git push origin main") -> None:
    """Resolved up to the destination check, which since R9-1 leaves every Level 1 push NOT MEASURED; the evidence
    at the sent commit showed no failure, and Level 2 passes the push."""
    answer, entry = n2c._level1(env, repo, command=command)
    n2c.assert_destination_not_measured(answer, entry)
    assert n2c._level2(env, repo).returncode == 0


EXCLUSIONS = ["^refs/heads/main", "^refs/heads/ma*", "^*main", "^refs/heads/*ain"]


@pytest.mark.parametrize("negative", EXCLUSIONS)
def test_git_does_not_fetch_an_excluded_branch_into_its_tracking_ref(tmp_path, negative):
    """Non-vacuous, the reviewer's counter-check: the tracking ref deleted, `git fetch` exits 0 and does not bring it
    back."""
    r = _repo(tmp_path, negative)
    _git(r.path, "update-ref", "-d", TRACKING)
    assert _fetch(r.path).returncode == 0
    assert _tracking(r.path) is None


@pytest.mark.parametrize("command", ["git push origin main", "git push"])
@pytest.mark.parametrize("negative", EXCLUSIONS)
def test_an_excluded_target_branch_is_not_measured(env, tmp_path, negative, command):
    r = _repo(tmp_path, negative)
    assert _verdict(env, r.path, command) == ("ask", ["push_not_measured"], False)


@pytest.mark.parametrize("negative", ["^main", "^refs/heads/other", "^refs/heads/o*"])
def test_control_an_exclusion_of_another_ref_keeps_the_pass(env, tmp_path, negative):
    """`^main` names the remote ref `main` exactly, which git never lists; the other two exclude other branches. git
    fetches main into its tracking ref, and the gate judges the push (up to the destination check, R9-1)."""
    r = _repo(tmp_path, negative)
    _git(r.path, "update-ref", "-d", TRACKING)
    assert _fetch(r.path).returncode == 0 and _tracking(r.path) == _remote_main(r.path)
    _judged(env, r.path)


COLLISIONS = {
    "middle star": "+refs/heads/o*her:refs/remotes/origin/ma*n",   # oiher -> main
    "short names": "+other:remotes/origin/main",
    "empty source": ":refs/remotes/origin/main",                   # the remote's HEAD
}


@pytest.mark.parametrize("name", list(COLLISIONS))
def test_a_second_rule_onto_the_tracking_ref_is_not_measured(env, tmp_path, name):
    """git refuses the fetch for each of these ("Cannot fetch both ... to refs/remotes/origin/main"), so the tracking
    ref no longer follows main; the gate read the spec as mapping nothing."""
    r = _repo(tmp_path, COLLISIONS[name])
    fetched = _fetch(r.path)
    assert fetched.returncode == 128 and f"to {TRACKING}" in fetched.stderr, fetched.stderr
    assert _verdict(env, r.path) == ("ask", ["push_not_measured"], False)


def test_control_a_middle_star_onto_other_refs_keeps_the_pass(env, tmp_path):
    r = _repo(tmp_path, "+refs/heads/o*her:refs/remotes/origin/x*y")
    assert _fetch(r.path).returncode == 0
    _judged(env, r.path)


def test_an_excluded_source_is_no_collision(env, tmp_path):
    """git fetches no excluded ref, so a rule that would write the tracking ref from it writes nothing: with
    `^refs/heads/oiher` the middle-star rule from oiher onto main is void, the fetch exits 0 and the tracking ref follows
    main. A plain source such as refs/heads/other is no longer read this way: which remote ref git resolves it to is not
    evidenced, so it is NOT MEASURED (review round 7 of 2026-10-10, R7-4, test_plugin_review_fix7_r4_*)."""
    r = _repo(tmp_path, "+refs/heads/o*her:refs/remotes/origin/ma*n", "^refs/heads/oiher")
    _git(r.path, "update-ref", "-d", TRACKING)
    assert _fetch(r.path).returncode == 0 and _tracking(r.path) == _remote_main(r.path)
    _judged(env, r.path)


def _second_remote(tmp_path, repo, spec: str) -> None:
    _git(repo, "remote", "add", "second", str(tmp_path / "remote.git"))
    _git(repo, "config", "--replace-all", "remote.second.fetch", spec)


def test_another_remote_whose_fetch_writes_the_tracking_ref_is_not_measured(env, tmp_path):
    r = _repo(tmp_path)
    _second_remote(tmp_path, r.path, "+refs/heads/other:refs/remotes/origin/main")
    assert _fetch(r.path, "second").returncode == 0
    assert _tracking(r.path) != _remote_main(r.path)   # fetching `second` wrote other's state into origin/main
    assert _verdict(env, r.path) == ("ask", ["push_not_measured"], False)


def test_control_another_remote_with_its_own_tracking_refs_keeps_the_pass(env, tmp_path):
    r = _repo(tmp_path)
    _second_remote(tmp_path, r.path, "+refs/heads/*:refs/remotes/second/*")
    assert _fetch(r.path, "second").returncode == 0 and _tracking(r.path) == _remote_main(r.path)
    _judged(env, r.path)


@pytest.mark.parametrize("spec", ["+refs/heads/*/*:refs/remotes/origin/*/*", "+^refs/heads/main",
                                  "^refs/heads/main:refs/x"])
def test_control_a_rule_git_refuses_stops_git_and_the_gate(env, tmp_path, spec):
    r = _repo(tmp_path, spec)
    fetched = _fetch(r.path)
    assert fetched.returncode == 128 and "invalid refspec" in fetched.stderr, fetched.stderr
    verdict, _reasons, reached = _verdict(env, r.path)
    assert verdict != "pass" and not reached
