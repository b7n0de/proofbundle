"""Review round 7 of 2026-10-10, R7-2: a ref name is read in full, never shortened and qualified again.

Measured by the reviewer at 0c88746f: with a tag `main` beside the branch `main`, `git symbolic-ref --short HEAD` says
heads/main; _default_push built refs/heads/heads/main from it and read branch.heads/main.*. A bare `git push` passed
with done while `git push origin HEAD:main`, the push git performs, asked with rules_changed; with an empty
branch.main.pushRemote besides, the gate stayed green while git exited 128.

Property: the gate reads every ref name from the same source and in the same meaning as git. HEAD is read as its full
refname (`symbolic-ref --quiet HEAD`). The class: a refspec source that answers to more than one ref (a branch and a
tag of one name) is refused by git push ("src refspec main matches more than one", measured with git 2.43.0 and
2.51.1), while `rev-parse --verify` took the tag and the gate judged the tag's commit; it is NOT MEASURED now. Red
against 0c88746f.
"""
from __future__ import annotations

import subprocess

import pytest
from proofbundle.emit import generate_signer

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git


def _swap(tmp_path) -> n2c.Repo:
    """main tracks origin/main at the declaring commit; the work commit swaps the done policy to its own key, a change
    of the rules against origin/main, with a valid receipt under that key. A tag `main` at the declaring commit, and a
    branch heads/main on the remote at the work commit, with its tracking ref: against it nothing changes."""
    r = n2c.Repo(tmp_path)
    mine = generate_signer()
    n2c._write(r.path / n2c.POLICY, n2c._policy(mine))
    n2c._commit(r.path, "swap the done policy to my key")
    n2c._receipt(r.path, mine)
    _git(r.path, "tag", "main", "HEAD~1")
    _git(r.path, "push", "-q", "--no-verify", "origin", "HEAD:refs/heads/heads/main")
    _git(r.path, "fetch", "-q", "origin")
    return r


def _out(repo, *args: str) -> str:
    return _git(repo, *args).stdout.strip()


def _git_push(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "push", "--dry-run", "--porcelain", "--no-verify", *args],
                          capture_output=True, text=True, timeout=60, check=False)


def _verdict(env, repo, command: str) -> tuple[str, list]:
    _answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"]


CONFIGS = {
    "upstream": {},   # main tracks origin/main, set by `push -u`
    "auto_setup_remote": {"push.autoSetupRemote": "true", "branch.main.merge": None},
    "current": {"push.default": "current"},
}


def _configure(repo, config: dict) -> None:
    for key, value in config.items():
        if value is None:
            _git(repo, "config", "--unset", key)
        else:
            _git(repo, "config", key, value)


@pytest.mark.parametrize("config", CONFIGS)
def test_git_names_the_branch_in_full_and_pushes_main(tmp_path, config):
    """Non-vacuous: the short form is heads/main, git pushes refs/heads/main, and the remote holds a heads/main the
    gate could have compared against."""
    r = _swap(tmp_path)
    _configure(r.path, CONFIGS[config])
    assert _out(r.path, "symbolic-ref", "--short", "HEAD") == "heads/main"
    assert _out(r.path, "symbolic-ref", "--quiet", "HEAD") == "refs/heads/main"
    push = _git_push(r.path)
    assert push.returncode == 0 and "\trefs/heads/main:refs/heads/main\t" in push.stdout, push.stdout + push.stderr
    assert _out(r.path, "rev-parse", "refs/remotes/origin/heads/main") == _out(r.path, "rev-parse", "HEAD")


@pytest.mark.parametrize("config", CONFIGS)
def test_the_bare_push_is_judged_as_the_push_git_performs(env, tmp_path, config):
    r = _swap(tmp_path)
    _configure(r.path, CONFIGS[config])
    explicit = _verdict(env, r.path, "git push origin HEAD:main")
    assert explicit == ("ask", ["rules_changed"]), explicit
    assert _verdict(env, r.path, "git push") == explicit


def test_an_empty_push_remote_of_the_branch_is_read_under_its_full_name(env, tmp_path):
    """branch.main.pushRemote set empty: git takes it, pushes nothing and exits 128; the gate reads the key of the branch git means and
    leaves the push NOT MEASURED, where it had read branch.heads/main.pushRemote, found nothing and passed."""
    r = _swap(tmp_path)
    _configure(r.path, dict(CONFIGS["auto_setup_remote"], **{"branch.main.pushRemote": ""}))
    push = _git_push(r.path)
    # git 2.43.0 says "no path specified", 2.51.1 "No configured push destination": the exit and the absent push count
    assert push.returncode == 128 and "\trefs/heads/" not in push.stdout, push.stdout + push.stderr
    assert _verdict(env, r.path, "git push") == ("ask", ["push_not_measured"])


@pytest.mark.parametrize("command", ["git push origin main", "git push origin main:main",
                                     "git push origin main:refs/heads/main"])
def test_a_source_that_names_a_branch_and_a_tag_is_not_measured(env, tmp_path, command):
    """The class: git refuses a source that answers to two refs, the gate judged the tag's commit (deny with
    stale_receipt at 0c88746f, pass where the tag is at the work commit)."""
    r = _swap(tmp_path)
    push = _git_push(r.path, *command.split()[2:])
    assert push.returncode != 0 and "src refspec main matches more than one" in push.stderr, push.stderr
    assert _verdict(env, r.path, command) == ("ask", ["push_not_measured"])


def test_a_source_that_names_a_branch_and_a_tag_at_the_pushed_commit_does_not_pass(env, tmp_path):
    r = _swap(tmp_path)
    _git(r.path, "tag", "-f", "main", "HEAD")
    assert _git_push(r.path, "origin", "main").returncode != 0
    assert _verdict(env, r.path, "git push origin main") == ("ask", ["push_not_measured"])


@pytest.mark.parametrize("command", ["git push origin refs/heads/main:refs/heads/main", "git push origin HEAD:main",
                                     "git push origin heads/main:main"])
def test_control_a_source_that_names_one_ref_is_judged(env, tmp_path, command):
    r = _swap(tmp_path)
    assert _git_push(r.path, *command.split()[2:]).returncode == 0
    assert _verdict(env, r.path, command) == ("ask", ["rules_changed"])


def test_control_without_the_tag_the_short_source_is_judged(env, tmp_path):
    r = _swap(tmp_path)
    _git(r.path, "tag", "-d", "main")
    assert _out(r.path, "symbolic-ref", "--short", "HEAD") == "main"
    assert _verdict(env, r.path, "git push origin main") == ("ask", ["rules_changed"])
    assert _verdict(env, r.path, "git push") == ("ask", ["rules_changed"])


def test_control_a_valid_push_with_the_tag_still_passes(env, tmp_path):
    """No rules change, a valid receipt, the tag beside the branch: the bare push passes, as the explicit one does."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "tag", "main", "HEAD~1")
    assert _verdict(env, r.path, "git push origin HEAD:main") == ("pass", ["done"])
    assert _verdict(env, r.path, "git push") == ("pass", ["done"])


def test_an_ambiguous_source_stays_not_measured_where_the_configuration_silences_the_warning(env, tmp_path):
    """Mutation M72c: with core.warnAmbiguousRefs false git push still refuses the source (it counts the refs
    either way), while rev-parse stops warning; the gate forces the warning on for its own count."""
    r = _swap(tmp_path)
    _git(r.path, "config", "core.warnAmbiguousRefs", "false")
    push = _git_push(r.path, "origin", "main")
    assert push.returncode != 0 and "src refspec main matches more than one" in push.stderr, push.stderr
    assert _verdict(env, r.path, "git push origin main") == ("ask", ["push_not_measured"])
