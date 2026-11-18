"""Review round 8 of 2026-10-10, the class of R8-3: the remote's URL list is read with git's reset rule and fallback.

Found in the class search of R8-3 (every list configuration git reads at push, with its reset rule and precedence):
remote.<name>.url is a list, and git 2.51.1 clears it with an empty value, while git 2.43.0 keeps the empty value as a
URL and refuses the push ("no path specified"). Where no URL is left, both take the remote's own name for one
(remote.c, add_url_alias) and push to that path below the top level: they refuse where nothing is there, and write
into a repository that stands there. The gate compared the fetch and push URLs `git remote get-url` printed, found
them equal, and passed each of these pushes (measured at 8766adc7 with git 2.43.0 and 2.51.1).

Property: a push endpoint counts only where git's reading of it does not depend on the reset rule or the fallback,
which is where exactly one non-empty URL is configured; every other URL list is NOT MEASURED. Red against 8766adc7.
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

#: NOT MEASURED at the URL list, before the destination check.
NOT_MEASURED = ("ask", ["push_not_measured"], False)
COMMANDS = ("git push origin main", "git push")


def _repo(tmp_path, urls: tuple[str, ...] | None, origin_repo: bool = False) -> n2c.Repo:
    """main tracks origin/main, one commit of work with a valid receipt; then remote.origin.url replaced by `urls`
    (None: no URL at all), and with origin_repo a bare repository named origin at the top level, kept out of status."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "config", "--unset-all", "remote.origin.url")
    for url in urls or ():
        _git(r.path, "config", "--add", "remote.origin.url", url.format(remote=tmp_path / "remote.git"))
    if origin_repo:
        subprocess.run(["git", "init", "-q", "--bare", str(r.path / "origin")], check=True, capture_output=True)
        with open(r.path / ".git" / "info" / "exclude", "a", encoding="utf-8") as handle:
            handle.write("/origin/\n")
    return r


def _push(repo) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "push", "--porcelain", "--no-verify", "origin", "main"],
                          capture_output=True, text=True, timeout=60, check=False)


def _remote_main(tmp_path) -> str:
    return subprocess.run(["git", "--git-dir", str(tmp_path / "remote.git"), "rev-parse", "refs/heads/main"],
                          capture_output=True, text=True, check=True).stdout


def _verdict(env, repo, command: str) -> tuple[str, list, bool]:
    """The verdict, its reasons, and whether the resolution reached the destination check (R9-1)."""
    answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"], n2c.reached_destination(json.dumps(answer, ensure_ascii=False))


#: URL lists under which git refuses the push in 2.43.0 or 2.51.1 or both, or pushes to the remote's name.
CASES = {"empty": ("",), "none": None, "reset_to_empty": ("{remote}", "")}


@pytest.mark.parametrize("case", CASES)
def test_git_refuses_the_push(tmp_path, case):
    """Non-vacuous: git 2.43.0 refuses the empty URL; with no URL left git takes `origin` for a path, where nothing
    is. The remote stays where it was, except that git 2.43.0 pushes to the first URL of reset_to_empty before it
    refuses the empty one (exit 128 with the remote written, measured)."""
    r = _repo(tmp_path, CASES[case])
    before = _remote_main(tmp_path)
    push = _push(r.path)
    assert push.returncode == 128, (case, push.stderr)
    if case != "reset_to_empty":
        assert _remote_main(tmp_path) == before


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("case", CASES)
def test_a_url_list_git_reads_with_its_reset_or_fallback_is_not_measured(env, tmp_path, case, command):
    r = _repo(tmp_path, CASES[case])
    assert _verdict(env, r.path, command) == NOT_MEASURED, (case, command)


def test_git_pushes_to_a_repository_named_like_the_remote(tmp_path):
    """Non-vacuous: with no URL and a repository called origin at the top level, git writes there, not to the
    remote the tracking ref records."""
    r = _repo(tmp_path, None, origin_repo=True)
    before = _remote_main(tmp_path)
    assert _push(r.path).returncode == 0
    assert subprocess.run(["git", "--git-dir", str(r.path / "origin"), "rev-parse", "refs/heads/main"],
                          capture_output=True, text=True, check=True).stdout.strip() == \
        subprocess.run(["git", "-C", str(r.path), "rev-parse", "HEAD"], capture_output=True, text=True,
                       check=True).stdout.strip()
    assert _remote_main(tmp_path) == before


@pytest.mark.parametrize("command", COMMANDS)
def test_a_push_to_a_repository_named_like_the_remote_is_not_measured(env, tmp_path, command):
    r = _repo(tmp_path, None, origin_repo=True)
    assert _verdict(env, r.path, command) == NOT_MEASURED, command


@pytest.mark.parametrize("command", COMMANDS)
def test_the_cost_a_list_newer_git_resets_to_one_url_is_not_measured(env, tmp_path, command):
    """git 2.51.1 clears `nowhere` with the empty value and pushes to the remote; git 2.43.0 tries every value. The
    gate does not read which git it runs under, so the list stays NOT MEASURED in both."""
    r = _repo(tmp_path, (str(tmp_path / "nowhere.git"), "", "{remote}"))
    assert _verdict(env, r.path, command) == NOT_MEASURED, command


@pytest.mark.parametrize("command", COMMANDS)
def test_control_one_non_empty_url_keeps_the_pass(env, tmp_path, command):
    """The one URL counts, and the push resolves up to the destination check (since R9-1 that leaves it NOT MEASURED);
    the pre-push hook passes it."""
    r = _repo(tmp_path, ("{remote}",))
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path, command=command))
    assert n2c._level2(env, r.path).returncode == 0, command
