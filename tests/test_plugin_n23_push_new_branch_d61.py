"""D61, addendum 1 to follow-up note 23: a push that creates a branch in a repository of b7n0de is resolved and checked.

Measured on account A's screen at 13:45Z and 13:54Z on 2026-10-17: `git -C <abs> push origin <sha>:refs/heads/<new>` and
`git -C <abs> push origin HEAD:refs/heads/fix/<new>`, the push form the gate itself names, asked with D3, because no
push to a branch the remote does not have is resolved (R9-1, TARGET_ABSENT_TEXT). Every new pull request starts so.

The rule: `git -C <abs> push <remote> <source>:refs/heads/<name>` as the whole command, under Claude Code, with the
source HEAD, a branch or a literal full object name, the remote a repository of b7n0de on github.com whose fetch profile
of D45 finds nothing. The gate measures the remote's branches and tags with its own `git ls-remote`, the form D59
measured; the push sends what the source reaches and no measured branch or tag holds. Those commits get the checks of a
push to an existing branch: a missing or failing piece of evidence denies (D26), the done check at the source, and the
evidence rules against those at the commits on the remote the new branch starts from. main, a release branch, a tag, a
force, more than one refspec, a remote outside b7n0de, a remote whose refs the gate cannot measure and every other form
keep the answer of D3.

The repository is the one of tests/test_plugin_gate_n2c_push_done.py with evidence and a valid receipt, its origin
set to https://github.com/b7n0de/r with the one fetch rule of a clone. No network: a stand-in `git` first on PATH
answers `ls-remote` with the refs of the local bare repository the fixture pushed to, and hands every other call to
git; with PB_TEST_LS_REMOTE=fail its ls-remote fails as an unreachable remote does. RED at 9f578c2a (and 4b4d8c91,
D59): the three free cases and the measured stale ref; the others are controls, green at both.
"""
from __future__ import annotations

import json
import pathlib
import shutil

import pytest

import test_plugin_gate_n2c_push_done as n2c
from _gate_answer import long_text

gate = n2c.gate
pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git
GIT = shutil.which("git")
FREE_ID = "verified_new_branch"


def _stand_in(tmp_path: pathlib.Path, env: dict) -> dict:
    """The hook's environment with the stand-in git first on PATH and the bare repository it reads."""
    folder = tmp_path / "git-stand-in"
    folder.mkdir()
    (folder / "git").write_text(
        "#!/bin/sh\n"
        "# test stand-in for the network: ls-remote reads the bare repository PB_TEST_REMOTE names, with the options\n"
        "# the gate gives it (N2324-2: a gate that leaves out --tags must not get the tags anyway)\n"
        "for a in \"$@\"; do\n"
        "  if [ -n \"$ls\" ]; then case \"$a\" in -*) opts=\"$opts $a\";; esac; fi\n"
        "  [ \"$a\" = ls-remote ] && ls=1\n"
        "done\n"
        "if [ -n \"$ls\" ]; then\n"
        "  [ \"$PB_TEST_LS_REMOTE\" = fail ] && { echo 'fatal: unable to access' >&2; exit 128; }\n"
        f"  exec {GIT} ls-remote $opts \"$PB_TEST_REMOTE\"\n"
        "fi\n"
        f"exec {GIT} \"$@\"\n", encoding="utf-8")
    (folder / "git").chmod(0o755)
    return {**env, "PATH": f"{folder}:{env['PATH']}", "PB_TEST_REMOTE": str(tmp_path / "remote.git")}


def _github(repo: pathlib.Path, owner: str = "b7n0de") -> None:
    """origin at https://github.com/<owner>/r with the one fetch rule of a clone (the fixture's recording rules go)."""
    _git(repo, "remote", "set-url", "origin", f"https://github.com/{owner}/r")
    _git(repo, "config", "--unset-all", "remote.origin.fetch")
    _git(repo, "config", "--add", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")


@pytest.fixture
def r(tmp_path):
    repo = n2c.Repo(tmp_path, evidence=True)
    repo.make("valid")
    _github(repo.path)
    return repo


def _push(env: dict, r, command: str, host: str = "claude"):
    answer, entry = n2c._level1(env, r.path, host=host, command=command.format(a=r.path))
    return answer, entry


def _free(entry: dict) -> bool:
    return (entry["verdict"], entry["reason_ids"]) == ("pass", [FREE_ID])


# --- resolved and free -----------------------------------------------------------------------------------------------

def test_D61_a_new_feature_branch_from_HEAD_is_free(env, r, tmp_path):
    answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/fix/budget-caps")
    assert _free(entry), entry
    assert answer == {}, answer          # D53: a pass prints nothing


def test_D61_a_new_branch_from_a_branch_is_free(env, r, tmp_path):
    _git(r.path, "branch", "topic")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin topic:refs/heads/topic")
    assert _free(entry), entry


def test_D61_a_new_branch_from_a_full_sha_is_free(env, r, tmp_path):
    sha = n2c._rev(r.path, "HEAD")
    _answer, entry = _push(_stand_in(tmp_path, env), r, f"git -C {{a}} push origin {sha}:refs/heads/claude/ser-drafts")
    assert _free(entry), entry




# --- a measured remote, not the local tracking refs ------------------------------------------------------------------

def test_D61_a_stale_tracking_ref_does_not_hide_a_commit_the_push_sends(env, r, tmp_path):
    """refs/remotes/origin/gone names a commit the remote does not hold (a branch deleted after a merge). `rev-list
    --not --remotes=origin` would leave it out; git push sends it. The gate subtracts only what the remote holds as it
    measured, so the commit is checked, and its broken evidence denies."""
    bad = r.path / ".proofbundle" / "b.json"
    good = bad.read_text(encoding="utf-8")
    bundle = json.loads(good)
    bundle["payload_b64"] = bundle["payload_b64"][:-4] + "AAAA"
    bad.write_text(json.dumps(bundle), encoding="utf-8")
    n2c._commit(r.path, "a commit with broken evidence")
    stale = n2c._rev(r.path, "HEAD")
    _git(r.path, "update-ref", "refs/remotes/origin/gone", stale)
    r.sign_evidence()
    n2c._commit(r.path, "valid evidence again on top")
    r.make("valid")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert entry["verdict"] == "deny", entry


def test_D61_a_commit_only_a_tag_on_the_remote_holds_is_not_sent(env, r, tmp_path):
    """N2324-2: the gate subtracts the remote's tags as git push does, not only its branches. A commit
    with broken evidence that only an annotated tag on the remote holds is not sent (case c5 of the ground truth of
    D61: one commit sent, not two), so the push of a new branch above it is free; a gate that leaves the tags out
    counts that commit as sent, and its broken evidence denies."""
    bad = r.path / ".proofbundle" / "b.json"
    bundle = json.loads(bad.read_text(encoding="utf-8"))
    bundle["payload_b64"] = bundle["payload_b64"][:-4] + "AAAA"
    bad.write_text(json.dumps(bundle), encoding="utf-8")
    n2c._commit(r.path, "a commit with broken evidence, which a tag on the remote holds")
    _git(r.path, "tag", "-a", "-m", "v1", "v1")
    _git(r.path, "push", "-q", "--no-verify", str(tmp_path / "remote.git"), "refs/tags/v1")
    r.sign_evidence()
    n2c._commit(r.path, "valid evidence again on top")
    r.make("valid")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert _free(entry), entry


# --- keeps the answer of D3, or denies -------------------------------------------------------------------------------

KEEPS = {
    "main": "git -C {a} push origin HEAD:refs/heads/main",
    "a release branch": "git -C {a} push origin HEAD:refs/heads/release/6.3.2",
    "release": "git -C {a} push origin HEAD:refs/heads/release",
    "a tag": "git -C {a} push origin HEAD:refs/tags/v9",
    "a force sign": "git -C {a} push origin +HEAD:refs/heads/topic",
    "--force": "git -C {a} push --force origin HEAD:refs/heads/topic",
    "--force-with-lease": "git -C {a} push --force-with-lease origin HEAD:refs/heads/topic",
    "two refspecs": "git -C {a} push origin HEAD:refs/heads/topic HEAD:refs/heads/other",
    "a short destination": "git -C {a} push origin HEAD:topic",
    "no -C": "git push origin HEAD:refs/heads/topic",
    "a chain": "git -C {a} push origin HEAD:refs/heads/topic && echo done",
    "a redirection": "git -C {a} push origin HEAD:refs/heads/topic 2>&1",
    "a prefix assignment": "GIT_TRACE=1 git -C {a} push origin HEAD:refs/heads/topic",
    "a URL as the remote": "git -C {a} push https://github.com/b7n0de/r HEAD:refs/heads/topic",
    "an option": "git -C {a} push -u origin HEAD:refs/heads/topic",
    "an abbreviated sha": "git -C {a} push origin {short}:refs/heads/topic",
}


@pytest.mark.parametrize("case", list(KEEPS))
def test_D61_control_every_other_form_keeps_the_ask(env, r, tmp_path, case):
    command = KEEPS[case].replace("{short}", n2c._rev(r.path, "HEAD")[:12])
    _answer, entry = _push(_stand_in(tmp_path, env), r, command)
    assert entry["verdict"] in ("ask", "deny") and FREE_ID not in entry["reason_ids"], (case, entry)


def test_D61_control_a_remote_outside_b7n0de_asks_and_says_why(env, r, tmp_path):
    _github(r.path, owner="someone-else")
    answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    assert "is not a repository of b7n0de on github.com" in long_text(answer) and "D61" in long_text(answer)


def test_D61_control_remote_refs_that_cannot_be_measured_keep_the_ask(env, r, tmp_path):
    stand_in = {**_stand_in(tmp_path, env), "PB_TEST_LS_REMOTE": "fail"}
    answer, entry = _push(stand_in, r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    assert "could not measure the remote's branches and tags" in long_text(answer), long_text(answer)
    assert "exit status 128" in long_text(answer) and "unable to access" not in long_text(answer)   # D49


def test_D61_control_a_branch_the_remote_already_has_is_no_creation(env, r, tmp_path):
    _git(r.path, "push", "-q", str(tmp_path / "remote.git"), "HEAD:refs/heads/topic")
    answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert entry["verdict"] == "ask" and "already has refs/heads/topic" in long_text(answer), entry


def test_D61_control_a_fetch_profile_finding_keeps_the_ask(env, r, tmp_path):
    _git(r.path, "config", "http.proxy", "http://127.0.0.1:3128")
    answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert entry["verdict"] == "ask" and "the fetch profile of D45 found" in long_text(answer), entry


def test_D61_control_a_pushurl_keeps_the_ask(env, r, tmp_path):
    _git(r.path, "config", "remote.origin.pushurl", "https://github.com/b7n0de/elsewhere")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert entry["verdict"] == "ask" and FREE_ID not in entry["reason_ids"], entry


def test_D61_a_missing_receipt_denies(env, tmp_path):
    repo = n2c.Repo(tmp_path, evidence=True)
    repo.make("missing")
    _github(repo.path)
    _answer, entry = _push(_stand_in(tmp_path, env), repo, "git -C {a} push origin HEAD:refs/heads/topic")
    assert (entry["verdict"], entry["reason_ids"]) == ("deny", ["no_receipt"]), entry


def test_D61_a_red_test_run_denies(env, tmp_path):
    repo = n2c.Repo(tmp_path, evidence=True)
    repo.make("red")
    _github(repo.path)
    _answer, entry = _push(_stand_in(tmp_path, env), repo, "git -C {a} push origin HEAD:refs/heads/topic")
    assert (entry["verdict"], entry["reason_ids"]) == ("deny", ["not_done"]), entry


def test_D61_evidence_that_does_not_verify_denies(env, r, tmp_path):
    bad = r.path / ".proofbundle" / "b.json"
    bundle = json.loads(bad.read_text(encoding="utf-8"))
    bundle["payload_b64"] = bundle["payload_b64"][:-4] + "AAAA"
    bad.write_text(json.dumps(bundle), encoding="utf-8")
    n2c._commit(r.path, "broken evidence")
    r.make("valid")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert entry["verdict"] == "deny", entry


def test_D61_a_change_of_the_evidence_rules_asks(env, r, tmp_path):
    r._declare([])
    n2c._commit(r.path, "drop the evidence items")
    r.make("valid")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["rules_changed"]), entry


def test_D61_control_a_history_that_shares_nothing_with_the_remote_keeps_the_ask(env, r, tmp_path):
    """An orphan branch with valid evidence and a fresh receipt: nothing on the remote it starts from, so no evidence
    rule to compare with, and the ask of D3 says so."""
    _git(r.path, "checkout", "-q", "--orphan", "alone")
    n2c._commit(r.path, "an orphan")
    r.make("valid")
    answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin alone:refs/heads/alone")
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    assert "share no history with the remote's branches and tags" in long_text(answer), long_text(answer)


FORM = {"git -C /r push origin HEAD:refs/heads/topic": ("/r", "origin", "HEAD", "topic"),
        "git -C /r push up feature/x:refs/heads/fix/y": ("/r", "up", "feature/x", "fix/y"),
        f"git -C /r push origin {'a' * 40}:refs/heads/t": ("/r", "origin", "a" * 40, "t"),
        "git -C /r push origin HEAD:refs/heads/main": None, "git -C /r push origin HEAD:refs/heads/release": None,
        "git -C /r push origin HEAD:refs/heads/release/6.3.2": None,
        "git -C /r push origin HEAD:refs/heads/HEAD": None, "git -C /r push origin +HEAD:refs/heads/t": None,
        "git -C /r push origin HEAD:refs/tags/t": None, "git -C /r push origin HEAD:t": None,
        "git -C r push origin HEAD:refs/heads/t": None, "git -C /r push -q origin HEAD:refs/heads/t": None,
        "git -C /r push origin 'HEAD:refs/heads/t'": None, "git -C /r push origin HEAD:refs/heads/a..b": None,
        "git -C /r push origin HEAD:refs/heads/t*": None, "git -C /r push origin ma\\in:refs/heads/t": None,
        "git -C /r push origin $X:refs/heads/t": None,
        # a comment adds no word: the shell runs the same push (_drop_comments, review round 10, R10-1)
        "git -C /r push origin HEAD:refs/heads/t # c": ("/r", "origin", "HEAD", "t")}


@pytest.mark.parametrize("command", list(FORM))
def test_D61_the_form_and_the_names_that_keep_the_ask(command):
    assert gate._new_branch_push_form(command) == FORM[command], command


def test_D61_control_under_codex_it_is_never_free(env, r, tmp_path):
    stand_in = {**_stand_in(tmp_path, env)}
    _answer, entry = _push(stand_in, r, "git -C {a} push origin HEAD:refs/heads/topic", host="codex")
    assert entry["verdict"] != "pass" and FREE_ID not in entry["reason_ids"], entry


def test_D61_an_ask_at_a_sent_commit_asks_with_its_own_reason(env, r, tmp_path):
    """A sent commit whose declaration holds an empty evidence list and no done check: its own ask (empty_declaration)
    is the push's answer, before the rules are compared (as in _evaluate_targets; the mutant run of the delivery)."""
    n2c._write(r.path / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": []})
    n2c._commit(r.path, "an empty evidence list and no done check")
    _answer, entry = _push(_stand_in(tmp_path, env), r, "git -C {a} push origin HEAD:refs/heads/topic")
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["empty_declaration"]), entry
