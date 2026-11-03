"""Review round 6 of 2026-10-10, the class of R6-1: every environment name with which git reads another history, other
refs, objects, index, work tree or configuration, as git 2.43.0 knows them (git(1), and the names compiled into the
installed binary, GIT_SHALLOW_FILE among them, which git(1) does not document).

Principle: the gate reads every input from the same source and in the same meaning as git; where that is not possible
the verdict stays NOT MEASURED. Each name is neutralized for the gate's own reads, read through git with the same
environment (the same source), or refused, and each has a case here. GIT_SHALLOW_FILE has its own file
(test_plugin_review_fix6_r1_shallow_source.py).

Red against f22f1c66 (the R6-1 commit): GIT_CONFIG (the push and the state digest), GIT_ICASE_PATHSPECS and
GIT_NAMESPACE. The other cases are green there and here; they show which source the gate reads.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

import _git_version as _gv
import pytest

import test_plugin_done_check as dc
import test_plugin_gate_n2c_push_done as n2c
import test_plugin_review_fix_f6_early_open as f6
from _plugin_env import plugin_env

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = n2c.env
keys = f6.keys
_clean_git_environment = n2c._clean_git_environment


def _green(tmp_path: pathlib.Path) -> n2c.Repo:
    r = n2c.Repo(tmp_path)
    r.make("valid")
    return r


def _push_answer(env: dict, repo: pathlib.Path, command: str = "git push origin main") -> tuple[str | None, dict]:
    answer, entry = n2c._level1(env, repo, command=command)
    return answer["hookSpecificOutput"].get("permissionDecision"), entry


def _stops_before_destination(env: dict, repo: pathlib.Path, command: str) -> dict:
    """The push is NOT MEASURED or denied at a step before the destination check (R9-1), never passed."""
    answer, entry = n2c._level1(env, repo, command=command)
    decision = answer["hookSpecificOutput"].get("permissionDecision")
    assert decision in ("ask", "deny") and entry["verdict"] != "pass", entry
    assert not n2c.reached_destination(json.dumps(answer, ensure_ascii=False)), answer
    return entry


def _done_check(env: dict, repo: pathlib.Path) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, "-I", str(dc.GATE), "done-check", "--repo", str(repo)], capture_output=True,
                          text=True, env=env, timeout=180, check=False)
    return proc.returncode, json.loads(proc.stdout)


# --- GIT_CONFIG: `git config` reads one file, git push, add and commit read the repository's -------------------------

def _other_remote(r: n2c.Repo, tmp_path: pathlib.Path) -> pathlib.Path:
    other = tmp_path / "other.git"
    subprocess.run(["git", "init", "--bare", "-q", str(other)], check=True, timeout=60)
    n2c._git(r.path, "remote", "add", "other", str(other))
    n2c._git(r.path, "config", "branch.main.pushRemote", "other")
    fake = tmp_path / "fake.cfg"   # the fetch refspec of origin, and no pushRemote
    fake.write_text('[remote "origin"]\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n', encoding="utf-8")
    return fake


def test_git_config_names_a_file_git_push_does_not_read(env, tmp_path):
    """Non-vacuous: with GIT_CONFIG set, `git config` finds no pushRemote and git push still pushes to `other`."""
    r = _green(tmp_path)
    fake = _other_remote(r, tmp_path)
    with_var = dict(env, GIT_CONFIG=str(fake))
    probe = subprocess.run(["git", "-C", str(r.path), "config", "--get", "branch.main.pushRemote"], capture_output=True,
                           text=True, env=with_var, timeout=60)
    assert probe.returncode == 1, probe
    dry = subprocess.run(["git", "-C", str(r.path), "push", "--dry-run", "--no-verify"], capture_output=True, text=True,
                         env=with_var, timeout=60)
    assert "other.git" in dry.stderr and "remote.git" not in dry.stderr, dry.stderr


def test_the_push_is_resolved_from_the_configuration_git_push_reads(env, tmp_path):
    r = _green(tmp_path)
    fake = _other_remote(r, tmp_path)
    entry = _stops_before_destination(dict(env, GIT_CONFIG=str(fake)), r.path, command="git push")
    assert entry["verdict"] == "ask", entry


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_the_state_digest_reads_the_configuration_git_reads(tmp_path, monkeypatch):
    """A change of the repository's configuration changes the digest also while GIT_CONFIG names another file."""
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, timeout=60)
    fake = tmp_path / "fake.cfg"
    fake.write_text("[user]\n\tname = x\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG", str(fake))
    digest = lambda: gate._bound_state_digest(str(repo), time.monotonic() + 60, plugin_env())  # noqa: E731
    before = digest()
    subprocess.run(["git", "-C", str(repo), "config", "--file", str(repo / ".git" / "config"), "core.fsmonitor",
                    "marker-program"], check=True, timeout=60)
    assert before is not None and digest() not in (None, before)


# --- pathspec names: the gate's own paths are literal ------------------------------------------------------------------

def _case_variant(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository whose HEAD holds .PROOFBUNDLE/EVIDENCE.JSON and no .proofbundle/evidence.json."""
    repo = f6._repo(tmp_path)
    dc._write(repo / ".PROOFBUNDLE" / "EVIDENCE.JSON", "{}")
    dc._commit(repo, "a file that differs from the declaration in case only")
    return repo


@pytest.mark.parametrize("name", ["GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
                                  "GIT_LITERAL_PATHSPECS"])
def test_a_pathspec_name_does_not_change_what_the_gates_paths_name(env, tmp_path, name):
    """Without a declaration there is no done check (inactive); a pathspec name keeps it so."""
    repo = _case_variant(tmp_path)
    assert _done_check(env, repo)[1]["verdict"] == "inactive"
    code, report = _done_check(dict(env, **{name: "1"}), repo)
    assert report["verdict"] == "inactive", report
    assert f6.stop(dict(env, **{name: "1"}), repo) is None


def test_git_icase_pathspecs_changes_what_the_declarations_path_names(env, tmp_path):
    """Non-vacuous: with GIT_ICASE_PATHSPECS git lists the commit of the other file under the declaration's path, and
    ls-tree refuses the path, where both find nothing without it."""
    repo = _case_variant(tmp_path)
    icase = dict(env, GIT_ICASE_PATHSPECS="1")
    run = lambda *args, e=env: subprocess.run(["git", "-C", str(repo), *args], capture_output=True,  # noqa: E731
                                              text=True, env=e, timeout=60)
    assert run("rev-list", "HEAD", "--", gate.DECLARATION).stdout == ""
    assert run("rev-list", "HEAD", "--", gate.DECLARATION, e=icase).stdout.strip() == dc._git(repo, "rev-parse", "HEAD")
    assert run("ls-tree", "HEAD", "--", gate.DECLARATION).returncode == 0
    refused = run("ls-tree", "HEAD", "--", gate.DECLARATION, e=icase)
    assert refused.returncode == 128 and "pathspec magic not supported" in refused.stderr, refused


# --- GIT_NAMESPACE: the push lands under refs/namespaces/ on the remote ------------------------------------------------

def test_git_namespace_sends_the_push_to_another_remote_ref(env, tmp_path):
    """Non-vacuous: a real push with GIT_NAMESPACE writes refs/namespaces/x/refs/heads/main and leaves main."""
    r = _green(tmp_path)
    before = n2c._rev(r.path, "origin/main")
    subprocess.run(["git", "-C", str(r.path), "push", "-q", "--no-verify", "origin", "main"], check=True,
                   capture_output=True, env=dict(env, GIT_NAMESPACE="x"), timeout=60)
    refs = subprocess.run(["git", "--git-dir", str(tmp_path / "remote.git"), "for-each-ref", "--format=%(refname) "
                           "%(objectname)"], capture_output=True, text=True, timeout=60).stdout.split("\n")
    assert f"refs/heads/main {before}" in refs
    assert f"refs/namespaces/x/refs/heads/main {n2c._rev(r.path, 'HEAD')}" in refs


@pytest.mark.parametrize("command", ["git push origin main", "git push"])
def test_level_1_does_not_judge_a_namespaced_push_against_the_tracking_ref(env, tmp_path, command):
    r = _green(tmp_path)
    entry = _stops_before_destination(dict(env, GIT_NAMESPACE="x"), r.path, command=command)
    assert entry["verdict"] == "ask", entry


def test_level_2_reads_the_remote_state_git_reports_under_the_namespace(env, tmp_path):
    """The pre-push hook gets the remote's state from git: under a namespace the target is new there, so the push is
    NOT MEASURED (the target-absent block), never a pass against main."""
    r = _green(tmp_path)
    recorded = tmp_path / "pre-push-stdin"
    hook = r.path / ".git" / "hooks" / "pre-push"
    hook.write_text(f"#!/bin/sh\ncat > '{recorded}'\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    subprocess.run(["git", "-C", str(r.path), "push", "origin", "main"], capture_output=True,
                   env=dict(env, GIT_NAMESPACE="x"), timeout=60)
    line = recorded.read_text(encoding="utf-8")
    assert line == f"refs/heads/main {n2c._rev(r.path, 'HEAD')} refs/heads/main {'0' * 40}\n", line  # git's report
    hook.unlink()
    proc = subprocess.run([sys.executable, "-I", str(dc.GATE), "pre-push", "origin", "remote.git"], input=line,
                          capture_output=True, text=True, cwd=str(r.path), env=dict(env, GIT_NAMESPACE="x"),
                          timeout=180, check=False)
    assert proc.returncode != 0, proc.stdout + proc.stderr


def test_control_an_empty_namespace_is_no_namespace(env, tmp_path):
    r = _green(tmp_path)
    answer, entry = n2c._level1(dict(env, GIT_NAMESPACE=""), r.path, command="git push origin main")
    n2c.assert_destination_not_measured(answer, entry)   # resolved as without a namespace up to the destination (R9-1)
    assert n2c._level2(dict(env, GIT_NAMESPACE=""), r.path).returncode == 0


def test_a_namespace_git_cannot_expand_fails_every_read(env, tmp_path):
    """GIT_NAMESPACE=/ makes git stop ("bad git namespace path"); the gate's reads fail with it, never a pass."""
    r = _green(tmp_path)
    _stops_before_destination(dict(env, GIT_NAMESPACE="/"), r.path, command="git push origin main")


# --- names that are neutralized for the gate's reads ------------------------------------------------------------------

def test_a_replace_ref_under_another_base_does_not_rewrite_the_gates_history(env, tmp_path, keys):
    """GIT_REPLACE_REF_BASE with a replacement that makes B a root: GIT_NO_REPLACE_OBJECTS of the gate wins, the base
    stays A, the work outside the paths blocks."""
    import test_plugin_review_fix6_r1_shallow_source as sh
    repo, commits = sh._history(tmp_path, keys)
    (repo / ".git" / "shallow").unlink()
    tree = dc._git(repo, "rev-parse", f"{commits['B']}^{{tree}}")
    fake = dc._git(repo, "commit-tree", tree, "-m", "B without a parent")
    dc._git(repo, "update-ref", f"refs/other-replace/{commits['B']}", fake)
    with_var = dict(env, GIT_REPLACE_REF_BASE="refs/other-replace/")
    assert dc._git(repo, "rev-list", "--parents", "-n", "1", commits["B"], env=with_var) == commits["B"]
    code, report = _done_check(with_var, repo)
    assert (code, report["reason_id"]) == (1, "outside_paths"), report


def test_an_index_named_by_git_index_file_does_not_stand_for_the_working_files(env, tmp_path, keys):
    """The gate reads the working state with an index of its own: an index that stages other content changes
    nothing, the receipt of the working files passes as without the name."""
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,))
    dc._commit(repo, "the order")
    dc._run(repo, keys.signer, UNIT)
    index = tmp_path / "other-index"
    dc._git(repo, "read-tree", "--empty", env=dict(env, GIT_INDEX_FILE=str(index)))
    assert _done_check(dict(env, GIT_INDEX_FILE=str(index)), repo)[1]["verdict"] == "pass"


# --- names read through git with the same environment (the same source) -----------------------------------------------

def test_git_dir_and_git_work_tree_name_the_repository_git_works_on(env, tmp_path, keys):
    """The Stop hook in a repository with a passing receipt, the names pointing at a repository whose receipt is
    missing: git works on the second, and the gate judges the second."""
    green = f6._repo(tmp_path, "green")
    dc._declare_order(green, keys.public, checks=(UNIT,))
    dc._commit(green, "the order")
    dc._run(green, keys.signer, UNIT)
    red = f6._repo(tmp_path, "red")
    dc._declare_order(red, keys.public, checks=(UNIT,))
    dc._commit(red, "the order")
    assert f6.stop(env, green) is not None and "decision" not in f6.stop(env, green)
    moved = dict(env, GIT_DIR=str(red / ".git"), GIT_WORK_TREE=str(red))
    answer = f6.stop(moved, green)
    assert answer is not None and answer.get("decision") == "block", answer


def test_git_ceiling_directories_is_gits_own_answer_for_no_repository(env, tmp_path, keys):
    """Below a ceiling git finds no repository: the gate stays inactive, and git itself can neither commit nor push
    there, so no work reaches the repository through that environment."""
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,))
    dc._commit(repo, "the order")
    below = repo / "src"
    ceiling = dict(env, GIT_CEILING_DIRECTORIES=str(repo))
    assert f6.stop(ceiling, below) is None
    commit = subprocess.run(["git", "-C", str(below), "commit", "--allow-empty", "-m", "x"], capture_output=True,
                            text=True, env=ceiling, timeout=60)
    assert commit.returncode == 128 and "not a git repository" in commit.stderr, commit


def test_an_object_directory_without_the_objects_blocks(env, tmp_path, keys):
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,))
    dc._commit(repo, "the order")
    dc._run(repo, keys.signer, UNIT)
    empty = tmp_path / "objects"
    empty.mkdir()
    answer = f6.stop(dict(env, GIT_OBJECT_DIRECTORY=str(empty)), repo)
    assert answer is not None and answer.get("decision") == "block", answer


def test_configuration_given_in_the_environment_is_read_as_git_reads_it(env, tmp_path):
    """GIT_CONFIG_COUNT names a pushRemote git push follows; the gate resolves the same remote, which it does not
    track, so the bare push is NOT MEASURED."""
    r = _green(tmp_path)
    _other_remote(r, tmp_path)
    n2c._git(r.path, "config", "--unset", "branch.main.pushRemote")
    injected = dict(env, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="branch.main.pushRemote", GIT_CONFIG_VALUE_0="other")
    entry = _stops_before_destination(injected, r.path, command="git push")
    assert entry["verdict"] == "ask", entry


def test_a_repository_git_will_not_read_as_ones_own_blocks(env, tmp_path, keys):
    """GIT_TEST_ASSUME_DIFFERENT_OWNER makes git refuse the repository (dubious ownership): a read that failed, never
    'no repository' (R5-1)."""
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,))
    dc._commit(repo, "the order")
    answer = f6.stop(dict(env, GIT_TEST_ASSUME_DIFFERENT_OWNER="1"), repo)
    assert answer is not None and answer.get("decision") == "block", answer
