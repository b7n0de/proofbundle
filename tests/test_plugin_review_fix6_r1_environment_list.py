"""Review round 6 of 2026-10-10, the class of R6-1, as a list: each environment variable of git 2.43.0 (git(1) and the
names compiled into the installed binary) with which git reads another history, other refs, objects, index, work
tree, configuration or attributes, with the gate's treatment and a catch case.

Treatment, one of three: the gate's reads take the variable from the same source as the git it judges (they run in
the push's own environment); the variable is neutralized for the gate's reads; or the gate refuses to judge under it.
The free forms of `git add` and `git commit` are refused under every such name (the state check frees only the names
it knows to be inert). The catch cases of the earlier files of this round are not repeated here
(tests/test_plugin_review_fix6_r1_environment.py, tests/test_plugin_review_fix6_r1_shallow_source.py,
tests/test_plugin_review_fix6_r2_trace_output.py). The function contract pins the gate's own environment, so a lock
that has no read today (GIT_LITERAL_PATHSPECS: the gate names only a fixed path without pattern characters and
`ls-tree` paths, which git reads without patterns, measured) cannot fall away unseen (mutation M61c).
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess

import pytest

import test_plugin_done_check as dc
import test_plugin_gate_k_nw_2_b as knw
import test_plugin_gate_n2c_push_done as n2c
import test_plugin_review_fix_f6_early_open as f6
import test_plugin_review_fix6_r1_environment as r1e
from _gate_answer import Silent

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment


# --- the gate's own environment ------------------------------------------------------------------------------------

SAME_SOURCE = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
               "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
               "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
               "GIT_CONFIG_PARAMETERS", "GIT_SHALLOW_FILE", "GIT_NAMESPACE", "GIT_INDEX_FILE", "GIT_ATTR_SOURCE",
               "GIT_TEST_ASSUME_DIFFERENT_OWNER")
DROPPED = ("GIT_CONFIG", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_TRACE",
           "GIT_TRACE_SETUP", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE_PERFORMANCE")
SET = {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull, "GIT_NO_LAZY_FETCH": "1",
       "GIT_LITERAL_PATHSPECS": "1", "LC_ALL": "C"}


def test_the_gates_own_git_environment(monkeypatch):
    """Function contract of _read_env: the same-source names pass through as the host set them, the neutralized ones
    are dropped or set to the gate's value, whatever the host set."""
    for name in SAME_SOURCE + DROPPED:
        monkeypatch.setenv(name, "host-value")
    for name in SET:
        monkeypatch.setenv(name, "host-value")
    monkeypatch.setenv("LANGUAGE", "de")
    env = gate._read_env()
    assert {name: env.get(name) for name in SAME_SOURCE} == {name: "host-value" for name in SAME_SOURCE}
    assert [name for name in DROPPED if name in env] == []
    assert {name: env.get(name) for name in SET} == SET
    assert "LANGUAGE" not in env


# --- the free forms ------------------------------------------------------------------------------------------------

def _free_form_values(repo: pathlib.Path, tmp: pathlib.Path) -> dict:
    """A value per name that leaves git able to read the repository, so the check reaches the environment."""
    git = repo / ".git"
    return {"GIT_COMMON_DIR": str(git), "GIT_OBJECT_DIRECTORY": str(git / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(git / "objects"), "GIT_WORK_TREE": str(repo),
            "GIT_CEILING_DIRECTORIES": str(tmp / "x"), "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
            "GIT_SHALLOW_FILE": str(tmp / "x"), "GIT_NAMESPACE": "x", "GIT_REPLACE_REF_BASE": "refs/x/",
            "GIT_GRAFT_FILE": str(tmp / "x"), "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG": str(tmp / "x"),
            "GIT_LITERAL_PATHSPECS": "1", "GIT_GLOB_PATHSPECS": "1", "GIT_NOGLOB_PATHSPECS": "1",
            "GIT_ICASE_PATHSPECS": "1", "GIT_ATTR_SOURCE": "HEAD", "GIT_QUARANTINE_PATH": str(tmp / "x"),
            "GIT_IMPLICIT_WORK_TREE": "1", "GIT_TEST_FSMONITOR": str(tmp / "x"), "GIT_REF_PARANOIA": "1",
            "GIT_INDEX_VERSION": "4", "GIT_PREFIX": "sub/", "GIT_COMMIT_GRAPH_PARANOIA": "1",
            "GIT_NO_LAZY_FETCH": "1", "GIT_TEST_ASSUME_DIFFERENT_OWNER": "0"}


FREE_FORM_NAMES = sorted(_free_form_values(pathlib.Path("r"), pathlib.Path("t")))


@pytest.mark.parametrize("name", FREE_FORM_NAMES)
def test_each_name_keeps_git_add_and_commit_not_free(tmp_path, monkeypatch, name):
    repo = knw._repo(tmp_path)
    monkeypatch.setenv(name, _free_form_values(repo, tmp_path)[name])
    knw._refused("git add a.txt", repo, name)


# --- the gate's reads: same source ---------------------------------------------------------------------------------

def _done_repo(tmp_path: pathlib.Path, keys) -> pathlib.Path:
    repo = f6._repo(tmp_path)
    dc._declare_order(repo, keys.public, checks=(UNIT,), paths=["src/*"])
    dc._commit(repo, "the order")
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "the work")
    dc._run(repo, keys.signer, UNIT)
    return repo


def _done(answer: dict | None) -> bool:
    """A done end: since D53 it prints nothing, and its log line names the done verdict."""
    return isinstance(answer, Silent) and answer.entry["reason_ids"] == ["done"]


def test_objects_git_finds_in_an_alternate_are_the_objects_the_gate_reads(env, tmp_path, keys):
    """GIT_OBJECT_DIRECTORY on an empty directory and the repository's objects as an alternate: git reads every
    object, and so does the gate; the Stop hook says done (with the empty directory alone it blocks, see the earlier
    file of this round)."""
    repo = _done_repo(tmp_path, keys)
    empty = tmp_path / "empty-objects"
    empty.mkdir()
    moved = dict(env, GIT_OBJECT_DIRECTORY=str(empty), GIT_ALTERNATE_OBJECT_DIRECTORIES=str(repo / ".git" / "objects"))
    log = subprocess.run(["git", "-C", str(repo), "log", "--format=%s", "-1"], capture_output=True, text=True,
                         env=moved, timeout=60, check=False)
    assert log.returncode == 0 and log.stdout.strip() == "the work", log
    assert _done(f6.stop(moved, repo, "claude")), "the gate reads the objects git reads"


def test_a_common_directory_git_cannot_read_head_from_blocks(env, tmp_path, keys):
    """GIT_COMMON_DIR naming another repository's .git: git takes refs and objects from there and cannot read HEAD's
    commit; the gate reads the same and blocks, it never reads the repository of the working directory instead."""
    repo = _done_repo(tmp_path, keys)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(other)], check=True, timeout=60)
    common = dict(env, GIT_COMMON_DIR=str(other / ".git"))
    log = subprocess.run(["git", "-C", str(repo), "log", "-1"], capture_output=True, text=True, env=common,
                         timeout=60, check=False)
    assert log.returncode != 0, log
    answer = f6.stop(common, repo, "claude")
    assert answer is not None and answer.get("decision") == "block", answer


@pytest.mark.parametrize("scope", ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS"])
def test_configuration_of_every_scope_git_push_reads_is_read_by_the_gate(env, tmp_path, scope):
    """A pushRemote git push follows, given through a configuration file of another scope or GIT_CONFIG_PARAMETERS:
    the gate resolves the same remote, which it does not track, so the bare push is NOT MEASURED."""
    r = r1e._green(tmp_path)
    r1e._other_remote(r, tmp_path)
    n2c._git(r.path, "config", "--unset", "branch.main.pushRemote")
    if scope == "GIT_CONFIG_PARAMETERS":
        injected = dict(env, GIT_CONFIG_PARAMETERS="'branch.main.pushremote'='other'")
    else:
        file = tmp_path / f"{scope}.cfg"
        file.write_text('[branch "main"]\n\tpushRemote = other\n', encoding="utf-8")
        injected = dict(env, **{scope: str(file)})
    dry = subprocess.run(["git", "-C", str(r.path), "push", "--dry-run", "--no-verify"], capture_output=True,
                         text=True, env=injected, timeout=60, check=False)
    assert "other.git" in dry.stderr, dry.stderr   # non-vacuous: git pushes to `other`
    entry = r1e._stops_before_destination(injected, r.path, command="git push")
    assert entry["verdict"] == "ask", entry


def test_control_a_system_file_git_does_not_read_is_not_read(env, tmp_path):
    """GIT_CONFIG_NOSYSTEM: git skips the system file, its pushRemote included, and the push to origin is resolved up
    to the destination check (since R9-1 the destination check leaves it NOT MEASURED; Level 2 passes it)."""
    r = r1e._green(tmp_path)
    r1e._other_remote(r, tmp_path)
    n2c._git(r.path, "config", "--unset", "branch.main.pushRemote")
    file = tmp_path / "system.cfg"
    file.write_text('[branch "main"]\n\tpushRemote = other\n', encoding="utf-8")
    skipped = dict(env, GIT_CONFIG_SYSTEM=str(file), GIT_CONFIG_NOSYSTEM="1")
    answer, entry = n2c._level1(skipped, r.path, command="git push")
    n2c.assert_destination_not_measured(answer, entry)
    assert n2c._level2(skipped, r.path).returncode == 0


# --- the gate's reads: neutralized or without a read of the gate ---------------------------------------------------

def test_no_gate_read_starts_the_fsmonitor_program_git_test_fsmonitor_names(env, tmp_path, keys):
    """git status starts the program GIT_TEST_FSMONITOR names (measured); every read of the gate runs with
    core.fsmonitor off or reads no index, so the program never runs and the verdicts stay those without it."""
    repo = _done_repo(tmp_path, keys)
    marker = tmp_path / "fsmonitor.marker"
    program = tmp_path / "fsmonitor.sh"
    program.write_text(f"#!/bin/sh\necho ran >> {marker}\n", encoding="utf-8")
    program.chmod(0o755)
    named = dict(env, GIT_TEST_FSMONITOR=str(program))
    subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, env=named, timeout=60,
                   check=False)
    assert marker.exists(), "non-vacuous: git status starts the program"
    marker.unlink()
    assert _done(f6.stop(named, repo, "claude"))
    code, report = r1e._done_check(named, repo)
    assert (code, report["verdict"]) == (0, "pass"), report
    assert not marker.exists(), marker.read_text()


def _outcome(answer: dict, entry: dict) -> tuple:
    """The full outcome of a Level 1 push: decision, reason ids, and whether it reached the destination check."""
    return (answer["hookSpecificOutput"].get("permissionDecision"), entry["verdict"], entry["reason_ids"],
            n2c.reached_destination(json.dumps(answer, ensure_ascii=False)))


NO_READ_EFFECT = {"GIT_INDEX_VERSION": "4", "GIT_IMPLICIT_WORK_TREE": "0", "GIT_REF_PARANOIA": "1",
                  "GIT_PREFIX": "sub/", "GIT_ATTR_SOURCE": "HEAD~1", "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
                  "GIT_COMMIT_GRAPH_PARANOIA": "1", "GIT_DEFAULT_HASH": "sha256", "GIT_QUARANTINE_PATH": "quarantine"}


@pytest.mark.parametrize("name", sorted(NO_READ_EFFECT))
def test_a_name_without_effect_on_the_gates_reads_keeps_its_verdicts(env, tmp_path, name):
    """Each of these changes what git writes (an index format, a new repository's hash, ref updates under quarantine),
    how it reports or where an alias runs, or reads attributes the gate never asks for (it reads blobs raw and working
    files itself): the push with a valid receipt reaches the destination check (since R9-1 NOT MEASURED there) and
    passes Level 2, and the one without is denied, as without the name."""
    value = NO_READ_EFFECT[name]
    if name == "GIT_QUARANTINE_PATH":
        value = str(tmp_path / value)
    r = n2c.Repo(tmp_path)
    r.make("valid")
    named = dict(env, **{name: value})
    answer, entry = n2c._level1(named, r.path)
    n2c.assert_destination_not_measured(answer, entry)
    assert _outcome(answer, entry) == _outcome(*n2c._level1(env, r.path))
    assert n2c._level2(named, r.path).returncode == 0
    (tmp_path / "no-receipt").mkdir()
    bare = n2c.Repo(tmp_path / "no-receipt")
    answer, entry = n2c._level1(named, bare.path)
    assert (entry["verdict"], entry["reason_ids"]) == ("deny", ["no_receipt"]), entry
    assert _outcome(answer, entry) == _outcome(*n2c._level1(env, bare.path))
