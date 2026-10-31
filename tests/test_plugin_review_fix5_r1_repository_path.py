"""Review round 5 of 2026-10-09, R5-1: every path that leads to a verdict judges exactly the repository the call names.

Measured by the reviewer at 9d333d1c: evaluate_repository, evaluate_push, the pre-push entry and run_evidence read the
work tree with `decode().strip()`, the done path and the setup with `rstrip(b"\\n")`. git prints the work tree with its
bytes and one closing newline, so a repository whose folder name ends in LF, CR, TAB, U+0085 or a blank was cut to
another name: the Stop hook of a repository with an order and a missing receipt answered nothing (inactive), the push
path judged the neighbour `r`, CI said not_required, and run_evidence ran the green neighbour instead of the red target.

Property: the path that reaches a verdict judges exactly the repository the call names; a work tree the gate cannot
name for sure frees nothing. Every site is executed here, not read: the Stop hook and TaskCompleted, done-check, the
Claude PreToolUse push, the MCP diagnosis, ci-check, git's real pre-push hook, done-init and run-evidence, for each of
the five closing characters, with and without a neighbour. Red against 9d333d1c where the old reading cuts the name
(strip: all five; rstrip(b"\\n"): LF only). Under Codex a plain push only warns (Karte 5 A), so that lane is a control
and the push itself is held by the pre-push hook, run here for real.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_done_check as dc
import test_plugin_review_fix_f6_early_open as f6
from _plugin_env import plugin_env
from _gate_answer import long_text

gate = dc.gate
UNIT = dc.UNIT
pytestmark = f6.pytestmark
env = f6.env
keys = f6.keys
_clean_git_environment = f6._clean_git_environment

SUFFIXES = {"LF": "\n", "CR": "\r", "TAB": "\t", "NEL": "\x85", "SP": " "}
NEIGHBOURS = ("none", "plain")
GREEN = "def test_green():\n    assert True\n"
RED = "def test_red():\n    assert False\n"


def _plain(tmp_path: pathlib.Path, name: str = "r", test: str | None = None) -> pathlib.Path:
    path = tmp_path / name
    path.mkdir()
    dc._git(path, "init", "-q", "-b", "main")
    dc._write(path / "tests" / "test_it.py", test or GREEN)
    dc._commit(path, "base")
    return path


def _ordered(tmp_path: pathlib.Path, keys, suffix: str, neighbour: str) -> pathlib.Path:
    if neighbour == "plain":
        _plain(tmp_path)
    repo = f6._repo(tmp_path, "r" + suffix)
    dc._declare_order(repo, keys.public, checks=(UNIT,))
    dc._commit(repo, "the order")
    return repo


def _with_remote(tmp_path: pathlib.Path, repo: pathlib.Path) -> pathlib.Path:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, timeout=60)
    dc._git(repo, "remote", "add", "origin", str(remote))
    dc._git(repo, "push", "-q", "-u", "origin", "main")
    return remote


def _gate(env: dict, cwd: pathlib.Path, argv: list[str], stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(dc.GATE), *argv], input=stdin, capture_output=True, text=True,
                          env=env, cwd=cwd, timeout=180, check=False)


def _pre_tool(env: dict, repo: pathlib.Path, host: str, tool: str, tool_input: dict) -> dict:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo), "session_id": "s",
                        "tool_input": tool_input})
    proc = _gate(env, repo, ["--host", host], event)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


ids = list(SUFFIXES)


# --- the done path: Stop (both hosts), TaskCompleted, done-check ----------------------------------------------------
@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_stop_hook_blocks_in_the_repository_the_cwd_names(env, tmp_path, keys, host, suffix, neighbour):
    repo = _ordered(tmp_path, keys, SUFFIXES[suffix], neighbour)
    answer = f6.stop(env, repo, host)
    assert answer is not None and answer.get("decision") == "block", answer
    assert "check unit is missing" in answer["reason"], answer


@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
def test_task_completed_keeps_the_task_open_in_the_named_repository(env, tmp_path, keys, suffix, neighbour):
    repo = _ordered(tmp_path, keys, SUFFIXES[suffix], neighbour)
    event = json.dumps({"hook_event_name": "TaskCompleted", "session_id": "s", "cwd": str(repo)})
    proc = _gate(env, repo, ["task-completed"], event)
    assert proc.returncode == 0 and "check unit is missing" in proc.stdout, (proc.stdout, proc.stderr)


@pytest.mark.parametrize("suffix", ids)
def test_done_check_judges_the_named_repository(env, tmp_path, keys, suffix):
    repo = _ordered(tmp_path, keys, SUFFIXES[suffix], "plain")
    proc = _gate(env, tmp_path, ["done-check", "--repo", str(repo)])
    report = json.loads(proc.stdout[:proc.stdout.rindex("}") + 1])
    assert (proc.returncode, report["verdict"], report["reason_id"]) == (1, "deny", "no_receipt"), report
    assert report["repo"] == str(repo)


# --- the push path: the Claude PreToolUse push, the MCP diagnosis, git's real pre-push hook --------------------------
@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
def test_the_claude_push_is_denied_in_the_repository_the_cwd_names(env, tmp_path, keys, suffix, neighbour):
    repo = _ordered(tmp_path, keys, SUFFIXES[suffix], neighbour)
    _with_remote(tmp_path, repo)
    answer = _pre_tool(env, repo, "claude", "Bash", {"command": "git push origin main"})
    decision = answer.get("hookSpecificOutput", {}).get("permissionDecision")
    assert decision == "deny", answer
    assert "check unit is missing" in answer["hookSpecificOutput"]["additionalContext"], answer   # D53


@pytest.mark.parametrize("suffix", ids)
def test_control_the_codex_push_warns_before_and_after(env, tmp_path, keys, suffix):
    """Under Codex a plain push warns and the pre-push hook decides (Karte 5 A); the push path is not reached."""
    repo = _ordered(tmp_path, keys, SUFFIXES[suffix], "plain")
    _with_remote(tmp_path, repo)
    answer = _pre_tool(env, repo, "codex", "Bash", {"command": "git push origin main"})
    assert "permissionDecision" not in answer.get("hookSpecificOutput", {}), answer
    assert "under Codex the gate cannot bind git push" in (long_text(answer) if answer else ""), answer


def _evidenced(tmp_path: pathlib.Path, suffix: str, neighbour: str) -> pathlib.Path:
    """A repository whose committed declaration names evidence that does not verify (a bundle item without its policy
    and subject: the gate denies), beside a neighbour without a declaration (inactive, nothing declared)."""
    if neighbour == "plain":
        _plain(tmp_path)
    repo = _plain(tmp_path, "r" + suffix)
    dc._write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA,
                                        "evidence": [{"kind": "bundle", "path": ".proofbundle/build.bundle.json"}]})
    dc._commit(repo, "the declaration")
    return repo


@pytest.mark.parametrize("suffix", ids)
@pytest.mark.parametrize("host,decision", [("claude", "ask"), ("codex", "deny")])
def test_the_mcp_diagnosis_reads_the_repository_the_cwd_names(env, tmp_path, suffix, host, decision):
    """The MCP tool is never freed (ask, deny); its diagnosis names the verdict of the repository at the cwd."""
    repo = _evidenced(tmp_path, SUFFIXES[suffix], "plain")
    answer = _pre_tool(env, repo, host, "mcp__github__create_pull_request", {"title": "t"})
    out = answer["hookSpecificOutput"]
    assert out["permissionDecision"] == decision, answer
    assert "reads 'deny' (" in out["additionalContext"], out["additionalContext"]   # D53: the model's long reason


@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
def test_the_pre_push_hook_refuses_the_push_of_the_named_repository(env, tmp_path, keys, suffix, neighbour):
    repo = _ordered(tmp_path, keys, SUFFIXES[suffix], neighbour)
    remote = _with_remote(tmp_path, repo)
    installed = _gate(env, tmp_path, ["install-pre-push", "--repo", str(repo)])
    if suffix == "LF":
        # The layout read (_repo_paths) cannot hold a git directory whose name carries a newline in git's line
        # output, so the setup refuses (closed); the same wrapper is written here so the hook entry itself runs.
        assert installed.returncode == 1 and "cannot read" in installed.stderr, installed.stderr
        hook = repo / ".git" / "hooks" / "pre-push"
        hook.write_text(gate.pre_push_wrapper(str(dc.GATE.parent.parent)), encoding="utf-8")
        hook.chmod(0o755)
    else:
        assert installed.returncode == 0, installed.stderr
    dc._write(repo / "src" / "module.py", "VALUE = 2\n")
    dc._commit(repo, "change")
    before = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "main"], capture_output=True, text=True,
                            check=True).stdout
    push = subprocess.run(["git", "-C", str(repo), "push", "origin", "main"], capture_output=True, text=True, env=env,
                          timeout=180, check=False)
    after = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "main"], capture_output=True, text=True,
                           check=True).stdout
    assert push.returncode != 0 and after == before, (push.returncode, push.stderr[-600:])
    assert "check unit is missing" in push.stderr, push.stderr[-600:]


# --- CI, the setup, run-evidence -------------------------------------------------------------------------------------
@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
def test_ci_check_fails_for_the_named_repository(env, tmp_path, suffix, neighbour):
    """The CI check judges the evidence of the named repository (deny, exit 1), never the undeclared neighbour
    (not_required, exit 0)."""
    repo = _evidenced(tmp_path, SUFFIXES[suffix], neighbour)
    proc = _gate(env, tmp_path, ["ci-check", "--repo", str(repo), "--require-declaration", "false"])
    report = json.loads(proc.stdout)
    assert (proc.returncode, report["verdict"]) == (1, "deny"), report
    assert report["repo"] == str(repo), report


@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
def test_done_init_writes_into_the_named_repository(env, tmp_path, suffix, neighbour):
    other = _plain(tmp_path) if neighbour == "plain" else None
    repo = _plain(tmp_path, "r" + SUFFIXES[suffix])
    proc = _gate(env, tmp_path, ["done-init", "--repo", str(repo)])
    assert proc.returncode == 0, proc.stderr
    staged = subprocess.run(["git", "-C", str(repo), "diff", "--cached", "--name-only"], capture_output=True,
                            text=True, check=True).stdout.split()
    assert gate.DECLARATION in staged, staged
    if other is not None:
        assert not (other / gate.DECLARATION).exists(), "the neighbour must not be set up"


def _run_env(tmp_path: pathlib.Path) -> dict:
    import proofbundle
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = plugin_env(without=("PROOFBUNDLE_", "PYTEST_"))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    return clean


@pytest.mark.parametrize("neighbour", NEIGHBOURS)
@pytest.mark.parametrize("suffix", ids)
def test_run_evidence_runs_the_named_repository(tmp_path, suffix, neighbour):
    """The reviewer's case: the target's test fails, the neighbour's passes; only the target may be run."""
    if neighbour == "plain":
        _plain(tmp_path, test=GREEN)
    repo = _plain(tmp_path, "r" + SUFFIXES[suffix], test=RED)
    out = tmp_path / "statement.json"
    proc = subprocess.run([sys.executable, str(dc.GATE), "run-evidence", "--repo", str(repo), "--out", str(out), "--",
                           sys.executable, "-m", "pytest", "-q", "tests"], capture_output=True, text=True,
                          env=_run_env(tmp_path), cwd=tmp_path, timeout=300, check=False)
    report = json.loads(proc.stdout)
    assert (proc.returncode, report["outcome"]) == (1, "no_evidence"), report
    assert not out.exists(), "a red run of the named repository writes no statement"


def test_control_without_a_closing_character_the_stop_hook_blocks(env, tmp_path, keys):
    repo = _ordered(tmp_path, keys, "", "none")
    answer = f6.stop(env, repo, "claude")
    assert answer is not None and answer.get("decision") == "block", answer


# --- a read that failed is not "no repository" -----------------------------------------------------------------------
#: Configurations git refuses to read, measured with git 2.43.0: rev-parse exits 128 with "Expected git repo version
#: <= 1, found 99", with "unknown repository extension found", and with a bad boolean whose quoted value carries the
#: words of git's answer for no repository. The done check used to read every failure as no repository (inactive).
BROKEN = {
    "format_version": [("core.repositoryformatversion", "99")],
    "unknown_extension": [("core.repositoryformatversion", "1"), ("extensions.pbunknown", "x")],
    "quoted_answer": [("core.bare", "not a git repository")],
}


def _broken(tmp_path: pathlib.Path, keys, case: str) -> pathlib.Path:
    repo = _ordered(tmp_path, keys, "", "none")
    for key, value in BROKEN[case]:
        subprocess.run(["git", "config", "--file", str(repo / ".git" / "config"), key, value], check=True, timeout=60)
    probe = subprocess.run(["git", "-C", str(repo), "rev-parse", "--show-toplevel"], capture_output=True, timeout=60,
                           check=False)
    assert probe.returncode == 128, probe   # non-vacuous: git itself refuses this repository
    return repo


@pytest.mark.parametrize("case", list(BROKEN))
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_stop_hook_does_not_end_where_git_refuses_to_read_the_repository(env, tmp_path, keys, host, case):
    repo = _broken(tmp_path, keys, case)
    answer = f6.stop(env, repo, host)
    assert answer is not None and answer.get("decision") == "block", answer
    assert "could not name the work tree" in answer["reason"], answer


@pytest.mark.parametrize("case", list(BROKEN))
def test_done_check_fails_where_git_refuses_to_read_the_repository(env, tmp_path, keys, case):
    repo = _broken(tmp_path, keys, case)
    proc = _gate(env, tmp_path, ["done-check", "--repo", str(repo)])
    assert proc.returncode != 0 and "inactive" not in proc.stdout, (proc.returncode, proc.stdout, proc.stderr)


@pytest.mark.parametrize("where", ["outside", "bare", "git_dir"])
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_git_s_own_answer_for_no_work_tree_stays_inactive(env, tmp_path, host, where):
    """No block where git says there is no work tree: outside every repository, in a bare repository, in .git."""
    if where == "outside":
        cwd = tmp_path / "plain"
        cwd.mkdir()
    elif where == "bare":
        cwd = tmp_path / "bare.git"
        subprocess.run(["git", "init", "-q", "--bare", str(cwd)], check=True, timeout=60)
    else:
        cwd = _plain(tmp_path) / ".git"
    assert f6.stop(env, cwd, host) is None
