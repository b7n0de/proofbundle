"""D93, follow-up note 37, addendum 3: in the work profile of b7n0de a card on the owner's decision board in place of an ask in the terminal.

The order: for the closed list of point 1 of follow-up note 35 the gate does not ask in the terminal in the work profile of
b7n0de but blocks with the hint to put a card on the owner's decision board (owner word of 2026-10-18, 16:52 Berlin: no options in the
terminal). Outside b7n0de the ask stays, as there is no decision board. How the profile is recognised is set and measured
here; without a measurement the general behaviour holds.

The rule (D93, after D85 to D92, under Claude Code with --autonomous): an ask of the closed list (klasse aussen, an
effect other than the programm of D91) in a repository of D71 (_work_repo_problem: a declaration at HEAD, every remote a
repository of b7n0de on github.com, no overlap with the gate directory) becomes a deny (autonomy_card, klasse karte).
The repository is the one `git -C <path>` names, else the hook's directory.

RED at c6761bf5 (the head of D92): every card. The asks outside the profile, the kept ask of a program of the clone,
Codex and the hook without the flag are controls, green at both.
"""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85).
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []
OUTSIDE = "https://github.com/someone/proofbundle.git"
#: One call each of the closed list, with its effect.
CLOSED = [("gh pr create --fill", "pr"), ("git tag v1", "tag"), ("gh release create v9 --notes x", "release"),
          ("gh pr merge 12 -R b7n0de/proofbundle --merge", "merge"), ("gh pr comment 12 --body x", "pr"),
          ("gh api -X DELETE repos/b7n0de/proofbundle/git/refs/heads/x", "gh_write"),
          ("git push origin --delete topic", "push_delete"), ("git push origin topic:other", "push"),
          ("gh repo edit --visibility public", "settings"), ("git push origin v0", "tag")]


def _hook(cwd, tmp_path, command, host="claude", tool="Bash", tool_input=None, flag=True):
    event = {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(cwd), "session_id": "s-d93",
             "tool_input": tool_input if tool_input is not None else {"command": command}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *(AUTONOMOUS if flag else [])],
                              json.dumps(event), env, cwd=str(cwd))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


@pytest.mark.parametrize("form, effect", CLOSED)
def test_D93_in_the_work_profile_of_b7n0de_the_closed_list_is_a_card(tmp_path, form, effect):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    specific = answer["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny" and "autonomy_card" in entry["reason_ids"], (form, answer)
    assert "card in the Leitstand" in specific["permissionDecisionReason"] and "(D93)." in ga.short_text(answer)
    assert entry["autonomy"] == {"klasse": "karte", "wirkung": [effect]} and entry["verdict"] == "ask", entry


def test_D93_a_gated_mcp_tool_is_a_card_too(tmp_path):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path, None, tool="mcp__github__create_pull_request",
                          tool_input={"owner": "b7n0de", "repo": "proofbundle", "title": "t", "head": "x", "base": "main"})
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny" and "autonomy_card" in entry["reason_ids"]


def test_D93_the_profile_is_read_in_the_repository_git_C_names(tmp_path):
    repo = d71._repo(tmp_path)
    other = d71._repo(tmp_path, url=OUTSIDE, name="o")
    answer, entry = _hook(tmp_path, tmp_path, f"git -C {repo} tag v1")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny" and "autonomy_card" in entry["reason_ids"]
    answer, entry = _hook(repo, tmp_path, f"git -C {other} tag v1")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer


@pytest.mark.parametrize("kind", ["other_owner", "no_declaration", "no_remote", "ssh_remote", "second_remote"])
@pytest.mark.parametrize("form, effect", CLOSED[:4])
def test_D93_control_outside_the_profile_the_ask_stays(tmp_path, kind, form, effect):
    url = {"other_owner": OUTSIDE, "no_remote": None, "ssh_remote": "git@github.com:b7n0de/proofbundle.git"}.get(
        kind, d71.URL)
    repo = d71._repo(tmp_path, url=url, declaration=None if kind == "no_declaration" else d71.DECLARATION)
    if kind == "second_remote":
        d71._git(repo, "remote", "add", "fork", OUTSIDE)
    answer, entry = _hook(repo, tmp_path, form)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", (kind, form, answer)
    assert "autonomy_card" not in entry["reason_ids"]


def test_D93_control_a_program_of_the_clone_keeps_the_ask_in_the_profile(tmp_path):
    repo = d71._repo(tmp_path)
    (repo / ".git" / "hooks" / "post-merge").write_text("#!/bin/sh\nexit 0\n")
    (repo / ".git" / "hooks" / "post-merge").chmod(0o755)
    (tmp_path / "msg.txt").write_text("Merge\n")
    answer, entry = _hook(repo, tmp_path, f"git merge -F {tmp_path}/msg.txt topic")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask" and "local_program" in entry["reason_ids"]


@pytest.mark.parametrize("form, effect", CLOSED[:3])
def test_D93_control_codex_and_the_hook_without_the_flag_answer_as_before(tmp_path, form, effect):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path, form, host="codex")
    assert "autonomy_card" not in entry["reason_ids"] and "autonomy" not in entry
    answer, entry = _hook(repo, tmp_path, form, flag=False)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask" and "autonomy" not in entry


@pytest.mark.parametrize("kind, in_profile", [("b7n0de", True), ("other_owner", False), ("no_declaration", False),
                                              ("no_remote", False), ("ssh_remote", False), ("second_remote", False),
                                              ("push_url_other", False), ("insteadof_other", False)])
def test_D93_the_measure_of_the_profile(tmp_path, kind, in_profile):
    """The profile is the repository condition of D71, read without the network: declaration, owner, transport."""
    url = {"other_owner": OUTSIDE, "no_remote": None, "ssh_remote": "git@github.com:b7n0de/proofbundle.git"}.get(
        kind, d71.URL)
    repo = d71._repo(tmp_path, url=url, declaration=None if kind == "no_declaration" else d71.DECLARATION)
    if kind == "second_remote":
        d71._git(repo, "remote", "add", "fork", OUTSIDE)
    if kind == "push_url_other":
        d71._git(repo, "remote", "set-url", "--push", "origin", OUTSIDE)
    if kind == "insteadof_other":
        d71._git(repo, "config", "url.https://github.com/someone/.insteadOf", "https://github.com/b7n0de/")
    environ = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                          "PROOFBUNDLE_GATE_DIR")}
    problem = gate._work_repo_problem(str(repo), time.monotonic() + 60, environ)
    assert (problem is None) is in_profile, (kind, problem)
