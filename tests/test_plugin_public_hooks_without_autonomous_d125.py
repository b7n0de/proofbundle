"""D125: the public hook commands carry no --autonomous (owner order N4-3, on the external review of the Guard Preview).

The order, translated: "The combined flag --autonomous is removed from the public hook commands. The standing release
for work branches (D87) exists publicly only after its own, protected, explicit consent. A house configuration with the
flag is marked as opt-in." The external review (KERN K-7 and finding 4, TESTS T-4): the flag of D85 also switches on the
standing GO of D87 for an own work branch, and the conditions of D87 do not obtain an outside user's consent; a test
that starts the gate with or without the flag is no witness of what the shipped hook answers.

The rule: no command of hooks/hooks.json and of .codex-plugin/plugin.json carries --autonomous, so the shipped Claude
Code hook answers as decide() judges. The gate keeps the flag as the house's opt-in (D85 to D92 and the tests that
start the gate with it); no protected consent channel for D87 exists, so the public default grants no standing GO.

Each shipped PreToolUse command is run here as the host runs it: the command of the group whose matcher matches the
tool, ${CLAUDE_PLUGIN_ROOT} put in as the plugin folder (and set in the environment), through `sh -c`, with the event on
stdin, in the repository and hook environment of the D87 tests. The python3 on PATH is the interpreter of the test run.

RED at 16cffca: the four PreToolUse commands of hooks/hooks.json name the flag; each D87 work-branch push passes under
the standing GO (free_work_branch_go) where the base gate asks; the asks of decide() for `git reset --hard HEAD~1`, for
a Write into .git/hooks and for a gated MCP write in the work profile are denies (D85, D93). Controls, green at both: the
Codex manifest, which never carried the flag, and the read of a key file, a deny with and without it.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n35_work_branch_go_d87 as d87

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
PLUGIN = pathlib.Path(gate.__file__).resolve().parent.parent
FLAG = "--autonomous"
#: Asks of decide() that the flag turns into a deny (tests/test_plugin_n35_autonomy_d85.py, D93): (tool, the tool's
#: input, {R} the repository). One per gate command of the manifest: the shell, a file tool, a gated MCP tool.
BASE_ASKS = [
    ("Bash", {"command": "git reset --hard HEAD~1"}),
    ("Write", {"file_path": "{R}/.git/hooks/pre-push", "content": "x"}),
    ("mcp__github__create_pull_request", {"owner": "b7n0de", "repo": "proofbundle", "title": "t", "head": "x",
                                          "base": "main"}),
]


def _commands(node) -> list[str]:
    """Every command string of a hook configuration, wherever it stands."""
    if isinstance(node, dict):
        return [v for k, v in node.items() if k == "command" and isinstance(v, str)] + \
            [c for k, v in node.items() if k != "command" for c in _commands(v)]
    if isinstance(node, list):
        return [c for v in node for c in _commands(v)]
    return []


def _shipped(tool: str) -> list[str]:
    """The commands Claude Code runs before `tool`: those of each PreToolUse group of hooks.json whose matcher matches."""
    groups = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    return [h["command"] for g in groups if re.fullmatch(g["matcher"], tool) for h in g["hooks"]]


def _env(tmp_path: pathlib.Path, data: str) -> dict:
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / data)
    env["CLAUDE_PLUGIN_ROOT"] = str(PLUGIN)
    return env


def _event(repo: pathlib.Path, tool: str, tool_input: dict) -> str:
    filled = {k: v.replace("{R}", str(repo)) if isinstance(v, str) else v for k, v in tool_input.items()}
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo), "session_id": "s-d125",
                       "tool_use_id": "toolu_d125", "tool_input": filled})


def _run_shipped(repo: pathlib.Path, tmp_path: pathlib.Path, tool: str, tool_input: dict):
    """The answer and log line of the one shipped command for `tool`, run as the host runs it."""
    (command,) = _shipped(tool)
    shim = tmp_path / "bin" / "python3"
    if not shim.exists():
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        shim.chmod(0o755)
    line = command.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN))
    proc, entry = ga.run_hook(["sh", "-c", line], _event(repo, tool, tool_input), _env(tmp_path, "data-shipped"),
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


def _run_base(repo: pathlib.Path, tmp_path: pathlib.Path, tool: str, tool_input: dict):
    """The answer and log line of the gate started without the flag: the base path, as decide() judges."""
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__], _event(repo, tool, tool_input),
                              _env(tmp_path, "data-base"), cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


def _decision(answer) -> str | None:
    return None if answer is None or isinstance(answer, ga.Silent) else \
        answer["hookSpecificOutput"].get("permissionDecision")


@pytest.mark.parametrize("manifest", ["hooks/hooks.json", ".codex-plugin/plugin.json"])
def test_D125_no_hook_command_of_either_manifest_carries_the_autonomous_flag(manifest):
    text = (PLUGIN / manifest).read_text(encoding="utf-8")
    commands = _commands(json.loads(text))
    assert commands and len(commands) == text.count('"command":'), commands
    assert [c for c in commands if FLAG in c] == []


@pytest.mark.parametrize("form", d87.FREE)
def test_D125_the_shipped_hook_grants_no_standing_go_for_the_own_work_branch(tmp_path, form):
    repo = d87._fixture(tmp_path)
    tool_input = {"command": form.replace("{R}", str(repo))}
    answer, entry = _run_shipped(repo, tmp_path, "Bash", tool_input)
    base, base_entry = _run_base(repo, tmp_path, "Bash", tool_input)
    assert "free_work_branch_go" not in entry["reason_ids"], (form, entry)
    assert _decision(answer) == "ask" and "autonomy" not in entry, (form, answer, entry)
    assert (_decision(answer), entry["verdict"], entry["decision"], entry["reason_ids"]) == \
        (_decision(base), base_entry["verdict"], base_entry["decision"], base_entry["reason_ids"]), form


@pytest.mark.parametrize("tool, tool_input", BASE_ASKS, ids=[t for t, _ in BASE_ASKS])
def test_D125_the_shipped_hook_answers_a_base_ask_as_an_ask(tmp_path, tool, tool_input):
    repo = d71._repo(tmp_path)
    answer, entry = _run_shipped(repo, tmp_path, tool, tool_input)
    base, base_entry = _run_base(repo, tmp_path, tool, tool_input)
    assert _decision(base) == "ask", base
    assert _decision(answer) == "ask" and "autonomy" not in entry, (tool, answer, entry)
    assert (entry["verdict"], entry["decision"], entry["reason_ids"]) == \
        (base_entry["verdict"], base_entry["decision"], base_entry["reason_ids"]), tool


@pytest.mark.parametrize("tool, key", [("Read", "file_path"), ("Grep", "path")])
def test_D125_control_the_shipped_read_hook_denies_a_key_file_as_the_base_gate_does(tmp_path, tool, key):
    repo = d71._repo(tmp_path)
    tool_input = {key: str(tmp_path / "home" / ".ssh" / "id_ed25519")}
    answer, entry = _run_shipped(repo, tmp_path, tool, tool_input)
    base, base_entry = _run_base(repo, tmp_path, tool, tool_input)
    assert _decision(answer) == _decision(base) == "deny", (answer, base)
    assert entry["reason_ids"] == base_entry["reason_ids"] == ["secret_path"], (entry, base_entry)
