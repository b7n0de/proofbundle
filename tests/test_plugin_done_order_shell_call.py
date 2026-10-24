"""D38, owner choice O2 of Nachtrag 13: done-order through the agent's shell.

A new order only adds a duty and the list only reads, so both stay free. `--replace` and `--remove` change a duty a
person set: they ask under Claude Code and are denied under Codex. The PreToolUse gate reads the call in each form it
reads a program in (directly, as the script of python, in a chain, in a shell's `-c` string), and a form it cannot read
whole (a switch, the script or the subcommand built by the shell) is answered as a replacement.

RED at f6408b97 for every changing form (no answer there); the free forms are green there and after. Each case runs the
gate as the host starts it.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import test_plugin_done_check as d
from _plugin_env import plugin_env

pytestmark = d.pytestmark
GATE = d.GATE
G = str(GATE)
KEY = "a" * 64

CHANGING = [
    f"python3 {G} done-order --replace --repo /work/clone",
    f"python3 -I {G} done-order --remove --repo /work/clone",
    f"{G} done-order --remove --key {KEY}",
    f"cd /work && python3 {G} done-order --replace --repo /work/clone",
    f"true && python3 {G} done-order --remove --repo /work/clone | cat",
    f"sh -c 'python3 {G} done-order --replace --repo /work/clone'",
    f"echo $(python3 {G} done-order --remove --key {KEY})",
    f"python3 {G} done-order --repo /work/clone $MORE",
    f"python3 {G} done-order --repo /work/clone --force",
    'python3 "$GATE" done-order --list',
    f"python3 {G} $SUBCOMMAND --repo /work/clone",
]
FREE = [
    f"python3 {G} done-order --repo /work/clone",
    f"python3 {G} done-order --repo /work/clone --declaration /src/evidence.json --policy /src/done-policy.json",
    f"python3 {G} done-order --list",
    f"{G} done-order --list",
    "echo done-order --replace",
]


def _answer(tmp_path, command: str, host: str) -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(tmp_path),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
@pytest.mark.parametrize("command", CHANGING)
def test_O2_a_replacement_or_removal_through_the_shell_asks_or_is_denied(tmp_path, command, host, expected):
    code, decision, reason = _answer(tmp_path, command, host)
    assert (code, decision) == (0, expected), (code, decision, reason)
    assert "replaces or removes a local done order" in reason, reason


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", FREE)
def test_O2_control_a_new_order_and_the_list_stay_free(tmp_path, command, host):
    assert _answer(tmp_path, command, host)[:2] == (0, None)
