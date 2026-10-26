"""Owner choice 3 of 2026-10-15 (Nachtrag 10 to FIX-18): the answer to a read form of class a under Codex.

Class a stays off under Codex (owner answer 10, D37). A read form the gate recognises now carries the reviewer's text of
review round 20, answer 4, word for word: the explanation and the next step. With an absolute `git -C` it does not say
that the directory is unknown. The verdict, the exit code and the reason id stay: the host answer is deny, exit 0,
git_form_not_free. A form outside class a keeps its own reason and text (`git remote`, a git form that is not free).

RED at b34ba9a2 (the text of D3), green after. Each case runs the gate as the host starts it, `--host codex`.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import test_plugin_ask_load_a_read as a
from _plugin_env import plugin_env

pytestmark = a.pytestmark
_clean = a._clean

EXPLANATION = ("NOT MEASURED. Under Codex, even with an absolute git -C path, the execution environment, filesystem and "
               "environment variables remain unbound. Without such a -C argument, the effective working directory is "
               "unbound as well. The gate therefore cannot free this read form.")
NEXT_STEP = ("Have a person run the call outside this unverified agent path, or use a host whose hook supplies the "
             "required execution context.")


def _host(repo, command: str, host: str = "codex"):
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", str(a.gate.__file__), "--host", host], input=event,
                          capture_output=True, text=True, env=plugin_env(), timeout=120, check=False)
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    out = answer.get("hookSpecificOutput", {})
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


@pytest.mark.parametrize("command", ["git status", "git -C {REPO} status", "git log --oneline -1",
                                     "git -C {REPO} log --oneline -1"])
def test_CODEX_a_read_form_of_class_a_carries_the_reviewers_text(tmp_path, command):
    repo = a._repo(tmp_path)
    command = command.replace("{REPO}", str(repo))
    code, decision, text = _host(repo, command)
    assert (code, decision) == (0, "deny"), (code, decision, text)
    assert EXPLANATION in text and NEXT_STEP in text, text
    assert "may start a program the gate does not see" not in text, text
    out = a.gate.decide(command, str(repo), a.time.monotonic() + 120, "codex", plugin_env())
    assert [v.reason_id for v in out.verdicts] == ["git_form_not_free"], out.verdicts


def test_CODEX_with_an_absolute_minus_C_the_text_does_not_say_the_directory_is_missing(tmp_path):
    repo = a._repo(tmp_path)
    _code, _decision, text = _host(repo, f"git -C {repo} status")
    assert "even with an absolute git -C path" in text
    assert "cannot resolve the directory" not in text and "directory_unresolved" not in text, text


@pytest.mark.parametrize("command", ["git remote show origin", "git stash list"])
def test_CODEX_control_a_form_outside_class_a_keeps_its_own_reason(tmp_path, command):
    repo = a._repo(tmp_path)
    code, decision, text = _host(repo, command)
    assert (code, decision) == (0, "deny"), (code, decision, text)
    assert EXPLANATION not in text and NEXT_STEP not in text, text


def test_CLAUDE_control_the_read_form_stays_free(tmp_path):
    repo = a._repo(tmp_path)
    code, decision, text = _host(repo, "git log --oneline -1", host="claude")
    assert (code, decision) == (0, None) and EXPLANATION not in text, (code, decision, text)
