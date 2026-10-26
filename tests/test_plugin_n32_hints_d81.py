"""D81, Nachtrag 32, point 3: a hint before a run that reads its evidence wrongly, as a hint and never as a question.

Measured in Nachtrag 32 (messung/hint_path_summary.txt) with Claude Code 2.1.302: of the outputs of a PreToolUse hook only
hookSpecificOutput.additionalContext reaches the model without a question (as a message of role system); systemMessage,
the reason of an allow, plain stdout and stderr do not. Delta's cases F4 (the exit code came from `tail` after a
`timeout`) and F5 (`-rs` read an empty set of red tests).

The rule: under Claude Code a Bash command whose test run or check script sends its output into a pipe without pipefail
set before it, and a pytest run whose -r selection names neither failed nor errors, get a hint as additional context; the
decision stays as it was, a denied call gets none, the log names the hint ids. RED at 9b331c1f (D80, before D81): each
hint. The controls are green at both.
"""
from __future__ import annotations

import pytest

import test_plugin_n20_short_line as sl

repo = sl.repo
shim = sl.shim
plain = sl.plain
_clean = sl._clean
gate = sl.gate


def _hint(answer) -> str:
    assert answer is not None, "no hint"
    specific = answer["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse" and "(D81)" in specific["additionalContext"], answer
    return specific["additionalContext"]


@pytest.mark.parametrize("command", ["timeout 600 python -m pytest -q 2>&1 | tail -5", "pytest -q | tee log.txt",
                                     "bash tools/crosscheck.sh | tail -3", "cd . && uv run pytest -x | head -40"])
def test_F4_a_run_whose_output_goes_into_a_pipe_without_pipefail_gets_a_hint(shim, plain, tmp_path, command):
    env = sl.with_data(shim, tmp_path)
    stdout, answer = sl.run(env, plain, command=command)
    text = _hint(answer)
    assert "set -o pipefail" in text and "permissionDecision" not in answer["hookSpecificOutput"]
    assert "systemMessage" not in answer
    assert sl.log_lines(env)[-1]["hints"] == ["pipe_without_pipefail"]


@pytest.mark.parametrize("command", ["python -m pytest -q -rs", "pytest -r s tests/", "pytest -rsx -q"])
def test_F5_a_pytest_r_selection_without_failures_gets_a_hint(shim, plain, tmp_path, command):
    env = sl.with_data(shim, tmp_path)
    assert "-rfE" in _hint(sl.run(env, plain, command=command)[1])
    assert sl.log_lines(env)[-1]["hints"] == ["pytest_r_without_failures"]


@pytest.mark.parametrize("command", ["set -o pipefail; timeout 600 python -m pytest -q 2>&1 | tail -5",
                                     "set -euo pipefail && pytest -q | tail -3", "timeout 600 python -m pytest -q",
                                     "pytest -q -rfE", "pytest -ra", "pytest -rA", "ls -la | head -3",
                                     "git log --oneline | head", "cat list.txt | xargs echo", "echo pytest | tail -1"])
def test_control_no_hint(shim, plain, tmp_path, command):
    env = sl.with_data(shim, tmp_path)
    assert sl.run(env, plain, command=command) == ("", None)
    assert "hints" not in sl.log_lines(env)[-1] if sl.log_lines(env) else True


def test_a_hint_beside_a_question_keeps_the_question(shim, repo, tmp_path):
    env = sl.with_data(shim, tmp_path)
    _stdout, answer = sl.run(env, repo, command="git stash list && pytest -q | tail -3")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask"
    text = _hint(answer)
    assert text.index("proofbundle hint (D81)") > 0   # the long reason of the question first, then the hint
    assert sl.short(answer).startswith("Gate asks at ")


def test_control_a_denied_call_gets_no_hint(shim, repo, tmp_path):
    env = sl.with_data(shim, tmp_path)
    _stdout, answer = sl.run(env, repo, command="pytest -q | tail -3 && git push --no-verify origin main")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "(D81)" not in answer["hookSpecificOutput"].get("additionalContext", "")


def test_control_codex_gets_no_hint(shim, plain, tmp_path):
    env = sl.with_data(shim, tmp_path)
    env["PLUGIN_DATA"] = env["CLAUDE_PLUGIN_DATA"]
    _stdout, answer = sl.run(env, plain, command="timeout 600 python -m pytest -q 2>&1 | tail -5", host="codex")
    assert answer is None or "(D81)" not in str(answer)


def test_control_a_file_tool_gets_no_hint(shim, plain, tmp_path):
    env = sl.with_data(shim, tmp_path)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(plain),
             "tool_input": {"file_path": str(plain / "x.txt"), "content": "pytest -q | tail -3"}}
    _stdout, answer = sl.run(env, plain, event=event)
    assert answer is None or "(D81)" not in str(answer)
