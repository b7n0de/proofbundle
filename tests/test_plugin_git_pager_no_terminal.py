"""D42, Nachtrag 18: a pager does not hinder a read form of class a under a host whose Bash tool gives no terminal.

Measured by Cowork at ba65da56 in delta's environment (GIT_OPTIONAL_LOCKS=0, GIT_EDITOR=true, the hook's AI_AGENT
claude-code_2-1-301_harness) with PAGER=less: `git log -3 --oneline` and `git -C <abs> diff --no-ext-diff --no-textconv
--stat` asked with "a pager: PAGER in the hook's environment". Owner answer O16-1: the binding of D41 for git's pagers.

Ground truth, measured under Claude Code 2.1.301 with git 2.43.0 and no network (host/host_cases_n18.py): log, show,
diff and grep with PAGER, GIT_PAGER, core.pager, pager.<command> naming a program and pager.<command>=true (the default
pager) started no pager as the Bash tool runs them, and started it on a terminal of script(1), each of the 40 runs.

Under Claude Code, when the hook's AI_AGENT names a host of _NO_TERMINAL_HOSTS, the read profile notes PAGER and
GIT_PAGER in the hook's environment and core.pager and pager.<command> in the configuration instead of counting them;
the pass names the pager and the host. Unchanged: Codex, every other host and value of AI_AGENT, a prefix assignment of
a pager in the command, an option that forces a pager, a program that gives git a terminal, and every other finding.

RED at ba65da56 for the four commands with each of the four sources under the bound host, all sources at once with the
pass text, a step whose output is the tool's or a pipe, and the other findings a noted pager no longer hides (there the
pager was named first); the controls answer the same at both heads.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

import _worktree_layout as w
import test_plugin_gate_n2c_push_done as n2c
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
gate = n2c.gate
BOUND = "claude-code_2-1-301_harness"
#: delta's environment as Cowork measured it, with the bound host.
DELTA = {"GIT_OPTIONAL_LOCKS": "0", "GIT_EDITOR": "true", "AI_AGENT": BOUND, "CLAUDECODE": "1"}
COMMANDS = {"log": "git log -3 --oneline", "show": "git show --stat HEAD",
            "diff": "git -C {main} diff --no-ext-diff --no-textconv --stat", "grep": "git grep -n one"}
SOURCES = ["PAGER", "GIT_PAGER", "core.pager", "pager.cmd"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def main(tmp_path):
    repo = w.main_repo(tmp_path)
    (repo / "README.md").write_text("one\ntwo\n")         # a change for git diff
    return repo


def _answer(cwd, command: str, host: str = "claude", **values: str) -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", w.G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(**values), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


def _with_source(main, cmd: str, source: str) -> dict:
    """The source set: an environment name returned for the hook, a configuration key written into the repository."""
    if source in ("PAGER", "GIT_PAGER"):
        return {source: "less"}
    w.git(main, "config", "core.pager" if source == "core.pager" else f"pager.{cmd}", "less")
    return {}


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("cmd", list(COMMANDS))
def test_N18_a_read_form_with_a_pager_is_free_under_the_bound_host(tmp_path, main, cmd, source):
    names = _with_source(main, cmd, source)
    command = COMMANDS[cmd].format(main=main)
    assert _answer(main, command, **DELTA, **names) == (0, None, "")


def test_N18_all_four_sources_at_once_are_free_and_the_pass_names_them(tmp_path, main, monkeypatch):
    w.git(main, "config", "core.pager", "less")
    w.git(main, "config", "pager.log", "less")
    assert _answer(main, COMMANDS["log"], **DELTA, PAGER="more", GIT_PAGER="less") == (0, None, "")
    for name, value in {**DELTA, "PAGER": "more", "GIT_PAGER": "less"}.items():
        monkeypatch.setenv(name, value)
    out = gate.decide(COMMANDS["log"], str(main), time.monotonic() + 120, "claude")
    assert [v.reason_id for v in out.verdicts] == ["free_after_read_profile"], out.verdicts
    text = out.verdicts[0].detail
    for named in ("core.pager in the", "pager.log in the", "GIT_PAGER in the hook's environment",
                  "PAGER in the hook's environment", BOUND, "D42"):
        assert named in text, (named, text)
    assert "no promisor remote, pager," not in text, text


@pytest.mark.parametrize("agent", [None, "", "claude-code_2-1-301_agent", "claude-code_2-0-301_harness",
                                   "claude-code_2-2-0_harness", "claude-code_2-1-301_harness ", "codex"])
@pytest.mark.parametrize("source", SOURCES)
def test_N18_control_without_the_bound_host_a_pager_asks(tmp_path, main, source, agent):
    names = _with_source(main, "log", source)
    values = {**DELTA, **names}
    values.pop("AI_AGENT")
    if agent is not None:
        values["AI_AGENT"] = agent
    code, decision, reason = _answer(main, COMMANDS["log"], **values)
    assert (code, decision) == (0, "ask") and "a pager:" in reason, reason


@pytest.mark.parametrize("source", SOURCES)
def test_N18_control_under_codex_the_answer_stays(tmp_path, main, source):
    names = _with_source(main, "log", source)
    unbound = {**DELTA, **names}
    unbound.pop("AI_AGENT")
    assert _answer(main, COMMANDS["log"], "codex", **DELTA, **names) == \
        _answer(main, COMMANDS["log"], "codex", **unbound)
    assert _answer(main, COMMANDS["log"], "codex", **DELTA, **names)[1] == "deny"


@pytest.mark.parametrize("command", ["PAGER=less git log -3 --oneline", "PAGER=cat git log -3 --oneline",
                                     "GIT_PAGER=cat git log -3 --oneline", "GIT_PAGER= git log -3 --oneline",
                                     "git -p log -3 --oneline", "git --paginate log -3 --oneline",
                                     "git -c core.pager=less log -3 --oneline",
                                     "git -c pager.log=true log -3 --oneline"])
def test_N18_control_a_pager_in_the_command_or_a_forced_pager_keeps_its_ask(tmp_path, main, command):
    code, decision, reason = _answer(main, command, **DELTA, PAGER="less")
    assert (code, decision) == (0, "ask"), (command, reason)


@pytest.mark.parametrize("command", ["script -qec 'git log -3 --oneline' /dev/null", "unbuffer git log -3 --oneline",
                                     "python3 -c \"import pty; pty.spawn(['git', 'log', '-3', '--oneline'])\"",
                                     "ssh -t localhost git log -3 --oneline", "tmux new-session -d git log -3",
                                     "exec > /dev/pts/0; git log -3 --oneline", "git log -3 --oneline > /dev/pts/0",
                                     "{ git log -3 --oneline; } > /dev/pts/0", "( git log -3 --oneline ) > /dev/pts/0"])
def test_N18_control_a_form_that_may_give_git_a_terminal_keeps_its_ask(tmp_path, main, command):
    code, decision, reason = _answer(main, command, **DELTA, PAGER="less")
    assert (code, decision) == (0, "ask"), (command, reason)


@pytest.mark.parametrize("command", ["true && git log -3 --oneline", "git log -3 --oneline | cat"])
def test_N18_a_step_whose_output_is_the_tools_or_a_pipe_is_free(tmp_path, main, command):
    """Class c judges the step on its own (D33): its standard output is the tool's or a pipe, no terminal."""
    assert _answer(main, command, **DELTA, PAGER="less") == (0, None, "")


@pytest.mark.parametrize("finding", ["unknown_key", "promisor", "fsmonitor", "hook", "filter", "foreign_env",
                                     "optional_locks_1"])
def test_N18_a_noted_pager_hides_no_other_finding(tmp_path, main, finding):
    """The pagers are noted and the reading goes on: the other finding is named (at ba65da56 the pager was named first,
    so these cases are red there by their text)."""
    values = {**DELTA, "PAGER": "less"}
    w.git(main, "config", "core.pager", "less")
    command, named = COMMANDS["log"], None
    if finding == "unknown_key":
        w.git(main, "config", "probe.unknown", "x")
        named = "probe.unknown"
    elif finding == "promisor":
        w.git(main, "config", "remote.origin.promisor", "true")
        named = "promisor"
    elif finding == "fsmonitor":
        w.git(main, "config", "core.fsmonitor", w.proxy(tmp_path, tmp_path / "fsm.sh", "fsmonitor"))
        command, named = COMMANDS["diff"].format(main=main), "fsmonitor"
    elif finding == "hook":
        w.proxy(tmp_path, main / ".git" / "hooks" / "post-index-change", "hook")
        command, named = COMMANDS["diff"].format(main=main), "a hook"
    elif finding == "filter":
        w.git(main, "config", "filter.probe.clean", "cat")
        command, named = "git -C {main} diff --stat".format(main=main), "a filter"
    elif finding == "foreign_env":
        values["GIT_PROBE_FOREIGN"] = "1"
        named = "GIT_PROBE_FOREIGN"
    else:
        values["GIT_OPTIONAL_LOCKS"] = "1"
        named = "GIT_OPTIONAL_LOCKS"
    code, decision, reason = _answer(main, command, **values)
    assert (code, decision) == (0, "ask") and named in reason, (finding, reason)
