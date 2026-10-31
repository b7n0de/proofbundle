"""D41, part 1 of follow-up note 16: GIT_OPTIONAL_LOCKS=0, which the Bash tool of Claude Code sets, hinders no form.

Measured by the review session at 82255a7c: with GIT_OPTIONAL_LOCKS=0 in the environment, `git log -3 --oneline`, `git -C <abs> diff
--no-ext-diff --no-textconv --stat`, `git -C <abs> add`, `git -C <abs> commit -F <file>` and `git -C <abs> worktree add …`
asked with "an environment setting the check does not know". GIT_OPTIONAL_LOCKS=0 turns off the optional index refresh
of `git status` and changes nothing else these forms do (measured with git 2.43.0, measure/optional_locks_starts.py: the
five forms started the same programs with it unset and with 0, `git status` one fewer). It now counts as inert with the
value 0 in the read profile, in K-NW-2 B and in the checkout check of D40; any other value and every other GIT_* name the
lists do not know keep today's answer, and so does a prefix assignment of the command.

The environment of the tool, as Claude Code 2.1.301 builds it (read in its binary): what the host process carries, then
SHELL, GIT_EDITOR=true, CLAUDECODE, CLAUDE_CODE_SESSION_ID, CLAUDE_CODE_CHILD_SESSION, CLAUDE_CODE_SESSION_ATTENDED,
CLAUDE_PID, AI_AGENT and CLAUDE_EFFORT; GIT_OPTIONAL_LOCKS=0 as the review session measured it on its host.

RED at 3970f101 for the five forms with GIT_OPTIONAL_LOCKS=0 and with the tool's environment under Claude Code, and for
add and commit under Codex; the controls answer the same at both heads.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import _worktree_layout as w
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
#: What the Bash tool of Claude Code 2.1.301 adds to the environment it inherits, with GIT_OPTIONAL_LOCKS=0.
TOOL = {"SHELL": "/bin/bash", "GIT_EDITOR": "true", "CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "00000000-0000-0000",
        "CLAUDE_CODE_CHILD_SESSION": "1", "CLAUDE_CODE_SESSION_ATTENDED": "1", "CLAUDE_PID": "4242",
        "AI_AGENT": "claude-code_2-1-301_agent", "CLAUDE_EFFORT": "high", "GIT_OPTIONAL_LOCKS": "0"}
FORMS = ("log", "diff", "add", "commit_F", "worktree_add")


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def layout(tmp_path):
    main = w.main_repo(tmp_path)
    scope = w.linked_worktree(tmp_path, main)
    (scope / "README.md").write_text("one\ntwo\n")
    return main, scope, w.message_file(tmp_path)


def _command(form: str, layout, tmp_path) -> str:
    main, scope, message = layout
    second = tmp_path / "mnt" / "speicher" / "claude_worktrees" / "scope_632"
    return {
        "log": "git log -3 --oneline",
        "diff": f"git -C {scope} diff --no-ext-diff --no-textconv --stat",
        "add": f"git -C {scope} add docs/release_scope/6.3.1.md",
        "commit_F": f"git -C {scope} commit -q -F {message}",
        "worktree_add": f"git -C {main} worktree add -q -b docs/release-scope-6-3-2 {second} origin/main",
    }[form]


def _answer(cwd, command: str, host: str = "claude", **values: str) -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", w.G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(**values), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


@pytest.mark.parametrize("form", FORMS)
def test_P1_each_form_is_free_with_optional_locks_0_under_claude_code(tmp_path, layout, form):
    main = layout[0]
    if form == "commit_F":
        w.git(layout[1], "add", "docs/release_scope/6.3.1.md")
    assert _answer(main, _command(form, layout, tmp_path), GIT_OPTIONAL_LOCKS="0") == (0, None, "")


@pytest.mark.parametrize("form", FORMS)
def test_P1_each_form_is_free_in_the_environment_of_the_bash_tool(tmp_path, layout, form):
    main = layout[0]
    if form == "commit_F":
        w.git(layout[1], "add", "docs/release_scope/6.3.1.md")
    assert _answer(main, _command(form, layout, tmp_path), **TOOL) == (0, None, "")


@pytest.mark.parametrize("form", FORMS)
def test_P1_under_codex_each_form_answers_as_without_the_variable(tmp_path, layout, form):
    main = layout[0]
    if form == "commit_F":
        w.git(layout[1], "add", "docs/release_scope/6.3.1.md")
    command = _command(form, layout, tmp_path)
    assert _answer(main, command, "codex", GIT_OPTIONAL_LOCKS="0") == _answer(main, command, "codex")


@pytest.mark.parametrize("name, value", [("GIT_OPTIONAL_LOCKS", "1"), ("GIT_OPTIONAL_LOCKS", ""),
                                         ("GIT_OPTIONAL_LOCKS", "false"), ("GIT_OPTIONAL_LOCKS", " 0"),
                                         ("GIT_PROBE_FOREIGN", "1"), ("GIT_PROBE_FOREIGN", "0")])
@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P1_control_another_value_or_a_foreign_name_keeps_the_form_not_free(tmp_path, layout, form, name, value, host,
                                                                            expected):
    main = layout[0]
    if form == "commit_F":
        w.git(layout[1], "add", "docs/release_scope/6.3.1.md")
    code, decision, reason = _answer(main, _command(form, layout, tmp_path), host, **{name: value})
    assert (code, decision) == (0, expected), reason
    if host == "claude":
        assert f"does not know to start no program: {name}" in reason, reason


def test_P1_control_the_variable_hides_no_other_way_and_the_hook_starts_in_bash(tmp_path, layout, monkeypatch):
    """GIT_OPTIONAL_LOCKS=0 in the environment, and a post-index-change hook `git add` runs: the check names the hook,
    and bash with the same environment starts it."""
    main, scope, _message = layout
    hook = main / ".git" / "hooks" / "post-index-change"
    w.proxy(tmp_path, hook, "post_index_change")
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "0")
    command = _command("add", layout, tmp_path)
    code, decision, reason = _answer(main, command)
    assert (code, decision) == (0, "ask") and f"a hook: {hook.name} in the repository's own hook directory" in reason, reason   # D49, N21
    assert w.started(tmp_path) == []
    w.bash(main, command)
    assert w.started(tmp_path) == ["post_index_change"]


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P1_control_a_prefix_assignment_keeps_its_answer(tmp_path, layout, host, expected):
    """The command's own assignment is judged by the prefix rules of _assign_class, which part 1 leaves as they are."""
    code, decision, reason = _answer(layout[0], "GIT_OPTIONAL_LOCKS=0 git log -3 --oneline", host)
    assert (code, decision) == (0, expected), reason
