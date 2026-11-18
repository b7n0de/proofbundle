"""O30-7, follow-up note 33 point 6 (B30-5): a plain chain whose redirection writes a configuration file or a hook names the
write in its held answer.

The order (owner choice O30-7 of 2026-10-18: yes): the write into configuration or hooks in the held answer of a plain
chain, with B30-5 as its case: `git add -A && git commit -m x > .git/hooks/post-commit` held the ask of D3 for the add
and named nothing of the hook it wrote.

Measured at 63b88d07 (the base of this branch): the write is already named there (write_to_repo_state in the log and in
the short line); this file keeps it so, as a regression test, under both hosts and through the hook.

GREEN at 63b88d07 and at the head: a regression test, no rule of its own.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

import _gate_answer as ga
from test_plugin_n30_short_line_d72 import HOSTS, _clean, _line, _outcome, _repo, gate, pytestmark  # noqa: F401

FORMS = ["git add -A && git commit -m x > .git/hooks/post-commit",                 # B30-5
         "git add -A && git commit -m x >> .git/hooks/pre-push", "git commit -m x > .git/config",
         "git add -A; git commit -m x 2> .git/hooks/commit-msg", "git status > .git/hooks/post-merge",
         "git add -A && git commit -m x &> .git/config"]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", FORMS)
def test_O30_7_the_write_into_configuration_or_hooks_is_named(tmp_path, form, host):
    out = _outcome(_repo(tmp_path), form, host)
    assert out is not None and out.decision in ("ask", "deny")
    assert "write_to_repo_state" in [v.reason_id for v in out.verdicts], (form, [v.reason_id for v in out.verdicts])
    assert "the write can change hooks or git settings that start programs later" in _line(out, host), \
        _line(out, host)   # D116: what can go wrong, before the D number


def test_O30_7_the_hook_logs_the_write_and_the_autonomous_answer_blocks_it(tmp_path):
    repo = _repo(tmp_path)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-o30-7",
             "tool_input": {"command": FORMS[0]}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR") if k in os.environ}
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--autonomous"], json.dumps(event), env,
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert "write_to_repo_state" in entry["reason_ids"], entry
    assert "hooks or git settings" in answer["systemMessage"], answer   # D116


@pytest.mark.parametrize("form", ["git add -A && git commit -m x > notes.txt", "git commit -m x > /dev/null"])
def test_O30_7_control_a_write_elsewhere_names_no_write_to_repo_state(tmp_path, form):
    out = _outcome(_repo(tmp_path), form, "claude")
    assert out is None or "write_to_repo_state" not in [v.reason_id for v in out.verdicts]
