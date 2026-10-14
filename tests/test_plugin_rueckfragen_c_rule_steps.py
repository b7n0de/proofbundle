"""A rule of N24 frees no step of class c (D25, D33), found while the hand-over was merged (Nachtrag 4 to FIX-18 part B).

N24 lets a human free one plain local git form in one repository, and never a chain or a pipe: the rule candidate is
the whole command. Since class c (135f9f9f) judged each step of a longer command as a command of its own, a rule for
`git stash list` freed that form as a step too (`git stash list; echo x`, `echo x; git stash list`, `git stash list |
cat`), and the log named no applied rule. A step is now judged without rules.

Red at 49e0b0f7 and at every head since 135f9f9f, green after; the controls are green on both sides.
"""
from __future__ import annotations

import pytest

import test_plugin_gate_n24 as n24

_clean_git_config = n24._clean_git_config

FORM = "git stash list"
STEPS = ["git stash list; echo x", "echo x; git stash list", "git stash list | cat", "git stash list && echo x",
         "true && git stash list"]


def _ruled(tmp_path):
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    repo = n24._repo(tmp_path)
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": FORM, "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    return env, repo


def test_CONTROL_the_rule_frees_its_form_as_the_whole_command(tmp_path):
    env, repo = _ruled(tmp_path)
    decision, entry = n24._hook(env, repo, "claude", FORM)
    assert decision is None and entry["applied_rule"]["form"] == FORM, entry


@pytest.mark.parametrize("command", STEPS)
def test_RED_a_rule_frees_no_step_of_a_longer_command(tmp_path, command):
    env, repo = _ruled(tmp_path)
    decision, entry = n24._hook(env, repo, "claude", command)
    assert decision == "ask", (command, decision, entry)
    assert "approved_by_rule" not in entry["reason_ids"] and "applied_rule" not in entry, (command, entry)


@pytest.mark.parametrize("command", [FORM] + STEPS)
def test_CONTROL_codex_denies_with_or_without_the_rule(tmp_path, command):
    env, repo = _ruled(tmp_path)
    decision, entry = n24._hook(env, repo, "codex", command)
    assert decision == "deny" and "approved_by_rule" not in entry["reason_ids"], (command, entry)
