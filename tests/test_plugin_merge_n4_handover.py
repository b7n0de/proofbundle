"""Nachtrag 4 to FIX-18 part B (owner choice of 2026-10-14, 19:3x Berlin): the push hand-over of D35 merged with class c
(D33) and class a (D34).

Rule 2 of the merge: a hand-over to Level 2 exists only for the whole command in the plain form, as on the counterpart's
branch. A push as a step of a longer command never gets one, not even as the first step; it keeps the answer it has
without a hand-over, and no step becomes freer through its neighbours. Each case runs Level 1 as the host starts it,
against a repository whose hand-over is set up (a bound Level 2, the approval mode, an approved transport), so the only
thing that can withhold the hand-over is the form of the command.

Red at the plain merge 814c341a for the forms in which class c judged the push step on its own and offered the hand-over
there (the verdict was `inactive` instead of `handover`, and a step wrote a hand-over record), green after.
"""
from __future__ import annotations

import pytest

import test_plugin_gate_push_destination_18 as g18
from _gate_answer import long_text

pytestmark = g18.pytestmark
_clean_git_environment = g18._clean_git_environment
handover_env = g18.env

#: Forms that get no hand-over, each with the answer it keeps under Claude Code.
NO_HANDOVER = {
    "push_then_echo": "git push origin main; echo done",
    "push_and_echo": "git push origin main && echo done",
    "add_commit_push": "git add a && git commit -m x && git push origin main",
    "prefix_assignment": "LANG=C git push origin main",
    "quoted_command_word": '"git" push origin main',
    "escaped_command_word": "\\git push origin main",
}


def test_HANDOVER_the_plain_push_alone_is_handed_over(handover_env, tmp_path):
    r = g18._repo(tmp_path, handover_env)
    answer, entry = g18._level1(handover_env, r.path, command="git push origin main")
    g18.assert_handed_over(answer, entry)
    assert g18._pointer(r.path).exists() and len(g18._records(handover_env)) == 1


@pytest.mark.parametrize("name", NO_HANDOVER)
def test_NO_HANDOVER_a_push_that_is_not_the_whole_plain_command(handover_env, tmp_path, name):
    """The push keeps an ask, and nothing is handed over: no pointer, no record."""
    r = g18._repo(tmp_path, handover_env)
    answer, entry = g18._level1(handover_env, r.path, command=NO_HANDOVER[name])
    assert g18._decision(answer) == "ask", (name, answer)
    assert entry["verdict"] != "handover" and "handed_over" not in entry["reason_ids"], (name, entry)
    assert "hands this push over" not in long_text(answer), (name, answer)
    assert not g18._pointer(r.path).exists() and g18._records(handover_env) == [], name


def test_CODEX_the_plain_push_alone_warns_as_before(handover_env, tmp_path):
    r = g18._repo(tmp_path, handover_env)
    answer, entry = g18._level1(handover_env, r.path, command="git push origin main", host="codex")
    assert g18._decision(answer) is None and (entry["verdict"], entry["reason_ids"]) == ("warn", ["codex_context_unbound"])
    assert not g18._pointer(r.path).exists() and g18._records(handover_env) == []


@pytest.mark.parametrize("name", NO_HANDOVER)
def test_CODEX_every_other_push_form_is_denied_as_before(handover_env, tmp_path, name):
    r = g18._repo(tmp_path, handover_env)
    answer, entry = g18._level1(handover_env, r.path, command=NO_HANDOVER[name], host="codex")
    assert g18._decision(answer) == "deny", (name, answer)
    assert entry["verdict"] != "handover", (name, entry)
    assert not g18._pointer(r.path).exists() and g18._records(handover_env) == [], name
