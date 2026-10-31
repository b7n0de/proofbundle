"""Review round 2 of 2026-10-09, without a finding of its own: a refused form names the narrower spelling the gate frees.

The reviewer noted that `git add -- *.py`, `git add -- src/*` and `git commit -m 'fix#12'` are free today while
`git add *.py`, `git add src/*` and `git commit -m fix#12` ask under Claude Code and are denied under Codex, and the
refusal named only the general hint. Now the refusal of such a form names the narrower spelling, and only one that the
gate frees itself (it is judged by the same scan), so the hint never sends an agent to a refused form.
"""
from __future__ import annotations

import pytest

import test_plugin_review_fix_f2_globs as f2

gate = f2.gate
pytestmark = f2.pytestmark
repo = f2.repo
_clean_git_environment = f2._clean_git_environment

NARROWER = {
    "git add *.py": "git add -- *.py",
    "git add src/*": "git add -- src/*",
    "git commit -m fix#12": "git commit -m 'fix#12'",
    "git commit -m msg *": "git commit -m msg -- *",
}


@pytest.mark.parametrize("command,spelling", NARROWER.items(), ids=NARROWER.keys())
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_refusal_names_the_narrower_spelling(repo, command, spelling, host):
    outcome = f2._decide(command, repo, host)
    assert outcome.decision != "pass" and {v.reason_id for v in outcome.verdicts} == {"git_form_not_free"}
    assert f"run `{spelling}` instead" in outcome.text, outcome.text
    assert all(spelling in v.next_step for v in outcome.verdicts)


@pytest.mark.parametrize("spelling", NARROWER.values())
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_named_spelling_is_free_itself(repo, spelling, host):
    (repo / "src").mkdir(exist_ok=True)
    outcome = f2._decide(spelling, repo, host)
    assert outcome.decision == "pass", (host, spelling, [v.reason_id for v in outcome.verdicts])


@pytest.mark.parametrize("command", ["git add -p", "git add -- *.py > out.txt", "git commit -m \"it's #1\"",
                                     "git add *.py && git commit -m x"])
def test_without_a_free_narrower_spelling_the_general_hint_stays(repo, command):
    assert gate._narrower_spelling(command) is None, command
    outcome = f2._decide(command, repo, "claude")
    assert "instead: it leaves no word" not in outcome.text
