"""Review round 3 of 2026-10-09, R3-5: a spelling the refusal names as free passes the whole gate in the same context.

Measured by the reviewer at 273763c3: after `git add git-*` the refusal promised that the gate frees
`git add -- git-*`, while that spelling still asked under Claude Code and was denied under Codex for net_unmodeled_git.
Likewise in a repository with core.fsmonitor=/nonexistent-fsmonitor the refusal of `git add *.py` named
`git add -- *.py`, which the repository state check of the same repository refuses. The proposal was judged by the
scan of gated_calls alone, not by the gate.

The class: a concrete hint whose promise was checked by a part of the gate. Now the spelling is named only when the
whole gate (decide without the hint, same host, directory, environment and deadline) passes it; otherwise the general
hint stays and no concrete spelling is named. Red against 63a704e0.
"""
from __future__ import annotations

import re

import pytest

import test_plugin_review_fix_f2_globs as f2
import test_plugin_review_fix2_narrower_spelling as fix2

gate = f2.gate
pytestmark = f2.pytestmark
repo = f2.repo
_clean_git_environment = f2._clean_git_environment

HOSTS = [("claude", "ask"), ("codex", "deny")]
NAMED = re.compile(r"run `([^`]*)` instead: it leaves no word")

#: Refused forms for which _narrower_spelling has a proposal (fix2.NARROWER), and the form of R3-5.
REFUSED = dict(fix2.NARROWER, **{"git add git-*": "git add -- git-*"})


def _named(outcome: gate.Outcome) -> set[str]:
    return set(NAMED.findall(outcome.text)) | {m for v in outcome.verdicts for m in NAMED.findall(v.next_step)}


@pytest.fixture
def fsmonitor(repo):
    f2._git(repo, "config", "core.fsmonitor", "/nonexistent-fsmonitor")
    return repo


@pytest.mark.parametrize("host,answer", HOSTS)
def test_the_spelling_for_a_glob_named_like_a_git_program_is_not_named(repo, host, answer):
    (repo / "git-x").write_text("x\n", encoding="utf-8")
    proposal = gate._narrower_spelling("git add git-*")
    assert proposal == "git add -- git-*", "non-vacuous: the scan alone has this proposal"
    checked = f2._decide(proposal, repo, host)
    assert checked.decision != "pass" and "net_unmodeled_git" in {v.reason_id for v in checked.verdicts}
    assert f2._host_answer(checked, host) == answer, "non-vacuous: the gate refuses the proposal itself"
    outcome = f2._decide("git add git-*", repo, host)
    assert f2._host_answer(outcome, host) == answer
    assert _named(outcome) == set(), outcome.text
    assert "instead: it leaves no word" not in outcome.text


@pytest.mark.parametrize("command", fix2.NARROWER)
@pytest.mark.parametrize("host,answer", HOSTS)
def test_a_spelling_the_state_check_refuses_is_not_named(fsmonitor, command, host, answer):
    proposal = gate._narrower_spelling(command)
    assert proposal is not None
    (fsmonitor / "src").mkdir(exist_ok=True)
    checked = f2._decide(proposal, fsmonitor, host)
    assert checked.decision != "pass", "non-vacuous: the state check of this repository refuses the proposal"
    assert f2._host_answer(checked, host) == answer
    outcome = f2._decide(command, fsmonitor, host)
    assert f2._host_answer(outcome, host) == answer
    assert _named(outcome) == set(), outcome.text


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_without_a_named_spelling_the_general_hint_stays(fsmonitor, host):
    outcome = f2._decide("git add *.py", fsmonitor, host)
    assert all(v.next_step == gate._FREE_FORMS_HINT for v in outcome.verdicts if v.reason_id == "git_form_not_free")


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_in_a_clean_repository_the_spelling_is_still_named(repo, host):
    outcome = f2._decide("git add *.py", repo, host)
    assert _named(outcome) == {"git add -- *.py"}, outcome.text


@pytest.mark.parametrize("state", ["clean", "fsmonitor"])
@pytest.mark.parametrize("command", REFUSED)
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_every_named_spelling_passes_the_whole_gate_in_the_same_context(repo, state, command, host):
    """The property: a spelling the refusal names concretely passes decide with the same host and directory."""
    if state == "fsmonitor":
        f2._git(repo, "config", "core.fsmonitor", "/nonexistent-fsmonitor")
    (repo / "src").mkdir(exist_ok=True)
    (repo / "git-x").write_text("x\n", encoding="utf-8")
    outcome = f2._decide(command, repo, host)
    for spelling in _named(outcome):
        checked = f2._decide(spelling, repo, host)
        assert checked.decision == "pass", (state, command, spelling, [v.reason_id for v in checked.verdicts])
