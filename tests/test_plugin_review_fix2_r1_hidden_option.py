"""Review round 2 of 2026-10-09, R2-1: a forbidden option stays forbidden where a shell reads the text another way.

Measured by the reviewer at 87dcbed8: in a directory with a file named `1`, `git push origin main <1-2> --no-verify`
warned under Codex as the plain push: the lexer read `<1-2>` as two redirections and dropped `--no-verify` as the
target of the second, while zsh 5.9 reads `<1-2>` as a numeric glob and runs `git push origin main 1 --no-verify`,
which turns the pre-push hook off. bash reads the same text as two redirections. Three positions of the glob.

The class: a word the lexer dropped before any predicate saw it. Now the lexer drops nothing: a redirection is a token
of its own with its target, and the hook check reads every target as it reads the words, so `--no-verify` denies in
the zsh reading and in the bash reading alike, under Claude Code and under Codex. Red against 87dcbed8.
"""
from __future__ import annotations

import pytest

import test_plugin_review_fix_f2_globs as f2

gate = f2.gate
pytestmark = f2.pytestmark
repo = f2.repo
_clean_git_environment = f2._clean_git_environment

#: The three positions of the reviewer: after the refspec, before the remote, between remote and refspec.
HIDDEN = {
    "after the refspec": "git push origin main <1-2> --no-verify",
    "before the remote": "git push <1-2> --no-verify origin main",
    "between remote and refspec": "git push origin <1-2> --no-verify main",
}


@pytest.fixture
def numbered(repo):
    (repo / "1").write_text("x\n", encoding="utf-8")
    return repo


@pytest.mark.parametrize("command", HIDDEN.values(), ids=HIDDEN.keys())
def test_zsh_hands_git_the_option_the_lexer_dropped(numbered, command):
    """Non-vacuous: zsh 5.9 really runs the push with --no-verify in this directory."""
    words = f2._expand("zsh", command, numbered)
    assert "--no-verify" in words and "1" in words, words


@pytest.mark.parametrize("command", HIDDEN.values(), ids=HIDDEN.keys())
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_push_with_no_verify_behind_a_numeric_glob_is_denied(numbered, command, host):
    outcome = f2._decide(command, numbered, host)
    assert outcome.decision == "deny", (host, command, [v.reason_id for v in outcome.verdicts])
    assert "hooks_disabled" in {v.reason_id for v in outcome.verdicts}
    assert f2._host_answer(outcome, host) == "deny"


@pytest.mark.parametrize("command", ["git push origin main > --no-verify", "git push origin main 2>--no-verify"])
def test_a_forbidden_word_as_a_redirection_target_is_read_as_well(numbered, command):
    """The bash reading puts the word into a redirection target; the hook check reads targets too."""
    for host in ("claude", "codex"):
        assert f2._decide(command, numbered, host).decision == "deny", (host, command)


def test_the_lexer_keeps_every_redirection_with_its_target():
    toks = gate._lex("git push origin main <1-2> --no-verify")
    redirections = [t for t in toks if t[0] == "redir"]
    assert [(t[1], t[2][0]) for t in redirections] == [("<", "1-2"), (">", "--no-verify")], toks
    assert [t[1] for t in toks if t[0] == "word"] == ["git", "push", "origin", "main"]


def test_control_the_plain_push_in_the_same_directory_still_warns_under_codex(numbered):
    outcome = f2._decide("git push origin main", numbered, "codex")
    assert outcome.decision == "warn" and {v.reason_id for v in outcome.verdicts} == {"codex_context_unbound"}
