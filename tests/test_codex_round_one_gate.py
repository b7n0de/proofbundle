"""The creator's own review call must be present, and nothing else may stand in for it.

MEASURED 2026-09-19 over six pull requests: the reviewer answered every call within twelve to
twenty-one seconds and never appeared without one. PR 227 carried no call and got no review. The
gate under test holds the call; these cases hold the gate.

THE THREE SUBSTITUTIONS THAT MUST NOT PASS are each their own case, because each is a plausible
way for the check to look satisfied while round one never happened: a call by somebody other than
the creator, the reviewer's own summary quoting the phrase back, and prose that merely mentions the
reviewer.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / "scripts" / "codex_round_one_gate.py"


def _gate():
    spec = importlib.util.spec_from_file_location("codex_round_one_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _c(login: str, body: str, at: str = "2026-09-14T17:34:59Z") -> dict:
    return {"author": {"login": login}, "body": body, "createdAt": at}


def test_the_creators_own_call_passes():
    """The shape actually measured on PR 207 and PR 208."""
    e = _gate().judge("b7n0de", [
        _c("b7n0de", "@codex review\n\nRound one belongs to the creator and I opened it."),
        _c("chatgpt-codex-connector", "Codex Review: Didn't find any major issues."),
    ])
    assert e["verdict"] == "OK", e
    assert e["called_at"] == "2026-09-14T17:34:59Z"


def test_THE_CATCH_no_call_is_red():  # noqa: N802
    """PR 227's shape: comments may exist, but none of them is the call."""
    e = _gate().judge("b7n0de", [_c("b7n0de", "Rebased onto main, the branch had fallen behind.")])
    assert e["verdict"] == "NO_CALL", e


def test_an_empty_comment_list_is_red_not_vacuously_green():
    """A pull request nobody commented on is the commonest case of a missing round one.

    An empty list is exactly where a check written as `any(...)` over comments quietly returns the
    wrong answer, so it gets its own case rather than living inside the one above.
    """
    assert _gate().judge("b7n0de", [])["verdict"] == "NO_CALL"


def test_a_call_by_SOMEBODY_ELSE_does_not_count():  # noqa: N802
    """Round one belongs to the creator. A call by a second person makes it round two.

    Without this, a reviewer could summon their own review of someone else's work and the gate
    would report that the creator had done it.
    """
    e = _gate().judge("b7n0de", [_c("someone-else", "@codex review")])
    assert e["verdict"] == "NO_CALL", e


def test_the_reviewers_OWN_summary_does_not_count():  # noqa: N802
    """Its summary quotes the phrase back.

    Counting it would let the check be satisfied by the very thing it exists to trigger, which is
    the shape where a gate certifies its own output.
    """
    body = ('Codex reacts when you comment "@codex review" or "@codex security review".')
    e = _gate().judge("b7n0de", [_c("chatgpt-codex-connector", body)])
    assert e["verdict"] == "NO_CALL", e


def test_prose_that_merely_mentions_the_reviewer_does_not_count():
    """A sentence about the reviewer is not a call to it."""
    e = _gate().judge("b7n0de", [
        _c("b7n0de", "I will ask codex to review this once the branch is rebased."),
    ])
    assert e["verdict"] == "NO_CALL", e


@pytest.mark.parametrize("body", ["@codex review", "@codex security review",
                                  "@Codex Review please", "  @codex   review  "])
def test_the_forms_actually_used_are_all_accepted(body: str):
    """Both documented forms, and the spacing and casing that occur in practice."""
    assert _gate().judge("b7n0de", [_c("b7n0de", body)])["verdict"] == "OK"


def test_an_unknown_author_fails_CLOSED():  # noqa: N802
    """Without an author, ownership of round one cannot be decided, and unknown is not permission."""
    assert _gate().judge(None, [_c("b7n0de", "@codex review")])["verdict"] == "AUTHOR_UNKNOWN"


@pytest.mark.parametrize("comments", [None, "nope", [42], [{"author": {"login": "b7n0de"}}]])
def test_an_unreadable_comment_list_fails_CLOSED(comments):  # noqa: N802
    """A shape this gate cannot read is UNREADABLE, never a pass."""
    assert _gate().judge("b7n0de", comments)["verdict"] == "UNREADABLE"


def test_ANTI_TAUTOLOGY_the_gate_can_actually_say_OK():  # noqa: N802
    """Every case above expects a refusal.

    A gate hard-wired to refuse would pass all of them and block every pull request forever. This
    holds that the accepting path is reachable with the exact comment measured on PR 226.
    """
    e = _gate().judge("b7n0de", [_c("b7n0de", "@codex review", "2026-09-18T20:06:13Z")])
    assert e["verdict"] == "OK" and e["calls"] == 1, e
