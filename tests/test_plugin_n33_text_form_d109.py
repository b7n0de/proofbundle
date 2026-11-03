"""D109, follow-up note 33, point 3 (fallbook C3): the text of a file a gh call sends is judged by the house's form checker.

The order: where the command names a file as the body, the gate reads it and checks it with the form checkers of the
house; where the form fails, it denies; where there is no checker, it asks and says so. Found by account A's fallbook (gate
44db2056): `gh pr comment <n> -R <repo> --body-file <file>` asked for the net (net_unmodeled_git), never for the text.

The rule: for `gh pr create|edit|comment|review`, `gh issue create|edit|comment` with --body-file or -F, and `gh api` with
`-F body=@<file>`, the house's form checker (scripts/b7_pr_form_gate.py at the remote's default branch, run as D92 runs
it) judges the file: rules (b) and (c) for the description of a pull request, rule (c) for a comment, a review or an
issue. Red: a deny (text_form_red) under both hosts. No checker, a checker that cannot measure, or a file the gate does
not read (outside the work tree and the temp folder, below a dotted name, a key path, no regular UTF-8 file): an ask
(text_form_unchecked) that says so. Green adds nothing.

RED at 63b88d07: the red text and the missing checker got no reason of their own. The green text is the control.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_n37_machine_check_d92 as d92

gate = d92.gate
pytestmark = d92.pytestmark
_clean = d92._clean
HOSTS = ("claude", "codex")
GREEN = "Text.\n\n" + d92.FOOTER


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _out(repo, form, host="claude"):
    return gate.decide(form, str(repo), time.monotonic() + 60, host)


@pytest.fixture
def repo(tmp_path):
    return d92._fixture(tmp_path)


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", ["gh pr comment 12 -R b7n0de/proofbundle --body-file note.md",
                                  "gh pr comment 12 -F note.md", "gh issue comment 3 --body-file=note.md",
                                  "gh pr review 12 --comment --body-file note.md",
                                  "gh api repos/b7n0de/proofbundle/issues/12/comments -F body=@note.md"])
def test_D109_a_comment_the_checker_finds_red_by_rule_c_is_denied(repo, form, host):
    (repo / "note.md").write_text("Generated with a tool.\n")
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "text_form_red" in _ids(out), (form, host, _ids(out))


def test_D109_a_comment_needs_no_footer_but_a_description_does(repo):
    (repo / "note.md").write_text("Text without the footer.\n")
    assert "text_form_red" not in _ids(_out(repo, "gh pr comment 12 --body-file note.md"))
    out = _out(repo, "gh pr create -R b7n0de/proofbundle --title t --body-file note.md")
    assert out is not None and out.decision == "deny" and "text_form_red" in _ids(out), _ids(out)


@pytest.mark.parametrize("form", ["gh pr comment 12 -Fnote.md", "gh issue create -t t -Fnote.md",
                                  "sudo gh pr comment 12 --body-file note.md", "gh pr comment 12 --body-file \"note.md\"",
                                  "git status && gh pr comment 12 --body-file note.md"])
def test_D109_the_siblings_of_the_form_are_judged_too(repo, form):
    (repo / "note.md").write_text("Generated with a tool.\n")
    out = _out(repo, form)
    assert out is not None and out.decision == "deny" and "text_form_red" in _ids(out), (form, _ids(out))


def test_D109_a_comment_whose_rule_c_cannot_measure_is_unchecked_whatever_rule_b_says(repo):
    (repo / "note.md").write_text("UNREADABLE\n")
    out = _out(repo, "gh pr comment 12 --body-file note.md")
    assert "text_form_unchecked" in _ids(out) and "text_form_red" not in _ids(out), _ids(out)


def test_D109_a_green_text_adds_nothing(repo):
    (repo / "note.md").write_text(GREEN)
    for form in ("gh pr comment 12 --body-file note.md", "gh pr create --title t --body-file note.md"):
        assert not {"text_form_red", "text_form_unchecked"} & set(_ids(_out(repo, form))), form


def test_D109_without_a_checker_the_call_asks_and_says_so(tmp_path):
    repo = d92._fixture(tmp_path, checker=None)
    (repo / "note.md").write_text(GREEN)
    out = _out(repo, "gh pr comment 12 --body-file note.md")
    assert out is not None and "text_form_unchecked" in _ids(out), _ids(out)
    unchecked = next(v for v in out.verdicts if v.reason_id == "text_form_unchecked")
    assert unchecked.decision == "ask" and "is not at the default branch" in unchecked.detail


def test_D109_a_file_outside_the_work_tree_or_below_a_dot_is_not_read(repo, tmp_path):
    (repo / ".hidden").mkdir()
    (repo / ".hidden" / "note.md").write_text("Generated with a tool.\n")
    out = _out(repo, "gh pr comment 12 --body-file .hidden/note.md")
    assert "text_form_unchecked" in _ids(out) and "text_form_red" not in _ids(out), _ids(out)


@pytest.mark.parametrize("path", ["~/.ssh/id_rsa", "id_ed25519", "deploy/server.pem"])
def test_D109_a_key_path_is_never_read_and_d102_denies(repo, monkeypatch, path):
    if not path.startswith("~"):
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text("Generated with a tool.\n")
    opened = []
    real = gate._read_regular
    monkeypatch.setattr(gate, "_read_regular", lambda p, n, **kw: (opened.append(p), real(p, n, **kw))[1])
    out = _out(repo, f"gh pr comment 12 --body-file {path}")
    name = path.rsplit("/", 1)[-1]
    assert out.decision == "deny" and "secret_path" in _ids(out) and not [p for p in opened if p.endswith(name)], \
        (_ids(out), opened)


@pytest.mark.parametrize("form", ["gh pr view 12", "gh pr comment 12 --body 'x'", "gh pr comment 12 --body-file -",
                                  "gh api repos/b7n0de/proofbundle/pulls/12 -F state=closed",
                                  "gh release create v1 -F notes.md"])
def test_D109_control_other_gh_calls_get_no_reason_of_d109(repo, form):
    (repo / "notes.md").write_text("Generated with a tool.\n")
    assert not {"text_form_red", "text_form_unchecked"} & set(_ids(_out(repo, form))), form


def test_D109_the_reasons():
    assert gate._SHORT_REASONS["text_form_red"][0] == "D109" and "text_form_red" in gate.FANG_REASONS
    assert gate._SHORT_REASONS["text_form_unchecked"][0] == "D109" and "text_form_unchecked" not in gate.FANG_REASONS
