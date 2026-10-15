"""D40, part 2 of Nachtrag 15: `git commit -F <literal file>` counts as a message, as `-m` does.

Measured in the pilot at 14a5feb1: `git -C … commit -q -F /mnt/bigstore/claude_scratch/…/commit_message_scope_631.txt`
asked; _plain_add_commit knew only `-m`, and a message from a file is the house rule for longer commit texts. Now `-F
<file>` and `--file=<file>` count as a message, with and without the `-C` of part 1, after the same state check. Not
free stay: `-F -` (the message from standard input), a file the shell may rewrite, `--file <file>` as two words, an `F`
inside a cluster, and `-e`, `--edit`, `-t`, `--template`, `--cleanup` and every other option.

RED at ff554382 for the form of the pilot under both hosts and for the other free spellings; the controls answer the
same at both heads.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w

pytestmark = w.d.pytestmark


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def layout(tmp_path):
    main = w.main_repo(tmp_path)
    scope = w.linked_worktree(tmp_path, main)
    w.git(scope, "add", "docs/release_scope/6.3.1.md")
    return main, scope, w.message_file(tmp_path)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_P2_the_commit_of_the_pilot_is_free_after_the_state_check(tmp_path, layout, host):
    _main, scope, message = layout
    assert w.answer(tmp_path, f"git -C {scope} commit -q -F {message}", host) == (0, None, "")


@pytest.mark.parametrize("form", ["--file={message}", "-F {message}", "-q --file={message} -- docs"])
def test_P2_the_other_spellings_are_free(tmp_path, layout, form):
    _main, scope, message = layout
    assert w.answer(scope, f"git commit {form.format(message=message)}") == (0, None, "")


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P2_a_hook_that_reads_the_message_asks_and_starts_in_bash(tmp_path, layout, host, expected):
    main, scope, message = layout
    hook = main / ".git" / "hooks" / "commit-msg"
    w.proxy(tmp_path, hook, "commit_msg")
    command = f"git -C {scope} commit -q -F {message}"
    code, decision, reason = w.answer(tmp_path, command, host)
    assert (code, decision) == (0, expected) and f"a hook: {hook}" in reason, reason
    w.bash(tmp_path, command)
    assert w.started(tmp_path) == ["commit_msg"]


@pytest.mark.parametrize("form", ["-F -", "-F ~/message.txt", "--file -", "--file {message}", "-qF {message}",
                                  "-e -F {message}", "--edit -F {message}", "-t {message} -F {message}",
                                  "--template={message} -F {message}", "--cleanup=verbatim -F {message}",
                                  "-F {message} --amend", "--file="])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_P2_control_every_other_form_keeps_its_answer(tmp_path, layout, form, host, expected):
    _main, scope, message = layout
    command = f"git -C {scope} commit {form.format(message=message)}"
    code, decision, reason = w.answer(tmp_path, command, host)
    assert (code, decision) == (0, expected), reason
