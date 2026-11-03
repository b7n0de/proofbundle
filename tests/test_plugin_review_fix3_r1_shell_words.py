"""Review round 3 of 2026-10-09, R3-1: the gate forms a word from quotes and escapes as the shell does.

Measured by the reviewer at 273763c3: inside double quotes the lexer kept a backslash-newline, which bash and zsh
remove, and the character reader dropped a backslash before an ordinary character, which both shells keep. Three
consequences: `git push "--no-\\<LF>verify" origin main` warned under Codex without a permission decision while both
shells hand git `--no-verify`; `git -C "a\\<LF>b" push origin main` was judged in the directory named a, backslash,
newline, b while the shell runs in `ab`; and the hint for `git commit -m "fix\\<LF>"#12` kept the backslash and the
newline, where bash forms `fix#12`.

The class: two word formations for one word. Now one rule (_shell_characters) forms the value of every word without a
substitution, so the predicates, the repository a `-C` names and a proposed spelling read the bytes git receives; a
line continuation between words adds no word, and a backslash at the very end of the command, which bash keeps and
zsh drops, leaves the command unparsed. Red against 273763c3.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

import test_plugin_review_fix_f2_globs as f2

gate = f2.gate
pytestmark = f2.pytestmark
repo = f2.repo
_clean_git_environment = f2._clean_git_environment

SHELLS = ["bash", "zsh"]

#: Words as written, each with the bytes bash 5.2 and zsh 5.9 form from it (measured, both the same).
WORDS = {
    "dq continuation": ('"a\\\nb"', "ab"),
    "dq backslash before a letter": ('"a\\b"', "a\\b"),
    "dq escaped backslash": ('"a\\\\b"', "a\\b"),
    "dq escaped quote": ('"a\\"b"', 'a"b'),
    "dq escaped backtick": ('"a\\`b"', "a`b"),
    "dq backslash before !": ('"a\\!b"', "a\\!b"),
    "continuation outside quotes": ("a\\\nb", "ab"),
    "sq keeps everything": ("'a\\\nb'", "a\\\nb"),
    "the option of R3-1": ('"--no-\\\nverify"', "--no-verify"),
    "the message of R3-1": ('"fix\\\n"#12', "fix#12"),
    "dq backslash before an apostrophe": ('"a\\\'b"', "a\\'b"),
    "dq backslash before x": ('"\\x"', "\\x"),
    "dq newline": ('"a\nb"', "a\nb"),
    "escaped backslash then continuation": ('"a\\\\\\\nb"', "a\\b"),
    "two continuations": ('x"\\\n\\\n"y', "xy"),
}


def _shell_words(shell: str, words_as_written: str) -> list[str]:
    """The words `shell` forms, measured as the positional parameters they become (their count first, so no word
    and one empty word differ), with a NUL after each."""
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    proc = subprocess.run([shell, "-c", "set -- " + words_as_written + "\nprintf '%s\\0' \"$#\" \"$@\""],
                          capture_output=True, timeout=30, check=True)
    count, *words = proc.stdout.decode("utf-8").split("\0")[:-1]
    assert int(count) == len(words), proc.stdout
    return words


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("raw,formed", WORDS.values(), ids=WORDS.keys())
def test_the_lexer_and_the_character_reader_form_the_word_the_shell_forms(raw, formed, shell):
    assert _shell_words(shell, raw) == [formed], "the table is the measured shell word"
    toks = gate._lex("printf " + raw)
    assert [t[1] for t in toks if t[0] == "word"] == ["printf", formed], toks
    assert "".join(ch for ch, _literal in gate._shell_characters(raw)) == formed


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("words", ["x \\\n y", "\\\n", "x\\\n y", "x \\\n\\\n y"])
def test_a_line_continuation_between_words_adds_no_word(words, shell):
    toks = gate._lex("printf " + words)
    assert [t[1] for t in toks if t[0] == "word"][1:] == _shell_words(shell, words), toks


def test_a_backslash_at_the_very_end_leaves_the_command_unparsed():
    """bash keeps a trailing backslash, zsh drops it (measured): the gate does not pick one."""
    assert gate._lex("git push origin main\\") is None
    assert [d for _n, d, _x in gate.gated_calls("git push origin main\\", "/r")] == [gate.UNKNOWN]


# --- the first consequence: an option split by a continuation inside double quotes ---------------------------------

HIDDEN = 'git push "--no-\\\nverify" origin main'


def _stub_words(shell: str, command: str, cwd: pathlib.Path) -> list[str]:
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    stub = "git() { printf '%s\\0' \"$@\"; }; "
    proc = subprocess.run([shell, "-c", stub + command], cwd=cwd, capture_output=True, timeout=30, check=True)
    return proc.stdout.decode("utf-8").split("\0")[:-1]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_no_verify_split_inside_double_quotes_is_denied(repo, shell, host):
    assert "--no-verify" in _stub_words(shell, HIDDEN, repo), "non-vacuous: the shell hands git --no-verify"
    outcome = f2._decide(HIDDEN, repo, host)
    assert outcome.decision == "deny" and "hooks_disabled" in {v.reason_id for v in outcome.verdicts}, outcome.verdicts
    assert f2._host_answer(outcome, host) == "deny"


@pytest.mark.parametrize("command", ["git push --no-\\\nverify origin main", 'git push "--no-verify" origin main'])
@pytest.mark.parametrize("host", ["claude", "codex"])
def test_control_the_continuation_outside_quotes_and_the_quoted_option_stay_denied(repo, command, host):
    outcome = f2._decide(command, repo, host)
    assert outcome.decision == "deny" and "hooks_disabled" in {v.reason_id for v in outcome.verdicts}


# --- the second consequence: the repository a -C names ---------------------------------------------------------------

def _tracked(path: pathlib.Path, bare: pathlib.Path, declaration: str | None) -> None:
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, timeout=60)
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True, timeout=60)
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    if declaration is not None:
        (path / ".proofbundle").mkdir()
        (path / ".proofbundle" / "evidence.json").write_text(declaration, encoding="utf-8")
    f2._git(path, "add", "-A")
    f2._git(path, "commit", "-q", "-m", "base")
    f2._git(path, "remote", "add", "origin", str(bare))
    f2._git(path, "push", "-q", "origin", "main")
    f2._git(path, "fetch", "-q", "origin")


@pytest.fixture
def two_directories(tmp_path) -> pathlib.Path:
    """`ab` with a committed declaration that is not valid, and `a\\<LF>b` with none; the command runs in work."""
    work = tmp_path / "work"
    work.mkdir()
    _tracked(work / "ab", tmp_path / "ab.git", "this is not a valid declaration\n")
    _tracked(work / "a\\\nb", tmp_path / "other.git", None)
    return work


SPLIT_C = 'git -C "a\\\nb" push origin main'


@pytest.mark.parametrize("shell", SHELLS)
def test_the_shell_runs_the_push_in_ab(two_directories, shell):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    proc = subprocess.run([shell, "-c", 'git -C "a\\\nb" rev-parse --show-toplevel'], cwd=two_directories,
                          capture_output=True, text=True, timeout=60, check=True)
    assert os.path.basename(proc.stdout.strip()) == "ab"


def test_the_gate_names_the_directory_the_shell_runs_in(two_directories):
    (_name, directory, _detail), = gate.gated_calls(SPLIT_C, str(two_directories))
    assert directory == os.path.join(str(two_directories), "ab")


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_push_is_judged_in_ab_and_denied(two_directories, host):
    outcome = f2._decide(SPLIT_C, two_directories, host)
    assert f2._host_answer(outcome, host) == "deny", (outcome.decision, [v.reason_id for v in outcome.verdicts])
    if host == "claude":
        assert {v.reason_id for v in outcome.verdicts} == {"gate_error"}, outcome.verdicts


# --- the third consequence: the bytes of a proposed spelling ---------------------------------------------------------

SPLIT_MESSAGE = 'git commit -m "fix\\\n"#12'


@pytest.mark.parametrize("shell", SHELLS)
def test_the_shell_forms_fix12(repo, shell):
    assert _stub_words(shell, SPLIT_MESSAGE, repo) == ["commit", "-m", "fix#12"]


def test_the_proposal_carries_the_bytes_the_shell_forms():
    assert gate._narrower_spelling(SPLIT_MESSAGE) == "git commit -m 'fix#12'"


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_no_hint_names_a_backslash_or_a_newline_the_shell_removes(repo, host):
    outcome = f2._decide(SPLIT_MESSAGE, repo, host)
    assert outcome.decision != "pass"
    assert "fix\\\n" not in outcome.text and all("fix\\\n" not in v.next_step for v in outcome.verdicts)
