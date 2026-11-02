"""Review round 2 of 2026-10-09, R2-6: what does not provably stay literal gets no positive form.

Measured by the reviewer at 87dcbed8: under zsh with MAGIC_EQUAL_SUBST, `a==git` becomes `a=` and the path of the git
program, and the predicate said False, so `git add a==git` was free under both hosts; the same for `''~` under zsh,
and for a backslash-newline before `~` under bash and zsh. The predicate read the raw word for a leading `~` or `=`
and for a `~` after `=` or `:`, but not after the shell had removed an empty quote or a line continuation, and not for
an `=` after `=`.

The class: a word the shell expands at a place the predicate did not look. Now the predicate reads the word as the
shell will see its expansion points: a line continuation (backslash-newline) is removed first, an empty quote adds
nothing, and an unquoted `~` or `=` that comes first, or right after an unquoted `=` or `:`, may be expanded. The tilde
the gate models in a `-C` value is only one the word starts with as written. Red against 87dcbed8.
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

HOME = f2.HOME
GIT = shutil.which("git") or "/usr/bin/git"

#: (word as written, shell and options, what the shell gives instead of the word the gate reads).
REWRITTEN = {
    "equals after equals (zsh magicequalsubst)": ("a==git", "zsh -o magicequalsubst", f"a={GIT}"),
    "empty quote before the tilde (zsh)": ("''~", "zsh", HOME),
    "empty double quote before the tilde (zsh)": ('""~', "zsh", HOME),
    "line continuation before the tilde (bash)": ("\\\n~", "bash", HOME),
    "line continuation before the tilde (zsh)": ("\\\n~", "zsh", HOME),
    "line continuation after an equals sign (bash)": ("a=\\\n~", "bash", f"a={HOME}"),
    "empty quote after an equals sign (zsh magicequalsubst)": ("a=''~", "zsh -o magicequalsubst", f"a={HOME}"),
    "equals after a colon (zsh magicequalsubst)": ("a=b:=git", "zsh -o magicequalsubst", f"a=b:{GIT}"),
}
LITERAL = ["a=b", "a.txt~b", "'a=~'", "--opt=value", "a=''", "x\\=y", "'~'", "\\~", "a\\\nb", "x:y"]


def _shell_word(shell: str, word: str, cwd: pathlib.Path) -> list[str]:
    program, *options = shell.split()
    if shutil.which(program) is None:
        pytest.skip(f"{program} is not installed")
    proc = subprocess.run([program, *options, "-c", f"printf '%s\\n' {word}"], cwd=cwd, capture_output=True,
                          text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


@pytest.mark.parametrize("word,shell,gives", REWRITTEN.values(), ids=REWRITTEN.keys())
def test_the_shell_really_rewrites_the_word(tmp_path, word, shell, gives):
    """Non-vacuous: the named shell gives another word than the one the lexer reads."""
    got = _shell_word(shell, word, tmp_path)
    lexed = [t[1] for t in gate._lex(f"git add {word}") if t[0] == "word"][2:]
    if gives is not None:
        assert got == [gives], (shell, got)
    assert got != lexed, (shell, got, lexed)


@pytest.mark.parametrize("word,shell,gives", REWRITTEN.values(), ids=REWRITTEN.keys())
def test_the_predicate_names_the_rewrite(word, shell, gives):
    assert gate._shell_rewrites(word), word
    assert gate._shell_rewrites(word, tilde_modelled=True), word


@pytest.mark.parametrize("word", LITERAL)
def test_the_predicate_leaves_a_literal_word(word):
    assert not gate._shell_rewrites(word), word


@pytest.mark.parametrize("word,shell,gives", REWRITTEN.values(), ids=REWRITTEN.keys())
def test_git_add_with_such_a_word_is_not_free_under_either_host(repo, word, shell, gives):
    command = f"git add {word}"
    for host in ("claude", "codex"):
        outcome = f2._decide(command, repo, host)
        assert outcome.decision != "pass", (host, command)
        assert f2._host_answer(outcome, host) == ("ask" if host == "claude" else "deny")


@pytest.mark.parametrize("value", ["''~", '""~'])
def test_a_c_value_the_shell_may_expand_differently_leaves_the_push_not_measured(value):
    calls = gate.gated_calls(f"git -C {value} push origin main", "/work")
    assert calls and all(directory is gate.UNKNOWN for _n, directory, _d in calls), calls


def test_a_continuation_before_the_tilde_is_removed_as_the_shell_removes_it():
    """Review round 3 (R3-1): a line continuation is removed before the shell reads the word, so `\\<LF>~` is the
    plain `~`, which bash 5.2 and zsh 5.9 both expand to the home directory (measured); the gate resolves it so."""
    for shell in ("bash", "zsh"):
        if shutil.which(shell) is None:
            continue
        proc = subprocess.run([shell, "-c", "printf %s \\\n~"], capture_output=True, text=True, timeout=30)
        assert proc.stdout == os.path.expanduser("~"), (shell, proc.stdout)
    (_name, directory, _detail), = gate.gated_calls("git -C \\\n~ push origin main", "/work")
    assert directory == os.path.expanduser("~")
