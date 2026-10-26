"""D54, Nachtrag 21 part 1 (review Runde 24, R24-1): the gh helper is free only in its two literal forms.

Found by the reviewer of round 24 at 6459ff53: the fetch profile split the value of credential.helper with shlex and
checked the words, but git hands the value after the `!` to a shell. `!"<tmp>/`touch review24_marker`/gh" auth
git-credential` gave shlex one absolute word ending in /gh, the gh on PATH when its folder is that very name, so the
fetch was free; the shell ran `touch` first and then started another gh. Owner choice of 2026-10-16: the helper is free
only as `!gh auth git-credential` or `!<abs> auth git-credential`, one space between the words, <abs> an absolute path
of A-Z a-z 0-9 / . _ + - only that ends in /gh, read on the value as git keeps it; everything else asks, a form the shell
reads literally (single quotes, a space in a double-quoted path) included.

Ground truth, git 2.43.0 and dash with a stand-in gh, `git credential fill` per form (truth_n21_helper.py of the
delivery): the backtick and $(…) forms ran touch, the $HOME and ${HOME} forms started a gh in the hook's HOME instead of
the one checked, a line end after git-credential made git's `get` a second command; the two literal forms started the
stand-in gh with `auth git-credential get` and nothing else.

Each asking form is built so that its gh is the gh on PATH, the case 6459ff53 freed: RED there, green after. The line
end followed by a second command asked at both (control). The two literal forms are free at both (controls); /usr/bin/gh
of the owner's example is not on this machine, so the absolute form uses the stand-in at <tmp>/usr/bin/gh, and the
grammar is checked on the exact text `!/usr/bin/gh auth git-credential` as well.
"""
from __future__ import annotations

import os
import pathlib

import pytest

import _worktree_layout as w
import test_plugin_ask_load_b_gh as b
import test_plugin_fetch_github_profile as f

pytestmark = w.d.pytestmark
gate = f.gate
COMMAND = "git -C {a} fetch -q origin main"
UNKNOWN = "a credential helper the fetch profile does not know: credential.helper in the local configuration"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    f._clean.__wrapped__(monkeypatch, tmp_path)


@pytest.fixture
def repo(tmp_path):
    return f.repo.__wrapped__(tmp_path)


def _gh_on_path(monkeypatch, folder: pathlib.Path) -> pathlib.Path:
    """The stand-in gh in folder, and folder first on PATH: the gh a value names is then the gh the profile checks."""
    folder.mkdir(parents=True, exist_ok=True)
    b._fake_gh(folder)
    monkeypatch.setenv("PATH", os.pathsep.join([str(folder), "/usr/local/bin", "/usr/bin", "/bin"]))
    return folder / "gh"


def _forms(tmp_path: pathlib.Path) -> dict:
    """name: (the folder of the gh on PATH, the value of credential.helper)."""
    t = tmp_path
    return {
        "reviewer: backticks in a double-quoted path": (t / "`touch review24_marker`",
                                                        '!"{d}/gh" auth git-credential'),
        "$(…) in a double-quoted path": (t / "$(touch review24_dollar)", '!"{d}/gh" auth git-credential'),
        "${HOME} in a double-quoted path": (t / "${HOME}", '!"{d}/gh" auth git-credential'),
        "$HOME in a double-quoted path": (t / "$HOME", '!"{d}/gh" auth git-credential'),
        "single quotes around the path": (t / "bin", "!'{d}/gh' auth git-credential"),
        "a space in the path": (t / "my bin", '!"{d}/gh" auth git-credential'),
        "a tab between gh and auth": (t / "bin", "!gh\tauth git-credential"),
        "a tab after an absolute path": (t / "bin", "!{d}/gh\tauth git-credential"),
        "a line end after git-credential": (t / "bin", "!gh auth git-credential\n"),
        "a line end in the path": (t / "a\nb", '!"{d}/gh" auth git-credential'),
        "two spaces between the words": (t / "bin", "!gh  auth git-credential"),
        "a backslash before a letter of the path": (t / "bin", "!{d}/g\\h auth git-credential"),
    }


ASKS = list(_forms(pathlib.Path("/t")))


@pytest.mark.parametrize("name", ASKS)
def test_N21_a_gh_helper_that_is_not_one_of_the_two_literal_forms_asks(tmp_path, repo, monkeypatch, name):
    folder, value = _forms(tmp_path)[name]
    _gh_on_path(monkeypatch, folder)
    w.git(repo, "config", "credential.helper", value.format(d=folder))
    out = f._decide(repo, COMMAND)
    assert f._asked(out) and UNKNOWN in out.text, (name, out and out.text)
    assert "touch" not in out.text and "review24" not in out.text, out.text
    assert not list(tmp_path.rglob("review24_*")), "the gate judged the value, it ran nothing"


def test_N21_control_a_line_end_and_a_second_command_ask_at_both(tmp_path, repo, monkeypatch):
    _gh_on_path(monkeypatch, tmp_path / "bin")
    w.git(repo, "config", "credential.helper", "!gh auth git-credential\ntouch review24_newline")
    out = f._decide(repo, COMMAND)
    assert f._asked(out) and UNKNOWN in out.text, out and out.text


def test_N21_control_the_bare_literal_form_is_free(tmp_path, repo, monkeypatch):
    _gh_on_path(monkeypatch, tmp_path / "bin")
    w.git(repo, "config", "credential.helper", "!gh auth git-credential")
    assert f._fetch_free(f._decide(repo, COMMAND))


def test_N21_control_the_absolute_literal_form_is_free(tmp_path, repo, monkeypatch):
    gh = _gh_on_path(monkeypatch, tmp_path / "usr" / "bin")
    assert set(str(gh)) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/._+-"), gh
    w.git(repo, "config", "credential.helper", f"!{gh} auth git-credential")
    assert f._fetch_free(f._decide(repo, COMMAND))


def test_N21_the_absolute_literal_form_keeps_the_ask_where_its_gh_is_not_the_gh_on_path(tmp_path, repo, monkeypatch):
    _gh_on_path(monkeypatch, tmp_path / "bin")
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    b._fake_gh(tmp_path / "usr" / "bin")
    w.git(repo, "config", "credential.helper", f"!{tmp_path / 'usr' / 'bin' / 'gh'} auth git-credential")
    out = f._decide(repo, COMMAND)
    assert f._asked(out) and "names a gh that is not the gh on PATH" in out.text, out and out.text


@pytest.mark.parametrize("value, literal", [
    ("!gh auth git-credential", True), ("!/usr/bin/gh auth git-credential", True), ("!/gh auth git-credential", True),
    ("!/opt/g_h-2.89+x/bin/gh auth git-credential", True),
    ("!/usr/bin/xgh auth git-credential", False), ("!usr/bin/gh auth git-credential", False),
    ("! gh auth git-credential", False), ("!gh auth git-credential ", False), (" !gh auth git-credential", False),
    ("!gh auth git-credential\n", False), ("!/usr/bin/gh auth git-credential get", False),
    ("!/usr/b~n/gh auth git-credential", False), ("!/usr/bïn/gh auth git-credential", False),
    ("!/usr/bin/gh auth git-credential", False), ("gh auth git-credential", False)])
def test_N21_the_grammar_is_read_on_the_text_as_git_keeps_it(value, literal):
    assert (gate._GH_HELPER_FORM.fullmatch(value) is not None) is literal, value
