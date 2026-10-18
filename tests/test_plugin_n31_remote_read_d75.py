"""D75, Nachtrag 31, R2: the read forms of `git remote` are read forms of class a.

Owner choice of 2026-10-18, 15:3x Berlin: `git remote`, `git remote -v`, `git remote get-url [--push] [--all] <name>` and
`git remote show -n <name>` become read forms of class a after strace. Measured with git 2.43.0 against a stand-in for
github.com (truth_remote_n31.py of the delivery): they started no program besides git, connected nowhere and wrote
nothing; pager.remote started its pager on a terminal, which the read profile counts. `git remote show` without -n,
update, prune, add, set-url, remove and rename keep their answer.

RED at 44db2056 (the head of Nachtrag 30): the free forms under Claude Code and the unit rows. The counter cases and the
answers under Codex are controls, green at both. No case reaches a network.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark

FREE = ["git remote", "git remote -v", "git remote --verbose", "git -C {R} remote -v", "git remote get-url origin",
        "git remote get-url --push origin", "git remote get-url --all origin", "git remote get-url --push --all origin",
        "git remote get-url --all --push origin", "git -C {R} remote get-url --push origin",
        "git remote show -n origin", "git -C {R} remote show -n origin"]
KEEP = ["git remote show origin", "git remote show", "git remote show -n", "git remote show -n origin upstream",
        "git remote update", "git remote prune origin", "git remote add x https://github.com/o/x",
        "git remote set-url origin https://github.com/o/y", "git remote remove origin", "git remote rename origin up",
        "git remote get-url", "git remote get-url origin upstream", "git remote get-url --push --push origin",
        "git remote get-url --foo origin", "git remote get-url -- origin", "git remote -v -v", "git remote -v show",
        "git remote -v > {T}/remotes.txt", "git -c core.pager=less remote -v"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment of the tests of D71: no GH_* or GIT_* name but the two empty configuration files."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME", "AI_AGENT")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gatedir"))
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    d71._fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _decide(repo, form, tmp_path, host="claude"):
    out = gate.decide(d71._command(form, repo, tmp_path), str(repo), time.monotonic() + 60, host)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("declared", [False, True])
@pytest.mark.parametrize("form", FREE)
def test_D75_a_read_form_of_git_remote_is_free_under_claude_code(tmp_path, form, declared):
    repo = d71._repo(tmp_path, declaration=d71.DECLARATION if declared else None)
    assert _decide(repo, form, tmp_path) == ("pass", ["free_after_read_profile"]), form


@pytest.mark.parametrize("form", FREE)
def test_D75_control_under_codex_a_read_form_of_git_remote_is_not_free(tmp_path, form):
    repo = d71._repo(tmp_path, declaration=None)
    decision, reasons = _decide(repo, form, tmp_path, "codex")
    assert decision in ("ask", "deny") and not any(r.startswith("free_") for r in reasons), (form, reasons)


@pytest.mark.parametrize("form", KEEP)
def test_D75_control_every_other_form_of_git_remote_keeps_its_answer(tmp_path, form):
    repo = d71._repo(tmp_path, declaration=None)
    decision, reasons = _decide(repo, form, tmp_path)
    assert decision in ("ask", "deny") and not any(r.startswith("free_") for r in reasons), (form, reasons)


@pytest.mark.parametrize("key, value", [("pager.remote", "less"), ("core.fsmonitor", "/bin/true"),
                                        ("credential.helper", "store")])
def test_D75_the_read_profile_judges_the_repository(tmp_path, key, value):
    """pager.remote started its pager on a terminal: the read profile asks for it, as for every pager key. The read
    profile's other rules hold too; a key it knows (a credential helper is one: no read form of git remote started it)
    leaves the form free."""
    repo = d71._repo(tmp_path, declaration=None)
    d71._git(repo, "config", key, value)
    decision, _reasons = _decide(repo, "git remote -v", tmp_path)
    assert decision == ("ask" if key == "pager.remote" else "pass"), (key, decision)


@pytest.mark.parametrize("args, free", [
    ([], True), (["-v"], True), (["--verbose"], True), (["get-url", "origin"], True),
    (["get-url", "--push", "--all", "o"], True), (["show", "-n", "origin"], True),
    (["show", "origin"], False), (["show"], False), (["get-url"], False), (["get-url", "-x"], False),
    (["get-url", "--all", "--all", "o"], False), (["get-url", "a", "b"], False), (["add", "x", "u"], False),
    (["-v", "-v"], False), (["show", "-n"], False), (["show", "-n", "-x"], False)])
def test_D75_the_grammar_of_the_read_forms(args, free):
    assert gate._remote_read_form(args, [False] * len(args)) is free, args
    if args:
        assert gate._remote_read_form(args, [True] + [False] * (len(args) - 1)) is False, args
