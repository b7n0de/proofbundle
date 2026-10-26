"""D39, part 2 of Nachtrag 14: `git diff --no-ext-diff --no-textconv`, a read form of class a whose filter check reads
the attributes.

`git diff` and `git show` are read forms of class a since D34; the read profile asks for `git diff` whenever any filter
key is configured (answer 2), and `git lfs install` puts one into the global configuration of most machines. With both
switches git starts no diff driver (measured with git 2.43.0: diff.external, GIT_EXTERNAL_DIFF, diff.<driver>.command
and textconv started for `git diff` without them and never with them); a filter starts only for a path an attribute
assigns it to; fsmonitor starts either way. So for `git diff` with both switches a configured filter counts only where
`git check-attr` finds a filter attribute on a path of the index; every other rule of the read profile stays, the
pager, the hooks, the submodules and every diff.* key that is no display setting among them.

RED at d6e248a8: the switch form in a repository without a filter attribute, with the lfs filter configured, asks
there and is free here; and the ask for a filter an attribute assigns names the path (text only). The asks of the
controls hold at both heads, each with a counter-probe in bash: the proxy starts for fsmonitor and for a filter an
attribute assigns. For diff.external the ask is the read profile's (the key is no display
setting); the counter-probe shows that with both switches the proxy does not start, and without them it does. Under
Codex every form keeps the reviewer's text of D37. Every repository lives under tmp_path and has no remote.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import test_plugin_done_check as d
from _plugin_env import plugin_env

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
G = str(d.GATE)
SWITCHED = "git diff --no-ext-diff --no-textconv --stat"
#: The filter section `git lfs install` writes into the global configuration.
LFS = '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n' \
      '\tprocess = git-lfs filter-process\n\trequired = true\n'


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment: no GIT_* name of the caller, no system file, a global file with the lfs filter, a home of
    its own, a folder for the markers."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    (tmp_path / "home").mkdir()
    (tmp_path / "marker").mkdir()
    (tmp_path / "global.gitconfig").write_text(LFS)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "global.gitconfig"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60,
                          check=True, env=plugin_env()).stdout


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """One commit and an unstaged change of a tracked file; no remote, no attribute."""
    repo = tmp_path / name
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60, env=plugin_env())
    for key, value in (("user.name", "t"), ("user.email", "t@example.org"), ("commit.gpgsign", "false")):
        _git(repo, "config", key, value)
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "one")
    (repo / "a.txt").write_text("one\ntwo\n")
    os.utime(repo / "a.txt", (1, 1))   # a stat change, so git reads the file again
    return repo


def _proxy(tmp_path: pathlib.Path, name: str, body: str = "exit 0") -> str:
    path = tmp_path / f"{name}.sh"
    path.write_text(f'#!/bin/sh\necho "$0 $*" >> {tmp_path / "marker" / name}.log\n{body}\n')
    path.chmod(0o755)
    return str(path)


def _started(tmp_path: pathlib.Path) -> list[str]:
    return sorted(p.stem for p in (tmp_path / "marker").glob("*.log"))


def _answer(cwd: pathlib.Path, command: str, host: str = "claude") -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


def _bash(repo: pathlib.Path, command: str) -> None:
    subprocess.run(["bash", "-c", command], cwd=repo, capture_output=True, timeout=60, check=False,
                   env=plugin_env(), stdin=subprocess.DEVNULL)


@pytest.mark.parametrize("form", [SWITCHED, "git diff --no-textconv --no-ext-diff", "git diff --no-ext-diff "
                                  "--no-textconv --name-only -- a.txt"])
def test_P2_the_switched_diff_is_free_where_no_attribute_assigns_a_filter(tmp_path, form):
    repo = _repo(tmp_path)
    assert _answer(repo, form) == (0, None, "")


def test_P2_the_switched_diff_with_one_literal_dash_C_is_free(tmp_path):
    repo = _repo(tmp_path)
    assert _answer(tmp_path, f"git -C {repo} {SWITCHED[4:]}") == (0, None, "")


def _assigned(tmp_path: pathlib.Path, repo: pathlib.Path, place: str) -> None:
    """The lfs filter stays configured; the attribute names a second driver, whose clean program is the proxy (the lfs
    driver's process program would take precedence over a clean program, and git-lfs need not be installed)."""
    line = "*.txt filter=probe\n"
    if place == "work_tree":
        (repo / ".gitattributes").write_text(line)
    elif place == "info":
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "attributes").write_text(line)
    else:
        (tmp_path / "home" / ".config" / "git").mkdir(parents=True)
        (tmp_path / "home" / ".config" / "git" / "attributes").write_text(line)
    _git(repo, "config", "filter.probe.clean", _proxy(tmp_path, "clean", "cat"))


@pytest.mark.parametrize("place", ["work_tree", "info", "global"])
def test_P2_control_a_filter_an_attribute_assigns_asks_and_starts_in_bash(tmp_path, place):
    repo = _repo(tmp_path)
    _assigned(tmp_path, repo, place)
    code, decision, reason = _answer(repo, SWITCHED)
    assert (code, decision) == (0, "ask") and "a filter" in reason, reason
    assert _started(tmp_path) == []          # the gate's own check started nothing
    _bash(repo, SWITCHED)
    assert _started(tmp_path) == ["clean"]


def test_P2_the_ask_names_the_path_an_attribute_assigns_a_filter_to(tmp_path):
    """RED at d6e248a8 by its text only: the ask was the same, and named the configured key alone."""
    repo = _repo(tmp_path)
    _assigned(tmp_path, repo, "work_tree")
    reason = _answer(repo, SWITCHED)[2]
    assert "assigned to a.txt by an attribute" in reason and "probe" not in reason, reason   # no value (D49)


def test_P2_control_fsmonitor_asks_and_starts_in_bash(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "core.fsmonitor", _proxy(tmp_path, "fsmonitor"))
    code, decision, reason = _answer(repo, SWITCHED)
    assert (code, decision) == (0, "ask"), reason
    assert _started(tmp_path) == []
    _bash(repo, SWITCHED)
    assert _started(tmp_path) == ["fsmonitor"]


def test_P2_control_diff_external_asks_and_starts_in_bash_only_without_the_switches(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "diff.external", _proxy(tmp_path, "external"))
    code, decision, reason = _answer(repo, SWITCHED)
    assert (code, decision) == (0, "ask"), reason
    _bash(repo, SWITCHED)
    assert _started(tmp_path) == []          # measured: --no-ext-diff keeps it from starting
    _bash(repo, "git diff")
    assert _started(tmp_path) == ["external"]


@pytest.mark.parametrize("form", ["git diff --stat", "git diff --no-ext-diff --stat", "git diff --no-textconv --stat",
                                  "git status"])
def test_P2_control_without_both_switches_the_filter_key_still_asks(tmp_path, form):
    repo = _repo(tmp_path)
    code, decision, reason = _answer(repo, form)
    assert (code, decision) == (0, "ask") and "a filter: filter.lfs" in reason, reason


@pytest.mark.parametrize("form", [SWITCHED, "git diff --stat", "git show --no-ext-diff --no-textconv --stat"])
def test_P2_control_under_codex_every_form_keeps_the_reviewer_text(tmp_path, form):
    repo = _repo(tmp_path)
    code, decision, reason = _answer(repo, form, "codex")
    assert (code, decision) == (0, "deny") and "Under Codex, even with an absolute git -C path" in reason, reason


@pytest.mark.parametrize("form", ["git diff --stat", SWITCHED, "git show --no-ext-diff --no-textconv --stat"])
def test_P2_control_without_any_filter_key_the_read_forms_stay_free(tmp_path, form):
    """D34 unchanged: with no filter key `git diff` is free with or without the switches, and so is `git show`."""
    (tmp_path / "global.gitconfig").write_text("")
    repo = _repo(tmp_path)
    assert _answer(repo, form) == (0, None, "")


@pytest.mark.parametrize("target", [".gitattributes", "sub/.gitattributes", ".git/info/attributes"])
def test_P2_control_a_step_that_writes_an_attributes_file_before_the_switched_diff_asks(tmp_path, target):
    """Class c: the attributes the filter check read are state; a step before that writes an attributes file may assign
    a filter the check did not see, so the switched diff asks (step_after_state_change). Asked at d6e248a8 as well."""
    repo = _repo(tmp_path)
    (repo / "sub").mkdir()
    _git(repo, "config", "filter.probe.clean", _proxy(tmp_path, "clean", "cat"))
    command = f"printf '*.txt filter=probe\\n' > {target} && {SWITCHED}"
    code, decision, reason = _answer(repo, command)
    assert (code, decision) == (0, "ask"), reason
    if target == ".gitattributes":
        _bash(repo, command)
        assert _started(tmp_path) == ["clean"]


def test_P2_a_step_that_writes_another_file_before_the_switched_diff_leaves_it_free(tmp_path):
    """RED at d6e248a8 (the filter key asked): a write of a file git reads no attributes from changes nothing the
    check read, so class c judges the switched diff on its own."""
    repo = _repo(tmp_path)
    assert _answer(repo, f"printf 'x\\n' > notes.txt && {SWITCHED}") == (0, None, "")
