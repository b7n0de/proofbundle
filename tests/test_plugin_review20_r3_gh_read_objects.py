"""R20-3 of review round 20 (Nachtrag 10 to FIX-18): a write step is judged against the files the later step's answer
actually read, not only against the folder they sit in.

Class c (D33) with class b (D36): the gh profile reads config.yml and hosts.yml in gh's configuration folder and the gh
program on PATH. A data step before the gh step that writes one of them changes what the profile read. A write through
a path outside the folder reached the same file where config.yml or hosts.yml is a symbolic link or a hard link to it,
and the chain stayed pass, free_after_gh_profile, under both hosts.

RED at b34ba9a2 for both link kinds, both files and both hosts, and for the sibling of the gh program a step overwrites;
green after. The unchanged configuration and a write to an unrelated file stay free; the direct path keeps its ask.
"""
from __future__ import annotations

import os
import pathlib
import shlex

import pytest

import test_plugin_ask_load_b_gh as b
from _plugin_env import plugin_env

pytestmark = b.pytestmark
_clean = b._clean

#: What a write step appends: the pager setting the profile refuses, in the place of each file.
APPEND = {"config.yml": "pager: /tmp/review-marker", "hosts.yml": "    pager: /tmp/review-marker"}
START = {"config.yml": "", "hosts.yml": "github.com:\n"}


def _linked(tmp_path: pathlib.Path, name: str, kind: str) -> pathlib.Path:
    """A regular file outside gh's folder that the folder's config.yml or hosts.yml names by a link; returns it."""
    outside = tmp_path / f"outside-{name}"
    outside.write_text(START[name], encoding="utf-8")
    inside = tmp_path / "home" / ".config" / "gh" / name
    if kind == "symlink":
        inside.symlink_to(outside)
    else:
        os.link(outside, inside)
    return outside


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("name", ["config.yml", "hosts.yml"])
def test_R20_3_a_write_to_the_file_a_link_names_keeps_the_gh_step_from_being_free(tmp_path, name, kind, host):
    repo = b._repo(tmp_path)
    outside = _linked(tmp_path, name, kind)
    assert b._decide(repo, "gh pr view 1", host)[0] in b.FREE, "the unchanged configuration is free"
    command = f"echo {shlex.quote(APPEND[name])} >> {shlex.quote(str(outside))}; gh pr view 1"
    decision, reasons = b._decide(repo, command, host)
    assert decision in ("ask", "deny") and "free_after_gh_profile" not in reasons, (decision, reasons)
    # the step changes exactly the file the profile reads: run alone, the profile then finds the pager
    with open(outside, "a", encoding="utf-8") as handle:
        handle.write(APPEND[name] + "\n")
    assert b.gate._gh_config_problem(plugin_env()) is not None


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_R20_3_sibling_a_write_to_the_gh_program_keeps_the_gh_step_from_being_free(tmp_path, host):
    """The profile reads the gh on PATH (`gh --version`); a step that overwrites that file, through a link too, keeps
    its mode and changes the program the gh step starts."""
    repo = b._repo(tmp_path)
    program = tmp_path / "bin" / "gh"
    alias = tmp_path / "gh-alias"
    os.link(program, alias)
    for target in (program, alias):
        command = f"cat {shlex.quote(str(program))} > {shlex.quote(str(target))}; gh pr view 1"
        decision, reasons = b._decide(repo, command, host)
        assert decision in ("ask", "deny") and "free_after_gh_profile" not in reasons, (target, decision, reasons)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_R20_3_control_the_direct_path_keeps_its_ask(tmp_path, host):
    repo = b._repo(tmp_path)
    path = tmp_path / "home" / ".config" / "gh" / "config.yml"
    path.write_text("", encoding="utf-8")
    decision, reasons = b._decide(repo, f"echo 'pager: less' >> {shlex.quote(str(path))}; gh pr view 1", host)
    # the append lies outside the work folder and is denied since D104 (Nachtrag 33); the step keeps its reason
    assert decision in ("ask", "deny") and "step_after_state_change" in reasons, reasons


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_R20_3_control_a_write_to_an_unrelated_file_stays_free(tmp_path, kind, host):
    repo = b._repo(tmp_path)
    _linked(tmp_path, "config.yml", kind)
    other = tmp_path / "notes.txt"
    # a write with `>`: an append outside the work folder is denied since D104 (Nachtrag 33)
    decision, reasons = b._decide(repo, f"echo x > {shlex.quote(str(other))}; gh pr view 1", host)
    assert decision in b.FREE and reasons == ["free_after_gh_profile"], (decision, reasons)


def test_R20_3_sibling_a_write_to_the_git_program_keeps_the_git_step_from_being_free(tmp_path):
    """The same class for a git step: the program `git` selects on PATH, here a wrapper, is what the step starts; a step
    that appends to it keeps its mode and changes that program (class a, Claude Code)."""
    repo = b._repo(tmp_path)
    wrapper = tmp_path / "bin" / "git"
    wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(b.shutil.which("git", path="/usr/local/bin:/usr/bin:/bin"))} "$@"\n',
                       encoding="utf-8")
    wrapper.chmod(0o755)
    assert b._decide(repo, "git log --oneline -1")[0] in b.FREE, "the wrapper alone keeps the read form free"
    decision, reasons = b._decide(repo, f"echo '# changed' >> {shlex.quote(str(wrapper))}; git log --oneline -1")
    assert decision in ("ask", "deny") and "free_after_read_profile" not in reasons, (decision, reasons)
    other = tmp_path / "notes.txt"
    # a write with `>`: an append outside the work folder is denied since D104 (Nachtrag 33)
    decision, reasons = b._decide(repo, f"echo x > {shlex.quote(str(other))}; git log --oneline -1")
    assert decision in b.FREE, (decision, reasons)
