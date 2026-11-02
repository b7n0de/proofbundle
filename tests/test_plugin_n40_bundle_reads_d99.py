"""D99, follow-up note 40 (B40-2 and B40-3): the heads of a bundle and the state of git's own fsmonitor daemon are reads.

Found on account A at f9e5f18e: `git -C <clone> bundle list-heads <bundle>` and `git fsmonitor--daemon status` were blocked
under the switch (possible_unmodeled_push); `git -C <clone> bundle verify <bundle>` ran free (D91).

Measured with git 2.43.0 (truth_b40.py of the delivery): `bundle list-heads` and `verify` started git only and no hook
and wrote nothing; `git fsmonitor--daemon` status, start, stop and run exited 128 on this platform. git added the daemon
in 2.36; on an older git the word runs an alias or a program git-fsmonitor--daemon on PATH.

The rule (D99): `git bundle list-heads <file>` is a read form of D71 and of the local class of D91 beside `bundle
verify`, and so is `git fsmonitor--daemon status` where the git on PATH lists it among its built-in commands (git
--list-cmds=builtins); the gate's own probe of D74 asks the same before it runs.

RED at f9e5f18e: list-heads and status, and the probe of D74 on a git without the daemon. The catch cases (standard
input, ref names, unbundle, start, stop and run, -c, Codex, a git without the daemon) are green at both.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import time

import pytest

import test_plugin_n40_bundle_fetch_d98 as d98

gate = d98.gate
pytestmark = d98.pytestmark
_clean = d98._clean
_cmd = d98._cmd
answered = d98.answered


@pytest.fixture
def env(tmp_path, monkeypatch):
    return d98.setup(tmp_path, monkeypatch)


#: B40-2 and B40-3, free at the head as reads of the local class (D91); at f9e5f18e list-heads and status were blocked.
READS = ["git -C {C} bundle list-heads {B}", "git bundle list-heads {B}", "git -C {C} fsmonitor--daemon status",
         "git fsmonitor--daemon status"]


@pytest.mark.parametrize("form", READS)
def test_B40_2_and_3_the_bundle_heads_and_the_daemon_status_are_reads(env, form):
    decision, reasons = answered(env, _cmd(form, env))
    assert decision == "pass" and "free_local_reversible" in reasons, (form, decision, reasons)


@pytest.mark.parametrize("form", ["git -C {C} bundle verify {B}", "git -C {C} bundle verify -q {B}"])
def test_B40_2_control_bundle_verify_stays_a_read(env, form):
    decision, reasons = answered(env, _cmd(form, env))
    assert decision == "pass" and "free_local_reversible" in reasons, (form, decision, reasons)


@pytest.mark.parametrize("form", [
    "git -C {C} bundle list-heads -", "git -C {C} bundle list-heads {B} refs/heads/topic",
    "git -C {C} bundle list-heads --x {B}", "git -C {C} bundle unbundle {B}", "git -C {C} bundle list-heads",
    "git -C {C} fsmonitor--daemon start", "git -C {C} fsmonitor--daemon stop", "git -C {C} fsmonitor--daemon run",
    "git -C {C} fsmonitor--daemon status --x", "git -C {C} fsmonitor--daemon", "git -C {C} -c x.y=z fsmonitor--daemon status",
])
def test_B40_2_and_3_catch_other_forms_are_no_reads(env, form):
    decision, reasons = answered(env, _cmd(form, env))
    assert decision != "pass", (form, decision, reasons)


@pytest.mark.parametrize("form", READS)
def test_B40_2_and_3_control_under_codex_they_keep_their_answer(env, form):
    decision, reasons = answered(env, _cmd(form, env), "codex")
    assert decision in ("ask", "deny"), (form, decision, reasons)


def _git_without_daemon(tmp_path, monkeypatch) -> pathlib.Path:
    """A git first on PATH that lists no fsmonitor--daemon among its built-in commands, as git 2.34.1 (git 2.36 added
    the daemon), logs every call and hands every other call to the git of the container."""
    real = shutil.which("git")
    folder = tmp_path / "git_old"
    folder.mkdir()
    log = tmp_path / "git_old.log"
    (folder / "git").write_text(f'#!/bin/sh\necho "$*" >> "{log}"\n'
                                f'case " $* " in *" --list-cmds=builtins "*) "{real}" "$@" | grep -v "^fsmonitor--daemon$"; '
                                f'exit 0;; esac\nexec "{real}" "$@"\n')
    (folder / "git").chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([str(folder), os.environ["PATH"]]))
    return log


def test_B40_3_where_the_daemon_is_no_built_in_command_the_status_is_no_read(env, tmp_path, monkeypatch):
    """On a git without the daemon `git fsmonitor--daemon` runs an alias or a program of that name on PATH."""
    log = _git_without_daemon(tmp_path, monkeypatch)
    decision, reasons = answered(env, _cmd("git -C {C} fsmonitor--daemon status", env))
    assert decision != "pass", (decision, reasons)
    calls = log.read_text().splitlines() if log.exists() else []
    assert not any(line.split()[-2:] == ["fsmonitor--daemon", "status"] for line in calls), calls


def test_B40_3_the_gate_itself_runs_no_daemon_status_where_git_has_no_daemon(env, tmp_path, monkeypatch):
    """D74 asked `git fsmonitor--daemon status` itself to know whether core.fsmonitor=true starts anything; on a git
    without the daemon that word runs an alias or a program. Now the gate asks git --list-cmds=builtins first."""
    log = _git_without_daemon(tmp_path, monkeypatch)
    glob = tmp_path / "global.gitconfig"
    glob.write_text("[core]\n\tfsmonitor = true\n")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home2"))
    (tmp_path / "home2").mkdir()
    shutil.copy(glob, tmp_path / "home2" / ".gitconfig")
    known = gate._fsmonitor_known("global", f"file:{tmp_path / 'home2' / '.gitconfig'}", "true", str(env["C"]),
                                  time.monotonic() + 60, {"HOME": os.environ["HOME"], "PATH": os.environ["PATH"]})
    assert known is False
    calls = log.read_text().splitlines() if log.exists() else []
    assert not any("fsmonitor--daemon status" in line for line in calls), calls
