"""A shell the host does not have is no failure of the gate's shell-differential tests (finding 9, review package -1).

Measured on 2026-10-26 on a host without zsh: tests/test_plugin_gate_runde14_n35.py and
tests/test_plugin_gate_runde15_n37.py failed in 35 cases with FileNotFoundError. Their probe
`subprocess.run([shell, "-c", "exit 0"]).returncode` branches on the exit code and has no branch for a program that is
not installed, and runde14 names zsh by the fixed path /usr/bin/zsh. On a host with zsh but without dash on PATH,
runde15 failed in 21 cases the same way (measured the same day).

The property held here: with a PATH that holds every program of the caller's PATH except zsh and dash, the two
differential tests end without a failure; a shell that is missing drops out of the differential with a warning that
its reading is NOT MEASURED, as a shell that does not start already did. The external review of -1 (TESTS, T-1 and
finding 1) names the sibling where bash is missing: runde13, runde14 and runde15 probe bash when the module is
collected, so without bash on PATH the three modules must still be collected, with their bash cases skipped.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

from _plugin_env import plugin_env

TESTS = pathlib.Path(__file__).resolve().parent
MODULES = ("test_plugin_gate_runde14_n35.py", "test_plugin_gate_runde15_n37.py")
#: The shells taken off PATH, with the names their packages install them under.
ABSENT = frozenset({"zsh", "zsh5", "zsh-static", "rzsh", "dash"})


def _bin_without(tmp_path: pathlib.Path, absent: frozenset = ABSENT) -> pathlib.Path:
    """A folder of links to every program on the caller's PATH except the shells in absent, the first one found first."""
    folder = tmp_path / "bin"
    folder.mkdir()
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isdir(entry):
            continue
        for name in sorted(os.listdir(entry)):
            target = os.path.join(entry, name)
            if name in absent or (folder / name).exists() or not os.access(target, os.X_OK):
                continue
            (folder / name).symlink_to(target)
    return folder


def test_a_missing_shell_is_no_failure_of_the_shell_differential(tmp_path):
    folder = _bin_without(tmp_path)
    if not (folder / "bash").exists():
        pytest.skip("bash is not installed here, so the differential has no shell to run (NOT MEASURED)")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                           *(str(TESTS / m) for m in MODULES), "-k", "net_covers_every"],
                          capture_output=True, text=True, env=plugin_env(PATH=str(folder)), cwd=TESTS.parent,
                          timeout=600, check=False)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert " passed" in proc.stdout and " failed" not in proc.stdout, proc.stdout[-2000:]


def test_a_missing_bash_is_no_error_when_the_differentials_are_collected(tmp_path):
    folder = _bin_without(tmp_path, ABSENT | {"bash"})
    modules = ("test_plugin_gate_runde13_n33.py", *MODULES)
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--collect-only",
                           *(str(TESTS / m) for m in modules)],
                          capture_output=True, text=True, env=plugin_env(PATH=str(folder)), cwd=TESTS.parent,
                          timeout=600, check=False)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert " error" not in proc.stdout, proc.stdout[-2000:]
