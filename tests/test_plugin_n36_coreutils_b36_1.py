"""B36-1, Nachtrag 36: at the Farmer head, tail, ls, date, sleep and wc are GNU coreutils 8.32, which D77 has not measured.

The order: measure 8.32 for options that run or write something, as 9.4 was measured; admit it where the result is the
same, every other version stays as it is. No program of coreutils 8.32 is in this container, no package of it in a
cache, no container service to start one, and the agent phase has no network (AGENTS.md): 8.32 is NOT MEASURED here, so
it stays out of D77 (_READ_PROGRAM_VERSIONS). The measurement for the Farmer is in the delivery (farmer_b36_1.sh with
truth_readprog_e1.py of Ergänzung 1 to Nachtrag 31).

The catch case per version and program: a program first on PATH that names 8.32 keeps the chain asking, one that names
9.4 leaves it silent. A control of today's rule, green at 53a8f4f7 and at the head; it turns red for 8.32 only when a
measurement admits that version.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

SEARCH = "find src | xargs grep -l 'git push'"
FORMS = {"head": "head -5 README.md", "tail": "tail -n 3 README.md", "ls": "ls -la", "date": "date -u",
         "sleep": "sleep 0", "wc": "wc -l README.md"}


@pytest.fixture
def work(tmp_path, monkeypatch):
    for key in ("BASH_ENV", "ENV", "CLAUDE_CONFIG_DIR"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SHELL", "/bin/bash")
    (tmp_path / "home").mkdir()
    (tmp_path / "w").mkdir()
    (tmp_path / "w" / "README.md").write_text("x\n")
    return tmp_path


def _fake(folder, name, version):
    folder.mkdir(exist_ok=True)
    (folder / name).write_text(f"#!/bin/sh\nprintf '%s\\n' '{name} (GNU coreutils) {version}'\nexit 0\n")
    (folder / name).chmod(0o755)


@pytest.mark.parametrize("version, silent", [("8.32", False), ("9.4", True)])
@pytest.mark.parametrize("name", sorted(FORMS))
def test_B36_1_each_program_counts_only_in_a_measured_version(work, monkeypatch, name, version, silent):
    _fake(work / "bin", name, version)
    monkeypatch.setenv("PATH", f"{work / 'bin'}:/usr/local/bin:/usr/bin:/bin")
    out = gate.decide(f"{FORMS[name]}; {SEARCH}", str(work / "w"), time.monotonic() + 60, "claude")
    assert (out is None) is silent, (name, version, out and out.decision)


def test_B36_1_the_measured_versions_are_what_the_decision_names():
    assert gate._READ_PROGRAM_VERSIONS == {"9.4"}
