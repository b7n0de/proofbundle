"""N405-a over 73e48202 (Nachtrag 28, Teil B): the memo of the state files holds for the writes of one command only.

D96 reads the state files of a folder once while class c judges the writes of one command, and keeps no memo outside
it. Since 1920006a the memo is a context variable that _sh_write_verdicts sets and resets, so no function rebinds a
module-level name (N405-a). A memo left set after a command would carry the state files the gate read for it into the
next decision of the same process: a file the configuration includes since then would not count as one. The hook and
the signer service decide once per process; decide() in a test, a measurement or another caller may decide more often.

The cases: after a Bash command that writes in the repository the memo is unset, and a Write and a second command to a
file the configuration has come to include since are named as writes to the repository's state; within one command the
state files of a folder are read once (D96), and the module of the key paths is loaded once (D102), as their texts say.
The mutants of the fix that switch the memo off or load the module each time keep every verdict; these two cases are
what tells them apart.
"""
from __future__ import annotations

import subprocess
import time

import test_plugin_n39_path_words_d96 as d96

gate = d96.gate
pytestmark = d96.pytestmark
_clean = d96._clean
repo = d96.repo


def _include(repo):
    subprocess.run(["git", "-C", str(repo), "config", "--add", "include.path", "../notes.cfg"], check=True,
                   timeout=60)


def test_after_a_command_that_writes_the_memo_is_unset(repo):
    out = d96._out(repo, "cp f.txt sub/x")
    assert "write_to_repo_state" not in d96._ids(out)
    assert gate._STATE_FILES_MEMO.get() is None


def test_a_file_tool_write_after_a_command_reads_the_state_files_anew(repo):
    d96._out(repo, "cp f.txt sub/x")
    _include(repo)
    out = gate.decide_write("Write", {"file_path": str(repo / "notes.cfg")}, str(repo), time.monotonic() + 60,
                            "claude")
    assert "write_to_repo_state" in d96._ids(out), d96._ids(out)


def test_a_second_command_reads_the_state_files_anew(repo):
    d96._out(repo, "cp f.txt sub/x")
    _include(repo)
    assert "write_to_repo_state" in d96._ids(d96._out(repo, "cp f.txt notes.cfg"))


def test_within_one_command_the_state_files_of_a_folder_are_read_once(repo, monkeypatch):
    reads = []
    real = gate._state_files_read

    def counted(directory, deadline):
        reads.append(directory)
        return real(directory, deadline)

    monkeypatch.setattr(gate, "_state_files_read", counted)
    d96._out(repo, "cp f.txt sub/x && cp f.txt sub/y && cp f.txt sub/z")
    assert reads and len(reads) == len(set(reads)), reads


def test_the_module_of_the_key_paths_is_loaded_once():
    assert gate._secrets() is gate._secrets()
