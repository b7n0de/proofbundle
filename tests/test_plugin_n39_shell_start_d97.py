"""D97, Nachtrag 39 (F35-2, owner question O38-1): a write into a file the shell runs before a later Bash call.

The order: a write into the snapshots of the shell of Claude Code, into the start files of bash and into a file BASH_ENV
names carries the weight of _D72_WRITES; first measure which files Claude Code runs before a Bash call. Found in
PLUGIN_N35 (F35-2): `cat > ~/.bashrc <<'EOF' … EOF` got no answer.

Measured with Claude Code 2.1.303 and GNU bash 5.2.21 under strace -f (truth_shell_start_n39.sh, a fresh HOME whose start
files write a marker, two Bash calls, with and without BASH_ENV): before every call bash reads /etc/bash.bashrc,
~/.bashrc and the snapshot; when the snapshot is made, once per session, also /etc/profile, the files of /etc/profile.d,
~/.bash_profile (the first of it, ~/.bash_login and ~/.profile) and the file BASH_ENV names. Claude Code 2.1.302 is no
longer in this container (NOT MEASURED); zsh is not installed (its start files read, not measured).

The rule: decide_write names a write into one of these files, a hard link or a symbolic link to one, or a file in the
snapshot folder (CLAUDE_CONFIG_DIR/shell-snapshots, else ~/.claude/shell-snapshots), /etc/profile.d or /etc/zsh, as
write_to_shell_start: an ask under Claude Code, with the weight of _D72_WRITES on the line and as a catch in the bilanz.
It holds for the file tools and for every write class c finds in a command (D95, D96, redirections).

RED at f9e5f18e (the head of PLUGIN_N35): every write into a start file. Writes beside them and the settings of Claude
Code (a passage of satz_v1, Nachtrag 33) are controls, green at both.
"""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")


@pytest.fixture
def repo(tmp_path):
    r = d72._repo(tmp_path)
    (r / "f.txt").write_text("alias x=y\n")
    return r


def _home() -> str:
    return os.environ["HOME"]


def _out(repo, form, host="claude"):
    return gate.decide(form.replace("{H}", _home()), str(repo), time.monotonic() + 60, host)


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


#: Shell forms that write a start file; each got no answer at f9e5f18e.
SHELL_FORMS = [
    "cat > ~/.bashrc <<'EOF'\nalias ls=x\nEOF", "echo x >> ~/.bashrc", "echo x >> {H}/.bashrc",
    "echo x >> \"$HOME/.bash_profile\"", "echo x >> ${HOME}/.bash_login", "printf x > ~/.profile",
    "echo x >> ~/.bash_aliases", "cp f.txt ~/.bashrc", "tee -a ~/.bashrc < f.txt", "sort -o ~/.bashrc f.txt",
    "echo x > ~/.claude/shell-snapshots/snapshot-bash-1.sh", "rm -rf ~/.claude/shell-snapshots",
    "echo x >> ~/.zshenv", "echo x >> ~/.zshrc", "echo x > /etc/profile.d/x.sh", "echo x >> /etc/bash.bashrc",
    "echo x >> /etc/profile",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", SHELL_FORMS)
def test_D97_a_shell_write_into_a_start_file_asks(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision in ("ask", "deny") and "write_to_shell_start" in _ids(out), \
        (form, host, _ids(out))


@pytest.mark.parametrize("name", [".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_aliases", ".zshenv",
                                  ".zprofile", ".zshrc", ".zlogin", ".claude/shell-snapshots/snapshot-zsh-2.sh"])
def test_D97_a_file_tool_write_into_a_start_file_asks(repo, name):
    out = gate.decide_write("Write", {"file_path": os.path.join(_home(), name), "content": "x"}, str(repo),
                            time.monotonic() + 60, "claude")
    assert out is not None and out.decision == "ask" and "write_to_shell_start" in _ids(out), (name, _ids(out))


def test_D97_the_snapshot_folder_of_claude_config_dir_and_zdotdir_and_bash_env(repo, tmp_path, monkeypatch):
    config, zdot, env_file = tmp_path / "cfg", tmp_path / "zdot", tmp_path / "env" / "bash_env.sh"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config))
    monkeypatch.setenv("ZDOTDIR", str(zdot))
    monkeypatch.setenv("BASH_ENV", str(env_file))
    for path in (config / "shell-snapshots" / "snapshot-bash-3.sh", zdot / ".zshrc", env_file):
        out = _out(repo, f"echo x > {path}")
        assert out is not None and "write_to_shell_start" in _ids(out), (path, _ids(out))
    monkeypatch.setenv("BASH_ENV", "relative.sh")
    assert _out(repo, "echo x > relative.sh") is None   # a relative BASH_ENV is not read (the shell's folder decides)


def test_D97_a_link_to_a_start_file_counts(repo, tmp_path):
    home = tmp_path / "home"
    (home / ".bashrc").write_text("# start\n")
    (tmp_path / "links").mkdir()
    os.symlink(home / ".bashrc", tmp_path / "links" / "soft")
    os.link(home / ".bashrc", tmp_path / "links" / "hard")
    for name in ("soft", "hard"):
        out = _out(repo, f"echo x >> {tmp_path / 'links' / name}")
        assert out is not None and "write_to_shell_start" in _ids(out), (name, _ids(out))


@pytest.mark.parametrize("form", ["echo x > ~/.bashrc.bak", "echo x > ~/notes.txt", "cp f.txt ~/bin/tool",
                                  "echo x > ~/.claude/CLAUDE.md", "echo x > ~/.claude/shell-snapshots-old",
                                  "echo x > /etc/profile.bak", "cat ~/.bashrc", "grep alias ~/.bashrc",
                                  "head -3 ~/.profile", "ls -la ~/.claude/shell-snapshots"])
def test_D97_control_writes_beside_the_start_files_and_reads_get_no_answer(repo, form):
    assert _out(repo, form) is None, (form, _ids(_out(repo, form)))


def test_D97_the_write_gives_the_chain_its_reason_and_the_line_its_weight(repo):
    out = _out(repo, "echo x >> ~/.bashrc && git status")
    assert out.decision == "ask" and "write_to_shell_start" in _ids(out), _ids(out)
    line = d72._line(out)
    assert " git status because the write touches a file the shell runs before a later call (D97)." in line, line


def test_D97_the_reason_weighs_and_catches():
    assert "write_to_shell_start" in gate._D72_WRITES and "write_to_shell_start" in gate.FANG_REASONS
    assert gate._SHORT_REASONS["write_to_shell_start"][0] == "D97"
    assert gate._SHELL_START_HOME == (".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_aliases")


@pytest.mark.parametrize("command", ["echo x >> ~/.bashrc", "cp f.txt ~/.profile"])
def test_D97_under_the_switch_of_claude_code_the_write_is_denied(repo, tmp_path, command):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d97",
             "tool_input": {"command": command}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", "claude", gate.AUTONOMOUS_FLAG],
                              json.dumps(event), env, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny", proc.stdout
    assert "write_to_shell_start" in entry["reason_ids"], entry
