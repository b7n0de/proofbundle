"""B36-2, Nachtrag 36: the word is not the program. A read program of D77 is silent as a bare word only where the gate
measured that no alias, function or hashed path of the session's shell carries its name.

Found by delta at the Farmer (gate 89d2e8b7, zsh 5.8.1): `ls` is an alias for colorls in the session's shell, so the
command text `ls` starts another program than /usr/bin/ls, while D77 judged by the word.

Measured with bash 5.2.21 as Claude Code runs a command, the snapshot sourced and the text evaluated, a marker program in
place of the other one (messung/truth_alias_n36.tsv, truth_alias_n36.sh): a function, a `hash -p` entry, an exported
function (BASH_FUNC_ls%%) and a function from BASH_ENV make a bare `ls` run another program, and so does an alias once
expand_aliases is on; `command ls` runs its own program past an alias and a function, but not past `hash -p ls`, a
function named command or an alias `command='command '`; `/usr/bin/ls` runs another program only where a function
carries that path as its name; functions named `test` and `[` replace the builtins; `xargs ls` runs its own program in
every case (xargs starts the program by its path, not through the shell). zsh is not installed here (NOT MEASURED).

How the gate measures, without running the session's shell (_session_definitions): it reads the snapshots Claude Code
keeps of the shell (shell-snapshots under CLAUDE_CONFIG_DIR, else ~/.claude; measured with Claude Code 2.1.302: aliases,
functions as `eval $'name () …'`, shopt and PATH) for a definition of the name, and the names of exported functions in
its environment; it reads no value. BASH_ENV or ENV set, a .zshenv of the person under zsh, a shell other than bash, zsh,
sh or dash, more than 64 snapshots, one larger than 1 MiB or one that is no regular file leave the session NOT MEASURED.

The rule: a bare read program, `[` and `test` are silent only where the session is measured and defines none of them; a
read program written `command <name>` is silent unless a measured session defines `command` or hashes the name; one
written as an absolute path is silent unless a measured session defines that path as a name, with the version check of
D77 on that path; xargs starts its program by path, so the session does not count for it.

RED at 53a8f4f7 (B36-3): every shadowed bare word; `command <name>` and the absolute path, which D77 did not read. The
forms of a session that defines nothing, and Codex, are controls, green at both.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import time

import pytest

import test_plugin_n26_read_only_d66 as d66

gate = d66.gate
pytestmark = d66.pytestmark
_clean_git_environment = d66._clean_git_environment

LS = shutil.which("ls") or "/usr/bin/ls"
#: A read that names git as text, which the steps of D72 do not free (xargs carries a program): only D66 and D77 make
#: a chain with it silent.
SEARCH = "find src | xargs grep -l 'git push'"
#: The bare forms of D77 a definition of the session shadows, each with the name it uses.
BARE = [("ls", f"ls -la; {SEARCH}"), ("head", f"head -5 README.md; {SEARCH}"),
        ("tail", f"tail -n 3 README.md; {SEARCH}"), ("wc", f"wc -l README.md; {SEARCH}"), ("date", f"date -u; {SEARCH}"),
        ("sleep", f"sleep 0; {SEARCH}"), ("sort", f"{SEARCH} | sort"), ("test", f"test -f README.md && {SEARCH}"),
        ("[", f"[ -f README.md ] && {SEARCH}")]
#: How a session defines a name: Claude Code's own form of a function, a plain function, an alias, a hashed path.
DEFINITIONS = {
    "eval": "eval $'{n} () \\n{{ \\n    colorls\\n}}'",
    "function": "{n} () {{ colorls; }}",
    "keyword": "function {n} {{ colorls; }}",
    "alias": "alias -- {n}='colorls'",
    "alias_plain": "alias {n}=colorls",
    "hash": "hash -p /opt/colorls/bin/colorls {n}",
}


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home of its own, bash as the session's shell, no BASH_ENV or ENV, the PATH of the system."""
    for key in ("BASH_ENV", "ENV", "CLAUDE_CONFIG_DIR", "ZDOTDIR"):
        monkeypatch.delenv(key, raising=False)
    for key in [k for k in os.environ if k.startswith("BASH_FUNC_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    (tmp_path / "home").mkdir()
    (tmp_path / "w").mkdir()
    (tmp_path / "w" / "README.md").write_text("x\n")
    return tmp_path / "home"


def snapshot(home: pathlib.Path, text: str, name: str = "snapshot-bash-1792331021032-33s3ng.sh",
             folder: pathlib.Path | None = None) -> pathlib.Path:
    folder = folder or home / ".claude" / "shell-snapshots"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("# Snapshot file\nunalias -a 2>/dev/null || true\nshopt -u expand_aliases\n# Functions\n"
                    f"{text}\n# Aliases\nexport PATH=/usr/local/bin:/usr/bin:/bin\n")
    return path


def decided(home: pathlib.Path, command: str, host: str = "claude"):
    out = gate.decide(command, str(home.parent / "w"), time.monotonic() + 60, host)
    return None if out is None else out.decision


@pytest.mark.parametrize("kind", sorted(DEFINITIONS))
@pytest.mark.parametrize("name, command", BARE)
def test_B36_2_a_bare_word_the_session_defines_is_not_silent(home, name, command, kind):
    snapshot(home, DEFINITIONS[kind].format(n=name))
    assert decided(home, command) in ("ask", "deny"), (name, command, kind)


@pytest.mark.parametrize("name, command", BARE)
def test_B36_2_an_exported_function_counts_too(home, monkeypatch, name, command):
    monkeypatch.setenv(f"BASH_FUNC_{name}%%", "() {  colorls\n}")
    assert decided(home, command) in ("ask", "deny"), command


@pytest.mark.parametrize("setup", ["BASH_ENV", "ENV", "fish", "zshenv", "symlink", "too_large", "too_many",
                                   "config_dir"])
def test_B36_2_a_session_the_gate_cannot_measure_keeps_a_bare_word_asking(home, monkeypatch, tmp_path, setup):
    if setup in ("BASH_ENV", "ENV"):
        (tmp_path / "rc").write_text("true\n")
        monkeypatch.setenv(setup, str(tmp_path / "rc"))
    elif setup == "fish":
        monkeypatch.setenv("SHELL", "/usr/bin/fish")
    elif setup == "zshenv":
        monkeypatch.setenv("SHELL", "/usr/bin/zsh")
        (home / ".zshenv").write_text("alias ls=colorls\n")
    elif setup == "symlink":
        target = snapshot(home, "true", name="real.sh", folder=tmp_path / "elsewhere")
        (home / ".claude" / "shell-snapshots").mkdir(parents=True)
        (home / ".claude" / "shell-snapshots" / "snapshot-bash-2.sh").symlink_to(target)
    elif setup == "too_large":
        snapshot(home, "#" * (1024 * 1024 + 1))
    elif setup == "too_many":
        for k in range(65):
            snapshot(home, "true", name=f"snapshot-bash-{k}.sh")
    elif setup == "config_dir":
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
        snapshot(home, "true", folder=tmp_path / "cfg" / "shell-snapshots")
        snapshot(home, "ls () { colorls; }", folder=tmp_path / "cfg" / "shell-snapshots", name="snapshot-zsh-1.sh")
    assert decided(home, f"ls -la; {SEARCH}") in ("ask", "deny"), setup


@pytest.mark.parametrize("kind", ["eval", "function", "alias"])
@pytest.mark.parametrize("command", [f"command ls -la; {SEARCH}", f"{LS} -la; {SEARCH}",
                                     f"command head -5 README.md; {SEARCH}", f"{SEARCH}; command ls",
                                     f"command wc -l README.md && {SEARCH}"])
def test_B36_2_command_and_the_absolute_path_are_silent_past_an_alias_or_a_function(home, command, kind):
    for name in ("ls", "head", "wc"):
        snapshot(home, DEFINITIONS[kind].format(n=name), name=f"snapshot-bash-{name}.sh")
    assert decided(home, command) is None, (command, kind)


@pytest.mark.parametrize("command", [f"command ls -la; {SEARCH}", f"{LS} -la; {SEARCH}"])
def test_B36_2_command_and_the_absolute_path_are_silent_where_the_session_is_not_measured(home, monkeypatch,
                                                                                         tmp_path, command):
    """The order: "Sonst still nur `command <name>` oder der absolute Pfad"."""
    (tmp_path / "rc").write_text("true\n")
    monkeypatch.setenv("BASH_ENV", str(tmp_path / "rc"))
    assert decided(home, command) is None, command


@pytest.mark.parametrize("definition, command", [
    ("command () { colorls; }", f"command ls -la; {SEARCH}"),
    ("alias command='command '", f"command ls -la; {SEARCH}"),
    ("hash -p /opt/colorls/bin/colorls ls", f"command ls -la; {SEARCH}"),
    (f"{LS} () {{ colorls; }}", f"{LS} -la; {SEARCH}"),
])
def test_B36_2_control_what_shadows_command_or_the_path_keeps_it_asking(home, definition, command):
    snapshot(home, definition)
    assert decided(home, command) in ("ask", "deny"), (definition, command)


@pytest.mark.parametrize("command", [f"command -p ls; {SEARCH}", f"command -v ls; {SEARCH}",
                                     f"command ls --hyperlink; {SEARCH}", f"/usr/bin/nosuchprogram -la; {SEARCH}",
                                     f"./ls -la; {SEARCH}", f"/bin/sh -c ls; {SEARCH}", f"command; {SEARCH}"])
def test_B36_2_control_other_forms_of_command_and_of_a_path_stay_as_they_were(home, command):
    assert decided(home, command) in ("ask", "deny"), command


def test_B36_2_control_a_program_at_a_path_that_is_no_gnu_coreutils_is_not_silent(home, tmp_path):
    fake = tmp_path / "bin" / "ls"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\necho 'colorls 1.5'\n")
    fake.chmod(0o755)
    assert decided(home, f"{fake} -la; {SEARCH}") in ("ask", "deny")


@pytest.mark.parametrize("kind", ["eval", "function", "alias", "hash"])
def test_B36_2_xargs_starts_its_program_by_path_so_the_session_does_not_count(home, kind):
    snapshot(home, DEFINITIONS[kind].format(n="ls"))
    assert decided(home, "grep -rl 'git push' src | xargs ls -l") is None, kind


@pytest.mark.parametrize("name, command", BARE)
def test_B36_2_control_a_session_that_defines_nothing_keeps_the_bare_word_silent(home, name, command):
    snapshot(home, "eval $'nvm () \\n{ \\n    unset -f nvm\\n}'\nfunction pkill {\n  command pkill \"$@\"\n}\n"
                   "if ! hash rg 2>/dev/null; then\n  alias rg='/usr/bin/rg'\nfi")
    assert decided(home, command) is None, command


@pytest.mark.parametrize("name, command", BARE[:3])
def test_B36_2_control_no_snapshot_folder_under_bash_is_measured_as_no_definition(home, name, command):
    assert decided(home, command) is None, command


@pytest.mark.parametrize("command", [f"ls -la; {SEARCH}", f"command ls -la; {SEARCH}", f"{LS} -la; {SEARCH}"])
def test_B36_2_control_codex_keeps_its_answer(home, command):
    snapshot(home, "true")
    assert decided(home, command, "codex") in ("ask", "deny"), command   # D77 is off under Codex (D37)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("definition, command, other", [
    ("ls () { pbmark; }", "ls /", True), ("ls () { pbmark; }", "command ls /", False),
    ("shopt -s expand_aliases\nalias ls=pbmark", "ls /", True), ("hash -p {bin}/pbmark ls", "command ls /", True),
    ("{ls} () {{ pbmark; }}", "{ls} /", True), ("test () { pbmark; }", "test -n x", True),
    ("ls () { pbmark; }", "echo / | xargs ls", False), ("ls () { pbmark; }", "{ls} /", False),
])
def test_B36_2_truth_the_shell_runs_another_program(tmp_path, definition, command, other):
    """The truth each rule stands on, run here as Claude Code runs a command: source the snapshot, eval the text."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "mark.log"
    (bin_dir / "pbmark").write_text(f"#!/bin/sh\necho ran >> {marker}\n")
    (bin_dir / "pbmark").chmod(0o755)
    snap = tmp_path / "snap.sh"
    snap.write_text(definition.replace("{bin}", str(bin_dir)).replace("{ls}", LS).replace("{{", "{")
                    .replace("}}", "}") + "\n")
    text = command.replace("{ls}", LS)
    subprocess.run(["bash", "-c", f"source {snap} 2>/dev/null || true && eval '{text}'"], capture_output=True,
                   timeout=30, env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)})
    assert marker.exists() is other, (definition, command)
