"""D101, follow-up note 33 (fallbook w01, w02): a write into the settings of the host, where its hooks and permissions stand.

The order: Edit and Write on the settings of the host are denied, under Claude Code and Codex, for the account and the
project. Found by account A's fallbook (tor 44db2056): `Edit` and `Write` on the settings got no answer under Claude Code.

Measured with Claude Code 2.1.303 (truth_host_n33.sh settings: a fresh HOME, a hook in each candidate file that names
the file, one Bash call through the stand-in API): the hooks of ~/.claude/settings.json, <project>/.claude/settings.json
and <project>/.claude/settings.local.json ran; Claude Code also read ~/.claude.json, ~/.claude/settings.local.json,
/etc/claude-code/managed-settings.json with the folder managed-settings.d, <project>/.mcp.json and ~/.claude/plugins.
Codex is not in this container: its folder (CODEX_HOME, else ~/.codex) and a project's .codex folder count whole, read,
not measured.

The rule: decide_write denies a write into one of these files or folders, written or resolved, a hard link to an account
file too, as write_to_host_settings, under both hosts and before the host split, so Codex names this reason and not the
unbound write. It holds for the file tools and for every write class c finds in a command (D95, D96, D100,
redirections). A project's file counts wherever it stands, by its last parts.

RED at 63b88d07 (the head of PLUGIN_N37): every write into a settings file. Reads of the settings and writes beside them
are controls, green at both.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")
TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


@pytest.fixture
def repo(tmp_path):
    r = d72._repo(tmp_path)
    (r / "f.txt").write_text("{}\n")
    return r


def _home() -> str:
    return os.environ["HOME"]


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _write(tool, path, repo, host="claude"):
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    return gate.decide_write(tool, {key: path, "content": "{}", "old_string": "a", "new_string": "b",
                                    "edits": [{"old_string": "a", "new_string": "b"}], "new_source": "x"},
                             str(repo), time.monotonic() + 60, host)


def _out(repo, form, host="claude"):
    return gate.decide(form.replace("{H}", _home()).replace("{R}", str(repo)), str(repo), time.monotonic() + 60, host)


#: The settings files and folders, {H} for HOME and {R} for the repository.
SETTINGS = ["{H}/.claude/settings.json", "{H}/.claude/settings.local.json", "{H}/.claude.json",
            "{H}/.claude/plugins/proofbundle/hooks/hooks.json", "{H}/.claude/plugins/installed_plugins.json",
            "{R}/.claude/settings.json", "{R}/.claude/settings.local.json", "{R}/.mcp.json",
            "{R}/sub/.claude/settings.json", "{H}/.codex/config.toml", "{H}/.codex/hooks.json",
            "{R}/.codex/config.toml", "/etc/claude-code/managed-settings.json",
            "/etc/claude-code/managed-settings.d/10-x.json"]


def _fill(path, repo):
    return path.replace("{H}", _home()).replace("{R}", str(repo))


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("path", SETTINGS)
def test_D101_a_file_tool_write_into_the_settings_of_the_host_is_denied(repo, path, tool, host):
    out = _write(tool, _fill(path, repo), repo, host)
    assert out is not None and out.decision == "deny" and _ids(out) == ["write_to_host_settings"], (path, _ids(out))


def test_D101_a_relative_path_counts_from_the_hook_directory(repo):
    out = _write("Write", ".claude/settings.local.json", repo)
    assert out is not None and _ids(out) == ["write_to_host_settings"], _ids(out)


def test_D101_claude_config_dir_and_codex_home_name_the_account_folders(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "cx"))
    for path in ("cfg/settings.json", "cfg/.claude.json", "cfg/plugins/x/hooks/hooks.json", "cx/config.toml"):
        out = _write("Write", str(tmp_path / path), repo)
        assert out is not None and _ids(out) == ["write_to_host_settings"], (path, _ids(out))


def test_D101_a_symbolic_and_a_hard_link_to_an_account_file_count(repo, tmp_path):
    settings = os.path.join(_home(), ".claude", "settings.json")
    os.makedirs(os.path.dirname(settings), exist_ok=True)
    with open(settings, "w") as handle:
        handle.write("{}\n")
    (tmp_path / "links").mkdir()
    os.symlink(settings, tmp_path / "links" / "soft")
    os.link(settings, tmp_path / "links" / "hard")
    for name in ("soft", "hard"):
        out = _write("Write", str(tmp_path / "links" / name), repo)
        assert out is not None and _ids(out) == ["write_to_host_settings"], (name, _ids(out))
        out = _out(repo, f"echo x > {tmp_path / 'links' / name}")
        assert out is not None and "write_to_host_settings" in _ids(out), (name, _ids(out))


def test_D101_a_link_to_a_settings_file_not_yet_there_or_to_a_settings_folder_counts(repo, tmp_path):
    """The resolved path decides where no file is there yet to compare (a link to a settings file that does not exist,
    a link to the plugins folder)."""
    claude = os.path.join(_home(), ".claude")
    os.makedirs(os.path.join(claude, "plugins"), exist_ok=True)
    (tmp_path / "ln").mkdir()
    os.symlink(os.path.join(claude, "settings.local.json"), tmp_path / "ln" / "dangling")
    os.symlink(os.path.join(claude, "plugins"), tmp_path / "ln" / "plugins")
    for path in (tmp_path / "ln" / "dangling", tmp_path / "ln" / "plugins" / "x.json"):
        out = _write("Write", str(path), repo)
        assert out is not None and _ids(out) == ["write_to_host_settings"], (path, _ids(out))


#: Shell forms that write a settings file; each got no answer at 63b88d07.
SHELL_FORMS = [
    "echo '{}' > ~/.claude/settings.json", "echo x >> {H}/.claude/settings.json", "printf x > \"$HOME/.claude.json\"",
    "cp f.txt ~/.claude/settings.json", "cp f.txt .claude/settings.local.json", "mv f.txt .mcp.json",
    "tee .claude/settings.json < f.txt", "sed -i s/a/b/ .claude/settings.json", "ln -sf f.txt ~/.claude.json",
    "cat > ~/.codex/config.toml <<'EOF'\n[x]\nEOF", "bash -c 'cp f.txt ~/.claude/settings.json'",
    "D=~/.claude; cp f.txt $D/settings.json", "rm ~/.claude/settings.json", "sort -o .claude/settings.json f.txt",
    "echo x > ~/.claude/plugins/proofbundle/hooks/proofbundle_gate.py",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", SHELL_FORMS)
def test_D101_a_shell_write_into_the_settings_of_the_host_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "write_to_host_settings" in _ids(out), (form, host, _ids(out))


@pytest.mark.parametrize("path", ["{R}/README.md", "{R}/.claude/CLAUDE.md", "{R}/.claude/commands/x.md",
                                  "{R}/claude/settings.json", "{R}/settings.json", "{R}/.claude-plugin/plugin.json",
                                  "{R}/.codex-plugin/plugin.json", "{H}/.claude/projects/x/y.jsonl",
                                  "{H}/notes/settings.json", "{R}/docs/.mcp.json.md"])
def test_D101_control_writes_beside_the_settings_get_no_answer(repo, path):
    assert _write("Write", _fill(path, repo), repo) is None, path


@pytest.mark.parametrize("form", ["cat ~/.claude/settings.json", "grep hooks .claude/settings.json",
                                  "head -3 ~/.claude.json", "ls -la ~/.claude", "echo x > ~/.claude/CLAUDE.md"])
def test_D101_control_reads_of_the_settings_get_no_answer(repo, form):
    assert _out(repo, form) is None, (form, _ids(_out(repo, form)))


def test_D101_named_cost_a_copy_out_of_the_settings_is_denied_since_D96_reads_no_direction_of_cp(repo):
    # D96 judges every path word of a program the gate does not model as a write (owner question O39-2): a copy that
    # only reads a settings file is denied as a write into it
    out = _out(repo, "cp ~/.claude/settings.json /tmp/x.json")
    assert out is not None and out.decision == "deny" and "write_to_host_settings" in _ids(out), _ids(out)


def test_D101_under_codex_the_reason_is_the_settings_not_the_unbound_write(repo):
    out = _write("Write", _fill("{R}/.claude/settings.json", repo), repo, "codex")
    assert _ids(out) == ["write_to_host_settings"]
    out = _write("Write", _fill("{R}/README.md", repo), repo, "codex")
    assert _ids(out) == ["codex_write_unbound"]


def test_D101_the_gate_reads_no_settings_file(repo, monkeypatch):
    opened = []
    real = open

    def watch(path, *args, **kwargs):
        opened.append(str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", watch)
    _write("Write", _fill("{H}/.claude/settings.json", repo), repo)
    assert not [p for p in opened if ".claude" in p], opened


def test_D101_the_write_gives_the_chain_its_reason_and_the_line_its_weight(repo):
    out = _out(repo, "echo x > ~/.claude/settings.json && git status")
    assert out.decision == "deny" and "write_to_host_settings" in _ids(out), _ids(out)
    line = d72._line(out)
    assert "the write could change the host's hooks and permissions, the gate's included (D101)." in line, \
        line   # D116: what can go wrong, before the D number


def test_D101_the_reason_weighs_and_catches():
    assert "write_to_host_settings" in gate._D72_WRITES and "write_to_host_settings" in gate.FANG_REASONS
    assert gate._SHORT_REASONS["write_to_host_settings"][0] == "D101"
