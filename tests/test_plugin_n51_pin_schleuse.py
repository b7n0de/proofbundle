"""Follow-up note 51, point 4 (owner answers O46-1 and O46-2): the owner's script that pins a clone through the lock.

The order: a checked script through the lock on the owner's decision board; it reads only the tree the owner names, prints the entry
of pin-state and writes into pin-state.json only after the owner's click, atomically, into the gate directory, with a
way back and a case book; one entry per work tree the owner gives a session, a linked work tree its own entry; pinning
and renewing only by the owner, never by a session.

The script, plugins/proofbundle/hooks/pin_state_schleuse.py: `zeigen` prints the entry the gate's own `pin-state`
gives and a release value that binds the write to the gate directory, the bytes of pin-state.json now and the bytes to
come, and writes nothing; `schreiben` writes only with that value, after a backup, atomically, and reads the file back;
`zurueck` restores a backup, a backup `.keine` removes the file; `liste` shows the entries and backups. The gate
denies every command of a session that names the script and only reads nothing (D114), and the script
refuses in an agent's environment.

This file is the case book of the script (F1 to F17). RED at d3ce27a2 (measured, 25 of 31): every case but the six
on reading the script (F17), which are green at both; the script and the gate's guard do not exist there.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71
from _plugin_env import plugin_env
import test_plugin_n46_pinned_state_d114_d115 as d114

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean

SCRIPT = pathlib.Path(gate.__file__).resolve().parent / "pin_state_schleuse.py"


def _env(**extra) -> dict:
    """The environment of the owner's call (plugin_env: the fixed names and the case's GIT_ and PROOFBUNDLE_ values),
    with no name of an agent."""
    return plugin_env(**extra)


def run(*args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True,
                          env=_env() if env is None else env, timeout=120, check=False)


def _gd() -> pathlib.Path:
    return d114._gate_dir()


def _files(folder: pathlib.Path) -> dict:
    return {p.name: p.read_bytes() for p in sorted(folder.iterdir()) if p.is_file() and not p.name.startswith(".")}


def _seal(out: str) -> str:
    return next(line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("Release value: "))


def _pin(repo) -> subprocess.CompletedProcess:
    shown = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert shown.returncode == 0, shown.stderr
    return run("schreiben", "--baum", str(repo), "--freigabe", _seal(shown.stdout), "--tor-verzeichnis", str(_gd()))


def test_F1_zeigen_prints_the_entry_of_the_gate_and_a_release_value_and_writes_nothing(tmp_path):
    repo = d114._repo(tmp_path)
    before = _files(_gd())
    shown = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert shown.returncode == 0, shown.stderr
    entry = json.loads(shown.stdout[shown.stdout.index("{"):shown.stdout.index("\n}") + 2])
    assert entry == d114._entry(repo) | {"pfad": os.path.realpath(repo), "hakenordner": os.path.realpath(
        repo / ".git" / "hooks")}
    assert "Effect: new" in shown.stdout and len(_seal(shown.stdout)) == 64
    assert _files(_gd()) == before


def test_F2_schreiben_with_the_value_pins_the_clone_and_the_gate_frees_the_commit(tmp_path):
    repo = d114._repo(tmp_path)
    assert not d114._free(d114.answered(repo, "git commit -m work"))
    written = _pin(repo)
    assert written.returncode == 0, written.stderr
    files = _files(_gd())
    assert gate.PIN_STATE_FILE in files and any(n.endswith(".keine") for n in files), sorted(files)
    data = json.loads(files[gate.PIN_STATE_FILE])
    assert data["schema"] == gate.PIN_STATE_SCHEMA and len(data["klone"]) == 1
    assert d114._free(d114.answered(repo, "git commit -m work"))


def test_F3_a_wrong_value_writes_nothing(tmp_path):
    repo = d114._repo(tmp_path)
    before = _files(_gd())
    out = run("schreiben", "--baum", str(repo), "--freigabe", "0" * 64, "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 3 and _files(_gd()) == before, out.stderr


@pytest.mark.parametrize("change", ["a new hook", "a changed config", "a change of pin-state.json"])
def test_F4_F5_a_change_between_zeigen_and_schreiben_writes_nothing(tmp_path, change):
    repo = d114._repo(tmp_path)
    other = d114._repo(tmp_path / "other")
    shown = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    if change == "a new hook":
        d114._hook(repo / ".git" / "hooks", name="commit-msg")
    elif change == "a changed config":
        d71._git(repo, "config", "frob.other", "2")
    else:
        assert _pin(other).returncode == 0
    before = _files(_gd())
    out = run("schreiben", "--baum", str(repo), "--freigabe", _seal(shown.stdout), "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 3 and _files(_gd()) == before, (change, out.stderr)


def test_F6_erneuern_replaces_the_entry_of_the_tree_and_keeps_the_others(tmp_path):
    repo, other = d114._repo(tmp_path), d114._repo(tmp_path / "other")
    assert _pin(repo).returncode == 0 and _pin(other).returncode == 0
    d71._git(repo, "config", "frob.other", "2")
    assert not d114._free(d114.answered(repo, "git commit -m work"))   # the pinned config changed
    shown = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert "Effect: renewed" in shown.stdout
    assert run("schreiben", "--baum", str(repo), "--freigabe", _seal(shown.stdout),
               "--tor-verzeichnis", str(_gd())).returncode == 0
    klone = json.loads((_gd() / gate.PIN_STATE_FILE).read_text())["klone"]
    assert sorted(e["pfad"] for e in klone) == sorted([os.path.realpath(repo), os.path.realpath(other)])
    assert d114._free(d114.answered(repo, "git commit -m work")) and d114._free(d114.answered(other, "git commit -m x"))


def test_F7_an_unchanged_entry_has_nothing_to_write(tmp_path):
    repo = d114._repo(tmp_path)
    assert _pin(repo).returncode == 0
    before = _files(_gd())
    shown = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert shown.returncode == 0 and "Nothing to write" in shown.stdout and "Release value" not in shown.stdout
    again = run("schreiben", "--baum", str(repo), "--freigabe", "x", "--tor-verzeichnis", str(_gd()))
    assert again.returncode == 0 and _files(_gd()) == before


def test_F8_a_linked_work_tree_gets_its_own_entry(tmp_path):
    repo = d114._repo(tmp_path)
    linked = tmp_path / "linked"
    d71._git(repo, "worktree", "add", "-q", "-b", "claude/linked", str(linked), "topic")
    assert _pin(repo).returncode == 0 and _pin(linked).returncode == 0
    klone = json.loads((_gd() / gate.PIN_STATE_FILE).read_text())["klone"]
    assert sorted(e["pfad"] for e in klone) == sorted([os.path.realpath(repo), os.path.realpath(linked)])


def test_F9_a_hook_folder_outside_the_clone_is_refused(tmp_path):
    repo = d114._repo(tmp_path)
    outside = tmp_path / "shared-hooks"
    d114._hook(outside)
    d71._git(repo, "config", "core.hooksPath", str(outside))
    before = _files(_gd())
    out = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 1 and "does not pin" in out.stderr and _files(_gd()) == before, out.stderr


@pytest.mark.parametrize("tree", ["no work tree", "relative"])
def test_F10_a_path_that_is_no_work_tree_or_not_absolute_is_refused(tmp_path, tree):
    (tmp_path / "plain").mkdir()
    path = str(tmp_path / "plain") if tree == "no work tree" else "plain"
    out = run("zeigen", "--baum", path, "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 1, out.stderr


@pytest.mark.parametrize("text", ['{"schema": "proofbundle-plugin/pin-state/v0.1", "klone": [], "klone": []}',
                                  '{"schema": "proofbundle-plugin/pin-state/v0.2", "klone": []}', "not json"])
def test_F11_a_pin_file_that_does_not_read_whole_is_left_as_it_is(tmp_path, text):
    repo = d114._repo(tmp_path)
    (_gd() / gate.PIN_STATE_FILE).write_text(text)
    out = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 1 and (_gd() / gate.PIN_STATE_FILE).read_text() == text, out.stderr


def test_F11_an_entry_of_this_tree_the_gate_does_not_read_is_not_replaced_silently(tmp_path):
    """The broken entry names the tree itself: a replacement would make the file read whole again, and still the
    script leaves the owner's file as it is and says why."""
    repo = d114._repo(tmp_path)
    entry = d114._entry(repo) | {"pfad": os.path.realpath(repo), "konfig": "not a sha256"}
    text = json.dumps({"schema": gate.PIN_STATE_SCHEMA, "klone": [entry]})
    (_gd() / gate.PIN_STATE_FILE).write_text(text)
    out = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 1 and "does not read whole" in out.stderr, (out.returncode, out.stdout, out.stderr)
    assert (_gd() / gate.PIN_STATE_FILE).read_text() == text


def test_F5_the_release_value_binds_the_bytes_of_the_file_now_not_only_the_bytes_to_come(tmp_path):
    """Between zeigen and schreiben the file is written again with the same entries in another form: the bytes to come
    are the same, the file is not, and nothing is written."""
    repo, other = d114._repo(tmp_path), d114._repo(tmp_path / "other")
    assert _pin(other).returncode == 0
    shown = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()))
    path = _gd() / gate.PIN_STATE_FILE
    path.write_text(json.dumps(json.loads(path.read_text())))   # the same entries, without the indentation
    before = _files(_gd())
    out = run("schreiben", "--baum", str(repo), "--freigabe", _seal(shown.stdout), "--tor-verzeichnis", str(_gd()))
    assert out.returncode == 3 and _files(_gd()) == before, out.stderr


def test_F12_zurueck_restores_the_state_before_and_the_gate_asks_again(tmp_path):
    repo = d114._repo(tmp_path)
    assert _pin(repo).returncode == 0 and d114._free(d114.answered(repo, "git commit -m work"))
    back = run("zurueck", "--tor-verzeichnis", str(_gd()))
    assert back.returncode == 0, back.stderr
    assert not (_gd() / gate.PIN_STATE_FILE).exists()
    assert not d114._free(d114.answered(repo, "git commit -m work"))
    again = run("zurueck", "--tor-verzeichnis", str(_gd()))   # a second zurueck takes the first back
    assert again.returncode == 0 and d114._free(d114.answered(repo, "git commit -m work"))


def test_F13_zurueck_to_a_named_backup(tmp_path):
    repo, other = d114._repo(tmp_path), d114._repo(tmp_path / "other")
    assert _pin(repo).returncode == 0
    first = (_gd() / gate.PIN_STATE_FILE).read_bytes()
    assert _pin(other).returncode == 0
    named = [n for n in _files(_gd()) if n.startswith(gate.PIN_STATE_FILE + ".vor-") and not n.endswith(".keine")]
    assert len(named) == 1
    assert run("zurueck", "--sicherung", named[0], "--tor-verzeichnis", str(_gd())).returncode == 0
    assert (_gd() / gate.PIN_STATE_FILE).read_bytes() == first
    assert run("zurueck", "--sicherung", "pin-state.json.vor-nichts", "--tor-verzeichnis", str(_gd())).returncode == 1


def test_F14_the_gate_directory_from_the_environment_and_a_missing_one(tmp_path):
    repo = d114._repo(tmp_path)
    shown = run("zeigen", "--baum", str(repo), env=_env(PROOFBUNDLE_GATE_DIR=str(_gd())))
    assert shown.returncode == 0 and f"Gate directory: {_gd()}" in shown.stdout
    missing = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(tmp_path / "nowhere"))
    assert missing.returncode == 1


@pytest.mark.parametrize("name", ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX"])
def test_F15_the_script_refuses_in_an_agent_environment(tmp_path, name):
    repo = d114._repo(tmp_path)
    before = _files(_gd())
    out = run("zeigen", "--baum", str(repo), "--tor-verzeichnis", str(_gd()), env=_env(**{name: "1"}))
    assert out.returncode == 1 and "an agent's" in out.stderr and _files(_gd()) == before


def _script_forms(repo, folder):
    s = str(SCRIPT)
    split = s.replace("schleuse", "sch'leu'se")   # quotes inside the name: only the normal form of the net shows it
    return [f"python3 -I {s} schreiben --baum {repo} --freigabe abc", f"python3 -I {s} zeigen --baum {repo}",
            f"python3 -I {s} zurueck", f"cd /tmp && python3 {s} schreiben --baum {repo} --freigabe abc",
            f"{s} liste", f"python3 '{s}' zeigen --baum {repo} --tor-verzeichnis {folder}",
            f"python3 $'{s}' zurueck", f"python3 {s.replace('schleuse', 'SCHLEUSE')} zurueck",
            f"cat {s} | python3 - zurueck", f"cp {s} {folder}/../x.py && python3 {folder}/../x.py zurueck",
            f"bash -c 'python3 {s} zurueck'", f"python3 {split} zurueck"]


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_F16_the_gate_denies_a_session_that_runs_the_script(tmp_path, host):
    repo = d114._repo(tmp_path)
    for form in _script_forms(repo, _gd()):
        out = gate.decide(form, str(repo), time.monotonic() + 60, host)
        assert out is not None and out.decision == "deny" and out.verdicts[0].reason_id == "write_to_gate_dir", \
            (host, form, out and out.decision)


@pytest.mark.parametrize("form", ["cat {S}", "grep -n schreiben {S}", "head -20 {S}", "wc -l {S}", "cat {S} | head -5",
                                  "sed -n '1,40p' {S}"])
def test_F17_reading_the_script_stays_free(tmp_path, form):
    repo = d114._repo(tmp_path)
    out = gate.decide(form.replace("{S}", str(SCRIPT)), str(repo), time.monotonic() + 60, "claude")
    assert out is None or out.decision not in ("deny", "ask"), (form, out and out.decision)
