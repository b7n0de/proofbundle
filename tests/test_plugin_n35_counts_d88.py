"""D88, Nachtrag 35, points 3 and 4: owner clicks, detours, catches and blocks, counted apart, in the log and in the
bilanz per period (schema b7n0de.plugin_bilanz), so that the test stand shows what the plugin improves in use.

The measures (point 3): owner clicks are the asks sent under Claude Code; a detour is a deny with a rewrite (D85) after
which the session ran one of the rewrite's calls and the gate let it run; a catch is an ask or a deny whose reasons name
a danger the gate caught (FANG_REASONS: a turned-off check, a write to the gate or the hooks, a house rule, evidence that
failed, a push blocked or asked for by its target, code that starts git, a change of a done order); a block is a deny.

The rule (D88): a deny with a rewrite keeps, per session (by the sha256 of its id) in the plugin data directory, the keys
of its calls (a sha256 of the words, a hole for the output of an earlier call, never the words); a later call of the
same session that the gate lets run and whose words match one key completes the detour once, and its log line carries
`umweg` with the hints and the time of the deny. `bilanz` reads the log and counts per UTC day (or the whole log) the
calls, owner_klicks, umwege, faenge and sperren, with the asks and denies per reason.

RED at the head of D87: the detour in the log, the state and the bilanz (none of them existed). Codex, another session,
another call and a second completion are controls.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85); a gate without the autonomous
#: answer (the base of the red run) is started as it always was.
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []


def _hook(repo, data, command, session="s-d88", host="claude", tool="Bash", tool_input=None):
    event = {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo), "session_id": session,
             "tool_input": tool_input if tool_input is not None else {"command": command.replace("{R}", str(repo))}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(data)
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *AUTONOMOUS], json.dumps(event), env,
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


@pytest.mark.parametrize("first, then", [
    ("cd {R} && git status", "git -C {R} status"),
    ("git add README.md && git status", "git status"),
    ("git log --oneline $(git rev-parse HEAD)", "git rev-parse HEAD"),
    ("git log --oneline $(git rev-parse HEAD)", "git log --oneline 0123abcd"),
    ("git commit -m \"$(cat <<'EOF'\nfix: x\n\ngit push later\nEOF\n)\"", "git commit -F /tmp/elsewhere/msg.txt"),
])
def test_D88_a_call_of_the_rewrite_completes_the_detour_once(tmp_path, first, then):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path / "data", first)
    assert entry["autonomy"]["klasse"] == "umweg" and "umweg" not in entry
    _answer, done = _hook(repo, tmp_path / "data", then)
    assert done["umweg"]["hinweise"] == entry["autonomy"]["hinweise"] and done["umweg"]["seit"], done
    _answer, again = _hook(repo, tmp_path / "data", then)
    assert "umweg" not in again


@pytest.mark.parametrize("then, session", [("git -C {R} status --short", "s-d88"), ("git -C {R} status", "other"),
                                           ("git status", "s-d88")])
def test_D88_control_another_call_or_another_session_completes_nothing(tmp_path, then, session):
    repo = d71._repo(tmp_path)
    _hook(repo, tmp_path / "data", "cd {R} && git status")
    _answer, entry = _hook(repo, tmp_path / "data", then, session=session)
    assert "umweg" not in entry, entry


def test_D88_control_a_call_the_gate_does_not_let_run_completes_nothing(tmp_path):
    repo = d71._repo(tmp_path)
    d71._git(repo, "config", "core.pager", "less")   # git -C <repo> status asks now
    _hook(repo, tmp_path / "data", "git add README.md && git status")
    _answer, entry = _hook(repo, tmp_path / "data", "git add README.md")
    assert "umweg" not in entry or entry["decision"] == "none", entry


def test_D88_the_state_keeps_keys_never_words(tmp_path):
    repo = d71._repo(tmp_path)
    _hook(repo, tmp_path / "data", "git log --oneline $(git rev-parse HEAD)")
    text = (tmp_path / "data" / gate.AUTONOMY_STATE).read_text()
    state = json.loads(text)
    assert state["schema"] == gate.AUTONOMY_STATE_SCHEMA
    assert "rev-parse" not in text and "oneline" not in text and "s-d88" not in text


def test_D88_the_state_is_bounded(tmp_path):
    repo = d71._repo(tmp_path)
    for k in range(gate._AUTONOMY_KEEP_SESSIONS + 3):
        _hook(repo, tmp_path / "data", "cd {R} && git status", session=f"s{k}")
    state = json.loads((tmp_path / "data" / gate.AUTONOMY_STATE).read_text())
    assert len(state["sessions"]) == gate._AUTONOMY_KEEP_SESSIONS


def test_D88_control_codex_keeps_no_state(tmp_path):
    repo = d71._repo(tmp_path)
    _hook(repo, tmp_path / "data", "cd {R} && git status", host="codex")
    _answer, entry = _hook(repo, tmp_path / "data", "git -C {R} status", host="codex")
    assert "umweg" not in entry and not (tmp_path / "data" / gate.AUTONOMY_STATE).exists()


def _line(ts, decision, reasons, host="claude", **extra):
    return {"ts": ts, "host": host, "decision": decision, "verdict": decision, "reason_ids": reasons, **extra}


LOG = [
    _line("2026-10-18T10:00:00Z", "ask", ["push_not_measured"]),
    _line("2026-10-18T10:01:00Z", "deny", ["directory_unresolved", "autonomy_rewrite"]),
    _line("2026-10-18T10:02:00Z", "none", ["free_after_read_profile"], umweg={"hinweise": ["git_C_statt_cd"],
                                                                              "seit": "2026-10-18T10:01:00Z"}),
    _line("2026-10-18T10:03:00Z", "deny", ["hooks_disabled"]),
    _line("2026-10-18T10:04:00Z", "deny", ["push_not_measured", "push_force"]),
    _line("2026-10-18T10:05:00Z", "deny", ["git_form_not_free"], host="codex"),
    _line("2026-10-19T08:00:00Z", "ask", ["push_not_measured", "push_delete"]),
    _line("2026-10-19T08:01:00Z", "none", ["not_gated"]),
]


def test_D88_the_bilanz_counts_per_day():
    result = gate.bilanz(LOG)
    assert result["schema"] == "b7n0de.plugin_bilanz" and result["bahn"] == "proofbundle"
    first, second = result["zeitraeume"]
    assert (first["aufrufe"], first["owner_klicks"], first["umwege"], first["faenge"], first["sperren"]) == \
        (6, 1, 1, 2, 4), first
    assert (second["aufrufe"], second["owner_klicks"], second["umwege"], second["faenge"], second["sperren"]) == \
        (2, 1, 0, 1, 0), second
    assert first["sperren_je_grund"]["push_force"] == 1 and first["fragen_je_grund"] == {"push_not_measured": 1}
    whole = gate.bilanz(LOG, period="gesamt")["zeitraeume"]
    assert len(whole) == 1 and whole[0]["aufrufe"] == 8 and whole[0]["sperren"] == 4


def test_D88_the_bilanz_command_reads_the_log_and_its_rotated_part(tmp_path):
    log = tmp_path / "gate-log.jsonl"
    log.write_text("".join(json.dumps(e) + "\n" for e in LOG[4:]) + "not json\n")
    (tmp_path / "gate-log.jsonl.1").write_text("".join(json.dumps(e) + "\n" for e in LOG[:4]))
    out = subprocess.run([sys.executable, "-I", gate.__file__, "bilanz", "--log", str(log), "--zeitraum", "gesamt"],
                         capture_output=True, text=True, timeout=60, check=True)
    result = json.loads(out.stdout)
    assert result["zeitraeume"][0]["aufrufe"] == 8 and result["quelle"] == {"log": "gate-log.jsonl"}


def test_D88_the_bilanz_of_a_session_as_the_hook_writes_it(tmp_path):
    repo = d71._repo(tmp_path)
    for command in ("cd {R} && git status", "git -C {R} status", "git push origin topic", "git push -f origin topic",
                    "git reset --hard HEAD~1", "git status"):
        _hook(repo, tmp_path / "data", command)
    entries = gate._bilanz_lines([str(tmp_path / "data" / "gate-log.jsonl")])
    row = gate.bilanz(entries, period="gesamt")["zeitraeume"][0]
    # changed in Nachtrag 37 (D93): the push to topic is a card in the work profile of b7n0de, a block, no click
    assert (row["aufrufe"], row["owner_klicks"], row["umwege"], row["faenge"], row["sperren"]) == (6, 0, 1, 1, 4), row


def test_D88_the_catches_are_a_closed_set_of_reasons():
    assert {"hooks_disabled", "push_force", "push_protected", "verification_failed", "house_admin_merge"} <= \
        gate.FANG_REASONS
    assert not {"push_not_measured", "git_form_not_free", "net_unmodeled_git", "directory_unresolved",
                "autonomy_rewrite", "autonomy_blocked"} & gate.FANG_REASONS
