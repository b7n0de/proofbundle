"""D94, Nachtrag 37, Ergänzung 4: learning from the share of yes. The bilanz counts per reason how often an ask was
answered yes and no and whether the reason ever caught something; a reason with nearly only yes and no catch over a
period appears as a candidate to free, as an owner question. The gate frees nothing itself.

Measured with Claude Code 2.1.302 on a pseudo terminal against a stand-in API, no network (ask_answer_n37.py of the
delivery): after a yes in the dialog of an ask Claude Code sends PostToolUse (PostToolUseFailure where the command
failed) with the tool_use_id of the PreToolUse event; after a no (Escape) it sends neither, and no PermissionDenied.

The rule (D94): with --autonomous the gate keeps the key of every ask it sends (sha256 of the tool_use_id, never the id)
in the plugin data directory and writes it into the log line (frage); the answer hook proofbundle_answered.py, on
PostToolUse and PostToolUseFailure, removes a kept key and appends a line answered/ja. The bilanz reads an ask as yes
where such a line names it, as no where its session made a later call or an hour has passed, else as open; it counts per
reason fragen, ja, nein, offen and whether the reason is a catch, and names the candidates of the last 14 days (at least
20 answers, at least 95 % yes, no catch).

RED at 3f309222 (the head of D93): the answer hook, the key, the answers per reason, the candidates. Codex and the hook
without the flag are controls.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []
HOOKS = pathlib.Path(gate.__file__).parent
ANSWER_HOOK = HOOKS / "proofbundle_answered.py"
OUTSIDE = "https://github.com/someone/proofbundle.git"


def _env(data):
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(data)
    return env


def _gate(repo, data, command, tool_use_id, session="s-d94", host="claude", flag=True):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": session,
             "tool_use_id": tool_use_id, "tool_input": {"command": command}}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *(AUTONOMOUS if flag else [])],
                              json.dumps(event), _env(data), cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


def _answer(data, tool_use_id, event_name="PostToolUse", session="s-d94"):
    event = {"hook_event_name": event_name, "tool_name": "Bash", "session_id": session, "tool_use_id": tool_use_id,
             "tool_input": {"command": "x"}, "tool_response": {"stdout": "x"}}
    proc = subprocess.run([sys.executable, "-I", str(ANSWER_HOOK)], input=json.dumps(event), text=True,
                          capture_output=True, env=_env(data), timeout=60)
    assert proc.returncode == 0 and proc.stdout == "" and proc.stderr == "", proc
    return proc


def _log(data):
    path = data / "gate-log.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_D94_a_yes_is_the_call_that_ran_after_the_ask(tmp_path):
    repo, data = d71._repo(tmp_path, url=OUTSIDE), tmp_path / "data"
    answer, entry = _gate(repo, data, "gh pr create --fill", "toolu_yes")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask" and len(entry["frage"]) == 32, entry
    _answer(data, "toolu_yes")
    lines = _log(data)
    assert lines[-1]["decision"] == "answered" and lines[-1]["antwort"] == "ja" and lines[-1]["frage"] == entry["frage"]
    assert lines[-1]["reason_ids"] == entry["reason_ids"]
    _answer(data, "toolu_yes")   # a second event for the same call adds nothing
    assert len(_log(data)) == len(lines)
    row = gate.bilanz(_log(data), period="gesamt")["zeitraeume"][0]
    reason = entry["reason_ids"][0]
    assert row["antworten_je_grund"][reason]["ja"] == 1 and row["aufrufe"] == 1 and row["owner_klicks"] == 1, row


def test_D94_a_failed_call_after_a_yes_is_a_yes_too(tmp_path):
    repo, data = d71._repo(tmp_path, url=OUTSIDE), tmp_path / "data"
    _gate(repo, data, "git tag v1", "toolu_fail")
    _answer(data, "toolu_fail", "PostToolUseFailure")
    assert _log(data)[-1]["antwort"] == "ja"


def test_D94_a_no_is_an_ask_whose_session_went_on_without_the_call(tmp_path):
    repo, data = d71._repo(tmp_path, url=OUTSIDE), tmp_path / "data"
    _answer_line, first = _gate(repo, data, "gh pr create --fill", "toolu_no")
    _gate(repo, data, "gh pr create --fill", "toolu_open", session="other")
    lines = _log(data)
    lines[-1]["ts"] = "2999-01-01T00:00:00Z"   # the other session's call comes later; it is no answer for this one
    later = dict(lines[0], ts="2999-01-01T00:00:01Z", frage=None, decision="none", reason_ids=["free_after_read_profile"])
    answers = gate._ask_answers(lines + [later])
    assert answers[first["frage"]] == "nein" and answers[lines[1]["frage"]] == "offen", answers


def test_D94_the_key_is_kept_never_the_id_and_the_store_is_bounded(tmp_path):
    repo, data = d71._repo(tmp_path, url=OUTSIDE), tmp_path / "data"
    _gate(repo, data, "git tag v1", "toolu_secretish_0001")
    text = (data / gate.ASKS_PENDING).read_text()
    assert "toolu_secretish_0001" not in text and json.loads(text)["schema"] == gate.ASKS_SCHEMA
    hook = gate._answer_hook()
    asks = {f"{k:032x}": {"ts": "2026-10-18T00:00:00Z", "gruende": ["x"]} for k in range(gate.MAX_ASKS_PENDING)}
    hook.write_asks(str(data), asks)
    _gate(repo, data, "git tag v2", "toolu_newest")
    kept = hook.read_asks(str(data))
    assert len(kept) == gate.MAX_ASKS_PENDING and f"{0:032x}" not in kept and hook.ask_key("toolu_newest") in kept


@pytest.mark.parametrize("event_name, tool_use_id", [("PostToolUse", "toolu_unknown"), ("PreToolUse", "toolu_kept"),
                                                     ("Stop", "toolu_kept")])
def test_D94_control_the_answer_hook_writes_nothing_for_another_call_or_event(tmp_path, event_name, tool_use_id):
    repo, data = d71._repo(tmp_path, url=OUTSIDE), tmp_path / "data"
    _gate(repo, data, "git tag v1", "toolu_kept")
    before = _log(data)
    _answer(data, tool_use_id, event_name)
    assert _log(data) == before


def test_D94_control_the_answer_hook_never_fails_a_call(tmp_path):
    for env in ({"PATH": os.environ["PATH"]}, {"PATH": os.environ["PATH"], "CLAUDE_PLUGIN_DATA": "relative"},
                {"PATH": os.environ["PATH"], "CLAUDE_PLUGIN_DATA": str(tmp_path / "missing")}):
        for text in ("not json", "{}", json.dumps({"hook_event_name": "PostToolUse", "tool_use_id": 7})):
            proc = subprocess.run([sys.executable, "-I", str(ANSWER_HOOK)], input=text, text=True,
                                  capture_output=True, env=env, timeout=60)
            assert (proc.returncode, proc.stdout, proc.stderr) == (0, "", ""), proc


@pytest.mark.parametrize("host, flag", [("codex", True), ("claude", False)])
def test_D94_control_codex_and_the_hook_without_the_flag_keep_no_key(tmp_path, host, flag):
    repo, data = d71._repo(tmp_path, url=OUTSIDE), tmp_path / "data"
    _answer_text, entry = _gate(repo, data, "git tag v1", "toolu_c", host=host, flag=flag)
    assert "frage" not in entry and not (data / "asks-pending.json").exists()


def _ask(ts, key, reasons, session="s"):
    return {"ts": ts, "host": "claude", "decision": "ask", "verdict": "ask", "reason_ids": reasons, "frage": key,
            "session_id": session}


def _yes(ts, key, reasons):
    return {"ts": ts, "host": "claude", "decision": "answered", "verdict": "answered", "antwort": "ja", "frage": key,
            "reason_ids": reasons, "session_id": "s"}


def test_D94_the_candidates_to_free(tmp_path):
    log = []
    for k in range(20):   # 19 yes, 1 no: 95 %, no catch
        log.append(_ask(f"2026-10-18T10:{k:02d}:00Z", f"a{k}", ["net_unmodeled_git"]))
        if k:
            log.append(_yes(f"2026-10-18T10:{k:02d}:30Z", f"a{k}", ["net_unmodeled_git"]))
    for k in range(20):   # all yes, but a catch
        log.append(_ask(f"2026-10-18T11:{k:02d}:00Z", f"b{k}", ["push_delete"]))
        log.append(_yes(f"2026-10-18T11:{k:02d}:30Z", f"b{k}", ["push_delete"]))
    for k in range(19):   # all yes, but too few
        log.append(_ask(f"2026-10-18T12:{k:02d}:00Z", f"c{k}", ["remote_read_not_modeled"]))
        log.append(_yes(f"2026-10-18T12:{k:02d}:30Z", f"c{k}", ["remote_read_not_modeled"]))
    for k in range(20):   # all yes, but older than the period
        log.append(_ask(f"2026-09-01T10:{k:02d}:00Z", f"d{k}", ["house_pr_limit"]))
        log.append(_yes(f"2026-09-01T10:{k:02d}:30Z", f"d{k}", ["house_pr_limit"]))
    log.append({"ts": "2026-10-18T13:00:00Z", "host": "claude", "decision": "none", "reason_ids": ["x"],
                "session_id": "s"})
    log.sort(key=lambda e: e["ts"])
    result = gate.bilanz(log, period="gesamt")
    assert [c["grund"] for c in result["kandidaten_zum_freigeben"]] == ["net_unmodeled_git"], result
    candidate = result["kandidaten_zum_freigeben"][0]
    assert (candidate["ja"], candidate["nein"], candidate["ja_quote"], candidate["owner_frage"]) == (19, 1, 0.95, "O37-5")
    cells = result["zeitraeume"][0]["antworten_je_grund"]
    assert cells["net_unmodeled_git"]["nein"] == 1 and cells["push_delete"]["fang"] is True
    assert result["zeitraeume"][0]["aufrufe"] == 80


def test_D94_a_card_is_counted_of_its_own():
    log = [{"ts": "2026-10-18T10:00:00Z", "host": "claude", "decision": "deny", "reason_ids": ["x", "autonomy_card"]}]
    assert gate.bilanz(log)["zeitraeume"][0]["karten"] == 1


def test_D94_the_answer_hook_stands_in_hooks_json_after_every_gated_call_and_not_for_codex():
    hooks = json.loads((HOOKS / "hooks.json").read_text())["hooks"]
    # the hook of the key paths of D102 never asks, so it has no answer hook
    matchers = [entry["matcher"] for entry in hooks["PreToolUse"]
                if "proofbundle_secrets.py" not in entry["hooks"][0]["command"]]
    for event in ("PostToolUse", "PostToolUseFailure"):
        assert [entry["matcher"] for entry in hooks[event]] == matchers
        for entry in hooks[event]:
            (hook,) = entry["hooks"]
            assert hook["command"] == 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_answered.py" || true'
    codex = (HOOKS.parent / ".codex-plugin" / "plugin.json").read_text()
    assert "proofbundle_answered" not in codex
    hook = gate._answer_hook()
    assert (hook.LOG_NAME, hook.DATA_VARIABLE, hook.ASKS_PENDING, hook.ASKS_SCHEMA) == \
        (gate.LOG_NAME, gate.LOG_DIR_VARIABLES["claude"][0], gate.ASKS_PENDING, gate.ASKS_SCHEMA)
