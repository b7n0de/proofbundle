"""Nachtrag 43, point 2 (owner choice O28B-1 of 2026-10-20): what the window of the pilot says of writes without a
receipt of Level 1 under the hook's autonomous answer, and that M5 counts them.

O28B-1: under the hook's autonomous answer (Claude Code, --autonomous) the signer service decides without that answer
(D58) and refuses the receipt of every write whose answer it changes (verdict_differs; measured in PLUGIN_N28B_KETTE
and in Nachtrag 43, point 1). The owner's choice: measure first; until then the pilot says so in the window, in one
sentence, and M5 counts such a write that reaches GitHub. The case: a push to the own work branch passes under the
standing GO (D87), the service refuses its receipt, the push arrives; the reconciliation counts it under M5, names it
among the unapproved effects, and its window carries the sentence (D113).

RED at f5540aad (the head of PLUGIN_N28B_KETTE): the sentence of the window; the counts of M5 are green there, as the
reconciliation counted them before. The reconciliation applies the profile the records keep, which needs the decision
verifier of main 22aa954e; an interpreter whose proofbundle does not have it skips this file, as for the tests of D57.
"""
from __future__ import annotations

import inspect
import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n35_work_branch_go_d87 as d87
import test_plugin_z405_observer as o
import test_plugin_z405_signer_service as s
from proofbundle.decision import verify_decision_receipt

p1, pd, pr, gate = o.p1, o.pd, o.pr, o.gate
sys.path.insert(0, str(o.PILOT))
import reconcile as rc  # noqa: E402

sys.path.pop(0)

pytestmark = pytest.mark.skipif("now" not in inspect.signature(verify_decision_receipt).parameters,
                                reason="the profile github-write/1 needs the decision verifier of main 22aa954e "
                                       "(verify_decision_receipt with now=); this proofbundle does not have it")
SESSION = "n43-session"


def observe(records, tmp_path, events, start, name="run-1"):
    folder = o.recorded(tmp_path, events, name=f"recorded-{name}")
    return o.run_observer(records, folder, start, o.now_plus(120), run=name)


def _note_of(result: dict) -> list:
    notes = result.get("window_notes", [])
    return [n for n in notes if all(w in n for w in ("autonomous answer", "Level 1", "M5"))]


# --- O28B-1: the window says it, M5 counts it ------------------------------------------------------------------------

def test_O28B1_a_go_push_without_its_receipt_counts_under_m5_and_the_window_says_why(tmp_path, monkeypatch, capsys):
    d71._clean.__wrapped__(monkeypatch, tmp_path)
    start = o.now_plus(-60)
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    data = tmp_path / "data"
    data.mkdir()
    env.update(CLAUDE_PLUGIN_DATA=str(data), PLUGIN_DATA=str(data), CLAUDE_CODE_SESSION_ID=SESSION,
               PYTHONPATH=str(pathlib.Path(p1.ROOT) / "src"))
    service = s.Service(env, tmp_path)
    repo = d87._fixture(tmp_path / "work", url=f"https://github.com/{o.REPO}.git")
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": SESSION,
                        "tool_input": {"command": "git push origin claude/x"}})
    proc = subprocess.run([sys.executable, "-I", str(s.GATE_FILE), "--host", "claude", gate.AUTONOMOUS_FLAG],
                          input=event, capture_output=True, text=True, env=env, cwd=str(repo), timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    printed = json.loads(proc.stdout) if proc.stdout.strip() else {}
    assert (printed.get("hookSpecificOutput") or {}).get("permissionDecision") is None, printed   # GO, D87
    assert p1.receipts_in(service.records) == []
    assert [(x["signed"], x["reason"]) for x in service.lines()] == [(False, "verdict_differs")]
    head = d71._git(repo, "rev-parse", "claude/x")
    observe(service.records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, head, o.now_plus(0),
                                                      ref="refs/heads/claude/x")], start)
    result = rc.reconcile(pr.Records(service.records))
    assert (result["M5"], result["M6"], result["decisions"]) == (1, 0, [])
    assert [u["target"] for u in result["unapproved_effects"]] == [f"https://github.com/{o.REPO}#refs/heads/claude/x"]
    assert len(_note_of(result)) == 1, result.get("window_notes")
    rc.main(["--records", str(service.records)])
    assert _note_of(result)[0] in capsys.readouterr().out


def test_O28B1_the_sentence_stands_in_every_window_also_without_a_write(tmp_path, monkeypatch):
    """The sentence is the window's, not a decision's: the reconciliation carries it once, also where nothing arrived."""
    pd._clean_git_environment.__wrapped__(monkeypatch)
    env = pd.env.__wrapped__(tmp_path)
    start = o.now_plus(-60)
    records = o.start_records(env, tmp_path)
    observe(records, tmp_path, [], start)
    result = rc.reconcile(pr.Records(records))
    assert (result["M5"], result["M6"]) == (0, 0) and len(_note_of(result)) == 1, result.get("window_notes")
