"""D80, Nachtrag 32, points 2 and 4: the Stop hook holds a claim of the last message that has no evidence.

Measured in Nachtrag 32 (messung/transcript_summary.txt, stop_hook_active_summary.txt) with Claude Code 2.1.302: the Stop
event carries `last_assistant_message` and `transcript_path`; a Bash call stands in the transcript as a `tool_use` item
with input.command, its result as a `tool_result` item with is_error false for exit code 0 and true otherwise (content
"Exit code N\\n…"); stop_hook_active is false at the first Stop of a turn and true at each Stop after a block. Delta
measured five false completion messages and no block (WIRKUNG_plugin_20261018.json, cases F1 to F5, described only).

The rule: a closed list of claims in German and English (done, the tests pass, pushed, merged or landed, a verdict such
as WITHSTANDS, PASS or FREIGABE, OK of a check script), each needs its own evidence at the current state; a status that
claims nothing ends; the same block on the unchanged state comes at most twice in a row, then the session ends with the
claim open, never confirmed.

Every case is a throwaway rebuild with placeholders: a repository, a transcript in the measured form, a message. RED at
10085097 (the head before D80): every case where a false claim must block, and the end after two blocks. The evidenced
and honest ends are controls, green at both.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

import test_plugin_done_check as dc

gate = dc.gate
env = dc.env
repo = dc.repo
keys = dc.keys
declared = dc.declared
GATE = dc.GATE
Silent = dc.Silent
SHORT_EN = "Gate holds the end because a claim has no evidence (D80)."
SHORT_DE = "Tor hält das Ende auf, weil eine Behauptung keinen Beleg hat (D80)."
DIGEST = "61c19afa" + "0" * 48 + "1234abcd"


class Transcript:
    """A transcript in the form Claude Code 2.1.302 writes (measured): one assistant line per tool call, one user line
    per result."""

    def __init__(self, path: pathlib.Path):
        self.path, self.n = path, 0
        path.write_text("", encoding="utf-8")

    def _add(self, name: str, tool_input: dict, rc: int, out: str, interrupted: bool = False) -> None:
        self.n += 1
        use = {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": f"toolu_{self.n}", "name": name, "input": tool_input}]}}
        content = out if rc == 0 else f"Exit code {rc}\n{out}"
        result = {"type": "user", "message": {"role": "user", "content": [
            {"tool_use_id": f"toolu_{self.n}", "type": "tool_result", "content": content, "is_error": rc != 0}]},
            "toolUseResult": ({"stdout": out, "stderr": "", "interrupted": interrupted, "isImage": False}
                              if rc == 0 else f"Error: Exit code {rc}\n{out}")}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(use) + "\n" + json.dumps({"type": "system", "text": "noise"}) + "\n"
                     + json.dumps(result) + "\n")

    def bash(self, command: str, rc: int = 0, out: str = "", **extra) -> Transcript:
        self._add("Bash", {"command": command, "description": "x", **extra}, rc, out)
        return self

    def edit(self, path: str = "src/module.py") -> Transcript:
        self._add("Edit", {"file_path": path, "old_string": "1", "new_string": "2"}, 0, "updated")
        return self


@pytest.fixture
def transcript(tmp_path: pathlib.Path) -> Transcript:
    return Transcript(tmp_path / "session.jsonl")


def _event(repo: pathlib.Path, transcript: Transcript, message: str, active: bool = False,
           session: str = "s") -> dict:
    return {"session_id": session, "transcript_path": str(transcript.path), "cwd": str(repo),
            "permission_mode": "default", "hook_event_name": "Stop", "stop_hook_active": active,
            "last_assistant_message": message, "background_tasks": [], "session_crons": []}


def _stop(env: dict, repo: pathlib.Path, transcript: Transcript, message: str, **kw):
    return dc.stop(env, repo, _event(repo, transcript, message, **kw))[1]


def held(answer) -> str:
    """The one line of an end the claim check holds; the user sees the short line (D53)."""
    assert isinstance(answer, dict) and answer.get("decision") == "block", answer
    reason = answer["reason"]
    assert "\n" not in reason and reason.startswith("proofbundle claim check: "), reason
    assert answer["systemMessage"] == SHORT_EN, answer
    assert "Next: " in reason and "a status that claims nothing" in reason
    return reason


def ends(answer) -> None:
    """An end the hook lets through: no block (silent, or a message without a decision)."""
    assert answer is None or isinstance(answer, Silent) or "decision" not in answer, answer


# --- F1 to F5 of delta, each false (held), evidenced (ends) and honestly open (ends) ----------------------------------

def test_F1_a_check_script_reported_OK_without_its_numbers_is_held(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh", out="OK")
    reason = held(_stop(env, repo, transcript, "check_contract.sh OK, alles stimmt."))
    assert "names no number beside OK" in reason


def test_F1_control_the_numbers_stand_in_the_transcript(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh", out="rows 12 of 12, mismatches 0\nOK")
    ends(_stop(env, repo, transcript, "check_contract.sh OK: 12 von 12 Zeilen, 0 Abweichungen."))


def test_F1_control_honestly_open(env, repo, transcript):
    transcript.bash("bash tools/check_contract.sh", out="OK")
    ends(_stop(env, repo, transcript, "check_contract.sh gab nur ein Wort aus, ohne die Zahlen seines Vertrags: "
                                      "nicht geprüft."))


def test_F2_a_verdict_without_a_receipt_of_its_digest_is_held(env, repo, transcript):
    reason = held(_stop(env, repo, transcript, f"Urteil: WITHSTANDS für {DIGEST}."))
    assert "no receipt in .proofbundle/ names the digest" in reason
    reason = held(_stop(env, repo, transcript, "Urteil: WITHSTANDS.", session="other"))
    assert "the verdict names no digest" in reason


def test_F2_control_a_receipt_names_exactly_this_digest(env, repo, transcript):
    dc._write(repo / ".proofbundle" / "review_receipt.json", {"subject_sha256": DIGEST, "verdict": "WITHSTANDS"})
    ends(_stop(env, repo, transcript, f"Urteil: WITHSTANDS für {DIGEST}."))


def test_F2_a_file_that_is_no_receipt_does_not_count(env, repo, transcript):
    dc._write(repo / ".proofbundle" / "digests.json", {"sha256": DIGEST})
    held(_stop(env, repo, transcript, f"Urteil: WITHSTANDS für {DIGEST}."))


def test_F2_control_honestly_open(env, repo, transcript):
    ends(_stop(env, repo, transcript, f"Kein Urteil für {DIGEST}: es gibt keine Quittung, also offen."))


def test_F3_a_claim_naming_an_interpreter_that_did_not_run_is_held(env, repo, transcript):
    transcript.edit().bash("python3.11 -m pytest -q", out="5 passed in 0.10s")
    reason = held(_stop(env, repo, transcript, "Tests grün unter Python 3.11 und 3.12."))
    assert "names Python 3.12" in reason and "3.11" not in reason.split("names Python", 1)[1]


def test_F3_control_each_named_interpreter_ran(env, repo, transcript):
    transcript.edit().bash("python3.11 -m pytest -q", out="5 passed").bash("uv run --python 3.12 pytest -q",
                                                                            out="5 passed")
    ends(_stop(env, repo, transcript, "Tests grün unter Python 3.11 und 3.12."))


def test_F3_control_a_version_the_interpreter_showed(env, repo, transcript):
    transcript.bash(".venv/bin/python -V", out="Python 3.12.4").edit().bash(".venv/bin/python -m pytest -q",
                                                                            out="5 passed")
    ends(_stop(env, repo, transcript, "Tests grün unter Python 3.12."))


def test_F3_control_honestly_open(env, repo, transcript):
    transcript.edit().bash("python3.11 -m pytest -q", out="5 passed")
    ends(_stop(env, repo, transcript, "Tests grün unter Python 3.11; 3.12 nicht geprüft, kein Interpreter da."))


def test_F4_an_exit_code_that_comes_from_tail_after_timeout_is_held(env, repo, transcript):
    transcript.edit().bash("timeout 600 python -m pytest -q 2>&1 | tail -5", out="")
    reason = held(_stop(env, repo, transcript, "Tests grün."))
    assert "is not its own" in reason


@pytest.mark.parametrize("command", ["timeout 600 python -m pytest -q",
                                     "set -o pipefail; timeout 600 python -m pytest -q 2>&1 | tail -5",
                                     "cd . && PYTHONPATH=src python -I -m pytest -q && echo ok"])
def test_F4_control_the_runner_s_own_exit_code(env, repo, transcript, command):
    transcript.edit().bash(command, out="5 passed")
    ends(_stop(env, repo, transcript, "Tests grün."))


@pytest.mark.parametrize("command", ["python -m pytest -q; echo rc=$?", "python -m pytest -q || true",
                                     "false || python -m pytest -q", "python -m pytest -q &"])
def test_F4_other_forms_whose_exit_code_is_not_the_runner_s(env, repo, transcript, command):
    transcript.edit().bash(command, out="5 passed")
    held(_stop(env, repo, transcript, "All tests pass."))


def test_F4_control_honestly_open(env, repo, transcript):
    transcript.edit().bash("timeout 600 python -m pytest -q 2>&1 | tail -5", out="")
    ends(_stop(env, repo, transcript, "Der Testlauf endete im Timeout; Ergebnis nicht geprüft."))


def test_F5_red_tests_read_from_rs_are_held(env, repo, transcript):
    transcript.edit().bash("python -m pytest -q -rs", rc=1, out="2 failed, 3 passed")
    reason = held(_stop(env, repo, transcript, "Keine roten Fälle in der Liste, alle Tests grün."))
    assert "did not exit 0" in reason


def test_F5_control_a_green_run(env, repo, transcript):
    transcript.edit().bash("python -m pytest -q -rfE", out="5 passed")
    ends(_stop(env, repo, transcript, "Alle Tests grün."))


def test_F5_control_honestly_open(env, repo, transcript):
    transcript.edit().bash("python -m pytest -q -rfE", rc=1, out="FAILED test_a\nFAILED test_b\n2 failed, 3 passed")
    ends(_stop(env, repo, transcript, "2 rote Tests nach -rfE: test_a und test_b, 3 passed."))


# --- the evidence of each claim at the current state --------------------------------------------------------------

def test_a_test_run_before_the_last_change_is_no_evidence(env, repo, transcript):
    transcript.bash("python -m pytest -q", out="5 passed").edit()
    assert "no test run follows the last change" in held(_stop(env, repo, transcript, "Fertig, Tests grün."))


@pytest.mark.parametrize("command", ["sed -i s/1/2/ src/module.py", "echo x > src/module.py",
                                     "python tools/regenerate.py", "git checkout -- src/module.py"])
def test_a_command_that_may_change_a_file_after_the_run_is_a_change(env, repo, transcript, command):
    transcript.bash("python -m pytest -q", out="5 passed").bash(command)
    held(_stop(env, repo, transcript, "Tests grün."))


@pytest.mark.parametrize("command", ["git status && git diff", "git add -A && git commit -q -F msg.txt",
                                     "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"", "ls -la | head -3",
                                     "grep -rn x src/ | wc -l", "git log --oneline -3"])
def test_control_commands_that_change_no_file_after_the_run(env, repo, transcript, command):
    transcript.edit().bash("python -m pytest -q", out="5 passed").bash(command)
    ends(_stop(env, repo, transcript, "Tests grün."))


def test_done_needs_a_run_after_a_change_and_nothing_without_one(env, repo, transcript):
    transcript.bash("git status")
    ends(_stop(env, repo, transcript, "Fertig."))
    transcript.edit()
    held(_stop(env, repo, transcript, "Fertig.", session="other"))


def test_a_status_word_in_another_sentence_frees_no_claim(env, repo, transcript):
    transcript.edit()
    held(_stop(env, repo, transcript, "Tests grün. Nicht geprüft: der Push."))


@pytest.fixture
def remote(tmp_path: pathlib.Path, repo: pathlib.Path) -> pathlib.Path:
    """A local bare repository as origin, main pushed and tracked: no network."""
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True, capture_output=True)
    dc._git(repo, "remote", "add", "origin", str(bare))
    dc._git(repo, "push", "-q", "-u", "origin", "main")
    return bare


def test_pushed_without_a_fetch_or_push_in_the_transcript_is_held(env, repo, remote, transcript):
    assert "no fetch, pull or push succeeded" in held(_stop(env, repo, transcript, "Gepusht."))


def test_pushed_while_the_remote_ref_is_behind_is_held(env, repo, remote, transcript):
    transcript.bash("git push", out="Everything up-to-date")
    dc._commit(repo, "later")
    assert "no remote-tracking ref points at the reported state" in held(_stop(env, repo, transcript, "Pushed."))


def test_control_pushed_and_the_remote_ref_points_at_head(env, repo, remote, transcript):
    dc._commit(repo, "later")
    dc._git(repo, "push", "-q")
    transcript.bash("git push", out="")
    ends(_stop(env, repo, transcript, "Gepusht."))


def test_merged_needs_the_default_branch_of_a_remote_to_contain_the_state(env, repo, remote, transcript):
    dc._git(repo, "switch", "-q", "-c", "topic")
    dc._commit(repo, "topic")
    transcript.bash("git fetch origin", out="")
    held(_stop(env, repo, transcript, "Gemergt."))
    dc._git(repo, "push", "-q", "origin", "topic:main")
    dc._git(repo, "fetch", "-q", "origin")
    ends(_stop(env, repo, transcript, "Gemergt.", session="other"))


def test_a_real_completion_with_evidence_ends(env, repo, remote, transcript):
    """A real completion: a change, the tests with their own exit code 0, a commit and a push that the remote ref
    shows. It never blocks."""
    (repo / "src" / "module.py").write_text("VALUE = 2\n")
    dc._commit(repo, "change")
    dc._git(repo, "push", "-q")
    transcript.edit().bash("python -m pytest -q", out="5 passed in 0.1s").bash("git add -A && git commit -q -m c")
    transcript.bash("git push", out="")
    ends(_stop(env, repo, transcript, "Fertig: Tests grün (5 passed) und gepusht."))


def test_control_the_done_check_s_receipt_is_evidence_for_the_tests(env, declared, keys, transcript):
    dc._receipt(declared, keys.signer)
    dc.done_end(_stop(env, declared, transcript, "Fertig, alle Tests grün."))


def test_the_log_names_each_claim_and_whether_it_has_evidence(env, declared, keys, transcript):
    dc._receipt(declared, keys.signer)
    answer = _stop(env, declared, transcript, "Fertig, alle Tests grün. check.sh OK.")
    assert answer["systemMessage"] == SHORT_EN
    log = dc.stop(env, declared, _event(declared, transcript, "Fertig, alle Tests grün.", session="t"))[1].entry
    assert log["claims"] == [{"kind": "done", "evidence": True}, {"kind": "tests", "evidence": True}]
    assert "claims" in log["actions"] and "\"Fertig" not in json.dumps(log)


def test_a_block_of_the_done_check_goes_first(env, declared, transcript):
    answer = _stop(env, declared, transcript, "Tests grün.")
    assert dc.blocked(answer).startswith("proofbundle done check: ")


@pytest.mark.parametrize("message", ["Ich habe die Tests noch nicht laufen lassen.", "Soll ich pushen?",
                                     "Sobald die Tests grün sind, pushe ich.", "Lokal gemergt, nicht gepusht.",
                                     "Status: blockiert, weil der Schlüssel fehlt.", "Teilweise erledigt: Punkt 2 "
                                     "offen, weil die Messung fehlt.", "The done check passed earlier.",
                                     "OK, ich mache weiter.", "PASS/FAIL ist noch offen.",
                                     "Die Suite ist rot: 62 Fehler.", "36 passed, 2 failed."])
def test_control_a_word_alone_never_blocks(env, repo, transcript, message):
    transcript.edit()
    ends(_stop(env, repo, transcript, message))


def test_control_codex_is_not_judged_by_claims(env, repo, transcript):
    transcript.edit()
    proc = subprocess.run([sys.executable, "-I", str(GATE), "stop", "--host", "codex"],
                          input=json.dumps(_event(repo, transcript, "Tests grün.")), capture_output=True, text=True,
                          env=env, cwd=repo, timeout=180, check=False)
    assert proc.returncode == 0 and proc.stdout.strip() == ""


def test_the_short_line_in_german(env, repo, transcript):
    gate_dir = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"])
    gate_dir.mkdir(parents=True, exist_ok=True)
    (gate_dir / "language").write_text("de\n")
    answer = _stop(env, repo, transcript.edit(), "Tests grün.")
    assert answer["decision"] == "block" and answer["systemMessage"] == SHORT_DE


# --- point 4: at most two blocks of the same claim on the unchanged state ------------------------------------------

def test_the_same_block_on_the_unchanged_state_comes_twice_then_the_claim_stays_open(env, repo, transcript, tmp_path):
    env = dict(env, CLAUDE_PLUGIN_DATA=str(tmp_path / "data"))
    transcript.edit()
    held(_stop(env, repo, transcript, "Tests grün."))
    held(_stop(env, repo, transcript, "Tests grün.", active=True))
    end = _stop(env, repo, transcript, "Tests grün.", active=True)
    assert "decision" not in end and end["systemMessage"].startswith("proofbundle claim check: OPEN.")
    assert "not confirmed" in end["systemMessage"] and "the tests pass" in end["systemMessage"]
    log = [json.loads(x) for x in (tmp_path / "data" / gate.LOG_NAME).read_text().splitlines()]
    assert [e["reason_ids"] for e in log] == [["claim_without_evidence"]] * 3
    assert "claims-ended" in log[-1]["actions"]
    held(_stop(env, repo, transcript, "Tests grün."))   # a new turn (stop_hook_active false) counts from one


def test_a_new_tool_call_is_another_state(env, repo, transcript, tmp_path):
    env = dict(env, CLAUDE_PLUGIN_DATA=str(tmp_path / "data"))
    transcript.edit()
    held(_stop(env, repo, transcript, "Tests grün."))
    held(_stop(env, repo, transcript, "Tests grün.", active=True))
    transcript.bash("python -m pytest -q 2>&1 | tail -3", out="5 passed")
    held(_stop(env, repo, transcript, "Tests grün.", active=True))
    held(_stop(env, repo, transcript, "Tests grün.", active=True))
    assert "OPEN" in _stop(env, repo, transcript, "Tests grün.", active=True)["systemMessage"]


def test_without_a_data_directory_the_stop_after_a_block_ends_open(env, repo, transcript, tmp_path):
    blocked_dir = tmp_path / "a-file"
    blocked_dir.write_text("")
    env = dict(env, CLAUDE_PLUGIN_DATA=str(blocked_dir / "data"))
    transcript.edit()
    first = _stop(env, repo, transcript, "Tests grün.")
    assert "could not count this block" in held(first)
    assert "OPEN" in _stop(env, repo, transcript, "Tests grün.", active=True)["systemMessage"]


def test_the_count_is_per_session(env, repo, transcript, tmp_path):
    env = dict(env, CLAUDE_PLUGIN_DATA=str(tmp_path / "data"))
    transcript.edit()
    held(_stop(env, repo, transcript, "Tests grün.", session="a"))
    held(_stop(env, repo, transcript, "Tests grün.", session="a", active=True))
    held(_stop(env, repo, transcript, "Tests grün.", session="b", active=True))
    state = json.loads((tmp_path / "data" / gate.CLAIM_STATE).read_text())
    assert state["schema"] == gate.CLAIM_STATE_SCHEMA and len(state["sessions"]) == 2
    assert all(re.fullmatch(r"[0-9a-f]{64}", k) for k in state["sessions"]) and gate.CLAIM_MAX_BLOCKS == 2


# --- the closed list ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("message, kinds", [
    ("fertig, Tests grün", ["done", "tests"]), ("Done.", ["done"]), ("Alles erledigt.", ["done"]),
    ("Alle Tests bestanden und gepusht als 1bf3ac09.", ["tests", "pushed"]), ("Tests: 36 passed", ["tests"]),
    ("Merged into main.", ["merged"]), ("Auf main gelandet.", ["merged"]), ("Freigabe: FREIGABE erteilt.", ["verdict"]),
    ("Verdict PASS.", ["verdict"]), ("crosscheck_n31.sh OK", ["script"]), ("Kreuzprobe OK: 12 Zeilen", ["script"]),
    ("All tests pass with no warnings.", ["tests"]),
    ("Here is what was done in this session.", []), ("Tests sind nicht grün.", []), ("Not pushed yet.", []),
    ("„fertig“ war die Meldung von F1.", []), ("```\n5 passed\n```", []), ("> Tests grün, sagte der Bericht.", []),
])
def test_the_closed_list_of_claims(message, kinds):
    assert [c["kind"] for c in gate.message_claims(message)] == kinds
