"""D136 (finding GF-E001): every text the model gets about a call begins with the verdict.

GF-E001, from echo's guard findings of 2026-11-04, case 1 of a real demonstration session: the hook answered `ask` to
`gh pr comment` (net_unmodeled_git). The user's short line said that the gate asks; the model got only
additionalContext, which began with NOT MEASURED, and the agent wrote that the gate had not escalated, while the signed
receipt of the call recorded ESCALATE. Since D136 the text names the verdict first; the decision, the reason ids and the
receipt are what they were.

This module holds:
- every decision under both hosts gives the model its verdict sentence first, from answer() and from the three passes
  of pre_tool_answer, and a deny's permissionDecisionReason under Claude Code too. The sentences are written in
  tests/_gate_answer.py, not read from the gate;
- the word in brackets is the word the receipt of Level 1 records for the outcome (_pilot_tool_verdict), for every case
  of the corpus below;
- the case of GF-E001 at the hook as the host runs it;
- the corpus below gives the decision, the reason ids and the receipt's statement that the gate gave before D136,
  recorded in tests/fixtures/plugin_d136/before.json with the gate of main ebda917b. The statement's policy digest is
  held constant in both, since it hashes the gate's own file by design (D55) and so changes with any change of the gate;
- a guard over the gate's source: every additionalContext of an answer to a call goes through verdict_first, and a
  planted place that does not is found.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import pathlib
import re
import sys
import time

import pytest

import _gate_answer as ga
from _plugin_env import plugin_env

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle-guard" / "hooks" / "proofbundle_gate.py"
BEFORE = pathlib.Path(__file__).resolve().parent / "fixtures" / "plugin_d136" / "before.json"

ga.skip_where_the_gate_is_not_shipped(GATE, ROOT)

sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

HOSTS = ("claude", "codex")
#: The texts a verdict sentence goes in front of: one with a part marked NOT MEASURED, one without.
WITH_MARK = "NOT MEASURED: Evidence: a git or gh command the gate could not resolve. Failed: the scan. Next step: x."
WITHOUT_MARK = "proofbundle gate: Evidence: the rules file. Failed: the write could change the rules. Next step: y."
SHORT = "Gate asks at gh pr comment because the call can act outside (D27)."
#: The receipt words, written here and not read from the gate.
RECEIPT_WORDS = {"ask": "ESCALATE", "deny": "DENY", "pass": "ALLOW"}

#: The pilot's configuration for the statement of the corpus: only the fields _pilot_statement reads.
CONFIG = {"closing_rules": None, "gate_id": "gate:d136", "agent_id": "agent:d136", "principal_id": "principal:d136",
          "observer_id": "observer:d136", "validity_seconds": 600}
POLICY = "0" * 64
DECIDED_NS = 1_762_905_600_000_000_000


def _bash(command: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s-d136", "tool_use_id": "t-d136",
            "tool_input": {"command": command}}


#: The calls the corpus judges. The first is the call of GF-E001 in its plain form, as echo measured it.
CASES = {
    "gf_e001_comment": _bash('gh pr comment 1 --repo o/r --body "x"'),
    "comment_quoted_word": _bash("gh pr comment 1 --repo o/r --body \"a 'quoted' word\""),
    "comment_after_cd": _bash('cd .. && gh pr comment 1 --repo o/r --body "x"'),
    "merge_by_head": _bash("gh pr merge 7 --repo o/r --merge --match-head-commit "
                           "0123456789abcdef0123456789abcdef01234567"),
    "api_comment": _bash("gh api repos/o/r/issues/1/comments -f body=x"),
    "push_plain": _bash("git push origin main"),
    "push_without_hooks": _bash("git push --no-verify origin main"),
    "status_outside_a_repository": _bash("git status"),
    "not_gated": _bash("ls -la"),
    "mcp_pull_request": {"hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_pull_request",
                         "session_id": "s-d136", "tool_use_id": "t-d136",
                         "tool_input": {"owner": "o", "repo": "r", "title": "x", "head": "topic", "base": "main"}},
    # the file of the gate's own rules, in the gate's folder of the case (the fixture `held`); filled in by record()
    "write_gate_rules": {"hook_event_name": "PreToolUse", "tool_name": "Write", "session_id": "s-d136",
                         "tool_use_id": "t-d136", "tool_input": {"file_path": None, "content": "[]"}},
}


def _filled(event: dict, cwd: pathlib.Path) -> dict:
    """The event in the case's folder: its cwd, and for the write the rules file in the gate's folder beside it."""
    event = {**event, "cwd": str(cwd)}
    if event["tool_name"] == "Write":
        event["tool_input"] = {**event["tool_input"], "file_path": str(cwd.parent / "gate-dir" / "rules.json")}
    return event


def record(module, cwd: pathlib.Path) -> dict:
    """What the corpus gives with one gate module: per host and case the gated actions, the decision, every verdict's
    decision and reason id, the receipt's verdict and, where the pilot reads the call, the receipt's statement with the
    policy digest held at POLICY. The tests below call it with the gate of this tree; before.json holds what it gave
    with the gate of main ebda917b."""
    rows: dict = {}
    for host in HOSTS:
        for name, event in CASES.items():
            event = _filled(event, cwd)
            _event, outcome, actions = module.tool_outcome(json.dumps(event), host, time.monotonic() + 60)
            row: dict = {"actions": actions, "decision": None if outcome is None else outcome.decision}
            if outcome is not None:
                row["verdicts"] = [[v.decision, v.reason_id] for v in outcome.verdicts]
                verdict = module._pilot_tool_verdict(outcome, host)
                row["receipt_verdict"] = verdict
                action, key = module._pilot_tool_action(event)
                if verdict is not None and action is not None:
                    row["statement"] = module._pilot_statement(CONFIG, {}, action, verdict,
                                                               [v.reason_id for v in outcome.verdicts], "a-d136#1",
                                                               DECIDED_NS)
            rows[f"{host}:{name}"] = row
    return rows


@pytest.fixture
def held(monkeypatch, tmp_path):
    """A cwd outside any repository, the gate's folder of the case's own, and the policy digest held at POLICY."""
    cwd = tmp_path / "work"
    cwd.mkdir()
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gate-dir"))
    monkeypatch.setattr(gate, "_pilot_policy_digest", lambda environ: POLICY)
    return cwd


def _printed(outcome, host: str, event: dict):
    """What main prints for an outcome, as main decides whether to print (pre_tool_answer)."""
    if outcome.decision != "pass" or any(v.reason_id in ("approved_by_rule", *gate.HINT_REASONS)
                                         for v in outcome.verdicts) or \
            (outcome.autonomy or {}).get("klasse") in ("go", "maschine", "freigabe"):
        return gate.pre_tool_answer(outcome, host, event, gate._step_of_event(event), environ={})
    return None


# --- every decision, both hosts -------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("decision", ["ask", "deny", "warn", "inactive", "handover"])
@pytest.mark.parametrize("text", [WITH_MARK, WITHOUT_MARK], ids=["with_mark", "without_mark"])
def test_every_answer_gives_the_model_its_verdict_first(decision, host, text):
    printed = gate.answer(decision, text, host=host, short=SHORT)
    specific = printed["hookSpecificOutput"]
    enforced = "deny" if (decision, host) == ("ask", "codex") else decision
    expected = text
    if enforced != decision:
        expected += " Codex cannot ask, so the gate denies the call."
    if decision == "warn":
        expected += " " + gate.CODEX_PUSH_WARNING
    assert ga.reason_of(specific["additionalContext"], enforced) == expected
    assert specific.get("permissionDecision") == (enforced if enforced in ("ask", "deny") else None)
    if (enforced, host) == ("deny", "claude"):
        assert specific["permissionDecisionReason"] == specific["additionalContext"]   # a deny's reason reaches the model
    assert printed["systemMessage"] == SHORT   # the user's short line stays as it was (D53)


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("decision", ["ask", "deny", "warn", "inactive", "handover"])
def test_without_a_short_line_the_users_line_is_the_same_text(decision, host):
    printed = gate.answer(decision, WITH_MARK, host=host)
    assert printed["systemMessage"] == printed["hookSpecificOutput"]["additionalContext"]


def test_a_pass_still_answers_nothing():
    assert gate.answer("pass", WITH_MARK, host="claude") is None and gate.answer("pass", WITH_MARK, host="codex") is None


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", ["rule", "hint", "go", "maschine", "freigabe"])
def test_the_passes_that_give_the_model_a_text_name_their_verdict_first(form, host):
    detail = "a rule frees this form in with-approvals mode. Mode and rules: mode as of 2026-11-12T01:00:00Z."
    reason_id = {"rule": "approved_by_rule", "hint": "hint_move_out"}.get(form, "verified")
    outcome = gate.Outcome("pass", detail, [gate.Verdict("pass", detail, reason_id)])
    if form in ("go", "maschine", "freigabe"):
        outcome.autonomy = {"klasse": form, "quittung": {"karte": "OA-d136"}}
    printed = gate.pre_tool_answer(outcome, host, {"session_id": "s-d136"}, "gh pr comment", environ={})
    specific = printed["hookSpecificOutput"]
    assert "permissionDecision" not in specific and "permissionDecisionReason" not in specific, printed
    assert ga.reason_of(specific["additionalContext"], "pass") == detail


# --- the word in brackets is the receipt's ------------------------------------------------------------------------

def test_the_word_in_brackets_is_the_word_of_the_receipt(held):
    seen = set()
    for host in HOSTS:
        for name, event in CASES.items():
            event = _filled(event, held)
            _event, outcome, _actions = gate.tool_outcome(json.dumps(event), host, time.monotonic() + 60)
            if outcome is None:
                continue
            printed = _printed(outcome, host, event)
            if printed is None:
                continue
            text = ga.model_text(printed)
            word = re.match(r"Verdict: [^.;(]*?(?: \(([A-Z]+)\))?[;.]", text)
            assert word is not None, (host, name, text[:200])
            receipt = gate._pilot_tool_verdict(outcome, host)
            assert word.group(1) == receipt, (host, name, word.group(1), receipt)
            enforced = "deny" if (host, outcome.decision) == ("codex", "ask") else outcome.decision
            assert receipt == RECEIPT_WORDS.get(enforced), (host, name, receipt)
            seen.add((host, enforced))
    # the corpus reaches an ask under Claude Code and a deny under Codex, the two answers of GF-E001's call
    assert {("claude", "ask"), ("codex", "deny")} <= seen, seen


# --- the case of GF-E001 at the hook as the host runs it ------------------------------------------------------------

@pytest.mark.parametrize("host", HOSTS)
def test_gf_e001_the_model_reads_the_verdict_before_not_measured(tmp_path, host):
    cwd = tmp_path / "work"
    cwd.mkdir()
    event = json.dumps({**CASES["gf_e001_comment"], "cwd": str(cwd)})
    args = [] if host == "claude" else ["--host", host]
    proc, entry = ga.run_hook([sys.executable, "-I", str(GATE), *args], event, plugin_env(), cwd=cwd)
    assert proc.returncode == 0, proc.stderr
    answer = ga.parsed(proc, entry)
    assert entry is not None and entry["verdict"] == "ask" and "net_unmodeled_git" in entry["reason_ids"], entry
    text = ga.model_text(answer)
    if host == "claude":
        assert answer["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert text.startswith(ga.VERDICT_LEADS["ask"] + " " + ga.NOT_MEASURED_SENTENCE + " Reason: NOT MEASURED: ")
    else:
        assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert text.startswith(ga.VERDICT_LEADS["deny"] + " " + ga.NOT_MEASURED_SENTENCE + " Reason: NOT MEASURED: ")
    assert text.index("Verdict: ") == 0 and text.index("NOT MEASURED") > text.index("(ESCALATE)" if host == "claude"
                                                                                     else "(DENY)")


# --- the decision, the reason ids and the receipt are what they were -----------------------------------------------

def test_d136_changes_no_decision_reason_id_or_receipt(held):
    before = json.loads(BEFORE.read_text(encoding="utf-8"))
    now = record(gate, held)
    assert sorted(now) == sorted(before["rows"])
    for key in before["rows"]:
        assert now[key] == before["rows"][key], key
    # the corpus is no empty comparison: it holds an ask, a deny, a receipt statement and a call the gate leaves alone
    decisions = {row["decision"] for row in now.values()}
    assert {"ask", "deny", None} <= decisions, decisions
    assert any("statement" in row for row in now.values())


# --- the guard over the gate's source --------------------------------------------------------------------------------

#: The places that give the model an additionalContext and judge no call, each with its reason.
NO_CALL_JUDGED = {
    "session_start_command": "the hand-over of open points at SessionStart (D127) judges no call",
    "main": "the D81 hints are added after the answer's text, or stand alone before a pass that prints nothing (D53)",
}


def _context_sites(source: str) -> list[tuple[str, int, str]]:
    """Every place in the source that sets an additionalContext: (function, line, form), form `call` where the value is a
    call of verdict_first, `reason` where it is the name `reason` and the function's last assignment of that name before
    the place is such a call, else `other`."""
    tree = ast.parse(source)
    sites = []

    def is_first(node) -> bool:
        return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "verdict_first"

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        reasons = sorted((n.lineno, is_first(n.value)) for n in ast.walk(function) if isinstance(n, ast.Assign)
                         and any(isinstance(t, ast.Name) and t.id == "reason" for t in n.targets))
        values = []
        for node in ast.walk(function):
            if isinstance(node, ast.Dict):
                values += [(v, k.lineno) for k, v in zip(node.keys, node.values)
                           if isinstance(k, ast.Constant) and k.value == "additionalContext"]
            elif isinstance(node, ast.Assign):
                values += [(node.value, node.lineno) for t in node.targets if isinstance(t, ast.Subscript)
                           and isinstance(t.slice, ast.Constant) and t.slice.value == "additionalContext"]
        for value, line in values:
            if is_first(value):
                form = "call"
            elif isinstance(value, ast.Name) and value.id == "reason":
                last = [first for at, first in reasons if at < line]
                form = "reason" if last and last[-1] else "other"
            else:
                form = "other"
            sites.append((function.name, line, form))
    return sites


def _unguarded(source: str) -> list[tuple[str, int, str]]:
    return [s for s in _context_sites(source) if s[2] == "other" and s[0] not in NO_CALL_JUDGED]


def test_every_additional_context_of_an_answer_goes_through_verdict_first():
    source = GATE.read_text(encoding="utf-8")
    sites = _context_sites(source)
    assert _unguarded(source) == [], _unguarded(source)
    # the guard reads the places it should: answer() and the three passes of pre_tool_answer
    assert ("answer", "reason") in {(f, form) for f, _l, form in sites}
    assert sum(1 for f, _l, form in sites if (f, form) == ("pre_tool_answer", "call")) == 3, sites
    assert {f for f, _l, form in sites if form == "other"} == set(NO_CALL_JUDGED), sites


def test_the_guard_finds_a_planted_place_without_the_verdict():
    source = GATE.read_text(encoding="utf-8")
    planted = source + ('\n\ndef _planted(outcome):\n    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",'
                        ' "additionalContext": outcome.text}}\n')
    assert [s[0] for s in _unguarded(planted)] == ["_planted"]
    line = "    reason = verdict_first(decision, reason)   # D136: the model reads the verdict before the reason\n"
    assert source.count(line) == 1
    assert [s[0] for s in _unguarded(source.replace(line, ""))] == ["answer"]
    late = source.replace(line, "").replace('    specific = {"hookEventName": "PreToolUse", "additionalContext": reason}\n',
                                            '    specific = {"hookEventName": "PreToolUse", "additionalContext": reason}\n'
                                            + line, 1)
    assert [s[0] for s in _unguarded(late)] == ["answer"]   # the sentence after the place does not count


def test_the_receipt_words_are_the_gates():
    # the brackets read _PILOT_VERDICTS, the table the receipt reads; the words here are written out
    assert gate._PILOT_VERDICTS == RECEIPT_WORDS


def test_the_gate_of_main_before_d136_had_no_verdict_first():
    # the recorded corpus is that of a gate without the change: the file the recording names does not define it
    meta = json.loads(BEFORE.read_text(encoding="utf-8"))["recorded"]
    assert meta["gate_commit"] == "ebda917b7a27dcf78e85de39c76b0e30fb894115" and meta["verdict_first_defined"] is False


def _load(path: pathlib.Path, name: str):
    """A gate file as a module of its own name, for the recording of before.json (see that file's `recorded`)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
