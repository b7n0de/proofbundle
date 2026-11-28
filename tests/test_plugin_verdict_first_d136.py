"""D136 (finding GF-E001): every text the model gets about a call the gate judges begins with the verdict.

GF-E001, from echo's guard findings of 2026-11-04, case 1 of a real demonstration session: the hook answered `ask` to
`gh pr comment` (net_unmodeled_git). The user's short line said that the gate asks; the model got only
additionalContext, which began with NOT MEASURED, and the agent wrote that the gate had not escalated, while the signed
receipt of the call recorded ESCALATE. Since D136 the text names the verdict first; the decision, the reason ids and the
receipt are what they were.

This module holds:
- every decision under both hosts gives the model its verdict sentence first, from answer() and from the three passes
  of pre_tool_answer, and a deny's permissionDecisionReason under Claude Code too. The sentences are written in
  tests/_gate_answer.py, not read from the gate;
- the D81 hints follow the answer's text, or the verdict sentence where the answer gives the model no text (a pass, an
  inactive gate already shown in the session); only beside a call the gate does not judge do they stand alone;
- the word in brackets is the word the receipt of Level 1 records for the outcome (_pilot_tool_verdict), for every case
  of the corpus below;
- the case of GF-E001 at the hook as the host runs it, with and without --autonomous;
- the corpus below gives, in the process and at the hook as the host runs it, the decision, the reason ids, the log
  line's verdict and the receipt's statement that the gate gave before D136, recorded in
  tests/fixtures/plugin_d136/before.json with the gate of main ebda917b. The statement's policy digest is held constant,
  since it hashes the gate's own file by design (D55) and so changes with any change of the gate. A hand-over (D35)
  needs a Level 2 set up and is not in the corpus; its sentence is checked on a built outcome;
- a guard over the gate's source: every place that sets an additionalContext takes it from verdict_first, or is one of
  two places named with their exact expression, and planted places in five forms are found.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
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

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

HOSTS = ("claude", "codex")
#: How the host starts the gate: Claude Code with and without the --autonomous of the Guard's hooks.json, and Codex.
MODES = {"claude": ("claude", False), "claude_autonomous": ("claude", True), "codex": ("codex", False)}
#: The texts a verdict sentence goes in front of: one with a part marked NOT MEASURED, one without.
WITH_MARK = "NOT MEASURED: Evidence: a git or gh command the gate could not resolve. Failed: the scan. Next step: x."
WITHOUT_MARK = "proofbundle gate: Evidence: the rules file. Failed: the write could change the rules. Next step: y."
SHORT = "Gate asks at gh pr comment because the call can act outside (D27)."
#: The receipt words, written here and not read from the gate.
RECEIPT_WORDS = {"ask": "ESCALATE", "deny": "DENY", "pass": "ALLOW"}
HINT = "proofbundle hint (D81): "

#: The pilot's configuration for the statement of the corpus: only the fields _pilot_statement reads.
CONFIG = {"closing_rules": None, "gate_id": "gate:d136", "agent_id": "agent:d136", "principal_id": "principal:d136",
          "observer_id": "observer:d136", "validity_seconds": 600}
POLICY = "0" * 64
DECIDED_NS = 1_762_905_600_000_000_000


def _bash(where: str, command: str) -> tuple[str, dict]:
    return where, {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s-d136",
                   "tool_use_id": "t-d136", "tool_input": {"command": command}}


#: The calls the corpus judges, each in a folder outside any repository (`outside`) or in a repository with one commit
#: and nothing declared (`repo`). The first is the call of GF-E001 in its plain form, as echo measured it.
CASES = {
    "gf_e001_comment": _bash("outside", 'gh pr comment 1 --repo o/r --body "x"'),
    "comment_quoted_word": _bash("outside", "gh pr comment 1 --repo o/r --body \"a 'quoted' word\""),
    "comment_after_cd": _bash("outside", 'cd .. && gh pr comment 1 --repo o/r --body "x"'),
    "merge_by_head": _bash("outside", "gh pr merge 7 --repo o/r --merge --match-head-commit "
                                      "0123456789abcdef0123456789abcdef01234567"),
    "api_comment": _bash("outside", "gh api repos/o/r/issues/1/comments -f body=x"),
    "push_plain": _bash("outside", "git push origin main"),
    "push_without_hooks": _bash("outside", "git push --no-verify origin main"),
    "status_outside_a_repository": _bash("outside", "git status"),
    "not_gated": _bash("outside", "ls -la"),
    "repo_status": _bash("repo", "git status"),
    "repo_record": _bash("repo", "git commit -m x"),
    "repo_push_plain": _bash("repo", "git push origin main"),
    "repo_push_bare": _bash("repo", "git push"),
    "mcp_pull_request": ("outside", {"hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_pull_request",
                                     "session_id": "s-d136", "tool_use_id": "t-d136",
                                     "tool_input": {"owner": "o", "repo": "r", "title": "x", "head": "topic",
                                                    "base": "main"}}),
    # the file of the gate's own rules, in the gate's folder of the case; filled in by _filled()
    "write_gate_rules": ("outside", {"hook_event_name": "PreToolUse", "tool_name": "Write", "session_id": "s-d136",
                                     "tool_use_id": "t-d136", "tool_input": {"file_path": None, "content": "[]"}}),
}


def make_places(base: pathlib.Path) -> dict:
    """The folders of the corpus under base: `outside`, `repo` (a repository with one empty commit and nothing declared)
    and `gate-dir`, the gate's folder."""
    places = {"outside": base / "work", "repo": base / "repo", "gate-dir": base / "gate-dir"}
    places["outside"].mkdir()
    places["repo"].mkdir()
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(base), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_DATE": "2026-11-12T00:00:00Z", "GIT_COMMITTER_DATE": "2026-11-12T00:00:00Z"}
    subprocess.run(["git", "init", "-q", "-b", "main", str(places["repo"])], check=True, env=env)
    subprocess.run(["git", "-C", str(places["repo"]), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "commit", "-q", "--allow-empty", "-m", "x"], check=True, env=env)
    return places


def _filled(where: str, event: dict, places: dict) -> dict:
    """The event in its folder: its cwd, and for the write the rules file in the gate's folder."""
    event = {**event, "cwd": str(places[where])}
    if event["tool_name"] == "Write":
        event["tool_input"] = {**event["tool_input"], "file_path": str(places["gate-dir"] / "rules.json")}
    return event


def record(module, places: dict) -> dict:
    """What the corpus gives in the process with one gate module: per mode and case the gated actions, the decision,
    every verdict's decision and reason id, the receipt's verdict and, where the pilot reads the call, the receipt's
    statement with the policy digest held at POLICY (the caller holds it)."""
    rows: dict = {}
    for mode, (host, autonomous) in MODES.items():
        for name, (where, event) in CASES.items():
            event = _filled(where, event, places)
            _event, outcome, actions = module.tool_outcome(json.dumps(event), host, time.monotonic() + 60,
                                                           autonomous=autonomous)
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
            rows[f"{mode}:{name}"] = row
    return rows


def hook_rows(gate_file: pathlib.Path, places: dict) -> dict:
    """What the corpus gives at the hook as the host runs it, with one gate file: per mode and case whether the hook
    printed an answer, its permission decision, and the log line's verdict, decision and reason ids."""
    rows: dict = {}
    env = plugin_env(PROOFBUNDLE_GATE_DIR=str(places["gate-dir"]))
    for mode, (host, autonomous) in MODES.items():
        args = (["--host", host] if host != "claude" else []) + (["--autonomous"] if autonomous else [])
        for name, (where, event) in CASES.items():
            event = _filled(where, event, places)
            proc, entry = ga.run_hook([sys.executable, "-I", str(gate_file), *args], json.dumps(event), env,
                                      cwd=places[where])
            printed = json.loads(proc.stdout) if proc.stdout.strip() else None
            rows[f"{mode}:{name}"] = {
                "rc": proc.returncode, "printed": printed is not None,
                "permissionDecision": ((printed or {}).get("hookSpecificOutput") or {}).get("permissionDecision"),
                "log": None if entry is None else [entry.get("verdict"), entry.get("decision"), entry.get("reason_ids")]}
    return rows


@pytest.fixture
def places(monkeypatch, tmp_path):
    """The corpus' folders, the gate's folder named for the gate in the process, and the policy digest held at POLICY."""
    found = make_places(tmp_path)
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(found["gate-dir"]))
    monkeypatch.setattr(gate, "_pilot_policy_digest", lambda environ: POLICY)
    return found


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


# --- the D81 hints follow the verdict ---------------------------------------------------------------------------------

def _outcome(decision: str) -> "gate.Outcome":
    return gate.Outcome(decision, "x", [gate.Verdict(decision, "x", "free_after_read_profile")])


@pytest.mark.parametrize("decision", ["pass", "inactive"])
def test_a_hint_beside_an_answer_without_text_follows_the_verdict_sentence(decision):
    printed = gate.hints_after_the_verdict(None, _outcome(decision), ["pytest_r_without_failures"])
    text = printed["hookSpecificOutput"]["additionalContext"]
    assert text == ga.VERDICT_LEADS[decision] + " " + gate._HINTS["pytest_r_without_failures"], text
    assert "systemMessage" not in printed and "permissionDecision" not in printed["hookSpecificOutput"]


def test_a_hint_beside_an_answer_with_text_follows_that_text():
    answered = gate.answer("ask", WITH_MARK, host="claude", short=SHORT)
    printed = gate.hints_after_the_verdict(answered, _outcome("ask"), ["pipe_without_pipefail"])
    text = printed["hookSpecificOutput"]["additionalContext"]
    assert text == answered["hookSpecificOutput"]["additionalContext"] + " " + gate._HINTS["pipe_without_pipefail"]
    assert text.count("Verdict: ") == 1 and printed["systemMessage"] == SHORT


def test_a_hint_beside_a_call_the_gate_does_not_judge_stands_alone():
    printed = gate.hints_after_the_verdict(None, None, ["pytest_r_without_failures"])
    assert printed["hookSpecificOutput"]["additionalContext"] == gate._HINTS["pytest_r_without_failures"]


def _hook(cwd, command: str, env: dict, session: str = "s-d136"):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd), "session_id": session,
             "tool_use_id": "t-d136", "tool_input": {"command": command}}
    proc, entry = ga.run_hook([sys.executable, "-I", str(GATE), "--autonomous"], json.dumps(event), env, cwd=cwd)
    assert proc.returncode == 0, proc.stderr
    return (json.loads(proc.stdout) if proc.stdout.strip() else None), entry


def test_at_the_hook_a_hint_beside_a_silent_pass_follows_the_pass_sentence(places):
    answer, entry = _hook(places["repo"], "git status; python -m pytest -q -rs", plugin_env())
    assert entry["verdict"] == "pass" and entry["hints"] == ["pytest_r_without_failures"], entry
    assert answer["hookSpecificOutput"]["additionalContext"].startswith(ga.VERDICT_LEADS["pass"] + " " + HINT)
    assert "systemMessage" not in answer   # the pass stays silent for the person (D53)


def test_at_the_hook_a_hint_beside_an_inactive_gate_shown_before_follows_the_inactive_sentence(places, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    env = plugin_env(CLAUDE_PLUGIN_DATA=str(data))
    command = "git push origin main; python -m pytest -q -rs"
    first, _entry = _hook(places["repo"], command, env)
    assert ga.model_reason(first).endswith(gate._HINTS["pytest_r_without_failures"]), first   # the line, then the hint
    second, entry = _hook(places["repo"], command, env)
    assert entry["verdict"] == "inactive" and "systemMessage" not in second, second   # shown once (D53)
    assert second["hookSpecificOutput"]["additionalContext"] == (ga.VERDICT_LEADS["inactive"] + " "
                                                                  + gate._HINTS["pytest_r_without_failures"])


def test_at_the_hook_a_hint_beside_a_call_the_gate_does_not_judge_stands_alone(places):
    answer, entry = _hook(places["outside"], "python -m pytest -q -rs", plugin_env())
    assert entry is None or entry.get("verdict") == "not_gated", entry
    assert answer["hookSpecificOutput"]["additionalContext"] == gate._HINTS["pytest_r_without_failures"]


# --- the word in brackets is the receipt's ------------------------------------------------------------------------

def test_the_word_in_brackets_is_the_word_of_the_receipt(places):
    seen = set()
    for mode, (host, autonomous) in MODES.items():
        for name, (where, event) in CASES.items():
            event = _filled(where, event, places)
            _event, outcome, _actions = gate.tool_outcome(json.dumps(event), host, time.monotonic() + 60,
                                                          autonomous=autonomous)
            if outcome is None:
                continue
            printed = _printed(outcome, host, event)
            if printed is None:
                continue
            text = ga.model_text(printed)
            sentence = re.match(r"Verdict: ([^.;]*)[.;]", text)
            assert sentence is not None, (mode, name, text[:200])
            word = re.search(r"\(([A-Z]+)\)", sentence.group(1))
            receipt = gate._pilot_tool_verdict(outcome, host)
            assert (word.group(1) if word else None) == receipt, (mode, name, sentence.group(1), receipt)
            enforced = "deny" if (host, outcome.decision) == ("codex", "ask") else outcome.decision
            assert receipt == RECEIPT_WORDS.get(enforced), (mode, name, receipt)
            seen.add((mode, enforced))
    # the corpus reaches an ask under Claude Code, a deny under Codex, an inactive gate and a warning
    assert {("claude", "ask"), ("claude_autonomous", "ask"), ("codex", "deny"), ("claude", "inactive"),
            ("codex", "warn")} <= seen, seen


# --- the case of GF-E001 at the hook as the host runs it ------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_gf_e001_the_model_reads_the_verdict_before_not_measured(places, mode):
    host, autonomous = MODES[mode]
    where, event = CASES["gf_e001_comment"]
    args = (["--host", host] if host != "claude" else []) + (["--autonomous"] if autonomous else [])
    proc, entry = ga.run_hook([sys.executable, "-I", str(GATE), *args], json.dumps(_filled(where, event, places)),
                              plugin_env(), cwd=places[where])
    assert proc.returncode == 0, proc.stderr
    answer = ga.parsed(proc, entry)
    assert entry is not None and entry["verdict"] == "ask" and "net_unmodeled_git" in entry["reason_ids"], entry
    enforced = "deny" if host == "codex" else "ask"
    assert answer["hookSpecificOutput"]["permissionDecision"] == enforced
    text = ga.model_text(answer)
    assert text.startswith(ga.VERDICT_LEADS[enforced] + " " + ga.NOT_MEASURED_SENTENCE + " Reason: NOT MEASURED: ")


# --- the decision, the reason ids, the log and the receipt are what they were ---------------------------------------

def test_d136_changes_no_decision_reason_id_or_receipt_in_the_process(places):
    before = json.loads(BEFORE.read_text(encoding="utf-8"))["rows"]
    now = record(gate, places)
    assert sorted(now) == sorted(before)
    for key in before:
        assert now[key] == before[key], key
    decisions = {row["decision"] for row in now.values()}
    assert {"ask", "deny", "warn", "inactive", "pass", None} <= decisions, decisions
    assert any("statement" in row for row in now.values())


def test_d136_changes_no_answer_decision_or_log_line_at_the_hook(places):
    before = json.loads(BEFORE.read_text(encoding="utf-8"))["hook_rows"]
    now = hook_rows(GATE, places)
    assert sorted(now) == sorted(before)
    for key in before:
        assert now[key] == before[key], key
    assert {row["permissionDecision"] for row in now.values()} >= {"ask", "deny", None}
    assert any(row["log"] and row["log"][0] == "pass" for row in now.values())
    assert any(row["log"] and row["log"][0] == "inactive" for row in now.values())


# --- the guard over the gate's source --------------------------------------------------------------------------------

#: The two places that set an additionalContext without verdict_first, each with its exact expression (ast.unparse) and
#: its reason. Any other expression there, and any other place, fails the guard.
NAMED = {
    ("session_start_command", "'\\n\\n'.join(contexts)"):
        "the hand-over of open points at SessionStart (D127) judges no call",
    ("hints_after_the_verdict", "' '.join(([head] if head else []) + [_HINTS[h] for h in hints])"):
        "the D81 hints after `head`, the answer's text or the verdict sentence (the next test pins `head`)",
}
HEAD = "specific.get('additionalContext') or (verdict_sentence(outcome.decision) if outcome is not None else '')"


class _Sites(ast.NodeVisitor):
    """Every place that sets an additionalContext, with the innermost function it is in: a dict display, a call of
    dict(), .update() or .setdefault(), and an assignment to a subscript, augmented ones included."""

    def __init__(self):
        self.stack, self.found, self.assigned = ["<module>"], [], {}

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.assigned[node.name] = sorted(
            (n.lineno, ast.unparse(n.value)) for n in ast.walk(node) if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "reason" for t in n.targets))
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _add(self, value, line):
        self.found.append((self.stack[-1], line, value))

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value == "additionalContext":
                self._add(value, key.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
        if name in ("dict", "update"):
            for kw in node.keywords:
                if kw.arg == "additionalContext":
                    self._add(kw.value, node.lineno)
        if name == "setdefault" and node.args and isinstance(node.args[0], ast.Constant) and \
                node.args[0].value == "additionalContext":
            self._add(node.args[1] if len(node.args) > 1 else ast.Constant(None), node.lineno)
        self.generic_visit(node)

    def _targets(self, targets, value, line):
        for target in targets:
            if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and \
                    target.slice.value == "additionalContext":
                self._add(value, line)

    def visit_Assign(self, node):
        self._targets(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._targets([node.target], ast.Constant("augmented"), node.lineno)
        self.generic_visit(node)


def _context_sites(source: str) -> list[tuple[str, int, str]]:
    """(function, line, form): `call` for a call of verdict_first, `reason` for the name `reason` whose last assignment
    before the place in that function is such a call, `named` for a place of NAMED, else `other`."""
    sites = _Sites()
    sites.visit(ast.parse(source))
    out = []
    for function, line, value in sites.found:
        text = ast.unparse(value)
        if isinstance(value, ast.Call) and getattr(value.func, "id", None) == "verdict_first":
            form = "call"
        elif text == "reason":
            last = [v for at, v in sites.assigned.get(function, []) if at < line]
            form = "reason" if last and last[-1].startswith("verdict_first(") else "other"
        elif (function, text) in NAMED:
            form = "named"
        else:
            form = "other"
        out.append((function, line, form))
    return out


def _unguarded(source: str) -> list[str]:
    return [f for f, _line, form in _context_sites(source) if form == "other"]


def test_every_additional_context_goes_through_verdict_first():
    source = GATE.read_text(encoding="utf-8")
    sites = _context_sites(source)
    assert _unguarded(source) == [], sites
    # the guard reads the places it should: answer(), the three passes of pre_tool_answer, the two named places
    assert ("answer", "reason") in {(f, form) for f, _l, form in sites}
    assert sum(1 for f, _l, form in sites if (f, form) == ("pre_tool_answer", "call")) == 3, sites
    assert {f for f, _l, form in sites if form == "named"} == {f for f, _t in NAMED}, sites


def test_the_hint_chain_starts_with_the_answer_or_the_verdict_sentence():
    function = next(n for n in ast.walk(ast.parse(GATE.read_text(encoding="utf-8")))
                    if isinstance(n, ast.FunctionDef) and n.name == "hints_after_the_verdict")
    heads = [ast.unparse(n.value) for n in ast.walk(function) if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "head" for t in n.targets)]
    assert heads == [HEAD]


def _planted_in(source: str, function: str, anchor: str, line: str) -> str:
    """source with line inserted before the first `anchor` inside `function`."""
    start = source.index(f"\ndef {function}(")
    at = source.index(anchor, start)
    return source[:at] + line + source[at:]


@pytest.mark.parametrize("form, function, anchor, line", [
    ("subscript in main", "main", "    if printed is not None:\n",
     '    printed["hookSpecificOutput"]["additionalContext"] = verdict.text\n'),
    ("update in answer", "answer", "    printed = {",
     "    specific.update(additionalContext=reason + ' ')\n"),
    ("setdefault in pre_tool_answer", "pre_tool_answer", "    session = event.get(",
     "    {}.setdefault('additionalContext', outcome.text)\n"),
    ("augmented in the hint chain", "hints_after_the_verdict", "    printed[\"hookSpecificOutput\"] = specific\n",
     "    specific['additionalContext'] += ' x'\n"),
    ("dict() in main", "main", "    if printed is not None:\n",
     "    printed = dict(printed or {}, hookSpecificOutput=dict(additionalContext=verdict.text))\n"),
])
def test_the_guard_finds_a_planted_place_without_the_verdict(form, function, anchor, line):
    source = GATE.read_text(encoding="utf-8")
    assert _unguarded(source) == []
    assert _unguarded(_planted_in(source, function, anchor, line)) == [function], form


def test_the_guard_finds_a_new_function_a_removed_sentence_and_a_changed_named_place():
    source = GATE.read_text(encoding="utf-8")
    planted = source + ('\n\ndef _planted(outcome):\n    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",'
                        ' "additionalContext": outcome.text}}\n')
    assert _unguarded(planted) == ["_planted"]
    line = "    reason = verdict_first(decision, reason)   # D136: the model reads the verdict before the reason\n"
    assert source.count(line) == 1
    assert _unguarded(source.replace(line, "")) == ["answer"]
    place = '    specific = {"hookEventName": "PreToolUse", "additionalContext": reason}\n'
    late = source.replace(line, "").replace(place, place + line, 1)
    assert _unguarded(late) == ["answer"]   # the sentence after the place does not count
    chain = "    specific[\"additionalContext\"] = \" \".join(([head] if head else []) + [_HINTS[h] for h in hints])\n"
    assert source.count(chain) == 1
    assert _unguarded(source.replace(chain, chain.replace("([head] if head else []) + ", ""))) == \
        ["hints_after_the_verdict"]


def test_the_receipt_words_are_the_gates():
    # the brackets read _PILOT_VERDICTS, the table the receipt reads; the words here are written out
    assert gate._PILOT_VERDICTS == RECEIPT_WORDS


def test_the_recording_is_of_the_gate_before_d136():
    meta = json.loads(BEFORE.read_text(encoding="utf-8"))["recorded"]
    assert meta["gate_commit"] == "ebda917b7a27dcf78e85de39c76b0e30fb894115" and meta["verdict_first_defined"] is False


def load_gate(path: pathlib.Path, name: str):
    """A gate file as a module of its own name, for the recording of before.json (see that file's `recorded`)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
