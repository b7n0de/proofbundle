"""Nachtrag 20, Ergänzung 3, parts 7 and 8 (DECISIONS.md D53): the gate is silent on a pass and answers everything
else with one short line, in English or, where a person set it, in German.

Measured by Cowork on delta's screen (Claude Code 2.1.301): every free command carried a grey block of some 700
characters, the reason of the pass as systemMessage, and the same text went to the model as additionalContext. The
owner chose: a free command shows nothing and its reason stays in the gate log; an ask or a block shows one short line
with the step that asks (D46), the reason in everyday words and the D number; the long reason goes on to the model.

Red at b4f14212 for every case but the log controls, which hold that the log entry stays what it was.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

import test_claude_code_plugin_gate as cg
from _plugin_env import plugin_env

GATE = cg.GATE
gate = cg.gate

#: The keys a log entry of a PreToolUse call carries, as before D53 (an applied rule adds applied_rule).
LOG_KEYS = {"ts", "host", "gate_version", "session_id", "tool", "actions", "decision", "verdict", "mode", "reason_ids",
            "repos"}
D_AT_END = re.compile(r"\((D[0-9]{1,3}[A-Z]?)\)\.$")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    cg._clean_git_config.__wrapped__(monkeypatch)


@pytest.fixture
def repo(tmp_path):
    return cg.repo.__wrapped__(tmp_path)


@pytest.fixture
def shim(tmp_path):
    return cg.shim.__wrapped__(tmp_path)


@pytest.fixture
def plain(tmp_path):
    """A repository that declares nothing: the gate is not active there (D5)."""
    path = tmp_path / "plain"
    path.mkdir()
    cg._git(path, "init", "-q", "-b", "main")
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    cg._commit(path)
    return path


def run(env: dict, cwd: pathlib.Path, *, command: str | None = None, event: dict | None = None,
        host: str = "claude") -> tuple[str, dict | None]:
    """The gate's stdout as it is, and the parsed answer or None when it printed nothing."""
    event = event or {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                      "tool_input": {"command": command}}
    argv = [sys.executable, str(GATE)] + (["--host", host] if host != "claude" else [])
    proc = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, timeout=120,
                          check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout, (json.loads(proc.stdout) if proc.stdout.strip() else None)


def with_data(env: dict, tmp_path: pathlib.Path, language: str | None = None) -> dict:
    data, gate_dir = tmp_path / "plugin-data", tmp_path / "gate-dir"
    gate_dir.mkdir(exist_ok=True)
    if language is not None:
        (gate_dir / "language").write_text(language + "\n", encoding="utf-8")
    return {**env, "CLAUDE_PLUGIN_DATA": str(data), "PROOFBUNDLE_GATE_DIR": str(gate_dir)}


def log_lines(env: dict) -> list[dict]:
    path = pathlib.Path(env["CLAUDE_PLUGIN_DATA"]) / gate.LOG_NAME
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def short(answer: dict) -> str:
    """The line the user sees, checked against its form: one line, at most 160 characters, ending in a D number."""
    line = answer["systemMessage"]
    assert "\n" not in line and len(line) <= 160, (len(line), line)
    assert D_AT_END.search(line) or re.search(r"\((D[0-9]{1,3}[A-Z]?)\)\. ", line), line
    return line


def german(line: str) -> None:
    assert line.startswith("Tor "), line
    assert "—" not in line and "–" not in line and ": " not in line, line


CHAIN_ASK = "git stash list && ls"
#: A push in a repository that declares nothing: the gate is not active there (D5). A read form is free there (D34).
INACTIVE_PUSH = "git push origin main"


# --- part 7: a pass is silent ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("host,command,reason", [
    ("claude", "git -C {repo} log -1 --oneline", "free_after_read_profile"),
    ("claude", "git commit -m msg", "free_after_state_check"),
    ("codex", "git commit -m msg", "free_after_state_check"),     # class a is off under Codex (D37); K-NW-2 B is not
])
def test_a_pass_prints_nothing(shim, repo, tmp_path, host, command, reason):
    env = with_data(shim, tmp_path)
    if host == "codex":
        env["PLUGIN_DATA"] = env["CLAUDE_PLUGIN_DATA"]
    stdout, answer = run(env, repo, command=command.format(repo=repo), host=host)
    entry = log_lines(env)[-1]
    assert (entry["verdict"], entry["reason_ids"]) == ("pass", [reason]), entry
    assert stdout == "" and answer is None


def test_a_pass_still_leaves_its_log_line_with_verdict_and_reason(shim, repo, tmp_path):
    env = with_data(shim, tmp_path)
    run(env, repo, command=f"git -C {repo} log -1 --oneline")
    entry = log_lines(env)[-1]
    assert set(entry) == LOG_KEYS, entry
    assert (entry["verdict"], entry["decision"]) == ("pass", "none") and entry["reason_ids"] == ["free_after_read_profile"]


@pytest.mark.parametrize("command,verdict", [(CHAIN_ASK, "ask"), (INACTIVE_PUSH, "inactive")])
def test_the_log_entry_keeps_its_keys_for_every_answer(shim, repo, plain, tmp_path, command, verdict):
    """Control, green before and after: the log line of each answer carries what it carried."""
    env = with_data(shim, tmp_path)
    run(env, repo if verdict == "ask" else plain, command=command)
    entry = log_lines(env)[-1]
    assert set(entry) == LOG_KEYS and entry["verdict"] == verdict, entry


def test_a_denied_write_keeps_its_log_line(shim, repo, tmp_path):
    env = with_data(shim, tmp_path)
    target = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "rules.json"
    run(env, repo, event={"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(repo),
                          "tool_input": {"file_path": str(target), "content": "[]"}})
    entry = log_lines(env)[-1]
    assert set(entry) == LOG_KEYS and entry["verdict"] == "deny" and entry["reason_ids"] == ["write_to_gate_dir"]


# --- part 7.4: inactive once per session and repository ---------------------------------------------------------------

def test_inactive_shows_once_per_session_and_repository(shim, plain, tmp_path):
    env = with_data(shim, tmp_path)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(plain), "session_id": "s1",
             "tool_input": {"command": INACTIVE_PUSH}}
    _out, first = run(env, plain, event=event)
    assert first is not None and "permissionDecision" not in first["hookSpecificOutput"], first
    assert short(first).startswith("Gate is not active here because the repository declares no evidence (D5)")
    assert "NOT MEASURED" in first["hookSpecificOutput"]["additionalContext"]
    assert run(env, plain, event=event) == ("", None)
    assert run(env, plain, event={**event, "tool_input": {"command": "git push origin HEAD:other"}}) == ("", None)
    assert run(env, plain, event={**event, "session_id": "s2"})[1] is not None
    assert [e["verdict"] for e in log_lines(env)] == ["inactive"] * 4


def test_inactive_without_a_session_or_a_data_directory_shows_every_time(shim, plain, tmp_path):
    env = with_data(shim, tmp_path)
    for _ in range(2):
        assert run(env, plain, command=INACTIVE_PUSH)[1] is not None
    bare = {k: v for k, v in env.items() if k != "CLAUDE_PLUGIN_DATA"}
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(plain), "session_id": "s1",
             "tool_input": {"command": INACTIVE_PUSH}}
    for _ in range(2):
        assert run(bare, plain, event=event)[1] is not None


# --- part 8: one short line ----------------------------------------------------------------------------------------------

def test_an_ask_shows_the_short_line_and_gives_the_model_the_long_reason(shim, repo, tmp_path):
    env = with_data(shim, tmp_path)
    _out, answer = run(env, repo, command=CHAIN_ASK)
    specific = answer["hookSpecificOutput"]
    line = short(answer)
    assert line == "Gate asks at git stash because git may start a program the gate does not see (D3).", line
    assert specific["permissionDecision"] == "ask" and specific["permissionDecisionReason"] == line
    assert specific["additionalContext"].startswith("NOT MEASURED: the step `git stash list` of this command asks")
    assert "Next step: " in specific["additionalContext"]


def test_the_short_line_is_german_where_a_person_set_it(shim, repo, tmp_path):
    env = with_data(shim, tmp_path, language="de")
    _out, answer = run(env, repo, command=CHAIN_ASK)
    line = short(answer)
    german(line)
    assert line == "Tor fragt bei git stash, weil git ein Programm starten kann, das das Tor nicht sieht (D3).", line
    assert answer["hookSpecificOutput"]["additionalContext"].startswith("NOT MEASURED: ")   # the model's text stays


@pytest.mark.parametrize("word", ["fr", "", "de de", "x" * 100])
def test_any_other_language_setting_is_english(shim, repo, tmp_path, word):
    env = with_data(shim, tmp_path, language=word)
    assert short(run(env, repo, command=CHAIN_ASK)[1]).startswith("Gate asks at ")


@pytest.mark.parametrize("language", ["en", "de"])
def test_a_deny_shows_the_short_line_and_gives_the_model_the_long_reason(shim, repo, tmp_path, language):
    env = with_data(shim, tmp_path, language=language)
    target = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "rules.json"
    _out, answer = run(env, repo, event={"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(repo),
                                         "tool_input": {"file_path": str(target), "content": "[]"}})
    specific = answer["hookSpecificOutput"]
    line = short(answer)
    assert specific["permissionDecision"] == "deny"
    assert specific["permissionDecisionReason"] == specific["additionalContext"] != line
    assert str(target) not in line and str(tmp_path) not in line, line
    if language == "de":
        german(line)
        assert line == "Tor sperrt Write, weil das Schreiben das Verzeichnis des Tors trifft (D25).", line
    else:
        assert line == "Gate blocks Write because the write targets the gate's own directory (D25).", line


@pytest.mark.parametrize("language", ["en", "de"])
def test_under_codex_an_ask_is_a_deny_with_the_short_line_and_the_codex_sentence(shim, repo, tmp_path, language):
    env = with_data(shim, tmp_path, language=language)
    env["PLUGIN_DATA"] = env["CLAUDE_PLUGIN_DATA"]
    _out, answer = run(env, repo, command=CHAIN_ASK, host="codex")
    specific = answer["hookSpecificOutput"]
    line = short(answer)
    assert specific["permissionDecision"] == "deny" and specific["permissionDecisionReason"] == line
    assert specific["additionalContext"].endswith("Codex cannot ask, so the gate denies the call.")
    if language == "de":
        german(line)
        assert line.startswith("Tor sperrt ") and line.endswith("Codex kann nicht fragen, darum sperrt das Tor den "
                                                                 "Aufruf."), line
    else:
        assert line.startswith("Gate blocks ") and line.endswith("Codex cannot ask, so the gate blocks the call."), line


@pytest.mark.parametrize("language", ["en", "de"])
def test_under_codex_a_plain_push_warns_with_the_short_line(shim, repo, tmp_path, language):
    env = with_data(shim, tmp_path, language=language)
    env["PLUGIN_DATA"] = env["CLAUDE_PLUGIN_DATA"]
    _out, answer = run(env, repo, command="git push origin main", host="codex")
    specific = answer["hookSpecificOutput"]
    line = short(answer)
    assert "permissionDecision" not in specific
    assert specific["additionalContext"].endswith(gate.CODEX_PUSH_WARNING)
    assert line == ("Tor warnt bei git push, weil der Codex-Haken das Arbeitsverzeichnis nicht mitgibt (D12)."
                    if language == "de" else
                    "Gate warns at git push because the Codex hook does not carry the working directory (D12)."), line


@pytest.mark.parametrize("language", ["en", "de"])
def test_a_hand_over_shows_the_short_line(language, tmp_path, monkeypatch):
    gate_dir = tmp_path / "gate-dir"
    gate_dir.mkdir()
    (gate_dir / "language").write_text(language, encoding="utf-8")
    text = "proofbundle gate: handed over to Level 2."
    outcome = gate.Outcome("handover", text, [gate.Verdict("handover", text, "handed_over")])
    answer = gate.pre_tool_answer(outcome, "claude", {}, "git push", environ={"PROOFBUNDLE_GATE_DIR": str(gate_dir)})
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    assert answer["hookSpecificOutput"]["additionalContext"] == text
    assert short(answer) == ("Tor übergibt git push an die Prüfung beim Push (D35)." if language == "de" else
                             "Gate hands git push over to the pre-push check (D35).")


def test_the_step_of_a_longer_command_is_named_without_its_path(shim, repo, tmp_path):
    """D46: the step that asks is named; the line names no path of it."""
    env = with_data(shim, tmp_path)
    command = f"git -C {repo} status --porcelain; git -C {repo} stash list"
    _out, answer = run(env, repo, command=command)
    line = short(answer)
    assert line.startswith("Gate asks at git stash because "), line
    assert str(repo) not in line and str(tmp_path) not in line


# --- the table: every line within its bounds -----------------------------------------------------------------------------

def test_every_reason_id_the_gate_names_has_a_short_reason():
    source = GATE.read_text(encoding="utf-8")
    named = set(re.findall(r'Verdict\(\s*(?:"(?:ask|deny|warn|handover|inactive)"|[^,]+?),\s*(?:f?"[^"]*"\s*)+,\s*'
                           r'"([a-z_]+)"', source))
    named |= set(re.findall(r':\s*"([a-z_]+)"', source.split("_OPEN_REASON = {", 1)[1].split("}", 1)[0]))
    named |= {"order_removed", "order_unreadable", gate.SANDBOX_REASON, "declaration_uncommitted",
              "absence_not_measured", "codex_context_unbound", "mcp_target_unbound", "write_to_repo_state"}
    passes = {"verified", "done", "approved_by_rule", "free_after_checkout_check", "free_after_fetch_profile",
              "free_after_gh_profile", "free_after_read_profile", "free_after_state_check",
              "verified_new_branch",   # D61, Ergänzung 1 to Nachtrag 23
              "free_work_profile"}     # D71, Nachtrag 29
    missing = sorted(named - passes - set(gate._SHORT_REASONS) - {"green_run"})
    assert not missing, missing


@pytest.mark.parametrize("language", ["en", "de"])
def test_every_line_is_short_and_in_the_house_style(language):
    step = "git " + "x" * 60
    for reason_id in gate._SHORT_REASONS:
        for decision in ("ask", "deny", "warn", "handover", "inactive"):
            verdict = gate.Verdict(decision, "detail (DECISIONS.md D3, D34).", reason_id)
            outcome = gate.Outcome(decision, verdict.detail, [verdict])
            for suffix in ("", gate._SHORT_CODEX_DENY[language]):
                line = gate.short_line(decision, outcome, step, language, suffix=suffix)
                assert len(line) <= 160 and "\n" not in line, (reason_id, decision, line)
                assert re.search(r"\(D[0-9]{1,3}[A-Z]?\)\.", line), line
                if language == "de":
                    german(line)


def test_a_reason_of_a_profile_takes_the_decision_its_long_reason_names():
    verdict = gate.Verdict("ask", "NOT MEASURED: the gate gives no free answer for git log: the read profile found "
                                  "x. (class a; DECISIONS.md D3, D34).", "git_form_not_free",
                           evidence="the repository state git log runs with")
    line = gate.short_line("ask", gate.Outcome("ask", verdict.detail, [verdict]), "git log", "en")
    assert line == "Gate asks at git log because a setting may make git start a program (D34).", line


def test_the_language_file_is_read_like_the_mode(tmp_path):
    gate_dir = tmp_path / "g"
    gate_dir.mkdir()
    environ = {"PROOFBUNDLE_GATE_DIR": str(gate_dir)}
    assert gate._read_language(environ) == "en"
    (gate_dir / "language").write_text("DE\n", encoding="utf-8")
    assert gate._read_language(environ) == "de"
    (gate_dir / "language").write_text("de" + " " * 100, encoding="utf-8")
    assert gate._read_language(environ) == "en"
    assert gate._read_language({"PROOFBUNDLE_GATE_DIR": "relative"}) == "en"
    assert plugin_env  # the plugin environment module stays imported for the guard of tests/test_plugin_env_guard.py
    assert os.path.isabs(str(gate_dir))


# --- a call a human rule frees stays visible (F15-2, D25) ---------------------------------------------------------------

@pytest.mark.parametrize("language", ["en", "de"])
def test_a_call_a_rule_frees_shows_the_short_line_with_the_time_of_the_rules(tmp_path, language):
    """Review Runde 15, F15-2: a shell command can switch the mode and the rules unseen, and every call a rule frees
    names them. D53 keeps that call visible as one short line; the model gets the whole text."""
    import test_plugin_gate_n24 as n24
    env, gate_dir = n24._gate_env(tmp_path, tmp_path / "logs")
    (gate_dir / "language").write_text(language, encoding="utf-8")
    repo = n24._repo(tmp_path)
    n24._set_mode(gate_dir, "with-approvals")
    n24._set_rules(gate_dir, [{"repo": n24._common(repo), "form": "git stash list", "effect": "free",
                               "state_digest": n24._digest(repo, env)}])
    _out, answer = run(env, repo, command="git stash list")
    specific = answer["hookSpecificOutput"]
    line = short(answer)
    assert "permissionDecision" not in specific and "permissionDecisionReason" not in specific, answer
    assert re.fullmatch((r"Tor gibt git stash nach einer Regel frei, die ein Mensch schrieb, Modus und Regeln Stand "
                         if language == "de" else r"Gate frees git stash by a rule a person wrote, mode and rules as of ")
                        + r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z \(D25\)\.", line), line
    assert "a rule frees this form in with-approvals mode" in specific["additionalContext"]
    assert "Mode and rules: " in specific["additionalContext"]
    entry = json.loads((tmp_path / "logs" / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    assert entry["verdict"] == "pass" and "approved_by_rule" in entry["reason_ids"] and "applied_rule" in entry
