"""Owner choice Karte 5 A with D (2026-10-08): under Codex a git push warns with the reason it was denied with.

Under `--host codex` the hook is not told the directory a command runs in (R5-2), so every `git push` stays NOT
MEASURED with the same reason as before. The answer changes: it carries no permission decision, only the reason and
a warning sentence, because the boundary is the done check at the end of the session and the required CI check, and
git's pre-push hook (Level 2, D24) checks the push in its own repository where it is installed (DECISIONS.md D12).
Claude Code is unchanged. A gh call starts no pre-push hook and stays denied, and so does every form that turns the
push check off or that the gate does not resolve as a push. Red against 395f0a87, where the push was denied.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest
from _gate_answer import Silent
from _plugin_env import plugin_env

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

#: The keys Codex accepts in a PreToolUse answer (codex-rs/hooks, as test_codex_plugin.py reads them).
CODEX_TOP = {"systemMessage", "hookSpecificOutput"}
CODEX_SPECIFIC_WARN = {"hookEventName", "additionalContext"}
#: The R5-2 reason as 395f0a87 wrote it for a push, field by field: the warning keeps every one.
R5_2_DETAIL = ("NOT MEASURED: under Codex the gate cannot bind git push to the directory and environment it runs in. "
               "The hook receives the session directory and the command text, not the execution workdir or a remote "
               "environment, so it could judge a different repository than the push acts on.")
R5_2_EVIDENCE = "the repository and target git push acts on"
R5_2_FAILED = "the Codex hook does not carry the command's working directory (workdir) or a remote environment"
R5_2_NEXT = ("run the push under a host that binds the execution directory to the gate, or have a person review the "
             "push")
#: A phrase of the warning sentence. The controls below look for it rather than for the constant, so they read the
#: same at 395f0a87, where the constant does not exist and those controls are green.
WARN_PHRASE = "warns about a git push"


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository whose main tracks origin/main, with nothing new to send."""
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, timeout=60)
    repo = tmp_path / "r"
    repo.mkdir()
    for args in (("init", "-q", "-b", "main"), ("config", "user.name", "t"), ("config", "user.email", "t@example.org"),
                 ("remote", "add", "origin", str(bare))):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, timeout=60)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    for args in (("add", "a.txt"), ("commit", "-q", "-m", "base"), ("push", "-q", "-u", "origin", "main")):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, timeout=60)
    return repo


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _hook(repo: pathlib.Path, logs: pathlib.Path, host: str, command: str) -> tuple[dict, dict]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = plugin_env(CLAUDE_PLUGIN_DATA=str(logs), PLUGIN_DATA=str(logs))
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return (json.loads(proc.stdout) if proc.stdout.strip() else Silent(entry)), entry   # D53: a pass prints nothing


@pytest.mark.parametrize("command", ["git push", "git push origin main", "git push -u origin main"])
def test_a_codex_push_keeps_its_reason_and_warns(tmp_path, command):
    repo = _repo(tmp_path)
    outcome = gate.decide(command, str(repo), _deadline(), host="codex")
    assert outcome is not None and outcome.decision == "warn", (command, outcome and outcome.decision)
    (verdict,) = outcome.verdicts
    assert (verdict.reason_id, verdict.detail, verdict.evidence, verdict.failed, verdict.next_step) == (
        "codex_context_unbound", R5_2_DETAIL, R5_2_EVIDENCE, R5_2_FAILED, R5_2_NEXT)
    answer = gate.answer(outcome.decision, outcome.text, host="codex")
    assert set(answer) == CODEX_TOP and set(answer["hookSpecificOutput"]) == CODEX_SPECIFIC_WARN, answer
    assert answer["systemMessage"] == f"{outcome.text} {gate.CODEX_PUSH_WARNING}"
    assert answer["hookSpecificOutput"]["additionalContext"] == answer["systemMessage"]
    assert "Codex cannot ask" not in answer["systemMessage"]


def test_the_warning_names_the_boundary_and_the_level_2_hook():
    for part in (WARN_PHRASE, "and does not deny it", "Karte 5 A", "DECISIONS.md D12",
                 "done check at the end of the session", "required CI check", "pre-push hook (Level 2, D24)",
                 "only where it is installed"):
        assert part in gate.CODEX_PUSH_WARNING, part


def test_the_hook_logs_a_warning_with_no_decision_sent(tmp_path):
    repo = _repo(tmp_path)
    answer, entry = _hook(repo, tmp_path / "logs", "codex", "git push origin main")
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    assert (entry["host"], entry["decision"], entry["verdict"], entry["reason_ids"]) == (
        "codex", "none", "warn", ["codex_context_unbound"])


@pytest.mark.parametrize("command, reason", [
    ("gh pr create --fill", "codex_context_unbound"),           # gh starts no pre-push hook
    ("gh release create v1", "codex_context_unbound"),
    ("git push --no-verify origin main", "hooks_disabled"),     # turns Level 2 off, denied under both hosts
    ("git -c core.hooksPath=/dev/null push origin main", "hooks_disabled"),
    ("git send-pack origin main", "possible_unmodeled_push"),   # git send-pack starts no pre-push hook either
    ("git -c alias.p=push p origin main", "possible_unmodeled_push"),
    ("git push origin main && git status", "git_form_not_free"),
])
def test_what_the_pre_push_hook_does_not_carry_stays_denied_under_codex(tmp_path, command, reason):
    repo = _repo(tmp_path)
    outcome = gate.decide(command, str(repo), _deadline(), host="codex")
    assert outcome is not None and outcome.decision in ("deny", "ask"), (command, outcome and outcome.decision)
    assert reason in {v.reason_id for v in outcome.verdicts if v.decision == outcome.decision}, outcome.verdicts
    answer = gate.answer(outcome.decision, outcome.text, host="codex")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", command
    assert WARN_PHRASE not in answer["systemMessage"]


def test_a_gated_mcp_publish_stays_denied_under_codex(tmp_path):
    outcome = gate.decide_mcp("mcp__github__create_pull_request", str(_repo(tmp_path)), _deadline(), host="codex")
    assert outcome is not None and outcome.decision == "deny"


def test_two_chained_pushes_are_not_the_plain_form_and_a_deny_beside_a_push_wins(tmp_path):
    repo = _repo(tmp_path)
    both = gate.decide("git push origin main && git push origin HEAD:main", str(repo), _deadline(), host="codex")
    assert both is not None and "warn" not in {v.decision for v in both.verdicts}, both.verdicts
    assert "codex_push_not_plain" in {v.reason_id for v in both.verdicts}
    assert gate.answer(both.decision, both.text, host="codex")["hookSpecificOutput"]["permissionDecision"] == "deny"
    mixed = gate.decide("git push origin main; gh pr create --fill", str(repo), _deadline(), host="codex")
    assert mixed is not None and gate.answer(mixed.decision, mixed.text, host="codex")[
        "hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("command", ["git push", "git push origin main", "cd $SOMEWHERE && git push",
                                     "git push --no-verify origin main", "gh pr create --fill"])
def test_claude_code_never_warns(tmp_path, command):
    outcome = gate.decide(command, str(_repo(tmp_path)), _deadline(), host="claude")
    assert outcome is not None and outcome.decision != "warn" and "warn" not in {v.decision for v in outcome.verdicts}
    assert WARN_PHRASE not in gate.answer(outcome.decision, outcome.text, host="claude")["systemMessage"]
