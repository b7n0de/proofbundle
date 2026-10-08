"""Owner choice K5-1 C (2026-10-08): under Codex only the plain `git push` warns; every other push form is denied.

Karte 5 A let every `git push` under Codex warn, because git's pre-push hook (Level 2) checks the push in its own
repository. Measured on 2026-10-08: a prefix assignment can switch that hook off
(`GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git push`), and a chain, a wrapper,
a global option or another git program may push from somewhere else or step around the hook too. The plain form is
one command headed by a bare `git`, `push` right after it, no prefix assignment of any kind, no chain, no expansion.
It keeps the Karte 5 A warning; any other form gets `codex_push_not_plain` and is denied. Claude Code is unchanged.
Red against 31031eb6, where every one of these forms warned.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

#: Each form that is not the plain push, by the way it differs.
NOT_PLAIN = {
    "prefix assignment, hooks off": "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null "
                                    "git push origin main",
    "prefix assignment, neutral": "LANG=C git push origin main",
    "prefix assignment, git dir": "GIT_DIR=/elsewhere/.git git push origin main",
    "prefix assignment, path": "PATH=/tmp/bin:$PATH git push origin main",
    "chain and": "cd /elsewhere && git push origin main",
    "chain semicolon": "git status; git push origin main",
    "chain or": "false || git push origin main",
    "chain newline": "true\ngit push origin main",
    "pipeline": "git push origin main | cat",
    "background": "git push origin main &",
    "subshell": "(git push origin main)",
    "group": "{ git push origin main; }",
    "wrapper env": "env git push origin main",
    "wrapper env assignment": "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null "
                              "git push origin main",
    "wrapper command": "command git push origin main",
    "wrapper exec": "exec git push origin main",
    "wrapper nice": "nice git push origin main",
    "wrapper time": "time git push origin main",
    "wrapper bash -c": "bash -c 'git push origin main'",
    "wrapper sh -c": "sh -c 'git push origin main'",
    "wrapper eval": "eval 'git push origin main'",
    "global option -c": "git -c push.default=current push origin main",
    "global option -C": "git -C . push origin main",
    "global option --git-dir": "git --git-dir=.git push origin main",
    "global option --exec-path": "git --exec-path=/tmp push origin main",
    "other git path absolute": "/usr/bin/git push origin main",
    "other git path relative": "./git push origin main",
    "other git program": "git-push origin main",
    "quoted command word": "'git' push origin main",
    "expansion": "git push origin $(echo main)",
    "parameter expansion": "git push origin $BRANCH",
}
PLAIN = ["git push", "git push origin main", "git push -u origin main", "git push origin HEAD:main",
         "git push origin main 2>&1", "git push --force-with-lease origin main", "git push -n origin main"]


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, timeout=60)
    path = tmp_path / "r"
    path.mkdir()
    for args in (("init", "-q", "-b", "main"), ("config", "user.name", "t"), ("config", "user.email", "t@example.org"),
                 ("remote", "add", "origin", str(bare))):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, timeout=60)
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    for args in (("add", "a.txt"), ("commit", "-q", "-m", "base"), ("push", "-q", "-u", "origin", "main")):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, timeout=60)
    return path


def _deadline() -> float:
    return gate.time.monotonic() + 30


@pytest.mark.parametrize("command", NOT_PLAIN.values(), ids=NOT_PLAIN.keys())
def test_under_codex_a_push_form_that_is_not_plain_is_denied(repo, command):
    outcome = gate.decide(command, str(repo), _deadline(), host="codex")
    assert outcome is not None and outcome.decision in ("ask", "deny"), (command, outcome and outcome.decision)
    answer = gate.answer(outcome.decision, outcome.text, host="codex")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", command
    assert "warn" not in {v.decision for v in outcome.verdicts}, outcome.verdicts
    assert "warns about a git push" not in answer["systemMessage"]


@pytest.mark.parametrize("command", [c for c in NOT_PLAIN.values() if "git push" in c and "'" not in c
                                     and "git-push" not in c and "|" not in c])
def test_the_denial_names_the_plain_form_where_the_push_is_seen(repo, command):
    outcome = gate.decide(command, str(repo), _deadline(), host="codex")
    reasons = {v.reason_id for v in outcome.verdicts}
    assert reasons & {"codex_push_not_plain", "hooks_disabled", "net_unmodeled_git", "git_form_not_free"}, reasons


@pytest.mark.parametrize("command", PLAIN)
def test_under_codex_the_plain_push_still_warns(repo, command):
    outcome = gate.decide(command, str(repo), _deadline(), host="codex")
    assert outcome is not None and outcome.decision == "warn", (command, outcome and outcome.decision)
    assert {v.reason_id for v in outcome.verdicts} == {"codex_context_unbound"}
    answer = gate.answer(outcome.decision, outcome.text, host="codex")
    assert "permissionDecision" not in answer["hookSpecificOutput"]


@pytest.mark.parametrize("command", [*NOT_PLAIN.values(), *PLAIN])
def test_claude_code_is_unchanged_by_the_plain_form(repo, command):
    outcome = gate.decide(command, str(repo), _deadline(), host="claude")
    assert outcome is None or "codex_push_not_plain" not in {v.reason_id for v in outcome.verdicts}
    assert outcome is None or outcome.decision != "warn"


def test_the_plain_form_predicate_reads_the_whole_command():
    assert gate._codex_plain_push("git push origin main")
    assert gate._codex_plain_push("git push origin main # a comment")
    for command in ("git push origin main && true", "LANG=C git push", "git -C . push", "\\git push",
                    "git 'push' origin main", "git status", "", "git"):
        assert not gate._codex_plain_push(command), command
