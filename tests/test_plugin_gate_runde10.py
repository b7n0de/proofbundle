"""Review Runde 10 (stand 494bb373): one regression test per finding, each exactly the review's case.

R10-1: a valid git command followed by a shell comment that holds an apostrophe got no answer on either host; the
gate now drops the comment and answers the command as its control without the comment. Red against 494bb373, green
after.
"""
from __future__ import annotations

import json
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


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                          check=True, capture_output=True, text=True, timeout=60)


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
    return repo


def _hook(repo: pathlib.Path, logs: pathlib.Path, host: str, command: str) -> tuple[str | None, list[str], dict]:
    """Run the gate as the host runs it, on the JSON event of a Bash call: the permission decision of its JSON
    answer (None for no answer), the reason ids of its log line, and the answer itself."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs)}
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer.get("hookSpecificOutput", {}).get("permissionDecision"), entry["reason_ids"], answer


# --- R10-1: a shell comment after a valid git command --------------------------------------------------------------

_R10_1 = [("git config proofbundle.parserMarker comment # don't bypass", "git config proofbundle.parserMarker comment"),
          ("git status --short # don't bypass", "git status --short")]


@pytest.mark.skipif(shutil.which("git") is None or shutil.which("bash") is None, reason="needs git and bash")
@pytest.mark.parametrize("commented, control", _R10_1, ids=["git-config", "git-status"])
def test_r10_1_a_git_command_with_a_shell_comment_is_answered_as_its_control(tmp_path, commented, control):
    """R10-1, the review's case over the real JSON answers of both host paths: the command with the comment is valid
    bash and does what its control does (the config case sets the value), and the gate gives it the control's
    answer, ask under Claude Code and deny under Codex, with the control's reason. At 494bb373 the commented command
    got no answer and the log said not_gated."""
    repo = _repo(tmp_path)
    ran = subprocess.run(["bash", "-c", commented], cwd=repo, capture_output=True, text=True, timeout=60, check=False)
    assert ran.returncode == 0, ran.stderr
    if "config" in commented:
        assert _git(repo, "config", "--get", "proofbundle.parserMarker").stdout.strip() == "comment"
    for host, expected in (("claude", "ask"), ("codex", "deny")):
        logs = tmp_path / f"logs-{host}"
        got, got_ids, got_answer = _hook(repo, logs, host, commented)
        want, want_ids, _ = _hook(repo, logs, host, control)
        assert want == expected, (host, control, want)
        assert (got, got_ids) == (want, want_ids), (host, commented, got_answer)
        assert "not_gated" not in got_ids
