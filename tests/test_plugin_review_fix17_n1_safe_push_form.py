"""Follow-up note 1 to review fix 17 (owner choice A of 2026-10-13, 23:3x Berlin, D32): the answer leads the agent to the push form
Level 1 resolves, `git -C <absolute path> push <remote> <refspec>`, and the resolution stays as it is.

Measured in the self-use of 2026-10-13 (head 101bd167): Claude Code writes a push as `cd <repo> && git push <remote>
<refspec>`, Level 1 answers ask with directory_unresolved, and the next step said "run the call in the repository's
directory", which leads straight back to `cd`. Now the next step of directory_unresolved for a push, of
possible_unmodeled_push and of mcp_target_unbound names the safe form with an example and says that the gate checks
it; the verdicts stay as they were. Under Codex the hint names the plain `git push …` (D12), since `-C` is denied
there. The counter-check: `git -C <absolute path> push origin HEAD:refs/heads/x` from a foreign working directory is
resolved as before, a valid done check passes its check and a missing one is denied. Run with git 2.43.0.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c
from _gate_answer import long_text

gate = n2c.gate
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
FORM = "`git -C <absolute path> push <remote> <refspec>`"
EXAMPLE = "`git -C /home/me/repo push origin HEAD:refs/heads/topic`"


def _hook(env: dict, cwd, command: str, host: str = "claude") -> tuple[dict, dict, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", str(n2c.GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    entry = json.loads((n2c.pathlib.Path(env["PLUGIN_DATA"]) / gate.LOG_NAME).read_text(encoding="utf-8")
                       .splitlines()[-1])
    answer = json.loads(proc.stdout) if proc.stdout.strip() else None   # D53: a pass prints nothing
    return answer, entry, (long_text(answer) if answer else "")


@pytest.fixture
def repo(tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    return r.path, elsewhere


@pytest.mark.parametrize("shape", ["cd {R} && git push origin HEAD:refs/heads/x", "cd {R}; git push origin HEAD:refs/heads/x",
                                   "(cd {R} && git push origin HEAD:refs/heads/x)",
                                   "pushd {R} && git push origin HEAD:refs/heads/x"],
                         ids=["cd and", "cd semicolon", "subshell", "pushd"])
def test_a_push_after_a_directory_change_is_asked_and_named_the_safe_form(env, repo, shape):
    path, elsewhere = repo
    answer, entry, text = _hook(env, elsewhere, shape.format(R=path))
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert entry["reason_ids"] == ["directory_unresolved"], entry
    assert FORM in text and EXAMPLE in text, text
    assert "checks the commits the push sends" in text and "a `cd`, a `pushd` or any chain" in text, text


def test_a_possible_unmodeled_push_names_the_safe_form(env, repo):
    path, _elsewhere = repo
    answer, entry, text = _hook(env, path, "git send-pack origin main")
    assert (answer["hookSpecificOutput"].get("permissionDecision"), entry["reason_ids"]) == \
        ("ask", ["possible_unmodeled_push"]), entry
    assert FORM in text and EXAMPLE in text, text


def test_a_gated_mcp_write_names_the_safe_form(repo):
    path, _elsewhere = repo
    outcome = gate.decide_mcp("mcp__github__push_files", str(path), time.monotonic() + 120, host="claude")
    assert outcome.decision == "ask" and FORM in outcome.text, outcome.text


@pytest.mark.parametrize("call", ["send-pack", "mcp"])
def test_under_codex_the_hint_names_the_plain_form(env, repo, call):
    path, _elsewhere = repo
    if call == "mcp":
        text = gate.decide_mcp("mcp__github__push_files", str(path), time.monotonic() + 120, host="codex").text
    else:
        text = _hook(env, path, "git send-pack origin main", host="codex")[2]
    assert "the plain `git push <remote> <refspec>` on its own, in the session's directory" in text, text
    assert FORM not in text, text


def test_another_gated_call_after_a_directory_change_is_named_literal_words(env, repo):
    path, elsewhere = repo
    answer, entry, text = _hook(env, elsewhere, f"cd {path} && gh pr create --fill")
    assert entry["reason_ids"] == ["directory_unresolved", "house_pr_limit"], entry    # H3 of D73
    assert "one command of its own with literal words" in text and "a `cd`, a `pushd` or any chain" in text, text


# --- the counter-check: the safe form is resolved as before ----------------------------------------------------

@pytest.mark.parametrize("refspec", ["HEAD:refs/heads/x", "main"])
@pytest.mark.parametrize("case", ["valid", "missing"])
def test_control_the_safe_form_from_a_foreign_directory_is_resolved_as_before(env, tmp_path, case, refspec):
    """The evidence at the commit the push sends is checked: valid passes its check (the destination stays NOT
    MEASURED, R9-1; refs/heads/x is a branch the remote does not have yet), a missing done check is denied."""
    r = n2c.Repo(tmp_path)
    r.make(case)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    answer, entry, text = _hook(env, elsewhere, f"git -C {r.path} push origin {refspec}")
    if case == "valid":
        assert (answer["hookSpecificOutput"].get("permissionDecision"), entry["reason_ids"]) == \
            ("ask", ["push_not_measured"]), entry
        assert f"the sent source commit(s) {n2c._rev(r.path, 'HEAD')[:12]} showed no failure" in text, text
        if refspec == "main":
            n2c.assert_destination_not_measured(answer, entry)
    else:
        assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
        assert entry["reason_ids"] == [n2c.REASONS["missing"]], entry
