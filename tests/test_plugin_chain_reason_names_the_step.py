"""D46, Ergänzung 1 to Nachtrag 19, part A: the reason of a longer command names the step that asks.

Measured by Cowork at 1db350a1 in delta's environment (AI_AGENT claude-code_2-1-301_harness, GIT_OPTIONAL_LOCKS=0,
PAGER=less, LESS=-R, GIT_EDITOR=true), a clone under an absolute path with origin on a local repository, delta's chain
of 09:53Z: every step alone was free but the fetch (ask, remote_read_not_modeled), the chain without the fetch was free,
and the whole chain asked with a reason that named status, rev-parse and log, each with "Evidence: none, the gate reads
no repository state for a git form", and not the fetch's reason. Reproduced here at 1db350a1 (probe_delta_chain_e1.py):
the fetch, a gated step that is not the first, made class c keep the answer of the whole command, and that answer gives
every git step of a longer command the not-free answer of D3.

Now, under Claude Code: where a step has the decision on its own, the reason names that step first with its reason ids
and text, then in one sentence which git and gh steps would be free on their own; where the reason belongs to no single
step (a form the parser does not model, a state change before a step), the reason says so. The decision and the verdicts
stay as they were; under Codex the texts stay those of D37.

RED at 1db350a1 by the text of each case; the decision and the Codex text are controls, green at both heads.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

import _worktree_layout as w
import test_plugin_gate_n2c_push_done as n2c
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
gate = n2c.gate
#: delta's environment of 09:53Z as Cowork measured it.
DELTA = {"AI_AGENT": "claude-code_2-1-301_harness", "GIT_OPTIONAL_LOCKS": "0", "PAGER": "less", "LESS": "-R",
         "GIT_EDITOR": "true", "CLAUDECODE": "1"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)
    for name, value in DELTA.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def clone(tmp_path):
    """A clone under an absolute path with origin on a local repository, as in Cowork's measurement."""
    origin = tmp_path / "origin"
    subprocess.run(["git", "init", "-q", "-b", "main", str(origin)], check=True, timeout=60, env=plugin_env())
    for key, value in (("user.name", "t"), ("user.email", "t@example.org"), ("commit.gpgsign", "false")):
        w.git(origin, "config", key, value)
    (origin / "a.txt").write_text("one\n")
    w.git(origin, "add", "a.txt")
    w.git(origin, "commit", "-q", "-m", "one\n\nbody 1\nbody 2\nbody 3")
    repo = tmp_path / "home" / "konrad" / "2bedone"
    repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "-q", str(origin), str(repo)], check=True, timeout=60, env=plugin_env())
    return repo


def _chain(repo) -> str:
    sha = w.git(repo, "rev-parse", "HEAD").strip()
    a = repo
    return (f"git -C {a} status --porcelain --branch; git -C {a} rev-parse HEAD; git -C {a} log -1 --format=%B {sha} | "
            f"tail -3; git -C {a} fetch -q origin main; git -C {a} rev-parse origin/main; git -C {a} merge-base "
            f'--is-ancestor {sha} HEAD; echo "basis_ist_vorfahr=$?"; ls {a}/.git/hooks/ | grep -v sample')


def _hook(cwd, command: str, host: str = "claude") -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", w.G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(**DELTA), timeout=180, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), out.get("permissionDecisionReason") or ""


def _decide(repo, command: str, host: str = "claude"):
    return gate.decide(command, str(repo), time.monotonic() + 180, host)


def test_E1A_deltas_chain_names_the_fetch_first_and_no_finding_for_the_reads(tmp_path, clone):
    code, decision, reason = _hook(tmp_path, _chain(clone))
    assert (code, decision) == (0, "ask"), reason
    assert reason.startswith(f"NOT MEASURED: the step `git -C {clone} fetch -q origin main` of this command asks "
                             "on its own "
                             "(remote_read_not_modeled):"), reason
    assert "the fetch profile found the URL of the remote origin is not https://github.com/<owner>/<repo>" in reason
    for name in ("git status", "git rev-parse", "git log", "git merge-base"):
        assert f"{name} may start a program" not in reason, (name, reason)
        assert f"the gate gives no free answer for {name}." not in reason, (name, reason)
    assert "Evidence: none, the gate reads no repository state for a git form" not in reason, reason
    free = reason.split("On their own, these git and gh steps of the command would be free: ", 1)[1]
    for step in ("status --porcelain --branch", "rev-parse HEAD", "log -1 --format=%B", "rev-parse origin/main",
                 "merge-base --is-ancestor"):
        assert f"git -C {clone} {step}" in free, (step, free)
    assert "fetch" not in free.split(".", 1)[0], free


def test_E1A_two_asking_steps_name_the_gated_one_and_then_the_other(tmp_path, clone):
    """The second fetch asks on its own and is a gated step that is not the first, which is why class c keeps the
    answer of the whole command: it is named first, the first fetch after it as a step that asks on its own too."""
    w.git(clone, "remote", "add", "other", str(tmp_path / "origin"))
    command = f"git -C {clone} fetch -q origin main; git -C {clone} fetch -q other main; git -C {clone} log -1"
    out = _decide(clone, command)
    assert out.decision == "ask", out.text
    assert out.text.startswith(f"NOT MEASURED: the step `git -C {clone} fetch -q other main` of this command asks on "
                               "its own (remote_read_not_modeled):"), out.text
    assert f"These steps ask on their own too: `git -C {clone} fetch -q origin main`." in out.text, out.text
    assert f"would be free: `git -C {clone} log -1`." in out.text, out.text


def test_E1A_two_asking_steps_judged_step_by_step_name_the_first_and_then_the_other(tmp_path, clone):
    command = f"git -C {clone} config core.pager less; git -C {clone} stash list; git -C {clone} log -1"
    out = _decide(clone, command)
    assert out.decision == "ask", out.text
    assert out.text.startswith(f"NOT MEASURED: the step `git -C {clone} config core.pager less` of this command asks "
                               "on its own (git_form_not_free):"), out.text
    assert f"These steps ask on their own too: `git -C {clone} stash list`." in out.text, out.text
    assert f"would be free: `git -C {clone} log -1`." in out.text, out.text


def test_E1A_a_form_the_parser_does_not_model_says_so(tmp_path, clone):
    out = _decide(clone, f"git -C {clone} status & git -C {clone} log -1")
    assert out.decision == "ask", out.text
    assert out.text.startswith("NOT MEASURED: the gate does not judge this command step by step: not modelled: a "
                               "background job. It keeps the answer of the whole command, in which no git step of a "
                               "longer command is free (D3); the reason belongs to the command, not to one step"), \
        out.text
    assert "Evidence: " in out.text and "Next step: " in out.text, out.text


def test_E1A_a_state_change_before_a_step_says_no_step_asks_on_its_own(tmp_path, clone):
    w.git(clone, "remote", "set-url", "origin", "https://github.com/o/r")
    out = _decide(clone, f"echo x > {clone}/.gitmodules; git -C {clone} fetch -q origin main")
    assert out.decision == "ask" and [v.reason_id for v in out.verdicts] == ["step_after_state_change"], out.text
    assert out.text.startswith("NOT MEASURED: no git or gh step of this command asks on its own; the reason belongs "
                               "to the command, not to one step."), out.text
    assert "would be free on its own, but a step before it or beside it (echo)" in out.text, out.text


def test_E1A_a_push_that_is_not_the_first_step_is_named_as_such(tmp_path, clone):
    out = _decide(clone, f"git -C {clone} status; git -C {clone} push origin main")
    assert out.decision == "ask", out.text
    assert out.text.startswith(f"NOT MEASURED: the step `git -C {clone} push origin main` of this command is a push or "
                               "another gated call, which the gate judges only as the first step of a command on its "
                               "own."), out.text
    assert "It is a gated step that is not the first step" in out.text, out.text
    assert "Next step: run the push as" in out.text, out.text                    # the safe push form (D32) stays
    assert "git status may start a program" not in out.text, out.text
    assert f"would be free: `git -C {clone} status`." in out.text, out.text


@pytest.mark.parametrize("command", ["git -C {a} status & git -C {a} log -1",
                                     "git -C {a} status; git -C {a} push origin main",
                                     "git -C {a} status; git -C {a} ls-remote origin"])
def test_E1A_a_kept_command_keeps_the_decision_and_verdicts_of_the_whole_command_and_says_why(tmp_path, clone, command):
    """Where class c keeps the answer of the whole command, only the text changes (D46)."""
    command = command.format(a=clone)
    out = _decide(clone, command)
    whole = gate._decide_outcome_whole(command, str(clone), time.monotonic() + 180, "claude", gate.os.environ)
    assert (out.decision, [v.reason_id for v in out.verdicts]) == \
        (whole.decision, [v.reason_id for v in whole.verdicts]), out.text
    assert out.text != whole.text


@pytest.mark.parametrize("command", ["git -C {a} fetch -q origin main; git -C {a} log -1 | tail -1",
                                     "git -C {a} config core.pager less; git -C {a} log -1",
                                     "echo x > {a}/.git/config; git -C {a} log -1"])
def test_E1A_control_a_command_judged_step_by_step_says_every_finding(tmp_path, clone, command):
    """The text is built from the verdicts of the decision: each of them appears in it (D46)."""
    out = _decide(clone, command.format(a=clone))
    assert out.decision == "ask", out.text
    for v in out.verdicts:
        if v.decision == out.decision:
            assert v.text() in out.text, (v.reason_id, out.text)


def test_E1A_control_under_codex_the_texts_stay(tmp_path, clone):
    out = _decide(clone, _chain(clone), host="codex")
    assert not out.text.startswith(("NOT MEASURED: no git or gh step", "NOT MEASURED: the step",
                                    "NOT MEASURED: the gate does not judge")), out.text
    assert out.text == " ".join(v.text() for v in out.verdicts if v.decision == out.decision), out.text


def test_E1A_control_a_single_command_keeps_its_text(tmp_path, clone):
    out = _decide(clone, f"git -C {clone} fetch -q origin main")
    assert out.text == " ".join(v.text() for v in out.verdicts if v.decision == out.decision), out.text


def test_E1A_a_step_whose_directory_is_unknown_after_cd_is_named_as_such(tmp_path, clone):
    out = _decide(clone, f"cd {clone} && git -C {clone} log -1 && git status")
    assert out.decision == "ask", out.text
    assert out.text.startswith(f"NOT MEASURED: the gate cannot judge the step `git -C {clone} log -1` of this command "
                               "on its own"), out.text
    assert "its directory is unknown after a directory change" in out.text, out.text


def test_E1A_a_gated_gh_call_that_is_not_the_first_step_keeps_its_own_text(tmp_path, clone):
    out = _decide(clone, f"git -C {clone} status; gh pr create --fill")
    assert out.decision == "ask", out.text
    assert out.text.startswith("NOT MEASURED: the step `gh pr create --fill` of this command is a push or another "
                               "gated call"), out.text
    assert "which repository gh pr create acts on" in out.text and "Next step: " in out.text, out.text
    assert "git status may start a program" not in out.text, out.text


def test_E1A_a_worktree_add_that_is_not_the_first_step_keeps_its_own_text(tmp_path, clone):
    """A sibling of the gh case: the whole command's answer names every worktree add the checkout check does not free
    `git worktree add`, two words after git (_strict_git), and the reason finds its texts by that name."""
    target = tmp_path / "wt_new"
    out = _decide(clone, f"git -C {clone} status; git -C {clone} worktree add -q {target} main")
    assert out.decision == "ask", out.text
    assert out.text.startswith(f"NOT MEASURED: the step `git -C {clone} worktree add -q {target} main` of this command "
                               "would be free on its own."), out.text
    assert "which repository git worktree add acts on" in out.text and "Next step: " in out.text, out.text
    assert "git status may start a program" not in out.text, out.text
    assert f"would be free: `git -C {clone} status`." in out.text, out.text
