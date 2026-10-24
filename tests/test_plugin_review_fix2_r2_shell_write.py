"""Review round 2 of 2026-10-09, R2-2: a form the gate accepts positively writes no file through the shell.

Measured by the reviewer at 87dcbed8: `git push origin main > .git/hooks/pre-pus?` and the literal control
`> .git/hooks/pre-push` were the plain push under Codex (warn, codex_context_unbound), in bash and in zsh, and the
17-byte dummy hook was 0 bytes before git started: the shell opens the redirection target first, so the push ran with
an empty pre-push hook. The lexer dropped the redirection, and the plain push took a dropped target as harmless;
FILE_WRITE_TOOLS and decide_write do not see a write through the shell. Forbidding glob characters alone does not
close it, the literal target writes as well.

The class: every positive answer the gate gives a shell command — the push it resolves under Claude Code, the plain
push under Codex, a human rule (N24) — now requires that no redirection writes a file. Kept are the redirections that
open no file: a duplication or a close of a descriptor (`2>&1`, `>&2`, `2>&-`) and `/dev/null` written exactly so.
Any other redirection leaves the push NOT MEASURED under Claude Code (ask), not plain under Codex (deny), and no rule
candidate. Red against 87dcbed8.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

import test_plugin_review_fix_f2_globs as f2

gate = f2.gate
pytestmark = f2.pytestmark
repo = f2.repo
_clean_git_environment = f2._clean_git_environment

HOOK = b"#!/bin/sh\nexit 1\n# 17 b"[:17]

WRITES = {
    "glob into the hook": "git push origin main > .git/hooks/pre-pus?",
    "literal hook": "git push origin main > .git/hooks/pre-push",
    "append": "git push origin main >> .git/hooks/pre-push",
    "clobber": "git push origin main >| .git/hooks/pre-push",
    "both streams": "git push origin main &> .git/hooks/pre-push",
    "stderr into a file": "git push origin main 2> out.txt",
    "before the remote": "git push > out.txt origin main",
    "read and write": "git push origin main <> out.txt",
}
NEUTRAL = ["git push origin main 2>&1", "git push origin main >&2", "git push origin main 2>&-",
           "git push origin main > /dev/null", "git push origin main 2>/dev/null",
           "git push origin main > /dev/null 2>&1", "git push origin main < /dev/null"]


@pytest.mark.parametrize("shell", ["bash", "zsh"])
@pytest.mark.parametrize("target", [".git/hooks/pre-pus?", ".git/hooks/pre-push"])
def test_the_shell_empties_the_hook_before_the_command_starts(repo, shell, target):
    """Non-vacuous: with `true` in place of git, the shell itself truncates the hook in both shells."""
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_bytes(HOOK)
    assert hook.stat().st_size == 17
    subprocess.run([shell, "-c", f"true origin main > {target}"], cwd=repo, check=True, timeout=30)
    assert hook.stat().st_size == 0


@pytest.mark.parametrize("command", WRITES.values(), ids=WRITES.keys())
def test_under_codex_a_push_that_writes_through_the_shell_is_not_plain(repo, command):
    assert not gate._codex_plain_push(command), command
    outcome = f2._decide(command, repo, "codex")
    assert "warn" not in {v.decision for v in outcome.verdicts}, outcome.verdicts
    assert f2._host_answer(outcome, "codex") == "deny"


@pytest.mark.parametrize("command", WRITES.values(), ids=WRITES.keys())
def test_under_claude_code_a_push_that_writes_through_the_shell_is_not_measured(repo, command):
    calls = gate.gated_calls(command, str(repo))
    assert calls and all(directory is gate.UNKNOWN for _n, directory, _d in calls), calls
    outcome = f2._decide(command, repo, "claude")
    assert outcome.decision == "ask" and f2._host_answer(outcome, "claude") == "ask", outcome.verdicts


@pytest.mark.parametrize("command", NEUTRAL)
def test_a_redirection_that_opens_no_file_keeps_the_push_plain_and_resolved(repo, command):
    assert gate._codex_plain_push(command), command
    assert f2._decide(command, repo, "codex").decision == "warn"
    calls = gate.gated_calls(command, str(repo))
    assert calls and all(directory is not gate.UNKNOWN for _n, directory, _d in calls), calls


@pytest.mark.parametrize("command", ["git status > out.txt", "git status 2> .git/hooks/pre-push",
                                     "git log > .git/hooks/pre-pus?"])
def test_a_rule_frees_no_form_that_writes_through_the_shell(repo, command):
    assert gate._rule_candidate(command, str(repo), time.monotonic() + 60) is None


@pytest.mark.parametrize("command", ["git status", "git status 2>&1", "git log > /dev/null"])
def test_control_a_rule_still_names_a_form_that_writes_nothing(repo, command):
    candidate = gate._rule_candidate(command, str(repo), time.monotonic() + 60)
    assert candidate is not None and candidate[0] == os.path.realpath(repo / ".git"), candidate
