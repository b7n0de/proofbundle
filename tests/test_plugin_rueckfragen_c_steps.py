"""Class c of the ask load (FIX-18 part B, DESIGN_rueckfragen.md 3.3 and 4): a command judged step by step.

The gate parses a command as bash 5.2 does for the forms it models, walks every simple command bash would execute,
and judges each git and gh step on its own; text in a here-document, an argument of a data command or a comment is no
call. Every form it does not model keeps the answer of the whole command. The owner's answers of 2026-10-14: no
inert-Python rule (answer 6, review finding Q18-1); an interpreter, or a program the gate does not know, whose text
names git or gh asks at least, and a literal redirection or tee target is judged as a file-tool write (answer 9).

RED: the answer at d828c2be, the parent of this build, differs (asked where only text names git, or free where code
names git or a redirect writes a hook). CONTROL: the same at the parent. The ground-truth cases run the command for
real in bash with stand-ins for git and gh that only log their words, and compare with the steps the parser finds.
Run with git 2.43.0 and GNU bash 5.2.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import time

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = [w1.pytestmark, pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")]
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

FREE = (None, "pass", "inactive")


def _decide(work: pathlib.Path, command: str, environ: dict, host: str = "claude"):
    out = gate.decide(command, str(work), time.monotonic() + 120, host, environ)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


def _whole(work: pathlib.Path, command: str, environ: dict, host: str = "claude"):
    """The answer of the whole command as the gate gave it before class c. At the parent, where class c does not
    exist, that is the gate's answer itself, so a CONTROL holds there by construction and compares like with like."""
    judge = getattr(gate, "_decide_outcome_whole", None)
    if judge is None:
        out = gate.decide(command, str(work), time.monotonic() + 120, host, environ)
    else:
        out = judge(command, str(work), time.monotonic() + 120, host, environ)
    return None if out is None else out.decision


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / "notes").mkdir()
    (work / "notes" / "a.md").write_text("a\n")
    return work


# --- the benefit: text is no call ---------------------------------------------------------------------------

TEXT_ONLY = {
    "heredoc_to_file": "cat > notes/plan.md <<'EOF'\n# Plan\nSchritt 1: `git push origin main`\nEOF",
    "heredoc_to_wc": "cat <<'EOF' | wc -l\ngit log\ngit show\nEOF",
    "tee_heredoc": "tee notes/t.md <<'EOF' >/dev/null\ngit for-each-ref\nEOF",
    "grep_argument": "grep -c 'git push' notes/a.md",
    "echo_string": "echo 'gh pr create --fill' > notes/b.md",
}


@pytest.mark.parametrize("name", sorted(TEXT_ONLY))
def test_RED_text_that_names_git_or_gh_is_no_call(env, tmp_path, name):
    """d828c2be asked (net_unmodeled_git or another reason) although bash runs no git and no gh here."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, TEXT_ONLY[name], env)
    assert decision is None, (decision, reasons)


def test_RED_add_and_commit_in_a_chain_are_judged_each_on_their_own(env, tmp_path):
    """K-NW-2 B in a chain (DESIGN_rueckfragen.md 8): each step gets the state check it gets alone, where no step
    before it may change the state that check read. d828c2be asked for the chain."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, "git add notes/a.md && git commit -m 'notes'", env)
    assert decision == "pass" and reasons == ["free_after_state_check", "free_after_state_check"], (decision, reasons)


def test_RED_a_data_command_that_writes_a_plain_file_does_not_stop_the_chain(env, tmp_path):
    work = _repo(tmp_path)
    decision, reasons = _decide(work, "echo hi > notes/c.md && git add notes/c.md && git commit -m c", env)
    assert decision == "pass", (decision, reasons)


# --- the strengthening: code that names git asks, a redirect into a hook is a write -------------------------

Q18_1 = {
    "pathlib_import": "python3 -c \"from pathlib import os; os.system('git push origin main')\"",
    "pathlib_attribute": "python3 -c 'import pathlib; pathlib.os.system(\"git push origin main\")'",
    "with_argument": "python3 -c 'import pathlib; pathlib.os.system(\"git push origin main\")' x",
    "plain_os": "python3 -c \"import os; os.system('git push origin main')\"",
    "awk_system": "awk 'BEGIN{system(\"git push origin main\")}'",
    "alias": "shopt -s expand_aliases\nalias cat='git push origin main'\ncat notes/a.md",
    "eval_of_a_value": "X='git push origin main'; eval \"$X\"",
}


@pytest.mark.parametrize("name", sorted(Q18_1))
def test_RED_code_that_names_git_asks_at_least(env, tmp_path, name):
    """Review finding Q18-1 and owner answers 6 and 9: d828c2be let these through (not_gated)."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, Q18_1[name], env)
    assert decision in ("ask", "deny") and "code_names_git" in reasons, (decision, reasons)


@pytest.mark.parametrize("command", ["mytool 'git push origin main'", "deploy-helper --run 'gh pr create --fill'"])
def test_CONTROL_a_program_the_gate_does_not_know_with_git_text_stays_asked(env, tmp_path, command):
    """Owner answer 9: an unknown program may run the text it is given; asked at d828c2be (the net), asked here
    (code_names_git), never free although no step of it is a git step."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, command, env)
    assert decision in ("ask", "deny"), (decision, reasons)


def test_CONTROL_the_heredoc_python_form_of_q18_1_stays_asked(env, tmp_path):
    """The form the prototype of Fassung 1 freed: asked at d828c2be, asked here (no inert-Python rule)."""
    work = _repo(tmp_path)
    command = "python3 - <<'PY'\nfrom pathlib import os\nos.system('git push origin main')\nPY"
    decision, reasons = _decide(work, command, env)
    assert decision in ("ask", "deny"), (decision, reasons)


WRITES = {
    "hook_redirect": "echo x > .git/hooks/pre-push",
    "config_append": "printf '[core]\\n\\thooksPath = /tmp\\n' >> .git/config",
    "tee_config": "cat notes/a.md | tee .git/config",
}


@pytest.mark.parametrize("name", sorted(WRITES))
def test_RED_a_redirect_into_the_configuration_or_a_hook_is_a_write(env, tmp_path, name):
    """Owner answer 9: judged like a file-tool write; d828c2be did not gate these Bash writes."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, WRITES[name], env)
    assert decision == "ask" and "write_to_repo_state" in reasons, (decision, reasons)


def test_RED_a_redirect_into_the_gate_directory_is_denied(env, tmp_path):
    work = _repo(tmp_path)
    decision, reasons = _decide(work, f"echo with-approvals > {env['PROOFBUNDLE_GATE_DIR']}/mode", env)
    assert decision == "deny" and "write_to_gate_dir" in reasons, (decision, reasons)


STATE_BEFORE = {
    "copy_into_hooks": "cp notes/a.md .git/hooks/pre-commit && git commit -m msg",
    "path_assignment": "PATH=/tmp/evil:$PATH; git commit -m msg",
    "printf_v": "printf -v PATH '/tmp/evil'; git commit -m msg",
    "export": "export GIT_DIR=/tmp/x; git add notes/a.md",
    "unknown_program": "mytool --setup && git add notes/a.md",
    "script": "./setup.sh && git commit -m msg",
}


@pytest.mark.parametrize("name", sorted(STATE_BEFORE))
def test_CONTROL_a_step_that_may_change_the_state_keeps_add_and_commit_asked(env, tmp_path, name):
    """A step before add or commit that may change the configuration, hooks or environment: the free answer of the
    step alone does not hold (step_after_state_change), as d828c2be asked for the whole command."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, STATE_BEFORE[name], env)
    assert decision in ("ask", "deny"), (decision, reasons)


# --- what keeps the whole command's answer --------------------------------------------------------------------

KEPT = {
    "if": "if true; then git status; fi",
    "for": "for f in a b; do git log -1; done",
    "background": "git status &",
    "function": "f() { git status; }; f",
    "ansi_c": "$'git' status",
    "case_variant": "GIT push origin main",
    "built_word": "$(echo git) push origin main",
    "group_redirect": "{ git log -1; } > notes/out.txt",
    "push_after_other_step": "echo start; git push origin main",
    "gh_create_after_view": "gh pr view 41 && gh pr create --fill",
    "pipe_into_shell": "git log --format=%s | sh",
    "comment_r11_2": "true # ; git config proofbundle.reviewMarker changed",
    "wrapper_glob_r14_1": "sudo gi* status",
    "env_glob_r14_1": "env -- gi* push origin main",
}


@pytest.mark.parametrize("name", sorted(KEPT))
def test_CONTROL_a_form_class_c_does_not_judge_keeps_the_whole_answer(env, tmp_path, name):
    work = _repo(tmp_path)
    whole = _whole(work, KEPT[name], env)
    decision, reasons = _decide(work, KEPT[name], env)
    assert decision == whole and decision not in FREE, (decision, reasons)


def test_CONTROL_a_deny_of_the_whole_command_stays_deny(env, tmp_path):
    """Text only, and still denied: the hook-disabling words in a here-document (DESIGN_rueckfragen.md 6)."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, "cat <<'EOF' > notes/n.md\ngit push --no-verify\nEOF", env)
    assert decision == "deny" and "hooks_disabled" in reasons, (decision, reasons)


def test_RED_a_push_as_the_first_step_gets_the_answer_of_the_push_alone(env, tmp_path):
    """The push runs before every other step, so no step can change what its check read. In this undeclared repository
    that is the local inactivity of owner choice 1 A; d828c2be asked for the chain (directory_unresolved)."""
    work = _repo(tmp_path)
    alone = _decide(work, "git push origin main", env)
    chained = _decide(work, "git push origin main; echo done", env)
    assert chained == alone and alone == ("inactive", ["nothing_declared_locally"]), (alone, chained)


def test_CONTROL_a_push_after_a_step_that_writes_keeps_the_whole_answer(env, tmp_path):
    work = _repo(tmp_path)
    command = "echo '{}' > .proofbundle-notes && git push origin main"
    whole = _whole(work, command, env)
    decision, reasons = _decide(work, command, env)
    assert decision == whole == "ask", (decision, reasons)


def test_CONTROL_a_step_after_cd_has_an_unknown_directory(env, tmp_path):
    """Asked at the parent too; class c names the reason directory_unresolved (class e is not built)."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, "cd notes && git add a.md", env)
    assert decision == "ask", (decision, reasons)


@pytest.mark.parametrize("name", ["heredoc_to_file", "grep_argument", "tee_heredoc"])
def test_RED_text_is_no_call_under_codex_either(env, tmp_path, name):
    """d828c2be asked under Codex (and so denied), for the git words in the text."""
    work = _repo(tmp_path)
    decision, reasons = _decide(work, TEXT_ONLY[name], env, host="codex")
    assert decision is None, (decision, reasons)


def test_CONTROL_under_codex_a_push_after_a_cd_keeps_the_whole_answer(env, tmp_path):
    work = _repo(tmp_path)
    whole = _whole(work, "cd notes && git push origin main", env, host="codex")
    decision, _reasons = _decide(work, "cd notes && git push origin main", env, host="codex")
    assert decision == whole and decision in ("ask", "deny"), decision


# --- Q18-2: no read of class c starts a program of the repository ----------------------------------------------

@pytest.mark.parametrize("command", [
    "git status && git log --oneline -3",
    "git add notes/a.md && git commit -m m",
    "cat <<'EOF' | wc -l\ngit log\nEOF",
    "echo x > notes/z.md && git add notes/z.md",
    "git diff --stat | tail -1",
])
def test_CONTROL_q18_2_no_fsmonitor_or_hook_of_the_repository_runs(env, tmp_path, command):
    """The repository names a marker program as core.fsmonitor and as the post-index-change hook: deciding a command
    of class c starts neither (review finding Q18-2: the prototype's submodule check had run fsmonitor)."""
    work = _repo(tmp_path)
    marker = tmp_path / "marker.log"
    program = tmp_path / "marker.sh"
    program.write_text(f"#!/bin/sh\necho \"$0 $*\" >> {marker}\nexit 0\n")
    program.chmod(0o755)
    w1._git(work, "config", "core.fsmonitor", str(program))
    hook = work / ".git" / "hooks" / "post-index-change"
    hook.write_text(f"#!/bin/sh\necho hook >> {marker}\n")
    hook.chmod(0o755)
    _decide(work, command, env)
    assert not marker.exists(), marker.read_text()


# --- the parser against bash -------------------------------------------------------------------------------------

GROUND = [
    "git status && git log --oneline -3",
    "cat > notes/x.md <<'EOF'\ngit push origin main\nEOF",
    "cat <<EOF > notes/y.md\n$(git rev-parse HEAD)\nEOF",
    "echo \"$(git rev-parse --short HEAD)\" | wc -c",
    "x=$(git log -1 --format=%H); echo \"$x\"",
    "git diff --stat | tail -1",
    "(git status; git log -1) > /dev/null",
    "grep -c 'git push' notes/a.md || true",
    "gh pr view 41 --json title | cat",
    "printf '%s\\n' \"$(gh api repos/o/r --jq .name)\"",
    "git log --format='%s' -3 | sort | uniq -c",
    "tee notes/t.md <<'EOF' >/dev/null\ngit for-each-ref\nEOF",
    "echo `git rev-parse HEAD`",
    "cat <(git log -1) | head -1",
    "! git diff --quiet",
    "git add notes/a.md && git commit -m 'msg with git push'",
    "cd notes && git status",
    "# a plain comment",
    "echo 'git push' # a comment",
    "cat <<-'EOF' | wc -l\n\tgit log\n\tEOF",
    "git log -1 \\\n  --oneline",
    "LANG=C git status",
    "git status; gh pr list",
    "echo \"$(echo \"$(git rev-parse HEAD)\")\"",
    "{ git status; git log -1; }",
    "git log -1 2>&1 | head -1",
]


def _stand_ins(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    bin_dir, log = tmp_path / "stand-in-bin", tmp_path / "calls.log"
    bin_dir.mkdir()
    for name in ("git", "gh"):
        script = bin_dir / name
        script.write_text("#!/bin/sh\n{ printf '%s' \"" + name + "\"; for a in \"$@\"; do printf '\\037%s' \"$a\"; "
                          "done; printf '\\036'; } >> \"$STAND_IN_LOG\"\n")
        script.chmod(0o755)
    return bin_dir, log


@pytest.mark.parametrize("command", GROUND, ids=[f"g{i:02d}" for i in range(len(GROUND))])
def test_the_parser_finds_the_git_and_gh_calls_bash_runs(tmp_path, command):
    """Bash runs the command in an empty folder with stand-ins for git and gh in front of PATH; the stand-ins log
    their words. The steps class c judges as git or gh steps are exactly those calls."""
    bin_dir, log = _stand_ins(tmp_path)
    work = tmp_path / "work"
    (work / "notes").mkdir(parents=True)
    (work / "notes" / "a.md").write_text("a\n")
    environ = {"PATH": f"{bin_dir}:/usr/bin:/bin", "STAND_IN_LOG": str(log), "HOME": str(tmp_path), "LANG": "C"}
    subprocess.run(["bash", "-c", command], cwd=work, env=environ, capture_output=True, timeout=30, check=False)
    ran = sorted(tuple(rec.split("\x1f")) for rec in (log.read_text() if log.exists() else "").split("\x1e") if rec)
    steps = []
    gate._sh_walk(gate._sh_parse(command), str(work), steps)
    found = sorted(tuple(s.words) for s in steps if s.kind in ("git", "gh"))
    assert found == ran, (found, ran)


@pytest.mark.parametrize("command", [
    "if true; then git status; fi", "git status &", "f() { git status; }", "$'git' status", "echo $\"x\"",
    "{ git log; } > out", "cat <<EOF\n$(cat <<X\nX\n)\nEOF", "echo `echo \\`git status\\``", "echo ${x:-\"git\"}",
    "git status {fd}>out", "case x in x) git status;; esac", "echo \"unclosed", "true # ; git status",
])
def test_the_parser_refuses_what_it_does_not_model(command):
    with pytest.raises(gate._ShUnmodeled):
        steps = []
        gate._sh_walk(gate._sh_parse(command), "/", steps)
