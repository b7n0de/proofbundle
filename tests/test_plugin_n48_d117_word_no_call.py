"""D117, Nachtrag 48, point 2: git or gh as a word in an argument, a string or the body of a here-document is no call.

Found by delta's sorting by hand (echo, 2026-10-20 16:26Z): 287 interventions since 2026-10-18, 37 false alarms, 36 of
one class, git or gh only as a word in an argument or in the body of a here-document; with the text made neutral the
gate is silent. Ids: net_unmodeled_git 28, directory_unresolved 4, git_form_not_free 3, code_names_git 2,
done_order_change 1. Measured at d3ce27a2 (probe_n48_wort.py, the forms below): the net of D27 counts every git or gh
word of the whole text with the quotes taken off, so a commit message that names `git push` is a second call it cannot
place (U1); the scan reads the body of a here-document as commands (U2); class c does not model a here-document inside
a substitution, so Claude Code's `git commit -m "$(cat <<'EOF' … EOF)"` falls back to that answer (U3); the search for
done-order reads such a body too (U4); a path program (cp, mv, mkdir, touch, rm, rmdir, ln, chmod) whose path names git
or gh asks (U5).

The rule, under Claude Code only (owner answer O48-2), where the session is measured and defines none of the programs
it relies on (D90): R1, `"$(cat <<'MARK'` … `)"` with a quoted marker is the literal word of its body; R2, the body of a
here-document with a quoted marker at a git, gh or data step is input, not shell text, for the scan, the net and
done-order; R3, a git or gh word in a literal argument of such a step is not counted by the net; R5, a path program with
literal words only is data. Every program position, every substitution, every assignment, every carrier of code and
every program the gate does not know count as before (owner answer O48-3: python -c, make, pytest, xargs, export,
sed -i keep asking).

RED at fd897f99, the head of PLUGIN_N51 (measured, 31 of 89): every case of FREED and REDUCED and the cases of R1
and of the view.
COUNTER, the Codex controls and the controls of the session are green at both.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n37_local_class_d91 as d91

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean

FREED = [
    ('b01', 'git commit -m "docs: explain git push flow"'),
    ('b02', 'git commit -m "fix(gate): gh pr merge asks"'),
    ('b11', "git commit -m 'Run `git push` later'"),
    ('b12', 'git commit -m "Run \\`git push\\` later"'),
    ('b16', 'git grep -n "gh pr"'),
    ('b19', 'git commit -m "x" -m "Mentions gh pr create and git push --force"'),
    ('c20', 'git commit -m "don\'t git push"'),
    ('b05', 'git add notes.md && git commit -m "notes on git push"'),
    ('b04', 'git commit -m "$(cat <<\'EOF\'\nfix: the gh helper\nEOF\n)"'),
    ('b41', 'git commit -q -m "$(cat <<\'EOF\'\ntest(gate): git push and gh pr merge stay asked\n\nBody.\nEOF\n)"'),
    ('c17', 'git commit -m "$(cat <<\'EOF\'\nplain message\nEOF\n)"'),
    ('c01', 'mkdir -p docs/gh'),
    ('c02', 'touch gh'),
    ('c03', 'cp notes.md docs/git/notes.md'),
    ('c04', 'rm -rf gh'),
    ('c05', 'mv notes.md gh/'),
    ('c06', 'mkdir -p docs/gh && cp notes.md docs/gh/'),
    ('c07', 'chmod 644 docs/git'),
    ('c08', 'ln -s notes.md gh'),
    ('b29', "cat > notes.md <<'EOF'\nproofbundle_gate.py done-order --remove\ngit push\nEOF"),
    ('c21', "cat > notes.md <<'EOF'\nproofbundle_gate.py done-order --remove --repo .\nEOF"),
]
REDUCED = [
    ('b06', 'git log --grep "gh pr"', 'net_unmodeled_git'),
    ('b10', "cat > msg.txt <<'EOF'\nfix: gh\nEOF\ngit commit -F msg.txt", 'net_unmodeled_git'),
    ('b42', "cat <<'EOF' > m.txt\ngit push origin main\nEOF\ngit commit -F m.txt", 'directory_unresolved'),
    ('b47', "git commit -m 'gh' --no-verify", 'net_unmodeled_git'),
    ('b48', "git notes add -m 'gh pr 12'", 'net_unmodeled_git'),
    ('c16', 'git add notes.md && git commit -m "$(cat <<\'EOF\'\nfix(gate): gh pr merge and git push stay asked\n\nThe message names git push.\nEOF\n)"', 'directory_unresolved'),
    ('c18', 'gh pr comment 12 --body "$(cat <<\'EOF\'\nPlease run git push again.\nEOF\n)"', 'directory_unresolved'),
    ('c22', "git commit -F - <<'EOF'\nnote: proofbundle_gate.py done-order --replace is for a person\nEOF", 'done_order_change'),
]
COUNTER = [
    ('k01', 'echo hi; git push origin main'),
    ('k02', 'echo "git" && git push origin main'),
    ('k03', 'echo $(git push origin main)'),
    ('k04', 'echo main | xargs git push origin'),
    ('k05', "sh -c 'git push origin main'"),
    ('k06', 'eval "git push origin main"'),
    ('k07', 'bash -c "gh pr merge 12"'),
    ('k08', "sh <<'EOF'\ngit push origin main\nEOF"),
    ('k09', 'cat <<EOF\n$(git push origin main)\nEOF'),
    ('k10', 'echo y | gh pr merge 12'),
    ('k11', 'echo "`git push origin main`"'),
    ('k12', 'echo "$(gh pr merge 12)"'),
    ('k13', 'python3 -c "import os; os.system(\'git push\')"'),
    ('k14', 'find . -exec git push \\;'),
    ('k15', 'env git push origin main'),
    ('k16', 'time git push origin main'),
    ('k17', 'echo git push origin main | sh'),
    ('k18', 'bash <<< "git push origin main"'),
    ('k19', "printf 'main\\n' | xargs -I{} sh -c 'git push origin {}'"),
    ('k20', 'nohup git push origin main'),
    ('k21', "echo 'git push' && gh pr merge 12"),
    ('k22', 'cat notes.md | xargs gh pr comment 12 --body'),
    ('k23', 'cd /tmp && git push origin main'),
    ('k24', 'grep x notes.md || git push origin main'),
    ('b28', 'cat <<EOF > notes.md\n$(git push origin main)\nEOF'),
    ('a13', 'python3 -c "print(\'git status\')"'),
    ('a22', 'echo "git" | xargs -n1 echo'),
    ('a23', 'make test 2>&1 | grep -c "git"'),
    ('a24', 'python3 -m pytest -q -k "git and push"'),
    ('a27', 'export MSG="git push later"'),
    ('a28', 'for w in git gh; do echo $w; done'),
    ('a42', 'python3 tools/x.py --name git'),
    ('a43', 'node -e "console.log(\'gh\')"'),
    ('a44', "cat <<'EOF' | python3 -\nprint('git push')\nEOF"),
    ('b45', "sed -i 's/git push/git push --dry-run/' notes.md"),
    ('b46', "perl -ne 'print if /git push/' notes.md"),
]
#: More counter cases, one or more per rule of D117: what R1 to R5 do not take stays as it is.
COUNTER += [
    ("r1_unquoted_marker", 'git commit -m "$(cat <<EOF\n$(gh pr merge 12)\nEOF\n)"'),
    ("r1_not_cat", "git commit -m \"$(sh <<'EOF'\ngh pr merge 12\nEOF\n)\""),
    ("r1_more_in_the_word", "git commit -m \"$(cat <<'EOF'\nx\nEOF\n) $(gh pr merge 12)\""),
    ("r2_body_into_a_shell", "cat <<'EOF' | sh\ngit push origin main\nEOF"),
    ("r2_shell_reads_the_body", "bash <<'EOF'\ngit push origin main\nEOF"),
    ("r2_script_then_run", "cat > x.sh <<'EOF'\ngit push origin main\nEOF\nsh x.sh"),
    ("r3_quoted_program_word", 'git commit -m x; "gh" pr merge 12'),
    ("r3_find_exec", "find . -name notes.md -exec git push origin main \\;"),
    ("r3_sed_runs_the_pattern", "sed 's/x/git push origin main/e' notes.md"),
    ("r3_awk_system", "awk 'BEGIN { system(\"gh pr merge 12\") }'"),
    ("r3_rg_preprocessor", "rg --pre gh x ."),
    ("r3_program_variable", "G=gh; $G pr merge 12"),
    ("r5_path_with_an_expansion", "cp notes.md $HOME/gh && $HOME/gh pr merge 12"),
    ("r5_install_strips_with_a_program", "install -s --strip-program=gh notes.md out.bin"),
]


def _repo(tmp_path):
    repo = d71._repo(tmp_path)
    d71._git(repo, "checkout", "-q", "-b", "claude/work", "topic")
    (repo / "notes.md").write_text("Notizen\n")
    (repo / "docs").mkdir(exist_ok=True)
    return repo


#: A deny of today stays (Nachtrag 48: no case that blocks today becomes free): the gate without D117 denies a
#: here-document that writes a hook-disabling push into a file (the corpus counts it as harmful, S373).
DENY_STAYS = [
    ("c13", "cat > notes.md <<'EOF'\ngit push --no-verify origin main\nEOF"),
    ("S373", "cat <<'EOF' > n.md\ngit push --no-verify origin main\nEOF"),
    ("deny_in_message", "git commit -m \"$(cat <<'EOF'\nthen git push --no-verify origin main\nEOF\n)\""),
]


@pytest.mark.parametrize("case, command", DENY_STAYS)
def test_D117_a_deny_of_today_stays_a_deny(tmp_path, case, command):
    decision, reasons, _klasse = d91.answered(_repo(tmp_path), command)
    assert decision == "deny" and "autonomy_blocked" not in reasons, (case, decision, reasons)


@pytest.mark.parametrize("case, command", FREED)
def test_D117_a_word_in_data_is_no_call(tmp_path, case, command):
    decision, reasons, _klasse = d91.answered(_repo(tmp_path), command)
    assert decision in (None, "pass"), (case, decision, reasons)


@pytest.mark.parametrize("case, command, gone", REDUCED)
def test_D117_the_reason_of_the_word_leaves_and_the_other_reasons_stay(tmp_path, case, command, gone):
    decision, reasons, _klasse = d91.answered(_repo(tmp_path), command)
    assert gone not in reasons and decision in ("ask", "deny"), (case, decision, reasons)


@pytest.mark.parametrize("case, command", COUNTER)
def test_D117_counter_a_real_call_or_code_keeps_its_answer(tmp_path, case, command):
    decision, reasons, _klasse = d91.answered(_repo(tmp_path), command)
    assert decision in ("ask", "deny"), (case, decision, reasons)


@pytest.mark.parametrize("case, command", [c for c in FREED if c[0] in ("b01", "b41", "c03", "c21", "b16")])
def test_D117_control_under_codex_nothing_changes(tmp_path, case, command):
    out = gate.decide(command, str(_repo(tmp_path)), time.monotonic() + 60, "codex")
    assert out is not None and out.decision in ("ask", "deny"), (case, out and out.decision)


@pytest.mark.parametrize("name, case", [("cat", "b41"), ("cp", "c03"), ("echo", "b29")])
def test_D117_control_a_session_that_defines_the_program_keeps_the_answer(tmp_path, monkeypatch, name, case):
    repo = _repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SHELL", "/bin/bash")
    command = dict(FREED)[case]
    if name == "echo":
        command = "echo x | tee notes.md; " + command
    decision, reasons, _klasse = d91.answered(repo, command)
    assert decision in (None, "pass"), (name, case, "without the session", decision, reasons)
    folder = tmp_path / "home" / ".claude" / "shell-snapshots"
    folder.mkdir(parents=True)
    (folder / "snapshot-bash-1.sh").write_text(f"# Snapshot file\n{name} () {{ eval \"$@\"; }}\n")
    decision, reasons, _klasse = d91.answered(repo, command)
    assert decision in ("ask", "deny"), (name, case, decision, reasons)


def test_D117_R1_the_message_is_the_literal_word_of_its_body():
    command = "git commit -m \"$(cat <<'EOF'\nfix(gate): don't ask for gh\n\nBody.\n\nEOF\n)\" && git status"
    env = {"HOME": "/nonexistent-home", "SHELL": "/bin/bash", "PATH": "/usr/bin:/bin"}
    assert gate._d117_literal_heredocs(command, "claude", env) == \
        "git commit -m 'fix(gate): don'\"'\"'t ask for gh\n\nBody.' && git status"
    assert gate._d117_literal_heredocs(command, "codex", env) == command
    inside = "echo '\"$(cat <<'EOF'\nx\nEOF\n)\"'"
    assert gate._d117_literal_heredocs(inside, "claude", env) == inside
    for kept in ("git commit -m \"$(cat <<'EOF'\nx\nEOF\n; gh pr merge 12)\"",
                 "git commit -m \"$(cat <<'EOF'\nx\nEOF\n) $(gh pr merge 12)\""):
        assert gate._d117_literal_heredocs(kept, "claude", env) == kept, kept


def test_D117_R2_R3_the_view_takes_only_data_kinds_and_literal_words():
    """What the net does not count: git or gh in a literal argument of a git, gh or data step; never in a word with a
    substitution (class c judges that step itself), and nothing at all in a command with a carrier of code."""
    env = {"HOME": "/nonexistent-home", "SHELL": "/bin/bash", "PATH": "/usr/bin:/bin"}
    assert gate._d117_view('git commit -m "a gh word"', "claude", env)[1] == 1
    assert gate._d117_view('echo "$(gh pr merge 12)" gh', "claude", env)[1] == 1
    for command in ("sh -c 'git push origin main'", "echo gh | sh", "make test gh"):
        assert gate._d117_view(command, "claude", env) == (command, 0), command
    body = "cat > notes.md <<'EOF'\ngit push\nEOF"
    assert gate._d117_view(body, "claude", env) == ("cat > notes.md <<'EOF'\nEOF", 0)
    assert gate._d117_view(body, "codex", env) == (body, 0)
