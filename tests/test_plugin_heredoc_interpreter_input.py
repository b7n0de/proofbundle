"""D39, part 1 of follow-up note 14: the body of a here-document to python is the interpreter's input, not shell text.

Measured in the pilot at 14a5feb1: `python3 - "$B" "$L" <<'EOF'` with Python that names git or gh in strings and
variable names asked twice in ten minutes, from the safety net ("a git or gh command word, or an unevaluable quote").
With a quoted marker the shell expands nothing in the body, and python reads it as its program. Such a command is now
judged by its words before the here-document, as `python3 file.py [arguments]` is today: it gets no freer answer than
that form, only no ask from the body. An unquoted marker, another interpreter, a shell as the interpreter, a second
here-document and a command beside it keep today's answer.

RED at d6e248a8 for the form of the pilot (the net asks, Codex denies); the controls answer the same at both. Each case
runs the gate as the host starts it.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import test_plugin_done_check as d
from _plugin_env import plugin_env

pytestmark = d.pytestmark
G = str(d.GATE)

#: Python that names git and gh in strings, in a variable name and in a comment, as in the pilot.
BODY = ('import subprocess, sys\n'
        'git_dir, log = sys.argv[1], sys.argv[2]\n'
        '# read what gh and git left behind\n'
        'out = subprocess.run(["git", "-C", git_dir, "log", "-1"], capture_output=True, text=True).stdout\n'
        'print("gh pr view", out, open(log).read())\n')

INPUT = [
    "python3 - \"$B\" \"$L\" <<'EOF'\n" + BODY + "EOF\n",
    "python - \"$B\" \"$L\" <<'EOF'\n" + BODY + "EOF\n",
    "python3 - \"$B\" \"$L\" <<\"EOF\"\n" + BODY + "EOF\n",
    "python3 - <<\\EOF\n" + BODY + "EOF",
]
INPUT_IDS = ["python3_quoted", "python_quoted", "python3_double_quoted", "python3_backslash"]
KEPT = [
    "bash <<'EOF'\ngit -C /work/clone status\nEOF\n",
    "sh <<'EOF'\ngh pr view 12\nEOF\n",
    "python3 - <<EOF\n" + BODY + "EOF\n",
    "python3 - <<'EOF' && git push\n" + BODY + "EOF\n",
    "python3 - <<'EOF'\n" + BODY + "EOF\ngit push\n",
    "python3 - <<'EOF' <<'END'\n" + BODY + "EOF\nprint(2)\nEND\n",
    "python3 - <<-'EOF'\n" + BODY + "\tEOF\n",
    "python3 <<'EOF'\n" + BODY + "EOF\n",
    "perl - <<'EOF'\nsystem('git status');\nEOF\n",
    "python3 - <<'EOF' | cat\n" + BODY + "EOF\n",
]
KEPT_IDS = ["bash", "sh", "unquoted_marker", "and_push", "push_after_marker", "two_heredocs", "dash_heredoc",
            "no_dash", "perl", "pipeline"]
#: The heredoc form and the file form it is judged as, with words before the here-document that name git.
AS_FILE = [
    ("python3 - git <<'EOF'\nprint(1)\nEOF\n", "python3 script.py git"),
    ("python3 - \"$(git push)\" <<'EOF'\nprint(1)\nEOF\n", "python3 script.py \"$(git push)\""),
    ("python3 - \"$B\" <<'EOF'\nprint(1)\nEOF\n", "python3 script.py \"$B\""),
]
AS_FILE_IDS = ["git_argument", "push_substitution", "expansion"]


def _answer(tmp_path, command: str, host: str) -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(tmp_path),
                        "tool_input": {"command": command}})
    args = [] if host == "claude" else ["--host", host]
    proc = subprocess.run([sys.executable, "-I", G, *args], input=event, capture_output=True, text=True,
                          env=plugin_env(), timeout=120, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), ((out.get("additionalContext") or "") if out.get("permissionDecision") else "")   # D53: the long reason


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", INPUT, ids=INPUT_IDS)
def test_P1_the_body_of_a_quoted_heredoc_to_python_is_no_shell_text(tmp_path, command, host):
    assert _answer(tmp_path, command, host) == (0, None, "")


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
@pytest.mark.parametrize("command", KEPT, ids=KEPT_IDS)
def test_P1_control_every_other_form_keeps_its_answer(tmp_path, command, host, expected):
    code, decision, reason = _answer(tmp_path, command, host)
    assert (code, decision) == (0, expected), (code, decision, reason)


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("heredoc, file_form", AS_FILE, ids=AS_FILE_IDS)
def test_P1_control_the_words_before_the_heredoc_are_judged_as_the_file_form(tmp_path, heredoc, file_form, host):
    assert _answer(tmp_path, heredoc, host) == _answer(tmp_path, file_form, host)
