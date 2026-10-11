"""Review round 9 of 2026-10-11, R9-3: the answer to a push NOT MEASURED says what the gate checked, not "nothing".

Measured by the reviewer at b288ee66 with git 2.51.1: submodule.recurse=true, then submodule.recurse=false added, and
PreToolUse with `git push origin main`. The answer confirmed the evidence check at the source commit and then said "so
it checked nothing". The verdict stays ask/push_not_measured. Property: the blanket statement is removed, the concrete
reason stays; where the gate did check nothing, the reason itself says so. Red against b288ee66.
"""
from __future__ import annotations

import json
import subprocess
import sys

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

R8_5 = "The configuration contains submodule.recurse=true; submodule push behavior is NOT MEASURED."


def test_the_answer_names_the_source_check_and_does_not_say_it_checked_nothing(env, tmp_path):
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "config", "submodule.recurse", "true")
    _git(r.path, "config", "--add", "submodule.recurse", "false")
    answer, entry = n2c._level1(env, r.path)
    text = json.dumps(answer, ensure_ascii=False)
    assert (entry["verdict"], entry["reason_ids"]) == ("ask", ["push_not_measured"]), entry
    assert R8_5 in text and "showed no failure" in text, text
    assert "checked nothing" not in text, text


def test_a_pre_push_ref_the_gate_does_not_model_says_no_evidence_was_checked(env, tmp_path):
    """Level 2, a ref that is not a branch or a tag: nothing was checked, and the reason says so itself."""
    r = n2c.Repo(tmp_path)
    head = n2c._rev(r.path, "HEAD")
    line = f"refs/notes/x {head} refs/notes/x {'0' * 40}\n"
    proc = subprocess.run([sys.executable, "-I", str(n2c.GATE), "pre-push", "origin", "remote.git"], input=line,
                          capture_output=True, text=True, cwd=str(r.path), env=env, timeout=180, check=False)
    assert proc.returncode != 0, proc.stderr
    assert "checked no evidence" in proc.stderr and "checked nothing" not in proc.stderr, proc.stderr
