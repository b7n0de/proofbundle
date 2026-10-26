"""decide() hands the environment it is given to the house rules and the guards (found with D112, Nachtrag 41 point 2).

decide(command, cwd, deadline, host, environ) judged the guards of Nachtrag 33 (D101 to D105) and the count of D110
with the process environment instead of the one it was given: _with_house_rules was called without it. The hook
passes no environment (the process environment is the hook's), and the autonomous answer passes the hook's, so the
answer of the hook did not change; a caller that hands decide() another environment got guards that did not read it.

RED at f18b3183 (the head of PLUGIN_N42): both cases; the control is green at both.
"""
from __future__ import annotations

import os
import time

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
SESSION = "sess-n41"


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _world(tmp_path):
    r = d72._repo(tmp_path)
    temp = tmp_path / "temp"
    scratch = temp / f"claude-{os.getuid()}" / "-proj" / SESSION / "scratchpad"
    scratch.mkdir(parents=True)
    return r, temp, scratch


def test_a_session_folder_named_by_the_given_environment_is_a_work_folder(tmp_path, monkeypatch):
    """D104: the folder of the session comes from TMPDIR and CLAUDE_CODE_SESSION_ID of the environment decide() is
    given, not of the process."""
    r, temp, scratch = _world(tmp_path)
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID", raising=False)
    given = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "TMPDIR": str(temp),
             "CLAUDE_CODE_SESSION_ID": SESSION}
    out = gate.decide(f"rm -rf {scratch}/build", str(r), time.monotonic() + 60, "claude", environ=given)
    assert "delete_outside_work" not in _ids(out), _ids(out)


def test_a_session_folder_the_given_environment_does_not_name_is_no_work_folder(tmp_path, monkeypatch):
    """The other way: the process names the folder of the session, the environment decide() is given does not."""
    r, temp, scratch = _world(tmp_path)
    monkeypatch.setenv("TMPDIR", str(temp))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    given = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"]}
    out = gate.decide(f"rm -rf {scratch}/build", str(r), time.monotonic() + 60, "claude", environ=given)
    assert "delete_outside_work" in _ids(out), _ids(out)


def test_control_without_an_environment_the_process_environment_counts(tmp_path, monkeypatch):
    r, temp, scratch = _world(tmp_path)
    monkeypatch.setenv("TMPDIR", str(temp))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    out = gate.decide(f"rm -rf {scratch}/build", str(r), time.monotonic() + 60, "claude")
    assert "delete_outside_work" not in _ids(out), _ids(out)
