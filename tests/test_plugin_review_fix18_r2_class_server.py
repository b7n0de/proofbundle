"""Review round 18 of 2026-10-14, the class of R18-2, in the plugin's MCP server: the gate's log is read only as a
regular file. Measured at 3604ba53: with the log a FIFO and no writer, `_read_log` was still blocked after 6 s, so the
gate status tool never answered. Each case runs in its own process; one still running after WAIT seconds is blocked."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import test_plugin_owner_choice1_undeclared_push as w1
from _plugin_env import plugin_env

pytestmark = w1.pytestmark
ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "plugins" / "proofbundle" / "server" / "proofbundle_mcp.py"
WAIT = 5.0
PROBE = r'''
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("probe_server", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
result, ok = m.tool_gate_status({})
print(json.dumps({"readable": result.get("readable"), "note": result.get("note")}))
'''


def _status(data: pathlib.Path) -> dict | str:
    environ = plugin_env(without=("GIT_", "PROOFBUNDLE_"))
    environ.update(CLAUDE_PLUGIN_DATA=str(data))
    environ.pop("PLUGIN_DATA", None)
    proc = subprocess.Popen([sys.executable, "-c", PROBE, str(SERVER)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=environ)
    try:
        out, err = proc.communicate(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return "BLOCKED"
    assert proc.returncode == 0, err
    return json.loads(out)


def test_RED_a_fifo_as_the_log_is_named_unreadable(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    os.mkfifo(data / "gate-log.jsonl")
    answer = _status(data)
    assert answer != "BLOCKED", "the gate status tool was still blocked on a FIFO as the log"
    assert answer["readable"] is False and "cannot be read" in answer["note"] and "not a regular file" in answer["note"]


def test_CONTROL_a_regular_log_is_read(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "gate-log.jsonl").write_text(json.dumps({"decision": "ask", "session_id": "x"}) + "\n")
    answer = _status(data)
    assert answer != "BLOCKED" and answer["readable"] is True, answer
