"""Review round 18 of 2026-10-14, the class of R18-2, second pass, in the plugin's MCP server: the self-test check reads
the base_oid and remote_refs of its throwaway folder only as regular files.

Measured at 3604ba53 and at 0ef0653f: with either file a FIFO and no writer, `tool_gate_selftest_check` was still
blocked after 4 s. Each case runs in its own process with TMPDIR inside the test's folder; one still running after WAIT
seconds is blocked. A value that cannot be read is NOT MEASURABLE, as for a missing file.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_owner_choice1_undeclared_push as w1
from _plugin_env import plugin_env

pytestmark = w1.pytestmark
ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "plugins" / "proofbundle" / "server" / "proofbundle_mcp.py"
WAIT = 5.0
BASE = "0" * 40
PROBE = r'''
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("probe_server", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
result, _flag = m.tool_gate_selftest_check({"work": sys.argv[2], "started_at": "2026-10-14T00:00:00Z"})
print(json.dumps({k: result.get(k) for k in ("target_changed", "base_oid", "other_refs_changed")}))
'''


def _folder(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    temp = tmp_path / "tmp"
    parent = temp / "proofbundle-selftest-probe"
    (parent / "work").mkdir(parents=True)
    (parent / "base_oid").write_text(BASE + "\n")
    (parent / "remote_refs").write_text("")
    return temp, parent


def _check(temp: pathlib.Path, parent: pathlib.Path) -> dict | str:
    environ = plugin_env(without=("GIT_", "PROOFBUNDLE_"))
    environ.update(TMPDIR=str(temp), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    proc = subprocess.Popen([sys.executable, "-c", PROBE, str(SERVER), str(parent / "work")], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=environ)
    try:
        out, err = proc.communicate(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return "BLOCKED"
    assert proc.returncode == 0, err
    return json.loads(out)


@pytest.mark.parametrize("name", ["base_oid", "remote_refs"])
def test_RED_a_fifo_in_the_throwaway_folder_is_not_measurable(tmp_path, name):
    temp, parent = _folder(tmp_path)
    (parent / name).unlink()
    os.mkfifo(parent / name)
    try:
        answer = _check(temp, parent)
    finally:
        (parent / name).unlink()
    assert answer != "BLOCKED", f"the self-test check was still blocked on a FIFO as {name}"
    assert answer["target_changed"] is None and answer["other_refs_changed"] is None, answer
    assert answer["base_oid"] == ("" if name == "base_oid" else BASE), answer


def test_CONTROL_regular_files_are_read_as_before(tmp_path):
    temp, parent = _folder(tmp_path)
    answer = _check(temp, parent)
    assert answer != "BLOCKED" and answer["base_oid"] == BASE, answer
