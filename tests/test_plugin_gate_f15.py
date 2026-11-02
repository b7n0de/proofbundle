"""The two Runde-15 classes the owner's rule for the user path keeps (DECISIONS.md, D27): F15-4, no JSON read of the
gate or the server takes NaN, Infinity or -Infinity, and a logging notification with a level MCP does not define
refuses the verifier run; F15-2, a call a rule frees names the mode and rules files and when they changed, and no
longer claims that the model cannot set the mode."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

import pytest

import proofbundle
from _plugin_env import plugin_env

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
SERVER = PLUGIN / "server" / "proofbundle_mcp.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
from _gate_answer import skip_where_the_gate_is_not_shipped  # noqa: E402
skip_where_the_gate_is_not_shipped(pathlib.Path(__file__).resolve().parent.parent / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py",
                                   pathlib.Path(__file__).resolve().parent.parent)
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode


# --- F15-4: non-JSON constants and unknown logging levels ----------------------------------------------------------

@pytest.mark.parametrize("text", ['{"a": NaN}', '[Infinity]', '{"a": {"b": -Infinity}}'])
def test_f15_4_strict_json_refuses_a_non_json_constant(text):
    with pytest.raises(ValueError):
        gate.strict_json(text)


def test_f15_4_the_declaration_refuses_a_non_json_constant():
    raw = json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": []}).replace("[]", "[NaN]").encode()
    with pytest.raises(gate.GateError):
        gate.parse_declaration(raw)


_INIT_OK = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                             "serverInfo": {"name": "proofbundle", "version": "0.3.0"}}})
_GREEN = json.dumps({"jsonrpc": "2.0", "id": 1,
                     "result": {"isError": False, "content": [{"type": "text", "text": json.dumps({"exit_code": 0})}]}})


def _run(monkeypatch, lines):
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = "".join(line + "\n" for line in lines)
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, _o=out, **k: subprocess.CompletedProcess(a, 0, _o, ""))
    return gate.verify_items([{"kind": "bundle"}], time.monotonic() + 30)


@pytest.mark.parametrize("notification", [
    '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t","progress":NaN}}',
    '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t","progress":Infinity}}',
    '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"verbose","data":"x"}}',
    '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":["info"],"data":"x"}}',
])
def test_f15_4_the_verifier_run_with_such_a_line_is_refused(monkeypatch, notification):
    """F15-4 (review round 15): at 13753b7e the NaN progress stream returned [{'exit_code': 0, 'is_error': False}]."""
    with pytest.raises(gate.GateError):
        _run(monkeypatch, [_INIT_OK, notification, _GREEN])


def test_f15_4_a_known_level_is_still_read(monkeypatch):
    results = _run(monkeypatch, [_INIT_OK, json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                                                       "params": {"level": "warning", "data": "x"}}), _GREEN])
    assert results[0]["exit_code"] == 0


def test_f15_4_the_server_refuses_a_request_with_a_non_json_constant():
    proc = subprocess.run([sys.executable, "-I", str(SERVER)], input='{"jsonrpc":"2.0","id":NaN,"method":"ping"}\n',
                          capture_output=True, text=True, timeout=60, check=False,
                          env=plugin_env(PYTHONPATH=str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)))
    reply = json.loads(proc.stdout.splitlines()[0])
    assert reply["error"]["code"] == -32700


# --- F15-2: a freed call is visible ---------------------------------------------------------------------------------

def test_f15_2_a_rule_that_frees_a_call_names_the_mode_and_the_rules_and_claims_nothing_false(monkeypatch, tmp_path):
    gate_dir = tmp_path / "g"
    gate_dir.mkdir()
    (gate_dir / "mode").write_text("with-approvals\n")
    (gate_dir / "rules.json").write_text("[]")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(gate_dir))
    outcome = gate._approved_outcome({"repo": str(tmp_path), "form": "git status", "effect": "free",
                                      "state_digest": "0" * 64})
    assert str(gate_dir / "mode") in outcome.text and str(gate_dir / "rules.json") in outcome.text
    assert "last changed" in outcome.text and "a shell command can" in outcome.text
    assert "model can neither set the mode" not in outcome.text
