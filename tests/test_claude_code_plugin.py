"""The Claude Code plugin under plugins/claude-code: its manifest, its skills and its MCP server.

The server is started the way the plugin's .mcp.json would start it, minus uv: the same script, run by
this interpreter, so it calls the proofbundle package of this checkout. Each verdict it returns is the
exit code of the package's own command line, and these tests hold it to that.

Properties checked:
- every component the plugin names exists, and a skill pre-approves only tools the server lists;
- the server script pins the package to exactly one version;
- a receipt the server emits verifies under the key it returns, and fails after a one-byte change or
  under another key;
- the server never overwrites a receipt and never answers a notification;
- the plugin directory is not part of the Python distribution.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

import proofbundle

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "claude-code"
SERVER = PLUGIN / "server" / "proofbundle_mcp.py"
SKILLS = ("verify", "emit", "review-receipt")
TOOL_PREFIX = "mcp__plugin_proofbundle_proofbundle__"


def _frontmatter(text: str) -> dict[str, str]:
    lines = text.split("\n")
    assert lines[0] == "---", "the frontmatter must open on the first line"
    end = lines.index("---", 1)
    fields = {}
    for line in lines[1:end]:
        key, sep, value = line.partition(":")
        assert sep, f"frontmatter line is not 'key: value': {line!r}"
        fields[key.strip()] = value.strip()
    return fields


class _Server:
    def __init__(self, cwd: pathlib.Path, data: pathlib.Path):
        env = dict(os.environ, CLAUDE_PLUGIN_DATA=str(data))
        # The server runs from a temporary directory, where a relative PYTHONPATH would resolve to
        # nothing and the child could import some other installed proofbundle. Put the package this
        # test imported first, so the server is measured against the code under test.
        package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
        env["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, env.get("PYTHONPATH")) if p)
        self.proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, cwd=cwd, env=env)
        self.next_id = 0

    def send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        reply = json.loads(self.proc.stdout.readline())
        assert reply["id"] == self.next_id
        return reply

    def tool(self, name: str, **arguments) -> tuple[dict, bool]:
        result = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        return json.loads(result["content"][0]["text"]), result["isError"]

    def close(self) -> int:
        self.proc.stdin.close()
        return self.proc.wait(timeout=30)


@pytest.fixture
def server(tmp_path):
    srv = _Server(tmp_path, tmp_path / "data")
    reply = srv.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "0"}})
    assert reply["result"]["protocolVersion"] == "2025-06-18"
    srv.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    yield srv
    assert srv.close() == 0


def test_every_component_the_plugin_names_exists():
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "proofbundle"
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", manifest["name"])
    assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["version"])
    servers = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert list(servers) == ["proofbundle"]
    args = servers["proofbundle"]["args"]
    assert "${CLAUDE_PLUGIN_ROOT}/server/proofbundle_mcp.py" in args
    assert SERVER.is_file()
    for skill in SKILLS:
        assert (PLUGIN / "skills" / skill / "SKILL.md").is_file(), skill
    assert sorted(p.name for p in (PLUGIN / "skills").iterdir()) == sorted(SKILLS)


def test_a_skill_pre_approves_only_tools_the_server_lists(server):
    listed = {tool["name"] for tool in server.request("tools/list")["result"]["tools"]}
    assert listed == {"receipt_template", "emit_receipt", "verify_receipt", "inspect_receipt"}
    for skill in SKILLS:
        fields = _frontmatter((PLUGIN / "skills" / skill / "SKILL.md").read_text(encoding="utf-8"))
        assert fields.get("description"), skill
        for granted in fields.get("allowed-tools", "").split():
            assert granted.startswith(TOOL_PREFIX), (skill, granted)
            assert granted[len(TOOL_PREFIX):] in listed, (skill, granted)
    # Signing writes a key and a file: no skill may pre-approve it.
    for skill in SKILLS:
        fields = _frontmatter((PLUGIN / "skills" / skill / "SKILL.md").read_text(encoding="utf-8"))
        assert TOOL_PREFIX + "emit_receipt" not in fields.get("allowed-tools", "").split(), skill


def test_the_server_pins_the_package_to_exactly_one_version():
    header = re.search(r"^# /// script\n(.*?)^# ///$", SERVER.read_text(encoding="utf-8"), re.M | re.S)
    assert header, "the server script carries no inline script metadata"
    deps = re.search(r"^# dependencies = (\[.*\])$", header.group(1), re.M)
    assert deps
    assert re.fullmatch(r'\["proofbundle==\d+\.\d+\.\d+"\]', deps.group(1)), deps.group(1)


def test_an_emitted_receipt_verifies_and_a_changed_one_does_not(server, tmp_path):
    template, failed = server.tool("receipt_template", kind="decision")
    assert not failed
    predicate = dict(template["output"], decisionId=template["suggested_id"])
    emitted, failed = server.tool("emit_receipt", kind="decision", predicate=predicate, out_path="r.json")
    assert not failed, emitted
    assert emitted["exit_code"] == 0
    assert emitted["key_created"] is True
    key = emitted["public_key"]

    verified, failed = server.tool("verify_receipt", kind="decision", path="r.json", public_key=key)
    assert (failed, verified["exit_code"], verified["verified"]) == (False, 0, True)
    assert verified["proofbundle_version"] == proofbundle.__version__

    envelope = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    payload = bytearray(base64.b64decode(envelope["payload"]))
    at = payload.index(b'"DENY"')
    payload[at + 1] = ord("P")
    envelope["payload"] = base64.b64encode(bytes(payload)).decode()
    (tmp_path / "changed.json").write_text(json.dumps(envelope), encoding="utf-8")
    changed, _ = server.tool("verify_receipt", kind="decision", path="changed.json", public_key=key)
    assert (changed["exit_code"], changed["verified"]) == (1, False)

    other = base64.b64encode(bytes(range(32))).decode()
    wrong, _ = server.tool("verify_receipt", kind="decision", path="r.json", public_key=other)
    assert (wrong["exit_code"], wrong["verified"]) == (1, False)

    missing, _ = server.tool("verify_receipt", kind="decision", path="absent.json", public_key=key)
    assert (missing["exit_code"], missing["verified"]) == (2, False)

    # The second receipt reuses the key the first one created.
    again, failed = server.tool("emit_receipt", kind="decision", predicate=predicate, out_path="r2.json")
    assert not failed
    assert (again["key_created"], again["public_key"]) == (False, key)

    inspected, failed = server.tool("inspect_receipt", kind="decision", path="r.json")
    assert not failed
    assert inspected["verified"] is False


def test_the_server_refuses_what_it_cannot_do_safely(server, tmp_path):
    (tmp_path / "taken.json").write_text("{}", encoding="utf-8")
    template, _ = server.tool("receipt_template", kind="decision")
    refused, failed = server.tool("emit_receipt", kind="decision", predicate=template["output"],
                                  out_path="taken.json")
    assert failed
    assert "refusing to overwrite" in refused["error"]
    assert (tmp_path / "taken.json").read_text(encoding="utf-8") == "{}"

    for bad_key in ("not base64!", base64.b64encode(bytes(31)).decode()):
        refused, failed = server.tool("verify_receipt", kind="decision", path="taken.json",
                                      public_key=bad_key)
        assert failed, bad_key
    refused, failed = server.tool("verify_receipt", kind="nothing", path="taken.json")
    assert failed

    assert server.request("tools/call", {"name": "absent", "arguments": {}})["error"]["code"] == -32602
    assert server.request("absent/method")["error"]["code"] == -32601
    server.proc.stdin.write("not json\n")
    server.proc.stdin.flush()
    assert json.loads(server.proc.stdout.readline())["error"]["code"] == -32700
    # A notification gets no answer: the next line on stdout belongs to the next request.
    server.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}})
    assert "result" in server.request("ping")


def test_the_plugin_is_not_part_of_the_python_distribution():
    rules = [line.split() for line in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    assert ["prune", "plugins"] in rules
    for rule in rules:
        if rule[0] in ("graft", "include", "recursive-include", "global-include"):
            assert not any(arg.startswith("plugins") for arg in rule[1:]), rule
