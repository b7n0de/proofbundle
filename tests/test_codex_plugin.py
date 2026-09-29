"""The Codex side of the proofbundle plugin (plugins/proofbundle/.codex-plugin/plugin.json).

One folder serves Claude Code and Codex. These tests hold the Codex manifest to the files the Claude
Code manifest uses, and hold the gate's Codex answers to what Codex accepts. The Codex facts come from
the Codex source, openai/codex at c248f6d4 (codex-rs):
- a PreToolUse answer may carry only continue, stopReason, suppressOutput, systemMessage, decision,
  reason and hookSpecificOutput, which in turn may carry only hookEventName, permissionDecision,
  permissionDecisionReason, updatedInput and additionalContext (hooks/src/schema.rs);
- ask is unsupported, and an unsupported answer fails the hook and lets the call run
  (hooks/src/engine/output_parser.rs, hooks/src/events/pre_tool_use.rs);
- a reason without a decision is unsupported too;
- a plugin's MCP entry gets no ${CLAUDE_PLUGIN_ROOT} expansion, and its relative cwd is joined onto the
  plugin root (codex-mcp/src/plugin_config.rs);
- on install, Codex copies regular files and drops symlinks (core-plugins/src/store.rs).

Properties checked:
- both manifests name the same plugin and version, and reach the same server, gate and skills;
- no file of the plugin's logic exists twice, and no symlink exists, so nothing can drift or vanish on
  install;
- under --host codex the gate never answers ask or allow, turns NOT MEASURED into deny, and uses only
  fields Codex accepts;
- the Codex MCP entry, run from the plugin root, starts the server;
- the emit skill runs only when invoked, under both hosts.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import proofbundle
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
CLAUDE = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
CODEX = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
SERVER = PLUGIN / "server" / "proofbundle_mcp.py"

CODEX_TOP_KEYS = {"continue", "stopReason", "suppressOutput", "systemMessage", "decision", "reason",
                  "hookSpecificOutput"}
CODEX_SPECIFIC_KEYS = {"hookEventName", "permissionDecision", "permissionDecisionReason", "updatedInput",
                       "additionalContext"}


def _codex_hook() -> dict:
    groups = CODEX["hooks"]["hooks"]["PreToolUse"]
    assert set(CODEX["hooks"]["hooks"]) == {"PreToolUse"}
    assert [g["matcher"] for g in groups] == ["Bash"]
    (entry,) = groups[0]["hooks"]
    return entry


# --- the manifests reach the same files --------------------------------------------------------------

def test_both_manifests_name_the_same_plugin_and_version():
    assert CODEX["name"] == CLAUDE["name"] == "proofbundle"
    assert CODEX["version"] == CLAUDE["version"]


def test_the_codex_manifest_uses_the_shared_skills_server_and_gate():
    assert CODEX["skills"] == "./skills"
    (server,) = CODEX["mcpServers"].values()
    mcp = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))
    (claude_server,) = mcp["mcpServers"].values()
    assert server["command"] == claude_server["command"] == "uv"
    assert server["cwd"] == "."
    assert server["args"][:-1] == claude_server["args"][:-1] == ["run", "--quiet", "--script"]
    assert (PLUGIN / server["cwd"] / server["args"][-1]).resolve() == SERVER
    assert claude_server["args"][-1] == "${CLAUDE_PLUGIN_ROOT}/server/proofbundle_mcp.py"
    assert "${" not in json.dumps(server), "Codex does not expand placeholders in an MCP entry"
    entry = _codex_hook()
    claude_hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    (claude_entry,) = claude_hooks["hooks"]["PreToolUse"][0]["hooks"]
    assert entry["command"] == claude_entry["command"].replace(
        '"${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"', '"${PLUGIN_ROOT}/hooks/proofbundle_gate.py" --host codex')
    assert entry["timeout"] == claude_entry["timeout"]


def test_no_logic_file_exists_twice_and_no_symlink_exists():
    files = [p for p in PLUGIN.rglob("*") if "__pycache__" not in p.parts]
    assert not [p for p in files if p.is_symlink()], "Codex drops symlinks on install"
    logic = [p for p in files if p.is_file() and "evals" not in p.relative_to(PLUGIN).parts]
    by_digest = collections.defaultdict(list)
    for path in logic:
        by_digest[hashlib.sha256(path.read_bytes()).hexdigest()].append(path.relative_to(PLUGIN))
    assert [paths for paths in by_digest.values() if len(paths) > 1] == []
    for name in ("proofbundle_mcp.py", "proofbundle_gate.py"):
        assert len(list(ROOT.joinpath("plugins").rglob(name))) == 1, name


def test_every_skill_has_what_codex_requires():
    for skill in sorted((PLUGIN / "skills").glob("*/SKILL.md")):
        lines = skill.read_text(encoding="utf-8").split("\n")
        head = lines[1:lines.index("---", 1)]
        fields = dict(line.split(":", 1) for line in head)
        assert fields.get("description", "").strip(), f"{skill}: Codex requires a description"
        assert len(skill.parent.name) <= 64


def test_the_emit_skill_runs_only_when_invoked_under_both_hosts():
    head = (PLUGIN / "skills" / "emit" / "SKILL.md").read_text(encoding="utf-8").split("\n---\n", 1)[0]
    assert "disable-model-invocation: true" in head.split("\n")
    policy = (PLUGIN / "skills" / "emit" / "agents" / "openai.yaml").read_text(encoding="utf-8")
    body = [line for line in policy.split("\n") if line and not line.startswith("#")]
    assert body == ["policy:", "  allow_implicit_invocation: false"]
    for other in ("verify", "review-receipt"):
        assert not (PLUGIN / "skills" / other / "agents").exists()


def test_the_marketplace_entry_matches_both_manifests():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    (entry,) = market["plugins"]
    assert entry["source"] == "./plugins/proofbundle"
    assert entry["name"] == CODEX["name"] == CLAUDE["name"]
    assert not (ROOT / ".agents" / "plugins" / "marketplace.json").exists(), "one marketplace file (D15)"


# --- the gate's Codex answers ------------------------------------------------------------------------

def _git(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@pytest.fixture
def shim(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nshift 3\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    env = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    return env


def _repo(tmp_path: pathlib.Path, *, declare: bool, tamper: bool = False) -> pathlib.Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("x\n", encoding="utf-8")
    if declare:
        signer = generate_signer()
        bundle = emit_bundle(b"release bytes", signer)
        if tamper:
            raw = bytearray(base64.b64decode(bundle["payload_b64"]))
            raw[0] ^= 1
            bundle["payload_b64"] = base64.b64encode(bytes(raw)).decode()
        (repo / "evidence").mkdir()
        (repo / "evidence" / "b.json").write_text(json.dumps(bundle), encoding="utf-8")
        (repo / ".proofbundle").mkdir()
        key = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
        (repo / ".proofbundle" / "policy.json").write_text(json.dumps({
            "schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": key}],
            "signature": {"require_expected_signer": True}}), encoding="utf-8")
        (repo / ".proofbundle" / "evidence.json").write_text(json.dumps({
            "schema": "proofbundle-plugin/evidence/v0.1",
            "evidence": [{"kind": "bundle", "path": "evidence/b.json", "policy": ".proofbundle/policy.json"}]}),
            encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    return repo


def _run(env: dict, repo: pathlib.Path, *args: str, command: str = "git push origin main") -> dict | None:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, str(GATE), *args], input=event, capture_output=True, text=True,
                          env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def _codex_valid(answer: dict) -> str:
    """The decision Codex would take from this answer, after checking Codex would accept it at all."""
    assert set(answer) <= CODEX_TOP_KEYS
    specific = answer["hookSpecificOutput"]
    assert set(specific) <= CODEX_SPECIFIC_KEYS
    assert specific["hookEventName"] == "PreToolUse"
    decision = specific.get("permissionDecision")
    assert decision in (None, "deny"), "Codex rejects ask, and allow without updatedInput"
    if decision is None:
        assert "permissionDecisionReason" not in specific, "Codex rejects a reason without a decision"
        return "pass"
    assert specific["permissionDecisionReason"].strip()
    return "deny"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_codex_nothing_declared_is_denied_as_not_measured(shim, tmp_path):
    repo = _repo(tmp_path, declare=False)
    claude = _run(shim, repo)
    assert claude["hookSpecificOutput"]["permissionDecision"] == "ask"
    codex = _run(shim, repo, "--host", "codex")
    assert _codex_valid(codex) == "deny"
    assert codex["hookSpecificOutput"]["permissionDecisionReason"].startswith("NOT MEASURED:")
    assert "Codex cannot ask" in codex["systemMessage"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_codex_a_tampered_bundle_is_denied_and_a_verified_one_passes(shim, tmp_path):
    assert _codex_valid(_run(shim, _repo(tmp_path / "a", declare=True, tamper=True), "--host", "codex")) == "deny"
    verified = _run(shim, _repo(tmp_path / "b", declare=True), "--host", "codex")
    assert _codex_valid(verified) == "pass"
    assert "declared items verified" in verified["systemMessage"]


def test_under_codex_a_call_the_gate_does_not_know_gets_no_answer(shim, tmp_path):
    assert _run(shim, tmp_path, "--host", "codex", command="ls -la") is None


@pytest.mark.parametrize("args", [["--host"], ["--host", "cursor"], ["--hots", "codex"], ["codex"]])
def test_an_unknown_argument_denies_every_call(shim, tmp_path, args):
    answer = _run(shim, tmp_path, *args, command="ls -la")
    assert _codex_valid(answer) == "deny"
    assert "unknown arguments" in answer["systemMessage"]


def test_the_codex_hook_entry_blocks_when_the_gate_cannot_run(tmp_path):
    entry = _codex_hook()
    event = json.dumps({"cwd": str(tmp_path), "tool_input": {"command": "ls"}})
    ok = subprocess.run(["sh", "-c", entry["command"]], input=event, capture_output=True, text=True,
                        env=dict(os.environ, PLUGIN_ROOT=str(PLUGIN)), check=False)
    assert (ok.returncode, ok.stdout) == (0, "")
    gone = subprocess.run(["sh", "-c", entry["command"]], input=event, capture_output=True, text=True,
                          env=dict(os.environ, PLUGIN_ROOT=str(tmp_path / "gone")), check=False)
    assert gone.returncode == 2
    assert gone.stderr.strip(), "Codex blocks on exit 2 only with a reason on stderr"


# --- the Codex MCP entry -----------------------------------------------------------------------------

def test_the_codex_mcp_entry_run_from_the_plugin_root_starts_the_server(shim):
    (server,) = CODEX["mcpServers"].values()
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
    proc = subprocess.run([server["command"], *server["args"]], input=request, capture_output=True, text=True,
                          cwd=PLUGIN / server["cwd"], env=shim, timeout=60, check=False)
    reply = json.loads(proc.stdout.splitlines()[0])
    assert reply["result"]["serverInfo"]["name"] == "proofbundle"
