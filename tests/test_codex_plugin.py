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
- an answer without a decision, carrying only systemMessage and additionalContext, is accepted and
  lets Codex's own approval flow decide;
- a plugin's MCP entry gets no ${CLAUDE_PLUGIN_ROOT} expansion, and its relative cwd is joined onto the
  plugin root (codex-mcp/src/plugin_config.rs);
- on install, Codex copies regular files and drops symlinks (core-plugins/src/store.rs).

Properties checked:
- both manifests name the same plugin and version, and reach the same server, gate and skills;
- no file of the plugin's logic exists twice, and no symlink exists, so nothing can drift or vanish on
  install;
- under --host codex the gate never answers ask or allow, turns every NOT MEASURED ask into deny, and
  uses only fields Codex accepts;
- a repository the gate measured to declare nothing, neither at HEAD nor in the working tree, gets an
  answer without a decision under both hosts, which Codex accepts, marked NOT MEASURED and saying the
  gate is not active there (D5, C; D12); a declaration only in the working tree is still denied;
- the Codex MCP entry, run from the plugin root, starts the server and tells it its host;
- under Codex, verify_receipt says that it cannot see whether the gate ran, and the verify skill passes
  that on and never claims the gate ran (Codex runs plugin hooks only after the user trusts them);
- the second matcher, for MCP tools that open a pull request or a release, push files, write a file or
  merge a pull request, is the same under both hosts, and under Codex such a call in a repository that
  declares nothing gets no decision, marked NOT MEASURED;
- the emit skill runs only when invoked, under both hosts;
- the runbook for the Mac run of a real Codex turn names every case with the answer it expects, and each
  case's scaffold mode exists.
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
CLAUDE_HOOKS = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
SERVER = PLUGIN / "server" / "proofbundle_mcp.py"
RUNBOOK = PLUGIN / "RUNBOOK_CODEX.md"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

#: The marketplace files Codex looks for, first match wins (core-plugins/src/marketplace.rs:20-25).
CODEX_MARKETPLACE_CANDIDATES = (".agents/plugins/marketplace.json", ".agents/plugins/api_marketplace.json",
                                ".claude-plugin/marketplace.json", ".cursor-plugin/marketplace.json")
CODEX_TOP_KEYS = {"continue", "stopReason", "suppressOutput", "systemMessage", "decision", "reason",
                  "hookSpecificOutput"}
CODEX_SPECIFIC_KEYS = {"hookEventName", "permissionDecision", "permissionDecisionReason", "updatedInput",
                       "additionalContext"}


def _codex_hook_matcher() -> str:
    """The MCP matcher exactly as the Codex manifest writes it, read from the file and not from the gate."""
    return CODEX["hooks"]["hooks"]["PreToolUse"][1]["matcher"]


def _codex_hook() -> dict:
    groups = CODEX["hooks"]["hooks"]["PreToolUse"]
    assert set(CODEX["hooks"]["hooks"]) == {"PreToolUse"}
    assert [g["matcher"] for g in groups] == [g["matcher"] for g in CLAUDE_HOOKS["hooks"]["PreToolUse"]]
    assert [g["matcher"] for g in groups] == ["Bash", gate.MCP_MATCHER]
    assert groups[0]["hooks"] == groups[1]["hooks"]
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
    assert server["env"] == {"PROOFBUNDLE_PLUGIN_HOST": "codex"}
    assert "env" not in claude_server
    entry = _codex_hook()
    (claude_entry,) = CLAUDE_HOOKS["hooks"]["PreToolUse"][0]["hooks"]
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
    present = [path for path in CODEX_MARKETPLACE_CANDIDATES if (ROOT / path).is_file()]
    assert present == [".claude-plugin/marketplace.json"], "one marketplace file for both hosts (D15)"


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
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    if declare:
        subject = {"algorithm": gate.TREE_ALGORITHM, "digest": gate.tree_digest(str(repo), "HEAD")}
        signer = generate_signer()
        bundle = emit_bundle(json.dumps({"subject": subject}).encode(), signer)
        if tamper:
            raw = bytearray(base64.b64decode(bundle["payload_b64"]))
            raw[0] ^= 1
            bundle["payload_b64"] = base64.b64encode(bytes(raw)).decode()
        (repo / ".proofbundle").mkdir()
        (repo / ".proofbundle" / "b.json").write_text(json.dumps(bundle), encoding="utf-8")
        key = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
        (repo / ".proofbundle" / "policy.json").write_text(json.dumps({
            "schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": key}],
            "signature": {"require_expected_signer": True}}), encoding="utf-8")
        (repo / ".proofbundle" / "evidence.json").write_text(json.dumps({
            "schema": gate.DECLARATION_SCHEMA,
            "evidence": [{"kind": "bundle", "path": ".proofbundle/b.json", "policy": ".proofbundle/policy.json",
                          "subject": subject}]}), encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "evidence")
    return repo


def _run(env: dict, repo: pathlib.Path, *args: str, command: str = "git push origin main",
         tool: str = "Bash") -> dict | None:
    tool_input = {"command": command} if tool == "Bash" else {"owner": "o", "repo": "r", "title": "t"}
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo),
                        "tool_input": tool_input})
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
        assert set(specific) == {"hookEventName", "additionalContext"}
        assert set(answer) == {"systemMessage", "hookSpecificOutput"}
        return "pass"
    assert specific["permissionDecisionReason"].strip()
    return "deny"


INACTIVE = "The gate is not active in this repository, because nothing is declared."


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_both_hosts_a_repository_that_declares_nothing_gets_no_decision(shim, tmp_path):
    repo = _repo(tmp_path, declare=False)
    claude = _run(shim, repo)
    codex = _run(shim, repo, "--host", "codex")
    assert codex == claude, "the same answer under both hosts"
    assert _codex_valid(codex) == "pass", "Codex accepts an answer without a decision"
    assert "permissionDecision" not in codex["hookSpecificOutput"]
    assert codex["systemMessage"].startswith("NOT MEASURED:")
    assert INACTIVE in codex["systemMessage"]
    assert codex["hookSpecificOutput"]["additionalContext"] == codex["systemMessage"]
    assert "Codex cannot ask" not in codex["systemMessage"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_codex_a_declaration_only_in_the_working_tree_is_denied_as_not_measured(shim, tmp_path):
    repo = _repo(tmp_path, declare=False)
    (repo / ".proofbundle").mkdir()
    (repo / ".proofbundle" / "evidence.json").write_text(json.dumps(
        {"schema": gate.DECLARATION_SCHEMA, "evidence": []}), encoding="utf-8")
    claude = _run(shim, repo)
    assert claude["hookSpecificOutput"]["permissionDecision"] == "ask"
    codex = _run(shim, repo, "--host", "codex")
    assert _codex_valid(codex) == "deny"
    assert codex["hookSpecificOutput"]["permissionDecisionReason"].startswith("NOT MEASURED:")
    assert "not committed" in codex["systemMessage"]
    assert "Codex cannot ask" in codex["systemMessage"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_codex_every_other_not_measured_case_is_still_denied(shim, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    _git(fresh, "init", "-q")
    empty = _repo(tmp_path / "empty", declare=False)
    (empty / ".proofbundle").mkdir()
    (empty / ".proofbundle" / "evidence.json").write_text(json.dumps(
        {"schema": gate.DECLARATION_SCHEMA, "evidence": []}), encoding="utf-8")
    _git(empty, "add", "-A")
    _git(empty, "commit", "-q", "-m", "empty declaration")
    cases = [(plain, "git push"), (fresh, "git push"), (empty, "git push"),
             (_repo(tmp_path / "unresolved", declare=False), "cd $SOMEWHERE && git push")]
    for where, command in cases:
        codex = _run(shim, where, "--host", "codex", command=command)
        assert _codex_valid(codex) == "deny", (where, command)
        assert codex["hookSpecificOutput"]["permissionDecisionReason"].startswith("NOT MEASURED:")
        claude = _run(shim, where, command=command)
        assert claude["hookSpecificOutput"]["permissionDecision"] == "ask", (where, command)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_codex_a_tampered_bundle_is_denied_and_a_verified_one_passes(shim, tmp_path):
    assert _codex_valid(_run(shim, _repo(tmp_path / "a", declare=True, tamper=True), "--host", "codex")) == "deny"
    verified = _run(shim, _repo(tmp_path / "b", declare=True), "--host", "codex")
    assert _codex_valid(verified) == "pass"
    assert "declared items verified" in verified["systemMessage"]


def test_under_codex_a_call_the_gate_does_not_know_gets_no_answer(shim, tmp_path):
    assert _run(shim, tmp_path, "--host", "codex", command="ls -la") is None
    assert _run(shim, tmp_path, "--host", "codex", tool="mcp__github__delete_file") is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_under_codex_an_mcp_pull_request_is_gated_like_a_push(shim, tmp_path):
    undeclared = _run(shim, _repo(tmp_path / "a", declare=False), "--host", "codex",
                      tool="mcp__github__create_pull_request")
    assert _codex_valid(undeclared) == "pass"
    assert undeclared["systemMessage"].startswith("NOT MEASURED:") and INACTIVE in undeclared["systemMessage"]
    declared = _run(shim, _repo(tmp_path / "b", declare=True), "--host", "codex", tool="mcp__gitlab__create_merge_request")
    assert _codex_valid(declared) == "pass"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
@pytest.mark.parametrize("tool", ["mcp__github__push_files", "mcp__github__create_or_update_file",
                                  "mcp__github__merge_pull_request"])
def test_under_codex_an_mcp_write_or_merge_is_gated_like_a_push(shim, tmp_path, tool):
    import re  # noqa: PLC0415
    assert re.search(_codex_hook_matcher(), tool)
    undeclared = _run(shim, _repo(tmp_path / "a", declare=False), "--host", "codex", tool=tool)
    assert _codex_valid(undeclared) == "pass"
    assert undeclared["systemMessage"].startswith("NOT MEASURED:") and INACTIVE in undeclared["systemMessage"]
    assert _codex_valid(_run(shim, _repo(tmp_path / "b", declare=True), "--host", "codex", tool=tool)) == "pass"


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
                          cwd=PLUGIN / server["cwd"], env=dict(shim, **server["env"]), timeout=60, check=False)
    reply = json.loads(proc.stdout.splitlines()[0])
    assert reply["result"]["serverInfo"]["name"] == "proofbundle"


def _verify_result(env: dict, bundle_path: pathlib.Path) -> dict:
    lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
             {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "verify_receipt", "arguments": {"kind": "bundle", "path": str(bundle_path)}}}]
    proc = subprocess.run([sys.executable, str(SERVER)], input="".join(json.dumps(m) + "\n" for m in lines),
                          capture_output=True, text=True, env=env, timeout=60, check=False)
    reply = [json.loads(line) for line in proc.stdout.splitlines()][1]
    return json.loads(reply["result"]["content"][0]["text"])


def test_under_codex_verify_says_it_cannot_see_whether_the_gate_ran(shim, tmp_path):
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps(emit_bundle(b"x", generate_signer())), encoding="utf-8")
    under_codex = _verify_result(dict(shim, PROOFBUNDLE_PLUGIN_HOST="codex"), bundle)
    note = under_codex["gate_note"]
    assert "trust" in note and "cannot see" in note and "ran" in note
    under_claude = _verify_result({k: v for k, v in shim.items() if k != "PROOFBUNDLE_PLUGIN_HOST"}, bundle)
    assert "gate_note" not in under_claude


def test_the_verify_skill_passes_the_note_on_and_never_claims_the_gate_ran():
    text = (PLUGIN / "skills" / "verify" / "SKILL.md").read_text(encoding="utf-8")
    assert "`gate_note`" in text
    assert "Never state that the pre-push gate ran" in text


# --- the runbook for the Mac run ---------------------------------------------------------------------

def test_the_mac_runbook_names_every_case_with_its_expected_answer():
    text = RUNBOOK.read_text(encoding="utf-8")
    scaffold = (PLUGIN / "evals" / "_fixtures" / "scaffold.sh").read_text(encoding="utf-8")
    rows = [line for line in text.split("\n") if line.startswith("| ") and "repo-" in line]
    modes = [row.split("|")[2].strip().strip("`") for row in rows]
    assert modes == ["repo-nodecl", "repo-worktree-only", "repo-tampered", "repo-missing", "repo-stale",
                     "repo-valid", "repo-valid"]
    for mode in set(modes):
        assert mode in scaffold, mode
    expected = [row.split("|")[4].strip() for row in rows]
    assert expected[0].startswith("no decision, NOT MEASURED")
    assert expected[1:5] == ["deny, NOT MEASURED", "deny", "deny", "deny"]
    assert expected[5].startswith("no decision")
    assert "NOT MEASURED" in text and "gate did not run" in text
    assert f"`{gate.MCP_MATCHER}`" in text, "the runbook names the matcher the manifests carry"


def _runbook_rows() -> list[tuple[str, str, str, list[str]]]:
    rows = []
    for line in RUNBOOK.read_text(encoding="utf-8").split("\n"):
        cells = [c.strip() for c in line.split("|")]
        if line.startswith("| ") and "repo-" in line and cells[3] == "trusted":
            quoted = [part for cell in cells[4:6] for n, part in enumerate(cell.split("`")) if n % 2]
            rows.append((cells[1], cells[2].strip("`"), cells[4], quoted))
    return rows


@pytest.mark.skipif(shutil.which("git") is None or shutil.which("bash") is None, reason="git or bash missing")
@pytest.mark.parametrize("case, mode, expected, quoted", _runbook_rows(), ids=[r[0] for r in _runbook_rows()])
def test_every_runbook_case_gets_from_the_gate_the_answer_its_row_expects(shim, tmp_path, case, mode, expected, quoted):
    """The runbook's expected answers, measured without Codex: its scaffold, the gate under --host codex."""
    work = tmp_path / "w"
    work.mkdir()
    subprocess.run(["bash", str(PLUGIN / "evals" / "_fixtures" / "scaffold.sh"), mode], cwd=work, check=True,
                   capture_output=True)
    answer = _run(shim, work, "--host", "codex")
    got = _codex_valid(answer)
    assert got == ("deny" if expected.startswith("deny") else "pass"), (case, answer)
    for text in quoted:
        if text not in ("NOT MEASURED:",):
            assert text in answer["systemMessage"], (case, text)
    if "NOT MEASURED" in expected:
        assert answer["systemMessage"].startswith("NOT MEASURED:"), case
    if "not active" in expected:
        assert INACTIVE in answer["systemMessage"], case
