"""The pre-tool gate of the proofbundle plugin (plugins/proofbundle/hooks).

The gate runs before every shell call. For git push, gh pr create and gh release create it verifies
the evidence the repository declares at HEAD, through the plugin's MCP server, and answers deny, ask or
nothing. These tests run the gate as the host runs it, a separate process fed one event on stdin, and
replace only `uv` by a shim that starts the same server with this interpreter and this checkout.

Properties checked:
- a gated call is found in the forms a shell accepts (chains, nesting, wrappers, directory changes),
  and a call the gate does not know is left alone;
- an MCP tool that opens a pull request, a merge request or a release is gated by name, through a
  second matcher, and an MCP tool the gate does not know gets no answer;
- every declared item names the proofbundle-tree-sha256/v1 digest of the tree at HEAD, both in the
  declaration and inside the signed evidence; a missing, stale or unsigned subject is denied;
- the gate never answers allow: a pass carries no permission decision;
- a repository that declares nothing, or a call whose repository the gate cannot resolve, is answered
  ask and NOT MEASURED, never a pass;
- tampered, missing, unpinned or unverifiable evidence, a malformed declaration, a verifier that cannot
  start and unreadable hook input are answered deny;
- the gate reads HEAD, not the working tree;
- the hook entry blocks the call when the gate itself cannot run, and its timeout exceeds the gate's
  own deadline, so a host that lets a timed-out hook pass never gets the chance.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import proofbundle
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
HOOKS = PLUGIN / "hooks" / "hooks.json"

# Import the gate without leaving a __pycache__ in the plugin folder, which a host copies on install.
_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _b64(key) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def _git(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


def _commit(repo: pathlib.Path, message: str = "c") -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)


def _write(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _pinned_policy(key) -> dict:
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "gate-test",
            "allowed_issuers": [{"public_key_b64": _b64(key)}], "signature": {"require_expected_signer": True}}


def _declare(repo: pathlib.Path, *items: dict) -> None:
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": list(items)})


def _subject(digest: str) -> dict:
    return {"algorithm": gate.TREE_ALGORITHM, "digest": digest}


def _statement(digest: str) -> bytes:
    """The payload a bundle signs to name its tree subject."""
    return json.dumps({"subject": _subject(digest)}).encode()


def _head_digest(repo: pathlib.Path) -> str:
    return gate.tree_digest(str(repo), "HEAD")


def _tamper_bundle(path: pathlib.Path) -> None:
    bundle = json.loads(path.read_text())
    raw = bytearray(base64.b64decode(bundle["payload_b64"]))
    raw[0] ^= 1
    bundle["payload_b64"] = base64.b64encode(bytes(raw)).decode()
    path.write_text(json.dumps(bundle))


BUNDLE = ".proofbundle/build.bundle.json"
POLICY = ".proofbundle/policy.json"


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository whose HEAD declares one bundle over its own tree, signed by the key its policy pins.

    The code is committed first, its tree digest computed, and the evidence committed on top under
    .proofbundle/, which the digest leaves out, so the second commit has the digest the evidence names.
    """
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "README.md", "release\n")
    _write(path / "src" / "app.py", "print('hi')\n")
    _commit(path)
    digest = _head_digest(path)
    signer = generate_signer()
    _write(path / BUNDLE, emit_bundle(_statement(digest), signer))
    _write(path / POLICY, _pinned_policy(signer))
    _declare(path, {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": _subject(digest)})
    _commit(path)
    assert _head_digest(path) == digest
    return path


@pytest.fixture
def shim(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    # The gate calls `uv run --quiet --script <server>`; the shim drops the three options.
    uv.write_text(f'#!/bin/sh\nshift 3\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    uv.chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    env = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    return env


def run_gate(env: dict, cwd: pathlib.Path | str, command: str, *, raw: str | None = None) -> dict | None:
    event = raw if raw is not None else json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd), "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, str(GATE)], input=event, capture_output=True, text=True,
                          env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def decision(answer: dict | None) -> str:
    assert answer is not None, "a gated call must be answered"
    specific = answer["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse"
    assert answer["systemMessage"] == specific["additionalContext"]
    got = specific.get("permissionDecision", "pass")
    assert got in ("deny", "ask", "pass"), "the gate must never answer allow"
    if got != "pass":
        assert specific["permissionDecisionReason"] == answer["systemMessage"]
    return got


def reason(answer: dict) -> str:
    return answer["systemMessage"]


# --- which calls are gated ---------------------------------------------------------------------------

@pytest.mark.parametrize("command, expected", [
    ("git push", [("git push", ".")]),
    ("git push origin main --tags", [("git push", ".")]),
    ("git -c push.default=simple push", [("git push", ".")]),
    ("git --no-pager push", [("git push", ".")]),
    ("/usr/bin/git push", [("git push", ".")]),
    ("git-push origin", [("git push", ".")]),
    ("FOO=1 sudo command git push", [("git push", ".")]),
    ("make && git push", [("git push", ".")]),
    ("git status\ngit push", [("git push", ".")]),
    ("x=$(git push)", [("git push", ".")]),
    ("`git push`", [("git push", ".")]),
    ("bash -c 'git push'", [("git push", ".")]),
    ("echo 'git push'", [("git push", ".")]),
    ("gh pr create --fill", [("gh pr create", ".")]),
    ("gh pr new", [("gh pr new", ".")]),
    ("gh -R owner/repo pr create", [("gh pr create", ".")]),
    ("gh release create v1.0.0", [("gh release create", ".")]),
    ("gh release new v1", [("gh release new", ".")]),
    ("cd sub && git push", [("git push", "sub")]),
    ("sh -c 'cd sub; git push'", [("git push", "sub")]),
    ("git -C ../other push", [("git push", "../other")]),
    ("cd $HOME && git push", [("git push", gate.UNKNOWN)]),
    ("git --git-dir=x push", [("git push", gate.UNKNOWN)]),
    ("popd; git push", [("git push", gate.UNKNOWN)]),
    ("git commit -m 'no closing quote; git push", [("unparsed command", gate.UNKNOWN)]),
])
def test_a_gated_call_is_found_in_every_shell_form(command, expected):
    assert gate.gated_calls(command) == expected


@pytest.mark.parametrize("command", [
    "git status", "git stash push", "git log --grep push", "git config push.default simple",
    "git -c a=b status push", "gh pr view 3", "gh pr list", "gh release list", "npm publish", "ls -la",
    "git commit -m 'no closing quote",
])
def test_a_call_the_gate_does_not_know_is_left_alone(command):
    assert gate.gated_calls(command) == []


# --- the declaration ---------------------------------------------------------------------------------

KEY = base64.b64encode(bytes(range(32))).decode()
SUBJ = {"algorithm": "proofbundle-tree-sha256/v1", "digest": "ab" * 32}
GOOD_BUNDLE = {"kind": "bundle", "path": ".proofbundle/b.json", "policy": ".proofbundle/p.json", "subject": SUBJ}
GOOD_DECISION = {"kind": "decision", "path": ".proofbundle/d.json", "public_key": KEY, "subject": SUBJ}


def _declaration(evidence, **extra) -> bytes:
    return json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": evidence, **extra}).encode()


def test_a_well_formed_declaration_is_read_exactly():
    items = gate.parse_declaration(_declaration([GOOD_BUNDLE, GOOD_DECISION]))
    assert items == [GOOD_BUNDLE, GOOD_DECISION]
    assert gate.parse_declaration(_declaration([])) == []
    assert gate.DECLARATION_SCHEMA == "proofbundle-plugin/evidence/v0.2"


@pytest.mark.parametrize("raw", [
    b"not json", b"[]", b'{"schema": "x", "evidence": []}',
    _declaration([], extra=1),
    b'{"schema": "proofbundle-plugin/evidence/v0.2", "schema": "proofbundle-plugin/evidence/v0.2", "evidence": []}',
    b'{"schema": "proofbundle-plugin/evidence/v0.1", "evidence": []}',
    _declaration({}), _declaration([GOOD_BUNDLE] * (gate.MAX_ITEMS + 1)),
    _declaration([dict(GOOD_BUNDLE, note="x")]), _declaration([dict(GOOD_BUNDLE, kind="statement")]),
    _declaration([dict(GOOD_BUNDLE, path="/etc/passwd")]), _declaration([dict(GOOD_BUNDLE, path="../x.json")]),
    _declaration([dict(GOOD_BUNDLE, path="./.proofbundle/b.json")]),
    _declaration([dict(GOOD_BUNDLE, path=".proofbundle//b.json")]),
    _declaration([dict(GOOD_BUNDLE, path=".proofbundle\\b.json")]), _declaration([dict(GOOD_BUNDLE, path="")]),
    _declaration([dict(GOOD_BUNDLE, path=5)]),
    _declaration([{"kind": "bundle", "path": ".proofbundle/b.json", "subject": SUBJ}]),
    _declaration([dict(GOOD_BUNDLE, public_key=KEY)]),
    _declaration([{"kind": "decision", "path": ".proofbundle/d.json", "subject": SUBJ}]),
    _declaration([dict(GOOD_DECISION, public_key=base64.b64encode(b"short").decode())]),
    _declaration([dict(GOOD_DECISION, public_key="not base64!")]),
    _declaration([dict(GOOD_DECISION, policy="../p")]),
    # the evidence and its policy live under .proofbundle/, which the tree digest leaves out
    _declaration([dict(GOOD_BUNDLE, path="evidence/b.json")]),
    _declaration([dict(GOOD_BUNDLE, policy="policy.json")]),
    _declaration([dict(GOOD_BUNDLE, path=".proofbundle")]),
    # every item names its tree subject, exactly
    _declaration([{k: v for k, v in GOOD_BUNDLE.items() if k != "subject"}]),
    _declaration([dict(GOOD_BUNDLE, subject=None)]),
    _declaration([dict(GOOD_BUNDLE, subject="ab" * 32)]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, algorithm="sha256"))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, algorithm="git-tree"))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, digest="AB" * 32))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, digest="ab" * 20))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, note="x"))]),
    # an outcome receipt has no field that can carry a tree subject
    _declaration([dict(GOOD_DECISION, kind="outcome")]),
])
def test_a_malformed_declaration_is_refused(raw):
    with pytest.raises(gate.GateError):
        gate.parse_declaration(raw)


# --- the answers -------------------------------------------------------------------------------------

def test_a_call_the_gate_does_not_know_gets_no_answer(shim, repo):
    assert run_gate(shim, repo, "git status && ls") is None


def test_declared_evidence_that_verifies_gets_no_permission_decision(shim, repo):
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "pass"
    assert "1 of 1 declared items verified" in reason(answer)
    assert "not that the recorded values are true" in reason(answer)


def _decision(shim: dict, signer, *snapshot: dict) -> dict:
    template = json.loads(subprocess.run([sys.executable, "-m", "proofbundle.cli", "decision", "init"],
                                         capture_output=True, text=True, check=True, env=shim).stdout)
    template["inputSnapshot"] = list(template["inputSnapshot"]) + list(snapshot)
    return emit_decision_receipt(template, signer)


def _tree_input(digest: str) -> dict:
    return {"name": "tree", "uri": gate.TREE_SUBJECT_URI, "digest": {"sha256": digest}}


def test_a_decision_receipt_under_its_pinned_key_passes_and_under_another_key_is_denied(shim, repo, tmp_path):
    signer = generate_signer()
    digest = _head_digest(repo)
    _write(repo / ".proofbundle" / "release.decision.json", _decision(shim, signer, _tree_input(digest)))
    item = {"kind": "decision", "path": ".proofbundle/release.decision.json", "public_key": _b64(signer),
            "subject": _subject(digest)}
    _declare(repo, item)
    _commit(repo)
    assert decision(run_gate(shim, repo, "gh release create v1")) == "pass"
    _declare(repo, dict(item, public_key=_b64(generate_signer())))
    _commit(repo)
    answer = run_gate(shim, repo, "gh release create v1")
    assert decision(answer) == "deny"
    assert "verification failed" in reason(answer)


def test_a_decision_receipt_that_does_not_name_the_tree_in_its_signed_inputs_is_denied(shim, repo):
    signer = generate_signer()
    digest = _head_digest(repo)
    item = {"kind": "decision", "path": ".proofbundle/release.decision.json", "public_key": _b64(signer),
            "subject": _subject(digest)}
    _write(repo / ".proofbundle" / "release.decision.json", _decision(shim, signer))
    _declare(repo, item)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "names no tree subject" in reason(answer)
    _write(repo / ".proofbundle" / "release.decision.json", _decision(shim, signer, _tree_input("cd" * 32)))
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "signed evidence names" in reason(answer)


# --- the tree subject --------------------------------------------------------------------------------

def test_evidence_signed_for_an_older_tree_is_denied(shim, repo):
    _write(repo / "src" / "app.py", "print('changed after signing')\n")
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "does not match the tree at HEAD" in reason(answer)
    assert _head_digest(repo) in reason(answer)


def test_a_declared_subject_the_signature_does_not_cover_is_denied(shim, repo):
    """Updating the declaration to the new digest does not help: the signed payload still names the old one."""
    _write(repo / "src" / "app.py", "print('changed after signing')\n")
    _commit(repo)
    declaration = json.loads((repo / gate.DECLARATION).read_text())
    declaration["evidence"][0]["subject"] = _subject(_head_digest(repo))
    _write(repo / gate.DECLARATION, declaration)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "signed evidence names" in reason(answer)


@pytest.mark.parametrize("payload", [b"release bytes", b"{}", b'{"subject": "x"}',
                                     b'{"subject": {"algorithm": "proofbundle-tree-sha256/v1"}}'])
def test_a_bundle_whose_payload_is_not_a_subject_statement_is_denied(shim, repo, payload):
    signer = generate_signer()
    _write(repo / BUNDLE, emit_bundle(payload, signer))
    _write(repo / POLICY, _pinned_policy(signer))
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "names no tree subject" in reason(answer)


def test_a_change_inside_the_evidence_folder_keeps_the_pass(shim, repo):
    _write(repo / ".proofbundle" / "notes.md", "an added note\n")
    _commit(repo)
    assert decision(run_gate(shim, repo, "git push")) == "pass"


def test_the_pass_names_the_tree_it_verified(shim, repo):
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "pass"
    assert f"{gate.TREE_ALGORITHM} {_head_digest(repo)}" in reason(answer)


def test_a_tampered_bundle_at_head_is_denied(shim, repo):
    _tamper_bundle(repo / BUNDLE)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "exit 1" in reason(answer)


def test_the_gate_reads_head_not_the_working_tree(shim, repo):
    _tamper_bundle(repo / BUNDLE)
    _write(repo / "src" / "app.py", "print('uncommitted')\n")
    assert decision(run_gate(shim, repo, "git push")) == "pass"
    (repo / gate.DECLARATION).unlink()
    assert decision(run_gate(shim, repo, "git push")) == "pass"


def test_a_declared_bundle_missing_at_head_is_denied(shim, repo):
    _git(repo, "rm", "-q", BUNDLE)
    _commit(repo)
    answer = run_gate(shim, repo, "gh pr create --fill")
    assert decision(answer) == "deny"
    assert "missing at HEAD" in reason(answer)


def test_a_bundle_signed_by_a_key_the_policy_does_not_pin_is_denied(shim, repo):
    _write(repo / POLICY, _pinned_policy(generate_signer()))
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "exit 3" in reason(answer) or "exit 1" in reason(answer)


@pytest.mark.parametrize("policy", [
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p"},
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [],
     "signature": {"require_expected_signer": True}},
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": KEY}]},
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": KEY}],
     "signature": {"require_expected_signer": "true"}},
    "not json",
])
def test_a_bundle_policy_that_pins_no_signer_is_denied(shim, repo, policy):
    _write(repo / POLICY, policy)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "pin a signer" in reason(answer) or "is not JSON" in reason(answer)


def test_a_malformed_declaration_is_denied(shim, repo):
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [{"kind": "bundle"}]})
    _commit(repo)
    assert decision(run_gate(shim, repo, "git push")) == "deny"


def test_a_repository_without_a_declaration_is_not_measured_and_asks(shim, repo):
    _git(repo, "rm", "-q", "-r", ".proofbundle")
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")
    _declare(repo, GOOD_BUNDLE)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert "not committed" in reason(answer)


def test_an_empty_declaration_is_not_measured_and_asks(shim, repo):
    _declare(repo)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")


def test_a_directory_without_a_repository_or_a_commit_is_not_measured(shim, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert decision(run_gate(shim, plain, "git push")) == "ask"
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    _git(fresh, "init", "-q")
    answer = run_gate(shim, fresh, "git push")
    assert decision(answer) == "ask"
    assert "no commit at HEAD" in reason(answer)


def test_a_call_whose_repository_cannot_be_resolved_is_not_measured(shim, repo):
    answer = run_gate(shim, repo, "cd $SOMEWHERE && git push")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")


def test_the_repository_a_directory_change_names_is_the_one_checked(shim, repo, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    _commit(other)
    assert decision(run_gate(shim, repo, "git push")) == "pass"
    assert decision(run_gate(shim, repo, f"cd {other} && git push")) == "ask"
    assert decision(run_gate(shim, other, f"git -C {repo} push")) == "pass"


def test_one_failing_repository_denies_the_whole_call(shim, repo, tmp_path):
    other = tmp_path / "other"
    shutil.copytree(repo, other)
    _tamper_bundle(other / BUNDLE)
    _commit(other)
    assert decision(run_gate(shim, repo, f"git push && git -C {other} push")) == "deny"


def test_a_verifier_that_cannot_start_denies(shim, repo, tmp_path):
    no_uv = dict(shim, PATH=os.pathsep.join(p for p in shim["PATH"].split(os.pathsep) if not (pathlib.Path(p) / "uv").exists()))
    answer = run_gate(no_uv, repo, "git push")
    assert decision(answer) == "deny"
    assert "uv is not on PATH" in reason(answer)
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "uv").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (broken / "uv").chmod(0o755)
    answer = run_gate(dict(shim, PATH=os.pathsep.join([str(broken), no_uv["PATH"]])), repo, "git push")
    assert decision(answer) == "deny"
    assert "no answer" in reason(answer)


@pytest.mark.parametrize("raw", ["not json", "[]", '{"tool_input": {}}', '{"tool_input": {"command": 5}}'])
def test_unreadable_hook_input_is_denied(shim, repo, raw):
    assert decision(run_gate(shim, repo, "", raw=raw)) == "deny"


def test_a_codex_style_argument_vector_is_read_as_a_command(shim, repo):
    event = json.dumps({"cwd": str(repo), "tool_input": {"command": ["bash", "-lc", "git push"]}})
    assert decision(run_gate(shim, repo, "", raw=event)) == "pass"


# --- MCP tools ---------------------------------------------------------------------------------------

def _mcp_event(repo: pathlib.Path | str, tool: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo),
                       "tool_input": {"owner": "o", "repo": "r", "title": "t", "head": "main", "base": "main"}})


GATED_MCP = ["mcp__github__create_pull_request", "mcp__plugin_x_github__create_pull_request",
             "mcp__gitlab__create_merge_request", "mcp__gitea__create_release", "mcp__a__b__create_release"]
UNGATED_MCP = ["mcp__github__push_files", "mcp__github__create_or_update_file", "mcp__github__merge_pull_request",
               "mcp__github__create_branch", "mcp__github__update_pull_request", "mcp__github__create_issue",
               "mcp__github__create_pull_request_review", "mcp__github__create_pull_request_x",
               "Bash_create_pull_request", "create_pull_request", "mcp__create_pull_request"]


def test_the_mcp_matcher_names_exactly_the_gated_tools():
    import re  # noqa: PLC0415
    assert gate.MCP_GATED_TOOLS == ("create_pull_request", "create_merge_request", "create_release")
    for tool in GATED_MCP:
        assert re.search(gate.MCP_MATCHER, tool), tool
        assert gate.mcp_gated(tool)
    for tool in UNGATED_MCP:
        assert not re.search(gate.MCP_MATCHER, tool), tool
        assert not gate.mcp_gated(tool)


@pytest.mark.parametrize("tool", GATED_MCP)
def test_an_mcp_tool_that_opens_a_pull_request_or_a_release_is_gated(shim, repo, tool):
    answer = run_gate(shim, repo, "", raw=_mcp_event(repo, tool))
    assert decision(answer) == "pass"
    assert "MCP" in reason(answer) and "the local repository" in reason(answer)
    _write(repo / "src" / "app.py", "print('changed after signing')\n")
    _commit(repo)
    assert decision(run_gate(shim, repo, "", raw=_mcp_event(repo, tool))) == "deny"


def test_an_mcp_pull_request_without_declared_evidence_is_not_measured(shim, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    _git(plain, "init", "-q", "-b", "main")
    _commit(plain)
    answer = run_gate(shim, plain, "", raw=_mcp_event(plain, "mcp__github__create_pull_request"))
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")


@pytest.mark.parametrize("tool", [t for t in UNGATED_MCP if t.startswith("mcp__")])
def test_an_mcp_tool_the_gate_does_not_know_gets_no_answer(shim, repo, tool):
    assert run_gate(shim, repo, "", raw=_mcp_event(repo, tool)) is None


# --- the hook entry ----------------------------------------------------------------------------------

def _hook_entries() -> list[dict]:
    config = json.loads(HOOKS.read_text(encoding="utf-8"))
    assert set(config) <= {"description", "hooks"}
    groups = config["hooks"]["PreToolUse"]
    assert [g["matcher"] for g in groups] == ["Bash", gate.MCP_MATCHER]
    assert groups[0]["hooks"] == groups[1]["hooks"], "both matchers run the same gate the same way"
    return groups[0]["hooks"]


def test_the_hook_runs_the_gate_on_every_shell_call_with_room_for_its_deadline():
    (entry,) = _hook_entries()
    assert entry["type"] == "command"
    assert "if" not in entry, "an if filter would let compound and nested forms of a gated call pass"
    assert '"${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"' in entry["command"]
    assert entry["timeout"] > gate.DEADLINE_SECONDS


def test_the_hook_blocks_the_call_when_the_gate_cannot_run(tmp_path, repo):
    (entry,) = _hook_entries()
    event = json.dumps({"cwd": str(repo), "tool_input": {"command": "git status"}})
    ok = subprocess.run(["sh", "-c", entry["command"]], input=event, capture_output=True, text=True,
                        env=dict(os.environ, CLAUDE_PLUGIN_ROOT=str(PLUGIN)), check=False)
    assert (ok.returncode, ok.stdout) == (0, "")
    missing = subprocess.run(["sh", "-c", entry["command"]], input=event, capture_output=True, text=True,
                             env=dict(os.environ, CLAUDE_PLUGIN_ROOT=str(tmp_path / "gone")), check=False)
    assert missing.returncode == 2
    assert "blocked" in missing.stderr
