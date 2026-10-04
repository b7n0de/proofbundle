"""Review Runde 12 (stand 1ae19b85): one regression test per finding, each exactly the review's case, at the gate
exit on both host paths.

R12-1: quote and escape spellings (g\\it, g'it', "git", "gh") fell through both checks; the net now reads a normal
form of the whole command (quotes and backslashes removed, $'…'/$"…' shell dropped, only A-Z lower-cased in place),
so each is NOT MEASURED. R12-2: a recognised push no longer masks a further git/gh command word — the net always
runs and every command word must map to a resolved call, else NOT MEASURED, never pass or inactive. R12-3: U+0130
before an ASCII call no longer slips through, because search and word boundaries read the one normal form. R12-4:
the verifier reader refuses a non-integer id, a reply that is not exactly one of result/error, and a line that is
not a JSON-RPC 2.0 message, keeps the envelope's isError authoritative, and counts exit_code only as a real integer.
Red against 1ae19b85, green after. Each finding also has its catch proof in the mutation run (n30/fang).
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

import proofbundle
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                          check=True, capture_output=True, text=True, timeout=60)


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
    return repo


def _repo_tracking(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repo whose `main` tracks `origin/main` at HEAD: a plain `git push origin main` has a known target and
    nothing new to send, so the gate resolves it and, with no evidence declaration, returns `inactive` under
    Claude (the state the review's R12-2 push started from)."""
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, timeout=60)
    repo = _repo(tmp_path)
    _git(repo, "remote", "add", "origin", str(bare))
    _git(repo, "push", "-q", "origin", "main")
    _git(repo, "branch", "--set-upstream-to=origin/main", "main")
    return repo


def _hook(repo: pathlib.Path, logs: pathlib.Path, host: str, command: str) -> tuple[str | None, list[str]]:
    """Run the gate as the host runs it: the permission decision of its JSON answer (None for no decision, i.e.
    a pass, an inactive gate or a call it does not gate) and the reason ids of its log line."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs)}
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer.get("hookSpecificOutput", {}).get("permissionDecision"), entry["reason_ids"]


def _gated(repo, logs_root, command, reason=None):
    """Assert the command is gated at the exit on both hosts: ask under Claude, deny under Codex. When `reason`
    is given, it is among the Claude log's reason ids."""
    d_claude, ids = _hook(repo, logs_root / "claude", "claude", command)
    d_codex, _ = _hook(repo, logs_root / "codex", "codex", command)
    assert d_claude == "ask", (command, d_claude, ids)
    assert d_codex == "deny", (command, d_codex)
    if reason is not None:
        assert reason in ids, (command, ids)
    return ids


# --- R12-1: quote and escape spellings reach the net (both host paths) --------------------------------------------
@pytest.mark.parametrize("command", [
    r": $'x'; g\it push origin main",      # a backslash in the middle of the word
    r": $'x'; g'it' push origin main",     # single quotes in the middle of the word
    r'true # ; "git" push origin main',    # a double-quoted git in a comment (zsh changed-comment-char case)
    r'"gh" pr list',                       # a double-quoted gh
    r'"gh" api --method POST /repos/o/r/issues -f title=x',
    r"gh api --method POST /repos/o/r/issues -f title=x",
])
def test_r12_1_quote_and_escape_spellings_are_not_measured(tmp_path, command):
    """R12-1: each hidden spelling is NOT MEASURED on both host paths (ask under Claude, deny under Codex); at
    1ae19b85 the escaped and quoted forms returned no decision."""
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason="net_unmodeled_git")


@pytest.mark.parametrize("command", ["git push origin main", "gh pr list"])
def test_r12_1_literal_controls_are_gated(tmp_path, command):
    """The literal controls are gated the same way, so the fix removes a difference, it does not add one."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


# --- R12-2: a recognised push does not mask a further command word ------------------------------------------------
def test_r12_2_a_hidden_second_call_in_a_comment_is_not_measured(tmp_path):
    """R12-2: `git push … # ; git config …` resolved to inactive at 1ae19b85 because the comment was dropped
    before the net ran. Now the net always runs and sees the second `git` command word, so the whole command is
    NOT MEASURED: ask under Claude, deny under Codex."""
    repo = _repo_tracking(tmp_path)
    _gated(repo, tmp_path / "logs", "git push origin main # ; git config proofbundle.reviewMarker changed",
           reason="net_unmodeled_git")


def test_r12_2_the_clean_push_control_is_still_inactive_under_claude(tmp_path):
    """Control: the same push without the hidden second call is one command word and one resolved call, so the
    gate still returns inactive under Claude (no permission decision) and denies under Codex (push unbound)."""
    repo = _repo_tracking(tmp_path)
    d_claude, ids = _hook(repo, tmp_path / "logs" / "claude", "claude", "git push origin main")
    d_codex, _ = _hook(repo, tmp_path / "logs" / "codex", "codex", "git push origin main")
    assert d_claude is None, (d_claude, ids)          # inactive: nothing declared, no decision
    assert "net_unmodeled_git" not in ids, ids
    assert d_codex == "deny", d_codex


def test_r12_2_the_control_without_the_hash_asks(tmp_path):
    """Control: without the `#` the `; git config …` is a real second command, an overmatch, NOT MEASURED."""
    repo = _repo_tracking(tmp_path)
    _gated(repo, tmp_path / "logs", "git push origin main ; git config proofbundle.reviewMarker changed")


# --- R12-3: Unicode lower-casing no longer shifts the net ---------------------------------------------------------
def test_r12_3_u0130_before_an_ascii_call_is_not_measured(tmp_path):
    """R12-3: U+0130 after `#` lower-cases to two code points; at 1ae19b85 that shifted the raw-text indices and
    the following `git` escaped the net. The normal form lower-cases only A-Z in place, so it is caught."""
    command = "true # İ ; git config proofbundle.reviewMarker changed"
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason="net_unmodeled_git")


def test_r12_3_the_ascii_control_is_caught_too(tmp_path):
    """Control with X in place of U+0130: already caught at 1ae19b85, still caught."""
    command = "true # X ; git config proofbundle.reviewMarker changed"
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason="net_unmodeled_git")


# --- R12-4: the verifier answer contract -------------------------------------------------------------------------
def _env(payload, *, isError=False, rid=1):
    return json.dumps({"jsonrpc": "2.0", "id": rid,
                       "result": {"isError": isError, "content": [{"type": "text", "text": json.dumps(payload)}]}})


_INIT_OK = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                             "serverInfo": {"name": "proofbundle", "version": "1"}}})


def _run_stream(monkeypatch, lines, *, init=True):
    """Drive verify_items over a crafted stream. A valid initialisation response (id 0) is prepended by default,
    as the real server sends one and verify_items now evaluates it (review Runde 14, R13-5); pass init=False to
    omit it."""
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = "".join(line + "\n" for line in ([_INIT_OK] + list(lines) if init else lines))
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, _o=out, **k: subprocess.CompletedProcess(a, 0, _o, ""))
    return gate.verify_items([{"kind": "bundle"}], time.monotonic() + 30)


_RED_ID_TRUE = json.dumps({"jsonrpc": "2.0", "id": True,
                           "result": {"isError": True, "content": [{"type": "text", "text": "{}"}]}})
_BOTH_RESULT_AND_ERROR = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"},
                                     "result": {"content": [{"type": "text", "text": "{}"}]}})


@pytest.mark.parametrize("lines", [
    [_RED_ID_TRUE, _env({"exit_code": 0})],              # boolean id then a green reply
    [_env({"exit_code": 0}), _RED_ID_TRUE],              # the other order
    [_BOTH_RESULT_AND_ERROR],                            # a reply with both result and error
    [json.dumps({"id": 1, "result": {"content": [{"type": "text", "text": "{}"}]}})],  # no jsonrpc 2.0
])
def test_r12_4_an_invalid_reply_object_refuses_the_whole_run(monkeypatch, lines):
    """R12-4: a non-integer id, a reply that is not exactly one of result/error, or a line that is not a JSON-RPC
    2.0 message refuses the whole run; a later valid reply does not heal it. At 1ae19b85 the first of these read
    as pass verified."""
    with pytest.raises(gate.GateError):
        _run_stream(monkeypatch, lines)


def test_r12_4_the_envelope_is_error_is_authoritative(monkeypatch):
    """R12-4: isError in the envelope stands even when the payload carries is_error false; the payload cannot
    weaken the tool-error status."""
    results = _run_stream(monkeypatch, [_env({"is_error": False, "exit_code": 0}, isError=True)])
    assert results[0]["is_error"] is True


def test_r12_4_exit_code_counts_only_as_a_real_integer(monkeypatch):
    """R12-4: exit_code false is not success, though bool == int 0 in Python. verify_items returns it verbatim;
    the evaluation treats a non-integer exit code as a failure."""
    results = _run_stream(monkeypatch, [_env({"exit_code": False})])
    ec = results[0]["exit_code"]
    assert not (isinstance(ec, int) and not isinstance(ec, bool) and ec == 0)


def test_r12_4_a_valid_stream_is_still_read(monkeypatch):
    """Control: a well-formed integer-id reply with a clean envelope is read as it is."""
    results = _run_stream(monkeypatch, [_env({"exit_code": 0})])
    assert results[0]["is_error"] is False and results[0]["exit_code"] == 0


# --- R12-4 at the gate exit: a crafted verifier stream drives the full ci-check verdict ---------------------------
_BUNDLE = ".proofbundle/build.bundle.json"
_POLICY = ".proofbundle/policy.json"


def _wr(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _declared_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repo whose HEAD declares one bundle over its own tree, signed by the key its policy pins — the gate
    reaches the verifier for it (mirrors tests/test_plugin_ci_check.py)."""
    repo = tmp_path / "declared"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _wr(repo / "README.md", "release\n")
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c")
    digest = gate.tree_digest(str(repo), "HEAD")
    subject = {"algorithm": gate.TREE_ALGORITHM, "digest": digest}
    signer = generate_signer()
    key = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
    _wr(repo / _BUNDLE, emit_bundle(json.dumps({"subject": subject}).encode(), signer))
    _wr(repo / _POLICY, {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "ci-test",
                         "allowed_issuers": [{"public_key_b64": key}],
                         "signature": {"require_expected_signer": True}})
    _wr(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA,
                                  "evidence": [{"kind": "bundle", "path": _BUNDLE, "policy": _POLICY,
                                                "subject": subject}]})
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "declare")
    return repo


def _uv_stream_env(tmp_path: pathlib.Path, replies: list[str]) -> dict:
    """PATH with a fake `uv` that ignores the request and emits REPLIES as the verifier's stdout — the review's
    own injection point ('ausschließlich als stdout des Prüferprozesses'), here driven to the gate exit."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stream = tmp_path / "stream.jsonl"
    stream.write_text("".join(line + "\n" for line in replies), encoding="utf-8")
    (bin_dir / "uv").write_text(f'#!/bin/sh\ncat > /dev/null\ncat "{stream}"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    env = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    return env


def _init_reply() -> str:
    return json.dumps({"jsonrpc": "2.0", "id": 0,
                       "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "serverInfo": {"name": "proofbundle", "version": "1"}}})


def _ci_check(env: dict, repo: pathlib.Path) -> int:
    proc = subprocess.run([sys.executable, str(GATE), "ci-check", "--repo", str(repo),
                           "--require-declaration", "true"], capture_output=True, text=True, env=env,
                          cwd=repo.parent, timeout=120, check=False)
    return proc.returncode


@pytest.mark.parametrize("payload, isError, note", [
    ({"exit_code": False, "proofbundle_version": "6.1.0"}, False, "exit_code false is not success"),
    ({"is_error": False, "exit_code": 0, "proofbundle_version": "6.1.0"}, True,
     "the envelope isError stands over a payload is_error false"),
])
def test_r12_4_crafted_stream_denies_at_the_gate_exit(tmp_path, payload, isError, note):
    """R12-4 at the gate exit: a verifier stream that at 1ae19b85 read as pass verified (exit 0) now fails the
    ci-check (exit 1). Injected as the verifier's stdout, exactly as the review measured it."""
    repo = _declared_repo(tmp_path)
    reply = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"isError": isError, "content": [{"type": "text", "text": json.dumps(payload)}]}})
    env = _uv_stream_env(tmp_path, [_init_reply(), reply])
    assert _ci_check(env, repo) == 1, note


def test_r12_4_crafted_valid_stream_passes_at_the_gate_exit(tmp_path):
    """Control: a clean verifier stream (integer id, isError false, exit_code 0) passes the ci-check (exit 0),
    so the denials above are not blanket."""
    repo = _declared_repo(tmp_path)
    reply = json.dumps({"jsonrpc": "2.0", "id": 1,
                        "result": {"isError": False,
                                   "content": [{"type": "text",
                                                "text": json.dumps({"exit_code": 0, "proofbundle_version": "6.1.0"})}]}})
    env = _uv_stream_env(tmp_path, [_init_reply(), reply])
    assert _ci_check(env, repo) == 0
