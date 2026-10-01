"""The gate's local log, the server's gate_status and the gate self-test (DECISIONS.md, D21).

Properties checked:
- every gate call appends one JSON line in the host's plugin data directory, a gated one with its
  actions, decision, reason ids, repository, HEAD and the sha256 of each evidence file it read, an
  ungated one with no action; the line carries no evidence content, no environment and no key;
- the directory is the first one the host names that is a writable directory: CLAUDE_PLUGIN_DATA under
  Claude Code, PLUGIN_DATA and then CLAUDE_PLUGIN_DATA under Codex; without one there is no log, and the
  answer is the same either way;
- the log rotates once above its size limit;
- gate_status reads the log the host names in the server's environment, says whether the gate ran in
  this session (by the host's session id, or since the server started), and says NOT MEASURED where it
  cannot read the log, with the gate note under Codex;
- the self-test pushes a stale-subject commit to a throwaway local bare remote on a tracked branch, which
  the gate denies; the check reports, observation-near, whether the gate logged that deny and whether the
  remote target moved ("Expected denial logged; test target unchanged." when the push was blocked, "...
  test target changed." when it was not, "Test target changed; no matching gate event observed." when the
  gate did not run, NOT MEASURABLE otherwise), with the limit that the log is local; it counts only its own
  deny, and refuses a work folder it did not create.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

import proofbundle
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
SERVER = PLUGIN / "server" / "proofbundle_mcp.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
ENTRY_KEYS = {"ts", "host", "gate_version", "session_id", "tool", "actions", "decision", "verdict", "reason_ids",
              "repos"}


def _git(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA", "PLUGIN_DATA",
                                                              "CLAUDE_CODE_SESSION_ID", "PROOFBUNDLE_PLUGIN_HOST")}
    clean["PATH"] = os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    return clean


def _declared_repo(tmp_path: pathlib.Path) -> tuple[pathlib.Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    subject = {"algorithm": gate.TREE_ALGORITHM, "digest": gate.tree_digest(str(repo), "HEAD")}
    signer = generate_signer()
    key = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
    (repo / ".proofbundle").mkdir()
    (repo / ".proofbundle" / "b.json").write_text(json.dumps(emit_bundle(json.dumps({"subject": subject}).encode(),
                                                                          signer)), encoding="utf-8")
    (repo / ".proofbundle" / "policy.json").write_text(json.dumps({
        "schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": key}],
        "signature": {"require_expected_signer": True}}), encoding="utf-8")
    (repo / ".proofbundle" / "evidence.json").write_text(json.dumps({
        "schema": gate.DECLARATION_SCHEMA, "evidence": [{"kind": "bundle", "path": ".proofbundle/b.json",
                                                         "policy": ".proofbundle/policy.json", "subject": subject}]}),
        encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "evidence")
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "remote.git"))
    _git(repo, "remote", "add", "origin", str(tmp_path / "remote.git"))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    return repo, key


def _gate(env: dict, cwd: pathlib.Path, command: str, *args: str, session: str = "s-1") -> tuple[dict | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "session_id": session, "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, str(GATE), *args], input=event, capture_output=True, text=True,
                          env=env, cwd=cwd, timeout=120, check=True)
    return (json.loads(proc.stdout) if proc.stdout.strip() else None), proc.stdout


def _lines(directory: pathlib.Path) -> list[dict]:
    path = directory / gate.LOG_NAME
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def test_a_gated_call_leaves_one_line_with_what_was_checked_and_nothing_else(env, tmp_path):
    repo, key = _declared_repo(tmp_path)
    data = tmp_path / "data"
    answer, _ = _gate(dict(env, CLAUDE_PLUGIN_DATA=str(data), SECRET_TOKEN="do-not-log"), repo, "git push")
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    (line,) = _lines(data)
    assert set(line) == ENTRY_KEYS
    assert (line["host"], line["gate_version"], line["session_id"], line["tool"]) == ("claude", "0.3.0", "s-1", "Bash")
    assert (line["actions"], line["decision"], line["verdict"], line["reason_ids"]) == (["git push"], "none", "pass", ["verified"])
    (entry,) = line["repos"]
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    assert (entry["path"], entry["head"]) == (str(repo), head)
    import hashlib  # noqa: PLC0415
    expected = [f".proofbundle/b.json sha256:{hashlib.sha256((repo / '.proofbundle' / 'b.json').read_bytes()).hexdigest()}",
                f".proofbundle/policy.json sha256:{hashlib.sha256((repo / '.proofbundle' / 'policy.json').read_bytes()).hexdigest()}"]
    assert entry["digests"] == expected
    raw = (data / gate.LOG_NAME).read_text(encoding="utf-8")
    assert key not in raw and "do-not-log" not in raw and "payload" not in raw and "signatures" not in raw


def test_an_ungated_call_is_logged_too_so_the_log_shows_the_hook_ran(env, tmp_path):
    data = tmp_path / "data"
    answer, stdout = _gate(dict(env, CLAUDE_PLUGIN_DATA=str(data)), tmp_path, "ls -la")
    assert answer is None and stdout == ""
    (line,) = _lines(data)
    assert (line["actions"], line["decision"], line["verdict"], line["repos"]) == ([], "none", "not_gated", [])


def test_a_deny_is_logged_with_its_reason_id(env, tmp_path):
    repo, _ = _declared_repo(tmp_path)
    (repo / "README.md").write_text("changed after signing\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "late change")
    data, first = tmp_path / "data", tmp_path / "first"
    answer, _ = _gate(dict(env, PLUGIN_DATA=str(first), CLAUDE_PLUGIN_DATA=str(data)), repo, "git push",
                      "--host", "codex")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _lines(data) == [], "under Codex the gate writes to PLUGIN_DATA first"
    (line,) = _lines(first)
    assert (line["host"], line["decision"], line["verdict"], line["reason_ids"]) == ("codex", "deny", "deny", ["stale_subject"])


@pytest.mark.parametrize("host, variables, used", [
    ("claude", {"CLAUDE_PLUGIN_DATA": "a"}, "a"),
    ("claude", {"PLUGIN_DATA": "a"}, None),
    ("codex", {"PLUGIN_DATA": "a", "CLAUDE_PLUGIN_DATA": "b"}, "a"),
    ("codex", {"CLAUDE_PLUGIN_DATA": "b"}, "b"),
    ("codex", {}, None),
])
def test_the_log_goes_to_the_first_directory_the_host_names(tmp_path, host, variables, used):
    environ = {name: str(tmp_path / value) for name, value in variables.items()}
    got = gate.log_directory(host, environ)
    assert got == (str(tmp_path / used) if used else None)


def test_without_a_writable_directory_there_is_no_log_and_the_same_answer(env, tmp_path):
    repo, _ = _declared_repo(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.write_text("a file where the directory should be\n", encoding="utf-8")
    with_log, _ = _gate(dict(env, CLAUDE_PLUGIN_DATA=str(tmp_path / "data")), repo, "git push")
    without, _ = _gate(dict(env, CLAUDE_PLUGIN_DATA=str(blocked)), repo, "git push")
    relative, _ = _gate(dict(env, CLAUDE_PLUGIN_DATA="relative/dir"), repo, "git push")
    assert with_log == without == relative
    assert blocked.read_text(encoding="utf-8").startswith("a file")
    assert not (repo / "relative").exists(), "a relative directory is not a named place"


def test_the_log_rotates_once_above_its_limit(env, tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    (data / gate.LOG_NAME).write_text("x" * (gate.MAX_LOG_BYTES + 1), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    assert gate.write_log({"ts": "t"}, "claude") == str(data / gate.LOG_NAME)
    assert (data / (gate.LOG_NAME + ".1")).stat().st_size == gate.MAX_LOG_BYTES + 1
    assert json.loads((data / gate.LOG_NAME).read_text(encoding="utf-8")) == {"ts": "t"}


# --- gate_status and the self-test, through the server ---------------------------------------------

def _server(env: dict, calls: list[tuple[str, dict]]) -> list[dict]:
    lines = [{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}]
    lines += [{"jsonrpc": "2.0", "id": n + 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
              for n, (name, args) in enumerate(calls)]
    proc = subprocess.run([sys.executable, str(SERVER)], input="".join(json.dumps(m) + "\n" for m in lines),
                          capture_output=True, text=True, env=env, timeout=120, check=True)
    replies = [json.loads(line) for line in proc.stdout.splitlines()][1:]
    return [dict(json.loads(r["result"]["content"][0]["text"]), is_error=r["result"]["isError"]) for r in replies]


def test_gate_status_says_whether_the_gate_ran_in_this_session(env, tmp_path):
    data = tmp_path / "data"
    _gate(dict(env, CLAUDE_PLUGIN_DATA=str(data)), tmp_path, "ls", session="other")
    (status,) = _server(dict(env, CLAUDE_PLUGIN_DATA=str(data), CLAUDE_CODE_SESSION_ID="mine"), [("gate_status", {})])
    assert (status["readable"], status["hook_ran_this_session"], status["entries_total"]) == (True, False, 1)
    assert "CLAUDE_CODE_SESSION_ID" in status["session_criterion"]
    _gate(dict(env, CLAUDE_PLUGIN_DATA=str(data)), tmp_path, "ls", session="mine")
    (status,) = _server(dict(env, CLAUDE_PLUGIN_DATA=str(data), CLAUDE_CODE_SESSION_ID="mine"), [("gate_status", {"limit": 1})])
    assert (status["hook_ran_this_session"], status["entries_this_session"], len(status["entries"])) == (True, 1, 1)


def test_gate_status_says_not_measured_where_it_cannot_read_the_log(env):
    (status,) = _server(dict(env, PROOFBUNDLE_PLUGIN_HOST="codex"), [("gate_status", {})])
    assert (status["readable"], status["hook_ran_this_session"]) == (False, None)
    assert status["note"].startswith("NOT MEASURED: ")
    assert "cannot see whether" in status["gate_note"]
    (bad,) = _server(env, [("gate_status", {"limit": 0})])
    assert bad["is_error"]


def _run_selftest(env: dict, tmp_path: pathlib.Path, *, hook: bool, data: pathlib.Path | None,
                  run_push: bool = True, stray: bool = False, before_check=None) -> dict:
    """Prepare the self-test, optionally run the gate hook over its push (logging a deny), optionally let
    the push reach the throwaway remote (run_push, as a host that ignores the deny would), then check. The
    gate denies the push for a stale subject, reached without the verifier, so no uv shim is needed."""
    server_env = dict(env) if data is None else dict(env, CLAUDE_PLUGIN_DATA=str(data))
    (prepared,) = _server(server_env, [("gate_selftest_prepare", {})])
    if stray:
        # A deny the gate logged for another repository, and an entry for this work folder from before
        # started_at: neither is the self-test push.
        other = tmp_path / "other"
        other.mkdir()
        _git(other, "init", "-q")
        _gate(server_env, other, "git push")
        data.mkdir(exist_ok=True)
        with open(data / gate.LOG_NAME, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": "2000-01-01T00:00:00Z", "actions": ["git push"], "decision": "deny",
                                     "repos": [{"path": prepared["work"], "reason_id": "stale_subject"}]}) + "\n")
    assert prepared["command"].startswith("git -C ") and " push origin main" in prepared["command"]
    assert pathlib.Path(prepared["remote"]).name == "remote.git"
    if hook:
        answer, _ = _gate(server_env, tmp_path, prepared["command"])
        assert answer["hookSpecificOutput"].get("permissionDecision") == "deny"
    if run_push:  # a host that does not honour the deny lets the push reach the remote
        subprocess.run(prepared["command"], shell=True, check=True, capture_output=True)
    if before_check is not None:  # tamper with the recorded base or the remote between prepare and check
        before_check(pathlib.Path(prepared["work"]).parent)
    (checked,) = _server(server_env, [("gate_selftest_check", {"work": prepared["work"],
                                                               "started_at": prepared["started_at"]})])
    assert checked["limit"].startswith("The results report whether an expected deny entry was found")
    assert "The log is a local file" in checked["limit"]
    shutil.rmtree(pathlib.Path(prepared["work"]).parent)
    return checked


def test_the_selftest_reports_a_blocked_push_as_denial_logged_and_target_unchanged(env, tmp_path):
    """The host honours the deny, so the throwaway remote never receives the push (N5, N6)."""
    checked = _run_selftest(env, tmp_path, hook=True, data=tmp_path / "data", run_push=False)
    assert (checked["result"], checked["target_changed"]) == ("Expected denial logged; test target unchanged.", False)
    assert checked["log_entries"][0]["reason_ids"] == ["stale_subject"]


def test_the_selftest_reports_a_denial_the_host_did_not_enforce(env, tmp_path):
    checked = _run_selftest(env, tmp_path, hook=True, data=tmp_path / "data", run_push=True)
    assert (checked["result"], checked["target_changed"]) == ("Expected denial logged; test target changed.", True)


def test_the_selftest_reports_a_push_with_no_gate_event(env, tmp_path):
    checked = _run_selftest(env, tmp_path, hook=False, data=tmp_path / "data", run_push=True)
    assert checked["result"] == "Test target changed; no matching gate event observed."


def test_the_selftest_counts_only_the_gate_deny_for_its_own_push(env, tmp_path):
    checked = _run_selftest(env, tmp_path, hook=False, data=tmp_path / "data", run_push=False, stray=True)
    assert checked["result"] == "NOT MEASURABLE", "a deny for another repo is not the self-test's own"


#: The reviewer's limit for the self-test results (review R3-6), verbatim.
R3_6_LIMIT = ("The results report whether an expected deny entry was found and whether the target still "
              "equals the recorded base OID. They do not establish why an observation is missing. NOT "
              "MEASURABLE means the observations do not support another result. The limit applies to every "
              "result.")


def test_the_selftest_limit_sentence_is_the_reviewers_and_stands_everywhere():
    """R3-6: the self-test reports two observations and does not explain a missing one. The reviewer's
    limit stands verbatim in the server's SELFTEST_LIMIT, the selftest skill and D21."""
    server_limit = re.search(r'SELFTEST_LIMIT = \((.*?)\)\n', SERVER.read_text(encoding="utf-8"), re.S).group(1)
    skill = (PLUGIN / "skills" / "selftest" / "SKILL.md").read_text(encoding="utf-8")
    decisions = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
    sources = {"SELFTEST_LIMIT": server_limit.replace('"', "").replace("\n", " "),
               "skill": skill, "D21": decisions}
    for where, text in sources.items():
        assert R3_6_LIMIT in " ".join(text.split()), where


def test_the_selftest_is_not_measurable_without_a_recorded_base_oid(env, tmp_path):
    """R3-5: a missing base OID must not be read as a comparison value. After a real deny with no executed
    push, deleting the recorded base left the gate reporting 'test target changed'. It is NOT MEASURABLE."""
    checked = _run_selftest(env, tmp_path, hook=True, data=tmp_path / "data", run_push=False,
                            before_check=lambda parent: (parent / "base_oid").unlink())
    assert checked["result"] == "NOT MEASURABLE"
    assert checked["target_changed"] is None


def test_the_selftest_is_not_measurable_with_no_base_oid_and_no_target(env, tmp_path):
    """R3-5, the reviewer's second case: deleting the base and the throwaway remote's main left the gate
    reporting 'test target unchanged' (empty equals empty). It is NOT MEASURABLE."""
    def tamper(parent):
        (parent / "base_oid").unlink()
        subprocess.run(["git", "--git-dir", str(parent / "remote.git"), "update-ref", "-d", "refs/heads/main"],
                       check=True, capture_output=True)
    checked = _run_selftest(env, tmp_path, hook=True, data=tmp_path / "data", run_push=False, before_check=tamper)
    assert checked["result"] == "NOT MEASURABLE"
    assert checked["target_changed"] is None


def test_the_selftest_is_not_measurable_without_a_readable_log(env, tmp_path):
    checked = _run_selftest(env, tmp_path, hook=True, data=None, run_push=False)
    assert checked["result"] == "NOT MEASURABLE"


def test_the_selftest_checks_only_a_folder_it_created(env, tmp_path):
    (refused,) = _server(dict(env, CLAUDE_PLUGIN_DATA=str(tmp_path)), [("gate_selftest_check", {
        "work": str(tmp_path), "started_at": "2000-01-01T00:00:00Z"})])
    assert refused["is_error"] and "gate_selftest_prepare" in refused["error"]


def test_the_gate_version_is_the_plugin_version():
    versions = {json.loads(p.read_text(encoding="utf-8"))["version"] for p in PLUGIN.rglob("plugin.json")
                if "evals" not in p.relative_to(PLUGIN).parts}
    assert versions == {gate.GATE_VERSION}
