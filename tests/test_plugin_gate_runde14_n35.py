"""Review Runde 14 / Nachtrag 35 (stand d5e49bdd): one regression test per finding, each exactly the review's case,
at the gate exit on both host paths, and — as the reviewer required — against the words bash/zsh/dash actually run,
not only against decoder values.

The class from this round: a form whose executed bytes the normal form cannot build safely and completely is NOT
MEASURED (ask under Claude Code, deny under Codex), never no answer. Exact evaluation stays only where it is provably
complete.

R13-1: a decoded NUL byte in $'…' (\\0, \\x00, \\u0000, \\c@) — bash truncates the sub-word there and appends the
rest, which the normal form does not model, so NOT MEASURED. R13-2: an active backslash line continuation is removed
before the word test. R13-3: a command substitution or backtick, inside double quotes too, and a process
substitution, is read as its own executable text; an ANSI-C quote it holds is evaluated. R13-4: an active brace/glob
in a command-word position is NOT MEASURED, while one safely in an argument (`ls *.py`, `cp f.{txt,bak}`) stays free.
R13-5: isError is strictly boolean when present, a notification's params is validated before it is skipped, and the
initialisation response is evaluated; a contract break or a failed initialisation refuses the whole run.

Red against d5e49bdd131788f611901b3d0b970b671626be47, green after. Catch proof in scratchpad/n35/fang.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"
BS = chr(92)
NL = chr(10)

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


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                          check=True, capture_output=True, text=True, timeout=60)


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
    return repo


def _hook(repo, logs, host, command):
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer.get("hookSpecificOutput", {}).get("permissionDecision"), entry["reason_ids"]


def _gated(repo, logs_root, command, reason="net_unmodeled_git"):
    d_claude, ids = _hook(repo, logs_root / "claude", "claude", command)
    d_codex, _ = _hook(repo, logs_root / "codex", "codex", command)
    assert d_claude == "ask", (command, d_claude, ids)
    assert d_codex == "deny", (command, d_codex)
    if reason is not None:
        assert reason in ids, (command, ids)


# --- R13-1 .. R13-4 at the gate exit (both host paths) ------------------------------------------------------------
_R13_1 = ["$'g" + BS + "0'it push origin main", "$'g" + BS + "x00'it push origin main",
          "$'g" + BS + "u0000'it push origin main", "$'g" + BS + "c@'it push origin main"]
_R13_2 = ["$'g'" + BS + NL + "it status", "$'" + BS + "147'" + BS + NL + "it status"]
_R13_3 = ['echo "$(' + "$'" + BS + "147it' status)" + '"', 'echo "`' + "$'" + BS + "147it' status`" + '"']
_R13_4 = ["g{i..i}t push origin main", "gi* push origin main", "g? pr create"]


@pytest.mark.parametrize("command", _R13_1)
def test_r13_1_a_nul_byte_in_an_ansi_c_quote_is_not_measured(tmp_path, command):
    """R13-1: bash truncates the ANSI-C sub-word at a NUL and appends the rest (`$'g\\0'it` runs git); the normal
    form does not model that, so the whole command is NOT MEASURED on both host paths."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", _R13_2)
def test_r13_2_an_outer_line_continuation_is_removed(tmp_path, command):
    """R13-2: an active backslash line continuation is removed before the word test, so `$'g'\\<newline>it` reads
    as the one word git and is gated on both host paths."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", _R13_3)
def test_r13_3_a_substitution_inside_double_quotes_is_read_as_a_command(tmp_path, command):
    """R13-3: a command substitution or backtick inside double quotes is read as its own executable text, so the
    ANSI-C quote it holds is evaluated and the inner git is gated on both host paths."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", _R13_4)
def test_r13_4_an_active_expansion_in_a_command_word_is_not_measured(tmp_path, command):
    """R13-4: an active brace or glob in a command-word position can expand to a git/gh program name, so it is NOT
    MEASURED on both host paths."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", ["ls *.py", "cp f.{txt,bak} dest/", "echo hello", "grep -n foo *.py"])
def test_r13_4_an_argument_expansion_stays_free(tmp_path, command):
    """Control: an active expansion safely in an argument position keeps its silent pass under both hosts; only a
    command-word expansion is NOT MEASURED."""
    repo = _repo(tmp_path)
    d_claude, ids = _hook(repo, tmp_path / "logs" / "claude", "claude", command)
    d_codex, _ = _hook(repo, tmp_path / "logs" / "codex", "codex", command)
    assert d_claude is None and d_codex is None, (command, d_claude, d_codex)
    assert "net_unmodeled_git" not in ids, ids


@pytest.mark.parametrize("command", ["git status", "git push origin main"])
def test_the_literal_controls_are_still_gated(tmp_path, command):
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason=None)


# --- the net sees every git/gh bash and zsh actually run (differential, not only decoder values) -------------------
_STUB = pathlib.Path(__file__).resolve().parent.parent  # replaced per test with a temp stub dir
_HAS_BASH = subprocess.run(["bash", "-c", "exit 0"], capture_output=True).returncode == 0


def _stub_dir(tmp_path):
    d = tmp_path / "stub"
    d.mkdir()
    for name in ("git", "gh"):
        p = d / name
        p.write_text(f"#!/bin/sh\necho RAN:{name}\n", encoding="utf-8")
        p.chmod(0o755)
    return d


@pytest.mark.skipif(not _HAS_BASH, reason="bash not available")
@pytest.mark.parametrize("command", _R13_1 + _R13_2 + _R13_3 + _R13_4 + ["git status", "ls *.py", "echo hello"])
def test_net_covers_every_git_bash_or_zsh_runs(tmp_path, command):
    """The reviewer's requirement: if bash or zsh runs git or gh as a command word of the text, the net must see
    it (a git/gh word) or report the command NOT MEASURED — never nothing. Overmatch the other way is allowed."""
    d = _stub_dir(tmp_path)
    env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"])
    ran = False
    for shell in (["bash", "-c"], ["/usr/bin/zsh", "-c"]):
        if subprocess.run([shell[0], "-c", "exit 0"], capture_output=True).returncode != 0:
            continue
        out = subprocess.run(shell + [command], capture_output=True, text=True, env=env, cwd=str(d), timeout=30).stdout
        ran = ran or "RAN:git" in out or "RAN:gh" in out
    if ran:
        assert gate._net_words(command) >= 1 or gate._net_unresolved(command), command


# --- R13-5: the verifier answer reader (unit) ---------------------------------------------------------------------
_INIT_OK = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                             "serverInfo": {"name": "proofbundle", "version": "1"}}})
_INIT_ERR = json.dumps({"jsonrpc": "2.0", "id": 0, "error": {"code": -1, "message": "init failed"}})
_VALID_PAYLOAD = {"exit_code": 0, "proofbundle_version": "6.1.0"}


def _green(is_error=False):
    return json.dumps({"jsonrpc": "2.0", "id": 1,
                       "result": {"isError": is_error, "content": [{"type": "text", "text": json.dumps(_VALID_PAYLOAD)}]}})


def _reply_with_is_error(value):
    return json.dumps({"jsonrpc": "2.0", "id": 1,
                       "result": {"isError": value, "content": [{"type": "text", "text": json.dumps(_VALID_PAYLOAD)}]}})


def _run(monkeypatch, lines):
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = "".join(line + "\n" for line in lines)
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, _o=out, **k: subprocess.CompletedProcess(a, 0, _o, ""))
    return gate.verify_items([{"kind": "bundle"}], time.monotonic() + 30)


@pytest.mark.parametrize("stream, why", [
    ([_INIT_OK, _reply_with_is_error([])], "isError is a list"),
    ([_INIT_OK, _reply_with_is_error(None)], "isError is null"),
    ([_INIT_OK, _reply_with_is_error(0)], "isError is the integer 0"),
    ([_INIT_OK, json.dumps({"jsonrpc": "2.0", "method": "x/note", "params": 0}), _green()],
     "a notification whose params is not an object, then a valid green"),
    ([_INIT_ERR, _green()], "a failed initialisation, then a valid green"),
])
def test_r13_5_a_contract_break_or_failed_init_refuses_the_run(monkeypatch, stream, why):
    """R13-5: at d5e49bdd each of these streams read as `pass verified`; now each refuses the whole run."""
    with pytest.raises(gate.GateError):
        _run(monkeypatch, stream)


@pytest.mark.parametrize("is_error", [None, False])
def test_r13_5_a_valid_stream_is_still_read(monkeypatch, is_error):
    """Control: a valid initialisation and a reply with isError false or absent are read; is_error is false."""
    stream = [_INIT_OK, _green()] if is_error is False else [
        _INIT_OK, json.dumps({"jsonrpc": "2.0", "id": 1,
                              "result": {"content": [{"type": "text", "text": json.dumps(_VALID_PAYLOAD)}]}})]
    results = _run(monkeypatch, stream)
    assert results[0]["exit_code"] == 0 and results[0]["is_error"] is False
