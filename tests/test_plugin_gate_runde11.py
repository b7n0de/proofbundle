"""Review Runde 11 (stand 44530e53): one regression test per finding, each exactly the review's case, plus the
safety net (owner choice A of 2026-10-04) and the four comment-strip bounds R10-1-C..F.

R11-1: three reproducers hid a literal git command from the lexer ($ before a separator, $'…'/$"…", a quoted ) in
$(…)); each now asks under Claude Code and denies under Codex, and its control does too. R11-2: a comment under a
changed zsh comment character still runs git, so the net reads the dropped text. R11-3: GIT/gIt reach the net.
R11-4: a boolean id and a non-JSON stdout line no longer let a run pass. The net and the four bounds have their own
catch proofs in the mutation run. Red against 44530e53, green after.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

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


def _hook(repo: pathlib.Path, logs: pathlib.Path, host: str, command: str) -> tuple[str | None, list[str]]:
    """Run the gate as the host runs it: the permission decision of its JSON answer (None for no answer) and the
    reason ids of its log line."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs)}
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer.get("hookSpecificOutput", {}).get("permissionDecision"), entry["reason_ids"]


def _both_gate(repo, logs_root, command):
    """Assert the command is gated on both host paths (ask under Claude, deny under Codex), and return the
    Claude reason ids."""
    claude, cids = _hook(repo, logs_root / "c", "claude", command)
    codex, _ = _hook(repo, logs_root / "x", "codex", command)
    assert claude == "ask", (command, claude)
    assert codex == "deny", (command, codex)
    return cids


# --- R11-1: a literal git command hidden from the lexer ------------------------------------------------------------

_R11_1 = [
    (": $\ngit push origin main", ": \ngit push origin main", "dollar-then-newline"),
    (": $'x'; git push origin main # '", ": $'x'; git push origin main", "dollar-single-quote"),
    (": $(printf ')'); git push origin main # '", ": $(printf ')'); git push origin main", "quoted-paren-in-subst"),
]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("hidden, control, ident", _R11_1, ids=[i for *_, i in _R11_1])
def test_r11_1_a_git_command_hidden_from_the_lexer_is_gated(tmp_path, hidden, control, ident):
    """R11-1, the review's three reproducers over the real JSON answers of both host paths: the form that hid a
    git push (a `$` before a separator, `$'…'`, a quoted `)` inside `$(…)`) now asks under Claude Code and denies
    under Codex, and so does its control (without the `$`, or without the trailing comment). At 44530e53 the
    hidden form got no answer and the log said not_gated."""
    # The structured scan must find the git form without the net: this isolates the lexer fixes (the `$`-before-
    # separator fix for case 1 and the quote-aware `$(` for case 3; case 2's `$'…'` is carried by the fallback).
    assert gate.gated_calls(hidden), hidden
    repo = _repo(tmp_path)
    cids = _both_gate(repo, tmp_path / "hidden", hidden)
    assert "not_gated" not in cids
    _both_gate(repo, tmp_path / "control", control)


# --- R11-2: a comment under a changed comment character still runs git --------------------------------------------

_R11_2_CMD = "true # ; git config proofbundle.reviewMarker changed"


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_r11_2_a_comment_that_may_run_git_is_gated_by_the_net(tmp_path):
    """R11-2: the gate removes the comment for the structured scan, so the net reads the dropped text; the command
    asks under Claude Code and denies under Codex (reason net_unmodeled_git). At 44530e53 the gate gave no answer."""
    repo = _repo(tmp_path)
    cids = _both_gate(repo, tmp_path / "logs", _R11_2_CMD)
    assert cids == ["net_unmodeled_git"], cids


@pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh not installable here; execution NICHT MESSBAR")
def test_r11_2_zsh_runs_the_commented_git_only_with_changed_histchars(tmp_path):
    """R11-2, the measured regression: under zsh the command runs git (sets the local marker) when histchars makes
    `#` an ordinary character, and does not with the default configuration. This is why the removed comment text
    must still be read (the net). Harmless local marker only, no network, no push."""
    zsh = shutil.which("zsh")

    def run(histchars: str) -> str:
        d = tmp_path / ("hc" if histchars else "def")
        repo = d / "r"
        repo.mkdir(parents=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, ZDOTDIR=str(d), HOME=str(d))
        _git(repo, "init", "-q", "-b", "main")
        (repo / "a.txt").write_text("a\n", encoding="utf-8")
        _git(repo, "add", "a.txt")
        _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
        (d / ".zshenv").write_text(f"histchars='{histchars}'\n" if histchars else "", encoding="utf-8")
        subprocess.run([zsh, "-c", _R11_2_CMD], cwd=repo, env=env, capture_output=True, text=True, timeout=60)
        got = subprocess.run(["git", "-C", str(repo), "config", "--get", "proofbundle.reviewMarker"],
                             env=env, capture_output=True, text=True).stdout.strip()
        return got

    assert run("") == "", "default zsh must treat # as a comment, git must not run"
    assert run("!^@") == "changed", "with histchars='!^@' zsh runs the git command"


# --- R11-3: a program name in a different letter case -------------------------------------------------------------

@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("command", ["GIT push origin main", "gIt push origin main"])
def test_r11_3_a_case_variant_of_git_is_gated_by_the_net(tmp_path, command):
    """R11-3: a program name in a different ASCII case reaches the net; it asks under Claude Code and denies under
    Codex. The lowercase control resolves as a push (not the net). At 44530e53 the case variant got no answer."""
    repo = _repo(tmp_path)
    cids = _both_gate(repo, tmp_path / "up", command)
    assert cids == ["net_unmodeled_git"], cids
    control = _both_gate(repo, tmp_path / "low", command.lower())
    assert "net_unmodeled_git" not in control, control


# --- R11-4: invalid verifier replies ------------------------------------------------------------------------------

def _reply(request_id, exit_code: int, raw: str | None = None) -> str:
    if raw is not None:
        return raw
    text = json.dumps({"exit_code": exit_code, "meaning": "synthetic", "proofbundle_version": "6.1.0"})
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": text}]}})


_GREEN_BOOL_ID = _reply(True, 0)
_GREEN = _reply(1, 0)
_RED_BROKEN = '{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "{\\"exit_code\\": 1}"'  # no close
_DOUBLE = [_reply(1, 0), _reply(1, 1)]  # the old double-answer control, both valid integer ids


@pytest.mark.parametrize("stream, ident", [
    ([_GREEN_BOOL_ID], "bool-id-no-integer-answer"),
    ([_RED_BROKEN, _GREEN], "broken-json-then-green"),
    ([_GREEN, _RED_BROKEN], "green-then-broken-json"),
    (_DOUBLE, "double-integer-answer"),
], ids=["bool-id", "broken-then-green", "green-then-broken", "double-answer"])
def test_r11_4_an_invalid_reply_stream_does_not_pass(monkeypatch, stream, ident):
    """R11-4, the review's streams for one expected request: a boolean id is no answer to request 1 (so the run
    has no reply and is denied), a non-JSON stdout line refuses the whole run, and the old double-answer still
    refuses. At 44530e53 the first three read as pass verified; now every one is a GateError the judge denies."""
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = "".join(line + "\n" for line in stream)
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, _o=out, **k: subprocess.CompletedProcess(a, 0, _o, ""))
    with pytest.raises(gate.GateError):
        gate.verify_items([{"kind": "bundle"}], gate.time.monotonic() + 30)


def test_r11_4_a_single_valid_reply_is_still_read(monkeypatch):
    """R11-4 control: one well-formed integer-id reply is read as it is, so the refusals above are not blanket."""
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = _reply(1, 1) + "\n"
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, out, ""))
    assert gate.verify_items([{"kind": "bundle"}], gate.time.monotonic() + 30)[0]["exit_code"] == 1


# --- the net and its word test -----------------------------------------------------------------------------------

@pytest.mark.parametrize("command, hit", [
    ("git push origin main", True), ("GIT push", True), ("/usr/bin/git push", True),
    ("true ; git push", True), ("x=$(git push)", True), ("gh pr create", True),
    (".gitignore", False), ("echo digit", False), ("foo-git bar", False),
    ("echo 'git push'", True), ("name=git value", False), ("echo github.com", False),
    ("git --version", True), ("ls -la", False),
])
def test_net_hit_names_only_command_words(command, hit):
    """The net's command-word test on the normal form (review Runde 12, R12-1): git/gh count as a command word
    in any ASCII case, behind a path or not, but not inside a longer word (.gitignore, digit, foo-git) nor as a
    value the separators leave whole (name=git). The quote exception of earlier rounds is gone, so the normal
    form of `echo 'git push'` names git as a command word. git --version is a hit here; decide exempts only that
    exact bare text separately."""
    assert gate._net_hit(command) is hit, command


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_net_leaves_the_bare_version_free_and_non_git_commands_alone(tmp_path):
    repo = _repo(tmp_path)
    for host in ("claude", "codex"):
        assert gate.decide("git --version", str(repo), gate.time.monotonic() + 30, host=host) is None, host
        assert gate.decide("ls -la", str(repo), gate.time.monotonic() + 30, host=host) is None, host
        # `echo 'git push'` is no longer free: under the Runde-12 normal form the quote is removed and git is a
        # command word, so it is NOT MEASURED (ask under Claude, deny under Codex). See test_plugin_gate_runde12.
        assert gate.decide("echo 'git push'", str(repo), gate.time.monotonic() + 30, host=host) is not None, host


# --- R10-1-C..F: the four comment-strip bounds -------------------------------------------------------------------

_BOUNDS = [
    ('echo "x" # git push origin main', "C-comment-after-non-plain"),
    ("cat <<EOF # git push origin main", "D-here-document-stops"),
    ("x=1#; git push origin main", "E-comment-at-word-start"),
    ("git --version #x", "F-bare-version-held-to-raw-text"),
]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("command, ident", _BOUNDS, ids=[i for _, i in _BOUNDS])
def test_r10_1_bounds_keep_the_structured_scan_honest(tmp_path, command, ident):
    """R10-1-C..F, the four comment-strip bounds (review Runde 11, Frage 2): with the bound in place the structured
    scan still finds the git form, so the command asks under Claude Code and denies under Codex. The mutation run
    shows that removing any one bound makes gated_calls miss its case (catch proof in the delivery)."""
    assert gate.gated_calls(command), command  # the structured scan finds it, it does not rely on the net
    _both_gate(_repo(tmp_path), tmp_path / "logs", command)
