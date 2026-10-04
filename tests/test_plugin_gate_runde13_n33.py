"""Review Runde 13 / Nachtrag 33 (stand 096b7191): one regression test per confirmed Codex candidate, each at the
gate exit on both host paths, plus the class siblings and a differential against real bash.

K1: a command word whose executed bytes the normal form could not build like bash slipped BOTH host paths with no
answer. The net now evaluates an ANSI-C quote $'…' to the bytes bash runs (octal, hex, Unicode, control, the named
escapes), and reports NOT MEASURED a form it cannot build exactly — a locale quote $"…", whose translation it
cannot read. So each K1 form is ask under Claude Code and deny under Codex. Measured: bash 5.2 AND zsh 5.9 run the
reproducer `$'\\147it' status` as `git status`; dash 0.5 does not. Brace expansion and pathname globbing that
construct a command word are named open in DECISIONS.md D8; this suite does not assert them closed.

K2: verify_items validated only content[0] and left content[1:] unexamined, so a schema-breaking sibling block rode
along and a crafted stream reached a pass on the Claude push path. The reader now checks EVERY element against the
measured proofbundle 6.1.0 tool-result contract — content is exactly one {"type":"text","text":<json>} element — and
refuses the whole run (GateError, envelope-error status as R12-4) otherwise. The Codex push path denies this push
before the verifier (codex_cwd_unbound), so a Codex pass from this stream stays NOT MEASURED by construction.

Red against 096b71915602db0c9096cd3e0daaf55a5d3d188d, green after. Each finding also has its catch proof in
scratchpad/n33/fang.
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
BACKSLASH = chr(92)  # the tool/JSON layer decodes \uXXXX etc.; build such bytes from chr to keep them literal

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


def _hook(repo: pathlib.Path, logs: pathlib.Path, host: str, command: str,
          env_extra: dict | None = None) -> tuple[str | None, list[str]]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer.get("hookSpecificOutput", {}).get("permissionDecision"), entry["reason_ids"]


def _gated(repo, logs_root, command, reason=None):
    """ask under Claude, deny under Codex at the gate exit; when reason is given it is in the Claude log."""
    d_claude, ids = _hook(repo, logs_root / "claude", "claude", command)
    d_codex, _ = _hook(repo, logs_root / "codex", "codex", command)
    assert d_claude == "ask", (command, d_claude, ids)
    assert d_codex == "deny", (command, d_codex)
    if reason is not None:
        assert reason in ids, (command, ids)
    return ids


# --- K1: the ANSI-C quote and the locale quote reach the net (both host paths) -------------------------------------
# Octal and hex survive the JSON/tool layer as literal backslashes; the Unicode case is built from chr(92).
K1_ANSI_FORMS = [
    r"$'\147it' status",          # octal \147 -> g
    r"gi$'\164' status",          # \164 -> t, mid-word
    r"$'\x67'it status",          # hex \x67 -> g
    r"$'\x67\x69\x74' status",    # g i t in hex
    r"$'\x67it' push origin main",  # the push form the review named
    "$'" + BACKSLASH + "u0067it' status",  # Unicode g -> g (built from chr(92) so the layer keeps it literal)
]


@pytest.mark.parametrize("command", K1_ANSI_FORMS)
def test_k1_ansi_c_quote_is_not_measured(tmp_path, command):
    """K1: an ANSI-C quote whose escapes spell a git/gh command word is NOT MEASURED on both host paths; at
    096b7191 the net read the undecoded bytes and gave no answer at all."""
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason="net_unmodeled_git")


@pytest.mark.parametrize("command", [
    r'$"git" status',             # a locale quote whose untranslated bytes are git
    r'gi$"t" push origin main',   # a locale quote mid-word
    'echo ' + '$"hello world"',   # a locale quote with no git word: still NOT MEASURED (translation unknown)
])
def test_k1_locale_quote_is_not_measured(tmp_path, command):
    """K1: a locale quote $"…" is NOT MEASURED whatever its content, because its message-catalogue translation is
    not knowable here; the gate cannot build its executed bytes exactly like bash."""
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason="net_unmodeled_git")


@pytest.mark.parametrize("command", ["git status", "git push origin main", "gh pr list"])
def test_k1_literal_controls_are_still_gated(tmp_path, command):
    """Control: the literal forms are gated the same way, so the fix removes a difference, it does not add one."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", ["ls -la", "echo digit", "printf '%s' done"])
def test_k1_plain_non_git_commands_are_untouched(tmp_path, command):
    """Control: a command with no git/gh word and no unevaluable quote still gets no decision under either host."""
    repo = _repo(tmp_path)
    d_claude, ids = _hook(repo, tmp_path / "logs" / "claude", "claude", command)
    d_codex, _ = _hook(repo, tmp_path / "logs" / "codex", "codex", command)
    assert d_claude is None and d_codex is None, (command, d_claude, d_codex)
    assert "net_unmodeled_git" not in ids, ids


# --- K1: the decoder matches bash, and the net never misses a git bash would run (differential) --------------------
_HAS_BASH = subprocess.run(["bash", "-c", "exit 0"], capture_output=True).returncode == 0


@pytest.mark.parametrize("body, expected", [
    (r"\147", "g"), (r"\x67", "g"), (r"\x67\x69\x74", "git"), (r"\z", r"\z"),
    (r"\x", r"\x"), (r"\xZZ", r"\xZZ"), (r"\\", BACKSLASH), (r"\'", "'"),
    (BACKSLASH + "u0067", "g"), (BACKSLASH + "U00000067", "g"),
])
def test_k1_decoder_values(body, expected):
    """_decode_ansi_c yields the exact bytes, closing-quote index past the quote."""
    decoded, end = gate._decode_ansi_c(body + "'", 0)
    assert decoded == expected, (body, decoded)
    assert end == len(body) + 1


@pytest.mark.skipif(not _HAS_BASH, reason="bash not available")
@pytest.mark.parametrize("body", [r"\147", r"\x67", r"\x67\x69\x74", r"\z", r"\x", r"\xZZ", r"\a"])
def test_k1_decoder_matches_bash(body):
    """Differential: the decoder's bytes for $'<body>' equal the bytes bash 5 prints for the same quote. (A null
    byte is not observable through printf '%s', so \\0 is not in this set; its decode is covered by unit values.)"""
    out = subprocess.run(["bash", "-c", "printf '%s' $'" + body + "'"], capture_output=True, timeout=30).stdout
    decoded, _ = gate._decode_ansi_c(body + "'", 0)
    assert decoded.encode("utf-8", "surrogatepass") == out, (body, decoded, out)


@pytest.mark.skipif(not _HAS_BASH, reason="bash not available")
@pytest.mark.parametrize("command", [
    r"$'\147it' status", r"gi$'\164' status", r"$'\x67'it push", "git status", "git push origin main",
    "gh pr list", "ls -la", "echo digit", r": $'x'; g\it push", "echo 'git push'", "true && gh pr create",
])
def test_k1_net_never_misses_a_git_bash_runs(command):
    """The strong safety property: if bash would run git or gh as the command word of ANY simple command in the
    text, the net sees at least one git/gh word (no miss). Overmatch the other way is allowed."""
    # what bash runs as command words, via a PATH of stubs that print their own name
    bindir = pathlib.Path(os.environ.get("PYTEST_CURRENT_TEST", "")).parent  # unused; stubs made below
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        for name in ("git", "gh"):
            p = pathlib.Path(d) / name
            p.write_text(f'#!/bin/sh\necho RAN:{name}\n', encoding="utf-8")
            p.chmod(0o755)
        env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"])
        res = subprocess.run(["bash", "-c", command], capture_output=True, text=True, env=env, timeout=30)
        bash_ran_git = "RAN:git" in res.stdout or "RAN:gh" in res.stdout
    if bash_ran_git:
        assert gate._net_words(command) >= 1 or gate._net_unresolved(command), command


# --- K2: verify_items checks every content element against the measured 6.1.0 contract -----------------------------
def _run_stream(monkeypatch, lines):
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = "".join(line + "\n" for line in lines)
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, _o=out, **k: subprocess.CompletedProcess(a, 0, _o, ""))
    return gate.verify_items([{"kind": "bundle"}], time.monotonic() + 30)


_VALID = {"type": "text", "text": json.dumps({"exit_code": 0, "proofbundle_version": "6.1.0"})}


def _reply(content) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": content}})


@pytest.mark.parametrize("content, why", [
    ([_VALID, 7], "the review's reproducer: a valid text block then the number 7"),
    ([_VALID, _VALID], "a second text block the gate does not read"),
    ([_VALID, {"type": "text", "text": "garbage"}], "a second, schema-shaped text block"),
    ([_VALID, {"type": "image", "data": "x"}], "a sibling block of another type"),
    ([_VALID, "text"], "a sibling that is a bare string"),
    ([_VALID, None], "a null sibling"),
    ([], "an empty content list"),
    ([{"type": "resource", "text": json.dumps({"exit_code": 0})}], "a lone block of the wrong type"),
    ([{"text": json.dumps({"exit_code": 0})}], "a lone block with no type field"),
    ([{"type": "text", "text": 5}], "a lone block whose text is not a string"),
])
def test_k2_a_content_stream_off_the_contract_refuses_the_whole_run(monkeypatch, content, why):
    """K2: every element of content is checked against the measured 6.1.0 contract (exactly one text block); any
    deviation refuses the whole run. At 096b7191 only content[0] was checked, so [valid, 7] read as verified."""
    with pytest.raises(gate.GateError):
        _run_stream(monkeypatch, [_reply(content)])


def test_k2_the_valid_single_text_block_is_read(monkeypatch):
    """Control: the measured shape — content with exactly one {'type':'text','text':<json>} element — is read."""
    results = _run_stream(monkeypatch, [_reply([_VALID])])
    assert results[0]["exit_code"] == 0 and results[0]["is_error"] is False


# --- K2 at the gate exit: a crafted verifier stream drives the full ci-check verdict -------------------------------
_BUNDLE = ".proofbundle/build.bundle.json"
_POLICY = ".proofbundle/policy.json"


def _wr(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _declared_repo(tmp_path: pathlib.Path, *, remote: bool = False) -> pathlib.Path:
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
    if remote:
        bare = tmp_path / "remote.git"
        _git(tmp_path, "init", "-q", "--bare", str(bare))
        _git(repo, "remote", "add", "origin", str(bare))
        _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    return repo


def _uv_stream_env(tmp_path: pathlib.Path, replies: list[str]) -> dict:
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


def test_k2_crafted_stream_denies_at_the_ci_check_exit(tmp_path):
    """K2 at the gate exit: a verifier stream with a valid block and a schema-breaking sibling (the number 7) now
    fails the ci-check (exit 1). At 096b7191 it read as verified (exit 0)."""
    repo = _declared_repo(tmp_path)
    reply = _reply([_VALID, 7])
    env = _uv_stream_env(tmp_path, [_init_reply(), reply])
    assert _ci_check(env, repo) == 1


def test_k2_valid_stream_passes_at_the_ci_check_exit(tmp_path):
    """Control: the same ci-check with a single valid content block passes (exit 0); the difference is only the
    added sibling block."""
    repo = _declared_repo(tmp_path)
    env = _uv_stream_env(tmp_path, [_init_reply(), _reply([_VALID])])
    assert _ci_check(env, repo) == 0


def _push_hook(repo, logs, host, env_extra):
    return _hook(repo, logs, host, "git push origin main", env_extra=env_extra)


def test_k2_crafted_stream_on_the_claude_push_path_denies(tmp_path):
    """K2 on the Claude push path (the path the review measured): the declared push reaches the verifier, and the
    crafted stream is now refused, so the gate denies. At 096b7191 it was a pass ('1 of 1 declared items
    verified')."""
    repo = _declared_repo(tmp_path, remote=True)
    env = _uv_stream_env(tmp_path, [_init_reply(), _reply([_VALID, 7])])
    decision, ids = _push_hook(repo, tmp_path / "logs" / "claude", "claude", env)
    assert decision == "deny", (decision, ids)


def test_k2_the_valid_stream_on_the_claude_push_path_passes(tmp_path):
    """Control: the same push with a single valid content block passes (no permission decision)."""
    repo = _declared_repo(tmp_path, remote=True)
    env = _uv_stream_env(tmp_path, [_init_reply(), _reply([_VALID])])
    decision, ids = _push_hook(repo, tmp_path / "logs" / "claude", "claude", env)
    assert decision is None, (decision, ids)


def test_k2_the_codex_push_path_denies_before_the_verifier(tmp_path):
    """Control: under Codex the push is denied before the verifier runs (codex_cwd_unbound), so a Codex pass from
    this stream is NOT MEASURED by construction. The crafted and the valid streams both deny."""
    repo = _declared_repo(tmp_path, remote=True)
    env = _uv_stream_env(tmp_path, [_init_reply(), _reply([_VALID, 7])])
    decision, _ = _push_hook(repo, tmp_path / "logs" / "codex", "codex", env)
    assert decision == "deny"
