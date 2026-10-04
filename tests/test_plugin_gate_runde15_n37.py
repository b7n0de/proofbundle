"""Review Runde 15 / Nachtrag 37 (stand 2a1c1237): one regression test per finding, each exactly the review's case,
at the gate exit on both host paths, and — as the reviewer required — against the words bash/zsh/dash actually run,
not only against decoder values.

The class from this round: the net frees a command only when it has positively understood it. A command whose
program position, embedded-context boundary or executed bytes it cannot establish is NOT MEASURED (ask under
Claude Code, deny under Codex), never no answer. The understood-versus-NOT-MEASURED decision is made at one site,
_net_unmodeled, and every free exit of the net goes through it (Punkt 2).

R14-1: a wrapper option (`env -- gi*`, `time -p gi*`), a shell keyword (`if gi* …`) or a wrapper (`command --`,
`sudo`) shifts the real program position, so an active expansion at or after it is NOT MEASURED; an expansion that
is a proven data argument of a plain program word (`ls *.py`, `if true; then ls *.py; fi`) stays free. R14-2: the
expansion check runs inside every executable subcontext (`echo "$(gi* status)"`, `echo "$(g{i..i}t status)"`), and
a context the lexer cannot parse (`: $'x'; gi* status`) is NOT MEASURED, not expansion-free. R14-3: an embedded
command's boundary counts only under understood syntax — an escaped paren, a `case`-pattern paren and a paren in a
comment no longer end the substitution early. R14-4: the initialisation result's mandatory fields and protocol
version, the contracts of permitted notifications, and the belonging of every reply id to a sent request are all
checked before any answer is read; a break refuses the whole run. The real pinned verifier still passes a valid
bundle and denies a changed signature.

The Nachtrag-24 approval path is held to the same site (owner correction to N37): a human rule never frees a form
the net reports NOT MEASURED, in with-approvals mode as in strict.

Red against 2a1c1237657b59eab4f6ae123441992ce7c3adb0, green after. Catch proof in scratchpad/n37/fang.
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


def _hook(repo, logs, host, command, environ=None):
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, **(environ or {})}
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


def _free(repo, logs_root, command):
    d_claude, ids = _hook(repo, logs_root / "claude", "claude", command)
    d_codex, _ = _hook(repo, logs_root / "codex", "codex", command)
    assert d_claude is None and d_codex is None, (command, d_claude, d_codex)
    assert "net_unmodeled_git" not in ids, (command, ids)


# --- R14-1 .. R14-3 at the gate exit (both host paths) ------------------------------------------------------------
_R14_1 = ["env -- gi* push origin main", "if gi* push origin main; then :; fi", "command -- gi* push origin main",
          "time -p gi* status", "sudo gi* status"]
_R14_2 = ['echo "$(gi* status)"', ": $'x'; gi* status", 'echo "$(g{i..i}t status)"',
          'echo "`gi* status`"']
_R14_3 = ['echo "$(printf ' + BS + '); $' + "'" + BS + "147it' status)" + '"',
          'echo "$(case x in x) gi* status;; esac)"',
          'echo "$(' + NL + 'gi* status # )' + NL + ')"']
#: Ordinary data-argument expansions and plain program words that MUST stay free — the daily cost is unchanged.
_FREE = ["ls *.py", "cp f.{txt,bak} dest/", "grep -n foo *.py", "rm build/*.o", "echo hello",
         "find . -name '*.py'", "tar -czf a.tgz src/*.py", "if true; then ls *.py; fi"]


@pytest.mark.parametrize("command", _R14_1)
def test_r14_1_a_wrapper_option_or_keyword_shifts_the_program_position(tmp_path, command):
    """R14-1: a wrapper option (`env --`, `time -p`), a shell keyword (`if`) or a wrapper (`command`, `sudo`)
    shifts the real program position, so the active expansion after it is NOT MEASURED on both host paths."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", _R14_2)
def test_r14_2_recursion_and_a_lexer_error_do_not_lose_the_expansion_check(tmp_path, command):
    """R14-2: the expansion check runs inside every executable subcontext, and a context the lexer cannot parse is
    NOT MEASURED at an unclear program position rather than treated as expansion-free."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", _R14_3)
def test_r14_3_an_embedded_boundary_counts_only_under_understood_syntax(tmp_path, command):
    """R14-3: an escaped paren, a `case`-pattern paren and a paren in a comment no longer end the command
    substitution early, so the inner git is seen and the command is NOT MEASURED on both host paths."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", _FREE)
def test_a_proven_data_argument_expansion_stays_free(tmp_path, command):
    """Control: an active expansion that is a proven data argument of a plain program word keeps its silent pass
    under both hosts; the eleven ordinary forms of the daily-cost corpus are unaffected."""
    _free(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", ["for f in *.py; do echo $f; done"])
def test_a_structural_keyword_with_an_expansion_is_deliberately_not_measured(tmp_path, command):
    """Deliberate strictness (DECISIONS.md D8): the net does not model `for`/`case` grammar, so an active
    expansion inside it is NOT MEASURED rather than guessed free. Named in the daily-cost report, not a regression
    the review flagged."""
    _gated(_repo(tmp_path), tmp_path / "logs", command)


@pytest.mark.parametrize("command", ["git status", "git push origin main"])
def test_the_literal_controls_are_still_gated(tmp_path, command):
    _gated(_repo(tmp_path), tmp_path / "logs", command, reason=None)


# --- the net sees every git/gh bash, zsh or dash actually runs (differential, not only decoder values) -------------
_HAS_BASH = subprocess.run(["bash", "-c", "exit 0"], capture_output=True).returncode == 0


def _stub_dir(tmp_path):
    d = tmp_path / "stub"
    d.mkdir()
    for name in ("git", "gh"):
        p = d / name
        p.write_text(f"#!/bin/sh{NL}echo RAN:{name}{NL}", encoding="utf-8")
        p.chmod(0o755)
    return d


@pytest.mark.skipif(not _HAS_BASH, reason="bash not available")
@pytest.mark.parametrize("command", _R14_1 + _R14_2 + _R14_3 + _FREE + ["git status"])
def test_net_covers_every_git_a_shell_runs(tmp_path, command):
    """The reviewer's requirement: if bash, zsh or dash runs git or gh as a command word of the text, the net must
    see it (a git/gh word) or report the command NOT MEASURED — never nothing. Overmatch the other way is allowed."""
    d = _stub_dir(tmp_path)
    env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"])
    ran = False
    for shell in (["bash", "-c"], ["/usr/bin/zsh", "-c"], ["dash", "-c"]):
        if subprocess.run([shell[0], "-c", "exit 0"], capture_output=True).returncode != 0:
            continue
        out = subprocess.run(shell + [command], capture_output=True, text=True, env=env, cwd=str(d),
                             timeout=30).stdout
        ran = ran or "RAN:git" in out or "RAN:gh" in out
    if ran:
        assert gate._net_words(command) >= 1 or gate._net_unresolved(command), command


# --- Punkt 2: one decision site, every free exit of the net goes through it ----------------------------------------
_ATTACKS = _R14_1 + _R14_2 + _R14_3 + ["for f in *.py; do echo $f; done"]


@pytest.mark.parametrize("command", _ATTACKS + _FREE + ["git status", "git push origin main", "echo hi"])
def test_the_net_verdict_is_the_single_sites_verdict(command):
    """Punkt 2: the net's unresolved verdict is exactly _net_unmodeled's. No other branch can let a command exit
    the net without going through the one site that decides understood versus NOT MEASURED."""
    assert gate._net_unresolved(command) == gate._net_unmodeled(command), command


def test_without_the_single_site_the_site_dependent_attacks_bypass(monkeypatch):
    """Punkt 2, the class test that goes red if a form bypasses: with the real site every attack is NOT MEASURED.
    Partition the class by whether the normal form already surfaces a literal git/gh word. The site-dependent forms
    (no literal word) are caught by the decision site alone: force the site to 'understood' and each exits the net
    free, proving the site — not some incidental branch — is what catches them. The remaining form keeps a literal
    git word from its decoded substitution and stays caught by the word test (defence in depth). The test goes red
    if a supposedly site-only form is still caught with the site disabled (the class was mislabelled) or if the
    real site lets any attack through."""
    for command in _ATTACKS:
        assert gate._net_unresolved(command) or gate._net_words(command) >= 1, command
    site_only = [c for c in _ATTACKS if gate._net_words(c) == 0]
    word_too = [c for c in _ATTACKS if gate._net_words(c) >= 1]
    assert site_only, "the class must contain forms only the site catches"
    for command in site_only:
        assert gate._net_unresolved(command) is True, command
    monkeypatch.setattr(gate, "_net_unmodeled", lambda text, depth=0: False)
    for command in site_only:
        assert gate._net_unresolved(command) is False and gate._net_words(command) == 0, command
    for command in word_too:
        assert gate._net_words(command) >= 1, command


# --- R14-4: the verifier answer reader, extended init / notification / reply-id contract (unit) --------------------
_INIT_OK = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                             "serverInfo": {"name": "proofbundle", "version": "0.3.0"}}})
_GREEN = json.dumps({"jsonrpc": "2.0", "id": 1,
                     "result": {"isError": False,
                                "content": [{"type": "text", "text": json.dumps({"exit_code": 0})}]}})


def _init(result):
    return json.dumps({"jsonrpc": "2.0", "id": 0, "result": result})


def _notif(method, params):
    return json.dumps({"jsonrpc": "2.0", "method": method, "params": params})


def _run(monkeypatch, lines):
    monkeypatch.setattr(gate.shutil, "which", lambda name: "/usr/bin/true")
    out = "".join(line + "\n" for line in lines)
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, _o=out, **k: subprocess.CompletedProcess(a, 0, _o, ""))
    return gate.verify_items([{"kind": "bundle"}], time.monotonic() + 30)


@pytest.mark.parametrize("stream, why", [
    ([_init(None), _GREEN], "result is null"),
    ([_init(False), _GREEN], "result is false"),
    ([_init({}), _GREEN], "result is an empty object"),
    ([_init({"protocolVersion": "1999-01-01", "capabilities": {}, "serverInfo": {"name": "p", "version": "1"}}),
      _GREEN], "an unsupported protocol version"),
    ([_init({"protocolVersion": "2025-06-18", "capabilities": None, "serverInfo": {"name": "p", "version": "1"}}),
      _GREEN], "capabilities is null"),
    ([_init({"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": False}), _GREEN],
     "serverInfo is false"),
    ([_INIT_OK, _notif("notifications/progress", {"progressToken": None, "progress": 1}), _GREEN],
     "a progress notification with a null token"),
    ([_INIT_OK, _notif("notifications/progress", {"progressToken": "t", "progress": False}), _GREEN],
     "a progress notification with a false progress"),
    ([_INIT_OK, _notif("notifications/unknown", {}), _GREEN], "a notification the gate does not model"),
    ([_INIT_OK, json.dumps({"jsonrpc": "2.0", "id": 99,
                            "result": {"content": [{"type": "text", "text": "{}"}]}}), _GREEN],
     "a reply for a request the gate did not send"),
])
def test_r14_4_a_contract_break_refuses_the_run(monkeypatch, stream, why):
    """R14-4: at 2a1c1237 each of these streams read as `pass`; now each refuses the whole verifier run."""
    with pytest.raises(gate.GateError):
        _run(monkeypatch, stream)


@pytest.mark.parametrize("stream", [
    [_INIT_OK, _GREEN],
    [_INIT_OK, _notif("notifications/progress", {"progressToken": "t", "progress": 1.5}), _GREEN],
    [_INIT_OK, _notif("notifications/message", {"level": "info", "data": "x"}), _GREEN],
])
def test_r14_4_a_valid_stream_is_still_read(monkeypatch, stream):
    """Control: a valid initialisation, a well-formed permitted notification and a green reply are read; the run
    is not refused by the stricter contract."""
    results = _run(monkeypatch, stream)
    assert results[0]["exit_code"] == 0 and results[0]["is_error"] is False


# --- R14-4: the real pinned verifier (valid -> verified, changed signature -> denied) ------------------------------
_HAS_UV = gate.shutil.which("uv") is not None


@pytest.fixture(scope="module")
def _real_bundle(tmp_path_factory):
    d = tmp_path_factory.mktemp("n37-real")
    payload = d / "payload.json"
    payload.write_text(json.dumps({"n37": "control", "value": 1}), encoding="utf-8")
    bundle, seed = d / "bundle.json", d / "seed.bin"
    proc = subprocess.run([sys.executable, "-m", "proofbundle.cli", "emit", "--payload-file", str(payload),
                           "--out", str(bundle), "--new-key", str(seed)], capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        pytest.skip(f"proofbundle emit unavailable: {proc.stderr.strip()[:120]}")
    obj = json.loads(bundle.read_text(encoding="utf-8"))
    sig = obj.get("signature")
    key = next((k for k in ("signature_b64", "sig_b64") if isinstance(sig, dict) and k in sig), None)
    if key is None:
        pytest.skip("the emitted bundle carries no recognised signature field")
    first = sig[key][0]
    sig[key] = ("B" if first != "B" else "C") + sig[key][1:]
    tampered = d / "bundle_tampered.json"
    tampered.write_text(json.dumps(obj), encoding="utf-8")
    return bundle, tampered


@pytest.mark.skipif(not _HAS_UV, reason="uv not available to start the pinned server")
def test_r14_4_the_real_server_verifies_a_valid_bundle(_real_bundle):
    """Control over the real pinned MCP server: a valid bundle verifies (exit 0)."""
    bundle, _ = _real_bundle
    results = gate.verify_items([{"kind": "bundle", "path": str(bundle)}], time.monotonic() + 180)
    assert results[0]["exit_code"] == 0 and results[0].get("verified") is True and results[0]["is_error"] is False


@pytest.mark.skipif(not _HAS_UV, reason="uv not available to start the pinned server")
def test_r14_4_the_real_server_denies_a_changed_signature(_real_bundle):
    """Control over the real pinned MCP server: a changed signature is not verified (exit non-zero)."""
    _, tampered = _real_bundle
    results = gate.verify_items([{"kind": "bundle", "path": str(tampered)}], time.monotonic() + 180)
    assert results[0]["exit_code"] != 0 and results[0].get("verified") is False


# --- owner correction to N37: a Nachtrag-24 rule never frees a NOT MEASURED form -----------------------------------
def _gate_dir_with(tmp_path, mode, rules):
    gatedir = tmp_path / "gatedir"
    gatedir.mkdir()
    (gatedir / "mode").write_text(mode + "\n", encoding="utf-8")
    (gatedir / "rules.json").write_text(json.dumps(rules), encoding="utf-8")
    return gatedir


def _env_for(gatedir):
    return {**os.environ, "PROOFBUNDLE_GATE_DIR": str(gatedir),
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}


def _rule_for(repo, form, environ, effect="free"):
    deadline = time.monotonic() + 10
    common = os.path.realpath(gate._repo_paths(str(repo), deadline)[0]["common"])
    digest = gate._bound_state_digest(str(repo), deadline, environ)
    return {"repo": common, "form": form, "effect": effect, "state_digest": digest}


def test_n24_a_rule_can_free_an_understood_plain_form(tmp_path):
    """Positive control for the N24 mechanism: in with-approvals mode a human rule frees a plain, understood local
    git form whose bound-state digest matches."""
    repo = _repo(tmp_path)
    gatedir = tmp_path / "gd"
    gatedir.mkdir()
    (gatedir / "mode").write_text("with-approvals\n", encoding="utf-8")
    environ = _env_for(gatedir)
    (gatedir / "rules.json").write_text(json.dumps([_rule_for(repo, "git status", environ)]), encoding="utf-8")
    out = gate.decide("git status", str(repo), time.monotonic() + 10, host="claude", environ=environ)
    assert out is not None and out.decision == "pass", out


@pytest.mark.parametrize("mode", ["with-approvals", "strict"])
def test_n24_a_rule_never_frees_a_not_measured_form(tmp_path, monkeypatch, mode):
    """Owner correction: a rule naming a NOT MEASURED form never frees it, in with-approvals mode as in strict.
    `git status` is forced NOT MEASURED through the single site; a freeing rule for it is installed; the gate still
    refuses to free it under either host."""
    repo = _repo(tmp_path)
    gatedir = tmp_path / "gd"
    gatedir.mkdir()
    (gatedir / "mode").write_text(mode + "\n", encoding="utf-8")
    environ = _env_for(gatedir)
    (gatedir / "rules.json").write_text(json.dumps([_rule_for(repo, "git status", environ)]), encoding="utf-8")
    monkeypatch.setattr(gate, "_net_unmodeled", lambda text, depth=0: True)
    assert gate._rule_candidate("git status", str(repo), time.monotonic() + 10) is None
    for host in ("claude", "codex"):
        out = gate.decide("git status", str(repo), time.monotonic() + 10, host=host, environ=environ)
        assert out is not None and out.decision != "pass", (mode, host, out.decision)


@pytest.mark.parametrize("mode", ["with-approvals", "strict"])
def test_n24_a_rule_for_a_real_not_measured_form_does_not_free_it(tmp_path, mode):
    """The same guarantee on a form that is genuinely NOT MEASURED without any monkeypatch: a locale quote. A rule
    naming it frees nothing; the gate asks (Claude) or denies (Codex)."""
    repo = _repo(tmp_path)
    form = 'git commit -m $"x"'
    assert gate._net_unresolved(form) is True
    gatedir = tmp_path / "gd"
    gatedir.mkdir()
    (gatedir / "mode").write_text(mode + "\n", encoding="utf-8")
    environ = _env_for(gatedir)
    (gatedir / "rules.json").write_text(
        json.dumps([{"repo": os.path.realpath(gate._repo_paths(str(repo), time.monotonic() + 10)[0]["common"]),
                     "form": form, "effect": "free", "state_digest": "0" * 64}]), encoding="utf-8")
    for host in ("claude", "codex"):
        out = gate.decide(form, str(repo), time.monotonic() + 10, host=host, environ=environ)
        assert out is None or out.decision != "pass", (mode, host, out)
