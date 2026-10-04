"""Nachtrag 24 (approval by a human-written rule), locks L1 to L10, at the gate exit on both host paths.

A human may free one plain local git form in one repository by writing a rule, but only in "with-approvals" mode
and never under Codex; push and gh are never freed; a freed form stops being free the moment the repository's
program-selecting state changes; and the model can neither set the mode nor write a rule (the gate directory is a
deny target for every file-writing tool, under both hosts). There is no click path: owner choice A of Nachtrag 31
measures the host's approval behaviour first, and until then the rule-file mechanism stands alone.

Red/green at the named commit (claude/codex-plugin):
- L2 (a free rule acts), L6 (a write to the gate directory denies on both hosts) and the `state-digest` CLI are
  red at 096b7191 (the capability and the deny are new), green after.
- L1, L3, L5, L7, L8, L9, L10 are safety constraints on the new capability; they are green at 096b7191 only
  because the capability does not exist there, so each also has its catch proof in the mutation run (n24/fang),
  where undoing the guard turns the lock red.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
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


def _common(repo: pathlib.Path) -> str:
    out = _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()
    return os.path.realpath(out)


def _gate_env(tmp_path: pathlib.Path, logs: pathlib.Path) -> tuple[dict, pathlib.Path]:
    """The host environment plus a user-wide gate directory the model cannot reach through the repository."""
    gate_dir = tmp_path / "gatehome" / ".config" / "proofbundle"
    gate_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(logs), "PLUGIN_DATA": str(logs),
           "PROOFBUNDLE_GATE_DIR": str(gate_dir)}
    return env, gate_dir


def _set_mode(gate_dir: pathlib.Path, mode: str) -> None:
    (gate_dir / "mode").write_text(mode + "\n", encoding="utf-8")


def _set_rules(gate_dir: pathlib.Path, rules: list[dict]) -> None:
    (gate_dir / "rules.json").write_text(json.dumps(rules), encoding="utf-8")


def _digest(repo: pathlib.Path, env: dict) -> str:
    value = gate._bound_state_digest(str(repo), __import__("time").monotonic() + 30, env)
    assert value is not None
    return value


def _hook(env: dict, repo: pathlib.Path, host: str, command: str) -> tuple[str | None, dict]:
    """Run the gate as the host runs it for a Bash command: the permission decision of its JSON answer (None for
    no decision — a pass, an inactive gate or an ungated call) and the last log entry."""
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    logs = pathlib.Path(env["CLAUDE_PLUGIN_DATA"] if host == "claude" else env["PLUGIN_DATA"])
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer.get("hookSpecificOutput", {}).get("permissionDecision"), entry


def _write_hook(env: dict, repo: pathlib.Path, host: str, tool: str, tool_input: dict) -> str | None:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo),
                        "tool_input": tool_input})
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return answer.get("hookSpecificOutput", {}).get("permissionDecision")


# --- L1: strict mode is the default, and a rule does not act in it -------------------------------------------------
def test_l1_strict_default_ignores_a_matching_free_rule(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    # no mode file -> strict (the default): the rule does not act, so the form asks under Claude, denies under Codex
    d_claude, entry = _hook(env, repo, "claude", "git status")
    d_codex, _ = _hook(env, repo, "codex", "git status")
    assert d_claude == "ask" and d_codex == "deny", (d_claude, d_codex)
    assert entry["mode"] == "strict" and "applied_rule" not in entry
    assert "approved_by_rule" not in entry["reason_ids"]


# --- L2: with-approvals, a matching free rule frees the exact form in the exact repo (red at 096b7191) -------------
def test_l2_with_approvals_a_matching_free_rule_passes(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    d_claude, entry = _hook(env, repo, "claude", "git status")
    assert d_claude is None, d_claude                      # a pass carries no permission decision
    assert entry["decision"] == "none" and entry["verdict"] == "pass"
    assert entry["mode"] == "with-approvals"
    assert entry["applied_rule"] == {"origin": "rule", "repo": _common(repo), "form": "git status",
                                     "effect": "free", "state_match": True}
    assert "approved_by_rule" in entry["reason_ids"]


def test_l2_without_a_rule_the_same_form_still_asks(tmp_path):
    """Control: with-approvals but no rule -> the form asks, so the pass is the rule's doing, not the mode's."""
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [])
    assert _hook(env, repo, "claude", "git status")[0] == "ask"


# --- L3: push and gh are never freed, even by a rule that names them -----------------------------------------------
def test_l3_a_rule_naming_push_or_gh_never_frees_it(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git push origin main", "effect": "free",
                           "state_digest": _digest(repo, env)},
                          {"repo": _common(repo), "form": "gh pr create --fill", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    for command in ("git push origin main", "gh pr create --fill"):
        d_claude, entry = _hook(env, repo, "claude", command)
        assert "applied_rule" not in entry, (command, entry.get("applied_rule"))
        assert "approved_by_rule" not in entry["reason_ids"], command
        assert _hook(env, repo, "codex", command)[0] == "deny", command


# --- L4/L6: a write to the gate directory denies on both hosts (red at 096b7191) -----------------------------------
@pytest.mark.parametrize("name", ["mode", "rules.json", "gate-log.jsonl", "sub/dir/evil"])
def test_l6_write_to_the_gate_directory_denies_on_both_hosts(tmp_path, name):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    target = str(gate_dir / name)
    for host in ("claude", "codex"):
        assert _write_hook(env, repo, host, "Write", {"file_path": target, "content": "with-approvals"}) == "deny", \
            (host, name)


def test_l6_an_apply_patch_into_the_gate_directory_denies(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    patch = f"*** Begin Patch\n*** Add File: {gate_dir / 'rules.json'}\n+[]\n*** End Patch\n"
    for host in ("claude", "codex"):
        assert _write_hook(env, repo, host, "apply_patch", {"command": patch}) == "deny", host


def test_l6_an_ordinary_file_in_the_repo_is_not_denied_by_the_gate_dir_rule(tmp_path):
    """Control: a write to an ordinary repo file is not a gate-directory write (it may still ask as a repo write,
    but it is never the gate-directory deny)."""
    logs = tmp_path / "logs"
    env, _ = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    assert _write_hook(env, repo, "claude", "Write", {"file_path": str(repo / "b.txt"), "content": "b"}) is None


# --- L5: a change to the program-selecting state stops a rule acting -----------------------------------------------
def test_l5_a_config_change_stops_the_rule(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    assert _hook(env, repo, "claude", "git status")[0] is None       # the rule acts
    _git(repo, "config", "core.pager", "less")                       # the state changes
    assert _hook(env, repo, "claude", "git status")[0] == "ask"      # the rule no longer acts
    _git(repo, "config", "--unset", "core.pager")                    # restored -> the rule acts again
    assert _hook(env, repo, "claude", "git status")[0] is None


def test_l5_a_new_hook_stops_the_rule(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    assert _hook(env, repo, "claude", "git status")[0] is None
    (pathlib.Path(_common(repo)) / "hooks" / "pre-commit").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert _hook(env, repo, "claude", "git status")[0] == "ask"


# --- L7: a malformed or oversized rule file frees nothing (fail-closed) --------------------------------------------
@pytest.mark.parametrize("content", [
    "{ not json",                                             # not JSON
    "{}",                                                     # a list is required
    '[{"repo":"x","form":"git status","effect":"free","state_digest":"d"}]',   # repo not absolute
    '[{"repo":"/a","form":"git status","effect":"maybe","state_digest":"d"}]',  # effect not free/ask
    '[{"repo":"/a","form":"git status","effect":"free"}]',   # missing state_digest
    '[{"repo":"/a","form":"git status","effect":"free","state_digest":"d","extra":1}]',  # unknown key
])
def test_l7_a_malformed_rule_file_asks(tmp_path, content):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    (gate_dir / "rules.json").write_text(content, encoding="utf-8")
    assert _hook(env, repo, "claude", "git status")[0] == "ask", content


def test_l7_a_duplicate_key_in_the_rule_file_asks(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    digest = _digest(repo, env)
    (gate_dir / "rules.json").write_text(
        f'[{{"repo":"{_common(repo)}","form":"git status","form":"git log","effect":"free",'
        f'"state_digest":"{digest}"}}]', encoding="utf-8")
    assert _hook(env, repo, "claude", "git status")[0] == "ask"


# --- L8: under Codex, rules are ignored and every form denies ------------------------------------------------------
def test_l8_codex_denies_even_with_a_matching_free_rule(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    d_codex, entry = _hook(env, repo, "codex", "git status")
    assert d_codex == "deny"
    assert "applied_rule" not in entry and "approved_by_rule" not in entry["reason_ids"]


# --- L9: a missing or unreadable mode file is strict ---------------------------------------------------------------
@pytest.mark.parametrize("mode_text", ["", "   ", "on", "approve", "x" * 200,
                                       "with-approvals" + " " * 60])   # a valid word padded past the size limit
def test_l9_an_unknown_or_oversized_mode_is_strict(tmp_path, mode_text):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    (gate_dir / "mode").write_text(mode_text, encoding="utf-8")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free",
                           "state_digest": _digest(repo, env)}])
    d_claude, entry = _hook(env, repo, "claude", "git status")
    assert d_claude == "ask" and entry["mode"] == "strict", mode_text


# --- L10: a rule with effect "ask" forces a question even in with-approvals ----------------------------------------
def test_l10_an_ask_rule_forces_a_question(tmp_path):
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    digest = _digest(repo, env)
    _set_rules(gate_dir, [{"repo": _common(repo), "form": "git status", "effect": "free", "state_digest": digest},
                          {"repo": _common(repo), "form": "git status", "effect": "ask", "state_digest": digest}])
    d_claude, entry = _hook(env, repo, "claude", "git status")
    assert d_claude == "ask" and "applied_rule" not in entry


# --- the state-digest CLI (red at 096b7191: the subcommand is new) -------------------------------------------------
def test_state_digest_cli_prints_the_digest_and_a_skeleton(tmp_path):
    env, _ = _gate_env(tmp_path, tmp_path / "logs")
    repo = _repo(tmp_path)
    proc = subprocess.run([sys.executable, "-I", str(GATE), "state-digest", "--repo", str(repo)],
                          capture_output=True, text=True, env=env, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0] == _digest(repo, env)                  # the same digest the gate recomputes
    skeleton = json.loads("\n".join(lines[1:]))
    assert skeleton["repo"] == _common(repo) and skeleton["effect"] == "free"
    assert skeleton["state_digest"] == lines[0]


def test_state_digest_cli_outside_a_repository_reports_and_exits_1(tmp_path):
    env, _ = _gate_env(tmp_path, tmp_path / "logs")
    outside = tmp_path / "plain"
    outside.mkdir()
    proc = subprocess.run([sys.executable, "-I", str(GATE), "state-digest", "--repo", str(outside)],
                          capture_output=True, text=True, env=env, timeout=60, check=False)
    assert proc.returncode == 1 and "not a git repository" in proc.stderr


# --- a path invocation or a global option is never a rule candidate ------------------------------------------------
@pytest.mark.parametrize("command", [
    "/usr/bin/git status",             # a program path, not a bare git
    "git -c core.pager=less status",   # a per-command config option
    "git -C . status",                 # a -C global option
    "GIT_PAGER=less git status",       # a prefix assignment
    "git status && git log",           # a chain
])
def test_a_non_plain_form_is_never_freed_by_a_rule(tmp_path, command):
    """Even a rule whose form is byte-identical to the command cannot free a non-plain form: the command must be
    exactly one bare `git <local-subcommand>` with no option or prefix, so the state digest binds its repository."""
    logs = tmp_path / "logs"
    env, gate_dir = _gate_env(tmp_path, logs)
    repo = _repo(tmp_path)
    _set_mode(gate_dir, "with-approvals")
    _set_rules(gate_dir, [{"repo": _common(repo), "form": command, "effect": "free",
                           "state_digest": _digest(repo, env)}])
    d_claude, entry = _hook(env, repo, "claude", command)
    assert "applied_rule" not in entry, (command, entry.get("applied_rule"))
    assert d_claude == "ask", (command, d_claude)
