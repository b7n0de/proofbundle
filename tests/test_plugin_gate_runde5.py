"""Nachtrag 18 (Runde 5): the gate's fixed tests for the reviewer's findings and Cowork's measurements.

Each property has a negative case that was red against 110bffdc and is green here. Built like Cowork's
probes: throwaway repositories, each with its own bare remote and a pushed base state, one declaring valid
evidence and one declaring evidence that does not exist. Ebene 1 is the shell grammar (gated_calls /
resolve_push_targets / the PreToolUse gate); Ebene 2 is the prototype pre-push hook (pre_push_verdict and
the `pre-push` CLI entry). The git configuration is isolated so the gate reads the clean configuration the
owner measured, not a proxy-injected global url.*.insteadOf (see _clean_git_config).

Covered: send-pack and unknown subcommands NOT MEASURED (Punkt 6/8); a per-command -c alias NOT MEASURED
without the word push (Punkt 7); R4-7 (url.insteadOf) and R4-6a (-c include.path) NOT MEASURED on Ebene 1,
R4-7K (a stale tracking ref) still possible on Ebene 1 with a comparison-state caveat in its verdict text
(Punkt 9); R5-1 (an unreadable remote OID is NOT MEASURED, never 'absent'); R5-4 (a new remote ref is NOT
MEASURED, not a traceback); R5-5 (a malformed pre-push ref line denies with exit 1); the exit rule (Ebene 2
exits 0 only for pass and a measured inactive); and the Codex case (every push NOT MEASURED, Punkt 10).
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
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    """Isolate git configuration so the gate reads the clean config the owner measured in throwaway repos
    (Runde 5). A proxy-injected global url.*.insteadOf would otherwise make Ebene 1 read NOT MEASURED
    everywhere (Punkt 9); the R4-7 test sets a LOCAL rewrite in the repository and still sees it."""
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=check, capture_output=True, text=True)


DECLARATION = ".proofbundle/evidence.json"
BUNDLE = ".proofbundle/b.json"
POLICY = ".proofbundle/policy.json"


def _make_repo(tmp_path: pathlib.Path, name: str, *, declare: str) -> tuple[pathlib.Path, pathlib.Path]:
    """A repository with its own bare remote and a pushed base state on main. declare is 'valid' (evidence
    that verifies over the tree), 'missing' (a declaration naming evidence files that do not exist), or
    'none'. Returns (repo, bare remote)."""
    repo, bare = tmp_path / name, tmp_path / f"{name}.git"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    if declare in ("valid", "missing"):
        subject = {"algorithm": gate.TREE_ALGORITHM, "digest": gate.tree_digest(str(repo), "HEAD")}
        (repo / ".proofbundle").mkdir()
        item = {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": subject}
        if declare == "valid":
            signer = generate_signer()
            (repo / BUNDLE).write_text(json.dumps(emit_bundle(
                json.dumps({"subject": subject}).encode(), signer)), encoding="utf-8")
            key = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
            (repo / POLICY).write_text(json.dumps({
                "schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
                "allowed_issuers": [{"public_key_b64": key}],
                "signature": {"require_expected_signer": True}}), encoding="utf-8")
        (repo / DECLARATION).write_text(json.dumps(
            {"schema": gate.DECLARATION_SCHEMA, "evidence": [item]}), encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "evidence")
    _git(repo, "init", "-q", "--bare", str(bare))
    _git(repo, "remote", "add", "origin", str(bare))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    _git(repo, "fetch", "-q", "origin")
    return repo, bare


def _deadline() -> float:
    return gate.time.monotonic() + 30


# --- Ebene 1: the shell grammar (Punkt 6, 7, 8) ------------------------------------------------------

@pytest.mark.parametrize("command, name", [
    ("git send-pack https://example/x.git main", "git send-pack"),   # Punkt 8
    ("git push-backup origin main", "git push-backup"),              # an unknown subcommand, Punkt 6
    ("git frobnicate --all", "git frobnicate"),                      # an unknown subcommand, Punkt 6
    ("git rebase -x 'git push origin main' main", "git rebase"),     # runs an arbitrary command, Punkt 6
    ("git bisect run ./pushes.sh", "git bisect"),                    # runs an arbitrary command, Punkt 6
    ("git submodule foreach 'git push'", "git submodule"),          # runs an arbitrary command, Punkt 6
    ("git -c alias.pp=push pp origin main", "git pp"),               # a -c alias, Punkt 7
    ("git -c alias.pp='!git push' pp origin main", "git pp"),        # a -c shell alias, Punkt 7
])
def test_an_unmodelled_git_transfer_is_not_measured(command, name):
    assert gate.gated_calls(command) == [(name, gate.UNKNOWN, [gate._MAYBE_PUSH])]


def test_an_alias_configured_in_the_repo_is_a_not_measured_possible_push():
    # `git pp origin main` with alias.pp set in the repo config: the subcommand `pp` is unknown to Ebene 1
    # (git aliases do not override built-ins), so it is NOT MEASURED, not left alone (Punkt 6/7).
    assert gate.gated_calls("git pp origin main") == [("git pp", gate.UNKNOWN, [gate._MAYBE_PUSH])]


@pytest.mark.parametrize("command", [
    "git status", "git log --oneline", "git diff origin/main", "git fetch origin", "git config user.name t",
])
def test_a_local_subcommand_is_still_left_alone(command):
    # Left alone by the command text; decide() still reads the repository state behind it (Nachtrag 19b).
    assert gate.gated_calls(command) == []


@pytest.mark.parametrize("command", ["git rebase main", "git bisect start", "git submodule status"])
def test_the_exec_capable_subcommands_left_the_allow_list(command):
    # Nachtrag 19b (S1, fallback A): rebase, bisect and submodule check out, merge or clone in their other
    # forms, and their program lists were not justified completely, so no form of them is free any more.
    name = command.split()[0] + " " + command.split()[1]
    assert gate.gated_calls(command) == [(name, gate.UNKNOWN, [gate._MAYBE_PUSH])]


def test_submodule_update_with_an_unchecked_option_is_not_measured():
    # Runde 6, R6-2: `submodule` is in the exec-when class (it can run a configured `!command`), and
    # `--init` is not a vetted inert option for it, so the invocation is NOT MEASURED rather than left
    # alone. Since Nachtrag 19b a bare `git submodule status` is NOT MEASURED too (submodule left the list).
    assert gate.gated_calls("git submodule update --init") == [("git submodule", gate.UNKNOWN, [gate._MAYBE_PUSH])]
    assert gate.gated_calls("git submodule status") == [("git submodule", gate.UNKNOWN, [gate._MAYBE_PUSH])]


def test_a_not_measured_transfer_asks_under_claude_and_denies_under_codex(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    claude = gate.decide("git send-pack file://x main", str(repo), _deadline())
    assert claude.decision == "ask" and claude.text.startswith("NOT MEASURED:")
    codex = gate.decide("git send-pack file://x main", str(repo), _deadline(), host="codex")
    assert codex.decision == "ask"  # the raw verdict; answer() turns a codex ask into a deny


# --- Ebene 1: R4-7 / R4-7K / R4-6a (Punkt 9) ---------------------------------------------------------

@pytest.mark.parametrize("key", ["url.https://mirror/.insteadOf", "url.https://mirror/.pushInsteadOf"])
def test_r4_7_an_insteadof_rewrite_makes_ebene_1_not_measured(tmp_path, key):
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    # The rewrite is configured AFTER the last fetch and applies to this remote's URL; Ebene 1 cannot prove
    # the push endpoint is the origin of the comparison state, so the push is NOT MEASURED (Punkt 9,
    # correcting R4-7 for symmetric insteadOf too). Runde 6, Punkt 2: the rule must actually match the
    # remote's URL; a rule for another host is excluded (test_plugin_gate_runde6.py).
    _git(repo, "config", key, str(bare))
    assert gate.resolve_push_targets(str(repo), ["origin", "main"], _deadline()) is None


def test_r4_6a_a_per_command_config_is_not_measured(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    include = tmp_path / "extra.cfg"
    include.write_text("[remote \"origin\"]\n\tpushurl = https://elsewhere/\n", encoding="utf-8")
    # `git -c include.path=<file> push` carries a per-command config Ebene 1 does not model: NOT MEASURED.
    calls = gate.gated_calls(f"git -c include.path={include} push origin main")
    assert calls == [("git push", gate.UNKNOWN, None)]


def test_r4_7k_a_stale_tracking_state_stays_possible_but_its_text_names_the_local_state(tmp_path):
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    # Another clone advances origin/main after our last fetch; our tracking ref is now stale, with no rewrite.
    other = tmp_path / "other"
    _git(tmp_path, "clone", "-q", "--branch", "main", str(bare), str(other))
    _git(other, "checkout", "-q", "-B", "main", "origin/main")
    (other / "README.md").write_text("moved\n", encoding="utf-8")
    _git(other, "add", "-A")
    _git(other, "commit", "-q", "-m", "advance")
    _git(other, "push", "-q", "origin", "HEAD:refs/heads/main")
    # Ebene 1 still resolves the push against the LOCALLY known (now stale) tracking ref: it is possible, and
    # its verdict text says the comparison is against the locally known state, not read from the remote.
    targets = gate.resolve_push_targets(str(repo), ["origin", "main"], _deadline())
    assert targets is not None
    verdict = gate.evaluate_push(str(repo), ["origin", "main"], _deadline())
    assert verdict.decision in ("pass", "inactive")
    assert "last known state in this repository" in verdict.text() or "last known state of the target" in verdict.text()


# --- Ebene 2: the prototype pre-push hook (R5-1, R5-4, R5-5, exit rule) --------------------------------

def _zero(repo: pathlib.Path) -> str:
    return "0" * len(_git(repo, "rev-parse", "HEAD").stdout.strip())


def test_exit_rule_pass_is_zero_and_a_rules_change_ask_is_one(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    remote = _git(repo, "rev-parse", "origin/main").stdout.strip()
    # A valid push the remote already holds: pass -> exit 0.
    good = _run_prepush(repo, f"refs/heads/main {head} refs/heads/main {remote}")
    assert good.returncode == 0, good.stderr
    # Widen the policy on top (a rules change -> ask); the exit rule now blocks an ask too (Punkt 1).
    policy = json.loads((repo / POLICY).read_text(encoding="utf-8"))
    policy["allowed_issuers"].append({"public_key_b64": base64.b64encode(
        generate_signer().public_key().public_bytes_raw()).decode()})
    (repo / POLICY).write_text(json.dumps(policy), encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "widen")
    new_head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    ask = _run_prepush(repo, f"refs/heads/main {new_head} refs/heads/main {remote}")
    assert ask.returncode == 1, ask.stderr


def test_r5_1_a_deletion_against_an_unreadable_remote_oid_is_not_measured(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    # The remote OID of the ref being deleted is a real-length object this clone does not have: the gate
    # cannot read its tree, so it must be NOT MEASURED (blocked), never 'inactive / nothing_declared' (R5-1).
    unknown = "1" * len(_git(repo, "rev-parse", "HEAD").stdout.strip())
    lines = [("refs/heads/policy", _zero(repo), "refs/heads/policy", unknown)]  # a deletion (local sha zero)
    verdict = gate.pre_push_verdict(str(repo), lines, _deadline())
    assert verdict.decision == "ask" and "NOT MEASURED" in verdict.text()
    assert verdict.reason_id != "nothing_declared"
    out = _run_prepush(repo, f"refs/heads/policy {_zero(repo)} refs/heads/policy {unknown}")
    assert out.returncode == 1, out.stderr


def test_r5_4_a_new_remote_ref_is_not_measured_not_a_traceback(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    # A brand-new remote ref: the remote side is all-zero, so there is no comparison state. The gate must
    # return a controlled NOT MEASURED, not raise a TypeError into rev-list(None) (R5-4).
    lines = [("refs/heads/feature", head, "refs/heads/feature", _zero(repo))]
    verdict = gate.pre_push_verdict(str(repo), lines, _deadline())
    assert verdict.decision == "ask" and "NOT MEASURED" in verdict.text()
    out = _run_prepush(repo, f"refs/heads/feature {head} refs/heads/feature {_zero(repo)}")
    assert out.returncode == 1, out.stderr


@pytest.mark.parametrize("stdin, note", [
    ("corrupt ref line", "a three-field-short line"),
    ("refs/heads/main aaa refs/heads/main", "a three-field line"),
    ("one two three four five", "a five-field line"),
])
def test_r5_5_a_malformed_ref_line_denies_with_exit_1(tmp_path, stdin, note):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    out = _run_prepush(repo, stdin)
    assert out.returncode == 1, (note, out.stdout, out.stderr)
    assert "four fields" in out.stderr, note


def test_a_blank_pre_push_stdin_is_inactive_and_exits_zero(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    out = _run_prepush(repo, "")
    assert out.returncode == 0, out.stderr


# --- the Codex case (Punkt 10) -----------------------------------------------------------------------

def test_codex_a_good_repo_push_is_denied(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": "git push origin main"}})
    out = _run_gate(repo, event, "--host", "codex")
    answer = json.loads(out.stdout)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert answer["hookSpecificOutput"]["permissionDecisionReason"].startswith("NOT MEASURED:")
    assert "workdir" in answer["systemMessage"]


# --- subprocess helpers ------------------------------------------------------------------------------

def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(pathlib.Path(proofbundle.__file__).resolve().parent.parent),
                    os.environ.get("PYTHONPATH")) if p)
    return env


def _run_prepush(repo: pathlib.Path, stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(GATE), "pre-push", "origin", "file://remote"],
                          input=stdin, capture_output=True, text=True, cwd=str(repo), env=_clean_env(),
                          timeout=120, check=False)


def _run_gate(repo: pathlib.Path, event: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(GATE), *args], input=event, capture_output=True, text=True,
                          cwd=str(repo), env=_clean_env(), timeout=120, check=False)
