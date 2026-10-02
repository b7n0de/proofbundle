"""Nachtrag 19 (Runde 6): fixed tests for the push gate's Befund 1 and 2, the insteadOf narrowing (Punkt 2),
the R4-7K verdict texts (Punkt 5) and R6-1 (gated MCP writes). R6-2 is in test_plugin_runde6_r62.py and
R6-3 in test_plugin_evals.py.

Each property was red against 2b813de2 and is green here. Built like the Runde 5 tests: throwaway
repositories, each with its own bare remote and a pushed base state, one declaring valid evidence and one
declaring evidence that does not exist. The git configuration is isolated; a test that needs a global rule
writes it to its own global config file and points GIT_CONFIG_GLOBAL at it. Nothing is pushed anywhere but
to the throwaway bare remotes, and no MCP tool is executed: the MCP cases are synthetic hook events.
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

TARGET_ABSENT = ("NOT MEASURED: The target ref does not exist; this gate does not yet implement the history "
                 "and initial-policy checks for creating it.")
#: A global rule that is common in practice and provably does not apply to a filesystem-path remote.
NON_HITTING_GLOBAL_RULE = ("url.ssh://git@github.com/", "https://github.com/")


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
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
    """As in test_plugin_gate_runde5: a repository with its own bare remote and a pushed base state on main;
    declare is 'valid', 'missing' (a declaration naming evidence files that do not exist) or 'none'."""
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


def _global_rule(tmp_path: pathlib.Path, monkeypatch, base: str, prefix: str, kind: str = "insteadOf") -> None:
    cfg = tmp_path / "global.gitconfig"
    cfg.write_text(f'[url "{base}"]\n\t{kind} = {prefix}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _zero(repo: pathlib.Path) -> str:
    return "0" * len(_git(repo, "rev-parse", "HEAD").stdout.strip())


# --- Befund 1: a proven evidence failure stays a deny when the target comparison is NOT MEASURED --------

def test_b1_a_global_rule_that_misses_the_target_and_missing_evidence_denies(tmp_path, monkeypatch):
    # The reviewer's measurement: the same clearly named source with missing evidence gave deny/missing_file
    # without the rule and ask/push_not_measured with a global rule irrelevant to the actual target.
    repo, _ = _make_repo(tmp_path, "r", declare="missing")
    _global_rule(tmp_path, monkeypatch, *NON_HITTING_GLOBAL_RULE)
    verdict = gate.evaluate_push(str(repo), ["origin", "main"], _deadline())
    assert (verdict.decision, verdict.reason_id) == ("deny", "missing_file"), verdict.text()


def test_b1_an_applicable_rewrite_keeps_a_proven_evidence_failure_a_deny(tmp_path):
    # A rule that DOES rewrite this remote's URL: the comparison stays NOT MEASURED, but the evidence at the
    # uniquely determined source commit is checked, and its failure stays a deny; the unmeasured comparison
    # is named separately in the same verdict (Punkt 1).
    repo, bare = _make_repo(tmp_path, "r", declare="missing")
    _git(repo, "config", f"url.{bare}.insteadOf", str(bare))
    verdict = gate.evaluate_push(str(repo), ["origin", "main"], _deadline())
    assert (verdict.decision, verdict.reason_id) == ("deny", "missing_file"), verdict.text()
    assert "comparison with the target was NOT MEASURED" in verdict.text()


def test_b1_an_applicable_rewrite_with_valid_evidence_is_never_positive(tmp_path):
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    _git(repo, "config", f"url.{bare}.insteadOf", str(bare))
    verdict = gate.evaluate_push(str(repo), ["origin", "main"], _deadline())
    assert verdict.decision == "ask" and verdict.reason_id == "push_not_measured", verdict.text()


@pytest.mark.parametrize("args", [["--all", "origin"], ["origin", "refs/heads/*:refs/heads/*"]])
def test_b1_an_unclear_source_is_never_judged_by_a_substitute_check_of_head(tmp_path, args):
    # With an unclear source no check of HEAD stands in: neither a positive verdict nor a deny derived from
    # HEAD; the push stays NOT MEASURED (Punkt 1, last sentence).
    for declare in ("missing", "valid"):
        repo, _ = _make_repo(tmp_path / declare, "r", declare=declare)
        verdict = gate.evaluate_push(str(repo), list(args), _deadline())
        assert verdict.decision == "ask" and verdict.reason_id == "push_not_measured", (declare, verdict.text())


def test_b1_sibling_a_new_remote_ref_with_missing_evidence_denies_on_ebene_2(tmp_path):
    # Sibling of Befund 1 in the shared core: the pre-push target ref does not exist (remote null OID), so
    # the comparison is NOT MEASURED, but the sent source commit's evidence failure is proven: deny.
    repo, _ = _make_repo(tmp_path, "r", declare="missing")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    verdict = gate.pre_push_verdict(str(repo), [("refs/heads/feature", head, "refs/heads/feature",
                                                 _zero(repo))], _deadline())
    assert (verdict.decision, verdict.reason_id) == ("deny", "missing_file"), verdict.text()
    assert TARGET_ABSENT[len("NOT MEASURED: "):] in verdict.text()


# --- Punkt 2: insteadOf asks only for rules that apply to this remote ---------------------------------

def test_p2_a_global_rule_that_misses_the_target_lets_a_valid_push_resolve(tmp_path, monkeypatch):
    # A rule for another host provably does not rewrite this (path) remote, so it no longer forces an ask:
    # the push resolves and its evidence is judged as without the rule (here: the tip the remote holds).
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    _global_rule(tmp_path, monkeypatch, *NON_HITTING_GLOBAL_RULE)
    assert gate.resolve_push_targets(str(repo), ["origin", "main"], _deadline()) is not None
    verdict = gate.evaluate_push(str(repo), ["origin", "main"], _deadline())
    assert (verdict.decision, verdict.reason_id) == ("pass", "verified"), verdict.text()


@pytest.mark.parametrize("kind", ["insteadOf", "pushInsteadOf"])
def test_p2_a_rule_that_rewrites_this_remote_stays_not_measured(tmp_path, monkeypatch, kind):
    # Equal effective fetch and push URLs do not prove where an existing tracking ref came from; a rule
    # that applies to this remote keeps the comparison NOT MEASURED, a global one included.
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    _global_rule(tmp_path, monkeypatch, f"file://{bare}", str(bare), kind)
    assert gate.resolve_push_targets(str(repo), ["origin", "main"], _deadline()) is None


def test_p2_the_longest_matching_prefix_decides_which_rule_applies(tmp_path):
    # Two insteadOf rules match the remote URL; git uses the longest. Either way the remote is rewritten,
    # so the comparison is NOT MEASURED, and the gate names the rule git applies.
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    short, long_ = str(bare)[: len(str(bare)) // 2], str(bare)
    _git(repo, "config", "url.file:///short/.insteadOf", short)
    _git(repo, "config", "url.file:///long/.insteadOf", long_)
    rules = gate._applicable_rewrites(str(repo), "origin", _deadline())
    assert rules and any("file:///long/" in r for r in rules), rules
    assert not any("file:///short/" in r for r in rules), rules  # the shorter match is not the one git uses


def test_p2_push_insteadof_is_ignored_for_a_remote_with_an_explicit_pushurl(tmp_path):
    # git-config: "If a remote has an explicit pushurl, Git will ignore this setting for that remote."
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    _git(repo, "config", "remote.origin.pushurl", str(bare))
    _git(repo, "config", "url.file:///elsewhere/.pushInsteadOf", str(bare))
    assert _git(repo, "remote", "get-url", "--push", "origin").stdout.strip() == str(bare)  # git ignores it
    assert gate._applicable_rewrites(str(repo), "origin", _deadline()) == []


def test_p2_insteadof_applies_to_an_explicit_pushurl(tmp_path):
    repo, bare = _make_repo(tmp_path, "r", declare="valid")
    _git(repo, "config", "remote.origin.pushurl", str(bare))
    _git(repo, "config", "url.file:///elsewhere/.insteadOf", str(bare))
    assert gate._applicable_rewrites(str(repo), "origin", _deadline()) != []
    assert gate.resolve_push_targets(str(repo), ["origin", "main"], _deadline()) is None


# --- Befund 2: a measured absent target ref and a missing local tracking ref are different messages ----

def test_b2_a_remote_null_oid_reports_the_verbatim_target_absent_message(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    verdict = gate.pre_push_verdict(str(repo), [("refs/heads/feature", head, "refs/heads/feature",
                                                 _zero(repo))], _deadline())
    assert verdict.decision == "ask"
    assert verdict.detail == TARGET_ABSENT
    assert verdict.text().startswith("NOT MEASURED: ") and TARGET_ABSENT[len("NOT MEASURED: "):] in verdict.text()


def test_b2_a_missing_local_tracking_ref_keeps_the_previous_text(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    verdict = gate.evaluate_push(str(repo), ["origin", "main:refs/heads/newbranch"], _deadline())
    assert verdict.decision == "ask" and verdict.reason_id == "push_not_measured"
    assert "does not track" in verdict.text()
    assert "The target ref does not exist" not in verdict.text()


# --- Punkt 5: every comparison verdict names the locally known state (R4-7K) -------------------------

def test_p5_a_rules_change_verdict_names_the_locally_known_state(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    policy = json.loads((repo / POLICY).read_text(encoding="utf-8"))
    policy["allowed_issuers"].append({"public_key_b64": base64.b64encode(
        generate_signer().public_key().public_bytes_raw()).decode()})
    (repo / POLICY).write_text(json.dumps(policy), encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "widen")
    verdict = gate.evaluate_push(str(repo), ["origin", "main"], _deadline())
    assert verdict.reason_id == "rules_changed", verdict.text()
    assert "last known state of the target in this repository, not a state read from the remote" in verdict.text()


def test_p5_a_rules_change_on_ebene_2_names_the_remote_state_git_reported(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    remote = _git(repo, "rev-parse", "origin/main").stdout.strip()
    policy = json.loads((repo / POLICY).read_text(encoding="utf-8"))
    policy["allowed_issuers"].append({"public_key_b64": base64.b64encode(
        generate_signer().public_key().public_bytes_raw()).decode()})
    (repo / POLICY).write_text(json.dumps(policy), encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "widen")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    verdict = gate.pre_push_verdict(str(repo), [("refs/heads/main", head, "refs/heads/main", remote)],
                                    _deadline())
    assert verdict.reason_id == "rules_changed", verdict.text()
    assert "the remote's state of the target as git reported it to the pre-push hook" in verdict.text()


# --- R6-1: a gated MCP write is NOT MEASURED; ask under Claude, deny under Codex ----------------------

def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(pathlib.Path(proofbundle.__file__).resolve().parent.parent),
                    os.environ.get("PYTHONPATH")) if p)
    return env


def _mcp(repo: pathlib.Path, tool: str, host: str) -> dict:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo),
                        "tool_input": {"owner": "o", "repo": "r", "branch": "main",
                                       "files": [{"path": ".proofbundle/evidence.json", "content": "{}"}]}})
    out = subprocess.run([sys.executable, str(GATE), "--host", host], input=event, capture_output=True,
                         text=True, cwd=str(repo), env=_clean_env(), timeout=120, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("tool", ["mcp__github__push_files", "mcp__github__create_release"])
@pytest.mark.parametrize("declare", ["none", "missing", "valid"])
@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_r6_1_a_gated_mcp_write_is_not_measured_whatever_the_local_repository(tmp_path, tool, declare,
                                                                              host, expected):
    # The reviewer's measurement: under --host codex an unchanged push_files with invalid evidence in the
    # files it writes read 'inactive', exit 0 and no permissionDecision when the local repository declared
    # nothing. Now the decision never depends on the local repository: NOT MEASURED, ask or deny by host.
    repo, _ = _make_repo(tmp_path, "r", declare=declare)
    answer = _mcp(repo, tool, host)
    specific = answer["hookSpecificOutput"]
    assert specific.get("permissionDecision") == expected, answer
    assert specific["permissionDecisionReason"].startswith("NOT MEASURED:"), answer
    assert "Diagnosis only" in answer["systemMessage"], answer


def test_r6_1_decide_mcp_takes_the_host(tmp_path):
    repo, _ = _make_repo(tmp_path, "r", declare="none")
    claude = gate.decide_mcp("mcp__github__push_files", str(repo), _deadline())
    codex = gate.decide_mcp("mcp__github__push_files", str(repo), _deadline(), host="codex")
    assert (claude.decision, codex.decision) == ("ask", "deny")
    assert claude.verdicts[0].reason_id == codex.verdicts[0].reason_id == "mcp_target_unbound"
    assert gate.decide_mcp("mcp__github__create_issue", str(repo), _deadline(), host="codex") is None


# --- R6-2 sibling: a push option that selects the receiving program --------------------------------------

@pytest.mark.parametrize("args", [["--receive-pack=/tmp/ship.sh", "origin", "main"],
                                  ["--exec", "/tmp/ship.sh", "origin", "main"]])
def test_r6_2_sibling_push_receive_pack_is_not_measured(tmp_path, args):
    # --receive-pack (alias --exec) names the program that runs as the receiving end; a path or file://
    # transport starts it on this machine. The push is NOT MEASURED, never resolved as if neutral.
    repo, _ = _make_repo(tmp_path, "r", declare="valid")
    assert gate.resolve_push_targets(str(repo), list(args), _deadline()) is None
    verdict = gate.evaluate_push(str(repo), list(args), _deadline())
    assert verdict.decision == "ask" and verdict.reason_id == "push_not_measured", verdict.text()
