"""Owner choice N2C-1 B (2026-10-08): the done section and the done policy are evidence rules.

Owner choice N2 C made a push pass only with the done check at the pushed commit, and that check reads the
declaration, the done policy and the order from that commit. Measured on 2026-10-08 at 31031eb6
(probe_done_policy_swap): a push whose own commit swaps the done policy to a new key, with a receipt signed by that
key, passed at Level 1 (`pass`, reason `done`) and the pre-push hook (Level 2) exited 0, because the comparison of
the evidence rules (D20) left the done section and the done policy out. Now both are rules: a push that changes
them against the target's known state asks under Claude Code (`rules_changed`), and Level 2 blocks it (exit 1).
Under Codex the plain push still only warns at Level 1 (K5-1 C); Level 2 carries the check there.

Counter-probes: the done policy swapped to a new key, the done policy rewritten with the same key, each part of the
done section changed, a done check added and removed. Controls: an unchanged done check with a valid receipt
passes, and a change to a file that is not a rule (a receipt, the work) changes nothing.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import time

import pytest

import proofbundle
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt

import test_plugin_gate_n2c_push_done as base

gate = base.gate
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean["CLAUDE_PLUGIN_DATA"] = clean["PLUGIN_DATA"] = str(tmp_path / "logs")
    return clean


def _done(repo: base.Repo) -> dict:
    return json.loads((repo.path / gate.DECLARATION).read_text(encoding="utf-8"))["done"]


def _set_done(repo: base.Repo, done: dict | None) -> None:
    doc = json.loads((repo.path / gate.DECLARATION).read_text(encoding="utf-8"))
    if done is None:
        doc.pop("done")
    else:
        doc["done"] = done
    base._write(repo.path / gate.DECLARATION, doc)


def _order(receipt: str = base.RECEIPT, **extra) -> dict:
    return {"policy": base.POLICY, "checks": [{"id": "tests", "args": [], "receipt": receipt}], **extra}


def _asks_with(env: dict, repo: base.Repo, phrase: str) -> None:
    """Level 2 refuses the push and names the change. Level 1 asks since R9-1 at the destination check, which comes
    before any comparison with the target, so it does not name the change; it never passes the push."""
    answer, entry = base._level1(env, repo.path)
    base.assert_destination_not_measured(answer, entry, clean=False)
    proc = base._level2(env, repo.path)
    assert proc.returncode == 1, proc.stderr
    assert phrase in proc.stderr


# --- the counter-probes -----------------------------------------------------------------------------------------

def test_a_push_that_swaps_the_done_policy_to_its_own_key_asks_and_level_2_blocks(env, tmp_path):
    repo = base.Repo(tmp_path)
    mine = generate_signer()
    base._write(repo.path / base.POLICY, base._policy(mine))
    base._commit(repo.path, "swap the done policy to my key")
    base._receipt(repo.path, mine)
    _asks_with(env, repo, f"the done policy {base.POLICY} changes")


def test_a_rewritten_done_policy_with_the_same_key_still_asks(env, tmp_path):
    repo = base.Repo(tmp_path)
    policy = base._policy(repo.signer)
    policy["policy_id"] = "done-test-2"
    base._write(repo.path / base.POLICY, policy)
    base._commit(repo.path, "rewrite the done policy")
    base._receipt(repo.path, repo.signer)
    _asks_with(env, repo, f"the done policy {base.POLICY} changes")


def _signed_receipt(repo: base.Repo, path: str, args: list | None) -> None:
    """A valid receipt of the done check at `path` for the working state now; for a check of the order it names the
    pytest arguments the check asks for, an empty PYTEST_ADDOPTS and no deselected test (D28)."""
    base._receipt(repo.path, repo.signer)
    if path != base.RECEIPT or args is not None:
        state = gate.working_state(str(repo.path), time.monotonic() + 60)
        clean = state["worktree"] == state["tree"]
        git = {"git_hash": state["commit"], "git_tree": state["tree"], "git_clean": clean}
        if not clean:
            git["git_worktree_tree"] = state["worktree"]
        provenance = {"harness": "pytest", "exit_status": 0, "tests_ran": 3, "tests_passed": 3, "n_passed": 3,
                      "n_failed": 0, "n_error": 0, "n_skipped": 0, "n_xfailed": 0, "n_xpassed": 0, **git}
        if args is not None:
            provenance |= {"pytest_args": args, "pytest_addopts": "", "n_deselected": 0}
        claim, _ = build_eval_claim(suite="pytest", suite_version="9", metric="pass_rate", comparator=">=",
                                    threshold="1", score="1", n=3, model_id=f"gitCommit:{state['commit']}",
                                    dataset_id="pytest-suite", issuer="", timestamp="2026-10-08T12:00:00+00:00",
                                    provenance=provenance)
        base._write(repo.path / path, emit_eval_receipt(claim, repo.signer))


@pytest.mark.parametrize("change", ["order form", "receipt", "args", "paths", "max_blocks", "policy path"])
def test_a_push_that_changes_the_done_section_asks_and_level_2_blocks(env, tmp_path, change):
    repo = base.Repo(tmp_path)
    receipt, args = base.RECEIPT, []
    if change == "order form":
        done = _order()
    elif change == "receipt":
        receipt, args = ".proofbundle/other_receipt.json", None
        done = {"receipt": receipt, "policy": base.POLICY}
    elif change == "args":
        args = ["-q"]
        done = _order() | {"checks": [{"id": "tests", "args": args, "receipt": base.RECEIPT}]}
    elif change == "paths":
        done = _order(paths=["src/*"])
    elif change == "max_blocks":
        done = _order(max_blocks=5)
    else:
        args = None
        base._write(repo.path / ".proofbundle" / "done-policy-2.json", base._policy(repo.signer))
        done = {"receipt": base.RECEIPT, "policy": ".proofbundle/done-policy-2.json"}
    _set_done(repo, done)
    base._commit(repo.path, f"change the done check: {change}")
    base._write(repo.path / "src" / "module.py", "VALUE = 4\n")   # work after the order, in its paths
    base._commit(repo.path, "work after the change")
    _signed_receipt(repo, receipt, args)
    _asks_with(env, repo, "the done check changes")


def test_a_push_that_adds_a_done_check_asks(env, tmp_path):
    repo = base.Repo(tmp_path, evidence=True)
    # The target's known state declares the evidence and no done check; the push adds one.
    _set_done(repo, None)
    base._commit(repo.path, "declare evidence only")
    base._git(repo.path, "push", "-q", "origin", "main")
    _set_done(repo, {"receipt": base.RECEIPT, "policy": base.POLICY})
    base._commit(repo.path, "add the done check")
    base._receipt(repo.path, repo.signer)
    _asks_with(env, repo, "the push adds a done check")


def test_a_push_that_removes_the_done_check_asks(env, tmp_path):
    repo = base.Repo(tmp_path, evidence=True)
    _set_done(repo, None)
    base._commit(repo.path, "remove the done check")
    _asks_with(env, repo, "the push removes the done check")


def test_under_codex_the_plain_push_warns_and_level_2_blocks_the_swap(env, tmp_path):
    repo = base.Repo(tmp_path)
    mine = generate_signer()
    base._write(repo.path / base.POLICY, base._policy(mine))
    base._commit(repo.path, "swap the done policy to my key")
    base._receipt(repo.path, mine)
    answer, entry = base._level1(env, repo.path, host="codex")
    assert "permissionDecision" not in answer["hookSpecificOutput"] and entry["verdict"] == "warn", answer
    proc = base._level2(env, repo.path)
    assert proc.returncode == 1 and f"the done policy {base.POLICY} changes" in proc.stderr, proc.stderr


# --- the controls -----------------------------------------------------------------------------------------------

def test_an_unchanged_done_check_with_a_valid_receipt_still_passes(env, tmp_path):
    """Level 2 passes; Level 1 asks at the destination check since R9-1, after the done check at the sent commit
    showed no failure."""
    repo = base.Repo(tmp_path)
    base._receipt(repo.path, repo.signer)
    answer, entry = base._level1(env, repo.path)
    base.assert_destination_not_measured(answer, entry)
    assert base._level2(env, repo.path).returncode == 0


def test_the_rules_hold_the_done_check_and_nothing_else_under_proofbundle(tmp_path):
    repo = base.Repo(tmp_path)
    deadline = time.monotonic() + 60
    head = gate._rules_at(str(repo.path), "HEAD", deadline)
    section, blob = head[3]
    assert section == (base.POLICY, (("tests", None, base.RECEIPT),), None, gate.DEFAULT_MAX_BLOCKS)
    assert blob == base._rev(repo.path, f"HEAD:{base.POLICY}")
    assert head == gate._rules_at(str(repo.path), "origin/main", deadline), "the work changes no rule"
    base._receipt(repo.path, repo.signer)   # a receipt is evidence, not a rule
    base._write(repo.path / ".proofbundle" / "notes.txt", "a file that is no rule\n")
    base._commit(repo.path, "a receipt and a note")
    assert gate._rules_at(str(repo.path), "HEAD", deadline) == head


def test_a_declaration_without_a_done_check_has_an_empty_done_rule(tmp_path):
    repo = base.Repo(tmp_path)
    _set_done(repo, None)
    base._commit(repo.path, "no done check")
    rules = gate._rules_at(str(repo.path), "HEAD", time.monotonic() + 60)
    assert rules[0] == "declared" and rules[3] == ()
