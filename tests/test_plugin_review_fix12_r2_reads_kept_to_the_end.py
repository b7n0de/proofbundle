"""Review round 12 of 2026-10-13, R12-2: the record of the evidence a push's check read survives every later failure.

Measured by the reviewer at 7588fe4a with git 2.51.1 and 2.43.0: the fixture test_claude_code_plugin_gate.repo with
"done": {"receipt": ".proofbundle/test.done.json", "policy": ".proofbundle/done-large-policy.json"} in the declaration and
a done policy of 65537 ASCII spaces, committed; Level 1 for `git push origin main`. The evidence check at the commit
passed with both digests, then the hook stopped at the size check of the done policy with deny/gate_error, and the log
held digests [], head null and no evidence field: _source_denial filled the record after the source check, and its call
of _push_done lay outside the block that hands the record to the GateError. The sibling: the uv test shim replaced by an
executable text file without a shebang, the verifier start failed with OSError, Exec format error, deny/internal_error,
digests, commit and record gone as well.

Property (owner choice 3 A, DECISIONS.md D21): evidence read stays bound to its commit, path, digest and check state when
the push's check stops later, for every kind of exception; a passed evidence check stays logged as passed while the later
done check fails on its own; the done policy that was not read gets no digest. Red against ca3ce87b.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time

import pytest

import test_claude_code_plugin_gate as cg
import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_clean_git_config = cg._clean_git_config
repo = cg.repo
gate = cg.gate

LARGE = ".proofbundle/done-large-policy.json"


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _with_large_done_policy(repo: pathlib.Path) -> str:
    declaration = json.loads((repo / gate.DECLARATION).read_text(encoding="utf-8"))
    declaration["done"] = {"receipt": ".proofbundle/test.done.json", "policy": LARGE}
    (repo / gate.DECLARATION).write_text(json.dumps(declaration), encoding="utf-8")
    (repo / LARGE).write_text(" " * 65537, encoding="ascii")
    cg._commit(repo)
    return n2c._rev(repo, "HEAD")


def _repo_entry(entry: dict) -> dict:
    (only,) = entry["repos"]
    return only


def _assert_evidence(repo: pathlib.Path, item: dict, head: str, check: str) -> None:
    expected = {f"{cg.BUNDLE} sha256:{_sha(repo / cg.BUNDLE)}", f"{cg.POLICY} sha256:{_sha(repo / cg.POLICY)}"}
    assert item["head"] == head, item
    assert set(item["digests"]) == expected, item
    assert sorted((e["commit"], e["path"], e["sha256"], e["check"]) for e in item.get("evidence", [])) == sorted(
        (head, path, _sha(repo / path), check) for path in (cg.BUNDLE, cg.POLICY)), item
    assert LARGE not in json.dumps(item), item


def test_the_reviewers_case_a_done_policy_over_the_limit_after_a_passed_evidence_check(env, repo):
    head = _with_large_done_policy(repo)
    answer, entry = n2c._level1(env, repo)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    item = _repo_entry(entry)
    assert (item["verdict"], item["reason_id"]) == ("deny", "gate_error"), item
    assert "larger than" in answer["systemMessage"], answer
    _assert_evidence(repo, item, head, "passed")


def test_the_reviewers_sibling_the_verifier_cannot_start_at_all(env, repo, tmp_path):
    head = n2c._rev(repo, "HEAD")
    shim = tmp_path / "bin" / "uv"
    shim.write_text("no interpreter line here\n", encoding="utf-8")
    shim.chmod(0o755)
    answer, entry = n2c._level1(env, repo)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    item = _repo_entry(entry)
    assert (item["verdict"], item["reason_id"]) == ("deny", "internal_error"), item
    assert "OSError" in answer["systemMessage"] or "Exec format error" in answer["systemMessage"], answer
    _assert_evidence(repo, item, head, "not completed: internal_error")


@pytest.mark.parametrize("where", ["_local_inactivity", "_rules_hints"])
def test_a_later_failure_of_another_kind_keeps_the_record(env, repo, monkeypatch, where):
    """In process: after the source check passed, a later step of the push's check raises an exception that is not a
    GateError; the answer denies and carries the record of the passed check."""
    head = n2c._rev(repo, "HEAD")
    for key in ("PATH", "PYTHONPATH"):
        monkeypatch.setenv(key, env[key])

    def boom(*_args, **_kwargs):
        raise RuntimeError("probe after the source check")
    monkeypatch.setattr(gate, where, boom)
    outcome = gate.decide("git push origin main", str(repo), time.monotonic() + 120)
    (verdict,) = outcome.verdicts
    assert (verdict.decision, verdict.reason_id) == ("deny", "internal_error"), verdict.detail
    assert "RuntimeError" in verdict.detail
    item = _repo_entry(gate.log_entry("claude", {}, outcome, ["git push"]))
    _assert_evidence(repo, item, head, "passed")


def test_control_a_push_whose_check_ends_keeps_its_record(env, repo):
    head = n2c._rev(repo, "HEAD")
    answer, entry = n2c._level1(env, repo)
    item = _repo_entry(entry)
    assert (item["verdict"], item["reason_id"]) == ("ask", "push_not_measured"), item
    assert {e["commit"] for e in item["evidence"]} == {head}, item
    assert [(e["path"], e["check"]) for e in sorted(item["evidence"], key=lambda e: e["path"])] == [
        (cg.BUNDLE, "passed"), (cg.POLICY, "passed")], item
