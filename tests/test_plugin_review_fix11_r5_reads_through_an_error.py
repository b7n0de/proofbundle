"""Review round 11 of 2026-10-12, R11-5: owner choice 3 keeps the evidence read before the gate stopped.

Measured by the reviewer at 3bbbf66f: in the fixture test_claude_code_plugin_gate.repo, .proofbundle/policy.json
replaced by 65537 ASCII spaces and committed; Level 1 for `git push origin main`. The bundle was read and its digest
taken, then the size check of the policy raised GateError; the log said deny/gate_error with digests [] and head null.

Property (D21): the reading record survives the exception. The bundle digest read is logged with its source commit and
the status of the check that stopped; the policy that was not read gets no digest. Red against c03d5022.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import test_claude_code_plugin_gate as cg
import test_plugin_owner_choice3_log_digests as c3
from test_claude_code_plugin_gate import _clean_git_config, repo, shim  # noqa: F401  (fixtures)

gate = cg.gate
pytestmark = cg.pytestmark if hasattr(cg, "pytestmark") else []


def _oversized_policy(folder: pathlib.Path) -> str:
    (folder / cg.POLICY).write_bytes(b" " * 65537)
    subprocess.run(["git", "-C", str(folder), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(folder), "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
                    "commit.gpgsign=false", "commit", "-q", "-m", "oversized policy"], check=True)
    return c3._head(folder)


def test_the_reviewers_case_the_bundle_read_before_the_error_is_logged(shim, repo, tmp_path):  # noqa: F811
    head = _oversized_policy(repo)
    answer, entry = c3._push(shim, repo, tmp_path / "logs")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    (logged,) = entry["repos"]
    assert (logged["verdict"], logged["reason_id"]) == ("deny", "gate_error"), entry
    assert "larger than" in json.dumps(answer), answer
    bundle = c3._blob_sha256(repo, head, cg.BUNDLE)
    assert logged["head"] == head, entry
    assert logged["digests"] == [f"{cg.BUNDLE} sha256:{bundle}"], entry
    assert logged["evidence"] == [{"commit": head, "path": cg.BUNDLE, "sha256": bundle,
                                   "check": "not completed: gate_error"}], entry


def test_the_policy_that_was_not_read_has_no_digest(shim, repo, tmp_path):  # noqa: F811
    _oversized_policy(repo)
    _answer, entry = c3._push(shim, repo, tmp_path / "logs")
    text = json.dumps(entry)
    assert cg.POLICY not in [read.get("path") for read in entry["repos"][0].get("evidence", [])], entry
    assert f"{cg.POLICY} sha256:" not in text, entry
