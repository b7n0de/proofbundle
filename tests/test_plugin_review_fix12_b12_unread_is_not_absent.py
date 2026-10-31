"""Review round 12 of 2026-10-13, B-12: a declaration the gate could not read is named as not read, never as absent or
as uncommitted.

Measured by the reviewer at 7588fe4a with git 2.51.1 and 2.43.0: in test_claude_code_plugin_gate.repo the valid
declaration padded with ASCII spaces to 65537 bytes and committed, blob and working file byte-equal; evaluate_repository
answered ask/declaration_uncommitted, said the declaration is absent and not committed, and asked to commit it. It was
committed, and over the read limit.

Property: absent, not read and shown only in the working tree are kept apart. A declaration the gate cannot read at the
commit (over the limit, in a tree git does not give whole, a commit this repository does not hold) is answered as not
read, with that cause and a fitting next step; only a measured absence is called absent, and only a declaration the
commit lacks is called uncommitted. Red against 7aeacb2a.
"""
from __future__ import annotations

import json
import subprocess
import time

import test_claude_code_plugin_gate as cg

pytestmark = cg.pytestmark
_clean_git_config = cg._clean_git_config
repo = cg.repo
gate = cg.gate

WRONG = ("is absent", "not committed", "commit the declaration")


def _deadline() -> float:
    return time.monotonic() + 120


def _assert_not_read(verdict, cause: str) -> None:
    assert (verdict.decision, verdict.reason_id) == ("ask", "declaration_unread"), verdict.detail
    text = verdict.text()
    assert text.startswith(f"NOT MEASURED: Evidence: the declaration {gate.DECLARATION}"), text
    assert "could not read" in text and cause in text, text
    assert not any(w in text for w in WRONG), text


def test_the_reviewers_case_a_committed_declaration_over_the_read_limit(repo):
    raw = (repo / gate.DECLARATION).read_bytes()
    padded = raw + b" " * (65537 - len(raw))
    (repo / gate.DECLARATION).write_bytes(padded)
    cg._commit(repo)
    blob = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"HEAD:{gate.DECLARATION}"], capture_output=True,
                          check=True).stdout
    assert blob == (repo / gate.DECLARATION).read_bytes() and len(blob) == 65537
    _assert_not_read(gate.evaluate_repository(str(repo), _deadline()), "larger than")


def test_a_declaration_in_a_tree_git_does_not_give_whole_is_not_read(repo):
    """A root tree that names .proofbundle twice (the class of R11-4): git's lookup finds the declaration, the gate gives
    no reading of it."""
    def raw(kind: str, data: bytes) -> str:
        return subprocess.run(["git", "-C", str(repo), "hash-object", "--literally", "-t", kind, "-w", "--stdin"],
                              input=data, capture_output=True, check=True).stdout.decode().strip()
    listing = subprocess.run(["git", "-C", str(repo), "cat-file", "tree", "HEAD^{tree}"], capture_output=True,
                             check=True).stdout
    empty = bytes.fromhex(raw("tree", b""))
    folder_at = listing.index(b"40000 .proofbundle\0")
    entry_end = folder_at + len(b"40000 .proofbundle\0") + 20
    twice = listing[:entry_end] + b"40000 .proofbundle\0" + empty + listing[entry_end:]
    commit = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                             "commit-tree", raw("tree", twice), "-p", "HEAD", "-m", "B"],
                            capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "update-ref", "refs/heads/main", commit], check=True)
    _assert_not_read(gate.evaluate_repository(str(repo), _deadline()), "names one entry twice")


def test_a_commit_this_repository_does_not_hold_is_not_read(repo):
    verdict = gate._evaluate_tree(str(repo), "1" * 40, _deadline(), "the pushed commit 111111111111", "")
    _assert_not_read(verdict, "not available in this repository")


def test_control_a_declaration_only_in_the_working_tree_is_named_uncommitted(tmp_path):
    work = cg._plain(tmp_path)
    (work / gate.DECLARATION).parent.mkdir()
    (work / gate.DECLARATION).write_text(json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": []}),
                                         encoding="utf-8")
    verdict = gate.evaluate_repository(str(work), _deadline())
    assert (verdict.decision, verdict.reason_id) == ("ask", "declaration_uncommitted"), verdict.detail


def test_control_a_measured_absence_stays_inactive(tmp_path):
    verdict = gate.evaluate_repository(str(cg._plain(tmp_path)), _deadline())
    assert (verdict.decision, verdict.reason_id) == ("inactive", "nothing_declared"), verdict.detail
