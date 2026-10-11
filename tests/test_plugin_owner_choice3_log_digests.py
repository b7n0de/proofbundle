"""Owner choice 3 A of 2026-10-11: the gate log entry of a NOT MEASURED push carries evidence digests where the source
check ran.

Only digests of evidence bytes the check actually read, each with its source commit and path; a digest alone attests
no verification, so each carries the outcome of the check of its commit, and a check that failed or stopped part way
carries its reason and only what it read before it stopped. No working-tree hash taken afterwards, no digest of a
candidate the check did not read. The verdict stays NOT MEASURED, or deny for an evidenced failure. Red against
760ac6a8, whose log entry for such a push carried no digest at all.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess

import test_claude_code_plugin_gate as cg
from test_claude_code_plugin_gate import _clean_git_config, repo, shim  # noqa: F401  (fixtures)

gate = cg.gate
pytestmark = cg.pytestmark if hasattr(cg, "pytestmark") else []


def _push(env: dict, folder: pathlib.Path, logs: pathlib.Path, command: str = "git push origin main") -> tuple:
    answer = cg.run_gate(dict(env, CLAUDE_PLUGIN_DATA=str(logs)), folder, command)
    entry = json.loads((logs / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return answer, entry


def _blob_sha256(folder: pathlib.Path, rev: str, path: str) -> str:
    raw = subprocess.run(["git", "-C", str(folder), "cat-file", "blob", f"{rev}:{path}"], capture_output=True,
                         check=True).stdout
    return hashlib.sha256(raw).hexdigest()


def _head(folder: pathlib.Path) -> str:
    return subprocess.run(["git", "-C", str(folder), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()


def test_a_not_measured_push_logs_what_its_source_check_read(shim, repo, tmp_path):  # noqa: F811
    answer, entry = _push(shim, repo, tmp_path / "logs")
    assert cg.at_destination(answer), answer
    head = _head(repo)
    assert entry["repos"][0]["evidence"] == [
        {"commit": head, "path": cg.BUNDLE, "sha256": _blob_sha256(repo, head, cg.BUNDLE), "check": "passed"},
        {"commit": head, "path": cg.POLICY, "sha256": _blob_sha256(repo, head, cg.POLICY), "check": "passed"},
    ], entry


def test_no_working_tree_hash_is_taken_afterwards(shim, repo, tmp_path):  # noqa: F811
    (repo / cg.BUNDLE).write_text('{"changed": "in the working tree only"}', encoding="utf-8")
    _answer, entry = _push(shim, repo, tmp_path / "logs")
    logged = {read["path"]: read["sha256"] for read in entry["repos"][0]["evidence"]}
    assert logged[cg.BUNDLE] == _blob_sha256(repo, "HEAD", cg.BUNDLE)
    assert logged[cg.BUNDLE] != hashlib.sha256((repo / cg.BUNDLE).read_bytes()).hexdigest()


def test_a_failed_check_logs_its_reads_with_the_failure(shim, repo, tmp_path):  # noqa: F811
    cg._tamper_bundle(repo / cg.BUNDLE)
    cg._commit(repo, "tampered")
    answer, entry = _push(shim, repo, tmp_path / "logs")
    assert cg.decision(answer) == "deny" and entry["reason_ids"] == ["verification_failed"], entry
    head = _head(repo)
    assert entry["repos"][0]["evidence"] == [
        {"commit": head, "path": cg.BUNDLE, "sha256": _blob_sha256(repo, head, cg.BUNDLE),
         "check": "failed: verification_failed"},
        {"commit": head, "path": cg.POLICY, "sha256": _blob_sha256(repo, head, cg.POLICY),
         "check": "failed: verification_failed"},
    ], entry


def test_a_check_that_stopped_part_way_logs_only_what_it_read(shim, repo, tmp_path):  # noqa: F811
    declaration = json.loads((repo / gate.DECLARATION).read_text(encoding="utf-8"))
    first = declaration["evidence"][0]
    declaration["evidence"].append(dict(first, path=".proofbundle/missing.json"))
    (repo / gate.DECLARATION).write_text(json.dumps(declaration), encoding="utf-8")
    cg._commit(repo, "a second item whose file is missing")
    answer, entry = _push(shim, repo, tmp_path / "logs")
    assert cg.decision(answer) == "deny" and entry["reason_ids"] == ["missing_file"], entry
    reads = entry["repos"][0]["evidence"]
    assert [read["path"] for read in reads] == [cg.BUNDLE, cg.POLICY], reads
    assert {read["check"] for read in reads} == {"failed: missing_file"}, reads


def test_an_unresolved_source_logs_no_digest_of_a_candidate(shim, repo, tmp_path):  # noqa: F811
    cg._git(repo, "tag", "main")
    answer, entry = _push(shim, repo, tmp_path / "logs")
    assert cg.decision(answer) == "ask" and "checked no evidence" in cg.reason(answer), answer
    assert "evidence" not in entry["repos"][0] and entry["repos"][0]["digests"] == [], entry


def test_d21_names_the_evidence_field():
    decisions = (pathlib.Path(gate.__file__).resolve().parents[1] / "DECISIONS.md").read_text(encoding="utf-8")
    flat = " ".join(decisions.split())
    assert "The entry of a push whose source check ran carries, per repository, `evidence`" in flat
    assert "A digest alone attests no verification." in flat
