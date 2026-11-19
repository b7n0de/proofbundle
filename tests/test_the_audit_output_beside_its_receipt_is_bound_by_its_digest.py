"""The audit output lies beside its receipt at the tag, bound by the receipt's signed digest.

FINDING (review finding P1 on pull request 541, measured 2026-11-18 on a throwaway clone at v6.6.0).
The receipt binds the tree as it was measured BEFORE the audit ran, and the audit output exists only
after the run. Committed beside the receipt, the output changed `subject_tree_digest`: the gate said
`verified` at the tag and `other_tree` with the 6.6.0 output committed, so a release could carry its
receipt or its audit output, never both, and the release step of lesson 2 could never pass.

THE RULE, owner choice A on card OA-71c0d50067: `audit_artifacts/<token>/pre_tag_audit_output_v<version>.txt`
is left out of the digest only when it is a regular file and a receipt of the same version in the same
folder names the SHA-256 of its bytes as `audit_output_digest`. Otherwise it stays in the digest, and a
receipt that bound the tree without it no longer verifies. The readiness binding applies the same rule
from the same library, and the audit matrix lets the canonical output path change after the candidate.

Each case builds its own git tree. Counter-cases are part of every property: an output that is not bound
must move the digest.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
VERSION = "6.6.1"
RECEIPT = "audit_artifacts/661/pre_tag_receipt_v6.6.1.json"
OUTPUT = "audit_artifacts/661/pre_tag_audit_output_v6.6.1.txt"
OUTPUT_BYTES = b"28245 passed, 158 skipped in 1234.56s\r\n"


def _module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, str(REPO / "scripts" / file))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _commit(repo: pathlib.Path, files: dict, message: str) -> str:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _receipt_naming(digest: str, version: str = VERSION) -> str:
    return json.dumps({"version": version, "audit_output_digest": digest}) + "\n"


@pytest.fixture
def tree(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    c = _commit(repo, {"pyproject.toml": f'[project]\nversion = "{VERSION}"\n', "src/pkg/__init__.py": "",
                       "audit_artifacts/661/README.md": "page\n"}, "candidate")
    return repo, c


def _digests(repo):
    lib = _module("_lib_output_beside", "pre_tag_receipt_lib.py")
    sra = _module("_sra_output_beside", "sign_readiness_artifact.py")
    return lib.subject_tree_digest(repo), sra.tree_digest(repo)


def test_a_bound_output_beside_its_receipt_leaves_both_digests_unchanged(tree):
    """[COUNTS] The finding: receipt and output after the candidate, both bindings stay those of the candidate."""
    repo, c = tree
    before = _digests(repo)
    _commit(repo, {RECEIPT: _receipt_naming(hashlib.sha256(OUTPUT_BYTES).hexdigest())}, "receipt")
    assert _digests(repo) == before
    e = _commit(repo, {OUTPUT: OUTPUT_BYTES}, "the audit output beside its receipt")
    assert _digests(repo) == before
    m = _module("_acm_output_beside", "audit_candidate_matrix.py")
    allowed, reason = m._evidenz_relation_erlaubt(repo, c, e)
    assert allowed is True, reason


@pytest.mark.parametrize("case", [
    "other_bytes", "no_receipt", "receipt_of_other_version", "receipt_version_field", "folder_of_other_version",
    "old_name", "below_src", "symlink", "symlink_text", "receipt_unreadable",
])
def test_an_output_that_no_receipt_binds_moves_both_digests(tree, case):
    """[COUNTS] Every way an output can fail to be bound keeps it in the digest."""
    repo, _c = tree
    digest = hashlib.sha256(OUTPUT_BYTES).hexdigest()
    receipt, output = RECEIPT, OUTPUT
    if case == "other_bytes":
        files = {receipt: _receipt_naming(hashlib.sha256(b"other bytes").hexdigest())}
    elif case == "no_receipt":
        files = {}
    elif case == "receipt_of_other_version":
        files = {"audit_artifacts/661/pre_tag_receipt_v6.6.2.json": _receipt_naming(digest, "6.6.2")}
    elif case == "receipt_version_field":
        files = {receipt: _receipt_naming(digest, "6.6.2")}
    elif case == "folder_of_other_version":
        receipt, output = "audit_artifacts/999/pre_tag_receipt_v6.6.1.json", "audit_artifacts/999/pre_tag_audit_output_v6.6.1.txt"
        files = {receipt: _receipt_naming(digest)}
    elif case == "old_name":
        output = "audit_artifacts/661/audit_output_v6.6.1.txt"
        files = {receipt: _receipt_naming(digest)}
    elif case == "below_src":
        receipt, output = "src/" + RECEIPT, "src/" + OUTPUT
        files = {receipt: _receipt_naming(digest)}
    elif case == "receipt_unreadable":
        files = {receipt: '{"version": "6.6.1", "audit_output_digest": "x", "audit_output_digest": "' + digest + '"}\n'}
    elif case == "symlink_text":  # the receipt names the bytes of the link text, which a checkout never yields
        files = {receipt: _receipt_naming(hashlib.sha256(b"../../outside/record.txt").hexdigest()),
                 "outside/record.txt": OUTPUT_BYTES}
    else:  # symlink: the receipt names the bytes of the link target, the committed entry is a link
        files = {receipt: _receipt_naming(digest), "outside/record.txt": OUTPUT_BYTES}
    if files:
        _commit(repo, files, "receipt")
    before = _digests(repo)
    if case in ("symlink", "symlink_text"):
        (repo / output).parent.mkdir(parents=True, exist_ok=True)
        try:
            (repo / output).symlink_to("../../outside/record.txt")
        except OSError as exc:
            pytest.skip(f"this file system refuses a symbolic link: {exc}")
        _git(repo, "add", "-A")
        _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "a link")
    else:
        _commit(repo, {output: OUTPUT_BYTES}, "an output")
    after = _digests(repo)
    assert after[0] != before[0], f"{case}: the receipt digest did not move"
    assert after[1] != before[1], f"{case}: the readiness digest did not move"


def test_the_path_rule_is_one_rule_in_both_bindings():
    """[COUNTS] The readiness binding asks the receipt library, and the folder must be the version's."""
    lib = _module("_lib_output_rule", "pre_tag_receipt_lib.py")
    sra = _module("_sra_output_rule", "sign_readiness_artifact.py")
    for path, expected in ((OUTPUT, True), ("audit_artifacts/641rc1/pre_tag_audit_output_v6.4.1rc1.txt", True),
                           ("audit_artifacts/999/pre_tag_audit_output_v6.6.1.txt", False),
                           ("src/" + OUTPUT, False), ("audit_artifacts/661/audit_output_v6.6.1.txt", False),
                           (OUTPUT + ".bak", False)):
        assert lib.ist_ausgabepfad(path) is expected, path
        assert sra.ist_ausgabepfad(path) is expected, path


@pytest.mark.parametrize("path", [
    "audit_artifacts/660/pre_tag_audit_output_v6.6.0.txt",
    "audit_artifacts/999/pre_tag_audit_output_v6.6.1.txt",
])
def test_a_later_evidence_commit_refuses_other_output_paths(tree, path):
    """[COUNTS] Only the canonical output path of the candidate's version may change after it."""
    repo, c = tree
    m = _module("_acm_other_output", "audit_candidate_matrix.py")
    e = _commit(repo, {path: OUTPUT_BYTES}, "other output")
    assert m._evidenz_relation_erlaubt(repo, c, e)[0] is False


def _signed_receipt(repo, priv, pub_b64, output_bytes):
    lib = _module("_lib_output_e2e", "pre_tag_receipt_lib.py")
    r = {
        "schema": lib.RECEIPT_SCHEMA, "version": VERSION, "subject_tree_digest": lib.subject_tree_digest(repo),
        "gate_source_digest": hashlib.sha256((REPO / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest(),
        "audit_command": "python -m pytest -q", "audit_exit_code": 0,
        "audit_output_digest": hashlib.sha256(output_bytes).hexdigest(), "runner_identity": "test",
        "produced_at": "2026-11-18T23:00:00Z",
    }
    r["signature"] = base64.b64encode(priv.sign(lib.canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub_b64
    return json.dumps(r, indent=2) + "\n"


def test_end_to_end_the_gate_verifies_with_the_output_beside_the_receipt_and_the_step_resolves(tmp_path):
    """[COUNTS] THE P1 SCENARIO. A signed receipt over the candidate, then the receipt and its audit output
    committed together: the real gate still verifies and the release step of lesson 2 resolves the digest.
    The control commits other bytes at the output path: the gate no longer verifies this tree."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    repo = tmp_path / "e2e"
    repo.mkdir()
    _git(repo, "init", "-q")
    _commit(repo, {"pyproject.toml": f'[project]\nversion = "{VERSION}"\n',
                   "audit_artifacts/pre_tag_trusted_pubkeys.txt": pub_b64 + "\n",
                   "audit_artifacts/661/README.md": "page\n"}, "candidate")
    receipt = _signed_receipt(repo, priv, pub_b64, OUTPUT_BYTES)
    _commit(repo, {RECEIPT: receipt, OUTPUT: OUTPUT_BYTES}, "receipt and audit output")
    gate = _module("_gate_output_e2e", "pre_tag_audit_gate.py")
    verdict = gate.evaluate(repo, VERSION)
    assert verdict["ok"] is True and verdict["state"] == "verified", verdict
    step = _module("_step_output_e2e", "audit_output_aufloesbar.py")
    result = step.fuer_version(repo, VERSION)
    assert result["zustand"] == "AUFLOESBAR", result
    assert result["quittungen"][0]["treffer"] == [OUTPUT], result
    _commit(repo, {OUTPUT: b"other bytes at the output path\n"}, "other bytes")
    verdict = gate.evaluate(repo, VERSION)
    assert verdict["ok"] is False and verdict["state"] == "other_tree", verdict
