"""Only the receipt of the version a tree declares leaves its digest (lesson 2, Codex on PR 541, round lx4, P0 2).

FINDING. The receipt rule matched every path of the receipt form, in every version's folder and at every mode, a link
and a gitlink included: `audit_artifacts/660/pre_tag_receipt_v6.6.0.json` could be added, changed or removed beside a
given 6.6.1 receipt, and the digest it binds did not move. Neither the 6.6.1 gate nor the outside verifier looks into
the folder of 6.6.0.

THE RULE, owner choice B (19 November 2026): the digest leaves out the receipt of the version the tree declares in
`pyproject.toml`, under one of the two names the house uses, as a regular file of mode 100644
(`pre_tag_receipt_lib.eigene_quittungen`), and nothing else. Both bindings apply it, the receipt's and the readiness
binding; the gate, the outside verifier and the readiness binding are each held to it below.

WHAT CHANGES FOR AN OLD TAG. A tree that carries receipts of earlier versions has another digest under this rule than
under the old one, so the new library does not verify the receipt of an old tag. An old tag is verified with the
scripts of its own commit: the outside verifier refuses to run from any other checkout (`_SCRIPT_CHECKOUT`), and
release.yml runs the workflow file of the tagged commit.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = pathlib.Path(__file__).resolve().parents[1]
VERSION = "6.6.1"
OWN = "audit_artifacts/661/pre_tag_receipt_v6.6.1.json"
OWN_PRODUCER_NAME = "audit_artifacts/661/pre_tag_receipt_6.6.1.json"
FOREIGN = "audit_artifacts/660/pre_tag_receipt_v6.6.0.json"
ANCHOR = "audit_artifacts/pre_tag_trusted_pubkeys.txt"
GATE = "scripts/pre_tag_audit_gate.py"
_TRUSTED = Ed25519PrivateKey.generate()


def _pub(priv) -> str:
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode()


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


def _receipt(repo, version: str = VERSION) -> str:
    """A receipt the trusted key signed over the digest of `repo`'s head, for `version`."""
    lib = _module("_lib_own_receipt", "pre_tag_receipt_lib.py")
    r = {"schema": lib.RECEIPT_SCHEMA, "version": version, "subject_tree_digest": lib.subject_tree_digest(repo),
         "gate_source_digest": hashlib.sha256((REPO / GATE).read_bytes()).hexdigest(),
         "audit_command": "python -m pytest -q", "audit_exit_code": 0, "audit_output_digest": "a" * 64,
         "runner_identity": "test", "produced_at": "2026-11-19T10:00:00Z"}
    r["signature"] = base64.b64encode(_TRUSTED.sign(lib.canonical_bytes(r))).decode()
    r["signer_pubkey"] = _pub(_TRUSTED)
    return json.dumps(r, indent=2) + "\n"


@pytest.fixture
def tree(tmp_path):
    """A 6.6.1 tree with the gate at its path (the outside verifier binds the committed gate) and the anchor."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _commit(repo, {"pyproject.toml": f'[project]\nversion = "{VERSION}"\n', ANCHOR: _pub(_TRUSTED) + "\n",
                   GATE: (REPO / GATE).read_bytes(), "src/pkg/__init__.py": "",
                   "audit_artifacts/661/README.md": "page\n"}, "candidate")
    return repo


def _digests(repo):
    lib = _module("_lib_own_receipt_d", "pre_tag_receipt_lib.py")
    sra = _module("_sra_own_receipt_d", "sign_readiness_artifact.py")
    return lib.subject_tree_digest(repo), sra.tree_digest(repo)


@pytest.mark.parametrize("name", [OWN, OWN_PRODUCER_NAME])
def test_the_own_receipt_leaves_both_digests_under_both_names(tree, name):
    """[COUNTS] GREEN CONTROL: the receipt of 6.6.1, under the bundle's and the producer's name."""
    before = _digests(tree)
    _commit(tree, {name: _receipt(tree)}, "the own receipt")
    assert _digests(tree) == before


@pytest.mark.parametrize("case", [
    "other_version_folder", "other_version_same_folder", "other_name", "other_folder", "below_src",
    "mode_100755", "symlink", "no_version",
])
def test_a_receipt_that_is_not_the_trees_own_moves_both_digests(tree, case):
    """[COUNTS] Every receipt-shaped path but the own one stays in both digests."""
    path = {"other_version_folder": FOREIGN, "other_version_same_folder": "audit_artifacts/661/pre_tag_receipt_v6.6.2.json",
            "other_name": "audit_artifacts/661/pre_tag_receipt_v6.6.1_b.json",
            "other_folder": "audit_artifacts/999/pre_tag_receipt_v6.6.1.json",
            "below_src": "src/" + OWN}.get(case, OWN)
    if case == "no_version":
        _commit(tree, {"pyproject.toml": "[project]\nname = 'x'\n"}, "no version")
    before = _digests(tree)
    if case == "mode_100755":
        (tree / OWN).parent.mkdir(parents=True, exist_ok=True)
        (tree / OWN).write_text(_receipt(tree), encoding="utf-8")
        _git(tree, "add", "--", OWN)
        _git(tree, "update-index", "--chmod=+x", OWN)
        _git(tree, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "executable receipt")
        assert _git(tree, "ls-tree", "HEAD", OWN).startswith("100755 "), "the fixture did not set the mode"
    elif case == "symlink":
        (tree / OWN).parent.mkdir(parents=True, exist_ok=True)
        try:
            (tree / OWN).symlink_to("README.md")
        except OSError as exc:
            pytest.skip(f"this file system refuses a symbolic link: {exc}")
        _git(tree, "add", "--", OWN)
        _git(tree, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "a link")
    else:
        _commit(tree, {path: _receipt(tree)}, "a receipt")
    after = _digests(tree)
    assert after[0] != before[0], f"{case}: the receipt digest did not move"
    assert after[1] != before[1], f"{case}: the readiness digest did not move"


def test_a_version_that_is_no_path_component_leaves_nothing_out(tree):
    """[COUNTS] `pyproject.toml` names `6.6.1/x`. Taken as it stands, the rule would leave out
    `audit_artifacts/661/x/pre_tag_receipt_v6.6.1/x.json`, a path anyone who writes the tree can create. A version that
    is not one path component names no receipt, and that file stays in both digests."""
    seltsam = "audit_artifacts/661/x/pre_tag_receipt_v6.6.1/x.json"
    _commit(tree, {"pyproject.toml": '[project]\nversion = "6.6.1/x"\n'}, "a version with a slash")
    before = _digests(tree)
    _commit(tree, {seltsam: "{}\n"}, "a file at the path that version would name")
    after = _digests(tree)
    assert after[0] != before[0] and after[1] != before[1], (before, after)


def test_adding_changing_and_removing_a_foreign_receipt_moves_both_digests(tree):
    """[COUNTS] The three moves of Codex's finding, one after the other, each against the digest before it."""
    stand = [_digests(tree)]
    _commit(tree, {FOREIGN: _receipt(tree, "6.6.0")}, "added")
    stand.append(_digests(tree))
    _commit(tree, {FOREIGN: _receipt(tree, "6.6.0").replace('"test"', '"other"')}, "changed")
    stand.append(_digests(tree))
    _git(tree, "rm", "-q", "--", FOREIGN)
    _git(tree, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "removed")
    stand.append(_digests(tree))
    for a, b in zip(stand, stand[1:]):
        assert a[0] != b[0] and a[1] != b[1], stand
    assert stand[-1] == stand[0], "removing the foreign receipt gives the first tree back"


def test_the_gate_and_the_outside_verifier_see_a_foreign_receipt_added_after_signing(tree):
    """[COUNTS] THE SCENARIO. The 6.6.1 receipt verifies at the gate and at the outside verifier; a receipt of 6.6.0
    added afterwards makes it bind another tree for both, and removing it again restores the verdict."""
    _commit(tree, {OWN: _receipt(tree)}, "the own receipt")
    gate = _module("_gate_own_receipt", "pre_tag_audit_gate.py")
    verifier = _module("_verifier_own_receipt", "verify_pre_tag_receipt.py")

    def urteile():
        kopf = _git(tree, "rev-parse", "HEAD")
        return gate.evaluate(tree, VERSION)["state"], verifier.measure(tree, kopf, VERSION)["verdict"]

    assert urteile() == ("verified", "VERIFIED")
    _commit(tree, {FOREIGN: _receipt(tree, "6.6.0")}, "a foreign receipt after signing")
    assert urteile() == ("other_tree", "NOT_VERIFIED")
    _git(tree, "rm", "-q", "--", FOREIGN)
    _git(tree, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "removed")
    assert urteile() == ("verified", "VERIFIED")


def test_the_receipt_pattern_stays_a_path_form_for_the_transition():
    """[COUNTS] The pattern no longer decides the digest; the readiness module still reads it from the library for
    `ist_quittungspfad`, which the audit matrix's transition uses."""
    lib = _module("_lib_own_receipt_p", "pre_tag_receipt_lib.py")
    sra = _module("_sra_own_receipt_p", "sign_readiness_artifact.py")
    assert sra._quittungsmuster().pattern == lib._RECEIPT_MUSTER.pattern
    assert sra.ist_quittungspfad(FOREIGN) and sra.ist_quittungspfad(OWN)
