"""Lens run (Claude family) on fix/a70-clean-tree-before-binding-work at 8879d736 (PR 249, round 2).

Every case below was RED at 8879d736f2ed62fe6cd2c97f06dc9eaf054cf788 when it was written (python -m
pytest on this file, Python 3.11.15, git 2.43.0) and is the reproduction of one row of
REVIEW_lens_claude_249_8879d736f2ed.md. No production code changes. The helpers are copied from
tests/test_pre_tag_receipt_git_answers_for_the_named_tree.py, so each case builds its trees the way
that file's cases do. Oracle: git's own object model (an object id names its content;
`git fsck` reports the substituted object as `hash-path mismatch`).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
GATE = SCRIPTS / "pre_tag_audit_gate.py"


def _child_env(**extra) -> dict:
    e = {k: v for k, v in os.environ.items()
         if not k.startswith("GIT_") and k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}
    e.update(extra)
    return e


def _git(cwd, *args) -> str:
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                        *args], cwd=str(cwd), capture_output=True, text=True, env=_child_env())
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


class L1TheTrustAnchorIsTheCommittedFile(unittest.TestCase):
    """PROPERTY: the release gate judges the tree the receipt names, through git answers about that
    tree. The chain reads the trusted keys with `git show HEAD:audit_artifacts/pre_tag_trusted_pubkeys.txt`
    (`load_trusted_pubkeys`), and git returns whatever the object store holds under the blob's id
    without checking that the content hashes to it. A loose object rewritten with other keys keeps
    its id, so `ls-tree` and the tree digest are unchanged, the working-tree file (which the
    cleanliness check hashes) is untouched, and the gate trusts a key the committed file does not
    name. The same class as `refs/replace`, which this branch closes with --no-replace-objects: a
    read that returns an object other than the one its id names. P0."""

    def setUp(self) -> None:
        for needed in (GATE, SCRIPTS / "pre_tag_receipt_lib.py"):
            if not needed.is_file():
                self.skipTest(f"{needed.name} is not in this tree")
        d = tempfile.mkdtemp(prefix="lens-249-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)

    def _candidate(self) -> pathlib.Path:
        repo = self.base / "genuine"
        (repo / "scripts").mkdir(parents=True)
        for s in ("pre_tag_audit_gate.py", "pre_tag_receipt_lib.py", "sign_readiness_artifact.py"):
            shutil.copy(SCRIPTS / s, repo / "scripts" / s)
        shutil.copytree(REPO / "src" / "proofbundle", repo / "src" / "proofbundle",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "5.0.0"\n', encoding="utf-8")
        (repo / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (repo / "audit_artifacts").mkdir()
        return repo

    @staticmethod
    def _key_line(priv) -> str:
        return base64.b64encode(priv.public_key().public_bytes_raw()).decode() + "\n"

    @staticmethod
    def _digest(repo: pathlib.Path) -> str:
        r = subprocess.run([sys.executable, "-c",
                            f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
                            "from pre_tag_receipt_lib import subject_tree_digest; "
                            f"print(subject_tree_digest({str(repo)!r}))"],
                           capture_output=True, text=True, timeout=120, env=_child_env())
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    def _receipt(self, repo: pathlib.Path, subject: str, priv) -> None:
        sys.path.insert(0, str(SCRIPTS))
        try:
            from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes  # noqa: PLC0415
        finally:
            sys.path.pop(0)
        context = {"schema": RECEIPT_SCHEMA, "version": "5.0.0", "subject_tree_digest": subject,
                   "gate_source_digest": hashlib.sha256(
                       (repo / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest(),
                   "audit_command": "a", "audit_exit_code": 0, "audit_output_digest": "0" * 64,
                   "runner_identity": "t", "produced_at": "2026-09-27T00:00:00Z"}
        receipt = dict(context, signature=base64.b64encode(priv.sign(canonical_bytes(context))).decode(),
                       signer_pubkey=self._key_line(priv).strip())
        (repo / "audit_artifacts" / "500").mkdir(parents=True, exist_ok=True)
        (repo / "audit_artifacts" / "500" / "pre_tag_receipt_5.0.0.json").write_text(
            json.dumps(receipt), encoding="utf-8")

    def _gate(self, repo: pathlib.Path) -> dict:
        r = subprocess.run([sys.executable, str(repo / "scripts" / "pre_tag_audit_gate.py"),
                            "--repo", str(repo), "--version", "5.0.0", "--json"],
                           capture_output=True, text=True, timeout=300, cwd=str(repo), env=_child_env())
        try:
            return json.loads(r.stdout)
        except ValueError:
            raise AssertionError(f"the gate gave no verdict: {r.stdout[-400:]}{r.stderr[-400:]}")

    def test_l1_a_substituted_trusted_keys_object(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
        trusted = Ed25519PrivateKey.from_private_bytes(b"\x21" * 32)
        other = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
        g = self._candidate()
        keys = g / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt"
        keys.write_text(self._key_line(trusted), encoding="utf-8")
        _git(g, "init", "-q")
        _git(g, "add", "-A")
        _git(g, "commit", "-qm", "genuine")
        digest = self._digest(g)
        self._receipt(g, digest, other)
        self.assertFalse(self._gate(g)["ok"], "precondition: a receipt by an untrusted key is refused")

        oid = _git(g, "rev-parse", "HEAD:audit_artifacts/pre_tag_trusted_pubkeys.txt")
        loose = g / ".git" / "objects" / oid[:2] / oid[2:]
        self.assertTrue(loose.is_file(), "precondition: the blob is a loose object")
        inhalt = self._key_line(other).encode()
        loose.chmod(0o644)
        loose.write_bytes(zlib.compress(b"blob %d\x00" % len(inhalt) + inhalt))
        self.assertEqual(self._digest(g), digest, "the tree digest does not see the substitution")
        self.assertEqual(keys.read_text(encoding="utf-8"), self._key_line(trusted),
                         "the working-tree file is the committed one")

        verdict = self._gate(g)
        self.assertFalse(verdict["ok"], f"the gate trusted a key the committed file does not name: {verdict}")


if __name__ == "__main__":
    unittest.main()
