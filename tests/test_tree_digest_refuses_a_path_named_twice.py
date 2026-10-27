"""R13-3 (external review of the user path, round 13): the receipt binds the tree it checked.

A tree object may name one path twice. `git show HEAD:app.py` then reads the first entry and a
checkout after `git reset --hard` leaves the other one on disk, while both tree digests sorted the
listing lines and so gave the same digest for the order first/last and for the order last/first.
Measured at f6ea5cc3: `subject_tree_digest` and `tree_digest` gave one digest for both commits, and
the release gate verified one receipt for both (`ok=True, state=verified`).

Both functions now refuse a tree that names a path twice on any level, before the exclusions and
therefore also inside them, with their own error instead of a digest; the release gate and the
readiness check then give no ok. The trust anchor read (`git_file`) refuses a name that stands
twice on its path as well, since it took the first entry. Digests of trees that name each path once
are byte-identical to the ones before the fix (the vectors below were computed at f6ea5cc3).
Test keys only, generated per case.
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

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

#: Digests at f6ea5cc3 of the trees `_vector_repo` builds, before the fix: (subject_tree_digest,
#: tree_digest). Each tree names every path once, so the fix must leave both unchanged.
#:
#: ONE VALUE MOVED ON PURPOSE (owner choice A on card OA-c04430c2ea, 2026-10-26). The tree "excluded"
#: carries a pre-tag receipt. Its readiness digest was c7da9ede…, the digest WITH the receipt inside,
#: while its subject digest left the receipt out. `sign_readiness_artifact.tree_digest` now leaves the
#: receipt out by the same pattern, so both digests of that tree are bab2c96f…. "plain" and "names"
#: carry no receipt and keep both values: the change reaches the receipt and nothing else.
VECTORS = {
    "plain": ("f7b07c572b04dc8a467739482133375ce9a9960731a0924cb60c2543f75b60b6",
              "f7b07c572b04dc8a467739482133375ce9a9960731a0924cb60c2543f75b60b6"),
    "names": ("7d0f763a4f32724a625e01ab69ca475b93eca3c22cb0e6467bfe3e074647cf32",
              "7d0f763a4f32724a625e01ab69ca475b93eca3c22cb0e6467bfe3e074647cf32"),
    "excluded": ("bab2c96fba851a69d1cbb9fed41126d8bfa35d540e8c5c0ac5d7493d2e7f704c",
                 "bab2c96fba851a69d1cbb9fed41126d8bfa35d540e8c5c0ac5d7493d2e7f704c"),
}


def _env() -> dict:
    return {k: v for k, v in os.environ.items()
            if not k.startswith("GIT_") and k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}


def _git(cwd, *args, stdin: bytes | None = None) -> bytes:
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                        "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args],
                       cwd=str(cwd), input=stdin, capture_output=True, env=_env())
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr.decode()}")
    return r.stdout


def _entries(raw: bytes) -> list:
    """[(mode, name, raw id)] of a raw tree object with 20-byte ids."""
    out, pos = [], 0
    while pos < len(raw):
        space = raw.index(b" ", pos)
        nul = raw.index(b"\0", space)
        out.append((raw[pos:space], raw[space + 1:nul], raw[nul + 1:nul + 21]))
        pos = nul + 21
    return out


def _raw_tree(repo, entries) -> str:
    """Write the tree with exactly these entries, in this order, without git's checks."""
    return _git(repo, "hash-object", "--literally", "-t", "tree", "-w", "--stdin",
                stdin=b"".join(m + b" " + n + b"\0" + o for m, n, o in entries)).strip().decode()


def _blob(repo, content: bytes) -> bytes:
    return bytes.fromhex(_git(repo, "hash-object", "-w", "--stdin", stdin=content).strip().decode())


def _named_twice(repo, path: bytes, first: bytes, last: bytes, mode_last: bytes = b"100644",
                 last_id: bytes | None = None) -> str:
    """A commit on top of HEAD whose tree names `path` twice: `first`, then `last` (or `last_id`)."""
    def rebuild(tree: str, parts: list) -> bytes:
        entries = _entries(_git(repo, "cat-file", "tree", tree)) if tree else []
        name = parts[0]
        if len(parts) == 1:
            entries = [e for e in entries if e[1] != name]
            entries.append((b"100644", name, _blob(repo, first)))
            entries.sort(key=lambda e: e[1])
            i = [k for k, e in enumerate(entries) if e[1] == name][0]
            entries.insert(i + 1, (mode_last, name, last_id or _blob(repo, last)))
        else:
            below = [e for e in entries if e[1] == name]
            sub = rebuild(below[0][2].hex() if below else "", parts[1:])
            entries = [e for e in entries if e[1] != name] + [(b"40000", name, sub)]
            entries.sort(key=lambda e: e[1] + (b"/" if e[0] == b"40000" else b""))
        return bytes.fromhex(_raw_tree(repo, entries))
    tree = rebuild(_git(repo, "rev-parse", "HEAD^{tree}").strip().decode(), path.split(b"/")).hex()
    return _git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "twice").strip().decode()


class _Base(unittest.TestCase):

    def setUp(self):
        for needed in ("pre_tag_audit_gate.py", "pre_tag_receipt_lib.py", "sign_readiness_artifact.py",
                       "audit_candidate_matrix.py"):
            if not (SCRIPTS / needed).is_file():
                self.skipTest(f"{needed} is not in this tree (a distributed artefact prunes scripts/)")
        d = tempfile.mkdtemp(prefix="path-named-twice-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)

    def _run(self, code: str) -> subprocess.CompletedProcess:
        """`code` in a child that imports the scripts under test, with a clean environment."""
        return subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(SCRIPTS)!r})\n" + code],
                              capture_output=True, text=True, timeout=300, env=_env())

    def _digests(self, repo) -> dict:
        """{'subject': digest or error, 'readiness': digest or error, 'live': (digest, reason)}."""
        r = self._run(
            "import json, pathlib, pre_tag_receipt_lib as lib, sign_readiness_artifact as sra\n"
            "import audit_candidate_matrix as acm\n"
            f"repo = pathlib.Path({str(repo)!r}); out = {{}}\n"
            "try:\n    out['subject'] = lib.subject_tree_digest(repo)\n"
            "except lib.BaumNichtLesbar as e:\n    out['subject'] = 'BaumNichtLesbar: ' + str(e)\n"
            "try:\n    out['readiness'] = sra.tree_digest(repo)\n"
            "except SystemExit as e:\n    out['readiness'] = 'SystemExit: ' + str(e)\n"
            "out['live'] = list(acm._live_tree_digest(repo))\n"
            "print(json.dumps(out))")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return json.loads(r.stdout)

    def _repo(self, name: str, files: dict) -> pathlib.Path:
        repo = self.base / name
        repo.mkdir()
        _git(repo, "init", "-q")
        for rel, content in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", name)
        return repo

    def assertRefused(self, out: dict, path: str):
        self.assertTrue(out["subject"].startswith("BaumNichtLesbar: "), out["subject"])
        self.assertIn("twice", out["subject"])
        self.assertTrue(out["readiness"].startswith("SystemExit: "), out["readiness"])
        self.assertIn(path, out["readiness"])
        self.assertIsNone(out["live"][0], out["live"])
        self.assertIn("twice", out["live"][1])


class APathNamedTwiceGetsNoDigest(_Base):

    def test_RED_both_orders_of_one_path_get_no_digest(self):
        """The review's case: app.py twice at the root, first/last and last/first."""
        repo = self._repo("root", {"other.txt": b"x\n"})
        for first, last in ((b"first\n", b"last\n"), (b"last\n", b"first\n")):
            _git(repo, "reset", "-q", "--hard", _named_twice(repo, b"app.py", first, last))
            self.assertEqual(_git(repo, "show", "HEAD:app.py"), first,
                             "precondition: git show reads the first of the two entries")
            self.assertRefused(self._digests(repo), "app.py")
            _git(repo, "reset", "-q", "--hard", "HEAD~1")

    def test_RED_a_path_named_twice_below_the_root(self):
        repo = self._repo("below", {"dir/keep.txt": b"k\n"})
        _git(repo, "update-ref", "HEAD", _named_twice(repo, b"dir/app.py", b"first\n", b"last\n"))
        self.assertRefused(self._digests(repo), "dir/app.py")

    def test_RED_a_path_named_twice_inside_the_excluded_evidence(self):
        """The exclusions leave this path out of the digest; the check comes before them."""
        rel = b"audit_artifacts/360/fuzz_soak_latest.json"
        repo = self._repo("excluded", {"audit_artifacts/keep.txt": b"k\n"})
        _git(repo, "update-ref", "HEAD", _named_twice(repo, rel, b'{"a":1}\n', b'{"a":2}\n'))
        self.assertRefused(self._digests(repo), rel.decode())

    def test_RED_a_name_that_is_a_file_and_a_folder(self):
        repo = self._repo("file-and-folder", {"app.py/inner.txt": b"i\n"})
        folder = _git(repo, "rev-parse", "HEAD:app.py").strip().decode()
        _git(repo, "update-ref", "HEAD", _named_twice(repo, b"app.py", b"file\n", b"", mode_last=b"40000",
                                                      last_id=bytes.fromhex(folder)))
        self.assertRefused(self._digests(repo), "app.py")


class TheGatesGiveNoOk(_Base):

    def _candidate(self, key) -> pathlib.Path:
        g = self.base / "candidate"
        (g / "scripts").mkdir(parents=True)
        for s in ("pre_tag_audit_gate.py", "pre_tag_receipt_lib.py", "sign_readiness_artifact.py"):
            shutil.copy(SCRIPTS / s, g / "scripts" / s)
        shutil.copytree(REPO / "src" / "proofbundle", g / "src" / "proofbundle",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (g / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "5.0.0"\n', encoding="utf-8")
        (g / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (g / "audit_artifacts").mkdir()
        (g / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(self._pub(key) + "\n", encoding="utf-8")
        _git(g, "init", "-q")
        _git(g, "add", "-A")
        _git(g, "commit", "-qm", "candidate")
        return g

    @staticmethod
    def _pub(key) -> str:
        return base64.b64encode(key.public_key().public_bytes_raw()).decode()

    @staticmethod
    def _listing_digest(repo) -> str:
        """The digest over the listing as both functions formed it before the fix."""
        text = _git(repo, "-c", "core.quotePath=true", "ls-tree", "--full-tree", "-r", "HEAD").decode("ascii")
        return hashlib.sha256("\n".join(sorted(text.splitlines())).encode("utf-8")).hexdigest()

    def _gate(self, g) -> dict:
        r = subprocess.run([sys.executable, str(g / "scripts" / "pre_tag_audit_gate.py"), "--repo", str(g),
                            "--version", "5.0.0", "--json"], capture_output=True, text=True, timeout=300,
                           cwd=str(g), env=_env())
        return json.loads(r.stdout)

    def test_RED_a_receipt_for_one_order_verifies_neither(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sys.path.insert(0, str(SCRIPTS))
        try:
            from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes  # noqa: PLC0415
        finally:
            sys.path.pop(0)
        key = Ed25519PrivateKey.generate()
        g = self._candidate(key)
        orders = {"first/last": _named_twice(g, b"app.py", b"first\n", b"last\n"),
                  "last/first": _named_twice(g, b"app.py", b"last\n", b"first\n")}
        _git(g, "reset", "-q", "--hard", orders["first/last"])
        context = {"schema": RECEIPT_SCHEMA, "version": "5.0.0", "subject_tree_digest": self._listing_digest(g),
                   "gate_source_digest": hashlib.sha256((g / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest(),
                   "audit_command": "a", "audit_exit_code": 0, "audit_output_digest": "0" * 64,
                   "runner_identity": "t", "produced_at": "2026-10-13T00:00:00Z"}
        receipt = dict(context, signature=base64.b64encode(key.sign(canonical_bytes(context))).decode(),
                       signer_pubkey=self._pub(key))
        (g / "audit_artifacts" / "500").mkdir(parents=True)
        (g / "audit_artifacts" / "500" / "pre_tag_receipt_5.0.0.json").write_text(json.dumps(receipt), encoding="utf-8")
        for order, commit in orders.items():
            _git(g, "reset", "-q", "--hard", commit)
            verdict = self._gate(g)
            self.assertFalse(verdict.get("ok"), f"{order}: {verdict}")


class TheAnchorIsNotReadFromAPathNamedTwice(_Base):

    def test_RED_an_anchor_named_twice_trusts_no_key(self):
        """`git_file` took the first of two entries of one name; `git show` and a checkout may read
        the other. A path named twice is no anchor, and the read fails closed."""
        rel = b"audit_artifacts/pre_tag_trusted_pubkeys.txt"
        repo = self._repo("anchor", {"audit_artifacts/keep.txt": b"k\n"})
        _git(repo, "update-ref", "HEAD", _named_twice(repo, rel, b"KEY-A\n", b"KEY-B\n"))
        r = self._run("import pathlib, pre_tag_receipt_lib as lib\n"
                      f"print(lib.load_trusted_pubkeys(pathlib.Path({str(self.base / 'anchor')!r})))")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertEqual(r.stdout.strip(), "[]")


class TreesThatNameEachPathOnceKeepTheirDigest(_Base):

    def _vector_repo(self, name: str) -> pathlib.Path:
        files = {
            "plain": {"a.txt": b"a\n", "dir/b.txt": b"b\n", "dir/sub/c.txt": b"c\n"},
            "names": {"caf\u00e9.txt": b"e\n", "with space.txt": b"s\n", "tab\there.txt": b"t\n",
                      "z/\u4e2d.txt": b"z\n"},
            "excluded": {"keep.txt": b"k\n", "audit_artifacts/360/fuzz_soak_latest.json": b"{}\n",
                         "audit_artifacts/360/rust_differential_matrix.json": b"{}\n",
                         "audit_artifacts/600/pre_tag_receipt_6.0.0.json": b"{}\n",
                         "audit_artifacts/pre_tag_trusted_pubkeys.txt": b"k\n"},
        }[name]
        repo = self._repo(name, files)
        if name == "plain":
            (repo / "run.sh").write_bytes(b"#!/bin/sh\n")
            (repo / "run.sh").chmod(0o755)
            (repo / "link").symlink_to("a.txt")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "more")
        return repo

    def test_CONTROL_the_digests_of_trees_without_a_doubled_path_are_unchanged(self):
        for name, (subject, readiness) in VECTORS.items():
            out = self._digests(self._vector_repo(name))
            self.assertEqual((out["subject"], out["readiness"]), (subject, readiness), name)
            self.assertEqual(out["live"], [readiness, "measured"], name)


if __name__ == "__main__":
    unittest.main()
