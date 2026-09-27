"""The receipt chain asks git about the tree it names, and reads each tracked path as git stores it.

Sweep of the classes behind the Codex findings of 2026-09-23 on PR #249, measured on the merge of
main into that branch (`814a0097`). Main's tool already closes the three reported instances; the
cases below are the neighbours the sweep found at other sites of the same classes. Every case
labelled [RED] failed against `814a0097`; a [GUARD] case was green there and fails against the
half fix it names, so it pins the part of the repair that a partial version would drop.

  environment decides the answer  the library's own git calls (tree digest and trust anchor) ran
                                  with whatever environment their caller had; the release gate is
                                  such a caller, and `GIT_DIR` made it verify a tampered tree. The
                                  producer's drop list lacked five of git's own repository-local
                                  names. The digest's text form followed `core.quotePath` from a
                                  user's configuration.
  a path read not as git stores   the gate source was hashed through a symbolic link, and names
  it                              that are not UTF-8 were decoded with replacement, so a committed
                                  file was looked up under a name no file carries.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
SKRIPT = SCRIPTS / "pre_tag_receipt.py"
GATE = SCRIPTS / "pre_tag_audit_gate.py"

#: The child starts from a known state: no GIT_* name of the parent and no bytecode switch may
#: answer for the code under test. A case that needs such a name sets it, and that is the
#: measurement.
_NOT_FROM_THE_PARENT_PREFIXES = ("GIT_",)
_NOT_FROM_THE_PARENT = ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")


def _child_env(**extra) -> dict:
    e = {k: v for k, v in os.environ.items()
         if not k.startswith(_NOT_FROM_THE_PARENT_PREFIXES) and k not in _NOT_FROM_THE_PARENT}
    e.update(extra)
    return e


def _git(cwd, *args) -> str:
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                        "-c", "commit.gpgsign=false", *args],
                       cwd=str(cwd), capture_output=True, text=True, env=_child_env())
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


def _python(code: str) -> str:
    return shlex.join([sys.executable, "-c", code])


class _Base(unittest.TestCase):

    def setUp(self):
        for needed in (SKRIPT, GATE, SCRIPTS / "pre_tag_receipt_lib.py"):
            if not needed.is_file():
                self.skipTest(f"{needed.name} is not in this tree (a distributed artefact prunes "
                              "scripts/), and a tool that is not here cannot be judged")
        d = tempfile.mkdtemp(prefix="pre-tag-named-tree-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)
        self._number = 0

    def _repo(self, name: str, files: dict[str, str]) -> pathlib.Path:
        repo = self.base / name
        repo.mkdir()
        _git(repo, "init", "-q")
        for rel, text in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", name)
        return repo

    def _emit(self, repo: pathlib.Path, **env):
        self._number += 1
        self.payload = self.base / f"payload_{self._number}.bin"
        self.context = self.base / f"context_{self._number}.json"
        return subprocess.run(
            [sys.executable, str(SKRIPT), "--repo", str(repo), "--version", "9.9.9",
             "--audit-command", _python("print('audit ran')"),
             "--audit-output-file", str(self.base / f"record_{self._number}.txt"),
             "--runner-identity", "t", "--produced-at", "2026-09-27T00:00:00Z",
             "--emit-payload", str(self.payload), "--context-out", str(self.context)],
            capture_output=True, text=True, timeout=300, env=_child_env(**env))


class TheLibraryAsksAboutTheNamedTree(_Base):
    """The release gate calls the library from a process nobody cleaned."""

    def _candidate(self, name: str) -> pathlib.Path:
        """A tree the release gate can judge: the gate, its library, the package it verifies with."""
        repo = self.base / name
        (repo / "scripts").mkdir(parents=True)
        for s in ("pre_tag_audit_gate.py", "pre_tag_receipt_lib.py", "sign_readiness_artifact.py"):
            shutil.copy(SCRIPTS / s, repo / "scripts" / s)
        shutil.copytree(REPO / "src" / "proofbundle", repo / "src" / "proofbundle",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "5.0.0"\n',
                                             encoding="utf-8")
        (repo / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (repo / "audit_artifacts").mkdir()
        return repo

    @staticmethod
    def _key_line(priv) -> str:
        return base64.b64encode(priv.public_key().public_bytes_raw()).decode() + "\n"

    @staticmethod
    def _digest(repo: pathlib.Path) -> str:
        """The tree digest as the library computes it, in a child with a clean environment."""
        r = subprocess.run(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
             f"from pre_tag_receipt_lib import subject_tree_digest; "
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
        receipt = dict(context,
                       signature=base64.b64encode(priv.sign(canonical_bytes(context))).decode(),
                       signer_pubkey=self._key_line(priv).strip())
        (repo / "audit_artifacts" / "500").mkdir(parents=True, exist_ok=True)
        (repo / "audit_artifacts" / "500" / "pre_tag_receipt_5.0.0.json").write_text(
            json.dumps(receipt), encoding="utf-8")

    def _gate(self, repo: pathlib.Path, **env) -> dict:
        r = subprocess.run([sys.executable, str(repo / "scripts" / "pre_tag_audit_gate.py"),
                            "--repo", str(repo), "--version", "5.0.0", "--json"],
                           capture_output=True, text=True, timeout=300, cwd=str(repo),
                           env=_child_env(**env))
        try:
            return json.loads(r.stdout)
        except ValueError:
            raise AssertionError(f"the gate gave no verdict: {r.stdout[-400:]}{r.stderr[-400:]}")

    def test_RED_the_release_gate_judges_the_named_tree_not_the_one_GIT_DIR_names(self):
        """Measured on `814a0097`: `ok=true, state=verified` with the variable, `ok=false` without.

        A genuine release tree G carries a receipt over its own digest. T is a clone of G with one
        source file changed and committed, carrying the same receipt. With `GIT_DIR` pointing at
        G, the library read G's digest and G's anchor and verified the tampered tree T.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        genuine_key = Ed25519PrivateKey.generate()
        g = self._candidate("genuine")
        (g / "src" / "proofbundle" / "payload.py").write_text("AUDITED = True\n", encoding="utf-8")
        (g / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            self._key_line(genuine_key), encoding="utf-8")
        _git(g, "init", "-q")
        _git(g, "add", "-A")
        _git(g, "commit", "-qm", "genuine")
        self._receipt(g, self._digest(g), genuine_key)
        self.assertTrue(self._gate(g)["ok"], "precondition: the receipt verifies on its own tree")

        t = self.base / "tampered"
        _git(self.base, "clone", "-q", str(g), str(t))
        (t / "src" / "proofbundle" / "payload.py").write_text("AUDITED = False\n", encoding="utf-8")
        _git(t, "commit", "-qam", "never audited")
        shutil.copytree(g / "audit_artifacts" / "500", t / "audit_artifacts" / "500")
        self.assertFalse(self._gate(t)["ok"], "precondition: without the variable T is refused")

        verdict = self._gate(t, GIT_DIR=str(g / ".git"))
        self.assertFalse(verdict["ok"],
                         f"GIT_DIR made the gate verify a tree it did not name: {verdict}")

    def test_RED_the_third_party_verifier_does_not_verify_a_checkout_GIT_DIR_stands_in_for(self):
        """The other caller of the same two functions. Measured on `814a0097`: a checkout at a commit
        that injected a dependency after the receipt, asked about the receipt commit C, with
        `GIT_DIR` pointing at a clone of the genuine release at C: `VERIFIED`, exit 0. Without the
        variable it refuses as not at the named commit.

        The verifier's own git calls (head check, status, receipt listing) still follow the
        variable; they are not part of this repair. What changed is that the tree digest and the
        anchor are the checkout's, so the receipt no longer binds what is measured, and the verdict
        is `NOT_VERIFIED` instead of a pass."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        g = self._candidate("genuine")
        shutil.copy(SCRIPTS / "verify_pre_tag_receipt.py", g / "scripts" / "verify_pre_tag_receipt.py")
        (g / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            self._key_line(key), encoding="utf-8")
        _git(g, "init", "-q")
        _git(g, "add", "-A")
        _git(g, "commit", "-qm", "genuine")
        self._receipt(g, self._digest(g), key)
        _git(g, "add", "-A")
        _git(g, "commit", "-qm", "receipt")
        c = _git(g, "rev-parse", "HEAD")

        t = self.base / "checkout"
        _git(self.base, "clone", "-q", str(g), str(t))
        pyproject = t / "pyproject.toml"
        pyproject.write_text(pyproject.read_text(encoding="utf-8")
                             + 'dependencies = ["injected==6.6.6"]\n', encoding="utf-8")
        _git(t, "commit", "-qam", "dependency injected after the receipt")

        def verify(**env) -> tuple[int, str]:
            r = subprocess.run([sys.executable, str(t / "scripts" / "verify_pre_tag_receipt.py"),
                                "--repo", str(t), "--commit", c, "--version", "5.0.0", "--json"],
                               capture_output=True, text=True, timeout=300, cwd=str(t),
                               env=_child_env(**env))
            try:
                return r.returncode, json.loads(r.stdout)["verdict"]
            except (ValueError, KeyError):
                raise AssertionError(f"no verdict: {r.stdout[-400:]}{r.stderr[-400:]}")

        self.assertNotEqual(verify()[1], "VERIFIED", "precondition: the checkout is not C")
        rc, verdict = verify(GIT_DIR=str(g / ".git"))
        self.assertNotEqual(verdict, "VERIFIED",
                            "GIT_DIR made the verifier pass a checkout it did not measure")
        self.assertNotEqual(rc, 0)

    def test_GUARD_the_trust_anchor_is_read_from_the_named_tree_as_well(self):
        """Green on `814a0097`, where neither call was isolated: the digest then came from the other
        repository too and did not match. It is red against a repair that isolates the digest and
        leaves the anchor: then the tree is T's, the keys are E's, and a receipt that E's key
        signed over T's digest verifies.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        genuine_key, foreign_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        t = self._candidate("tree")
        (t / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            self._key_line(genuine_key), encoding="utf-8")
        _git(t, "init", "-q")
        _git(t, "add", "-A")
        _git(t, "commit", "-qm", "tree")
        self._receipt(t, self._digest(t), foreign_key)
        e = self._repo("elsewhere", {"audit_artifacts/pre_tag_trusted_pubkeys.txt":
                                     self._key_line(foreign_key)})
        self.assertFalse(self._gate(t)["ok"], "precondition: the foreign key is not T's anchor")
        verdict = self._gate(t, GIT_DIR=str(e / ".git"))
        self.assertFalse(verdict["ok"],
                         f"the trust anchor was read from the repository GIT_DIR names: {verdict}")

    def test_RED_the_tree_digest_does_not_follow_core_quotePath_of_a_user(self):
        """Measured on `814a0097`: a tree with a non-ASCII path had one digest under a plain home and
        another under a home whose `.gitconfig` sets `core.quotePath=false`, because the digest
        hashes the text of `ls-tree`, and that setting prints the name raw."""
        name = "caf" + chr(0xE9) + ".txt"
        try:
            repo = self._repo("quoted", {name: "x\n"})
        except OSError as e:
            self.skipTest(f"this filesystem does not take the name: {e}")
        plain_home, raw_home = self.base / "home_plain", self.base / "home_raw"
        plain_home.mkdir()
        raw_home.mkdir()
        (raw_home / ".gitconfig").write_text("[core]\n\tquotePath = false\n", encoding="utf-8")
        xdg = self.base / "xdg_empty"
        xdg.mkdir()

        def listing(home):
            return subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD"],
                                  capture_output=True, env=_child_env(HOME=str(home),
                                                                      XDG_CONFIG_HOME=str(xdg))).stdout

        self.assertNotEqual(listing(plain_home), listing(raw_home),
                            "precondition: the setting does not change the listing here, so this "
                            "case would measure nothing")

        def digest(home):
            r = subprocess.run(
                [sys.executable, "-c",
                 f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
                 f"from pre_tag_receipt_lib import subject_tree_digest; "
                 f"print(subject_tree_digest({str(repo)!r}))"],
                capture_output=True, text=True, timeout=120,
                env=_child_env(HOME=str(home), XDG_CONFIG_HOME=str(xdg)))
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout.strip()

        self.assertEqual(digest(plain_home), digest(raw_home),
                         "the tree digest depends on the configuration of whoever computes it")


class TheProducerDropsGitsOwnList(_Base):

    def test_RED_every_repository_local_name_git_knows_leaves_the_process(self):
        """The oracle is git itself: `git rev-parse --local-env-vars`. Measured on `814a0097`:
        GIT_GRAFT_FILE, GIT_IMPLICIT_WORK_TREE, GIT_INTERNAL_SUPER_PREFIX, GIT_PREFIX and
        GIT_SHALLOW_FILE survived the import of the tool. `GIT_NO_REPLACE_OBJECTS` is on git's list
        and is set to 1 on purpose, so it is checked for its value."""
        oracle = subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True,
                                text=True, env=_child_env()).stdout.split()
        self.assertIn("GIT_DIR", oracle, f"git gave no usable list: {oracle}")
        planted = {n: "/nonexistent" for n in oracle}
        planted.update({"GIT_CONFIG_KEY_0": "core.excludesFile", "GIT_CONFIG_VALUE_0": "/x",
                        "GIT_NO_REPLACE_OBJECTS": "0"})
        probe = ("import importlib.util, json, os\n"
                 f"spec = importlib.util.spec_from_file_location('_ptr_probe', {str(SKRIPT)!r})\n"
                 "mod = importlib.util.module_from_spec(spec)\n"
                 "spec.loader.exec_module(mod)\n"
                 f"names = {sorted(planted)!r}\n"
                 "print(json.dumps({n: os.environ[n] for n in names if n in os.environ}))\n")
        r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                           timeout=120, env=_child_env(**planted))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        left = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(left, {"GIT_NO_REPLACE_OBJECTS": "1"},
                         f"names git calls repository-local survived the import of the tool: {left}")

    def test_RED_GIT_INTERNAL_SUPER_PREFIX_does_not_decide_the_verdict(self):
        """Measured on `814a0097`: a clean tree refused with `ls-tree doesn't support
        --super-prefix`, exit 1. The environment decided the verdict, in the refusing direction."""
        repo = self._repo("clean", {"a.txt": "a\n", "scripts/pre_tag_audit_gate.py": "# gate\n"})
        r = self._emit(repo, GIT_INTERNAL_SUPER_PREFIX="sub/")
        self.assertEqual(r.returncode, 0, f"a clean tree was refused:\n{r.stdout}{r.stderr}")


class EachPathIsReadAsGitStoresIt(_Base):

    def test_RED_a_gate_source_that_is_a_symbolic_link_is_refused(self):
        """Measured on `814a0097`: exit 0, and the payload bound sha256 of the link's TARGET while
        the head carries the LINK TEXT at `scripts/pre_tag_audit_gate.py`, which is the blob the
        third-party verifier hashes."""
        repo = self._repo("linked_gate", {"a.txt": "a\n", "scripts/real_gate.py": "# real gate\n"})
        os.symlink("real_gate.py", repo / "scripts" / "pre_tag_audit_gate.py")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "the gate is a link")
        r = self._emit(repo)
        message = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, f"a payload was produced:\n{message[-800:]}")
        self.assertFalse(self.payload.exists(), "a payload was written despite the refusal")
        self.assertIn("scripts/pre_tag_audit_gate.py", message)
        self.assertIn("not as a regular file", message)
        self.assertNotIn("Traceback", message, message[-800:])

    def test_CONTROL_the_bound_gate_digest_is_the_committed_blob(self):
        """A regular gate emits, and what the payload binds is exactly what a reader of the commit
        computes: sha256 of `git show HEAD:scripts/pre_tag_audit_gate.py`."""
        repo = self._repo("regular_gate", {"a.txt": "a\n",
                                           "scripts/pre_tag_audit_gate.py": "# the gate\n"})
        r = self._emit(repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        blob = subprocess.run(["git", "-C", str(repo), "show", "HEAD:scripts/pre_tag_audit_gate.py"],
                              capture_output=True, env=_child_env()).stdout
        bound = json.loads(self.context.read_text(encoding="utf-8"))["gate_source_digest"]
        self.assertEqual(bound, hashlib.sha256(blob).hexdigest())

    def _with_a_name_that_is_not_utf8(self) -> tuple[pathlib.Path, str]:
        name = os.fsdecode(b"caf\xe9.txt")
        repo = self._repo("latin1", {"a.txt": "a\n", "scripts/pre_tag_audit_gate.py": "# gate\n"})
        try:
            (repo / name).write_text("bytes\n", encoding="utf-8")
        except (OSError, UnicodeError) as e:
            self.skipTest(f"this filesystem does not take a name that is not UTF-8: {e}")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "a name that is not UTF-8")
        return repo, name

    def test_RED_a_clean_tree_with_a_name_that_is_not_utf8_emits(self):
        """Measured on `814a0097`: exit 1 with `D caf?.txt` and `?? caf\\udce9.txt`, one file under
        two spellings, because the listing was decoded with replacement and the walk was not."""
        repo, _name = self._with_a_name_that_is_not_utf8()
        r = self._emit(repo)
        self.assertEqual(r.returncode, 0, f"a clean tree was refused:\n{r.stdout}{r.stderr}")

    def test_CONTROL_a_changed_file_with_such_a_name_is_still_refused(self):
        """The repair must not make such a file invisible: changed bytes refuse, by name."""
        repo, name = self._with_a_name_that_is_not_utf8()
        (repo / name).write_text("changed\n", encoding="utf-8")
        r = self._emit(repo)
        self.assertNotEqual(r.returncode, 0, f"a changed file was not seen:\n{r.stdout}{r.stderr}")
        self.assertIn("uncommitted path", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
