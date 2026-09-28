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
  an object read is not the one   (review finding on PR 249, measured at `995cabdd`) git hands out
  its id names                    whatever the object store holds under an id; a rewritten loose
                                  object, a pack whose index names another id, an alternate object
                                  directory or a rewritten tree decided the anchor, the gate source
                                  and the receipt. See `EachObjectReadIsTheObjectItsIdNames`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

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


#: The trust anchor's path in the tree.
KEYS = "audit_artifacts/pre_tag_trusted_pubkeys.txt"


def _git_still(cwd, *args) -> str:
    """`_git` without git's automatic maintenance, so that no object of a case is packed behind its
    back (git 2.47 and later run that maintenance in the background after `commit`)."""
    return _git(cwd, "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args)


def _git_bytes(cwd, *args, stdin: bytes | None = None) -> bytes:
    """A plain git call, bytes in and out: what any git reads from the store, the oracle of the
    object cases below."""
    r = subprocess.run(["git", "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args],
                       cwd=str(cwd), input=stdin, capture_output=True, env=_child_env())
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr.decode()}")
    return r.stdout


def _loose(objects: pathlib.Path, oid: str) -> pathlib.Path:
    return objects / oid[:2] / oid[2:]


def _write_loose(objects: pathlib.Path, oid: str, typ: str, content: bytes) -> None:
    """Store `content` as a loose object of `typ` under `oid` in the object directory `objects`,
    whatever it hashes to: the substitution git does not notice when it reads."""
    path = _loose(objects, oid)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    path.write_bytes(zlib.compress(typ.encode() + b" " + str(len(content)).encode() + b"\0" + content))


def _forged_pack(repo: pathlib.Path, oid: str, typ: str, content: bytes, work: pathlib.Path) -> None:
    """Add a pack to `repo` whose index names `oid` for an object of `typ` with `content`, and take
    the loose object `oid` out of the store, so that the pack is where git finds it (measured: with
    both present, git 2.34.1 read the pack and git 2.55.0 the loose object). git writes the pack for
    the object's true id; only that one name in the version 2 index is changed, with the fan-out
    table and the index checksum that follow from it."""
    helper = work / f"packer-{oid[:12]}"
    _git(work, "init", "-q", "--bare", str(helper))
    true_id = _git_bytes(helper, "hash-object", "-w", "-t", typ, "--stdin", stdin=content).decode().strip()
    name = _git_bytes(helper, "pack-objects", str(helper / "p"),
                      stdin=(true_id + "\n").encode()).decode().strip()
    index = bytearray((helper / f"p-{name}.idx").read_bytes())
    width = len(oid) // 2
    assert index[:8] == b"\xfftOc\x00\x00\x00\x02", "a version 2 pack index"
    index[8 + 1024:8 + 1024 + width] = bytes.fromhex(oid)
    for i in range(256):
        struct.pack_into(">I", index, 8 + 4 * i, 1 if i >= int(oid[:2], 16) else 0)
    index[-width:] = hashlib.new("sha1" if width == 20 else "sha256", bytes(index[:-width])).digest()
    target = repo / ".git" / "objects" / "pack"
    shutil.copy(helper / f"p-{name}.pack", target / f"pack-{name}.pack")
    (target / f"pack-{name}.idx").write_bytes(bytes(index))
    _loose(repo / ".git" / "objects", oid).unlink()


def _foreign_store(repo: pathlib.Path, oid: str, typ: str, content: bytes, work: pathlib.Path) -> None:
    """Take the loose object `oid` out of `repo`'s store and name, in
    `.git/objects/info/alternates`, a directory that holds other content under that id."""
    foreign = work / f"foreign-objects-{oid[:12]}"
    _write_loose(foreign, oid, typ, content)
    _loose(repo / ".git" / "objects", oid).unlink()
    info = repo / ".git" / "objects" / "info"
    info.mkdir(exist_ok=True)
    (info / "alternates").write_text(f"{foreign}\n", encoding="utf-8")


def _tree_entries(raw: bytes, width: int = 20) -> list[tuple[bytes, bytes, str]]:
    """[(mode, name, id)] of a raw tree object."""
    out, pos = [], 0
    while pos < len(raw):
        space = raw.index(b" ", pos)
        nul = raw.index(b"\0", space)
        out.append((raw[pos:space], raw[space + 1:nul], raw[nul + 1:nul + 1 + width].hex()))
        pos = nul + 1 + width
    return out


def _tree_with(repo: pathlib.Path, tree: str, name: bytes, new_id: str) -> bytes:
    """The raw tree `tree` with the entry `name` pointing at `new_id`: a well-formed tree that lists
    another object under the same name."""
    entries = _tree_entries(_git_bytes(repo, "cat-file", "tree", tree))
    assert any(n == name for _m, n, _o in entries), f"{name!r} is not in the tree {tree}"
    return b"".join(m + b" " + n + b"\0" + bytes.fromhex(new_id if n == name else o)
                    for m, n, o in entries)


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
        _git_still(repo, "init", "-q")
        for rel, text in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        _git_still(repo, "add", "-A")
        _git_still(repo, "commit", "-qm", name)
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

    def _receipt(self, repo: pathlib.Path, subject: str, priv, gate: str | None = None) -> str:
        """Write a receipt signed by `priv` over `subject` and the gate `gate` (default: the gate in
        `repo`); return its text."""
        sys.path.insert(0, str(SCRIPTS))
        try:
            from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes  # noqa: PLC0415
        finally:
            sys.path.pop(0)
        context = {"schema": RECEIPT_SCHEMA, "version": "5.0.0", "subject_tree_digest": subject,
                   "gate_source_digest": gate or hashlib.sha256(
                       (repo / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest(),
                   "audit_command": "a", "audit_exit_code": 0, "audit_output_digest": "0" * 64,
                   "runner_identity": "t", "produced_at": "2026-09-27T00:00:00Z"}
        receipt = dict(context,
                       signature=base64.b64encode(priv.sign(canonical_bytes(context))).decode(),
                       signer_pubkey=self._key_line(priv).strip())
        (repo / "audit_artifacts" / "500").mkdir(parents=True, exist_ok=True)
        text = json.dumps(receipt)
        (repo / "audit_artifacts" / "500" / "pre_tag_receipt_5.0.0.json").write_text(
            text, encoding="utf-8")
        return text

    def _gate(self, repo: pathlib.Path, **env) -> dict:
        r = subprocess.run([sys.executable, str(repo / "scripts" / "pre_tag_audit_gate.py"),
                            "--repo", str(repo), "--version", "5.0.0", "--json"],
                           capture_output=True, text=True, timeout=300, cwd=str(repo),
                           env=_child_env(**env))
        try:
            return json.loads(r.stdout)
        except ValueError:
            raise AssertionError(f"the gate gave no verdict: {r.stdout[-400:]}{r.stderr[-400:]}")


class TheLibraryAsksAboutTheNamedTree(_Base):
    """The release gate calls the library from a process nobody cleaned."""

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

        When this case was written the verifier's own git calls (head check, status, receipt
        listing) still followed the variable, and the verdict became `NOT_VERIFIED` because the
        digest and the anchor were the checkout's. Since round two every one of those calls goes
        through the chain's funnel as well, and the run is refused as not at the named commit."""
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


#: Runs in a child: loads the tree's own producer and library by path, forges every object the head
#: names, one at a time, as a loose object under its own id, and prints the chain's answers for the
#: clean store and for each forgery.
_FORGERY_DRIVER = r'''
import importlib.util, json, os, pathlib, stat, subprocess, sys, zlib
scripts, repo = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, scripts / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
producer = load("_forge_producer", "pre_tag_receipt.py")
lib = load("_forge_lib", "pre_tag_receipt_lib.py")
os.environ["GIT_CONFIG_SYSTEM"] = os.devnull
def git(*args, stdin=None):
    r = subprocess.run(["git", "-C", str(repo), *args], input=stdin, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"git {args} failed: {r.stderr!r}")
    return r.stdout
def safe(f):
    try:
        return ["answer", f()]
    except SystemExit as e:
        return ["refused", str(e)]
    except Exception as e:
        return ["refused", f"{type(e).__name__}: {e}"]
def answers():
    return {"digest": safe(lambda: lib.subject_tree_digest(repo)),
            "anchor": safe(lambda: lib.load_trusted_pubkeys(repo)),
            "tree": safe(lambda: producer._baumzustand_oder_stop(repo, "measured")),
            "gate_source": safe(lambda: producer._gate_source_digest(repo))}
ids = [ln.split(" ", 1)[0] for ln in git("rev-list", "--objects", "HEAD").decode().splitlines()]
kinds = git("cat-file", "--batch-check=%(objecttype)", stdin="".join(i + "\n" for i in ids).encode())
types = dict(zip(ids, kinds.decode().split()))
by_type = {}
for i, t in types.items():
    by_type.setdefault(t, []).append(i)
def entries(raw):
    out, pos = [], 0
    while pos < len(raw):
        sp = raw.index(b" ", pos)
        nul = raw.index(b"\0", sp)
        out.append([raw[pos:sp], raw[sp + 1:nul], raw[nul + 1:nul + 21]])
        pos = nul + 21
    return out
def forged(oid, typ, raw):
    """Another well-formed object of the same type: a blob with other bytes, a tree whose first
    blob entry names another blob, a commit that names another tree."""
    if typ == "blob":
        return raw + b"forged\n"
    if typ == "commit":
        first, rest = raw.split(b"\n", 1)
        other = next(t for t in by_type["tree"] if t.encode() != first[5:])
        return b"tree " + other.encode() + b"\n" + rest
    es = entries(raw)
    e = next(e for e in es if types[e[2].hex()] == "blob")
    e[2] = bytes.fromhex(next(b for b in by_type["blob"] if b != e[2].hex()))
    return b"".join(m + b" " + n + b"\0" + i for m, n, i in es)
results = {"baseline": answers(), "objects": {}}
for oid, typ in types.items():
    path = repo / ".git" / "objects" / oid[:2] / oid[2:]
    saved = path.read_bytes()
    content = forged(oid, typ, git("cat-file", typ, oid))
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    try:
        path.write_bytes(zlib.compress(typ.encode() + b" " + str(len(content)).encode() + b"\0"
                                       + content))
        live = git("cat-file", typ, oid) == content
        results["objects"][oid] = {"type": typ, "live": live, "answers": answers()}
    finally:
        path.write_bytes(saved)
print(json.dumps(results))
'''

#: Appended to a checkout's receipt library by the checker case below: a library that verifies
#: everything, so that only a check which does not run on the library can refuse.
_FORGED_LIBRARY_TAIL = '''

def verify_receipt(*_args, **_kwargs):
    return True, "forged"


def subject_tree_digest(_repo):
    return "0" * 64


def load_trusted_pubkeys(_repo, **_kwargs):
    return ["forged"]
'''

#: Appended after `_FORGED_LIBRARY_TAIL` by the case that measures the ORDER of the checker's steps:
#: a library that acts when it is loaded. It writes the genuine bytes of one loose object back into
#: the store, so that a check which runs after the library was loaded finds nothing to refuse.
_RESTORING_TAIL = '''

import base64 as _b64, os as _os, stat as _stat
_os.chmod({path!r}, _stat.S_IRUSR | _stat.S_IWUSR)
with open({path!r}, "wb") as _f:
    _f.write(_b64.b64decode({data!r}))
'''

#: Runs in a child: loads the tree's own library and producer by path and asks one question while a
#: writer rewrites one tree object of the store for exactly the duration of each `ls-tree` call the
#: named module makes through its funnel, and puts the genuine object back after it. The chain reads
#: the objects it checks with `cat-file --batch`; a listing that reads them again is a second read,
#: and this is the writer between the two. Prints the clean answer, the answer under the writer, and
#: for each listing the writer served whether it named the other blob.
_BETWEEN_READS_DRIVER = r'''
import importlib.util, json, pathlib, stat, sys, zlib
scripts, repo, question = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
oid, raw, other = sys.argv[4], bytes.fromhex(sys.argv[5]), sys.argv[6]
def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, scripts / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
lib = load("_between_lib", "pre_tag_receipt_lib.py")
producer = load("_between_producer", "pre_tag_receipt.py")
path = repo / ".git" / "objects" / oid[:2] / oid[2:]
genuine = path.read_bytes()
forged = zlib.compress(b"tree " + str(len(raw)).encode() + b"\0" + raw)
served = []
def between(original):
    def run(where, *args, **kwargs):
        if not args or args[0] != "ls-tree":
            return original(where, *args, **kwargs)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        path.write_bytes(forged)
        try:
            answer = original(where, *args, **kwargs)
        finally:
            path.write_bytes(genuine)
        served.append(other.encode() in answer.stdout)
        return answer
    return run
def safe(f):
    try:
        return ["answer", f()]
    except SystemExit as e:
        return ["refused", str(e)]
    except Exception as e:
        return ["refused", f"{type(e).__name__}: {e}"]
if question == "digest":
    clean = safe(lambda: lib.subject_tree_digest(repo))
    lib.git_run = between(lib.git_run)
    got = safe(lambda: lib.subject_tree_digest(repo))
else:
    clean = None
    producer.git_run = between(producer.git_run)
    got = safe(lambda: producer._baumzustand_oder_stop(repo, "measured"))
print(json.dumps({"clean": clean, "got": got, "served": served}))
'''


class EachObjectReadIsTheObjectItsIdNames(_Base):
    """An object id names one content, and git hands out whatever lies under it without hashing it.

    Review finding on PR 249 (P0): the trust anchor was read with `git show HEAD:<anchor>`, and the
    loose object of the anchor, rewritten with another key under the same id, made the release gate
    answer `ok=true, state=verified` for a receipt signed by a key the committed file does not name;
    the tree digest and the checked-out file were unchanged. The class is "a git read returns an
    object other than the one its id names".

    WHICH GIT HASHES WHAT, measured with plain git on a rewritten loose object: git 2.34.1 hashes an
    object it parses from a revision argument (`git show <rev>:<path>` refuses with "hash mismatch"),
    git 2.55.0 does not; `cat-file` hashes nothing on either; a tree below the root is read without a
    hash on both, on the way to a path and by `ls-tree -r`; a commit and a root tree are hashed on
    both. So the [RED] cases failed at `995cabddb3850562d442e82b28af5560273dfdea` as follows:
      with git 2.34.1 and 2.55.0   a rewritten tree (gate), the producer's gate source, the checker's
                                   cleanliness check, and the generator (four trees, the gate blob);
                                   and three cases that each catch a planted half fix no other case
                                   caught: a writer between the check and a second read (the
                                   producer's comparison, the digest's listing), and a library that
                                   acts when it is loaded (the checker's order);
      with git 2.55.0 only         the finding itself (a loose object), the same substitution
                                   through a pack whose index names another id and through an
                                   alternate object directory, and the checker's gate source,
                                   anchor and receipt: git 2.34.1 refused those reads itself.
    The [GUARD] cases hold what was already so: a rewritten commit is refused, and a genuine store
    in a pack or behind alternates still verifies. The contract holds the checker's own copy of the
    check to the library's.
    """

    def _keys(self):
        """(the key the committed anchor names, another key), both made fresh. No case depends on
        the bytes of a key, and a shipped test file loads no fixed private key
        (`tests/test_sdist_ohne_signierwerkzeug.py` counts `from_private_bytes` with an argument that
        is not written out as a literal)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

    def _committed_candidate(self, name: str, anchor_key, *, checker: bool = False) -> pathlib.Path:
        g = self._candidate(name)
        if checker:
            shutil.copy(SCRIPTS / "verify_pre_tag_receipt.py", g / "scripts" / "verify_pre_tag_receipt.py")
        (g / KEYS).write_text(self._key_line(anchor_key), encoding="utf-8")
        _git_still(g, "init", "-q")
        _git_still(g, "add", "-A")
        _git_still(g, "commit", "-qm", name)
        return g

    @staticmethod
    def _plain_digest(repo: pathlib.Path, tree: str = "HEAD") -> str:
        """The digest over the listing a plain git prints NOW for `tree`, formed as the library
        forms it (the fixtures carry no path the library leaves out)."""
        text = _git_bytes(repo, "-c", "core.quotePath=true", "ls-tree", "--full-tree", "-r",
                          tree).decode("ascii")
        return hashlib.sha256("\n".join(sorted(text.splitlines())).encode("utf-8")).hexdigest()

    def _objects(self, repo: pathlib.Path) -> pathlib.Path:
        return repo / ".git" / "objects"

    def _assert_the_store_no_longer_gives(self, repo: pathlib.Path, spec: str, other: bytes) -> str:
        """Precondition of a forgery: a plain `git show <spec>` reads `other`, or refuses with a hash
        mismatch. Which of the two depends on the git (measured: 2.34.1 hashes an object it parses
        from a revision argument and refuses, 2.55.0 reads the forged content); either way the
        store no longer gives the committed content silently. -> "reads" or "refuses"."""
        r = subprocess.run(["git", "show", spec], cwd=str(repo), capture_output=True, env=_child_env())
        reads = r.returncode == 0 and r.stdout == other
        refuses = r.returncode != 0 and b"hash mismatch" in r.stderr
        self.assertTrue(reads or refuses,
                        f"precondition: git neither reads the forged content at {spec} nor refuses it "
                        f"as a hash mismatch (rc={r.returncode}, {r.stdout[:80]!r}, {r.stderr[:200]!r})")
        return "reads" if reads else "refuses"

    # ── the release gate ─────────────────────────────────────────────────────────────────────

    def _gate_after(self, forge) -> dict:
        """A tree whose anchor names the trusted key, a receipt signed by another key, and the gate's
        verdict after `forge(g, content)` rewrote the store so that a git which does not hash what it
        reads finds `content` at the anchor's path. The receipt binds the digest over the listing
        such a git prints: `forge` returns a genuine tree whose listing that is, or None when the
        listing of HEAD is unchanged."""
        trusted, other = self._keys()
        g = self._committed_candidate("genuine", trusted)
        self.assertEqual(self._plain_digest(g), self._digest(g),
                         "precondition: this case forms the digest as the library does")
        self._receipt(g, self._plain_digest(g), other)
        self.assertFalse(self._gate(g)["ok"],
                         "precondition: a receipt by a key the committed anchor does not name is refused")
        listed = forge(g, self._key_line(other).encode())
        self.assertEqual((g / KEYS).read_text(encoding="utf-8"), self._key_line(trusted),
                         "the checked-out anchor is still the committed one")
        self._receipt(g, self._plain_digest(g, listed or "HEAD"), other)
        return self._gate(g)

    def _anchor_id(self, g: pathlib.Path) -> str:
        return _git(g, "rev-parse", f"HEAD:{KEYS}")

    def test_RED_L1_a_rewritten_loose_object_of_the_anchor_trusts_no_other_key(self):
        """The review finding, as its red test wrote it: the loose object of the anchor rewritten
        with the other key under the same id. At `995cabdd` with git 2.55.0: `ok=true,
        state=verified`. With git 2.34.1 `git show` hashes the blob and fails, and the gate refused
        there already."""
        def forge(g, content):
            oid, before = self._anchor_id(g), self._plain_digest(g)
            self.assertTrue(_loose(self._objects(g), oid).is_file(), "precondition: a loose object")
            _write_loose(self._objects(g), oid, "blob", content)
            self.assertEqual(self._plain_digest(g), before, "the tree digest does not see the substitution")
            self._assert_the_store_no_longer_gives(g, f"HEAD:{KEYS}", content)
        verdict = self._gate_after(forge)
        self.assertFalse(verdict["ok"], f"the gate trusted a key the committed anchor does not name: {verdict}")

    def test_RED_an_anchor_from_a_pack_whose_index_names_another_id(self):
        """The same substitution, packed: the loose object leaves the store, and a pack whose index
        names its id for other content is where git finds it. At `995cabdd` with git 2.55.0:
        `ok=true`."""
        def forge(g, content):
            _forged_pack(g, self._anchor_id(g), "blob", content, self.base)
            self._assert_the_store_no_longer_gives(g, f"HEAD:{KEYS}", content)
        verdict = self._gate_after(forge)
        self.assertFalse(verdict["ok"], f"a packed object under a foreign id was trusted: {verdict}")

    def test_RED_an_anchor_from_an_alternate_object_directory(self):
        """The genuine object leaves the store, and `.git/objects/info/alternates` names a directory
        that holds other content under its id. At `995cabdd` with git 2.55.0: `ok=true`."""
        def forge(g, content):
            _foreign_store(g, self._anchor_id(g), "blob", content, self.base)
            self._assert_the_store_no_longer_gives(g, f"HEAD:{KEYS}", content)
        verdict = self._gate_after(forge)
        self.assertFalse(verdict["ok"], f"an object of an alternate directory was trusted: {verdict}")

    def test_RED_a_rewritten_tree_names_another_anchor(self):
        """The tree `audit_artifacts`, rewritten under its id to list another blob as the anchor.
        git reads a tree on the way to a path without hashing it on both measured versions, so the
        digest a plain git computes moves with it, and the receipt binds that digest. At
        `995cabdd`: `ok=true`, with git 2.34.1 and 2.55.0."""
        def forge(g, content):
            new = _git_bytes(g, "hash-object", "-w", "--stdin", stdin=content).decode().strip()
            tree = _git(g, "rev-parse", "HEAD:audit_artifacts")
            _write_loose(self._objects(g), tree, "tree",
                         _tree_with(g, tree, b"pre_tag_trusted_pubkeys.txt", new))
            self.assertEqual(self._assert_the_store_no_longer_gives(g, f"HEAD:{KEYS}", content), "reads",
                             "precondition: a plain git reads through the rewritten tree")
        verdict = self._gate_after(forge)
        self.assertFalse(verdict["ok"], f"a rewritten tree decided the anchor: {verdict}")

    def test_GUARD_a_rewritten_commit_names_no_other_tree(self):
        """The head's commit object, rewritten under its id to name another root tree (a genuine one
        whose anchor lists the other key). git hashes a commit it parses, on both measured versions,
        so this was refused at `995cabdd` as well; the case holds that it stays refused."""
        def forge(g, content):
            new = _git_bytes(g, "hash-object", "-w", "--stdin", stdin=content).decode().strip()
            anchors = _git_bytes(g, "mktree", stdin=f"100644 blob {new}\tpre_tag_trusted_pubkeys.txt\n"
                                 .encode()).decode().strip()
            root = _git(g, "rev-parse", "HEAD^{tree}")
            other_root = _git_bytes(g, "hash-object", "-w", "-t", "tree", "--stdin",
                                    stdin=_tree_with(g, root, b"audit_artifacts", anchors)).decode().strip()
            commit = _git(g, "rev-parse", "HEAD")
            _first, rest = _git_bytes(g, "cat-file", "commit", commit).split(b"\n", 1)
            forged = b"tree " + other_root.encode() + b"\n" + rest
            _write_loose(self._objects(g), commit, "commit", forged)
            self.assertEqual(_git_bytes(g, "cat-file", "commit", commit), forged,
                             "precondition: the store holds the rewritten commit under the head's id")
            return other_root
        verdict = self._gate_after(forge)
        self.assertFalse(verdict["ok"], f"a rewritten commit decided the tree: {verdict}")

    def test_GUARD_a_genuine_store_in_a_pack_verifies(self):
        """Green at `995cabdd` and here: the check hashes what it reads, and a genuine packed object
        hashes to its id, so a packed repository is not refused."""
        trusted, _other = self._keys()
        g = self._committed_candidate("packed", trusted)
        _git_still(g, "repack", "-a", "-d", "-q")
        _git_still(g, "prune-packed")
        self.assertFalse(_loose(self._objects(g), self._anchor_id(g)).exists(), "precondition: packed")
        self._receipt(g, self._digest(g), trusted)
        verdict = self._gate(g)
        self.assertTrue(verdict["ok"], f"a genuine packed store was refused: {verdict}")

    def test_GUARD_a_genuine_store_behind_alternates_verifies(self):
        """Green at `995cabdd` and here: a clone made with `--shared` holds no object of its own and
        reads every one through alternates; each still hashes to its id."""
        trusted, _other = self._keys()
        g = self._committed_candidate("source", trusted)
        c = self.base / "shared"
        _git_still(self.base, "clone", "-q", "--shared", str(g), str(c))
        self.assertTrue((self._objects(c) / "info" / "alternates").is_file(), "precondition")
        self.assertFalse(_loose(self._objects(c), self._anchor_id(c)).exists(),
                         "precondition: the clone reads the anchor through alternates")
        self._receipt(c, self._digest(c), trusted)
        verdict = self._gate(c)
        self.assertTrue(verdict["ok"], f"a genuine store behind alternates was refused: {verdict}")

    # ── the producer ─────────────────────────────────────────────────────────────────────────

    def test_RED_the_producer_binds_no_gate_source_the_head_does_not_carry(self):
        """The producer hashed the gate source from `git cat-file blob <id>`, which hashes nothing on
        either measured version. With the gate's loose object rewritten, the checkout still equals
        the head (the cleanliness check hashes the bytes on disk), and at `995cabdd` the emit
        returned 0 and bound sha256 of the rewritten bytes, with git 2.34.1 and 2.55.0."""
        repo = self._repo("gate_source", {"a.txt": "a\n", "scripts/pre_tag_audit_gate.py": "# the gate\n"})
        oid = _git(repo, "rev-parse", "HEAD:scripts/pre_tag_audit_gate.py")
        self.assertTrue(_loose(self._objects(repo), oid).is_file(), "precondition: a loose object")
        _write_loose(self._objects(repo), oid, "blob", b"# another gate\n")
        self.assertEqual(_git_bytes(repo, "cat-file", "blob", oid), b"# another gate\n",
                         "precondition: the read the producer used gives the other gate")
        r = self._emit(repo)
        message = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0,
                            f"the payload binds a gate the head does not carry:\n{message[-800:]}")
        self.assertFalse(self.payload.exists(), "a payload was written despite the refusal")
        self.assertIn("scripts/pre_tag_audit_gate.py", message)
        self.assertIn("is not the object its id names", message)
        self.assertNotIn("Traceback", message, message[-800:])

    def _between(self, repo: pathlib.Path, question: str, tree: str, raw: bytes, other: str) -> dict:
        """`_BETWEEN_READS_DRIVER` on `repo`: the tree object `tree` reads as `raw` while the named
        module lists a tree through its funnel, and as itself at every other moment."""
        r = subprocess.run([sys.executable, "-B", "-c", _BETWEEN_READS_DRIVER, str(SCRIPTS), str(repo),
                            question, tree, raw.hex(), other],
                           capture_output=True, text=True, timeout=300,
                           env=_child_env(GIT_CONFIG_SYSTEM=os.devnull))
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_RED_the_producer_compares_the_checkout_with_the_tree_it_checked(self):
        """The producer compares the bytes on disk with the head's entries. Those entries must be the
        ones read from checked objects, not a listing git prints afterwards: with the tree `src`
        rewritten for exactly the duration of a listing, to name the modified `src/x.py` that lies
        on disk, a comparison against that listing found the checkout clean, and the digest at the
        end (taken from the genuine store again) bound the head. At `995cabdd` the producer took its
        entries from `ls-tree -r -z HEAD` and answered for this checkout; a planted copy of this
        head that takes them from that listing again answered as well. Here the comparison is with
        the checked tree, and the modified file refuses by name."""
        repo = self._repo("between_producer", {"a.txt": "a\n", "src/x.py": "X = 1\n",
                                               "scripts/pre_tag_audit_gate.py": "# gate\n"})
        (repo / "src" / "x.py").write_text("X = 2\n", encoding="utf-8")
        other = _git_bytes(repo, "hash-object", "-w", "--stdin", stdin=b"X = 2\n").decode().strip()
        src = _git(repo, "rev-parse", "HEAD:src")
        self.assertTrue(_loose(self._objects(repo), src).is_file(), "precondition: a loose tree")
        got = self._between(repo, "producer", src, _tree_with(repo, src, b"x.py", other), other)
        self.assertEqual(got["got"][0], "refused",
                         f"the checkout was compared with a listing read after the check: {got}")
        self.assertIn("M src/x.py", got["got"][1])

    # ── the third-party checker ──────────────────────────────────────────────────────────────

    def _checker_commit(self, anchor_key, receipt_key, *, gate: str | None = None,
                        spoil: bool = False) -> tuple[pathlib.Path, str, str]:
        """A committed candidate with the checker and a committed receipt; -> (repo, commit, the
        text of the receipt as signed). With `spoil` the committed receipt carries one signed field
        changed, so its signature does not verify."""
        g = self._committed_candidate("checker", anchor_key, checker=True)
        signed = self._receipt(g, self._digest(g), receipt_key, gate=gate)
        if spoil:
            (g / "audit_artifacts" / "500" / "pre_tag_receipt_5.0.0.json").write_text(
                json.dumps(dict(json.loads(signed), runner_identity="someone else")), encoding="utf-8")
        _git_still(g, "add", "-A")
        _git_still(g, "commit", "-qm", "receipt")
        return g, _git(g, "rev-parse", "HEAD"), signed

    @staticmethod
    def _verify(repo: pathlib.Path, commit: str) -> tuple[int, dict]:
        r = subprocess.run([sys.executable, str(repo / "scripts" / "verify_pre_tag_receipt.py"),
                            "--repo", str(repo), "--commit", commit, "--version", "5.0.0", "--json"],
                           capture_output=True, text=True, timeout=300, cwd=str(repo),
                           env=_child_env())
        try:
            return r.returncode, json.loads(r.stdout)
        except ValueError:
            raise AssertionError(f"the checker gave no verdict: {r.stdout[-400:]}{r.stderr[-400:]}")

    def _assert_checker_refuses(self, repo: pathlib.Path, commit: str, what: str) -> None:
        rc, res = self._verify(repo, commit)
        self.assertNotEqual(res["verdict"], "VERIFIED", f"{what}: {res}")
        self.assertNotEqual(rc, 0, f"{what}: exit 0")

    def test_RED_the_checker_hashes_no_gate_source_the_commit_does_not_carry(self):
        """A receipt signed by the trusted key binds a gate other than the committed one. At
        `995cabdd`, with the gate's loose object rewritten to that other gate, the checker hashed
        what `git show` gave and said `VERIFIED`, exit 0, with git 2.55.0 (git 2.34.1 hashes what
        `show` parses and the checker refused there already)."""
        trusted, _other = self._keys()
        other_gate = (SCRIPTS / "pre_tag_audit_gate.py").read_bytes() + b"# not the committed gate\n"
        g, c, _ = self._checker_commit(trusted, trusted, gate=hashlib.sha256(other_gate).hexdigest())
        self.assertNotEqual(self._verify(g, c)[1]["verdict"], "VERIFIED",
                            "precondition: the receipt binds a gate the commit does not carry")
        oid = _git(g, "rev-parse", f"{c}:scripts/pre_tag_audit_gate.py")
        self.assertTrue(_loose(self._objects(g), oid).is_file(), "precondition: a loose object")
        _write_loose(self._objects(g), oid, "blob", other_gate)
        self._assert_the_store_no_longer_gives(g, f"{c}:scripts/pre_tag_audit_gate.py", other_gate)
        self._assert_checker_refuses(g, c, "the checker hashed a gate the commit does not carry")

    def test_RED_the_checker_trusts_no_key_the_committed_anchor_does_not_name(self):
        """The checker loads the anchor through the same library read as the gate. At `995cabdd`,
        with the anchor's loose object rewritten to the other key: `VERIFIED`, exit 0, with git
        2.55.0 (git 2.34.1 refused there already, as for the gate)."""
        trusted, other = self._keys()
        g, c, _ = self._checker_commit(trusted, other)
        self.assertNotEqual(self._verify(g, c)[1]["verdict"], "VERIFIED", "precondition")
        oid = _git(g, "rev-parse", f"{c}:{KEYS}")
        self.assertTrue(_loose(self._objects(g), oid).is_file(), "precondition: a loose object")
        _write_loose(self._objects(g), oid, "blob", self._key_line(other).encode())
        self._assert_the_store_no_longer_gives(g, f"{c}:{KEYS}", self._key_line(other).encode())
        self._assert_checker_refuses(g, c, "the checker trusted a key the committed anchor does not name")

    def test_RED_the_checker_judges_the_receipt_the_commit_carries(self):
        """The committed receipt's signature does not verify (one signed field changed). At
        `995cabdd`, with its loose object rewritten to the receipt as signed, the checker read that
        through `git show` and said `VERIFIED`, exit 0, for a commit whose receipt is broken, with
        git 2.55.0 (git 2.34.1 refused there already)."""
        trusted, _other = self._keys()
        g, c, signed = self._checker_commit(trusted, trusted, spoil=True)
        self.assertNotEqual(self._verify(g, c)[1]["verdict"], "VERIFIED",
                            "precondition: the committed receipt does not verify")
        rel = "audit_artifacts/500/pre_tag_receipt_5.0.0.json"
        oid = _git(g, "rev-parse", f"{c}:{rel}")
        self.assertTrue(_loose(self._objects(g), oid).is_file(), "precondition: a loose object")
        _write_loose(self._objects(g), oid, "blob", signed.encode())
        self._assert_the_store_no_longer_gives(g, f"{c}:{rel}", signed.encode())
        self._assert_checker_refuses(g, c, "the checker judged a receipt the commit does not carry")

    def test_RED_the_checker_does_not_judge_with_a_library_a_rewritten_tree_hides(self):
        """The checker refuses a checkout whose `scripts/` differ from the commit, by `git status`,
        which compares the checkout with the commit's TREES. The tree `scripts`, rewritten under its
        id to list a modified library (added to the index as well), made `git status` clean, and at
        `995cabdd` that library then judged a receipt nobody trusted signed: `VERIFIED`, exit 0.
        The library's own checks do not help here, because it is the library that was replaced; the
        check has to run on the checker's own code, before the cleanliness check trusts the trees."""
        trusted, other = self._keys()
        g, c, _ = self._checker_commit(trusted, other)
        self.assertNotEqual(self._verify(g, c)[1]["verdict"], "VERIFIED", "precondition")
        lib = g / "scripts" / "pre_tag_receipt_lib.py"
        lib.write_text(lib.read_text(encoding="utf-8") + _FORGED_LIBRARY_TAIL, encoding="utf-8")
        new = _git_bytes(g, "hash-object", "-w", "scripts/pre_tag_receipt_lib.py").decode().strip()
        scripts_tree = _git(g, "rev-parse", f"{c}:scripts")
        _write_loose(self._objects(g), scripts_tree, "tree",
                     _tree_with(g, scripts_tree, b"pre_tag_receipt_lib.py", new))
        _git_still(g, "add", "scripts/pre_tag_receipt_lib.py")
        self.assertEqual(_git_bytes(g, "status", "--porcelain", "--untracked-files=all", "--",
                                    "scripts", "src"), b"",
                         "precondition: a plain git status sees no modification under scripts/")
        self._assert_checker_refuses(g, c, "a library hidden by a rewritten tree judged the commit")

    def test_RED_the_checker_checks_the_trees_before_it_loads_the_library(self):
        """The case above with a library that ACTS WHEN IT IS LOADED: it writes the genuine tree
        `scripts` back into the store. The checker has to check the commit's trees before it loads
        anything from the checkout; a check that runs after the load finds a genuine store and lets
        the planted library judge. At `995cabdd` there was no check (`VERIFIED`, exit 0); a planted
        copy of this head with the check moved behind the cleanliness check and the load said
        `VERIFIED` as well, while the case above stayed green against it."""
        trusted, other = self._keys()
        g, c, _ = self._checker_commit(trusted, other)
        self.assertNotEqual(self._verify(g, c)[1]["verdict"], "VERIFIED", "precondition")
        scripts_tree = _git(g, "rev-parse", f"{c}:scripts")
        loose = _loose(self._objects(g), scripts_tree)
        self.assertTrue(loose.is_file(), "precondition: a loose tree")
        lib = g / "scripts" / "pre_tag_receipt_lib.py"
        lib.write_text(lib.read_text(encoding="utf-8") + _FORGED_LIBRARY_TAIL + _RESTORING_TAIL.format(
            path=str(loose), data=base64.b64encode(loose.read_bytes()).decode()), encoding="utf-8")
        new = _git_bytes(g, "hash-object", "-w", "scripts/pre_tag_receipt_lib.py").decode().strip()
        _write_loose(self._objects(g), scripts_tree, "tree",
                     _tree_with(g, scripts_tree, b"pre_tag_receipt_lib.py", new))
        _git_still(g, "add", "scripts/pre_tag_receipt_lib.py")
        self.assertEqual(_git_bytes(g, "status", "--porcelain", "--untracked-files=all", "--",
                                    "scripts", "src"), b"",
                         "precondition: a plain git status sees no modification under scripts/")
        self._assert_checker_refuses(g, c, "a library that restores the store when it is loaded "
                                           "judged the commit")

    # ── a second read after the check ────────────────────────────────────────────────────────

    def test_RED_the_digest_is_not_taken_over_a_listing_read_after_the_check(self):
        """The tree digest is taken over the text of `ls-tree`, which reads the commit and its trees
        a second time after `git_tree` checked them. With the tree `src` rewritten for exactly the
        duration of that listing, to name another blob, the digest must still be the clean one or
        refuse. At `995cabdd` it was the digest of the rewritten listing; a planted copy of this head
        without the comparison of the listing with the checked tree gave the same wrong digest,
        while every other case stayed green against it."""
        repo = self._repo("between_digest", {"a.txt": "a\n", "src/x.py": "X = 1\n", KEYS: "KEY\n"})
        other = _git_bytes(repo, "hash-object", "-w", "--stdin", stdin=b"X = 2\n").decode().strip()
        src = _git(repo, "rev-parse", "HEAD:src")
        self.assertTrue(_loose(self._objects(repo), src).is_file(), "precondition: a loose tree")
        got = self._between(repo, "digest", src, _tree_with(repo, src, b"x.py", other), other)
        self.assertEqual(got["clean"][0], "answer", got)
        self.assertEqual(got["served"], [True],
                         f"precondition: the listing after the check named the other blob: {got}")
        self.assertTrue(got["got"][0] == "refused" or got["got"] == got["clean"],
                        f"the digest was taken over a listing that is not the checked tree: {got}")

    # ── the class, generated ─────────────────────────────────────────────────────────────────

    def test_RED_every_object_the_head_names_forged_one_at_a_time(self):
        """A generator instead of a point fixture: git's own list of the objects a head names
        (`rev-list --objects`), each rewritten in turn as a well-formed object of its type under its
        own id, and the chain's four answers about the tree (digest, anchor, the producer's
        measurement, the gate source). Each answer must equal the clean store's or refuse; an
        answer that CHANGES is an answer about an object the id does not name. At `995cabdd` the
        four trees below the root and the gate blob changed an answer with git 2.34.1 and 2.55.0,
        and the anchor blob with 2.55.0; git itself refused the commit and the root tree."""
        repo = self._repo("forged", {"a.txt": "a\n", "scripts/pre_tag_audit_gate.py": "# gate\n",
                                     KEYS: "KEY\n", "src/x.py": "X = 1\n", "src/sub/y.py": "Y = 1\n"})
        r = subprocess.run([sys.executable, "-B", "-c", _FORGERY_DRIVER, str(SCRIPTS), str(repo)],
                           capture_output=True, text=True, timeout=900,
                           env=_child_env(GIT_CONFIG_SYSTEM=os.devnull))
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        results = json.loads(r.stdout.strip().splitlines()[-1])
        baseline = results["baseline"]
        self.assertEqual(baseline["anchor"], ["answer", ["KEY"]], baseline)
        self.assertEqual(baseline["tree"][0], "answer", baseline)
        self.assertRegex(baseline["digest"][1], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(baseline["gate_source"], ["answer", hashlib.sha256(b"# gate\n").hexdigest()])
        kinds = [o["type"] for o in results["objects"].values()]
        self.assertEqual((kinds.count("commit"), kinds.count("tree"), kinds.count("blob")), (1, 5, 5),
                         "anti-vacuity: every object of the head was forged")
        for oid, got in results["objects"].items():
            with self.subTest(object=f"{got['type']} {oid[:12]}"):
                self.assertTrue(got["live"], "precondition: a plain git reads the forged object")
                for name, answer in got["answers"].items():
                    if answer[0] == "refused" or answer == baseline[name]:
                        continue
                    if name == "anchor" and answer == ["answer", []]:
                        continue                                    # no anchor: fails closed
                    self.fail(f"the {name} answered about another object: {answer} (clean: "
                              f"{baseline[name]})")

    # ── the checker's copy of the check ──────────────────────────────────────────────────────

    def test_CONTRACT_the_checker_and_the_library_read_one_tree_and_refuse_one_forgery(self):
        """The checker carries its own copy of the object check (it must not run the library it
        checks), and the library's tree digest now holds the `ls-tree` text against the checked
        objects. Held here on names git quotes: both copies list the same entries as git does, the
        digest is the one over `ls-tree`'s text, an id is what `git hash-object` computes, and both
        refuse the same rewritten tree. New functions: this case errors at `995cabdd`."""
        import importlib.util as ilu  # noqa: PLC0415
        mods = {}
        for rel in ("pre_tag_receipt_lib.py", "verify_pre_tag_receipt.py"):
            spec = ilu.spec_from_file_location(f"_object_contract_{rel[:-3]}", SCRIPTS / rel)
            mods[rel] = ilu.module_from_spec(spec)
            spec.loader.exec_module(mods[rel])
        lib, checker = mods["pre_tag_receipt_lib.py"], mods["verify_pre_tag_receipt.py"]
        files = {"a.txt": "a\n", "quote\"d.txt": "q\n", "tab\tbed.txt": "t\n", "new\nline.txt": "n\n",
                 "back\\slash.txt": "b\n", "caf" + chr(0xE9) + ".txt": "c\n",
                 os.fsdecode(b"lat\xe9.txt"): "l\n", "deep/er/z.txt": "z\n"}
        try:
            repo = self._repo("quoted_names", files)
        except OSError as e:
            self.skipTest(f"this filesystem does not take the names: {e}")
        (repo / "link").symlink_to("a.txt")
        (repo / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (repo / "run.sh").chmod(stat.S_IRUSR | stat.S_IXUSR)
        _git_still(repo, "add", "-A")
        _git_still(repo, "commit", "-qm", "a link and an executable")
        commit, entries = lib.git_tree(repo, "HEAD")
        self.assertEqual(commit, _git(repo, "rev-parse", "HEAD"))
        oracle = []
        for field in _git_bytes(repo, "ls-tree", "-r", "-t", "-z", "HEAD").split(b"\0"):
            if field:
                head, _tab, path = field.partition(b"\t")
                mode, typ, oid = head.decode().split(" ")
                oracle.append((mode, typ, oid, path))
        self.assertEqual(sorted(entries), sorted(oracle), "the library's walk is not git's listing")
        self.assertEqual(checker._baum(repo, commit),
                         {os.fsdecode(p): (t, o) for _m, t, o, p in entries},
                         "the checker's walk is not the library's")
        text = _git_bytes(repo, "-c", "core.quotePath=true", "ls-tree", "--full-tree", "-r", "HEAD")
        self.assertIn(b'"', text, "precondition: git quotes some of these names")
        self.assertEqual(lib.subject_tree_digest(repo),
                         hashlib.sha256(b"\n".join(sorted(text.splitlines()))).hexdigest(),
                         "the digest is not the one over the text of ls-tree")
        for _m, typ, oid, _p in entries:
            if typ == "blob":
                raw = _git_bytes(repo, "cat-file", "blob", oid)
                self.assertEqual(lib.git_object_id("blob", raw, len(oid)),
                                 _git_bytes(repo, "hash-object", "--stdin", stdin=raw).decode().strip())
                self.assertEqual(lib.git_objects(repo, [(oid, "blob")]),
                                 checker._objekte(repo, [(oid, "blob")]))
        deep = _git(repo, "rev-parse", "HEAD:deep/er")
        _write_loose(self._objects(repo), deep, "tree",
                     _tree_with(repo, deep, b"z.txt", _git(repo, "rev-parse", "HEAD:a.txt")))
        with self.assertRaises(lib.BaumNichtLesbar):
            lib.git_tree(repo, "HEAD")
        with self.assertRaises(checker._NichtDasObjekt):
            checker._baum(repo, commit)


if __name__ == "__main__":
    unittest.main()
