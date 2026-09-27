"""Git's configuration and environment do not answer for the pre-tag receipt chain.

Round two of pull request 249, after an adversarial lens and a Codex review of `4e67ba25`. That
commit removed a LIST of redirecting environment names from two of the chain's git calls. The
findings below are what git still answered through: the third-party verifier's own calls, a
configured excludes file, the replacement switch in the configuration, `core.worktree` and a
`--repo` that names a subdirectory, untracked names read as pathspec magic, the executable bit,
a directory replaced by a symbolic link, and environment names the list did not carry.

Every case labelled RED failed against `4e67ba25` in the form it has here, for the reason its
docstring names; a GUARD case was green there and fails against the half repair it names; a
CONTROL case keeps a refusal from passing for a tool that refuses everything; an unlabelled case
pins a property whose docstring says how it stood at `4e67ba25`. Each case drives the real script
(producer, release gate or third-party verifier) as a process, against a throwaway repository,
with a throwaway home, so no configuration of the machine that runs the suite answers for a case.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
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
PRODUCER = SCRIPTS / "pre_tag_receipt.py"
_CHAIN = ("pre_tag_receipt.py", "pre_tag_receipt_lib.py", "pre_tag_audit_gate.py",
          "verify_pre_tag_receipt.py", "sign_readiness_artifact.py")
_KEY_ANCHOR = "audit_artifacts/pre_tag_trusted_pubkeys.txt"


def _clean_env(home: pathlib.Path, **extra) -> dict:
    """The parent's environment without git's namespace, with a throwaway home and no bytecode
    written into the trees under test. A case that needs a name sets it; that is the measurement."""
    e = {k: v for k, v in os.environ.items()
         if not k.startswith("GIT_")
         and k not in ("HOME", "XDG_CONFIG_HOME", "PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE")}
    e.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".xdg"),
              "PYTHONDONTWRITEBYTECODE": "1"})
    e.update(extra)
    return e


def _lib():
    """The receipt library of the tree under test, loaded by path (its import runs no git)."""
    spec = importlib.util.spec_from_file_location("_pre_tag_config_case_lib",
                                                  SCRIPTS / "pre_tag_receipt_lib.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _key_line(priv) -> str:
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode() + "\n"


class _Case(unittest.TestCase):

    def setUp(self):
        for name in _CHAIN:
            if not (SCRIPTS / name).is_file():
                self.skipTest(f"scripts/{name} is not in this tree (a distributed artefact prunes "
                              "scripts/), and a tool that is not here cannot be judged")
        d = tempfile.mkdtemp(prefix="pre-tag-config-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)
        self.home = self.base / "home"
        (self.home / ".xdg").mkdir(parents=True)
        self._n = 0

    # ── fixtures ─────────────────────────────────────────────────────────────────────────────
    def git(self, cwd, *args, env: dict | None = None) -> str:
        r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "-c", "commit.gpgsign=false", *args],
                           cwd=str(cwd), capture_output=True, env=env or _clean_env(self.home))
        if r.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr.decode()}")
        return r.stdout.decode("utf-8", "replace")

    def status(self, repo, **env) -> str:
        return self.git(repo, "status", "--porcelain", "--untracked-files=all", "--ignored",
                        env=_clean_env(self.home, **env))

    def repo(self, name: str, files: dict, modes: dict | None = None,
             force: tuple = ()) -> pathlib.Path:
        r = self.base / name
        r.mkdir()
        self.git(r, "init", "-q")
        for rel, content in files.items():
            p = r / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content if isinstance(content, bytes) else content.encode())
        for rel, mode in (modes or {}).items():
            os.chmod(r / rel, mode)
        self.git(r, "add", "-A")
        for rel in force:
            self.git(r, "add", "-f", rel)
        self.git(r, "commit", "-qm", name)
        return r

    def candidate(self, where: pathlib.Path, anchor: str,
                  payload: str = "AUDITED = True\n") -> pathlib.Path:
        """A tree the release gate and the verifier can judge, not yet a repository."""
        (where / "scripts").mkdir(parents=True)
        for s in ("pre_tag_audit_gate.py", "pre_tag_receipt_lib.py", "sign_readiness_artifact.py",
                  "verify_pre_tag_receipt.py"):
            shutil.copy(SCRIPTS / s, where / "scripts" / s)
        shutil.copytree(REPO / "src" / "proofbundle", where / "src" / "proofbundle",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (where / "src" / "proofbundle" / "payload.py").write_text(payload, encoding="utf-8")
        (where / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "5.0.0"\n',
                                              encoding="utf-8")
        (where / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (where / "audit_artifacts").mkdir()
        (where / _KEY_ANCHOR).write_text(anchor, encoding="utf-8")
        return where

    def digest(self, repo: pathlib.Path) -> str:
        """The tree digest as the library computes it, in a child with a clean environment."""
        code = (f"import importlib.util as u\n"
                f"s = u.spec_from_file_location('_d', {str(SCRIPTS / 'pre_tag_receipt_lib.py')!r})\n"
                f"m = u.module_from_spec(s)\ns.loader.exec_module(m)\n"
                f"print(m.subject_tree_digest({str(repo)!r}))\n")
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                           timeout=120, env=_clean_env(self.home))
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def receipt(self, repo: pathlib.Path, subject: str, priv, gate: pathlib.Path,
                version: str = "5.0.0") -> pathlib.Path:
        lib = _lib()
        context = {"schema": lib.RECEIPT_SCHEMA, "version": version,
                   "subject_tree_digest": subject,
                   "gate_source_digest": hashlib.sha256(gate.read_bytes()).hexdigest(),
                   "audit_command": "a", "audit_exit_code": 0, "audit_output_digest": "0" * 64,
                   "runner_identity": "t", "produced_at": "2026-09-27T00:00:00Z"}
        signed = dict(context,
                      signature=base64.b64encode(priv.sign(lib.canonical_bytes(context))).decode(),
                      signer_pubkey=_key_line(priv).strip())
        ziel = repo / "audit_artifacts" / version.replace(".", "") / f"pre_tag_receipt_{version}.json"
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text(json.dumps(signed), encoding="utf-8")
        return ziel

    # ── the three tools ──────────────────────────────────────────────────────────────────────
    def emit(self, repo: pathlib.Path, env: dict | None = None, **extra):
        self._n += 1
        self.payload = self.base / f"payload_{self._n}.bin"
        self.context = self.base / f"context_{self._n}.json"
        return subprocess.run(
            [sys.executable, "-B", str(PRODUCER), "--repo", str(repo), "--version", "9.9.9",
             "--audit-command", shlex.join([sys.executable, "-c", "print('audit ran')"]),
             "--audit-output-file", str(self.base / f"record_{self._n}.txt"),
             "--runner-identity", "t", "--produced-at", "2026-09-27T00:00:00Z",
             "--emit-payload", str(self.payload), "--context-out", str(self.context)],
            capture_output=True, encoding="utf-8", errors="replace", timeout=300,
            env=env or _clean_env(self.home, **extra))

    def gate(self, repo: pathlib.Path, script: pathlib.Path, **extra) -> dict:
        r = subprocess.run([sys.executable, "-B", str(script), "--repo", str(repo),
                            "--version", "5.0.0", "--json"],
                           capture_output=True, text=True, timeout=300, cwd=str(repo),
                           env=_clean_env(self.home, **extra))
        try:
            return json.loads(r.stdout)
        except ValueError:
            raise AssertionError(f"the gate gave no verdict: {r.stdout[-600:]}{r.stderr[-600:]}")

    def verify(self, repo: pathlib.Path, script: pathlib.Path, commit: str, version: str,
               **extra) -> tuple[int, dict]:
        r = subprocess.run([sys.executable, "-B", str(script), "--repo", str(repo),
                            "--commit", commit, "--version", version, "--json"],
                           capture_output=True, text=True, timeout=300, cwd=str(repo),
                           env=_clean_env(self.home, **extra))
        try:
            return r.returncode, json.loads(r.stdout)
        except ValueError:
            raise AssertionError(f"the verifier gave no verdict: {r.stdout[-600:]}{r.stderr[-600:]}")

    def refused(self, r, *expected: str) -> str:
        message = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, f"a payload was produced:\n{message[-900:]}")
        self.assertFalse(self.payload.exists(), "a payload was written despite the refusal")
        for e in expected:
            self.assertIn(e, message, f"the refusal does not say {e!r}: {message[-900:]}")
        self.assertNotIn("Traceback", message, f"a refusal is a decision, not a crash: {message[-900:]}")
        return message

    def emitted(self, r) -> None:
        self.assertEqual(r.returncode, 0, f"a clean tree was refused:\n{(r.stdout + r.stderr)[-900:]}")
        self.assertTrue(self.payload.exists())


# ── the third-party verifier's own git calls ────────────────────────────────────────────────────


class TheVerifierMeasuresTheCheckoutItNames(_Case):

    def test_RED_GIT_WORK_TREE_on_a_clean_clone_does_not_hide_a_modified_library(self):
        """Codex on `4e67ba25`, re-measured: an invalid 6.1.0 receipt committed, `verify_receipt`
        replaced by a local edit that always returns true, and `GIT_WORK_TREE` pointing at a clean
        clone of the same commit. The verifier's cleanliness check read the clone, came back
        empty, and the commit was `VERIFIED`, exit 0."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        g = self.candidate(self.base / "g", _key_line(key))
        (g / "audit_artifacts" / "610").mkdir()
        (g / "audit_artifacts" / "610" / "pre_tag_receipt_6.1.0.json").write_text(
            json.dumps({"schema": "b7n0de.pre_tag_audit_receipt.v1", "version": "6.1.0",
                        "signature": "not a signature"}), encoding="utf-8")
        self.git(g, "init", "-q")
        self.git(g, "add", "-A")
        self.git(g, "commit", "-qm", "an invalid receipt")
        commit = self.git(g, "rev-parse", "HEAD").strip()
        clean = self.base / "clean"
        self.git(self.base, "clone", "-q", str(g), str(clean))
        lib_file = g / "scripts" / "pre_tag_receipt_lib.py"
        lib_file.write_text(lib_file.read_text(encoding="utf-8")
                            + "\n\ndef verify_receipt(receipt, **kw):\n"
                              "    return True, 'FORGED by a local edit'\n", encoding="utf-8")
        verifier = g / "scripts" / "verify_pre_tag_receipt.py"
        # anti-vacuity: the variable does redirect a plain status, and without it the edit is seen
        self.assertEqual(self.git(g, "status", "--porcelain",
                                  env=_clean_env(self.home, GIT_WORK_TREE=str(clean))), "")
        rc0, res0 = self.verify(g, verifier, commit, "6.1.0")
        self.assertEqual((rc0, res0["verdict"]), (2, "NOT_MEASURABLE"), res0)

        rc, res = self.verify(g, verifier, commit, "6.1.0", GIT_WORK_TREE=str(clean))
        self.assertNotEqual(res["verdict"], "VERIFIED",
                            f"GIT_WORK_TREE made the verifier judge a checkout it did not name: {res}")
        self.assertEqual(rc, 2, res)
        self.assertIn("local modification", res["reason"] or "", res)


    def test_GUARD_a_library_that_lies_about_status_cannot_hide_itself(self):
        """Green on `4e67ba25`, where the verifier ran its cleanliness check with its own code. Red
        against a repair that routes that check through the library's funnel: the check exists to
        refuse a modified `scripts/pre_tag_receipt_lib.py`, and a modified library whose funnel
        returns an empty `status` (and whose `verify_receipt` returns true) then hid itself and the
        commit with an invalid receipt was `VERIFIED`. The check must run on the verifier's own
        file only."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        g = self.candidate(self.base / "g", _key_line(key))
        (g / "audit_artifacts" / "610").mkdir()
        (g / "audit_artifacts" / "610" / "pre_tag_receipt_6.1.0.json").write_text(
            json.dumps({"schema": "b7n0de.pre_tag_audit_receipt.v1", "version": "6.1.0",
                        "signature": "not a signature"}), encoding="utf-8")
        self.git(g, "init", "-q")
        self.git(g, "add", "-A")
        self.git(g, "commit", "-qm", "an invalid receipt")
        commit = self.git(g, "rev-parse", "HEAD").strip()
        lib_file = g / "scripts" / "pre_tag_receipt_lib.py"
        lib_file.write_text(lib_file.read_text(encoding="utf-8") + (
            "\n\nif 'git_run' in globals():\n"
            "    _the_real_git_run = git_run\n\n"
            "    def git_run(repo, *args, **kw):\n"
            "        answer = _the_real_git_run(repo, *args, **kw)\n"
            "        if args and args[0] == 'status':\n"
            "            answer.stdout = b''\n"
            "        return answer\n\n\n"
            "def verify_receipt(receipt, **kw):\n"
            "    return True, 'FORGED by a local edit'\n"), encoding="utf-8")
        self.assertIn(" M scripts/pre_tag_receipt_lib.py", self.status(g),
                      "precondition: git itself sees the edited library")
        rc, res = self.verify(g, g / "scripts" / "verify_pre_tag_receipt.py", commit, "6.1.0")
        self.assertNotEqual(res["verdict"], "VERIFIED",
                            f"the edited library answered the check that exists to catch it: {res}")
        self.assertEqual(rc, 2, res)
        self.assertIn("local modification", res["reason"] or "", res)


# ── a configured excludes file ─────────────────────────────────────────────────────────────────


class AConfiguredExcludesFileHidesNothing(_Case):
    """`check-ignore -v` names an excludes file by the string the configuration gives, and that
    string can be the name of a TRACKED file. The producer took the rule for the tree's own."""

    def _tree(self) -> pathlib.Path:
        r = self.repo("excludes", {
            "a.txt": "a\n", "scripts/pre_tag_audit_gate.py": "# gate\n",
            ".gitignore": "__pycache__/\n",
            "logs/.gitignore": "*\n!.gitignore\n",
            "sub/.gitignore": "sub/evil.py\n"})
        (r / "evil.py").write_text("PLANTED = True\n", encoding="utf-8")
        return r

    def _hidden(self, r, **env) -> None:
        self.assertNotIn("?? evil.py", self.status(r, **env),
                         "precondition: the setting does not hide the file from git here")

    def test_RED_in_the_repository_configuration(self):
        r = self._tree()
        self.git(r, "config", "core.excludesFile", "logs/.gitignore")
        self._hidden(r)
        self.refused(self.emit(r), "uncommitted path", "evil.py")

    def test_RED_in_the_user_configuration(self):
        r = self._tree()
        (self.home / ".gitconfig").write_text("[core]\n\texcludesFile = logs/.gitignore\n",
                                              encoding="utf-8")
        self._hidden(r)
        self.refused(self.emit(r), "uncommitted path", "evil.py")

    def test_RED_in_the_xdg_configuration(self):
        r = self._tree()
        (self.home / ".xdg" / "git").mkdir()
        (self.home / ".xdg" / "git" / "config").write_text(
            "[core]\n\texcludesFile = logs/.gitignore\n", encoding="utf-8")
        self._hidden(r)
        self.refused(self.emit(r), "uncommitted path", "evil.py")

    def test_RED_through_an_includeIf(self):
        r = self._tree()
        inc = self.home / "included.conf"
        inc.write_text("[core]\n\texcludesFile = logs/.gitignore\n", encoding="utf-8")
        (self.home / ".gitconfig").write_text(
            f'[includeIf "gitdir:{r}/.git"]\n\tpath = {inc}\n', encoding="utf-8")
        self._hidden(r)
        self.refused(self.emit(r), "uncommitted path", "evil.py")

    def test_RED_a_tracked_gitignore_above_the_path_named_as_the_excludes_file(self):
        """[RED] and the case that only the configuration pin catches. `sub/.gitignore` is tracked
        and sits above `sub/evil.py`, so the source passes the rule that a hiding file must be a
        tracked `.gitignore` in a directory that contains the path. Read as a per-directory file,
        its line `sub/evil.py` means `sub/sub/evil.py`; read as the configured excludes file, it
        means `sub/evil.py`. Only the second reading hides the planted file."""
        r = self._tree()
        (r / "evil.py").unlink()
        (r / "sub" / "evil.py").write_text("PLANTED = True\n", encoding="utf-8")
        self.assertIn("?? sub/evil.py", self.status(r), "precondition: the tree's own rule hides nothing")
        self.git(r, "config", "core.excludesFile", "sub/.gitignore")
        self.assertNotIn("?? sub/evil.py", self.status(r), "precondition: the setting hides it")
        self.refused(self.emit(r), "uncommitted path", "sub/evil.py")

    def test_CONTROL_a_tracked_rule_still_hides_what_the_tree_ignores(self):
        """The pin must not take the tree's own rules away: `logs/y.txt` is ignored by the tracked
        `logs/.gitignore`, and a tree whose only extra file is that one emits."""
        r = self._tree()
        (r / "evil.py").unlink()
        (r / "logs" / "y.txt").write_text("a log\n", encoding="utf-8")
        self.emitted(self.emit(r))

    def test_a_hiding_rule_counts_only_from_a_tracked_gitignore_above_the_path(self):
        """The second layer, measured on its own: which source names the tree's own word about a
        path. In a child, because importing the producer changes the importing process."""
        code = (f"import importlib.util as u, json\n"
                f"s = u.spec_from_file_location('_p', {str(PRODUCER)!r})\n"
                f"m = u.module_from_spec(s)\ns.loader.exec_module(m)\n"
                "t = {'.gitignore', 'logs/.gitignore', 'sub/.gitignore', 'notes.txt'}\n"
                "f = m._eine_verfolgte_regel_fuer\n"
                "print(json.dumps([f('.gitignore', 'evil.py', t), f('logs/.gitignore', 'logs/a', t),"
                " f('logs/.gitignore', 'evil.py', t), f('logs/.gitignore', 'logsx/a', t),"
                " f('notes.txt', 'evil.py', t), f('other/.gitignore', 'other/a', t),"
                " f('/abs/.git/info/exclude', 'evil.py', t)]))\n")
        r = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                           timeout=120, env=_clean_env(self.home))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1]),
                         [True, True, False, False, False, False, False])


# ── the replacement switch in the configuration ────────────────────────────────────────────────


class TheReplacementSwitchIsPinnedOff(_Case):

    def test_RED_the_gate_does_not_verify_a_tampered_checkout_through_the_replaced_commit(self):
        """Measured on `4e67ba25`: genuine commit G with a receipt over its digest; T is G with
        `AUDITED = False`, and the checkout is at T. `git replace T G` alone was refused;
        `core.useReplaceRefs=true` in `.git/config` on top made the gate answer `ok=true,
        state=verified` with G's digest, because git reads the configuration after the
        environment switch."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        g = self.candidate(self.base / "g", _key_line(key))
        self.git(g, "init", "-q")
        self.git(g, "add", "-A")
        self.git(g, "commit", "-qm", "genuine")
        gate = g / "scripts" / "pre_tag_audit_gate.py"
        self.receipt(g, self.digest(g), key, gate)
        self.git(g, "add", "-A")
        self.git(g, "commit", "-qm", "receipt")
        genuine = self.git(g, "rev-parse", "HEAD").strip()
        self.assertTrue(self.gate(g, gate)["ok"], "precondition: the receipt verifies on G")
        (g / "src" / "proofbundle" / "payload.py").write_text("AUDITED = False\n", encoding="utf-8")
        self.git(g, "commit", "-qam", "never audited")
        tampered = self.git(g, "rev-parse", "HEAD").strip()
        self.assertFalse(self.gate(g, gate)["ok"], "precondition: T is refused")
        self.git(g, "replace", tampered, genuine)
        self.git(g, "config", "core.useReplaceRefs", "true")
        self.assertIn("AUDITED = True",
                      self.git(g, "show", "HEAD:src/proofbundle/payload.py",
                               env=_clean_env(self.home, GIT_NO_REPLACE_OBJECTS="1")),
                      "precondition: the configuration switches replacement back on")
        verdict = self.gate(g, gate)
        self.assertFalse(verdict["ok"], f"the gate verified the replacement: {verdict}")

    def test_RED_the_producer_binds_the_raw_head_not_the_replacement(self):
        """Measured on `4e67ba25`: base with `a.txt=eins`, second with `a.txt=zwei`, `git replace
        base second`, the checkout read through the replacement, and `core.useReplaceRefs=true`:
        the emit returned 0 and bound the replacement's digest while HEAD names base."""
        r = self.repo("replaced", {"a.txt": "eins\n", "scripts/pre_tag_audit_gate.py": "# gate\n"})
        base = self.git(r, "rev-parse", "HEAD").strip()
        (r / "a.txt").write_text("zwei\n", encoding="utf-8")
        self.git(r, "commit", "-qam", "second")
        second = self.git(r, "rev-parse", "HEAD").strip()
        self.git(r, "reset", "-q", "--hard", base)
        self.git(r, "replace", base, second)
        self.git(r, "reset", "-q", "--hard", base)
        self.git(r, "config", "core.useReplaceRefs", "true")
        self.assertEqual((r / "a.txt").read_text(encoding="utf-8"), "zwei\n")
        self.assertEqual(self.status(r, GIT_NO_REPLACE_OBJECTS="1"), "",
                         "precondition: git itself calls this tree clean, even with the switch set")
        self.refused(self.emit(r), "uncommitted path", "M a.txt")


# ── git answers for the top level it is given ─────────────────────────────────────────────────


class GitAnswersForTheTopLevelItIsGiven(_Case):

    def test_RED_core_worktree_does_not_move_the_ignore_rules(self):
        """Measured on `4e67ba25`: `core.worktree` points at a directory whose `.gitignore` is `*`,
        and `--repo` holds an untracked `evil.py`. `check-ignore` changed into the configured work
        tree, reported `.gitignore` as the source, which is a tracked name in `--repo`, and the
        emit returned 0."""
        r = self.repo("worktree", {"a.txt": "a\n", ".gitignore": "__pycache__/\n",
                                   "scripts/pre_tag_audit_gate.py": "# gate\n"})
        other = self.base / "other"
        other.mkdir()
        (other / ".gitignore").write_text("*\n", encoding="utf-8")
        (r / "evil.py").write_text("PLANTED = True\n", encoding="utf-8")
        self.git(r, "config", "core.worktree", str(other))
        self.refused(self.emit(r), "uncommitted path", "?? evil.py")

    def _nested(self, root_anchor: str, inner_anchor: str, signer):
        """`--repo W/inner`, where `inner/.git` is a gitfile to a git directory whose
        `core.worktree` is `W`. HEAD's tree is `inner/` (a copy of the genuine tree G, its receipt
        included) plus a tampered `src/proofbundle/payload.py` at the root, and the root-relative
        copies of the anchor, the gate and the receipt that `git show HEAD:<path>` finds."""
        g = self.candidate(self.base / "g", inner_anchor)
        self.git(g, "init", "-q")
        self.git(g, "add", "-A")
        self.git(g, "commit", "-qm", "genuine")
        receipt = self.receipt(g, self.digest(g), signer, g / "scripts" / "pre_tag_audit_gate.py")
        w = self.base / "w"
        shutil.copytree(g, w / "inner", ignore=shutil.ignore_patterns(".git"))
        (w / "src" / "proofbundle").mkdir(parents=True)
        (w / "src" / "proofbundle" / "payload.py").write_text("AUDITED = False\n", encoding="utf-8")
        (w / "audit_artifacts" / "500").mkdir(parents=True)
        (w / _KEY_ANCHOR).write_text(root_anchor, encoding="utf-8")
        shutil.copy(receipt, w / "audit_artifacts" / "500" / receipt.name)
        (w / "scripts").mkdir()
        shutil.copy(g / "scripts" / "pre_tag_audit_gate.py", w / "scripts" / "pre_tag_audit_gate.py")
        gitdir = self.base / "w.git"
        self.git(self.base, f"--git-dir={gitdir}", f"--work-tree={w}", "init", "-q")
        self.git(self.base, f"--git-dir={gitdir}", "config", "core.worktree", str(w))
        self.git(self.base, f"--git-dir={gitdir}", f"--work-tree={w}", "add", "-A")
        self.git(self.base, f"--git-dir={gitdir}", f"--work-tree={w}", "commit", "-qm", "nested")
        (w / "inner" / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
        inner = w / "inner"
        self.assertEqual(self.git(inner, "rev-parse", "--show-prefix").strip(), "inner/",
                         "precondition: git answers for W with the prefix inner/")
        return inner, self.git(inner, "rev-parse", "HEAD").strip()

    def test_RED_the_gate_digests_the_whole_tree_not_the_subdirectory(self):
        """Measured on `4e67ba25`: `ok=true, state=verified` with G's digest for a HEAD whose root
        carries a tampered payload. `ls-tree -r HEAD` listed the subdirectory; `--full-tree` and the
        top-level check of the funnel make the digest the whole tree's."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        inner, _commit = self._nested(_key_line(key), _key_line(key), key)
        verdict = self.gate(inner, inner / "scripts" / "pre_tag_audit_gate.py")
        self.assertFalse(verdict["ok"], f"a subdirectory view of a tampered tree verified: {verdict}")

    def test_RED_the_verifier_does_not_verify_a_subdirectory_view(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        inner, commit = self._nested(_key_line(key), _key_line(key), key)
        rc, res = self.verify(inner, inner / "scripts" / "verify_pre_tag_receipt.py", commit, "5.0.0")
        self.assertNotEqual(res["verdict"], "VERIFIED", res)
        self.assertNotEqual(rc, 0, res)

    def test_RED_the_anchor_and_the_digest_come_from_one_tree(self):
        """Measured on `4e67ba25`: the root anchor holds an attacker key, `inner/` the genuine one,
        and the receipt is self-signed by the attacker over the digest of `inner/`. The anchor was
        read root-relative and the digest prefix-relative, and the gate said `ok=true`."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        genuine, attacker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        inner, _commit = self._nested(_key_line(attacker), _key_line(genuine), attacker)
        verdict = self.gate(inner, inner / "scripts" / "pre_tag_audit_gate.py")
        self.assertFalse(verdict["ok"], f"an attacker key from the root verified: {verdict}")

    def test_a_subdirectory_as_repo_is_refused_before_anything_is_listed(self):
        """`--repo` naming a subdirectory of a repository. `4e67ba25` refused this too, but by
        accident: `ls-tree` listed paths relative to the subdirectory and `hash-object` could not
        open them (`could not open 'b.txt'`). The refusal now names the reason and comes before
        anything is listed, so it no longer depends on which command happens to fail first."""
        r = self.repo("outer", {"a.txt": "a\n", "sub/b.txt": "b\n",
                                "sub/scripts/pre_tag_audit_gate.py": "# gate\n",
                                "scripts/pre_tag_audit_gate.py": "# gate\n"})
        self.refused(self.emit(r / "sub"), "as a repository")


# ── untracked names are not pathspecs ─────────────────────────────────────────────────────────


class AnUntrackedNameIsNotAPathspec(_Case):

    def test_RED_a_name_that_looks_like_magic_is_still_untracked(self):
        """Measured on `4e67ba25`: `:build/conftest.py` was read by `check-ignore` as the magic
        `:` over `build/conftest.py`, matched the tracked rule `build/`, and the emit returned 0.
        git status says `?? :build/conftest.py`."""
        r = self.repo("magic", {"a.txt": "a\n", ".gitignore": "build/\n",
                                "scripts/pre_tag_audit_gate.py": "# gate\n"})
        (r / ":build").mkdir()
        (r / ":build" / "conftest.py").write_text("PLANTED = True\n", encoding="utf-8")
        self.assertIn("?? :build/conftest.py", self.status(r))
        self.refused(self.emit(r), "uncommitted path", "?? :build/conftest.py")

    def test_RED_an_ignored_name_that_looks_like_magic_is_still_ignored(self):
        """Measured on `4e67ba25`: an ignored `:!x.log` made git die with `pathspec magic not
        supported by this command: 'exclude'`, and a clean tree refused."""
        r = self.repo("magic2", {"a.txt": "a\n", ".gitignore": "*.log\n",
                                 "scripts/pre_tag_audit_gate.py": "# gate\n"})
        (r / ":!x.log").write_text("a log\n", encoding="utf-8")
        self.assertEqual(self.status(r), "!! :!x.log\n")
        self.emitted(self.emit(r))


# ── the executable bit is the owner's ─────────────────────────────────────────────────────────


class TheExecutableBitIsTheOwners(_Case):

    def test_RED_a_lost_owner_bit_is_a_mode_change(self):
        """Measured on `4e67ba25`: `run.sh` committed 100755, 0655 on disk. git status ` M run.sh`,
        and the emit returned 0 because `0o655 & 0o111` is not zero."""
        r = self.repo("exec", {"run.sh": "#!/bin/sh\necho ok\n",
                               "scripts/pre_tag_audit_gate.py": "# gate\n"}, modes={"run.sh": 0o755})
        os.chmod(r / "run.sh", 0o655)
        self.assertEqual(self.status(r), " M run.sh\n")
        self.refused(self.emit(r), "uncommitted path", "mode run.sh (100755 -> 100644)")

    def test_RED_a_group_or_other_bit_is_not_a_mode_change(self):
        """Measured on `4e67ba25`: a file committed 100644 with 0645 on disk; git status is empty
        and the emit refused `mode plain.txt (100644 -> 100755)`."""
        r = self.repo("plain", {"plain.txt": "x\n", "scripts/pre_tag_audit_gate.py": "# gate\n"},
                      modes={"plain.txt": 0o644})
        os.chmod(r / "plain.txt", 0o645)
        self.assertEqual(self.status(r), "")
        self.emitted(self.emit(r))


# ── no path is read through a linked directory ────────────────────────────────────────────────


class NoPathIsReadThroughALinkedDirectory(_Case):

    def test_RED_a_tracked_directory_replaced_by_a_link_refuses(self):
        """Measured on `4e67ba25`: `vendor/lib.py` force-added under the tracked rule `vendor`, then
        `vendor` replaced by a link to an identical copy outside the tree. git status: ` D
        vendor/lib.py` and `!! vendor`; the emit returned 0 and the audit read the outside file."""
        r = self.repo("linked", {"a.txt": "a\n", ".gitignore": "vendor\n",
                                 "scripts/pre_tag_audit_gate.py": "# gate\n",
                                 "vendor/lib.py": "LIB = 1\n"}, force=("vendor/lib.py",))
        outside = self.base / "outside_vendor"
        shutil.copytree(r / "vendor", outside)
        shutil.rmtree(r / "vendor")
        os.symlink(outside, r / "vendor")
        self.assertIn(" D vendor/lib.py", self.status(r))
        self.refused(self.emit(r), "uncommitted path", "vendor/lib.py", "symbolic link")


# ── environment names the list did not carry ──────────────────────────────────────────────────


class NoEnvironmentNameReachesGit(_Case):

    def _clean_tree(self) -> pathlib.Path:
        return self.repo("clean", {"a.txt": "a\n", ".gitignore": "*.log\n",
                                   "scripts/pre_tag_audit_gate.py": "# gate\n"})

    def test_RED_pathspec_switches_do_not_refuse_a_clean_tree(self):
        """Measured on `4e67ba25`, new there: `ls-tree -z HEAD -- scripts/pre_tag_audit_gate.py`
        died with `pathspec magic not supported by this command: 'icase'` (or `'glob'`), exit 1 on
        a clean tree; main emitted."""
        r = self._clean_tree()
        for name in ("GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS"):
            with self.subTest(name=name):
                self.emitted(self.emit(r, **{name: "1"}))

    def test_RED_literal_pathspecs_do_not_refuse_an_ignored_file(self):
        """`check-ignore` rejects every path under `GIT_LITERAL_PATHSPECS=1` (measured: `pathspec
        magic not supported by this command: 'literal'`), so on `4e67ba25` a clean tree with one
        ignored file refused. The lens saw the name as harmless on a tree with nothing ignored."""
        r = self._clean_tree()
        (r / "x.log").write_text("a log\n", encoding="utf-8")
        self.emitted(self.emit(r, GIT_LITERAL_PATHSPECS="1"))

    def test_RED_trace_output_does_not_enter_the_digest(self):
        """Measured on `4e67ba25`: with `GIT_TRACE`, `GIT_TRACE_SETUP` or `GIT_TRACE2_EVENT` on
        `/dev/stdout`, the timestamped trace lines went into the listing the digest hashes, and
        the digest changed on every run."""
        r = self._clean_tree()
        baseline = self.digest(r)
        code = (f"import importlib.util as u\n"
                f"s = u.spec_from_file_location('_d', {str(SCRIPTS / 'pre_tag_receipt_lib.py')!r})\n"
                f"m = u.module_from_spec(s)\ns.loader.exec_module(m)\n"
                f"print(m.subject_tree_digest({str(r)!r}))\n")
        for name in ("GIT_TRACE", "GIT_TRACE_SETUP", "GIT_TRACE2_EVENT"):
            with self.subTest(name=name):
                p = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True,
                                   text=True, timeout=120,
                                   env=_clean_env(self.home, **{name: "/dev/stdout"}))
                self.assertEqual(p.stdout.strip().splitlines()[-1:], [baseline], p.stderr[-400:])


# ── the audit program's environment ──────────────────────────────────────────────────────────


class TheAuditProgramGetsNoGitName(_Case):

    def test_RED_a_name_set_after_the_import_does_not_reach_the_audit(self):
        """On `4e67ba25` the audit program inherited the process environment as it stood at the run.
        The import cleans the process once; a caller that imports the producer and sets `GIT_DIR`
        afterwards handed it to the program whose run the receipt records. The environment of the
        audit is now built at the run, without git's namespace."""
        r = self.repo("audit", {"a.txt": "a\n", "scripts/pre_tag_audit_gate.py": "# gate\n"})
        record = self.base / "audit_record.txt"
        show = shlex.join([sys.executable, "-c",
                           "import os; print(sorted(k for k in os.environ if k.startswith('GIT_')))"])
        code = (f"import importlib.util as u, os, pathlib\n"
                f"s = u.spec_from_file_location('_p', {str(PRODUCER)!r})\n"
                f"m = u.module_from_spec(s)\ns.loader.exec_module(m)\n"
                f"os.environ['GIT_DIR'] = '/elsewhere/.git'\n"
                f"os.environ['GIT_WORK_TREE'] = '/elsewhere'\n"
                f"print(m._audit_ausfuehren(pathlib.Path({str(r)!r}), {show!r}, "
                f"pathlib.Path({str(record)!r}))[0])\n")
        p = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                           timeout=120, env=_clean_env(self.home))
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertEqual(record.read_text(encoding="utf-8").strip(), "['GIT_NO_REPLACE_OBJECTS']")


# ── the ignore answer is decoded as the filesystem names it ───────────────────────────────────


class TheIgnoreAnswerIsReadAsTheFilesystemNamesIt(_Case):

    def test_an_ignored_name_that_is_not_utf8_emits(self):
        """Green on `4e67ba25`, where the `os.fsdecode` of the `check-ignore` reader was added and no
        case measured it: reverting that one line to UTF-8 with replacement left all ten pre-tag
        files green. With it reverted, `caf\\xe9.log` comes back as `caf\\ufffd.log`, no name on disk
        matches, and a clean tree refuses."""
        r = self._tree()
        try:
            (r / os.fsdecode(b"caf\xe9.log")).write_text("a log\n", encoding="utf-8")
        except (OSError, UnicodeError) as e:
            self.skipTest(f"this filesystem does not take a name that is not UTF-8: {e}")
        self.emitted(self.emit(r))

    def _tree(self) -> pathlib.Path:
        return self.repo("latin1", {"a.txt": "a\n", ".gitignore": "*.log\n",
                                    "scripts/pre_tag_audit_gate.py": "# gate\n"})


if __name__ == "__main__":
    unittest.main()
