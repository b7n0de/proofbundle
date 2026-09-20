"""The pre-tag receipt binds the committed head, so it may not be produced from a dirty tree.

`subject_tree_digest()` digests `git ls-tree -r HEAD`. The audit whose output the receipt carries
runs over the WORKING TREE. Those are the same bytes only while nothing is uncommitted, and until
this gate existed nothing checked: a measurement on the operating tree found two modified paths
while a receipt was produced, so the receipt attested a tree that had not been the one examined.

The cases below run the real script through `--emit-payload`, not the helper alone, because the
question is whether the REFUSAL IS ON THE PATH the release chain takes. A gate that exists and is
never called is the defect it was written against.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "pre_tag_receipt.py"


def _git(cwd, *args) -> str:
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


class EmitVerweigertEinenSchmutzigenBaum(unittest.TestCase):

    def setUp(self):
        if not SKRIPT.is_file():
            self.skipTest("scripts/pre_tag_receipt.py is not in this tree — a distributed "
                          "artefact prunes scripts/, and a tool that is not here cannot be judged")
        d = tempfile.mkdtemp(prefix="pre-tag-dirty-")
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        self.baum = pathlib.Path(d) / "repo"
        self.baum.mkdir()
        _git(self.baum, "init", "-q")
        _git(self.baum, "config", "user.email", "t@example.invalid")
        _git(self.baum, "config", "user.name", "t")
        (self.baum / "a.txt").write_text("eins\n", encoding="utf-8")
        # `_gate_source_digest` hashes this path OUT OF THE --repo TREE, so the fixture has to
        # carry it or a CLEAN tree fails for a reason that has nothing to do with the gate under
        # test. The control case found that, which is what a control is for.
        (self.baum / "scripts").mkdir()
        (self.baum / "scripts" / "pre_tag_audit_gate.py").write_text(
            "# stub: only its bytes are hashed by _gate_source_digest\n", encoding="utf-8")
        _git(self.baum, "add", "a.txt", "scripts/pre_tag_audit_gate.py")
        _git(self.baum, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
        self.ausgabe = pathlib.Path(d) / "audit.txt"
        self.ausgabe.write_text("audit output\n", encoding="utf-8")

    def _emit(self) -> subprocess.CompletedProcess:
        ziel = self.baum.parent / "payload.bin"
        kontext = self.baum.parent / "context.json"
        return subprocess.run(
            [sys.executable, str(SKRIPT), "--repo", str(self.baum),
             "--emit-payload", str(ziel), "--context-out", str(kontext),
             "--version", "6.1.0", "--audit-command", "true", "--audit-exit", "0",
             "--audit-output-file", str(self.ausgabe),
             "--runner-identity", "test", "--produced-at", "2026-09-20T00:00:00Z"],
            capture_output=True, text=True, cwd=str(REPO),
            env=dict(os.environ, PYTHONPATH=str(REPO / "scripts")))

    def test_ein_schmutziger_baum_wird_abgewiesen(self):
        """The case this file exists for: one uncommitted path and the emit refuses by name."""
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        self.assertNotEqual(_git(self.baum, "status", "--porcelain"), "",
                            "the fixture is not dirty, so this case is not testing what it says")
        r = self._emit()
        self.assertNotEqual(r.returncode, 0, f"a dirty tree produced a payload:\n{r.stdout}")
        meldung = r.stdout + r.stderr
        self.assertIn("uncommitted path", meldung, meldung[-800:])
        self.assertIn("a.txt", meldung, "the refusal does not name what is uncommitted")

    def test_KONTROLLE_ein_sauberer_baum_kommt_durch(self):
        """Without this the first case would also pass for a gate that refuses ALWAYS."""
        self.assertEqual(_git(self.baum, "status", "--porcelain"), "")
        r = self._emit()
        self.assertEqual(r.returncode, 0, f"a clean tree was refused:\n{r.stdout}\n{r.stderr}")
        self.assertIn("emitted payload", r.stdout, r.stdout)

    def test_auch_eine_unverfolgte_datei_zaehlt(self):
        """`--porcelain` reports untracked files too, and they change what the audit read."""
        (self.baum / "neu.txt").write_text("hinzu\n", encoding="utf-8")
        r = self._emit()
        self.assertNotEqual(r.returncode, 0, "an untracked file did not stop the emit")
        self.assertIn("neu.txt", r.stdout + r.stderr)

    def test_der_zweite_aufrufer_ist_ebenso_gebunden(self):
        """The gate sits in build_context, so `build_and_sign` cannot reach the digest around it.

        The first version of this fix guarded the emit branch of main(). A counter-reading named
        the other caller: `build_and_sign` calls `build_context` too, so the inline signing path
        reached `subject_tree_digest` ungated. `_inline_erlaubt_oder_stop` stands in front of that
        path, but it answers whether inline signing is PERMITTED, not whether the tree is the one
        that was measured — a different question with a different failure.

        Rather than drive the inline CLI, which is fail-closed by Owner decision and would refuse
        for that reason instead, this imports the module and calls `build_context` directly: the
        one function both paths go through.
        """
        import importlib.util
        spec = importlib.util.spec_from_file_location("_ptr", SKRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_ptr"] = mod
        sys.path.insert(0, str(REPO / "scripts"))
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.path.pop(0)

        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        self.assertNotEqual(_git(self.baum, "status", "--porcelain"), "", "fixture is not dirty")
        with self.assertRaises(SystemExit) as gefangen:
            mod.build_context(self.baum, "6.1.0", "true", 0, "audit", "test",
                              "2026-09-20T00:00:00Z")
        self.assertIn("uncommitted path", str(gefangen.exception), str(gefangen.exception))

    def test_nicht_bestimmbar_ist_keine_freigabe(self):
        """A directory that is no repository at all must refuse, not fall through to a digest."""
        kein_repo = self.baum.parent / "kein_repo"
        kein_repo.mkdir()
        ziel = self.baum.parent / "p2.bin"
        kontext = self.baum.parent / "c2.json"
        r = subprocess.run(
            [sys.executable, str(SKRIPT), "--repo", str(kein_repo),
             "--emit-payload", str(ziel), "--context-out", str(kontext),
             "--version", "6.1.0", "--audit-command", "true", "--audit-exit", "0",
             "--audit-output-file", str(self.ausgabe),
             "--runner-identity", "test", "--produced-at", "2026-09-20T00:00:00Z"],
            capture_output=True, text=True, cwd=str(REPO),
            env=dict(os.environ, PYTHONPATH=str(REPO / "scripts")))
        self.assertNotEqual(r.returncode, 0, "a non-repository produced a payload")
        self.assertFalse(ziel.exists(), "a payload was written despite the refusal")


if __name__ == "__main__":
    unittest.main()
