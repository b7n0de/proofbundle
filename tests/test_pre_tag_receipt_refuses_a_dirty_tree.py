"""The pre-tag receipt binds the committed head, so it may not be produced from a dirty tree, and
the audit whose output it records runs between two measurements of that tree.

`subject_tree_digest()` digests `git ls-tree -r HEAD`. The audit whose output the receipt carries
runs over the WORKING TREE. Those are the same bytes only while nothing is uncommitted, and until
this gate existed nothing checked: a measurement on the operating tree found two modified paths
while a receipt was produced, so the receipt attested a tree that had not been the one examined.

TWO MORE CLASSES, measured 2026-09-21 by a counter-reading from another model family and swept
for their siblings. First, the check ran AFTER the audit: the tool received the audit's output as
a file and could not say what the tree looked like while that output was produced (modify, run,
restore, emit went through). Now the tool starts the audit itself, measures before and after, and
records what it captured. Second, the check took `git status`'s word, and that word depends on
configuration outside the tree: `status.showUntrackedFiles=no`, a global `core.excludesFile`,
`.git/info/exclude`, an untracked `.gitignore` covering itself, `GIT_DIR` in the environment.
Each of them hid a path from the first version; each has a case below. The second counter-reading,
the same day, named the index flags `assume-unchanged` and `skip-worktree`, which hide a modified
tracked file from `git status` altogether; the comparison now runs through a fresh index read from
HEAD, and those two have their cases as well. The third round, own sweep plus a second
counter-reading the same day, measured that git still answered through its configuration on that
fresh index: a clean filter defined in the configuration, `core.worktree` and `core.fileMode`. The
comparison is now computed from the bytes on disk against `git ls-tree -r HEAD`, and those three
have their cases below, each red against `97af10d`. The fourth round (Codex) measured
`core.ignoreCase=true` hiding an untracked file from `git ls-files --others`; the untracked paths
now come from the filesystem, and that case is red against `f4203e5`.

The cases run the real script through `--emit-payload`, not the helper alone, because the
question is whether the REFUSAL IS ON THE PATH the release chain takes. A gate that exists and is
never called is the defect it was written against.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "pre_tag_receipt.py"


#: Variables that let the ENVIRONMENT supply what the PRODUCTION CODE is supposed to supply.
#: MEASURED 2026-09-20 by a counter-reading from another model family: with
#: `_bytecode_cache_elsewhere()` removed but `PYTHONDONTWRITEBYTECODE=1` exported, the bytecode
#: case PASSED — the very false green it was rewritten to close, one layer out. The two GIT_ names
#: are the same class rather than the same symptom: they redirect `git status --porcelain` away
#: from `--repo`, so the cleanliness gate would be answered about a tree nobody chose. A case must
#: measure the code, so the child starts without them.
_UMGEBUNG_DARF_DAS_NICHT_BEANTWORTEN = (
    "PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX",
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
)


def _kindumgebung(**zusatz) -> dict:
    """The parent environment minus everything that could stand in for what is under test."""
    e = dict(os.environ)
    for name in _UMGEBUNG_DARF_DAS_NICHT_BEANTWORTEN:
        e.pop(name, None)
    e.update(zusatz)
    return e


def _git(cwd, *args) -> str:
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr}")
    return r.stdout.strip()


def _python(code: str) -> str:
    """An audit command that runs `code` in this interpreter, as one shell-quoted line."""
    return shlex.join([sys.executable, "-c", code])


#: What the default audit of these cases says, and what its record must therefore contain.
_AUDIT_SAGT = b"audit ran\n"


class EmitVerweigertEinenSchmutzigenBaum(unittest.TestCase):

    def setUp(self):
        if not SKRIPT.is_file():
            self.skipTest("scripts/pre_tag_receipt.py is not in this tree — a distributed "
                          "artefact prunes scripts/, and a tool that is not here cannot be judged")
        d = tempfile.mkdtemp(prefix="pre-tag-dirty-")
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        self.aussen = pathlib.Path(d)
        self.baum = self.aussen / "repo"
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
        self._laufende_nummer = 0

    def _aufzeichnung(self) -> pathlib.Path:
        """A fresh record path OUTSIDE the tree for each emit; the tool refuses an existing one."""
        self._laufende_nummer += 1
        return self.aussen / f"audit_{self._laufende_nummer}.txt"

    def _emit(self, befehl: str | None = None, aufzeichnung: pathlib.Path | None = None,
              skript: pathlib.Path | None = None, cwd: pathlib.Path | None = None,
              umgebung: dict | None = None, extra: list[str] | None = None):
        ziel = self.aussen / "payload.bin"
        kontext = self.aussen / "context.json"
        for alt in (ziel, kontext):
            alt.unlink(missing_ok=True)
        self.payload, self.kontext = ziel, kontext
        return subprocess.run(
            [sys.executable, str(skript or SKRIPT), "--repo", str(self.baum),
             "--emit-payload", str(ziel), "--context-out", str(kontext),
             "--version", "6.1.0",
             "--audit-command", befehl if befehl is not None else _python("print('audit ran')"),
             "--audit-output-file", str(aufzeichnung or self._aufzeichnung()),
             "--runner-identity", "test", "--produced-at", "2026-09-20T00:00:00Z",
             *(extra or [])],
            capture_output=True, text=True, cwd=str(cwd or REPO),
            env=umgebung or _kindumgebung(PYTHONPATH=str(REPO / "scripts")))

    def _abgewiesen(self, r, *erwartet: str):
        meldung = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, f"a payload was produced:\n{meldung[-800:]}")
        self.assertFalse(self.payload.exists(), "a payload was written despite the refusal")
        for e in erwartet:
            self.assertIn(e, meldung, f"the refusal does not say {e!r}: {meldung[-800:]}")
        self.assertNotIn("Traceback", meldung, f"a refusal is a decision, not a crash: {meldung[-800:]}")
        return meldung

    # ── the tree must be clean, and the tool must be the one who says so ─────────────────────────

    def test_ein_schmutziger_baum_wird_abgewiesen(self):
        """The case this file exists for: one uncommitted path and the emit refuses by name."""
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        self.assertNotEqual(_git(self.baum, "status", "--porcelain"), "",
                            "the fixture is not dirty, so this case is not testing what it says")
        self._abgewiesen(self._emit(), "uncommitted path", "a.txt", "before the audit")

    def test_KONTROLLE_ein_sauberer_baum_kommt_durch(self):
        """Without this the refusals would also hold for a gate that refuses ALWAYS. And the
        control says what the payload binds: the digest of the record this run wrote, and the
        exit code the audit returned."""
        self.assertEqual(_git(self.baum, "status", "--porcelain"), "")
        aufzeichnung = self._aufzeichnung()
        r = self._emit(aufzeichnung=aufzeichnung)
        self.assertEqual(r.returncode, 0, f"a clean tree was refused:\n{r.stdout}\n{r.stderr}")
        self.assertIn("emitted payload", r.stdout, r.stdout)
        self.assertEqual(aufzeichnung.read_bytes(), _AUDIT_SAGT, "the record is not what the audit said")
        kontext = json.loads(self.kontext.read_text(encoding="utf-8"))
        self.assertEqual(kontext["audit_exit_code"], 0)
        self.assertEqual(kontext["audit_output_digest"], hashlib.sha256(_AUDIT_SAGT).hexdigest(),
                         "audit_output_digest is not the sha256 of the record's bytes")
        self.assertEqual(kontext["subject_tree_digest"],
                         self._tree_digest(), "the payload does not bind the head that was measured")

    def _tree_digest(self) -> str:
        sys.path.insert(0, str(REPO / "scripts"))
        try:
            from pre_tag_receipt_lib import subject_tree_digest  # noqa: PLC0415
        finally:
            sys.path.pop(0)
        return subject_tree_digest(self.baum)

    def test_auch_eine_unverfolgte_datei_zaehlt(self):
        """An untracked file changes what the audit read, so it counts as dirt."""
        (self.baum / "neu.txt").write_text("hinzu\n", encoding="utf-8")
        self._abgewiesen(self._emit(), "uncommitted path", "neu.txt")

    # ── the answer must not depend on configuration outside the tree ─────────────────────────────

    def test_status_showUntrackedFiles_no_verbirgt_keinen_pfad(self):
        """[ZAEHLT] P1 of the counter-reading, 2026-09-21: `git status --porcelain` honours
        `status.showUntrackedFiles`, so a checkout configured with `no` hid an untracked path from
        the gate and the emit went through. Red against the version that asked `git status`."""
        (self.baum / "neu.txt").write_text("hinzu\n", encoding="utf-8")
        _git(self.baum, "config", "status.showUntrackedFiles", "no")
        # anti-vacuity: the configuration really hides the file from a plain status
        self.assertEqual(_git(self.baum, "status", "--porcelain"), "",
                         "the configuration did not hide the path, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "neu.txt")

    def test_ein_globaler_ausschluss_verbirgt_keinen_pfad(self):
        """[ZAEHLT] Sibling of the same class: `core.excludesFile` is read by `git status` from
        any configuration level, and a pattern there hid the untracked path. Measured 2026-09-21."""
        (self.baum / "neu.txt").write_text("hinzu\n", encoding="utf-8")
        ausschluss = self.aussen / "excludes"
        ausschluss.write_text("neu.txt\n", encoding="utf-8")
        _git(self.baum, "config", "core.excludesFile", str(ausschluss))
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "the excludes file did not hide the path, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "neu.txt")

    def test_info_exclude_verbirgt_keinen_pfad(self):
        """[ZAEHLT] Sibling: `.git/info/exclude` lives outside the committed tree and hid the path
        from `git status --untracked-files=all` as well. Measured 2026-09-21."""
        (self.baum / "neu.txt").write_text("hinzu\n", encoding="utf-8")
        with (self.baum / ".git" / "info" / "exclude").open("a", encoding="utf-8") as fh:
            fh.write("neu.txt\n")
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "")
        self._abgewiesen(self._emit(), "uncommitted path", "neu.txt")

    def test_eine_unverfolgte_ignore_datei_versteckt_sich_nicht_selbst(self):
        """[ZAEHLT] Sibling: an untracked `sub/.gitignore` containing `*` hides itself and
        everything beside it from `git status` and from `ls-files --others --exclude-per-directory`.
        Measured 2026-09-21: nothing listed, `sub/evil.py` invisible. The refusal names the ignore
        file and the source that hid it."""
        (self.baum / "sub").mkdir()
        (self.baum / "sub" / ".gitignore").write_text("*\n", encoding="utf-8")
        (self.baum / "sub" / "evil.py").write_text("x = 1\n", encoding="utf-8")
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "the ignore file did not hide the directory, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "sub/.gitignore", "not a tracked rule")

    def test_assume_unchanged_verbirgt_keine_aenderung(self):
        """[ZAEHLT] P1 of the second counter-reading, 2026-09-21: `git update-index
        --assume-unchanged` tells git not to look at a tracked file, so `git status` and `git diff`
        report nothing for it while its bytes differ from HEAD. The first version asked `git status`
        and emitted. Red against the version that asked `git status`."""
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        _git(self.baum, "update-index", "--assume-unchanged", "a.txt")
        # anti-vacuity: the flag really hides the modification from a plain status
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "the flag did not hide the modification, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "a.txt")

    def test_skip_worktree_verbirgt_keine_aenderung(self):
        """[ZAEHLT] The sibling flag of the same round: `skip-worktree` is index metadata as well,
        and it hides a modified tracked file from every listing that goes through that index."""
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        _git(self.baum, "update-index", "--skip-worktree", "a.txt")
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "the flag did not hide the modification, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "a.txt")

    def test_eine_gestagte_aenderung_zaehlt(self):
        """[GETRENNT] A change that sits in the index but not in HEAD is dirt too: the receipt
        binds HEAD, and the audit would read bytes HEAD does not carry. The version that asked
        `git status` refused this as well, so the case could not be red against it; it pins that
        the fresh-index comparison still sees the index."""
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        _git(self.baum, "add", "a.txt")
        self._abgewiesen(self._emit(), "uncommitted path", "a.txt")

    def test_eine_geloeschte_verfolgte_datei_zaehlt(self):
        """[GETRENNT] A tracked file missing from the checkout is a tree that differs from HEAD.
        Refused by the previous version too, so not red against it; it pins that `git read-tree`
        into a fresh index reports the absence as `D` rather than as nothing."""
        (self.baum / "a.txt").unlink()
        self._abgewiesen(self._emit(), "uncommitted path", "a.txt")

    # ── the third round: git answered through its configuration even on a fresh index ──────────

    def test_ein_clean_filter_aus_der_konfiguration_verbirgt_keine_aenderung(self):
        """[ZAEHLT] Own sweep plus a second counter-reading, 2026-09-21: `git diff-index` converts
        the working file through the clean filter before comparing, and the filter command comes
        from the configuration. `git show HEAD:%f` as the filter makes every modified file look
        like its committed self. Red against `97af10d`, the version that asked `diff-index`."""
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        (self.baum / ".git" / "info" / "attributes").write_text("a.txt filter=hide\n", encoding="utf-8")
        _git(self.baum, "config", "filter.hide.clean", "git show HEAD:%f")
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "the filter did not hide the modification, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "M a.txt")

    def test_core_worktree_zeigt_git_auf_einen_anderen_baum(self):
        """[ZAEHLT] `core.worktree` in the checkout's config makes every git listing answer about
        another directory, while the audit runs in this one. Red against `97af10d`."""
        import shutil  # noqa: PLC0415
        sauber = self.aussen / "sauber"
        shutil.copytree(self.baum, sauber, symlinks=True)
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        _git(self.baum, "config", "core.worktree", str(sauber))
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "git still looked at this directory, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "M a.txt")

    def test_core_fileMode_false_verbirgt_keine_modusaenderung(self):
        """[ZAEHLT] The tree digest covers modes (`ls-tree` prints them), so a mode change is a
        tree the head does not name; `core.fileMode=false` told git not to look. Red against
        `97af10d`."""
        os.chmod(self.baum / "a.txt", 0o755)
        _git(self.baum, "config", "core.fileMode", "false")
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "git still reported the mode change, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "mode a.txt")

    def test_KONTROLLE_der_filter_allein_stoert_einen_sauberen_baum_nicht(self):
        """A configured filter over an unchanged file must not refuse: the comparison is over the
        bytes on disk, and those equal the blob."""
        (self.baum / ".git" / "info" / "attributes").write_text("a.txt filter=hide\n", encoding="utf-8")
        _git(self.baum, "config", "filter.hide.clean", "git show HEAD:%f")
        r = self._emit()
        self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-800:])
        self.assertTrue(self.payload.exists())

    def test_KONTROLLE_eine_ausfuehrbare_datei_und_ein_symlink_gleich_dem_head_stoeren_nicht(self):
        """The mode comparison accepts 100755 where 100755 was committed, and a symbolic link whose
        target equals the committed one; a changed link target refuses by name."""
        lauf = self.baum / "run.sh"
        lauf.write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(lauf, 0o755)
        os.symlink("a.txt", self.baum / "link")
        _git(self.baum, "add", "run.sh", "link")
        _git(self.baum, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "exec and link")
        r = self._emit()
        self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-800:])
        os.unlink(self.baum / "link")
        os.symlink("scripts", self.baum / "link")
        # `_git` strips the output, so the porcelain state column loses its leading blank.
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"),
                         "M link", "precondition: git itself reports the retargeted link")
        self._abgewiesen(self._emit(), "uncommitted path", "M link")

    # ── the fourth round: git's configured path equality hid an untracked file ────────────────

    def test_core_ignoreCase_verbirgt_keine_unverfolgte_datei(self):
        """[ZAEHLT] Codex, round four, 2026-09-21: with `core.ignoreCase=true` an untracked `A.TXT`
        beside the tracked `a.txt` is invisible to `git ls-files --others` on a case-sensitive
        filesystem, while the audit can read it. Red against `f4203e5`, which still asked git for
        the untracked paths; the paths now come from the filesystem."""
        (self.baum / "A.TXT").write_text("planted\n", encoding="utf-8")
        _git(self.baum, "config", "core.ignoreCase", "true")
        self.assertEqual(_git(self.baum, "status", "--porcelain", "--untracked-files=all"), "",
                         "git still listed the file, so this case measures nothing")
        self._abgewiesen(self._emit(), "uncommitted path", "?? A.TXT")

    def test_ein_fremdes_repository_im_baum_wird_benannt(self):
        """[GETRENNT] A nested repository is something the head does not carry; the walk names its
        `.git` rather than descending into it. `f4203e5` refused this too (git lists the
        directory), so the case pins the walk, not the round."""
        _git(self.baum, "init", "-q", "fremd")
        (self.baum / "fremd" / "x.txt").write_text("x\n", encoding="utf-8")
        self._abgewiesen(self._emit(), "uncommitted path", "fremd/.git")

    def test_KONTROLLE_ein_werkzeugcache_hinter_einer_verfolgten_regel_stoert_nicht(self):
        """Without this the case above would also pass for a gate that refuses every untracked
        ignore file — and pytest, ruff, mypy and hypothesis all write one (`*`) into their cache
        directory. A cache whose directory a TRACKED rule ignores is the tree's own word."""
        (self.baum / ".gitignore").write_text("cache/\n", encoding="utf-8")
        _git(self.baum, "add", ".gitignore")
        _git(self.baum, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "ignore the cache")
        (self.baum / "cache").mkdir()
        (self.baum / "cache" / ".gitignore").write_text("*\n", encoding="utf-8")
        (self.baum / "cache" / "x").write_text("cached\n", encoding="utf-8")
        r = self._emit()
        self.assertEqual(r.returncode, 0, f"a tool cache behind a tracked rule was refused:\n{r.stdout}\n{r.stderr}")

    def test_GIT_DIR_in_der_umgebung_lenkt_die_messung_nicht_um(self):
        """[ZAEHLT] Sibling in the environment: with `GIT_DIR`/`GIT_WORK_TREE` pointing at another,
        clean repository, `git -C <repo> status` answered about THAT repository. Measured
        2026-09-21. The dirty --repo tree must still refuse."""
        anderer = self.aussen / "anderer"
        anderer.mkdir()
        _git(anderer, "init", "-q")
        _git(anderer, "config", "user.email", "t@example.invalid")
        _git(anderer, "config", "user.name", "t")
        (anderer / "b.txt").write_text("b\n", encoding="utf-8")
        _git(anderer, "add", "b.txt")
        _git(anderer, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "other")
        (self.baum / "a.txt").write_text("zwei\n", encoding="utf-8")
        umleitung = {"GIT_DIR": str(anderer / ".git"), "GIT_WORK_TREE": str(anderer)}
        # anti-vacuity: under the redirection a plain status from inside the dirty tree is clean
        r0 = subprocess.run(["git", "-C", str(self.baum), "status", "--porcelain"],
                            capture_output=True, text=True, env=_kindumgebung(**umleitung))
        self.assertEqual(r0.stdout.strip(), "", "the redirection did not take, so this case measures nothing")
        umgebung = _kindumgebung(PYTHONPATH=str(REPO / "scripts"), **umleitung)
        self._abgewiesen(self._emit(umgebung=umgebung), "uncommitted path", "a.txt")

    # ── the audit runs between the two measurements ──────────────────────────────────────────────

    def test_eine_aenderung_waehrend_des_audits_wird_abgewiesen(self):
        """[ZAEHLT] P1 of the counter-reading, 2026-09-21: the check ran after an audit that had run
        elsewhere. Now the audit runs here; an audit that leaves the tree changed is refused by the
        measurement after it, and no payload binds the head to output from another tree."""
        befehl = _python("open('a.txt', 'w').write('zwei\\n'); print('audit over modified bytes')")
        self._abgewiesen(self._emit(befehl), "after the audit ran", "uncommitted path", "a.txt")

    def test_ein_audit_das_den_kopf_bewegt_wird_abgewiesen(self):
        """[ZAEHLT] The head is compared, not only the dirt: an empty commit during the run leaves
        the tree clean and the tree digest unchanged, and moves HEAD. That is a different head from
        the one measured, and the receipt would name the wrong one."""
        befehl = _python("import subprocess; subprocess.run(['git', '-c', 'commit.gpgsign=false', "
                         "'commit', '-q', '--allow-empty', '-m', 'moved'], check=True); print('moved')")
        kopf_vorher = _git(self.baum, "rev-parse", "HEAD")
        self._abgewiesen(self._emit(befehl), "changed while the audit ran")
        self.assertNotEqual(_git(self.baum, "rev-parse", "HEAD"), kopf_vorher,
                            "the audit did not move the head, so this case measures nothing")

    def test_die_aufzeichnung_ist_was_der_lauf_gesagt_hat(self):
        """stdout and stderr of the audit, in order, are the record; the digest is over those bytes;
        the exit code is the program's, not a typed number."""
        befehl = _python("import sys; print('hello'); print('warn', file=sys.stderr); raise SystemExit(3)")
        aufzeichnung = self._aufzeichnung()
        r = self._emit(befehl, aufzeichnung=aufzeichnung)
        self.assertEqual(r.returncode, 0, f"an audit that exited 3 was not recorded:\n{r.stdout}\n{r.stderr}")
        aufgezeichnet = aufzeichnung.read_bytes()
        self.assertIn(b"hello\n", aufgezeichnet)
        self.assertIn(b"warn\n", aufgezeichnet)
        kontext = json.loads(self.kontext.read_text(encoding="utf-8"))
        self.assertEqual(kontext["audit_exit_code"], 3)
        self.assertEqual(kontext["audit_output_digest"], hashlib.sha256(aufgezeichnet).hexdigest())
        self.assertIn("exit 3", r.stdout)

    def test_der_lauf_sieht_keinen_bytecode_im_baum(self):
        """The audit program inherits the bytecode settings of this tool: it neither writes
        `__pycache__` into the tree nor reads one that lies there."""
        befehl = _python("import sys; print(sys.pycache_prefix is not None, sys.dont_write_bytecode)")
        aufzeichnung = self._aufzeichnung()
        r = self._emit(befehl, aufzeichnung=aufzeichnung)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(aufzeichnung.read_bytes(), b"True True\n")

    def test_die_aufzeichnung_liegt_ausserhalb_des_baums(self):
        """A record inside the tree would dirty it while the audit runs; refused BEFORE the run,
        and the marker proves the audit never started."""
        marke = self.aussen / "marke"
        befehl = _python(f"open({str(marke)!r}, 'w').write('ran')")
        self._abgewiesen(self._emit(befehl, aufzeichnung=self.baum / "audit.txt"),
                         "inside the tree", "before the run")
        self.assertFalse(marke.exists(), "the audit ran although the record path was refused")

    def test_eine_vorhandene_aufzeichnung_wird_nicht_gebunden(self):
        """A record that was already there is a record this run did not produce — the old input
        contract, and the hole the counter-reading measured. Refused, and the file is untouched."""
        alt = self._aufzeichnung()
        alt.write_bytes(b"output produced from a dirty tree, restored afterwards\n")
        marke = self.aussen / "marke2"
        befehl = _python(f"open({str(marke)!r}, 'w').write('ran')")
        self._abgewiesen(self._emit(befehl, aufzeichnung=alt), "already exists")
        self.assertEqual(alt.read_bytes(), b"output produced from a dirty tree, restored afterwards\n")
        self.assertFalse(marke.exists())

    def test_ein_getippter_exit_code_wird_nicht_angenommen(self):
        """The exit code is measured; the flag that let a caller type one is gone."""
        r = self._emit(extra=["--audit-exit", "0"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unrecognized arguments: --audit-exit", r.stderr)

    # ── carried from the first version of this file ──────────────────────────────────────────────

    def test_der_lauf_legt_keinen_bytecode_neben_die_quellen(self):
        """[ZAEHLT] The run must not create the very debris the gate would refuse.

        MEASURED 2026-09-20 by the FULL suite, not by this file: the first version of the gate
        refused `tests/test_pre_tag_receipt_commit_flow.py`, because the subprocess writes
        `scripts/__pycache__/` and `src/proofbundle/__pycache__/` on import and `git status
        --porcelain` reports both. The gate refused BECAUSE IT RAN. Running only this file's own
        cases would never have shown it, because they build a fixture and never import the judged
        tree into it; the change touches a file that 20 test files read.

        A first repair filtered those paths out of the gate's view, and it was the wrong half of
        the choice. `verify_pre_tag_receipt._bytecode_cache_elsewhere` had already rejected that
        answer for this exact class and named the attack it misses: a `.pyc` carrying a forged
        `verify_ed25519 -> True` beside an untouched `.py`, which Python runs and `git status`
        never lists. So the emit path now uses the same mechanism, `sys.pycache_prefix` plus
        `dont_write_bytecode`, and the gate keeps every tooth it had.

        This case measures the guarantee that replaces the filter: after a full emit, no
        `__pycache__` appears next to the sources THE RUN ITSELF IMPORTS.

        MEASURED 2026-09-20, and the first version of this case did not measure it. It looked for
        `__pycache__` inside `self.baum`, the throwaway repository passed as `--repo`. No Python
        module is ever imported out of that directory, so no cache can appear there with the fix
        or without it: removing `_bytecode_cache_elsewhere()` left the case GREEN. A case that
        cannot go red is not a catch proof. The sources the run does import are `scripts/` and
        `src/proofbundle/`, so this version copies both into a directory of its own and watches
        THAT.
        """
        import shutil  # noqa: PLC0415
        eigen = pathlib.Path(tempfile.mkdtemp(prefix="pre-tag-quellen-"))
        self.addCleanup(shutil.rmtree, eigen, ignore_errors=True)
        shutil.copytree(REPO / "scripts", eigen / "scripts")
        shutil.copytree(REPO / "src", eigen / "src")
        for rest in (eigen / "scripts").rglob("__pycache__"):
            shutil.rmtree(rest, ignore_errors=True)
        for rest in (eigen / "src").rglob("__pycache__"):
            shutil.rmtree(rest, ignore_errors=True)
        r = self._emit(skript=eigen / "scripts" / "pre_tag_receipt.py", cwd=eigen,
                       umgebung=_kindumgebung(PYTHONPATH=os.pathsep.join(
                           [str(eigen / "src"), str(eigen / "scripts")])))
        self.assertEqual(r.returncode, 0, f"the control emit failed: {r.stdout + r.stderr}")
        gefunden = sorted(str(q.relative_to(eigen)) for q in eigen.rglob("__pycache__"))
        self.assertEqual(gefunden, [],
                         f"the run left bytecode caches next to the sources it imported ({gefunden}), "
                         f"so an emit in a checkout would refuse because of debris it created itself")

    def test_ANTI_gepflanzter_bytecode_wird_weiterhin_abgewiesen(self):
        """[ZAEHLT] The exemption that was almost added must not exist.

        The gate refuses ANY untracked path, and a `__pycache__` it did not create is no
        exception — a cache that is present is not evidence of anything, and treating it as
        harmless is exactly the hole `verify_pre_tag_receipt` documents. This case fails the
        moment someone reintroduces the filter.
        """
        # PLANTED UNDER `scripts/`, because that directory already carries a tracked file in the
        # fixture. Under a wholly untracked directory git collapses the report to `?? src/`, and an
        # assertion on the literal `__pycache__` then hangs on git's SPELLING rather than on the
        # property. Measured 2026-09-20, first version of this case: git said `?? src/`, the
        # assertion went red, and the gate had refused correctly all along.
        (self.baum / "scripts" / "__pycache__").mkdir(exist_ok=True)
        (self.baum / "scripts" / "__pycache__" / "x.cpython-310.pyc").write_bytes(b"\x00\x01")
        self._abgewiesen(self._emit(), "uncommitted path", "__pycache__")

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
            mod.build_context(self.baum, "6.1.0", _python("print('audit')"), "test",
                              "2026-09-20T00:00:00Z", self._aufzeichnung())
        self.assertIn("uncommitted path", str(gefangen.exception), str(gefangen.exception))

    def test_nicht_bestimmbar_ist_keine_freigabe(self):
        """A directory that is no repository at all must refuse, not fall through to a digest."""
        kein_repo = self.aussen / "kein_repo"
        kein_repo.mkdir()
        ziel = self.aussen / "p2.bin"
        kontext = self.aussen / "c2.json"
        r = subprocess.run(
            [sys.executable, str(SKRIPT), "--repo", str(kein_repo),
             "--emit-payload", str(ziel), "--context-out", str(kontext),
             "--version", "6.1.0", "--audit-command", _python("print('audit')"),
             "--audit-output-file", str(self._aufzeichnung()),
             "--runner-identity", "test", "--produced-at", "2026-09-20T00:00:00Z"],
            capture_output=True, text=True, cwd=str(REPO),
            env=_kindumgebung(PYTHONPATH=str(REPO / "scripts")))
        self.assertNotEqual(r.returncode, 0, "a non-repository produced a payload")
        self.assertFalse(ziel.exists(), "a payload was written despite the refusal")
        # THE EXIT CODE ALONE DOES NOT NAME THE MECHANISM. Measured 2026-09-20: with the gate
        # removed the script still left with 1, because `subject_tree_digest` raises an unhandled
        # `BaumNichtLesbar` one step later. The case was green in both states and therefore proved
        # nothing about the gate. It now asserts the gate's OWN refusal, which is the thing under
        # test, and a traceback no longer passes for a decision.
        meldung = r.stdout + r.stderr
        self.assertIn("refusing to bind a tree digest", meldung,
                      f"the run failed, but not through the cleanliness gate: {meldung[-800:]}")
        self.assertNotIn("Traceback", meldung,
                         f"a refusal is a decision, not a crash: {meldung[-800:]}")


if __name__ == "__main__":
    unittest.main()
