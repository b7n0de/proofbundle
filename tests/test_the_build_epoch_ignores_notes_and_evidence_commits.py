"""The build epoch is the time of the last commit outside release notes and audit artefacts, not of HEAD.

SOURCE. Measured on 2026-09-29 in a local probe of the 6.2.0 release chain (the candidate, the notes
commit, the register commit, the receipt commit, the evidence commit and the merge that carries the
tag). With the epoch taken from HEAD, the receipt commit, the evidence commit and the merge built
three different sdists and wheels while their content was equal; built with one epoch, the three were
byte-identical. The signed soak and differential bind the distributions of the head they are signed
at, and the tag sits on a later commit, so under the HEAD rule the published bytes are never the bound
ones, and `audit_candidate_matrix` refuses the binding at the evidence commit when the `dist/` it reads
was built with the default. 6.1.0 shows the same gap: its evidence binds the sdist 62a00fb7…, PyPI
carries d6355491….

THE RULE. A commit that changes only `release_notes/` or `audit_artifacts/` changes nothing the
package ships (MANIFEST.in never lists the first and prunes the second), so it does not move the
epoch either. These are the only two the tag chain writes; other unshipped paths still move it. These are the two prefixes `render_release.liefert_dasselbe_paket` already allows
between the tree the notes describe and the tagged tree; the last class below holds the two copies
equal, because a build rule and a notes rule that drew the line in different places would each pass
on its own and disagree about the same release.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import build_reproducible as br

REPO = Path(__file__).resolve().parents[1]

_T_SRC, _T_NOTES, _T_EVIDENCE, _T_MERGE, _T_SRC2 = (1790000000, 1790000100, 1790000200,
                                                     1790000300, 1790000400)


def _git(repo: Path, *args: str, zeit: int | None = None) -> str:
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    if zeit is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"@{zeit} +0000"
    r = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@localhost",
                        "-c", "commit.gpgsign=false", *args],
                       capture_output=True, text=True, env=env, timeout=30)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def _commit(repo: Path, rel: str, text: str, zeit: int) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    _git(repo, "add", rel)
    _git(repo, "commit", "-q", "-m", f"touch {rel}", zeit=zeit)


class TheEpochIgnoresCommitsThatShipNothing(unittest.TestCase):

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="pb_epoch_")
        self.repo = Path(self._td.name)
        _git(self.repo, "init", "-q", "-b", "main")
        _commit(self.repo, "src/pkg/__init__.py", "x = 1\n", _T_SRC)

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_a_notes_commit_and_an_evidence_commit_keep_the_epoch(self) -> None:
        _commit(self.repo, "release_notes/notes.md", "notes\n", _T_NOTES)
        self.assertEqual(br.head_commit_epoch(self.repo), _T_SRC)
        _commit(self.repo, "audit_artifacts/360/evidence.json", "{}\n", _T_EVIDENCE)
        self.assertEqual(br.head_commit_epoch(self.repo), _T_SRC)

    def test_a_merge_over_the_evidence_commit_keeps_the_epoch(self) -> None:
        # The shape of the 6.2.0 tag: the first parent is main, the second the evidence commit, and
        # main is an ancestor of the second, so the merged tree is the evidence tree.
        basis = _git(self.repo, "rev-parse", "HEAD")
        _git(self.repo, "checkout", "-q", "-b", "kette")
        _commit(self.repo, "release_notes/notes.md", "notes\n", _T_NOTES)
        _commit(self.repo, "audit_artifacts/360/evidence.json", "{}\n", _T_EVIDENCE)
        _git(self.repo, "checkout", "-q", "main")
        self.assertEqual(_git(self.repo, "rev-parse", "HEAD"), basis)
        _git(self.repo, "merge", "-q", "--no-ff", "kette", "-m", "merge", zeit=_T_MERGE)
        self.assertEqual(_git(self.repo, "log", "-1", "--format=%ct"), str(_T_MERGE))
        self.assertEqual(br.head_commit_epoch(self.repo), _T_SRC)

    def test_control_a_shipped_change_moves_the_epoch(self) -> None:
        _commit(self.repo, "release_notes/notes.md", "notes\n", _T_NOTES)
        _commit(self.repo, "src/pkg/__init__.py", "x = 2\n", _T_SRC2)
        self.assertEqual(br.head_commit_epoch(self.repo), _T_SRC2)

    def test_control_a_path_that_only_starts_like_an_excluded_one_moves_the_epoch(self) -> None:
        # The exclusion is a directory, not a name prefix: `release_notes_extra/` ships as far as
        # this rule knows, and treating it as notes would let a shipped change keep an old epoch.
        _commit(self.repo, "release_notes_extra/x.py", "y = 1\n", _T_NOTES)
        self.assertEqual(br.head_commit_epoch(self.repo), _T_NOTES)


_SKRIPT = REPO / "scripts" / "render_release.py"
_spec = importlib.util.spec_from_file_location("_render_release_epoch_contract", _SKRIPT)
_rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rr)


class TheBuildRuleAndTheNotesRuleDrawTheSameLine(unittest.TestCase):

    def test_both_name_the_same_unshipped_prefixes(self) -> None:
        self.assertEqual(tuple(br.NICHT_AUSGELIEFERT), tuple(_rr.NICHT_AUSGELIEFERT))


if __name__ == "__main__":
    unittest.main()
