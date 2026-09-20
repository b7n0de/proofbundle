"""Counts the readiness pack states about the tree are derived from the tree.

MEASURED 2026-09-20 by sweeping the pack completely instead of sampling it: 25 number-shaped hits
across ten files. Most are not claims at all -- IACR paper numbers, an eIDAS regulation reference,
version slots, a section heading. Of the real ones, three name their date or their commit and hold
as written, and five were measurably wrong:

    index.json                "F1 offline corpus, 29 cases"        the corpus holds 130
    AUDITOR_OPEN_POINTS.md    "the 36 PENDING surfaces"            the registry holds 61
    rust_parity_scope.md      "57 cases as of v3.7.0 ... 56/56"    read as current coverage
    differential_matrix.md    "grown to 57 cases"                  the corpus holds 130
    rust_parity_scope.md      "40 conformance vectors"             the relation corpus holds 45

Correcting five numbers without binding any of them schedules a sixth, and the sixth arrived the
same day. A counter-reading swept the pack again and found `REPRODUCTION_RUNBOOK.md` saying "the
34-check acceptance matrix (§9 minus external)" where `scripts/audit_candidate_matrix.py` holds
33 machine-checkable checks plus one external one -- "minus external" is 33 by its own definition,
and the other four mentions in this pack say 33.

THE SWEEP THAT FOUND FIVE WAS NOT WRONG, ITS INSTRUMENT WAS TOO NARROW. It matched `\d+ <noun>`
and `\d+ of \d+`, so every hyphenated compound in the pack -- `33-check`, `54-case`, `40-character`,
`4000-line` -- was invisible to it, as were percentages and spelled-out numbers. A set claim
measured with a pattern is a claim about the pattern, and "swept completely" was a statement about
reach that had itself never been measured.

So this binds what is DERIVABLE and STABLE: counts over files in the tree, and now the check-matrix
size, which is the one hyphenated figure with a real source. It deliberately does not bind figures
that move with every added test, because a gate on a daily-changing number is one people learn to
re-run -- those carry their command and their date in the text instead.

HONEST LIMITS. A closing lens took the first version of this file apart with executed exploits and
the account below is what survived. None of these is hidden; a rule whose edge is written down can
be argued with, one whose edge is discovered cannot.

1. A WRONG NUMBER MAY STAND BESIDE THE RIGHT ONE. The corpus rule requires the CURRENT number to
   appear in a document that states a size and tolerates another number next to it. "57 cases that
   existed at v3.7.0" beside today's 130 is legitimate history and, by the number alone, is
   indistinguishable from drift. Tightening it would turn honest prose red, so it stays loose.

2. A PATTERN HAS AN EDGE AND THIS ONE IS NAMED. The corpus sweep reads `29 cases`, `29-case` and
   `29cases`, in either case. It does NOT read a number written as a word, so "twenty-nine cases"
   walks past. The acceptance-matrix rule reads the hyphenated form and the phrase with `N checks`
   within one sentence either way round; a sentence that states the size without naming the matrix
   is not reached. These are the measured edges, not a claim that none exists.

3. THE EXCLUSION LIST IS A JUDGEMENT. Digest and key files (.sha256, .b64, .sig) are skipped
   because they are long hex and base64 runs that a number sweep misreads, and because no one
   states a count in them. If that ever stops being true, this list is the place it goes wrong.

4. THE FALLBACK MEASURES SOMETHING SLIGHTLY DIFFERENT. When git cannot answer, the envelope count
   comes from a directory walk with tool debris filtered out. That counts files present rather
   than files tracked, so a deliberately untracked file would be included. It still runs and can
   still fail, which is the property that matters; the failure message says which reading produced
   the number.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import subprocess
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
PACK = REPO / "docs" / "readiness_pack"


def _case_json(unter: pathlib.Path) -> int:
    return len(list(unter.rglob("case.json")))


#: Files in the pack that are machine-generated digests or key material. They hold long hex and
#: base64 runs, which a number sweep reads as numbers, and no human states a count in them. This
#: is an EXCLUSION list on purpose: an inclusion list of extensions made a new `.txt` invisible,
#: which a counter-reading demonstrated by dropping one in with two already-corrected numbers.
AUSGESCHLOSSEN = {".sha256", ".b64", ".sig", ".pyc"}


def _pack_dokumente() -> list[pathlib.Path]:
    """Every document in the pack, so a new one cannot carry a corrected-away number unseen."""
    return [p for p in PACK.rglob("*")
            if p.is_file() and p.suffix not in AUSGESCHLOSSEN and "__pycache__" not in p.parts]


def _ist_werkzeugmuell(teile: tuple[str, ...]) -> bool:
    return any(t.startswith(".") or t == "__pycache__" or t.endswith(".pyc") for t in teile)


def _versandte_dateien(unter: pathlib.Path) -> tuple[list[str], str]:
    """What ships under a directory, and by which measurement -- never nothing.

    The tree is what SHIPS, and `rglob` also counts what a tool dropped: a `.DS_Store` or a
    `__pycache__` entry moved the envelope-profile count by two and turned this red without any
    drift in the corpus. A false red is a test people learn to switch off.

    BUT THE FIRST FIX TRADED A FALSE RED FOR A SILENT ABSENCE. It returned None when git could
    not answer and the caller SKIPPED -- so on a machine without git on PATH, the one check that
    guards these counts disappeared without a word. A counter-reading ran it with an emptied PATH
    and got `1 skipped`, green by omission. That is the same class the .DS_Store fix was aimed at,
    one mechanism over: a guard that removes itself is worse than one that cries wolf.

    So git is the PREFERRED reading and the walk is the FALLBACK, with tool debris filtered out
    of it. The check always runs; the answer says which measurement produced it.
    """
    try:
        fertig = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "--", str(unter)],
                                capture_output=True, text=True, timeout=60)
        if fertig.returncode == 0:
            return [t for t in fertig.stdout.split("\0") if t], "git ls-files"
    except (OSError, subprocess.SubprocessError):
        pass
    gefunden = [p for p in unter.rglob("*")
                if p.is_file() and not _ist_werkzeugmuell(p.relative_to(REPO).parts)]
    return [str(p.relative_to(REPO)) for p in gefunden], "directory walk (git could not answer)"


class TestTheReadinessPackCountsMatchTheTree(unittest.TestCase):

    def setUp(self):
        if not PACK.is_dir():
            self.skipTest("docs/readiness_pack/ is not in this tree — a distributed artefact "
                          "prunes it, and a pack that is not here cannot be checked")

    def test_the_corpus_size_is_the_same_in_every_document_that_states_it(self):
        """Three documents state one fact. The fix on 2026-09-08 corrected ONE of them."""
        manifest = json.loads((REPO / "conformance" / "manifest.json").read_text())["cases"]
        self.assertIsInstance(manifest, list, "`cases` must be a list to be a corpus")
        gemessen = len(manifest)
        self.assertEqual(_case_json(REPO / "conformance"), gemessen,
                         "the manifest and the tree disagree about the corpus, so neither number "
                         "may be quoted until they do not")
        # EVERY DOCUMENT IN THE PACK, not a list of three names. The first version named the three
        # files that happened to be wrong that day, so a new or renamed document could carry the
        # same corrected-away number and stay invisible -- demonstrated by creating one.
        for datei in sorted(_pack_dokumente()):
            with self.subTest(datei=datei.name):
                # SAME SHAPES AS ITS SIBLING. The check-matrix rule was widened after a lens
                # escaped it; leaving this one narrow would have kept the identical hole open for
                # the figure next to it. Measured escapes that now close: `29-case`, `29cases`,
                # `29 Cases`. A number written as a word is still out of reach, and says so above.
                genannt = [int(x) for x in re.findall(r"(\d+)[\s-]?[Cc]ases?\b",
                                                      datei.read_text())]
                if not genannt:
                    continue
                heutige = [x for x in genannt if x == gemessen]
                self.assertTrue(
                    heutige,
                    f"{datei.name} names case counts {genannt} and the corpus holds "
                    f"{gemessen}; a document that states the size must state the current one "
                    f"somewhere")

    def test_the_relation_vector_count_matches_the_relation_corpus(self):
        """`40 conformance vectors` against 45 on disk, found by the sweep on 2026-09-20."""
        datei = PACK / "rust_parity_scope.md"
        if not datei.is_file():
            self.skipTest("rust_parity_scope.md is not in this tree")
        gemessen = _case_json(REPO / "conformance" / "relation")
        treffer = re.search(r"relation-statement/v0\.1 surface: (\d+) conformance vectors",
                            datei.read_text())
        self.assertIsNotNone(treffer, "the sentence naming the relation vector count is gone — if "
                                      "it was removed on purpose, remove this check with it")
        self.assertEqual(int(treffer.group(1)), gemessen,
                         f"rust_parity_scope.md claims {treffer.group(1)} relation vectors, "
                         f"conformance/relation holds {gemessen}")

    def test_the_envelope_profile_counts_match_the_tree(self):
        """This one was already right. It is bound so it stays right, not because it was wrong."""
        datei = PACK / "index.json"
        if not datei.is_file():
            self.skipTest("index.json is not in this tree")
        treffer = re.search(r"(\d+) of (\d+) files, (\d+) of (\d+) case\.json", datei.read_text())
        if treffer is None:
            self.skipTest("the envelope-profile sentence is gone; nothing left to bind")
        unter = REPO / "conformance" / "envelope_profile"
        versandt, wie = _versandte_dateien(unter)
        dateien = len(versandt)
        faelle = len([t for t in versandt if pathlib.PurePosixPath(t).name == "case.json"])
        self.assertEqual([int(x) for x in treffer.groups()],
                         [dateien, dateien, faelle, faelle],
                         f"index.json claims {treffer.group(0)!r}; the tree holds {dateien} files "
                         f"and {faelle} case.json (measured by {wie})")

    def test_the_acceptance_matrix_size_matches_the_matrix(self):
        """`34-check` against 33, in a form the sweep that found the other five could not see.

        The pattern that swept this pack matched a number followed by a noun, so `33-check` and
        `34-check` both walked past it. Four places in the pack said 33 and one said 34, and the one
        that said 34 also said "§9 minus external" in the same breath -- which is the definition
        of 33. The source is a list in the matrix script: 33 entries with a `C` id plus one `EXT`
        entry, 34 together, and the pack's number is the machine-checkable subset.
        """
        skript = REPO / "scripts" / "audit_candidate_matrix.py"
        if not skript.is_file():
            self.skipTest("scripts/audit_candidate_matrix.py is not in this tree")
        # Read, do not import: the module pulls in the gates it orchestrates.
        # THE MODULE BODY, not `ast.walk`. The first version walked every node and kept the LAST
        # `CHECKS = [...]` it saw, so a local of that name inside ANY function -- visited after the
        # real one, because the walk is breadth-first -- silently became the answer. A
        # counter-reading planted a two-element decoy in an uncalled function and the derivation
        # reported 2; the pack was then free to claim "2-check acceptance matrix" and pass. A
        # derivation that matches a bare NAME instead of a scoped binding is not a derivation.
        baum = ast.parse(skript.read_text(encoding="utf-8"))
        kennungen = None
        for knoten in baum.body:
            if isinstance(knoten, ast.Assign) and isinstance(knoten.value, (ast.List, ast.Tuple)):
                if any(isinstance(z, ast.Name) and z.id == "CHECKS" for z in knoten.targets):
                    kennungen = [e.elts[0].value for e in knoten.value.elts
                                 if isinstance(e, (ast.Tuple, ast.List)) and e.elts
                                 and isinstance(e.elts[0], ast.Constant)]
        self.assertIsNotNone(kennungen, "the CHECKS list is gone — if the matrix was restructured, "
                                        "rewrite this derivation with it")
        gemessen = len([k for k in kennungen if str(k).startswith("C")])
        self.assertGreater(gemessen, 0, f"no machine-checkable check ids in {kennungen[:5]}")
        for datei in sorted(_pack_dokumente()):
            text = datei.read_text()
            # TWO SHAPES, because one was not enough. The hyphenated form is what the pack uses;
            # a counter-reading escaped it with "the acceptance matrix now has 40 checks" in a
            # neighbouring document and the sweep never looked at the sentence. Both forms are
            # anchored on the phrase, so an unrelated number elsewhere is not dragged in.
            genannt = {int(x) for x in re.findall(r"(\d+)-check acceptance matrix", text)}
            genannt |= {int(x) for x in re.findall(
                r"acceptance matrix[^.\n]{0,80}?(\d+) checks?\b", text)}
            genannt |= {int(x) for x in re.findall(
                r"(\d+) checks?\b[^.\n]{0,80}?acceptance matrix", text)}
            if not genannt:
                continue
            with self.subTest(datei=datei.name):
                self.assertEqual(genannt, {gemessen},
                                 f"{datei.name} says {sorted(genannt)} for the acceptance matrix "
                                 f"and the matrix holds {gemessen} machine-checkable checks")


if __name__ == "__main__":
    unittest.main()
