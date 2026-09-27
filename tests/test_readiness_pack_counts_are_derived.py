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

2. A PATTERN HAS AN EDGE AND THIS ONE IS NAMED. The corpus sweep reads `29 cases`, `29-case`,
   `29cases` and `4,130 cases`, in either case. It does NOT read a number written as a word, so
   "twenty-nine cases" walks past. The acceptance-matrix rule reads the hyphenated form and the
   phrase followed by a size-stating verb (`the acceptance matrix has 40 checks`); a sentence that
   states the size in some other construction is not reached.

   THE LIST ABOVE WAS SHORTER AND SAID "all of them". A fresh adversarial pass found four more
   edges of the same size in under an hour -- two escapes, one false positive, one crash -- and
   each is now either fixed or written here. That is the honest status of any such enumeration:
   these are the edges MEASURED SO FAR. A list of known edges is a record of who has looked, not a
   boundary of what exists, and claiming otherwise is the error this file keeps finding elsewhere.

3. THE EXCLUSION LIST IS A JUDGEMENT. Digest and key files (.sha256, .b64, .sig) are skipped
   because they are long hex and base64 runs that a number sweep misreads, and because no one
   states a count in them. If that ever stops being true, this list is the place it goes wrong.

4. THE FALLBACK MEASURES SOMETHING SLIGHTLY DIFFERENT. When git cannot answer, the envelope count
   comes from a directory walk with tool debris filtered out. That counts files present rather
   than files tracked, so a deliberately untracked file would be included. It still runs and can
   still fail, which is the property that matters; the failure message says which reading produced
   the number. Measured consequence, stated rather than left to be found: while git DOES answer,
   an untracked addition is invisible here, because git is preferred and git does not see it.

5. THE DEBRIS FILTER WOULD DROP A TRACKED DOTFILE. `_ist_werkzeugmuell` refuses any path component
   beginning with a dot. Under the fallback that would silently under-count a dotfile the
   repository legitimately tracks. Measured: no such file exists under `conformance/` today, so
   the rule is dormant rather than wrong. It is written down because dormant is not the same as
   safe, and the next tracked dotfile is the moment it stops being dormant.

6. AMBIGUITY IN THE MATRIX SOURCE REFUSES RATHER THAN GUESSES. If module scope ever carries more
   than one `CHECKS` list, this test fails and says so instead of choosing. That is deliberate: it
   converts a silent wrong answer into a loud question. It also means a legitimate restructuring
   of that script breaks this test on purpose, and whoever does it has to say which list is
   authoritative.
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
    # THE SAME DEBRIS FILTER AS ITS SIBLING, which it should have had from the start. The commit
    # that taught `_versandte_dateien` to ignore a `.DS_Store` left this function, twenty lines
    # away, walking the filesystem with no such filter -- so a binary dropped in the pack reached
    # `.read_text()` and burst a subtest with a UnicodeDecodeError. A counter-reading did it. One
    # fix, one of two callers: that is fixing the instance and calling it the class.
    return [p for p in PACK.rglob("*")
            if p.is_file() and p.suffix not in AUSGESCHLOSSEN
            and not _ist_werkzeugmuell(p.relative_to(PACK).parts)]


def _zahl(roh: str) -> int:
    """A number as a document writes it: digits with grouping separators removed."""
    return int(roh.replace(",", ""))


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
                # THE COMMA IS PART OF THE NUMBER. `\d+` against "now totals 4,130 cases" matches
                # only the trailing group, 130 -- which happened to equal the true count, so a
                # document stating a number that was never right passed. A counter-reading built
                # exactly that. The digits and their separators are read together and the
                # separators removed, and a match may not begin in the middle of a number.
                genannt = [_zahl(x) for x in re.findall(r"(?<![\d,])(\d[\d,]*)[\s-]?[Cc]ases?\b",
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
        # AMBIGUITY REFUSES. THIS IS THE THIRD SHAPE OF ONE MISTAKE, so the mistake gets named
        # rather than patched again. Version one walked every node and kept the LAST `CHECKS`,
        # so a decoy inside an uncalled function won. Version two read only `baum.body`, so a
        # decoy at true top level won while the REAL list, wrapped in `if True:`, became
        # invisible. Both were executed by counter-readings; both made the derivation report 2
        # and let the pack claim "2-check acceptance matrix" and pass.
        #
        # What both versions share is not a scoping bug, it is a DISPOSITION: when several
        # candidates carried the name, they picked one. First, last, top-level -- every rule for
        # picking is a rule an attacker or a refactor chooses for you. So this one collects
        # every module-scope candidate, descending through `if`/`try`/`with` (which do not make a
        # new scope) but NOT into functions or classes (which do), and refuses unless there is
        # exactly one. Two candidates is not a number to choose between; it is a question this
        # test is not entitled to answer.
        # A STATEMENT LIST, not a node with a body. The first attempt at this refusal took a NODE
        # and recursed only into sub-nodes that themselves had a `body` -- so a plain
        # `CHECKS = [...]` sitting directly inside `if True:` was never looked at, because an
        # assignment has no body. Measured over twelve shapes, that version found ZERO candidates
        # for a list inside `if`, and with a top-level decoy beside it found exactly one: the
        # DECOY. The attack it was written against still walked through.
        #
        # WORSE, AND THE REASON THIS COMMENT IS LONG: the catch-proof for that version went red,
        # and was reported as proof the refusal worked. It went red because the derived number
        # disagreed with the documents, not because anything refused. Set the documents to match
        # the decoy -- which is what the counter-reading did -- and it passed. A case going red
        # proves only that it goes red; WHY it goes red is a second measurement.
        def _modul_kandidaten(anweisungen):
            for k in anweisungen or []:
                if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue  # a new scope: a `CHECKS` in there is not the module's
                if isinstance(k, ast.Assign) and isinstance(k.value, (ast.List, ast.Tuple)):
                    if any(isinstance(z, ast.Name) and z.id == "CHECKS" for z in k.targets):
                        yield k.value
                for feld in ("body", "orelse", "finalbody", "handlers"):
                    yield from _modul_kandidaten(getattr(k, feld, None))

        baum = ast.parse(skript.read_text(encoding="utf-8"))
        kandidaten = list(_modul_kandidaten(baum.body))
        self.assertEqual(
            len(kandidaten), 1,
            f"module scope carries {len(kandidaten)} assignments named CHECKS; a derivation that "
            f"picks one of several is choosing, not deriving — if the matrix legitimately has "
            f"more than one, this test has to learn which is authoritative before it may judge")
        kennungen = [e.elts[0].value for e in kandidaten[0].elts
                     if isinstance(e, (ast.Tuple, ast.List)) and e.elts
                     and isinstance(e.elts[0], ast.Constant)]
        gemessen = len([k for k in kennungen if str(k).startswith("C")])
        self.assertGreater(gemessen, 0, f"no machine-checkable check ids in {kennungen[:5]}")
        for datei in sorted(_pack_dokumente()):
            text = datei.read_text()
            # PROXIMITY IS NOT A CLAIM. A third pattern used to match any "N checks" within eighty
            # characters of the phrase, in either direction. A counter-reading planted "We
            # performed 12 checks on formatting before building the acceptance matrix document"
            # and the rule accused an innocent sentence of misstating the matrix size. A rule that
            # turns honest prose red is a defect of the same size as one that lets a wrong number
            # through, and it is worse in one way: it trains people to switch the rule off.
            #
            # What remains states the size rather than standing near it: the hyphenated form the
            # pack uses, and the phrase followed by a size-stating verb. "has 40 checks" is still
            # caught; "12 checks on formatting ... acceptance matrix" no longer is.
            genannt = {_zahl(x) for x in re.findall(r"(\d[\d,]*)-check acceptance matrix", text)}
            genannt |= {_zahl(x) for x in re.findall(
                r"acceptance matrix\b[^.\n]{0,40}?\b(?:has|holds|contains|comprises|is)\b"
                r"[^.\n]{0,20}?(\d[\d,]*) checks?\b", text)}
            if not genannt:
                continue
            with self.subTest(datei=datei.name):
                self.assertEqual(genannt, {gemessen},
                                 f"{datei.name} says {sorted(genannt)} for the acceptance matrix "
                                 f"and the matrix holds {gemessen} machine-checkable checks")


if __name__ == "__main__":
    unittest.main()
