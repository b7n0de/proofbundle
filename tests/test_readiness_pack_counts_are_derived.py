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

Correcting five numbers without binding any of them schedules a sixth. This binds the ones that
are DERIVABLE and STABLE: a count over files in the tree. It deliberately does not bind figures
that move with every added test, because a gate on a daily-changing number is one people learn to
re-run -- those carry their command and their date in the text instead.
"""
from __future__ import annotations

import json
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
PACK = REPO / "docs" / "readiness_pack"


def _case_json(unter: pathlib.Path) -> int:
    return len(list(unter.rglob("case.json")))


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
        for name in ("rust_parity_scope.md", "differential_matrix.md", "index.json"):
            datei = PACK / name
            if not datei.is_file():
                continue
            with self.subTest(datei=name):
                genannt = [int(x) for x in re.findall(r"(\d+) cases\b", datei.read_text())]
                heutige = [x for x in genannt if x == gemessen]
                self.assertTrue(
                    heutige,
                    f"{name} names case counts {genannt} and the corpus holds {gemessen}; a "
                    f"document that states the size must state the current one somewhere")

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
        dateien = len([p for p in unter.rglob("*") if p.is_file()])
        faelle = _case_json(unter)
        self.assertEqual([int(x) for x in treffer.groups()],
                         [dateien, dateien, faelle, faelle],
                         f"index.json claims {treffer.group(0)!r}; the tree holds {dateien} files "
                         f"and {faelle} case.json")


if __name__ == "__main__":
    unittest.main()
