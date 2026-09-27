"""One establisher for the verdict type, not two. The count is measured over the source.

WHERE THIS CAME FROM. R-B4 (CWE-1287, ``bool("false") is True``) was fixed in five sites inside
``intoto.py`` on 2026-09-24. A SIXTH was found afterwards, in ``sdjwt_issue.py``, and it was the one
that signs. The reason it was missed is recorded in ``_membership.is_bool``: five of six lived in one
file, and sweeping a file is not sweeping a class. The fix then produced its own second-order instance,
which an independent lens of the house deep-gate reported the same day:

    "two independent, unconnected implementations with identical intent — risk: a future change at one
     site forgets the other."

WHAT THIS FILE MEASURES, and why it is not the same thing the scanner beside it measures.
``tests/test_verdikt_truthiness_scanner.py`` answers "does every site that READS the verdict route
through an establisher"; its ``ETABLIERER`` set is a list of NAMES. This file answers a different
question — "how many IMPLEMENTATIONS of that establisher exist" — and a name list cannot answer it,
because two definitions of the same name pass a name check. One question per contract.

THE GUARD MATTERS AS MUCH AS THE COUNT. A file that only asserted "exactly one def" would also pass if
the function were deleted and every caller went back to reading the field raw. So the callers are
measured too: both modules must IMPORT the shared one, and the shared one must actually refuse.
"""
from __future__ import annotations

import ast
import pathlib
import unittest

QUELLE = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

#: The one name. If it is ever renamed, this constant is the single place that changes.
NAME = "require_bool_verdict"

#: Where it is allowed to be DEFINED. Everything else may only import it.
HEIMAT = "_verdict.py"


def _definitionen(name: str) -> list[tuple[str, int]]:
    """Every `def <name>` across the package, as (relative path, line). Measured over the syntax tree,
    not over text, so a mention in a docstring or a comment is not counted as a definition — that
    distinction is the whole reason this is an AST walk."""
    treffer = []
    for pfad in sorted(QUELLE.rglob("*.py")):
        try:
            baum = ast.parse(pfad.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):          # pragma: no cover - a broken file is another test's job
            continue
        for knoten in ast.walk(baum):
            if isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)) and knoten.name == name:
                treffer.append((pfad.name, knoten.lineno))
    return treffer


def _importiert(modul: str, name: str) -> bool:
    """True iff `modul` imports `name` — again over the tree, so a mention in prose does not count."""
    baum = ast.parse((QUELLE / modul).read_text(encoding="utf-8"))
    for knoten in ast.walk(baum):
        if isinstance(knoten, ast.ImportFrom) and any(a.name == name for a in knoten.names):
            return True
    return False


class TestGenauEineUmsetzung(unittest.TestCase):
    def test_der_etablierer_ist_genau_einmal_definiert(self):
        """THE CATCH PROOF. Before the merge this measured two: intoto.py and sdjwt_issue.py each had a
        private copy under the name `_require_bool_verdict`."""
        gefunden = _definitionen(NAME)
        self.assertEqual(len(gefunden), 1, f"{len(gefunden)} implementations of {NAME}: {gefunden}")
        self.assertEqual(gefunden[0][0], HEIMAT,
                         f"{NAME} is defined in {gefunden[0][0]}, not in {HEIMAT}")

    def test_die_alten_privaten_kopien_sind_weg(self):
        """Named explicitly rather than covered by the count above: if one comes back under the OLD
        name, the count of the NEW name stays at one and nothing else would notice."""
        alt = _definitionen("_require_bool_verdict")
        self.assertEqual(alt, [], f"a private copy came back: {alt}")


class TestBeideBahnenBenutzenIhn(unittest.TestCase):
    """WITHOUT THESE THE COUNT PROVES NOTHING. Deleting the function entirely would satisfy a count of
    one just as well as a correct merge does — these two cases are what separates the two states."""

    def test_intoto_importiert_ihn(self):
        self.assertTrue(_importiert("intoto.py", NAME), "intoto.py no longer imports the establisher")

    def test_sdjwt_issue_importiert_ihn(self):
        self.assertTrue(_importiert("sdjwt_issue.py", NAME),
                        "sdjwt_issue.py no longer imports the establisher")

    def test_er_weist_wirklich_ab(self):
        """The behavioural guard: the shared one must still refuse a string verdict, and refuse a
        non-dict claim, or the two cases above are satisfied by an establisher that establishes
        nothing."""
        from proofbundle._verdict import require_bool_verdict
        from proofbundle.errors import BundleFormatError
        for schlecht in ("false", "true", 0, 1, [], {}, None):
            with self.subTest(wert=schlecht):
                with self.assertRaises(BundleFormatError):
                    require_bool_verdict({"passed": schlecht}, wo="probe")
        with self.assertRaises(BundleFormatError):
            require_bool_verdict("kein dict", wo="probe")
        self.assertIs(require_bool_verdict({"passed": True}, wo="probe"), True)
        self.assertIs(require_bool_verdict({"passed": False}, wo="probe"), False)


if __name__ == "__main__":
    unittest.main()
