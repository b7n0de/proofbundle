"""Every operator of the mutation gate names exactly one site of today's source, and its mutant parses.

WHY (2026-09-29, pull request 311). The gate reports an operator whose text is not in its file as a gap
("pattern not found, operator is stale"), but the mutation job runs only for a landing candidate (the
label `landung`, a release branch, the merge queue or a run by hand). At v6.1.0 (dcac5aee) each of the
100 operators named one site. At main 52231c95, 19 of 106 named none: the round-12 reading (`type()`
where `isinstance` stood, one reading into a plain copy) rewrote the guarded lines, and no operator was
drawn along. Nothing in the ordinary suite saw it. Four of the 19 sat on relation.py, and two of those
hid a gap in the tests: drawn onto today's source, the two R7-2b lookup mutants survived their test file
(the case that kills them is in tests/test_never_raise_surface_family_property.py). This check runs with
the suite on every pull request, so a change that moves a guarded line fails where it is made.

EXACTLY ONE, NOT AT LEAST ONE. The gate replaces the first occurrence of each text; a text that names two
sites mutates whichever comes first, and the label then describes a site the gate may not have touched.

THE MUTANT PARSES. A mutant that is no valid Python breaks the import of every test file that reaches it,
and the gate reads a module that fails to collect as a kill. Such an operator would report KILLED for a
reason that has nothing to do with the defence it names.

THIS FILE STANDS IN THE GATE'S PER-MUTANT EXCLUSIONS (`_AUSSCHLUSS_JE_MUTANTE`). Under a mutant it reads
the mutated file, finds the operator's text gone and fails; the gate would take that for a kill of every
operator. It says nothing about one mutant, it says something about the list.
"""
from __future__ import annotations

import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _mutation_check():
    spec = importlib.util.spec_from_file_location("_mc_ein_ort", ROOT / "scripts" / "mutation_check.py")
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    return mc


def _befunde(operatoren, wurzel: Path) -> list[str]:
    """What is wrong with each operator against the tree at `wurzel`, one line per finding."""
    befunde = []
    for rel, alt, neu, label, _ in operatoren:
        pfad = wurzel / rel
        if not pfad.is_file():
            befunde.append(f"[{label}] {rel} is not in the tree")
            continue
        text = pfad.read_text(encoding="utf-8")
        paare = list(zip(alt, neu)) if isinstance(alt, tuple) else [(alt, neu)]
        if isinstance(alt, tuple) and (not isinstance(neu, tuple) or len(alt) != len(neu)):
            befunde.append(f"[{label}] names {len(alt)} sites and gives another number of replacements")
            continue
        mutiert = text
        for o, n in paare:
            anzahl = text.count(o)
            if anzahl != 1:
                befunde.append(f"[{label}] names {anzahl} sites of {rel}, not one: {o[:80]!r}")
            if o == n:
                befunde.append(f"[{label}] replaces a text by itself")
            mutiert = mutiert.replace(o, n, 1)
        if rel.endswith(".py") and mutiert != text:
            try:
                ast.parse(mutiert)
            except SyntaxError as exc:
                befunde.append(f"[{label}] its mutant of {rel} is no valid Python: {exc.msg}")
    return befunde


class EveryOperatorNamesOneSite(unittest.TestCase):

    def test_every_operator_names_exactly_one_site_and_its_mutant_parses(self) -> None:
        mc = _mutation_check()
        self.assertGreaterEqual(len(mc.MUTATIONS), 100, "the operator list collapsed; this check would pass on nothing")
        befunde = _befunde(mc.MUTATIONS, ROOT)
        self.assertEqual(befunde, [], "operators that do not name exactly one site of today's source:\n"
                         + "\n".join(befunde))

    def test_this_file_stands_in_the_gates_exclusions(self) -> None:
        self.assertIn(Path(__file__).stem, _mutation_check()._AUSSCHLUSS_JE_MUTANTE,
                      "under a mutant this check fails for every operator and would read as the killer of each")

    def test_control_a_stale_a_doubled_and_a_broken_operator_are_each_found(self) -> None:
        import tempfile  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as tmp:
            wurzel = Path(tmp)
            (wurzel / "m.py").write_text("def f(x):\n    if x is None:\n        return 1\n    return 2\n",
                                         encoding="utf-8")
            heil = ("m.py", "    if x is None:", "    if False:", "sound", True)
            self.assertEqual(_befunde([heil], wurzel), [])
            for operator, teil in ((("m.py", "    if x is not None:", "    if False:", "stale", True), "names 0 sites"),
                                   (("m.py", "return", "yield", "doubled", True), "names 2 sites"),
                                   (("m.py", "    if x is None:", "    if x is None", "broken", True),
                                    "no valid Python"),
                                   (("m.py", "    if x is None:", "    if x is None:", "same", True), "by itself"),
                                   (("gibt_es_nicht.py", "a", "b", "absent", True), "is not in the tree")):
                with self.subTest(operator=operator[3]):
                    befunde = _befunde([operator], wurzel)
                    self.assertTrue(any(teil in b for b in befunde), befunde)


if __name__ == "__main__":
    unittest.main()
