"""Gate-META-check for the ground-truth population and the nested-leaf matrix (deep gate iter 8, L3-05).

WHY THIS FILE EXISTS AT ALL. On 2026-08-26 the CI-blocking `type_confusion_gate` reported
`never_raise_ok=true` with zero violations while three of the surfaces it is responsible for crashed
with raw `TypeError`s on attacker-shaped JSON. Nothing was broken in a way anything could report: the
gate ran, exited 0, and was believed by every later lens. A gate that cannot fail is worse than no
gate, because it also removes the doubt.

So this file does NOT test the library. It tests THE GATE, in both places it was blind, and it does it
the only way that means anything: by PLANTING a defect and requiring the gate to go red.

  Half 1 — THE MUTATION SPACE. A surface with an unguarded membership test must be caught. Control:
           the guarded form of the same surface must NOT be caught, or a generator that flags
           everything would pass this file.

  Half 2 — THE POPULATION. A `verify_*` inside a class, one inside a subpackage, and a `validate_*`
           must all APPEAR in the ground-truth inventory. Control: a non-matching name must not.

Half 2 is the half that was missing from every earlier version of this fix, including its author's own
proposal. The nested-leaf matrix was built first, run, and reported zero — not because it did not work
but because the surfaces it was built for were never enumerated. A perfect generator finds nothing on a
surface that is not in the population, and that is indistinguishable from "there is nothing to find".

HOUSE RULE THIS ENCODES (Owner, 2026-08-26): at zero hits, first ask whether the object is in the
population, and only then turn the tool. Twice in one day is not an anecdote.
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in (REPO / "src", REPO / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import rust_parity_gate as rpg  # noqa: E402
import type_confusion_gate as tcg  # noqa: E402


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")


# --------------------------------------------------------------------------------------------------
# Half 1: the mutation space must catch a planted unguarded membership test.
# --------------------------------------------------------------------------------------------------

_PLANTED_SOURCE = '''
_ALLOWED = {"ok", "fail"}

def validate_planted_predicate(predicate):
    """A planted surface with the exact defect class of iteration 8."""
    errors = []
    if not isinstance(predicate, dict):
        return ["must be an object"]
    # THE DEFECT: `status` comes straight from attacker JSON and is hashed by the membership test.
    if "status" in predicate and predicate.get("status") not in _ALLOWED:
        errors.append("status must be one of %s" % sorted(_ALLOWED))
    return errors

def validate_guarded_predicate(predicate):
    """The CONTROL: same shape, same field, but the value is type-checked before it is hashed."""
    errors = []
    if not isinstance(predicate, dict):
        return ["must be an object"]
    st = predicate.get("status")
    if "status" in predicate and (not isinstance(st, str) or st not in _ALLOWED):
        errors.append("status must be one of %s" % sorted(_ALLOWED))
    return errors
'''


class _PlantedModule:
    """Registers a real module under a `proofbundle.`-prefixed name, backed by a real file.

    The gate reads field names out of the module's SOURCE (`__module__` -> `__file__` -> AST), so a
    function defined inline in this test file would yield no field names at all and the meta-check
    would pass VACUOUSLY — the very failure mode it is here to prevent. Nothing under src/ is touched.
    """

    NAME = "proofbundle.__planted_for_gate_meta_test"

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        datei = Path(self._tmp.name) / "planted.py"
        datei.write_text(_PLANTED_SOURCE, encoding="utf-8")
        modul = types.ModuleType(self.NAME)
        modul.__file__ = str(datei)
        exec(compile(_PLANTED_SOURCE, str(datei), "exec"), modul.__dict__)  # noqa: S102
        sys.modules[self.NAME] = modul
        tcg._FIELD_CACHE.pop(self.NAME, None)
        return modul

    def __exit__(self, *exc):
        sys.modules.pop(self.NAME, None)
        tcg._FIELD_CACHE.pop(self.NAME, None)
        self._tmp.cleanup()
        return False


class TestNestedLeafMatrixCatchesAPlantedDefect(unittest.TestCase):
    def test_planted_unguarded_membership_test_is_caught(self):
        with _PlantedModule() as modul:
            violations, n, _ = tcg._exercise_nested(modul.validate_planted_predicate, {})
        self.assertGreater(n, 0, "no nested payloads were generated — the check would be vacuous")
        self.assertTrue(violations, "the planted unguarded membership test was NOT caught")
        self.assertTrue(any("unhashable" in v for v in violations), violations)

    def test_anti_parity_the_guarded_form_is_not_caught(self):
        # Without this, a generator that reports every surface as broken would pass the test above.
        with _PlantedModule() as modul:
            violations, n, _ = tcg._exercise_nested(modul.validate_guarded_predicate, {})
        self.assertGreater(n, 0)
        self.assertEqual(violations, [], "the CONTROL was flagged — the generator flags too much")

    def test_whole_argument_matrix_alone_would_miss_it(self):
        # The measured reason the old gate was vacuous: pass-one payloads never survive the outer
        # shape check, so no inner validator ever runs. If this ever starts finding the planted
        # defect, the two passes have converged and the second one's justification must be re-read.
        with _PlantedModule() as modul:
            alt = tcg._exercise(modul.validate_planted_predicate, {}, tcg.TYPE_CONFUSION_PAYLOADS)
        self.assertEqual(alt, [], "pass one now catches it; the docstring's rationale is stale")

    def test_depth_two_is_reached(self):
        # `run_ledger`'s membership test only runs per entry under `runs`, i.e. at depth 2. A fixed
        # depth of 1 misses it silently — this asserts the second depth is actually generated.
        with _PlantedModule() as modul:
            pfade = {p for _, p in tcg._depth2_payloads(modul.validate_planted_predicate, set())[0]}
        self.assertTrue(any("[0]." in p for p in pfade), "no depth-2 payload was generated")


# --------------------------------------------------------------------------------------------------
# Half 2: the population must enumerate the shapes it used to exclude.
# --------------------------------------------------------------------------------------------------

class TestPopulationEnumeratesEveryDecidingShape(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        src = Path(self._tmp.name)
        _write(src / "top.py", """\
            def verify_top(x): return True
            def validate_top_predicate(x): return []
            def helper_top(x): return True
            def _verify_private(x): return True

            class Holder:
                def verify_method(self): return True
                def validate_method_predicate(self): return []
                def unrelated(self): return True
        """)
        _write(src / "sub" / "__init__.py", "")
        _write(src / "sub" / "deep.py", """\
            def verify_in_subpackage(x): return True
            def validate_in_subpackage(x): return []
        """)
        self.found = rpg.discover_python_verify_functions(src)

    def tearDown(self):
        self._tmp.cleanup()

    def test_validate_prefixed_function_is_enumerated(self):
        # Two of the four confirmed iteration-8 defects live on `validate_*` surfaces.
        self.assertIn("proofbundle.top.validate_top_predicate", self.found)

    def test_verify_method_inside_a_class_is_enumerated(self):
        self.assertIn("proofbundle.top.Holder.verify_method", self.found)

    def test_validate_method_inside_a_class_is_enumerated(self):
        self.assertIn("proofbundle.top.Holder.validate_method_predicate", self.found)

    def test_surface_inside_a_subpackage_is_enumerated(self):
        self.assertIn("proofbundle.sub.deep.verify_in_subpackage", self.found)
        self.assertIn("proofbundle.sub.deep.validate_in_subpackage", self.found)

    def test_anti_parity_unrelated_names_are_still_excluded(self):
        # A population that enumerates EVERYTHING would pass all of the above and mean nothing.
        for nicht in ("proofbundle.top.helper_top", "proofbundle.top._verify_private",
                      "proofbundle.top.Holder.unrelated"):
            self.assertNotIn(nicht, self.found)

    def test_every_enumerated_name_actually_resolves(self):
        # A name in the population that cannot be resolved is the same vacuity one layer down: the
        # consumer records IMPORT_ERROR and moves on. Measured against the REAL tree, not the fixture.
        echt = rpg.discover_python_verify_functions()
        self.assertGreaterEqual(len(echt), 57)
        for qname in echt:
            with self.subTest(qname=qname):
                self.assertTrue(callable(rpg.resolve_surface(qname)))

    def test_the_two_confirmed_iteration8_surfaces_are_in_the_real_population(self):
        # The concrete regression guard: these two were NOT enumerated before this fix, which is why
        # a correct generator reported zero against them.
        echt = rpg.discover_python_verify_functions()
        self.assertIn("proofbundle.outcome.validate_outcome_predicate", echt)
        self.assertIn("proofbundle.run_ledger.validate_run_ledger_predicate", echt)


if __name__ == "__main__":
    unittest.main()
