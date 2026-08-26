"""No unguarded membership test on attacker data (deep gate iteration 8, L3-01..L3-04).

THE CLASS, stated as the violated assumption: *a value taken from parsed JSON is hashable.* It is
not. `set` / `dict` / `frozenset` membership HASHES the left operand, so

    if predicate.get("status") not in _OUTCOME_STATUS:   # a set

raises a bare ``TypeError: unhashable type: 'list'`` on ``{"status": []}`` — before any signature is
checked, out of a function whose contract is "returns a verdict or raises ProofBundleError".
Iteration 8 confirmed it on four surfaces including the flagship ``verify_bundle``.

WHY A SCANNER AND NOT 27 REVIEWED DIFFS. The 27 sites are fixed; the scanner is what stops the 28th.
This repository has paid for the instance fix three times already (statuslist.py:122, kbjwt.py:151,
kbjwt.py:230) — each time the outer argument was hardened and an inner field kept crashing. A diff
review cannot see a site that does not exist yet.

THE CONTAINER TYPE IS MEASURED FROM THE AST, NOT LISTED. That is the load-bearing decision, and it
is what covers the 25 `tuple`/`list` neighbours WITHOUT touching them today: they do not hash, so
they are not violations now — but the day someone changes ``_ALLOWED = ("a", "b")`` to
``_ALLOWED = {"a", "b"}`` for speed, every membership test against it becomes a violation and this
scanner turns red in the same commit. A hand-maintained list of "dangerous containers" would have to
be updated by exactly the person who forgot.

HONEST LIMIT: this scans `src/proofbundle/**`, module-level container constants, and single-operator
comparisons. A container built at runtime, imported from another module, or a chained comparison is
NOT covered — that is stated here rather than left for someone to discover, and `is_member` is safe
to use everywhere regardless.
"""
from __future__ import annotations

import ast
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"

_HASHING = {"set", "dict", "frozenset"}


def _hashing_containers(tree: ast.Module) -> dict[str, str]:
    """Module-level names bound to a hash-based container — the ones whose membership test hashes."""
    gefunden: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        ziele = node.targets if isinstance(node, ast.Assign) else [node.target]
        wert = node.value
        if wert is None:
            continue
        art = None
        if isinstance(wert, (ast.Set, ast.SetComp)):
            art = "set"
        elif isinstance(wert, (ast.Dict, ast.DictComp)):
            art = "dict"
        elif (isinstance(wert, ast.Call) and isinstance(wert.func, ast.Name)
                and wert.func.id in ("set", "frozenset", "dict")):
            art = wert.func.id
        if art in _HASHING:
            for t in ziele:
                if isinstance(t, ast.Name):
                    gefunden[t.id] = art
    return gefunden


def unguarded_membership_sites(quelle: str, name: str = "<quelle>") -> list[tuple[int, str, str]]:
    """(Zeile, linker Ausdruck, Behälter) für jeden ungeschützten Mitgliedstest.

    A CONSTANT left operand is skipped on purpose: ``"status" in predicate`` asks whether a KEY is
    present, the left side is a literal string, and a literal is always hashable. Flagging it would
    make the scanner noisy exactly where it is always right, and a noisy scanner gets silenced."""
    tree = ast.parse(quelle, filename=name)
    behaelter = _hashing_containers(tree)
    treffer: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
            continue
        rechts = node.comparators[0]
        if not isinstance(rechts, ast.Name) or rechts.id not in behaelter:
            continue
        if isinstance(node.left, ast.Constant):
            continue
        treffer.append((node.lineno, ast.unparse(node.left), rechts.id))
    return treffer


class TestNoUnguardedMembershipInTheTree(unittest.TestCase):
    def test_no_source_file_hashes_attacker_data_in_a_membership_test(self):
        befunde = []
        for pfad in sorted(SRC.rglob("*.py")):
            if "__pycache__" in pfad.parts or pfad.name == "_membership.py":
                continue
            for zeile, links, cont in unguarded_membership_sites(
                    pfad.read_text(encoding="utf-8"), str(pfad)):
                befunde.append(f"{pfad.relative_to(SRC.parent)}:{zeile}  {links} in {cont}")
        self.assertEqual(
            befunde, [],
            "unguarded membership test(s) on a hashing container — route through "
            "proofbundle._membership.is_member:\n  " + "\n  ".join(befunde))

    def test_the_guard_is_actually_imported_where_it_is_used(self):
        # A call to a name that was never imported is a NameError at runtime, i.e. a crash in the
        # very code path meant to prevent one. Cheap to check, expensive to discover in production.
        for pfad in sorted(SRC.rglob("*.py")):
            if "__pycache__" in pfad.parts or pfad.name == "_membership.py":
                continue
            text = pfad.read_text(encoding="utf-8")
            if "is_member(" not in text:
                continue
            with self.subTest(datei=str(pfad.relative_to(SRC.parent))):
                self.assertIn("_membership import is_member", text)


class TestTheScannerActuallyCatches(unittest.TestCase):
    """Plant-and-must-catch, both directions. Without this the file above proves only that the tree
    is clean OR that the scanner is blind, and those two look identical from the outside."""

    def test_a_planted_unguarded_site_is_found(self):
        gepflanzt = textwrap.dedent('''
            _ALLOWED = {"ok", "fail"}
            def validate(p):
                return "status" in p and p.get("status") not in _ALLOWED
        ''')
        treffer = unguarded_membership_sites(gepflanzt)
        self.assertEqual(len(treffer), 1, treffer)
        self.assertEqual(treffer[0][2], "_ALLOWED")

    def test_anti_parity_the_guarded_form_is_not_flagged(self):
        # Without this, a scanner that flags EVERY membership test would pass the test above and
        # then be silenced by the first person who has to look at its output.
        geschuetzt = textwrap.dedent('''
            from ._membership import is_member
            _ALLOWED = {"ok", "fail"}
            def validate(p):
                return "status" in p and not is_member(p.get("status"), _ALLOWED)
        ''')
        self.assertEqual(unguarded_membership_sites(geschuetzt), [])

    def test_anti_parity_a_key_presence_test_is_not_flagged(self):
        # `"status" in predicate` is the single most common membership test in this codebase and is
        # never a defect: the left side is a literal, and a literal is always hashable.
        harmlos = textwrap.dedent('''
            _ALLOWED = {"ok"}
            def validate(p):
                return "status" in p and "x" in _ALLOWED
        ''')
        self.assertEqual(unguarded_membership_sites(harmlos), [])

    def test_a_tuple_container_is_not_flagged_today(self):
        # Today's honest state: a tuple does not hash, so this cannot raise.
        mit_tuple = textwrap.dedent('''
            _ALLOWED = ("ok", "fail")
            def validate(p):
                return p.get("status") not in _ALLOWED
        ''')
        self.assertEqual(unguarded_membership_sites(mit_tuple), [])

    def test_the_same_site_IS_flagged_once_that_tuple_becomes_a_set(self):
        # THE POINT OF MEASURING THE CONTAINER TYPE. `statuslist._ALLOWED_BITS` and
        # `policy._SUPPORTED_SCHEMAS` are tuples and therefore only ACCIDENTALLY safe; iteration 8
        # named exactly that. A tuple -> set change for speed silently arms this defect class, and
        # this assertion is what makes that change loud instead of silent.
        als_set = textwrap.dedent('''
            _ALLOWED = {"ok", "fail"}
            def validate(p):
                return p.get("status") not in _ALLOWED
        ''')
        self.assertEqual(len(unguarded_membership_sites(als_set)), 1)


class TestTheGuardItself(unittest.TestCase):
    def setUp(self):
        import sys
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        from proofbundle._membership import is_member
        self.is_member = is_member

    def test_unhashable_values_answer_False_instead_of_raising(self):
        for wert in ([], {}, set(), [1], {"a": 1}):
            with self.subTest(wert=repr(wert)):
                self.assertFalse(self.is_member(wert, {"ok", "fail"}))

    def test_a_real_member_still_answers_True(self):
        # The anti-parity half of the guard: one that always returned False would pass everything
        # above and quietly accept every value as invalid.
        self.assertTrue(self.is_member("ok", {"ok", "fail"}))
        self.assertTrue(self.is_member("k", {"k": 1}))

    def test_non_members_answer_False(self):
        self.assertFalse(self.is_member("nope", {"ok", "fail"}))

    def test_it_works_unchanged_on_containers_that_do_not_hash(self):
        # So routing tuple/list sites through it later is a no-op, not a behaviour change.
        self.assertTrue(self.is_member("ok", ("ok", "fail")))
        self.assertFalse(self.is_member([], ["ok"]))


class TestScannerOnADisposableTree(unittest.TestCase):
    def test_it_reads_real_files_not_only_strings(self):
        # The tree scan above walks files; if the file-reading path were broken it would report an
        # empty list and look like a clean tree. Same vacuity, one layer down.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "planted.py"
            p.write_text('_A = {"x"}\ndef f(o):\n    return o.get("k") in _A\n', encoding="utf-8")
            self.assertEqual(len(unguarded_membership_sites(p.read_text(encoding="utf-8"), str(p))), 1)


if __name__ == "__main__":
    unittest.main()
