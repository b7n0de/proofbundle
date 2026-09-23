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
    """(line, left expression, container) for every unguarded membership test.

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


def _liest_aus_geparsten_daten(knoten: ast.AST) -> bool:
    """A heuristic, and it is named as one here: does this expression come from parsed data?

    Only the ``.get(...)`` call is measured — exactly the idiom with which this repository reads
    parsed JSON.

    WHY NOT THE INDEX ``x["k"]`` AS WELL, measured while building this on 2026-09-14: the first
    version counted it and immediately reported ``relation_statement.py:340``,
    ``sorted({v["code"] for v in _viol})``. That is a FALSE ALARM — ``_viol`` is built seven lines
    above, in-house, from the literals ``"code"`` and ``"message"``. An index says nothing about the
    ORIGIN of a value, and a guard that shouts at in-house data gets switched off; the comment on
    ``_ERSATZ_STAEMME`` in this house has warned about exactly that for weeks.

    HONEST LOWER BOUND, held as a contract rather than a footnote: an index on genuinely foreign
    data (``doc["x"]``) escapes this detector, and so does anyone who puts the value into a variable
    first. Sharpening that needs origin tracking (is the base a parameter, or derived from one?) —
    that is a piece of work in its own right, not a tightening done in passing.
    """
    for k in ast.walk(knoten):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr == "get"):
            return True
    return False


def _durch_isinstance_gedeckt(ausdruck: ast.AST, generatoren: list) -> bool:
    """Do the comprehension's ``if`` clauses hold an ``isinstance`` on EXACTLY this expression?"""
    ziel = ast.unparse(ausdruck)
    for g in generatoren:
        for bed in g.ifs:
            for k in ast.walk(bed):
                if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                        and k.func.id == "isinstance" and k.args
                        and ast.unparse(k.args[0]) == ziel):
                    return True
    return False


def unguarded_hashing_constructions(quelle: str, name: str = "<quelle>") -> list[tuple[int, str]]:
    """(line, hashed expression) for every site that hashes unchecked data while BUILDING a hash
    container.

    WHY THIS SECOND DETECTOR EXISTS, measured 2026-09-14. ``unguarded_membership_sites`` visits only
    ``ast.Compare`` with ``in``/``not in``, and additionally requires the container to be a
    MODULE-LEVEL name. Both conditions missed the same real site:

        zitiert = {a.get("stratum") for a in aa if isinstance(a, dict)}   # cap1.py:220

    The container is built LOCALLY, and the hashing happens not at the test but already in the
    comprehension — an unhashable ``stratum`` value raised a bare ``TypeError`` there. Against the
    full source of ``cap1.py`` the older scanner returned ZERO hits while the defect was
    reproducible by execution. A scanner that knows a class in only ONE of its shapes reports green
    and means "this shape does not occur".

    The module header of ``_membership.py`` says "with a scanner that fails on any new unguarded
    site". This detector is the part of that promise that was missing.
    """
    tree = ast.parse(quelle, filename=name)
    treffer: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.SetComp):
            gehasht, gen = node.elt, node.generators
        elif isinstance(node, ast.DictComp):
            gehasht, gen = node.key, node.generators
        else:
            continue
        if isinstance(gehasht, ast.Constant):
            continue
        if not _liest_aus_geparsten_daten(gehasht):
            continue
        if _durch_isinstance_gedeckt(gehasht, gen):
            continue
        treffer.append((node.lineno, ast.unparse(gehasht)))
    return treffer


def _grundlinie() -> dict:
    import json  # noqa: PLC0415
    return json.loads((REPO / "conformance" / "unguarded_hashing_constructions_baseline.json")
                      .read_text(encoding="utf-8"))


def _umschliessende_definition(quelle: str) -> dict[int, str]:
    """line -> qualified name of the enclosing def/class, otherwise '<modulebene>'.

    WHY THIS KEY COMPONENT EXISTS, measured 2026-09-15 by an adversarial lens. One version of this
    guard keyed on (file, expression) with a count. That made the budget LAUNDERABLE: close the
    carried, attacker-exposed site in ``derive_limitation_codes`` and open a NEW unguarded
    construction with the SAME expression elsewhere in the same file — the count stayed three, the
    guard stayed green, and the new code demonstrably raised
    ``TypeError: unhashable type: 'list'``. The old, line-bound rule WOULD have caught it. The name
    of the enclosing definition survives a line shift and still tells two sites apart: a new site
    lands in a different definition and is therefore new.
    """
    baum = ast.parse(quelle)
    karte: dict[int, str] = {}

    def geh(knoten: ast.AST, praefix: str) -> None:
        for k in ast.iter_child_nodes(knoten):
            if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{praefix}.{k.name}" if praefix else k.name
                for tief in ast.walk(k):
                    if hasattr(tief, "lineno"):
                        karte.setdefault(tief.lineno, name)
                geh(k, name)
            else:
                geh(k, praefix)

    geh(baum, "")
    return karte


def _gesehene_stellen(quelltexte: dict[str, str] | None = None) -> dict[tuple[str, str, str], list[int]]:
    """(file, enclosing definition, expression) -> lines.

    The lines are CARRIED ALONG so that a message can send a human to the right place — but they
    are NOT the key. Whoever makes them the key builds a gate that every merge re-arms without a
    single site having changed.

    AN EMPTY quelltexte IS AN ERROR, not an empty tree (lens finding P3, 2026-09-15): the check read
    ``is not None``, so an empty dict silently skipped the ENTIRE on-disk run and reported clean. A
    future caller passing only changed files would have walked into exactly that silent green.
    """
    if quelltexte is not None and not quelltexte:
        raise ValueError(
            "empty quelltexte: that would be a silent acquittal over an unexamined tree. "
            "For the full tree pass None, not {}")
    gesehen: dict[tuple[str, str, str], list[int]] = {}
    paare = (quelltexte.items() if quelltexte is not None
             else ((str(d.relative_to(SRC.parent)), d.read_text(encoding="utf-8"))
                   for d in sorted(SRC.rglob("*.py"))))
    for name, quelle in paare:
        wo = _umschliessende_definition(quelle)
        for zeile, ausdruck in unguarded_hashing_constructions(quelle, name):
            gesehen.setdefault((name, wo.get(zeile, "<modulebene>"), ausdruck), []).append(zeile)
    return gesehen


def _ueberzaehlige_stellen(quelltexte: dict[str, str] | None = None) -> list[str]:
    """What the baseline does NOT cover — per (file, expression) the count above the carried state."""
    import collections  # noqa: PLC0415
    getragen = collections.Counter(
        (e["file"], e["qualname"], e["expr"]) for e in _grundlinie()["carried"])
    funde: list[str] = []
    for schluessel, zeilen in sorted(_gesehene_stellen(quelltexte).items()):
        ueberzaehlig = len(zeilen) - getragen.get(schluessel, 0)
        if ueberzaehlig > 0:
            funde.append(f"{schluessel[0]}  in {schluessel[1]}()  {schluessel[2]}  "
                         f"{ueberzaehlig} of {len(zeilen)} not carried, lines {sorted(zeilen)}")
    return funde


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

    def test_no_source_file_builds_a_hash_container_from_unchecked_data(self):
        """THE LIVE GUARD FOR THE SECOND SHAPE. It catches what the membership scanner cannot see.

        Measured 2026-09-14: `cap1.py:220` built `{a.get("stratum") for a in aa ...}` from unchecked
        document values. The older scanner returned ZERO hits against the same file, because it
        knows only `in`/`not in` against MODULE-LEVEL containers. The defect was reproducible by
        execution at the same time. Green did not mean "does not occur" there, it meant "this shape
        is not measured".
        """
        funde = _ueberzaehlige_stellen()
        self.assertEqual(funde, [], "\n".join(
            ["a hash container is built from unchecked data — that hashes at CONSTRUCTION time, "
             "before any membership test runs. The seven pre-existing sites are named in "
             "conformance/unguarded_hashing_constructions_baseline.json, carried as "
             "(file, expression) with a count; IN EXCESS of that is:"] + funde))

    def test_die_grundlinie_weist_sich_als_luecke_aus_nicht_als_erlaubnis(self):
        """A baseline that reads as permission becomes permission.

        It must (a) say WHY it exists, (b) name the exposure per site or honestly mark it as NOT
        MEASURED, and (c) carry its own lower bound.
        """
        import json
        g = json.loads((REPO / "conformance" / "unguarded_hashing_constructions_baseline.json")
                       .read_text(encoding="utf-8"))
        self.assertIn("NAMED GAP, not permission", g["why_this_file_exists"])
        self.assertTrue(g["honest_limit"], "the lower bound is missing")
        for e in g["carried"]:
            marke = f"{e.get('file')}  {e.get('expr')}"
            self.assertTrue(e.get("file"), f"{e}: no field file")
            self.assertTrue(e.get("expr"), f"{marke}: no field expr — without the expression the "
                                           "entry cannot be matched once lines move")
            self.assertTrue(e.get("qualname"), f"{marke}: no field qualname — without the "
                                               "enclosing definition the budget can be laundered "
                                               "(lens finding 2026-09-15)")
            self.assertTrue(e.get("exposure"), f"{marke}: no statement about exposure")
            if not e.get("exposure_measured"):
                self.assertIn("NICHT GEMESSEN", e["exposure"],
                              f"{marke}: unmeasured, but does not say so")

    def test_die_grundlinie_ueberlebt_eine_zeilenverschiebung(self):
        """THE CASE THAT WAS RED ON 2026-09-15 — and that COULD go red before the class fix.

        Measured that day: merging origin/main into this branch added 19 lines to
        ``agent_review.py``. Not one of the seven carried sites changed, but all seven moved — and
        the guard reported its OWN baseline as seven new findings. The old rule compared
        ``file:line``; a line number is a property of the surrounding file, not of the site.

        Under the old rule this case would have produced seven findings, which makes it a genuine
        anti-case rather than a green witness: it can fall the moment someone binds to lines again.
        """
        verschoben = {str(d.relative_to(SRC.parent)): "\n" * 40 + d.read_text(encoding="utf-8")
                      for d in sorted(SRC.rglob("*.py"))}
        self.assertEqual(
            _ueberzaehlige_stellen(verschoben), [],
            "the baseline hangs on line numbers again — every merge re-arms the gate without a "
            "single site having changed")

    def test_eine_vierte_stelle_derselben_form_gilt_als_neu(self):
        """THE COUNTER-DIRECTION TO THE COUNT. Without it the class fix would be permission.

        The key is (file, definition, expression) — were the count not part of it, one carried entry
        would cover arbitrarily many further occurrences of the same shape in the SAME definition.
        ``derive_limitation_codes`` carries exactly ONE ``i.get('assurance')``; a second one there
        is new.
        """
        quelle = ("def derive_limitation_codes(xs):\n"
                  "    a = {i.get('assurance') for i in xs}\n"
                  "    b = {i.get('assurance') for i in xs}\n"
                  "    return a, b\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(len(funde), 1, funde)
        self.assertIn("1 of 2 not carried", funde[0])

    def test_eine_neue_definition_mit_getragenem_ausdruck_gilt_als_neu(self):
        """THE LAUNDERING RUN that an adversarial lens executed on 2026-09-15.

        It closed the carried, attacker-exposed site in ``derive_limitation_codes`` and opened a NEW
        unguarded construction with the SAME expression elsewhere in the same file. Under a key of
        (file, expression) the count stayed equal and the guard stayed green — while the new code
        demonstrably raised ``TypeError: unhashable type: 'list'``. The previous, line-bound rule
        would have caught it; on THIS axis the repair was therefore weaker than what it replaced.

        Exactly that movement is reproduced here: same file, same expression, same total — only a
        different enclosing definition. If this test stays green, the budget is launderable again.
        """
        quelle = ("def derive_limitation_codes(xs):\n"
                  "    return set()\n"
                  "\n"
                  "def _neu_und_ungeprueft(xs):\n"
                  "    return {i.get('assurance') for i in xs}\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(
            len(funde), 1,
            "a new definition carrying an already-carried expression does not count as new — the "
            f"budget can be laundered: {funde}")
        self.assertIn("_neu_und_ungeprueft", funde[0])

    def test_ein_leeres_quelltexte_ist_ein_fehler_kein_sauberer_baum(self):
        """Lens finding P3: ``is not None`` let an empty dict silently skip the whole on-disk run
        and report clean. A caller that passes only changed files and one day has none would have
        acquitted an unexamined tree with it."""
        with self.assertRaises(ValueError):
            _ueberzaehlige_stellen({})

    def test_die_grundlinie_traegt_keine_stelle_die_es_nicht_mehr_gibt(self):
        """A baseline that keeps carrying a closed site is permission held in reserve.

        The file says of itself: *every entry still has to be closed*. Close one and leave the entry
        standing, and from then on it covers a site that no longer exists — and the next one to
        reintroduce the same shape slips under it without a sound. Red here means: remove the entry,
        not the test.
        """
        import collections  # noqa: PLC0415
        getragen = collections.Counter(
            (e["file"], e["qualname"], e["expr"]) for e in _grundlinie()["carried"])
        gesehen = {k: len(v) for k, v in _gesehene_stellen().items()}
        tot = [f"{f}  in {q}()  {x}: getragen {n}, im Baum {gesehen.get((f, q, x), 0)}"
               for (f, q, x), n in sorted(getragen.items()) if gesehen.get((f, q, x), 0) < n]
        self.assertEqual(tot, [], "\n".join(
            ["the baseline carries sites that no longer occur in the tree — remove them:"] + tot))

    def test_a_planted_unguarded_construction_is_found(self):
        """PLANT-AND-MUST-CATCH for the second shape, the historical line verbatim."""
        quelle = ('def r8(doc, aa):\n'
                  '    zitiert = {a.get("stratum") for a in aa if isinstance(a, dict)}\n'
                  '    return zitiert\n')
        self.assertEqual(len(unguarded_hashing_constructions(quelle)), 1,
                         "the historical shape has to be caught")

    def test_anti_parity_a_guarded_construction_is_not_flagged(self):
        """THE COUNTER-DIRECTION. Check the value for str first and nothing unhashable is hashed."""
        quelle = ('def r8(aa):\n'
                  '    z = {a.get("stratum") for a in aa if isinstance(a.get("stratum"), str)}\n'
                  '    return z\n')
        self.assertEqual(unguarded_hashing_constructions(quelle), [])

    def test_anti_parity_a_literal_set_is_not_flagged(self):
        """A set literal hashes only what stands in the source — never foreign data."""
        self.assertEqual(unguarded_hashing_constructions('X = {"a", "b"}\n'), [])

    def test_UNTERGRENZE_ein_index_auf_fremde_daten_entgeht_dem_detektor(self):
        """THE BOUND AS A CONTRACT, deliberately GREEN although the case would be real.

        ``{doc["x"] for doc in docs}`` hashes foreign data just the same — the detector does not see
        it, because an index says nothing about origin, and the first, wider version produced a
        false alarm that was measured afterwards (``relation_statement.py:340``, an in-house list).
        Whoever later gets this contract RED has extended the detector with origin tracking and may
        rewrite it; whoever DELETES it because it is inconvenient has lost the bound and will not
        notice.
        """
        quelle = 'def f(docs):\n    return {doc["x"] for doc in docs}\n'
        self.assertEqual(unguarded_hashing_constructions(quelle), [],
                         "the lower bound has moved — rewrite the contract, do not delete it")

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
                # import-ORDER-robust: `from ._membership import as_dict, is_member` is isort-canonical,
                # so a literal-substring check for "_membership import is_member" false-flags a legitimate
                # multi-name import. The INTENT is unchanged — is_member must be imported from _membership
                # where it is called — and this regex checks exactly that regardless of the name order.
                import re as _re  # noqa: PLC0415
                self.assertTrue(
                    _re.search(r"_membership import [\w,\s]*\bis_member\b", text),
                    f"{pfad.name} calls is_member() but does not import it from _membership")


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


class TestTheGuardCannotRaiseItself(unittest.TestCase):
    """REGRESSION for the finding the mandatory review lane raised on 2026-08-26 (verdict REJECT).

    A guard whose entire contract is "never raises" must not have a shape that raises. The first
    version used `isinstance(value, Hashable)` alone, and that tests whether `__hash__` EXISTS, not
    whether calling it succeeds — a tuple inherits `__hash__` and only fails once it hashes its
    elements. Not reachable from `json.loads` today, which is a property of the CALLERS, not of this
    function; a guard that is only correct because of what happens to be passed to it is not a guard.
    """

    def setUp(self):
        import sys
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        from proofbundle._membership import is_member
        self.is_member = is_member

    def test_a_tuple_holding_an_unhashable_element_does_not_raise(self):
        self.assertFalse(self.is_member(("a", []), {"ok"}))
        self.assertFalse(self.is_member((1, {}), {"ok"}))
        self.assertFalse(self.is_member(((),[]), {"ok"}))

    def test_the_reviewers_dict_example_was_already_covered(self):
        # Recorded because half the finding did NOT hold: `dict.__hash__` is None, so the isinstance
        # check rejects it before any hashing. Keeping the measurement stops the wrong half from
        # being "re-discovered" later as a new defect.
        from collections.abc import Hashable
        self.assertFalse(isinstance({"a": []}, Hashable))
        self.assertFalse(self.is_member({"a": []}, {"ok"}))

    def test_anti_parity_a_hashable_tuple_still_works_normally(self):
        # Without this, an is_member that returned False for every tuple would pass the test above.
        self.assertTrue(self.is_member(("a", "b"), {("a", "b"), "x"}))
        self.assertFalse(self.is_member(("a", "b"), {"x"}))
