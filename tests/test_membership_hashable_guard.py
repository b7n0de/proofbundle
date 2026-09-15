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


def _liest_aus_geparsten_daten(knoten: ast.AST) -> bool:
    """Heuristik, und sie wird hier als solche benannt: kommt dieser Ausdruck aus geparsten Daten?

    Gemessen wird ausschliesslich der ``.get(...)``-Aufruf, also genau das Idiom, mit dem dieses
    Repository geparstes JSON liest.

    WARUM NICHT AUCH DER INDEX ``x["k"]``, gemessen beim Bauen am 14.09.2026: die erste Fassung
    zaehlte ihn mit und meldete sofort ``relation_statement.py:340``,
    ``sorted({v["code"] for v in _viol})``. Das ist ein FEHLALARM — ``_viol`` wird sieben Zeilen
    darueber im Haus selbst gebaut, mit den Literalen ``"code"`` und ``"message"``. Der Index sagt
    nichts ueber die HERKUNFT des Werts, und ein Riegel, der bei hauseigenen Daten schreit, wird
    abgeschaltet; genau davor warnt der Kommentar zu ``_ERSATZ_STAEMME`` in diesem Haus seit Wochen.

    EHRLICHE UNTERGRENZE, als Vertrag festgehalten statt als Fussnote: ein Index auf wirklich
    fremde Daten (``doc["x"]``) entgeht diesem Detektor, und wer den Wert vorher in eine Variable
    legt, ebenfalls. Wer das schaerfen will, braucht eine Herkunftsverfolgung (ist die Basis ein
    Parameter oder aus einem Parameter abgeleitet?) — das ist eine eigene Arbeit und keine
    Nebenbei-Verschaerfung.
    """
    for k in ast.walk(knoten):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr == "get"):
            return True
    return False


def _durch_isinstance_gedeckt(ausdruck: ast.AST, generatoren: list) -> bool:
    """Steht in den ``if``-Klauseln der Comprehension ein ``isinstance`` GENAU auf diesen Ausdruck?"""
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
    """(Zeile, gehashter Ausdruck) je Stelle, die beim AUFBAU eines Hash-Behaelters ungepruefte
    Daten hasht.

    WARUM ES DIESEN ZWEITEN DETEKTOR GIBT, gemessen am 14.09.2026. ``unguarded_membership_sites``
    besucht ausschliesslich ``ast.Compare`` mit ``in``/``not in`` und verlangt ausserdem, dass der
    Behaelter ein MODULWEITER Name ist. Beide Bedingungen verfehlten dieselbe echte Stelle:

        zitiert = {a.get("stratum") for a in aa if isinstance(a, dict)}   # cap1.py:220

    Der Behaelter entsteht LOKAL, und gehasht wird nicht im Test, sondern schon in der
    Comprehension — ein unhashbarer ``stratum``-Wert loeste dort ein rohes ``TypeError`` aus. Gegen
    den vollen Quelltext von ``cap1.py`` lieferte der alte Scanner NULL Treffer, waehrend der
    Defekt ausfuehrbar reproduzierbar war. Ein Scanner, der eine Klasse nur in EINER ihrer Formen
    kennt, meldet gruen und meint "diese Form kommt nicht vor".

    Der Modulkopf von ``_membership.py`` sagt "with a scanner that fails on any new unguarded
    site". Dieser Detektor ist der Teil dieser Zusage, der gefehlt hat.
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


def _gesehene_stellen(quelltexte: dict[str, str] | None = None) -> dict[tuple[str, str], list[int]]:
    """(Datei, Ausdruck) -> Zeilen, ueber den ganzen Quellbaum oder ueber gestellte Quelltexte.

    Die Zeilen werden MITGEFUEHRT, damit eine Meldung einen Menschen hinschickt — aber sie sind
    NICHT der Schluessel. Wer sie zum Schluessel macht, baut ein Tor, das jeder Merge neu scharf
    stellt, ohne dass sich eine einzige Stelle geaendert haette.
    """
    gesehen: dict[tuple[str, str], list[int]] = {}
    paare = (quelltexte.items() if quelltexte is not None
             else ((str(d.relative_to(SRC.parent)), d.read_text(encoding="utf-8"))
                   for d in sorted(SRC.rglob("*.py"))))
    for name, quelle in paare:
        for zeile, ausdruck in unguarded_hashing_constructions(quelle, name):
            gesehen.setdefault((name, ausdruck), []).append(zeile)
    return gesehen


def _ueberzaehlige_stellen(quelltexte: dict[str, str] | None = None) -> list[str]:
    """Was die Grundlinie NICHT deckt — je (Datei, Ausdruck) die Anzahl ueber dem getragenen Stand."""
    import collections  # noqa: PLC0415
    getragen = collections.Counter((e["file"], e["expr"]) for e in _grundlinie()["carried"])
    funde: list[str] = []
    for schluessel, zeilen in sorted(_gesehene_stellen(quelltexte).items()):
        ueberzaehlig = len(zeilen) - getragen.get(schluessel, 0)
        if ueberzaehlig > 0:
            funde.append(f"{schluessel[0]}  {schluessel[1]}  "
                         f"{ueberzaehlig} von {len(zeilen)} nicht getragen, Zeilen {sorted(zeilen)}")
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
        """DER LIVE-GUARD FUER DIE ZWEITE FORM. Er faengt, was der Mitgliedstest-Scanner nicht sieht.

        Gemessen 14.09.2026: `cap1.py:220` baute `{a.get("stratum") for a in aa ...}` aus
        ungeprueften Dokumentwerten. Der aeltere Scanner lieferte gegen dieselbe Datei NULL
        Treffer, weil er nur `in`/`not in` gegen MODULWEITE Behaelter kennt. Der Defekt war
        gleichzeitig ausfuehrbar reproduzierbar. Gruen hiess dort nicht "kommt nicht vor",
        sondern "diese Form wird nicht gemessen".
        """
        funde = _ueberzaehlige_stellen()
        self.assertEqual(funde, [], "\n".join(
            ["ein Hash-Behaelter wird aus ungeprueften Daten gebaut — das hasht beim AUFBAU, "
             "bevor irgendein Mitgliedstest laeuft. Die sieben Bestandsstellen stehen namentlich "
             "in conformance/unguarded_hashing_constructions_baseline.json, gefuehrt als "
             "(Datei, Ausdruck) mit Anzahl; UEBERZAEHLIG ist:"] + funde))

    def test_die_grundlinie_weist_sich_als_luecke_aus_nicht_als_erlaubnis(self):
        """Eine Grundlinie, die sich als Erlaubnis liest, wird zur Erlaubnis.

        Sie muss (a) sagen, WARUM es sie gibt, (b) je Stelle die Exponiertheit benennen oder sie
        ehrlich als NICHT GEMESSEN markieren, und (c) ihre eigene Untergrenze tragen.
        """
        import json
        g = json.loads((REPO / "conformance" / "unguarded_hashing_constructions_baseline.json")
                       .read_text(encoding="utf-8"))
        self.assertIn("NAMED GAP, not permission", g["why_this_file_exists"])
        self.assertTrue(g["honest_limit"], "die Untergrenze fehlt")
        for e in g["carried"]:
            marke = f"{e.get('file')}  {e.get('expr')}"
            self.assertTrue(e.get("file"), f"{e}: kein Feld file")
            self.assertTrue(e.get("expr"), f"{marke}: kein Feld expr — ohne Ausdruck ist der "
                                           "Eintrag nicht zuordenbar, sobald Zeilen wandern")
            self.assertTrue(e.get("exposure"), f"{marke}: keine Aussage zur Exponiertheit")
            if not e.get("exposure_measured"):
                self.assertIn("NICHT GEMESSEN", e["exposure"],
                              f"{marke}: ungemessen, sagt es aber nicht")

    def test_die_grundlinie_ueberlebt_eine_zeilenverschiebung(self):
        """DER FALL, DER AM 15.09.2026 ROT WAR — und der vor dem Klassenfix rot werden KONNTE.

        Gemessen an diesem Tag: der Merge von origin/main in diesen Zweig fuegte
        ``agent_review.py`` 19 Zeilen hinzu. Keine einzige der sieben getragenen Stellen aenderte
        sich, aber alle sieben wanderten — und der Riegel meldete seine EIGENE Grundlinie als
        sieben neue Funde. Die alte Regel verglich ``datei:zeile``; eine Zeilennummer ist eine
        Eigenschaft der umgebenden Datei, nicht der Stelle.

        Dieser Fall haette mit der alten Regel sieben Funde ergeben und ist damit ein echter
        Anti-Fall, kein gruener Zeuge: er kann fallen, sobald jemand wieder an die Zeile bindet.
        """
        verschoben = {str(d.relative_to(SRC.parent)): "\n" * 40 + d.read_text(encoding="utf-8")
                      for d in sorted(SRC.rglob("*.py"))}
        self.assertEqual(
            _ueberzaehlige_stellen(verschoben), [],
            "die Grundlinie haengt wieder an Zeilennummern — jeder Merge stellt das Tor neu scharf, "
            "ohne dass sich eine Stelle geaendert haette")

    def test_eine_vierte_stelle_derselben_form_gilt_als_neu(self):
        """DIE GEGENRICHTUNG ZUR ANZAHL. Ohne sie waere der Klassenfix eine Erlaubnis.

        Der Schluessel ist (Datei, Ausdruck) — waere er das ALLEIN, deckte ein getragener Eintrag
        beliebig viele weitere Vorkommen derselben Form in derselben Datei. Die Anzahl ist, was die
        Regel scharf haelt: drei getragene ``i.get('assurance')`` in ``agent_review.py`` erlauben
        genau drei, das vierte ist NEU.
        """
        quelle = ("def f(xs):\n"
                  "    a = {i.get('assurance') for i in xs}\n"
                  "    b = {i.get('assurance') for i in xs}\n"
                  "    c = {i.get('assurance') for i in xs}\n"
                  "    d = {i.get('assurance') for i in xs}\n"
                  "    return a, b, c, d\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(len(funde), 1, funde)
        self.assertIn("1 von 4 nicht getragen", funde[0])

    def test_die_grundlinie_traegt_keine_stelle_die_es_nicht_mehr_gibt(self):
        """Eine Grundlinie, die eine geschlossene Stelle weiter traegt, ist eine Erlaubnis auf Vorrat.

        Die Datei sagt von sich: *jeder Eintrag muss noch geschlossen werden*. Wird einer
        geschlossen und der Eintrag bleibt stehen, deckt er ab da eine Stelle, die es nicht mehr
        gibt — und die naechste, die dieselbe Form wieder einfuehrt, faellt lautlos darunter.
        Rot heisst hier: Eintrag entfernen, nicht Test entfernen.
        """
        import collections  # noqa: PLC0415
        getragen = collections.Counter((e["file"], e["expr"]) for e in _grundlinie()["carried"])
        gesehen = {k: len(v) for k, v in _gesehene_stellen().items()}
        tot = [f"{f}  {x}: getragen {n}, im Baum {gesehen.get((f, x), 0)}"
               for (f, x), n in sorted(getragen.items()) if gesehen.get((f, x), 0) < n]
        self.assertEqual(tot, [], "\n".join(
            ["die Grundlinie traegt Stellen, die im Baum nicht mehr vorkommen — entfernen:"] + tot))

    def test_a_planted_unguarded_construction_is_found(self):
        """PLANT-AND-MUST-CATCH fuer die zweite Form, woertlich die historische Zeile."""
        quelle = ('def r8(doc, aa):\n'
                  '    zitiert = {a.get("stratum") for a in aa if isinstance(a, dict)}\n'
                  '    return zitiert\n')
        self.assertEqual(len(unguarded_hashing_constructions(quelle)), 1,
                         "die historische Form muss gefangen werden")

    def test_anti_parity_a_guarded_construction_is_not_flagged(self):
        """DIE GEGENRICHTUNG. Wer den Wert vorher auf str prueft, hasht nichts Unhashbares."""
        quelle = ('def r8(aa):\n'
                  '    z = {a.get("stratum") for a in aa if isinstance(a.get("stratum"), str)}\n'
                  '    return z\n')
        self.assertEqual(unguarded_hashing_constructions(quelle), [])

    def test_anti_parity_a_literal_set_is_not_flagged(self):
        """Ein Mengenliteral hasht nur, was im Quelltext steht — nie fremde Daten."""
        self.assertEqual(unguarded_hashing_constructions('X = {"a", "b"}\n'), [])

    def test_UNTERGRENZE_ein_index_auf_fremde_daten_entgeht_dem_detektor(self):
        """DIE GRENZE ALS VERTRAG, absichtlich GRUEN obwohl der Fall echt waere.

        ``{doc["x"] for doc in docs}`` hasht fremde Daten genauso — der Detektor sieht es nicht,
        weil ein Index nichts ueber die Herkunft sagt und die erste, weitere Fassung dadurch einen
        nachgemessenen Fehlalarm erzeugte (``relation_statement.py:340``, hauseigene Liste).
        Wer diesen Vertrag spaeter ROT bekommt, hat den Detektor um eine Herkunftsverfolgung
        erweitert und darf ihn neu schreiben; wer ihn LOESCHT, weil er unbequem ist, hat die
        Grenze verloren und merkt es nicht mehr.
        """
        quelle = 'def f(docs):\n    return {doc["x"] for doc in docs}\n'
        self.assertEqual(unguarded_hashing_constructions(quelle), [],
                         "die Untergrenze hat sich verschoben — Vertrag neu schreiben, nicht loeschen")

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
