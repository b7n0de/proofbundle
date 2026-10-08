"""Every public surface that takes an ALREADY-PARSED structure must reach the structural budget.

THE CLASS (deep gate wf_cfe249d0-ee8, finding L2-01, P1). ``loads_strict`` owns the ``input_bytes`` cap,
but that cap is a FILE proxy: on the DIRECT-DICT path there are no bytes to measure, so it is inert. A
surface that accepts a parsed ``dict`` and then decodes, expands or copies something proportional to its
size is therefore unbounded — measured on ``verify_evidence_pack``, a payload ONE unit over the
``string_len`` limit still allocated 2.6 MB in 0.095 s before failing for an unrelated reason.

WHY THIS FILE IS A DERIVATION AND NOT A LIST. The finding is explicit that wiring a 6th, 7th, ... call
site is the INSTANCE fix and re-opens on the next added surface. So the population is DERIVED here — from
the signatures in ``src/proofbundle`` — and the property is REACHABILITY in the static call graph, not
"the call appears in this function's own body". A surface that delegates to ``verify_bundle`` is covered
by that delegation, and demanding a literal call in every body would produce false findings that push
people to weaken the check.

THE THIRD STATE IS NOT GREEN. A first parameter with no annotation makes membership UNDECIDABLE. Such a
surface is neither passed nor silently dropped: it is reported, because "we could not tell" has been the
shape of every fail-open in this ledger. It is listed explicitly so the list can only shrink by ANNOTATING
a surface, never by forgetting one.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import unittest

from _pytest.outcomes import Skipped

QUELLE = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"
ZIEL = "enforce_structural_budget"
_STRUKTUR = ("dict", "Mapping", "list", "Sequence", "Any")

# Surfaces whose first parameter is unannotated. Each entry states WHY it is not a direct-dict surface.
# This is an explicit-exclusion list with a reason per entry, never a way to make a finding disappear.
_UNANNOTIERT_ERWARTET = {
    "anchors.verify_anchors": "nimmt eine Liste von Anker-Absichten, keine geparste Fremdstruktur",
    "evalcard.verify_evaluation_card": "nimmt einen PFAD — parst selbst ueber loads_strict",
    "prereg.verify_prereg": "nimmt einen PFAD — parst selbst ueber loads_strict",
}

# Flaechen, die eine EIGENE fachliche Schranke tragen statt der generischen. Der Wert ist die
# Budget-Dimension, und sie wird NACHGEWIESEN (siehe test_eine_eigene_schranke_wird_belegt) — ein
# Ausschluss ohne Beleg waere genau der Weg, auf dem eine ungeschuetzte Flaeche hier verschwindet.
_EIGENE_SCHRANKE = {
    "renewal.verify_sequence": (
        "renewal_ats_chain",
        "nimmt list[list[ArchiveTimeStamp]] — TYPISIERTE Objekte, kein rohes geparstes JSON. Die "
        "Elemente sind per Shape-Guard ArchiveTimeStamp-Instanzen; enforce_structural_budget wuerde "
        "ueber sie hinweglaufen (weder str noch dict noch list) und nur die Listenlaenge messen, und "
        "die gegen json_nodes = 200.000, also 20-fach LOSER als die eigene Dimension. Der Einbau "
        "haette diesen Riegel gruen gemacht, ohne irgendetwas zu schuetzen. — WAS HIER FRUEHER ZU "
        "VIEL STAND (korrigiert 2026-09-05, deep gate 6.0.0, L2-600-01): der Satz nannte die Kette "
        "'bereits fachlich und schaerfer begrenzt' und meinte damit auch die KOSTEN. Gemessen war "
        "das falsch — am groessten zugelassenen Wert (10.000; die Pruefung ist value <= limit) "
        "kostete der Durchlauf 59,5 s Rechenzeit, waehrend 10.001 Eintraege in 0,002 s abgewiesen "
        "wurden. Eine Zahlenschranke ist erst dann eine Kostenschranke, wenn die Kosten AN IHR "
        "gemessen sind. Genau das ist die Bedingung, die dieser Ausschluss jetzt traegt, und sie "
        "wird unten gegen tests/test_budget_kostenkurve.py geprueft."),
}

# Die Kostenkurve, gegen die eine eigene Schranke belegt wird. Ihr eigener Test
# `test_keine_dimension_ohne_last` leitet die Menge der gemessenen Dimensionen aus
# `VerificationBudget` ab — deshalb genuegt hier der Nachweis, dass die Datei die Dimension nennt:
# dass die Menge VOLLSTAENDIG ist, sichert sie selbst.
KOSTENKURVE = pathlib.Path(__file__).resolve().parent / "test_budget_kostenkurve.py"


def _lokal_gebunden(fn: ast.AST) -> set[str]:
    """Namen, die INNERHALB dieser Funktion an etwas gebunden werden (Zuweisung, with-as, Parameter, ...).

    Ein so gebundener Name ist NICHT die gleichnamige Funktion eines anderen Moduls.
    """
    gebunden: set[str] = set()
    for arg in getattr(getattr(fn, "args", None), "args", []) or []:
        gebunden.add(arg.arg)
    for x in ast.walk(fn):
        if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
            gebunden.add(x.id)
        elif isinstance(x, ast.AnnAssign) and isinstance(x.target, ast.Name):
            gebunden.add(x.target.id)
        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) and x is not fn:
            gebunden.add(x.name)
    return gebunden


def _aufrufgraph() -> dict[str, set[str]]:
    """(modul.funktion) -> aufgerufene (modul.funktion). MODULQUALIFIZIERT, und das ist der Punkt.

    Die erste Fassung war namensbasiert und "bewusst weit". Weit war der falsche Fehler: eine unqualifizierte
    Kante erzeugt keine Fehlmeldung, sondern FALSCHE DECKUNG. Live gemessen am 2026-08-08 — ``renewal.py``
    bindet eine LOKALE Variable ``verify_anchor`` (Z. 547/550/553) an einen Callable-Parameter; sobald
    ``anchors.verify_anchor`` den Riegel bekam, galt ``renewal.verify_sequence`` schlagartig als gedeckt,
    ohne dass sich an ihr irgendetwas geaendert hatte. Der Riegel gegen fake-green war selbst fake-green.

    Aufloesung, konservativ in die richtige Richtung: erst im EIGENEN Modul, sonst nur bei einer repo-weit
    EINDEUTIGEN Definition, und niemals fuer einen Namen, der in der Funktion lokal gebunden wird. Bleibt
    ein Aufruf unaufloesbar, entsteht KEINE Kante — dann meldet der Riegel im Zweifel einen Fund statt eine
    Deckung. Ein Fehlbefund kostet eine Minute Nachsehen; eine falsche Deckung kostet den Riegel.
    """
    roh: dict[str, tuple[str, set[str], set[str]]] = {}
    definiert_in: dict[str, list[str]] = {}
    for p in sorted(QUELLE.glob("*.py")):
        for node in ast.parse(p.read_text(encoding="utf-8")).body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            definiert_in.setdefault(node.name, []).append(p.stem)
            namen = set()
            for x in ast.walk(node):
                if isinstance(x, ast.Call):
                    if isinstance(x.func, ast.Name):
                        namen.add(x.func.id)
                    elif isinstance(x.func, ast.Attribute):
                        namen.add(x.func.attr)
            roh[f"{p.stem}.{node.name}"] = (p.stem, namen, _lokal_gebunden(node))

    graph: dict[str, set[str]] = {}
    for schluessel, (modul, namen, lokal) in roh.items():
        kanten = set()
        for n in namen:
            if n in lokal:
                continue                                  # lokal gebunden -> nicht die fremde Funktion
            if f"{modul}.{n}" in roh:
                kanten.add(f"{modul}.{n}")                # eigenes Modul gewinnt
            else:
                orte = definiert_in.get(n, [])
                if len(orte) == 1:
                    kanten.add(f"{orte[0]}.{n}")          # repo-weit eindeutig
                # mehrdeutig -> keine Kante (lieber ein Fund zu viel als eine Deckung zu viel)
        graph[schluessel] = kanten
    return graph


def _erreicht(graph: dict[str, set[str]], start: str, ziel: str = ZIEL, tiefe: int = 12) -> bool:
    """Der Graph ist modulqualifiziert (``modul.funktion``); das Ziel wird an seinem NAMENSTEIL erkannt,
    weil ``enforce_structural_budget`` ueber lokale Importe aus mehreren Modulen erreicht wird."""
    gesehen, rand = set(), {start}
    for _ in range(tiefe):
        neu: set[str] = set()
        for n in rand:
            if n in gesehen:
                continue
            gesehen.add(n)
            for m in graph.get(n, ()):
                if m.rsplit(".", 1)[-1] == ziel:
                    return True
                neu.add(m)
        rand = neu - gesehen
        if not rand:
            break
    return False


def _population() -> tuple[dict[str, bool], dict[str, str]]:
    graph = _aufrufgraph()
    familie: dict[str, bool] = {}
    unentscheidbar: dict[str, str] = {}
    for p in sorted(QUELLE.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"proofbundle.{p.stem}")
        except Exception:                                    # optionales Extra fehlt
            continue
        for n, f in vars(mod).items():
            if not n.startswith(("verify_", "recompute_")) or not callable(f):
                continue
            if getattr(f, "__module__", "") != mod.__name__:
                continue
            try:
                ps = list(inspect.signature(f).parameters.values())
            except (TypeError, ValueError):
                continue
            if not ps:
                continue
            ann = str(ps[0].annotation)
            schluessel = f"{p.stem}.{n}"
            if "_empty" in ann:
                unentscheidbar[schluessel] = ps[0].name
            elif any(t in ann for t in _STRUKTUR):
                familie[schluessel] = _erreicht(graph, schluessel)
    return familie, unentscheidbar


class StrukturBudgetErreichbarkeit(unittest.TestCase):

    def test_die_population_ist_nicht_leer(self):
        """Ohne das koennte jede Verschaerfung durch eine leere Menge 'bestehen'."""
        familie, _ = _population()
        self.assertGreaterEqual(len(familie), 15,
                                f"die Ableitung findet nur {len(familie)} Flaechen — sie misst nicht mehr, "
                                "was sie zu messen behauptet")

    def test_jede_direct_dict_flaeche_erreicht_die_schranke(self):
        familie, _ = _population()
        offen = sorted(k for k, v in familie.items() if not v and k not in _EIGENE_SCHRANKE)
        self.assertEqual(
            offen, [],
            "diese Flaechen nehmen eine geparste Struktur entgegen und erreichen "
            f"{ZIEL} in ihrem Aufrufgraphen NICHT — auf ihnen ist die input_bytes-Schranke inert:\n  "
            + "\n  ".join(offen))

    def test_unentscheidbare_flaechen_sind_benannt_statt_uebergangen(self):
        """DER DRITTE ZUSTAND. Nicht entscheidbar ist keine Freigabe.

        Waechst die Menge, ist eine neue Flaeche ohne Annotation dazugekommen und niemand kann sagen, ob
        sie zur Familie gehoert — das faellt hier auf, statt still zu passieren.
        """
        _, unentscheidbar = _population()
        neu = sorted(set(unentscheidbar) - set(_UNANNOTIERT_ERWARTET))
        self.assertEqual(neu, [],
                         "neue Flaeche mit unannotiertem ersten Parameter — annotieren oder mit "
                         f"Begruendung in _UNANNOTIERT_ERWARTET aufnehmen: {neu}")

    def test_eine_eigene_schranke_wird_belegt_statt_behauptet(self):
        """Ein Ausschluss gilt nur gegen Beleg — sonst waere _EIGENE_SCHRANKE die Tuer, durch die eine
        ungeschuetzte Flaeche verschwindet. Geprueft wird EFFEKTBASIERT: die genannte Budget-Dimension
        existiert wirklich und wird im Modul der Flaeche wirklich benutzt."""
        from proofbundle.budget import DEFAULT_BUDGET
        for schluessel, (dimension, _grund) in _EIGENE_SCHRANKE.items():
            modul = schluessel.split(".", 1)[0]
            with self.subTest(flaeche=schluessel):
                self.assertTrue(hasattr(DEFAULT_BUDGET, dimension),
                                f"Budget-Dimension {dimension!r} existiert nicht")
                quelle = (QUELLE / f"{modul}.py").read_text(encoding="utf-8")
                self.assertIn(dimension, quelle,
                              f"{modul}.py benutzt {dimension!r} nicht — der Ausschluss ist unbelegt")

    def test_eine_eigene_schranke_muss_ihre_KOSTEN_belegen(self):
        """DIE ZWEITE HAELFTE DES BELEGS, und sie fehlte zweimal (deep gate 6.0.0, L2-600-01, dann
        Review Runde 2, B5).

        Dass eine Flaeche eine eigene Dimension traegt, sagt nur, dass eine ZAHL an der Eingabe
        begrenzt ist. Was diese Zahl KOSTET, sagt es nicht — und genau daran ist der Ausschluss
        hier gescheitert: `renewal_ats_chain` = 10.000 feuerte korrekt und liess trotzdem einen Fall
        zu, der 59,5 s Rechenzeit kostete, weil der geschuetzte Durchlauf quadratisch war. Ein
        Ausschluss von der generischen Schranke gilt deshalb nur, wenn die Kosten AM LIMIT der
        eigenen Dimension gemessen sind.

        Review Runde 2, B5: die vorige Fassung pruefte das per ``assertIn(f'Dimension("{dimension}"',
        kurve)`` gegen den QUELLTEXT von ``test_budget_kostenkurve.py`` — das besteht durch die
        blosse ANWESENHEIT der Zeichenkette, auch als Kommentar, als tote/nie ausgefuehrte
        Deklaration oder mit einer laengst roten Kurve daneben; ein Quelltext-Grep prueft die
        Schreibweise, nicht die Sache. Hier wird ``test_budget_kostenkurve`` stattdessen IMPORTIERT
        und seine ECHTE, gecachte ``_messung()`` fuer genau diese Dimension AUSGEFUEHRT — geprueft
        wird das tatsaechlich gemessene Ergebnis (Reichweite und CPU-Obergrenze), nicht ein
        Textmuster."""
        self.assertTrue(KOSTENKURVE.exists(),
                        f"{KOSTENKURVE.name} fehlt — dann ist keine eigene Schranke mehr belegt")
        kurve_mod = importlib.import_module("test_budget_kostenkurve")
        dimensionen_nach_name = {d.name: d for d in kurve_mod.DIMENSIONEN}
        for schluessel, (dimension, _grund) in _EIGENE_SCHRANKE.items():
            with self.subTest(flaeche=schluessel):
                self.assertIn(
                    dimension, dimensionen_nach_name,
                    f"{dimension!r} hat keine Dimension in {kurve_mod.__name__}.DIMENSIONEN — der "
                    "Ausschluss behauptet eine Kostenschranke, die niemand misst")
                m = kurve_mod._messung(dimensionen_nach_name[dimension])
                ist = m["reihe"][-1][0]
                self.assertGreaterEqual(
                    ist, 0.95 * m["limit"],
                    f"{dimension!r}: die gemessene Kurve in {kurve_mod.__name__} erreicht nur {ist} "
                    f"von {m['limit']} — misst nicht den teuersten zugelassenen Fall")
                # The cost verdict is the curve's own, through its own test method, never a second
                # copy of its rule. The copy that stood here compared the maximum with the bare
                # GRENZE_S: no machine factor (OA-0646ecdf70) and no reference-machine binding
                # (OA-dc37e26295), so on a CI runner under coverage it judged the runner, not the
                # code. Measured 2026-09-28 at 3977fcdf: 1.025 s against 1.0 s, red, while the
                # curve itself skipped the same axis on that host with the measured factor as its
                # reason. The same pattern is used by scripts/budget_axis_measurement.py.
                fall = kurve_mod.TestObergrenzeAmGroesstenZugelassenenWert()
                try:
                    fall.test_kosten_am_limit_unter_der_obergrenze(dimensionen_nach_name[dimension])
                except Skipped as e:
                    self.skipTest(f"{dimension!r}, the curve's own verdict: {e.msg}")

    # ── counter-examples for the cost verdict: it is the curve's, and it can still be red ──────────

    def _kosten_urteil_bei(self, kosten_s: float, marke: "str | None") -> unittest.TestResult:
        """Run the cost case above against a planted measurement of the one excluded dimension.

        The clamp is the reference machine's own recording, so the machine factor is 1.0 on every
        host and the verdict turns on the planted cost alone. The build-host mark belongs to the
        case, not to the environment the suite happens to run in."""
        kurve_mod = importlib.import_module("test_budget_kostenkurve")
        (dimension, _grund), = _EIGENE_SCHRANKE.values()
        limit = getattr(kurve_mod.B, dimension)
        vorher = dict(kurve_mod._MESSUNGEN)
        kurve_mod._MESSUNGEN[dimension] = {
            "limit": limit, "reihe": [(limit, 0.0, None)],
            "rand": {limit - 1: (limit - 1, 0.0, True), limit: (limit, 0.0, True),
                     limit + 1: (limit + 1, 0.0, False)},
            "kosten_am_limit_max": kosten_s,
            "referenz_klammer": list(kurve_mod._REFERENZ_FARMER_S),
            "referenz_klammer_frei": list(kurve_mod._REFERENZ_FARMER_HASHFREI_S)}
        ergebnis = unittest.TestResult()
        try:
            with kurve_mod._bauhost_marke(marke):
                StrukturBudgetErreichbarkeit("test_eine_eigene_schranke_muss_ihre_KOSTEN_belegen").run(ergebnis)
        finally:
            kurve_mod._MESSUNGEN.clear()
            kurve_mod._MESSUNGEN.update(vorher)
        return ergebnis

    def test_fangnachweis_kosten_ueber_der_latte_bleiben_rot(self):
        """Five times the bound on the reference machine fails, with the curve's own message."""
        r = self._kosten_urteil_bei(5.0, None)
        self.assertEqual((len(r.failures), len(r.errors), len(r.skipped)), (1, 0, 0),
                         f"failures={r.failures} errors={r.errors} skipped={r.skipped}")
        self.assertIn("L2-600-01", r.failures[0][1])

    def test_fangnachweis_kosten_unter_der_latte_bleiben_gruen(self):
        r = self._kosten_urteil_bei(0.5, None)
        self.assertEqual((len(r.failures), len(r.errors), len(r.skipped)), (0, 0, 0),
                         f"failures={r.failures} errors={r.errors} skipped={r.skipped}")

    def test_fangnachweis_ein_bauhost_urteilt_nicht_ueber_seine_maschine(self):
        """The value measured on the CI runner at 3977fcdf, 1.025 s, is over the bare bound. The copy
        of the rule that stood here failed on it; the curve's own verdict does not judge a build host
        and says so, naming the owner card and the measured factor (OA-dc37e26295)."""
        r = self._kosten_urteil_bei(1.025, "GITHUB_ACTIONS")
        self.assertEqual((len(r.failures), len(r.errors), len(r.skipped)), (0, 0, 1),
                         f"failures={r.failures} errors={r.errors} skipped={r.skipped}")
        self.assertIn("OA-dc37e26295", r.skipped[0][1])

    def test_ein_ausschluss_ohne_eintrag_verschwindet_nicht(self):
        """Die Gegenrichtung dazu: was NICHT in _EIGENE_SCHRANKE steht, muss den Riegel erreichen."""
        familie, _ = _population()
        ausgeschlossen = set(_EIGENE_SCHRANKE)
        self.assertTrue(ausgeschlossen <= set(familie),
                        f"_EIGENE_SCHRANKE nennt Flaechen, die es nicht (mehr) gibt: "
                        f"{sorted(ausgeschlossen - set(familie))}")

    def test_gegenrichtung_der_erreichbarkeits_test_kann_rot_werden(self):
        """Anti-Tautologie: ein Graph ohne die Zielkante MUSS als nicht-erreichbar gelten.

        Ohne diese Zeile waere ein immer-True-Erreichbarkeitstest von einem echten nicht zu unterscheiden.
        """
        self.assertFalse(_erreicht({"m.a": {"m.b"}, "m.b": {"m.c"}}, "m.a"),
                         "Erreichbarkeit meldet ein Ziel, das im Graphen nicht vorkommt")
        self.assertTrue(_erreicht({"m.a": {"m.b"}, "m.b": {f"x.{ZIEL}"}}, "m.a"),
                        "Erreichbarkeit findet das Ziel ueber zwei Kanten nicht")


if __name__ == "__main__":
    unittest.main()
