"""Ein Budget-Wert wird BEHAUPTET oder GEDECKELT — nie roh in eine Testlast geführt.

WAS HIER GESCHLOSSEN WIRD. Deep Gate Lauf 11, Fund `LAUF11-L3`: `HARTER_LASTDECKEL`
(`tests/test_budget.py`) deckelte genau EINE Achse, `data_digests`. Die übrigen bauen ihre Last
weiter direkt aus der geprüften Konstante.

WARUM DAS ZÄHLT, gemessen am 11.09.2026: ein Mutationsoperator, der eine Budget-Konstante
hochsetzt (`idx=90`: `data_digests: 2.000 -> 2.000.000.000`), steuert damit die GRÖSSE der
Testlast. Drei Sampler massen 428,9 -> 51.129,2 MiB in 58 s (rund 874 MiB/s); unter `RLIMIT_AS`
von 6 GiB endete derselbe Ausdruck nach 7,87 s mit `MemoryError`. Auf dem Runner ist das kein
Fehlschlag des Tests, sondern sein **Tod** — und ein toter Test tötet den Mutanten nicht, er
meldet SIGKILL.

DIE EIGENSCHAFT, über die dieser Riegel quantifiziert, und sie ist bewusst nicht „jede Achse hat
einen Deckel": jeder Ausdruck, der einen Budget-Wert LIEST, steht entweder in einer **Zusicherung**
über diesen Wert (dann ist er die Aussage, nicht die Last) oder ist durch
`min(..., HARTER_LASTDECKEL)` **begrenzt** (dann ist er die Last, nicht die Aussage). Beides
zugleich ist der richtige Bau: die Zusicherung lässt den Mutanten an der Aussage sterben, der
Deckel hält den Lauf am Leben, damit er das kann.

Der Riegel liest den AST. Eine Aufzählung der heute bekannten Achsen wäre beim nächsten neuen
Budget-Feld stillschweigend zu kurz — dieselbe Klasse, gegen die er steht.
"""
from __future__ import annotations

import ast
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
DECKEL_NAME = "HARTER_LASTDECKEL"
#: Namen, die auch OHNE sichtbare Bindung als Budget-Objekt gelten: pytest-Fixtures und Parameter,
#: die das Objekt hereinreichen. Alles andere wird aus den Bindungen der Datei ABGELEITET.
BUDGET_NAMEN = ("DEFAULT_BUDGET", "budget")
#: Diese Dateien bauen keine Last aus dem Budget, sie DEFINIEREN den Deckel bzw. diesen Riegel.
_AUSSER_ACHT = {"_lastdeckel.py", Path(__file__).name}

#: Aufrufe, deren Argument eine Aussage ÜBER den Wert ist statt eine Last AUS ihm.
_ZUSICHERUNGEN = {"assertLess", "assertLessEqual", "assertGreater", "assertGreaterEqual",
                  "assertEqual", "assertNotEqual", "assertTrue", "assertFalse", "assertIn",
                  "assertIsNone", "assertIsNotNone", "within", "check"}

#: Aufrufe, die aus einer Zahl n eine n-proportionale Datenstruktur bauen. LAUF12-L3 F2 (P1): nur
#: `range` und `*` waren erfasst; `bytes(n)` baut n Byte und blieb unsichtbar. Die Liste ist
#: bewusst breit — ein Fehlalarm kostet eine Lesung, eine Lücke kostet einen SIGKILL.
_LASTBAUER = {"range", "bytes", "bytearray", "repeat", "zeros", "ones", "full", "empty"}


def _budget_bindungen(baum: ast.AST) -> tuple[set[str], set[str]]:
    """(objekt_namen, modul_namen): welche lokalen Namen in DIESER Datei das Budget-Objekt bzw. das
    Modul `proofbundle.budget` bezeichnen — aus Importen und Zuweisungen ABGELEITET.

    LAUF12-L3 F1 (P1) und der bekannte Alias-Fund: `from proofbundle.budget import DEFAULT_BUDGET as B`,
    `import proofbundle.budget as pbb`, `B = DEFAULT_BUDGET` — sechs Formen, die eine Namensliste
    nie sieht. Eine Bindung ist eine Eigenschaft des Codes; ein Name ist eine Schreibweise."""
    objekte: set[str] = set(BUDGET_NAMEN)
    module: set[str] = set()
    for k in ast.walk(baum):
        if isinstance(k, ast.ImportFrom) and k.module == "proofbundle.budget":
            for a in k.names:
                if a.name == "DEFAULT_BUDGET":
                    objekte.add(a.asname or a.name)
        elif isinstance(k, ast.ImportFrom) and k.module == "proofbundle":
            for a in k.names:
                if a.name == "budget":
                    module.add(a.asname or a.name)
        elif isinstance(k, ast.Import):
            for a in k.names:
                if a.name == "proofbundle.budget":
                    module.add(a.asname or a.name)
    # Zuweisungs-Aliasse, bis nichts Neues mehr dazukommt (X = DEFAULT_BUDGET; Y = X).
    geaendert = True
    while geaendert:
        geaendert = False
        for k in ast.walk(baum):
            if not (isinstance(k, ast.Assign) and len(k.targets) == 1
                    and isinstance(k.targets[0], ast.Name)):
                continue
            ziel = k.targets[0].id
            if ziel in objekte:
                continue
            if _ist_budget_objekt(k.value, objekte, module):
                objekte.add(ziel)
                geaendert = True
    return objekte, module


def _ist_budget_objekt(knoten: ast.AST, objekte: set[str], module: set[str]) -> bool:
    """Bezeichnet der Ausdruck das Budget-Objekt selbst?"""
    if isinstance(knoten, ast.Name):
        return knoten.id in objekte
    if isinstance(knoten, ast.Attribute) and knoten.attr == "DEFAULT_BUDGET":
        basis = knoten.value
        if isinstance(basis, ast.Name) and basis.id in module:
            return True
        # proofbundle.budget.DEFAULT_BUDGET
        return (isinstance(basis, ast.Attribute) and basis.attr == "budget"
                and isinstance(basis.value, ast.Name) and basis.value.id == "proofbundle")
    return False


def _liest_budget(knoten: ast.AST, bindungen: tuple[set[str], set[str]] | None = None) -> bool:
    """Enthält der Teilbaum einen Zugriff auf einen Wert des Budget-Objekts — als Attribut, über
    `getattr`, über `asdict(...)[...]` oder `__dict__[...]`?"""
    objekte, module = bindungen if bindungen else (set(BUDGET_NAMEN), set())
    for k in ast.walk(knoten):
        if isinstance(k, ast.Attribute) and _ist_budget_objekt(k.value, objekte, module):
            return True
        if isinstance(k, ast.Call):
            name = k.func.attr if isinstance(k.func, ast.Attribute) else getattr(k.func, "id", "")
            if name in ("getattr", "asdict", "vars") and k.args \
                    and _ist_budget_objekt(k.args[0], objekte, module):
                return True
    return False


def _ist_gedeckelt(knoten: ast.AST) -> bool:
    """Ist die Groesse im Teilbaum begrenzt — durch `gedeckelt(...)` oder `min(..., DECKEL)`?

    ZWEI SCHREIBWEISEN, EINE EIGENSCHAFT: `gedeckelt()` aus `tests/_lastdeckel.py` ist der Weg,
    `min(..., HARTER_LASTDECKEL)` die aeltere Form, die `test_budget.py` zuerst trug. Beide
    begrenzen; der Riegel bindet an die Wirkung, nicht an eine davon.
    """
    for k in ast.walk(knoten):
        if isinstance(k, ast.Call) and getattr(k.func, "id", None) == "gedeckelt":
            return True
        if (isinstance(k, ast.Call) and getattr(k.func, "id", None) == "min"
                and any(isinstance(a, ast.Name) and a.id == DECKEL_NAME for a in k.args)):
            return True
    return False


def _ist_lastkontext(k: ast.AST) -> bool:
    if isinstance(k, ast.Call):
        name = k.func.attr if isinstance(k.func, ast.Attribute) else getattr(k.func, "id", None)
        return name in _LASTBAUER
    return isinstance(k, ast.BinOp) and isinstance(k.op, ast.Mult)


def _lastargumente(k: ast.AST) -> list:
    if isinstance(k, ast.Call):
        return list(k.args)
    return [k.left, k.right]


_SCOPE_KNOTEN = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _eigene_knoten(scope: ast.AST) -> tuple[list, list]:
    """(Knoten dieses Scopes in Quellreihenfolge, direkte Unter-Scopes). Steigt NICHT in verschachtelte
    Funktionen/Klassen ab — die sind eigene Namensraeume (Gegenlesung un_turbov1, Lauf 13, Stelle 2c:
    ein `n` in einer inneren Funktion ist eine ANDERE Variable als das `n` des Moduls)."""
    eigene: list = []
    unter: list = []

    def rek(k):
        for kind in ast.iter_child_nodes(k):
            if isinstance(kind, _SCOPE_KNOTEN):
                unter.append(kind)
            else:
                eigene.append(kind)
                rek(kind)
    rek(scope)
    return eigene, unter


def _budget_funktionen(baum: ast.AST, bindungen) -> set[str]:
    """Funktionen dieser Datei, deren `return` einen Budget-Wert liest — ein Aufruf `f()` ist dann ein
    Budget-Zugriff hinter einem Namen (Stelle 2b der Gegenlesung: `min(B.x, _cap())` mit `_cap()` =
    `B.x` waere sonst eine 'fremde Schranke', die keine ist). Bis zum Fixpunkt, damit `g()` = `f()`
    ebenfalls zaehlt."""
    namen: set[str] = set()
    geaendert = True
    while geaendert:
        geaendert = False
        for k in ast.walk(baum):
            if not isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef)) or k.name in namen:
                continue
            for r in ast.walk(k):
                if isinstance(r, ast.Return) and r.value is not None and (
                        _liest_budget(r.value, bindungen) or _ruft_budget_funktion(r.value, namen)):
                    namen.add(k.name)
                    geaendert = True
                    break
    return namen


def _ruft_budget_funktion(knoten: ast.AST, namen: set[str]) -> bool:
    return any(isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id in namen
               for k in ast.walk(knoten))


def ungedeckelte_lastquellen(datei: Path) -> list[str]:
    """'datei:zeile — code' für jede Stelle, an der ein Budget-Wert die GRÖSSE einer erzeugten
    Datenstruktur bestimmt, ohne durch `gedeckelt(...)` / `min(..., HARTER_LASTDECKEL)` begrenzt zu sein.

    ZWEISTUFIG, und der Grund steht in der ersten Fassung dieses Riegels: sie meldete JEDE
    Zuweisung aus einem Budget-Wert und traf damit `knapp_drunter = 2 ** (int_bits - 1)` (eine
    ZAHL, keine Last) und `_SL = DEFAULT_BUDGET.string_len` (eine Konstante, aus der erst später
    etwas gebaut wird). Ein Riegel, der an der Schreibweise bindet statt an der Wirkung, erzeugt
    Fehlalarme — und ein Riegel mit Fehlalarmen wird umgangen statt gelesen.

    Stufe 1 sammelt Namen, die aus einem Budget-Wert abgeleitet sind. Stufe 2 meldet nur, wo ein
    solcher Name ODER ein direkter Budget-Zugriff in einem LAST-Kontext steht: einem Lastbauer
    (`range`, `bytes`, `bytearray`, `repeat`, …) oder einer Wiederholung `x * n`. Eine Potenz ist
    kein Last-Kontext.

    JE SCOPE (Lauf 13): Modul, jede Funktion und jede Klasse werden getrennt abgeleitet; ein innerer
    Scope erbt den Endzustand des aeusseren, aendert ihn aber nicht zurueck. Ein Aufruf einer
    Funktion, deren `return` das Budget liest, gilt als Budget-Zugriff.
    """
    quelle = datei.read_text(encoding="utf-8")
    try:
        baum = ast.parse(quelle)
    except SyntaxError:
        return []
    zeilen = quelle.splitlines()
    bindungen = _budget_bindungen(baum)
    funktionen = _budget_funktionen(baum, bindungen)

    def liest(knoten: ast.AST) -> bool:
        return _liest_budget(knoten, bindungen) or _ruft_budget_funktion(knoten, funktionen)

    ausgenommen: set[int] = set()
    for k in ast.walk(baum):
        if isinstance(k, ast.Call):
            name = k.func.attr if isinstance(k.func, ast.Attribute) else getattr(k.func, "id", "")
            if name in _ZUSICHERUNGEN:
                for kind in ast.walk(k):
                    ausgenommen.add(id(kind))
        if isinstance(k, ast.Assert):
            for kind in ast.walk(k):
                ausgenommen.add(id(kind))

    treffer: list[str] = []
    gemeldete_zeilen: set[int] = set()

    def analysiere(scope: ast.AST, geerbt: dict[str, int]) -> None:
        abgeleitet: dict[str, int] = dict(geerbt)
        eigene, unter = _eigene_knoten(scope)

        def groesse_aus_budget(knoten: ast.AST) -> bool:
            if liest(knoten):
                return True
            return any(isinstance(kk, ast.Name) and kk.id in abgeleitet for kk in ast.walk(knoten))

        def min_mit_fremder_schranke(ausdruck: ast.AST) -> bool:
            """`min(a, B.x)` ist durch `a` begrenzt, wenn `a` NICHT aus dem Budget stammt — der
            Budget-Wert kann das Ergebnis nur senken. Sind alle Argumente Budget-Groessen (direkt,
            abgeleitet oder hinter einer Funktion), begrenzt nichts."""
            if not (isinstance(ausdruck, ast.Call) and getattr(ausdruck.func, "id", None) == "min"
                    and len(ausdruck.args) >= 2):
                return False
            return any(not groesse_aus_budget(a) for a in ausdruck.args)

        # Stufe 1, in Quellreihenfolge dieses Scopes: eine gedeckelte NEUZUWEISUNG hebt die Ableitung
        # desselben Namens auf — nur hier, nicht im aeusseren Scope.
        for k in eigene:
            if not (isinstance(k, ast.Assign) and liest(k.value)):
                continue
            begrenzt = _ist_gedeckelt(k.value) or min_mit_fremder_schranke(k.value)
            for ziel in k.targets:
                if isinstance(ziel, ast.Name):
                    if begrenzt:
                        abgeleitet.pop(ziel.id, None)
                    else:
                        abgeleitet[ziel.id] = k.lineno
        # Stufe 2: Lastkontexte dieses Scopes.
        for k in eigene:
            if not _ist_lastkontext(k) or not any(groesse_aus_budget(a) for a in _lastargumente(k)):
                continue
            if id(k) in ausgenommen or _ist_gedeckelt(k):
                continue
            if any(min_mit_fremder_schranke(a) for a in _lastargumente(k)):
                continue
            # Die MELDUNG zeigt auf die Ableitung, wenn es eine gibt — dort gehört der Deckel hin.
            zl = k.lineno
            for kk in ast.walk(k):
                if isinstance(kk, ast.Name) and kk.id in abgeleitet:
                    zl = abgeleitet[kk.id]
                    break
            if zl in gemeldete_zeilen:
                continue
            gemeldete_zeilen.add(zl)
            treffer.append(f"{datei.name}:{zl} — {zeilen[zl - 1].strip()[:100]}")
        for s in unter:
            analysiere(s, abgeleitet)

    analysiere(baum, {})
    return treffer


def _messform_data_digests(n: int) -> list:
    return ["%064x" % i for i in range(n)]


def _messform_json_nodes(n: int) -> list:
    return list(range(n))


def _messform_string_len(n: int) -> str:
    return "y" * n


def _messform_renewal_ats_chain(n: int) -> list:
    # Die Form der Kostenkurve: je Kettenglied EINE Liste mit EINEM ArchiveTimeStamp.
    from proofbundle.renewal import ArchiveTimeStamp  # noqa: PLC0415
    return [[ArchiveTimeStamp("sha256", "a" * 64, i)] for i in range(n)]


def _messform_signatures(n: int) -> list:
    return [{"sig": "AA=="} for _ in range(n)]


def _messform_witnesses(n: int) -> dict:
    return {f"w{i}": {"publicKey": "A" * 44} for i in range(n)}


#: Die Form, in der die Testsuite ein Element dieser Achse WIRKLICH baut — gemessen wird DAS, nicht
#: eine Annahme. Achsen ohne Eintrag haben heute keine Lastquelle in der Suite; kommt eine dazu,
#: gehoert ihre Form hierher, sonst ist ihre Zahl in der Tabelle wieder eine Behauptung
#: (`test_jede_lastachse_hat_eine_messform` meldet das).
MESSFORMEN = {
    "data_digests": _messform_data_digests,
    "json_nodes": _messform_json_nodes,
    "merkle_path": _messform_data_digests,
    "renewal_ats_chain": _messform_renewal_ats_chain,
    "signatures": _messform_signatures,
    "string_len": _messform_string_len,
    "witnesses": _messform_witnesses,
}


def gemessene_bytes_je_element(achse: str, n1: int = 20_000, n2: int = 40_000) -> float:
    """Bytes je Element der Messform, mit tracemalloc als STEIGUNG zwischen zwei Groessen — so
    faellt der konstante Anteil (Listenkopf, Objektkopf des einen Strings) heraus und die Zahl ist
    wirklich je Element. Die Tabelle in `tests/_lastdeckel.py` muss sich daran messen lassen."""
    import tracemalloc  # noqa: PLC0415
    form = MESSFORMEN[achse]
    form(8)  # Importe und Caches vorher, damit sie nicht in die Messung fallen
    spitzen = []
    for n in (n1, n2):
        tracemalloc.start()
        tracemalloc.reset_peak()
        vorher, _ = tracemalloc.get_traced_memory()
        last = form(n)
        _, spitze = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        del last
        spitzen.append(spitze - vorher)
    return round((spitzen[1] - spitzen[0]) / (n2 - n1), 1)


def alle_testdateien() -> list[Path]:
    """ALLE Python-Dateien unter tests/ — nicht nur `test_*.py`. LAUF12-L3 F1(f): eine Hilfsdatei
    `tests/_hilfe.py`, die die Last baut und von einem Test gerufen wird, lag ausserhalb des
    Glob-Musters. Der Ort einer Last ist keine Eigenschaft ihres Dateinamens."""
    return sorted(f for f in TESTS.rglob("*.py")
                  if f.name not in _AUSSER_ACHT and "__pycache__" not in f.parts)


def last_achsen(dateien) -> set[str]:
    """Die Budget-Achsen, die im Baum tatsaechlich eine Last bestimmen — abgeleitet, nicht getippt.

    Warum abgeleitet: `renewal_work` ist 40.000.000 und damit weit ueber jedem Deckel, aber es ist
    ein ARBEITS-Budget (Kette x Digests), aus dem nie eine Liste gebaut wird. Eine getippte Liste
    der Lastachsen waere beim naechsten neuen Feld still zu kurz oder zu lang; diese hier liest,
    was der Baum tut.
    """
    achsen: set[str] = set()
    for f in dateien:
        try:
            baum = ast.parse(f.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        objekte, module = _budget_bindungen(baum)
        for k in ast.walk(baum):
            if not _ist_lastkontext(k):
                continue
            for kk in ast.walk(k):
                if isinstance(kk, ast.Attribute) and _ist_budget_objekt(kk.value, objekte, module):
                    achsen.add(kk.attr)
    return achsen


class TestKeineUngedeckelteTestlast(unittest.TestCase):

    def test_kein_test_baut_eine_ungedeckelte_last_aus_einem_budget_wert(self):
        offen: list[str] = []
        for f in alle_testdateien():
            offen.extend(ungedeckelte_lastquellen(f))
        self.assertEqual(
            offen, [],
            "diese Stellen leiten eine Testlast direkt aus einem Budget-Wert ab, ohne Deckel: ein "
            "Mutationsoperator, der die Konstante hochsetzt, steuert damit den Speicherbedarf des "
            "Laufs und tötet den Test, statt von ihm getötet zu werden:\n  " + "\n  ".join(offen))

    def test_der_deckel_schneidet_keinen_legitimen_wert_ab(self):
        """DIE GEGENRICHTUNG, und ohne sie ist der Deckel ein Schaden statt eines Schutzes: kein
        heute geltender Budget-Wert darf durch ihn gekuerzt werden. Sonst prueft ein Test, der die
        Grenze erreichen will, sie nie mehr — und faellt gruen aus, weil er zu klein geworden ist.

        Die erste Fassung deckelte auf 100.000 Elemente quer ueber alle Achsen und haette
        `string_len` (1.000.000) auf ein Zehntel gekuerzt. Diese Zusicherung haette das gefangen.
        """
        sys.path.insert(0, str(TESTS))
        from _lastdeckel import gedeckelt  # noqa: PLC0415
        from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415
        # DIESELBE Tabelle wie die Aufrufstellen, aus _lastdeckel importiert statt hier getippt:
        # zwei Tabellen mit demselben Zweck sind zwei Wahrheiten, und die zweite altert unbemerkt.
        from _lastdeckel import KOSTEN_JE_ELEMENT  # noqa: PLC0415
        # NUR die Achsen, aus denen der Baum wirklich eine Last baut. `renewal_work` (40.000.000)
        # ist ein ARBEITS-Budget, kein Elementzaehler — es erzeugt nie eine Liste, und ein Deckel
        # darauf waere eine Zahl ohne Gegenstand. Gemessen beim Bau dieses Tests: er meldete genau
        # diese eine Achse, und die Meldung war seine, nicht die des Deckels.
        achsen = last_achsen(alle_testdateien())
        self.assertTrue(achsen, "keine Lastachse gefunden — dann misst dieser Test nichts")
        gekuerzt = []
        for dim in sorted(achsen):
            wert = getattr(DEFAULT_BUDGET, dim, None)
            if not isinstance(wert, int) or isinstance(wert, bool):
                continue
            # Kein stiller Standardwert (LAUF12-L3): eine Achse ohne Tabelleneintrag ist eine Achse
            # ohne gemessene Kosten, und 64 waere wieder eine Zahl, die an der Form haengt.
            self.assertIn(dim, KOSTEN_JE_ELEMENT, f"Lastachse {dim!r} hat keinen Eintrag in KOSTEN_JE_ELEMENT")
            bje = KOSTEN_JE_ELEMENT[dim]
            g = gedeckelt(wert, bytes_je_element=bje)
            if g < wert:
                gekuerzt.append(f"{dim}: {wert:,} -> {g:,} (bytes_je_element={bje})")
        self.assertEqual(
            gekuerzt, [],
            "der Deckel kuerzt einen LEGITIMEN Budget-Wert — jeder Test, der diese Grenze erreichen "
            "will, prueft sie danach nicht mehr und wird gruen, weil er zu klein ist:\n  "
            + "\n  ".join(gekuerzt))

    def test_meta_eine_gepflanzte_ungedeckelte_last_wird_gefangen(self):
        """PLANT-AND-MUST-CATCH, in drei Formen: direkt in range(), über eine Zwischenvariable und
        als Wiederholung."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "test_gepflanzt.py"
            f.write_text(
                "from proofbundle.budget import DEFAULT_BUDGET\n"
                "def test_direkt():\n"
                "    xs = [i for i in range(DEFAULT_BUDGET.witnesses + 1)]\n"
                "def test_indirekt():\n"
                "    over = DEFAULT_BUDGET.signatures + 1\n"
                "    ys = list(range(over))\n"
                "def test_wiederholung():\n"
                "    s = 'a' * DEFAULT_BUDGET.string_len\n", encoding="utf-8")
            gefunden = ungedeckelte_lastquellen(f)
            self.assertEqual(len(gefunden), 3, f"nicht alle drei Formen gefangen: {gefunden}")

    def test_meta_die_sechs_aliasformen_und_bytes_werden_gefangen(self):
        """LAUF12-L3 F1/F2 — die Formen, fuer die der Riegel am Kopf e8a7f8e blind war, je einzeln
        gepflanzt. Jede muss GENAU EINE Meldung ergeben."""
        formen = {
            "import_alias": "from proofbundle.budget import DEFAULT_BUDGET as B\n"
                            "def test_a():\n    xs = [i for i in range(B.witnesses)]\n",
            "modul_alias": "import proofbundle.budget as pbb\n"
                           "def test_b():\n    xs = list(range(pbb.DEFAULT_BUDGET.witnesses))\n",
            "zuweisung": "from proofbundle.budget import DEFAULT_BUDGET\nB = DEFAULT_BUDGET\n"
                         "def test_c():\n    xs = list(range(B.witnesses))\n",
            "getattr": "from proofbundle.budget import DEFAULT_BUDGET\n"
                       "def test_d():\n    xs = list(range(getattr(DEFAULT_BUDGET, 'witnesses')))\n",
            "asdict": "import dataclasses\nfrom proofbundle.budget import DEFAULT_BUDGET\n"
                      "def test_e():\n    xs = list(range(dataclasses.asdict(DEFAULT_BUDGET)['witnesses']))\n",
            "repeat": "import itertools\nfrom proofbundle.budget import DEFAULT_BUDGET\n"
                      "def test_f():\n    xs = list(itertools.repeat(0, DEFAULT_BUDGET.witnesses))\n",
            "bytes": "from proofbundle.budget import DEFAULT_BUDGET\n"
                     "def test_g():\n    b = bytes(DEFAULT_BUDGET.string_len)\n",
            "bytearray": "from proofbundle.budget import DEFAULT_BUDGET\n"
                         "def test_h():\n    b = bytearray(DEFAULT_BUDGET.string_len)\n",
            "modul_aus_paket": "from proofbundle import budget as bud\n"
                               "def test_i():\n    xs = list(range(bud.DEFAULT_BUDGET.witnesses))\n",
        }
        with tempfile.TemporaryDirectory() as d:
            for name, quelle in formen.items():
                f = Path(d) / f"test_{name}.py"
                f.write_text(quelle, encoding="utf-8")
                with self.subTest(form=name):
                    self.assertEqual(len(ungedeckelte_lastquellen(f)), 1,
                                     f"Form {name} nicht (genau einmal) gefangen: "
                                     f"{ungedeckelte_lastquellen(f)}")

    def test_meta_min_mit_fremder_schranke_ist_begrenzt_min_aus_zwei_budgets_nicht(self):
        """`n = min(n, B.x)` ist durch `n` begrenzt und keine Meldung; `min(B.x, B.y)` begrenzt
        nichts; eine gedeckelte Neuzuweisung hebt eine fruehere Ableitung auf."""
        faelle = {
            "fremde_schranke": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                                "def test_a(n):\n    n = min(n, B.witnesses)\n    xs = list(range(n))\n", 0),
            "inline": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                       "def test_b(n):\n    xs = list(range(min(n, B.witnesses)))\n", 0),
            "zwei_budgets": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                             "def test_c():\n    xs = list(range(min(B.witnesses, B.signatures)))\n", 1),
            "neuzuweisung_gedeckelt": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                                       "from _lastdeckel import gedeckelt\n"
                                       "def test_d():\n    n = B.renewal_work // 5\n"
                                       "    n = min(n, gedeckelt(B.renewal_ats_chain, bytes_je_element=384))\n"
                                       "    xs = list(range(n))\n", 0),
            "neuzuweisung_offen": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                                   "def test_e():\n    n = B.renewal_work // 5\n"
                                   "    n = min(n, B.renewal_ats_chain)\n    xs = list(range(n))\n", 1),
        }
        with tempfile.TemporaryDirectory() as d:
            for name, (quelle, erwartet) in faelle.items():
                f = Path(d) / f"test_{name}.py"
                f.write_text(quelle, encoding="utf-8")
                with self.subTest(fall=name):
                    self.assertEqual(len(ungedeckelte_lastquellen(f)), erwartet, ungedeckelte_lastquellen(f))

    def test_meta_funktion_hinter_dem_budget_und_scopes(self):
        """Gegenlesung un_turbov1 (Lauf 13, Stelle 2b/2c): `min(B.x, _cap())` mit `_cap()` = `B.x` ist
        KEINE fremde Schranke; `min(B.x, len(_pool))` mit `_pool` aus `B.x` auch nicht; ein `n` in
        einer inneren Funktion ist eine andere Variable als das `n` des Moduls."""
        faelle = {
            "funktion_hinter_budget": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                                       "def _cap():\n    return B.witnesses\n"
                                       "def test_a():\n    n = min(B.witnesses, _cap())\n    xs = list(range(n))\n", 1),
            "funktion_zweistufig": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                                    "def _cap():\n    return B.witnesses\ndef _cap2():\n    return _cap()\n"
                                    "def test_b():\n    xs = list(range(_cap2()))\n", 1),
            "len_einer_budgetliste": ("from proofbundle.budget import DEFAULT_BUDGET as B\n"
                                      "def test_c():\n    _pool = [0] * B.witnesses\n"
                                      "    n = min(B.witnesses, len(_pool))\n    xs = list(range(n))\n", 2),
            "innerer_scope_deckelt_nicht_den_aeusseren": (
                "from proofbundle.budget import DEFAULT_BUDGET as B\nfrom _lastdeckel import gedeckelt\n"
                "n = B.witnesses\n"
                "def f():\n    n = gedeckelt(B.witnesses, bytes_je_element=2048)\n    return list(range(n))\n"
                "ys = list(range(n))\n", 1),
            "aeusserer_deckel_vererbt_sich": (
                "from proofbundle.budget import DEFAULT_BUDGET as B\nfrom _lastdeckel import gedeckelt\n"
                "n = gedeckelt(B.witnesses, bytes_je_element=2048)\n"
                "def f():\n    return list(range(n))\n", 0),
        }
        with tempfile.TemporaryDirectory() as d:
            for name, (quelle, erwartet) in faelle.items():
                f = Path(d) / f"test_{name}.py"
                f.write_text(quelle, encoding="utf-8")
                with self.subTest(fall=name):
                    self.assertEqual(len(ungedeckelte_lastquellen(f)), erwartet, ungedeckelte_lastquellen(f))

    def test_meta_eine_last_in_einer_hilfsdatei_ausserhalb_des_musters_wird_gesehen(self):
        """F1(f): der Ort einer Last ist keine Eigenschaft ihres Dateinamens."""
        fremde = [f for f in alle_testdateien() if not f.name.startswith("test_")]
        self.assertTrue(fremde, "kein Nicht-test_-Modul unter tests/ — dann misst dieser Test nichts")
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "_hilfe.py"
            h.write_text("from proofbundle.budget import DEFAULT_BUDGET\n"
                         "def baue():\n    return list(range(DEFAULT_BUDGET.witnesses))\n",
                         encoding="utf-8")
            self.assertEqual(len(ungedeckelte_lastquellen(h)), 1)

    def test_die_kostentabelle_ist_gemessen_nicht_geschaetzt(self):
        """LAUF12-L3 F3/F4/F5 (P1): `KOSTEN_JE_ELEMENT` behauptete „gemessen" und war es nicht —
        json_nodes 8 statt 36 B, renewal_ats_chain 256 statt 292 B, data_digests 64 statt 121 B;
        unter Mutation wuchs eine Testlast auf 521 MiB statt 64 MiB. Hier wird jede Achse mit einer
        Messform NACHGEMESSEN; die Tabelle darf nie unter der Wirklichkeit liegen."""
        sys.path.insert(0, str(TESTS))
        from _lastdeckel import KOSTEN_JE_ELEMENT  # noqa: PLC0415
        zu_niedrig = []
        for achse in sorted(MESSFORMEN):
            gemessen = gemessene_bytes_je_element(achse)
            if KOSTEN_JE_ELEMENT[achse] < gemessen:
                zu_niedrig.append(f"{achse}: Tabelle {KOSTEN_JE_ELEMENT[achse]} B < gemessen {gemessen:.1f} B")
        self.assertEqual(
            zu_niedrig, [],
            "die Kostentabelle liegt UNTER der gemessenen Elementgroesse — der Deckel laesst dann "
            "mehr Speicher zu, als er verspricht (Faktor Wirklichkeit/Tabelle):\n  "
            + "\n  ".join(zu_niedrig))

    def test_jede_lastachse_hat_eine_messform(self):
        """Eine Achse, aus der der Baum eine Last baut, aber die niemand misst, hat in der Tabelle
        wieder nur eine Behauptung."""
        achsen = last_achsen(alle_testdateien())
        # Achsen, die ohne Datenstruktur je Element auskommen (ein Bit, ein Byte, eine Ebene): ihre
        # Kosten sind definitorisch, nicht messbar — benannt, nicht verschwiegen.
        definitorisch = {"input_bytes", "int_bits", "json_depth"}
        ohne = sorted(a for a in achsen if a not in MESSFORMEN and a not in definitorisch)
        self.assertEqual(ohne, [], f"Lastachsen ohne Messform: {ohne} — ihre Tabellenzahl ist ungemessen")

    def test_anti_tautologie_die_gedeckelte_form_wird_NICHT_gemeldet(self):
        """Die Gegenrichtung: der korrekt gebaute Test darf nicht melden — sonst misst der Riegel
        nur, ob das Wort DEFAULT_BUDGET vorkommt."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "test_sauber.py"
            f.write_text(
                "from proofbundle.budget import DEFAULT_BUDGET\n"
                "HARTER_LASTDECKEL = 100_000\n"
                "class T:\n"
                "    def test_ok(self):\n"
                "        self.assertLessEqual(DEFAULT_BUDGET.witnesses, HARTER_LASTDECKEL)\n"
                "        over = min(DEFAULT_BUDGET.witnesses, HARTER_LASTDECKEL) + 1\n"
                "        xs = list(range(over))\n", encoding="utf-8")
            self.assertEqual(ungedeckelte_lastquellen(f), [],
                             "der Riegel meldet die korrekt gedeckelte Form — dann misst er die "
                             "Schreibweise, nicht die Eigenschaft")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
