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
#: By path, not by name: a file of the same name in a subfolder is another file (counter review 2026-10-17).
_AUSSER_ACHT = {TESTS / "_lastdeckel.py", Path(__file__).resolve()}

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
    # The text without a byte order mark for the lines of the report, the tree from the bytes (see _read_tree).
    quelle = datei.read_text(encoding="utf-8-sig")
    try:
        baum = _read_tree(datei)
    except SyntaxError as fehler:
        return [f"{datei.name}:{fehler.lineno or 0} does not parse, so the guard cannot read it"]
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
                  if f.resolve() not in _AUSSER_ACHT and "__pycache__" not in f.parts)


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
            baum = _read_tree(f)
        except (OSError, SyntaxError):
            # test_every_file_the_guards_read_parses turns red for such a file.
            continue
        objekte, module = _budget_bindungen(baum)
        for k in ast.walk(baum):
            if not _ist_lastkontext(k):
                continue
            for kk in ast.walk(k):
                if isinstance(kk, ast.Attribute) and _ist_budget_objekt(kk.value, objekte, module):
                    achsen.add(kk.attr)
    return achsen


#: The module that defines the cap and the table; a binding from anywhere else is not the measured table.
_CAP_MODULES = ("_lastdeckel", "tests._lastdeckel")
#: The names this guard follows. A file binds each of them once, by its import from the cap module.
_TRACKED_NAMES = ("gedeckelt", "KOSTEN_JE_ELEMENT", "MAX_TESTLAST_BYTES", "_lastdeckel")
#: A string that is one of the names above or holds one of these reaches the cap, its table or its module by a way
#: the guard cannot read: getattr, setattr, globals(), sys.modules, exec.
_TRACKED_IN_TEXT = ("gedeckelt(", "KOSTEN_JE_ELEMENT", "_lastdeckel")
#: The attributes of the cap module a file may read.
_MODULE_READS = ("gedeckelt", "KOSTEN_JE_ELEMENT", "MAX_TESTLAST_BYTES", "HARTER_LASTDECKEL")


def _read_tree(path: Path) -> ast.AST:
    """The syntax tree of one file, parsed from its bytes as Python reads a source file. A file that starts with a byte
    order mark is read, not skipped; a SyntaxError reaches the caller."""
    return ast.parse(path.read_bytes(), filename=str(path))


def _bindings(tree: ast.AST):
    """(name, line, node, how) for every way the file binds a name: imports, every assignment target, parameters,
    function and class names, global and nonlocal declarations, exception names and match captures."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.asname or a.name.split(".")[0], node.lineno, node, a
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                yield a.asname or a.name, node.lineno, node, a
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            yield node.id, node.lineno, node, "an assignment"
        elif isinstance(node, ast.arg):
            yield node.arg, node.lineno, node, "a parameter"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name, node.lineno, node, "a definition"
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                yield name, node.lineno, node, "a global or nonlocal declaration"
        elif isinstance(node, ast.ExceptHandler) and node.name:
            yield node.name, node.lineno, node, "an exception name"
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            yield node.name, node.lineno, node, "a match capture"
        elif isinstance(node, ast.MatchMapping) and node.rest:
            yield node.rest, node.lineno, node, "a match capture"


def _cap_bindings(tree: ast.AST) -> tuple[set[str], set[str], set[str], list[tuple[int, str]]]:
    """(cap names, table names, module expressions, findings) of one file.

    The cap, the table and the module count only through their import from the cap module. Every other binding of a
    followed name is a finding of its own, because from then on the name may mean something else: a second import, an
    assignment, a parameter, a definition, a declaration, a capture. A star import is a finding too, since the names it
    binds cannot be listed."""
    caps: set[str] = set()
    tables: set[str] = set()
    modules: set[str] = set()
    allowed: set[int] = set()
    findings: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    findings.append((node.lineno, f"imports * from {node.module}, so the guard cannot list what it "
                                                  "binds"))
                elif node.module in _CAP_MODULES and a.name == "gedeckelt":
                    caps.add(a.asname or a.name)
                    allowed.add(id(a))
                    if a.asname:
                        findings.append((node.lineno, f"imports the cap as {a.asname}; import it as gedeckelt"))
                elif node.module in _CAP_MODULES and a.name == "KOSTEN_JE_ELEMENT":
                    tables.add(a.asname or a.name)
                    allowed.add(id(a))
                elif node.module in _CAP_MODULES:
                    allowed.add(id(a))
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name in _CAP_MODULES:
                    modules.add(a.asname or a.name)
                    allowed.add(id(a))
    followed = set(_TRACKED_NAMES) | caps | tables | {m.split(".")[0] for m in modules}
    for name, line, node, how in _bindings(tree):
        if name not in followed or (isinstance(how, ast.alias) and id(how) in allowed):
            continue
        if isinstance(how, ast.alias):
            how = f"an import from {node.module}" if isinstance(node, ast.ImportFrom) else f"an import of {how.name}"
        findings.append((line, f"binds {name} by {how}, so the name may no longer be the cap, its table or its module"))
    return caps, tables, modules, findings


def _is_the_table(node: ast.AST, tables: set[str], modules: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tables
    return (isinstance(node, ast.Attribute) and node.attr == "KOSTEN_JE_ELEMENT"
            and ast.unparse(node.value) in modules)


def _unproven_cap_call(call: ast.Call, table, budget, tables: set[str], modules: set[str]) -> str | None:
    """Why the cost of this call is not proven to be at least the measured entry of its axis, or None.

    Two forms are proven, and only these: the entry of the same axis read from the table, and an int literal at or
    above that entry. Everything else is a finding, because a form the guard does not read is a form it cannot vouch
    for."""
    # A `**` argument has the key None here, so the same check refuses it.
    named = {kw.arg: kw.value for kw in call.keywords}
    if len(call.args) > 1 or set(named) - {"wert", "bytes_je_element"} or (call.args and "wert" in named):
        return "passes arguments the cap does not take in this form, ** arguments included"
    value = call.args[0] if call.args else named.get("wert")
    if not (isinstance(value, ast.Attribute) and _ist_budget_objekt(value.value, *budget)):
        return "caps a value that is not read from the budget object, so the guard cannot tell its axis"
    axis = value.attr
    if axis not in table:
        return f"{axis}: the table has no entry for this axis"
    cost = named.get("bytes_je_element")
    if isinstance(cost, ast.Constant) and type(cost.value) is int:
        if cost.value < table[axis]:
            return f"{axis}: typed {cost.value} B below the table's {table[axis]} B"
        return None
    if isinstance(cost, ast.Subscript) and _is_the_table(cost.value, tables, modules):
        key = cost.slice
        if isinstance(key, ast.Constant) and key.value == axis:
            return None
        return f"{axis}: reads the entry {ast.unparse(key)} of the table instead of its own axis"
    shown = "nothing" if cost is None else ast.unparse(cost)[:60]
    return f"{axis}: the cost {shown} is neither the table entry of this axis nor a number the guard can compare"


def _docstrings(tree: ast.AST) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                found.add(id(first.value))
    return found


def unproven_cap_costs(path: Path, table) -> list[str]:
    """'file:line problem' for every place where a test file reaches the cap `gedeckelt`, its table or its module in a
    way the guard cannot prove keeps the cost per element at least the measured entry of its axis.

    A POSITIVE LIST, because a list of refused forms binds only what its author thought of. Two counter reviews on
    2026-10-17 showed it twice: the first form of this guard read only `bytes_je_element=<int>` and passed seven other
    forms of a cost of 8 against the entry 48, and the second still passed nineteen, among them a file starting with a
    byte order mark that it skipped as unparseable, the table changed in place, the module attribute replaced, and the
    cap handed on through a helper file. What is allowed now:
      - the cap, its table and its module are bound once, by their import from the cap module, the cap by its own
        name; any other binding of these names is a finding, and so is a star import;
      - the cap is called directly, and the call is proven by `_unproven_cap_call`; any other use of it is a finding;
      - the table is only read, one entry by subscript; the module only gives the cap, the table or its sizes;
      - no attribute of that name is assigned or deleted on any object, and no string other than a docstring names
        them, since getattr, setattr, globals(), sys.modules and exec reach them through strings.
    A file that does not parse is a finding. What the guard does not see: code assembled at run time from pieces (a
    string concatenated to `gedeckelt`, a computed attribute or module name), and a change made from outside the test
    files. The table itself is read-only at run time (`tests/_lastdeckel.py`), so no form lowers one of its entries."""
    try:
        tree = _read_tree(path)
    except SyntaxError as fehler:
        return [f"{path.name}:{fehler.lineno or 0} does not parse, so the guard cannot read it"]
    caps, tables, modules, bound = _cap_bindings(tree)
    budget = _budget_bindungen(tree)
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    docstrings = _docstrings(tree)
    found = [f"{path.name}:{line} {problem}" for line, problem in bound]

    def report(node: ast.AST, problem: str) -> None:
        found.append(f"{path.name}:{node.lineno} {problem}")

    def read_by_subscript(node: ast.AST) -> bool:
        parent = parents.get(id(node))
        return isinstance(parent, ast.Subscript) and parent.value is node and isinstance(parent.ctx, ast.Load)

    for node in ast.walk(tree):
        load = isinstance(getattr(node, "ctx", None), ast.Load)
        parent = parents.get(id(node))
        if (isinstance(node, ast.Name) and load and node.id in caps) or (
                isinstance(node, ast.Attribute) and load and node.attr == "gedeckelt"):
            if isinstance(parent, ast.Call) and parent.func is node:
                problem = _unproven_cap_call(parent, table, budget, tables, modules)
                if problem:
                    report(node, problem)
            else:
                report(node, "uses the cap other than in a direct call, so the guard cannot read what it caps")
        elif isinstance(node, ast.Attribute) and not load and node.attr in _TRACKED_NAMES:
            report(node, f"assigns or deletes the attribute {node.attr} of {ast.unparse(node.value)}")
        elif load and _is_the_table(node, tables, modules) and not read_by_subscript(node):
            report(node, "uses the table other than to read one entry, so it may change it")
        elif isinstance(node, (ast.Name, ast.Attribute)) and load and ast.unparse(node) in modules:
            # An assignment to one of these attributes is reported once, by the branch for attributes above.
            if not (isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in _MODULE_READS):
                report(node, "uses the cap module other than to read the cap, its table or its sizes")
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
              and (node.value in _TRACKED_NAMES or any(t in node.value for t in _TRACKED_IN_TEXT))):
            report(node, "names the cap, its table or its module in a string, which the guard cannot follow")
    return found


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

    def test_die_tabelle_traegt_auch_ungeteilte_instanz_dicts(self):
        """Measured 2026-10-08 on pull request 309: under `--dist=worksteal` the test ran in a worker where an
        instance of ArchiveTimeStamp had broken the key sharing of the instance dicts before, and every further
        instance cost 572.8 B instead of 356.6 B. That is memory the suite really holds, so the table must carry it.
        Measured in a FRESH process, because the break changes the class state for the rest of the process and must
        touch nothing else here.

        The break costs memory on CPython 3.10 only. Measured 2026-10-16 in a fresh process per version: 216.4 B more
        per element on 3.10.12, between 0.0 and 0.2 B on 3.11.15, 3.12.15, 3.13.16 and 3.14.8, where an instance keeps
        its values without a dict of its own until one is asked for (Objects/object_layout.md in CPython). The control
        below therefore states what each interpreter does, a cost above the noise on 3.10 and none beyond it from 3.11
        on. The former `ungeteilt > geteilt` decided on the 0.1 B rounding there: under the baseline of the mutation
        layer (PYTHONHASHSEED=0, CPython 3.12.15) it read 320.9 against 320.9 and stopped all 36 shards of run
        38932917601."""
        import subprocess  # noqa: PLC0415
        programm = (
            "import importlib.util, sys\n"
            f"sys.path[:0] = [{str(TESTS)!r}, {str(TESTS.parent / 'src')!r}]\n"
            f"s = importlib.util.spec_from_file_location('t', {str(Path(__file__))!r})\n"
            "t = importlib.util.module_from_spec(s); s.loader.exec_module(t)\n"
            "from proofbundle.renewal import ArchiveTimeStamp\n"
            "x = ArchiveTimeStamp('sha256', 'a' * 64, 0)\n"
            "geteilt = t.gemessene_bytes_je_element('renewal_ats_chain')\n"
            "object.__delattr__(x, 'time')\n"
            "print(geteilt, t.gemessene_bytes_je_element('renewal_ats_chain'))\n")
        lauf = subprocess.run([sys.executable, "-c", programm], capture_output=True, text=True, timeout=600)
        self.assertEqual(lauf.returncode, 0, lauf.stderr[-2000:])
        geteilt, ungeteilt = (float(z) for z in lauf.stdout.split())
        # One pointer per element: far above the measured spread (0.2 B), far below the effect on 3.10 (216.4 B).
        rauschen = 8.0
        if sys.version_info < (3, 11):
            self.assertGreater(ungeteilt - geteilt, rauschen, "control: breaking the key sharing costs memory")
        else:
            self.assertLessEqual(
                abs(ungeteilt - geteilt), rauschen,
                "control: from CPython 3.11 on breaking the key sharing costs nothing measurable; if it does again, "
                "the entry renewal_ats_chain of the table has to be measured again on this interpreter")
        sys.path.insert(0, str(TESTS))
        from _lastdeckel import KOSTEN_JE_ELEMENT  # noqa: PLC0415
        self.assertGreaterEqual(KOSTEN_JE_ELEMENT["renewal_ats_chain"], max(geteilt, ungeteilt))

    def test_every_cap_cost_is_proven_at_least_the_table(self):
        """Measured 2026-10-16 on the head of pull request 354: 19 calls in eight test files gave `gedeckelt` a typed
        cost per element below the table, 8 B for json_nodes against 48, 256 B for signatures against 320 and 64 B
        for merkle_path against 128. Under the current budget that changes nothing, but under a mutant that raises
        the budget, `list(range(gedeckelt(B.json_nodes, bytes_je_element=8)))` admitted about five times the memory
        the cap promises. The same class as the default of 64 that the docstring of `gedeckelt` names. Every use of
        the cap in the test files must carry a cost the guard can prove, see `unproven_cap_costs`."""
        sys.path.insert(0, str(TESTS))
        from _lastdeckel import KOSTEN_JE_ELEMENT  # noqa: PLC0415
        found = []
        for f in alle_testdateien():
            found.extend(unproven_cap_costs(f, KOSTEN_JE_ELEMENT))
        self.assertEqual(found, [], "these uses of the cap carry a cost per element the guard cannot prove to be at "
                         "least the measured table:\n  " + "\n  ".join(found))

    def test_meta_every_unproven_form_of_a_cap_is_caught(self):
        """Planted cases for the guard above. Each entry is a piece of a planted test file with the lines, counted from
        its first, that the guard must report; an entry with none must not be reported. Every check of the guard has at
        least one entry that only it catches, so a check removed or loosened turns this test red. The forms come from
        the two counter reviews of 2026-10-17, which planted them against the earlier forms of the guard and saw them
        pass."""
        sys.path.insert(0, str(TESTS))
        from _lastdeckel import KOSTEN_JE_ELEMENT  # noqa: PLC0415
        entry = KOSTEN_JE_ELEMENT["json_nodes"]
        entries = [
            # imports the guard accepts
            ("from proofbundle.budget import DEFAULT_BUDGET as B", []),
            ("import _lastdeckel", []),
            ("import _lastdeckel as ld", []),
            ("from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt", []),
            ("from _lastdeckel import KOSTEN_JE_ELEMENT as K, MAX_TESTLAST_BYTES", []),
            ("from functools import partial", []),
            ("import fakemod as other_module", []),
            # the proven forms
            (f"at = gedeckelt(B.json_nodes, bytes_je_element={entry})", []),
            ("lookup = gedeckelt(B.json_nodes, bytes_je_element=KOSTEN_JE_ELEMENT['json_nodes'])", []),
            ("alias_lookup = gedeckelt(B.json_nodes, bytes_je_element=K['json_nodes'])", []),
            ("module_lookup = gedeckelt(B.json_nodes, bytes_je_element=_lastdeckel.KOSTEN_JE_ELEMENT['json_nodes'])", []),
            ("ld_lookup = ld.gedeckelt(B.json_nodes, bytes_je_element=ld.KOSTEN_JE_ELEMENT['json_nodes'])", []),
            (f"by_keyword = gedeckelt(wert=B.json_nodes, bytes_je_element={entry})", []),
            ("limit = _lastdeckel.MAX_TESTLAST_BYTES", []),
            ("read_elsewhere = KOSTEN_JE_ELEMENT['json_nodes']", []),
            ("def documented():\n    \"\"\"Names gedeckelt( and _lastdeckel in a docstring.\"\"\"\n    return None", []),
            ("class Other: json_nodes = 10 ** 12", []),
            ("text = 'a string that names nothing the guard follows'", []),
            # calls whose cost is not proven
            (f"below = gedeckelt(B.json_nodes, bytes_je_element={entry - 1})", [0]),
            ("unknown = gedeckelt(B.no_such_axis, bytes_je_element=4096)", [0]),
            ("_COST = 8", []),
            ("named_cost = gedeckelt(B.json_nodes, bytes_je_element=_COST)", [0]),
            (f"keyword_below = gedeckelt(wert=B.json_nodes, bytes_je_element={entry - 1})", [0]),
            ("n = B.json_nodes", []),
            (f"named_value = gedeckelt(n, bytes_je_element={entry})", [0]),
            ("expression = gedeckelt(B.json_nodes, bytes_je_element=4 * 2)", [0]),
            ("lookup_minus = gedeckelt(B.json_nodes, bytes_je_element=KOSTEN_JE_ELEMENT['json_nodes'] - 40)", [0]),
            (f"not_an_int = gedeckelt(B.json_nodes, bytes_je_element={float(entry)})", [0]),
            ("star = gedeckelt(B.json_nodes, **{'bytes_je_element': 8})", [0]),
            ("options = {}", []),
            (f"star_beside = gedeckelt(B.json_nodes, bytes_je_element={entry}, **options)", [0]),
            ("positional = gedeckelt(B.json_nodes, 8)", [0]),
            (f"positional_beside = gedeckelt(B.json_nodes, 8, bytes_je_element={entry})", [0]),
            (f"value_twice = gedeckelt(B.json_nodes, wert=B.json_nodes, bytes_je_element={entry})", [0]),
            (f"other_object = gedeckelt(Other.json_nodes, bytes_je_element={entry})", [0]),
            (f"not_the_budget = gedeckelt(len('abc'), bytes_je_element={entry})", [0]),
            ("other_axis = gedeckelt(B.json_nodes, bytes_je_element=KOSTEN_JE_ELEMENT['string_len'])", [0]),
            ("other_table = gedeckelt(B.json_nodes, bytes_je_element=other_module.KOSTEN_JE_ELEMENT['json_nodes'])",
             [0]),
            ("through_module = ld.gedeckelt(B.json_nodes, bytes_je_element=8)", [0]),
            ("not_a_call = partial(gedeckelt, bytes_je_element=8)", [0]),
            # bindings of a followed name other than its import from the cap module
            ("from _lastdeckel import gedeckelt as cap", [0]),
            ("aliased = cap(B.json_nodes, bytes_je_element=8)", [0]),
            ("from fakemod import KOSTEN_JE_ELEMENT", [0]),
            ("from fakemod import *", [0]),
            ("import fakemod as _lastdeckel", [0]),
            ("KOSTEN_JE_ELEMENT = {'json_nodes': 8}", [0]),
            ("K |= {'json_nodes': 8}", [0]),
            ("(gedeckelt := print)", [0]),
            ("for _lastdeckel in (): pass", [0]),
            ("del MAX_TESTLAST_BYTES", [0]),
            ("with open('x') as ld: pass", [0]),
            ("def takes(KOSTEN_JE_ELEMENT): return None", [0]),
            ("def gedeckelt(wert, *, bytes_je_element): return wert", [0]),
            ("class KOSTEN_JE_ELEMENT: pass", [0]),
            ("def declares():\n    global KOSTEN_JE_ELEMENT\n    return None", [1]),
            ("try:\n    pass\nexcept ValueError as gedeckelt:\n    pass", [2]),
            ("match 1:\n    case gedeckelt:\n        pass", [1]),
            ("match []:\n    case [*KOSTEN_JE_ELEMENT]:\n        pass", [1]),
            ("match {}:\n    case {**K}:\n        pass", [1]),
            # uses of the table, the module or the attributes other than the allowed ones
            ("KOSTEN_JE_ELEMENT.update(json_nodes=8)", [0]),
            ("K['json_nodes'] = 8", [0]),
            ("copy = KOSTEN_JE_ELEMENT", [0]),
            ("_lastdeckel.KOSTEN_JE_ELEMENT['json_nodes'] = 8", [0]),
            ("_lastdeckel.MAX_TESTLAST_BYTES = 1 << 62", [0]),
            ("other_module.gedeckelt = print", [0]),
            ("del ld.gedeckelt", [0]),
            ("module_dict = ld.__dict__", [0]),
            ("setattr(_lastdeckel, 'x', 1)", [0]),
            ("by_name = globals()['KOSTEN_JE_ELEMENT']", [0]),
            ("by_attribute_name = getattr(other_module, 'gedeckelt')", [0]),
            ("exec(\"KOSTEN_JE_ELEMENT = {'json_nodes': 8}\")", [0]),
            ("patch_target = '_lastdeckel.MAX_TESTLAST_BYTES'", [0]),
        ]
        source, expected, line = [], [], 1
        for text, caught in entries:
            source.append(text)
            expected.extend(f"test_planted.py:{line + offset}" for offset in caught)
            line += text.count("\n") + 1
        elsewhere = (
            "from proofbundle.budget import DEFAULT_BUDGET as B\n"
            "from _lastdeckel import gedeckelt\n"
            "from somewhere_else import KOSTEN_JE_ELEMENT\n"
            "elsewhere = gedeckelt(B.json_nodes, bytes_je_element=KOSTEN_JE_ELEMENT['json_nodes'])\n")
        with tempfile.TemporaryDirectory() as d:
            planted = Path(d) / "test_planted.py"
            planted.write_text("\n".join(source) + "\n", encoding="utf-8")
            found = unproven_cap_costs(planted, KOSTEN_JE_ELEMENT)
            (Path(d) / "test_elsewhere.py").write_text(elsewhere, encoding="utf-8")
            found_elsewhere = unproven_cap_costs(Path(d) / "test_elsewhere.py", KOSTEN_JE_ELEMENT)
            bom = Path(d) / "test_bom.py"
            bom.write_bytes(b"\xef\xbb\xbf" + (
                "from proofbundle.budget import DEFAULT_BUDGET as B\nfrom _lastdeckel import gedeckelt\n"
                "xs = list(range(gedeckelt(B.json_nodes, bytes_je_element=8)))\n").encode("utf-8"))
            found_bom = unproven_cap_costs(bom, KOSTEN_JE_ELEMENT)
            broken = Path(d) / "test_broken.py"
            broken.write_text("def broken(:\n    pass\n", encoding="utf-8")
            found_broken = unproven_cap_costs(broken, KOSTEN_JE_ELEMENT)
        self.assertEqual(sorted(f.split(" ", 1)[0] for f in found), sorted(expected), "\n".join(found))
        self.assertEqual([f.split(" ", 1)[0] for f in found_elsewhere], ["test_elsewhere.py:3", "test_elsewhere.py:4"],
                         found_elsewhere)
        self.assertEqual([f.split(" ", 1)[0] for f in found_bom], ["test_bom.py:3"], found_bom)
        self.assertEqual(len(found_broken), 1, found_broken)
        self.assertIn("does not parse", found_broken[0])

    def test_every_file_the_guards_read_parses(self):
        """A file the guards of this module cannot parse is a file they do not read. The first form of the cost guard
        skipped such a file in silence, and a file that starts with a byte order mark was one: Python runs it, while
        `ast.parse` of its decoded text refuses it (counter review 2026-10-17). The guards now parse the bytes, and a
        file that still does not parse turns this test red instead of passing unread."""
        unread = []
        for f in alle_testdateien():
            try:
                _read_tree(f)
            except SyntaxError as fehler:
                unread.append(f"{f.relative_to(TESTS)}:{fehler.lineno}")
        self.assertEqual(unread, [], "the guards cannot read these files:\n  " + "\n  ".join(unread))

    def test_the_table_refuses_every_change_at_run_time(self):
        """The guard reads source, and code can reach the table at run time in forms no reading of source lists. So
        the table itself refuses a change: no entry can be set, updated or deleted, whatever form the code takes."""
        sys.path.insert(0, str(TESTS))
        import _lastdeckel  # noqa: PLC0415
        with self.assertRaises(TypeError):
            _lastdeckel.KOSTEN_JE_ELEMENT["json_nodes"] = 8
        with self.assertRaises(TypeError):
            del _lastdeckel.KOSTEN_JE_ELEMENT["json_nodes"]
        with self.assertRaises(AttributeError):
            _lastdeckel.KOSTEN_JE_ELEMENT.update(json_nodes=8)
        self.assertEqual(_lastdeckel.KOSTEN_JE_ELEMENT["json_nodes"], 48)

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
