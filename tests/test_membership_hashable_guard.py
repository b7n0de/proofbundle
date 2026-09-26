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

HONEST LIMIT: this scans `src/proofbundle/**`, module-level container constants (also when bound
inside a module-level `if`, `try`, `with`, `for`, `while` or `match`, and also when another module of
the package imports them by name, `from .x import NAME`, through a chain of such imports, or with
`from .x import *`), and single-operator comparisons. A container built at runtime (a module-level
`set(A) | {...}` included), reached as a module attribute (`x.NAME`) or through a string
(`globals()`), or a chained comparison is NOT covered — that is stated here rather than left for
someone to discover, and `is_member` is safe to use everywhere regardless. A LOOKUP or a WRITE hashes
its key too (`CONST.get(x)`, `CONST[x]`, `CONST[x] = v`, `del CONST[x]`, `CONST.setdefault(x)`,
`CONST.pop(x)`, and `add`, `discard`, `remove` on a set); those sites are listed with the reason each
is safe and the number of sites per key, in `_LOOKUPS_CLASSIFIED` below. Every OTHER read of such a
container name (handed to a function, put in a tuple, a method reached without a call, a set
operation with a literal that holds a name, `set()` over `.values()`) is listed the same way in
`_OTHER_USES_CLASSIFIED`: the guard reads every use of the name and reports what no known form covers,
so a spelling nobody listed turns it red, and so does one more site under a listed key.
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


def _module_level_statements(anweisungen: list):
    """Every statement that runs at module level: the module body, and the bodies of the compound
    statements in it (`if`, `try` with its handlers, `else` and `finally`, `with`, `for`, `while`,
    `match`), never the body of a def, a class or a lambda. The delta run on 09d5c5b3 bound
    `_M = {"a": 1}` under `try:` and read `_M.get(k)`: only `tree.body` was scanned, so `_M` was no
    container and the TypeError went unreported."""
    for s in anweisungen:
        yield s
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for feld in ("body", "orelse", "finalbody"):
            yield from _module_level_statements(getattr(s, feld, None) or [])
        for zweig in (getattr(s, "handlers", None) or []) + (getattr(s, "cases", None) or []):
            yield from _module_level_statements(zweig.body)


def _hashing_containers(tree: ast.Module) -> dict[str, str]:
    """Module-level names bound to a hash-based container — the ones whose membership test hashes."""
    gefunden: dict[str, str] = {}
    for node in _module_level_statements(tree.body):
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


def _modulname(pfad: Path, wurzel: Path) -> str:
    return pfad.relative_to(wurzel).with_suffix("").as_posix().replace("/", ".").removesuffix(".__init__")


def containers_by_module(quellen: dict[str, str | tuple[str, bool]]) -> dict[str, dict[str, str]]:
    """module -> {name: art} for every hashing container a module of the package binds: its own, and
    the ones it imports, resolved to a fixpoint. A value is the source, or (source, is_package_init)
    for a package `__init__`, whose relative imports resolve from the package itself.

    WHY A FIXPOINT, measured by the delta run on 09d5c5b3: `from .renewal import HASH_REGISTRY`, where
    `renewal` itself imported the name from `hashalg`, and `from .hashalg import *` both bound the dict
    and read `HASH_REGISTRY.get(alg)`; a view of each module's OWN containers resolved neither, and
    both raised for an unhashable `alg` with the guard green. A name imported from a module that
    itself imported it is the same container, however long the chain; the loop runs until no module's
    view changes, and a view that still changes after one round per module is an error, not a result."""
    baeume: dict[str, tuple[ast.Module, bool]] = {}
    for modul, wert in quellen.items():
        text, ist_init = (wert, False) if isinstance(wert, str) else wert
        baeume[modul] = (ast.parse(text), ist_init)
    eigene = {modul: _hashing_containers(baum) for modul, (baum, _i) in baeume.items()}
    sicht = {modul: dict(e) for modul, e in eigene.items()}
    for _runde in range(len(baeume) + 1):
        geaendert = False
        for modul, (baum, ist_init) in baeume.items():
            neu = {**imported_containers(baum, modul, ist_init, sicht), **eigene[modul]}
            if neu != sicht[modul]:
                sicht[modul], geaendert = neu, True
        if not geaendert:
            return sicht
    raise RuntimeError("the imported containers reach no fixpoint: one name is imported from two "
                       "modules that disagree on what it is")


def _package_sources() -> dict[str, tuple[str, bool]]:
    """module -> (source, is_package_init) for every module under src/proofbundle."""
    return {_modulname(p, SRC.parent): (p.read_text(encoding="utf-8"), p.name == "__init__.py")
            for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts}


def imported_containers(tree: ast.Module, modul: str, ist_init: bool,
                        je_modul: dict[str, dict[str, str]]) -> dict[str, str]:
    """Names this module binds by `from <module> import NAME [as ALIAS]` to a hashing container that
    module defines. Gate run 1 on 11110281 (234-1-02): `_hashing_containers` read one file, so a dict
    imported from another module was no container at all; `renewal.py` read `HASH_REGISTRY` from
    `hashalg`, `cli.py` read `AUTOMATION_BLOCKER_REASONS` from `bundle`, and `relation_statement.py`
    tested membership in `SUCCESSOR_RELATIONS` from `relation`, all four unseen. An import inside a
    function counts for the whole file: that reads more, never less. `from <module> import *` binds
    every hashing container `je_modul` gives for that module, underscore names included (the same
    rule: more, never less); with the view of `containers_by_module` that is the module's own
    containers and the ones it imports."""
    paket = modul if ist_init else modul.rpartition(".")[0]
    gefunden: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            basis = paket
            for _ in range(node.level - 1):
                basis = basis.rpartition(".")[0]
            ziel = f"{basis}.{node.module}" if node.module else basis
        else:
            ziel = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                gefunden.update(je_modul.get(ziel, {}))
                continue
            art = je_modul.get(ziel, {}).get(alias.name)
            if art:
                gefunden[alias.asname or alias.name] = art
    return gefunden


def _behaelter(tree: ast.Module, modul: str | None, ist_init: bool = False,
               je_modul: dict[str, dict[str, str]] | None = None) -> dict[str, str]:
    """The hashing containers a module can see: its own, and with `modul` the ones it imports."""
    eigene = _hashing_containers(tree)
    if modul is None or je_modul is None:
        return eigene
    return {**imported_containers(tree, modul, ist_init, je_modul), **eigene}


def unguarded_membership_sites(quelle: str, name: str = "<quelle>", modul: str | None = None,
                               ist_init: bool = False,
                               je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(Zeile, linker Ausdruck, Behälter) für jeden ungeschützten Mitgliedstest.

    A CONSTANT left operand is skipped on purpose: ``"status" in predicate`` asks whether a KEY is
    present, the left side is a literal string, and a literal is always hashable. Flagging it would
    make the scanner noisy exactly where it is always right, and a noisy scanner gets silenced."""
    tree = ast.parse(quelle, filename=name)
    behaelter = _behaelter(tree, modul, ist_init, je_modul)
    treffer: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
            continue
        rechts = node.comparators[0]
        # `x in CONST.keys()` hashes x as `x in CONST` does (the second delta run on e4ea49b9).
        if (isinstance(rechts, ast.Call) and not rechts.args and isinstance(rechts.func, ast.Attribute)
                and rechts.func.attr == "keys" and isinstance(rechts.func.value, ast.Name)):
            rechts = rechts.func.value
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


def _umschliessende_definition(quelle: str) -> dict[int, str]:
    """Zeile -> qualifizierter Name der umschliessenden def/class, sonst '<modulebene>'.

    WARUM DIESER SCHLUESSELTEIL EXISTIERT, gemessen am 15.09.2026 von einer adversarialen Linse.
    Eine Fassung dieses Riegels band auf (Datei, Ausdruck) mit Anzahl. Damit liess sich das Budget
    WASCHEN: die getragene, angreiferexponierte Stelle in ``derive_limitation_codes`` schliessen und
    anderswo in derselben Datei eine NEUE ungeschuetzte Konstruktion mit DEMSELBEN Ausdruck
    aufmachen — die Anzahl blieb drei, der Riegel blieb gruen, und der neue Code warf nachweislich
    ``TypeError: unhashable type: 'list'``. Die alte, zeilengebundene Regel HAETTE ihn gefangen.
    Der Name der umschliessenden Definition ueberlebt eine Zeilenverschiebung und unterscheidet
    trotzdem zwei Stellen: eine neue Stelle landet in einer anderen Definition und ist damit neu.
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
    """(Datei, umschliessende Definition, Ausdruck) -> Zeilen.

    Die Zeilen werden MITGEFUEHRT, damit eine Meldung einen Menschen hinschickt — aber sie sind
    NICHT der Schluessel. Wer sie zum Schluessel macht, baut ein Tor, das jeder Merge neu scharf
    stellt, ohne dass sich eine einzige Stelle geaendert haette.

    EIN LEERES quelltexte IST EIN FEHLER, kein leerer Baum (Linsenfund P3 vom 15.09.2026): die
    Pruefung lautete ``is not None``, und ein leeres dict uebersprang damit still den GANZEN
    Plattenlauf und meldete sauber. Ein kuenftiger Aufrufer, der nur geaenderte Dateien reicht,
    waere genau so in ein stilles Gruen gelaufen.
    """
    if quelltexte is not None and not quelltexte:
        raise ValueError(
            "leeres quelltexte: das waere ein stiller Freispruch ueber einen ungeprueften Baum. "
            "Fuer den vollen Baum None uebergeben, nicht {}")
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
    """Was die Grundlinie NICHT deckt — je (Datei, Ausdruck) die Anzahl ueber dem getragenen Stand."""
    import collections  # noqa: PLC0415
    getragen = collections.Counter(
        (e["file"], e["qualname"], e["expr"]) for e in _grundlinie()["carried"])
    funde: list[str] = []
    for schluessel, zeilen in sorted(_gesehene_stellen(quelltexte).items()):
        ueberzaehlig = len(zeilen) - getragen.get(schluessel, 0)
        if ueberzaehlig > 0:
            funde.append(f"{schluessel[0]}  in {schluessel[1]}()  {schluessel[2]}  "
                         f"{ueberzaehlig} von {len(zeilen)} nicht getragen, Zeilen {sorted(zeilen)}")
    return funde


#: The methods that hash their first argument, per kind of module-level container. A lens on 3c513874
#: (the 228bc stack delta, D-2) wrote `_VERIFIERS[type_name] = verifier` and `_VERIFIERS.setdefault(...)`
#: past the first form, which knew `.get` and a read `CONST[x]` only: a write hashes its key as a read
#: does. `update` and `|=` are read when every argument is a literal that names its keys; with a name,
#: a `*x` or `**x`, and when the container is handed to a function, the read is an other use
#: (`other_uses` below) and is listed.
_HASHING_METHODS = {"dict": {"get", "setdefault", "pop", "__getitem__", "__setitem__", "__delitem__",
                             "__contains__"},
                    "set": {"add", "discard", "remove", "__contains__"}, "frozenset": {"__contains__"}}
#: `operator.getitem(CONST, k)` and its siblings hash k as `CONST[k]` does (the second delta run on
#: e4ea49b9 wrote `operator.getitem` and `CONST.__getitem__` past the first form).
_OPERATOR_ACCESS = {"getitem", "setitem", "delitem", "contains"}


def _literal_keys(value) -> list | None:
    """The keys a dict literal or the elements a set, list or tuple literal hands to `update` or `|=`,
    each of which is hashed on the way in; None when the value is not such a literal or does not name
    every key it hands over (`**x` in a dict, `*x` in a set, list or tuple), because then it hashes
    keys nobody can list."""
    if isinstance(value, ast.Dict):
        return None if any(k is None for k in value.keys) else list(value.keys)
    if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
        return None if any(isinstance(e, ast.Starred) for e in value.elts) else list(value.elts)
    return None


def _update_keys(call: ast.Call, art: str) -> list | None:
    """The keys `CONST.update(...)` hashes, or None when it hashes one nobody can list.

    The delta run on 09d5c5b3: `set.update(*iterables)` hashes EVERY argument, and the first form read
    the first one only, so `_S.update(["type"], k)` was known and raised for `k = [[1]]`. Every
    positional argument has to be a literal that names its keys; a keyword `.update(k=v)` on a dict
    hashes only the identifier, a literal, and `**x` hashes keys nobody can list."""
    if art not in ("dict", "set"):
        return None
    if any(kw.arg is None for kw in call.keywords) or (call.keywords and art != "dict"):
        return None
    keys: list = []
    for arg in call.args:
        literal = _literal_keys(arg)
        if literal is None:
            return None
        keys.extend(literal)
    return keys


def constant_lookups(quelle: str, name: str = "<quelle>", modul: str | None = None,
                     ist_init: bool = False,
                     je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(line, container, key) for every call of a method that hashes its argument on a module-level
    hashing container CONST (`get`, `setdefault`, `pop` on a dict; `add`, `discard`, `remove` on a set),
    and every `CONST[x]` on a dict whether it reads, writes or deletes, where CONST is the module's own or
    with `modul` one it imports from the package, and the key is not a literal. Such an access hashes `x`
    and raises TypeError for an unhashable one. For `update` and `|=` every key of every literal
    argument is listed; an argument that is no literal is reported by `other_uses`."""
    tree = ast.parse(quelle, filename=name)
    behaelter = _behaelter(tree, modul, ist_init, je_modul)
    operator_names = {"operator"} | {a.asname for n in ast.walk(tree) if isinstance(n, ast.Import)
                                     for a in n.names if a.name == "operator" and a.asname}
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        keys: list = []
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id in behaelter):
            const = node.func.value.id
            if node.func.attr in _HASHING_METHODS[behaelter[const]] and node.args:
                keys = [node.args[0]]
            elif node.func.attr == "update":
                # every literal argument, also next to one that is not (other_uses reports that one)
                keys = [k for arg in node.args for k in (_literal_keys(arg) or [])]
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and isinstance(node.func.value, ast.Name) and node.func.value.id in operator_names
              and node.func.attr in _OPERATOR_ACCESS and len(node.args) >= 2
              and isinstance(node.args[0], ast.Name) and node.args[0].id in behaelter):
            const, keys = node.args[0].id, [node.args[1]]
        elif (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
              and behaelter.get(node.value.id) == "dict"):
            const, keys = node.value.id, [node.slice]
        elif (isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr)
              and isinstance(node.target, ast.Name) and node.target.id in behaelter):
            const, keys = node.target.id, _literal_keys(node.value) or []
        for key in keys:
            if not isinstance(key, ast.Constant):
                found.append((node.lineno, const, ast.unparse(key)))
    return found


#: The calls that only iterate their one argument, the calls that hash what they iterate, and the dict
#: views a loop or such a call iterates.
_ITERATING_CALLS = {"sorted", "list", "tuple", "len"}
_HASHING_CALLS = {"set", "frozenset", "dict"}
_VIEW_METHODS = {"items", "values", "keys"}


def _hashing_call(p: ast.AST | None, node: ast.AST) -> bool:
    return (isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id in _HASHING_CALLS
            and p.args == [node] and not p.keywords)


def _iterated(node: ast.AST, parents: dict, view: str | None = None) -> bool:
    """Is this expression the source of a `for`, of a comprehension, or the one argument of a call
    that only iterates it? Iterating a container hashes nothing from outside.

    `set`, `frozenset` and `dict` HASH what they iterate. Over the container or its `.keys()` that is a
    key, already hashed; over `.values()` or `.items()` it is a value, which can come from outside:
    the delta run on 09d5c5b3 wrote `_M["a"] = v` with `v = []`, and `set(_M.values())` raised while the
    guard counted it as iteration. A set or dict comprehension over those views hashes the same values,
    and so does a generator handed to `set`, `frozenset` or `dict`; each is an other use."""
    p = parents.get(node)
    werte = view in ("values", "items")
    if isinstance(p, (ast.For, ast.comprehension)) and p.iter is node:
        if not (werte and isinstance(p, ast.comprehension)):
            return True
        comp = parents.get(p)
        return not (isinstance(comp, (ast.SetComp, ast.DictComp))
                    or (isinstance(comp, ast.GeneratorExp) and _hashing_call(parents.get(comp), comp)))
    if _hashing_call(p, node):
        return not werte
    return (isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id in _ITERATING_CALLS
            and p.args == [node] and not p.keywords)


def other_uses(quelle: str, name: str = "<quelle>", modul: str | None = None, ist_init: bool = False,
               je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(line, container, use) for every read of a module-level hashing container that none of the
    known forms covers. DENY BY DEFAULT: the third delta run on 1ab75135 wrote five more spellings
    past the two detectors above (`getter = CONST.get`, `getattr(CONST, "get")`,
    `CONST.__class__.__getitem__`, `CONST.keys().__contains__`, `x in CONST.items()`), and each hashed
    an unhashable key. A list of spellings is one spelling behind; a list of the forms that are known,
    with everything else named, is not.

    Known, and not reported here: a hashing access with a key (`constant_lookups`, including `update`
    and `|=` when every argument is a literal that names its keys, and `update(k=v)` on a dict), a
    membership test (`unguarded_membership_sites`, also through `.keys()`), the second argument of
    `is_member`, iteration (a `for`, a comprehension, the one argument of sorted/list/tuple/len, also
    through `.items()`, `.values()`, `.keys()`; the one argument of set/frozenset/dict, a set or dict
    comprehension and a generator handed to set/frozenset/dict only over the container or `.keys()`,
    because they hash what they iterate), a condition, and a set operation or comparison whose other
    side is another constant container, a literal, or a set or dict literal whose elements or keys are
    all literals. Every other read is reported: passing the container to a function, putting it in a
    tuple, reaching a method without calling it, `update` or `|=` with a name, a `*x` or `**x`,
    `_S | {k}`, `set(CONST.values())`. Keys are version-stable forms, not `ast.unparse` of the whole
    expression."""
    tree = ast.parse(quelle, filename=name)
    behaelter = _behaelter(tree, modul, ist_init, je_modul)
    operator_names = {"operator"} | {a.asname for n in ast.walk(tree) if isinstance(n, ast.Import)
                                     for a in n.names if a.name == "operator" and a.asname}
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}

    def constant(e: ast.AST) -> bool:
        # A set literal hashes its elements when it is built and a dict literal its keys, so it is a
        # constant operand only when every one of them is a literal: `_S | {k}` and `_M | {k: 1}`
        # raised for `k = []` while the first form counted any literal as constant (the delta run on
        # 09d5c5b3). A `**x` in a dict literal has the key None here and is no literal either.
        if isinstance(e, ast.Set):
            return all(isinstance(x, ast.Constant) for x in e.elts)
        if isinstance(e, ast.Dict):
            return all(isinstance(k, ast.Constant) for k in e.keys)
        return isinstance(e, ast.Constant) or (isinstance(e, ast.Name) and e.id in behaelter)

    found: list[tuple[int, str, str]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id in behaelter:
            if not (isinstance(n.op, ast.BitOr) and _literal_keys(n.value) is not None):
                found.append((n.lineno, n.target.id, f"{type(n.op).__name__}= {ast.unparse(n.value)}"))
            continue
        if not (isinstance(n, ast.Name) and n.id in behaelter and isinstance(n.ctx, ast.Load)):
            continue
        art, p, known = behaelter[n.id], parents.get(n), False
        if isinstance(p, ast.Attribute):
            call = parents.get(p)
            called = isinstance(call, ast.Call) and call.func is p
            if called and p.attr in _HASHING_METHODS[art] and call.args:
                known = True
            elif called and p.attr == "update" and _update_keys(call, art) is not None:
                known = True
            elif called and p.attr in _VIEW_METHODS and not call.args:
                over = parents.get(call)
                known = _iterated(call, parents, p.attr) or (
                    p.attr == "keys" and isinstance(over, ast.Compare) and len(over.ops) == 1
                    and isinstance(over.ops[0], (ast.In, ast.NotIn)) and over.comparators[0] is call)
            use = f".{p.attr}()" if called else f".{p.attr}"
        elif isinstance(p, ast.Subscript) and p.value is n:
            known, use = art == "dict", "[...]"
        elif isinstance(p, ast.Compare):
            if len(p.ops) == 1 and isinstance(p.ops[0], (ast.In, ast.NotIn)) and p.comparators[0] is n:
                known = True
            else:
                others = [e for e in (p.left, *p.comparators) if e is not n]
                known = (not any(isinstance(o, (ast.In, ast.NotIn)) for o in p.ops)
                         and all(constant(e) for e in others))
            use = " ".join(type(o).__name__ for o in p.ops) + " " + " ".join(
                ast.unparse(e) for e in (p.left, *p.comparators) if e is not n)
        elif isinstance(p, ast.Call):
            func = ast.unparse(p.func)
            if func == "is_member" and len(p.args) == 2 and p.args[1] is n:
                known = True
            elif (isinstance(p.func, ast.Attribute) and isinstance(p.func.value, ast.Name)
                  and p.func.value.id in operator_names and p.func.attr in _OPERATOR_ACCESS
                  and len(p.args) >= 2 and p.args[0] is n):
                known = True
            else:
                known = _iterated(n, parents)
            use = f"{func}(argument {p.args.index(n) + 1})" if n in p.args else f"{func}(*)"
        elif isinstance(p, ast.keyword):
            call = parents.get(p)
            use = f"{ast.unparse(call.func)}({p.arg}=)" if isinstance(call, ast.Call) else f"{p.arg}="
        elif isinstance(p, (ast.For, ast.comprehension)) and p.iter is n:
            known, use = True, "iteration"
        elif isinstance(p, (ast.If, ast.IfExp, ast.While)) and p.test is n:
            known, use = True, "condition"
        elif isinstance(p, ast.BinOp):
            other = p.right if p.left is n else p.left
            known, use = constant(other), f"{type(p.op).__name__} {ast.unparse(other)}"
        else:
            use = type(p).__name__ if p is not None else "module"
        if not known:
            found.append((n.lineno, n.id, use))
    return found


#: Every lookup on a module-level dict with a key that is not a literal, and why it cannot raise.
#: Keyed by (file, enclosing definition, dict, key), not by line (the lesson of the baseline below), and
#: each key carries the NUMBER of sites it covers with the reason: (count, reason). A key without a count
#: covered any number of sites, so a second site under a classified key was not new (the delta run on
#: 09d5c5b3 planted `_probe = _VERIFIERS.get(atype)` in `anchors.verify_anchor` before the is_member
#: check, the guard stayed green, and the probe raised TypeError for a list).
#: WHERE THIS COMES FROM: the ECMA-reading generator of the 228bc fix sent a list as a trust pack key's
#: `alg`, and `_KEY_ALG_LABEL.get(alg)` raised TypeError out of `verify_trust_pack` before any signature
#: was counted. The membership scanner above sees `in` and `not in`, not a lookup. Measured on 9151e4ca
#: (2026-09-26): 14 sites, none open. Gate run 1 on 11110281 (234-1-02) found three more that the first
#: form could not see, because their dict is imported from another module: 17 then. The 228bc stack
#: delta (D-2) found the writes, `CONST[x] = v` and `.setdefault`, which the lookup form did not visit:
#: 19. Measured again on the tree of 09d5c5b3 after every form of the delta run was read: 19 sites
#: under 19 keys, none open. A new site, also one more under a listed key, turns this red until it is
#: classified here; a site that is gone must leave the list or lower its count.
_LOOKUPS_CLASSIFIED = {
    ("proofbundle/__init__.py", "__getattr__", "_LAZY", "name"):
        (1, "own value: the attribute protocol passes a str"),
    ("proofbundle/agent_review.py", "evaluate_time_policy", "_POLICY_ACHSE", "art"):
        (1, "guarded: isinstance(art, str) and is_member(art, _POLICY_ACHSE) return before it"),
    ("proofbundle/anchors.py", "verify_anchor", "_VERIFIERS", "atype"):
        (1, "guarded: isinstance(atype, str) and is_member(atype, _VERIFIERS) return before it"),
    ("proofbundle/hashalg.py", "resolve_hash_alg", "HASH_REGISTRY", "alg_id"):
        (1, "guarded: a non-str alg_id raises MissingHashAlgId before it"),
    ("proofbundle/intoto.py", "to_test_result_statement", "_RESULT_ENUM", "verdikt"):
        (1, "own value: require_bool_verdict returns a bool or raises"),
    ("proofbundle/kbjwt.py", "verify_key_binding", "_HASH_ALG", "sd_alg"):
        (1, "guarded: is_member(sd_alg, _HASH_ALG) returns before it"),
    ("proofbundle/policy_profiles.py", "canonical_profile_name", "PROFILE_ALIASES", "short"):
        (1, "guarded: is_member(short, PROFILE_ALIASES) in the same branch"),
    ("proofbundle/policy_profiles.py", "profile_path", "PROFILE_ALIASES", "short"):
        (1, "guarded: is_member(short, PROFILE_ALIASES) in the same branch"),
    ("proofbundle/policy_profiles.py", "profile_path", "PROFILE_NAMES", "canonical"):
        (1, "guarded: canonical is a member of PROFILE_NAMES or a value of PROFILE_ALIASES, else it raised"),
    ("proofbundle/sdjwt.py", "_digest", "_HASH_ALG", "alg"):
        (1, "guarded by the one caller: verify_sd_jwt returns on not is_member(sd_alg, _HASH_ALG) first"),
    ("proofbundle/sdjwt.py", "verify_sd_jwt", "_ISSUER_SIG_VERIFIERS", "alg"):
        (1, "guarded: isinstance(alg, str) in the same expression"),
    ("proofbundle/sdjwt_issue.py", "present_with_key_binding", "_HASH_BY_SD_ALG", "sd_alg"):
        (1, "guarded: is_member(sd_alg, _HASH_BY_SD_ALG) raises ValueError before it"),
    ("proofbundle/statuslist.py", "verify_status_snapshot", "STATUS_LABELS", "status"):
        (1, "own value: an int read from the bit array"),
    ("proofbundle/trust_pack.py", "validate_trust_pack_predicate", "_KEY_ALG_LABEL", "alg"):
        (1, "guarded: `alg in _KEY_ALGS` against a tuple, which compares and hashes nothing"),
    # Three more, seen once imported containers counted (gate run 1 on 11110281, 234-1-02).
    ("proofbundle/renewal.py", "_is_deprecated_hash", "HASH_REGISTRY", "alg"):
        (1, "guarded: a non-str alg returns False before it"),
    ("proofbundle/renewal.py", "verify_sequence", "HASH_REGISTRY", "newest.hash_alg"):
        (1, "guarded: isinstance(newest.hash_alg, str) in the same expression"),
    ("proofbundle/cli.py", "_cmd_verify", "AUTOMATION_BLOCKER_REASONS", "_blk"):
        (1, "own value: bundle.py builds automationBlockers from string literals only"),
    # Two writes, seen once a write hashes its key as a read does (the 228bc stack delta, D-2).
    ("proofbundle/anchors.py", "register_anchor_type", "_VERIFIERS", "type_name"):
        (1, "guarded: a type_name that is no non-empty str raises BundleFormatError before it"),
    ("proofbundle/anchors.py", "_ensure_builtin_types", "_VERIFIERS", "anchors_chia.ANCHOR_TYPE"):
        (1, "own value: anchors_chia.ANCHOR_TYPE is the string literal \"chia-datalayer/v1\""),
}


def _in_the_tree(detektor, ersatz: dict[str, str] | None = None) -> dict[tuple, int]:
    """(file, enclosing definition, container, key or use) -> NUMBER of sites the detector reports
    over src/proofbundle. `ersatz` maps a file (as `proofbundle/x.py`) to a planted text read in its
    place, so a test can plant a site into a copy of the real tree; a name that is not a file of the
    tree is an error, not a file nobody reads."""
    import collections  # noqa: PLC0415
    quellen = _package_sources()
    for datei, text in (ersatz or {}).items():
        modul = _modulname(SRC.parent / datei, SRC.parent)
        if modul not in quellen:
            raise KeyError(f"{datei} is no file of the tree; a plant there would be read by nobody")
        quellen[modul] = (text, quellen[modul][1])
    je_modul = containers_by_module(quellen)
    gezaehlt: collections.Counter = collections.Counter()
    for d in sorted(SRC.rglob("*.py")):
        if "__pycache__" in d.parts:
            continue
        modul = _modulname(d, SRC.parent)
        quelle, ist_init = quellen[modul]
        wo = _umschliessende_definition(quelle)
        for zeile, const, was in detektor(quelle, str(d), modul, ist_init, je_modul):
            gezaehlt[(str(d.relative_to(SRC.parent)), wo.get(zeile, "<modulebene>"), const, was)] += 1
    return dict(gezaehlt)


def _drift(gezaehlt: dict[tuple, int], klassiert: dict[tuple, tuple[int, str]]) -> tuple[list[str], list[str]]:
    """(new, gone): the keys with more sites in the tree than classified, and the classified keys with
    fewer sites in the tree than their count. Both directions, exact: a list of keys without counts let
    one classified key cover any number of sites."""
    neu = [f"{k}: {n} in the tree, {klassiert[k][0] if k in klassiert else 0} classified"
           for k, n in sorted(gezaehlt.items()) if n > (klassiert[k][0] if k in klassiert else 0)]
    weg = [f"{k}: {gezaehlt.get(k, 0)} in the tree, {n} classified"
           for k, (n, _grund) in sorted(klassiert.items()) if gezaehlt.get(k, 0) < n]
    return neu, weg


_REJECT_UNKNOWN = ("passed to _reject_unknown: it computes set(obj) - allowed over a dict the caller "
                   "checked before it (isinstance or _require_dict), and the keys of a dict are hashable")
_REJECT_PAIR = ("passed to _reject_unknown: the loop over these pairs hands it a section only after "
                "isinstance(sect, dict), and the keys of a dict are hashable")
_NESTED = ("passed to {fn}: it looks up only paths it builds itself (the empty string, a dict key or an "
           "f-string over them), all hashable")
_OWN_SET = "own value: set({x}) is built from {what}, so the set operation hashes nothing new"

#: Every other read of a module-level hashing container, and why it cannot hash a value from outside.
#: Keyed like `_LOOKUPS_CLASSIFIED`, with the same (count, reason). The first form said "35 reads" on
#: 1ab75135; 35 was the number of KEYS. Measured on the tree of 09d5c5b3 after every form of the delta
#: run was read: 38 reads under 35 keys. Three keys cover two reads each: `_REQUIRED - set(claim)` and
#: `set(claim) - _REQUIRED` in both `decode_eval_claim` and `emit_eval_receipt`, and the two
#: `automation_summary` calls in `verify_trust_pack`. Each read was read at its callee or at the check
#: before it. A new read, also one more under a listed key, turns the tree test red until it is
#: classified here, and a classified read that is gone has to leave the list or lower its count.
_OTHER_USES_CLASSIFIED = {
    ("proofbundle/agent_review.py", "_validate_coverage", "_COVERAGE_FIELDS_V02", "LtE zusatz"):
        (1, "own value: zusatz comes from the package (_COVERAGE_FIELDS_V02 or the empty default), and a "
         "subset test between two frozensets hashes nothing new"),
    ("proofbundle/agent_review.py", "_validate_declaration", "_DECLARATION_FIELDS", "BitOr zusatz"):
        (1, "own value: zusatz comes from the package (_DECLARATION_FIELDS_V02 or the empty default), and the "
         "key tested against the union is a key of a dict"),
    ("proofbundle/agent_review.py", "validate_agent_review_v02_predicate", "_COVERAGE_FIELDS_V02",
     "validate_agent_review_predicate(cov_zusatz=)"):
        (1, "passed to validate_agent_review_predicate: _validate_coverage tests keys of a dict against it"),
    ("proofbundle/agent_review.py", "validate_agent_review_v02_predicate", "_DECLARATION_FIELDS_V02",
     "validate_agent_review_predicate(decl_zusatz=)"):
        (1, "passed to validate_agent_review_predicate: _validate_declaration tests keys of a dict against it"),
    ("proofbundle/agent_review.py", "validate_agent_review_v03_predicate", "_PRODUCER_FIELDS_V03",
     "validate_agent_review_v02_predicate(_producer_zusatz=)"):
        (1, "passed to validate_agent_review_v02_predicate: it reaches `k in producer_zusatz` only after "
         "k == \"verifier\""),
    ("proofbundle/anchors.py", "verify_anchor", "_ANCHOR_KEYS", "Sub set(anchor)"):
        (1, _OWN_SET.format(x="anchor", what="a dict (isinstance(anchor, dict) returns before it)")),
    ("proofbundle/bundle.py", "verify_bundle", "_MERKLE_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/bundle.py", "verify_bundle", "_SD_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/bundle.py", "verify_bundle", "_SIG_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/bundle.py", "verify_bundle", "_TOP_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/cap1.py", "_is_digest", "_HEX", "LtE set(x)"):
        (1, _OWN_SET.format(x="x", what="a str (isinstance(x, str) in the same expression)")),
    ("proofbundle/decision.py", "validate_decision_predicate", "_NESTED_ALLOWED",
     "nested_closure_violations(argument 2)"):
        (1, _NESTED.format(fn="nested_closure_violations")),
    ("proofbundle/decision.py", "validate_decision_predicate", "_NESTED_TYPES",
     "nested_type_violations(argument 2)"):
        (1, _NESTED.format(fn="nested_type_violations")),
    ("proofbundle/evalclaim.py", "decode_eval_claim", "_OPTIONAL", "Sub set(claim) - _REQUIRED"):
        (1, _OWN_SET.format(x="claim", what="a dict (load_claim_text returns a dict or raises)")),
    ("proofbundle/evalclaim.py", "decode_eval_claim", "_REQUIRED", "Sub set(claim)"):
        (2, _OWN_SET.format(x="claim", what="a dict (load_claim_text returns a dict or raises)")),
    ("proofbundle/evalclaim.py", "emit_eval_receipt", "_OPTIONAL", "Sub set(claim) - _REQUIRED"):
        (1, _OWN_SET.format(x="claim", what="dict(claim)")),
    ("proofbundle/evalclaim.py", "emit_eval_receipt", "_REQUIRED", "Sub set(claim)"):
        (2, _OWN_SET.format(x="claim", what="dict(claim)")),
    ("proofbundle/outcome.py", "validate_outcome_predicate", "_NESTED_ALLOWED",
     "nested_closure_violations(argument 2)"):
        (1, _NESTED.format(fn="nested_closure_violations")),
    ("proofbundle/outcome.py", "validate_outcome_predicate", "_NESTED_TYPES",
     "nested_type_violations(argument 2)"):
        (1, _NESTED.format(fn="nested_type_violations")),
    ("proofbundle/policy.py", "_huelle_pruefen", "_ANCHORS_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_ASSURANCE_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_CHECKPOINT_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/policy.py", "_huelle_pruefen", "_DECISION_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_DECISION_MAKER_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/policy.py", "_huelle_pruefen", "_ISSUER_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/policy.py", "_huelle_pruefen", "_MERKLE_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_SDJWT_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_SIG_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_STATUS_KEYS", "Tuple"):
        (1, _REJECT_PAIR),
    ("proofbundle/policy.py", "_huelle_pruefen", "_TOP_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/policy.py", "_huelle_relations", "_RELATIONS_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/policy.py", "_validate_checkpoint_entry", "_CHECKPOINT_KEYS", "_reject_unknown(argument 2)"):
        (1, _REJECT_UNKNOWN),
    ("proofbundle/policy_profiles.py", "instantiate_template", "_RESERVED_OVERLAY_KEYS", "BitAnd set(overlay)"):
        (1, _OWN_SET.format(x="overlay", what="a dict (a non-dict overlay raises before it)")),
    ("proofbundle/trust_pack.py", "_finalize_failclosed", "_AUTOMATION_REQUIRED_CHECKS",
     "automation_summary(required_checks=)"):
        (1, "passed to automation_summary: it reads the mapping with literal keys only"),
    ("proofbundle/trust_pack.py", "verify_trust_pack", "_AUTOMATION_REQUIRED_CHECKS",
     "automation_summary(required_checks=)"):
        (2, "passed to automation_summary: it reads the mapping with literal keys only"),
}


class TestNoUnguardedMembershipInTheTree(unittest.TestCase):
    def test_no_source_file_hashes_attacker_data_in_a_membership_test(self):
        quellen = _package_sources()
        je_modul = containers_by_module(quellen)
        befunde = []
        for pfad in sorted(SRC.rglob("*.py")):
            if "__pycache__" in pfad.parts or pfad.name == "_membership.py":
                continue
            modul = _modulname(pfad, SRC.parent)
            for zeile, links, cont in unguarded_membership_sites(
                    quellen[modul][0], str(pfad), modul, quellen[modul][1], je_modul):
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
            self.assertTrue(e.get("qualname"), f"{marke}: kein Feld qualname — ohne die "
                                               "umschliessende Definition laesst sich das Budget "
                                               "waschen (Linsenfund 15.09.2026)")
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

        Der Schluessel ist (Datei, Definition, Ausdruck) — waere die Anzahl nicht dabei, deckte ein
        getragener Eintrag beliebig viele weitere Vorkommen derselben Form in DERSELBEN Definition.
        ``derive_limitation_codes`` traegt genau EIN ``i.get('assurance')``; ein zweites dort ist neu.
        """
        quelle = ("def derive_limitation_codes(xs):\n"
                  "    a = {i.get('assurance') for i in xs}\n"
                  "    b = {i.get('assurance') for i in xs}\n"
                  "    return a, b\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(len(funde), 1, funde)
        self.assertIn("1 von 2 nicht getragen", funde[0])

    def test_eine_neue_definition_mit_getragenem_ausdruck_gilt_als_neu(self):
        """DER WASCHGANG, den eine adversariale Linse am 15.09.2026 ausgefuehrt hat.

        Sie schloss die getragene, angreiferexponierte Stelle in ``derive_limitation_codes`` und
        machte anderswo in derselben Datei eine NEUE ungeschuetzte Konstruktion mit DEMSELBEN
        Ausdruck auf. Bei einem Schluessel aus (Datei, Ausdruck) blieb die Anzahl gleich und der
        Riegel gruen — im neuen Code lief nachweislich ``TypeError: unhashable type: 'list'``. Die
        vorherige, zeilengebundene Regel haette ihn gefangen; die Reparatur war also auf DIESER
        Achse schwaecher als das, was sie ersetzte.

        Genau diese Bewegung wird hier nachgestellt: dieselbe Datei, derselbe Ausdruck, dieselbe
        Gesamtzahl — nur eine andere umschliessende Definition. Bleibt dieser Test gruen, ist das
        Budget wieder waschbar.
        """
        quelle = ("def derive_limitation_codes(xs):\n"
                  "    return set()\n"
                  "\n"
                  "def _neu_und_ungeprueft(xs):\n"
                  "    return {i.get('assurance') for i in xs}\n")
        funde = _ueberzaehlige_stellen({"proofbundle/agent_review.py": quelle})
        self.assertEqual(
            len(funde), 1,
            "eine neue Definition mit einem getragenen Ausdruck gilt nicht als neu — das Budget "
            f"laesst sich waschen: {funde}")
        self.assertIn("_neu_und_ungeprueft", funde[0])

    def test_ein_leeres_quelltexte_ist_ein_fehler_kein_sauberer_baum(self):
        """Linsenfund P3: ``is not None`` liess ein leeres dict den ganzen Plattenlauf still
        ueberspringen und sauber melden. Ein Aufrufer, der nur geaenderte Dateien reicht und einmal
        keine hat, haette damit einen ungeprueften Baum freigesprochen."""
        with self.assertRaises(ValueError):
            _ueberzaehlige_stellen({})

    def test_die_grundlinie_traegt_keine_stelle_die_es_nicht_mehr_gibt(self):
        """Eine Grundlinie, die eine geschlossene Stelle weiter traegt, ist eine Erlaubnis auf Vorrat.

        Die Datei sagt von sich: *jeder Eintrag muss noch geschlossen werden*. Wird einer
        geschlossen und der Eintrag bleibt stehen, deckt er ab da eine Stelle, die es nicht mehr
        gibt — und die naechste, die dieselbe Form wieder einfuehrt, faellt lautlos darunter.
        Rot heisst hier: Eintrag entfernen, nicht Test entfernen.
        """
        import collections  # noqa: PLC0415
        getragen = collections.Counter(
            (e["file"], e["qualname"], e["expr"]) for e in _grundlinie()["carried"])
        gesehen = {k: len(v) for k, v in _gesehene_stellen().items()}
        tot = [f"{f}  in {q}()  {x}: getragen {n}, im Baum {gesehen.get((f, q, x), 0)}"
               for (f, q, x), n in sorted(getragen.items()) if gesehen.get((f, q, x), 0) < n]
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


class TestEveryConstantLookupOnAForeignKeyIsClassified(unittest.TestCase):
    """The third form of the class: a lookup hashes its key as a membership test does.

    STATED LIMIT: the guard reads every use of a container's NAME, covers it by a known form or lists
    it, and holds both lists exact, with the number of sites per key. A container is a name bound at
    module level to a set, dict or frozenset literal, comprehension or `set()`/`frozenset()`/`dict()`
    call, also inside a module-level `if`, `try`, `with`, `for`, `while` or `match`, and also when
    another module of the package imports it by name, through a chain of such imports, or with
    `from .x import *`. A container reached as a module attribute (`x.NAME`), through a string
    (`globals()`, `vars()`), or built at run time is not a name it reads; that includes a module-level
    `_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)`, a set built by an operator. A value that
    leaves the container (`for v in CONST.values(): ...`) is not followed. It does NOT prove the
    reasons in `_LOOKUPS_CLASSIFIED` and `_OTHER_USES_CLASSIFIED`. A person read each guard before
    classifying the site, and a guard removed later leaves the reason standing. Only a test that sends
    an unhashable value to the surface can catch that; this one cannot."""

    def test_the_tree_holds_exactly_the_classified_lookups(self):
        neu, weg = _drift(_in_the_tree(constant_lookups), _LOOKUPS_CLASSIFIED)
        self.assertEqual(neu, [],
                         "a new lookup on a module-level dict with a foreign key: route the key through "
                         "is_member first, or classify it in _LOOKUPS_CLASSIFIED with the reason")
        self.assertEqual(weg, [],
                         "a classified lookup is gone: remove it from _LOOKUPS_CLASSIFIED or lower its count")

    def test_every_classification_says_why(self):
        for key, (count, reason) in _LOOKUPS_CLASSIFIED.items():
            with self.subTest(site=key):
                self.assertIsInstance(count, int)
                self.assertGreaterEqual(count, 1)
                self.assertRegex(reason, r"^(guarded|guarded by the one caller|own value): \S")

    def test_a_planted_lookup_is_found_and_a_literal_key_is_not(self):
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            def f(p):
                return _M.get(p.get("k")), _M[p["k"]], _M["a"], _M.get("a"), p.get("x")
        ''')
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(quelle)],
                         [("_M", "p.get('k')"), ("_M", "p['k']")])

    def test_a_write_hashes_its_key_as_a_read_does(self):
        """The 228bc stack delta (D-2): a write and `.setdefault` were unseen. Every form that hashes a
        foreign key is found, and a literal key is not, in any of them."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            def f(p, k):
                _M[k] = 1
                del _M[k]
                _M.setdefault(k, 2)
                _M.pop(k, None)
                _S.add(k)
                _S.discard(k)
                _S.remove(k)
                _M["a"] = 1
                _M.setdefault("a", 2)
                _S.add("a")
                return _S.get
        ''')
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(quelle)],
                         [("_M", "k")] * 4 + [("_S", "k")] * 3)

    def test_every_spelling_of_a_hashing_access_is_found(self):
        """The second delta run on e4ea49b9 wrote five more spellings past the guard; each hashes k.
        A mapping or iterable handed to `update` or `|=` that is not a literal there, and the container
        handed to a function, are not keys this detector can list; `other_uses` reports them."""
        quelle = textwrap.dedent('''
            import operator
            import operator as op
            _M = {"a": 1}
            _S = {"a"}
            def f(p, k):
                global _M, _S
                _M.__getitem__(k)
                _M.__setitem__(k, 1)
                _S.__contains__(k)
                operator.getitem(_M, k)
                op.contains(_S, k)
                _M |= {k: 1, "a": 2}
                _S |= {k, "a"}
                _M.update({k: 3})
                _S.update([k])
                operator.getitem(_M, "a")
                _M.update(other)
                return p.get("r") in _M.keys()
        ''')
        self.assertEqual(sorted((c, k) for _l, c, k in constant_lookups(quelle)),
                         [("_M", "k")] * 5 + [("_S", "k")] * 4)
        self.assertEqual([(links, c) for _l, links, c in unguarded_membership_sites(quelle)],
                         [("p.get('r')", "_M")])

    def test_the_tree_holds_exactly_the_classified_other_uses(self):
        neu, weg = _drift(_in_the_tree(other_uses), _OTHER_USES_CLASSIFIED)
        self.assertEqual(neu, [],
                         "a new read of a module-level hashing container that no known form covers: "
                         "classify it in _OTHER_USES_CLASSIFIED with the reason it hashes nothing from outside")
        self.assertEqual(weg, [],
                         "a classified read is gone: remove it from _OTHER_USES_CLASSIFIED or lower its count")

    def test_every_other_use_says_why(self):
        for key, (count, reason) in _OTHER_USES_CLASSIFIED.items():
            with self.subTest(site=key):
                self.assertIsInstance(count, int)
                self.assertGreaterEqual(count, 1)
                self.assertRegex(reason, r"^(own value|passed to [\w.]+): \S")

    def test_a_spelling_nobody_listed_is_an_other_use(self):
        """The third delta run on 1ab75135 wrote five spellings past both detectors; each hashed an
        unhashable key. Deny by default: every one of them, and a name handed to `update` or `|=`, is
        reported, while the forms that hash nothing from outside are not."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            _T = {"b"}
            def f(k, item, other):
                global _M, _S
                getter = _M.get
                getattr(_M, "get")(k)
                _M.__class__.__getitem__(_M, k)
                _M.keys().__contains__(k)
                _M.update(other)
                _S |= other
                return getter(k), item in _M.items()
            def known(p, k):
                for x in _S:
                    pass
                if _M:
                    pass
                return (sorted(_M), is_member(k, _S), _M.get(k), k in _M, k in _M.keys(),
                        _S - _T, _S <= {"a"}, [v for v in _M.values()], sorted(_M.items()))
        ''')
        self.assertEqual(sorted((c, u) for _l, c, u in other_uses(quelle)),
                         [("_M", ".__class__"), ("_M", ".get"), ("_M", ".items()"), ("_M", ".keys()"),
                          ("_M", ".update()"), ("_M", "_M.__class__.__getitem__(argument 1)"),
                          ("_M", "getattr(argument 1)"), ("_S", "BitOr= other")])
        for label, access in (("bound", lambda m: (m.get)([])), ("getattr", lambda m: getattr(m, "get")([])),
                              ("__class__", lambda m: m.__class__.__getitem__(m, [])),
                              ("keys().__contains__", lambda m: m.keys().__contains__([])),
                              ("items", lambda m: ([], "v") in m.items())):
            with self.subTest(spelling=label), self.assertRaises(TypeError):
                access({"a": 1})

    def test_an_imported_container_is_seen_in_both_forms(self):
        """234-1-02 as a planted package: a dict and a frozenset defined in one module, read in another
        through `from .a import ...` (one of them inside a function, as cli.py does)."""
        a = '_M = {"x": 1}\n_S = frozenset({"x"})\n'
        b = ("from .a import _M\n"
             "def f(p):\n"
             "    from .a import _S as S\n"
             "    return _M.get(p.get('k')), p.get('r') in S\n")
        je_modul = containers_by_module({"pkg.a": a, "pkg.b": b})
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(b, "b.py", "pkg.b", False, je_modul)],
                         [("_M", "p.get('k')")])
        self.assertEqual([(links, c) for _l, links, c in
                          unguarded_membership_sites(b, "b.py", "pkg.b", False, je_modul)],
                         [("p.get('r')", "S")])
        # anti-parity: without the package view the same file shows nothing, which was the first form
        self.assertEqual(constant_lookups(b, "b.py"), [])

    def test_a_relative_import_resolves_from_a_subpackage_and_an_init(self):
        je_modul = containers_by_module({"pkg.a": '_M = {"x": 1}\n', "pkg.sub.c": "", "pkg": ""})
        tiefer = "from ..a import _M\ndef f(p):\n    return _M[p]\n"
        self.assertEqual(len(constant_lookups(tiefer, "c.py", "pkg.sub.c", False, je_modul)), 1)
        init = "from .a import _M\ndef f(p):\n    return _M[p]\n"
        self.assertEqual(len(constant_lookups(init, "__init__.py", "pkg", True, je_modul)), 1)

    def test_the_trust_pack_shape_raised_before_it_was_guarded(self):
        """The measured consequence, as the lookup reads it: an unhashable key raises."""
        with self.assertRaises(TypeError):
            {"mldsa65": "ML-DSA-65"}.get(["mldsa65"])

    # The delta run on 09d5c5b3 wrote six counter-examples past this guard, each executed. One test
    # per finding; each is planted in a source string and none touches src/.

    @staticmethod
    def _reported_lines(quelle: str, funde) -> list[str]:
        zeilen = quelle.splitlines()
        return [zeilen[z - 1].strip() for z, _c, _was in sorted(funde)]

    def test_a_second_site_under_a_classified_key_is_new(self):
        """Finding 1: both lists were sets of keys, so a site under a key already listed was no new
        site. Planted into a copy of the real tree, in `anchors.verify_anchor` before its is_member
        check: the delta run's probe `_VERIFIERS.get(atype)`, and a second `set(anchor) - _ANCHOR_KEYS`.
        Each is a second site under a key classified once, and both lists now say so."""
        anker = '    atype = anchor.get("type")\n'
        quelle = (SRC / "anchors.py").read_text(encoding="utf-8")
        self.assertEqual(quelle.count(anker), 1, "the plant point moved: plant where verify_anchor reads atype")
        # exact equality: the copy read in place of the file adds nothing but the planted site
        gepflanzt = {"proofbundle/anchors.py": quelle.replace(
            anker, anker + "    _probe = _VERIFIERS.get(atype)\n    _probe2 = set(anchor) - _ANCHOR_KEYS\n")}
        schluessel = ("proofbundle/anchors.py", "verify_anchor", "_VERIFIERS", "atype")
        self.assertEqual(_drift(_in_the_tree(constant_lookups, gepflanzt), _LOOKUPS_CLASSIFIED),
                         ([f"{schluessel}: 2 in the tree, 1 classified"], []))
        schluessel = ("proofbundle/anchors.py", "verify_anchor", "_ANCHOR_KEYS", "Sub set(anchor)")
        self.assertEqual(_drift(_in_the_tree(other_uses, gepflanzt), _OTHER_USES_CLASSIFIED),
                         ([f"{schluessel}: 2 in the tree, 1 classified"], []))
        # the other direction: a classified count above the tree is a site that is gone, also when
        # one of two sites under a key goes and the key stays
        self.assertEqual(_drift({schluessel: 1}, {schluessel: (2, "own value: x")}),
                         ([], [f"{schluessel}: 1 in the tree, 2 classified"]))
        with self.assertRaises(TypeError):
            {"rfc3161-tsa": None}.get([[1]])

    def test_update_hashes_every_argument(self):
        """Finding 2: `set.update(*iterables)` hashes every argument, and the first form read only the
        first; `_S.update(["type"], k)` counted as known and raised for `k = [[1]]`. Every positional
        argument has to be a literal that names its keys, and each non-literal key is listed."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            def f(k, other):
                _S.update(["type"], k)
                _S.update(["type"], [k])
                _S.update([*other])
                _M.update({**other})
                _M.update({"a": 1}, **other)
                _S.update(["type"], ("b",))
                _M.update(a=1)
                _M.update({k: 1})
                _S |= {*other}
        ''')
        self.assertEqual(sorted((c, k) for _l, c, k in constant_lookups(quelle)), [("_M", "k"), ("_S", "k")])
        self.assertEqual(self._reported_lines(quelle, other_uses(quelle)),
                         ['_S.update(["type"], k)', "_S.update([*other])", "_M.update({**other})",
                          '_M.update({"a": 1}, **other)', "_S |= {*other}"])
        with self.assertRaises(TypeError):
            {"a"}.update(["type"], [[1]])

    def test_a_set_or_dict_literal_with_a_foreign_element_is_no_constant_operand(self):
        """Finding 3: any set or dict literal counted as a constant operand, whatever it held, so
        `_S | {k}`, `_S - {k}`, `_S == {k}`, `_S <= {k}` and `_M | {k: 1}` were unreported and raised
        for `k = []`. A literal counts only when every element, or every key, is a literal."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            _S = {"a"}
            def f(k, other):
                a = _S | {k}
                b = _S - {k}
                c = _S == {k}
                d = _S <= {k}
                e = _M | {k: 1}
                g = _M | {**other}
                h = {"b", k} & _S
                i = _S | {"a"}
                j = _M | {"a": k}
                return a, b, c, d, e, g, h, i, j
        ''')
        self.assertEqual(self._reported_lines(quelle, other_uses(quelle)),
                         ["a = _S | {k}", "b = _S - {k}", "c = _S == {k}", "d = _S <= {k}",
                          "e = _M | {k: 1}", "g = _M | {**other}", 'h = {"b", k} & _S'])
        for label, access in (("|", lambda k: {"a"} | {k}), ("-", lambda k: {"a"} - {k}),
                              ("==", lambda k: {"a"} == {k}), ("<=", lambda k: {"a"} <= {k}),
                              ("dict |", lambda k: {"a": 1} | {k: 1})):
            with self.subTest(operation=label), self.assertRaises(TypeError):
                access([])

    def test_a_star_import_and_a_re_export_chain_reach_the_container(self):
        """Finding 4: `from .hashalg import *` and a chain `from .renewal import HASH_REGISTRY`, where
        renewal imported the name from hashalg, both read `HASH_REGISTRY.get(alg)` unseen. Planted as
        a package, and then into a copy of the real tree, through the real chain."""
        paket = {
            "pkg.a": ('_M = {"x": 1}\n', False),
            "pkg.b": ("from .a import _M\n", False),                                    # re-export
            "pkg.c": ("from .b import _M\ndef f(p):\n    return _M.get(p)\n", False),   # the chain
            "pkg.d": ("from .a import *\ndef g(p):\n    return _M.get(p)\n", False),    # star
            "pkg.e": ("from .c import *\ndef h(p):\n    return p.get('r') in _M\n", False),
            "pkg": ("from .b import _M as M\ndef i(p):\n    return M[p]\n", True)}      # an __init__
        je_modul = containers_by_module(paket)
        for modul in ("pkg.c", "pkg.d", "pkg"):
            with self.subTest(modul=modul):
                self.assertEqual(len(constant_lookups(paket[modul][0], modul, modul, paket[modul][1],
                                                      je_modul)), 1)
        self.assertEqual([(links, c) for _l, links, c in unguarded_membership_sites(
            paket["pkg.e"][0], "e", "pkg.e", False, je_modul)], [("p.get('r')", "_M")])
        cli = (SRC / "cli.py").read_text(encoding="utf-8")
        gepflanzt = {"proofbundle/cli.py": cli + (
            "\n\nfrom .renewal import HASH_REGISTRY as _PROBE_REGISTRY\n"
            "def _probe_chain(alg):\n    return _PROBE_REGISTRY.get(alg)\n")}
        self.assertEqual(_drift(_in_the_tree(constant_lookups, gepflanzt), _LOOKUPS_CLASSIFIED),
                         ([f"{('proofbundle/cli.py', '_probe_chain', '_PROBE_REGISTRY', 'alg')}: "
                           "1 in the tree, 0 classified"], []))
        gepflanzt = {"proofbundle/cli.py": cli + (
            "\n\nfrom .hashalg import *\ndef _probe_star(alg):\n    return HASH_REGISTRY.get(alg)\n")}
        self.assertEqual(_drift(_in_the_tree(constant_lookups, gepflanzt), _LOOKUPS_CLASSIFIED),
                         ([f"{('proofbundle/cli.py', '_probe_star', 'HASH_REGISTRY', 'alg')}: "
                           "1 in the tree, 0 classified"], []))

    def test_a_container_bound_under_a_module_level_block_is_a_container(self):
        """Finding 5: only `tree.body` was scanned, so `_M = {"a": 1}` under `try:` was no container and
        `_M.get(k)` raised unreported. Every module-level block is read; a def, a class and a lambda
        are not module level."""
        quelle = textwrap.dedent('''
            import contextlib
            try:
                _M = {"a": 1}
            except ImportError:
                _N = {}
            else:
                _E = {"e"}
            finally:
                _Z = frozenset({"z"})
            if True:
                _S = {"a"}
            else:
                _T = set()
            with contextlib.suppress(Exception):
                _W = {"w": 1}
            for _i in range(1):
                _F = dict(a=1)
            else:
                _O = {"o"}
            while False:
                pass
            else:
                _L = {"l"}
            match 1:
                case 1:
                    _C = {"c"}
            def f(k):
                _LOCAL = {"x"}
                return _LOCAL
            class K:
                _ATTR = {"y"}
            _LAMBDA = lambda: {"z"}
        ''')
        self.assertEqual(_hashing_containers(ast.parse(quelle)),
                         {"_M": "dict", "_N": "dict", "_E": "set", "_Z": "frozenset", "_S": "set",
                          "_T": "set", "_W": "dict", "_F": "dict", "_O": "set", "_L": "set", "_C": "set"})
        beispiel = 'try:\n    _M = {"a": 1}\nexcept ImportError:\n    _M = {}\ndef f(k):\n    return _M.get(k)\n'
        self.assertEqual([(c, k) for _l, c, k in constant_lookups(beispiel)], [("_M", "k")])

    def test_a_call_that_hashes_the_values_of_a_dict_is_an_other_use(self):
        """Finding 6: `set`, `frozenset` and `dict` HASH what they iterate. `set(_M.values())` counted
        as iteration, and with `_M["a"] = v` for `v = []` it raised. Over the container or its keys
        they hash keys; over `.values()` or `.items()` they hash values, and so does a set or dict
        comprehension or a generator handed to one of them. `sorted`, `list`, `tuple` and `len` hash
        nothing, over any view."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            def f(v):
                _M["a"] = v
                a = set(_M.values())
                b = frozenset(_M.items())
                c = dict(_M.values())
                d = {x for x in _M.values()}
                e = {x: 1 for x in _M.items()}
                g = set(x for x in _M.values())
                return (a, b, c, d, e, g, set(_M), set(_M.keys()), frozenset(_M), dict(_M),
                        {x for x in _M}, sorted(_M.values()), list(_M.items()), tuple(_M.values()),
                        len(_M.items()), [x for x in _M.values()], sorted(x for x in _M.values()))
        ''')
        self.assertEqual(self._reported_lines(quelle, other_uses(quelle)),
                         ["a = set(_M.values())", "b = frozenset(_M.items())", "c = dict(_M.values())",
                          "d = {x for x in _M.values()}", "e = {x: 1 for x in _M.items()}",
                          "g = set(x for x in _M.values())"])
        m = {"a": 1}
        m["a"] = []
        for label, access in (("set", lambda: set(m.values())), ("frozenset", lambda: frozenset(m.items())),
                              ("comprehension", lambda: {x for x in m.values()})):
            with self.subTest(form=label), self.assertRaises(TypeError):
                access()


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
