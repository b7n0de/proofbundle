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
inside a module-level `if`, `try`, `with`, `for`, `while` or `match`, by unpacking a tuple
(`_S, _M = {"a"}, {"a": 1}`, also around a starred name), by `:=`, as the target of a `for` over a
tuple or list display, as a second name for a container, to `dict.fromkeys(...)` or
`types.MappingProxyType(...)`, or to a set operation over containers
(`_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)`), and also when another module of the package
imports them by name, `from .x import NAME`, through a chain of such imports, or with
`from .x import *`), the containers DERIVED from them (`_Sicht`: a set operation between two
constants, a `set()`, `frozenset()`, `dict()` or `dict.fromkeys()` copy or a set or dict
comprehension over one or over a module-level tuple, and a local name bound to such an expression,
also by a walrus in a nested function's default), and single-operator comparisons. A walrus and a
conditional are read as the values they pass on, through any nesting of the two (`_passed_values`), so
`k in (s := _A)` is `k in _A` and `k in (s := _A if c else _B)` a test in `_A` or `_B`. A binding counts
as followed only when a reader reads the name it binds (`_scope_bindings`); a container bound
anywhere else is reported where it is read. NOT covered: a container built at runtime from a value
that is not constant (`x in set(allowed)`: one membership test in the tree, `relation.py`, over a list
filtered to strings; the second, in `adapters/agt_receipt.py`, hashed every entry of the relying party's
list and raised for an unhashable one although `x` was a str, and reads the list without a set since the
lens on e5b39b81), a literal on its own
(`x in {"a"}`, `{"a": 1}[k]`: no membership test and six lookups in the tree, each behind an
`is_member` or `isinstance` check or keyed by a literal the package chose), a container reached as a
module attribute (`x.NAME`), through a string (`globals()`) or bound in a class body, a container a
function call returns (the one in the tree, `policy._LOW_ORDER_ED25519_Y`, is named with its reason
and held by a runtime oracle, `TestTheRuntimeSeesNoContainerTheGuardDoesNot`), a tuple constant
imported from another module, a copy of a dict's values bound to a name and hashed through it, or
handed on through a wrapper other than the ones `_passing_call` knows, and a chained comparison.
That is stated here rather than left for someone to discover, and `is_member` is safe to use
everywhere regardless. A LOOKUP or a
WRITE hashes its key too (`CONST.get(x)`, `CONST[x]`, `CONST[x] = v`, `del CONST[x]`,
`CONST.setdefault(x)`, `CONST.pop(x)`, and `add`, `discard`, `remove` on a set); those sites are
listed with the reason each is safe and the number of sites per key, in `_LOOKUPS_CLASSIFIED` below.
Every OTHER read of such a container (handed to a function, returned, put in a tuple, a method
reached without a call, a set operation with a literal that holds a name, a construction that hashes
`.values()` or `.items()` through any chain of copies, comprehensions, starred displays or passing
calls, a binding no reader follows) is listed the same way in `_OTHER_USES_CLASSIFIED`: the guard reads every
use of the name, and of a derived expression, and reports what no known form covers, so a spelling
nobody listed turns it red, and so does one more site under a listed key.

A FOURTH FORM needs no hashing at all: a container of NUMBERS classifies `true` and `2.0` as known
elements, because `True == 1` and `2.0 == 2`. `number_container_sites` reports every membership test,
lookup and `is_member` call on one, unless it reads through `_membership.is_int_member` or is listed in
`_NUMBER_SITES_CLASSIFIED` (the section before `_RUNTIME_ONLY_CONTAINERS` states what it reads).
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

#: The scopes a local name belongs to.
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _scope_nodes(wurzel: ast.AST):
    """The nodes that run in the scope `wurzel` opens (a module, a function or a lambda): its body, and
    of every function, lambda or class defined in it what Python evaluates where it is defined, the
    decorators, the default values, the base classes and the class keywords, never their bodies. A
    function's OWN decorators and defaults belong to the scope around it, and are read there.

    At module level that is the module body and the bodies of the compound statements in it (`if`,
    `try` with its handlers, `else` and `finally`, `with`, `for`, `while`, `match`), never the body of a
    def, a class or a lambda: the delta run on 09d5c5b3 bound `_M = {"a": 1}` under `try:` and read
    `_M.get(k)`, only `tree.body` was scanned, and the TypeError went unreported. In a function, the
    lens on c3bd89a4 bound `allowed` by a walrus in the default of a nested function, `def g(x=(allowed
    := _A - _B))`: the first form walked neither the nested function's defaults nor, when it read the
    nested function, the right scope, so `k in allowed` raised in the outer function unreported."""
    if isinstance(wurzel, ast.Lambda):
        stapel: list[ast.AST] = [wurzel.body]
    elif isinstance(wurzel, (ast.FunctionDef, ast.AsyncFunctionDef)):
        stapel = list(wurzel.body)
    else:
        stapel = list(ast.iter_child_nodes(wurzel))
    # in source order, so that of two bindings of one name the later one is read later
    stapel.reverse()
    while stapel:
        k = stapel.pop()
        yield k
        if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            kinder = [*getattr(k, "decorator_list", []),
                      *(d for d in (*k.args.defaults, *k.args.kw_defaults) if d is not None)]
        elif isinstance(k, ast.ClassDef):
            kinder = [*k.decorator_list, *k.bases, *k.keywords]
        else:
            kinder = list(ast.iter_child_nodes(k))
        stapel.extend(reversed(kinder))


#: The operators that build a set (or a dict, for `|`) out of two hashing containers.
_SET_OPERATORS = (ast.BitOr, ast.BitAnd, ast.Sub, ast.BitXor)


def _walrus_value(e):
    """The value an expression passes on once every walrus around it is taken away: `(s := v)`
    evaluates to `v`, and so does `(a := (b := v))`.

    A WALRUS BINDS AND PASSES ON, both at once. The lens on 8ecb6edf wrote seven forms in which the
    value of a walrus was itself an operand, `k in (s := _A)`, `(m := _M).get(k)`, `(m := _M)[k]`,
    `(m := _M).setdefault(k, 1)`, `k in (s := _A - _B)`, `k in (s := set(_A))` and a walrus in a
    comprehension condition: each raised TypeError at run time, and all three detectors were silent,
    because the readers looked at the walrus and not at its value, and `other_uses` counted the value
    as bound and looked no further. The readers now see the value, and `other_uses` judges it where
    the walrus is used as well as where it is bound."""
    while isinstance(e, ast.NamedExpr):
        e = e.value
    return e


def _passed_values(e) -> list:
    """Every expression `e` can pass on: a walrus passes its value, a conditional one of its two
    branches, through any nesting of the two. `_A if c else (t := _B)` passes `_A` or `_B`.

    ONE RULE FOR BOTH SIDES OF THE GUARD. The lens on d5747000 wrote a walrus over a conditional,
    `k in (s := _A if c else _B)`: the binding side split the conditional, so `s` was a container and
    both branches counted as bound, while every reader looked through the walrus, found the conditional
    and saw no container in it. All three detectors were silent, and six forms of it raised at run time
    (`.get`, a subscript, a module-level and a local name bound to such a walrus, a chained walrus).
    Readers and bindings now take the passed values from this one function."""
    if isinstance(e, ast.NamedExpr):
        return _passed_values(e.value)
    if isinstance(e, ast.IfExp):
        return _passed_values(e.body) + _passed_values(e.orelse)
    return [e]


def _passing_nodes(e) -> list:
    """`e`, and every walrus, conditional and passed value below it on the way its value is passed on
    (`_passed_values` gives the last of these only). A binding binds its name to each of them, so that a
    read inside the value is bound however deep the walrus and the conditional stand around it."""
    if isinstance(e, ast.NamedExpr):
        return [e, *_passing_nodes(e.value)]
    if isinstance(e, ast.IfExp):
        return [e, *_passing_nodes(e.body), *_passing_nodes(e.orelse)]
    return [e]


def _bindings(ziele: list, wert: ast.AST):
    """(name, value) for every name a binding binds to one value: `X = v`, `X = Y = v`, and a tuple or
    list unpacked element by element, also nested. The review of fc863e2e bound two containers in one
    statement, `_S, _M = {"a"}, {"a": 1}`: the target was a tuple, so neither name was a container, and
    `_M.get(k)` raised for an unhashable `k` with the guard green. A name is bound to the value and to
    every node its value passes through (`_passing_nodes`): a conditional binds each of its two
    branches, and so does a conditional under a walrus (`s = (t := _A if c else _B)`, the lens on
    d5747000; before, only a conditional standing directly as the value was split). An unpacking reads
    every display the value can pass on (`required, allowed = (_A, _B) if pr else (_C, _D)`, as
    `agent_review._validate_subject` does). A starred target (`_S, *_R = {"a"}, {"b"}, {"c"}`, the lens
    on c3bd89a4) binds the names around it one to one; the starred name gets a list of the rest, which
    hashes nothing, so the values that go into it are bound to no name this follows. An unpacking whose
    value is no tuple or list display (`_S, _M = make()`), or one with a `*x` in the value, binds nothing
    this can name."""
    for t in ziele:
        if isinstance(t, ast.Name):
            for v in _passing_nodes(wert):
                yield t.id, v
            continue
        for anzeige in _passed_values(wert):
            if not (isinstance(t, (ast.Tuple, ast.List)) and isinstance(anzeige, (ast.Tuple, ast.List))
                    and not any(isinstance(e, ast.Starred) for e in anzeige.elts)):
                continue
            stern = [i for i, e in enumerate(t.elts) if isinstance(e, ast.Starred)]
            if not stern and len(t.elts) == len(anzeige.elts):
                paare = list(zip(t.elts, anzeige.elts))
            elif len(stern) == 1 and len(anzeige.elts) >= len(t.elts) - 1:
                vorn, hinten = stern[0], len(t.elts) - stern[0] - 1
                paare = (list(zip(t.elts[:vorn], anzeige.elts[:vorn]))
                         + list(zip(t.elts[len(t.elts) - hinten:], anzeige.elts[len(anzeige.elts) - hinten:])))
            else:
                continue
            for ziel, teil in paare:
                yield from _bindings([ziel], teil)


def _scope_bindings(wurzel: ast.AST, modulebene: bool) -> list[tuple[str, ast.AST, bool]]:
    """(name, value, followed) for every binding the two container readers read in the scope `wurzel`
    opens: `x = v`, also unpacked, starred or as a branch of a conditional, `x: T = v`, `(x := v)`, and
    at module level the target of a `for` over a tuple or list display, bound to each element
    (`for _S in ({"a"},): pass`, the lens on c3bd89a4). A `for` inside a function is not read; its
    elements stand in their tuple, which `other_uses` reports.

    The readers make a name a container from every pair. `followed` says whether the VALUE goes
    nowhere else: not when another target of the same assignment is no name (`x = a.b = v` also stores
    `v` in `a.b`), and not when the name is declared `global` or `nonlocal` in this function, because
    then its uses stand in a scope this reader does not read (`global _X; _X = _A - _B` in a function,
    `nonlocal allowed; allowed = _A - _B` in a nested one, both from the lens on c3bd89a4).

    ONE LIST FOR BOTH SIDES. `other_uses` counts a container read as bound ONLY when it is the value of
    a followed pair whose name became a container. The first form judged "bound" on its own, by the
    shape of the statement, and cleared bindings nothing followed: a module-level walrus, a `global` or
    `nonlocal` name assigned in a function, a starred unpacking, a `for` target, a walrus in a nested
    default. Each raised at run time with the guard green."""
    erklaert: set[str] = set()
    if not modulebene:
        for k in _scope_nodes(wurzel):
            if isinstance(k, (ast.Global, ast.Nonlocal)):
                erklaert.update(k.names)
    paare: list[tuple[str, ast.AST, bool]] = []
    for k in _scope_nodes(wurzel):
        if isinstance(k, ast.Assign):
            je_ziel = [list(_bindings([t], k.value)) for t in k.targets]
            gemeinsam = set.intersection(*({id(w) for _n, w in b} for b in je_ziel))
            paare.extend((n, w, id(w) in gemeinsam and n not in erklaert) for b in je_ziel for n, w in b)
        elif isinstance(k, ast.AnnAssign) and k.value is not None:
            paare.extend((n, w, n not in erklaert) for n, w in _bindings([k.target], k.value))
        elif isinstance(k, ast.NamedExpr) and isinstance(k.target, ast.Name):
            paare.extend((n, w, n not in erklaert) for n, w in _bindings([k.target], k.value))
        elif (modulebene and isinstance(k, (ast.For, ast.AsyncFor))
              and isinstance(k.iter, (ast.Tuple, ast.List))
              and not any(isinstance(e, ast.Starred) for e in k.iter.elts)):
            for teil in k.iter.elts:
                paare.extend((n, w, True) for n, w in _bindings([k.target], teil))
    return paare


def _ist_fromkeys(func: ast.AST) -> bool:
    return (isinstance(func, ast.Attribute) and func.attr == "fromkeys"
            and isinstance(func.value, ast.Name) and func.value.id == "dict")


def _ist_mapping_proxy(func: ast.AST) -> bool:
    return ((isinstance(func, ast.Name) and func.id == "MappingProxyType")
            or (isinstance(func, ast.Attribute) and func.attr == "MappingProxyType"))


def _module_level_art(wert: ast.AST, bekannt: dict[str, str]) -> str | None:
    """The kind of hashing container a module-level value is, or None. A set or dict literal, a set or
    dict comprehension and a `set()`, `frozenset()` or `dict()` call are containers whatever they hold,
    because at module level what they hold is fixed by the source. A name is one when `bekannt` names
    it. A set operation (`|`, `&`, `-`, `^`) of two such values is one too: the review of fc863e2e
    measured that `other_uses` cleared `_TIME_ASSURANCE - _V02_ASSURANCE_ALLOWED_FOR_CLAIMS` as a set
    operation between two constants and never looked at what used the RESULT, a membership test that
    raised; `_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)` is the same result bound to a name.
    The kind of an operation is the kind of its left side, as Python's is. `dict.fromkeys(...)` and
    `types.MappingProxyType(...)` are dicts whatever they hold (the lens on c3bd89a4 bound both at
    module level and read `.get(k)` unseen). A walrus is read as its value (`_walrus_value`), and a
    conditional is one when each of its branches is one, of the first branch's kind: the operand of a
    set operation is constant whichever branch runs, or it is not constant."""
    wert = _walrus_value(wert)
    zweige = _passed_values(wert)
    if len(zweige) > 1:
        arten = [_module_level_art(z, bekannt) for z in zweige]
        return arten[0] if all(arten) else None
    if isinstance(wert, (ast.Set, ast.SetComp)):
        return "set"
    if isinstance(wert, (ast.Dict, ast.DictComp)):
        return "dict"
    if isinstance(wert, ast.Call) and isinstance(wert.func, ast.Name) and wert.func.id in _HASHING:
        return wert.func.id
    if isinstance(wert, ast.Call) and (_ist_fromkeys(wert.func) or _ist_mapping_proxy(wert.func)):
        return "dict"
    if isinstance(wert, ast.Name):
        return bekannt.get(wert.id)
    if isinstance(wert, ast.BinOp) and isinstance(wert.op, _SET_OPERATORS):
        links = _module_level_art(wert.left, bekannt)
        return links if links and _module_level_art(wert.right, bekannt) else None
    return None


def _hashing_containers(tree: ast.Module, importiert: dict[str, str] | None = None) -> dict[str, str]:
    """Module-level names bound to a hash-based container — the ones whose membership test hashes.
    `importiert` names the containers the module imports, which a module-level set operation or a
    second name for a container (`_B = _A`) may read; they are not returned as the module's own.

    A literal form is read in order and a later binding wins, as always. A name, or a set operation
    over names, is resolved afterwards to a fixpoint, so the order of the bindings does not decide;
    such a binding adds a name and never changes one a literal form bound. The bindings are those of
    `_scope_bindings` at module level, a walrus and a `for` over a display included."""
    bindungen = [(name, wert) for name, wert, _gefolgt in _scope_bindings(tree, True)]
    gefunden: dict[str, str] = {}
    for name, wert in bindungen:
        art = _module_level_art(wert, {})
        if art:
            gefunden[name] = art
    sicht = {**(importiert or {}), **gefunden}
    neu = True
    while neu:
        neu = False
        for name, wert in bindungen:
            if name in gefunden:
                continue
            art = _module_level_art(wert, sicht)
            if art:
                gefunden[name] = sicht[name] = art
                neu = True
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
    sicht = {modul: _hashing_containers(baum) for modul, (baum, _i) in baeume.items()}
    for _runde in range(len(baeume) + 1):
        geaendert = False
        for modul, (baum, ist_init) in baeume.items():
            importiert = imported_containers(baum, modul, ist_init, sicht)
            neu = {**importiert, **_hashing_containers(baum, importiert)}
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
    if modul is None or je_modul is None:
        return _hashing_containers(tree)
    importiert = imported_containers(tree, modul, ist_init, je_modul)
    return {**importiert, **_hashing_containers(tree, importiert)}


def _module_sequences(tree: ast.Module) -> set[str]:
    """Module-level names bound to a tuple display, or to another such name: the constants a `set()`
    or `frozenset()` inside a function copies into a container. The lens on c3bd89a4 wrote
    `allowed = set(_T)` over `_T = ("a", "b")` and `k in allowed` raised unseen, because a tuple is
    no hashing container and the copy was therefore built "from a value that is not constant". A list
    display is left out: a module-level list can be appended to at run time, a tuple cannot."""
    paare = [(name, wert) for name, wert, _g in _scope_bindings(tree, True)]
    folgen = {name for name, wert in paare if isinstance(wert, ast.Tuple)}
    neu = True
    while neu:
        neu = False
        for name, wert in paare:
            if name not in folgen and isinstance(wert, ast.Name) and wert.id in folgen:
                folgen.add(name)
                neu = True
    return folgen


class _Sicht:
    """What the three detectors see in one module: the module-level containers (its own and the ones it
    imports), the containers DERIVED from them, and the local names bound to a derived one.

    THE DERIVED RULE, measured by the review of fc863e2e on `agent_review.validate_time_claim`:

        if tc.get("assurance") in (_TIME_ASSURANCE - _V02_ASSURANCE_ALLOWED_FOR_CLAIMS):

    raised `TypeError` for `assurance = []`, and `verify_agent_review_v02` answered `internal_error`,
    "a defect in the verifier". The membership scanner saw only a NAME on the right of `in`, and
    `other_uses` cleared both names as a set operation between two constants without looking at what
    used the result. A set built from constant containers hashes like the containers do, so it is one:

    * a CONSTANT operand is a container (module-level, or a local name bound to a derived one), a set or
      dict literal whose elements or keys are all literals, or a derived expression;
    * a DERIVED expression is a set operation (`|`, `&`, `-`, `^`) of two constant operands, or a
      `set()`, `frozenset()`, `dict()` or `dict.fromkeys()` call or a set or dict comprehension over
      sources only, where a source is a constant operand, its `.keys()`, a module-level tuple constant
      (`_module_sequences`), a copy of a source (`list`, `tuple`, `sorted`), or a list comprehension or
      generator over sources;
    * a LOCAL NAME is derived when the function that binds it (or one enclosing it) binds it to a
      derived expression or to a container, also by unpacking, by `:=` (also in the default of a
      function defined in it) or as a branch of a conditional, anywhere in its body.

    NOT A SOURCE: `.values()` and `.items()`, and every copy of them (the lens on c3bd89a4). The values
    of a dict can be set from outside at run time (`_M["a"] = v`), so a container built from them is
    not constant; its construction hashes those values and is reported as an other use where the dict
    is read (`_iterated`), and the result is no derived container.

    A set built at run time from something that is not constant (`set(claim)`, `set(allowed)`) is not
    derived: what it hashes on construction is reported where the constant meets it (`_REQUIRED -
    set(claim)`), and a membership test in it is not seen (the honest limit in the module docstring).

    `gebunden` holds the container reads that are the value of a binding a reader follows: the value
    of a pair `_scope_bindings` marks followed, whose name became a container in the scope that binds
    it. `other_uses` counts exactly these as bound. A WALRUS IS READ AS ITS VALUE (`_walrus_value`),
    by every reader here, because it passes that value to the expression around it: a bound walrus
    value is judged where the walrus stands as well, unless the walrus is a statement of its own.

    A CONDITIONAL PASSES ONE OF ITS BRANCHES, and is read through `_passed_values` (the lens on
    d5747000). As the container of a test or a lookup it is one when any branch is one, because the
    access hashes whenever that branch runs; as a constant operand or a source it counts only when
    every branch does, because only then is what it passes on constant."""

    def __init__(self, tree: ast.Module, behaelter: dict[str, str]):
        self.behaelter = behaelter
        self.folgen = _module_sequences(tree)
        self.parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        # the innermost function each node belongs to (None at module level). A function's decorators,
        # defaults and annotations belong to the scope around it, where Python evaluates them, and
        # where `_scope_nodes` reads them; only its body belongs to it.
        self.scope: dict[ast.AST, ast.AST | None] = {tree: None}
        stapel: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
        while stapel:
            k, fn = stapel.pop()
            koerper = None
            if isinstance(k, _SCOPES):
                koerper = {id(x) for x in ([k.body] if isinstance(k, ast.Lambda) else k.body)}
            for c in ast.iter_child_nodes(k):
                s = fn if koerper is None or id(c) in koerper else self.scope[k]
                self.scope[c] = s
                stapel.append((c, c if isinstance(c, _SCOPES) else s))
        self.lokal: dict[ast.AST, dict[str, str]] = {}
        self._sichtbar: dict[ast.AST | None, dict[str, str]] = {None: {}}
        paare: dict[ast.AST, list[tuple[str, ast.AST, bool]]] = {}
        # ast.walk goes breadth first, so a function is read before the ones nested in it
        for fn in ast.walk(tree):
            if isinstance(fn, _SCOPES):
                paare[fn] = _scope_bindings(fn, False)
                self.lokal[fn] = self._local_names(fn, paare[fn])
        self.gebunden: set[int] = {
            id(wert) for name, wert, gefolgt in _scope_bindings(tree, True)
            if gefolgt and name in behaelter}
        for fn, liste in paare.items():
            self.gebunden.update(id(wert) for name, wert, gefolgt in liste
                                 if gefolgt and name in self.lokal[fn])

    def _visible_in(self, fn: ast.AST | None) -> dict[str, str]:
        if fn not in self._sichtbar:
            self._sichtbar[fn] = {**self._visible_in(self.scope.get(fn)), **self.lokal.get(fn, {})}
        return self._sichtbar[fn]

    def visible(self, knoten: ast.AST) -> dict[str, str]:
        """The local derived names visible at `knoten`: those of every function enclosing it, the
        innermost winning."""
        return self._visible_in(self.scope.get(knoten))

    def _local_names(self, fn: ast.AST, paare: list[tuple[str, ast.AST, bool]]) -> dict[str, str]:
        # every pair, a `global` or `nonlocal` name too: its uses in THIS function are read as a
        # container's; that the binding is not followed further is `gebunden`'s business
        bindungen = [(name, wert) for name, wert, _gefolgt in paare]
        aussen = self._visible_in(self.scope.get(fn))
        eigene: dict[str, str] = {}
        neu = True
        while neu:
            neu = False
            for name, wert in bindungen:
                if name in eigene:
                    continue
                sichtbar = {**aussen, **eigene}
                wert = _walrus_value(wert)
                art = (self.konstant(wert, sichtbar) if isinstance(wert, ast.Name)
                       else self.derived(wert, sichtbar))
                if art:
                    eigene[name] = art
                    neu = True
        return eigene

    def konstant(self, e: ast.AST, sichtbar: dict[str, str]) -> str | None:
        """The kind of a constant hashing operand, or None. A conditional is one when every branch is."""
        e = _walrus_value(e)
        zweige = _passed_values(e)
        if len(zweige) > 1:
            arten = [self.konstant(z, sichtbar) for z in zweige]
            return arten[0] if all(arten) else None
        if isinstance(e, ast.Name):
            return sichtbar.get(e.id) or self.behaelter.get(e.id)
        if isinstance(e, ast.Set) and all(isinstance(x, ast.Constant) for x in e.elts):
            return "set"
        if isinstance(e, ast.Dict) and all(isinstance(k, ast.Constant) for k in e.keys):
            return "dict"
        return self.derived(e, sichtbar)

    def _source(self, e: ast.AST, sichtbar: dict[str, str]) -> bool:
        """Is `e` something constant a copy is built over: a constant operand, its `.keys()`, a
        module-level tuple constant, a copy of a source (`list`, `tuple`, `sorted`), or a list
        comprehension or generator over sources? Never `.values()` or `.items()` (see the class). A
        conditional is a source when every branch is."""
        e = _walrus_value(e)
        zweige = _passed_values(e)
        if len(zweige) > 1:
            return all(self._source(z, sichtbar) for z in zweige)
        if (isinstance(e, ast.Call) and not e.args and not e.keywords
                and isinstance(e.func, ast.Attribute) and e.func.attr == "keys"):
            e = e.func.value
        if (isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id in _COPYING_CALLS
                and len(e.args) == 1 and not e.keywords):
            return self._source(e.args[0], sichtbar)
        if isinstance(e, (ast.ListComp, ast.GeneratorExp)):
            return all(self._source(g.iter, sichtbar) for g in e.generators)
        if isinstance(e, ast.Name) and e.id in self.folgen and e.id not in sichtbar:
            return True
        return self.konstant(e, sichtbar) is not None

    def derived(self, e: ast.AST, sichtbar: dict[str, str]) -> str | None:
        """The kind of a derived expression (never a bare name), or None."""
        e = _walrus_value(e)
        if isinstance(e, ast.BinOp) and isinstance(e.op, _SET_OPERATORS):
            links = self.konstant(e.left, sichtbar)
            return links if links and self.konstant(e.right, sichtbar) else None
        if (isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id in _HASHING
                and len(e.args) == 1 and not e.keywords and self._source(e.args[0], sichtbar)):
            return e.func.id
        if (isinstance(e, ast.Call) and _hashing_call(e, e.args[0] if e.args else None)
                and isinstance(e.func, ast.Attribute) and self._source(e.args[0], sichtbar)):
            return "dict"   # dict.fromkeys(source, ...)
        if (isinstance(e, (ast.SetComp, ast.DictComp))
                and all(self._source(g.iter, sichtbar) for g in e.generators)):
            return "set" if isinstance(e, ast.SetComp) else "dict"
        return None

    def container(self, e: ast.AST, bei: ast.AST) -> tuple[str, str] | None:
        """(label, kind) when `e`, read at `bei`, is a hashing container: a module-level one or a local
        derived name by its name, a derived expression by its source text. A walrus is its value, and a
        conditional is a container when any branch is one, labelled by its source text: `k in (_A if c
        else x)` hashes `k` whenever `c` holds."""
        sichtbar = self.visible(bei)
        e = _walrus_value(e)
        zweige = _passed_values(e)
        if len(zweige) > 1:
            arten = [wer[1] for wer in (self.container(z, bei) for z in zweige) if wer is not None]
            return (ast.unparse(e), arten[0]) if arten else None
        if isinstance(e, ast.Name):
            art = sichtbar.get(e.id) or self.behaelter.get(e.id)
            return (e.id, art) if art else None
        art = self.derived(e, sichtbar)
        return (ast.unparse(e), art) if art else None


def unguarded_membership_sites(quelle: str, name: str = "<quelle>", modul: str | None = None,
                               ist_init: bool = False,
                               je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(Zeile, linker Ausdruck, Behälter) für jeden ungeschützten Mitgliedstest.

    A CONSTANT left operand is skipped on purpose: ``"status" in predicate`` asks whether a KEY is
    present, the left side is a literal string, and a literal is always hashable. Flagging it would
    make the scanner noisy exactly where it is always right, and a noisy scanner gets silenced.

    The right side is a container by name or a derived one (`_Sicht`): `x in (_A - _B)`, `x in
    set(_M)` and `x in allowed` after `allowed = _A | {"b"}` hash x as `x in _A` does; the review of
    fc863e2e found the first of them live in `agent_review.validate_time_claim`."""
    tree = ast.parse(quelle, filename=name)
    sicht = _Sicht(tree, _behaelter(tree, modul, ist_init, je_modul))
    treffer: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
            continue
        rechts = _walrus_value(node.comparators[0])
        # `x in CONST.keys()` hashes x as `x in CONST` does (the second delta run on e4ea49b9).
        if (isinstance(rechts, ast.Call) and not rechts.args and isinstance(rechts.func, ast.Attribute)
                and rechts.func.attr == "keys"):
            rechts = rechts.func.value
        wer = sicht.container(rechts, node)
        if wer is None or isinstance(node.left, ast.Constant):
            continue
        treffer.append((node.lineno, ast.unparse(node.left), wer[0]))
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
    argument is listed; an argument that is no literal is reported by `other_uses`. A derived container
    (`_Sicht`) is read the same way: `(_M | _N).get(x)`, `set(_S).add(x)`, and `allowed[x]` after
    `allowed = dict(_M)`, labelled by the source text of the expression or by the local name."""
    tree = ast.parse(quelle, filename=name)
    sicht = _Sicht(tree, _behaelter(tree, modul, ist_init, je_modul))
    operator_names = {"operator"} | {a.asname for n in ast.walk(tree) if isinstance(n, ast.Import)
                                     for a in n.names if a.name == "operator" and a.asname}
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        keys: list = []
        wer = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            wer = sicht.container(node.func.value, node)
        if wer is not None:
            const, art = wer
            if node.func.attr in _HASHING_METHODS[art] and node.args:
                keys = [node.args[0]]
            elif node.func.attr == "update":
                # every literal argument, also next to one that is not (other_uses reports that one)
                keys = [k for arg in node.args for k in (_literal_keys(arg) or [])]
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and isinstance(node.func.value, ast.Name) and node.func.value.id in operator_names
              and node.func.attr in _OPERATOR_ACCESS and len(node.args) >= 2
              and (wer := sicht.container(node.args[0], node)) is not None):
            const, keys = wer[0], [node.args[1]]
        elif (isinstance(node, ast.Subscript) and (wer := sicht.container(node.value, node)) is not None
              and wer[1] == "dict"):
            const, keys = wer[0], [node.slice]
        elif (isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr)
              and (wer := sicht.container(node.target, node)) is not None):
            const, keys = wer[0], _literal_keys(node.value) or []
        for key in keys:
            if not isinstance(key, ast.Constant):
                found.append((node.lineno, const, ast.unparse(key)))
    return found


#: The calls that only iterate their one argument (the first three copy it into a sequence), the calls
#: that hash what they iterate, and the dict views a loop or such a call iterates.
_COPYING_CALLS = {"sorted", "list", "tuple"}
_ITERATING_CALLS = _COPYING_CALLS | {"len"}
_HASHING_CALLS = {"set", "frozenset", "dict"}
_VIEW_METHODS = {"items", "values", "keys"}


def _hashing_call(p: ast.AST | None, node: ast.AST) -> bool:
    """Does call `p` hash what `node`, its argument, yields: `set(node)`, `frozenset(node)`,
    `dict(node)`, and `dict.fromkeys(node, ...)`, which hashes its first argument's elements as keys."""
    if not isinstance(p, ast.Call) or p.keywords:
        return False
    if isinstance(p.func, ast.Name):
        return p.func.id in _HASHING_CALLS and p.args == [node]
    return (isinstance(p.func, ast.Attribute) and p.func.attr == "fromkeys"
            and isinstance(p.func.value, ast.Name) and p.func.value.id == "dict"
            and bool(p.args) and p.args[0] is node)


#: Calls that hand on the elements of one argument, in some order or in part: the copies above, and
#: `reversed`, `iter` and `enumerate` over their first argument, `filter` over its second, `map` over
#: every argument after the function, `zip` over every argument.
_PASSING_FIRST = _COPYING_CALLS | {"reversed", "iter", "enumerate"}


def _passing_call(p: ast.AST | None, e: ast.AST) -> bool:
    """Does call `p` hand on what `e`, one of its arguments, yields?"""
    if not (isinstance(p, ast.Call) and isinstance(p.func, ast.Name)):
        return False
    wer = p.func.id
    if wer in _PASSING_FIRST:
        return bool(p.args) and p.args[0] is e
    if wer == "filter":
        return len(p.args) >= 2 and p.args[1] is e
    if wer == "map":
        return any(a is e for a in p.args[1:])
    return wer == "zip" and any(a is e for a in p.args)


def _hashed_downstream(e: ast.AST | None, parents: dict) -> bool:
    """Do the elements the sequence `e` yields reach a construction that hashes them, directly or
    through any chain of copies, comprehensions, generators and passing calls (`_passing_call`)?

    The review of fc863e2e wrote three copies past the guard, each of which hashed the values of a
    dict: `set([x for x in _M.values()])`, `set(list(_M.values()))` and `dict.fromkeys(...)` over
    either. The lens on c3bd89a4 wrote seven more past the second form, which followed copies only up
    to a DIRECT hashing call: `{x for x in list(_M.values())}`, `set(x for x in list(...))`,
    `{x: 1 for x in sorted(...)}`, `set([x for x in list(...)])` (a comprehension over a copy),
    `{*list(...)}` (a starred element of a set display), `set(reversed(list(...)))` and
    `frozenset(filter(None, list(...)))` (a wrapper between the copy and the set). Each hashes the
    values, and each is followed here: a set or dict comprehension and a set display hash, a list
    comprehension, a generator, a list or tuple display with the sequence starred in it and a passing
    call hand the elements on, and anything else is where the elements leave (the stated limit)."""
    while e is not None:
        p = parents.get(e)
        if _hashing_call(p, e):
            return True
        if isinstance(p, ast.comprehension) and p.iter is e:
            comp = parents.get(p)
            if isinstance(comp, (ast.SetComp, ast.DictComp)):
                return True
            if not isinstance(comp, (ast.ListComp, ast.GeneratorExp)):
                return False
            e = comp
        elif isinstance(p, ast.Starred) and p.value is e:
            anzeige = parents.get(p)
            if isinstance(anzeige, ast.Set):
                return True
            if not isinstance(anzeige, (ast.List, ast.Tuple)):
                return False
            e = anzeige
        elif _passing_call(p, e):
            e = p
        elif isinstance(p, ast.NamedExpr) and p.value is e:
            # a walrus hands the elements on to the expression around it (`set((w := list(...)))`,
            # the lens on 8ecb6edf); what the name then carries is the stated limit below
            e = p
        elif isinstance(p, ast.IfExp) and p.test is not e:
            # so does a conditional, as one of its branches (`set(list(...) if c else [])`, found while
            # closing the lens on d5747000, which wrote the same step past the readers)
            e = p
        else:
            return False
    return False


def _iterated(node: ast.AST, parents: dict, view: str | None = None) -> bool:
    """Is this expression the source of a `for`, of a comprehension, or the one argument of a call
    that only iterates it? Iterating a container hashes nothing from outside.

    `set`, `frozenset`, `dict` and `dict.fromkeys` HASH what they iterate. Over the container or its
    `.keys()` that is a key, already hashed; over `.values()` or `.items()` it is a value, which can come
    from outside: the delta run on 09d5c5b3 wrote `_M["a"] = v` with `v = []`, and `set(_M.values())`
    raised while the guard counted it as iteration. A set or dict comprehension over those views hashes
    the same values, and so does every chain `_hashed_downstream` follows to a hashing construction;
    each is an other use."""
    p = parents.get(node)
    werte = view in ("values", "items")
    if isinstance(p, (ast.For, ast.comprehension)) and p.iter is node:
        return not (werte and isinstance(p, ast.comprehension) and _hashed_downstream(node, parents))
    if _hashing_call(p, node):
        return not werte
    if (isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id in _ITERATING_CALLS
            and p.args == [node] and not p.keywords):
        return not (werte and _hashed_downstream(node, parents))
    return False


def other_uses(quelle: str, name: str = "<quelle>", modul: str | None = None, ist_init: bool = False,
               je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(line, container, use) for every read of a hashing container that none of the known forms
    covers. DENY BY DEFAULT: the third delta run on 1ab75135 wrote five more spellings past the two
    detectors above (`getter = CONST.get`, `getattr(CONST, "get")`, `CONST.__class__.__getitem__`,
    `CONST.keys().__contains__`, `x in CONST.items()`), and each hashed an unhashable key. A list of
    spellings is one spelling behind; a list of the forms that are known, with everything else named,
    is not.

    A read is a load of a module-level container's name, of a local name bound to a derived container,
    or a derived expression itself (`_Sicht`). A set operation between two constants is known only
    because its RESULT is read in turn: the review of fc863e2e found `x in (_A - _B)` raising in
    `agent_review.validate_time_claim` while this function cleared `_A - _B` and looked no further.

    Known, and not reported here: a hashing access with a key (`constant_lookups`, including `update`
    and `|=` when every argument is a literal that names its keys, and `update(k=v)` on a dict), a
    membership test (`unguarded_membership_sites`, also through `.keys()`), the second argument of
    `is_member`, iteration (a `for`, a comprehension, the one argument of sorted/list/tuple/len, also
    through `.items()`, `.values()`, `.keys()`; the one argument of set/frozenset/dict and the first of
    `dict.fromkeys`, and a set or dict comprehension, only over the container or `.keys()`, because they
    hash what they iterate, and so does every chain of copies, comprehensions, starred displays and
    passing calls that reaches one of them, `_hashed_downstream`), a condition, a comparison whose
    other side is a constant, a set operation whose other side is a constant (its result is read as a
    derived container), and the value of a binding a reader follows (`_Sicht.gebunden`). A constant is
    a literal, a container, a derived expression, or a set or dict literal whose elements or keys are
    all literals. Every other read is reported: passing the container to a function, returning it,
    putting it in a tuple, reaching a method without calling it, `update` or `|=` with a name, a `*x` or
    `**x`, `_S | {k}`, `set(CONST.values())`, `{x for x in list(CONST.values())}`, a binding whose name
    is `global` or `nonlocal`, an attribute, or a class attribute. The container is named by its name,
    or a derived expression by its source text."""
    tree = ast.parse(quelle, filename=name)
    sicht = _Sicht(tree, _behaelter(tree, modul, ist_init, je_modul))
    parents = sicht.parents
    operator_names = {"operator"} | {a.asname for n in ast.walk(tree) if isinstance(n, ast.Import)
                                     for a in n.names if a.name == "operator" and a.asname}

    def constant(e: ast.AST, bei: ast.AST) -> bool:
        # A set literal hashes its elements when it is built and a dict literal its keys, so it is a
        # constant operand only when every one of them is a literal: `_S | {k}` and `_M | {k: 1}`
        # raised for `k = []` while the first form counted any literal as constant (the delta run on
        # 09d5c5b3). A `**x` in a dict literal has the key None here and is no literal either.
        return isinstance(e, ast.Constant) or sicht.konstant(e, sicht.visible(bei)) is not None

    def bound(n: ast.AST) -> bool:
        # THE VALUE OF A BINDING A READER FOLLOWS, and nothing that only looks like one: `_Sicht.gebunden`
        # is built from the same pairs the readers make containers from (`_scope_bindings`). A name in a
        # class body is an attribute, which no reader follows, so it is not there either.
        return id(n) in sicht.gebunden

    def use_of(n: ast.AST, art: str) -> tuple[bool, str]:
        p, known = parents.get(n), False
        if (isinstance(n, (ast.NamedExpr, ast.IfExp)) and _hashed_downstream(n, parents)
                and not sicht._source(n, sicht.visible(n))):
            # A HASHING COPY OVER A VALUE BUILT AT RUN TIME IS NO DERIVED CONTAINER, so no reader reads
            # it, and it is reported here. The lens on d6d89763 wrote `k in set((s := _A if c else x))`
            # with `x` from outside: the walrus bound `_A` to `s`, so `_A` read as bound and then as
            # iteration into `set()`, while the membership reader saw a set over a conditional that is
            # no source and looked away. `frozenset(...)` and `dict.fromkeys(...).get(k)` went the same
            # way. Without the walrus the branch was an other use of its own (`IfExp`); now both are
            # judged by what the copy hashes and whether every value it passes on is a source.
            return False, "hashed together with a value built at run time"
        if isinstance(p, ast.IfExp) and p.test is not n and bound(n):
            # A BOUND BRANCH GOES WHERE ITS CONDITIONAL GOES, and is judged there. `_bindings` binds
            # the conditional and its branches to one name, so the conditional is bound as well, and
            # where it is the value of a walrus it is judged where the walrus stands. Before, a bound
            # branch was known by its binding alone, so `foo((s := _A if c else _B))` read as bound
            # (the lens on d5747000). An UNBOUND branch stays an other use of its own (`IfExp`): the
            # conditional around it is no container a reader follows, and judging the branch by the
            # conditional's use would clear it under a rule that assumes one (a set operation with a
            # constant, whose result a reader then reads).
            return use_of(p, art)
        if isinstance(p, ast.NamedExpr) and p.value is n:
            # THE VALUE OF A WALRUS GOES TWO WAYS: into the name, which counts as known only when a
            # reader follows it, and into the expression around the walrus, where it is judged as the
            # walrus itself. A walrus standing as a statement of its own passes nothing on. Before,
            # a followed binding was the whole answer, and `foo((s := _A))` or `k in (s := _A)` read
            # as bound (the lens on 8ecb6edf).
            if not bound(n):
                return False, "NamedExpr"
            if isinstance(parents.get(p), ast.Expr):
                return True, "bound"
            return use_of(p, art)
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
                         and all(constant(e, n) for e in others))
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
            # KNOWN ONLY WHEN BOTH OPERANDS ARE CONSTANT, which is what makes the result a derived
            # container that the readers then read. For a container or a derived expression `n` is
            # constant by what it is; a walrus or a conditional reached through a binding is constant
            # only when every value it passes on is (`(s := _A if c else x) | {"a"}` is built at run
            # time from `x` and is reported, as `_A | x` always was).
            other = p.right if p.left is n else p.left
            known, use = (constant(other, n) and constant(n, n),
                          f"{type(p.op).__name__} {ast.unparse(other)}")
        elif bound(n):
            known, use = True, "bound"
        else:
            use = type(p).__name__ if p is not None else "module"
        return known, use

    found: list[tuple[int, str, str]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.AugAssign):
            wer = sicht.container(n.target, n)
            if wer is not None and not (isinstance(n.op, ast.BitOr) and _literal_keys(n.value) is not None):
                found.append((n.lineno, wer[0], f"{type(n.op).__name__}= {ast.unparse(n.value)}"))
            continue
        if isinstance(n, ast.Name):
            wer = sicht.container(n, n) if isinstance(n.ctx, ast.Load) else None
        elif isinstance(n, (ast.BinOp, ast.Call, ast.SetComp, ast.DictComp)):
            wer = sicht.container(n, n)
        else:
            wer = None
        if wer is None:
            continue
        known, use = use_of(n, wer[1])
        if not known:
            found.append((n.lineno, wer[0], use))
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
#: under 19 keys, none open. Measured once more after the review of fc863e2e, with module-level set
#: operations and derived containers read as containers: still 19 sites under 19 keys, none new; no
#: derived container in the tree is looked up. Measured after the lens on c3bd89a4, with a set or dict
#: built over a module-level tuple read as a container: 20 sites under 20 keys, the new one
#: `daten[f]` in `adapters/agt_receipt.canonical_payload`, read at its source. A new site, also one more
#: under a listed key, turns this red until it is classified here; a site that is gone must leave the
#: list or lower its count.
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
    # Seen once a set or dict built over a module-level tuple constant is a container (the lens on
    # c3bd89a4, `allowed = set(_T)`): `daten = {f: receipt[f] for f in _PFLICHTFELDER}`.
    ("proofbundle/adapters/agt_receipt.py", "canonical_payload", "daten", "f"):
        (1, "own value: f runs over _WAHLFELDER, a tuple of two string literals of the module"),
}


def _in_the_tree(detektor, ersatz: dict[str, str] | None = None, ansicht=None) -> dict[tuple, int]:
    """(file, enclosing definition, container, key or use) -> NUMBER of sites the detector reports
    over src/proofbundle. `ersatz` maps a file (as `proofbundle/x.py`) to a planted text read in its
    place, so a test can plant a site into a copy of the real tree; a name that is not a file of the
    tree is an error, not a file nobody reads. `ansicht` builds the per-module view the detector reads,
    `containers_by_module` unless named (`numbers_by_module` for the number containers)."""
    import collections  # noqa: PLC0415
    quellen = _package_sources()
    for datei, text in (ersatz or {}).items():
        modul = _modulname(SRC.parent / datei, SRC.parent)
        if modul not in quellen:
            raise KeyError(f"{datei} is no file of the tree; a plant there would be read by nobody")
        quellen[modul] = (text, quellen[modul][1])
    je_modul = (ansicht or containers_by_module)(quellen)
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

#: Every other read of a hashing container, and why it cannot hash a value from outside. Keyed like
#: `_LOOKUPS_CLASSIFIED`, with the same (count, reason); a derived container is named by its source
#: text. The first form said "35 reads" on 1ab75135; 35 was the number of KEYS. Measured on the tree of
#: 09d5c5b3 after every form of the delta run was read: 38 reads under 35 keys. Three keys cover two
#: reads each: `_REQUIRED - set(claim)` and `set(claim) - _REQUIRED` in both `decode_eval_claim` and
#: `emit_eval_receipt`, and the two `automation_summary` calls in `verify_trust_pack`. Measured after
#: the review of fc863e2e: 40 reads under 37 keys, the two new ones `decision._ALLOWED_TOP` (a
#: module-level set operation, now a container) and `dict(PROFILE_ALIASES)` returned by
#: `policy_profiles.profile_aliases` (a derived container). Measured after the lens on c3bd89a4: 45
#: reads under 42 keys, the five new ones each a set or dict built over a module-level tuple (in
#: `adapters/agt_receipt`, `cli`, `public_transparency` and twice `relation`); no binding in the tree
#: that the first form counted as followed is one no reader follows. Each read was read at its callee
#: or at the check before it. A new read, also one more under a listed key, turns the tree test red
#: until it is classified here, and a classified read that is gone has to leave the list or lower its
#: count.
_OTHER_USES_CLASSIFIED = {
    ("proofbundle/agent_review.py", "_validate_coverage", "_COVERAGE_FIELDS_V02", "LtE zusatz"):
        (1, "own value: zusatz comes from the package (_COVERAGE_FIELDS_V02 or the empty default), and a "
         "subset test between two frozensets hashes nothing new"),
    ("proofbundle/agent_review.py", "_validate_declaration", "_DECLARATION_FIELDS", "BitOr zusatz"):
        (1, "own value: zusatz comes from the package (_DECLARATION_FIELDS_V02 or the empty default), and the "
         "union is tested only with `k`, a key of `dec`, which isinstance(dec, dict) checked before it; "
         "with a parameter on one side the union is no derived container, so its membership test is "
         "read here and not by the membership scanner"),
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
    # Seen once a module-level set operation is a container (the review of fc863e2e).
    ("proofbundle/decision.py", "validate_decision_predicate", "_ALLOWED_TOP", "Sub set(predicate)"):
        (1, _OWN_SET.format(x="predicate", what="a dict (isinstance(predicate, dict) returns before it)")),
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
    # Seen once a derived expression is a read (the review of fc863e2e).
    ("proofbundle/policy_profiles.py", "profile_aliases", "dict(PROFILE_ALIASES)", "Return"):
        (1, "own value: a copy of PROFILE_ALIASES, whose keys and values are string literals of the "
         "package, handed to the caller; the one caller in the package, cli._cmd_policy_list_profiles, "
         "iterates its items and keys a dict of its own by those literal values"),
    ("proofbundle/trust_pack.py", "_finalize_failclosed", "_AUTOMATION_REQUIRED_CHECKS",
     "automation_summary(required_checks=)"):
        (1, "passed to automation_summary: it reads the mapping with literal keys only"),
    ("proofbundle/trust_pack.py", "verify_trust_pack", "_AUTOMATION_REQUIRED_CHECKS",
     "automation_summary(required_checks=)"):
        (2, "passed to automation_summary: it reads the mapping with literal keys only"),
    # Seen once a set or dict built over a module-level tuple constant is a container (the lens on
    # c3bd89a4). Each was read at its source.
    ("proofbundle/adapters/agt_receipt.py", "canonical_payload", "daten", "_sortkeys_json(argument 1)"):
        (1, "passed to _sortkeys_json: it hands the mapping to json.dumps, which serialises it and sorts "
         "its keys, the string literals of _PFLICHTFELDER and _WAHLFELDER; it hashes nothing"),
    ("proofbundle/cli.py", "_error_verify_fields", "fields", "Return"):
        (1, "own value: keyed by the string literals of _VERIFY_NULLABLE_FIELDS and three more literals; "
         "the one caller, _cmd_verify, spreads it into a dict display and hands that to json.dumps"),
    ("proofbundle/public_transparency.py", "evaluate_public_transparency", "statuses", "Dict"):
        (1, "own value: keyed by the string literals of _STATUS_NAMES, every value a literal the function "
         "writes (PASS, FAIL, NOT_EVALUATED), returned in the result dict"),
    ("proofbundle/relation.py", "_validate_edge_digest", "set(_DIGEST_ALLOWED)", "Sub set(obj)"):
        (1, _OWN_SET.format(x="obj", what="a dict (isinstance(obj, dict) returns before it)")),
    ("proofbundle/relation.py", "validate_relationships", "set(_EDGE_ALLOWED)", "Sub set(edge)"):
        (1, _OWN_SET.format(x="edge", what="a dict (a non-dict edge is skipped by `continue` before it)")),
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
             "bevor irgendein Mitgliedstest laeuft. Die fuenf Bestandsstellen stehen namentlich "
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
        ``render_disclosure_block`` carries exactly ONE ``str(a.get('assertedBy'))``; a second one
        there is new. (Until c3bd89a4 this planted into ``derive_limitation_codes``, and until the
        renderer fix on this branch into ``i.get('assurance')`` of the renderer; both sites are closed
        now and left the baseline.)
        """
        quelle = ("def render_disclosure_block(xs):\n"
                  "    a = {str(a.get('assertedBy')) for a in xs}\n"
                  "    b = {str(a.get('assertedBy')) for a in xs}\n"
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

    STATED LIMIT: the guard reads every use of a container's NAME and of a DERIVED container, covers
    it by a known form or lists it, and holds both lists exact, with the number of sites per key. A
    container is a name bound at module level to a set, dict or frozenset literal, comprehension or
    `set()`/`frozenset()`/`dict()`/`dict.fromkeys()`/`MappingProxyType()` call, to another container's
    name, or to a set operation over such values, also by unpacking a tuple (around a starred name
    too), by `:=`, as a `for` target over a display, and inside a module-level `if`, `try`, `with`,
    `for`, `while` or `match`, and also when another module of the package imports it by name, through
    a chain of such imports, or with `from .x import *`. An expression derived from containers or from
    a module-level tuple, and a local name bound to one, is read as a container too (`_Sicht`); a
    binding counts as followed only when a reader reads its name, anything else is reported. A
    container reached as a module attribute (`x.NAME`), through a string (`globals()`, `vars()`),
    bound in a class body, returned by a function call, or built at run time from a value that is not
    constant is not one it reads. A value that leaves the container (`for v in CONST.values(): ...`,
    or a copy of the values bound to a name) is not followed. It does NOT prove the reasons in
    `_LOOKUPS_CLASSIFIED` and `_OTHER_USES_CLASSIFIED`. A person read each guard before classifying
    the site, and a guard removed later leaves the reason standing. Only a test that sends an
    unhashable value to the surface can catch that; this one cannot."""

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
                         "a new read of a hashing container that no known form covers: "
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
        reported, while the forms that hash nothing from outside are not. A set operation between two
        constants is known because its result is read in turn (the review of fc863e2e), here by
        `sorted`; the same result returned in the tuple would be reported where it leaves."""
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
                        sorted(_S - _T), _S <= {"a"}, [v for v in _M.values()], sorted(_M.items()))
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
        for `k = []`. A literal counts only when every element, or every key, is a literal. `i` and `j`
        are then containers derived from constants (the review of fc863e2e), so the tuple that returns
        them is reported once for each; the others hold `k` and are not derived."""
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
                          "e = _M | {k: 1}", "g = _M | {**other}", 'h = {"b", k} & _S',
                          "return a, b, c, d, e, g, h, i, j", "return a, b, c, d, e, g, h, i, j"])
        self.assertEqual(sorted(c for _z, c, u in other_uses(quelle) if u == "Tuple"), ["i", "j"])
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
        nothing, over any view. Each result that is a container derived from `_M`'s keys (`set(_M)`
        and its siblings) is reported where it leaves in the returned tuple (the review of fc863e2e).
        The names `a` to `g` are built from the values and are no derived containers (the lens on
        c3bd89a4): values are not constant, so their construction is the reported site, not their
        use; the lists and the sorted copies are no hashing containers."""
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
        funde = other_uses(quelle)
        self.assertEqual(self._reported_lines(quelle, [f for f in funde if f[2] != "Tuple"]),
                         ["a = set(_M.values())", "b = frozenset(_M.items())", "c = dict(_M.values())",
                          "d = {x for x in _M.values()}", "e = {x: 1 for x in _M.items()}",
                          "g = set(x for x in _M.values())"])
        self.assertEqual(sorted(c for _z, c, u in funde if u == "Tuple"),
                         sorted(["set(_M)", "set(_M.keys())", "frozenset(_M)", "dict(_M)",
                                 "{x for x in _M}"]))
        m = {"a": 1}
        m["a"] = []
        for label, access in (("set", lambda: set(m.values())), ("frozenset", lambda: frozenset(m.items())),
                              ("comprehension", lambda: {x for x in m.values()})):
            with self.subTest(form=label), self.assertRaises(TypeError):
                access()


class TestADerivedContainerIsAContainer(unittest.TestCase):
    """The review of fc863e2e found a live defect past this guard and named the class behind it: a
    container DERIVED from constant containers hashes as they do, and nothing read it. The membership
    scanner saw only a name on the right of `in`, and `other_uses` cleared a set operation between two
    constants without looking at what used the result. One test per form the review wrote; each plants
    in a source string, the first into a copy of the real file."""

    @staticmethod
    def _reported_lines(quelle: str, funde) -> list[str]:
        zeilen = quelle.splitlines()
        return [zeilen[z - 1].strip() for z, _c, _was in sorted(funde)]

    def test_the_live_defect_is_found_where_it_stood(self):
        """`agent_review.validate_time_claim` on fc863e2e, planted back into a copy of the real file:
        the membership scanner reports it, labelled with the derived container, and the file as it is
        now reports nothing."""
        quelle = (SRC / "agent_review.py").read_text(encoding="utf-8")
        jetzt = 'if is_member(tc.get("assurance"), _TIME_ASSURANCE - _V02_ASSURANCE_ALLOWED_FOR_CLAIMS):'
        damals = 'if tc.get("assurance") in (_TIME_ASSURANCE - _V02_ASSURANCE_ALLOWED_FOR_CLAIMS):'
        self.assertEqual(quelle.count(jetzt), 1, "the plant point moved: plant where the rung is tested")
        je_modul = containers_by_module(_package_sources())

        def sites(text: str) -> list[tuple[str, str]]:
            return [(links, c) for _z, links, c in unguarded_membership_sites(
                text, "agent_review.py", "proofbundle.agent_review", False, je_modul)]

        self.assertEqual(sites(quelle), [])
        self.assertEqual(sites(quelle.replace(jetzt, damals)),
                         [("tc.get('assurance')", "_TIME_ASSURANCE - _V02_ASSURANCE_ALLOWED_FOR_CLAIMS")])
        with self.assertRaises(TypeError):
            [] in ({"selfDeclared", "runnerObserved"} - {"selfDeclared"})   # noqa: B015

    def test_a_membership_test_in_a_derived_container_is_found(self):
        """Every derived form on the right of `in`, inline and through a local name (bound by `=`, by
        unpacking, by `:=`, as a branch of a conditional, or in an enclosing function). Not found: a
        literal on the left, `is_member`, a tuple, a set built from a value that is not constant, and a
        set operation with a literal that holds a name (that one is an other use)."""
        quelle = textwrap.dedent('''
            _A = {"a", "b"}
            _B = frozenset({"b"})
            _M = {"a": 1}
            _T = ("a", "b")
            def f(p, k):
                allowed = _A | {"c"}
                x = set(_M)
                (y := dict(_M))
                u, v = _A - _B, 1
                w = _A if k else _B
                r, erl = (_T, _A) if k else (_T, _B)
                z = allowed & _B
                def inner(q):
                    return q in allowed
                found = (p.get("a") in (_A - _B), k in set(_M), k in frozenset(_A), k in dict(_M),
                         k in {e for e in _A}, k in {e: 1 for e in _M}, k in dict(_M).keys(),
                         k in allowed, k in x, k in y, k in u, k in w, k in erl, k in z)
                known = ("a" in (_A - _B), is_member(k, _A - _B), k in _T, k in set(p), k in v,
                         k in (_A | {k}), k in list(_A), k in r)
                return found, known
        ''')
        self.assertEqual(sorted((links, c) for _z, links, c in unguarded_membership_sites(quelle)),
                         sorted([("q", "allowed"), ("p.get('a')", "_A - _B"), ("k", "set(_M)"),
                                 ("k", "frozenset(_A)"), ("k", "dict(_M)"), ("k", "{e for e in _A}"),
                                 ("k", "{e: 1 for e in _M}"), ("k", "dict(_M)"), ("k", "allowed"),
                                 ("k", "x"), ("k", "y"), ("k", "u"), ("k", "w"), ("k", "erl"), ("k", "z")]))
        with self.assertRaises(TypeError):
            [] in ({"a", "b"} | {"c"})                                        # noqa: B015

    def test_a_lookup_on_a_derived_container_is_found(self):
        """`<derived>.get(x)`, `<derived>[x]`, a set method that hashes, and `operator.getitem`, inline
        and through a local name. A literal key is not reported."""
        quelle = textwrap.dedent('''
            import operator
            _M = {"a": 1}
            _N = {"b": 2}
            _S = {"a"}
            def f(k):
                merged = _M | _N
                kopie = dict(_M)
                menge = set(_S)
                merged.get(k)
                kopie[k]
                menge.add(k)
                (_M | _N).get(k)
                dict(_M)[k]
                operator.getitem(_M | _N, k)
                merged["a"]
                return menge.discard("a")
        ''')
        self.assertEqual(sorted((c, k) for _l, c, k in constant_lookups(quelle)),
                         sorted([("merged", "k"), ("kopie", "k"), ("menge", "k"), ("_M | _N", "k"),
                                 ("dict(_M)", "k"), ("_M | _N", "k")]))
        with self.assertRaises(TypeError):
            ({"a": 1} | {"b": 2}).get([])

    def test_a_module_level_unpacking_or_set_operation_binds_a_container(self):
        """`_S, _M = {"a"}, {"a": 1}` bound two containers the guard did not see (the review of
        fc863e2e), and a module-level set operation such as `_ALLOWED_TOP = set(_REQUIRED_ALWAYS) |
        set(_OPTIONAL)` was a stated limit. Both are containers now, and so is a second name for one;
        an unpacking of a call binds nothing the guard can name, and a tuple stays a tuple."""
        quelle = textwrap.dedent('''
            _S, _M = {"a"}, {"a": 1}
            (_P, (_Q, _R)) = frozenset({"p"}), ({"q": 1}, ("r",))
            _T = ("a", "b")
            _U = set(_T) | {"c"}
            _V = _U - _S
            _W = _M
            _X = _Y = {"x"}
            _Z, _O = make()
            def f(k):
                return _M.get(k), k in _U, k in _V, _Q[k]
        ''')
        self.assertEqual(_hashing_containers(ast.parse(quelle)),
                         {"_S": "set", "_M": "dict", "_P": "frozenset", "_Q": "dict", "_U": "set",
                          "_V": "set", "_W": "dict", "_X": "set", "_Y": "set"})
        self.assertEqual(sorted((c, k) for _l, c, k in constant_lookups(quelle)), [("_M", "k"), ("_Q", "k")])
        self.assertEqual([(links, c) for _l, links, c in unguarded_membership_sites(quelle)],
                         [("k", "_U"), ("k", "_V")])
        with self.assertRaises(TypeError):
            [] in (set(("a", "b")) | {"c"})                                   # noqa: B015

    def test_the_result_of_a_set_operation_between_constants_is_read_in_turn(self):
        """A derived container is read like a container: handed to a function, reached through
        `getattr` or returned, it is reported; iterated, bound to a local name, or the second argument
        of `is_member`, it is known. A name bound in a class body is an attribute, which nothing
        follows, so that binding is reported."""
        quelle = textwrap.dedent('''
            _A = {"a"}
            _B = {"b"}
            def f(k):
                erlaubt = _A | _B
                foo(_A - _B)
                foo(erlaubt)
                getattr(erlaubt, "__contains__")(k)
                sorted(_A | _B)
                for x in _A & _B:
                    pass
                is_member(k, _A ^ _B)
                return _A - _B
            class K:
                X = _A | _B
        ''')
        self.assertEqual(sorted((c, u) for _l, c, u in other_uses(quelle)),
                         [("_A - _B", "Return"), ("_A - _B", "foo(argument 1)"), ("_A | _B", "Assign"),
                          ("erlaubt", "foo(argument 1)"), ("erlaubt", "getattr(argument 1)")])
        with self.assertRaises(TypeError):
            getattr({"a"} | {"b"}, "__contains__")([])

    def test_a_copy_that_hashes_the_values_of_a_dict_is_an_other_use(self):
        """Three copies the review of fc863e2e wrote past `_iterated`, each of which hashes the values
        of a dict: `set([x for x in _M.values()])` (a list comprehension; the first form knew only a
        generator), `set(list(_M.values()))` (a copy in between), and `dict.fromkeys(...)` over either
        (a hashing call the first form did not know). Over the keys `dict.fromkeys` hashes keys, and a
        copy that reaches no hashing call hashes nothing."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            def f(v):
                _M["a"] = v
                a = set([x for x in _M.values()])
                b = set(list(_M.values()))
                c = dict.fromkeys(_M.values())
                d = dict.fromkeys(x for x in _M.values())
                e = dict.fromkeys(sorted(_M.values()), 0)
                g = frozenset(tuple(_M.items()))
                h = dict.fromkeys(_M)
                i = sorted(list(_M.values()))
                j = len(list(_M.values()))
                return None
        ''')
        self.assertEqual(self._reported_lines(quelle, other_uses(quelle)),
                         ["a = set([x for x in _M.values()])", "b = set(list(_M.values()))",
                          "c = dict.fromkeys(_M.values())", "d = dict.fromkeys(x for x in _M.values())",
                          "e = dict.fromkeys(sorted(_M.values()), 0)", "g = frozenset(tuple(_M.items()))"])
        m = {"a": []}
        for label, access in (("list comprehension", lambda: set([x for x in m.values()])),
                              ("copy", lambda: set(list(m.values()))),
                              ("fromkeys", lambda: dict.fromkeys(m.values()))):
            with self.subTest(form=label), self.assertRaises(TypeError):
                access()


def _ueber_die_werte(ausdruck: str) -> tuple[str, object]:
    """A planted module whose `f(v)` stores `v` as a value of `_M` and builds `ausdruck` over it."""
    return f'_M = {{"a": 1}}\ndef f(v):\n    _M["a"] = v\n    s = {ausdruck}\n    return None\n', [[1]]


#: Every form the lens on c3bd89a4 executed against the guard, each a module with a function `f` whose
#: call with the given argument raises TypeError at run time (`init` runs first where it exists), in
#: the lens's own spelling (a copy of the values bound to a name the function then drops). The controls
#: are forms the guard already saw. One list, so that the runtime and the three detectors are asked
#: about the same text.
_PLANTED_FORMS: dict[str, tuple[str, object]] = {
    # 2b: bindings nothing followed, and forms the container readers did not know
    "module-level dict.fromkeys over a container":
        ('_A = {"a", "b"}\n_X = dict.fromkeys(_A)\ndef f(k):\n    return _X.get(k), k in _X\n', []),
    "module-level dict.fromkeys over a tuple":
        ('_T = ("a", "b")\n_X = dict.fromkeys(_T)\ndef f(k):\n    return _X.get(k)\n', []),
    "module-level walrus":
        ('_A = {"a", "b"}\n_B = {"b"}\n(_X := _A - _B)\ndef f(k):\n    return k in _X\n', []),
    "global bound in a function":
        ('_A = {"a", "b"}\n_B = {"b"}\n_X = None\ndef init():\n    global _X\n    _X = _A - _B\n'
         'def f(k):\n    return k in _X\n', []),
    "nonlocal":
        ('_A = {"a", "b"}\n_B = {"b"}\ndef f(k):\n    allowed = None\n    def fill():\n'
         '        nonlocal allowed\n        allowed = _A - _B\n    fill()\n    return k in allowed\n', []),
    "walrus in a nested default":
        ('_A = {"a", "b"}\n_B = {"b"}\ndef f(k):\n    def g(x=(allowed := _A - _B)):\n        return x\n'
         '    g()\n    return k in allowed\n', []),
    "set() over a module tuple in a function":
        ('_T = ("a", "b")\ndef f(k):\n    allowed = set(_T)\n    return k in allowed\n', []),
    "MappingProxyType at module level":
        ('import types\n_M = types.MappingProxyType({"a": 1})\ndef f(k):\n    return _M.get(k)\n', []),
    "starred unpacking at module level":
        ('_S, *_R = {"a"}, {"b"}, {"c"}\ndef f(k):\n    return k in _S\n', []),
    "for target at module level":
        ('for _S in ({"a"},):\n    pass\ndef f(k):\n    return k in _S\n', []),
    # 2a: the values of a constant dict hashed through a chain over a copy
    "set comprehension over a copy of the values": _ueber_die_werte("{x for x in list(_M.values())}"),
    "generator over a copy into set()": _ueber_die_werte("set(x for x in list(_M.values()))"),
    "starred copy in a set display": _ueber_die_werte("{*list(_M.values())}"),
    "reversed between the copy and set()": _ueber_die_werte("set(reversed(list(_M.values())))"),
    "dict comprehension over sorted values": _ueber_die_werte("{x: 1 for x in sorted(_M.values())}"),
    "list comprehension over a copy into set()": _ueber_die_werte("set([x for x in list(_M.values())])"),
    "filter between the copy and frozenset()":
        _ueber_die_werte("frozenset(filter(None, list(_M.values())))"),
    # the lens on 8ecb6edf: the value of a walrus used as an operand, unseen by all three detectors
    "walrus as the container of a membership test":
        ('_A = {"a", "b"}\ndef f(k):\n    return k in (s := _A)\n', []),
    "walrus over a set operation as the container":
        ('_A = {"a", "b"}\n_B = {"b"}\ndef f(k):\n    return k in (s := _A - _B)\n', []),
    "walrus over a set() copy as the container":
        ('_A = {"a"}\ndef f(k):\n    return k in (s := set(_A))\n', []),
    "walrus as the object of .get":
        ('_M = {"a": 1}\ndef f(k):\n    return (m := _M).get(k)\n', []),
    "walrus as the object of a subscript":
        ('_M = {"a": 1}\ndef f(k):\n    return (m := _M)[k]\n', []),
    "walrus as the object of .setdefault":
        ('_M = {"a": 1}\ndef f(k):\n    (m := _M).setdefault(k, 1)\n', []),
    "walrus in a comprehension condition":
        ('_A = {"a"}\ndef f(k):\n    return [x for x in [k] if x in (s := _A)]\n', []),
    "walrus over a module-level name as the container":
        ('_A = {"a"}\n_X = None\ndef f(k):\n    return k in (_X := _A)\n', []),
    "walrus between a copy of the values and set()": _ueber_die_werte("set((w := list(_M.values())))"),
    # the lens on d5747000: a walrus over a conditional, unseen by all three detectors; the last four
    # are siblings of the same class, found while closing it and unseen there too
    "walrus over a conditional as the container of a membership test":
        ('_A = {"a"}\n_B = {"b"}\ndef f(k, c=True):\n    return k in (s := _A if c else _B)\n', []),
    "walrus over a conditional as the object of .get":
        ('_M = {"a": 1}\n_N = {"b": 2}\ndef f(k, c=True):\n    return (m := _M if c else _N).get(k)\n', []),
    "walrus over a conditional as the object of a subscript":
        ('_M = {"a": 1}\n_N = {"b": 2}\ndef f(k, c=True):\n    return (m := _M if c else _N)[k]\n', []),
    "module-level name bound to a walrus over a conditional":
        ('_A = {"a"}\n_B = {"b"}\nC = True\n_S = (_T := _A if C else _B)\ndef f(k):\n    return k in _S\n', []),
    "local name bound to a walrus over a conditional":
        ('_A = {"a"}\n_B = {"b"}\ndef f(k, c=True):\n    s = (t := _A if c else _B)\n    return k in s\n', []),
    "chained walrus over a conditional":
        ('_A = {"a"}\n_B = {"b"}\ndef f(k, c=True):\n    return k in (s := (t := _A if c else _B))\n', []),
    "walrus over a conditional handed to a function":
        ('_M = {"a": 1}\n_N = {"b": 2}\ndef _get(m, k):\n    return m.get(k)\n'
         'def f(k, c=True):\n    return _get((m := _M if c else _N), k)\n', []),
    "set() over a walrus over a conditional":
        ('_A = {"a"}\n_B = {"b"}\ndef f(k, c=True):\n    return k in set((s := _A if c else _B))\n', []),
    "conditional between a copy of the values and set()":
        _ueber_die_werte("set(list(_M.values()) if v else [])"),
    "walrus over a conditional with a branch from outside in a set operation":
        ('_A = {"a"}\ndef f(k, c=True, x=frozenset()):\n    return k in ((s := _A if c else x) | {"a"})\n', []),
    # the lens on d6d89763: a hashing copy over a walrus over a conditional with a branch from outside,
    # unseen by all three detectors
    "set() over a walrus over a conditional with a branch from outside":
        ('_A = {"a"}\ndef f(k, c=True, x=frozenset()):\n    return k in set((s := _A if c else x))\n', []),
    "frozenset() over a walrus over a conditional with a branch from outside":
        ('_A = {"a"}\ndef f(k, c=True, x=frozenset()):\n    return k in frozenset((s := _A if c else x))\n',
         []),
    "dict.fromkeys over a walrus over a conditional with a branch from outside":
        ('_A = {"a"}\ndef f(k, c=True, x=frozenset()):\n    return dict.fromkeys((s := _A if c else x)).get(k)\n',
         []),
    # controls, seen before this change
    "control: unpacking two containers":
        ('_S, _M = {"a"}, {"a": 1}\ndef f(k):\n    return _M.get(k)\n', []),
    "control: set() over a copy of the values": _ueber_die_werte("set(list(_M.values()))"),
}


class TestEveryBindingAndEveryCopyIsFollowedOrReported(unittest.TestCase):
    """The lens on c3bd89a4 executed seventeen forms past the guard, each raising at run time with all
    three detectors silent. Two classes behind them:

    * `_hashed_downstream` followed a copy of a dict's values only up to a DIRECT hashing call, and
      `_Sicht._source` took `list(_M.values())` as a constant source although the values of a dict can
      be set from outside at run time;
    * `other_uses.bound()` counted a binding as followed by the SHAPE of its statement, while nothing
      read the name it bound: a module-level walrus, a `global` or `nonlocal` name, a starred
      unpacking, a `for` target, a walrus in a nested default; and the readers did not know
      `dict.fromkeys`, `MappingProxyType` or a `set()` over a module-level tuple.

    Every test here fails against the guard of c3bd89a4, but the stated limit at the end, which is
    green on purpose. The lens on 8ecb6edf added nine more forms, each a walrus whose value is itself
    an operand; they fail `test_every_planted_form_that_raises_is_reported` against the guard of
    8ecb6edf, and `test_a_walrus_passes_its_value_to_the_expression_around_it` fails there too. The
    lens on d5747000 wrote a walrus over a conditional in six forms, and closing it found four
    siblings; all ten fail `test_every_planted_form_that_raises_is_reported` against the guard of
    d5747000, and so does `test_a_conditional_passes_a_branch_to_the_expression_around_it`. The lens
    on d6d89763 wrote three more, a `set()`, `frozenset()` or `dict.fromkeys()` copy over a walrus over
    a conditional with one branch from outside; all three fail
    `test_every_planted_form_that_raises_is_reported` against the guard of d6d89763, and so does
    `test_a_hashing_copy_over_a_value_built_at_run_time_is_reported`. (A set comprehension over such a
    walrus is no fourth form: Python refuses a walrus in a comprehension's iterable at compile time.)"""

    @staticmethod
    def _funde(quelle: str) -> list:
        return (unguarded_membership_sites(quelle) + constant_lookups(quelle) + other_uses(quelle))

    @staticmethod
    def _raises(quelle: str, argument: object) -> bool:
        ns: dict = {}
        exec(compile(quelle, "<planted>", "exec"), ns)          # noqa: S102 - a planted test module
        if "init" in ns:
            ns["init"]()
        try:
            ns["f"](argument)
        except TypeError:
            return True
        return False

    def test_every_planted_form_that_raises_is_reported(self):
        """The runtime is the oracle: each form raises, so at least one detector must report it."""
        for name, (quelle, argument) in _PLANTED_FORMS.items():
            with self.subTest(form=name):
                self.assertTrue(self._raises(quelle, argument),
                                "the plant does not raise; it proves nothing")
                self.assertTrue(self._funde(quelle), "raises at run time, and the guard sees nothing")

    def test_a_construction_that_hashes_copied_values_is_an_other_use(self):
        """2a, by line: each chain over a copy of `.values()` that ends in a hashing construction is
        reported where the dict is read. A chain that ends anywhere else hands the values on and is
        not (anti-parity); where they go from there is the stated limit."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            def f(v):
                _M["a"] = v
                a = {x for x in list(_M.values())}
                b = set(x for x in list(_M.values()))
                c = {*list(_M.values())}
                d = set(reversed(list(_M.values())))
                e = {x: 1 for x in sorted(_M.values())}
                g = set([x for x in list(_M.values())])
                h = frozenset(filter(None, list(_M.values())))
                i = set(map(str, tuple(_M.items())))
                j = dict(zip(sorted(_M.values()), "ab"))
                ok1 = sorted(reversed(list(_M.values())))
                ok2 = [x for x in list(_M.values())]
                ok3 = len(list(_M.values()))
                ok4 = [*list(_M.values())]
                for ok5 in list(_M.values()):
                    pass
                return None
        ''')
        zeilen = quelle.splitlines()
        self.assertEqual([zeilen[z - 1].strip() for z, c, u in sorted(other_uses(quelle))],
                         ["a = {x for x in list(_M.values())}",
                          "b = set(x for x in list(_M.values()))",
                          "c = {*list(_M.values())}", "d = set(reversed(list(_M.values())))",
                          "e = {x: 1 for x in sorted(_M.values())}",
                          "g = set([x for x in list(_M.values())])",
                          "h = frozenset(filter(None, list(_M.values())))",
                          "i = set(map(str, tuple(_M.items())))",
                          "j = dict(zip(sorted(_M.values()), \"ab\"))"])

    def test_a_copy_of_the_values_is_no_constant_source(self):
        """2a, the second half: a container built from `.values()` or `.items()` is not constant, so
        it is no derived container. Its construction is the reported site (an other use of `_M`), and
        a membership test or a lookup in it is not read as one in a constant container."""
        quelle = textwrap.dedent('''
            _M = {"a": 1}
            def f(k):
                s = set(_M.values())
                d = dict(_M.items())
                return k in s, d.get(k), k in set(list(_M.values())), k in set(_M.keys())
        ''')
        self.assertEqual([(links, c) for _z, links, c in unguarded_membership_sites(quelle)],
                         [("k", "set(_M.keys())")])
        self.assertEqual(constant_lookups(quelle), [])
        self.assertEqual(sorted(u for _z, c, u in other_uses(quelle)),
                         [".items()", ".values()", ".values()"])

    def test_every_binding_a_reader_follows_makes_a_container(self):
        """2b, the forms added to the readers: each binds a name the three detectors then read."""
        for name in ("module-level dict.fromkeys over a container",
                     "module-level dict.fromkeys over a tuple",
                     "module-level walrus", "walrus in a nested default",
                     "set() over a module tuple in a function", "MappingProxyType at module level",
                     "starred unpacking at module level", "for target at module level"):
            quelle = _PLANTED_FORMS[name][0]
            with self.subTest(form=name):
                self.assertTrue(unguarded_membership_sites(quelle) + constant_lookups(quelle),
                                "the name is not read as a container")
                # The walrus in `def g(x=(allowed := _A - _B))` passes its value to the default of
                # `x` as well, and no reader follows a parameter: since the lens on 8ecb6edf that use
                # is judged where it stands, and it is reported. The binding itself is followed.
                erwartet = ([(4, "_A - _B", "arguments")] if name == "walrus in a nested default"
                            else [])
                self.assertEqual(other_uses(quelle), erwartet)
        self.assertEqual(_hashing_containers(ast.parse(textwrap.dedent('''
            import types
            _A = {"a"}
            _F = dict.fromkeys(_A)
            _P = types.MappingProxyType({"p": 1})
            (_W := _A | {"w"})
            _S, *_R, _E = {"s"}, (), (), {"e"}
            for _L in ({"l"}, {"m"}):
                pass
        '''))), {"_A": "set", "_F": "dict", "_P": "dict", "_W": "set", "_S": "set", "_E": "set",
                  "_L": "set"})

    def test_a_binding_no_reader_follows_is_an_other_use(self):
        """2b, deny by default: a container bound where no reader follows the name is reported as
        the read it is. A `global` or `nonlocal` name is used in a scope the binding's reader does
        not read; `a.b` is no name; a class body binds attributes; a starred target gets a list."""
        quelle = textwrap.dedent('''
            _A = {"a"}
            _B = {"b"}
            _C = {"c"}
            _S, *_R = _A, _B, _C
            _X = None
            def init():
                global _X
                _X = _A - _B
            def f(k, obj):
                allowed = None
                def fill():
                    nonlocal allowed
                    allowed = _A | _B
                fill()
                y = obj.attr = _A & _B
                return k in allowed
            class K:
                Z = _A ^ _B
        ''')
        self.assertEqual(sorted((c, u) for _z, c, u in other_uses(quelle)),
                         [("_A & _B", "Assign"), ("_A - _B", "Assign"), ("_A ^ _B", "Assign"),
                          ("_A | _B", "Assign"), ("_B", "Tuple"), ("_C", "Tuple")])
        # the inner function's own use of the nonlocal name is still read as a container's
        self.assertEqual(unguarded_membership_sites(textwrap.dedent('''
            _A = {"a"}
            def f(k):
                allowed = None
                def fill():
                    nonlocal allowed
                    allowed = _A
                    return k in allowed
                return fill()
        ''')), [(8, "k", "allowed")])

    def test_a_walrus_passes_its_value_to_the_expression_around_it(self):
        """The lens on 8ecb6edf: `_Sicht.gebunden` marked the value of every followed walrus as bound,
        so a walrus used as an operand was judged by its binding alone, and the readers looked at the
        walrus instead of its value. Each hashing use is now reported by the detector that owns the
        form. A walrus standing as a statement, iterated, tested as a condition or handed to
        `is_member` hashes nothing from outside and is not reported (anti-parity); handed to a function
        it is an other use, as the bare container would be."""
        quelle = textwrap.dedent('''
            _A = {"a", "b"}
            _B = {"b"}
            _M = {"a": 1}
            def f(k, foo):
                r1 = k in (s := _A)
                r2 = k in (t := _A - _B)
                r3 = (m := _M).get(k)
                r4 = (n := _M)[k]
                (o := _M).setdefault(k, 1)
                r5 = [x for x in [k] if x in (u := _A)]
                foo((v := _A))
                (w := _A)
                for x in (y := _A):
                    pass
                if (z := _A):
                    pass
                return is_member(k, (q := _A)), r1, r2, r3, r4, r5
        ''')
        zeilen = quelle.splitlines()

        def wo(funde) -> list[str]:
            return [zeilen[z - 1].strip() for z, _c, _w in sorted(funde)]

        self.assertEqual(wo(unguarded_membership_sites(quelle)),
                         ["r1 = k in (s := _A)", "r2 = k in (t := _A - _B)",
                          "r5 = [x for x in [k] if x in (u := _A)]"])
        self.assertEqual(wo(constant_lookups(quelle)),
                         ["r3 = (m := _M).get(k)", "r4 = (n := _M)[k]", "(o := _M).setdefault(k, 1)"])
        self.assertEqual([(c, u) for _z, c, u in other_uses(quelle)], [("_A", "foo(argument 1)")])
        for label, access in (("in", lambda k: k in (s := {"a"})), ("get", lambda k: (m := {"a": 1}).get(k)),
                              ("subscript", lambda k: (m := {"a": 1})[k])):
            with self.subTest(form=label), self.assertRaises(TypeError):
                access([])

    def test_a_conditional_passes_a_branch_to_the_expression_around_it(self):
        """The lens on d5747000: `_bindings` split a conditional only where it stood directly as the
        value, so under a walrus both branches counted as bound while every reader looked through the
        walrus at a conditional and saw no container. Each hashing use is now reported by the detector
        that owns the form, a branch is judged where its conditional goes, and a conditional that is
        iterated, bound or tested as a condition is not reported (anti-parity)."""
        quelle = textwrap.dedent('''
            _A = {"a", "b"}
            _B = {"b"}
            _M = {"a": 1}
            _N = {"b": 2}
            C = True
            _S = (_T := _A if C else _B)
            def f(k, c, foo):
                r1 = k in (s := _A if c else _B)
                r2 = (m := _M if c else _N).get(k)
                r3 = (n := _M if c else _N)[k]
                w = (t := _A if c else _B)
                r4 = k in w
                r5 = k in (u := (v := _A if c else _B))
                r6 = k in _S
                foo((x := _M if c else _N))
                for y in (z := _A if c else _B):
                    pass
                if (q := _A if c else _B):
                    pass
                return r1, r2, r3, r4, r5, r6
        ''')
        zeilen = quelle.splitlines()

        def wo(funde) -> list[str]:
            return [zeilen[z - 1].strip() for z, _c, _w in sorted(funde)]

        self.assertEqual(wo(unguarded_membership_sites(quelle)),
                         ["r1 = k in (s := _A if c else _B)", "r4 = k in w",
                          "r5 = k in (u := (v := _A if c else _B))", "r6 = k in _S"])
        self.assertEqual(wo(constant_lookups(quelle)),
                         ["r2 = (m := _M if c else _N).get(k)", "r3 = (n := _M if c else _N)[k]"])
        self.assertEqual(sorted((c, u) for _z, c, u in other_uses(quelle)),
                         [("_M", "foo(argument 1)"), ("_N", "foo(argument 1)")])
        for label, access in (("in", lambda k: k in (s := {"a"} if k else {"b"})),
                              ("get", lambda k: (m := {"a": 1} if k else {"b": 2}).get(k))):
            with self.subTest(form=label), self.assertRaises(TypeError):
                access([[1]])

    def test_a_hashing_copy_over_a_value_built_at_run_time_is_reported(self):
        """The lens on d6d89763: a walrus over a conditional with one branch from outside, copied by
        `set()`, `frozenset()` or `dict.fromkeys()`, hid the constant branch from all three detectors,
        because the walrus made it bound and the copy was then read as iteration. Each copy is now
        reported where the constant is read. A conditional whose branches are all
        constant is a source, so its copy is a derived container the membership reader reads; a
        conditional that is only iterated, measured or sorted hashes nothing (anti-parity)."""
        quelle = textwrap.dedent('''
            _A = {"a", "b"}
            _B = {"b"}
            def f(k, c, x):
                r1 = k in set((s := _A if c else x))
                r2 = k in frozenset((t := _A if c else x))
                r3 = dict.fromkeys((u := _A if c else x)).get(k)
                r4 = k in set((w := _A if c else _B))
                n = len((a := _A if c else x))
                o = sorted((b := _A if c else x))
                for y in (d := _A if c else x):
                    pass
                return r1, r2, r3, r4, n, o
        ''')
        zeilen = quelle.splitlines()

        def wo(funde) -> list[str]:
            return [zeilen[z - 1].strip() for z, _c, _w in sorted(funde)]

        self.assertEqual(wo(other_uses(quelle)),
                         ["r1 = k in set((s := _A if c else x))",
                          "r2 = k in frozenset((t := _A if c else x))",
                          "r3 = dict.fromkeys((u := _A if c else x)).get(k)"])
        self.assertEqual(wo(unguarded_membership_sites(quelle)), ["r4 = k in set((w := _A if c else _B))"])
        self.assertEqual(wo(constant_lookups(quelle)), [])
        for label, access in (("set", lambda k: k in set((s := {"a"} if k else ()))),
                              ("fromkeys", lambda k: dict.fromkeys((s := {"a"} if k else ())).get(k))):
            with self.subTest(form=label), self.assertRaises(TypeError):
                access([[1]])

    def test_UNTERGRENZE_values_bound_to_a_name_leave_the_guard(self):
        """THE STATED LIMIT, green on purpose although the case is real: a copy of the values bound
        to a name and hashed through that name is not followed (`vals = list(_M.values());
        set(vals)`), as a value after it leaves the container never was. Whoever turns this red has
        taught the guard to follow a copy through a name and rewrites this contract; deleting it
        loses the limit."""
        quelle = ('_M = {"a": 1}\ndef f(v):\n    _M["a"] = v\n    vals = list(_M.values())\n'
                  '    return set(vals)\n')
        self.assertTrue(self._raises(quelle, [[1]]))
        self.assertEqual(self._funde(quelle), [])


# ── the fourth form: a container of numbers meets a value of another JSON type ───────────────────────
#
# THE CLASS, stated as the violated assumption: *a value that equals an element of a container of
# numbers is a number of that kind.* It need not be. `True == 1`, `1.0 == 1` and `hash(True) ==
# hash(1)`, so a membership test in a tuple, list, set or frozenset of numbers, a lookup in a dict keyed
# by numbers, and `is_member` against either classify a JSON `true` or `2.0` as a known element.
# Nothing hashes badly here, which is why the three readers above are silent: a tuple does not hash at
# all. A lens on e5b39b81 measured it in `statuslist`: under `bits not in (1, 2, 4, 8)` a signed Status
# List Token with `"bits": true` verified ok as a 1-bit list, `2.0` passed and then raised a raw
# TypeError at the bit array, and the emitter signed `"bits": true`. The sweep that closed it found the
# inline form of the same test in `anchors_chia.merkle_root_from_layers`, `side not in (0, 1)`, where
# `true`, `false`, `1.0` and `0.0` were accepted as the sides of a DataLayer proof.
#
# THE RULE: such a test reads through `_membership.is_int_member`, which refuses a bool and every value
# that is no int before it compares (the house rule `isinstance(x, bool) or not isinstance(x, int)`),
# or it stands in `_NUMBER_SITES_CLASSIFIED` with the reason its value is an int the package made.
#
# A CONTAINER OF NUMBERS is a tuple, list or set display, or a dict display by its keys, whose elements
# are all numbers written as literals (an int, a float, a complex or a bool, also with a sign); a
# `set()`, `frozenset()`, `tuple()`, `list()`, `dict()` or `dict.fromkeys()` over one and its `.keys()`;
# `range(...)`, whose `in` compares by `==` too (`True in range(2)`); a name bound to one at module
# level (also imported from another module of the package, resolved as the hashing containers are) or
# in the function that reads it or one around it; a set operation over two of them; and a walrus or a
# conditional of which any value it passes on is one. NOT READ, and stated rather than left to be
# found: a display with a name in it (`(_A, _B)` over two int constants; the tree has none in a test), a
# comprehension, a container a function returns, a comparison with one number (`x == 1`, `0 <= x < 4`),
# iteration (`any(x == b for b in C)`), and a container handed to a function. A name bound to a number
# container in one scope counts in every function inside it, whatever else binds that name there; that
# reads more, never less.

def _number_literal(e: ast.AST) -> bool:
    """A number written as a literal: an int, a float, a complex or a bool, also with a sign."""
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, (ast.USub, ast.UAdd)):
        e = e.operand
    return isinstance(e, ast.Constant) and isinstance(e.value, (int, float, complex))


_NUMBER_COPIES = {"set", "frozenset", "tuple", "list", "dict"}


def _number_value(e: ast.AST, bekannt: set[str]) -> bool:
    """Is `e` a container of numbers, where `bekannt` holds the names that are one? A walrus or a
    conditional is one when any value it passes on is one, because the test compares with that value
    whenever it is passed."""
    zweige = _passed_values(e)
    if len(zweige) > 1:
        return any(_number_value(z, bekannt) for z in zweige)
    e = zweige[0]
    if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
        return bool(e.elts) and all(_number_literal(x) for x in e.elts)
    if isinstance(e, ast.Dict):
        return bool(e.keys) and all(k is not None and _number_literal(k) for k in e.keys)
    if isinstance(e, ast.Name):
        return e.id in bekannt
    if isinstance(e, ast.BinOp) and isinstance(e.op, _SET_OPERATORS):
        return _number_value(e.left, bekannt) and _number_value(e.right, bekannt)
    if isinstance(e, ast.Call) and not e.keywords:
        f = e.func
        if isinstance(f, ast.Attribute) and f.attr == "keys" and not e.args:
            return _number_value(f.value, bekannt)
        if isinstance(f, ast.Name) and f.id == "range" and e.args:
            return True
        if ((isinstance(f, ast.Name) and f.id in _NUMBER_COPIES and len(e.args) == 1)
                or (_ist_fromkeys(f) and e.args)):
            return _number_value(e.args[0], bekannt)
    return False


def _module_numbers(tree: ast.Module, importiert: frozenset[str] = frozenset()) -> set[str]:
    """Module-level names bound to a container of numbers (`_scope_bindings` at module level: also by
    unpacking, a walrus, a `for` over a display, inside a module-level block), to a fixpoint over names
    and set operations. `importiert` names the ones the module imports."""
    bindungen = [(name, wert) for name, wert, _gefolgt in _scope_bindings(tree, True)]
    gefunden: set[str] = set()
    neu = True
    while neu:
        neu = False
        for name, wert in bindungen:
            if name not in gefunden and _number_value(wert, gefunden | importiert):
                gefunden.add(name)
                neu = True
    return gefunden


def numbers_by_module(quellen: dict[str, str | tuple[str, bool]]) -> dict[str, dict[str, str]]:
    """module -> {name: "numbers"} for every container of numbers a module of the package binds at
    module level or imports by name (`from .x import NAME`, `*`, and chains of them), to a fixpoint,
    as `containers_by_module` resolves the hashing containers."""
    baeume: dict[str, tuple[ast.Module, bool]] = {}
    for modul, wert in quellen.items():
        text, ist_init = (wert, False) if isinstance(wert, str) else wert
        baeume[modul] = (ast.parse(text), ist_init)
    sicht = {modul: dict.fromkeys(sorted(_module_numbers(baum)), "numbers")
             for modul, (baum, _i) in baeume.items()}
    for _runde in range(len(baeume) + 1):
        geaendert = False
        for modul, (baum, ist_init) in baeume.items():
            importiert = imported_containers(baum, modul, ist_init, sicht)
            eigene = _module_numbers(baum, frozenset(importiert))
            neu = {**importiert, **dict.fromkeys(sorted(eigene), "numbers")}
            if neu != sicht[modul]:
                sicht[modul], geaendert = neu, True
        if not geaendert:
            return sicht
    raise RuntimeError("the imported number containers reach no fixpoint")


class _Zahlensicht:
    """The names that are containers of numbers at a node: the module's, and those bound to one in the
    function around the node or in any function around that one."""

    def __init__(self, tree: ast.Module, modulweit: set[str]):
        self.modulweit = set(modulweit)
        self.parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        self.lokal: dict[ast.AST, set[str]] = {}
        # ast.walk goes breadth first, so a function is read before the ones nested in it
        for fn in ast.walk(tree):
            if not isinstance(fn, _SCOPES):
                continue
            aussen = self.sichtbar(fn)
            paare = [(n, w) for n, w, _g in _scope_bindings(fn, False)]
            eigene: set[str] = set()
            neu = True
            while neu:
                neu = False
                for n, w in paare:
                    if n not in eigene and _number_value(w, aussen | eigene):
                        eigene.add(n)
                        neu = True
            self.lokal[fn] = eigene

    def sichtbar(self, knoten: ast.AST) -> set[str]:
        namen = set(self.modulweit)
        k = self.parents.get(knoten)
        while k is not None:
            namen |= self.lokal.get(k, set())
            k = self.parents.get(k)
        return namen


#: Methods that compare their first argument with the elements (or keys) of the container they are
#: called on, and the `operator` functions that do the same with their second.
_NUMBER_METHODS = {"get", "setdefault", "pop", "index", "count", "__contains__", "__getitem__"}
_NUMBER_OPERATOR = {"contains", "getitem", "indexOf", "countOf"}


def number_container_sites(quelle: str, name: str = "<quelle>", modul: str | None = None,
                           ist_init: bool = False,
                           je_modul: dict[str, dict[str, str]] | None = None) -> list[tuple[int, str, str]]:
    """(line, container, value) for every place a value meets the elements of a container of numbers
    by equality: `x in C` and `x not in C` (also inside a chained comparison), `C.get(x)` and the other
    `_NUMBER_METHODS`, `C[x]` read, written or deleted (a tuple indexed by `True` reads element 1),
    `operator.contains(C, x)` and its siblings, and `is_member(x, C)`, which answers the hashing
    question only. A literal value is left out, the package chose it; `is_int_member(x, C)` is the
    guarded form and is no site. With `modul` the module-level containers come from `je_modul`
    (`numbers_by_module`), else from this source alone."""
    tree = ast.parse(quelle, filename=name)
    modulweit = (set(je_modul.get(modul, {})) if modul is not None and je_modul is not None
                 else _module_numbers(tree))
    sicht = _Zahlensicht(tree, modulweit)
    operator_names = {"operator"} | {a.asname for n in ast.walk(tree) if isinstance(n, ast.Import)
                                     for a in n.names if a.name == "operator" and a.asname}
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        paare: list[tuple[ast.AST, ast.AST]] = []          # (container, value)
        if isinstance(node, ast.Compare):
            links = node.left
            for op, rechts in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    paare.append((rechts, links))
                links = rechts
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in _NUMBER_METHODS and node.args:
                paare.append((f.value, node.args[0]))
            if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in operator_names
                    and f.attr in _NUMBER_OPERATOR and len(node.args) >= 2):
                paare.append((node.args[0], node.args[1]))
            if isinstance(f, ast.Name) and f.id == "is_member" and len(node.args) == 2:
                paare.append((node.args[1], node.args[0]))
        elif isinstance(node, ast.Subscript) and not isinstance(node.slice, ast.Slice):
            paare.append((node.value, node.slice))
        for behaelter, wert in paare:
            if _number_literal(wert) or isinstance(wert, ast.Constant):
                continue
            if _number_value(behaelter, sicht.sichtbar(node)):
                found.append((node.lineno, ast.unparse(behaelter), ast.unparse(wert)))
    return found


#: Every site `number_container_sites` reports in src/proofbundle, and why its value is an int of the
#: package's own making. Keyed like `_LOOKUPS_CLASSIFIED`, with the number of sites per key. Measured on
#: the tree of this change: 3 sites under 3 keys. Before it, 8 sites: the two `bits` tests of
#: `statuslist`, `side not in (0, 1)` in `anchors_chia` and the two recovery-id tests of
#: `anchors_rootcommit.eip191_recover_address` read through `is_int_member` now, and the three below
#: stay. The same sweep over `scripts/` (which this test does not read) found three membership tests,
#: each on a subprocess return code, an int the runtime produces: `audit_candidate_matrix.py`,
#: `mutation_check.py` and `test_manifest_gate.py`.
_NUMBER_SITES_CLASSIFIED = {
    ("proofbundle/intoto.py", "to_test_result_statement", "_RESULT_ENUM", "verdikt"):
        (1, "own value: require_bool_verdict returns a bool or raises, and the dict is keyed by True "
         "and False"),
    ("proofbundle/sdjwt.py", "verify_sd_jwt", "(2, 3)", "len(parsed)"):
        (1, "own value: len() returns an int"),
    ("proofbundle/statuslist.py", "verify_status_snapshot", "STATUS_LABELS", "status"):
        (1, "own value: _status_at computes an int from the bytes of the bit array, with a width "
         "is_int_member admitted"),
}


class TestANumberContainerComparesTheType(unittest.TestCase):
    """The fourth form, `is_int_member`: a container of numbers classifies `true` and `2.0` as known
    elements unless the value's type is tested first (the lens on e5b39b81, M2 and M3)."""

    @staticmethod
    def _reported_lines(quelle: str, funde) -> list[str]:
        zeilen = quelle.splitlines()
        return [zeilen[z - 1].strip() for z, _c, _was in sorted(funde)]

    def test_the_tree_holds_exactly_the_classified_number_sites(self):
        neu, weg = _drift(_in_the_tree(number_container_sites, ansicht=numbers_by_module),
                          _NUMBER_SITES_CLASSIFIED)
        self.assertEqual(neu, [],
                         "a value meets a container of numbers by equality: read it through "
                         "_membership.is_int_member, or classify it in _NUMBER_SITES_CLASSIFIED with the "
                         "reason its value is an int the package made")
        self.assertEqual(weg, [],
                         "a classified number site is gone: remove it from _NUMBER_SITES_CLASSIFIED or "
                         "lower its count")

    def test_every_number_classification_says_why(self):
        for key, (count, reason) in _NUMBER_SITES_CLASSIFIED.items():
            with self.subTest(site=key):
                self.assertIsInstance(count, int)
                self.assertGreaterEqual(count, 1)
                self.assertRegex(reason, r"^(guarded|own value): \S")

    def test_the_statuslist_defect_is_found_where_it_stood(self):
        """PLANT AND MUST CATCH in a copy of the real tree: `bits not in _ALLOWED_BITS` put back in
        both functions of `statuslist`, and `side not in (0, 1)` in `anchors_chia`, are three new sites;
        the files as they are report none."""
        status = (SRC / "statuslist.py").read_text(encoding="utf-8")
        jetzt, damals = "if not is_int_member(bits, _ALLOWED_BITS):", "if bits not in _ALLOWED_BITS:"
        self.assertEqual(status.count(jetzt), 2, "the plant point moved: plant where bits is tested")
        chia = (SRC / "anchors_chia.py").read_text(encoding="utf-8")
        jetzt_c, damals_c = "if not is_int_member(side, (0, 1)):", "if side not in (0, 1):"
        self.assertEqual(chia.count(jetzt_c), 1, "the plant point moved: plant where the side is tested")
        gepflanzt = {"proofbundle/statuslist.py": status.replace(jetzt, damals),
                     "proofbundle/anchors_chia.py": chia.replace(jetzt_c, damals_c)}
        neu, weg = _drift(_in_the_tree(number_container_sites, gepflanzt, numbers_by_module),
                          _NUMBER_SITES_CLASSIFIED)
        self.assertEqual(neu, [
            f"{('proofbundle/anchors_chia.py', 'merkle_root_from_layers', '(0, 1)', 'side')}: "
            "1 in the tree, 0 classified",
            f"{('proofbundle/statuslist.py', 'issue_status_list_token', '_ALLOWED_BITS', 'bits')}: "
            "1 in the tree, 0 classified",
            f"{('proofbundle/statuslist.py', 'verify_status_snapshot', '_ALLOWED_BITS', 'bits')}: "
            "1 in the tree, 0 classified"])
        self.assertEqual(weg, [])
        # the runtime half: each is a membership the value of another JSON type passes
        for wert in (True, 1.0, 2.0, 8.0):
            with self.subTest(wert=wert):
                self.assertIn(wert, (1, 2, 4, 8))
        self.assertIn(False, (0, 1))

    def test_every_form_of_a_number_container_is_found(self):
        """Every container form and every access form of the rule above, on planted source; the guarded
        form, a literal value, a container of strings and a display with a name in it are not."""
        quelle = textwrap.dedent('''
            import operator
            import operator as op
            _BITS = (1, 2, 4, 8)
            _NEG = [-1, 0, +1]
            _SET = {1, 2}
            _FRO = frozenset({3, 4})
            _MAP = {0: "a", 1: "b"}
            _BOOL = {True: "P", False: "F"}
            _FLT = (0.5, 1.0)
            _ALIAS = _BITS
            _UNION = _SET | _FRO
            _KEYS = dict.fromkeys((1, 2))
            _STR = ("1", "2")
            _MIX = (1, "a")
            A = 1
            _NAMED = (A, 2)
            def f(p, k, c):
                lokal = (5, 6)
                r = [p.get("a") in _BITS, k not in _NEG, k in _SET, k in _FRO, k in _MAP, _MAP.get(k),
                     _BOOL[k], k in _FLT, k in _ALIAS, k in _UNION, k in _KEYS, k in lokal,
                     k in (7, 8), k in {9}, k in range(3), k in (s := _BITS), k in (_BITS if c else _STR),
                     _BITS.index(k), _BITS.count(k), _BITS[k], operator.contains(_SET, k),
                     op.getitem(_MAP, k), is_member(k, _SET), k in _MAP.keys(), 0 < k in _BITS]
                _MAP[k] = "c"
                def inner(q):
                    return q in lokal
                known = [is_int_member(k, _BITS), 1 in _BITS, _MAP.get(0), k in _STR, k in _MIX,
                         k in _NAMED, _BITS[0], _BITS[1:], -1 in _NEG]
                return r, known, inner
        ''')
        self.assertEqual(sorted((c, v) for _z, c, v in number_container_sites(quelle)), sorted([
            ("_BITS", "p.get('a')"), ("_NEG", "k"), ("_SET", "k"), ("_FRO", "k"), ("_MAP", "k"),
            ("_MAP", "k"), ("_BOOL", "k"), ("_FLT", "k"), ("_ALIAS", "k"), ("_UNION", "k"),
            ("_KEYS", "k"), ("lokal", "k"), ("(7, 8)", "k"), ("{9}", "k"), ("range(3)", "k"),
            ("(s := _BITS)", "k"), ("_BITS if c else _STR", "k"), ("_BITS", "k"), ("_BITS", "k"),
            ("_BITS", "k"), ("_SET", "k"), ("_MAP", "k"), ("_SET", "k"), ("_MAP.keys()", "k"),
            ("_BITS", "k"), ("_MAP", "k"), ("lokal", "q")]))
        # the runtime half: every one of these forms lets a value of another JSON type through
        for label, zugriff in (("tuple", lambda k: k in (1, 2, 4, 8)), ("set", lambda k: k in {1, 2}),
                               ("dict", lambda k: {0: "a", 1: "b"}.get(k) is not None),
                               ("range", lambda k: k in range(3)),
                               ("is_member", lambda k: self._is_member()(k, {1, 2}))):
            for wert in (True, 1.0):
                with self.subTest(form=label, wert=wert):
                    self.assertTrue(zugriff(wert))

    @staticmethod
    def _is_member():
        import sys  # noqa: PLC0415
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        from proofbundle._membership import is_member  # noqa: PLC0415
        return is_member

    def test_an_imported_number_container_is_seen(self):
        """A container of numbers defined in one module and tested in another, by name, through a chain
        and through `*`, as the hashing containers are; a module-level container of strings is not."""
        paket = {
            "pkg.a": ('_BITS = (1, 2, 4, 8)\n_NAMES = ("x", "y")\n', False),
            "pkg.b": ("from .a import _BITS\n", False),
            "pkg.c": ("from .b import _BITS\ndef f(k):\n    return k in _BITS\n", False),
            "pkg.d": ("from .a import *\ndef g(k):\n    return k not in _BITS, k in _NAMES\n", False),
        }
        je_modul = numbers_by_module(paket)
        self.assertEqual(je_modul["pkg.a"], {"_BITS": "numbers"})
        for modul in ("pkg.c", "pkg.d"):
            with self.subTest(modul=modul):
                self.assertEqual([(c, v) for _z, c, v in number_container_sites(
                    paket[modul][0], modul, modul, False, je_modul)], [("_BITS", "k")])
        # anti-parity: without the package view the importing file shows nothing
        self.assertEqual(number_container_sites(paket["pkg.c"][0]), [])

    def test_is_int_member_admits_an_int_and_nothing_that_only_equals_one(self):
        import sys  # noqa: PLC0415
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        from proofbundle._membership import is_int_member  # noqa: PLC0415
        for wert in (1, 2, 4, 8):
            with self.subTest(wert=wert):
                self.assertTrue(is_int_member(wert, (1, 2, 4, 8)))
                self.assertTrue(is_int_member(wert, {1, 2, 4, 8}))
        for i, wert in enumerate((True, False, 1.0, 2.0, "1", b"\x01", None, [1], {"a": 1}, {1}, (1,), 3,
                                  10**5000)):
            with self.subTest(fall=i, typ=type(wert).__name__):
                self.assertFalse(is_int_member(wert, (1, 2, 4, 8)))
                self.assertFalse(is_int_member(wert, {0: "a", 1: "b", 2: "c", 4: "d", 8: "e"}))

        class _KaputtesInt(int):
            def __hash__(self):
                raise TypeError("a hash that fails")

        self.assertFalse(is_int_member(_KaputtesInt(1), {1, 2}))
        self.assertTrue(is_int_member(_KaputtesInt(1), (1, 2)))   # a tuple compares, it does not hash


#: Module-level hashing containers the static view does not read, found by importing every module of
#: the package and asking the objects, each with the reason it hashes no value from outside. The lens
#: on c3bd89a4 ran this oracle and found exactly this one; it stays outside the view on purpose, because
#: what a function returns is not a constant the source names, and its one use is held here instead.
_RUNTIME_ONLY_CONTAINERS = {
    ("proofbundle.policy", "_LOW_ORDER_ED25519_Y"):
        "bound to the frozenset `_low_order_ed25519_y()` returns; its one use, `y in "
        "_LOW_ORDER_ED25519_Y` in `_validate_pinned_ed25519_pubkey`, tests an int the function "
        "computes from the decoded key bytes (`int.from_bytes(raw, \"little\") & _ED25519_Y_MASK`)",
}

#: Modules that need an optional dependency at import, with that dependency. Such a module is named
#: when it cannot be imported, never skipped in silence; any other ImportError fails the test.
_OPTIONAL_AT_IMPORT = {"proofbundle.inspect_hook": "inspect_ai"}


def runtime_only_containers(objekte: dict, je_modul: dict[str, dict[str, str]]) -> set[tuple[str, str]]:
    """(module, name) for every module-level object that IS a set or a mapping at run time and is no
    container of the static view. `objekte` maps a module name to the imported module object."""
    import collections.abc as cabc  # noqa: PLC0415
    import types  # noqa: PLC0415
    fehlt: set[tuple[str, str]] = set()
    for modul, objekt in objekte.items():
        for name, wert in vars(objekt).items():
            if name.startswith("__") or isinstance(
                    wert, (types.ModuleType, type, types.FunctionType, types.BuiltinFunctionType)):
                continue
            if isinstance(wert, (cabc.Set, cabc.Mapping)) and name not in je_modul.get(modul, {}):
                fehlt.add((modul, name))
    return fehlt


class TestTheRuntimeSeesNoContainerTheGuardDoesNot(unittest.TestCase):
    """AN INDEPENDENT ORACLE for the view the three detectors share. The view is read from the AST, and
    every form it missed so far was found by someone who ran the code; this test runs it. Every
    module is imported and every module-level object that IS a set or a mapping must be a container
    of the view, or be listed in `_RUNTIME_ONLY_CONTAINERS` with its reason. A new container the view
    does not read turns this red, whatever its spelling."""

    def test_every_module_level_hashing_container_is_in_the_view_or_named(self):
        import importlib  # noqa: PLC0415
        import sys  # noqa: PLC0415
        import warnings  # noqa: PLC0415
        if str(REPO / "src") not in sys.path:
            sys.path.insert(0, str(REPO / "src"))
        quellen = _package_sources()
        objekte, nicht_importiert = {}, {}
        for modul in sorted(quellen):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    objekte[modul] = importlib.import_module(modul)
            except ImportError as exc:
                nicht_importiert[modul] = exc.name
        self.assertEqual(runtime_only_containers(objekte, containers_by_module(quellen)),
                         set(_RUNTIME_ONLY_CONTAINERS),
                         "a module-level set or mapping the guard's view does not read: add the form "
                         "to the view, or name it with its reason in _RUNTIME_ONLY_CONTAINERS")
        for modul, abhaengigkeit in nicht_importiert.items():
            with self.subTest(modul=modul):
                self.assertEqual(_OPTIONAL_AT_IMPORT.get(modul), abhaengigkeit,
                                 "a module that cannot be imported here is not measured")

    def test_the_oracle_catches_a_planted_container_the_view_does_not_read(self):
        """PLANT AND MUST CATCH, both directions: a dict built by a method call is a mapping at run time
        and no container of the view, so the oracle names it; the same dict as a literal is in the view,
        so it does not."""
        import types  # noqa: PLC0415
        quelle = '_P = {"a": 1}.copy()\n_Q = {"a": 1}\n'
        modul = types.ModuleType("pkg.m")
        exec(compile(quelle, "<planted>", "exec"), modul.__dict__)          # noqa: S102 - a planted module
        self.assertEqual(runtime_only_containers({"pkg.m": modul}, containers_by_module({"pkg.m": quelle})),
                         {("pkg.m", "_P")})


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
