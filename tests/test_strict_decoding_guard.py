"""The guard of the strict decoding class: no new lax JSON or CBOR decode site without a named reason.

The strict decoding rule of this repository, stated here (since 2026-10-14): every reader of checked, signed or
evidential bytes refuses duplicate keys, invalid encoding and bytes after the value, and a contract test finds a new
decode site that bypasses the strict helpers.

WHAT IT READS. The Python source under ``src/``, ``plugins/``, ``tools/`` and ``docs/scitt/``, parsed with ``ast``.

A DECODE REFERENCE, BY A POSITIVE LIST. ``NOT_DECODING`` names the members of ``json`` and ``cbor2`` that do not
decode (the encoders, the tag and simple-value types, the error classes). Every other reference to either library
is a decode reference: ``json.loads`` and ``cbor2.loads`` called or not (``loads = json.loads`` counts where the name
is taken), ``json.JSONDecoder``, ``cbor2.decoder.loads``, a name imported from a decoding member or submodule
(``from cbor2 import decoder``, ``from cbor2.decoder import loads``), ``from json import *``, the module object itself
handed on (``getattr(json, "loads")``), and ``importlib.import_module`` or ``__import__`` of either library. A first
version listed the five lax calls it knew and missed each of these forms, as an adversarial review measured. A call
is strict, and not counted, only when its ``object_pairs_hook=`` names a function of ``STRICT_HOOKS`` that the same
module defines and does not rebind; a name alone, a lambda or an imported hook is counted.

WHAT IT REQUIRES. Every other reference is in ``EXCEPTIONS`` with the exact number per file and a reason outside a
verify path. A new reference turns this red, and so does one that went away, so the list never outlives what it
describes. Each function defined under a name in ``STRICT_HOOKS`` is run on duplicate member names, adjacent and not,
and must refuse each, and an ``assert`` in its body does not count, because ``python -O`` removes it.

THE CBOR2 6 CLASS. Under a tag, at any depth, cbor2 6 returns an array as a tuple and a map as a frozendict, where
cbor2 5 returned a list and a dict (measured with 5.9.0 and 6.1.4; without a tag both return list and dict). A
reader that tests for ``list`` or ``dict`` behind cbor2 is therefore right under one version only. In every module
that imports cbor2, by any form of import, the names ``list``, ``dict``, ``List``, ``Dict``, ``MutableSequence`` and
``MutableMapping`` (also through an alias of an import) may stand only in a call or as its argument (``list(x)``,
``defaultdict(list)``), in an annotation, or in the type argument of ``isinstance``/``issubclass`` together with
``tuple`` or ``Sequence`` (for the sequences) and ``Mapping``, ``frozendict`` or ``FrozenDict`` (for the maps). Every
other place is a finding: ``type(v) is list``, ``isinstance(v, list | None)``, ``case list():``, ``LISTS = (list,)``.

HONEST LIMITS. It reads Python only; the Rust and Go readers are measured by their own runs. It does not see a
hand-written decoder such as ``cbor_min``; those are held by the shared corpus in ``test_strict_cbor``. Code that
reaches a decoder through an object handed in from elsewhere, without importing either library, is not seen, and
neither is a decoder of another library (``orjson``, ``pycose``). A container test by type name (``type(v).__name__``)
or through ``type([])`` is not seen. A hook that refuses on these probes but not on others passes.

OUTSIDE THE SCOPE, and therefore not held here: ``scripts/`` (release and office tooling), ``conformance/``,
``interop/``, ``examples/``, ``fuzz/`` and ``benchmarks/``. Among them are readers of signed bytes:
``scripts/verify_pre_tag_receipt.py`` reads the committed pre-tag receipt with ``json.loads`` before it verifies the
signature, and ``conformance/run_conformance.py`` and ``examples/verdict_contract/check_example.py`` read signed
envelopes the same way. Measured with this file's functions on 2026-10-15: 50 references in 27 files under
``scripts/``, 38 in 6 under ``conformance/``, 8 in 3 under ``interop/``, 7 in 4 under ``examples/``, 1 under ``fuzz/``
and 1 under ``benchmarks/``. Those numbers record that day; nothing holds them, because a count that moves with
unrelated pull requests would turn their work red.
"""
from __future__ import annotations

import ast
import builtins
from collections.abc import Mapping
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ROOTS = ("src", "plugins", "tools", "docs/scitt")
OUTSIDE = ("scripts", "conformance", "interop", "examples", "fuzz", "benchmarks")

#: json hooks that refuse a duplicate member name; every function defined under one of these names is run below.
STRICT_HOOKS = {"_reject_duplicate_keys", "no_duplicate_members"}

#: The members of each library that do not decode. Everything else the library has is a decode reference.
NOT_DECODING = {
    "json": {"dumps", "dump", "JSONEncoder", "JSONDecodeError"},
    "cbor2": {"dumps", "dump", "CBOREncoder", "CBORTag", "CBORSimpleValue", "undefined", "CBORError",
              "CBORDecodeError", "CBOREncodeError", "CBORDecodeValueError", "CBORDecodeEOF", "CBOREncodeTypeError",
              "CBOREncodeValueError", "FrozenDict"},
}

#: path -> (number of lax decode references, reason they lie outside a verify path)
EXCEPTIONS = {
    "src/proofbundle/adapters/eee.py": (1, "reads the JSON schema file this package ships, not input"),
    "src/proofbundle/trust_pack.py": (1, "reads back the RFC 8785 bytes it just wrote from an already parsed object"),
    "tools/cap1_unabhaengige_umsetzung/lauf.py": (
        2, "measures the last-wins and first-wins readings of CAP-1 on purpose; the verdict table is the result"),
    "tools/cap1_unabhaengige_umsetzung/py/cap1_verify.py": (
        1, "the independent CAP-1 implementation, frozen at 8b581d7 by tests/test_cap1_teil_c_sonden.py; its command "
           "line is the last-wins reading that lauf.py and the README of that directory measure next to the strict one"),
    "tools/cap1_unabhaengige_umsetzung/sonden.py": (
        2, "builds the duplicate-key probes from the author's vectors; it writes test input, it judges nothing"),
    "tools/capability_matrix/measure.py": (
        6, "measurement harness: reads its own run outputs and the PyPI index, every verdict comes from the verifier"),
    "tools/merkle_accumulator/accumulator.py": (
        1, "reads back the canonical bytes of a state whose signature was verified one line before"),
    "tools/merkle_accumulator/render_runs.py": (1, "renders recorded run summaries for reading, decides nothing"),
    "tools/pb_verify_rs/crosscheck.py": (
        16, "differential harness: the verdicts compared are those of the Python and the Rust verifier; two sites "
            "under the alias _json build its own test inputs"),
    "tools/scitt_ccf_datahash_vector/reader_matrix.py": (
        2, "measures cbor2 itself: what the library accepts is the result"),
    "docs/scitt/statement_identification/package/build.py": (
        3, "producer of the package: reads back the statements it has just built"),
    "docs/scitt/statement_identification/package/verify.py": (
        4, "standalone checker for external readers; every cbor2 call runs behind its own pre-scan item_end, "
           "which refuses duplicate keys and bytes after the item, and decodes each map once more to refuse one that "
           "cbor2 reads with fewer entries than it has pairs; its decoding is held by test_strict_cbor"),
}

_SEQ, _MAP = {"tuple", "Sequence"}, {"Mapping", "frozendict", "FrozenDict"}
_TYPE_PARTNERS = {"list": _SEQ, "List": _SEQ, "MutableSequence": _SEQ,
                  "dict": _MAP, "Dict": _MAP, "MutableMapping": _MAP}
#: The modules a container type name can be imported from under another name.
_TYPE_MODULES = {"typing", "collections.abc", "builtins"}


def _library(module: str | None) -> str | None:
    top = (module or "").split(".")[0]
    return top if top in NOT_DECODING else None


def _aliases(tree: ast.AST) -> dict:
    """local name -> (library, member path or None for the library itself), for json and cbor2."""
    out: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                lib = _library(a.name)
                if lib is None:
                    continue
                if a.asname is None:
                    out[a.name.split(".")[0]] = (lib, None)
                else:
                    out[a.asname] = (lib, a.name.split(".", 1)[1] if "." in a.name else None)
        elif isinstance(node, ast.ImportFrom) and _library(node.module):
            lib = _library(node.module)
            sub = node.module.split(".", 1)[1] if "." in node.module else None
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = (lib, f"{sub}.{a.name}" if sub else a.name)
    return out


def _decoding(lib: str, member: str | None) -> bool:
    """A member decodes unless the name it ends in is one of NOT_DECODING: ``json.decoder.JSONDecodeError`` does not,
    ``json.decoder`` and ``cbor2.decoder.loads`` do."""
    return member is not None and member.split(".")[-1] not in NOT_DECODING[lib]


def _parents(tree: ast.AST) -> dict:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _local_hooks(tree: ast.AST) -> set:
    """The names of STRICT_HOOKS this module defines as a function and never binds otherwise."""
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in STRICT_HOOKS}
    rebound = {t.id for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
               for t in (n.targets if isinstance(n, ast.Assign) else [n.target]) if isinstance(t, ast.Name)}
    imported = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    return defined - rebound - imported


def _strict_call(call: ast.AST | None, local_hooks: set = frozenset()) -> bool:
    if not isinstance(call, ast.Call):
        return False
    for kw in call.keywords:
        if kw.arg == "object_pairs_hook":
            return isinstance(kw.value, ast.Name) and kw.value.id in local_hooks
    return False


def _is_func_of(node: ast.AST, parent: ast.AST | None) -> bool:
    return isinstance(parent, ast.Call) and parent.func is node


def _import_call(node: ast.AST) -> str | None:
    """'cbor2' for importlib.import_module('cbor2') or __import__('cbor2...'), else None."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)) and node.args):
        return None
    name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
    arg = node.args[0]
    if name in ("import_module", "__import__") and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value if _library(arg.value) else None
    return None


def sites(source: str) -> list:
    """The lax decode references of one module, as (line, what)."""
    tree = ast.parse(source)
    aliases, parents, hooks = _aliases(tree), _parents(tree), _local_hooks(tree)
    out = []
    for node in ast.walk(tree):
        imported = _import_call(node)
        if imported:
            out.append((node.lineno, f"import of {imported}"))
        elif isinstance(node, ast.ImportFrom) and _library(node.module) and any(a.name == "*" for a in node.names):
            out.append((node.lineno, f"from {node.module} import *"))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            lib, member = aliases[node.value.id]
            path = f"{member}.{node.attr}" if member else node.attr
            if _decoding(lib, path) and not (_is_func_of(node, parents.get(node)) and _strict_call(parents[node], hooks)):
                out.append((node.lineno, f"{lib}.{path}"))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in aliases:
            lib, member = aliases[node.id]
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue                          # judged above, with the whole member path
            if member is None:
                out.append((node.lineno, f"{lib} handed on"))
            elif _decoding(lib, member) and not (_is_func_of(node, parent) and _strict_call(parent, hooks)):
                out.append((node.lineno, f"{lib}.{member}"))
    return sorted(out)


def _imports_cbor2(tree: ast.AST) -> bool:
    if any(lib == "cbor2" for lib, _ in _aliases(tree).values()):
        return True
    return any(_library(_import_call(n)) == "cbor2" for n in ast.walk(tree))


def _annotation_nodes(tree: ast.AST) -> set:
    roots = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
    return {n for r in roots for n in ast.walk(r)}


def _type_aliases(tree: ast.AST) -> tuple:
    """(local name -> container type name for `from typing import Dict as D`, names bound to the builtins module)."""
    names, builtins_names = {}, set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module in _TYPE_MODULES:
            for a in n.names:
                if a.name in _TYPE_PARTNERS:
                    names[a.asname or a.name] = a.name
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "builtins":
                    builtins_names.add(a.asname or a.name)
    return names, builtins_names


def _type_name(node: ast.AST, names: dict = None, builtins_names: set = frozenset({"builtins"})) -> str | None:
    names = names or {}
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        if node.id in _TYPE_PARTNERS:
            return node.id
        return names.get(node.id)
    if isinstance(node, ast.Attribute) and node.attr in ("List", "Dict", "MutableSequence", "MutableMapping"):
        return node.attr
    if (isinstance(node, ast.Attribute) and node.attr in ("list", "dict") and isinstance(node.value, ast.Name)
            and node.value.id in builtins_names | {"builtins"}):
        return node.attr
    return None


def _an_argument(node: ast.AST, parent: ast.AST | None) -> bool:
    """`defaultdict(list)`, `field(default_factory=list)`, `dict.fromkeys(k)`: the type is used, not tested."""
    if isinstance(parent, ast.Call) and not (isinstance(parent.func, ast.Name)
                                             and parent.func.id in ("isinstance", "issubclass")):
        return node in parent.args
    if isinstance(parent, ast.keyword):
        return True
    return isinstance(parent, ast.Attribute) and parent.value is node


def _names_in(node: ast.AST) -> set:
    return {n.id if isinstance(n, ast.Name) else n.attr for n in ast.walk(node)
            if isinstance(n, (ast.Name, ast.Attribute))}


def container_checks(source: str) -> list:
    """Lines where ``list``/``dict`` (or ``List``/``Dict``) stand outside a call, an annotation and an
    ``isinstance``/``issubclass`` that also names the cbor2 6 partner type, in a module that imports cbor2."""
    tree = ast.parse(source)
    if not _imports_cbor2(tree):
        return []
    parents, annotations = _parents(tree), _annotation_nodes(tree)
    names, builtins_names = _type_aliases(tree)
    out = []
    for node in ast.walk(tree):
        name = _type_name(node, names, builtins_names)
        parent = parents.get(node)
        if name is None or node in annotations or _is_func_of(node, parent) or _an_argument(node, parent):
            continue
        cur, ok = node, False
        while cur in parents:
            up = parents[cur]
            if (isinstance(up, ast.Call) and isinstance(up.func, ast.Name)
                    and up.func.id in ("isinstance", "issubclass") and len(up.args) == 2 and up.args[1] is cur):
                ok = bool(_TYPE_PARTNERS[name] & _names_in(cur))
                break
            cur = up
        if not ok:
            out.append(node.lineno)
    return sorted(set(out))


def _hook_definitions(source: str) -> list:
    return [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name in STRICT_HOOKS]


#: Inputs a strict hook must refuse: the same name twice with the same and with another value, a duplicate that is not
#: adjacent, and one among more pairs.
DUPLICATE_PROBES = ([("a", 1), ("a", 1)], [("a", 1), ("a", 2)], [("a", 1), ("b", 2), ("a", 3)],
                    [("x", 0), ("y", 0), ("z", 0), ("y", 1)])
UNIQUE_PROBE = [("a", 1), ("b", 2), ("c", 3)]


def hook_refuses_a_duplicate(node: ast.FunctionDef, where: str) -> tuple:
    """Run one hook definition on its own: -> (refuses every input of DUPLICATE_PROBES, what it returns for
    UNIQUE_PROBE, whether its body uses `assert`). A name the hook reads from its module is bound to a fresh exception
    class, so a hook that raises its module's error still raises."""
    params = {a.arg for a in node.args.args}
    stored = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    free = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} - params - stored
    namespace: dict = {n: type(n, (ValueError,), {}) for n in free if not hasattr(builtins, n)}
    exec(compile(ast.Module(body=[node], type_ignores=[]), where, "exec"), namespace)  # noqa: S102 - this repo's code
    hook = namespace[node.name]

    def refuses(pairs):
        try:
            hook(pairs)
        except Exception:  # noqa: BLE001 - any refusal counts, its kind belongs to the module
            return True
        return False

    uses_assert = any(isinstance(n, ast.Assert) for n in ast.walk(node))
    return all(refuses(p) for p in DUPLICATE_PROBES), hook(list(UNIQUE_PROBE)), uses_assert


def _sources(roots=ROOTS, repo=REPO):
    for root in roots:
        base = repo / root
        if base.is_dir():
            for path in sorted(base.rglob("*.py")):
                yield path.relative_to(repo).as_posix(), path.read_text(encoding="utf-8")


def _measure(repo=REPO):
    found, type_findings, hooks = {}, {}, []
    for rel, source in _sources(repo=repo):
        s = sites(source)
        if s:
            found[rel] = s
        t = container_checks(source)
        if t:
            type_findings[rel] = t
        hooks.extend((rel, node) for node in _hook_definitions(source))
    return found, type_findings, hooks


def test_every_lax_decode_reference_is_named_and_counted():
    found, _, _ = _measure()
    assert found, "the guard found no decode reference at all, so it measured nothing"
    new = {rel: s for rel, s in found.items() if rel not in EXCEPTIONS}
    wrong = {rel: (len(s), EXCEPTIONS[rel][0]) for rel, s in found.items()
             if rel in EXCEPTIONS and len(s) != EXCEPTIONS[rel][0]}
    gone = sorted(set(EXCEPTIONS) - set(found))
    assert not new, f"lax decode references without a named reason, use a strict helper: {new}"
    assert not wrong, f"the number of lax references changed, (found, listed): {wrong}"
    assert not gone, f"listed exceptions with no reference left, remove them from EXCEPTIONS: {gone}"


def test_behind_cbor2_every_container_check_holds_under_cbor2_5_and_6():
    _, type_findings, _ = _measure()
    assert not type_findings, ("list or dict behind cbor2 outside a call, an annotation and an isinstance with "
                               f"tuple or Mapping (cbor2 6 returns tuples and frozendicts under a tag): {type_findings}")


def test_every_strict_hook_defined_in_the_scope_refuses_a_duplicate_member_name():
    _, _, hooks = _measure()
    assert len(hooks) >= 3, f"the guard found {len(hooks)} strict hook definitions, so it measured too little"
    for rel, node in hooks:
        refuses, result, uses_assert = hook_refuses_a_duplicate(node, rel)
        assert refuses, f"{rel}:{node.lineno} {node.name} does not refuse every duplicate member name"
        assert not uses_assert, f"{rel}:{node.lineno} {node.name} refuses with assert, which python -O removes"
        assert isinstance(result, Mapping) and dict(result) == dict(UNIQUE_PROBE), f"{rel}:{node.lineno} {node.name}"


def test_counter_probe_the_three_measurements_reach_a_planted_tree(tmp_path):
    """The functions are held on strings below; this holds the walk over the tree that calls them."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "planted.py").write_text(
        "import json\nimport cbor2\njson.loads(x)\nisinstance(v, list)\n"
        "def _reject_duplicate_keys(pairs):\n    return dict(pairs)\n", encoding="utf-8")
    found, type_findings, hooks = _measure(tmp_path)
    assert found == {"src/planted.py": [(3, "json.loads")]}
    assert type_findings == {"src/planted.py": [4]}
    assert [(rel, n.name) for rel, n in hooks] == [("src/planted.py", "_reject_duplicate_keys")]
    assert hook_refuses_a_duplicate(hooks[0][1], "planted")[0] is False


@pytest.mark.parametrize("source, expected", [
    ("import json\njson.loads(x)\n", [(2, "json.loads")]),
    ("import json as j\nj.load(f)\n", [(2, "json.load")]),
    ("from json import loads as l\nl(x)\n", [(2, "json.loads")]),
    ("import cbor2\ncbor2.loads(b)\n", [(2, "cbor2.loads")]),
    ("from cbor2 import CBORDecoder\nCBORDecoder(f)\n", [(2, "cbor2.CBORDecoder")]),
    ("import json\njson.loads(x, object_pairs_hook=first_wins)\n", [(2, "json.loads")]),
    # Forms an adversarial review found that the first version missed.
    ("from json import JSONDecoder\nJSONDecoder().decode(x)\n", [(2, "json.JSONDecoder")]),
    ("import json\njson.JSONDecoder().raw_decode(x)\n", [(2, "json.JSONDecoder")]),
    ("import json\nloads = json.loads\nloads(x)\n", [(2, "json.loads")]),
    ("import json\nlist(map(json.loads, xs))\n", [(2, "json.loads")]),
    ("import cbor2\ncbor2.decoder.loads(b)\n", [(2, "cbor2.decoder")]),
    ("import cbor2.decoder\ncbor2.decoder.loads(b)\n", [(2, "cbor2.decoder")]),
    ("from cbor2 import decoder\ndecoder.loads(b)\n", [(2, "cbor2.decoder.loads")]),
    ("import cbor2.decoder as d\nd.loads(b)\n", [(2, "cbor2.decoder.loads")]),
    ("from cbor2.decoder import loads\nloads(b)\n", [(2, "cbor2.decoder.loads")]),
    ("import functools, json\nfunctools.partial(json.loads)\n", [(2, "json.loads")]),
    ("import json\ngetattr(json, 'loads')(x)\n", [(2, "json handed on")]),
    ("from json import *\nloads(x)\n", [(1, "from json import *")]),
    ("import importlib\nimportlib.import_module('cbor2').loads(b)\n", [(2, "import of cbor2")]),
    ("__import__('json').loads(x)\n", [(1, "import of json")]),
    # A hook name is not a hook: the module must define it as a function and keep it.
    ("import json\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n", [(2, "json.loads")]),
    ("import json\n_reject_duplicate_keys = dict\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
     [(3, "json.loads")]),
    ("import json\nno_duplicate_members = lambda p: dict(p)\njson.loads(x, object_pairs_hook=no_duplicate_members)\n",
     [(3, "json.loads")]),
    ("import json\nfrom os import _reject_duplicate_keys\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
     [(3, "json.loads")]),
    ("import json\njson.load(f, object_pairs_hook=mod.no_duplicate_members)\n", [(2, "json.load")]),
    ("import json\njson.loads(x, object_pairs_hook=lambda p: dict(p))\n", [(2, "json.loads")]),
    ("import json\ndef _reject_duplicate_keys(p):\n    raise ValueError\n_reject_duplicate_keys = dict\n"
     "json.loads(x, object_pairs_hook=_reject_duplicate_keys)\n", [(5, "json.loads")]),
])
def test_counter_probe_a_planted_lax_site_is_found(source, expected):
    assert sites(source) == expected


_HOOK = "def _reject_duplicate_keys(pairs):\n    raise ValueError\n"


@pytest.mark.parametrize("source", [
    "import json\n" + _HOOK + "json.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
    "import json\n" + _HOOK + "json.load(f, cls=C, object_pairs_hook=_reject_duplicate_keys)\n",
    "import json\n" + _HOOK + "json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys).decode(x)\n",
    "from json import loads\n" + _HOOK + "loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
    "from json.decoder import JSONDecodeError\nimport cbor2\nfrom cbor2.types import CBORTag\n"
    "e = (cbor2.CBORDecodeValueError, cbor2.CBORDecodeEOF, cbor2.FrozenDict)\n",
    "from proofbundle._strict_json import loads_strict\nloads_strict(x)\n",
    "import json\njson.dumps(x)\njson.dump(x, f)\n",
    "import json\ntry:\n    pass\nexcept json.JSONDecodeError:\n    pass\n",
    "import cbor2\ncbor2.dumps(cbor2.CBORTag(18, [1]))\nisinstance(e, cbor2.CBORDecodeError)\n",
    "def loads(x):\n    return x\nloads(1)\n",
])
def test_control_strict_and_unrelated_calls_do_not_count(source):
    assert sites(source) == []


@pytest.mark.parametrize("source, lines", [
    ("import cbor2\nisinstance(v, list)\nisinstance(v, (list, dict))\n", [2, 3]),
    ("import cbor2\nisinstance(v, dict)\nisinstance(v, (bytes, dict))\n", [2, 3]),
    # Forms an adversarial review found that the first version missed.
    ("import cbor2\nfrom typing import List\nisinstance(v, List)\n", [3]),
    ("import cbor2\nimport typing\nisinstance(v, typing.Dict)\n", [3]),
    ("import cbor2\nisinstance(v, list | None)\n", [2]),
    ("import cbor2\nLISTS = (list,)\nisinstance(v, LISTS)\n", [2]),
    ("import cbor2\nisinstance(v, (list,) + EXTRA)\n", [2]),
    ("import cbor2\ntype(v) is list\ntype(v) == dict\nv.__class__ is list\n", [2, 3, 4]),
    ("import cbor2\nmatch v:\n    case list():\n        pass\n    case dict():\n        pass\n", [3, 5]),
    ("import builtins\nimport cbor2\nisinstance(v, builtins.list)\n", [3]),
    ("import cbor2.decoder\nisinstance(v, list)\n", [2]),
    ("from cbor2.decoder import loads\nisinstance(v, dict)\n", [2]),
    ("import importlib\nimportlib.import_module('cbor2')\nisinstance(v, list)\n", [3]),
    # Forms a second adversarial review found: the mutable abstract types and aliases of an import.
    ("import cbor2\nfrom collections.abc import MutableMapping\nisinstance(v, MutableMapping)\n", [3]),
    ("import cbor2\nimport collections.abc as abc\nisinstance(v, abc.MutableSequence)\n", [3]),
    ("import cbor2\nfrom typing import Dict as D\nisinstance(v, D)\n", [3]),
    ("import cbor2\nfrom builtins import list as L\nisinstance(v, L)\n", [3]),
    ("import cbor2\nimport builtins as b\nisinstance(v, b.list)\n", [3]),
])
def test_counter_probe_a_container_check_behind_cbor2_is_found(source, lines):
    assert container_checks(source) == lines


@pytest.mark.parametrize("source", [
    "import cbor2\nisinstance(v, (list, tuple))\n",
    "import cbor2\nfrom collections.abc import Mapping\nisinstance(v, Mapping)\nisinstance(v, (dict, Mapping))\n",
    "import cbor2\nimport collections.abc as abc\nisinstance(v, (dict, abc.Mapping))\n",
    "import cbor2\nx = list(y)\nd = dict(pairs)\n",
    "import cbor2\ndef f(x: list, y: dict | None = None) -> dict:\n    out: list = []\n    return {}\n",
    "import cbor2\nimport typing, collections\nv = typing.cast(list, v)\nd = collections.defaultdict(list)\n"
    "f = field(default_factory=dict)\ne = dict.fromkeys(k)\n",
    "import cbor2\nfrom collections.abc import MutableMapping, Mapping\nisinstance(v, (MutableMapping, Mapping))\n",
    "isinstance(v, list)\ntype(v) is dict\n",
])
def test_control_calls_annotations_and_checks_with_the_partner_do_not_count(source):
    assert container_checks(source) == []


@pytest.mark.parametrize("source, refuses, uses_assert", [
    ("def _reject_duplicate_keys(pairs):\n    return dict(pairs)\n", False, False),
    ("def no_duplicate_members(pairs):\n    out = {}\n    for k, v in pairs:\n        out.setdefault(k, v)\n"
     "    return out\n", False, False),
    # Laxer than strict on some input only: adjacent duplicates, at most two pairs, an assert.
    ("def _reject_duplicate_keys(pairs):\n    for (a, _), (b, _) in zip(pairs, pairs[1:]):\n        if a == b:\n"
     "            raise ValueError(a)\n    return dict(pairs)\n", False, False),
    ("def _reject_duplicate_keys(pairs):\n    if len(pairs) <= 2 and len({n for n, _ in pairs}) < len(pairs):\n"
     "        raise ValueError\n    return dict(pairs)\n", False, False),
    ("def _reject_duplicate_keys(pairs):\n    out = {}\n    for k, v in pairs:\n        assert k not in out\n"
     "        out[k] = v\n    return out\n", True, True),
    ("def _reject_duplicate_keys(pairs):\n    names = [n for n, _ in pairs]\n"
     "    if len(set(names)) != len(names):\n        raise Malformed('duplicate')\n    return dict(pairs)\n",
     True, False),
])
def test_counter_probe_a_hook_is_judged_by_what_it_does_not_by_its_name(source, refuses, uses_assert):
    (node,) = _hook_definitions(source)
    got_refuses, _result, got_assert = hook_refuses_a_duplicate(node, "<planted>")
    assert (got_refuses, got_assert) == (refuses, uses_assert)


def test_the_docstring_names_the_directories_outside_the_scope_that_exist():
    """The scope statement above is held: each directory it names as outside exists, and none of them is a root."""
    for top in OUTSIDE:
        assert f"``{top}/``" in __doc__, top
        assert (REPO / top).is_dir(), top
        assert top not in ROOTS
