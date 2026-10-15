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
version listed the five lax calls it knew and missed each of these forms (lens on fb22b3bd, F3-a). A call whose
``object_pairs_hook=`` names one of ``STRICT_HOOKS`` is strict and not counted.

WHAT IT REQUIRES. Every other reference is in ``EXCEPTIONS`` with the exact number per file and a reason outside a
verify path. A new reference turns this red, and so does one that went away, so the list never outlives what it
describes. Each function defined under a name in ``STRICT_HOOKS`` is run on a duplicate member name and must refuse
it, so a lax hook named like a strict one is red here too.

THE CBOR2 6 CLASS. Under a tag, at any depth, cbor2 6 returns an array as a tuple and a map as a frozendict, where
cbor2 5 returned a list and a dict (measured with 5.9.0 and 6.1.4; without a tag both return list and dict). A
reader that tests for ``list`` or ``dict`` behind cbor2 is therefore right under one version only. In every module
that imports cbor2, by any form of import, the names ``list``, ``dict``, ``List`` and ``Dict`` may stand only in a
call (``list(x)``), in an annotation, or in the type argument of ``isinstance``/``issubclass`` together with ``tuple``
or ``Sequence`` (for list) and ``Mapping``, ``frozendict`` or ``FrozenDict`` (for dict). Every other place is a
finding: ``type(v) is list``, ``isinstance(v, list | None)``, ``case list():``, ``LISTS = (list,)``.

HONEST LIMITS. It reads Python only; the Rust and Go readers are measured by their own runs. It does not see a
hand-written decoder such as ``cbor_min``; those are held by the shared corpus in ``test_strict_cbor``. Code that
reaches a decoder through an object handed in from elsewhere, without importing either library, is not seen.

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
              "CBORDecodeError", "CBOREncodeError"},
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
        3, "standalone checker for external readers; every cbor2 call runs behind its own pre-scan item_end, "
           "which refuses duplicate keys, keys that are one dict key and bytes after the item, and its decoding is "
           "held by test_strict_cbor"),
}

_TYPE_PARTNERS = {"list": {"tuple", "Sequence"}, "List": {"tuple", "Sequence"},
                  "dict": {"Mapping", "frozendict", "FrozenDict"}, "Dict": {"Mapping", "frozendict", "FrozenDict"}}


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
    return member is not None and member.split(".")[0] not in NOT_DECODING[lib]


def _parents(tree: ast.AST) -> dict:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _strict_call(call: ast.AST | None) -> bool:
    if not isinstance(call, ast.Call):
        return False
    for kw in call.keywords:
        if kw.arg == "object_pairs_hook":
            v = kw.value
            name = v.id if isinstance(v, ast.Name) else v.attr if isinstance(v, ast.Attribute) else None
            return name in STRICT_HOOKS
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
    aliases, parents = _aliases(tree), _parents(tree)
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
            if _decoding(lib, path) and not (_is_func_of(node, parents.get(node)) and _strict_call(parents[node])):
                out.append((node.lineno, f"{lib}.{path}"))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in aliases:
            lib, member = aliases[node.id]
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue                          # judged above, with the whole member path
            if member is None:
                out.append((node.lineno, f"{lib} handed on"))
            elif _decoding(lib, member) and not (_is_func_of(node, parent) and _strict_call(parent)):
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


def _type_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in _TYPE_PARTNERS:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in ("List", "Dict"):
        return node.attr
    if (isinstance(node, ast.Attribute) and node.attr in ("list", "dict") and isinstance(node.value, ast.Name)
            and node.value.id == "builtins"):
        return node.attr
    return None


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
    out = []
    for node in ast.walk(tree):
        name = _type_name(node)
        if name is None or node in annotations or _is_func_of(node, parents.get(node)):
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


def hook_refuses_a_duplicate(node: ast.FunctionDef, where: str) -> tuple:
    """Run one hook definition on its own: -> (refuses [("a", 1), ("a", 1)], refuses [("a", 1), ("a", 2)], what it
    returns for [("a", 1), ("b", 2)]). A name the hook reads from its module is bound to a fresh exception class, so a
    hook that raises its module's error still raises."""
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

    return refuses([("a", 1), ("a", 1)]), refuses([("a", 1), ("a", 2)]), hook([("a", 1), ("b", 2)])


def _sources(roots=ROOTS):
    for root in roots:
        base = REPO / root
        if base.is_dir():
            for path in sorted(base.rglob("*.py")):
                yield path.relative_to(REPO).as_posix(), path.read_text(encoding="utf-8")


def _measure():
    found, type_findings, hooks = {}, {}, []
    for rel, source in _sources():
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
        same, different, result = hook_refuses_a_duplicate(node, rel)
        assert same and different, f"{rel}:{node.lineno} {node.name} does not refuse a duplicate member name"
        assert isinstance(result, Mapping) and dict(result) == {"a": 1, "b": 2}, f"{rel}:{node.lineno} {node.name}"


@pytest.mark.parametrize("source, expected", [
    ("import json\njson.loads(x)\n", [(2, "json.loads")]),
    ("import json as j\nj.load(f)\n", [(2, "json.load")]),
    ("from json import loads as l\nl(x)\n", [(2, "json.loads")]),
    ("import cbor2\ncbor2.loads(b)\n", [(2, "cbor2.loads")]),
    ("from cbor2 import CBORDecoder\nCBORDecoder(f)\n", [(2, "cbor2.CBORDecoder")]),
    ("import json\njson.loads(x, object_pairs_hook=first_wins)\n", [(2, "json.loads")]),
    # The forms a lens found that the first version missed (fb22b3bd, F3-a).
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
])
def test_counter_probe_a_planted_lax_site_is_found(source, expected):
    assert sites(source) == expected


@pytest.mark.parametrize("source", [
    "import json\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
    "import json\njson.load(f, object_pairs_hook=mod.no_duplicate_members)\n",
    "import json\njson.JSONDecoder(object_pairs_hook=_reject_duplicate_keys).decode(x)\n",
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
    # The forms a lens found that the first version missed (fb22b3bd, F3-b).
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
])
def test_counter_probe_a_container_check_behind_cbor2_is_found(source, lines):
    assert container_checks(source) == lines


@pytest.mark.parametrize("source", [
    "import cbor2\nisinstance(v, (list, tuple))\n",
    "import cbor2\nfrom collections.abc import Mapping\nisinstance(v, Mapping)\nisinstance(v, (dict, Mapping))\n",
    "import cbor2\nimport collections.abc as abc\nisinstance(v, (dict, abc.Mapping))\n",
    "import cbor2\nx = list(y)\nd = dict(pairs)\n",
    "import cbor2\ndef f(x: list, y: dict | None = None) -> dict:\n    out: list = []\n    return {}\n",
    "isinstance(v, list)\ntype(v) is dict\n",
])
def test_control_calls_annotations_and_checks_with_the_partner_do_not_count(source):
    assert container_checks(source) == []


@pytest.mark.parametrize("source, expected", [
    ("def _reject_duplicate_keys(pairs):\n    return dict(pairs)\n", (False, False)),
    ("def no_duplicate_members(pairs):\n    out = {}\n    for k, v in pairs:\n        out.setdefault(k, v)\n"
     "    return out\n", (False, False)),
    ("def _reject_duplicate_keys(pairs):\n    names = [n for n, _ in pairs]\n"
     "    if len(set(names)) != len(names):\n        raise Malformed('duplicate')\n    return dict(pairs)\n",
     (True, True)),
])
def test_counter_probe_a_hook_is_judged_by_what_it_does_not_by_its_name(source, expected):
    (node,) = _hook_definitions(source)
    same, different, _result = hook_refuses_a_duplicate(node, "<planted>")
    assert (same, different) == expected


def test_the_docstring_names_the_directories_outside_the_scope_that_exist():
    """The scope statement above is held: each directory it names as outside exists, and none of them is a root."""
    for top in OUTSIDE:
        assert f"``{top}/``" in __doc__, top
        assert (REPO / top).is_dir(), top
        assert top not in ROOTS
