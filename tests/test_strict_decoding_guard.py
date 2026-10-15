"""The guard of the strict decoding class: no new lax JSON or CBOR decode site without a named reason.

The strict decoding rule of this repository (2026-10-14): every reader of checked, signed or evidential bytes
refuses duplicate keys, invalid encoding and bytes after the value, and a contract test finds a new decode site
that bypasses the strict helpers.

WHAT IT READS. The Python source under ``src/``, ``plugins/``, ``tools/`` and ``docs/scitt/``, parsed with ``ast``.
A call counts as a decode site when it resolves, through the module's imports and aliases, to ``json.loads``,
``json.load``, ``cbor2.loads``, ``cbor2.load`` or ``cbor2.CBORDecoder``. A ``json`` call with
``object_pairs_hook=`` naming one of ``STRICT_HOOKS`` is strict and not counted.

WHAT IT REQUIRES. Every other site is in ``EXCEPTIONS`` with the exact number of sites per file and a reason
outside a verify path. A new site turns this red, and so does a site that went away, so the list never outlives
what it describes.

THE CBOR2 6 CLASS. Under a tag, at any depth, cbor2 6 returns an array as a tuple and a map as a frozendict, where
cbor2 5 returned a list and a dict (measured with 5.9.0 and 6.1.4; without a tag both return list and dict). A
reader that checks ``isinstance(x, list)`` or ``isinstance(x, dict)`` behind cbor2 is therefore right under one
version only. In every module that imports cbor2, an ``isinstance`` check naming ``list`` must name ``tuple`` as
well, and one naming ``dict`` must name ``Mapping`` or ``frozendict`` as well.

HONEST LIMITS. It reads Python only; the Rust and Go readers are measured by their own runs. It does not see a
hand-written decoder such as ``cbor_min``; those are held by the shared corpus in ``test_strict_cbor``. A hook is
recognised by its name, so a lax hook named like a strict one would pass here; each strict hook has its own
behavioural test. The scope is the code that verifies; ``scripts/`` is release and office tooling and not in it.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ROOTS = ("src", "plugins", "tools", "docs/scitt")

#: json hooks that refuse a duplicate member name, each with its own behavioural test.
STRICT_HOOKS = {"_reject_duplicate_keys", "no_duplicate_members"}

_TARGETS = {("json", "loads"), ("json", "load"), ("cbor2", "loads"), ("cbor2", "load"), ("cbor2", "CBORDecoder")}

#: path -> (number of lax decode sites, reason they lie outside a verify path)
EXCEPTIONS = {
    "src/proofbundle/adapters/eee.py": (1, "reads the JSON schema file this package ships, not input"),
    "src/proofbundle/trust_pack.py": (1, "reads back the RFC 8785 bytes it just wrote from an already parsed object"),
    "tools/cap1_unabhaengige_umsetzung/lauf.py": (
        2, "measures the last-wins and first-wins readings of CAP-1 on purpose; the verdict table is the result"),
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
           "which refuses duplicate keys and bytes after the item, and its decoding is held by test_strict_cbor"),
}


def _aliases(tree: ast.AST) -> dict:
    """local name -> (module, attribute or None) for json and cbor2."""
    out: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in ("json", "cbor2"):
                    out[a.asname or a.name] = (a.name, None)
        elif isinstance(node, ast.ImportFrom) and node.module in ("json", "cbor2"):
            for a in node.names:
                out[a.asname or a.name] = (node.module, a.name)
    return out


def _target(call: ast.Call, aliases: dict):
    f = call.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in aliases:
        module, attr = aliases[f.value.id]
        if attr is None and (module, f.attr) in _TARGETS:
            return module, f.attr
    if isinstance(f, ast.Name) and f.id in aliases:
        module, attr = aliases[f.id]
        if attr is not None and (module, attr) in _TARGETS:
            return module, attr
    return None


def _strict(call: ast.Call, module: str) -> bool:
    if module != "json":
        return False
    for kw in call.keywords:
        if kw.arg == "object_pairs_hook":
            v = kw.value
            name = v.id if isinstance(v, ast.Name) else v.attr if isinstance(v, ast.Attribute) else None
            return name in STRICT_HOOKS
    return False


def sites(source: str) -> list:
    """The lax decode sites of one module, as (line, 'module.attribute')."""
    tree = ast.parse(source)
    aliases = _aliases(tree)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            z = _target(node, aliases)
            if z and not _strict(node, z[0]):
                out.append((node.lineno, f"{z[0]}.{z[1]}"))
    return sorted(out)


def list_without_tuple(source: str) -> list:
    """Lines of `isinstance(x, list)` or a tuple of types naming list but not tuple, in a module importing cbor2."""
    tree = ast.parse(source)
    if not any(m == "cbor2" for m, _ in _aliases(tree).values()):
        return []
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "isinstance"
                and len(node.args) == 2):
            types = node.args[1]
            names = [t.id for t in (types.elts if isinstance(types, ast.Tuple) else [types]) if isinstance(t, ast.Name)]
            if "list" in names and "tuple" not in names:
                out.append(node.lineno)
    return out


def dict_without_mapping(source: str) -> list:
    """Lines of `isinstance(x, dict)` or a tuple of types naming dict but neither Mapping nor frozendict, in a module
    importing cbor2."""
    tree = ast.parse(source)
    if not any(m == "cbor2" for m, _ in _aliases(tree).values()):
        return []
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "isinstance"
                and len(node.args) == 2):
            types = node.args[1]
            elts = types.elts if isinstance(types, ast.Tuple) else [types]
            names = [t.id if isinstance(t, ast.Name) else t.attr for t in elts if isinstance(t, (ast.Name, ast.Attribute))]
            if "dict" in names and not {"Mapping", "frozendict", "FrozenDict"} & set(names):
                out.append(node.lineno)
    return out


def _sources():
    for root in ROOTS:
        base = REPO / root
        if base.is_dir():
            for path in sorted(base.rglob("*.py")):
                yield path.relative_to(REPO).as_posix(), path.read_text(encoding="utf-8")


def _measure():
    found, type_findings = {}, {}
    for rel, source in _sources():
        s = sites(source)
        if s:
            found[rel] = s
        t = list_without_tuple(source) + dict_without_mapping(source)
        if t:
            type_findings[rel] = sorted(t)
    return found, type_findings


def test_every_lax_decode_site_is_named_and_counted():
    found, _ = _measure()
    assert found, "the guard found no decode site at all, so it measured nothing"
    new = {rel: s for rel, s in found.items() if rel not in EXCEPTIONS}
    wrong = {rel: (len(s), EXCEPTIONS[rel][0]) for rel, s in found.items()
              if rel in EXCEPTIONS and len(s) != EXCEPTIONS[rel][0]}
    gone = sorted(set(EXCEPTIONS) - set(found))
    assert not new, f"lax decode sites without a named reason, use a strict helper: {new}"
    assert not wrong, f"the number of lax sites changed, (found, listed): {wrong}"
    assert not gone, f"listed exceptions with no site left, remove them from EXCEPTIONS: {gone}"


def test_behind_cbor2_every_container_check_holds_under_cbor2_5_and_6():
    _, type_findings = _measure()
    assert not type_findings, ("isinstance(..., list) without tuple or isinstance(..., dict) without Mapping behind "
                               f"cbor2 (cbor2 6 returns tuples and frozendicts under a tag): {type_findings}")


@pytest.mark.parametrize("source, expected", [
    ("import json\njson.loads(x)\n", [(2, "json.loads")]),
    ("import json as j\nj.load(f)\n", [(2, "json.load")]),
    ("from json import loads as l\nl(x)\n", [(2, "json.loads")]),
    ("import cbor2\ncbor2.loads(b)\n", [(2, "cbor2.loads")]),
    ("from cbor2 import CBORDecoder\nCBORDecoder(f)\n", [(2, "cbor2.CBORDecoder")]),
    ("import json\njson.loads(x, object_pairs_hook=first_wins)\n", [(2, "json.loads")]),
])
def test_counter_probe_a_planted_lax_site_is_found(source, expected):
    assert sites(source) == expected


@pytest.mark.parametrize("source", [
    "import json\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
    "from proofbundle._strict_json import loads_strict\nloads_strict(x)\n",
    "import json\njson.dumps(x)\n",
    "def loads(x):\n    return x\nloads(1)\n",
])
def test_control_strict_and_unrelated_calls_do_not_count(source):
    assert sites(source) == []


def test_counter_probe_a_list_check_without_tuple_behind_cbor2_is_found():
    assert list_without_tuple("import cbor2\nisinstance(v, list)\nisinstance(v, (list, dict))\n") == [2, 3]
    assert list_without_tuple("import cbor2\nisinstance(v, (list, tuple))\n") == []
    assert list_without_tuple("isinstance(v, list)\n") == []


def test_counter_probe_a_dict_check_without_mapping_behind_cbor2_is_found():
    assert dict_without_mapping("import cbor2\nisinstance(v, dict)\nisinstance(v, (bytes, dict))\n") == [2, 3]
    assert dict_without_mapping("import cbor2\nfrom collections.abc import Mapping\nisinstance(v, Mapping)\n") == []
    assert dict_without_mapping("import cbor2\nimport collections.abc as abc\nisinstance(v, (dict, abc.Mapping))\n") == []
    assert dict_without_mapping("isinstance(v, dict)\n") == []
