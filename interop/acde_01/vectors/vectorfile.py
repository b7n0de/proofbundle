"""Compact vector form: a shared base profile and base frozen input, each vector a JSON Merge Patch
(RFC 7396) against them plus its own records and claims. Report-tampering vectors carry a list of
edit operations instead of an embedded report.

Edit operation: {"op": "set" | "delete", "path": [...], "value": ...}. A path element is an object
key, a list index, or {"where": {field: value}} selecting the first list element whose fields match.
"""
from __future__ import annotations

import copy

_ABSENT = object()


def merge_patch(target, patch):
    """RFC 7396 section 2 MergePatch."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    out = copy.deepcopy(target) if isinstance(target, dict) else {}
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = merge_patch(out.get(k), v)
    return out


def make_patch(base, target):
    """A merge patch p with merge_patch(base, p) == target. Values that are null in the target are
    not expressible in RFC 7396; the builders never need one except where the base already has it."""
    if not isinstance(base, dict) or not isinstance(target, dict):
        return copy.deepcopy(target)
    p = {}
    for k in base:
        if k not in target:
            p[k] = None
    for k, v in target.items():
        if k not in base:
            p[k] = copy.deepcopy(v)
        elif base[k] != v:
            if isinstance(base[k], dict) and isinstance(v, dict):
                p[k] = make_patch(base[k], v)
            else:
                p[k] = copy.deepcopy(v)
    return p


def _step(node, el):
    if isinstance(el, dict) and "where" in el:
        for i, x in enumerate(node):
            if isinstance(x, dict) and all(x.get(k) == v for k, v in el["where"].items()):
                return i
        raise KeyError(f"no element matches {el['where']}")
    return el


def apply_ops(doc, ops):
    doc = copy.deepcopy(doc)
    for op in ops:
        node = doc
        path = op["path"]
        for el in path[:-1]:
            node = node[_step(node, el)]
        last = _step(node, path[-1])
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[last]
        else:
            raise ValueError(op["op"])
    return doc


def compact_run(run, base_profile, base_frozen):
    out = {"profile_patch": make_patch(base_profile, run["profile"]),
           "frozen_patch": make_patch(base_frozen, run["frozen"]),
           "records": run["records"], "claims": run["claims"]}
    assert expand_run(out, base_profile, base_frozen) == run, "patch round trip failed"
    return out


def expand_run(c, base_profile, base_frozen):
    return {"profile": merge_patch(base_profile, c["profile_patch"]),
            "frozen": merge_patch(base_frozen, c["frozen_patch"]),
            "records": copy.deepcopy(c["records"]), "claims": copy.deepcopy(c["claims"])}
