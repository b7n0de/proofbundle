"""Evaluate one derived EQR vector: run the reader on its input and compare every selector.

Selectors (keys of a vector's ``expect``):

* a dotted path into the result of :func:`eqr00.verify.verify` (``qualification.qualifies``);
* ``refusals.has_code``, ``unverifiable.has_code``, ``policy.has_code``, ``notes.has_code``: the code is
  among those of that list;
* for ``set`` vectors, ``r<n>.<selector>`` for the n-th receipt's result, ``history.<path>`` and
  ``history.has_code`` for the history findings.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from eqr00.verify import verify, verify_set  # noqa: E402

_MISSING = object()


def _dig(node, path):
    for part in path.split(".") if path else []:
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return _MISSING
    return node


def _select(result, key):
    head, _, rest = key.partition(".")
    if rest == "has_code" and head in ("refusals", "unverifiable", "policy", "notes", "findings"):
        return sorted({x.get("code") for x in result.get(head, [])})
    return _dig(result, key)


def _match(key, want, got):
    if key.endswith("has_code"):
        return got is not _MISSING and want in got
    return got == want


def evaluate(vec):
    """Return (passed, failures, observed)."""
    inp, expect = vec["input"], vec["expect"]
    fails, seen = [], {}
    if vec["type"] == "verify":
        result = verify(inp["receipt"], inp["context"])
        for key, want in expect.items():
            got = _select(result, key)
            seen[key] = None if got is _MISSING else got
            if not _match(key, want, got):
                fails.append(f"{key}: expected {want!r}, got {seen[key]!r}")
        return not fails, fails, seen
    if vec["type"] == "set":
        out = verify_set(inp["receipts"], inp["context"])
        for key, want in expect.items():
            head, _, rest = key.partition(".")
            if head.startswith("r") and head[1:].isdigit():
                got = _select(out["receipts"][int(head[1:])], rest)
            elif head == "history" and rest == "has_code":
                got = sorted({f["code"] for f in out["history"]["findings"]})
            elif head == "history":
                got = _dig(out["history"], rest)
            else:
                got = _MISSING
            seen[key] = None if got is _MISSING else got
            if not _match(key, want, got):
                fails.append(f"{key}: expected {want!r}, got {seen[key]!r}")
        return not fails, fails, seen
    return False, [f"unknown vector type {vec['type']}"], {}
