"""Evaluate one derived vector: run the implementation on its input and compare every selector.

Selectors (keys of a vector's ``expect``):

* ``errors`` / ``errors_include`` - profile vectors: requirement ids of the profile errors
* ``violations`` / ``violations_include`` - report and rendering checks
* ``obl:<instruction>/<target>.<path>`` - one obligation; ``has_diag`` matches a diagnostic code
* ``instr:<instruction>.<path>``, ``claim:<claim_id>.<path>`` (``condition`` matches a named
  condition), ``receiver:<record>.class``, ``input:<record>.class``, ``op:<operation>.status``,
  ``op:<operation>.fact:<boundary>``, ``path:<path_id>.preservation``, ``path:<path_id>.hop0``,
  ``exclusions.<rule>.count``, ``non_claim:<property>``, ``structural.has_blocker``,
  ``run.errors_include``
* ``check`` - report_check and the text rendering check of the produced report
* ``deterministic_under_reorder`` - the same dispositions with the input records reversed
* ``v<n>.<selector>`` / ``v1.previous_is_v0`` - versioned runs
* any other key - a dotted path into the report
"""
from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from acde01.profile import validate_profile  # noqa: E402
from acde01.reconcile import reconcile, reconcile_versions, render_summary  # noqa: E402
from acde01.report_check import check_report, check_rendering  # noqa: E402
from vectorfile import apply_ops, expand_run  # noqa: E402

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


def _select(report, key):
    if key.startswith("obl:"):
        ident, _, path = key[4:].partition(".")
        iid, _, tid = ident.partition("/")
        ob = next((o for o in report["obligations"] if o["instruction_id"] == iid and o["target_id"] == tid), None)
        if ob is None:
            return _MISSING
        if path == "has_diag":
            return sorted({d["code"] for d in ob["diagnostics"]})
        if path == "enforcement.has_diag":
            return sorted({d["code"] for d in ob["enforcement"]["diagnostics"]})
        return _dig(ob, path)
    if key.startswith("instr:"):
        iid, _, path = key[6:].partition(".")
        e = next((x for x in report["instructions"] if x["instruction_id"] == iid), None)
        if e is None:
            return _MISSING
        if path == "zero_obligation_condition_present":
            return bool(e.get("zero_obligation_condition"))
        return _dig(e, path)
    if key.startswith("claim:"):
        cid, _, path = key[6:].partition(".")
        c = next((x for x in report["claims"] if x["claim_id"] == cid), None)
        if c is None:
            return _MISSING
        if path == "condition":
            return sorted(x["predicate"] for x in c["conditions"])
        if path == "has_scope_fields":
            sc = c["claim_scope"]
            return isinstance(sc.get("instructions"), list) and all(sc.get(k) not in (None, [], "") for k in ("boundaries", "cutoff", "fact"))
        return _dig(c, path)
    if key.startswith("receiver:"):
        rid, _, path = key[9:].partition(".")
        return _dig(report["record_accounting"]["receiver_records"].get(rid, {}), path) \
            if rid in report["record_accounting"]["receiver_records"] else _MISSING
    if key.startswith("input:"):
        rid, _, path = key[6:].partition(".")
        return _dig(report["record_accounting"]["inputs"].get(rid, {}), path) \
            if rid in report["record_accounting"]["inputs"] else _MISSING
    if key.startswith("op:"):
        oid, _, path = key[3:].partition(".")
        op = next((x for x in report["operations"] if x["operation_id"] == oid), None)
        if op is None:
            return _MISSING
        if path.startswith("fact:"):
            f = next((x for x in op["facts"] if x["boundary"] == path[5:]), None)
            return f["relation_to_activation"] if f else _MISSING
        return _dig(op, path)
    if key.startswith("path:"):
        pid, _, path = key[5:].partition(".")
        p = next((x for x in report["intermediary_paths"] if x["path_id"] == pid), None)
        if p is None:
            return _MISSING
        if path == "hop0":
            return p["hops"][0]["result"]
        return _dig(p, path)
    if key.startswith("exclusions."):
        rule, _, path = key[11:].partition(".")
        e = next((x for x in report["exclusions"] if x["rule"] == rule), None)
        return _dig(e, path) if e else _MISSING
    if key.startswith("non_claim:"):
        nc = next((x for x in report["non_claims"] if x["property"] == key[10:]), None)
        return nc["status"] if nc else _MISSING
    if key == "structural.has_blocker":
        return sorted({b["code"] for b in report["structural"]["pass_blockers"]})
    if key == "run.errors_include":
        return sorted({e["requirement"] for e in report["run"]["errors"]})
    return _dig(report, key)


def _match(key, want, got):
    if key.endswith(("has_diag", "has_blocker", "errors_include", ".condition")):
        return got is not _MISSING and want in got
    return got == want


def _check_run(report, run, expect):
    fails, seen = [], {}
    for key, want in expect.items():
        if key == "check":
            got = sorted({v["requirement"] for v in check_report(report) + check_rendering(render_summary(report))})
        elif key == "deterministic_under_reorder":
            r2 = copy.deepcopy(run)
            r2["records"] = list(reversed(r2["records"]))
            other = reconcile(r2)
            got = ([(o["instruction_id"], o["target_id"], o["disposition"]) for o in report["obligations"]] ==
                   [(o["instruction_id"], o["target_id"], o["disposition"]) for o in other["obligations"]]
                   and report["structural"]["structural_result"] == other["structural"]["structural_result"])
        else:
            got = _select(report, key)
        seen[key] = None if got is _MISSING else got
        if not _match(key, want, got):
            fails.append(f"{key}: expected {want!r}, got {seen[key]!r}")
    return fails, seen


def expand(vec, base):
    """A vector from the compact file form back to the full input."""
    v = copy.deepcopy(vec)
    bp, bf = base["base_profile"], base["base_frozen"]
    t, inp = v["type"], v["input"]
    if t == "profile":
        from vectorfile import merge_patch  # noqa: PLC0415
        v["input"] = merge_patch(bp, inp["profile_patch"])
    elif t == "run":
        v["input"] = expand_run(inp, bp, bf)
    elif t == "versions":
        v["input"] = {"run": expand_run(inp["run"], bp, bf), "cutoffs": inp["cutoffs"]}
    elif t in ("report_check", "render_check") and "from_run" in inp:
        v["input"] = dict(inp, from_run=expand_run(inp["from_run"], bp, bf))
    return v


def evaluate(vec):
    """Return (passed, failures, observed). ``vec`` is a full (expanded) vector."""
    t, inp, expect = vec["type"], vec["input"], vec["expect"]
    if t == "profile":
        errs = sorted({e["requirement"] for e in validate_profile(inp)})
        if "errors" in expect:
            fails = [] if errs == expect["errors"] else [f"errors: expected {expect['errors']}, got {errs}"]
        else:
            fails = [f"errors_include: {r} not in {errs}" for r in expect["errors_include"] if r not in errs]
        return not fails, fails, {"errors": errs}
    if t in ("report_check", "render_check"):
        if t == "report_check":
            rep = apply_ops(reconcile(inp["from_run"]), inp["ops"])
            got = sorted({v["requirement"] for v in check_report(rep)})
        else:
            text = inp["text"] if "text" in inp else render_summary(reconcile(inp["from_run"]))
            got = sorted({v["requirement"] for v in check_rendering(text)})
        if "violations" in expect:
            fails = [] if got == expect["violations"] else [f"violations: expected {expect['violations']}, got {got}"]
        else:
            fails = [f"violations_include: {r} not in {got}" for r in expect["violations_include"] if r not in got]
        return not fails, fails, {"violations": got}
    if t == "run":
        report = reconcile(inp)
        fails, seen = _check_run(report, inp, expect)
        return not fails, fails, seen
    if t == "versions":
        reports = reconcile_versions(inp["run"], inp["cutoffs"])
        fails, seen = [], {}
        for key, want in expect.items():
            v, _, sel = key.partition(".")
            n = int(v[1:])
            if sel == "previous_is_v0":
                got = reports[n]["run"]["previous_report_digest"] == reports[0]["report_digest"]
            else:
                got = _select(reports[n], sel)
            seen[key] = None if got is _MISSING else got
            if not _match(sel, want, got):
                fails.append(f"{key}: expected {want!r}, got {seen[key]!r}")
        return not fails, fails, seen
    return False, [f"unknown vector type {t}"], {}
