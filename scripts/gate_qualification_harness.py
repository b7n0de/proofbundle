#!/usr/bin/env python3
"""Gate Qualification Harness (makellose-500 Spur 1). Evaluates the GATES, not the product: each of the
15 mandatory counter-proof classes is SEEDED as a known defect and the responsible gate must DETECT it.
Acceptance is 15/15 detected WITH a green positive control per gate (a guard that rejects everything is
not a gate). One surviving preregistered counter-proof strips that gate of its release power.

Maps the 15 classes to the three reconstructed gates:
  type_confusion_gate (F1/F3/F4/F5): empty population, vanished/parser/import surface, nested-leaf,
    string|path on a dict|str primary, shared-payload mutation, comment-as-coverage, inventory disagreement.
  pre_tag_audit_gate  (F6): copied/bare attestation line, wrong subject digest, unsigned/untrusted receipt.
  audit_candidate_matrix (F2/F7): PENDING_JUSTIFIED, DATA_BLOCKED, unknown verdict, negated-keyword decoy.

Spur-2 Linse A note (rounds 1-3): cc01/cc02 OBSERVE gate.evaluate() (they were vacuous re-transcriptions
of the rule); class 15 is a distinct inventory-disagreement counter-example (it duplicated cc10); and
cc15-cc22 bind acceptance to evaluate()'s HEADLINE verdict for EVERY release-deciding detection wiring and
completeness sub-term, each with a MINIMAL seed reachable through ONE wiring only:
  never_raise: nested-leaf (16), whole-arg (17), str_matrix/F5 (18), NON_JSON/F3 (19);
  completeness: population>0 (01), evaluated==population (20), not parse_skips (02),
  and inventories_agree's THREE conjuncts — not only_ast (15), not only_runtime (21),
  not runtime_import_errors (22); nested DEPTH-2 traversal (23, real _field_names path). (import_error==0 /
  no_input==0 are redundant defensive terms of evaluated==population — see cc20's note.)
RESIDUAL (named, honest, P3): _field_names' subscript vs in-compare AST branches are not INDIVIDUALLY
isolated — a subscript on a missing key raises KeyError (still a crash), so a crash-critical field cannot
be extracted via subscript-ONLY without an in-compare/.get guard that re-extracts it (the Gates lens noted
the same: 'not each given a separate real-module crasher'). cc23 binds depth-2 + the real _field_names
extraction as a group (a total extraction break reddens it); the finer branch split is future-regression
detection of a field-extraction sub-mechanism, not a live defect.
Rounds 2-4 each found a wiring bound only IN ISOLATION or by a NON-minimal seed (cc04/05/07 tested helpers;
cc15's old whole-inventory seed tripped only_ast AND only_runtime at once) — so stripping one term stayed
green. Every term is now bound + proven isolated by the wiring-strip meta-test in the anchor test.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import type_confusion_gate as tcg  # noqa: E402
import audit_candidate_matrix as acm  # noqa: E402
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, verify_receipt  # noqa: E402
from proofbundle.errors import BundleFormatError  # noqa: E402


def _kp():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    p = Ed25519PrivateKey.generate()
    return p, base64.b64encode(p.public_key().public_bytes_raw()).decode()


# ---- type_confusion_gate counter-examples (a gate helper must CATCH a seeded raw crash / gap) --------
def cc01_empty_population():
    # OBSERVE the gate, never re-transcribe its rule (Spur-2 Linse A: cc01/cc02 were vacuous — they
    # recomputed `0>0` and Python's own ast.parse without touching the gate). Seed an empty inventory and
    # confirm evaluate() ITSELF computes population_complete=False; a future regression that drops the
    # population>0 guard turns THIS red.
    orig_disc, orig_rt = tcg.discover_python_verify_functions, tcg._runtime_inventory
    tcg.discover_python_verify_functions = lambda: {}
    tcg._runtime_inventory = lambda: (set(), [])
    try:
        r = tcg.evaluate()
    finally:
        tcg.discover_python_verify_functions, tcg._runtime_inventory = orig_disc, orig_rt
    detected = r["population_complete"] is False and r["population_size"] == 0
    return detected, f"gate.evaluate() on an empty population -> population_complete={r['population_complete']} (fail-closed)"


def cc02_vanished_or_parser_surface():
    # OBSERVE the gate's OWN parse-skip detection on a seeded unparseable file under the scanned root,
    # THEN confirm evaluate() propagates it to population_complete=False (the `and not parse_skips` clause).
    # discover silently skips a SyntaxError file (its verify_* vanish) — the gate must FAIL, not skip.
    import tempfile
    orig_src = tcg.SRC
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "seeded_broken.py").write_text("def broken(:\n")  # a real SyntaxError source
        tcg.SRC = Path(d)
        try:
            skips = tcg._parse_skips()
        finally:
            tcg.SRC = orig_src
    detected_scan = any("seeded_broken.py" in x for x in skips)
    orig_ps = tcg._parse_skips
    tcg._parse_skips = lambda: ["seeded_broken.py: SyntaxError: seeded"]
    try:
        r = tcg.evaluate()
    finally:
        tcg._parse_skips = orig_ps
    detected = detected_scan and r["population_complete"] is False
    return detected, f"gate._parse_skips detects the seeded file ({detected_scan}) -> evaluate.complete={r['population_complete']}"


def cc03_import_error_surface():
    info = tcg._classify("proofbundle.does_not_exist.verify_ghost")
    return info["status"] == "IMPORT_ERROR", f"unresolvable surface -> {info['status']} (counted, --strict fails)"


def cc04_nested_leaf_crash():
    def victim(x):  # a form-valid outer object whose inner 'status' leaf is hashed unguarded
        if not isinstance(x, dict):
            raise BundleFormatError("shape")
        return x["status"] in {"ok", "bad"}  # unhashable leaf -> raw TypeError
    tcg._FIELD_CACHE["__hq__"] = ["status"]
    try:
        victim.__module__ = "__hq__"
        viol, _n, _t = tcg._exercise_nested(victim, {}, "x", False)
    finally:
        tcg._FIELD_CACHE.pop("__hq__", None)
    return bool(viol), f"nested-leaf matrix caught {len(viol)} raw crash(es) on a form-valid outer object"


def cc05_string_on_dict_or_str_primary():
    def victim(x):  # a dict|str primary that raw-OSErrors on a string (the F5 'correct API' fallacy)
        if isinstance(x, str):
            raise OSError("bad path")
        return False
    viol, _ = tcg._exercise(victim, {}, tcg._COMPACT_STR_PAYLOADS, "x", False)
    return bool(viol), f"string matrix caught {len(viol)} raw OSError(s) on a dict|str primary"


def cc06_shared_payload_mutation():
    # a mutating verifier must not corrupt the shared payload for a later one (deepcopy per call).
    seen = {}

    def mutator(x):
        if isinstance(x, dict):
            x["poisoned"] = True
        return False

    def victim(x):
        seen["poisoned"] = isinstance(x, dict) and x.get("poisoned")
        return False
    payloads = [{"a": 1}]
    tcg._exercise(mutator, {}, payloads, "x", False)
    tcg._exercise(victim, {}, payloads, "x", False)
    # if deepcopy works, victim never sees the mutation AND the shared list is unchanged
    detected = not seen.get("poisoned") and payloads == [{"a": 1}]
    return detected, "deepcopy per call: a mutating verifier cannot poison a later one's payload"


def cc07_comment_as_coverage():
    # a NON_JSON surface is EXERCISED, not delegated by a comment. Detection = it is not silently skipped.
    info = tcg._classify("proofbundle.merkle.verify_inclusion")
    return "fn" in info and info["status"] == "NON_JSON", "NON_JSON surface is resolved+exercised, no comment-delegation"


# ---- pre_tag_audit_gate counter-examples --------------------------------------------------------------
_TREE, _GATE, _VER = "a" * 40, "b" * 64, "5.0.0"


def _receipt(priv, pub, **over):
    r = {"schema": RECEIPT_SCHEMA, "version": _VER, "subject_tree_digest": _TREE,
         "gate_source_digest": _GATE, "audit_command": "c", "audit_exit_code": 0,
         "audit_output_digest": "d" * 64, "runner_identity": "ci", "produced_at": "t"}
    r.update(over)
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub
    return r


def _v(receipt, trusted):
    ok, _ = verify_receipt(receipt, trusted_pubkeys=trusted, expected_version=_VER,
                           subject_tree_digest=_TREE, gate_source_digest=_GATE)
    return ok


def cc08_bare_or_copied_attestation_line():
    ok = _v("pre-tag-adversarial-audit: RUN | version=5.0.0", ["x"])  # a bare prose line is not a receipt
    return not ok, "a bare/copied prose attestation line does not grant the pass (P6)"


def cc09_wrong_subject_digest():
    priv, pub = _kp()
    r = _receipt(priv, pub, subject_tree_digest="f" * 40)
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    return not _v(r, [pub]), "a receipt bound to another tree cannot attest this one"


def cc10_unsigned_or_untrusted_receipt():
    priv, pub = _kp()
    return not _v(_receipt(priv, pub), []), "no trusted key pinned -> fail-closed (unbound substitute check)"


# ---- audit_candidate_matrix counter-examples --------------------------------------------------------
def _acm_ready(rows, pin="bound"):
    reg = [(cid, 1, cid, (lambda v=v: (v, "s"))) for cid, v in rows]
    orig_c, orig_p = acm.CHECKS, acm.version_pin_binding
    acm.CHECKS = reg
    acm.version_pin_binding = lambda _v: {"state": pin, "detail": "t"}
    try:
        return acm.evaluate()["audit_candidate_ready"]
    finally:
        acm.CHECKS, acm.version_pin_binding = orig_c, orig_p


def cc11_pending_justified_internal():
    return not _acm_ready([("C2.1", acm.PASS), ("C7.3", acm.PENDING), ("EXT.1", acm.EXTERNAL)]), \
        "internal PENDING_JUSTIFIED withholds readiness"


def cc12_data_blocked_internal():
    return not _acm_ready([("C2.1", acm.PASS), ("C6.3", acm.DATA_BLOCKED), ("EXT.1", acm.EXTERNAL)]), \
        "internal DATA_BLOCKED withholds readiness"


def cc13_unknown_verdict():
    return not _acm_ready([("C2.1", acm.PASS), ("C3.1", "WEIRD"), ("EXT.1", acm.EXTERNAL)]), \
        "an unknown verdict withholds readiness"


def cc14_negated_keyword_decoy():
    # the lexical checks are INFORMATIVE: a decoy PASS on them (incl. a negated-keyword sentence) plus a
    # single DATA_BLOCKED deciding check must still withhold readiness.
    rows = [(cid, acm.PASS) for cid in acm._INFORMATIVE_CHECKS] + [("C6.3", acm.DATA_BLOCKED), ("EXT.1", acm.EXTERNAL)]
    return not _acm_ready(rows), "lexical decoys are informative -> cannot grant readiness"


def cc15_inventory_disagreement():
    # inventories_agree conjunct `not only_ast` (Gates re-gate round 4: MINIMAL seed so this binds only_ast
    # ALONE). runtime = ast minus one surface -> only_ast={that one}, only_runtime=[], errors=[].
    r = _seed_inventory(["proofbundle.a.verify_x", "proofbundle.a.verify_y"], ["proofbundle.a.verify_x"], [])
    detected = (r["population_complete"] is False and bool(r["inventory_only_ast"])
                and not r["inventory_only_runtime"] and not r["inventory_runtime_import_errors"])
    return detected, f"only_ast disagreement -> only_ast={r['inventory_only_ast']}, complete={r['population_complete']}"


def cc21_only_runtime_disagreement():
    # inventories_agree conjunct `not only_runtime` (MINIMAL): runtime = ast plus one phantom the AST lacks.
    r = _seed_inventory(["proofbundle.a.verify_x"], ["proofbundle.a.verify_x", "proofbundle.a.verify_phantom"], [])
    detected = (r["population_complete"] is False and bool(r["inventory_only_runtime"])
                and not r["inventory_only_ast"] and not r["inventory_runtime_import_errors"])
    return detected, f"only_runtime disagreement -> only_runtime={r['inventory_only_runtime']}, complete={r['population_complete']}"


def cc22_runtime_import_errors():
    # inventories_agree conjunct `not runtime_import_errors` (MINIMAL): inventories equal, but a submodule
    # failed to import at runtime — a broken surface must withhold completeness, not be silently dropped.
    r = _seed_inventory(["proofbundle.a.verify_x"], ["proofbundle.a.verify_x"], ["proofbundle.brokenmod: ImportError"])
    detected = (r["population_complete"] is False and bool(r["inventory_runtime_import_errors"])
                and not r["inventory_only_ast"] and not r["inventory_only_runtime"])
    return detected, f"runtime_import_errors -> errors={r['inventory_runtime_import_errors']}, complete={r['population_complete']}"


def _make_real_module_victim():
    """Gates re-gate round 5: cc16/cc04 seed _FIELD_CACHE and crash at DEPTH-1, leaving the nested wiring's
    DEPTH-2 traversal (_exercise_nested v2) and the real _field_names AST extraction unqualified — a one-line
    `return v1` (drop v2) blinds never_raise_ok for a depth-2-only crasher while the harness stays green.
    This builds a REAL importable proofbundle.* module (so _field_names reads its SOURCE, no cache seed)
    whose verifier survives every depth-1 payload and raw-crashes ONLY at depth-2. Returns (module, dir)."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "regate_seed_depth2.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "def verify_regate_depth2(pred):\n"
            "    runs = pred.get('runs')\n"                       # .get branch -> field 'runs'
            "    if isinstance(runs, list):\n"
            "        for entry in runs:\n"
            "            if isinstance(entry, dict):\n"
            "                _ = entry.get('status') in {'ok', 'bad'}\n"   # .get 'status'; unhashable -> depth-2 crash
            "    return False\n")
    spec = importlib.util.spec_from_file_location("proofbundle.regate_seed_depth2", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["proofbundle.regate_seed_depth2"] = mod
    spec.loader.exec_module(mod)
    return mod, d


def cc23_nested_depth2_observed():
    # NESTED DEPTH-2 traversal (v2) + the real _field_names extraction path (Gates re-gate round 5). Strip
    # the depth-2 wiring (`return v1` instead of `v1 + v2`) -> a depth-2-only crash is missed -> THIS reddens.
    # Strip _field_names' extraction -> no fields -> no nested payload -> no crash -> THIS reddens.
    mod, d = _make_real_module_victim()
    try:
        r = _seed_evaluate({"status": "IN_SCOPE", "fn": mod.verify_regate_depth2, "extra_kwargs": {},
                            "payloads": [], "primary_name": "pred", "primary_kwonly": False, "str_matrix": []})
    finally:
        tcg._FIELD_CACHE.pop("proofbundle.regate_seed_depth2", None)
        sys.modules.pop("proofbundle.regate_seed_depth2", None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"nested depth-2 (real _field_names) -> never_raise_ok={r['never_raise_ok']}, raw={r['raw_exception_count']}"


# ---- Gates re-gate ROUND 3 fix-the-CLASS: bind EVERY release-deciding detection wiring to evaluate() ----
# The round-2 fix added ONE observing class (cc16, nested-leaf). The re-gate showed the SIBLING wirings —
# whole-arg _exercise, the str_matrix (F5), the NON_JSON exercise (F3), and the completeness term
# (evaluated==population) — were still bound only in isolation (cc04/05/07 test the helpers), so stripping
# any one stayed 16/16 green. Generalise cc16's technique: one class per release-deciding wiring, each
# seeding a defect reachable ONLY through that wiring and observing the FULL evaluate() headline verdict.
# MAINTENANCE INVARIANT: a NEW detection wiring in type_confusion_gate.evaluate() needs a NEW class here.


class _Boom(RuntimeError):
    pass


def _seed_evaluate(info, *, field_cache_mod=None, field_cache_fields=None):
    """Drive the FULL tcg.evaluate() with a single seeded surface classified as `info` (a copy per call),
    so a class OBSERVES evaluate()'s headline verdict for ONE detection wiring. AST/runtime inventories are
    made to agree (both carry the phantom) so only the targeted term can move the verdict."""
    saved = (tcg.discover_python_verify_functions, tcg._runtime_inventory, tcg._classify, tcg._parse_skips)
    if field_cache_mod:
        tcg._FIELD_CACHE[field_cache_mod] = field_cache_fields
    tcg.discover_python_verify_functions = lambda: {"proofbundle.seeded.verify_x": None}
    tcg._runtime_inventory = lambda: ({"proofbundle.seeded.verify_x"}, [])
    tcg._parse_skips = lambda: []
    tcg._classify = lambda q, i=None: dict(info)
    try:
        return tcg.evaluate()
    finally:
        (tcg.discover_python_verify_functions, tcg._runtime_inventory, tcg._classify, tcg._parse_skips) = saved
        if field_cache_mod:
            tcg._FIELD_CACHE.pop(field_cache_mod, None)


def _v_nested(x):
    if not isinstance(x, dict):
        raise BundleFormatError("shape")
    return x["status"] in {"ok", "bad"}   # unhashable inner leaf -> raw TypeError, only the nested matrix finds it


def _v_wholearg(x):
    if not isinstance(x, dict):
        raise _Boom("raw crash on a non-dict WHOLE argument")   # only the whole-arg matrix reaches this
    return False


def _v_str(x):
    if isinstance(x, str):
        raise _Boom("raw crash on a string primary")            # only the str_matrix reaches this
    return False


def _v_nonjson(x):
    if not isinstance(x, dict):
        raise _Boom("raw crash on a non-json primary")          # only the NON_JSON _exercise reaches this
    return False


def _v_benign(x):
    return False   # a clean verify: returns a verdict, never crashes (for the inventory-disagreement seeds)


def _seed_inventory(ast_names, runtime_names, runtime_errors):
    """Drive evaluate() with a CONTROLLED AST-vs-runtime inventory, every surface benign IN_SCOPE so the
    ONLY term that can withhold population_complete is the inventories_agree conjunct under test. Gates
    re-gate round 4: cc15's old whole-inventory seed tripped only_ast AND only_runtime at once, so no
    conjunct was isolated (stripping one still left cc15 detecting via its sibling). A MINIMAL seed per
    conjunct fixes that: only_ast (runtime = ast minus one), only_runtime (runtime = ast plus one),
    runtime_import_errors (runtime = ast, with an import error)."""
    saved = (tcg.discover_python_verify_functions, tcg._runtime_inventory, tcg._classify, tcg._parse_skips)
    tcg.discover_python_verify_functions = lambda: {n: None for n in ast_names}
    tcg._runtime_inventory = lambda: (set(runtime_names), list(runtime_errors))
    tcg._parse_skips = lambda: []
    tcg._classify = lambda q, i=None: {"status": "IN_SCOPE", "fn": _v_benign, "extra_kwargs": {},
                                       "payloads": [{}], "primary_name": "x", "primary_kwonly": False,
                                       "str_matrix": []}
    try:
        return tcg.evaluate()
    finally:
        (tcg.discover_python_verify_functions, tcg._runtime_inventory, tcg._classify, tcg._parse_skips) = saved


def cc16_evaluate_never_raise_verdict_observed():
    # NESTED-leaf wiring + the headline never_raise_ok/raw verdict (Gates re-gate round 2).
    _v_nested.__module__ = "proofbundle_seeded_cc16"
    r = _seed_evaluate({"status": "IN_SCOPE", "fn": _v_nested, "extra_kwargs": {}, "payloads": [],
                        "primary_name": "x", "primary_kwonly": False, "str_matrix": []},
                       field_cache_mod="proofbundle_seeded_cc16", field_cache_fields=["status"])
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"nested-leaf wiring -> never_raise_ok={r['never_raise_ok']}, raw={r['raw_exception_count']}"


def cc17_wholearg_wiring_observed():
    # WHOLE-ARG _exercise wiring: strip it and this class alone reddens (nested/str untouched).
    r = _seed_evaluate({"status": "IN_SCOPE", "fn": _v_wholearg, "extra_kwargs": {},
                        "payloads": [None, 0, [], "s", 5], "primary_name": "x", "primary_kwonly": False,
                        "str_matrix": []})
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"whole-arg wiring -> never_raise_ok={r['never_raise_ok']}, raw={r['raw_exception_count']}"


def cc18_str_matrix_wiring_observed():
    # STR-MATRIX (F5, Union[dict,str] string primary) wiring: payloads carry NO str, str_matrix does.
    r = _seed_evaluate({"status": "IN_SCOPE", "fn": _v_str, "extra_kwargs": {},
                        "payloads": [None, {}, {"a": 1}], "primary_name": "x", "primary_kwonly": False,
                        "str_matrix": tcg._COMPACT_STR_PAYLOADS})
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"str-matrix wiring -> never_raise_ok={r['never_raise_ok']}, raw={r['raw_exception_count']}"


def cc19_nonjson_exercise_wiring_observed():
    # NON_JSON (F3) exercise wiring: a NON_JSON primary that raw-crashes must be EXERCISED, not skipped.
    r = _seed_evaluate({"status": "NON_JSON", "fn": _v_nonjson, "extra_kwargs": {},
                        "payloads": tcg._BYTES_PAYLOADS, "primary_name": "x", "primary_kwonly": False,
                        "primary_kind": "bytes", "notes": "seeded non_json crasher"})
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"NON_JSON wiring -> never_raise_ok={r['never_raise_ok']}, raw={r['raw_exception_count']}"


def cc20_completeness_wiring_observed():
    # COMPLETENESS (evaluated==population) wiring: an unevaluated NEEDS_FIXTURE surface must withhold
    # population_complete (a coverage gap is not a clean run). Strip the term -> completeness stays True.
    # REDUNDANCY NOTE (un round-3 flagged import_error==0 as "unbound"; verified redundant): every
    # unresolved status — NEEDS_FIXTURE, IMPORT_ERROR, NO_INPUT — is NOT counted in `evaluated`, so any one
    # forces evaluated<population and this class already catches it. The population_complete terms
    # import_error==0 and no_input==0 are therefore DEFENSIVE REDUNDANCY of evaluated==population, not
    # independent wirings; a dedicated class would share this mechanism and break one-class-per-strip
    # isolation. The redundancy invariant is pinned by test_unresolved_surfaces_all_reduce_evaluated.
    r = _seed_evaluate({"python_ref": "proofbundle.seeded.verify_x", "status": "NEEDS_FIXTURE",
                        "notes": "seeded: extra required arg has no benign fixture"})
    detected = r["population_complete"] is False and r["evaluated_count"] < r["population_size"]
    return detected, f"completeness wiring -> population_complete={r['population_complete']}, evaluated={r['evaluated_count']}/{r['population_size']}"


# ---- Gates re-gate ROUND 6 fix-the-CLASS: bind the REAL _classify ROUTING to evaluate() --------------
# The round-5 re-gate (WIDERLEGT) showed cc16-cc23 bind the never-raise wirings only through a MOCKED
# _classify (_seed_evaluate sets status="IN_SCOPE" directly). The REAL router that ENABLES nested
# detection — _is_json_primary's Any/dict->IN_SCOPE branch — was therefore unbound: a one-token strip of
# `"Any" in text or ` reclassifies an Any-primary surface IN_SCOPE->NON_JSON (no nested matrix, crash
# missed) while the harness stayed 23/23 green. Same class: the bytes->NON_JSON exclusion and the
# RecursionError handler. FIX: three classes that plant a REAL importable proofbundle.* module and drive
# the FULL evaluate() with the REAL _classify (only discover/_runtime_inventory/_parse_skips patched,
# NEVER _classify) — so the real routing is the ONLY thing that can carry the detection.
# MAINTENANCE INVARIANT: a NEW routing branch in _classify/_is_json_primary/_primary_kind needs a NEW
# class here that reaches it through the real router, not a seeded status.

def _real_router_victim(modname: str, src: str):
    """Write a REAL importable proofbundle.<modname> to a tempdir and register it in sys.modules, so the
    gate's REAL resolve_surface(qname) imports it and the REAL _classify routes it by its real signature.
    Returns (qname, full_module_name, tmpdir). Caller cleans up _FIELD_CACHE + sys.modules + tmpdir."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, f"{modname}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    full = f"proofbundle.{modname}"
    spec = importlib.util.spec_from_file_location(full, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    fn_name = next(line.split("(")[0].removeprefix("def ").strip()
                   for line in src.splitlines() if line.startswith("def "))
    return f"{full}.{fn_name}", full, d


def _seed_evaluate_real_router(qname: str):
    """Drive the FULL tcg.evaluate() scoped to ONE real surface with the REAL _classify (NOT mocked): only
    discover/_runtime_inventory/_parse_skips are patched (both inventories carry the phantom so
    inventories_agree stays True). The REAL routing is thus the ONLY thing that can carry the verdict —
    unlike _seed_evaluate, which patches tcg._classify and therefore never exercises the router."""
    saved = (tcg.discover_python_verify_functions, tcg._runtime_inventory, tcg._parse_skips)
    tcg.discover_python_verify_functions = lambda: {qname: None}
    tcg._runtime_inventory = lambda: ({qname}, [])
    tcg._parse_skips = lambda: []
    try:
        return tcg.evaluate()
    finally:
        (tcg.discover_python_verify_functions, tcg._runtime_inventory, tcg._parse_skips) = saved


_CC24_SRC = '''from typing import Any
_ALLOWED = {"ok", "bad"}
def validate_cc24_any_route(obj: Any):
    """Any-primary (name NOT in _JSON_PRIMARY_NAMES) with a depth-2 nested-leaf membership defect. Routes
    IN_SCOPE ONLY via _is_json_primary's `"Any" in text`; strip that token -> NON_JSON -> crash missed."""
    if not isinstance(obj, dict):
        return ["shape"]
    runs = obj.get("runs")
    if isinstance(runs, list):
        for entry in runs:
            if isinstance(entry, dict):
                if entry.get("status") not in _ALLOWED:
                    return ["bad"]
    return []
'''

_CC25_SRC = '''def validate_cc25_bytes_route(bundle: bytes):
    """bytes primary whose NAME ('bundle') IS in _JSON_PRIMARY_NAMES; routes NON_JSON ONLY via
    _is_json_primary's `"bytes" in text` exclusion. Strip that token -> IN_SCOPE by name -> JSON matrix
    (no bytes payload) -> the bytes crash is missed."""
    if isinstance(bundle, (bytes, bytearray)):
        raise OSError("raw crash on a bytes primary")
    return []
'''

_CC26_SRC = '''def validate_cc26_recursion(bundle: dict):
    """Unbounded recursion -> RecursionError, which _exercise MUST count as a violation (a bounded-depth
    defence is owed). Strip `except RecursionError: violations.append(...)` -> swallowed -> missed."""
    return validate_cc26_recursion(bundle)
'''


def cc24_any_inscope_routing_real():
    # REAL _classify routing: an Any-annotated primary must route IN_SCOPE and receive the nested matrix.
    # Strip `"Any" in text or ` from _is_json_primary -> NON_JSON -> nested crash missed -> THIS reddens.
    qname, full, d = _real_router_victim("cc24_any_route", _CC24_SRC)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, (f"real Any->IN_SCOPE routing -> in_scope={r.get('in_scope')} "
                      f"never_raise_ok={r['never_raise_ok']} raw={r['raw_exception_count']}")


def cc25_bytes_nonjson_routing_real():
    # REAL _classify routing: a bytes primary must be EXCLUDED from the JSON matrix and exercised with the
    # bytes NON_JSON matrix. Strip `"bytes" in text or ` -> IN_SCOPE by name -> JSON matrix (no bytes) ->
    # the bytes crash missed -> THIS reddens.
    qname, full, d = _real_router_victim("cc25_bytes_route", _CC25_SRC)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, (f"real bytes->NON_JSON routing -> non_json={r.get('non_json')} "
                      f"never_raise_ok={r['never_raise_ok']} raw={r['raw_exception_count']}")


def cc26_recursionerror_routing_real():
    # REAL evaluate(): a verifier that recurses unbounded raises RecursionError, which _exercise MUST count
    # as a violation. Strip the RecursionError->violations.append -> swallowed -> missed -> THIS reddens.
    qname, full, d = _real_router_victim("cc26_recursion", _CC26_SRC)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, (f"real RecursionError handling -> never_raise_ok={r['never_raise_ok']} "
                      f"raw={r['raw_exception_count']}")


# ---- Gates re-gate ROUND 7 fix-the-CLASS: bind EVERY IN_SCOPE routing token, not just "Any" ----------
# Round 6 bound the "Any" token (cc24) but that was itself an INSTANCE fix: _is_json_primary routes a
# JSON-object primary IN_SCOPE via SEVEN string tokens (dict/Dict/Mapping/list/List/Any/Union[dict), and
# stripping any of the other five leaves a nested-leaf surface of that annotation routed NON_JSON (no
# nested matrix, crash missed) while the harness stayed 26/26 — the exact Any-hole class, five siblings
# over. ("Union[dict" is dominated by "dict": any annotation that matches it also matches "dict", so it is
# redundant, not a separate reachable branch.) cc27 binds the WHOLE token set: one real-module plant per
# token, annotated to route IN_SCOPE ONLY via that token, each with the depth-2 nested-leaf defect; strip
# ANY token -> its plant routes NON_JSON -> nested crash missed -> cc27 reddens. A COVERAGE GUARD test
# asserts this table lists every IN_SCOPE token the gate actually has, so a NEW token cannot be added
# without a binding (generator-hardening, not a point fixture).

# (token-in-_is_json_primary, annotation-source that str()-matches ONLY that token)
_INSCOPE_ROUTING_TOKENS = [
    ("dict", "dict"),        # str(dict)      = "<class 'dict'>"
    ("Dict", "Dict"),        # str(Dict)      = "typing.Dict"
    ("Mapping", "Mapping"),  # str(Mapping)   = "typing.Mapping"
    ("list", "list"),        # str(list)      = "<class 'list'>"
    ("List", "List"),        # str(List)      = "typing.List"
    ("Any", "Any"),          # str(Any)       = "typing.Any"
]

_CC27_HDR = "from typing import Dict, List, Mapping, Any, Union\n_ALLOWED = {\"ok\", \"bad\"}\n"
_CC27_TMPL = '''def validate_cc27_{tok}(obj: {ann}):
    """Routes IN_SCOPE ONLY via _is_json_primary's `"{tok}" in text`; strip that token -> NON_JSON -> the
    depth-2 nested-leaf crash is missed. Annotation str() matches only "{tok}"."""
    if not isinstance(obj, dict):
        return ["shape"]
    runs = obj.get("runs")
    if isinstance(runs, list):
        for entry in runs:
            if isinstance(entry, dict):
                if entry.get("status") not in _ALLOWED:
                    return ["bad"]
    return []
'''


def _cc27_probe_one(tok, ann):
    src = _CC27_HDR + _CC27_TMPL.format(tok=tok, ann=ann)
    qname, full, d = _real_router_victim(f"cc27_{tok.lower()}_{ann.lower().replace('[','_').replace(']','').replace(',','_').replace(' ','')}", src)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    return (r["never_raise_ok"] is False and r["raw_exception_count"] > 0), r.get("in_scope")


def cc27_all_inscope_routing_tokens_real():
    # fix-the-CLASS: bind EVERY IN_SCOPE routing token through the real _classify. detected iff ALL tokens'
    # nested-leaf plants are caught; strip any token -> its plant routes NON_JSON -> missed -> cc27 reddens.
    missed = []
    for tok, ann in _INSCOPE_ROUTING_TOKENS:
        caught, in_scope = _cc27_probe_one(tok, ann)
        if not caught:
            missed.append(f"{tok}(in_scope={in_scope})")
    detected = not missed
    return detected, ("all IN_SCOPE routing tokens bound"
                      if detected else "UNBOUND IN_SCOPE token(s): " + ", ".join(missed))


# ---- Gates re-gate ROUND 7 fix-the-CLASS: bind the NON_JSON kind routing (not just bytes/cc25) ---------
# The IN_SCOPE side is bound by cc27. The NON_JSON side has the SAME class of holes: _is_json_primary's
# exclusion tokens (bytes/int/float/str) decide NON_JSON, and _primary_kind (bytes/int/path/compact_str)
# decides WHICH never-raise matrix. Measured: stripping `text == "int"` sends an int-primary surface out
# of the int matrix and a huge-int raw crash is MISSED with NO fallback (the int matrix's 2**64 is unique).
# cc28 binds each NON_JSON kind through the real router: one real-module plant per kind that raw-crashes
# ONLY on a payload UNIQUE to that kind's matrix; mis-route it (strip the exclusion OR the _primary_kind
# branch) -> wrong matrix -> crash missed -> cc28 reddens. bytes stays additionally bound by cc25.

# (label, annotated-signature, crash-body reached ONLY by a payload unique to the correct kind matrix)
_NONJSON_KIND_PROBES = [
    ("int",  "obj_int: int",
     "if isinstance(obj_int, int) and not isinstance(obj_int, bool) and obj_int >= 2**64:\n"
     "        raise OverflowError('raw crash on a huge int')"),
    ("compact_str", "obj_str: str",
     "if isinstance(obj_str, str) and len(obj_str) >= 100000:\n"
     "        raise OSError('raw crash on a long compact string')"),
    ("path", "obj_path: str",
     "if isinstance(obj_path, str) and obj_path.startswith('/nonexistent'):\n"
     "        raise OSError('raw crash on a bad path')"),
    ("bytes", "obj_bytes: bytes",
     "if isinstance(obj_bytes, (bytes, bytearray)) and len(obj_bytes) >= (1 << 20):\n"
     "        raise OSError('raw crash on a 1 MiB byte blob')"),
]


def _cc28_probe_one(label, annsig, body):
    src = f"def validate_cc28_{label}({annsig}):\n    {body}\n    return []\n"
    qname, full, d = _real_router_victim(f"cc28_{label}", src)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    return (r["never_raise_ok"] is False and r["raw_exception_count"] > 0), r.get("non_json"), r.get("in_scope")


def cc28_all_nonjson_kind_routing_real():
    # fix-the-CLASS: bind every NON_JSON kind route through the real _classify. Each kind crashes ONLY on a
    # payload UNIQUE to its matrix; strip its exclusion or _primary_kind branch -> wrong matrix -> missed
    # -> cc28 reddens. detected iff ALL kinds caught.
    missed = []
    for label, annsig, body in _NONJSON_KIND_PROBES:
        caught, nj, isc = _cc28_probe_one(label, annsig, body)
        if not caught:
            missed.append(f"{label}(non_json={nj},in_scope={isc})")
    detected = not missed
    return detected, ("all NON_JSON kind routes bound"
                      if detected else "UNBOUND NON_JSON kind(s): " + ", ".join(missed))


_CC29_SRC = """def validate_cc29_nested_recursion(bundle: dict):
    if isinstance(bundle, dict) and "runs" in bundle:
        return validate_cc29_nested_recursion(bundle)
    return []
"""


def cc29_nested_recursionerror_real():
    # the NESTED-path RecursionError handler (distinct from cc26's whole-arg one): recurses ONLY when a
    # nested field is present, so only the nested matrix triggers it. Strip the nested except-append -> missed.
    qname, full, d = _real_router_victim("cc29_nested_recursion", _CC29_SRC)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"nested-path RecursionError -> never_raise_ok={r['never_raise_ok']} raw={r['raw_exception_count']}"


_CC30_SRC = """from typing import Union
def validate_cc30_union_str(bundle: Union[dict, str]):
    if isinstance(bundle, str):
        raise OSError("raw crash on a string primary of a Union[dict,str] surface")
    return []
"""


def cc30_str_matrix_assignment_real():
    # the str_matrix ASSIGNMENT in the real _classify (F5, L250): a Union[dict,str] primary crashing ONLY on
    # a string is caught ONLY by str_matrix=_COMPACT_STR_PAYLOADS. Strip the assignment (-> []) -> the string
    # crash is missed (whole-arg is _NONSTR, nested needs dict fields), harness stays green -> THIS reddens.
    # cc18 tests only the str_matrix CONSUMPTION via a MOCKED _classify; cc30 drives the REAL router.
    qname, full, d = _real_router_victim("cc30_union_str", _CC30_SRC)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"real str_matrix assignment (Union[dict,str]) -> never_raise_ok={r['never_raise_ok']} raw={r['raw_exception_count']}"


_CC31_SRC = """def validate_cc31_subscript(obj: dict):
    from proofbundle.errors import BundleFormatError
    if not isinstance(obj, dict):
        raise BundleFormatError("shape")
    if set(obj.keys()) != {"status"}:
        raise BundleFormatError("keys")
    return obj["status"] in {"ok", "bad"}
"""


def cc31_field_extraction_subscript_real():
    # the ast.Subscript branch of _field_names (round-9 re-gate WIDERLEGT): a strict exact-keys shape check
    # makes obj["status"] UNCONDITIONAL (no KeyError fallback), and "status" is reachable ONLY via the
    # subscript branch (the {"status"} set is an ast.Set; obj["status"] in {...} is a Compare whose LEFT is a
    # Subscript, not a Constant). cc23/24/27 extract via .get, cc29 via in-compare -- none via bare subscript.
    # Strip the subscript branch -> "status" not extracted -> no {status: unhashable} nested payload -> missed.
    qname, full, d = _real_router_victim("cc31_subscript", _CC31_SRC)
    try:
        r = _seed_evaluate_real_router(qname)
    finally:
        tcg._FIELD_CACHE.pop(full, None)
        sys.modules.pop(full, None)
        shutil.rmtree(d, ignore_errors=True)
    detected = r["never_raise_ok"] is False and r["raw_exception_count"] > 0
    return detected, f"_field_names subscript branch -> never_raise_ok={r['never_raise_ok']} raw={r['raw_exception_count']}"


def cc32_pretag_check_coverage():
    # round 12 (fix-the-class, un gegenlesung REJECT): EVERY release-deciding verify_receipt check must reject a
    # receipt valid EXCEPT that one thing -- the four binding fields (schema/version/gate_source/audit_exit) AND
    # the signer-trust (#8) and signature-verify (#10) checks (the named P3-2, now harness-bound). subject_tree=cc09,
    # no-trusted-key=cc10; #9 isinstance(sig,str) is inert -- subsumed by #10 fail-closed b64decode except (a785573f).
    priv, pub = _kp()
    priv2, pub2 = _kp()  # an untrusted signer carrying its OWN valid self-signature
    tampered = _receipt(priv, pub)
    tampered["signature"] = base64.b64encode(b"\x00" * 64).decode()  # valid b64, signature does not verify
    cases = {
        "version": _receipt(priv, pub, version="4.9.9"),
        "gate_source_digest": _receipt(priv, pub, gate_source_digest="f" * 64),
        "audit_exit_code": _receipt(priv, pub, audit_exit_code=1),
        "schema": _receipt(priv, pub, schema="wrong.receipt.schema"),
        "untrusted_signer": _receipt(priv2, pub2),  # #8: valid self-sig, signer not in trusted set
        "tampered_signature": tampered,             # #10: trusted signer, signature fails to verify
    }
    accepted = [k for k, r in cases.items() if _v(r, [pub])]
    return (not accepted), ("all valid-except-one release-deciding receipts rejected"
                            if not accepted else "WRONGLY ACCEPTED (unbound check): " + ", ".join(accepted))


CLASSES = [
    ("01_empty_population", "type_confusion", cc01_empty_population),
    ("02_vanished_or_parser_surface", "type_confusion", cc02_vanished_or_parser_surface),
    ("03_import_error_surface", "type_confusion", cc03_import_error_surface),
    ("04_nested_leaf", "type_confusion", cc04_nested_leaf_crash),
    ("05_string_on_dict_or_str", "type_confusion", cc05_string_on_dict_or_str_primary),
    ("06_shared_payload_mutation", "type_confusion", cc06_shared_payload_mutation),
    ("07_comment_as_coverage", "type_confusion", cc07_comment_as_coverage),
    ("08_bare_copied_attestation", "pre_tag", cc08_bare_or_copied_attestation_line),
    ("09_wrong_subject_digest", "pre_tag", cc09_wrong_subject_digest),
    ("10_unsigned_unbound_receipt", "pre_tag", cc10_unsigned_or_untrusted_receipt),
    ("11_pending_justified", "audit_candidate", cc11_pending_justified_internal),
    ("12_data_blocked", "audit_candidate", cc12_data_blocked_internal),
    ("13_unknown_verdict", "audit_candidate", cc13_unknown_verdict),
    ("14_negated_keyword_decoy", "audit_candidate", cc14_negated_keyword_decoy),
    ("15_inventory_disagreement", "type_confusion", cc15_inventory_disagreement),
    ("16_evaluate_never_raise_verdict", "type_confusion", cc16_evaluate_never_raise_verdict_observed),
    ("17_wholearg_wiring", "type_confusion", cc17_wholearg_wiring_observed),
    ("18_str_matrix_wiring", "type_confusion", cc18_str_matrix_wiring_observed),
    ("19_nonjson_exercise_wiring", "type_confusion", cc19_nonjson_exercise_wiring_observed),
    ("20_completeness_wiring", "type_confusion", cc20_completeness_wiring_observed),
    ("21_only_runtime_wiring", "type_confusion", cc21_only_runtime_disagreement),
    ("22_runtime_import_errors_wiring", "type_confusion", cc22_runtime_import_errors),
    ("23_nested_depth2_wiring", "type_confusion", cc23_nested_depth2_observed),
    ("24_any_inscope_routing_real", "type_confusion", cc24_any_inscope_routing_real),
    ("25_bytes_nonjson_routing_real", "type_confusion", cc25_bytes_nonjson_routing_real),
    ("26_recursionerror_routing_real", "type_confusion", cc26_recursionerror_routing_real),
    ("27_all_inscope_routing_tokens", "type_confusion", cc27_all_inscope_routing_tokens_real),
    ("28_all_nonjson_kind_routing", "type_confusion", cc28_all_nonjson_kind_routing_real),
    ("29_nested_recursionerror", "type_confusion", cc29_nested_recursionerror_real),
    ("30_str_matrix_assignment", "type_confusion", cc30_str_matrix_assignment_real),
    ("31_field_extraction_subscript", "type_confusion", cc31_field_extraction_subscript_real),
    ("32_pretag_binding_checks", "pre_tag", cc32_pretag_check_coverage),
]


def _positive_controls():
    # each gate must ACCEPT a clean input (not a constant reject).
    out = []
    priv, pub = _kp()
    out.append(("pre_tag_clean_receipt", _v(_receipt(priv, pub), [pub])))
    out.append(("audit_candidate_all_pass", _acm_ready([("C2.1", acm.PASS), ("EXT.1", acm.EXTERNAL)])))
    # type_confusion: a defended verifier produces NO violation (returns a verdict, not a raw crash)
    viol, ret = tcg._exercise(lambda x: False, {}, [None, {}, "s", 5], "x", False)
    out.append(("type_confusion_defended_clean", (not viol) and ret > 0))
    # the REAL gate must ACCEPT the clean subject tree (population_complete True) — proves the 15 detections
    # above are a discriminating gate, not a constant reject (green positive control per gate).
    _real = tcg.evaluate()
    out.append(("type_confusion_real_population_complete", _real["population_complete"] is True))
    # and the gate's HEADLINE never-raise verdict must be green on the clean tree (Gates re-gate T1):
    # cc16 seeds a crash and demands detection; this control demands the clean tree is NOT a false-positive.
    out.append(("type_confusion_real_never_raise_ok", _real["never_raise_ok"] is True))
    return out


def run() -> dict:
    results = []
    for cid, gate, fn in CLASSES:
        try:
            detected, detail = fn()
        except Exception as e:  # noqa: BLE001
            detected, detail = False, f"harness error: {type(e).__name__}: {e}"
        results.append({"class": cid, "gate": gate, "detected": bool(detected), "detail": detail})
    pos = [{"control": c, "passed": bool(p)} for c, p in _positive_controls()]
    detected_n = sum(1 for r in results if r["detected"])
    return {
        "schema": "b7n0de.makellose500.gate_qualification.v1",
        "classes_total": len(results),
        "classes_detected": detected_n,
        "detection_rate": f"{detected_n}/{len(results)}",
        "acceptance_all_classes_detected": detected_n == len(results) and len(results) >= 15,
        "acceptance_15_15": detected_n == len(results) and len(results) >= 15,  # back-compat alias
        "positive_controls": pos,
        "positive_controls_all_green": all(p["passed"] for p in pos),
        "results": results,
    }


def main(argv=None) -> int:
    r = run()
    print(json.dumps(r, indent=2, ensure_ascii=False))
    ok = r["acceptance_all_classes_detected"] and r["positive_controls_all_green"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
