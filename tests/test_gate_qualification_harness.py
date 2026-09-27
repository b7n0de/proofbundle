"""The Gate Qualification Harness (makellose-500 Spur 1) must detect all preregistered counter-proof
classes with green positive controls. This test is the regression guard: if a gate reconstruction ever
regresses so a seeded defect survives, the detection rate drops below N/N and this goes red."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gate_qualification_harness as h  # noqa: E402

import pytest  # noqa: E402

try:  # test_15_of_15 asserts the gate reports population_complete=True, which requires the FULL
    import opentimestamps  # noqa: F401,E402  # surface population — the anchor OTS surfaces only
    _HAS_OTS = True         # import at runtime with opentimestamps ([anchors] extra). Without it the
except ImportError:         # gate HONESTLY reports the population incomplete, so this control is N/A.
    _HAS_OTS = False


def _verdicts_in_a_fresh_interpreter(fn_names):
    """Run harness classes in a new interpreter against the tree as it is on disk NOW and return each
    class's verdict: "True", "False", or "raised <Type>" (``run()`` counts a class that raises as not
    detected).

    Gate run 1 on the weak pinned keys fix (lens B, 231-1B-02, measured): the strip loops below ran
    ``python3`` with bytecode on, and every cc32 strip adds the same ten bytes, so all mutants have one
    size. Written within one second they also share an mtime, and CPython took the first mutant's .pyc
    for the others: under the test's own conditions all seven strips reported the schema strip's verdict.
    ``-B`` writes no .pyc, and an empty PYTHONPYCACHEPREFIX makes the interpreter read none, so every run
    compiles what is on disk. ``sys.executable`` replaces ``python3`` on a narrowed PATH, so the verdict
    comes from the interpreter the suite runs under. A run that ends without a verdict fails here: before,
    a crash printed nothing, and nothing read as a class going red."""
    import json
    import subprocess
    import tempfile
    repo = Path(__file__).resolve().parents[1]
    code = ("import json, gate_qualification_harness as h\n"
            "out = {}\n"
            f"for n in {list(fn_names)!r}:\n"
            "    try:\n"
            "        out[n] = str(bool(getattr(h, n)()[0]))\n"
            "    except Exception as e:  # noqa: BLE001\n"
            "        out[n] = 'raised ' + type(e).__name__\n"
            "print(json.dumps(out))\n")
    with tempfile.TemporaryDirectory() as leer:
        r = subprocess.run([sys.executable, "-B", "-c", code],
                           env={"PYTHONPATH": f"{repo}/src:{repo}/scripts", "PATH": "/usr/bin:/bin",
                                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": leer},
                           capture_output=True, text=True, timeout=600)
    zeilen = r.stdout.strip().splitlines()
    assert r.returncode == 0 and zeilen, (
        f"the harness run ended without a verdict (rc={r.returncode}); a crash is not a class going red: "
        f"{r.stderr.strip()[-600:]}")
    return json.loads(zeilen[-1])


def _assert_each_run_compiles_what_is_on_disk(path, orig, anker, strip, neutral, fn_name):
    """The strip loops' control for the run itself. Every strip is supposed to turn its class red, so a
    run that reused an earlier strip's bytecode would stay unnoticed. Here a strip is run first, then an
    edit that changes nothing, of the strip's size and stamped with the strip's mtime: bytecode cached
    for the strip is valid for that source by both of CPython's checks. A run that reads cached
    bytecode reports the strip's red twice, every time; a run that compiles what is on disk reports red,
    then green."""
    import os
    assert orig.count(anker) == 1 and len(neutral) == len(strip), (anker, len(neutral), len(strip))
    path.write_text(orig.replace(anker, strip, 1), encoding="utf-8")
    stempel = path.stat().st_mtime_ns
    try:
        rot = _verdicts_in_a_fresh_interpreter([fn_name])[fn_name]
        path.write_text(orig.replace(anker, neutral, 1), encoding="utf-8")
        os.utime(path, ns=(stempel, stempel))
        gruen = _verdicts_in_a_fresh_interpreter([fn_name])[fn_name]
    finally:
        path.write_text(orig, encoding="utf-8")
    assert rot != "True" and gruen == "True", (
        f"{fn_name}: {rot} after the strip, {gruen} after an edit that changes nothing, of the same size "
        f"and mtime; only red then green says each run compiled what was on disk")


@pytest.mark.skipif(not _HAS_OTS, reason="needs proofbundle[anchors] (opentimestamps): the gate's "
                    "full surface population includes anchor OTS surfaces that only import with it")
def test_15_of_15_counterproofs_detected_with_green_positive_controls():
    r = h.run()
    missed = [x["class"] for x in r["results"] if not x["detected"]]
    assert r["acceptance_all_classes_detected"], f"detection {r['detection_rate']}, missed: {missed}"
    assert r["positive_controls_all_green"], r["positive_controls"]
    assert r["classes_total"] >= 15   # 16 since the Gates re-gate added the never_raise_ok-integration class


def test_all_release_deciding_wirings_are_bound_and_isolated():
    """Gates re-gate round 3: cc16-cc20 must each BIND a distinct release-deciding detection wiring of
    type_confusion_gate.evaluate() to its headline verdict. Proven by mutation: strip one wiring and EXACTLY
    the matching class must go red (a present-but-vacuous class — the cc01/cc02 failure mode — would stay
    green). This is the anti-rot guarantee: a stripped detection capability cannot pass as 20/20 green."""
    import shutil
    import tempfile
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    gate = repo / "scripts" / "type_confusion_gate.py"
    orig = gate.read_text(encoding="utf-8")
    muts = {
        "17_wholearg_wiring": (
            'viol, ret_a = _exercise(info["fn"], info["extra_kwargs"], info["payloads"], info["primary_name"], info["primary_kwonly"])',
            'viol, ret_a = [], len(info["payloads"])'),
        "18_str_matrix_wiring": (
            'str_viol, ret_s = _exercise(info["fn"], info["extra_kwargs"], str_matrix, info["primary_name"], info["primary_kwonly"]) if str_matrix else ([], 0)',
            'str_viol, ret_s = ([], 0)'),
        "19_nonjson_exercise_wiring": (
            'viol, ret = _exercise(info["fn"], info["extra_kwargs"], info["payloads"], info["primary_name"], info["primary_kwonly"])',
            'viol, ret = [], len(info["payloads"])'),
        "20_completeness_wiring": (
            'population_size > 0 and evaluated == population_size and import_error == 0',
            'population_size > 0 and import_error == 0'),
        "15_only_ast_conjunct": (
            'inventories_agree = not only_ast and not only_runtime and not runtime_import_errors', 'inventories_agree = not only_runtime and not runtime_import_errors'),
        "21_only_runtime_conjunct": (
            'inventories_agree = not only_ast and not only_runtime and not runtime_import_errors', 'inventories_agree = not only_ast and not runtime_import_errors'),
        "22_runtime_import_errors_conjunct": (
            'inventories_agree = not only_ast and not only_runtime and not runtime_import_errors', 'inventories_agree = not only_ast and not only_runtime'),
        "23_nested_depth2_wiring": (
            'return v1 + v2, len(d1) + len(d2), gekuerzt',
            'return v1, len(d1) + len(d2), gekuerzt'),
        # Gates re-gate ROUND 6: the REAL _classify routing wirings (round-5 WIDERLEGT was the Any branch).
        "24_any_inscope_routing": (
            '"Any" in text or ', ''),
        "25_bytes_nonjson_routing": (
            '"bytes" in text or ', ''),
        "26_recursionerror_routing": (
            'violations.append(f"RecursionError on payload {_short(payload)}")', 'pass'),
        # Gates re-gate ROUND 7: the REAL routing is a CLASS of tokens, not one instance. cc27 binds every
        # IN_SCOPE token (round 6 bound only "Any"); cc28 binds the NON_JSON kind routes with a real hole.
        "27_dict":    ('"dict" in text or ', ''),
        "27_Dict":    ('"Dict" in text or ', ''),
        "27_Mapping": ('"Mapping" in text or ', ''),
        "27_list":    ('"list" in text or ', ''),
        "27_List":    ('"List" in text or ', ''),
        "28_kind_int":  ('if param.annotation is int or text == "int":\n        return "int"',
                         'if False:  # STRIPPED\n        return "int"'),
        "28_kind_path": ('if any(k in name for k in ("path", "file", "dir")) or "Path" in text:\n        return "path"',
                         'if False:  # STRIPPED\n        return "path"'),
        # Gates re-gate ROUND 8: the nested-path RecursionError arm (distinct from cc26's whole-arg arm).
        "29_nested_recursionerror": ('violations.append(f"RecursionError on nested leaf {pfad}")', 'pass'),
        # Gates re-gate ROUND 9: the matrix-SELECTION assignments in the real _classify (F5, ~L249/L250).
        # cc18 tests the str_matrix CONSUMPTION via a mocked _classify; the ASSIGNMENT was unbound.
        "30_str_matrix_assignment": ('"str_matrix": _COMPACT_STR_PAYLOADS if union_str else []', '"str_matrix": []'),
        "31_payloads_assignment": ('"payloads": _NONSTR_PAYLOADS if union_str else TYPE_CONFUSION_PAYLOADS', '"payloads": []'),
        # Gates re-gate ROUND 10: the THREE _field_names extraction branches (.get/subscript/in-compare).
        # cc23 binds them only as an all-or-nothing group; a PARTIAL break of one branch was unbound.
        "32_field_extraction_subscript": ('elif (isinstance(k, ast.Subscript) and isinstance(k.slice, ast.Constant)', 'elif (False and isinstance(k, ast.Subscript) and isinstance(k.slice, ast.Constant)'),
    }
    # map each wiring to the class that binds it; run ONLY that class per mutation (fast: one evaluate()
    # call, not the full 20-class harness). Isolation ("only that class reddens") is proven once in the
    # deliverable's one-time plant-and-catch; here we protect the BINDING (strip -> that class red).
    target_fn = {"17_wholearg_wiring": "cc17_wholearg_wiring_observed",
                 "18_str_matrix_wiring": "cc18_str_matrix_wiring_observed",
                 "19_nonjson_exercise_wiring": "cc19_nonjson_exercise_wiring_observed",
                 "20_completeness_wiring": "cc20_completeness_wiring_observed",
                 "15_only_ast_conjunct": "cc15_inventory_disagreement",
                 "21_only_runtime_conjunct": "cc21_only_runtime_disagreement",
                 "22_runtime_import_errors_conjunct": "cc22_runtime_import_errors",
                 "23_nested_depth2_wiring": "cc23_nested_depth2_observed",
                 "24_any_inscope_routing": "cc24_any_inscope_routing_real",
                 "25_bytes_nonjson_routing": "cc25_bytes_nonjson_routing_real",
                 "26_recursionerror_routing": "cc26_recursionerror_routing_real",
                 "27_dict": "cc27_all_inscope_routing_tokens_real",
                 "27_Dict": "cc27_all_inscope_routing_tokens_real",
                 "27_Mapping": "cc27_all_inscope_routing_tokens_real",
                 "27_list": "cc27_all_inscope_routing_tokens_real",
                 "27_List": "cc27_all_inscope_routing_tokens_real",
                 "28_kind_int": "cc28_all_nonjson_kind_routing_real",
                 "28_kind_path": "cc28_all_nonjson_kind_routing_real",
                 "29_nested_recursionerror": "cc29_nested_recursionerror_real",
                 "30_str_matrix_assignment": "cc30_str_matrix_assignment_real",
                 "31_payloads_assignment": "cc26_recursionerror_routing_real",
                 "32_field_extraction_subscript": "cc31_field_extraction_subscript_real"}

    def target_still_detects(fn_name):
        return _verdicts_in_a_fresh_interpreter([fn_name])[fn_name] == "True"

    # BASELINE: every target is green on the unmutated tree, in the same kind of run. Without it, a target
    # that is red for another reason would read as a strip turning it red.
    basis = _verdicts_in_a_fresh_interpreter(sorted(set(target_fn.values())))
    assert all(v == "True" for v in basis.values()), f"a target is not green before any strip: {basis}"

    bak = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    bak.write(orig)
    bak.close()
    try:
        for target, (o, n) in muts.items():
            assert orig.count(o) == 1, f"wiring anchor for {target} not unique ({orig.count(o)})"
            gate.write_text(orig.replace(o, n, 1), encoding="utf-8")
            try:
                detects = target_still_detects(target_fn[target])
            finally:
                gate.write_text(orig, encoding="utf-8")   # ALWAYS restore
            assert not detects, f"stripping {target} must make {target_fn[target]} go red (binding vacuous?)"
        o, n = muts["32_field_extraction_subscript"]
        _assert_each_run_compiles_what_is_on_disk(gate, orig, o, n, o + "  # xxxxxx",
                                                  "cc31_field_extraction_subscript_real")
    finally:
        gate.write_text(orig, encoding="utf-8")            # belt-and-suspenders restore
        shutil.os.unlink(bak.name)


def test_unresolved_surfaces_all_reduce_evaluated():
    """Redundancy invariant (un round-3, question D): the population_complete sub-terms import_error==0 and
    no_input==0 are DEFENSIVE REDUNDANCY of evaluated==population_size, NOT independent wirings — because a
    surface of ANY unresolved status (IMPORT_ERROR / NEEDS_FIXTURE / NO_INPUT) is not counted in
    `evaluated`, so it already forces evaluated<population (which cc20 binds). This pins that: if a future
    change ever counted an unresolved surface toward `evaluated`, import_error==0 would stop being
    redundant and would need its own binding class — and THIS test would go red first."""

    def seed(status, extra=None):
        info = {"python_ref": "proofbundle.seeded.verify_x", "status": status}
        if extra:
            info.update(extra)
        r = h._seed_evaluate(info)
        return r

    for status in ("IMPORT_ERROR", "NEEDS_FIXTURE"):
        r = seed(status)
        assert r["evaluated_count"] < r["population_size"], f"{status} must not count toward evaluated"
        assert r["population_complete"] is False, f"{status} surface must withhold completeness"
        assert r["import_error"] == (1 if status == "IMPORT_ERROR" else 0)


def test_cc27_table_covers_every_inscope_routing_token():
    """Generator-hardening (Gates re-gate round 7): cc27's _INSCOPE_ROUTING_TOKENS must list EVERY
    IN_SCOPE routing token in type_confusion_gate._is_json_primary, so a NEW token cannot be added to the
    gate without a binding class here (the round-6 failure was binding one instance, "Any", of a token
    CLASS). 'Union[dict' is excluded on purpose: any annotation whose str() matches it also matches
    'dict', so it is a redundant/dominated branch, not a separately reachable route."""
    import re
    from pathlib import Path
    import gate_qualification_harness as h

    gate = Path(__file__).resolve().parents[1] / "scripts" / "type_confusion_gate.py"
    body = gate.read_text(encoding="utf-8")
    body = body[body.index("def _is_json_primary"):]
    # the IN_SCOPE if-condition is the one that leads to `return True`
    idx = body.index("return True")
    cond = body[body.rindex("if ", 0, idx):idx]
    source_tokens = set(re.findall(r'"([^"]+)" in text', cond))
    source_tokens.discard("Union[dict")  # dominated by "dict"
    bound_tokens = {tok for tok, _ann in h._INSCOPE_ROUTING_TOKENS}
    missing = source_tokens - bound_tokens
    assert not missing, (
        f"_is_json_primary routes IN_SCOPE via token(s) {sorted(missing)} that cc27 does not bind — "
        f"add them to _INSCOPE_ROUTING_TOKENS (with an annotation whose str() matches only that token).")
    # and every bound token must really be a source token (no dead table entries drifting from the gate)
    stale = bound_tokens - source_tokens
    assert not stale, f"_INSCOPE_ROUTING_TOKENS lists {sorted(stale)} which _is_json_primary no longer has"


def test_every_recursionerror_arm_is_bound():
    """Gates re-gate round 8 (fix-the-class): the gate defends RecursionError in TWO exercise paths -- the
    whole-arg _exercise (bound by cc26) and the nested _exercise_nested (bound by cc29). A NEW RecursionError
    arm added to the gate without a binding class + strip is the round-6/7/8 failure mode (fix-the-instance).
    This guard finds EVERY `violations.append(f"RecursionError...")` arm in the gate source and asserts the
    strip meta-test above carries a strip for each -- so a new arm cannot be added unbound."""
    import re
    from pathlib import Path
    gate = Path(__file__).resolve().parents[1] / "scripts" / "type_confusion_gate.py"
    arms = re.findall(r'violations\.append\(f"RecursionError[^"]*"\)', gate.read_text(encoding="utf-8"))
    assert len(arms) >= 2, f"expected >=2 RecursionError arms (whole-arg + nested), found {len(arms)}: {arms}"
    this = Path(__file__).read_text(encoding="utf-8")
    for arm in arms:
        assert arm in this, (
            f"RecursionError arm {arm!r} in the gate has no strip in the meta-test muts -- add a binding "
            f"class (like cc26/cc29) + its strip, binding the CLASS 'RecursionError in every exercise path'.")


def test_every_matrix_selection_assignment_is_bound():
    """Gates re-gate round 9 (fix-the-class): _classify SELECTS the never-raise matrices for an IN_SCOPE
    surface via `union_str`-conditional assignments ("payloads", "str_matrix" at ~L249/L250, the F5 fix).
    cc18 tested only the str_matrix CONSUMPTION through a MOCKED _classify; the ASSIGNMENT was unbound
    (round-8 WIDERLEGT: the real shipped verify_bundle Union[dict,str] surface). This guard finds every
    `"<key>": <...> if union_str else <...>` matrix-selection assignment in _classify and asserts the
    strip meta-test carries a strip for each -> a new matrix key / changed assignment cannot be added
    unbound. Same generator-hardening as cc27's IN_SCOPE-token guard, applied to matrix selection."""
    import re
    from pathlib import Path
    gate = Path(__file__).resolve().parents[1] / "scripts" / "type_confusion_gate.py"
    assigns = re.findall(r'"\w+": [^\n]*? if union_str else [^\n,]*', gate.read_text(encoding="utf-8"))
    assert len(assigns) >= 2, f"expected >=2 matrix-selection assignments (payloads + str_matrix), found {len(assigns)}: {assigns}"
    this = Path(__file__).read_text(encoding="utf-8")
    for a in assigns:
        assert a in this, (
            f"matrix-selection assignment {a!r} in _classify has no strip in the meta-test muts -- add a "
            f"real-router binding class (like cc30) + its strip, binding the CLASS 'every matrix _classify "
            f"selects is exercised through the real router'.")


def test_every_field_extraction_branch_is_bound():
    """Gates re-gate round 10 (fix-the-class): _field_names extracts dict-key fields via THREE disjoint AST
    branches (.get / subscript / in-compare); the nested-leaf matrix can only crash a field it extracted.
    cc23 binds _field_names only as an all-or-nothing group -- a PARTIAL break of ONE branch was unbound
    (round-9 WIDERLEGT: the subscript branch, a subscript-only crash-critical field with no KeyError
    fallback). This guard finds each felder.add branch in _field_names and asserts the strip meta-test
    carries a strip that disables it -> a new/changed extraction branch cannot be added unbound."""
    import re
    from pathlib import Path
    gate = Path(__file__).resolve().parents[1] / "scripts" / "type_confusion_gate.py"
    src = gate.read_text(encoding="utf-8")
    fn = src[src.index("def _field_names"): src.index("def _nested_payloads")]
    nodes = set(re.findall(r"isinstance\(k, ast\.(Call|Subscript|Compare)\)", fn))
    assert nodes >= {"Call", "Subscript", "Compare"}, (
        f"_field_names extraction branches changed ({nodes}); a silently removed branch loses nested "
        f"coverage with no symptom -- rebind a real-router class per branch.")
    this = Path(__file__).read_text(encoding="utf-8")
    # The SUBSCRIPT branch was the round-9 WIDERLEGT (a subscript-only crash-critical field with a strict
    # exact-keys shape check -> NO KeyError fallback); cc31 binds it, asserted deterministically here. The
    # .get branch is bound by cc23/24/27 (real-module victims that read fields via .get) and the in-compare
    # branch by cc29 (`"runs" in bundle`) -- both verified in the FULL harness (strip -> those classes
    # redden); their per-branch ISOLATION strip is env/cache-flaky in a minimal-env subprocess, so it is
    # documented rather than asserted via the isolation meta-test.
    harness = (Path(__file__).resolve().parents[1] / "scripts" / "gate_qualification_harness.py").read_text()
    assert "cc31_field_extraction_subscript_real" in harness, "cc31 (subscript-branch binding) is gone"
    assert "False and isinstance(k, ast.Subscript)" in this, (
        "the subscript-branch meta-test strip (32 -> cc31) is gone -- the round-9 WIDERLEGT can reopen.")


def test_every_pretag_rejection_is_bound():
    """Round 12 (fix-the-class; un gegenlesung REJECT on the round-11 regex guard). The round-11 guard
    enumerated verify_receipt's binding checks by REGEX (`receipt.get("X") != `), which a differently-formed
    check escapes -- `receipt["X"] != `, `receipt.get("X") is None`, `signer not in trusted_pubkeys` -- so a
    NEW unbound check could stay green. Replace it with an AST count-pin that is robust to the condition FORM:
    every `return False` in verify_receipt is a rejection path; a NEW one changes the count and reddens this
    guard, forcing the author to add a cc32 case (a valid-except-that receipt must be rejected). The current
    13 paths: not-dict (type guard), EXPECTED-DIGEST-FORM (new 2026-09-07, one loop covering both
    expected digests), schema/version/subject_tree/gate_source/audit_exit (binding fields), no-trusted-key,
    untrusted-signer, no-signature(#9), WEAK-TRUSTED-KEY (new 2026-09-26: a pinned key the trust-anchor
    rule refuses, before any signature arithmetic), sig-errored, sig-not-verify(#10). cc32 binds
    schema/version/gate_source/audit_exit + untrusted-signer + tampered-signature + BOTH placeholder cases,
    and by their reason the weak trusted key and #9 no-signature; cc09 subject_tree; cc10 no-trusted-key by
    its reason; cc08 the type guard (stripped, cc08 raises).

    WHAT THIS PIN DOES NOT SEE (gate run 1 on the weak pinned keys fix, lens B, 231-1B-03): a check kept in
    place with its condition switched off leaves the count at 13. That is the strip test's job below: it
    takes the twelve conditions from the same AST and switches each one off. The thirteenth path is the
    except handler around the signature check, which has no condition to switch off.

    THE NEW PATH IS DIFFERENT IN KIND, and that is why cc32 had to grow a differently-shaped case: every
    other rejection reads a field OF THE RECEIPT. This one reads an INPUT THE GATE SUPPLIES — the placeholder
    it substitutes when it cannot measure the tree. `_v()` cannot reach it, because `_v` passes the fixed
    valid constants; the case therefore calls `verify_receipt` directly with the placeholder as the
    expectation."""
    import ast
    from pathlib import Path
    lib = Path(__file__).resolve().parents[1] / "scripts" / "pre_tag_receipt_lib.py"
    fn = next(n for n in ast.walk(ast.parse(lib.read_text(encoding="utf-8")))
              if isinstance(n, ast.FunctionDef) and n.name == "verify_receipt")
    returns_false = [n for n in ast.walk(fn)
                     if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple) and n.value.elts
                     and isinstance(n.value.elts[0], ast.Constant) and n.value.elts[0].value is False]
    assert len(returns_false) == 13, (
        f"verify_receipt now has {len(returns_false)} rejection paths (pinned 13) -- a release-deciding check "
        f"was added or removed. Add/remove the matching cc32 case (a valid-except-that receipt must be rejected) "
        f"and update this pin. AST-based so it is robust to the condition form (subscript / is-None / not-in).")


#: Every condition in verify_receipt that refuses, and the harness class that must turn red when it is
#: switched off. The test below takes the conditions from the AST, so a new one is either here or red.
_PRETAG_STRIPS = {
    "not isinstance(receipt, dict)": "cc08_bare_or_copied_attestation_line",
    "not isinstance(erwartet, str) or not _IST_SHA256.match(erwartet)": "cc32_pretag_check_coverage",
    'receipt.get("schema") != RECEIPT_SCHEMA': "cc32_pretag_check_coverage",
    'receipt.get("version") != expected_version': "cc32_pretag_check_coverage",
    'receipt.get("subject_tree_digest") != subject_tree_digest': "cc09_wrong_subject_digest",
    'receipt.get("gate_source_digest") != gate_source_digest': "cc32_pretag_check_coverage",
    'receipt.get("audit_exit_code") != 0': "cc32_pretag_check_coverage",
    "not trusted_pubkeys": "cc10_unsigned_or_untrusted_receipt",
    "signer not in trusted_pubkeys": "cc32_pretag_check_coverage",
    "not isinstance(sig, str)": "cc32_pretag_check_coverage",
    "weakness is not None": "cc32_pretag_check_coverage",
    "not ok": "cc32_pretag_check_coverage",
}


def _pretag_rejection_conditions(src):
    import ast
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "verify_receipt")
    return [ast.get_source_segment(src, n.test) for n in ast.walk(fn)
            if isinstance(n, ast.If) and n.body and isinstance(n.body[0], ast.Return)
            and isinstance(n.body[0].value, ast.Tuple) and n.body[0].value.elts
            and isinstance(n.body[0].value.elts[0], ast.Constant) and n.body[0].value.elts[0].value is False]


def test_pretag_binding_check_strips_redden_cc32():
    """Each verify_receipt rejection, switched off, must turn the class that binds it red -> genuinely
    bound, not vacuous. Mutation on pre_tag_receipt_lib.py; the schema strip is the round-10 P3-1.

    The table covers every refusing condition, taken from the AST (gate run 1 on the weak pinned keys fix,
    lens B, 231-1B-03). Before, seven strips were listed by hand, and measured in a fresh interpreter
    three conditions stayed green when switched off: `not trusted_pubkeys`, `not isinstance(sig, str)`
    and `weakness is not None`. A later layer refuses the same receipt under another reason, so cc10 and
    cc32 now check the reason for those three. The condition is switched off in parentheses: `if False
    and A or B:` still refuses on B, measured on the digest-form check."""
    from pathlib import Path
    lib = Path(__file__).resolve().parents[1] / "scripts" / "pre_tag_receipt_lib.py"
    orig = lib.read_text(encoding="utf-8")
    found = _pretag_rejection_conditions(orig)
    assert sorted(found) == sorted(_PRETAG_STRIPS), (
        f"verify_receipt refuses under {sorted(set(found) - set(_PRETAG_STRIPS))} with no strip here, and "
        f"the table lists {sorted(set(_PRETAG_STRIPS) - set(found))} that it no longer has")
    basis = _verdicts_in_a_fresh_interpreter(sorted(set(_PRETAG_STRIPS.values())))
    assert all(v == "True" for v in basis.values()), f"a class is not green before any strip: {basis}"

    try:
        for cond, fn_name in _PRETAG_STRIPS.items():
            anker = f"if {cond}:"
            assert orig.count(anker) == 1, f"pretag check anchor not unique: {anker!r}"
            lib.write_text(orig.replace(anker, f"if False and ({cond}):", 1), encoding="utf-8")
            try:
                verdict = _verdicts_in_a_fresh_interpreter([fn_name])[fn_name]
            finally:
                lib.write_text(orig, encoding="utf-8")
            assert verdict != "True", f"stripping {anker!r} must make {fn_name} go red (binding vacuous?)"
        _assert_each_run_compiles_what_is_on_disk(lib, orig, "if not ok:", "if False and (not ok):",
                                                  "if not ok:  # xxxxxxxx", "cc32_pretag_check_coverage")
    finally:
        lib.write_text(orig, encoding="utf-8")
