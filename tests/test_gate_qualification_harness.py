"""The Gate Qualification Harness (makellose-500 Spur 1) must detect all preregistered counter-proof
classes with green positive controls. This test is the regression guard: if a gate reconstruction ever
regresses so a seeded defect survives, the detection rate drops below N/N and this goes red."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gate_qualification_harness as h  # noqa: E402


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
    import subprocess
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
    }
    env = {"PYTHONPATH": str(repo / "src"), "PATH": "/usr/bin:/bin"}

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
                 "31_payloads_assignment": "cc26_recursionerror_routing_real"}

    def target_still_detects(fn_name):
        code = f"import gate_qualification_harness as h; print(h.{fn_name}()[0])"
        r = subprocess.run(["python3", "-c", code], env=dict(env, PYTHONPATH=f"{repo}/src:{repo}/scripts"),
                           capture_output=True, text=True)
        return r.stdout.strip().endswith("True")

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
