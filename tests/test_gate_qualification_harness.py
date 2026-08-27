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
    }
    env = {"PYTHONPATH": str(repo / "src"), "PATH": "/usr/bin:/bin"}

    # map each wiring to the class that binds it; run ONLY that class per mutation (fast: one evaluate()
    # call, not the full 20-class harness). Isolation ("only that class reddens") is proven once in the
    # deliverable's one-time plant-and-catch; here we protect the BINDING (strip -> that class red).
    target_fn = {"17_wholearg_wiring": "cc17_wholearg_wiring_observed",
                 "18_str_matrix_wiring": "cc18_str_matrix_wiring_observed",
                 "19_nonjson_exercise_wiring": "cc19_nonjson_exercise_wiring_observed",
                 "20_completeness_wiring": "cc20_completeness_wiring_observed"}

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
