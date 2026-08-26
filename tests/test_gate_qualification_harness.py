"""The Gate Qualification Harness (makellose-500 Spur 1) must detect all 15 preregistered counter-proof
classes with green positive controls. This test is the regression guard: if a gate reconstruction ever
regresses so a seeded defect survives, the detection rate drops below 15/15 and this goes red."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gate_qualification_harness as h  # noqa: E402


def test_15_of_15_counterproofs_detected_with_green_positive_controls():
    r = h.run()
    missed = [x["class"] for x in r["results"] if not x["detected"]]
    assert r["acceptance_15_15"], f"detection {r['detection_rate']}, missed: {missed}"
    assert r["positive_controls_all_green"], r["positive_controls"]
    assert r["classes_total"] == 15
