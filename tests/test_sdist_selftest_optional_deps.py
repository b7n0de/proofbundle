"""`pip install <sdist> && pytest` must exit 0 in a base-only install — skips permitted, failures not.

FOUND BY THE PRE-TAG DEEP GATE, 2026-08-25 (L6-F1-SDIST-PYYAML, P2, jury-confirmed). Built the
sdist, extracted it, created a clean venv with only the base dependencies (`cryptography`,
`rfc8785`) plus pytest, and ran the suite from the extracted tree: **six tests FAILED** instead of
skipping. `pyproject.toml` documents that invariant; nothing enforced it.

WHY THE PRODUCTION CODE IS NOT THE DEFECT, and this is the interesting half.
`audit_candidate_matrix.c1_1_two_ci_gates` catches the `ImportError` and reports an honest
`DATA_BLOCKED` — exactly the three-state discipline. The TEST asserted `PASS` and thereby turned
the third state into a failure. A test that checks a three-state gate with `assertEqual` against
one state has abolished the third answer.

MEASURED HERE with the import forced absent: **seven** methods are affected, not six — all of them
`c1_1`-related. The gate's count was close; the exact set is what the marker now covers.

WHAT THIS FILE GUARDS, in both directions:
  * with PyYAML absent, exactly the dependency-bound tests skip (and none of the others),
  * with PyYAML present, NOTHING skips — a marker that silently swallowed a whole class of tests
    in the normal environment would be worse than the failure it replaced.

HONEST BOUNDARY: this measures the SKIP MARKER, not a real base-only install. A genuine
`pip install <sdist>` in a clean venv is a CI job (the gate's remediation asks for one) and cannot
run inside the suite it is testing. What is proven here is that the marker binds the right set and
is inert when the dependency is present.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ZIEL = REPO / "tests" / "test_audit_candidate_360.py"

# Die sieben, gemessen mit blockiertem Import — nicht aus dem Gate-Bericht abgeschrieben.
ERWARTET = {
    "test_c1_1_collect_only_is_not_a_test_run",
    "test_c1_1_fails_when_second_gate_is_not_a_test_gate",
    "test_c1_1_green_on_real_repo",
    "test_c1_1_real_unittest_discover_passes",
    "test_c1_1_which_pytest_is_not_a_test_run",
    "test_variant3_pytest_only_in_comment_echo_or_disabled_job_fails_c1_1",
    "test_variant3b_real_executing_run_step_passes_c1_1",
}


def _lade(yaml_da: bool):
    """Die Zieldatei mit gesetztem Marker laden — das ist die Lage, die eine Basis-Installation
    erzeugt, ohne dass dieser Test eine Installation nachbauen muesste."""
    quelle = ZIEL.read_text(encoding="utf-8")
    alt = '_YAML_DA = importlib.util.find_spec("yaml") is not None'
    assert alt in quelle, "die Marker-Zeile hat sich geaendert — dieser Test misst dann nichts"
    ns = {"__name__": f"_t360_{yaml_da}", "__file__": str(ZIEL)}
    exec(compile(quelle.replace(alt, f"_YAML_DA = {yaml_da}"), str(ZIEL), "exec"), ns)
    return ns


def _uebersprungen(klasse) -> set:
    return {n for n in dir(klasse) if n.startswith("test_")
            and getattr(getattr(klasse, n), "__unittest_skip__", False)}


class TestOhneDieOptionaleAbhaengigkeit:
    def test_genau_die_abhaengigen_tests_ueberspringen(self):
        ns = _lade(False)
        assert _uebersprungen(ns["TestCheckDiscrimination"]) == ERWARTET

    def test_der_grund_steht_am_skip(self):
        """Ein Skip ohne Grund ist von einem vergessenen Test nicht zu unterscheiden."""
        ns = _lade(False)
        m = getattr(ns["TestCheckDiscrimination"], "test_c1_1_green_on_real_repo")
        grund = getattr(m, "__unittest_skip_why__", "")
        assert "PyYAML" in grund and "DATA_BLOCKED" in grund, grund


class TestMitDerAbhaengigkeit:
    def test_nichts_wird_still_uebersprungen(self):
        """ANTI-PARITY, und sie ist der Punkt: ein Marker, der IMMER skippt, bestuende den Test
        oben und wuerde sieben echte Pruefungen stillschweigend abschalten."""
        ns = _lade(True)
        assert _uebersprungen(ns["TestCheckDiscrimination"]) == set()

    def test_die_umgebung_hier_hat_die_abhaengigkeit(self):
        """Kontrolle fuer den Test darueber: waere PyYAML hier ohnehin absent, sagte er nichts."""
        if importlib.util.find_spec("yaml") is None:
            pytest.skip("PyYAML fehlt in dieser Umgebung — die Gegenrichtung ist hier nicht messbar")
        assert True
