"""The limit of a mutant run follows the measured baseline of its selection (owner card OA-667bf9346e).

WHY THIS FILE EXISTS. Z230 gave every run of the suite one fixed limit of 3600 s. On the head of pull
request 385 (877bc38f, run 39167414888, shard 17) the baseline over a selection of 500 test files took
3435 s, three mutants were KILLED after 3348 to 3378 s, and `hashalg: B2 deprecated-algorithm reject
disabled` stopped at 3600.0 s in both attempts: NOT MEASURABLE, a gap, though on main 2379659e the same
mutant was KILLED after 3267 s. The fixed limit turned the growth of the suite into a gap that says
nothing about the mutant.

The cases drive the real `_run_operators` and `_basislinie`; only the suite run is replaced, by a run
on a fake clock that takes as long as the case says. The first case is the counter case: on the code
before the fix the mutant run stops at 3600 s and the operator is NOT MEASURABLE; with the fix it gets
its verdict. The anti-parity case holds the other half: a run that really hangs stays NOT MEASURABLE.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

KILLER = "tests.test_x::test_y"


def _modul():
    spec = importlib.util.spec_from_file_location("_mc_grenze", ROOT / "scripts" / "mutation_check.py")
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    return mc


def _fahre(monkeypatch, tmp_path, *, basislinie_s: float, mutant_s: float):
    """One operator on a planted tree; the baseline run takes `basislinie_s`, the mutant run
    `mutant_s` on the fake clock. A run whose limit is shorter stops at the limit and leaves no
    verdict, as a run that `subprocess` ends with `TimeoutExpired` does. Returns (gaps, output)."""
    mc = _modul()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.py").write_text("alt\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_y():\n    pass\n", encoding="utf-8")
    uhr = {"jetzt": 0.0}
    selektion = ("tests/test_x.py",)

    def lauf(work, *, auswahl=None, aus=None, gruen=None, grenze=3600):
        mutiert = (work / "src" / "x.py").read_text(encoding="utf-8") == "neu\n"
        if auswahl == selektion:
            braucht = mutant_s if mutiert else basislinie_s
            if grenze < braucht:
                uhr["jetzt"] += grenze
                return None
            uhr["jetzt"] += braucht
        else:
            uhr["jetzt"] += 1.0             # the killer runs again by itself
        rot = {KILLER: "call:AssertionError"} if mutiert else {}
        if aus is not None:
            aus.append(rot)
        if gruen is not None:
            gruen.append(set() if mutiert else {KILLER})
        return len(rot)

    monkeypatch.setattr(mc, "MUTATIONS", [("src/x.py", "alt", "neu", "op: planted", True)])
    monkeypatch.setattr(mc, "_auswahl", lambda work, rel: selektion)
    monkeypatch.setattr(mc, "_red_count", lauf)
    monkeypatch.setattr(mc, "time", types.SimpleNamespace(monotonic=lambda: uhr["jetzt"]))
    puffer = io.StringIO()
    with contextlib.redirect_stdout(puffer):
        gaps = mc._run_operators(tmp_path)
    return gaps, puffer.getvalue()


def test_a_mutant_that_needs_longer_than_3600_s_gets_its_verdict(monkeypatch, tmp_path):
    """THE COUNTER CASE, the measurement of shard 17 in small: a baseline of 3435 s and a mutant run
    of 3700 s. Red on the code before the fix (NICHT MESSBAR at 3600 s, one gap)."""
    gaps, text = _fahre(monkeypatch, tmp_path, basislinie_s=3435.0, mutant_s=3700.0)
    assert "KILLED" in text and "NICHT MESSBAR" not in text, text
    assert gaps == 0, text
    assert "limit per mutant run: 5153 s (the baseline took 3435.0 s)" in text, text


def test_a_baseline_past_3600_s_runs_under_its_own_limit(monkeypatch, tmp_path):
    """The baseline is the first run over a selection and has no measurement before it; at 4000 s
    the code before the fix stopped it, and the whole shard ended with SystemExit."""
    gaps, text = _fahre(monkeypatch, tmp_path, basislinie_s=4000.0, mutant_s=4100.0)
    assert gaps == 0 and "KILLED" in text, text
    assert "limit per mutant run: 6000 s" in text, text


def test_ANTI_PARITY_a_run_that_really_hangs_stays_not_measurable(monkeypatch, tmp_path):
    """The limit keeps its first reason. A mutant run that would take ten times its baseline stops
    at 1.5 times the baseline and is a gap, not a verdict."""
    gaps, text = _fahre(monkeypatch, tmp_path, basislinie_s=3435.0, mutant_s=34350.0)
    assert gaps == 1, text
    assert "NICHT MESSBAR" in text and "limit 5153 s" in text, text


def test_ANTI_PARITY_a_short_baseline_keeps_the_old_floor(monkeypatch, tmp_path):
    """A small selection keeps 3600 s: 1.5 times a baseline of 60 s is no limit for a loaded runner."""
    gaps, text = _fahre(monkeypatch, tmp_path, basislinie_s=60.0, mutant_s=3500.0)
    assert gaps == 0 and "limit per mutant run: 3600 s" in text, text


@pytest.mark.parametrize("dauer, grenze", [(0.0, 3600), (2400.0, 3600), (2400.1, 3601),
                                           (3435.0, 5153), (5400.0, 8100)])
def test_the_rule_in_numbers(dauer, grenze):
    assert _modul()._grenze_je_mutant(dauer) == grenze


def test_the_limit_reaches_the_subprocess(monkeypatch, tmp_path):
    """The named limit is the `timeout` the child runs under, and a call that names none keeps 3600 s
    (the contract in tests/test_mutationstor_sammler_sieht_die_freigabeflaeche.py)."""
    mc = _modul()
    gesehen = []

    def falle(argv, **kw):
        gesehen.append(kw.get("timeout"))
        raise mc.subprocess.TimeoutExpired(cmd="pytest", timeout=kw.get("timeout"))

    monkeypatch.setattr(mc.subprocess, "run", falle)
    monkeypatch.setattr(mc, "_AUSSCHLUSS_JE_MUTANTE", {})
    with contextlib.redirect_stdout(io.StringIO()):
        assert mc._red_count(tmp_path, grenze=5153) is None
        assert mc._red_count(tmp_path) is None
    assert gesehen == [5153, 3600], gesehen


def test_the_baseline_names_its_limit(monkeypatch, tmp_path):
    mc = _modul()
    gesehen = []

    def lauf(work, *, auswahl=None, aus=None, gruen=None, grenze=3600):
        gesehen.append(grenze)
        aus.append({})
        gruen.append({KILLER})
        return 0

    monkeypatch.setattr(mc, "_red_count", lauf)
    with contextlib.redirect_stdout(io.StringIO()):
        b = mc._basislinie(tmp_path, ("tests/test_x.py",), {})
    assert mc.GRENZE_BASISLINIE == 5400 and gesehen == [5400], gesehen
    assert b.bestanden == frozenset({KILLER}) and b.dauer >= 0.0
