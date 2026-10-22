"""The mutation run projects its wall clock early and stops above a budget (ECHO-MUTATION-HOCHRECHNUNG-UND-STOPP-01).

WHY THIS FILE EXISTS. The canonical run at 07b6122c started unsharded on 2026-10-21 at 23:13Z. Every
mutant selected 528 of 531 test files and took as long as the baseline (2089.6 s; nine mutants 2002 s to
2104 s), so the run would have needed about 67 h, and that became visible only hours later, from
outside. scripts/mutation_check.py now writes a projection after every judged operator, marked as one,
and with `--budget-stunden` it stops before the next operator once the projection is above the budget:
NICHT MESSBAR under exit code 3, never OK.

The cases drive the real `_run_operators`; only the suite run is replaced, by a run on a fake clock that
takes as long as the case says, as in tests/test_the_mutant_limit_follows_its_baseline.py. The counter
case is red on the code before the change: that gate knows no budget and runs every operator.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

KILLER = "tests.test_x::test_y"
STUNDE = 3600.0


def _modul():
    spec = importlib.util.spec_from_file_location("_mc_hochrechnung", ROOT / "scripts" / "mutation_check.py")
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    return mc


def _fahre(monkeypatch, tmp_path, *, operatoren: int, basislinie_s: float, mutant_s: float,
           bestaetigung_s: float = 10.0, **kw):
    """`operatoren` operators on one planted file, each KILLED; the baseline takes `basislinie_s`, each
    mutant run `mutant_s`, each confirming run `bestaetigung_s` on the fake clock. Returns
    (module, mutant runs, output, the result or the exception)."""
    mc = _modul()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.py").write_text("alt\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_y():\n    pass\n", encoding="utf-8")
    uhr = {"jetzt": 0.0}
    selektion = ("tests/test_x.py",)
    laeufe = {"mutant": 0}

    def lauf(work, *, auswahl=None, aus=None, gruen=None, grenze=3600):
        mutiert = (work / "src" / "x.py").read_text(encoding="utf-8") == "neu\n"
        if auswahl == selektion:
            uhr["jetzt"] += mutant_s if mutiert else basislinie_s
            laeufe["mutant"] += 1 if mutiert else 0
        else:
            uhr["jetzt"] += bestaetigung_s
        rot = {KILLER: "call:AssertionError"} if mutiert else {}
        if aus is not None:
            aus.append(rot)
        if gruen is not None:
            gruen.append(set() if mutiert else {KILLER})
        return len(rot)

    monkeypatch.setattr(mc, "MUTATIONS", [("src/x.py", "alt", "neu", f"op: planted {i}", True)
                                          for i in range(operatoren)])
    monkeypatch.setattr(mc, "_auswahl", lambda work, rel: selektion)
    monkeypatch.setattr(mc, "_red_count", lauf)
    monkeypatch.setattr(mc, "time", types.SimpleNamespace(monotonic=lambda: uhr["jetzt"]))
    puffer = io.StringIO()
    with contextlib.redirect_stdout(puffer):
        try:
            ergebnis = mc._run_operators(tmp_path, **kw)
        except mc.HochrechnungUeberBudget as stopp:
            ergebnis = stopp
    return mc, laeufe["mutant"], puffer.getvalue(), ergebnis


def _hochrechnungen(text: str) -> list[dict]:
    return [json.loads(z.split(" ", 1)[1]) for z in text.splitlines() if z.startswith("MUTATION_PROJECTION ")]


def test_a_slow_baseline_stops_the_run_above_its_budget(monkeypatch, tmp_path):
    """THE COUNTER CASE, the night of 2026-10-21 in small: five operators, a baseline of one hour, each
    mutant one hour. After the baseline and the first mutant the run has used about 2 h and projects
    about 6 h; with a budget of 3 h it stops before the second operator. Red on the code before the
    change, which knows no budget and runs all five."""
    mc, mutanten, text, ergebnis = _fahre(monkeypatch, tmp_path, operatoren=5, basislinie_s=STUNDE,
                                          mutant_s=STUNDE, budget_s=3 * STUNDE)
    assert isinstance(ergebnis, mc.HochrechnungUeberBudget), (ergebnis, text)
    assert mutanten == 1, (mutanten, text)
    h = _hochrechnungen(text)
    assert len(h) == 1 and h[0]["art"] == "Hochrechnung, keine Messung", text
    assert h[0]["lauf_s"] > 3 * STUNDE and h[0]["budget_s"] == 3 * STUNDE and h[0]["nach_operatoren"] == 1, h
    assert 5.5 * STUNDE < h[0]["lauf_s"] < 6.5 * STUNDE, h
    assert ergebnis.gaps == 0 and ergebnis.hochrechnung == h[0], ergebnis.gaps
    assert "MUTATION_DURATIONS" in text, "the judged operator keeps its duration line"


def test_ANTI_PARITY_a_run_inside_its_budget_judges_every_operator(monkeypatch, tmp_path):
    """The other half: the same run with a budget above its projection runs to the end, every operator
    KILLED, and it writes a projection before each operator after the first."""
    mc, mutanten, text, ergebnis = _fahre(monkeypatch, tmp_path, operatoren=5, basislinie_s=STUNDE,
                                          mutant_s=STUNDE, budget_s=10 * STUNDE)
    assert ergebnis == 0 and mutanten == 5, (ergebnis, mutanten, text)
    assert text.count("KILLED") == 5 and len(_hochrechnungen(text)) == 4, text


def test_without_a_budget_the_run_only_reports_its_projection(monkeypatch, tmp_path):
    mc, mutanten, text, ergebnis = _fahre(monkeypatch, tmp_path, operatoren=3, basislinie_s=STUNDE,
                                          mutant_s=STUNDE)
    assert ergebnis == 0 and mutanten == 3, (ergebnis, text)
    h = _hochrechnungen(text)
    assert [x["budget_s"] for x in h] == [None, None], h
    # after the second operator: 1 h baseline + 2 x (1 h + 20 s) gone, one operator of about 1 h to come
    assert abs(h[-1]["lauf_s"] - (4 * STUNDE + 60)) < 1, h


def test_the_projection_in_numbers():
    """Seconds per selected test file, from the measured mutants and baselines; a selection still
    without a baseline costs a baseline, an empty one nothing."""
    mc = _modul()
    assert mc._hochrechnung_s([(2000.0, 500)], [(2100.0, 500)], [500, 250, 0], [250]) == pytest.approx(
        4.0 * 750 + 4.2 * 250)
    assert mc._hochrechnung_s([(100.0, 10)], [], [10], [10]) == pytest.approx(200.0)   # no baseline yet
    assert mc._hochrechnung_s([], [], [10], [10]) == 0.0


def _main(mc, monkeypatch, argv, run):
    monkeypatch.setattr(mc, "_run_operators", run)
    monkeypatch.setattr(mc, "_prepare_workdir", lambda root, work: None)
    monkeypatch.setattr(mc, "_worktree_status", lambda root: "")
    puffer = io.StringIO()
    with contextlib.redirect_stdout(puffer):
        rc = mc.main(argv)
    return rc, puffer.getvalue()


def test_a_stop_above_the_budget_is_not_measured_and_never_ok(monkeypatch):
    """The closing line carries neither OK nor FAILED (the summary job of ci.yml reads the operator
    count from `=> (OK|FAILED) (N operators`), it names projection and budget, and the exit code is 3."""
    mc = _modul()
    gesehen = {}

    def stopp(work, **kw):
        gesehen.update(kw)
        raise mc.HochrechnungUeberBudget({"lauf_s": 6 * STUNDE, "budget_s": kw["budget_s"],
                                          "nach_operatoren": 1, "von_operatoren": 5}, 0)
    rc, text = _main(mc, monkeypatch, ["--budget-stunden", "3"], stopp)
    assert rc == mc.RC_UEBER_BUDGET == 3, (rc, text)
    assert gesehen == {"budget_s": 3 * STUNDE}, gesehen
    schluss = [z for z in text.splitlines() if z.startswith("=>")][-1]
    assert schluss.startswith("=> NICHT MESSBAR") and "6.0 h" in schluss and "3.0 h" in schluss, schluss
    assert f"total={len(mc.MUTATIONS)}" in schluss and "OK" not in schluss and "FAILED" not in schluss, schluss


def test_without_a_budget_the_old_call_stands(monkeypatch):
    """A stub without the new keyword keeps working (tests/test_mutation_shard_partition.py)."""
    mc = _modul()
    rc, text = _main(mc, monkeypatch, [], lambda work: 0)
    assert rc == 0 and "=> OK" in text, text


@pytest.mark.parametrize("budget", ["0", "-1", "nan", "inf"])
def test_a_budget_is_a_positive_number_of_hours(monkeypatch, budget):
    """Refused with its reason, not by argparse not knowing the option (the gate before the change
    exits 2 on any of these, which says nothing about the budget)."""
    mc = _modul()
    with pytest.raises(SystemExit) as stopp:
        _main(mc, monkeypatch, ["--budget-stunden", budget], lambda work, **kw: 0)
    assert "positive number of hours" in str(stopp.value.code), stopp.value.code
