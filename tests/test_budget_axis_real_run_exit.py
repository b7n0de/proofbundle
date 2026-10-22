"""BA1 (6.3.1): a real run of scripts/budget_axis_measurement.py ends with its verdict, never with a traceback.

The measurement writes `kombinationen`; main() read `kombis`, so every run that reached the end of main() died with
KeyError and exit 1 after writing its file, a passing run included. The tests of the writer fed main() a hand-built
dict that carried `kombis`, which is why nothing saw it. These cases drive the REAL messe() over the REAL test module
of the budget axis and the real main(), narrowed to one axis and one combination (json_depth, merkle_path x int_bits,
about five seconds here) so the run fits the suite. Narrowing changes the population, not the path: the same
assertions are called, and the record compares its names against the same narrowed lists.

RED at 22aa954e (KeyError: 'kombis' in both cases); green after the fix.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_budget_axis_real_run", REPO / "scripts" / "budget_axis_measurement.py")
bam = importlib.util.module_from_spec(_spec)
sys.modules["_budget_axis_real_run"] = bam
_spec.loader.exec_module(bam)

AXIS, KOMBI = "json_depth", "merkle_path x int_bits"


def _narrow(monkeypatch, marker: str | None):
    """The real test module, narrowed to one axis and one combination, with exactly one build-host marker or none."""
    t = bam._testmodul()
    monkeypatch.setattr(t, "DIMENSIONEN", [d for d in t.DIMENSIONEN if d.name == AXIS])
    monkeypatch.setattr(t, "KOMBIS", [k for k in t.KOMBIS if k[0] == KOMBI])
    assert [d.name for d in t.DIMENSIONEN] == [AXIS] and [k[0] for k in t.KOMBIS] == [KOMBI]
    for name in t._BAUHOST_MERKMALE:
        monkeypatch.delenv(name, raising=False)
    if marker:
        monkeypatch.setenv(marker, "true")
    return t


def _printed_entries(out: str) -> set:
    return {line.split("[budget-axis]   ", 1)[1].split(":", 1)[0] for line in out.splitlines()
            if line.startswith("[budget-axis]   ")}


def test_BA1_a_real_run_on_a_build_host_ends_with_exit_1_and_names_each_entry_that_did_not_pass(
        monkeypatch, capsys, tmp_path):
    _narrow(monkeypatch, "CI")
    out_file = tmp_path / "budget.json"
    rc = bam.main(["--out", str(out_file)])
    out = capsys.readouterr().out
    record = json.loads(out_file.read_text(encoding="utf-8"))
    assert record["ok"] is False and record["bauhost_marke"] == "CI", record
    assert rc == 1, out
    assert [k["urteil"] for k in record["kombinationen"]] == ["UEBERSPRUNGEN"], record["kombinationen"]
    assert _printed_entries(out) == {f"achse {AXIS}", f"kombi {KOMBI}"}, out


def test_BA1_a_real_run_ends_with_exit_0_exactly_when_its_record_says_ok(monkeypatch, capsys, tmp_path):
    """Without a marker the run judges; whatever it judges on this machine, the exit code follows the record (0 for ok,
    1 otherwise) and each entry that did not pass is named, the combinations included."""
    _narrow(monkeypatch, None)
    out_file = tmp_path / "budget.json"
    rc = bam.main(["--out", str(out_file)])
    out = capsys.readouterr().out
    record = json.loads(out_file.read_text(encoding="utf-8"))
    assert record["ist_referenzmessung"] is True, record
    assert rc == (0 if record["ok"] else 1), (rc, record["ok"], out)
    expected = {f"achse {a['name']}" for a in record["achsen"] if a["urteil"] != "BESTANDEN"} | \
        {f"kombi {k['name']}" for k in record["kombinationen"] if k["urteil"] != "BESTANDEN"}
    assert _printed_entries(out) == expected, out
