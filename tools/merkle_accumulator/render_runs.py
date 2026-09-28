#!/usr/bin/env python3
"""Write the before-and-after table of the accumulator from the recorded runs, never by hand.

docs/merkle_accumulator/README.md carries two blocks between markers: the runs, and the growing history
with emit_bundle (the whole tree rebuilt) beside the accumulator (the frontier kept). Both are rendered
here from docs/merkle_accumulator/runs/<run>/summary.json, which benchmarks/runtime_baseline/run.py wrote
with this accumulator present; tests/test_merkle_accumulator_runs.py holds the README to this output.
Times are the recorded nanoseconds shown as microseconds with one decimal.

Usage: python tools/merkle_accumulator/render_runs.py          rewrite the blocks in the README
       python tools/merkle_accumulator/render_runs.py --check  exit 1 when the README differs
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "docs" / "merkle_accumulator" / "runs"
README = REPO / "docs" / "merkle_accumulator" / "README.md"


def runs() -> list:
    """(name, summary) of every recorded run, in name order."""
    return [(d.name, json.loads((d / "summary.json").read_text(encoding="utf-8")))
            for d in sorted(RUNS.iterdir()) if (d / "summary.json").is_file()]


def _us(ns: int) -> str:
    return f"{ns / 1000:.1f}"


def runs_block(laeufe: list) -> list:
    zeilen = ["| run | commit measured | measured at (end) | load average at start (1, 5, 15 min) | at end | "
              "tree clean |", "|---|---|---|---|---|---|"]
    for name, s in laeufe:
        e = s["environment"]
        start = ", ".join(f"{x:.2f}" for x in e["load_average_at_start"])
        ende = ", ".join(f"{x:.2f}" for x in e["load_average_at_end"])
        zeilen.append(f"| {name} | `{e['package']['commit'][:8]}` | {s['measured_at']} | {start} | {ende} | "
                      f"{'yes' if e['package']['tree_clean_for_src_benchmarks_tools'] else 'NO'} |")
    return zeilen


def history_block(laeufe: list) -> list:
    k = len(laeufe)
    zeilen = [f"| prior leaves n | SHA-256 calls, emit_bundle | SHA-256 calls, append | emit_bundle p50, runs 1 to "
              f"{k} | through the accumulator p50, runs 1 to {k} | append alone p50, run 1 |",
              "|---|---|---|---|---|---|"]
    erste = laeufe[0][1]["summary"]
    for n in sorted(erste["emit_growing_history"], key=int):
        vorher = [s["summary"]["emit_growing_history"][n] for _, s in laeufe]
        nachher = [s["summary"]["accumulator_growing_history"][n] for _, s in laeufe]
        zeilen.append(
            f"| {n} | {vorher[0]['hash_calls_per_emit']['total']} | {nachher[0]['hash_calls_per_append']['total']} | "
            + " / ".join(_us(x["emit"]["p50"]) for x in vorher) + " | "
            + " / ".join(_us(x["emit_through_accumulator"]["p50"]) for x in nachher) + " | "
            + f"{_us(nachher[0]['append']['p50'])} |")
    return zeilen


BLOCKS = (("runs", runs_block), ("history", history_block))


def render(text: str, laeufe: list) -> str:
    """`text` with every block between its markers replaced by the rendering of `laeufe`."""
    for name, bauer in BLOCKS:
        anfang, ende = f"<!-- {name}: written by render_runs.py -->", f"<!-- end of {name} -->"
        vor, rest = text.split(anfang, 1)
        _, nach = rest.split(ende, 1)
        text = vor + anfang + "\n\n" + "\n".join(bauer(laeufe)) + "\n\n" + ende + nach
    return text


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    alt = README.read_text(encoding="utf-8")
    neu = render(alt, runs())
    if "--check" in argv:
        return 0 if neu == alt else 1
    README.write_text(neu, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
