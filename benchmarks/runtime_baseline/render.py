#!/usr/bin/env python3
"""Write the runtime baseline's README tables from the recorded runs, never by hand.

README.md carries three blocks between markers: the machine and the runs, the stages, and the growing
history. Each is rendered here from results/<run>/summary.json; tests/test_runtime_baseline.py holds the
README to this output. Times are the recorded nanoseconds shown as microseconds with one decimal.

Usage: python benchmarks/runtime_baseline/render.py          rewrite the blocks in README.md
       python benchmarks/runtime_baseline/render.py --check  exit 1 when README.md differs
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
README = HERE / "README.md"
STAGES = ("capture", "canonicalize", "hash_sha256", "hash_leaf", "sign", "emit_empty_history", "durable_write",
          "policy", "verify")


def runs() -> list:
    """(name, summary) of every recorded run, in name order."""
    return [(d.name, json.loads((d / "summary.json").read_text(encoding="utf-8")))
            for d in sorted(RESULTS.iterdir()) if (d / "summary.json").is_file()]


def _us(ns: int) -> str:
    return f"{ns / 1000:.1f}"


def _joined(werte: list) -> str:
    return " / ".join(werte)


def machine_block(laeufe: list) -> list:
    erste = laeufe[0][1]
    env, st = erste["environment"], erste["settings"]
    zeilen = [
        "| what | value |", "|---|---|",
        f"| commit measured | `{env['package']['commit']}` |",
        f"| CPU | {env['cpu']['model']}, {env['cpu']['logical_cpus']} logical CPUs, {env['cpu']['machine']} |",
        f"| memory | {env['memory'].get('MemTotal')} total |",
        f"| operating system | {env['os']['release']}, kernel {env['os']['kernel']} |",
        f"| Python | {env['python']['implementation']} {env['python']['version']} |",
        "| dependencies | " + ", ".join(f"{k} {v}" for k, v in sorted(env["dependencies"].items())) + " |",
        f"| disk of the durable write | {env['disk']['fs_type']} on {env['disk']['device']}, mounted at "
        f"`{env['disk']['mount_point']}` |",
        f"| samples per case | {st['samples']} after {st['warmup']} untimed warm-up calls |",
        f"| payload | {st['payload_bytes']} bytes, sha256 `{st['payload_sha256']}` |",
        "",
        "| run | measured at (end) | load average at start (1, 5, 15 min) | at end | tree clean |", "|---|---|---|---|---|",
    ]
    for name, s in laeufe:
        e = s["environment"]
        start = ", ".join(f"{x:.2f}" for x in e["load_average_at_start"])
        ende = ", ".join(f"{x:.2f}" for x in e["load_average_at_end"])
        zeilen.append(f"| {name} | {s['measured_at']} | {start} | {ende} | "
                      f"{'yes' if e['package']['tree_clean_for_src_benchmarks_tools'] else 'NO'} |")
    return zeilen


def stages_block(laeufe: list) -> list:
    k = len(laeufe)
    zeilen = [f"| stage | p50, runs 1 to {k} | p95, run 1 | p99, runs 1 to {k} | max, run 1 |", "|---|---|---|---|---|"]
    for stufe in STAGES:
        z = [s["summary"][stufe] for _, s in laeufe]
        zeilen.append(f"| {stufe} | {_joined([_us(x['p50']) for x in z])} | {_us(z[0]['p95'])} | "
                      f"{_joined([_us(x['p99']) for x in z])} | {_us(z[0]['max'])} |")
    return zeilen


def history_block(laeufe: list) -> list:
    k = len(laeufe)
    zeilen = [f"| prior leaves n | SHA-256 calls per emit | emit p50, runs 1 to {k} | emit p99, run 1 | "
              "Merkle part p50, run 1 | signature p50, run 1 |", "|---|---|---|---|---|---|"]
    erste = laeufe[0][1]["summary"]["emit_growing_history"]
    for n in sorted(erste, key=int):
        z = [s["summary"]["emit_growing_history"][n] for _, s in laeufe]
        zeilen.append(f"| {n} | {z[0]['hash_calls_per_emit']['total']} | "
                      f"{_joined([_us(x['emit']['p50']) for x in z])} | {_us(z[0]['emit']['p99'])} | "
                      f"{_us(z[0]['merkle_part']['p50'])} | {_us(z[0]['sign_part']['p50'])} |")
    return zeilen


BLOCKS = (("machine", machine_block), ("stages", stages_block), ("history", history_block))


def render(text: str, laeufe: list) -> str:
    """`text` with every block between its markers replaced by the rendering of `laeufe`."""
    for name, bauer in BLOCKS:
        anfang, ende = f"<!-- {name}: written by render.py -->", f"<!-- end of {name} -->"
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
