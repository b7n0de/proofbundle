#!/usr/bin/env python3
"""Parity of the WebAssembly build of pb_verify_rs with the native build and the Python verifier.

    python tools/pb_verify_web/parity/parity.py --out <dir> [--native <binary>] [--no-browser]

Three measurements, all on the vectors of tools/pb_verify_rs/crosscheck.py:

1. crosscheck.py with the native binary, then with the WebAssembly build (run.mjs) in its place.
   crosscheck.py compares each binary with the Python verifier; this script then compares the two
   runs with each other: exit code, printed result and the relation differential matrix.
2. crosscheck.py once more through recorder.py, which records every call of the native binary
   with its input files and its output.
3. replay.mjs replays every recorded call against the WebAssembly build in Node and in a headless
   Chromium, through the page's own code, and counts the calls whose exit code, stdout and stderr
   are identical to the native call.

The native binary and site/pb_verify_rs.wasm must be built first (cargo build --release in
tools/pb_verify_rs, and build.sh here). The package under test must be importable.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
WEB = HERE.parent
RS = WEB.parent / "pb_verify_rs"

CROSSCHECK = """
import pathlib, sys
sys.path.insert(0, {rs!r})
import crosscheck
crosscheck.BIN = pathlib.Path({binary!r})
crosscheck._KANDIDATEN = [crosscheck.BIN]
sys.argv = ["crosscheck.py", "--matrix", {matrix!r}]
sys.exit(crosscheck.main())
"""


def crosscheck(binary: pathlib.Path, matrix: pathlib.Path, env: dict | None = None) -> tuple[int, list[str]]:
    code = CROSSCHECK.format(rs=str(RS), binary=str(binary), matrix=str(matrix))
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False)
    # The first line names the binary and the matrix line names the output path; both differ by design.
    lines = [line for line in proc.stdout.splitlines()
             if not line.startswith("BINARY UNDER TEST") and not line.startswith("wrote relation differential")]
    return proc.returncode, lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--native", type=pathlib.Path, default=RS / "target" / "release" / "pb_verify_rs")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    wasm = WEB / "site" / "pb_verify_rs.wasm"
    for need in (args.native, wasm):
        if not need.is_file():
            print(f"NOT MEASURED: {need} is missing; build it first")
            return 2
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    native_rc, native_lines = crosscheck(args.native, out / "matrix_native.json")
    wasm_rc, wasm_lines = crosscheck(WEB / "run.mjs", out / "matrix_wasm.json")
    rows = [json.loads((out / f"matrix_{k}.json").read_text(encoding="utf-8"))["rows"]
            for k in ("native", "wasm")]

    record = out / "record.jsonl"
    record.unlink(missing_ok=True)
    env = dict(os.environ, RECORD_TARGET=str(args.native), RECORD_LOG=str(record))
    record_rc, _ = crosscheck(HERE / "recorder.py", out / "matrix_recorded.json", env=env)
    replay = subprocess.run(["node", str(HERE / "replay.mjs"), str(WEB / "site"), str(record),
                             str(out / "replay.json"), *(["--no-browser"] if args.no_browser else [])],
                            capture_output=True, text=True, check=False)
    summary = {
        "crosscheck_exit": {"native": native_rc, "wasm": wasm_rc, "recording": record_rc},
        "crosscheck_output_identical": native_lines == wasm_lines,
        "relation_matrix_rows": {"native": len(rows[0]), "wasm": len(rows[1]), "identical": rows[0] == rows[1]},
        "replay_exit": replay.returncode,
        "replay": json.loads((out / "replay.json").read_text(encoding="utf-8"))["summary"]
        if (out / "replay.json").is_file() else replay.stderr[-2000:],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    ok = (native_rc == wasm_rc == record_rc == 0 and summary["crosscheck_output_identical"]
          and summary["relation_matrix_rows"]["identical"] and replay.returncode == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
