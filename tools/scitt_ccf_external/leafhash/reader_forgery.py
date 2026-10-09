"""The leaf/node confusion forgeries of measure.py against proofbundle's -05 section 3.2 reader.

Runs ``proofbundle.scitt_ccf._inclusion_root`` from this repository's src under the pinned cbor2 of
the [scitt] extra, on every interior node of forgery_inputs.json (written by measure.py):
  A    the node's children as leaf components: itx = left child, evidence "x", data-hash = right child
  B    sizes and types unchecked: itx = left child, evidence = the right child's own preimage as text
       (latin-1, one character per byte), data-hash empty
  B32  as B with a 32-byte data-hash, so the preimage is 96 bytes again
A positive control runs the real newer receipt of the same run through the same harness.

Measurement only. Writes reader_result.json next to this file.

Usage: python3 reader_forgery.py --run RUN_DIR   (the run directory with newer.receipt.cbor)
"""
from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import version
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "src"))

import cbor2  # noqa: E402 - after the path to this repository's src
from proofbundle import scitt_ccf as SC  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--run", type=Path, required=True)
    args = ap.parse_args()
    d = json.loads((HERE / "forgery_inputs.json").read_text(encoding="utf-8"))
    root = bytes.fromhex(d["last_signed_root"])
    out: dict = {"cbor2": version("cbor2"), "nodes": len(d["nodes"]),
                 "control_reader_computes_root_for_a_real_leaf": None,
                 "A": {"accepts": 0, "refusals": {}, "computed_other_root": 0},
                 "B": {"accepts": 0, "refusals": {}, "computed_other_root": 0},
                 "B32": {"accepts": 0, "refusals": {}, "computed_other_root": 0}}

    def run(key, proof):
        try:
            r, _ = SC._inclusion_root(cbor2.dumps(proof))
        except Exception as exc:  # noqa: BLE001 - the refusal is the measurement
            m = str(exc)[:90]
            out[key]["refusals"][m] = out[key]["refusals"].get(m, 0) + 1
            return
        out[key]["accepts" if r == root else "computed_other_root"] += 1

    rc = cbor2.loads((args.run / "newer.receipt.cbor").read_bytes())
    rc = rc.value if hasattr(rc, "value") else rc
    r_ctrl, _ = SC._inclusion_root(rc[1][396][-1][0])
    out["control_reader_computes_root_for_a_real_leaf"] = r_ctrl == root
    for n in d["nodes"]:
        left, right = bytes.fromhex(n["L"]), bytes.fromhex(n["R"])
        p = [[side, bytes.fromhex(s)] for side, s in n["path"]]
        rp = bytes.fromhex(n["right_child_preimage"])
        run("A", {1: [left, "x", right], 2: p})
        run("B", {1: [left, rp.decode("latin-1"), b""], 2: p})
        run("B32", {1: [left, rp.decode("latin-1"), bytes(32)], 2: p})
    (HERE / "reader_result.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
