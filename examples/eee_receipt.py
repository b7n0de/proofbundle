#!/usr/bin/env python3
"""Convert an Every Eval Ever (EEE) dataset record into a signed proofbundle receipt, and verify it.

Reads a real EEE v0.2.2 JSON (no runtime import of every_eval_ever, which needs Python 3.12) and builds a
signed receipt with the model/dataset kept as salted commitments. Needs `pip install "proofbundle[eval]"`."""
from pathlib import Path

from proofbundle import verify_bundle
from proofbundle.adapters import from_eee_dataset
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import decode_eval_claim, emit_eval_receipt

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "eee_arc_easy.json"


def main() -> int:
    claim, _ = from_eee_dataset(FIXTURE, comparator=">=", threshold="0.30")
    bundle = emit_eval_receipt(claim, generate_signer())
    ok = verify_bundle(bundle).ok
    decoded = decode_eval_claim(bundle)
    print(f"suite {decoded['suite']}  metric {decoded['metric']} {decoded['comparator']} {decoded['threshold']}")
    print(f"passed {decoded['passed']}  provenance {decoded['provenance']}")
    print("=> OK" if ok else "=> FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
