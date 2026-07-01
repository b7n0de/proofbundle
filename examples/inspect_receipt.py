#!/usr/bin/env python3
"""Turn a REAL inspect_ai eval log into a signed, verifiable eval receipt (offline).

Reads a genuine inspect_ai `.eval` log (a mockllm run, generated offline with no API key or GPU) via the
stable read_eval_log API, builds a claim for a metric, emits a proofbundle receipt, and verifies it. The
receipt proves `passed` against `threshold` while keeping model/dataset as salted commitments, and carries
run provenance. Needs `pip install "proofbundle[inspect,eval]"`.
"""
from pathlib import Path

from proofbundle import verify_bundle
from proofbundle.adapters import from_inspect_ai_log
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import decode_eval_claim, emit_eval_receipt

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "inspect_logs" / "safety_refusal_demo.eval"


def main() -> int:
    claim, _salts = from_inspect_ai_log(FIXTURE, "accuracy", comparator=">=", threshold="0.00",
                                        timestamp="2026-07-01T12:00:00Z")
    bundle = emit_eval_receipt(claim, generate_signer())
    ok = verify_bundle(bundle).ok
    decoded = decode_eval_claim(bundle)
    print(f"suite {decoded['suite']}  metric {decoded['metric']} {decoded['comparator']} {decoded['threshold']}")
    print(f"passed {decoded['passed']}  provenance {decoded['provenance']}")
    print("=> OK" if ok else "=> FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
