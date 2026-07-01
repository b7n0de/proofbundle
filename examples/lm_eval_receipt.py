#!/usr/bin/env python3
"""Turn a REAL EleutherAI lm-evaluation-harness results file into a signed, verifiable eval receipt.

Reads the harness export (no lm_eval import), builds a claim for a task/metric, emits a proofbundle
receipt, and verifies it — all offline. The receipt proves `passed` against `threshold` and keeps the
model/dataset as salted commitments, while carrying run provenance (git_hash, task version, n-shot).
"""
from pathlib import Path

from proofbundle import verify_bundle
from proofbundle.adapters import from_lm_eval_results
from proofbundle.emit import generate_signer
from proofbundle.evalclaim import decode_eval_claim, emit_eval_receipt

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "lm_eval_arc_easy_real.json"


def main() -> int:
    claim, _salts = from_lm_eval_results(FIXTURE, "arc_easy", "acc", comparator=">=", threshold="0.30",
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
